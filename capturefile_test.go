package main

import (
	"bytes"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestCaptureRoundTrip(t *testing.T) {
	now := time.Unix(1700000000, 42)
	source, destination := net.IPv4(192, 0, 2, 10), net.IPv4(198, 51, 100, 20)
	s := newSession(map[string]bool{source.String(): true})
	add := func(offset time.Duration, reverse, syn, ack bool, payload []byte) {
		t.Helper()
		src, dst := source, destination
		sp, dp := layers.TCPPort(54000), layers.TCPPort(443)
		if reverse {
			src, dst, sp, dp = dst, src, dp, sp
		}
		eth := &layers.Ethernet{EthernetType: layers.EthernetTypeIPv4, SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}}
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: src, DstIP: dst}
		tcp := &layers.TCP{SrcPort: sp, DstPort: dp, SYN: syn, ACK: ack}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
			t.Fatal(err)
		}
		data := buf.Bytes()
		ci := gopacket.CaptureInfo{Timestamp: now.Add(offset), CaptureLength: len(data), Length: len(data)}
		if err := s.append(decodePacket(data, ci, layers.LinkTypeEthernet, "eth0")); err != nil {
			t.Fatal(err)
		}
	}
	add(0, false, true, false, nil)
	add(time.Millisecond, true, true, true, nil)
	add(2*time.Millisecond, false, false, true, nil)
	add(time.Second, false, false, true, []byte{22, 3, 3, 0, 1, 1})
	add(2*time.Second, true, false, true, []byte{21, 3, 3, 0, 2, 2, 40})
	app := &App{session: s}
	if err := app.SetNote(2, "Ответ сервера", true); err != nil {
		t.Fatal(err)
	}
	if err := app.SetNote(5, "", true); err != nil {
		t.Fatal(err)
	}

	for _, format := range []string{"pcap", "pcapng"} {
		t.Run(format, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "test."+format)
			if err := writeCapture(path, format, s.packets); err != nil {
				t.Fatal(err)
			}
			got, err := readCapture(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(got.packets) != 5 || len(got.flows) != 1 || got.flows[0].Count != 5 {
				t.Fatalf("round trip produced %d packets and %+v", len(got.packets), got.flows)
			}
			for i, p := range got.packets {
				if !bytes.Equal(p.data, s.packets[i].data) || !p.ci.Timestamp.Equal(s.packets[i].ci.Timestamp) {
					t.Fatalf("packet %d changed on round trip", p.ID)
				}
			}
			localized := got.view(Query{Text: "connection attempt", Language: "en"})
			if localized.Total != 2 {
				t.Fatalf("translated events did not match: %+v", localized.Packets)
			}
			view := got.view(Query{Text: "tls && port=443", HasInterval: true, From: 1, To: 2, IncludeGraph: true})
			if view.Total != 1 || view.Packets[0].ID != 4 {
				t.Fatalf("unexpected interval and filter result: %+v", view.Packets)
			}
			diagnosis, err := got.diagnose(destination.String())
			if err != nil {
				t.Fatal(err)
			}
			if len(diagnosis.Connections) != 1 || diagnosis.Connections[0].TCP.State != "ok" || diagnosis.Connections[0].TLS.Packet != 5 {
				t.Fatalf("unexpected diagnosis: %+v", diagnosis)
			}
			if format == "pcapng" {
				notes := got.view(Query{Tab: "notes"})
				if notes.Total != 2 || notes.Packets[0].Note != "Ответ сервера" || notes.Packets[1].ID != 5 {
					t.Fatalf("bookmarks lost: %+v", notes.Packets)
				}
				if view.Graph[0].In == 0 || view.Graph[0].Out == 0 {
					t.Fatalf("directions lost: %+v", view.Graph)
				}
			}
		})
	}
}

func TestDiagnoseDNS(t *testing.T) {
	now := time.Unix(1700000000, 0)
	client, resolver := net.IPv4(192, 0, 2, 10), net.IPv4(192, 0, 2, 53)
	s := newSession(nil)
	add := func(at time.Time, response bool) {
		t.Helper()
		source, destination := client, resolver
		sp, dp := layers.UDPPort(51000), layers.UDPPort(53)
		if response {
			source, destination, sp, dp = resolver, client, dp, sp
		}
		eth := &layers.Ethernet{EthernetType: layers.EthernetTypeIPv4, SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}}
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: source, DstIP: destination}
		udp := &layers.UDP{SrcPort: sp, DstPort: dp}
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		dns := &layers.DNS{ID: 42, QR: response, Questions: []layers.DNSQuestion{{Name: []byte("missing.example"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}}
		if response {
			dns.ResponseCode = layers.DNSResponseCodeNXDomain
		}
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, dns); err != nil {
			t.Fatal(err)
		}
		data := buf.Bytes()
		ci := gopacket.CaptureInfo{Timestamp: at, CaptureLength: len(data), Length: len(data)}
		if err := s.append(decodePacket(data, ci, layers.LinkTypeEthernet, "eth0")); err != nil {
			t.Fatal(err)
		}
	}
	add(now, false)
	s.span = 6
	pending, err := s.diagnose("missing.example")
	if err != nil || pending.DNS.State != "warning" || pending.DNS.Packet != 1 {
		t.Fatalf("unexpected unanswered DNS result: %+v, %v", pending, err)
	}
	add(now.Add(7*time.Second), true)
	result, err := s.diagnose("https://MISSING.example/")
	if err != nil || result.DNS.State != "error" || result.DNS.Packet != 2 {
		t.Fatalf("unexpected negative DNS result: %+v, %v", result, err)
	}
}
