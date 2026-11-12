package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSocketEndpointDecoding(t *testing.T) {
	for _, value := range []string{"127.0.0.1:443", "[2001:db8::1234]:4567", "[::ffff:192.0.2.10]:53"} {
		expected := netip.MustParseAddrPort(value)
		address := expected.Addr().AsSlice()
		var field string
		for i := 0; i < len(address); i += 4 {
			field += fmt.Sprintf("%08X", binary.NativeEndian.Uint32(address[i:i+4]))
		}
		field += fmt.Sprintf(":%04X", expected.Port())
		got := parseProcEndpoint(field)
		expected = netip.AddrPortFrom(expected.Addr().Unmap(), expected.Port())
		if got != expected {
			t.Fatalf("parseProcEndpoint(%q) = %v, want %v", field, got, expected)
		}
	}
}

func TestProcessMatching(t *testing.T) {
	at := time.Now()
	s := newSession(map[string]bool{"127.0.0.1": true})
	s.socketOwners = &socketSnapshot{at: at, sockets: make(map[socketKey]string), owners: make(map[string]*ProcessOwner)}
	s.socketOwners.owners["12"] = &ProcessOwner{PID: 42, Name: "sender"}
	const source = "127.0.0.1"
	const peer = "198.51.100.2"
	path := filepath.Join(t.TempDir(), "udp")
	table := fmt.Sprintf("0: %08X:2800 00000000:0000 07 0:0 0:0 0 1000 0 12\n", binary.NativeEndian.Uint32([]byte{127, 0, 0, 1}))
	if err := os.WriteFile(path, []byte(table), 0600); err != nil {
		t.Fatal(err)
	}
	readSocketTable(path, "UDP", s.socketOwners.sockets)
	p := Packet{Source: source, Destination: peer, srcPort: 10240, dstPort: 443, transport: "UDP"}
	p.ci.Timestamp = at
	if got := s.findProcess(p); got == nil || got.PID != 42 {
		t.Fatalf("no owner for an unambiguous UDP socket: %+v", got)
	}
	p.Source, p.Destination = p.Destination, p.Source
	if got := s.findProcess(p); got != nil {
		t.Fatalf("attributed an incoming packet: %+v", got)
	}
	p.Source, p.Destination = source, peer
	wildcard := socketKey{"UDP", netip.MustParseAddrPort("0.0.0.0:10240"), netip.AddrPort{}}
	s.socketOwners.sockets[wildcard] = "13"
	if got := s.findProcess(p); got != nil {
		t.Fatalf("attributed an ambiguous packet: %+v", got)
	}
}
