package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type Packet struct {
	ID          int           `json:"id"`
	Time        float64       `json:"time"`
	Source      string        `json:"source"`
	Destination string        `json:"destination"`
	Protocol    string        `json:"protocol"`
	Length      int           `json:"length"`
	Info        string        `json:"info"`
	Event       string        `json:"event"`
	Flow        int           `json:"flow"`
	Note        string        `json:"note"`
	Marked      bool          `json:"marked"`
	Process     *ProcessOwner `json:"process,omitempty"`

	data                 []byte
	tcpPayload           []byte
	ci                   gopacket.CaptureInfo
	link                 layers.LinkType
	iface                string
	transport            string
	network              string
	srcPort, dstPort     uint16
	seq                  uint32
	syn, ack, rst, fin   bool
	tlsClient, tlsServer bool
	tlsAlert, tlsFatal   bool
	serverName           string
	dns                  *dnsEvidence
	direction            int
}

type dnsEvidence struct {
	response bool
	code     layers.DNSResponseCode
	names    []string
	answers  map[string][]string
}

type PacketDetail struct {
	Packet            Packet  `json:"packet"`
	Layers            []Layer `json:"layers"`
	Hex               string  `json:"hex"`
	CanInspectRequest bool    `json:"canInspectRequest"`
}

type Layer struct {
	Name string `json:"name"`
	Text string `json:"text"`
}

func decodePacket(data []byte, ci gopacket.CaptureInfo, link layers.LinkType, iface string) Packet {
	p := Packet{Length: ci.Length, Protocol: "OTHER", Event: "Сетевой пакет", Info: link.String(), data: data, ci: ci, link: link, iface: iface}
	decoded := gopacket.NewPacket(data, link, gopacket.NoCopy)
	if layer := decoded.LinkLayer(); layer != nil {
		source, destination := layer.LinkFlow().Endpoints()
		p.Source, p.Destination = source.String(), destination.String()
	}
	if layer := decoded.NetworkLayer(); layer != nil {
		source, destination := layer.NetworkFlow().Endpoints()
		p.Source, p.Destination = source.String(), destination.String()
		p.Protocol = layer.LayerType().String()
		p.network = p.Protocol
	}
	switch layer := decoded.TransportLayer().(type) {
	case *layers.TCP:
		p.Protocol, p.transport = "TCP", "TCP"
		p.srcPort, p.dstPort = uint16(layer.SrcPort), uint16(layer.DstPort)
		p.seq, p.tcpPayload = layer.Seq, layer.Payload
		p.syn, p.ack, p.rst, p.fin = layer.SYN, layer.ACK, layer.RST, layer.FIN
		var flags []string
		for _, flag := range []struct {
			set  bool
			name string
		}{
			{layer.SYN, "SYN"}, {layer.ACK, "ACK"}, {layer.RST, "RST"}, {layer.FIN, "FIN"},
			{layer.PSH, "PSH"}, {layer.URG, "URG"}, {layer.ECE, "ECE"}, {layer.CWR, "CWR"},
		} {
			if flag.set {
				flags = append(flags, flag.name)
			}
		}
		p.Info = fmt.Sprintf("%d → %d [%s] Seq=%d Ack=%d Win=%d", p.srcPort, p.dstPort, strings.Join(flags, ", "), layer.Seq, layer.Ack, layer.Window)
		p.Event = "Пакет TCP"
		switch {
		case p.rst:
			p.Event = "Соединение сброшено"
		case p.syn && p.ack:
			p.Event = "Сервер ответил на подключение"
		case p.syn:
			p.Event = "Попытка подключения"
		case p.fin:
			p.Event = "Завершение соединения"
		}
		p.readApplication(layer.Payload)
	case *layers.UDP:
		p.Protocol, p.transport, p.Event = "UDP", "UDP", "Пакет UDP"
		p.srcPort, p.dstPort = uint16(layer.SrcPort), uint16(layer.DstPort)
		p.Info = fmt.Sprintf("%d → %d, %d B", p.srcPort, p.dstPort, len(layer.Payload))
	}
	if layer, ok := decoded.Layer(layers.LayerTypeDNS).(*layers.DNS); ok {
		p.readDNS(layer)
	} else if tcp, ok := decoded.TransportLayer().(*layers.TCP); ok && (p.srcPort == 53 || p.dstPort == 53) && len(tcp.Payload) > 2 {
		size := int(binary.BigEndian.Uint16(tcp.Payload))
		var dns layers.DNS
		if size <= len(tcp.Payload)-2 && dns.DecodeFromBytes(tcp.Payload[2:2+size], gopacket.NilDecodeFeedback) == nil {
			p.readDNS(&dns)
		}
	}
	for _, kind := range []gopacket.LayerType{layers.LayerTypeICMPv4, layers.LayerTypeICMPv6, layers.LayerTypeARP} {
		if layer := decoded.Layer(kind); layer != nil {
			p.Protocol, p.Info = strings.ToUpper(kind.String()), gopacket.LayerString(layer)
			p.Event = "Служебное сообщение: " + p.Protocol
		}
	}
	return p
}

func (p *Packet) readDNS(layer *layers.DNS) {
	p.Protocol, p.Event = "DNS", "Запрос DNS"
	e := &dnsEvidence{response: layer.QR, code: layer.ResponseCode}
	var questions []string
	for _, question := range layer.Questions {
		name := strings.ToLower(strings.TrimSuffix(string(question.Name), "."))
		e.names = append(e.names, name)
		questions = append(questions, name+" ("+question.Type.String()+")")
	}
	p.Info = strings.Join(questions, ", ")
	if layer.QR {
		p.Event = "Ответ DNS"
		p.Info = layer.ResponseCode.String() + " · " + p.Info
		e.answers = make(map[string][]string)
		aliases := make(map[string]string)
		for _, answer := range layer.Answers {
			name := strings.ToLower(strings.TrimSuffix(string(answer.Name), "."))
			if answer.Type == layers.DNSTypeA || answer.Type == layers.DNSTypeAAAA {
				e.answers[name] = append(e.answers[name], answer.IP.String())
			} else if answer.Type == layers.DNSTypeCNAME {
				aliases[name] = strings.ToLower(strings.TrimSuffix(string(answer.CNAME), "."))
			}
		}
		for _, name := range e.names {
			target := name
			for step := 0; step < len(aliases) && aliases[target] != ""; step++ {
				target = aliases[target]
			}
			if target != name {
				e.answers[name] = e.answers[target]
			}
		}
	}
	p.dns = e
}

func (p *Packet) readApplication(payload []byte) {
	if len(payload) >= 6 && payload[1] == 3 && payload[2] <= 4 && payload[0] >= 20 && payload[0] <= 23 {
		size := int(binary.BigEndian.Uint16(payload[3:5]))
		if size == 0 || size > 18432 {
			return
		}
		p.Protocol, p.Event, p.Info = "TLS", "Защищённое соединение", "TLS Record"
		switch {
		case payload[0] == 22 && payload[5] == 1:
			p.tlsClient, p.Info = true, "Client Hello"
			if size <= len(payload)-5 {
				p.serverName = clientServerName(payload[5 : 5+size])
			}
			if p.serverName != "" {
				p.Info += " · " + p.serverName
			}
		case payload[0] == 22 && payload[5] == 2:
			p.tlsServer, p.Info = true, "Server Hello"
		case payload[0] == 21:
			p.tlsAlert, p.Info = true, "TLS Alert"
			if size == 2 && len(payload) >= 7 {
				p.tlsFatal = payload[5] == 2
				p.Info = fmt.Sprintf("TLS Alert · %d", payload[6])
			}
			p.Event = "Уведомление TLS"
		case payload[0] == 23:
			p.Info = "Application Data"
		}
		return
	}
	line, _, _ := strings.Cut(string(payload[:min(len(payload), 250)]), "\n")
	line = strings.TrimRight(line, "\r")
	method, _, _ := strings.Cut(line, " ")
	switch method {
	case "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT":
		if !strings.Contains(line, " HTTP/1.") {
			return
		}
	default:
		if !strings.HasPrefix(line, "HTTP/1.") {
			return
		}
	}
	p.Protocol, p.Event, p.Info = "HTTP", "Запрос или ответ HTTP", line
}

func clientServerName(message []byte) string {
	if len(message) < 39 {
		return ""
	}
	size := int(message[1])<<16 | int(message[2])<<8 | int(message[3])
	if size > len(message)-4 {
		return ""
	}
	body := message[4 : 4+size]
	if len(body) < 35 {
		return ""
	}
	body = body[34:]
	for _, width := range []int{1, 2, 1} {
		if len(body) < width {
			return ""
		}
		size := int(body[0])
		if width == 2 {
			size = int(binary.BigEndian.Uint16(body))
		}
		if size > len(body)-width {
			return ""
		}
		body = body[width+size:]
	}
	if len(body) < 2 {
		return ""
	}
	size = int(binary.BigEndian.Uint16(body))
	if size > len(body)-2 {
		return ""
	}
	extensions := body[2 : 2+size]
	for len(extensions) >= 4 {
		kind, length := binary.BigEndian.Uint16(extensions), int(binary.BigEndian.Uint16(extensions[2:]))
		if length > len(extensions)-4 {
			return ""
		}
		value := extensions[4 : 4+length]
		if kind == 0 && len(value) >= 5 && value[2] == 0 {
			length := int(binary.BigEndian.Uint16(value[3:]))
			if length <= len(value)-5 && length <= 253 && int(binary.BigEndian.Uint16(value)) == len(value)-2 {
				return strings.ToLower(string(value[5 : 5+length]))
			}
			return ""
		}
		extensions = extensions[4+length:]
	}
	return ""
}

func (p Packet) detail() PacketDetail {
	decoded := gopacket.NewPacket(p.data, p.link, gopacket.NoCopy)
	result := PacketDetail{Packet: p, Hex: hex.Dump(p.data), CanInspectRequest: p.transport == "TCP" && p.Flow != 0}
	result.Layers = append(result.Layers, Layer{"Кадр", fmt.Sprintf("Время: %s\nНа линии: %d B\nЗахвачено: %d B\nИнтерфейс: %s", p.ci.Timestamp.Format("2006-01-02 15:04:05.999999999 MST"), p.Length, len(p.data), p.iface)})
	for _, layer := range decoded.Layers() {
		if layer.LayerType() == gopacket.LayerTypePayload {
			continue
		}
		result.Layers = append(result.Layers, Layer{layer.LayerType().String(), gopacket.LayerString(layer)})
	}
	if p.Protocol == "TLS" || p.Protocol == "HTTP" || p.Protocol == "DNS" && decoded.Layer(layers.LayerTypeDNS) == nil {
		result.Layers = append(result.Layers, Layer{p.Protocol, p.Info})
	}
	return result
}

func endpoint(address string, port uint16) string {
	return net.JoinHostPort(address, fmt.Sprint(port))
}
