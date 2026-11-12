package main

import (
	"errors"
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/gopacket/gopacket/layers"
)

type Diagnosis struct {
	Target      string                `json:"target"`
	DNS         Stage                 `json:"dns"`
	Connections []ConnectionDiagnosis `json:"connections"`
	More        int                   `json:"more"`
}

type Stage struct {
	State  string `json:"state"`
	Text   string `json:"text"`
	Packet int    `json:"packet"`
}

type ConnectionDiagnosis struct {
	Flow        int    `json:"flow"`
	Destination string `json:"destination"`
	TCP         Stage  `json:"tcp"`
	TLS         Stage  `json:"tls"`
}

type flowEvidence struct {
	id                                                              int
	server                                                          string
	port                                                            uint16
	syn, synAck, ack, reset, clientHello, serverHello, alert, fatal int
	synTime, helloTime                                              float64
}

func (s *session) diagnose(input string) (Diagnosis, error) {
	target := strings.ToLower(strings.TrimSpace(input))
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err != nil {
			return Diagnosis{}, errors.New("Введите домен, IP-адрес или URL")
		}
		target = u.Hostname()
	}
	target = strings.TrimSuffix(strings.Trim(target, "[]"), ".")
	if target == "" || len(target) > 253 || strings.ContainsAny(target, " /@\t\r\n") {
		return Diagnosis{}, errors.New("Введите домен, IP-адрес или URL")
	}
	ip := net.ParseIP(target)
	if ip != nil {
		target = ip.String()
	}
	result := Diagnosis{Target: target, DNS: Stage{"unknown", "Запросы DNS для этого имени не видны в захвате", 0}}
	addresses := map[string]bool{}
	if ip != nil {
		addresses[target] = true
		result.DNS = Stage{"unknown", "Указан IP-адрес. Для проверки DNS введите имя сайта", 0}
	}
	var request, response, failure, answer *Packet
	var evidence = make(map[int]*flowEvidence)
	var confirmedName = make(map[int]bool)
	for i := range s.packets {
		p := &s.packets[i]
		if ip == nil && p.dns != nil && (slices.Contains(p.dns.names, target) || len(p.dns.answers[target]) != 0) {
			switch {
			case !p.dns.response:
				request = p
			case p.dns.code != layers.DNSResponseCodeNoErr:
				response, failure = p, p
			default:
				response = p
				for _, address := range p.dns.answers[target] {
					addresses[address] = true
					answer = p
				}
			}
		}
		if p.transport != "TCP" || p.Flow == 0 {
			continue
		}
		e := evidence[p.Flow]
		if e == nil {
			e = &flowEvidence{id: p.Flow}
			evidence[p.Flow] = e
		}
		if p.syn && !p.ack && e.syn == 0 {
			e.syn, e.synTime, e.server, e.port = p.ID, p.Time, p.Destination, p.dstPort
		}
		if p.syn && p.ack && (e.server == "" || p.Source == e.server && p.srcPort == e.port) {
			e.synAck, e.server, e.port = p.ID, p.Source, p.srcPort
		}
		if p.ack && !p.syn && !p.rst && e.synAck != 0 && p.Destination == e.server && p.dstPort == e.port && e.ack == 0 {
			e.ack = p.ID
		}
		if p.rst && e.reset == 0 {
			e.reset = p.ID
		}
		if p.tlsClient && e.clientHello == 0 {
			e.clientHello, e.helloTime, e.server, e.port = p.ID, p.Time, p.Destination, p.dstPort
		}
		if p.tlsServer && e.serverHello == 0 {
			e.serverHello, e.server, e.port = p.ID, p.Source, p.srcPort
		}
		if p.tlsAlert && e.alert == 0 {
			e.alert = p.ID
		}
		if p.tlsFatal && e.fatal == 0 {
			e.fatal = p.ID
		}
		if p.serverName == target {
			confirmedName[p.Flow] = true
		}
	}
	switch {
	case answer != nil:
		result.DNS = Stage{"ok", "DNS вернул IP-адрес сайта", answer.ID}
	case failure != nil:
		result.DNS = Stage{"error", "Ошибка DNS: " + failure.dns.code.String(), failure.ID}
	case response != nil:
		result.DNS = Stage{"warning", "Ответ DNS без записи A или AAAA для этого имени", response.ID}
	case request != nil:
		result.DNS = unanswered("В захвате виден запрос DNS", request.ID, s.span-request.Time)
	}
	for i := len(s.flows) - 1; i >= 0; i-- {
		flow := s.flows[i]
		e := evidence[flow.ID]
		if e == nil {
			continue
		}
		destination := flow.Destination
		if e.server != "" {
			destination = endpoint(e.server, e.port)
		}
		host, _, _ := net.SplitHostPort(destination)
		if !confirmedName[e.id] && !addresses[host] {
			continue
		}
		if len(result.Connections) == 20 {
			result.More++
			continue
		}
		item := ConnectionDiagnosis{Flow: e.id, Destination: destination}
		switch {
		case e.reset != 0 && e.ack == 0:
			item.TCP = Stage{"error", "Виден сброс TCP до наблюдаемого завершения подключения", e.reset}
		case e.ack != 0:
			item.TCP = Stage{"ok", "Сервер ответил, клиент подтвердил подключение", e.ack}
		case e.synAck != 0:
			item.TCP = Stage{"warning", "Виден ответ SYN-ACK. Подтверждение клиента отсутствует в захвате", e.synAck}
		case e.syn != 0:
			item.TCP = unanswered("Виден SYN", e.syn, s.span-e.synTime)
		default:
			item.TCP = Stage{"unknown", "Начало TCP-соединения отсутствует в захвате", 0}
		}
		switch {
		case e.fatal != 0:
			item.TLS = Stage{"error", "Виден фатальный TLS Alert", e.fatal}
		case e.serverHello != 0:
			item.TLS = Stage{"ok", "Виден Server Hello. Результат рукопожатия может быть зашифрован", e.serverHello}
		case e.alert != 0:
			item.TLS = Stage{"warning", "Видно уведомление TLS Alert", e.alert}
		case e.clientHello != 0:
			item.TLS = unanswered("Виден Client Hello", e.clientHello, s.span-e.helloTime)
		default:
			item.TLS = Stage{"unknown", "Начало TLS-рукопожатия отсутствует в захвате", 0}
		}
		result.Connections = append(result.Connections, item)
	}
	return result, nil
}

func unanswered(label string, id int, seconds float64) Stage {
	if seconds >= 5 {
		return Stage{"warning", label + ". Ответа нет как минимум в следующих пяти секундах захвата", id}
	}
	return Stage{"unknown", label + ". Ответ пока не виден", id}
}
