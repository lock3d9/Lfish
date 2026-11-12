package main

import (
	"cmp"
	"errors"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	maxPackets = 150000
	maxBytes   = 128 << 20
	pageSize   = 150
)

var errLimit = errors.New("Достигнут лимит сеанса: 150 000 пакетов или 128 МиБ данных")

type flowKey struct {
	transport, a, b string
}

type Flow struct {
	ID          int     `json:"id"`
	Transport   string  `json:"transport"`
	Source      string  `json:"source"`
	Destination string  `json:"destination"`
	Count       int     `json:"count"`
	Bytes       int64   `json:"bytes"`
	Start       float64 `json:"start"`
	End         float64 `json:"end"`

	syn, synAck, established, closed bool
	seq                              uint32
}

type session struct {
	packets           []Packet
	flows             []Flow
	flowIDs           map[flowKey]int
	local             map[string]bool
	socketOwners      *socketSnapshot
	protocols         map[string]int
	marked            int
	noteRevision      uint64
	savedNoteRevision uint64
	bytes             int
	start             time.Time
	span              float64
	path              string
	iface             string
	dropped           int
	notice            string
}

func newSession(local map[string]bool) *session {
	return &session{local: local, flowIDs: make(map[flowKey]int), protocols: make(map[string]int), dropped: -1}
}

func (s *session) append(p Packet) error {
	if len(s.packets) >= maxPackets || s.bytes+len(p.data) > maxBytes {
		return errLimit
	}
	if s.start.IsZero() && !p.ci.Timestamp.IsZero() {
		s.start = p.ci.Timestamp
	}
	p.ID = len(s.packets) + 1
	if p.ci.Timestamp.IsZero() {
		p.Time = s.span
	} else {
		p.Time = p.ci.Timestamp.Sub(s.start).Seconds()
	}
	s.span = max(s.span, p.Time)
	if s.local[p.Source] && !s.local[p.Destination] {
		p.direction = 1
	} else if s.local[p.Destination] && !s.local[p.Source] {
		p.direction = -1
	}

	if p.transport != "" && p.Source != "" && p.Destination != "" {
		src, dst := endpoint(p.Source, p.srcPort), endpoint(p.Destination, p.dstPort)
		key := flowKey{p.transport, min(src, dst), max(src, dst)}
		id := s.flowIDs[key]
		if id != 0 {
			flow := &s.flows[id-1]
			switch {
			case p.syn && !p.ack && (flow.closed || flow.syn && flow.seq != p.seq):
				id = 0
			case p.transport == "UDP" && p.Time-flow.End > 60:
				id = 0
			}
		}
		if id == 0 {
			id = len(s.flows) + 1
			s.flowIDs[key] = id
			s.flows = append(s.flows, Flow{ID: id, Transport: p.transport, Source: src, Destination: dst, Start: p.Time, End: p.Time})
		}
		p.Flow = id
		flow := &s.flows[id-1]
		flow.Count++
		flow.Bytes += int64(p.Length)
		flow.End = max(flow.End, p.Time)
		if p.syn && !p.ack {
			flow.syn, flow.seq = true, p.seq
		}
		if p.rst || p.fin {
			flow.closed = true
		}
		if p.syn && p.ack && flow.syn && dst == flow.Source {
			flow.synAck = true
		}
		if p.ack && !p.syn && !p.rst && src == flow.Source && flow.synAck && !flow.established {
			flow.established = true
			if p.Protocol == "TCP" {
				p.Event = "Соединение установлено"
			}
		}
	}
	if p.Marked {
		s.marked++
	}
	p.Process = s.findProcess(p)
	s.packets = append(s.packets, p)
	s.bytes += len(p.data)
	s.protocols[p.Protocol]++
	return nil
}

type Query struct {
	Text         string  `json:"text"`
	Language     string  `json:"language"`
	Tab          string  `json:"tab"`
	Flow         int     `json:"flow"`
	Offset       int     `json:"offset"`
	Latest       bool    `json:"latest"`
	HasInterval  bool    `json:"hasInterval"`
	From         float64 `json:"from"`
	To           float64 `json:"to"`
	IncludeGraph bool    `json:"includeGraph"`
}

type Stats struct {
	Total     int             `json:"total"`
	Marked    int             `json:"marked"`
	Dropped   int             `json:"dropped"`
	Bytes     int             `json:"bytes"`
	Protocols []ProtocolCount `json:"protocols"`
}

type ProtocolCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type Bucket struct {
	From  float64 `json:"from"`
	To    float64 `json:"to"`
	In    int64   `json:"in"`
	Out   int64   `json:"out"`
	Other int64   `json:"other"`
}

type View struct {
	Packets   []Packet `json:"packets"`
	Flows     []Flow   `json:"flows"`
	Stats     Stats    `json:"stats"`
	Graph     []Bucket `json:"graph"`
	Total     int      `json:"total"`
	Offset    int      `json:"offset"`
	Path      string   `json:"path"`
	Interface string   `json:"interface"`
	Notice    string   `json:"notice"`
	Running   bool     `json:"running"`
}

func (s *session) view(q Query) View {
	v := View{Path: s.path, Interface: s.iface, Notice: s.notice}
	v.Stats = Stats{Total: len(s.packets), Marked: s.marked, Dropped: s.dropped, Bytes: s.bytes}
	for name, count := range s.protocols {
		v.Stats.Protocols = append(v.Stats.Protocols, ProtocolCount{name, count})
	}
	slices.SortFunc(v.Stats.Protocols, func(a, b ProtocolCount) int {
		if a.Count != b.Count {
			return cmp.Compare(b.Count, a.Count)
		}
		return cmp.Compare(a.Name, b.Name)
	})
	if q.IncludeGraph {
		v.Graph = s.graph()
	}

	var matches []int
	seen := make(map[int]bool)
	group := q.Tab == "flows" && q.Flow == 0
	filter := packetFilter(q.Text, q.Language)
	for i := range s.packets {
		p := &s.packets[i]
		if q.Flow != 0 && p.Flow != q.Flow || q.Tab == "notes" && !p.Marked || q.HasInterval && (p.Time < q.From || p.Time >= q.To) {
			continue
		}
		if !filter(p) {
			continue
		}
		if group {
			if p.Flow == 0 || seen[p.Flow] {
				continue
			}
			seen[p.Flow] = true
			matches = append(matches, p.Flow-1)
		} else {
			matches = append(matches, i)
		}
	}
	v.Total = len(matches)
	last := max(0, (v.Total-1)/pageSize*pageSize)
	v.Offset = min(max(q.Offset, 0), last)
	if q.Latest {
		v.Offset = last
	}
	for _, index := range matches[v.Offset:min(v.Offset+pageSize, v.Total)] {
		if group {
			v.Flows = append(v.Flows, s.flows[index])
		} else {
			v.Packets = append(v.Packets, s.packets[index])
		}
	}
	return v
}

func packetFilter(query, language string) func(*Packet) bool {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return func(*Packet) bool { return true }
	}
	var branches [][]string
	for _, branch := range strings.Split(query, "||") {
		if strings.TrimSpace(branch) == "" {
			continue
		}
		terms := strings.Split(branch, "&&")
		for i := range terms {
			terms[i] = strings.TrimSpace(terms[i])
		}
		branches = append(branches, terms)
	}
	return func(p *Packet) bool {
		for _, terms := range branches {
			match := true
			for _, term := range terms {
				if !p.matches(term, language) {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
		return false
	}
}

func (p *Packet) matches(term, language string) bool {
	switch term {
	case "tcp", "udp":
		return strings.EqualFold(p.transport, term)
	case "icmp":
		return strings.HasPrefix(p.Protocol, "ICMP")
	case "ipv4", "ipv6":
		return strings.EqualFold(p.network, term)
	case "tls", "dns", "http", "arp":
		return strings.EqualFold(p.Protocol, term)
	case "marked":
		return p.Marked
	case "":
		return false
	}
	if key, value, ok := strings.Cut(term, "="); ok {
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "src":
			return strings.EqualFold(p.Source, value)
		case "dst":
			return strings.EqualFold(p.Destination, value)
		case "port":
			port, err := strconv.ParseUint(value, 10, 16)
			return err == nil && p.transport != "" && (uint16(port) == p.srcPort || uint16(port) == p.dstPort)
		case "id":
			return strconv.Itoa(p.ID) == value
		}
	}
	if strings.Contains(strings.ToLower(p.Source+" "+p.Destination+" "+p.Protocol+" "+p.Info+" "+p.Event+" "+p.Note), term) {
		return true
	}
	if p.Process != nil && (strings.Contains(strings.ToLower(p.Process.Name), term) || strconv.Itoa(p.Process.PID) == term) {
		return true
	}
	if language != "en" && language != "uk" {
		return false
	}
	event, detail, hasDetail := strings.Cut(p.Event, ": ")
	event = localText(language, event)
	if hasDetail {
		event += ": " + detail
	}
	return strings.Contains(strings.ToLower(event), term)
}

func (s *session) graph() []Bucket {
	if len(s.packets) == 0 {
		return nil
	}
	first := 0.0
	for i := range s.packets {
		first = min(first, s.packets[i].Time)
	}
	first = math.Floor(first)
	step := max(1, math.Ceil((s.span-first)/47))
	n := int(math.Floor((s.span-first)/step)) + 1
	buckets := make([]Bucket, n)
	for i := range buckets {
		buckets[i].From = first + float64(i)*step
		buckets[i].To = buckets[i].From + step
	}
	for i := range s.packets {
		p := &s.packets[i]
		bucket := &buckets[int(math.Floor((p.Time-first)/step))]
		switch p.direction {
		case -1:
			bucket.In += int64(p.Length)
		case 1:
			bucket.Out += int64(p.Length)
		default:
			bucket.Other += int64(p.Length)
		}
	}
	return buckets
}
