package live

import (
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

const (
	Ready       = "ready"
	Packet      = "packet"
	Stats       = "stats"
	Permission  = "permission"
	OpenError   = "open"
	FilterError = "filter"
	ReadError   = "read"
)

type Message struct {
	Kind      string
	Detail    string
	Link      layers.LinkType
	Data      []byte
	Timestamp time.Time
	Length    int
	Dropped   int
}

func (m Message) CaptureInfo() gopacket.CaptureInfo {
	return gopacket.CaptureInfo{
		Timestamp: m.Timestamp, Length: m.Length, CaptureLength: len(m.Data),
	}
}
