package main

import (
	"bufio"
	"encoding/gob"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"

	"lfish/internal/live"
)

func main() {
	if len(os.Args) != 3 {
		os.Exit(2)
	}

	stop := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		close(stop)
	}()

	output := bufio.NewWriter(os.Stdout)
	encoder := gob.NewEncoder(output)
	send := func(message live.Message) error {
		if err := encoder.Encode(message); err != nil {
			return err
		}
		return output.Flush()
	}
	_ = capture(os.Args[1], os.Args[2], stop, send)
}

func capture(device, filter string, stop <-chan struct{}, send func(live.Message) error) error {
	handle, err := pcap.OpenLive(device, 262144, false, 150*time.Millisecond)
	if err != nil {
		kind := live.OpenError
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "permission") || strings.Contains(message, "privilege") ||
			strings.Contains(message, "not permitted") {
			kind = live.Permission
		}
		return send(live.Message{Kind: kind, Detail: err.Error()})
	}
	defer handle.Close()

	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			return send(live.Message{Kind: live.FilterError, Detail: err.Error()})
		}
	}

	link := handle.LinkType()
	const linuxDLTRaw = 12
	if link == linuxDLTRaw {
		link = layers.LinkTypeRaw
	}
	if err := send(live.Message{Kind: live.Ready, Link: link}); err != nil {
		return err
	}

	report := func() error {
		stats, err := handle.Stats()
		if err != nil {
			return nil
		}
		return send(live.Message{Kind: live.Stats, Dropped: stats.PacketsDropped})
	}
	nextStats := time.Now().Add(time.Second)
	for {
		select {
		case <-stop:
			return report()
		default:
		}
		if time.Now().After(nextStats) {
			if err := report(); err != nil {
				return err
			}
			nextStats = time.Now().Add(time.Second)
		}

		data, ci, err := handle.ZeroCopyReadPacketData()
		if errors.Is(err, pcap.NextErrorTimeoutExpired) {
			continue
		}
		if err != nil {
			return send(live.Message{Kind: live.ReadError, Detail: err.Error()})
		}
		if err := send(live.Message{Kind: live.Packet, Data: data, Length: ci.Length, Timestamp: ci.Timestamp}); err != nil {
			return err
		}
	}
}
