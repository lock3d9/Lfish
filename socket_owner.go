package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const ownerRefreshInterval = 400 * time.Millisecond

type ProcessOwner struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
}

type socketKey struct {
	protocol     string
	source, peer netip.AddrPort
}

type socketSnapshot struct {
	at      time.Time
	sockets map[socketKey]string
	owners  map[string]*ProcessOwner
}

func (a *App) trackSocketOwners(ctx context.Context, s *session) {
	ticker := time.NewTicker(ownerRefreshInterval)
	defer ticker.Stop()
	for {
		snapshot := readSocketSnapshot(ctx)
		a.mu.Lock()
		if ctx.Err() != nil || a.session != s {
			a.mu.Unlock()
			return
		}
		s.socketOwners = snapshot
		for i := len(s.packets) - 1; i >= 0; i-- {
			p := &s.packets[i]
			if p.ci.Timestamp.Before(snapshot.at.Add(-ownerRefreshInterval)) {
				break
			}
			if p.Process == nil {
				p.Process = s.findProcess(*p)
			}
		}
		a.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *session) findProcess(p Packet) *ProcessOwner {
	snapshot := s.socketOwners
	if snapshot == nil || p.transport == "" {
		return nil
	}
	age := p.ci.Timestamp.Sub(snapshot.at)
	if age < -ownerRefreshInterval || age > 2*ownerRefreshInterval {
		return nil
	}
	source, err := netip.ParseAddr(p.Source)
	if err != nil || !(s.local[p.Source] || source.IsLoopback()) {
		return nil
	}
	peer, err := netip.ParseAddr(p.Destination)
	if err != nil {
		return nil
	}
	key := socketKey{p.transport, netip.AddrPortFrom(source.Unmap(), p.srcPort), netip.AddrPortFrom(peer.Unmap(), p.dstPort)}
	if inode, found := snapshot.sockets[key]; found {
		return snapshot.owners[inode]
	}
	if p.transport != "UDP" {
		return nil
	}
	key.peer = netip.AddrPort{}
	bound, hasBound := snapshot.sockets[key]
	wildcard := netip.IPv4Unspecified()
	if source.Is6() && !source.Is4In6() {
		wildcard = netip.IPv6Unspecified()
	}
	key.source = netip.AddrPortFrom(wildcard, p.srcPort)
	unbound, hasUnbound := snapshot.sockets[key]
	if hasBound && hasUnbound && bound != unbound {
		return nil
	}
	if hasBound {
		return snapshot.owners[bound]
	}
	return snapshot.owners[unbound]
}

func readSocketSnapshot(ctx context.Context) *socketSnapshot {
	snapshot := &socketSnapshot{
		at: time.Now(), sockets: make(map[socketKey]string), owners: make(map[string]*ProcessOwner),
	}
	for _, table := range []struct{ path, protocol string }{
		{"/proc/net/tcp", "TCP"}, {"/proc/net/tcp6", "TCP"},
		{"/proc/net/udp", "UDP"}, {"/proc/net/udp6", "UDP"},
	} {
		readSocketTable(table.path, table.protocol, snapshot.sockets)
	}
	known := make(map[string]bool)
	for _, inode := range snapshot.sockets {
		if inode != "" && inode != "0" {
			known[inode] = true
		}
	}
	if len(known) == 0 {
		return snapshot
	}
	processes, _ := os.ReadDir("/proc")
	for _, process := range processes {
		if ctx.Err() != nil {
			return snapshot
		}
		pid, err := strconv.Atoi(process.Name())
		if err != nil || !process.IsDir() {
			continue
		}
		path := filepath.Join("/proc", process.Name())
		fds, err := os.ReadDir(filepath.Join(path, "fd"))
		if err != nil {
			continue
		}
		var owner *ProcessOwner
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(path, "fd", fd.Name()))
			if err != nil || !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
				continue
			}
			inode := target[len("socket:[") : len(target)-1]
			if !known[inode] {
				continue
			}
			if owner == nil {
				name, err := os.ReadFile(filepath.Join(path, "comm"))
				if err != nil {
					break
				}
				owner = &ProcessOwner{PID: pid, Name: strings.TrimSpace(string(name))}
			}
			if existing, seen := snapshot.owners[inode]; !seen {
				snapshot.owners[inode] = owner
			} else if existing != nil && existing.PID != pid {
				snapshot.owners[inode] = nil
			}
		}
	}
	return snapshot
}

func readSocketTable(path, protocol string, sockets map[socketKey]string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 || protocol == "TCP" && fields[3] == "0A" {
			continue
		}
		source, peer := parseProcEndpoint(fields[1]), parseProcEndpoint(fields[2])
		if !source.IsValid() || !peer.IsValid() || source.Port() == 0 {
			continue
		}
		if protocol == "UDP" && peer.Addr().IsUnspecified() && peer.Port() == 0 {
			peer = netip.AddrPort{}
		}
		key := socketKey{protocol, source, peer}
		inode := fields[9]
		if existing, found := sockets[key]; found && existing != inode {
			sockets[key] = ""
		} else {
			sockets[key] = inode
		}
	}
}

func parseProcEndpoint(value string) netip.AddrPort {
	address, port, ok := strings.Cut(value, ":")
	if !ok || len(address) != 8 && len(address) != 32 {
		return netip.AddrPort{}
	}
	portNumber, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return netip.AddrPort{}
	}
	var raw [16]byte
	for i := 0; i < len(address)/2; i += 4 {
		word, err := strconv.ParseUint(address[2*i:2*i+8], 16, 32)
		if err != nil {
			return netip.AddrPort{}
		}
		binary.NativeEndian.PutUint32(raw[i:i+4], uint32(word))
	}
	if len(address) == 8 {
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(raw[:4])), uint16(portNumber))
	}
	return netip.AddrPortFrom(netip.AddrFrom16(raw).Unmap(), uint16(portNumber))
}
