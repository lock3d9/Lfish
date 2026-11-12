package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

const maxFrame = 1 << 20

func readCapture(path string) (result *session, resultErr error) {
	defer func() {
		if recover() != nil {
			result, resultErr = nil, errors.New("Повреждённая структура файла захвата")
		}
	}()
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("Выберите обычный файл захвата")
	}
	if info.Size() > 1<<30 {
		return nil, errors.New("Файл захвата больше 1 ГиБ")
	}
	input := bufio.NewReader(file)
	magic, err := input.Peek(4)
	if err != nil {
		return nil, err
	}

	s := newSession(nil)
	s.path = path
	if bytes.Equal(magic, []byte{0x0a, 0x0d, 0x0d, 0x0a}) {
		if err := validateNg(file, info.Size()); err != nil {
			return nil, err
		}
		options := pcapgo.NgReaderOptions{WantMixedLinkType: true}
		section := 0
		options.SectionEndCallback = func([]pcapgo.NgInterface, pcapgo.NgSectionInfo) { section++ }
		reader, err := pcapgo.NewNgReader(input, options)
		if err != nil {
			return nil, err
		}
		for {
			data, ci, options, err := reader.ReadPacketDataWithOptions()
			if err == io.EOF {
				return s, nil
			}
			if err != nil {
				return nil, err
			}
			link, ok := ci.AncillaryData[0].(layers.LinkType)
			if !ok {
				return nil, errors.New("Не удалось прочитать тип канала PCAPNG")
			}
			intf, err := reader.Interface(ci.InterfaceIndex)
			if err != nil {
				return nil, err
			}
			iface := intf.Name
			if iface == "" {
				iface = fmt.Sprintf("IF %d.%d", section+1, ci.InterfaceIndex+1)
			}
			p := decodePacket(data, ci, link, iface)
			p.Marked = len(options.Comments) != 0
			p.Note = strings.Join(options.Comments, "\n")
			if options.Flags != nil {
				switch options.Flags.Direction {
				case pcapgo.NgEpbFlagDirectionInbound:
					p.direction = -1
				case pcapgo.NgEpbFlagDirectionOutbound:
					p.direction = 1
				}
			}
			if len(p.Note) > 4000 {
				p.Note = strings.ToValidUTF8(p.Note[:4000], "")
				s.notice = "Заметки длиннее 4000 байт сокращены"
			}
			if err := s.append(p); err != nil {
				return nil, err
			}
		}
	}

	reader, err := pcapgo.NewReader(input)
	if err != nil {
		return nil, err
	}
	reader.SetSnaplen(min(reader.Snaplen(), maxFrame))
	for {
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			if data != nil {
				return nil, io.ErrUnexpectedEOF
			}
			return s, nil
		}
		if err != nil {
			return nil, err
		}
		if err := s.append(decodePacket(data, ci, reader.LinkType(), "PCAP")); err != nil {
			return nil, err
		}
	}
}

func writeCapture(path, format string, packets []Packet) error {
	if len(packets) == 0 {
		return errors.New("В сеансе пока нет пакетов")
	}
	if format == "pcapng" {
		return atomicFile(path, func(w io.Writer) error { return writePcapng(w, packets) })
	}
	link := packets[0].link
	var snaplen int
	for _, p := range packets {
		if p.link != link {
			return errors.New("Для разных типов канала используйте PCAPNG")
		}
		snaplen = max(snaplen, len(p.data))
	}
	return atomicFile(path, func(w io.Writer) error {
		buffer := bufio.NewWriter(w)
		writer := pcapgo.NewWriterNanos(buffer)
		if err := writer.WriteFileHeader(uint32(snaplen), link); err != nil {
			return err
		}
		for _, p := range packets {
			ci := p.ci
			if ci.Timestamp.IsZero() {
				ci.Timestamp = time.Unix(0, 0)
			}
			if err := writer.WritePacket(ci, p.data); err != nil {
				return err
			}
		}
		return buffer.Flush()
	})
}

func writePcapng(w io.Writer, packets []Packet) error {
	type key struct {
		link  layers.LinkType
		name  string
		index int
	}
	idFor := make(map[key]int)
	interfaceKey := func(p Packet) key { return key{p.link, p.iface, p.ci.InterfaceIndex} }
	makeInterface := func(p Packet) pcapgo.NgInterface {
		intf := pcapgo.DefaultNgInterface
		intf.Name, intf.LinkType, intf.SnapLength = p.iface, p.link, 0
		return intf
	}
	options := pcapgo.DefaultNgWriterOptions
	options.SectionInfo.Application = "LFish"
	writer, err := pcapgo.NewNgWriterInterface(w, makeInterface(packets[0]), options)
	if err != nil {
		return err
	}
	idFor[interfaceKey(packets[0])] = 0
	for _, p := range packets {
		key := interfaceKey(p)
		id, ok := idFor[key]
		if !ok {
			id, err = writer.AddInterface(makeInterface(p))
			if err != nil {
				return err
			}
			idFor[key] = id
		}
		ci := p.ci
		ci.InterfaceIndex = id
		if ci.Timestamp.IsZero() {
			ci.Timestamp = time.Unix(0, 0)
		}
		options := pcapgo.NgPacketOptions{}
		if p.Marked {
			options.Comments = []string{p.Note}
		}
		switch p.direction {
		case -1:
			options.Flags = &pcapgo.NgEpbFlags{Direction: pcapgo.NgEpbFlagDirectionInbound}
		case 1:
			options.Flags = &pcapgo.NgEpbFlags{Direction: pcapgo.NgEpbFlagDirectionOutbound}
		}
		if err := writer.WritePacketWithOptions(ci, p.data, options); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func atomicFile(path string, write func(io.Writer) error) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".lfish-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := write(file); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func validateNg(file *os.File, size int64) error {
	const (
		sectionHeaderBlock        = 0x0a0d0d0a
		interfaceDescriptionBlock = 1
		packetBlock               = 2
		simplePacketBlock         = 3
		enhancedPacketBlock       = 6
	)
	bad := errors.New("Некорректный размер блока PCAPNG")
	var header [28]byte
	var order binary.ByteOrder = binary.LittleEndian
	var firstSnaplen uint32
	interfaces := 0
	for offset := int64(0); offset < size; {
		if _, err := file.ReadAt(header[:12], offset); err != nil {
			return io.ErrUnexpectedEOF
		}
		if binary.LittleEndian.Uint32(header[:4]) == sectionHeaderBlock {
			switch binary.BigEndian.Uint32(header[8:12]) {
			case 0x1a2b3c4d:
				order = binary.BigEndian
			case 0x4d3c2b1a:
				order = binary.LittleEndian
			default:
				return errors.New("Неизвестный порядок байтов PCAPNG")
			}
			interfaces, firstSnaplen = 0, 0
		}
		length := int64(order.Uint32(header[4:8]))
		if length < 12 || length%4 != 0 || length > size-offset {
			return bad
		}
		var frameLength uint32
		switch order.Uint32(header[:4]) {
		case sectionHeaderBlock:
			if length < 28 {
				return bad
			}
		case interfaceDescriptionBlock:
			if length < 20 {
				return bad
			}
			if interfaces == 0 {
				if _, err := file.ReadAt(header[12:16], offset+12); err != nil {
					return err
				}
				firstSnaplen = order.Uint32(header[12:16])
			}
			interfaces++
		case packetBlock, enhancedPacketBlock:
			if length < 32 {
				return bad
			}
			if _, err := file.ReadAt(header[20:28], offset+20); err != nil {
				return err
			}
			frameLength = order.Uint32(header[20:24])
			if frameLength > order.Uint32(header[24:28]) || int64(frameLength) > length-32 {
				return bad
			}
		case simplePacketBlock:
			if length < 16 || interfaces == 0 {
				return bad
			}
			frameLength = order.Uint32(header[8:12])
			if firstSnaplen != 0 {
				frameLength = min(frameLength, firstSnaplen)
			}
			if int64(frameLength) > length-16 {
				return bad
			}
		}
		if frameLength > maxFrame {
			return errors.New("Кадр захвата больше 1 МиБ")
		}
		if _, err := file.ReadAt(header[:4], offset+length-4); err != nil {
			return err
		}
		if int64(order.Uint32(header[:4])) != length {
			return bad
		}
		offset += length
	}
	return nil
}
