package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"mime/multipart"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestRequestContentAcrossTCP(t *testing.T) {
	body := `{"account":9007199254740993,"labels":["test"]}`
	first := fmt.Sprintf("POST /api HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	wire := first + "GET /status HTTP/1.1\r\nHost: example.test\r\n\r\n"
	s := newSession(nil)
	add := func(seq uint32, reverse bool, data string) {
		t.Helper()
		p := Packet{transport: "TCP", Protocol: "TCP", Source: "192.0.2.10", Destination: "198.51.100.1",
			srcPort: 50000, dstPort: 80, seq: seq, tcpPayload: []byte(data)}
		if reverse {
			p.Source, p.Destination = p.Destination, p.Source
			p.srcPort, p.dstPort = p.dstPort, p.srcPort
		}
		if err := s.append(p); err != nil {
			t.Fatal(err)
		}
	}
	origin := uint32(0xffffffe0)
	add(origin+70, false, wire[70:])
	add(origin, false, wire[:40])
	add(origin+30, false, wire[30:75])
	add(100, true, "HTTP/1.1 200 OK\r\nContent-Length: 35\r\n\r\nGET /example HTTP/1.1\r\nHost: x\r\n\r\n")
	add(origin, false, wire[:40])

	result, err := (&App{session: s}).RequestContent(4)
	if err != nil || result.Incomplete || len(result.Requests) != 2 {
		t.Fatalf("reassembly failed: %+v, %v", result, err)
	}
	post, get := result.Requests[0], result.Requests[1]
	if post.Method != "POST" || post.Packet != 2 || post.Host != "example.test" || post.Target != "/api" ||
		post.Body.Kind != "json" || !strings.Contains(post.Body.Text, "\n  \"account\": 9007199254740993,") {
		t.Fatalf("unexpected POST preview: %+v", post)
	}
	selected, err := (&App{session: s}).RequestContent(5)
	if err != nil || selected.Selected != 1 {
		t.Fatalf("request at the selected retransmitted packet was not selected: %+v, %v", selected, err)
	}
	if get.Target != "/status" || get.Body.Kind != "empty" {
		t.Fatalf("unexpected GET preview: %+v", get)
	}
}

func TestRequestContentChunkedAndMultipart(t *testing.T) {
	var form bytes.Buffer
	writer := multipart.NewWriter(&form)
	file, err := writer.CreateFormFile("upload", "event.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte(`{"event":"hello"}`)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	wire := fmt.Sprintf("POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Type: %s\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", writer.FormDataContentType(), form.Len(), form.String())
	var result RequestContents
	result.readDirection([]requestSegment{{100, 1, []byte(wire)}}, 0)
	if len(result.Requests) != 1 {
		t.Fatalf("unexpected requests: %+v", result)
	}
	request := result.Requests[0]
	if request.Incomplete || request.Body.Kind != "multipart" || len(request.Parts) != 1 ||
		request.Parts[0].Filename != "event.json" || request.Parts[0].Body.Kind != "json" {
		t.Fatalf("unexpected multipart preview: %+v", request)
	}
}

func TestRequestContentGzipAndTruncatedBody(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(`{"zip":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	headers := fmt.Sprintf("PUT /config HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Disposition: attachment; filename=config.json\r\nContent-Length: %d\r\n\r\n", compressed.Len())
	wire := append([]byte(headers), compressed.Bytes()...)
	var result RequestContents
	result.readDirection([]requestSegment{{1, 1, wire}}, 0)
	if len(result.Requests) != 1 || result.Requests[0].Filename != "config.json" ||
		result.Requests[0].Body.Kind != "json" || result.Requests[0].Incomplete {
		t.Fatalf("unexpected gzip preview: %+v", result)
	}
	result = RequestContents{}
	result.readDirection([]requestSegment{{1, 1, wire[:len(wire)-10]}}, 0)
	if len(result.Requests) != 1 || !result.Requests[0].Incomplete {
		t.Fatalf("truncated request must be marked incomplete: %+v", result)
	}
}

func TestRequestContentDoesNotJoinAcrossGap(t *testing.T) {
	first := []byte("POST /api HTTP/1.1\r\nHost: example.test\r\nContent-Length: 8\r\n\r\n{\"a\":")
	var result RequestContents
	result.readDirection([]requestSegment{{1, 1, first}, {uint32(len(first) + 4), 2, []byte("1}")}}, 0)
	if len(result.Requests) != 1 || !result.Incomplete || !result.Requests[0].Incomplete ||
		result.Requests[0].Body.Text != "{\"a\":" {
		t.Fatalf("gapped request was not marked incomplete: %+v", result)
	}
}

func TestRequestContentDetectsTLS(t *testing.T) {
	s := newSession(nil)
	err := s.append(Packet{Source: "192.0.2.1", Destination: "192.0.2.2", srcPort: 50000, dstPort: 443,
		Protocol: "TLS", transport: "TCP", tcpPayload: []byte{23, 3, 3, 0, 3, 1, 2, 3}, link: layers.LinkTypeEthernet,
		ci: gopacket.CaptureInfo{Length: 8}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := (&App{session: s}).RequestContent(1)
	if err != nil || !result.Encrypted || len(result.Requests) != 0 {
		t.Fatalf("unexpected TLS result: %+v, %v", result, err)
	}
}
