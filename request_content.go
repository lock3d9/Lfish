package main

import (
	"bufio"
	"bytes"
	"cmp"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	maxRequestStream  = 4 << 20
	maxRequestHeader  = 64 << 10
	maxRequestBody    = 1 << 20
	maxRequestPreview = 64 << 10
	maxRequests       = 16
	maxRequestParts   = 16
)

type RequestContents struct {
	Requests   []CapturedRequest `json:"requests"`
	Selected   int               `json:"selected"`
	Encrypted  bool              `json:"encrypted"`
	Incomplete bool              `json:"incomplete"`
	Limited    bool              `json:"limited"`
}

type CapturedRequest struct {
	Packet      int            `json:"packet"`
	Method      string         `json:"method"`
	Host        string         `json:"host"`
	Target      string         `json:"target"`
	ContentType string         `json:"contentType"`
	Encoding    string         `json:"encoding"`
	Filename    string         `json:"filename"`
	Body        RequestPreview `json:"body"`
	Parts       []RequestPart  `json:"parts"`
	Incomplete  bool           `json:"incomplete"`
	Limited     bool           `json:"limited"`
}

type RequestPart struct {
	Field       string         `json:"field"`
	Filename    string         `json:"filename"`
	ContentType string         `json:"contentType"`
	Body        RequestPreview `json:"body"`
}

type RequestPreview struct {
	Kind      string `json:"kind"`
	Text      string `json:"text"`
	Truncated bool   `json:"truncated"`
}

type requestSegment struct {
	sequence uint32
	packet   int
	data     []byte
}

type requestMark struct {
	offset int
	packet int
}

type requestSpan struct {
	start, end int
}

func (a *App) RequestContent(id int) (RequestContents, error) {
	a.mu.RLock()
	if id < 1 || id > len(a.session.packets) {
		a.mu.RUnlock()
		return RequestContents{}, errors.New("Пакет не найден")
	}
	selected := &a.session.packets[id-1]
	if selected.transport != "TCP" || selected.Flow == 0 {
		a.mu.RUnlock()
		return RequestContents{}, nil
	}
	var directions [2][]requestSegment
	result := RequestContents{}
	for i := range a.session.packets {
		p := &a.session.packets[i]
		if p.Flow != selected.Flow {
			continue
		}
		if p.Protocol == "TLS" {
			result.Encrypted = true
		}
		if len(p.tcpPayload) == 0 {
			continue
		}
		direction := 0
		if p.Source != selected.Source || p.srcPort != selected.srcPort {
			direction = 1
		}
		seq := p.seq
		if p.syn {
			seq++
		}
		directions[direction] = append(directions[direction], requestSegment{seq, p.ID, p.tcpPayload})
	}
	a.mu.RUnlock()

	for _, segments := range directions {
		result.readDirection(segments, id)
	}
	return result, nil
}

func (result *RequestContents) readDirection(segments []requestSegment, selectedID int) {
	if len(segments) == 0 {
		return
	}
	origin := segments[0].sequence
	offset := func(segment requestSegment) int { return int(int32(segment.sequence - origin)) }
	var selected requestSpan
	for _, segment := range segments {
		if segment.packet == selectedID {
			selected = requestSpan{offset(segment), offset(segment) + len(segment.data)}
			break
		}
	}
	slices.SortStableFunc(segments, func(a, b requestSegment) int { return cmp.Compare(offset(a), offset(b)) })

	var data []byte
	var marks []requestMark
	start := offset(segments[0])
	readRun := func(data []byte) {
		result.readRun(data, marks, requestSpan{selected.start - start, selected.end - start})
	}
	remaining := maxRequestStream
	for _, segment := range segments {
		position := offset(segment)
		end := start + len(data)
		if position > end {
			result.Incomplete = true
			readRun(data)
			data, marks = data[:0], marks[:0]
			start, end = position, position
		}

		overlap := min(end-position, len(segment.data))
		if overlap > 0 && !bytes.Equal(data[position-start:position-start+overlap], segment.data[:overlap]) {
			result.Incomplete = true
			readRun(data[:position-start])
			return
		}
		tail := segment.data[overlap:]
		if len(tail) == 0 {
			continue
		}
		if len(result.Requests) >= maxRequests || len(tail) > remaining {
			result.Limited = true
			if len(result.Requests) < maxRequests && remaining > 0 {
				marks = append(marks, requestMark{len(data), segment.packet})
				data = append(data, tail[:remaining]...)
			}
			break
		}
		marks = append(marks, requestMark{len(data), segment.packet})
		data = append(data, tail...)
		remaining -= len(tail)
	}
	readRun(data)
}

func (result *RequestContents) readRun(data []byte, marks []requestMark, selected requestSpan) {
	mark := 0
	for position := 0; position < len(data); {
		if len(result.Requests) == maxRequests {
			result.Limited = true
			return
		}
		lineEnd := bytes.IndexByte(data[position:], '\n')
		if lineEnd < 0 {
			return
		}
		line := bytes.TrimSuffix(data[position:position+lineEnd], []byte("\r"))
		if bytes.HasPrefix(line, []byte("HTTP/1.1 ")) || bytes.HasPrefix(line, []byte("HTTP/1.0 ")) {
			return
		}
		if !isRequestLine(line) {
			position += lineEnd + 1
			continue
		}
		if !bytes.Contains(data[position:position+min(len(data)-position, maxRequestHeader)], []byte("\r\n\r\n")) {
			if len(data)-position >= maxRequestHeader {
				result.Limited = true
			} else {
				result.Incomplete = true
			}
			return
		}
		reader := bytes.NewReader(data[position:])
		buffer := bufio.NewReader(reader)
		request, err := http.ReadRequest(buffer)
		if err != nil {
			result.Incomplete = true
			return
		}
		for mark+1 < len(marks) && marks[mark+1].offset <= position {
			mark++
		}
		message, stop := readCapturedRequest(request, marks[mark].packet)
		result.Requests = append(result.Requests, message)
		next := len(data) - reader.Len() - buffer.Buffered()
		if result.Selected == 0 && selected.start < selected.end && selected.start < next && selected.end > position {
			result.Selected = len(result.Requests)
		}
		if stop || request.Method == http.MethodConnect || request.Header.Get("Upgrade") != "" {
			return
		}
		position = next
	}
}

func isRequestLine(line []byte) bool {
	if len(line) > 8192 {
		return false
	}
	method, rest, ok := bytes.Cut(line, []byte(" "))
	if !ok {
		return false
	}
	switch string(method) {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace:
		return bytes.HasSuffix(rest, []byte(" HTTP/1.1")) || bytes.HasSuffix(rest, []byte(" HTTP/1.0"))
	default:
		return false
	}
}

func readCapturedRequest(request *http.Request, packet int) (CapturedRequest, bool) {
	message := CapturedRequest{
		Packet: packet, Method: request.Method, Host: request.Host, Target: request.RequestURI,
		ContentType: request.Header.Get("Content-Type"), Encoding: request.Header.Get("Content-Encoding"),
	}
	_, disposition, _ := mime.ParseMediaType(request.Header.Get("Content-Disposition"))
	message.Filename = disposition["filename"]
	body, err := io.ReadAll(io.LimitReader(request.Body, maxRequestBody+1))
	message.Incomplete = err != nil
	message.Limited = len(body) > maxRequestBody
	stop := message.Incomplete || message.Limited
	if len(body) == 0 {
		message.Body.Kind = "empty"
		return message, stop
	}
	body = body[:min(len(body), maxRequestBody)]
	switch strings.ToLower(strings.TrimSpace(message.Encoding)) {
	case "", "identity":
	case "gzip", "x-gzip":
		var decodedIncomplete, decodedLimited bool
		body, decodedIncomplete, decodedLimited = decodeRequestGzip(body)
		message.Incomplete = message.Incomplete || decodedIncomplete
		message.Limited = message.Limited || decodedLimited
		if len(body) == 0 && decodedIncomplete {
			message.Body.Kind = "encoded"
			return message, stop
		}
	default:
		message.Body.Kind = "encoded"
		return message, stop
	}

	mediaType, parameters, _ := mime.ParseMediaType(message.ContentType)
	if strings.HasPrefix(mediaType, "multipart/") && parameters["boundary"] != "" {
		message.Body.Kind = "multipart"
		message.readParts(body, parameters["boundary"])
		return message, stop
	}
	message.Body = previewRequestBody(body, mediaType, maxRequestPreview)
	return message, stop
}

func decodeRequestGzip(body []byte) ([]byte, bool, bool) {
	reader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, true, false
	}
	defer reader.Close()
	decoded, err := io.ReadAll(io.LimitReader(reader, maxRequestBody+1))
	return decoded[:min(len(decoded), maxRequestBody)], err != nil, len(decoded) > maxRequestBody
}

func (message *CapturedRequest) readParts(body []byte, boundary string) {
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	remaining := maxRequestPreview
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			message.Incomplete = true
			return
		}
		if len(message.Parts) == maxRequestParts {
			message.Limited = true
			return
		}
		data, err := io.ReadAll(part)
		contentType := part.Header.Get("Content-Type")
		mediaType, _, _ := mime.ParseMediaType(contentType)
		item := RequestPart{Field: part.FormName(), Filename: part.FileName(), ContentType: contentType}
		item.Body = previewRequestBody(data, mediaType, remaining)
		message.Parts = append(message.Parts, item)
		remaining -= len(item.Body.Text)
		if err != nil {
			message.Incomplete = true
			return
		}
	}
}

func previewRequestBody(body []byte, mediaType string, limit int) RequestPreview {
	if len(body) == 0 {
		return RequestPreview{Kind: "empty"}
	}
	kind := "binary"
	switch {
	case json.Valid(body):
		kind = "json"
		if len(body) <= limit {
			body = formatRequestJSON(body, limit)
		}
	case strings.HasPrefix(mediaType, "text/"), mediaType == "application/json",
		strings.HasSuffix(mediaType, "+json"), mediaType == "application/x-www-form-urlencoded",
		isRequestText(body):
		kind = "text"
	default:
		return RequestPreview{Kind: kind}
	}
	end := min(len(body), limit)
	for end > 0 && end < len(body) && !utf8.RuneStart(body[end]) {
		end--
	}
	prefix := body[:end]
	text := strings.ToValidUTF8(string(prefix), "")
	return RequestPreview{Kind: kind, Text: text, Truncated: len(body) > limit}
}

func isRequestText(body []byte) bool {
	if !utf8.Valid(body) {
		return false
	}
	for _, b := range body {
		if b < 0x20 && b != '\n' && b != '\r' && b != '\t' || b == 0x7f {
			return false
		}
	}
	return true
}

func formatRequestJSON(data []byte, limit int) []byte {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	depth := 0
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch token {
		case json.Delim('{'), json.Delim('['):
			depth++
			if depth > 24 {
				return data
			}
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
	}
	var pretty bytes.Buffer
	if json.Indent(&pretty, data, "", "  ") == nil && pretty.Len() <= limit {
		return pretty.Bytes()
	}
	return data
}
