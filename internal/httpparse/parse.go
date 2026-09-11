// Package httpparse recognises HTTP/1.1 messages in captured payload prefixes.
//
// It reads only the start line and the headers needed to identify a service. A
// captured payload is a prefix of one write or read, so it is routinely
// truncated and frequently not HTTP at all: TLS record headers, HTTP/2 frames,
// and response bodies all arrive through the same path. Every entry point
// therefore reports whether the input was recognised rather than returning a
// zero value that reads as valid.
package httpparse

import (
	"bytes"
)

// Kind distinguishes the two sides of an exchange.
type Kind uint8

const (
	// NotHTTP covers everything the parser does not recognise: TLS record
	// headers, HTTP/2 frames, response body continuations, and binary data.
	NotHTTP Kind = iota
	Request
	Response
)

func (k Kind) String() string {
	switch k {
	case Request:
		return "request"
	case Response:
		return "response"
	default:
		return "not-http"
	}
}

// Message is what the parser extracts from a start line.
type Message struct {
	Kind Kind

	// Request fields.
	Method string
	Path   string

	// Response fields.
	Status int
	Reason string

	// Version as written on the wire, e.g. "HTTP/1.1".
	Version string

	// Host from the request headers, when present within the captured prefix.
	// Service name inference uses it, and it is absent whenever the headers
	// extend past the capture limit.
	Host string
}

// methods are the HTTP/1.1 methods this parser accepts.
//
// An explicit list rather than a general token match, because the input is
// arbitrary binary: any four printable bytes followed by a space would
// otherwise be read as a method, and captured payloads contain plenty of those.
//
// PRI is deliberately absent. "PRI * HTTP/2.0" is the HTTP/2 connection
// preface, and it parses cleanly as a request line — it is the first thing a
// client sends after negotiating h2 over ALPN. Accepting it would report HTTP/2
// connections as HTTP/1.1 requests to a path of "*".
var methods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("HEAD "),
	[]byte("DELETE "), []byte("PATCH "), []byte("OPTIONS "), []byte("TRACE "),
	[]byte("CONNECT "),
}

var (
	http11  = []byte("HTTP/1.1")
	http10  = []byte("HTTP/1.0")
	crlf    = []byte("\r\n")
	hostKey = []byte("host:")
)

// Parse examines a captured payload prefix.
//
// The second result reports whether anything was recognised; when false the
// message is unusable and the payload should be ignored.
func Parse(b []byte) (Message, bool) {
	// The shortest meaningful start line is a status line, "HTTP/1.0 200".
	if len(b) < 12 {
		return Message{}, false
	}

	if m, ok := parseStatusLine(b); ok {
		return m, true
	}
	if m, ok := parseRequestLine(b); ok {
		return m, true
	}
	return Message{}, false
}

// parseStatusLine reads "HTTP/1.1 200 OK".
func parseStatusLine(b []byte) (Message, bool) {
	var version []byte
	switch {
	case bytes.HasPrefix(b, http11):
		version = http11
	case bytes.HasPrefix(b, http10):
		version = http10
	default:
		return Message{}, false
	}

	rest := b[len(version):]
	if len(rest) < 5 || rest[0] != ' ' {
		return Message{}, false
	}
	rest = rest[1:]

	code, ok := parseStatusCode(rest[:3])
	if !ok {
		return Message{}, false
	}

	m := Message{Kind: Response, Status: code, Version: string(version)}

	// The reason phrase is optional and may be empty, so its absence is not a
	// parse failure.
	rest = rest[3:]
	if len(rest) > 0 && rest[0] == ' ' {
		rest = rest[1:]
		if i := bytes.Index(rest, crlf); i >= 0 {
			m.Reason = string(rest[:i])
		} else {
			// Truncated before the line ended; take what was captured.
			m.Reason = string(rest)
		}
	}
	return m, true
}

// parseStatusCode reads exactly three digits and rejects codes outside the
// range HTTP defines, so that three arbitrary digits in binary data do not
// become a response.
func parseStatusCode(b []byte) (int, bool) {
	if len(b) != 3 {
		return 0, false
	}
	n := 0
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	if n < 100 || n > 599 {
		return 0, false
	}
	return n, true
}

// parseRequestLine reads "GET /path HTTP/1.1".
func parseRequestLine(b []byte) (Message, bool) {
	var method []byte
	for _, cand := range methods {
		if bytes.HasPrefix(b, cand) {
			method = cand[:len(cand)-1] // drop the trailing space
			break
		}
	}
	if method == nil {
		return Message{}, false
	}

	rest := b[len(method)+1:]

	// The path runs to the next space. Without one the line was truncated
	// mid-path, and the request target is unknown rather than empty.
	sp := bytes.IndexByte(rest, ' ')
	if sp <= 0 {
		return Message{}, false
	}
	path := rest[:sp]

	// The version must follow, which is what separates a real request line
	// from arbitrary text that happens to begin with a method name.
	rest = rest[sp+1:]
	var version []byte
	switch {
	case bytes.HasPrefix(rest, http11):
		version = http11
	case bytes.HasPrefix(rest, http10):
		version = http10
	default:
		return Message{}, false
	}

	return Message{
		Kind:    Request,
		Method:  string(method),
		Path:    string(path),
		Version: string(version),
		Host:    findHost(b),
	}, true
}

// findHost returns the value of the Host header if it falls within the captured
// prefix.
//
// Header names are case-insensitive, and the search stops at the end of the
// headers so that a body containing something resembling a header is not read
// as one.
func findHost(b []byte) string {
	rest := b
	for {
		i := bytes.Index(rest, crlf)
		if i < 0 {
			return "" // truncated before the header was seen
		}
		line := rest[:i]
		if len(line) == 0 {
			return "" // blank line: headers ended, Host was not present
		}
		if len(line) > len(hostKey) && asciiEqualFold(line[:len(hostKey)], hostKey) {
			return string(bytes.TrimSpace(line[len(hostKey):]))
		}
		rest = rest[i+2:]
	}
}

// asciiEqualFold compares ASCII bytes case-insensitively. Header names are
// ASCII by definition, so the general Unicode folding in strings.EqualFold is
// unnecessary here and allocates.
func asciiEqualFold(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
