package httpparse

import (
	"strings"
	"testing"
)

func TestParseRequestLine(t *testing.T) {
	cases := []struct {
		name          string
		in            string
		method, path  string
		version, host string
	}{
		{
			// The exact bytes captured from curl on this host.
			name: "curl", in: "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n",
			method: "GET", path: "/", version: "HTTP/1.1", host: "example.com",
		},
		{
			name: "path with query", in: "GET /api/v1/users?id=42&sort=name HTTP/1.1\r\nHost: api.internal\r\n\r\n",
			method: "GET", path: "/api/v1/users?id=42&sort=name", version: "HTTP/1.1", host: "api.internal",
		},
		{
			name: "post", in: "POST /submit HTTP/1.1\r\nHost: x.io\r\nContent-Length: 4\r\n\r\nbody",
			method: "POST", path: "/submit", version: "HTTP/1.1", host: "x.io",
		},
		{
			name: "http/1.0 without host", in: "GET /old HTTP/1.0\r\n\r\n",
			method: "GET", path: "/old", version: "HTTP/1.0", host: "",
		},
		{
			// Header names are case-insensitive.
			name: "lowercase host header", in: "GET / HTTP/1.1\r\nhost: lower.example\r\n\r\n",
			method: "GET", path: "/", version: "HTTP/1.1", host: "lower.example",
		},
		{
			name: "connect", in: "CONNECT proxy.internal:443 HTTP/1.1\r\nHost: proxy.internal:443\r\n\r\n",
			method: "CONNECT", path: "proxy.internal:443", version: "HTTP/1.1", host: "proxy.internal:443",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, ok := Parse([]byte(c.in))
			if !ok || m.Kind != Request {
				t.Fatalf("Parse(%q) = %v, %v; want a request", c.in, m.Kind, ok)
			}
			if m.Method != c.method || m.Path != c.path || m.Version != c.version {
				t.Errorf("got %s %s %s, want %s %s %s", m.Method, m.Path, m.Version, c.method, c.path, c.version)
			}
			if m.Host != c.host {
				t.Errorf("host = %q, want %q", m.Host, c.host)
			}
		})
	}
}

func TestParseStatusLine(t *testing.T) {
	cases := []struct {
		in     string
		status int
		reason string
	}{
		{"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n", 200, "OK"},
		{"HTTP/1.1 404 Not Found\r\n\r\n", 404, "Not Found"},
		{"HTTP/1.1 500 Internal Server Error\r\n\r\n", 500, "Internal Server Error"},
		{"HTTP/1.0 301 Moved Permanently\r\n\r\n", 301, "Moved Permanently"},
		{"HTTP/1.1 204 No Content\r\n\r\n", 204, "No Content"},
		// The reason phrase is optional.
		{"HTTP/1.1 200 \r\n\r\n", 200, ""},
		{"HTTP/1.1 200\r\n\r\n", 200, ""},
	}

	for _, c := range cases {
		m, ok := Parse([]byte(c.in))
		if !ok || m.Kind != Response {
			t.Errorf("Parse(%q) = %v, %v; want a response", c.in, m.Kind, ok)
			continue
		}
		if m.Status != c.status || m.Reason != c.reason {
			t.Errorf("got %d %q, want %d %q", m.Status, m.Reason, c.status, c.reason)
		}
	}
}

// TestRejectsHTTP2Preface guards the case that actually occurred during
// development. curl and Go both negotiate HTTP/2 over ALPN by default, and the
// first payload on such a connection is this preface. It parses cleanly as a
// request line, so without an explicit rejection every HTTP/2 connection is
// reported as an HTTP/1.1 request to "*".
func TestRejectsHTTP2Preface(t *testing.T) {
	const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	if m, ok := Parse([]byte(preface)); ok {
		t.Errorf("HTTP/2 preface parsed as %v %s %s; want rejection", m.Kind, m.Method, m.Path)
	}
}

func TestRejectsNonHTTP(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		// A TLS record header, which both OpenSSL and Go read in a call of its
		// own. These are roughly half of all captured ingress events.
		{"tls record header", []byte{0x17, 0x03, 0x03, 0x02, 0x9b}},
		{"empty", nil},
		{"binary", []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0x80, 0x7f, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55}},
		{"html body continuation", []byte("<!doctype html><html lang=\"en\"><head><title>Example</title>")},
		// Begins with a method name but has no version, so it is not a request
		// line. Response bodies contain text like this routinely.
		{"prose starting with a method", []byte("GET the latest release from our downloads page")},
		{"method without path", []byte("GET  HTTP/1.1\r\n\r\n")},
		{"unknown version", []byte("GET / HTTP/3.0\r\n\r\n")},
		{"lowercase method", []byte("get / HTTP/1.1\r\n\r\n")},
		{"status code out of range", []byte("HTTP/1.1 999 Nope\r\n\r\n")},
		{"non-numeric status", []byte("HTTP/1.1 2O0 OK\r\n\r\n")},
		{"version only", []byte("HTTP/1.1")},
		{"truncated status line", []byte("HTTP/1.1 2")},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if m, ok := Parse(c.in); ok {
				t.Errorf("parsed as %v (%s %s %d); want rejection", m.Kind, m.Method, m.Path, m.Status)
			}
		})
	}
}

// TestTruncatedAtCaptureLimit covers the normal case rather than an edge case:
// captured payloads are a fixed-size prefix, so headers are cut off whenever a
// request carries more than the capture limit.
func TestTruncatedAtCaptureLimit(t *testing.T) {
	// A request line that survives truncation, with headers that do not.
	long := "GET /health HTTP/1.1\r\nHost: svc.internal\r\nCookie: " + strings.Repeat("a", 300)
	m, ok := Parse([]byte(long[:256]))
	if !ok || m.Kind != Request {
		t.Fatalf("a truncated request should still yield its request line")
	}
	if m.Method != "GET" || m.Path != "/health" {
		t.Errorf("got %s %s, want GET /health", m.Method, m.Path)
	}
	if m.Host != "svc.internal" {
		t.Errorf("host = %q, want svc.internal", m.Host)
	}

	// Truncated before the Host header arrives: the host is unknown, which is
	// reported as empty rather than guessed.
	short := "GET /health HTTP/1.1\r\nX-Request-Id: " + strings.Repeat("b", 40)
	m, ok = Parse([]byte(short))
	if !ok {
		t.Fatal("request line should still parse")
	}
	if m.Host != "" {
		t.Errorf("host = %q, want empty when truncated before Host", m.Host)
	}
}

// TestHostNotReadFromBody ensures the header scan stops at the blank line, so
// that a body containing something shaped like a header is not mistaken for one.
func TestHostNotReadFromBody(t *testing.T) {
	in := "POST /upload HTTP/1.1\r\nContent-Length: 20\r\n\r\nHost: attacker.example\r\n"
	m, ok := Parse([]byte(in))
	if !ok {
		t.Fatal("expected a request")
	}
	if m.Host != "" {
		t.Errorf("host = %q, want empty; it was read from the body", m.Host)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"))
	f.Add([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	f.Add([]byte{0x17, 0x03, 0x03, 0x02, 0x9b})
	f.Add([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))

	// The parser reads attacker-influenced bytes out of another process, so it
	// must not panic on any input.
	f.Fuzz(func(t *testing.T, b []byte) {
		m, ok := Parse(b)
		if !ok {
			return
		}
		switch m.Kind {
		case Request:
			if m.Method == "" || m.Path == "" {
				t.Errorf("request with empty method or path: %+v", m)
			}
		case Response:
			if m.Status < 100 || m.Status > 599 {
				t.Errorf("status out of range: %d", m.Status)
			}
		default:
			t.Errorf("ok with kind %v", m.Kind)
		}
	})
}
