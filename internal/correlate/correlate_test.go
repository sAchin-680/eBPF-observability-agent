package correlate

import (
	"testing"
	"time"

	"github.com/sAchin-680/ebpf-observability-agent/internal/capture"
)

func req(pid uint32, conn uint64, at time.Duration, path string) capture.Event {
	return capture.Event{
		PID: pid, Conn: conn, Timestamp: at, Comm: "svc",
		Direction: capture.Egress,
		Data:      []byte("GET " + path + " HTTP/1.1\r\nHost: svc.internal\r\n\r\n"),
	}
}

func resp(pid uint32, conn uint64, at time.Duration, line string) capture.Event {
	return capture.Event{
		PID: pid, Conn: conn, Timestamp: at, Comm: "svc",
		Direction: capture.Ingress,
		Data:      []byte("HTTP/1.1 " + line + "\r\n\r\n"),
	}
}

func collect() (*Correlator, *[]Record) {
	var got []Record
	c := New(DefaultTTL, func(r Record) { got = append(got, r) })
	return c, &got
}

func TestPairsRequestWithResponse(t *testing.T) {
	c, got := collect()
	c.Handle(req(10, 0xaaaa, 1000, "/users"))
	c.Handle(resp(10, 0xaaaa, 1_500_000, "200 OK"))

	if len(*got) != 1 {
		t.Fatalf("got %d records, want 1", len(*got))
	}
	r := (*got)[0]
	if r.Method != "GET" || r.Path != "/users" || r.Status != 200 {
		t.Errorf("got %s %s %d, want GET /users 200", r.Method, r.Path, r.Status)
	}
	if r.Host != "svc.internal" {
		t.Errorf("host = %q", r.Host)
	}
	if r.Duration != 1_499_000*time.Nanosecond {
		t.Errorf("duration = %v, want 1.499ms", r.Duration)
	}
	if r.Outcome != Completed {
		t.Errorf("outcome = %v, want completed", r.Outcome)
	}
	if c.Pending() != 0 {
		t.Errorf("pending = %d, want 0", c.Pending())
	}
}

// TestInterleavedConnections is the case a thread-keyed or process-keyed
// correlator gets wrong. Two connections in one process exchange messages out
// of order, which is the normal behaviour of any concurrent server.
func TestInterleavedConnections(t *testing.T) {
	c, got := collect()
	c.Handle(req(10, 0xaaaa, 1000, "/a"))
	c.Handle(req(10, 0xbbbb, 2000, "/b"))
	c.Handle(resp(10, 0xbbbb, 3000, "500 Internal Server Error")) // second finishes first
	c.Handle(resp(10, 0xaaaa, 4000, "200 OK"))

	if len(*got) != 2 {
		t.Fatalf("got %d records, want 2", len(*got))
	}
	if (*got)[0].Path != "/b" || (*got)[0].Status != 500 {
		t.Errorf("first record = %s %d, want /b 500", (*got)[0].Path, (*got)[0].Status)
	}
	if (*got)[1].Path != "/a" || (*got)[1].Status != 200 {
		t.Errorf("second record = %s %d, want /a 200", (*got)[1].Path, (*got)[1].Status)
	}
}

// TestSameConnAddressInDifferentProcesses covers address reuse across address
// spaces: two processes can hold the same pointer value at the same time.
func TestSameConnAddressInDifferentProcesses(t *testing.T) {
	c, got := collect()
	c.Handle(req(10, 0xcccc, 1000, "/from-pid-10"))
	c.Handle(req(11, 0xcccc, 1100, "/from-pid-11"))
	c.Handle(resp(11, 0xcccc, 2000, "404 Not Found"))
	c.Handle(resp(10, 0xcccc, 2100, "200 OK"))

	if len(*got) != 2 {
		t.Fatalf("got %d records, want 2", len(*got))
	}
	for _, r := range *got {
		switch r.PID {
		case 10:
			if r.Path != "/from-pid-10" || r.Status != 200 {
				t.Errorf("pid 10 got %s %d", r.Path, r.Status)
			}
		case 11:
			if r.Path != "/from-pid-11" || r.Status != 404 {
				t.Errorf("pid 11 got %s %d", r.Path, r.Status)
			}
		}
	}
}

// TestKeepAliveReuse covers sequential requests on one connection, which is the
// default for HTTP/1.1.
func TestKeepAliveReuse(t *testing.T) {
	c, got := collect()
	for i, path := range []string{"/one", "/two", "/three"} {
		at := time.Duration(i*1000 + 1000)
		c.Handle(req(10, 0xdddd, at, path))
		c.Handle(resp(10, 0xdddd, at+500, "200 OK"))
	}
	if len(*got) != 3 {
		t.Fatalf("got %d records, want 3", len(*got))
	}
	for i, want := range []string{"/one", "/two", "/three"} {
		if (*got)[i].Path != want {
			t.Errorf("record %d = %s, want %s", i, (*got)[i].Path, want)
		}
	}
}

// TestUnansweredRequestExpires covers the observed case of more requests than
// responses. Without expiry these entries would accumulate for the agent's
// lifetime.
func TestUnansweredRequestExpires(t *testing.T) {
	c, got := collect()
	c.Handle(req(10, 0xeeee, 1000, "/never-answered"))
	if c.Pending() != 1 {
		t.Fatalf("pending = %d, want 1", c.Pending())
	}

	// Advance event time past the TTL with unrelated traffic.
	later := time.Duration(DefaultTTL) + 2000
	c.Handle(req(99, 0xffff, later, "/other"))
	c.Expire()

	if c.Pending() != 1 {
		t.Errorf("pending = %d, want 1 (only /other should remain)", c.Pending())
	}
	if len(*got) != 1 {
		t.Fatalf("got %d records, want 1", len(*got))
	}
	r := (*got)[0]
	if r.Path != "/never-answered" || r.Outcome != Expired {
		t.Errorf("got %s %v, want /never-answered expired", r.Path, r.Outcome)
	}
	// An expired record must not claim a status. The request may well have
	// succeeded without the response being captured.
	if r.Status != 0 {
		t.Errorf("expired record has status %d, want 0", r.Status)
	}
}

// TestPipelinedRequestExpiresPrevious covers a second request arriving on a
// connection whose first is still outstanding.
func TestPipelinedRequestExpiresPrevious(t *testing.T) {
	c, got := collect()
	c.Handle(req(10, 0x1111, 1000, "/first"))
	c.Handle(req(10, 0x1111, 2000, "/second"))
	c.Handle(resp(10, 0x1111, 3000, "200 OK"))

	if len(*got) != 2 {
		t.Fatalf("got %d records, want 2", len(*got))
	}
	if (*got)[0].Path != "/first" || (*got)[0].Outcome != Expired {
		t.Errorf("first = %s %v, want /first expired", (*got)[0].Path, (*got)[0].Outcome)
	}
	if (*got)[1].Path != "/second" || (*got)[1].Status != 200 {
		t.Errorf("second = %s %d, want /second 200", (*got)[1].Path, (*got)[1].Status)
	}
}

func TestResponseWithoutRequestIsCounted(t *testing.T) {
	c, got := collect()
	// The agent attached mid-connection, so the request was never seen.
	c.Handle(resp(10, 0x2222, 1000, "200 OK"))

	if len(*got) != 0 {
		t.Errorf("got %d records, want 0", len(*got))
	}
	if c.Stats().ResponsesUnmatched != 1 {
		t.Errorf("unmatched responses = %d, want 1", c.Stats().ResponsesUnmatched)
	}
}

func TestNonHTTPIsIgnored(t *testing.T) {
	c, got := collect()
	// A TLS record header, roughly half of all captured ingress events.
	c.Handle(capture.Event{PID: 10, Conn: 0x3333, Timestamp: 1000,
		Data: []byte{0x17, 0x03, 0x03, 0x02, 0x9b}})

	if len(*got) != 0 || c.Pending() != 0 {
		t.Errorf("non-HTTP produced %d records and %d pending", len(*got), c.Pending())
	}
	if c.Stats().NotHTTP != 1 {
		t.Errorf("notHTTP = %d, want 1", c.Stats().NotHTTP)
	}
}

func TestStats(t *testing.T) {
	c, _ := collect()
	c.Handle(req(10, 0x1, 1000, "/a"))
	c.Handle(resp(10, 0x1, 2000, "200 OK"))
	c.Handle(req(10, 0x2, 3000, "/b"))
	c.Handle(resp(10, 0x9, 4000, "200 OK")) // no matching request

	s := c.Stats()
	if s.Requests != 2 || s.Completed != 1 || s.ResponsesUnmatched != 1 {
		t.Errorf("stats = %+v", s)
	}
}
