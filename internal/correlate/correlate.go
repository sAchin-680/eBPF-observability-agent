// Package correlate pairs captured request and response payloads into single
// request records.
package correlate

import (
	"time"

	"github.com/sAchin-680/ebpf-observability-agent/internal/capture"
	"github.com/sAchin-680/ebpf-observability-agent/internal/httpparse"
)

// DefaultTTL bounds how long an unanswered request is kept.
//
// Not every request produces a response event: a connection can be closed
// mid-exchange, a response can arrive split across reads in a way that leaves
// no start line in any captured prefix, and the ring buffer can drop the
// response while delivering the request. Without an upper bound those requests
// accumulate for the lifetime of the agent.
//
// The value is a compromise. Too short and slow endpoints are reported as
// timed out; too long and memory tracks the rate of unanswered requests rather
// than the number in flight.
const DefaultTTL = 30 * time.Second

// Outcome describes how a request record was completed.
type Outcome uint8

const (
	// Completed means a response was matched to the request.
	Completed Outcome = iota
	// Expired means no response arrived within the TTL. The record carries no
	// status, and reporting it as an error would be a guess: the request may
	// have succeeded unobserved.
	Expired
)

func (o Outcome) String() string {
	if o == Expired {
		return "expired"
	}
	return "completed"
}

// Record is one request and its response, reconstructed from captured payloads.
type Record struct {
	Method string
	Path   string
	Host   string

	// Status is the response status, or zero when the record expired.
	Status int
	Reason string

	// Duration between the request payload and the response payload, measured
	// from kernel monotonic timestamps.
	Duration time.Duration

	PID     uint32
	Comm    string
	Source  capture.Source
	Conn    uint64
	Outcome Outcome

	// Peer is the remote endpoint of the connection, when the socket hook
	// observed it. Empty when it did not: a connection whose first write has
	// not yet happened, an evicted entry, or a kernel where the socket probe
	// could not attach.
	Peer string
	// Local is the local endpoint, under the same conditions.
	Local string
}

// connKey scopes a connection pointer to its process.
//
// The pointer alone is not sufficient: two processes have independent address
// spaces and can hold the same address simultaneously.
type connKey struct {
	pid  uint32
	conn uint64
}

type pending struct {
	msg  httpparse.Message
	ev   capture.Event
	seen time.Duration // kernel monotonic timestamp of the request
}

// Stats counts what the correlator did, so that unmatched traffic is visible
// rather than silently absent.
type Stats struct {
	Requests           uint64
	Completed          uint64
	Expired            uint64
	ResponsesUnmatched uint64
	NotHTTP            uint64
}

// Correlator pairs requests with responses per connection.
//
// It is not safe for concurrent use; the agent drives it from a single reader.
type Correlator struct {
	ttl  time.Duration
	emit func(Record)

	// endpoints resolves a connection to its socket addresses. Optional: when
	// nil, records carry no endpoints and everything else is unaffected.
	endpoints func(pid uint32, conn uint64) (local, peer string, ok bool)

	pending map[connKey]pending
	stats   Stats

	// now is the latest kernel timestamp observed. Expiry is driven by event
	// time rather than wall-clock time so that behaviour is reproducible in
	// tests and unaffected by how long userspace took to drain the buffer.
	now time.Duration
}

// SetEndpointResolver supplies a lookup from connection to socket addresses.
func (c *Correlator) SetEndpointResolver(f func(pid uint32, conn uint64) (local, peer string, ok bool)) {
	c.endpoints = f
}

// New returns a Correlator that calls emit for each completed or expired record.
func New(ttl time.Duration, emit func(Record)) *Correlator {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Correlator{
		ttl:     ttl,
		emit:    emit,
		pending: make(map[connKey]pending),
	}
}

// Handle processes one captured payload.
func (c *Correlator) Handle(ev capture.Event) {
	if ev.Timestamp > c.now {
		c.now = ev.Timestamp
	}

	msg, ok := httpparse.Parse(ev.Data)
	if !ok {
		c.stats.NotHTTP++
		return
	}

	key := connKey{pid: ev.PID, conn: ev.Conn}

	switch msg.Kind {
	case httpparse.Request:
		c.stats.Requests++
		// A request arriving while one is already outstanding on the same
		// connection means the first will never be matched. HTTP/1.1 allows
		// pipelining, and a reused keep-alive connection whose response was
		// dropped produces the same pattern. The earlier request is reported
		// as expired rather than discarded, so the traffic is not lost.
		if prev, exists := c.pending[key]; exists {
			c.stats.Expired++
			c.emitRecord(prev, httpparse.Message{}, 0, Expired)
		}
		c.pending[key] = pending{msg: msg, ev: ev, seen: ev.Timestamp}

	case httpparse.Response:
		req, exists := c.pending[key]
		if !exists {
			// A response with no matching request: the request predates the
			// agent's attachment, or was dropped.
			c.stats.ResponsesUnmatched++
			return
		}
		delete(c.pending, key)
		c.stats.Completed++
		c.emitRecord(req, msg, ev.Timestamp-req.seen, Completed)
	}
}

// Expire reports every pending request older than the TTL.
//
// Called periodically by the agent. Expiry is by event time, so a quiet period
// with no traffic does not expire anything until the next event arrives.
func (c *Correlator) Expire() {
	for key, p := range c.pending {
		if c.now-p.seen < c.ttl {
			continue
		}
		delete(c.pending, key)
		c.stats.Expired++
		c.emitRecord(p, httpparse.Message{}, 0, Expired)
	}
}

// Pending reports how many requests are awaiting a response.
func (c *Correlator) Pending() int { return len(c.pending) }

// Stats returns a snapshot of the counters.
func (c *Correlator) Stats() Stats { return c.stats }

func (c *Correlator) emitRecord(req pending, resp httpparse.Message, d time.Duration, o Outcome) {
	if c.emit == nil {
		return
	}
	var local, peer string
	if c.endpoints != nil {
		local, peer, _ = c.endpoints(req.ev.PID, req.ev.Conn)
	}

	c.emit(Record{
		Method:   req.msg.Method,
		Path:     req.msg.Path,
		Host:     req.msg.Host,
		Status:   resp.Status,
		Reason:   resp.Reason,
		Duration: d,
		PID:      req.ev.PID,
		Comm:     req.ev.Comm,
		Source:   req.ev.Source,
		Conn:     req.ev.Conn,
		Outcome:  o,
		Local:    local,
		Peer:     peer,
	})
}
