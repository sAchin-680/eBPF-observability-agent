package ebpf

import (
	"errors"
	"fmt"
	"net/netip"

	bpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Tuple is the socket endpoint pair a connection travelled between.
type Tuple struct {
	Source      netip.AddrPort
	Destination netip.AddrPort
}

// connKey mirrors struct conn_key in bpf/conn.h.
type connKey struct {
	PID  uint32
	_    uint32
	Conn uint64
}

// connTuple mirrors struct conn_tuple in bpf/conn.h. Addresses are sixteen raw
// bytes in network order, with IPv4 occupying the first four; ports are host
// order.
type connTuple struct {
	SAddr  [16]byte
	DAddr  [16]byte
	SPort  uint16
	DPort  uint16
	Family uint16
	_      uint16
}

// sockTracer holds the socket program and the maps it shares with the TLS
// programs.
type sockTracer struct {
	objs sockObjects
	link link.Link
}

// newSockTracer loads the socket program and attaches it.
//
// Attachment can fail on a kernel where the probed function has been renamed or
// inlined, since it is an internal symbol with no stability guarantee. That is
// reported to the caller and treated as a degradation rather than a fatal
// error: records are still produced, without network endpoints.
func newSockTracer() (*sockTracer, error) {
	var objs sockObjects
	if err := loadSockObjects(&objs, nil); err != nil {
		var ve *bpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("verifier rejected socket program:\n%+v", ve)
		}
		return nil, fmt.Errorf("loading socket program: %w", err)
	}

	kp, err := link.Kprobe("tcp_sendmsg", objs.ProbeTcpSendmsg, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attaching kprobe to tcp_sendmsg: %w", err)
	}

	return &sockTracer{objs: objs, link: kp}, nil
}

// sharedMaps returns the maps the TLS programs must use instead of creating
// their own.
//
// The programs are compiled separately, so each declares its own copy of these
// maps and would otherwise get its own instance at load time. Passing the
// socket program's instances as replacements makes all of them operate on the
// same kernel maps, which is what lets a TLS probe record a connection that the
// socket probe then reads.
func (s *sockTracer) sharedMaps() map[string]*bpf.Map {
	return map[string]*bpf.Map{
		"active_conn": s.objs.ActiveConn,
		"conn_tuples": s.objs.ConnTuples,
	}
}

// Lookup returns the endpoints recorded for a connection, if any.
//
// A missing entry is not an error. It means no send has yet been observed for
// that connection: a response read before the first write, a connection whose
// entry has been evicted, or a kernel where the socket probe failed to attach.
func (s *sockTracer) Lookup(pid uint32, conn uint64) (Tuple, bool) {
	var raw connTuple
	key := connKey{PID: pid, Conn: conn}
	if err := s.objs.ConnTuples.Lookup(&key, &raw); err != nil {
		return Tuple{}, false
	}
	return Tuple{
		Source:      addrPort(raw.Family, raw.SAddr, raw.SPort),
		Destination: addrPort(raw.Family, raw.DAddr, raw.DPort),
	}, true
}

func (s *sockTracer) Close() error {
	if s.link != nil {
		s.link.Close()
	}
	return s.objs.Close()
}

// Address families, as the kernel numbers them.
const (
	afInet  = 2
	afInet6 = 10
)

// addrPort converts a kernel address to a netip.AddrPort.
//
// The bytes are already in network order, which is the order netip expects, so
// they are used directly. An IPv4-mapped IPv6 address is unmapped, so that a
// v4 client reaching a dual-stack listener is reported as 127.0.0.1 rather than
// ::ffff:127.0.0.1.
func addrPort(family uint16, addr [16]byte, port uint16) netip.AddrPort {
	if family == afInet {
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(addr[:4])), port)
	}
	return netip.AddrPortFrom(netip.AddrFrom16(addr).Unmap(), port)
}

// LookupTuple returns the socket endpoints recorded for a connection.
func (t *Tracer) LookupTuple(pid uint32, conn uint64) (Tuple, bool) {
	if t.sock == nil {
		return Tuple{}, false
	}
	return t.sock.Lookup(pid, conn)
}
