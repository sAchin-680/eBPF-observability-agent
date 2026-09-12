package ebpf

import (
	"errors"
	"fmt"
	"log"
	"sync"

	bpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/sAchin-680/ebpf-observability-agent/internal/proc"
)

// probe describes one attachment: a symbol in the target library, the program
// to run, and whether it fires on entry or on return.
type probe struct {
	symbol string
	prog   func(*sslObjects) *bpf.Program
	onExit bool
}

// probes covers both OpenSSL APIs. Callers are split between them with nothing
// to distinguish them from outside: curl calls SSL_write and SSL_read, CPython
// calls SSL_write_ex and SSL_read_ex exclusively. Probing one pair misses the
// other's callers silently, because the unprobed symbols are still present and
// nothing reports an error.
//
// The write paths carry their payload on entry, so one probe covers each. The
// read paths fill the caller's buffer before returning and need an entry probe
// to record the destination and a return probe to read it.
var probes = []probe{
	{"SSL_write", func(o *sslObjects) *bpf.Program { return o.ProbeSslWrite }, false},
	{"SSL_write_ex", func(o *sslObjects) *bpf.Program { return o.ProbeSslWriteEx }, false},
	{"SSL_read", func(o *sslObjects) *bpf.Program { return o.ProbeSslReadEntry }, false},
	{"SSL_read", func(o *sslObjects) *bpf.Program { return o.ProbeSslReadRet }, true},
	{"SSL_read_ex", func(o *sslObjects) *bpf.Program { return o.ProbeSslReadExEntry }, false},
	{"SSL_read_ex", func(o *sslObjects) *bpf.Program { return o.ProbeSslReadExRet }, true},
}

// Tracer holds the loaded kernel programs and the probes attached to them.
type Tracer struct {
	objs     sslObjects
	gotls    *goTracer
	discover *discoverer
	sock     *sockTracer
	links    []link.Link
	attached map[string]bool

	// sharedOpts carries the map replacements that bind the separately
	// compiled programs to one set of shared maps. Nil when the socket program
	// failed to load, in which case each program uses its own maps and the
	// connection binding simply never happens.
	sharedOpts *bpf.CollectionOptions

	// received counts events read from the ring buffers. Accessed atomically
	// because the readers run concurrently with the metrics callback.
	received uint64

	// mu guards links and attached. Attachment happens both from the startup
	// scan and from the goroutines inspecting newly executed processes.
	mu sync.Mutex
}

// NewTracer loads the kernel-side programs. The verifier runs during this call:
// on rejection nothing has executed, and the program never entered the kernel.
func NewTracer() (*Tracer, error) {
	// BPF maps and programs are charged against locked memory. Kernels before
	// 5.11 apply a default limit far below what a typical program needs and
	// report the shortfall as a permission error. Later kernels account for
	// this through cgroups and ignore the limit.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("raising memlock limit: %w", err)
	}

	// The socket program is loaded first because it owns the maps the TLS
	// programs share. Its failure is not fatal: without it, records carry no
	// network endpoints, which is a smaller loss than not tracing at all.
	var opts *bpf.CollectionOptions
	sock, err := newSockTracer()
	if err != nil {
		log.Printf("socket endpoints unavailable: %v", err)
	} else {
		opts = &bpf.CollectionOptions{MapReplacements: sock.sharedMaps()}
	}

	var objs sslObjects
	if err := loadSslObjects(&objs, opts); err != nil {
		// A verifier rejection carries an instruction-level log of the register
		// state that caused it. Anything less is not diagnosable.
		var ve *bpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("verifier rejected program:\n%+v", ve)
		}
		return nil, fmt.Errorf("loading programs: %w", err)
	}

	return &Tracer{
		objs:       objs,
		sock:       sock,
		sharedOpts: opts,
		attached:   make(map[string]bool),
	}, nil
}

// AttachLibrary attaches the capture probes to one TLS library. It reports
// whether an attachment was made; a library already attached is skipped.
//
// A uprobe is placed in a file rather than in a process, so one attachment
// covers every process mapping that file, including processes started later.
// Attaching once per process instead would multiply every captured event by the
// number of processes sharing the library.
//
// A symbol that is absent is skipped rather than treated as fatal. Builds
// differ in which entry points they export, and refusing to trace a library
// over one missing symbol would discard the ones it does export. An attachment
// that yields no probes at all is an error, since that library cannot be
// traced.
func (t *Tracer) AttachLibrary(lib proc.Library) (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.attachLibraryLocked(lib)
}

// attachLibraryLocked is AttachLibrary without locking. The caller must hold mu.
func (t *Tracer) attachLibraryLocked(lib proc.Library) (bool, error) {
	if t.attached[lib.Key] {
		return false, nil
	}
	t.attached[lib.Key] = true

	ex, err := link.OpenExecutable(lib.HostPath)
	if err != nil {
		return false, fmt.Errorf("opening %s: %w", lib.HostPath, err)
	}

	var n int
	for _, p := range probes {
		var l link.Link
		var err error
		if p.onExit {
			l, err = ex.Uretprobe(p.symbol, p.prog(&t.objs), nil)
		} else {
			l, err = ex.Uprobe(p.symbol, p.prog(&t.objs), nil)
		}
		if err != nil {
			log.Printf("skipping %s in %s: %v", p.symbol, lib.Path, err)
			continue
		}
		t.links = append(t.links, l)
		n++
	}

	if n == 0 {
		return false, fmt.Errorf("no probes attached to %s", lib.Path)
	}
	return true, nil
}

// attachPID attaches to whatever TLS implementation one process uses, and
// returns how many new targets were attached.
//
// Both the library and the Go path are attempted: they are not alternatives. A
// Go binary can link OpenSSL for purposes other than its own HTTP client, and a
// process can load libssl at any point rather than only at startup.
//
// The caller must hold mu.
func (t *Tracer) attachPID(pid int, comm string) (int, error) {
	var n int

	libs, err := proc.TLSLibrariesForPID(pid)
	if err == nil {
		for _, lib := range libs {
			ok, err := t.attachLibraryLocked(lib)
			if err != nil {
				log.Printf("attach failed for %s: %v", lib.Path, err)
				continue
			}
			if ok {
				log.Printf("attached %s (pid %d, %s)", lib.Path, pid, comm)
				n++
			}
		}
	}

	if target, err := proc.GoTLSTargetForPID(pid); err == nil && target != nil {
		ok, err := t.attachGoLocked(*target)
		if err != nil {
			log.Printf("attach failed for %s: %v", target.Path, err)
		} else if ok {
			log.Printf("attached %s (pid %d, %s, go, %d return sites)",
				target.Path, pid, comm, len(target.ReadReturnOffsets))
			n++
		}
	}

	return n, nil
}

// AttachAll discovers every TLS library currently mapped on the host and
// attaches to each distinct one. It returns the number of libraries attached.
func (t *Tracer) AttachAll() (int, error) {
	libs, err := proc.FindTLSLibraries()
	if err != nil {
		return 0, fmt.Errorf("discovering TLS libraries: %w", err)
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	var n int
	for _, lib := range libs {
		ok, err := t.attachLibraryLocked(lib)
		if err != nil {
			log.Printf("attach failed for %s: %v", lib.Path, err)
			continue
		}
		if ok {
			log.Printf("attached %s (pid %d, %s)", lib.Path, lib.PID, lib.Key)
			n++
		}
	}
	return n, nil
}

// Close detaches every probe and releases the loaded programs.
//
// Probe lifetime is bound to these file descriptors. If the agent exits without
// calling Close, including on a crash, the kernel releases them and detaches the
// probes, leaving traced processes running as before.
//
// Probes are not detached when a traced process exits. The probe belongs to the
// library file, and other processes may still be using it; detaching on process
// exit would stop tracing everything else sharing that library.
func (t *Tracer) Close() error {
	var firstErr error
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, l := range t.links {
		if err := l.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if t.discover != nil {
		if err := t.discover.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if t.sock != nil {
		if err := t.sock.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := t.objs.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	if t.gotls != nil {
		if err := t.gotls.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
