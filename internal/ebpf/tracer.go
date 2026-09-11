package ebpf

import (
	"errors"
	"fmt"
	"os"

	bpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// libsslSearchPaths lists where OpenSSL 3 is installed by the common
// distributions. Debian and Ubuntu use multiarch directories, RHEL and its
// derivatives use lib64.
//
// This is a starting point, not the final approach: a process can load a
// private copy of libssl from anywhere, so per-process resolution has to read
// the loaded object list from /proc rather than searching the host.
var libsslSearchPaths = []string{
	"/usr/lib/aarch64-linux-gnu/libssl.so.3",
	"/usr/lib/x86_64-linux-gnu/libssl.so.3",
	"/usr/lib64/libssl.so.3",
	"/lib/aarch64-linux-gnu/libssl.so.3",
	"/lib/x86_64-linux-gnu/libssl.so.3",
}

// FindLibSSL returns the path to the host's OpenSSL 3 shared library. The
// LIBSSL_PATH environment variable overrides the search.
func FindLibSSL() (string, error) {
	if p := os.Getenv("LIBSSL_PATH"); p != "" {
		return p, nil
	}
	for _, p := range libsslSearchPaths {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", errors.New("libssl.so.3 not found; set LIBSSL_PATH to override")
}

// Tracer holds the loaded kernel programs and the probes attached to them.
type Tracer struct {
	objs  sslObjects
	links []link.Link
}

// NewTracer loads the kernel-side programs. The verifier runs during this
// call: on rejection nothing has executed, and the program never entered the
// kernel.
func NewTracer() (*Tracer, error) {
	// BPF maps and programs are charged against locked memory. Kernels before
	// 5.11 apply a default limit far below what a typical program needs, and
	// report the shortfall as a permission error. Later kernels account for
	// this through cgroups and ignore the limit.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("raising memlock limit: %w", err)
	}

	var objs sslObjects
	if err := loadSslObjects(&objs, nil); err != nil {
		// A verifier rejection carries an instruction-level log of the
		// register state that caused it. Anything less is not diagnosable.
		var ve *bpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("verifier rejected program:\n%+v", ve)
		}
		return nil, fmt.Errorf("loading programs: %w", err)
	}

	return &Tracer{objs: objs}, nil
}

// AttachOpenSSL attaches the capture probes to the OpenSSL library at path.
//
// The probes are attached to the library file, so they fire for every process
// that has it mapped, including processes started after attachment. That is
// what makes the agent independent of the traced application's lifecycle.
func (t *Tracer) AttachOpenSSL(path string) error {
	ex, err := link.OpenExecutable(path)
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}

	// Both OpenSSL APIs are probed. Callers are split between them with no
	// way to tell from the outside: curl calls SSL_write and SSL_read,
	// CPython calls SSL_write_ex and SSL_read_ex exclusively. Probing one
	// pair misses the other's callers silently, since the unprobed symbols
	// are still present in the library and nothing reports an error.
	//
	// The write paths carry their payload on entry, so a single probe covers
	// each. The read paths fill the caller's buffer before returning and need
	// an entry probe to record the destination and a return probe to read it.
	for _, p := range []struct {
		symbol string
		prog   *bpf.Program
		ret    bool
	}{
		{"SSL_write", t.objs.ProbeSslWrite, false},
		{"SSL_write_ex", t.objs.ProbeSslWriteEx, false},
		{"SSL_read", t.objs.ProbeSslReadEntry, false},
		{"SSL_read", t.objs.ProbeSslReadRet, true},
		{"SSL_read_ex", t.objs.ProbeSslReadExEntry, false},
		{"SSL_read_ex", t.objs.ProbeSslReadExRet, true},
	} {
		var l link.Link
		var err error
		if p.ret {
			l, err = ex.Uretprobe(p.symbol, p.prog, nil)
		} else {
			l, err = ex.Uprobe(p.symbol, p.prog, nil)
		}
		if err != nil {
			return fmt.Errorf("attaching to %s: %w", p.symbol, err)
		}
		t.links = append(t.links, l)
	}

	return nil
}

// Close detaches every probe and releases the loaded programs.
//
// Probe lifetime is bound to these file descriptors. If the agent exits
// without calling Close, including on a crash, the kernel releases them and
// detaches the probes, leaving the traced process running as before.
func (t *Tracer) Close() error {
	var firstErr error
	for _, l := range t.links {
		if err := l.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := t.objs.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}
