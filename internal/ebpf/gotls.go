package ebpf

import (
	"errors"
	"fmt"
	"log"

	bpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/sAchin-680/ebpf-observability-agent/internal/proc"
)

// goTracer holds the Go TLS programs. They are loaded separately from the
// OpenSSL programs so that a host with no Go processes carries none of their
// cost, and so that a failure in one path does not prevent the other loading.
type goTracer struct {
	objs gotlsObjects
}

func newGoTracer(opts *bpf.CollectionOptions) (*goTracer, error) {
	var objs gotlsObjects
	if err := loadGotlsObjects(&objs, opts); err != nil {
		var ve *bpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("verifier rejected Go programs:\n%+v", ve)
		}
		return nil, fmt.Errorf("loading Go programs: %w", err)
	}
	return &goTracer{objs: objs}, nil
}

// attach probes one Go executable and returns the links it created.
//
// Every Go binary carries its own copy of crypto/tls at its own addresses, so
// unlike a shared library there is no single file that covers many processes:
// each distinct executable needs its own attachment.
func (g *goTracer) attach(t proc.GoTLSTarget) ([]link.Link, error) {
	ex, err := link.OpenExecutable(t.HostPath)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", t.HostPath, err)
	}

	var links []link.Link
	fail := func(err error) ([]link.Link, error) {
		for _, l := range links {
			l.Close()
		}
		return nil, err
	}

	w, err := ex.Uprobe(proc.GoTLSWriteSymbol, g.objs.ProbeGoTlsWrite, nil)
	if err != nil {
		return fail(fmt.Errorf("attaching to %s: %w", proc.GoTLSWriteSymbol, err))
	}
	links = append(links, w)

	r, err := ex.Uprobe(proc.GoTLSReadSymbol, g.objs.ProbeGoTlsReadEntry, nil)
	if err != nil {
		return fail(fmt.Errorf("attaching to %s: %w", proc.GoTLSReadSymbol, err))
	}
	links = append(links, r)

	// One probe per return instruction. Offset is measured from the symbol's
	// own address, so the loader resolves the symbol and adds the delta; no
	// file offset is computed here.
	for _, off := range t.ReadReturnOffsets {
		l, err := ex.Uprobe(proc.GoTLSReadSymbol, g.objs.ProbeGoTlsReadReturn,
			&link.UprobeOptions{Offset: off})
		if err != nil {
			return fail(fmt.Errorf("attaching to %s+%#x: %w", proc.GoTLSReadSymbol, off, err))
		}
		links = append(links, l)
	}

	return links, nil
}

func (g *goTracer) Close() error {
	return g.objs.Close()
}

// AttachGoBinaries discovers Go executables using crypto/tls and attaches to
// each distinct one. It returns the number newly attached.
func (t *Tracer) AttachGoBinaries() (int, error) {
	targets, err := proc.FindGoTLSTargets()
	if err != nil {
		return 0, fmt.Errorf("discovering Go binaries: %w", err)
	}
	if len(targets) == 0 {
		return 0, nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	var n int
	for _, target := range targets {
		ok, err := t.attachGoLocked(target)
		if err != nil {
			log.Printf("attach failed for %s: %v", target.Path, err)
			continue
		}
		if ok {
			log.Printf("attached %s (pid %d, go, %d return sites)",
				target.Path, target.PID, len(target.ReadReturnOffsets))
			n++
		}
	}
	return n, nil
}

// attachGoLocked attaches to one Go executable. The caller must hold mu.
//
// The Go programs are loaded on first use so that a host running no Go binaries
// carries none of their cost.
func (t *Tracer) attachGoLocked(target proc.GoTLSTarget) (bool, error) {
	if t.attached[target.Key] {
		return false, nil
	}

	if t.gotls == nil {
		gt, err := newGoTracer(t.sharedOpts)
		if err != nil {
			return false, err
		}
		t.gotls = gt
	}

	links, err := t.gotls.attach(target)
	if err != nil {
		return false, err
	}
	t.attached[target.Key] = true
	t.links = append(t.links, links...)
	return true, nil
}
