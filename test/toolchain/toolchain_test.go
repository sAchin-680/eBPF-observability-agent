package toolchain

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// TestBuildPipeline asserts that the compiled BPF object loads into the
// running kernel and that its CO-RE relocations resolve. It requires root and
// a Linux host; it is skipped elsewhere so `go test ./...` stays usable on a
// development machine.
//
// This test is the gate for the kernel version matrix in CI: a failure means
// the toolchain or kernel cannot support the agent, independent of any agent
// logic.
func TestBuildPipeline(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise RLIMIT_MEMLOCK, test requires root: %v", err)
	}

	var objs smokeObjects
	if err := loadSmokeObjects(&objs, nil); err != nil {
		// The verifier's rejection log carries the instruction-level register
		// state that explains the failure. Surfacing it verbatim is the
		// difference between a diagnosable CI failure and a mystery.
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier rejected program:\n%+v", ve)
		}
		t.Fatalf("loading BPF objects: %v", err)
	}
	defer objs.Close()

	// Attaching proves the program is valid for its declared hook, not merely
	// that it passed verification.
	tp, err := link.Tracepoint("sched", "sched_process_exec", objs.ToolchainSmoke, nil)
	if err != nil {
		t.Fatalf("attaching tracepoint: %v", err)
	}
	defer tp.Close()

	// Reading the map confirms it was created in the kernel and that the
	// generated binding resolves to it.
	var key, tgid uint32
	if err := objs.SmokeResult.Lookup(&key, &tgid); err != nil {
		t.Fatalf("reading smoke_result map: %v", err)
	}
}
