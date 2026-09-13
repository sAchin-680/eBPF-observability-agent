// Package verifier records what the kernel verifier accepts and rejects when
// HTTP header parsing is attempted in kernel space.
//
// The agent parses HTTP in userspace. This test is the evidence for that
// decision: it loads each attempt at the in-kernel version and records the
// verifier's response, including the rejections. The rejections are the point.
//
// It requires root and a Linux host, and is skipped elsewhere.
package verifier

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target native -cflags "-O2 -g -Wall -Werror -I../../bpf" headers headers.bpf.c

// logDir is where the verifier's own output is written, so that the rejection
// can be read rather than described. A paraphrased verifier log is worth
// nothing: the value is in the instruction offset and the register state.
const logDir = "../../docs/verifier"

type attempt struct {
	program string
	summary string
	// accepted records what is expected of this program, so a change in
	// behaviour on another kernel shows up as a test failure rather than as a
	// quietly different log file.
	accepted bool

	// captureLog requests the verifier's own output.
	//
	// Off for the size sweep, because retrieving the log is what made it
	// unrunnable. The loader retries with a progressively larger buffer while
	// the log is truncated, and for one of these programs no buffer is ever
	// large enough: the process reached 5.3 GB resident on a 5.9 GB machine and
	// was killed by the kernel before it could report anything. Verification
	// itself completes in seconds. Only the log is unbounded.
	captureLog bool
}

var attempts = []attempt{
	{"count_headers_unbounded", "scan until the data says to stop", false, true},
	{"count_headers_runtime_bound", "scan bounded by a length from userspace", false, true},
	{"count_headers_bounded", "scan bounded by the buffer", true, true},

	// The same per-header parse at a range of sizes, to locate the boundary
	// rather than only observing that one exists. Logs are not retrieved; see
	// captureLog.
	{"parse_headers_32", "per-header parse over 32 bytes", true, false},
	{"parse_headers_64", "per-header parse over 64 bytes", false, false},
	{"parse_headers_96", "per-header parse over 96 bytes", false, false},
	{"parse_headers_128", "per-header parse over 128 bytes", false, false},
	{"parse_headers_bounded", "per-header parse over 256 bytes", false, false},
}

func TestVerifierOnInKernelHeaderParsing(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("requires root: %v", err)
	}

	spec, err := loadHeaders()
	if err != nil {
		t.Fatalf("loading compiled objects: %v", err)
	}

	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatalf("creating %s: %v", logDir, err)
	}

	for _, a := range attempts {
		t.Run(a.program, func(t *testing.T) {
			progSpec, ok := spec.Programs[a.program]
			if !ok {
				t.Fatalf("no program named %q in the compiled object", a.program)
			}

			// Each program is loaded on its own. Loading them together would
			// stop at the first rejection and say nothing about the rest.
			opts := bpf.ProgramOptions{LogDisabled: true}
			if a.captureLog {
				// LogSize was removed in cilium/ebpf v0.18: the library now
				// grows the log buffer itself and retries, which is what this
				// test used to do by hand with a fixed 1 MiB. LogSizeStart only
				// sets where that growth begins.
				opts = bpf.ProgramOptions{
					LogLevel:     bpf.LogLevelInstruction,
					LogSizeStart: 1 << 20,
				}
			}

			start := time.Now()
			prog, err := bpf.NewProgramWithOptions(progSpec, opts)

			elapsed := time.Since(start)

			var ve *bpf.VerifierError
			switch {
			case err == nil:
				defer prog.Close()
				writeLog(t, a, "accepted", verifierLog(progSpec, elapsed))
				t.Logf("accepted in %v (%d instructions)", elapsed.Round(time.Millisecond), len(progSpec.Instructions))
				if !a.accepted {
					t.Errorf("expected the verifier to reject this program, but it loaded")
				}

			case errors.As(err, &ve):
				writeLog(t, a, "rejected",
					fmt.Sprintf("verification took %v\n\n%+v", elapsed.Round(time.Millisecond), ve))
				if a.accepted {
					t.Errorf("expected the verifier to accept this program:\n%+v", ve)
				}
				t.Logf("rejected in %v, as expected: %s",
					elapsed.Round(time.Millisecond), firstLine(ve.Error()))

			default:
				t.Fatalf("loading %s failed for a reason other than verification: %v", a.program, err)
			}
		})
	}
}

// writeLog records the verifier's output for one program.
func writeLog(t *testing.T, a attempt, outcome, log string) {
	t.Helper()

	path := filepath.Join(logDir, a.program+".log")
	body := fmt.Sprintf(
		"program: %s\nattempt: %s\noutcome: %s\nkernel:  %s\n\n%s\n",
		a.program, a.summary, outcome, kernelRelease(), log)

	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Errorf("writing %s: %v", path, err)
	}
}

// verifierLog returns the log for a program that loaded successfully, where the
// interesting figure is the instruction count the verifier processed.
func verifierLog(spec *bpf.ProgramSpec, elapsed time.Duration) string {
	// Verification time is recorded because it is the signal that precedes
	// rejection: a program the verifier struggles with takes noticeably longer
	// before it is refused, and the increase is visible while it is still
	// being accepted.
	return fmt.Sprintf("accepted by the verifier\ninstructions in program: %d\nverification took: %v\n",
		len(spec.Instructions), elapsed.Round(time.Millisecond))
}

func kernelRelease() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(b))
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
