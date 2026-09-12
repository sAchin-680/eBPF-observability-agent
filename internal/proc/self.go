package proc

import (
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

// Self-exclusion.
//
// The agent is itself a Go program that uses crypto/tls, to ship telemetry. It
// therefore matches its own discovery criteria exactly, and without an
// exclusion it attaches probes to itself.
//
// The result is a feedback loop rather than a cosmetic problem. Every export
// the agent performs is a TLS write, which fires the agent's own probes, which
// produces events, which the agent exports — each export generating more
// exports. The loop is self-amplifying and the agent does not survive it.
//
// Exclusion is by file identity rather than by process id, because the agent
// may have more than one process (a re-exec, a child) and because a pid says
// nothing about what is running under it.

var (
	selfOnce sync.Once
	selfKey  string
)

// selfFileKey returns the device and inode of the running agent's executable.
func selfFileKey() string {
	selfOnce.Do(func() {
		fi, err := os.Stat("/proc/self/exe")
		if err != nil {
			return
		}
		if key, ok := fileKey(fi); ok {
			selfKey = key
		}
	})
	return selfKey
}

// IsSelf reports whether a process is running the agent's own executable.
func IsSelf(pid int) bool {
	if pid == os.Getpid() {
		return true
	}

	self := selfFileKey()
	if self == "" {
		// Identity could not be established, so exclusion cannot be applied.
		// Falling back to the pid check alone is the safe direction: tracing
		// one process too few is a gap, tracing the agent is a loop.
		return false
	}

	fi, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return false
	}
	key, ok := fileKey(fi)
	return ok && key == self
}
