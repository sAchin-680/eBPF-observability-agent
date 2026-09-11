package proc

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// tlsLibraryNames matches the shared libraries whose TLS entry points the agent
// probes.
//
// Matching on the library name is deliberate rather than matching on a fixed
// path: the same library is installed at different locations by different
// distributions, shipped privately by some applications, and mounted at
// arbitrary paths inside containers.
//
// This finds only dynamically linked OpenSSL. A binary with OpenSSL compiled in
// statically has no libssl mapping at all and needs its own symbol resolution
// against the executable, as Go does.
var tlsLibraryNames = []string{"libssl.so"}

// Library is a TLS library currently mapped by at least one process.
type Library struct {
	// Key identifies the file. Probes attach to files, not processes, so this
	// is the unit of attachment.
	Key string

	// Path is the library's path within the mount namespace of the process
	// that mapped it. Used for reporting; it may not exist on the host.
	Path string

	// HostPath reaches the same file from the agent's own namespace, through
	// the /proc entry of a process that has it mapped. It is what the agent
	// opens.
	HostPath string

	// PID is one process that maps this library. HostPath depends on this
	// process still existing.
	PID int
}

// FindTLSLibraries scans every visible process and returns the TLS libraries
// they have loaded, one entry per distinct file.
//
// Deduplication matters: a uprobe is placed in a file, so a library mapped by
// fifty processes needs one attachment. Attaching per process would multiply
// every captured event by the number of processes sharing the library.
//
// Processes that vanish mid-scan are skipped rather than treated as errors;
// on a busy host that is a normal occurrence, not a fault.
func FindTLSLibraries() ([]Library, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	var libs []Library

	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a process directory
		}

		f, err := os.Open(filepath.Join("/proc", e.Name(), "maps"))
		if err != nil {
			continue // exited, or not permitted
		}
		mappings, err := ParseMaps(f)
		f.Close()
		if err != nil {
			continue
		}

		for _, m := range mappings {
			if !isTLSLibrary(m.Path) {
				continue
			}
			if _, dup := seen[m.Key()]; dup {
				continue
			}

			// The path from maps is resolved inside the process's own mount
			// namespace. For a containerised process it names a file in the
			// container image, which either does not exist on the host or is a
			// different build with different symbol offsets. Going through
			// /proc/<pid>/root reaches the file the process actually mapped.
			hostPath := filepath.Join("/proc", e.Name(), "root", m.Path)
			if _, err := os.Stat(hostPath); err != nil {
				continue
			}

			seen[m.Key()] = struct{}{}
			libs = append(libs, Library{
				Key:      m.Key(),
				Path:     m.Path,
				HostPath: hostPath,
				PID:      pid,
			})
		}
	}

	return libs, nil
}

func isTLSLibrary(path string) bool {
	base := filepath.Base(path)
	for _, name := range tlsLibraryNames {
		if strings.HasPrefix(base, name) {
			return true
		}
	}
	return false
}
