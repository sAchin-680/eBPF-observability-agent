// Package proc discovers which shared libraries a process has actually loaded,
// by reading the kernel's view of its address space rather than searching the
// filesystem for well-known paths.
package proc

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Mapping is one file-backed region of a process's address space.
//
// Device and Inode together identify the file. Path is how the file is named
// inside the process's own mount namespace, which is not necessarily a path the
// agent can open.
type Mapping struct {
	Device string
	Inode  uint64
	Path   string
}

// Key identifies the underlying file. Two mappings with the same key refer to
// the same file even when their paths differ, which happens routinely: on
// Debian and Ubuntu /lib and /usr/lib are the same directory reached by two
// names, so the same library appears under both.
func (m Mapping) Key() string {
	return m.Device + ":" + strconv.FormatUint(m.Inode, 10)
}

// ParseMaps reads the format of /proc/<pid>/maps and returns the file-backed
// mappings, one per distinct file.
//
// Each line describes a single region:
//
//	start-end perms offset device inode path
//
// A loaded library occupies several regions — executable code, read-only data,
// writable data, and a guard — so it appears on several consecutive lines with
// the same inode. Regions with no backing file, such as the heap and anonymous
// mappings, carry inode 0 and are skipped.
func ParseMaps(r io.Reader) ([]Mapping, error) {
	var out []Mapping
	seen := make(map[string]struct{})

	sc := bufio.NewScanner(r)
	// Lines are short, but a pathological path could exceed the default limit.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// Fewer than six fields means no path, i.e. an anonymous region.
		if len(fields) < 6 {
			continue
		}

		inode, err := strconv.ParseUint(fields[4], 10, 64)
		if err != nil || inode == 0 {
			continue
		}

		// Rejoining preserves paths containing spaces, which are unusual but
		// legal. Repeated spaces collapse, which is acceptable: the path is
		// used for matching and for opening through /proc, and a path that
		// relies on repeated spaces would already be ambiguous here.
		path := strings.Join(fields[5:], " ")

		// Pseudo-paths for special regions are bracketed, e.g. [heap], [stack].
		if strings.HasPrefix(path, "[") {
			continue
		}

		// The kernel appends this marker when the backing file has been
		// unlinked while still mapped, typically after a package upgrade. The
		// mapping remains valid and reachable through /proc.
		path = strings.TrimSuffix(path, " (deleted)")

		m := Mapping{Device: fields[3], Inode: inode, Path: path}
		if _, dup := seen[m.Key()]; dup {
			continue
		}
		seen[m.Key()] = struct{}{}
		out = append(out, m)
	}

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading maps: %w", err)
	}
	return out, nil
}
