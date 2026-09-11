package proc

import (
	"strings"
	"testing"
)

// Real output from /proc/<pid>/maps, trimmed to the relevant regions. A loaded
// library spans four regions with one inode, which is the case deduplication
// has to collapse.
const sampleMaps = `aaaac0d40000-aaaac0d48000 r-xp 00000000 fd:01 2361  /usr/bin/curl
e9f25c150000-e9f25c56a000 r-xp 00000000 fd:01 3187  /usr/lib/aarch64-linux-gnu/libcrypto.so.3
e9f25c56a000-e9f25c57a000 ---p 0041a000 fd:01 3187  /usr/lib/aarch64-linux-gnu/libcrypto.so.3
e9f25c5e0000-e9f25c682000 r-xp 00000000 fd:01 3188  /usr/lib/aarch64-linux-gnu/libssl.so.3
e9f25c682000-e9f25c696000 ---p 000a2000 fd:01 3188  /usr/lib/aarch64-linux-gnu/libssl.so.3
e9f25c696000-e9f25c6a0000 r--p 000a6000 fd:01 3188  /usr/lib/aarch64-linux-gnu/libssl.so.3
e9f25c6a0000-e9f25c6a4000 rw-p 000b0000 fd:01 3188  /usr/lib/aarch64-linux-gnu/libssl.so.3
ffffc1e40000-ffffc1e61000 rw-p 00000000 00:00 0     [stack]
e9f25c700000-e9f25c721000 rw-p 00000000 00:00 0
e9f25c800000-e9f25c821000 rw-p 00000000 00:00 0     [heap]
`

func TestParseMapsDeduplicatesByInode(t *testing.T) {
	got, err := ParseMaps(strings.NewReader(sampleMaps))
	if err != nil {
		t.Fatalf("ParseMaps: %v", err)
	}

	// curl, libcrypto, libssl — four libssl regions collapse to one entry.
	if len(got) != 3 {
		t.Fatalf("expected 3 distinct files, got %d: %+v", len(got), got)
	}

	var ssl *Mapping
	for i := range got {
		if strings.Contains(got[i].Path, "libssl") {
			ssl = &got[i]
		}
	}
	if ssl == nil {
		t.Fatal("libssl mapping not found")
	}
	if ssl.Inode != 3188 {
		t.Errorf("inode = %d, want 3188", ssl.Inode)
	}
	if ssl.Key() != "fd:01:3188" {
		t.Errorf("key = %q, want %q", ssl.Key(), "fd:01:3188")
	}
}

func TestParseMapsSkipsAnonymousRegions(t *testing.T) {
	got, err := ParseMaps(strings.NewReader(sampleMaps))
	if err != nil {
		t.Fatalf("ParseMaps: %v", err)
	}
	for _, m := range got {
		if m.Inode == 0 {
			t.Errorf("anonymous region not skipped: %+v", m)
		}
		if strings.HasPrefix(m.Path, "[") {
			t.Errorf("pseudo-path not skipped: %+v", m)
		}
	}
}

func TestParseMapsStripsDeletedMarker(t *testing.T) {
	// The kernel marks a mapping whose file was unlinked while still mapped,
	// which happens whenever a package is upgraded under a running process.
	const deleted = "e9f25c5e0000-e9f25c682000 r-xp 00000000 fd:01 3188  /usr/lib/libssl.so.3 (deleted)\n"

	got, err := ParseMaps(strings.NewReader(deleted))
	if err != nil {
		t.Fatalf("ParseMaps: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 mapping, got %d", len(got))
	}
	if got[0].Path != "/usr/lib/libssl.so.3" {
		t.Errorf("path = %q, want the marker stripped", got[0].Path)
	}
}

func TestParseMapsDistinguishesSameNameDifferentInode(t *testing.T) {
	// The failure this task exists to fix: two processes loading libraries with
	// identical names from different locations. Matching on name alone would
	// treat these as one file and probe only the first.
	const twoCopies = `e9f25c5e0000-e9f25c682000 r-xp 00000000 fd:01 3188   /usr/lib/aarch64-linux-gnu/libssl.so.3
f05665770000-f05665812000 r-xp 00000000 fd:01 541016 /opt/customssl/libssl.so.3
`
	got, err := ParseMaps(strings.NewReader(twoCopies))
	if err != nil {
		t.Fatalf("ParseMaps: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 distinct files, got %d: %+v", len(got), got)
	}
	if got[0].Key() == got[1].Key() {
		t.Errorf("distinct files share a key: %q", got[0].Key())
	}
}

func TestIsTLSLibrary(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/usr/lib/aarch64-linux-gnu/libssl.so.3", true},
		{"/opt/customssl/libssl.so.3", true},
		{"/usr/lib/libssl.so.1.1", true},
		{"/usr/lib/aarch64-linux-gnu/libcrypto.so.3", false},
		{"/usr/bin/curl", false},
		// The match includes the dot, so an unrelated library whose name merely
		// begins with the same letters is not picked up.
		{"/usr/lib/libsslackware.so", false},
		// libcrypto holds the primitives but none of the TLS record layer, so
		// the payload boundary this agent probes does not exist in it.
		{"/usr/lib/libcrypto.so.1.1", false},
	}
	for _, c := range cases {
		if got := isTLSLibrary(c.path); got != c.want {
			t.Errorf("isTLSLibrary(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}
