package proc

import (
	"os"
	"strconv"
	"syscall"
)

// fileKey derives the same identity used for library mappings — device and
// inode — from a stat result, so that executables and shared libraries share
// one deduplication space.
func fileKey(fi os.FileInfo) (string, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", false
	}
	return strconv.FormatUint(uint64(st.Dev), 10) + "/" +
		strconv.FormatUint(st.Ino, 10), true
}
