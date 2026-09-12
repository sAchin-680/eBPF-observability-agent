package proc

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

// Go TLS entry points. Go implements TLS in pure Go and links no OpenSSL, so a
// Go binary contains no libssl mapping and none of the library-based discovery
// applies. The symbols live in the application binary itself.
const (
	GoTLSWriteSymbol = "crypto/tls.(*Conn).Write"
	GoTLSReadSymbol  = "crypto/tls.(*Conn).Read"
)

// armRET is the AArch64 RET instruction, `ret x30`. AArch64 instructions are a
// fixed four bytes and always four-byte aligned, so scanning a function body
// for this word locates every return site exactly.
//
// The equivalent on x86-64 is a single 0xc3 byte within a variable-length
// instruction stream, where that byte also occurs inside other instructions and
// inside embedded data. Locating returns there requires decoding instruction
// lengths from the function start, which this does not attempt.
const armRET = 0xd65f03c0

// GoTLSTarget is a Go executable whose TLS entry points can be probed.
type GoTLSTarget struct {
	// Key identifies the executable file, matching Library.Key so that both
	// kinds of target share one deduplication space.
	Key string

	// Path is the executable as named inside its own mount namespace.
	Path string

	// HostPath reaches the same file from the agent's namespace.
	HostPath string

	PID int

	// ReadReturnOffsets are the return sites within the read function,
	// relative to the function's own start address.
	//
	// Return probes are attached at these offsets rather than with a uretprobe.
	// A uretprobe replaces the return address on the stack with a kernel
	// trampoline; Go's runtime walks its own stack using pclntab metadata,
	// does not recognise that address, and aborts the process:
	//
	//	runtime: g 35: unexpected return pc for crypto/tls.(*Conn).Read
	//	         called from 0xfffffffff000
	//
	// The traced application dies. Probing the return instructions directly
	// leaves the stack untouched.
	ReadReturnOffsets []uint64
}

// IsGoBinary reports whether path is a Go executable.
//
// The pclntab section is present in every Go binary including stripped ones,
// which makes it a more reliable marker than the symbol table.
func IsGoBinary(path string) bool {
	f, err := elf.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	return f.Section(".gopclntab") != nil || f.Section(".go.buildinfo") != nil
}

// InspectGoBinary locates the Go TLS entry points in an executable and the
// return sites within its read function.
//
// Symbols are read from .symtab. A binary built with -ldflags="-s -w" has no
// symbol table, and this reports that rather than guessing: recovering the
// symbols would mean parsing pclntab's function table, which is an internal
// runtime format that changes between Go releases.
func InspectGoBinary(path string) (*GoTLSTarget, error) {
	if runtime.GOARCH != "arm64" {
		return nil, fmt.Errorf("return-site scanning is implemented for arm64 only, not %s", runtime.GOARCH)
	}

	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	syms, err := f.Symbols()
	if err != nil {
		return nil, fmt.Errorf("no symbol table in %s (stripped binary): %w", path, err)
	}

	var readSym *elf.Symbol
	var haveWrite bool
	for i := range syms {
		switch syms[i].Name {
		case GoTLSReadSymbol:
			readSym = &syms[i]
		case GoTLSWriteSymbol:
			haveWrite = true
		}
	}
	if readSym == nil || !haveWrite {
		return nil, fmt.Errorf("%s does not use crypto/tls", path)
	}

	offsets, err := scanReturns(f, readSym.Value, readSym.Size)
	if err != nil {
		return nil, err
	}
	if len(offsets) == 0 {
		return nil, fmt.Errorf("no return instructions found in %s", GoTLSReadSymbol)
	}

	return &GoTLSTarget{Path: path, HostPath: path, ReadReturnOffsets: offsets}, nil
}

// scanReturns returns the offsets of every RET instruction within the function
// at virtual address addr, relative to that address.
func scanReturns(f *elf.File, addr, size uint64) ([]uint64, error) {
	text := f.Section(".text")
	if text == nil {
		return nil, fmt.Errorf("no .text section")
	}
	if addr < text.Addr || addr+size > text.Addr+text.Size {
		return nil, fmt.Errorf("function at 0x%x lies outside .text", addr)
	}

	body := make([]byte, size)
	if _, err := text.ReadAt(body, int64(addr-text.Addr)); err != nil {
		return nil, fmt.Errorf("reading function body: %w", err)
	}

	var out []uint64
	for i := 0; i+4 <= len(body); i += 4 {
		if binary.LittleEndian.Uint32(body[i:]) == armRET {
			out = append(out, uint64(i))
		}
	}
	return out, nil
}

// FindGoTLSTargets scans every visible process for Go executables that use
// crypto/tls, returning one entry per distinct executable.
//
// Unlike shared libraries, each Go executable carries its own copy of the TLS
// implementation at its own addresses, so there is no shared file to attach to
// once. Every distinct Go binary on the host needs its own attachment.
func FindGoTLSTargets() ([]GoTLSTarget, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	var out []GoTLSTarget

	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}

		if IsSelf(pid) {
			continue
		}
		t, err := GoTLSTargetForPID(pid)
		if err != nil || t == nil {
			continue
		}
		if _, dup := seen[t.Key]; dup {
			continue
		}
		seen[t.Key] = struct{}{}
		out = append(out, *t)
	}

	return out, nil
}

// GoTLSTargetForPID inspects one process. It returns nil without error when the
// process is not a Go binary using crypto/tls, which is the common case.
func GoTLSTargetForPID(pid int) (*GoTLSTarget, error) {
	if IsSelf(pid) {
		return nil, nil
	}
	dir := strconv.Itoa(pid)

	// The executable is reached through /proc rather than by its reported
	// path: the path is meaningful only inside the process's own mount
	// namespace, and the file may have been replaced or unlinked since the
	// process started. This link always refers to the running image.
	exe := filepath.Join("/proc", dir, "exe")
	fi, err := os.Stat(exe)
	if err != nil {
		return nil, err
	}
	key, ok := fileKey(fi)
	if !ok {
		return nil, nil
	}
	if !IsGoBinary(exe) {
		return nil, nil
	}

	t, err := InspectGoBinary(exe)
	if err != nil {
		return nil, nil // not a TLS client, or stripped
	}

	t.Key = key
	t.PID = pid
	t.HostPath = exe
	if target, err := os.Readlink(exe); err == nil {
		t.Path = target
	}
	return t, nil
}
