//go:build tools

// Package tools pins build-time dependencies that are not imported by any
// production code path, so that `go mod tidy` does not drop them.
//
// bpf2go compiles the kernel-side C in bpf/ and generates the Go bindings and
// embedded ELF the agent loads at runtime. Pinning it here keeps every
// developer and CI job on the same generator version: a mismatch produces
// bindings that differ from the committed ones for no visible reason.
package tools

import _ "github.com/cilium/ebpf/cmd/bpf2go"
