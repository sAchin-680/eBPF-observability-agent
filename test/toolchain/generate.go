// Package toolchain verifies that the eBPF build pipeline produces a loadable
// object on the host kernel. See smoke.bpf.c for what is asserted and why.
package toolchain

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -cflags "-O2 -g -Wall -Werror -I../../bpf" smoke smoke.bpf.c
