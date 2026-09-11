// Package ebpf loads the agent's kernel-side programs and attaches them to
// their probe points.
package ebpf

// Compiled per architecture rather than for a generic little-endian BPF
// target. A uprobe receives the CPU register state at the call site, so
// reading a function argument means reading whichever register the platform
// ABI assigns to it. The PT_REGS_PARMn macros resolve that per architecture
// and refuse to compile without knowing which one, so a generic bpfel target
// cannot build any program that reads probe arguments.
//
// Built for the host architecture only. Naming a foreign architecture also
// requires that architecture's struct definitions, and bpf/vmlinux.h is
// generated from the running kernel's BTF, so struct pt_regs carries the host
// layout and a foreign build fails on the register names. Producing release
// artifacts for several architectures therefore needs a vmlinux.h per
// architecture, which belongs with deployment packaging rather than here.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target native -cflags "-O2 -g -Wall -Werror -I../../bpf" ssl ../../bpf/ssl.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target native -cflags "-O2 -g -Wall -Werror -I../../bpf" gotls ../../bpf/gotls.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target native -cflags "-O2 -g -Wall -Werror -I../../bpf" discover ../../bpf/discover.bpf.c
