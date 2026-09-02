package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -cflags "-O2 -g -Wall -Werror -I../../bpf" /* name? */ ../../bpf/ssl.bpf.c
