#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL"

#define MAX_DATA
struct event { 
    __u32 pid; 
    __u8 comm[16]; 
    __32 len;
    __u8 data[MAX_DATA];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __unint(max_entries, 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,);
    __type(value,);
} ssl_read_bufs SEC(".maps");

// ---- WRITE: easy half ---- 
SEC("uprobe/SSL_write")
int BPF_UPROBE(probe_ssl_write, void *ssl, const void *buf, int num)
{
    return 0;
}


// ---- READ ----
SEC("uprobe/SSL_read")
int BPF_UPROBE(prove_ssl)