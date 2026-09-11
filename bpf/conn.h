/*
 * Connection identity: binding a TLS connection to its socket.
 *
 * A probe on a TLS library sees the connection object and the plaintext, but
 * nothing about the network. The socket four-tuple lives in struct sock, which
 * only appears in the kernel's TCP path, where the plaintext no longer exists.
 * Neither hook alone can produce a record carrying both.
 *
 * They are joined by the thread. A TLS write encrypts and then calls write(),
 * which reaches tcp_sendmsg on the same thread without an intervening context
 * switch. Recording which connection a thread is currently inside, before that
 * call, lets the TCP hook attribute the socket it is handed to that connection.
 *
 * The maps are declared here and shared between the separately compiled
 * programs: the TLS programs write active_conn, the socket program reads it and
 * fills conn_tuple, and userspace reads conn_tuple. Sharing is arranged at load
 * time rather than by compiling everything into one object, so that the Go
 * programs are still only loaded on a host that runs Go binaries.
 */

#ifndef __CONN_H
#define __CONN_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

/*
 * Socket endpoints for one connection.
 *
 * Addresses are held as sixteen raw bytes in network order, which is the form
 * both address families share: an IPv4 address occupies the first four and the
 * rest are unused. Storing a 32-bit integer instead would work only for IPv4,
 * and IPv6 is not an edge case here — a Go or Node server binding its default
 * dual-stack address accepts loopback connections over IPv6, so the common
 * local case is already IPv6.
 *
 * Ports are host order; addresses stay in network order so that userspace can
 * use the bytes directly without a byte-swap that only applies to one family.
 */
struct conn_tuple {
	__u8 saddr[16];
	__u8 daddr[16];
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 _pad;
};

/*
 * The connection a thread is currently executing inside.
 *
 * Written on entry to a TLS read or write and read by the socket hook that the
 * same call reaches. The key is the thread, which is correct here even though
 * it is not correct for pairing a request with its response: the window is a
 * single uninterrupted call rather than a round trip, so there is no
 * opportunity for a goroutine to migrate or a thread to be reused.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64); /* pid_tgid */
	__type(value, __u64); /* connection object address */
} active_conn SEC(".maps");

/*
 * Socket endpoints per connection object, scoped by process.
 *
 * Populated once per connection and read by userspace when a captured payload
 * arrives. Entries outlive the connections they describe, which is why the map
 * is bounded and why userspace treats a missing entry as unknown rather than as
 * an error.
 */
struct conn_key {
	__u32 pid;
	__u32 _pad;
	__u64 conn;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct conn_key);
	__type(value, struct conn_tuple);
} conn_tuples SEC(".maps");

/* Records which connection this thread is inside, for the socket hook. */
static __always_inline void mark_active_conn(__u64 conn)
{
	__u64 id = bpf_get_current_pid_tgid();

	bpf_map_update_elem(&active_conn, &id, &conn, BPF_ANY);
}

static __always_inline void clear_active_conn(void)
{
	__u64 id = bpf_get_current_pid_tgid();

	bpf_map_delete_elem(&active_conn, &id);
}

#endif /* __CONN_H */
