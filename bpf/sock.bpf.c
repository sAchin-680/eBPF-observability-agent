/*
 * Socket endpoint capture.
 *
 * Records the four-tuple of the socket a TLS connection writes to, so that a
 * captured payload can carry the network endpoints it travelled between.
 *
 * This hooks tcp_sendmsg, a kernel-internal function, with a kprobe. That is a
 * deliberate exception to preferring tracepoints, and the reason is that no
 * tracepoint provides what is needed here. The available socket tracepoints fire
 * on state transitions — sock:inet_sock_set_state and friends — which report a
 * connection being established, not a particular send. Establishment happens on
 * a different thread from the TLS call in the accept path, and in softirq
 * context with no useful process identity, so the thread-based association this
 * relies on is unavailable there.
 *
 * The cost of the exception is real. tcp_sendmsg's signature is an internal
 * detail with no stability guarantee, so this program can fail to attach on a
 * kernel where the symbol has been renamed or inlined. That failure is handled
 * as a degradation: attachment is attempted, a failure is reported, and the
 * agent continues producing records without network endpoints rather than
 * refusing to start.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "conn.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define AF_INET 2
#define AF_INET6 10

/*
 * int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
 *
 * Reached from the write() that a TLS library performs after encrypting. The
 * thread is still the one that entered the TLS call, so the connection it
 * recorded on entry is still current.
 */
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(probe_tcp_sendmsg, struct sock *sk)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u64 *conn;
	struct conn_key key = {};
	struct conn_tuple tuple = {};
	__u16 family;

	/* No recorded connection means this send did not originate from a TLS
	 * call being traced. Most TCP traffic on a host falls into this case, so
	 * returning early here is the common path and keeps the cost of this
	 * probe to a single map lookup. */
	conn = bpf_map_lookup_elem(&active_conn, &id);
	if (!conn)
		return 0;

	/* Field offsets within sock_common differ between kernel versions.
	 * BPF_CORE_READ emits relocations that are resolved against the running
	 * kernel's own type information at load time. */
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	tuple.family = family;

	if (family == AF_INET) {
		/* Stored as a big-endian word. Copying its bytes preserves network
		 * order, which is the form the address field holds. */
		__be32 s4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		__be32 d4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);

		__builtin_memcpy(tuple.saddr, &s4, sizeof(s4));
		__builtin_memcpy(tuple.daddr, &d4, sizeof(d4));
	} else if (family == AF_INET6) {
		/* A server bound to the default dual-stack address accepts IPv4
		 * clients through an IPv4-mapped IPv6 address, so this branch also
		 * covers connections that are IPv4 on the wire. Userspace unmaps
		 * them rather than reporting ::ffff:127.0.0.1. */
		BPF_CORE_READ_INTO(&tuple.saddr, sk,
				   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
		BPF_CORE_READ_INTO(&tuple.daddr, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr8);
	} else {
		return 0; /* not an internet socket */
	}

	/* skc_num is stored in host byte order; skc_dport is in network order.
	 * The asymmetry is a long-standing kernel detail, and reading both the
	 * same way yields a correct local port beside a byte-swapped remote one. */
	tuple.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	tuple.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

	key.pid = id >> 32;
	key.conn = *conn;
	bpf_map_update_elem(&conn_tuples, &key, &tuple, BPF_ANY);
	return 0;
}
