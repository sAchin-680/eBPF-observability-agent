/*
 * Shared capture path: event layout, ring buffer, and drop accounting.
 *
 * Included by every kernel-side program so that all of them emit an identical
 * record regardless of which TLS implementation they hooked. Each program is
 * compiled into its own object and therefore gets its own instance of these
 * maps; userspace drains each one.
 */

#ifndef __CAPTURE_H
#define __CAPTURE_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/*
 * Payload bytes carried per event.
 *
 * Records are built in ring buffer memory rather than on the stack, so the
 * 512-byte stack limit that constrained the earlier trace-pipe path no longer
 * applies. The binding constraint is now throughput: every byte reserved is
 * ring buffer capacity unavailable to the next event, and an event that cannot
 * reserve space is dropped. 256 bytes covers an HTTP/1.1 request line and the
 * first headers, which is what the parser needs.
 */
#define MAX_DATA 256

/* Which side of the exchange the payload came from. */
#define DIR_EGRESS 0  /* written by the traced process */
#define DIR_INGRESS 1 /* read by the traced process */

/* Which implementation produced it, retained so that a capture gap can be
 * attributed to the right attach strategy. */
#define SRC_OPENSSL 0
#define SRC_GOTLS 1

struct event {
	/* Monotonic kernel timestamp. Wall-clock time is not available in this
	 * context, and monotonic time is what request duration needs anyway. */
	__u64 timestamp_ns;

	__u32 pid; /* thread group id, what userspace calls the process */
	__u32 tid; /* thread id */

	/* Length the call reported, which may exceed what was captured. Keeping
	 * both makes truncation visible rather than silent. */
	__u64 len;
	__u32 captured;

	__u8 direction;
	__u8 source;
	__u8 comm[16];
	__u8 data[MAX_DATA];
};

/*
 * BPF_MAP_TYPE_RINGBUF, available since kernel 5.8.
 *
 * A single shared buffer rather than one per CPU, so ordering between events is
 * preserved and memory is not multiplied by core count. Capacity must be a
 * power of two and a multiple of the page size.
 *
 * 256 KiB holds roughly 850 events of this size. At a few thousand requests per
 * second that is well under a second of buffering, which is the figure the
 * drop-rate benchmark exists to establish.
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

/*
 * Events lost because the ring buffer was full.
 *
 * A full ring buffer drops silently: the reservation fails and the traced
 * application is unaffected and unaware. Without this counter the agent would
 * under-report traffic while appearing healthy, which is the failure mode NFR2
 * exists to prevent.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} dropped SEC(".maps");

static __always_inline void count_drop(void)
{
	__u32 key = 0;
	__u64 *n = bpf_map_lookup_elem(&dropped, &key);

	/* Atomic because probes on different CPUs can drop concurrently. */
	if (n)
		__sync_fetch_and_add(n, 1);
}

/*
 * Copies up to MAX_DATA bytes out of the traced process and publishes one event.
 *
 * The buffer address belongs to another address space and cannot be
 * dereferenced: the page may not be resident, and the verifier rejects direct
 * access. bpf_probe_read_user performs the copy and reports failure rather than
 * faulting.
 */
static __always_inline void submit_event(__u8 direction, __u8 source,
					 const void *buf, __u64 len)
{
	struct event *e;
	__u32 n;

	if (len == 0)
		return;

	/* Reserve before reading, so a full buffer costs nothing but the
	 * failed reservation. */
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return;
	}

	if (len > MAX_DATA)
		n = MAX_DATA;
	else
		n = (__u32)len;

	/* Masking as well as clamping: the verifier needs the copy length
	 * provably within the destination on every path, and the explicit mask
	 * states that bound in a form it accepts without tracking the branch
	 * above. MAX_DATA is a power of two, so this is exact. */
	n &= (MAX_DATA - 1);
	if (n == 0)
		n = MAX_DATA;

	if (bpf_probe_read_user(&e->data, n, buf) != 0) {
		/* Discard rather than submit: a partially filled record would be
		 * indistinguishable from a real short read. */
		bpf_ringbuf_discard(e, 0);
		return;
	}

	e->timestamp_ns = bpf_ktime_get_ns();
	__u64 id = bpf_get_current_pid_tgid();
	e->pid = id >> 32;
	e->tid = (__u32)id;
	e->len = len;
	e->captured = n;
	e->direction = direction;
	e->source = source;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
}

#endif /* __CAPTURE_H */
