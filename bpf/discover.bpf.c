/*
 * Process execution notification.
 *
 * Reports every exec on the host so that userspace can inspect the new process
 * and attach probes to any TLS implementation it loads.
 *
 * This replaces periodically rescanning /proc. Scanning is sampling: a process
 * that starts and exits between two scans is never observed, and no interval
 * closes that gap — a short-lived client can complete an entire request in less
 * time than any practical scan period. Notification has no such window.
 *
 * The hook is the sched_process_exec tracepoint rather than a kprobe on the
 * kernel's exec implementation. Tracepoints are a stable interface the kernel
 * commits to keeping; the internal functions behind exec are not, and have been
 * renamed and restructured across releases. A kprobe on one of them would load
 * successfully on the kernel it was written against and silently fail to attach
 * elsewhere, which defeats the portability CO-RE provides.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct exec_event {
	__u32 pid;
	__u8 comm[16];
};

/*
 * Execs are far less frequent than payload events and each record is small, so
 * this buffer is sized well below the capture path's.
 *
 * A dropped exec event means a process is never inspected and its traffic is
 * never seen, so drops are counted rather than ignored.
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 1024);
} exec_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} exec_dropped SEC(".maps");

/*
 * Only the process identity is reported. The executable path is available in
 * the tracepoint's variable-length payload, but reading it correctly means
 * decoding a per-kernel format, and userspace can read /proc/<pid>/exe instead
 * — which also resolves the running image rather than a path that may have been
 * replaced since.
 */
SEC("tracepoint/sched/sched_process_exec")
int handle_exec(void *ctx)
{
	struct exec_event *e;
	__u32 key = 0;
	__u64 *drops;

	e = bpf_ringbuf_reserve(&exec_events, sizeof(*e), 0);
	if (!e) {
		drops = bpf_map_lookup_elem(&exec_dropped, &key);
		if (drops)
			__sync_fetch_and_add(drops, 1);
		return 0;
	}

	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}
