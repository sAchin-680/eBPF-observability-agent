//go:build ignore

/*
 * Build-pipeline verification program.
 *
 * This is not agent functionality and is not a template for the agent's
 * kernel-side code. It exists solely so the build pipeline has an input that
 * can be compiled, loaded, and verified in CI, asserting four things at once:
 *
 *   1. clang emits a valid BPF ELF object for the target architecture
 *   2. bpf/vmlinux.h was generated and parses
 *   3. CO-RE relocations resolve against the running kernel's BTF
 *   4. the verifier accepts a load and global data (.bss) is supported
 *
 * Phase 4 runs this across the kernel version matrix. A failure here means the
 * toolchain or the kernel is at fault, never the agent.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* A named map, rather than a plain global. Globals live in .bss, which the
 * kernel exposes as a map named ".bss" — not a valid Go identifier, so no
 * binding is generated for it. Declaring the map explicitly both produces a
 * usable binding and exercises map creation, which the agent's ring buffer
 * depends on. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} smoke_result SEC(".maps");

/* sched_process_exec is a stable tracepoint, chosen here because its ABI does
 * not vary across the kernel versions under test. BPF_CORE_READ forces a CO-RE
 * relocation: task_struct's layout differs between kernels, and this is the
 * mechanism that makes one compiled object portable across them. */
SEC("tracepoint/sched/sched_process_exec")
int toolchain_smoke(void *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u32 key = 0;
	__u32 tgid = BPF_CORE_READ(task, tgid);

	bpf_map_update_elem(&smoke_result, &key, &tgid, BPF_ANY);
	return 0;
}
