/*
 * Go crypto/tls payload capture.
 *
 * Go implements TLS in pure Go and links no OpenSSL, so none of the libssl
 * probes apply to a Go process. The entry points live in the application binary
 * itself, one copy per executable.
 *
 * Two properties of the Go runtime shape this file:
 *
 * Return probes are attached to the function's own RET instructions, never with
 * a uretprobe. A uretprobe replaces the return address on the stack with a
 * kernel trampoline. Go's runtime walks its own stack using pclntab metadata,
 * does not recognise that address, and aborts the process:
 *
 *	runtime: g 35: unexpected return pc for crypto/tls.(*Conn).Read
 *	         called from 0xfffffffff000
 *
 * The traced application dies, which is the outcome the agent exists to avoid.
 *
 * Entry and return are correlated by goroutine, not by thread. A goroutine that
 * blocks on network I/O — which a TLS read does by definition — can resume on a
 * different OS thread, so a thread-keyed entry would be looked up from the
 * wrong thread at return and miss. The running goroutine is held in a dedicated
 * register, which gives a stable identity across the migration.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "capture.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * The register holding the current goroutine under Go's register ABI, in place
 * since Go 1.17.
 */
#if defined(__TARGET_ARCH_arm64)
#define GOROUTINE_PTR(ctx) (((struct pt_regs *)(ctx))->regs[28])
#elif defined(__TARGET_ARCH_x86)
#define GOROUTINE_PTR(ctx) (((struct pt_regs *)(ctx))->r14)
#else
#error "goroutine register is architecture specific"
#endif

/* Destination buffer recorded at read entry, awaiting the return site. */
struct go_read_args {
	__u64 buf;
	__u64 conn; /* the *tls.Conn this read belongs to */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64); /* goroutine pointer */
	__type(value, struct go_read_args);
} go_read_args SEC(".maps");

static __always_inline void emit_go(__u8 direction, __u64 conn, const void *buf,
				    __u64 len)
{
	submit_event(direction, SRC_GOTLS, conn, buf, len);
}

/*
 * func (c *Conn) Write(b []byte) (int, error)
 *
 * Go passes arguments in registers. A slice occupies three of them — pointer,
 * length, capacity — so after the receiver the layout is:
 *
 *	PARM1 = c        PARM2 = b.ptr     PARM3 = b.len     PARM4 = b.cap
 *
 * The payload is present on entry, so no return probe is needed.
 *
 * This register layout holds on arm64, where Go's ABI and the platform C ABI
 * assign the same registers to the first arguments. They diverge on x86-64: Go
 * passes in RAX, RBX, RCX while the C ABI macros read RDI, RSI, RDX, so these
 * macros would read the wrong registers there.
 */
SEC("uprobe/go_tls_write")
int BPF_UPROBE(probe_go_tls_write, void *conn, const void *buf, __u64 len)
{
	emit_go(DIR_EGRESS, (__u64)conn, buf, len);
	return 0;
}

/*
 * func (c *Conn) Read(b []byte) (int, error)
 *
 * On entry the destination buffer is empty; it is filled before the function
 * returns. Record its address against the calling goroutine.
 */
SEC("uprobe/go_tls_read")
int BPF_UPROBE(probe_go_tls_read_entry, void *conn, void *buf, __u64 cap)
{
	__u64 g = GOROUTINE_PTR(ctx);
	struct go_read_args args = {.buf = (__u64)buf, .conn = (__u64)conn};

	bpf_map_update_elem(&go_read_args, &g, &args, BPF_ANY);
	return 0;
}

/*
 * Attached to each RET instruction in the read function rather than to its
 * return.
 *
 * Go returns values in registers, so the byte count is in the first return
 * register at the point the function returns. Reading it through the argument
 * macro is correct here only because the first argument and first result share
 * a register on this ABI.
 *
 * The entry is deleted on every path. A goroutine whose read errored, or which
 * never reaches a probed return site, would otherwise leave an entry behind
 * until the map filled.
 */
SEC("uprobe/go_tls_read_return")
int BPF_UPROBE(probe_go_tls_read_return)
{
	__u64 g = GOROUTINE_PTR(ctx);
	struct go_read_args *args;
	long n = PT_REGS_PARM1(ctx);

	args = bpf_map_lookup_elem(&go_read_args, &g);
	if (!args)
		return 0;

	if (n > 0)
		emit_go(DIR_INGRESS, args->conn, (void *)args->buf, (__u64)n);

	bpf_map_delete_elem(&go_read_args, &g);
	return 0;
}
