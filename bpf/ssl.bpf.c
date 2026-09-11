/*
 * OpenSSL TLS payload capture.
 *
 * Hooks the read and write entry points in libssl. Both handle plaintext:
 * encryption happens inside the write path after the caller's buffer is handed
 * over, and decryption completes inside the read path before the caller's
 * buffer is filled. Probing at these boundaries yields cleartext HTTP without
 * terminating TLS, manipulating certificates, or modifying the traced process.
 *
 * Four entry points are covered, not two. OpenSSL 1.1.1 added SSL_write_ex and
 * SSL_read_ex, and callers are split between the two APIs: curl uses the
 * original pair, CPython 3.12 uses the _ex pair exclusively. Probing only the
 * original pair silently misses every caller that adopted the newer API, with
 * no error and no missing symbol to diagnose.
 *
 * Output goes to the kernel trace pipe. That is a debugging channel, not a data
 * path: it is global, rate limited, and lossy. It is replaced by a ring buffer
 * once the capture path is proven.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "capture.h"
#include "conn.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";


/*
 * State carried from a read entry probe to its return probe.
 *
 * The read paths are not symmetric with the write paths. A write call's buffer
 * holds the payload on entry. A read call receives an empty destination buffer
 * and fills it before returning, so the payload exists only at return. A return
 * probe does not receive the original arguments, so the destination address
 * must be carried across.
 *
 * The two read APIs report length differently:
 *
 *   ssize_t SSL_read   (SSL *ssl, void *buf, int num);
 *   int     SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes);
 *
 * SSL_read returns the byte count directly. SSL_read_ex returns 1 or 0 for
 * success or failure and writes the count through an out-parameter, so that
 * pointer must be carried across as well; it is unused by the SSL_read path.
 */
struct read_args {
	__u64 buf;       /* destination buffer in the traced process */
	__u64 count_ptr; /* where SSL_read_ex will write the byte count */
	__u64 conn;      /* the SSL* this read belongs to */
};

/*
 * In-flight read calls, awaiting return.
 *
 * The key is the value returned by bpf_get_current_pid_tgid(), which packs the
 * thread ID and the process ID. A thread executes one call at a time, so it can
 * have at most one read outstanding, making the thread the correct unit of
 * identity. Keying on the process instead would let concurrent threads in the
 * same process overwrite each other's entries, producing payloads attributed to
 * the wrong call under load while appearing correct when a single request is in
 * flight.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);
	__type(value, struct read_args);
} ssl_read_args SEC(".maps");

/* Publishes one captured payload. Kept as a named wrapper so the call sites
 * read the same as before the trace pipe was replaced. */
static __always_inline void emit(__u8 direction, __u64 conn, const void *buf,
				 __u64 len)
{
	submit_event(direction, SRC_OPENSSL, conn, buf, len);
}

/* Records read state for the matching return probe. */
static __always_inline int stash_read(void *ssl, void *buf, void *count_ptr)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct read_args args = {
		.buf = (__u64)buf,
		.count_ptr = (__u64)count_ptr,
		.conn = (__u64)ssl,
	};

	bpf_map_update_elem(&ssl_read_args, &id, &args, BPF_ANY);
	return 0;
}

/*
 * int SSL_write(SSL *ssl, const void *buf, int num)
 *
 * The payload is present on entry, so no return probe is required. num is the
 * caller's requested length rather than the number of bytes actually written;
 * a short write would be reported here as its full requested size.
 */
SEC("uprobe/SSL_write")
int BPF_UPROBE(probe_ssl_write, void *ssl, const void *buf, int num)
{
	mark_active_conn((__u64)ssl);
	if (num > 0)
		emit(DIR_EGRESS, (__u64)ssl, buf, (__u64)num);
	return 0;
}

/*
 * int SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written)
 *
 * The payload is likewise present on entry. The actual count is only available
 * through *written at return, but the requested length is sufficient to locate
 * the request line at this stage.
 */
SEC("uprobe/SSL_write_ex")
int BPF_UPROBE(probe_ssl_write_ex, void *ssl, const void *buf, __u64 num)
{
	mark_active_conn((__u64)ssl);
	emit(DIR_EGRESS, (__u64)ssl, buf, num);
	return 0;
}

/* ssize_t SSL_read(SSL *ssl, void *buf, int num) */
SEC("uprobe/SSL_read")
int BPF_UPROBE(probe_ssl_read_entry, void *ssl, void *buf, int num)
{
	return stash_read(ssl, buf, NULL);
}

/*
 * Return from SSL_read. The return value is the number of bytes decrypted into
 * the buffer recorded on entry; zero or negative indicates no payload.
 *
 * The map entry is deleted on every path, including error paths. An entry left
 * behind by a call that errored would accumulate for the lifetime of a
 * long-running process until the map filled.
 */
SEC("uretprobe/SSL_read")
int BPF_URETPROBE(probe_ssl_read_ret, int ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct read_args *args;

	args = bpf_map_lookup_elem(&ssl_read_args, &id);
	if (!args)
		return 0;

	if (ret > 0)
		emit(DIR_INGRESS, args->conn, (void *)args->buf, (__u64)ret);

	bpf_map_delete_elem(&ssl_read_args, &id);
	return 0;
}

/* int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes) */
SEC("uprobe/SSL_read_ex")
int BPF_UPROBE(probe_ssl_read_ex_entry, void *ssl, void *buf, __u64 num,
	       void *readbytes)
{
	return stash_read(ssl, buf, readbytes);
}

/*
 * Return from SSL_read_ex. The return value reports success or failure only;
 * the byte count was written through the out-parameter captured on entry, and
 * must be read back out of the traced process.
 */
SEC("uretprobe/SSL_read_ex")
int BPF_URETPROBE(probe_ssl_read_ex_ret, int ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct read_args *args;
	__u64 count = 0;

	args = bpf_map_lookup_elem(&ssl_read_args, &id);
	if (!args)
		return 0;

	if (ret == 1 && args->count_ptr != 0) {
		if (bpf_probe_read_user(&count, sizeof(count),
					(void *)args->count_ptr) == 0 && count > 0)
			emit(DIR_INGRESS, args->conn, (void *)args->buf, count);
	}

	bpf_map_delete_elem(&ssl_read_args, &id);
	return 0;
}
