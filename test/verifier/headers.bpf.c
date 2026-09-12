//go:build ignore

/*
 * Header parsing in kernel space, in progressively more acceptable forms.
 *
 * The agent parses HTTP in userspace. This file is the experiment that
 * establishes why, by attempting the in-kernel version and recording what the
 * verifier says about it. None of these programs is attached to anything; they
 * exist to be loaded, and the interesting ones are the loads that fail.
 *
 * Parsing headers means scanning for the blank line that ends them. The length
 * of that scan is a property of the data, not of the program, which is the
 * shape the verifier exists to reject: it must prove termination and memory
 * safety before a single instruction runs, and it cannot do either for a scan
 * whose length is discovered at run time.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Small enough to leave room on the 512-byte stack for everything else. */
#define BUF 256

/* No maps.
 *
 * Each program is loaded on its own so that one rejection does not hide the
 * others, and a program holding a map reference cannot be loaded without the
 * collection that creates the map. The count is returned instead, which is
 * also enough to stop the optimiser removing the loop that produces it. */

/*
 * 1. Scan until the data says to stop.
 *
 * The natural way to write this, and the reason in-kernel parsing is not simply
 * a matter of writing the loop carefully. The bound is the content of the
 * buffer, so there is no bound the verifier can establish.
 */
SEC("uprobe/unbounded")
int BPF_UPROBE(count_headers_unbounded, void *ssl, const char *buf, int num)
{
	char data[BUF];
	__u32 i = 0, lines = 0;

	if (bpf_probe_read_user(&data, sizeof(data), buf) != 0)
		return 0;

	while (data[i] != '\0') {
		if (data[i] == '\n')
			lines++;
		i++;
	}

	return lines;
}

/*
 * 2. Bound the scan by the caller's length.
 *
 * An improvement in intent: the loop now has a bound. The bound arrives in a
 * register from userspace, so the verifier knows nothing about its value and
 * must assume the worst.
 */
SEC("uprobe/runtime_bound")
int BPF_UPROBE(count_headers_runtime_bound, void *ssl, const char *buf, int num)
{
	char data[BUF];
	__u32 lines = 0;

	if (bpf_probe_read_user(&data, sizeof(data), buf) != 0)
		return 0;

	for (int i = 0; i < num; i++) {
		if (data[i] == '\n')
			lines++;
	}

	return lines;
}

/*
 * 3. Bound the scan by the buffer.
 *
 * The bound is now a compile-time constant and the index provably cannot leave
 * the buffer. This is the form that can be verified, and it is also the form
 * that answers a different question: it reports what is in the captured prefix,
 * not what is in the request.
 */
SEC("uprobe/compile_time_bound")
int BPF_UPROBE(count_headers_bounded, void *ssl, const char *buf, int num)
{
	char data[BUF];
	__u32 lines = 0;

	if (bpf_probe_read_user(&data, sizeof(data), buf) != 0)
		return 0;

	for (int i = 0; i < BUF; i++) {
		if (data[i] == '\n')
			lines++;
	}

	return lines;
}

/*
 * 4. Parse each header, rather than counting line breaks.
 *
 * Bounded as above, but doing per-header work inside the scan: tracking where
 * each line begins, and comparing its first bytes against a name. This is the
 * smallest thing that resembles actually parsing headers, and it is included to
 * find where a verifiable program stops being a practical one.
 */
SEC("uprobe/bounded_parse")
int BPF_UPROBE(parse_headers_bounded, void *ssl, const char *buf, int num)
{
	char data[BUF];
	__u32 matches = 0;
	__u32 line_start = 0;

	if (bpf_probe_read_user(&data, sizeof(data), buf) != 0)
		return 0;

	for (int i = 0; i + 1 < BUF; i++) {
		if (data[i] != '\r' || data[i + 1] != '\n')
			continue;

		/* A header name comparison, bounded and unrolled by the compiler. */
		if (line_start + 5 < BUF &&
		    data[line_start] == 'H' &&
		    data[line_start + 1] == 'o' &&
		    data[line_start + 2] == 's' &&
		    data[line_start + 3] == 't' &&
		    data[line_start + 4] == ':')
			matches++;

		line_start = i + 2;
	}

	return matches;
}

/*
 * 5. The same parse, at a range of buffer sizes.
 *
 * Program 4 is rejected. Knowing that is less useful than knowing where it
 * stops being accepted, because the boundary is what a design has to be built
 * around. Each of these is the identical parse over a different number of
 * bytes.
 *
 * The loop is not unrolled by hand: the compiler unrolls it, and the verifier
 * then walks every resulting path. The cost is therefore not linear in the
 * bound.
 */
#define PARSE_AT(size)                                                        \
	SEC("uprobe/parse_" #size)                                            \
	int BPF_UPROBE(parse_headers_##size, void *ssl, const char *buf,      \
		       int num)                                               \
	{                                                                     \
		char data[size];                                              \
		__u32 matches = 0;                                            \
		__u32 line_start = 0;                                         \
                                                                              \
		if (bpf_probe_read_user(&data, sizeof(data), buf) != 0)       \
			return 0;                                             \
                                                                              \
		for (int i = 0; i + 1 < size; i++) {                          \
			if (data[i] != '\r' || data[i + 1] != '\n')            \
				continue;                                     \
			if (line_start + 5 < size &&                          \
			    data[line_start] == 'H' &&                        \
			    data[line_start + 1] == 'o' &&                    \
			    data[line_start + 2] == 's' &&                    \
			    data[line_start + 3] == 't' &&                    \
			    data[line_start + 4] == ':')                      \
				matches++;                                    \
			line_start = i + 2;                                   \
		}                                                             \
		return matches;                                               \
	}

PARSE_AT(32)
PARSE_AT(64)
PARSE_AT(96)
PARSE_AT(128)
