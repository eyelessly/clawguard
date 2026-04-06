// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// uprobe on OpenSSL SSL_write — plaintext before encryption.

#include <linux/bpf.h>
#include <linux/types.h>

/* libbpf headers only forward-declare these under -target bpf; complete layouts (UAPI). */
#if defined(__TARGET_ARCH_arm64)
struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};
#elif defined(__TARGET_ARCH_x86)
struct pt_regs {
	__u64 r15;
	__u64 r14;
	__u64 r13;
	__u64 r12;
	__u64 bp;
	__u64 bx;
	__u64 r11;
	__u64 r10;
	__u64 r9;
	__u64 r8;
	__u64 ax;
	__u64 cx;
	__u64 dx;
	__u64 si;
	__u64 di;
	__u64 orig_ax;
	__u64 ip;
	__u64 cs;
	__u64 flags;
	__u64 sp;
	__u64 ss;
};
#endif

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_PAYLOAD 256

struct ssl_event {
	__u32 pid;
	__u32 len;
	__u8 payload[MAX_PAYLOAD];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/*
 * SSL_write(SSL *ssl, const void *buf, int num)
 * SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written)
 * First three arguments match (buf = PARM2, len = PARM3 on x86_64 and arm64).
 * CPython 3.10+ uses SSL_write_ex only — hook both or Python HTTPS shows no events.
 */
static __always_inline int emit_ssl_plaintext(struct pt_regs *ctx)
{
	struct ssl_event *e;
	void *buf;
	long num_long;
	int num;

	buf = (void *)PT_REGS_PARM2(ctx);
	num_long = (long)PT_REGS_PARM3(ctx);

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = bpf_get_current_pid_tgid() >> 32;
	if (num_long < 0 || num_long > 0x7fffffff) {
		e->len = 0;
		bpf_ringbuf_submit(e, 0);
		return 0;
	}
	num = (int)num_long;

	if (num <= 0) {
		e->len = 0;
		bpf_ringbuf_submit(e, 0);
		return 0;
	}

	/*
	 * Strict verifiers (e.g. Linux 6.12 linuxkit): only a constant or
	 * "var & const" satisfies R2; range-split alone is not enough.
	 * Always use constant read size — matches verifier hint for bpf_probe_read_user.
	 * Truncate reported len to num (capped); payload may read past short buffers
	 * only if the mapping allows (common for heap TLS buffers).
	 */
	if (bpf_probe_read_user(e->payload, MAX_PAYLOAD, buf)) {
		e->len = 0;
	} else {
		__u32 n = (__u32)num;
		if (n > MAX_PAYLOAD)
			n = MAX_PAYLOAD;
		e->len = n;
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("uprobe")
int probe_ssl_write(struct pt_regs *ctx)
{
	return emit_ssl_plaintext(ctx);
}

SEC("uprobe")
int probe_ssl_write_ex(struct pt_regs *ctx)
{
	return emit_ssl_plaintext(ctx);
}
