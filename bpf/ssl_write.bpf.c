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
	__u64 rbp;
	__u64 rbx;
	__u64 r11;
	__u64 r10;
	__u64 r9;
	__u64 r8;
	__u64 rax;
	__u64 rcx;
	__u64 rdx;
	__u64 rsi;
	__u64 rdi;
	__u64 orig_rax;
	__u64 rip;
	__u64 cs;
	__u64 eflags;
	__u64 rsp;
	__u64 ss;
};
#endif

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define CHUNK_SIZE 512
#define MAX_CAPTURE_BYTES 16384
#define MAX_FRAGMENTS (MAX_CAPTURE_BYTES / CHUNK_SIZE)
#define DEDUP_WINDOW_NS 2000000ULL

#define HOOK_SSL_WRITE 1
#define HOOK_SSL_WRITE_EX 2

struct ssl_event {
	__u32 pid;
	__u32 tid;
	__u32 call_id;
	__u32 orig_len;
	__u32 total_len;
	__u32 truncated;
	__u32 frag_idx;
	__u32 frag_cnt;
	__u32 chunk_len;
	__u32 hook_type;
	__u8 payload[CHUNK_SIZE];
};

struct call_state {
	__u64 last_buf;
	__u32 last_num;
	__u32 last_call_id;
	__u64 last_ts_ns;
	__u32 seq;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct call_state);
} call_states SEC(".maps");

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/*
 * SSL_write(SSL *ssl, const void *buf, int num)
 * SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written)
 * First three arguments match (buf = PARM2, len = PARM3 on x86_64 and arm64).
 * CPython 3.10+ uses SSL_write_ex only — hook both or Python HTTPS shows no events.
 */
static __always_inline __u32 next_call_id(__u64 pid_tgid, __u64 buf, __u32 num, __u64 now_ns)
{
	struct call_state *st;
	struct call_state init = {};
	__u32 call_id = 0;

	st = bpf_map_lookup_elem(&call_states, &pid_tgid);
	if (!st) {
		init.seq = 1;
		init.last_buf = buf;
		init.last_num = num;
		init.last_call_id = init.seq;
		init.last_ts_ns = now_ns;
		bpf_map_update_elem(&call_states, &pid_tgid, &init, BPF_ANY);
		return init.last_call_id;
	}

	if (st->last_buf == buf && st->last_num == num && now_ns >= st->last_ts_ns &&
	    now_ns - st->last_ts_ns <= DEDUP_WINDOW_NS) {
		call_id = st->last_call_id;
	} else {
		st->seq += 1;
		if (st->seq == 0)
			st->seq = 1;
		call_id = st->seq;
	}

	st->last_buf = buf;
	st->last_num = num;
	st->last_call_id = call_id;
	st->last_ts_ns = now_ns;
	return call_id;
}

static __always_inline int emit_ssl_plaintext(struct pt_regs *ctx, __u32 hook_type)
{
	void *buf;
	long num_long;
	int num;
	__u32 total_len;
	__u32 orig_len;
	__u32 truncated;
	__u32 frag_cnt;
	__u32 call_id;
	__u64 pid_tgid;
	__u64 now_ns;
	__u32 i;

	buf = (void *)PT_REGS_PARM2(ctx);
	num_long = (long)PT_REGS_PARM3(ctx);
	if (num_long < 0 || num_long > 0x7fffffff) {
		return 0;
	}
	num = (int)num_long;

	if (num <= 0 || !buf) {
		return 0;
	}

	orig_len = (__u32)num;
	total_len = orig_len;
	truncated = 0;
	if (total_len > MAX_CAPTURE_BYTES)
	{
		total_len = MAX_CAPTURE_BYTES;
		truncated = 1;
	}

	frag_cnt = (total_len + CHUNK_SIZE - 1) / CHUNK_SIZE;
	if (frag_cnt == 0)
		return 0;
	if (frag_cnt > MAX_FRAGMENTS)
		frag_cnt = MAX_FRAGMENTS;

	pid_tgid = bpf_get_current_pid_tgid();
	now_ns = bpf_ktime_get_ns();
	call_id = next_call_id(pid_tgid, (__u64)buf, (__u32)num, now_ns);

	/*
	 * Strict verifiers (e.g. Linux 6.12 linuxkit): only a constant or
	 * "var & const" satisfies R2; range-split alone is not enough.
	 * Always use constant read size — matches verifier hint for bpf_probe_read_user.
	 * For fragment events we still keep CHUNK_SIZE constant and truncate chunk_len.
	 */
	#pragma unroll
	for (i = 0; i < MAX_FRAGMENTS; i++) {
		struct ssl_event *e;
		__u32 offset;
		__u32 chunk_len;

		if (i >= frag_cnt)
			break;

		offset = i * CHUNK_SIZE;
		chunk_len = total_len - offset;
		if (chunk_len > CHUNK_SIZE)
			chunk_len = CHUNK_SIZE;

		e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (!e)
			break;

		e->pid = pid_tgid >> 32;
		e->tid = (__u32)pid_tgid;
		e->call_id = call_id;
		e->orig_len = orig_len;
		e->total_len = total_len;
		e->truncated = truncated;
		e->frag_idx = i;
		e->frag_cnt = frag_cnt;
		e->chunk_len = chunk_len;
		e->hook_type = hook_type;

		if (bpf_probe_read_user(e->payload, CHUNK_SIZE, (void *)((char *)buf + offset))) {
			e->chunk_len = 0;
		}
		bpf_ringbuf_submit(e, 0);
	}
	return 0;
}

SEC("uprobe")
int probe_ssl_write(struct pt_regs *ctx)
{
	return emit_ssl_plaintext(ctx, HOOK_SSL_WRITE);
}

SEC("uprobe")
int probe_ssl_write_ex(struct pt_regs *ctx)
{
	return emit_ssl_plaintext(ctx, HOOK_SSL_WRITE_EX);
}
