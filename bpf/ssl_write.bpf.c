// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// uprobe on OpenSSL SSL_write - plaintext before encryption (streaming, no default size cap).

#include <linux/bpf.h>
#include <linux/types.h>

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
/* Kernel bpf_loop hard limit is 1<<23; keep headroom for ringbuf pressure. */
#define BPF_LOOP_MAX (1u << 20)
#define DEDUP_WINDOW_NS 2000000ULL

#define HOOK_SSL_WRITE 1
#define HOOK_SSL_WRITE_EX 2
#define HOOK_GO_TLS_WRITE 3

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

/* config[0] = optional max capture bytes; 0 = unlimited (default). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 25);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct call_state);
} call_states SEC(".maps");

struct emit_ctx {
	const char *buf;
	__u64 pid_tgid;
	__u32 call_id;
	__u32 orig_len;
	__u32 total_len;
	__u32 truncated;
	__u32 frag_cnt;
	__u32 hook_type;
};

char LICENSE[] SEC("license") = "Dual MIT/GPL";

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

static __always_inline __u32 optional_max_capture(void)
{
	__u32 key = 0;
	__u32 *v = bpf_map_lookup_elem(&config_map, &key);
	if (!v)
		return 0;
	return *v;
}

static long emit_one_frag(__u32 index, void *data)
{
	struct emit_ctx *c = data;
	struct ssl_event *e;
	__u32 offset;
	__u32 chunk_len;

	if (index >= c->frag_cnt)
		return 1;

	offset = index * CHUNK_SIZE;
	chunk_len = c->total_len - offset;
	if (chunk_len > CHUNK_SIZE)
		chunk_len = CHUNK_SIZE;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		c->truncated = 1;
		return 1;
	}

	e->pid = c->pid_tgid >> 32;
	e->tid = (__u32)c->pid_tgid;
	e->call_id = c->call_id;
	e->orig_len = c->orig_len;
	e->total_len = c->total_len;
	e->truncated = c->truncated;
	e->frag_idx = index;
	e->frag_cnt = c->frag_cnt;
	e->chunk_len = chunk_len;
	e->hook_type = c->hook_type;

	if (bpf_probe_read_user(e->payload, CHUNK_SIZE, (void *)(c->buf + offset))) {
		e->chunk_len = 0;
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline int emit_from_buf(const void *buf, long num_long, __u32 hook_type)
{
	__u32 total_len;
	__u32 orig_len;
	__u32 truncated;
	__u32 frag_cnt;
	__u32 call_id;
	__u32 max_cap;
	__u64 pid_tgid;
	__u64 now_ns;
	__u64 frag64;
	struct emit_ctx ec = {};
	int num;

	if (num_long < 0 || num_long > 0x7fffffff)
		return 0;
	num = (int)num_long;
	if (num <= 0 || !buf)
		return 0;

	orig_len = (__u32)num;
	total_len = orig_len;
	truncated = 0;

	max_cap = optional_max_capture();
	if (max_cap > 0 && total_len > max_cap) {
		total_len = max_cap;
		truncated = 1;
	}

	frag64 = ((__u64)total_len + CHUNK_SIZE - 1) / CHUNK_SIZE;
	if (frag64 == 0)
		return 0;
	if (frag64 > BPF_LOOP_MAX) {
		frag_cnt = BPF_LOOP_MAX;
		total_len = BPF_LOOP_MAX * CHUNK_SIZE;
		truncated = 1;
	} else {
		frag_cnt = (__u32)frag64;
	}

	pid_tgid = bpf_get_current_pid_tgid();
	now_ns = bpf_ktime_get_ns();
	call_id = next_call_id(pid_tgid, (__u64)buf, (__u32)num, now_ns);

	ec.buf = (const char *)buf;
	ec.pid_tgid = pid_tgid;
	ec.call_id = call_id;
	ec.orig_len = orig_len;
	ec.total_len = total_len;
	ec.truncated = truncated;
	ec.frag_cnt = frag_cnt;
	ec.hook_type = hook_type;

	bpf_loop(frag_cnt, emit_one_frag, &ec, 0);
	return 0;
}

static __always_inline int emit_ssl_plaintext(struct pt_regs *ctx, __u32 hook_type)
{
	void *buf = (void *)PT_REGS_PARM2(ctx);
	long num_long = (long)PT_REGS_PARM3(ctx);
	return emit_from_buf(buf, num_long, hook_type);
}

/*
 * Go register ABI (1.17+): method (c *Conn).Write(b []byte)
 * amd64: AX=recv, BX=ptr, CX=len, DI=cap
 * arm64: R0=recv, R1=ptr, R2=len, R3=cap
 */
SEC("uprobe")
int probe_go_tls_write(struct pt_regs *ctx)
{
	void *buf;
	long num;

#if defined(__TARGET_ARCH_x86)
	buf = (void *)ctx->rbx;
	num = (long)ctx->rcx;
#elif defined(__TARGET_ARCH_arm64)
	{
		struct user_pt_regs *uregs = (struct user_pt_regs *)ctx;
		buf = (void *)uregs->regs[1];
		num = (long)uregs->regs[2];
	}
#else
	return 0;
#endif
	return emit_from_buf(buf, num, HOOK_GO_TLS_WRITE);
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
