#ifndef _PROFILE_H
#define _PROFILE_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "hash.h"

#define LOG_DEBUG		1
#define LOG_INFO		2
#define LOG_ERROR		3
#define LOG_LEVEL		LOG_ERROR

#define LOOP_CONTINUE		(0)
#define LOOP_BREAK		(1)
#define ARRAY_SIZE(a)		(sizeof(a) / sizeof(a[0]))
u32 ZERO = 0;
u32 STRINGS_MAP_SIZE;
u32 STACKS_MAP_SIZE;
u32 EH_FRAME_COUNT;
#define STR_MAX_SIZE		(64)

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef MAX_STACK_DEPTH
#define MAX_STACK_DEPTH 128
#endif

enum {
	REG_RBX = 3,
	REG_RDI = 5,
	REG_RBP = 6,
	REG_RSP = 7,
	REG_RA = 16,
	REG_COUNT,
};

#define LUA_ADDR  (1ull << 63)

#define MARK_LUA_ADDR(a)	((void *)((uintptr_t)(a) | LUA_ADDR))

#ifndef memcmp
#define memcmp(s1, s2, n) __builtin_memcmp((s1), (s2), (n))
#endif

#ifndef memset
#define memset(dest, chr, n)   __builtin_memset((dest), (chr), (n))
#endif

#ifndef memcpy
#define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
#define memmove(dest, src, n)  __builtin_memmove((dest), (src), (n))
#endif

#if LOG_LEVEL <= LOG_DEBUG
	#define DEBUG(...)	bpf_printk("D "__VA_ARGS__)
#else
	#define DEBUG(...)	(void)0
#endif

#if LOG_LEVEL <= LOG_INFO
	#define INFO(...)	bpf_printk("I "__VA_ARGS__)
#else
	#define INFO(...)	(void)0
#endif

#if LOG_LEVEL <= LOG_ERROR
	#define ERROR(...)	bpf_printk("E "__VA_ARGS__)
#else
	#define ERROR(...)	(void)0
#endif

#define DECLARE_TMP_VAR(typ, name)	\
struct {\
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); \
	__type(key, u32); \
    	__type(value, typ); \
	__uint(max_entries, 1); \
} tmp_##name SEC(".maps")

#define	FETCH_TMP_VAR(typ, name, ret)	 \
	typ *name = bpf_map_lookup_elem(&tmp_##name, &ZERO); \
	if (name == NULL) \
		return ret;

enum event_type {
	EVENT_NONE = 0,
	EVENT_TRACE = 1,
	EVENT_STACK = 2,
	EVENT_STRING = 3,
};

enum reg_rule {
	Undefined = 0,
	SameValue = 1,
	Offset = 2,
	ValOffset = 3,
	Register = 4,
	Expression = 5,
	ValExpression = 6,
};

enum cfa_rule {
	CFA_Undefined = 0,
	CFA_Register = 2,
	CFA_Expression = 3,
};

typedef __u64 call_stack_t[MAX_STACK_DEPTH];

struct stack_event {
	u8 event_type;
	u32 pid;
	u32 cpu_id;
	u32 stk_id;
	char comm[TASK_COMM_LEN];
	s32 kstack_sz;
	s32 ustack_sz;
	s32 lstack_sz;
	call_stack_t kstack;
	call_stack_t ustack;
	call_stack_t lstack;
};

struct stack_count {
	u8 event_type;
	u32 id;
	u32 ver;
	u32 count;
	u32 hash;
	s32 kstack_sz;
	s32 ustack_sz;
	s32 lstack_sz;
	call_stack_t kstack;
	call_stack_t ustack;
	call_stack_t lstack;
};

struct string {
	u8 event_type;
	u8 len;
	u32 id;
	u32 ver;
	u32 hash;
	char data[STR_MAX_SIZE];
};

struct eh_reg {
	enum reg_rule rule;
	s32 data;
};

typedef struct eh_ctx {
	u64 eip;
	u32 size;
	enum cfa_rule cfa_rule;
	u32 cfa_reg;
	s64 cfa_off;
	struct eh_reg regs[REG_COUNT];
} eh_ctx;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u64);
} eh_frame_header SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, eh_ctx);
} eh_frame SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
    	__type(value, struct string);
} strings SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
    	__type(value, struct stack_count);
} stacks SEC(".maps");

struct fn_var_pos {
	u64 eip_begin;
	u64 eip_end;
	bool is_mem;
	u8  reg;	//reg id
	s32 disp;	//disp value
};

struct ctrl {
	u64 lua_eip_begin;
	u64 lua_eip_end;
	struct fn_var_pos lua_var_pos[3];
	pid_t target_pid;
	unsigned long long dev;
	unsigned long long ino;
};

struct ctrl ctrl;

// Dummy instance to get skeleton to generate definition for `struct event`
union {
	enum event_type _x1;
	struct eh_ctx _x2;
	struct stack_event _x3;
	struct stack_count _x4;
	struct string _x5;
} dummy;

struct str_cache_ctx {
	const struct string *src;
	struct string *dst;
};

static int str_cache_cpy_iter(int i, void *ud)
{
	struct str_cache_ctx *ctx = (struct str_cache_ctx *)ud;
	const struct string *src = ctx->src;
	struct string *dst = ctx->dst;
	size_t n = (size_t)i & 0xffff;
	if (n >= ARRAY_SIZE(dst->data)) {
		return LOOP_BREAK;
	}
	if (n >= ARRAY_SIZE(src->data)) {
		return LOOP_BREAK;
	}
	dst->data[n] = src->data[n];
	return LOOP_CONTINUE;
}

static int str_cache_cmp_iter(int i, void *ud)
{
	char a, b;
	struct str_cache_ctx *ctx = (struct str_cache_ctx *)ud;
	const struct string *src = ctx->src;
	struct string *dst = ctx->dst;
	size_t n = (size_t)i & 0xffff;
	if (n >= ARRAY_SIZE(dst->data)) {
		return LOOP_BREAK;
	}
	if (n >= ARRAY_SIZE(src->data)) {
		return LOOP_BREAK;
	}
	a = src->data[n];
	b = dst->data[n];
	return (a != b) ? LOOP_BREAK : LOOP_CONTINUE;
}

static __always_inline bool cache_str_cmp_eq(struct string *a, struct string *b)
{
	u32 zero = 0;
	if (a->len != b->len || a->hash != b->hash) {
		return false;
	}
	struct str_cache_ctx ctx = {
		.src = a,
		.dst = b,
	};
	size_t cmp_count = a->len + 1;
	return (bpf_loop(a->len + 1, str_cache_cmp_iter, &ctx, 0) == (a->len + 1));
}

static __always_inline void cache_str_cpy(struct string *dst, const struct string *src)
{
	dst->len = src->len;
	dst->hash = src->hash;
	struct str_cache_ctx ctx = {
		.src = src,
		.dst = dst,
	};
	bpf_loop(dst->len, str_cache_cpy_iter, &ctx, 0);
}

DECLARE_TMP_VAR(struct string, str_buf);
static __always_inline u32 string_to_id(char *str, u32 len)
{
	int err;
	u32 hash, i;
	struct string *cache;
	FETCH_TMP_VAR(struct string, str_buf, 0)
	if (len > sizeof(str_buf->data)) {
		 str += len - sizeof(str_buf->data);
		 len = sizeof(str_buf->data);
	}
	len &= 0xfffff;
	str_buf->len = len;
	err = bpf_probe_read_user(str_buf->data, str_buf->len, str);
	if (err != 0) {
		ERROR("string_to_id read string fail");
		return 0;
	}
	str_buf->hash = (u32)((uintptr_t)str);
	i = str_buf->hash % STRINGS_MAP_SIZE;
	cache = (struct string *)bpf_map_lookup_elem(&strings, &i);
	if (cache == NULL) {
		ERROR("string_to_id cache:%d is NULL", i);
		return 0;
	}
	if (cache_str_cmp_eq(cache, str_buf)) {
		DEBUG("string_to_id i:%d, len:%u id:%d", i, cache->len, cache->id);
		return cache->id;
	}
	if (cache->id != 0) { //skip the first empty cache
		struct string *event;
		event = (struct string *)bpf_ringbuf_reserve(&events, sizeof(*event), 0);
		if (event == NULL) {
			bpf_printk("string_to_id: alloc ringbuf  for '%s' fail", str);
			return 0;
		}
		*event = *cache;
		event->event_type = EVENT_STRING;
		bpf_ringbuf_submit(event, 0);
	}
	cache_str_cpy(cache, str_buf);
	cache->ver++;
	cache->id = cache->ver * STRINGS_MAP_SIZE + i;
	DEBUG("string_to_id i:%d, len:%u id:%d", i, cache->len, cache->id);
	return cache->id;
}

struct stack_ctx {
	const struct stack_event *stk;
	struct stack_count *counter;
};

static int stack_cmp_iter(int i, void *ud)
{
	u64 a, b;
	struct stack_ctx *ctx = (struct stack_ctx *)ud;
	size_t n = (size_t)i & 0xffff;
	if (n >= MAX_STACK_DEPTH) {
		return LOOP_BREAK;
	}
	if (n < ctx->stk->kstack_sz && ctx->stk->kstack[n] != ctx->counter->kstack[n]) {
		return LOOP_BREAK;
	}
	if (n < ctx->stk->ustack_sz && ctx->stk->ustack[n] != ctx->counter->ustack[n]) {
		return LOOP_BREAK;
	}
	if (n < ctx->stk->lstack_sz && ctx->stk->lstack[n] != ctx->counter->lstack[n]) {
		return LOOP_BREAK;
	}
	return LOOP_CONTINUE;
}

static int stack_cpy_iter(int i, void *ud)
{
	u64 a, b;
	struct stack_ctx *ctx = (struct stack_ctx *)ud;
	size_t n = (size_t)i & 0xffff;
	if (n >= MAX_STACK_DEPTH) {
		return LOOP_BREAK;
	}
	if (n < ctx->stk->kstack_sz) {
		ctx->counter->kstack[n] = ctx->stk->kstack[n];
	}
	if (n < ctx->stk->ustack_sz) {
		ctx->counter->ustack[n] = ctx->stk->ustack[n];
	}
	if (n < ctx->stk->lstack_sz) {
		ctx->counter->lstack[n] = ctx->stk->lstack[n];
	}
	return LOOP_CONTINUE;
}

static __always_inline bool stack_cmp_eq(struct stack_count *counter, struct stack_event *stk, u32 stk_hash)
{
	if (
		counter->hash != stk_hash ||
		counter->kstack_sz != stk->kstack_sz ||
		counter->ustack_sz != stk->ustack_sz ||
		counter->lstack_sz != stk->lstack_sz) {
		return false;
	}
	struct stack_ctx ctx = {
		.stk = stk,
		.counter = counter,
	};
	u32 n = stk->kstack_sz;
	if (n < stk->ustack_sz) {
		n = stk->ustack_sz;
	}
	if (n < stk->lstack_sz) {
		n = stk->lstack_sz;
	}
	 n = n / sizeof(u64) + 1;
	return bpf_loop(n, stack_cmp_iter, &ctx, 0) == n;
}

static __always_inline void stack_cpy(struct stack_count *counter, struct stack_event *stk)
{
	counter->kstack_sz = stk->kstack_sz;
	counter->ustack_sz = stk->ustack_sz;
	counter->lstack_sz = stk->lstack_sz;
	struct stack_ctx ctx = {
		.stk = stk,
		.counter = counter,
	};
	u32 n = stk->kstack_sz;
	if (n < stk->ustack_sz) {
		n = stk->ustack_sz;
	}
	if (n < stk->lstack_sz) {
		n = stk->lstack_sz;
	}
	bpf_loop(n, stack_cpy_iter, &ctx, 0);
}

static __always_inline u32 get_stack_id(struct stack_event *event)
{
	u32 hash = 0;
	struct stack_count *counter;
	hash = murmur_hash2((u32 *)event->kstack, event->kstack_sz / sizeof(u32), hash);
	hash = murmur_hash2((u32 *)event->ustack, event->ustack_sz / sizeof(u32), hash);
	hash = murmur_hash2((u32 *)event->lstack, event->lstack_sz / sizeof(u32), hash);
	u32 i = hash % STACKS_MAP_SIZE;
	counter = bpf_map_lookup_elem(&stacks, &i);
	if (counter == NULL) {
		ERROR("get_stack_id counter:%d is NULL", hash);
		return 0;
	}
	DEBUG("get_stack_id %u, i:%d h:%u", hash, i, counter->hash);
	if (stack_cmp_eq(counter, event, hash)) {
		counter->count++;
		DEBUG("get_stack_id id:%d count:%d", counter->id, counter->count);
		return counter->id;
	}
	if (counter->id != 0) {
		struct stack_count *event;
		event = (struct stack_count *)bpf_ringbuf_reserve(&events, sizeof(*event), 0);
		if (event == NULL) {
			ERROR("get_stack_id alloc ringbuf fail");
			return 0;
		}
		event->event_type = EVENT_STACK;
		event->id = counter->id;
		event->count = counter->count;
		event->hash = counter->hash;
		event->kstack_sz = counter->kstack_sz;
		event->ustack_sz = counter->ustack_sz;
		event->lstack_sz = counter->lstack_sz;
		memcpy(event->kstack, counter->kstack, MAX_STACK_DEPTH * sizeof(u64));
		memcpy(event->ustack, counter->ustack, MAX_STACK_DEPTH * sizeof(u64));
		memcpy(event->lstack, counter->lstack, MAX_STACK_DEPTH * sizeof(u64));
		bpf_ringbuf_submit(event, 0);
	}
	counter->ver++;
	counter->id = counter->ver * STACKS_MAP_SIZE + i;
	counter->count = 1;
	counter->hash = hash;
	stack_cpy(counter, event);
	DEBUG("get_stack_id stack i:%d id:%d count:%d", i, counter->id, counter->count);
	return counter->id;
}

// Values for x86_64 as of 6.0.18-200.
#define TOP_OF_KERNEL_STACK_PADDING 0
#define THREAD_SIZE_ORDER 2
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define THREAD_SIZE (PAGE_SIZE << THREAD_SIZE_ORDER)

// Kernel addresses have the top bits set.
static __always_inline bool in_kernel(u64 ip) {
  return ip & (1UL << 63);
}

// kthreads mm's is not set.
// We don't check for the return value of `retrieve_task_registers`, it's
// caller due the verifier not liking that code.
static __always_inline bool is_kthread() {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  if (task == NULL) {
    return false;
  }
  void *mm;
  int err = bpf_probe_read_kernel(&mm, 8, &task->mm);
  if (err) {
    ERROR("is_kthread bpf_probe_read_kernel failed with %d", err);
    return false;
  }
  return mm == NULL;
}

// avoid R0 invalid mem access 'scalar'
// Port of `task_pt_regs` in BPF.
static __always_inline bool retrieve_task_registers(u64 *ip, u64 *sp, u64 *bp, u64 *rbx) {
	int err;
	void *stack;
	if (ip == NULL || sp == NULL || bp == NULL) {
		return false;
	}
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (task == NULL) {
		return false;
	}
	if (is_kthread()) {
		return false;
	}

 	err = bpf_probe_read_kernel(&stack, 8, &task->stack);
	if (err) {
		ERROR("retrieve_task_registers bpf_probe_read_kernel failed with %d", err);
		return false;
	}
	void *ptr = stack + THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING;
	struct pt_regs *regs = ((struct pt_regs *)ptr) - 1;

	*ip = PT_REGS_IP_CORE(regs);
	*sp = PT_REGS_SP_CORE(regs);
	*bp = PT_REGS_FP_CORE(regs);
	*rbx = BPF_CORE_READ(regs, bx);
	return true;
}

#endif
