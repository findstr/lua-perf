#include "vmlinux.h"
#include "profile.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "lua.h"

char LICENSE[] SEC("license") = "GPL";

static __always_inline struct eh_ctx *search(u64 eip) 
{
	u32 i = 0;
	s32 key = -1;
	u32 left = 0;
	struct eh_ctx *ctx;
	u32 right = EH_FRAME_COUNT;
	while (i++ < 20 && left < right) {
		u64 *mid_eip;
		u32 mid = (left + right) / 2;
		mid_eip = bpf_map_lookup_elem(&eh_frame_header, &mid);
		if (mid_eip == NULL) {
			break;
		}
		if (*mid_eip > eip) {
			right = mid;
		} else {
			key = (s32)mid;
			left = mid + 1;
		}
	}	
	if (key == -1) {
		ERROR("search eh_frame_header fail eip:%lx", eip);
		return NULL;
	}
	ctx = bpf_map_lookup_elem(&eh_frame, &key);
	if (ctx == NULL) {
		ERROR("search eh_frame fail key:%d", key);
		return NULL;
	}
	return ctx;
}

struct lua_stack {
	u32 count;
	lua_State *L;
	lua_State *buf[MAX_STACK_DEPTH];
	u8 L_cnt;
	u8 cnt[MAX_STACK_DEPTH];
};

struct c_stk_ctx {
	u64 cfa;
	u64 rip;
	u64 rsp;
	u64 rbp;
	u64 rbx;
	struct lua_stack *lua;
	struct stack_event *event;
};

struct lua_stk_ctx {
	int calln;
	int lua_index;
	StkIdRel stack;	
	CallInfo  *ci;
	struct lua_stack *lua;
	struct stack_event *event;
};


static __always_inline u64 unwind_get(struct c_stk_ctx *ctx, int reg) {
	switch (reg) {
	case REG_RBP:
		return ctx->rbp;
	case REG_RSP:
		return ctx->rsp;
	case REG_RDI:
		return ctx->rbx;
	case REG_RA:
		return ctx->rip;
	default:
		ERROR("unwind get reg:%d unspport", reg);
		return 0;
	}
}

static __always_inline u64 unwind_reg(struct c_stk_ctx *ctx, int reg, struct eh_reg *reg_conf) {
	long ret;
	u64 ptr, val;
	switch (reg_conf->rule) {
	case Undefined:
		if (reg == REG_RA) {
			return 0;
		} else {
			return unwind_get(ctx, reg);
		}
	case SameValue:
		return unwind_get(ctx, reg);
	case Offset:	
		ptr = ctx->cfa + reg_conf->data;
		ret = bpf_probe_read_user(&val, 8, (void *)ptr);
		return (ret == 0) ? val : 0;
	case ValOffset:
		return ctx->cfa + reg_conf->data;
	case Register:
		return unwind_get(ctx, reg_conf->data);
	case Expression:
	case ValExpression:
		ERROR("unsupport rule:%d", reg_conf->rule);
		return 0;
	}
	return 0;
}



static int
unwind_c(u32 i, void *ud)
{
	struct c_stk_ctx *ctx = (struct c_stk_ctx *)ud;
	struct stack_event *event = ctx->event;
	struct lua_stack *lua = ctx->lua;
	if (i >= ARRAY_SIZE(event->ustack)) {
		return LOOP_BREAK;
	}	
	if (ctx->rip >= ctrl.lua_eip_begin && ctx->rip < ctrl.lua_eip_end) {
		lua_State *L = (lua_State *)ctx->rbx;
		if (lua->L == NULL) {
			ctx->lua->L = L;
			ctx->lua->L_cnt = 1;
		} else if (lua->L != L) {
			size_t x = (size_t)lua->count & 0xffff;
			if (x < MAX_STACK_DEPTH) {
				lua->buf[x] = lua->L;
				lua->cnt[x] = lua->L_cnt;
				lua->L = L;
				lua->L_cnt = 1;
				lua->count++;
			}
			DEBUG("unwind_c lua stack change:%lx", L);
		} else {
			ctx->lua->L_cnt++;
		}
	}
	event->ustack[i] = ctx->rip;
	event->ustack_sz++;
	struct eh_ctx *eh_ctx = search(ctx->rip);
	if (eh_ctx == NULL) {
		return LOOP_BREAK;
	}
	//DEBUG("rip1:%lx rule:%d, %d", ctx->rip, eh_ctx->cfa_reg, eh_ctx->cfa_off);
	if (eh_ctx->cfa_rule == CFA_Register) {
		switch (eh_ctx->cfa_reg) {
		case REG_RBP: //rbp
			ctx->cfa = ctx->rbp + eh_ctx->cfa_off;
			break;
		case REG_RSP: //rsp
			ctx->cfa = ctx->rsp + eh_ctx->cfa_off;
			break;
		default:
			ERROR("unsupport cfa_reg:%d", eh_ctx->cfa_reg);
			break;
		}
	} else {
		ERROR("unsupport cfa_rule:%d", eh_ctx->cfa_rule);
		return LOOP_BREAK;
	}
	ctx->rbp = unwind_reg(ctx, REG_RBP, &eh_ctx->regs[REG_RBP]);
	PRINT_REG_RULE(eh_ctx, REG_RDI);
	ctx->rbx = unwind_reg(ctx, REG_RDI, &eh_ctx->regs[REG_RBX]);
	ctx->rip = unwind_reg(ctx, REG_RA, &eh_ctx->regs[REG_RA]);
	ctx->rsp = ctx->cfa;
	if (ctx->rip == 0) 
		return LOOP_BREAK;
	return LOOP_CONTINUE;
}

struct foo_iter {
	struct stack_event *event;
};

static int foo_memcpy_iter(int i, void *ud)
{
	char n;
	struct foo_iter *iter = (struct foo_iter *)ud;
	struct stack_event *event = iter->event;
	if (i >= ARRAY_SIZE(event->ustack)) {
		return LOOP_BREAK;
	}	
	event->ustack[i] = (uintptr_t)ud;
	event->ustack_sz++;
	return LOOP_CONTINUE;
}

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
    	__type(value, CallInfo);
	__uint(max_entries, 1);
} tmp_call_info SEC(".maps");

DECLARE_TMP_VAR(CallInfo, ci);

static __always_inline int lua_ci_stk(void *ptr, CallInfo **ci, StkIdRel *stk) {
	lua_State L;
	int err = bpf_probe_read_user(&L, sizeof(L), ptr);
	if (err == 0) {
		*ci = L.ci;
		*stk = L.stack;
	} else {
		ERROR("lua_ci_stk read L error:%d", err);
	}
	return err;
}

static int
unwind_lua(u32 i, void *ud) 
{
	int err;
	void *addr;
	u32 zero = 0;
	FETCH_TMP_VAR(CallInfo, ci, LOOP_BREAK);
	struct lua_stk_ctx *ctx = (struct lua_stk_ctx *)ud;
	DEBUG("----unwind_lua ci:%lx", ctx->ci);
	if ((ctx->event->lstack_sz & 0xffff) >= ARRAY_SIZE(ctx->event->lstack)) {
		return LOOP_BREAK;
	}	
	if (ctx->ci == NULL) {
		DEBUG("unwind_lua read ci:%d", ctx->lua_index);
		size_t i = (size_t)ctx->lua_index & 0xffff;
		if (i >= ctx->lua->count || i > MAX_STACK_DEPTH) {
			return LOOP_BREAK;
		}
		lua_State *L = ctx->lua->buf[i];
		ctx->calln = ctx->lua->cnt[i];
		DEBUG("unwind_lua begin ci:%d calln:%d", ctx->lua_index, ctx->calln);
		int err = lua_ci_stk(L, &ctx->ci, &ctx->stack);
		if (err != 0) {
			DEBUG("unwind_lua read L error:%d", err);
			return LOOP_BREAK;
		} 
		ctx->lua_index++;
	}
	err = bpf_probe_read_user(ci, sizeof(*ci), (void *)ctx->ci);
	if (err != 0) {
		ERROR("unwind_lua read ci error:%d", err);
		return LOOP_BREAK;
	}
	addr = lua_func_addr(ctx->stack, ci);
	if (addr == NULL) {
		ctx->ci = NULL;
		DEBUG("unwind_lua lua_func_addr fail:%lx", ctx->ci);
		return LOOP_CONTINUE;
	}
	DEBUG("unwind_lua i:%d luaV_execute :%lx calln:%d prev:%lx", i, addr, ctx->calln, ci->previous);
	size_t j = (size_t)ctx->event->lstack_sz & 0xffff;
	if (j < ARRAY_SIZE(ctx->event->lstack)) {
		ctx->event->lstack[j] = (u64)addr;
		ctx->event->lstack_sz++;
	}
	j = (size_t)ctx->event->lstack_sz & 0xffff;
	if (j < ARRAY_SIZE(ctx->event->lstack) && lua_ci_is_fresh(ci)) {
		ctx->event->lstack[j] = 0;
		ctx->event->lstack_sz++;
		if (--ctx->calln <= 0) {
			ci->previous = NULL;
		}
	}
		ctx->ci = ci->previous;
	return LOOP_CONTINUE;
}

DECLARE_TMP_VAR(struct stack_event, stack_event);
DECLARE_TMP_VAR(struct lua_stack, lua_stack);

SEC("perf_event")
int profile(struct bpf_perf_event_data *perf_ctx)
{
	FETCH_TMP_VAR(struct stack_event, stack_event, 1)
	FETCH_TMP_VAR(struct lua_stack, lua_stack, 1)
	union {
		struct bpf_pidns_info ns;
		struct c_stk_ctx c;
		struct lua_stk_ctx l;
	} ctx;
	bpf_get_ns_current_pid_tgid(ctrl.dev, ctrl.ino, &ctx.ns, sizeof(ctx.ns));
	if (ctx.ns.tgid != (u32)ctrl.target_pid)
		return 0;
	u32 zero = 0;
	u32 pid = ctx.ns.pid;
	int cpu_id = bpf_get_smp_processor_id();
	stack_event->pid = pid;
	stack_event->cpu_id = cpu_id;
	if (bpf_get_current_comm(stack_event->comm, sizeof(stack_event->comm)))
		stack_event->comm[0] = 0;
	stack_event->kstack_sz = bpf_get_stack(perf_ctx, stack_event->kstack, sizeof(stack_event->kstack), 0);
	bpf_user_pt_regs_t *regs = &perf_ctx->regs;
	if (in_kernel(PT_REGS_IP(regs))) {
		if (!retrieve_task_registers(&ctx.c.rip, &ctx.c.rsp, &ctx.c.rbp, &ctx.c.rbx)) {
			return 1;
		}
	} else {
		ctx.c.rip = PT_REGS_IP(regs);
		ctx.c.rsp = PT_REGS_SP(regs);
		ctx.c.rbp = PT_REGS_FP(regs);
		//TODO: portable
		ctx.c.rbx = regs->bx;
	}
	ctx.c.cfa = ctx.c.rsp;
	ctx.c.lua = lua_stack;
	ctx.c.event = stack_event;
	stack_event->ustack_sz = 0;
	lua_stack->L = NULL;
	lua_stack->L_cnt = 0;
	lua_stack->count = 0;
	//unwind user space
	DEBUG("---------profile unwind start:%lx", ctx.c.rip);
	long n = bpf_loop(MAX_STACK_DEPTH, unwind_c, &ctx, 0);
	DEBUG("---------profile unwind end:%lx", ctx.c.rip);
	if (n > 0) {
		stack_event->ustack_sz *= sizeof(u64);
	} else {
		ERROR("profile unwind loop fail:%d", n);
	}
	//unwind lua_State
	if (ctx.c.lua->L != NULL && (ctx.c.lua->count & 0xffff) < MAX_STACK_DEPTH) {
		int i = ctx.c.lua->count & 0xffff;
		ctx.c.lua->buf[i] = ctx.c.lua->L;
		ctx.c.lua->cnt[i] = ctx.c.lua->L_cnt;
		ctx.c.lua->count++;
	}
	stack_event->lstack_sz = 0;
	DEBUG("profile unwind lua count:%d", ctx.c.lua->count);
	if (ctx.c.lua->count > 0) {
		ctx.l.lua_index = 0;
		ctx.l.lua = lua_stack;
		ctx.l.ci = NULL;
		ctx.l.event = stack_event;
		n = bpf_loop(MAX_STACK_DEPTH, unwind_lua, &ctx.l, 0);
		stack_event->lstack_sz *= sizeof(u64);
	}
	stack_event->stk_id = get_stack_id(stack_event);
	#if LOG_LEVEL <= LOG_DEBUG
	struct stack_event *new_event = bpf_ringbuf_reserve(&events, sizeof(*stack_event), 0);
	if (!new_event)
		return 1;
	new_event->event_type = EVENT_TRACE;
	new_event->pid = stack_event->pid;
	new_event->cpu_id = stack_event->cpu_id;
	new_event->comm[0] = stack_event->comm[0];
	new_event->kstack_sz = stack_event->kstack_sz;
	new_event->ustack_sz = stack_event->ustack_sz;
	new_event->lstack_sz = stack_event->lstack_sz;
	new_event->stk_id = stack_event->stk_id;
	for (int i = 0; i < MAX_STACK_DEPTH; i++) {
		new_event->kstack[i] = stack_event->kstack[i];
		new_event->ustack[i] = stack_event->ustack[i];
		new_event->lstack[i] = stack_event->lstack[i];
	}
	bpf_ringbuf_submit(new_event, 0);
	#endif
	return 0;
}