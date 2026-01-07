/*
** Lua 5.3.6 Header for BPF
** Derived from Lua 5.3.6 source code
*/

#ifndef lstate_h
#define lstate_h

#include "vmlinux.h"
#include "profile.h"

typedef struct lua_State lua_State;
typedef struct lua_Debug lua_Debug;
typedef unsigned char lu_byte;
typedef signed char ls_byte;
typedef size_t lu_mem;
typedef ptrdiff_t l_mem;
typedef int sig_atomic_t;
typedef uint32_t Instruction;
typedef struct CallInfo CallInfo;
typedef uint64_t lua_Integer;
typedef double lua_Number;
typedef ptrdiff_t lua_KContext;
typedef int (*lua_CFunction) (lua_State *L);
typedef int (*lua_KFunction) (lua_State *L, int status, lua_KContext ctx);
typedef void * (*lua_Alloc) (void *ud, void *ptr, size_t osize, size_t nsize);
typedef void (*lua_Hook) (lua_State *L, lua_Debug *ar);

#define check_exp(c,e) (e)

/* Common Header */
#define CommonHeader	struct GCObject *next; lu_byte tt; lu_byte marked

/*
** In Lua 5.3, TValuefields is: Value value_; int tt_
** note the int type for tt_
*/
#define TValuefields	Value value_; int tt_

#define l_signalT sig_atomic_t
#define STRCACHE_N		53
#define STRCACHE_M		2
#define LUA_NUMTAGS		9

/*
** Bits in CallInfo status (Lua 5.3.6 lstate.h)
*/
#define CIST_OAH	(1<<0)	/* original value of 'allowhook' */
#define CIST_LUA	(1<<1)	/* call is running a Lua function */
#define CIST_HOOKED	(1<<2)	/* call is running a debug hook */
#define CIST_FRESH	(1<<3)	/* call is running on a fresh invocation of luaV_execute */
#define CIST_YPCALL	(1<<4)	/* call is a yieldable protected call */
#define CIST_TAIL	(1<<5)	/* call was tail called */
#define CIST_HOOKYIELD	(1<<6)	/* last hook called yielded */
#define CIST_LEQ	(1<<7)  /* using __lt for __le */
#define CIST_FIN	(1<<8)  /* call is running a finalizer */

/* profile.bpf.c uses isLua(ci) which checks !CIST_C in 5.4.
   In 5.3, we check CIST_LUA directly.
   But wait, the macro in 5.4 header was: #define isLua(ci) (!((ci)->callstatus & CIST_C))
   In 5.3, isLua(ci) is ((ci)->callstatus & CIST_LUA).
   We should conform to 5.3 semantics.
*/
#define isLua(ci)	((ci)->callstatus & CIST_LUA)

typedef enum {
  TM_INDEX,
  TM_NEWINDEX,
  TM_GC,
  TM_MODE,
  TM_LEN,
  TM_EQ,  /* last tag method with fast access */
  TM_ADD,
  TM_SUB,
  TM_MUL,
  TM_MOD,
  TM_POW,
  TM_DIV,
  TM_IDIV,
  TM_BAND,
  TM_BOR,
  TM_BXOR,
  TM_SHL,
  TM_SHR,
  TM_UNM,
  TM_BNOT,
  TM_LT,
  TM_LE,
  TM_CONCAT,
  TM_CALL,
  TM_N		/* number of elements in the enum */
} TMS;

typedef struct GCObject {
	CommonHeader;
} GCObject;

typedef union Value {
  struct GCObject *gc;    /* collectable objects */
  void *p;         /* light userdata */
  int b;           /* booleans */
  lua_CFunction f; /* light C functions */
  lua_Integer i;   /* integer numbers */
  lua_Number n;    /* float numbers */
} Value;

typedef struct TValue {
	TValuefields;
} TValue;

typedef struct UpVal {
  TValue *v;  /* points to stack or to its own value */
  lu_mem refcount;  /* reference counter */
  union {
    struct {  /* (when open) */
      struct UpVal *next;  /* linked list */
      int touched;  /* mark to avoid cycles with dead threads */
    } open;
    TValue value;  /* the value (when closed) */
  } u;
} UpVal;

/* Lua 5.3 TString
** In original Lua 5.3, string data is stored after the TString structure.
** We add contents[1] as a flexible array member to access it.
** Note: In 5.3, there's no 0xFF marker for long strings like in 5.4.
*/
typedef struct TString {
  CommonHeader;
  lu_byte extra;  /* reserved words for short strings; "has hash" for longs */
  lu_byte shrlen;  /* length for short strings */
  unsigned int hash;
  union {
    size_t lnglen;  /* length for long strings */
    struct TString *hnext;  /* linked list for hash table */
  } u;
  char contents[1];  /* string content starts here (flexible array) */
} TString;

typedef struct stringtable {
  TString **hash;
  int nuse;  /* number of elements */
  int size;
} stringtable;

/* StkId in 5.3 is just TValue* */
typedef TValue *StkId;

/* StkIdRel for compatibility with profile.bpf.c interface */
typedef union {
	StkId p;
} StkIdRel;

/* Lua 5.3 CallInfo */
struct CallInfo {
  StkId func;  /* function index in the stack */
  StkId	top;  /* top for this function */
  struct CallInfo *previous, *next;  /* dynamic call link */
  union {
    struct {  /* only for Lua functions */
      StkId base;  /* base for this function */
      const Instruction *savedpc;
    } l;
    struct {  /* only for C functions */
      lua_KFunction k;  /* continuation in case of yields */
      ptrdiff_t old_errfunc;
      lua_KContext ctx;  /* context info. in case of yields */
    } c;
  } u;
  ptrdiff_t extra;
  short nresults;  /* expected number of results from this function */
  unsigned short callstatus;
};

/* Lua 5.3 global_State */
typedef struct global_State {
  lua_Alloc frealloc;  /* function to reallocate memory */
  void *ud;         /* auxiliary data to 'frealloc' */
  l_mem totalbytes;  /* number of bytes currently allocated - GCdebt */
  l_mem GCdebt;  /* bytes allocated not yet compensated by the collector */
  lu_mem GCmemtrav;  /* memory traversed by the GC */
  lu_mem GCestimate;  /* an estimate of the non-garbage memory in use */
  stringtable strt;  /* hash table for strings */
  TValue l_registry;
  unsigned int seed;  /* randomized seed for hashes */
  lu_byte currentwhite;
  lu_byte gcstate;  /* state of garbage collector */
  lu_byte gckind;  /* kind of GC running */
  lu_byte gcrunning;  /* true if GC is running */
  GCObject *allgc;  /* list of all collectable objects */
  GCObject **sweepgc;  /* current position of sweep in list */
  GCObject *finobj;  /* list of collectable objects with finalizers */
  GCObject *gray;  /* list of gray objects */
  GCObject *grayagain;  /* list of objects to be traversed atomically */
  GCObject *weak;  /* list of tables with weak values */
  GCObject *ephemeron;  /* list of ephemeron tables (weak keys) */
  GCObject *allweak;  /* list of all-weak tables */
  GCObject *tobefnz;  /* list of userdata to be GC */
  GCObject *fixedgc;  /* list of objects not to be collected */
  struct lua_State *twups;  /* list of threads with open upvalues */
  unsigned int gcfinnum;  /* number of finalizers to call in each GC step */
  int gcpause;  /* size of pause between successive GCs */
  int gcstepmul;  /* GC 'granularity' */
  lua_CFunction panic;  /* to be called in unprotected errors */
  struct lua_State *mainthread;
  const lua_Number *version;  /* pointer to version number */
  TString *memerrmsg;  /* memory-error message */
  TString *tmname[TM_N];  /* array with tag-method names */
  // struct Table *mt[LUA_NUMTAGS]; -- Removing table struct usage to avoid confusion if struct Table not defined.
  // We can treat it as void* if we don't access it. But we don't access it in BPF.
  void *mt[LUA_NUMTAGS];
  TString *strcache[STRCACHE_N][STRCACHE_M];  /* cache for strings in API */
} global_State;

/* Lua 5.3 lua_State
** Note: In original Lua 5.3, StkId is just TValue* (not a union like in 5.4/5.5).
** Here we use StkIdRel (a union wrapping StkId) for compatibility with profile.bpf.c.
** Since StkIdRel = union{StkId p;}, the memory layout is identical to using StkId directly.
** Access the actual pointer via .p field.
*/
struct lua_State {
  CommonHeader;
  unsigned short nci;  /* number of items in 'ci' list */
  lu_byte status;
  StkIdRel top;  /* first free slot in the stack */
  global_State *l_G;
  CallInfo *ci;  /* call info for current function */
  const Instruction *oldpc;  /* last pc traced */
  StkIdRel stack_last;  /* last free slot in the stack */
  StkIdRel stack;  /* stack base */
  UpVal *openupval;  /* list of open upvalues in this stack */
  GCObject *gclist;
  struct lua_State *twups;  /* list of threads with open upvalues */
  struct lua_longjmp *errorJmp;  /* current error recover point */
  CallInfo base_ci;  /* CallInfo for first level (C calling Lua) */
  volatile lua_Hook hook;
  ptrdiff_t errfunc;  /* current error handling function (stack index) */
  int stacksize;
  int basehookcount;
  int hookcount;
  unsigned short nny;  /* number of non-yieldable calls in stack */
  unsigned short nCcalls;  /* number of nested C calls */
  l_signalT hookmask;
  lu_byte allowhook;
};

#define ClosureHeader \
	CommonHeader; lu_byte nupvalues; GCObject *gclist

typedef struct CClosure {
  ClosureHeader;
  lua_CFunction f;
  TValue upvalue[1];  /* list of upvalues */
} CClosure;


typedef struct LClosure {
  ClosureHeader;
  struct Proto *p;
  UpVal *upvals[1];  /* list of upvalues */
} LClosure;


typedef union Closure {
  CClosure c;
  LClosure l;
} Closure;

typedef struct Upvaldesc {
  TString *name;  /* upvalue name (for debug information) */
  lu_byte instack;  /* whether it is in stack (register) */
  lu_byte idx;  /* index of upvalue (in stack or in outer function's list) */
} Upvaldesc;

typedef struct LocVar {
  TString *varname;
  int startpc;  /* first point where variable is active */
  int endpc;    /* first point where variable is dead */
} LocVar;

/* Lua 5.3 Proto */
typedef struct Proto {
  CommonHeader;
  lu_byte numparams;  /* number of fixed parameters */
  lu_byte is_vararg;
  lu_byte maxstacksize;  /* number of registers needed by this function */
  int sizeupvalues;  /* size of 'upvalues' */
  int sizek;  /* size of 'k' */
  int sizecode;
  int sizelineinfo;
  int sizep;  /* size of 'p' */
  int sizelocvars;
  int linedefined;  /* debug information  */
  int lastlinedefined;  /* debug information  */
  TValue *k;  /* constants used by the function */
  Instruction *code;  /* opcodes */
  struct Proto **p;  /* functions defined inside the function */
  int *lineinfo;  /* map from opcodes to source lines (debug information) */
  LocVar *locvars;  /* information about local variables (debug information) */
  Upvaldesc *upvalues;  /* upvalue information */
  struct LClosure *cache;  /* last-created closure with this prototype */
  TString  *source;  /* used for debug information */
  GCObject *gclist;
} Proto;

/* Pseudo AbsLineInfo to satisfy profile.bpf.c usage if needed,
   but profile.bpf.c uses struct line_ctx which contains AbsLineInfo array.
   5.3 doesn't have AbsLineInfo in Proto.
   However, we need to define AbsLineInfo struct so BPF code compiles.
*/
typedef struct AbsLineInfo {
	int pc;
	int line;
} AbsLineInfo;

#define getproto(o)	(clLvalue(o)->p)

union GCUnion {
  GCObject gc;  /* common header */
  struct TString ts;
  /* struct Udata u;  -- not needed for BPF */
  union Closure cl;
  /* struct Table h; -- not needed */
  struct Proto p;
  struct lua_State th;  /* thread */
};

#define cast(t, exp)	((t)(exp))
#define cast_int(i)	 cast(int, (i))
#define val_(o)		((o)->value_)
#define cast_u(o)	cast(union GCUnion *, (o))
#define gco2lcl(o)  check_exp((o)->tt == LUA_TLCL, &((cast_u(o))->cl.l))
#define clLvalue(o)	gco2lcl(val_(o).gc)
#define pcRel(pc, p)	(cast_int((pc) - (p)->code) - 1)
#define ci_func(ci)	(clLvalue((ci)->func))
#define getstr(ts)	((ts)->contents)

/* Tag constants for Lua 5.3 */
#define LUA_TNONE		(-1)
#define LUA_TNIL		0
#define LUA_TBOOLEAN		1
#define LUA_TLIGHTUSERDATA	2
#define LUA_TNUMBER		3
#define LUA_TSTRING		4
#define LUA_TTABLE		5
#define LUA_TFUNCTION		6
#define LUA_TUSERDATA		7
#define LUA_TTHREAD		8
#define LUA_NUMTAGS		9

#define BIT_ISCOLLECTABLE	(1 << 6)
#define ctb(t)			((t) | BIT_ISCOLLECTABLE)

/* Lua 5.3 tag checking uses tt_ field directly */
#define rawtt(o)	((o)->tt_)
#define checktag(o,t)	(rawtt(o) == (t))

/* Variant tags */
#define LUA_TLCL	(LUA_TFUNCTION | (0 << 4))  /* Lua closure */
#define LUA_TLCF	(LUA_TFUNCTION | (1 << 4))  /* light C function */
#define LUA_TCCL	(LUA_TFUNCTION | (2 << 4))  /* C closure */

#define LUA_TSHRSTR	(LUA_TSTRING | (0 << 4))  /* short strings */
#define LUA_TLNGSTR	(LUA_TSTRING | (1 << 4))  /* long strings */

#define LUA_VSHRSTR LUA_TSHRSTR

#define ttisLclosure(o)		checktag((o), ctb(LUA_TLCL))
#define ttislcf(o)		checktag((o), LUA_TLCF)
#define ttisCclosure(o)		checktag((o), ctb(LUA_TCCL))

/* Constants for BPF consumption */
#define LUA_VLCL LUA_TLCL
#define LUA_VLCF LUA_TLCF
#define LUA_VCCL LUA_TCCL

/* String length macro */
#define tsslen(s)	((s)->tt == LUA_TSHRSTR ? (s)->shrlen : (s)->u.lnglen)

#define LUA_FILE_LEN	(64)
#define LINE_BUF_SIZE	(8)

static __always_inline int currentpc (CallInfo *ci) {
	return pcRel(ci->u.l.savedpc, ci_func(ci)->p);
}

struct line_ctx {
	//input
	int pc;
	void *ptr;
	unsigned int count;
	union {
		AbsLineInfo abslineinfo[LINE_BUF_SIZE];
		lu_byte lineinfo[LINE_BUF_SIZE];
	};
	//output
	int basepc;
	int baseline;
};

/* BPF Helper functions for Lua 5.3 */

static __always_inline void *lua_get_closure(StkIdRel stk_base, CallInfo *ci, int *ctype)
{
	void *ptr;
	int err;
	TValue val;

    /* In 5.3, ci->func is a direct pointer to TValue on stack */
	ptr = (void *)ci->func;

	DEBUG("lua_get_closure read stk:%lx", ptr);
	err = bpf_probe_read_user(&val, sizeof(val), ptr);
	if (err != 0) {
		ERROR("lua_get_closure read stk failed");
		return NULL;
	}
	*ctype = 0;
	if (ttisLclosure(&val)) {
		*ctype = LUA_TLCL;
	} else if (ttislcf(&val)) {
		*ctype = LUA_TLCF;
	} else if (ttisCclosure(&val))  {
		*ctype = LUA_TCCL;
	}
	DEBUG("lua_get_closure ci type:%d %lx", *ctype, val.value_.f);
	return (void *)val.value_.gc;
}

static __always_inline void *lua_get_proto(void *ptr, int ctype)
{
	int err;
	Closure cl;
	err = bpf_probe_read_user(&cl, sizeof(cl.l), ptr);
	if (err != 0) {
		ERROR("lua_get_proto read %d failed ptr:%lx", ctype, ptr);
		return NULL;
	}
	switch (ctype) {
	case LUA_TLCL:	//lua closure
		return cl.l.p;
	case LUA_TCCL:	//c closure
		return cl.c.f;
	default:
		ERROR("lua_get_proto unknow ctype:%d", ctype);
		return NULL;
	}
}

struct lua_proto_source {
	TString *source;	/* used for debug information */
	int linedefined;	/* debug information	*/
};

static __always_inline uint32_t lua_get_source(void *ptr, struct lua_proto_source *source)
{
	int err;
	Proto p;
	err = bpf_probe_read_user(&p, sizeof(p), ptr);
	if (err != 0) {
		ERROR("lua_get_source read proto failed:%lx", ptr);
		return err;
	}
	source->source = p.source;	/* used for debug information */
	source->linedefined = p.linedefined;	/* debug information	*/
	return 0;
}

static __always_inline void *lua_get_file(struct lua_proto_source *proto, size_t *sz)
{
	size_t n;
	TString source;
	void *ptr = proto->source;
	int err = bpf_probe_read_user(&source, offsetof(TString, contents), ptr);
	if (err != 0) {
		ERROR("lua_get_file read source failed:%lx", ptr);
		return NULL;
	}
	ptr += offsetof(TString, contents);
	*sz = tsslen(&source);
	return ptr;
}

static __always_inline void *lua_func_addr(StkIdRel stk, CallInfo *ci) {
	int err;
	void *ptr;
	int ctype;
	size_t n;
	uint32_t file_id;
	struct lua_proto_source source;
	//read stk
	ptr = lua_get_closure(stk, ci, &ctype);
	if (ptr == NULL || ctype == LUA_TLCF) {
		return ptr;
	}
	ptr = lua_get_proto(ptr, ctype);
	if (ptr == NULL) {
		return NULL;
	}
	if (ctype != LUA_TLCL) { //not a Lua closure, direct return c function addr
		return ptr;
	}
	if (lua_get_source(ptr, &source) != 0) {
		return NULL;
	}
	ptr = lua_get_file(&source, &n);
	if (ptr == NULL) {
		return NULL;
	}
	file_id = string_to_id(ptr, n);
	if (file_id == 0) {
		return NULL;
	}
	DEBUG("lua_func_addr lua:%x %x", file_id, source.linedefined);
	return MARK_LUA_ADDR((uintptr_t)source.linedefined << 32 | file_id);
}

#define lua_ci_is_fresh(ci)	((ci->callstatus & CIST_FRESH) == CIST_FRESH)

#endif