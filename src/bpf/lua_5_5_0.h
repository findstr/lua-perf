/*
** Lua 5.5.0 Header for BPF
** Derived from Lua 5.5.0 source code
*/

#ifndef lstate_h
#define lstate_h

#include "vmlinux.h"
#include "profile.h"

typedef struct lua_State lua_State;
typedef struct lua_Debug lua_Debug;
typedef unsigned char lu_byte;
typedef signed char ls_byte;
typedef u32 l_uint32;
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
typedef void (*lua_WarnFunction) (void *ud, const char *msg, int tocont);
typedef void (*lua_Hook) (lua_State *L, lua_Debug *ar);

#define check_exp(c,e) (e)

/* Common Header */
#define CommonHeader	struct GCObject *next; lu_byte tt; lu_byte marked

/* TValuefields from 5.5.0 lobject.h */
#define TValuefields	Value value_; lu_byte tt_

#define l_signalT sig_atomic_t
#define STRCACHE_N		53
#define STRCACHE_M		2
#define LUA_NUMTYPES		9
#define LUA_EXTRASPACE		(sizeof(void *))
#define LUA_GCPN		6
#define TM_N		25

/*
** Bits in CallInfo status (Lua 5.5.0 lstate.h)
*/
#define CIST_NRESULTS	0xffu
#define CIST_CCMT	8
#define MAX_CCMT	(0xfu << CIST_CCMT)
#define CIST_RECST	12
#define CIST_C		(1u << (CIST_RECST + 3))
#define CIST_FRESH	(cast(l_uint32, CIST_C) << 1)
#define CIST_CLSRET	(CIST_FRESH << 1)
#define CIST_TBC	(CIST_CLSRET << 1)
#define CIST_OAH	(CIST_TBC << 1)
#define CIST_HOOKED	(CIST_OAH << 1)
#define CIST_YPCALL	(CIST_HOOKED << 1)
#define CIST_TAIL	(CIST_YPCALL << 1)
#define CIST_HOOKYIELD	(CIST_TAIL << 1)
#define CIST_FIN	(CIST_HOOKYIELD << 1)

#define isLua(ci)	(!((ci)->callstatus & CIST_C))

typedef struct GCObject {
	CommonHeader;
} GCObject;

typedef union Value {
  struct GCObject *gc;    /* collectable objects */
  void *p;         /* light userdata */
  lua_CFunction f; /* light C functions */
  lua_Integer i;   /* integer numbers */
  lua_Number n;    /* float numbers */
  lu_byte ub;
} Value;

typedef struct TValue {
	TValuefields;
} TValue;

/* Forward declaration for Node */
union LuaNode;
typedef union LuaNode LuaNode;

typedef struct Table {
  CommonHeader;
  lu_byte flags;
  lu_byte lsizenode;
  unsigned int asize;
  Value *array;
  LuaNode *node;
  struct Table *metatable;
  GCObject *gclist;
} Table;

/* Nodes for Hash tables */
union LuaNode {
  struct NodeKey {
    TValuefields;  /* fields for value */
    lu_byte key_tt;  /* key type */
    int next;  /* for chaining */
    Value key_val;  /* key value */
  } u;
  TValue i_val;  /* direct access to node's value as a proper 'TValue' */
};

typedef struct UpVal {
  CommonHeader;
  union {
    TValue *p;  /* points to stack or to its own value */
    ptrdiff_t offset;  /* used while the stack is being reallocated */
  } v;
  union {
    struct {  /* (when open) */
      struct UpVal *next;  /* linked list */
      struct UpVal **previous;
    } open;
    TValue value;  /* the value (when closed) */
  } u;
} UpVal;

/* Kinds of long strings (stored in 'shrlen') */
#define LSTRREG		-1  /* regular long string */
#define LSTRFIX		-2  /* fixed external long string */
#define LSTRMEM		-3  /* external long string with deallocation */

/* Lua 5.5 TString
** In 5.5, shrlen >= 0 means short string (shrlen is the length)
** shrlen < 0 means long string (shrlen indicates kind: LSTRREG/LSTRFIX/LSTRMEM)
** For short strings, content starts at &ts->contents (the address of the pointer field)
** For long strings, content is at ts->contents (the pointer value)
*/
typedef struct TString {
  CommonHeader;
  lu_byte extra;  /* reserved words for short strings; "has hash" for longs */
  ls_byte shrlen;  /* length for short strings, negative for long strings */
  unsigned int hash;
  union {
    size_t lnglen;  /* length for long strings */
    struct TString *hnext;  /* linked list for hash table */
  } u;
  char *contents;  /* pointer to content in long strings; short strings start here */
  lua_Alloc falloc;  /* deallocation function for external strings */
  void *ud;  /* user data for external strings */
} TString;

/* Check if string is short */
#define strisshr(ts)	((ts)->shrlen >= 0)

typedef struct stringtable {
  TString **hash;
  int nuse;  /* number of elements */
  int size;
} stringtable;

typedef union StackValue {
  TValue val;
  struct {
    TValuefields;
    unsigned short delta;
  } tbclist;
} StackValue;

typedef StackValue *StkId;

typedef union {
  StkId p;  /* actual pointer */
  ptrdiff_t offset;  /* used while the stack is being reallocated */
} StkIdRel;

/* Lua 5.5 CallInfo */
struct CallInfo {
  StkIdRel func;  /* function index in the stack */
  StkIdRel top;  /* top for this function */
  struct CallInfo *previous, *next;  /* dynamic call link */
  union {
    struct {  /* only for Lua functions */
      const Instruction *savedpc;
      volatile l_signalT trap;  /* function is tracing lines/counts */
      int nextraargs;  /* # of extra arguments in vararg functions */
    } l;
    struct {  /* only for C functions */
      lua_KFunction k;  /* continuation in case of yields */
      ptrdiff_t old_errfunc;
      lua_KContext ctx;  /* context info. in case of yields */
    } c;
  } u;
  union {
    int funcidx;  /* called-function index */
    int nyield;  /* number of values yielded */
    int nres;  /* number of values returned */
  } u2;
  l_uint32 callstatus;
};

typedef struct global_State {
  lua_Alloc frealloc;  /* function to reallocate memory */
  void *ud;         /* auxiliary data to 'frealloc' */
  l_mem GCtotalbytes;  /* number of bytes currently allocated + debt */
  l_mem GCdebt;  /* bytes counted but not yet allocated */
  l_mem GCmarked;  /* number of objects marked in a GC cycle */
  l_mem GCmajorminor;  /* auxiliary counter to control major-minor shifts */
  stringtable strt;  /* hash table for strings */
  TValue l_registry;
  TValue nilvalue;  /* a nil value */
  unsigned int seed;  /* randomized seed for hashes */
  lu_byte gcparams[LUA_GCPN];
  lu_byte currentwhite;
  lu_byte gcstate;  /* state of garbage collector */
  lu_byte gckind;  /* kind of GC running */
  lu_byte gcstopem;  /* stops emergency collections */
  lu_byte gcstp;  /* control whether GC is running */
  lu_byte gcemergency;  /* true if this is an emergency collection */
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
  /* fields for generational collector */
  GCObject *survival;  /* start of objects that survived one GC cycle */
  GCObject *old1;  /* start of old1 objects */
  GCObject *reallyold;  /* objects more than one cycle old ("really old") */
  GCObject *firstold1;  /* first OLD1 object in the list (if any) */
  GCObject *finobjsur;  /* list of survival objects with finalizers */
  GCObject *finobjold1;  /* list of old1 objects with finalizers */
  GCObject *finobjrold;  /* list of really old objects with finalizers */
  struct lua_State *twups;  /* list of threads with open upvalues */
  lua_CFunction panic;  /* to be called in unprotected errors */
  TString *memerrmsg;  /* message for memory-allocation errors */
  TString *tmname[TM_N];  /* array with tag-method names */
  struct Table *mt[LUA_NUMTYPES];  /* metatables for basic types */
  TString *strcache[STRCACHE_N][STRCACHE_M];  /* cache for strings in API */
  lua_WarnFunction warnf;  /* warning function */
  void *ud_warn;         /* auxiliary data to 'warnf' */
  // LX mainth;  /* main thread of this state - omit for BPF */
} global_State;

/* Lua 5.5 lua_State */
struct lua_State {
  CommonHeader;
  lu_byte allowhook;
  unsigned char status; // TStatus is lu_byte
  StkIdRel top;
  global_State *l_G;
  CallInfo *ci;
  StkIdRel stack_last;
  StkIdRel stack;
  UpVal *openupval;
  StkIdRel tbclist;
  GCObject *gclist;
  struct lua_State *twups;
  struct lua_longjmp *errorJmp;
  CallInfo base_ci;
  volatile lua_Hook hook;
  ptrdiff_t errfunc;
  l_uint32 nCcalls;
  int oldpc;
  int nci;
  int basehookcount;
  int hookcount;
  volatile l_signalT hookmask;
  struct {
    int ftransfer;
    int ntransfer;
  } transferinfo;
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
  lu_byte kind;  /* kind of corresponding variable */
} Upvaldesc;

typedef struct LocVar {
  TString *varname;
  int startpc;  /* first point where variable is active */
  int endpc;    /* first point where variable is dead */
} LocVar;

typedef struct AbsLineInfo {
  int pc;
  int line;
} AbsLineInfo;

/* Lua 5.5 Proto */
typedef struct Proto {
  CommonHeader;
  lu_byte numparams;  /* number of fixed (named) parameters */
  lu_byte flag;
  lu_byte maxstacksize;  /* number of registers needed by this function */
  int sizeupvalues;  /* size of 'upvalues' */
  int sizek;  /* size of 'k' */
  int sizecode;
  int sizelineinfo;
  int sizep;  /* size of 'p' */
  int sizelocvars;
  int sizeabslineinfo;  /* size of 'abslineinfo' */
  int linedefined;  /* debug information  */
  int lastlinedefined;  /* debug information  */
  TValue *k;  /* constants used by the function */
  Instruction *code;  /* opcodes */
  struct Proto **p;  /* functions defined inside the function */
  Upvaldesc *upvalues;  /* upvalue information */
  ls_byte *lineinfo;  /* information about source lines (debug information) */
  AbsLineInfo *abslineinfo;  /* idem */
  LocVar *locvars;  /* information about local variables (debug information) */
  TString  *source;  /* used for debug information */
  GCObject *gclist;
} Proto;

#define getproto(o)	(clLvalue(o)->p)

union GCUnion {
  GCObject gc;  /* common header */
  struct TString ts;
  /* struct Udata u; */
  union Closure cl;
  Table h;
  struct Proto p;
  struct lua_State th;  /* thread */
  struct UpVal upv;
};

#define cast(t, exp)	((t)(exp))
#define cast_int(i)	 cast(int, (i))
#define val_(o)		((o)->value_)
#define cast_u(o)	cast(union GCUnion *, (o))
#define gco2lcl(o)  check_exp((o)->tt == LUA_VLCL, &((cast_u(o))->cl.l))
#define clLvalue(o)	gco2lcl(val_(o).gc)
#define pcRel(pc, p)	(cast_int((pc) - (p)->code) - 1)
#define ci_func(ci)	(clLvalue(s2v((ci)->func.p)))
#define s2v(o)	(&(o)->val)

/* Tag constants for Lua 5.5 */
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
#define LUA_NUMTYPES		9

/* Variant tags */
#define LUA_TFUNCTION		6
#define LUA_VLCL	(LUA_TFUNCTION | (0 << 4))  /* Lua closure */
#define LUA_VLCF	(LUA_TFUNCTION | (1 << 4))  /* light C function */
#define LUA_VCCL	(LUA_TFUNCTION | (2 << 4))  /* C closure */

#define LUA_TSTRING		4
#define LUA_VSHRSTR	(LUA_TSTRING | (0 << 4))  /* short strings */
#define LUA_VLNGSTR	(LUA_TSTRING | (1 << 4))  /* long strings */

#define BIT_ISCOLLECTABLE	(1 << 6)
#define ctb(t)			((t) | BIT_ISCOLLECTABLE)

#define rawtt(o)	((o)->tt_)
#define checktag(o,t)	(rawtt(o) == (t))

#define ttisLclosure(o)		checktag((o), ctb(LUA_VLCL))
#define ttislcf(o)		checktag((o), LUA_VLCF)
#define ttisCclosure(o)		checktag((o), ctb(LUA_VCCL))

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

/* BPF Helper functions for Lua 5.5 */

/* TString in 5.5: short strings have data after struct, long strings have ptr */
/* We need to handle this. But wait, `getstr` macro in 5.5 source:
   #define getstr(ts) 	(strisshr(ts) ? rawgetshrstr(ts) : (ts)->contents)
   #define rawgetshrstr(ts)  (cast_charp(&(ts)->contents))
   Struct TString has `char *contents` at the end in our definition?
   No, in source:
   typedef struct TString {
     ...
     char *contents;  // pointer to content in long strings
     ...
   } TString;
   For short strings, `contents` field is OVERLAPPED by data?
   No, `sizestrshr` uses `offsetof(TString, contents)`.
   So the data starts AT the `contents` field offset for short strings.
   This means `contents` field itself is overwritten by the first bytes of the string.

   In our struct definition above:
   char *contents;

   If we read TString, for short strings, we must read from `&ts->contents`.
   For long strings, we read from `ts->contents` (the pointer).
*/

static __always_inline void *lua_get_closure(StkIdRel stk_base, CallInfo *ci, int *ctype)
{
	void *ptr;
	int err;
	StackValue stk;

    // 5.5 has StkIdRel func
    // If it's a pointer (low bits not set?), it's absolute?
    // In 5.5 `StkIdRel` is a union { StkId p; ptrdiff_t offset; }.
    // If we assume `ci->func.p` is valid (stack not being reallocated), we use p.

	ptr = (void *)ci->func.p;
    // But wait, if we are in BPF, we might need to apply offset if `stk_base` suggests so?
    // profile.bpf.c lua_get_closure implementation for 5.4 checks if ptr < 1MB (offset).
    // Let's copy that logic.

    if ((uintptr_t)ptr < 1024*1024) { //it's a offset
		ptr += (uintptr_t)(stk_base.p);
	}

	DEBUG("lua_get_closure read stk:%lx", ptr);
	err = bpf_probe_read_user(&stk, sizeof(stk), ptr);
	if (err != 0) {
		ERROR("lua_get_closure read stk failed");
		return NULL;
	}
	*ctype = 0;
	if (ttisLclosure(&stk.val)) {
		*ctype = LUA_VLCL;
	} else if (ttislcf(&stk.val)) {
		*ctype = LUA_VLCF;
	} else if (ttisCclosure(&stk.val))  {
		*ctype = LUA_VCCL;
	}
	DEBUG("lua_get_closure ci type:%d %lx", *ctype, stk.val.value_.f);
	return (void *)stk.val.value_.gc;
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
	case LUA_VLCL:	//lua closure
		return cl.l.p;
	case LUA_VCCL:	//c closure
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
	source->source = p.source;
	source->linedefined = p.linedefined;
	return 0;
}

static __always_inline void *lua_get_file(struct lua_proto_source *proto, size_t *sz)
{
	size_t n;
	TString source;
	void *ptr = proto->source;
    // Read TString struct
	int err = bpf_probe_read_user(&source, sizeof(TString), ptr);
	if (err != 0) {
		ERROR("lua_get_file read source failed:%lx", ptr);
		return NULL;
	}

    // Check if short string using shrlen >= 0 (Lua 5.5 semantics)
    if (strisshr(&source)) {
        // Short string: content starts at the address of the 'contents' field
        // (the contents pointer field itself is overwritten by string data)
        ptr += offsetof(TString, contents);
        *sz = (size_t)source.shrlen;
        return ptr;
    } else {
        // Long string: contents is a pointer to the actual data
        *sz = source.u.lnglen;
        return source.contents;
    }
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
	if (ptr == NULL || ctype == LUA_VLCF) {
		return ptr;
	}
	ptr = lua_get_proto(ptr, ctype);
	if (ptr == NULL) {
		return NULL;
	}
	if (ctype != LUA_VLCL) { //not a Lua closure, direct return c function addr
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