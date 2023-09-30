/*
** $Id: lstate.h $
** Global State
** See Copyright Notice in lua.h
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
typedef uint32_t l_uint32;
typedef uint64_t lua_Integer;
typedef double lua_Number;
typedef ptrdiff_t lua_KContext;
typedef int (*lua_CFunction) (lua_State *L);
typedef int (*lua_KFunction) (lua_State *L, int status, lua_KContext ctx);
typedef void * (*lua_Alloc) (void *ud, void *ptr, size_t osize, size_t nsize);
typedef void (*lua_WarnFunction) (void *ud, const char *msg, int tocont);
typedef void (*lua_Hook) (lua_State *L, lua_Debug *ar);

#define CommonHeader	struct GCObject *next; lu_byte tt; lu_byte marked
#define TValuefields	Value value_; lu_byte tt_
#define l_signalT sig_atomic_t
#define STRCACHE_N		53
#define STRCACHE_M		2
#define LUA_NUMTYPES		9
#define MAXIWTHABS      	128

/*
** Bits in CallInfo status
*/
#define CIST_OAH				(1<<0)	/* original value of 'allowhook' */
#define CIST_C					(1<<1)	/* call is running a C function */
#define CIST_FRESH			(1<<2)	/* call is on a fresh "luaV_execute" frame */
#define CIST_HOOKED		 (1<<3)	/* call is running a debug hook */
#define CIST_YPCALL		 (1<<4)	/* doing a yieldable protected call */
#define CIST_TAIL			 (1<<5)	/* call was tail called */
#define CIST_HOOKYIELD	(1<<6)	/* last hook called yielded */
#define CIST_FIN				(1<<7)	/* function "called" a finalizer */
#define CIST_TRAN			 (1<<8)	/* 'ci' has transfer information */
#define CIST_CLSRET		 (1<<9)	/* function is closing tbc variables */
/* Bits 10-12 are used for CIST_RECST (see below) */
#define CIST_RECST			10
#if defined(LUA_COMPAT_LT_LE)
#define CIST_LEQ				(1<<13)	/* using __lt for __le */
#endif

#define isLua(ci)			 (!((ci)->callstatus & CIST_C))	 

typedef enum {
	TM_INDEX,
	TM_NEWINDEX,
	TM_GC,
	TM_MODE,
	TM_LEN,
	TM_EQ,	/* last tag method with fast access */
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
	TM_CLOSE,
	TM_N		/* number of elements in the enum */
} TMS;

typedef struct GCObject {
	CommonHeader;
} GCObject;

typedef union Value {
	struct GCObject *gc;		/* collectable objects */
	void *p;				 /* light userdata */
	lua_CFunction f; /* light C functions */
	lua_Integer i;	 /* integer numbers */
	lua_Number n;		/* float numbers */
	/* not used, but may avoid warnings for uninitialized value */
	lu_byte ub;
} Value;

typedef struct TValue {
	TValuefields;
} TValue;

typedef struct UpVal {
	CommonHeader;
	union {
		TValue *p;	/* points to stack or to its own value */
		ptrdiff_t offset;	/* used while the stack is being reallocated */
	} v;
	union {
		struct {	/* (when open) */
			struct UpVal *next;	/* linked list */
			struct UpVal **previous;
		} open;
		TValue value;	/* the value (when closed) */
	} u;
} UpVal;

typedef struct TString {
	CommonHeader;
	lu_byte extra;	/* reserved words for short strings; "has hash" for longs */
	lu_byte shrlen;	/* length for short strings */
	unsigned int hash;
	union {
		size_t lnglen;	/* length for long strings */
		struct TString *hnext;	/* linked list for hash table */
	} u;
	char contents[1];
} TString;

typedef struct stringtable {
	TString **hash;
	int nuse;	/* number of elements */
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
	StkId p;	/* actual pointer */
	ptrdiff_t offset;	/* used while the stack is being reallocated */
} StkIdRel;

struct CallInfo {
	StkIdRel func;	/* function index in the stack */
	StkIdRel	top;	/* top for this function */
	struct CallInfo *previous, *next;	/* dynamic call link */
	union {
		struct {	/* only for Lua functions */
			const Instruction *savedpc;
			volatile l_signalT trap;
			int nextraargs;	/* # of extra arguments in vararg functions */
		} l;
		struct {	/* only for C functions */
			lua_KFunction k;	/* continuation in case of yields */
			ptrdiff_t old_errfunc;
			lua_KContext ctx;	/* context info. in case of yields */
		} c;
	} u;
	union {
		int funcidx;	/* called-function index */
		int nyield;	/* number of values yielded */
		int nres;	/* number of values returned */
		struct {	/* info about transferred values (for call/return hooks) */
			unsigned short ftransfer;	/* offset of first value transferred */
			unsigned short ntransfer;	/* number of values transferred */
		} transferinfo;
	} u2;
	short nresults;	/* expected number of results from this function */
	unsigned short callstatus;
};


typedef struct global_State {
	lua_Alloc frealloc;	/* function to reallocate memory */
	void *ud;				 /* auxiliary data to 'frealloc' */
	l_mem totalbytes;	/* number of bytes currently allocated - GCdebt */
	l_mem GCdebt;	/* bytes allocated not yet compensated by the collector */
	lu_mem GCestimate;	/* an estimate of the non-garbage memory in use */
	lu_mem lastatomic;	/* see function 'genstep' in file 'lgc.c' */
	stringtable strt;	/* hash table for strings */
	TValue l_registry;
	TValue nilvalue;	/* a nil value */
	unsigned int seed;	/* randomized seed for hashes */
	lu_byte currentwhite;
	lu_byte gcstate;	/* state of garbage collector */
	lu_byte gckind;	/* kind of GC running */
	lu_byte gcstopem;	/* stops emergency collections */
	lu_byte genminormul;	/* control for minor generational collections */
	lu_byte genmajormul;	/* control for major generational collections */
	lu_byte gcstp;	/* control whether GC is running */
	lu_byte gcemergency;	/* true if this is an emergency collection */
	lu_byte gcpause;	/* size of pause between successive GCs */
	lu_byte gcstepmul;	/* GC "speed" */
	lu_byte gcstepsize;	/* (log2 of) GC granularity */
	GCObject *allgc;	/* list of all collectable objects */
	GCObject **sweepgc;	/* current position of sweep in list */
	GCObject *finobj;	/* list of collectable objects with finalizers */
	GCObject *gray;	/* list of gray objects */
	GCObject *grayagain;	/* list of objects to be traversed atomically */
	GCObject *weak;	/* list of tables with weak values */
	GCObject *ephemeron;	/* list of ephemeron tables (weak keys) */
	GCObject *allweak;	/* list of all-weak tables */
	GCObject *tobefnz;	/* list of userdata to be GC */
	GCObject *fixedgc;	/* list of objects not to be collected */
	/* fields for generational collector */
	GCObject *survival;	/* start of objects that survived one GC cycle */
	GCObject *old1;	/* start of old1 objects */
	GCObject *reallyold;	/* objects more than one cycle old ("really old") */
	GCObject *firstold1;	/* first OLD1 object in the list (if any) */
	GCObject *finobjsur;	/* list of survival objects with finalizers */
	GCObject *finobjold1;	/* list of old1 objects with finalizers */
	GCObject *finobjrold;	/* list of really old objects with finalizers */
	struct lua_State *twups;	/* list of threads with open upvalues */
	lua_CFunction panic;	/* to be called in unprotected errors */
	struct lua_State *mainthread;
	TString *memerrmsg;	/* message for memory-allocation errors */
	TString *tmname[TM_N];	/* array with tag-method names */
	struct Table *mt[LUA_NUMTYPES];	/* metatables for basic types */
	TString *strcache[STRCACHE_N][STRCACHE_M];	/* cache for strings in API */
	lua_WarnFunction warnf;	/* warning function */
	void *ud_warn;				 /* auxiliary data to 'warnf' */
} global_State;


/*
** 'per thread' state
*/
struct lua_State {
	CommonHeader;
	lu_byte status;
	lu_byte allowhook;
	unsigned short nci;	/* number of items in 'ci' list */
	StkIdRel top;	/* first free slot in the stack */
	global_State *l_G;
	CallInfo *ci;	/* call info for current function */
	StkIdRel stack_last;	/* end of stack (last element + 1) */
	StkIdRel stack;	/* stack base */
	UpVal *openupval;	/* list of open upvalues in this stack */
	StkIdRel tbclist;	/* list of to-be-closed variables */
	GCObject *gclist;
	struct lua_State *twups;	/* list of threads with open upvalues */
	struct lua_longjmp *errorJmp;	/* current error recover point */
	CallInfo base_ci;	/* CallInfo for first level (C calling Lua) */
	volatile lua_Hook hook;
	ptrdiff_t errfunc;	/* current error handling function (stack index) */
	l_uint32 nCcalls;	/* number of nested (non-yieldable | C)	calls */
	int oldpc;	/* last pc traced */
	int basehookcount;
	int hookcount;
	volatile l_signalT hookmask;
};

#define ClosureHeader \
				CommonHeader; lu_byte nupvalues; GCObject *gclist

typedef struct CClosure {
	ClosureHeader;
	lua_CFunction f;
	TValue upvalue[1];	/* list of upvalues */
} CClosure;


typedef struct LClosure {
	ClosureHeader;
	struct Proto *p;
	UpVal *upvals[1];	/* list of upvalues */
} LClosure;


typedef union Closure {
	CClosure c;
	LClosure l;
} Closure;

typedef struct AbsLineInfo {
	int pc;
	int line;
} AbsLineInfo;

typedef struct Upvaldesc {
	TString *name;	/* upvalue name (for debug information) */
	lu_byte instack;	/* whether it is in stack (register) */
	lu_byte idx;	/* index of upvalue (in stack or in outer function's list) */
	lu_byte kind;	/* kind of corresponding variable */
} Upvaldesc;

typedef struct LocVar {
	TString *varname;
	int startpc;	/* first point where variable is active */
	int endpc;		/* first point where variable is dead */
} LocVar;

typedef struct Proto {
	CommonHeader;
	lu_byte numparams;	/* number of fixed (named) parameters */
	lu_byte is_vararg;
	lu_byte maxstacksize;	/* number of registers needed by this function */
	int sizeupvalues;	/* size of 'upvalues' */
	int sizek;	/* size of 'k' */
	int sizecode;
	int sizelineinfo;
	int sizep;	/* size of 'p' */
	int sizelocvars;
	int sizeabslineinfo;	/* size of 'abslineinfo' */
	int linedefined;	/* debug information	*/
	int lastlinedefined;	/* debug information	*/
	TValue *k;	/* constants used by the function */
	Instruction *code;	/* opcodes */
	struct Proto **p;	/* functions defined inside the function */
	Upvaldesc *upvalues;	/* upvalue information */
	ls_byte *lineinfo;	/* information about source lines (debug information) */
	AbsLineInfo *abslineinfo;	/* idem */
	LocVar *locvars;	/* information about local variables (debug information) */
	TString	*source;	/* used for debug information */
	GCObject *gclist;
} Proto;

#define getproto(o)		 (clLvalue(o)->p)


union GCUnion {
	GCObject gc;	/* common header */
	struct TString ts;
	union Closure cl;
	struct Proto p;
	struct lua_State th;	/* thread */
	struct UpVal upv;
};

/*
** basic types
*/
#define LUA_TNONE							 (-1)

#define LUA_TNIL								0
#define LUA_TBOOLEAN						1
#define LUA_TLIGHTUSERDATA			2
#define LUA_TNUMBER						 3
#define LUA_TSTRING						 4
#define LUA_TTABLE							5
#define LUA_TFUNCTION					 6
#define LUA_TUSERDATA					 7
#define LUA_TTHREAD						 8

#define LUA_NUMTYPES						9

#define BIT_ISCOLLECTABLE		 (1 << 6) 

#define makevariant(t,v)				((t) | ((v) << 4)) 
#define cast(t, exp)	((t)(exp))
#define cast_int(i)	 cast(int, (i)) 
#define s2v(o)				(&(o)->val)
#define val_(o)			 ((o)->value_)
#define cast_u(o)		 cast(union GCUnion *, (o))
#define gco2lcl(o)		(&((cast_u(o))->cl.l))
#define clLvalue(o)	 gco2lcl(val_(o).gc)
#define pcRel(pc, p)	(cast_int((pc) - (p)->code) - 1)
#define ci_func(ci)		(clLvalue(s2v((ci)->func.p)))
#define getstr(ts)		((ts)->contents) 
#define LUA_VSHRSTR	 makevariant(LUA_TSTRING, 0)	
#define tsslen(s)		 ((s)->tt == LUA_VSHRSTR ? (s)->shrlen : (s)->u.lnglen)		 
#define ctb(t)				((t) | BIT_ISCOLLECTABLE)			
#define rawtt(o)				((o)->tt_)		 
#define checktag(o,t)	 (rawtt(o) == (t))	

#define LUA_VLCL				makevariant(LUA_TFUNCTION, 0)	/* Lua closure */
#define LUA_VLCF				makevariant(LUA_TFUNCTION, 1)	/* light C function */
#define LUA_VCCL				makevariant(LUA_TFUNCTION, 2)	/* C closure */


#define withvariant(t)				((t) & 0x3F)	 
#define ttisLclosure(o)				checktag((o), ctb(LUA_VLCL))
#define ttislcf(o)				checktag((o), LUA_VLCF)
#define ttisCclosure(o)				checktag((o), ctb(LUA_VCCL))

#define LUA_FILE_LEN	(64)

static __always_inline int currentpc (CallInfo *ci) {
	return pcRel(ci->u.l.savedpc, ci_func(ci)->p);
}

#define LINE_BUF_SIZE	(8)

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

static __always_inline void *lua_get_closure(StkIdRel stk_base, CallInfo *ci, int *ctype) 
{
	void *ptr;
	int err;
	StackValue stk;
	ptr = (u8 *)ci->func.p;
	if ((uintptr_t)ptr < 1024*1024) { //it's a offset
		ptr += (uintptr_t)(stk_base.p);
	}
	DEBUG("lua_get_closure read stk:%lx %lx", ptr, ci->func.p);
	err = bpf_probe_read_user(&stk, sizeof(stk), (void *)ptr);
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

#endif

