mod maps;
mod eh;
mod var;
mod syscall;
mod dwarf;
mod version;

use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::sync::Arc;
use core::time::Duration;
use std::mem::{MaybeUninit, size_of};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::vec::Vec;
use blazesym::symbolize;
use blazesym::symbolize::source::{Source, Kernel, Process};
use blazesym::symbolize::{Input, Symbolized};
use gimli::X86_64;
use goblin::elf::Elf;
use libc::pid_t;
use std::os::linux::fs::MetadataExt;
use std::collections::HashMap;

use anyhow::bail;
use anyhow::Result;
use plain::Plain;
use libbpf_rs::MapFlags;
use libbpf_rs::MapCore;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;

use nix::unistd::close;

use tracing::subscriber::set_global_default as set_global_subscriber;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::FmtSubscriber;

use std::mem;
use std::path::PathBuf;
use tracing::{debug, info, error};

const STRINGS_MAP_SIZE: u32 = 2048;
const STACKS_MAP_SIZE: u32 = 1024 * 10;
const LUA_MASK: u64 = 1 << 63;

// Import all skeleton versions
#[allow(non_snake_case)]
mod bpf_5_3_6 {
    include!(concat!(env!("OUT_DIR"), "/profile_5_3_6.skel.rs"));
}
#[allow(non_snake_case)]
mod bpf_5_4_0 {
    include!(concat!(env!("OUT_DIR"), "/profile_5_4_0.skel.rs"));
}
#[allow(non_snake_case)]
mod bpf_5_5_0 {
    include!(concat!(env!("OUT_DIR"), "/profile_5_5_0.skel.rs"));
}

// Use 5.4.0 types as canonical types since they share the same C definitions
use bpf_5_4_0::types;

unsafe impl Plain for types::stack_event {}
unsafe impl Plain for types::reg_rule {}
unsafe impl Plain for types::eh_reg {}
unsafe impl Plain for types::eh_ctx {}
unsafe impl Plain for types::ctrl {}

// Trait to abstract over different ProfileSkel versions
trait ProfileSkelTrait {
    fn map_strings(&self) -> &libbpf_rs::Map<'_>;
    fn map_stacks(&self) -> &libbpf_rs::Map<'_>;
    fn map_events(&self) -> &libbpf_rs::Map<'_>;
    fn attach_perf_event(&mut self, fd: i32) -> Result<libbpf_rs::Link, libbpf_rs::Error>;
}

macro_rules! impl_skel_trait {
    ($mod:ident) => {
        impl<'a> ProfileSkelTrait for $mod::ProfileSkel<'a> {
            fn map_strings(&self) -> &libbpf_rs::Map<'_> { &self.maps.strings }
            fn map_stacks(&self) -> &libbpf_rs::Map<'_> { &self.maps.stacks }
            fn map_events(&self) -> &libbpf_rs::Map<'_> { &self.maps.events }
            fn attach_perf_event(&mut self, fd: i32) -> Result<libbpf_rs::Link, libbpf_rs::Error> {
                self.progs.profile.attach_perf_event(fd)
            }
        }
    }
}

impl_skel_trait!(bpf_5_3_6);
impl_skel_trait!(bpf_5_4_0);
impl_skel_trait!(bpf_5_5_0);


#[derive(Debug, Eq, PartialEq, Hash)]
struct StackFrame {
	kstack: Vec<u64>,
	ustack: Vec<u64>,
	lstack: Vec<u64>,
}

#[derive(Debug)]
enum LuaFrame {
	Lua(String),
	C(u64),
}

#[derive(Clone)]
struct SymInfo {
	addr: u64,
	offset: u64,
	name: String,
}

impl StackFrame {
	fn convert_stack_vec(size: i32, kstack: &[u64; 128]) -> Vec<u64> {
		let mut stack = Vec::new();
		let size = size / std::mem::size_of::<u64>() as i32;
		for i in 0..size {
			stack.push(kstack[i as usize]);
		}
		stack
	}
	fn from_event(event: &types::stack_event) -> Self {
		Self {
			kstack: Self::convert_stack_vec(event.kstack_sz, &event.kstack),
			ustack: Self::convert_stack_vec(event.ustack_sz, &event.ustack),
			lstack: Self::convert_stack_vec(event.lstack_sz, &event.lstack),
		}
	}
	fn from_count(stk: &types::stack_count) -> Self {
		Self {
			kstack: Self::convert_stack_vec(stk.kstack_sz, &stk.kstack),
			ustack: Self::convert_stack_vec(stk.ustack_sz, &stk.ustack),
			lstack: Self::convert_stack_vec(stk.lstack_sz, &stk.lstack),
		}
	}
}

pub struct LuaFn {
	pub addr: u64,
	pub size: u64,
	pub vars: Vec<var::FnVarPos>,
}


	fn build_eh_ctx(pid: pid_t) ->(std::vec::Vec<types::eh_ctx>, LuaFn) {
		let mut lua_fn = LuaFn{
			addr: 0,
			size: 0,
			vars: Vec::new(),
		};
		let mut eh_all_ctx = Vec::new();
		let maps = maps::Files::from_pid(pid as pid_t);
		for (path, maps) in maps.iter() {
			if path.contains("(deleted)") {
				continue;
			}
			let elf_data = std::fs::read(path).unwrap();
			let elf = Elf::parse(&elf_data).unwrap();
			let eh_ctx = eh::EhInstrContext::from_elf(&elf, &elf_data);
			if let Some(lua_fde) = eh_ctx.get_fde_desc(&"luaV_execute+0x0".to_string()) {
				assert!(lua_fde.size < u32::MAX as u64);
				lua_fn.addr = maps.translate(lua_fde.loc);
				lua_fn.size = lua_fde.size;
				let fns_var_pos = var::collect_lua_fn_var_pos(&elf, &elf_data);
				for var_pos in fns_var_pos.iter() {
					let addr = maps.translate(var_pos.addr);
					let fn_var_pos = var::FnVarPos {
						addr,
						size: var_pos.size,
						pos: var_pos.pos.clone(),
					};
					lua_fn.vars.push(fn_var_pos);
				}
			}
			for inst in eh_ctx.iter() {
				let eip = maps.translate(inst.loc);
				let mut bss_eh = types::eh_ctx {
					eip,
					size: inst.size as u32,
					cfa_rule: types::cfa_rule::CFA_Undefined,
					cfa_reg: 0,
					cfa_off: 0,
					regs: std::array::from_fn(|_| types::eh_reg {
						rule: types::reg_rule::Undefined,
						data: 0,
					}),
					__pad_20: [0;4],
				};
				match &inst.cfa_reg {
					eh::CfaRule::Undefined => {
						bss_eh.cfa_rule = types::cfa_rule::CFA_Undefined;
					}
					eh::CfaRule::Register(r) => {
						bss_eh.cfa_rule = types::cfa_rule::CFA_Register;
						bss_eh.cfa_reg = r.0 as u32;
						bss_eh.cfa_off = inst.cfa_off;
					}
					eh::CfaRule::Expression(_e) => {
						bss_eh.cfa_rule = types::cfa_rule::CFA_Expression;
						bss_eh.cfa_reg = 0;
						bss_eh.cfa_off = 0;
					}
				}
				for (i, reg) in inst.regs.iter().enumerate() {
					match reg {
						eh::RegRule::Undefined => {
							bss_eh.regs[i].rule = types::reg_rule::Undefined;
						}
						eh::RegRule::SameValue => {
							bss_eh.regs[i].rule = types::reg_rule::SameValue;
						}
						eh::RegRule::Offset(off) => {
							bss_eh.regs[i].rule = types::reg_rule::Offset;
							bss_eh.regs[i].data = *off as i32;
						}
						eh::RegRule::Register(r) => {
							bss_eh.regs[i].rule = types::reg_rule::Register;
							bss_eh.regs[i].data = r.0 as i32;
						}
						eh::RegRule::ValOffset(val) => {
							bss_eh.regs[i].rule = types::reg_rule::ValOffset;
							bss_eh.regs[i].data = *val as i32;
						}
						eh::RegRule::Expression(_e) => {	//TODO:
							bss_eh.regs[i].rule = types::reg_rule::Expression;
							bss_eh.regs[i].data = 0;
						}
						eh::RegRule::ValExpression(_e) => { //TODO:
							bss_eh.regs[i].rule = types::reg_rule::ValExpression;
							bss_eh.regs[i].data = 0;
						}
					}
				}
				eh_all_ctx.push(bss_eh);
			}
		}
		//对eh_all_ctx进行排序
		eh_all_ctx.sort_by_key(|a| a.eip);
		(eh_all_ctx, lua_fn)
	}

	// Pid 0 means a kernel space stack.
	fn show_stack_trace(stack: &[u64], symbolizer: &symbolize::Symbolizer, pid: u32) {
		let converted_stack;
		// The kernel always reports `u64` addresses, whereas blazesym uses `usize`.
		// Convert the stack trace as necessary.
		let stack = if mem::size_of::<blazesym::Addr>() != mem::size_of::<u64>() {
			converted_stack = stack
				.iter()
				.copied()
				.map(|addr| addr as blazesym::Addr)
				.collect::<Vec<_>>();
			converted_stack.as_slice()
		} else {
			// SAFETY: `Addr` has the same size as `u64`, so it can be trivially and
			//		 safely converted.
			unsafe { mem::transmute::<&[u64], &[blazesym::Addr]>(stack) }
		};
		let src = if pid == 0 {
			Source::from(Kernel::default())
		} else {
			Source::from(Process::new(pid.into()))
		};
		let syms = match symbolizer.symbolize(&src, Input::AbsAddr(stack)) {
			Ok(syms) => syms,
			Err(err) => {
				eprintln!("  failed to symbolize addresses: {err:#}");
				return;
			}
		};

		for (i, (addr, sym_result)) in stack.iter().zip(syms).enumerate() {
			let addr_fmt = format!(" {i:2} [<{addr:016x}>]");
			match sym_result {
				Symbolized::Sym(sym) => {
					let src_loc = if let Some(code_info) = &sym.code_info {
						let path: Option<PathBuf> = if let Some(dir) = &code_info.dir {
							Some(dir.join(&code_info.file))
						} else {
							Some(PathBuf::from(&code_info.file))
						};
						if let (Some(path), Some(line)) = (path, code_info.line) {
							if let Some(col) = code_info.column {
								format!(" {}:{line}:{col}", path.display())
							} else {
								format!(" {}:{line}", path.display())
							}
						} else {
							String::new()
						}
					} else {
						String::new()
					};

					let symbolize::Sym {
						name, addr, offset, ..
					} = sym;

					println!("{addr_fmt} {name} @ {addr:#x}+{offset:#x}{src_loc}");
				}
				Symbolized::Unknown(_) => {
					println!("{addr_fmt}");
				}
			}
		}
	}

	pub struct Perf {
		pid: pid_t,
		symbolizer: symbolize::Symbolizer,
		strings: HashMap<u32, std::string::String>,
		stacks: Vec<types::stack_count>,
	}

	impl Perf {
		pub fn new(pid: pid_t) -> Self {
			Self {
				pid,
				symbolizer: symbolize::Symbolizer::new(),
				strings: HashMap::new(),
				stacks: Vec::new(),
			}
		}	fn bump_memlock_rlimit() -> Result<()> {
		let rlimit = libc::rlimit {
			rlim_cur: 128 << 20,
			rlim_max: 128 << 20,
		};

		if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
			bail!("Failed to increase rlimit");
		}

		Ok(())
	}
	fn build_eh_ctx(pid: pid_t) ->(std::vec::Vec<types::eh_ctx>, LuaFn) {
		build_eh_ctx(pid)
	}
	fn bpf_var_pos(var_pos: &var::FnVarPos) -> types::fn_var_pos {
		let mut pos = types::fn_var_pos {
			eip_begin: var_pos.addr,
			eip_end: var_pos.addr + var_pos.size,
			..Default::default()
		};
		match &var_pos.pos {
			var::VarPos::Reg(reg_name)=> {
				let reg = X86_64::name_to_register(reg_name).unwrap();
				pos.is_mem = MaybeUninit::new(false);
				pos.reg = reg.0 as u8;
			},
			var::VarPos::Mem(reg_name, disp) => {
				let reg = X86_64::name_to_register(reg_name).unwrap();
				pos.is_mem = MaybeUninit::new(true);
				pos.reg = reg.0 as u8;
				pos.disp = *disp as i32;
			},
		}
		pos
	}

	fn init_perf_monitor(&self, freq: u64) -> Vec<i32> {
		let nprocs = libbpf_rs::num_possible_cpus().unwrap();
		let pid = -1;
		let buf: Vec<u8> = vec![0; mem::size_of::<syscall::perf_event_attr>()];
		let mut attr = unsafe {
			Box::<syscall::perf_event_attr>::from_raw(
				buf.leak().as_mut_ptr() as *mut syscall::perf_event_attr
			)
		};
		attr._type = syscall::PERF_TYPE_SOFTWARE;
		attr.size = mem::size_of::<syscall::perf_event_attr>() as u32;
		attr.config = syscall::PERF_COUNT_HW_CPU_CYCLES;
		attr.sample.sample_freq = freq;
		attr.flags = 1 << 10; // freq = 1
		println!("nprocs:{}", nprocs);
		(0..nprocs)
			.map(|cpu| {
				let fd = syscall::perf_event_open(attr.as_ref(), pid, cpu as i32, -1, 0);
				fd as i32
			})
			.collect()
	}

	fn attach_perf_event(		&mut self,
		skel: &mut dyn ProfileSkelTrait,
		pefds: &[i32],
	) -> Vec<Result<libbpf_rs::Link, libbpf_rs::Error>> {
		pefds
			.iter()
			.map(|pefd| skel.attach_perf_event(*pefd))
			.collect()
	}
	fn event_counter(&mut self, data: &[u8]) -> ::std::os::raw::c_int {
		if data.len() != mem::size_of::<types::stack_count>() {
			error!(
				"Invalid size {} != {}",
				data.len(),
				mem::size_of::<types::stack_count>()
			);
			return 1;
		}
		let event_ptr = unsafe { &*(data.as_ptr() as *const types::stack_count) };
		let event: types::stack_count = *event_ptr;
		if (event.kstack_sz + event.ustack_sz + event.lstack_sz) <= 0 {
			return 1;
		}
		self.stacks.push(event);
		0
	}

	fn event_string(&mut self, data: &[u8]) -> ::std::os::raw::c_int {
		if data.len() != mem::size_of::<types::string>() {
			error!(
				"Invalid size {} != {}",
				data.len(),
				mem::size_of::<types::string>()
			);
			return 1;
		}
		let event_ptr = unsafe { &*(data.as_ptr() as *const types::string) };
		let event: types::string = *event_ptr;
		let mut data = event.data.to_vec();
		data.resize(event.len as usize, 0);
		let mut utf8_buffer: Vec<u8> = Vec::new();
		for c in data {
			utf8_buffer.push(c as u8);
		}
		let s = std::string::String::from_utf8(utf8_buffer).unwrap();
		self.strings.insert(event.id, s);
		0
	}
	fn event_handler(&mut self, skel: &dyn ProfileSkelTrait, data: &[u8]) -> ::std::os::raw::c_int {
		let event_type = data[0];
		if event_type == types::event_type::EVENT_STACK.0 as u8 {
			debug!("EVENT_STACK");
			self.event_counter(data)
		} else if event_type == types::event_type::EVENT_STRING.0 as u8 {
			debug!("EVENT_STRING");
			self.event_string(data)
		} else if event_type == types::event_type::EVENT_TRACE.0 as u8 {
			self.event_trace(skel, skel.map_strings(), &self.symbolizer, data)
		} else {
			debug!("EVENT_UNKNOWN");
			0
		}
	}

	fn event_trace(&self, skel: &dyn ProfileSkelTrait, bindings: &libbpf_rs::Map<'_>, symbolizer: &symbolize::Symbolizer, data: &[u8]) -> ::std::os::raw::c_int {
		if data.len() != mem::size_of::<types::stack_event>() {
			error!(
				"Invalid size {} != {}",
				data.len(),
				mem::size_of::<types::stack_event>()
			);
			return 1;
		}

		let event = unsafe { &*(data.as_ptr() as *const types::stack_event) };

		if event.kstack_sz <= 0 && event.ustack_sz <= 0 {
			return 1;
		}

		let event_comm: Vec<u8> = event.comm.iter().map(|&x| x as u8).collect();
		let comm = std::str::from_utf8(&event_comm)
			.unwrap_or("<unknown>");
		println!("COMM: {} (pid={}) @ CPU {}", comm, event.pid, event.cpu_id);

		if event.kstack_sz > 0 {
			println!("Kernel:");
			show_stack_trace(
				&event.kstack[0..(event.kstack_sz as usize / mem::size_of::<u64>())],
				symbolizer,
				0,
			);
		} else {
			println!("No Kernel Stack");
		}

		if event.ustack_sz > 0 {
			println!("Userspace:");
			show_stack_trace(
				&event.ustack[0..(event.ustack_sz as usize / mem::size_of::<u64>())],
				symbolizer,
				event.pid,
			);
		} else {
			println!("No Userspace Stack");
		}
		println!("LuaStack:");
		if event.lstack_sz > 0 {
			for addr in event.lstack.iter().take(event.lstack_sz as usize / mem::size_of::<u64>()) {
				if (addr & LUA_MASK) != 0 {
					let addrv = *addr & !LUA_MASK;
					let file_id = addrv as u32;
					let line = (addrv >> 32) as u32;
					let i = file_id % 2048;
					let key = i.to_ne_bytes().to_vec();
					match bindings.lookup(&key, MapFlags::ANY) {
						Ok(val) => {
							match val {
								Some(val) => {
									let cache = unsafe { &*(val.as_ptr() as *const types::string) };
									let mut data = cache.data.to_vec();
									data.resize(cache.len as usize, 0);
									let mut utf8_buffer: Vec<u8> = Vec::new();
									for c in data {
										utf8_buffer.push(c as u8);
									}
									let s = std::string::String::from_utf8(utf8_buffer).unwrap();
									println!("Lua Stack:{}:{} len:{}", s, line, cache.len);
								}
								None => {
									println!("Lua Stack:Unkonw {:X}", i);
								}
							}
						}
						Err(_) => {
							println!("Lua Stack:ERR {}", line);
						}
					}
				} else {
					println!("Lua Stack:{:X}", *addr);
					let stk = [*addr];
					show_stack_trace(
						&stk[0..1],
						symbolizer,
						event.pid,
					);
				}
			}
		}

		println!();

		let stack = StackFrame::from_event(event);
		let mut stack_strs = self.combine_stack(skel, &stack);
		stack_strs.reverse();
		println!("combined:");
		println!("{}", stack_strs.join("\n"));
		println!("=============");
		0
	}

	fn poll_events<'a>(&'a mut self, skel: &'a mut dyn ProfileSkelTrait) -> Result<()> {
		let mut builder = libbpf_rs::RingBufferBuilder::new();
		builder.add(skel.map_events(), |data| {
			self.event_handler(skel, data)
		}).unwrap();
		let ringbuf = builder.build()?;
		let running = Arc::new(AtomicBool::new(true));
		let r = running.clone();
		let _ = ctrlc::set_handler(move ||{
			r.store(false, Ordering::SeqCst);
		});
		while running.load(Ordering::SeqCst) {
			let ret = ringbuf.poll(Duration::from_millis(100));
			match ret {
				Ok(_) => {}
				Err(_) => {
					break;
				}
			}
		}
		Ok(())
	}

	fn syms_of_stack(&self, pid: pid_t, stack: &Vec<u64>) -> Vec<SymInfo> {
		let mut stack_syms: Vec<SymInfo> = Vec::new();
		let converted_stack;
		let stack = if mem::size_of::<blazesym::Addr>() != mem::size_of::<u64>() {
			converted_stack = stack
				.iter()
				.copied()
				.map(|addr| addr as blazesym::Addr)
				.collect::<Vec<_>>();
			converted_stack.as_slice()
		} else {
			// SAFETY: `Addr` has the same size as `u64`, so it can be trivially and
			//		 safely converted.
			unsafe { mem::transmute::<_, &[blazesym::Addr]>(stack.as_slice()) }
		};
		let src = if pid == 0 {
			Source::from(Kernel::default())
		} else {
			Source::from(Process::new((pid as u32).into()))
		};
		let syms = match self.symbolizer.symbolize(&src, Input::AbsAddr(stack)) {
			Ok(syms) => syms,
			Err(err) => {
				error!("  failed to symbolize addresses: {err:#}");
				return stack_syms;
			}
		};

		for (addr, sym_result) in stack.iter().zip(syms) {
			let addr_fmt = format!("[<{addr:016x}>]");
			match sym_result {
				Symbolized::Sym(sym) => {
					let symbolize::Sym {
						name, offset, ..
					} = sym;
					stack_syms.push(SymInfo{
						addr: *addr as u64,
						offset: offset as u64,
						name: name.to_string(),
					})
				}
				Symbolized::Unknown(_) => {
					stack_syms.push(SymInfo{
						addr: 0,
						offset: 0,
						name: addr_fmt.clone(),
					})
				}
			}
		}
		stack_syms
	}

	fn id_to_str(&self, skel: &dyn ProfileSkelTrait, file_id: u32) -> String {
		let i = file_id % STRINGS_MAP_SIZE;
		let key = i.to_ne_bytes().to_vec();
		let str = match skel.map_strings().lookup(&key, MapFlags::ANY) {
			Ok(val) => {
				match val {
					Some(val) => {
						let cache = unsafe { &*(val.as_ptr() as *const types::string) };
						if cache.id != file_id {
							String::new()
						} else {
							let mut data = cache.data.to_vec();
							data.resize(cache.len as usize, 0);
							let mut utf8_buffer: Vec<u8> = Vec::new();
							for c in data {
								utf8_buffer.push(c as u8);
							}
							std::string::String::from_utf8(utf8_buffer).unwrap()
						}
					}
					None => String::new(),
				}
			},
			Err(_) => String::from("ERR"),
		};
		if !str.is_empty() {
			return str;
		}
		match self.strings.get(&file_id) {
			Some(v) => v.clone(),
			None => String::from("None"),
		}
	}
	fn split_lua_chunk(&self, skel: &dyn ProfileSkelTrait, frame: &StackFrame) -> Vec<Vec<LuaFrame>> {
		let mut chunks: Vec<Vec<LuaFrame>> = Vec::new();
	    	let mut chunk: Vec<LuaFrame> = Vec::new();
	    	for addr in frame.lstack.iter() {
			if *addr == 0 { //CIST_FRESH
				chunk.reverse();
				chunks.push(chunk);
			   	chunk = Vec::new();
			    	continue
			}
			if *addr & LUA_MASK == 0 {
			    	chunk.push(LuaFrame::C(*addr))
			} else {
				let addrv = *addr & !LUA_MASK;
				let file_id = addrv as u32;
				let line = (addrv >> 32) as u32;
				let str = format!("{}:{}", self.id_to_str(skel, file_id), line);
				chunk.push(LuaFrame::Lua(str));
			}
		}
		if !chunk.is_empty() {
			chunk.reverse();
			chunks.push(chunk);
		}
		chunks.reverse();
		chunks
	}

	fn split_c_chunk(&self, usym: &[SymInfo], l_chunks: &[Vec<LuaFrame>]) -> Vec<Vec<SymInfo>> {
		let mut chunks: Vec<Vec<SymInfo>> = Vec::new();
		let mut chunk: Vec<SymInfo> = Vec::new();
		for sym in usym.iter().rev() {
			//TODO process recursive call
			let start_addr = sym.addr - sym.offset;
			let c_start = l_chunks.iter().any(|x|
				match x.first() {
					Some(LuaFrame::C(addr)) => *addr == start_addr,
					_ => false,
				}
			);
			if c_start || sym.name.contains("luaV_execute") {
				if !c_start {
					chunk.push(sym.clone());
				}
				chunks.push(chunk);
				chunk = Vec::new();
			} else {
				chunk.push(sym.clone());
			}
		}
		if !chunk.is_empty() {
			chunks.push(chunk);
		}
		chunks
	}

	fn combine_stack(&self, skel: &dyn ProfileSkelTrait, frame: &StackFrame) -> Vec<String> {
		let ksyms = self.syms_of_stack(0, &frame.kstack);
		let usyms = self.syms_of_stack(self.pid, &frame.ustack);
		//split lua call chunk
		let mut lua_chunks = self.split_lua_chunk(skel, frame);
		let mut c_chunks = self.split_c_chunk(&usyms, &lua_chunks);
		let mut frame_strs:Vec<String> = Vec::new();
		for c_chunk in c_chunks.iter_mut() {
			for sym in c_chunk.iter() {
				frame_strs.push(sym.name.clone());
			}
			if !lua_chunks.is_empty() { //has lua stack left
				let lua_chunk = lua_chunks.remove(0);
				let lua_c_func: Vec<u64> = lua_chunk.iter().map(
					|f| match f {
						LuaFrame::Lua(_) => 0,
						LuaFrame::C(addr) => *addr,
					}
				).collect();
				let lua_c_syms = self.syms_of_stack(self.pid, &lua_c_func);
				for (frame, sym) in lua_chunk.iter().zip(lua_c_syms) {
					match frame {
					LuaFrame::Lua(str) => {
						frame_strs.push(str.clone())
					},
					LuaFrame::C(addr) =>
						if !c_chunk.iter().any(|x| x.addr - x.offset == *addr) {
							frame_strs.push(sym.name.clone())
						}
					}
				};
			}
		}
		let mut kstack = ksyms.iter().rev().map(|s| s.name.clone()).collect();
		frame_strs.append(&mut kstack);
		frame_strs
	}

	fn flame_entry(&self, skel: &dyn ProfileSkelTrait, frame: &StackFrame) -> String {
		let strs = self.combine_stack(skel, frame);
		strs.join(";")
	}
	fn collect_flame(&self, skel: &dyn ProfileSkelTrait) {
		let mut stack_count: HashMap<String, u32> = HashMap::new();
		let mut frame_list:Vec<(String, u32)> = Vec::new();
		for i in 0..STACKS_MAP_SIZE {
			let key = i.to_ne_bytes().to_vec();
			match skel.map_stacks().lookup(&key, MapFlags::ANY) {
				Ok(val) => {
					match val {
						Some(val) => {
							let counter = unsafe { &*(val.as_ptr() as *const types::stack_count) };
							if (counter.kstack_sz + counter.ustack_sz + counter.lstack_sz) > 0 {
								let stack = StackFrame::from_count(counter);
								let stack_str = self.flame_entry(skel, &stack);
								*stack_count.entry(stack_str).or_insert(0) += counter.count;
							}
						}
						None => {
							//warn!("Flame:Unknown {:X}", i);
						}
					}
				}
				Err(_) => {
					//error!("Flame:ERR {}", i);
				}
			}
		}
		for stack in self.stacks.iter() {
			let count = stack.count;
			let stack = StackFrame::from_count(stack);
			let stack_str = self.flame_entry(skel, &stack);
			*stack_count.entry(stack_str).or_insert(0) += count;
		}
		for (stack, count) in stack_count.iter() {
			frame_list.push((stack.clone(), *count));
		}
		frame_list.sort_by_key(|a| a.1);
		//write to file
		let mut file = File::create("perf.folded").unwrap();
		for (stack, count) in frame_list.iter() {
			let line = format!("{} {}\n", stack, count);
			file.write_all(line.as_bytes()).unwrap();
		}
	}

	pub fn exec(&mut self, args: &crate::args::Args) ->Result<()> {
		let level = LevelFilter::INFO;
		let subscriber = FmtSubscriber::builder()
			.with_max_level(level)
			.with_span_events(FmtSpan::FULL)
			.with_timer(SystemTime)
			.finish();
		let _ = set_global_subscriber(subscriber);

		Self::bump_memlock_rlimit()?;
		let mut open_object = MaybeUninit::uninit();
		
		// Detect version first
        let maps = maps::Files::from_pid(self.pid);
        let mut detected_version = String::new();
        for (path, _) in maps.iter() {
            if path.contains("(deleted)") { continue; }
            if let Ok(ver) = version::detect_lua_version(path) {
                info!("Detected Lua version: {} in {}", ver, path);
                println!("Detected Lua version: {} in {}", ver, path);
                detected_version = ver;
                break;
            }
        }
        
        if detected_version.is_empty() {
            bail!("Could not detect Lua version in target process.");
        }

        // Macro to instantiate specific skeleton
        macro_rules! init_skel {
            ($skel_mod:ident) => {{
                let mut skel_builder = $skel_mod::ProfileSkelBuilder::default();
                skel_builder.obj_builder.debug(false);
                let mut open_skel = skel_builder.open(&mut open_object).unwrap();
                
                let result = Self::build_eh_ctx(self.pid);
                let eh_list = result.0;
                let lua_fn = result.1;

                // Set max entries
                open_skel.maps.eh_frame_header.set_max_entries(eh_list.len() as u32).unwrap();
                open_skel.maps.eh_frame.set_max_entries(eh_list.len() as u32).unwrap();
                open_skel.maps.strings.set_max_entries(STRINGS_MAP_SIZE as u32).unwrap();
                open_skel.maps.stacks.set_max_entries(STACKS_MAP_SIZE as u32).unwrap();

                // Write arguments into prog
                let pid_path = format!("/proc/{}/ns/pid", self.pid);
                let stat = fs::metadata(&pid_path).unwrap();
                {
                    let bss = open_skel.maps.bss_data.as_mut().unwrap();
                    bss.ctrl.dev = stat.st_dev();
                    bss.ctrl.ino = stat.st_ino();
                    bss.ctrl.target_pid = self.pid;
                    bss.ctrl.lua_eip_begin = lua_fn.addr;
                    bss.ctrl.lua_eip_end = lua_fn.addr + lua_fn.size;
                    for (i, var) in lua_fn.vars.iter().enumerate() {
                        // We need to cast our types::fn_var_pos to local types::fn_var_pos
                        let common_pos = Self::bpf_var_pos(var);
                        unsafe {
                             std::ptr::copy_nonoverlapping(
                                &common_pos as *const types::fn_var_pos as *const $skel_mod::types::fn_var_pos,
                                &mut bss.ctrl.lua_var_pos[i],
                                1
                            );
                        }
                    }
                    bss.EH_FRAME_COUNT = eh_list.len() as u32;
                    bss.STRINGS_MAP_SIZE = STRINGS_MAP_SIZE;
                    bss.STACKS_MAP_SIZE = STACKS_MAP_SIZE;
                }

                let skel = open_skel.load().map_err(|e| {
                    error!("Failed to load BPF skeleton: {}", e);
                    anyhow::anyhow!("BPF load failed. Try running with sudo or check kernel version/lockdown.")
                })?;
                
                // Populate eh_frame maps
                for (i, ctx) in eh_list.iter().enumerate() {
                    let key = (i as u32).to_ne_bytes();
                    let eip = ctx.eip.to_ne_bytes();
                    // We need to cast ctx (canonical type) to the specific module's eh_ctx
                    let val_ptr = ctx as *const types::eh_ctx as *const $skel_mod::types::eh_ctx;
                    // And cast to byte slice. But libbpf-rs update expects &[u8].
                    // types::eh_ctx is Plain, so we can cast.
                    // But to be safe, let's use the local type's size.
                    let val_slice = unsafe { 
                        std::slice::from_raw_parts(val_ptr as *const u8, size_of::<$skel_mod::types::eh_ctx>()) 
                    };
                    
                    skel.maps.eh_frame_header.update(&key, &eip, MapFlags::ANY).unwrap();
                    skel.maps.eh_frame.update(&key, val_slice, MapFlags::ANY).unwrap();
                }
                
                Box::new(skel) as Box<dyn ProfileSkelTrait>
            }}
        }

        let mut skel: Box<dyn ProfileSkelTrait> = match detected_version.as_str() {
            v if v.starts_with("5.3") => init_skel!(bpf_5_3_6),
            v if v.starts_with("5.4") => init_skel!(bpf_5_4_0),
            v if v.starts_with("5.5") => init_skel!(bpf_5_5_0),
            _ => {
                bail!("Unsupported Lua version: {}. Only 5.3, 5.4, 5.5 are supported.", detected_version);
            }
        };

		let pef_fds = self.init_perf_monitor(args.freq);
		let _links = self.attach_perf_event(&mut *skel, &pef_fds);
		self.poll_events(&mut *skel)?;
		self.collect_flame(&*skel);
		for pefd in pef_fds {
			close(pefd).unwrap();
		}
		Ok(())
	}
}



#[cfg(test)]
mod tests {
	use goblin::elf::Elf;
	use super::var;
	#[test]
	fn test_find_func_code() {
		let paths = vec![
			"lua.clang.o0",
			"lua.clang.o1",
			"lua.clang.o2",
			"lua.clang.o3",
			"lua.gcc.o0",
			"lua.gcc.o1",
			"lua.gcc.o2",
			"lua.gcc.o3",
		];
		for path in paths.iter() {
			if let Ok(elf_data) = std::fs::read(path) {
				let data = &elf_data;
				let elf = Elf::parse(data).unwrap();
				let fn_vars = var::collect_lua_fn_var_pos(&elf, &elf_data);
				println!("========{}======:{:?}", path, fn_vars);
			}
		}
	}
}