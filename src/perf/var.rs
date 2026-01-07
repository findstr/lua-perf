use capstone::arch::x86::X86OperandType;
use capstone::{prelude::*, Insn, arch::x86::X86Operand, RegId};
use goblin::elf::Elf;
use goblin::elf::section_header::SHT_SYMTAB;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub enum VarPos {
	Reg(String),
	Mem(String, i64),
}

#[derive(Debug, Clone)]
pub struct FnVarPos {
	pub addr: u64,
	pub size: u64,
	pub pos: VarPos,
}

struct FnCode<'a> {
	name: String,
	addr: u64,
	size: u64,
	code: &'a [u8],
}

fn collect_callee_addr(elf: &Elf) -> Vec<u64> {
	let mut fns: Vec<u64> = Vec::new();
	for section_header in &elf.section_headers {
		if section_header.sh_type != SHT_SYMTAB {
			continue;
		}
		let symtab = &elf.syms;
		let strtab = &elf.strtab;
		for symbol in symtab.iter() {
			if let Some(name) = strtab.get_at(symbol.st_name) {
				if name == "luaV_execute" || name == "ccall" {
					fns.push(symbol.st_value);
				}
			}
		}
	}
	fns
}

fn collect_caller_code<'a>(elf: &'a Elf<'a>, elf_data: &'a [u8]) -> Vec<FnCode<'a>> {
	let mut fns: Vec<FnCode<'a>> = Vec::new();
	for section_header in &elf.section_headers {
		if section_header.sh_type != SHT_SYMTAB {
			continue;
		}
		let symtab = &elf.syms;
		let strtab = &elf.strtab;
		for symbol in symtab.iter() {
			if let Some(name) = strtab.get_at(symbol.st_name) {
				if name == "luaD_call" || name == "luaD_callnoyield" || name == "luaD_rawrunprotected" {
					let start = symbol.st_value as usize;
					let end = start + symbol.st_size as usize;
					fns.push(FnCode {
						name: String::from(name),
						addr: symbol.st_value,
						size: symbol.st_size,
						code: &elf_data[start..end],
					});
				}
			}
		}
	}
	fns
}

fn instr_ops(cs: &Capstone, instr: &Insn) -> (String, Vec<X86Operand>) {
	let detail = cs.insn_detail(instr).unwrap();
	let arc_detail = detail.arch_detail();
	let arc_detail = arc_detail.x86().unwrap();
	let instr_name = cs.insn_name(instr.id()).unwrap();
	let ops: Vec<_> = arc_detail.operands().collect();
	(instr_name, ops)
}

fn trace_reg(mov_ops: &mut X86Operand, mut mov_idx: usize, callee_save_reg: &[u32], instructions: capstone::Instructions<'_>, cs: &Capstone) {
	if let X86OperandType::Reg(reg) = mov_ops.op_type {
		let reg_id: u32 = reg.0 as u32;
		while mov_idx > 0 && !callee_save_reg.contains(&reg_id) {
			mov_idx -= 1;
			let instr = &instructions[mov_idx];
			let (inst_name, ops) = instr_ops(cs, instr);
			if inst_name == "mov" && ops.len() == 2 && ops[1].op_type == X86OperandType::Reg(reg) {
				*mov_ops = ops[0].clone();
				if let X86OperandType::Reg(reg) = mov_ops.op_type {
					let reg_id: u32 = reg.0 as u32;
					if callee_save_reg.contains(&reg_id) {
						break
					}
				} else {
					break
				}
			}
		}
	}
}

pub fn collect_lua_fn_var_pos<'a>(elf: &'a Elf<'a>, elf_data: &'a [u8]) -> Vec<FnVarPos> {
	let cs = Capstone::new()
		.x86()
		.mode(arch::x86::ArchMode::Mode64)
		.syntax(arch::x86::ArchSyntax::Att)
		.detail(true)
		.build().unwrap();
	let callee_save_reg = vec!{
		arch::x86::X86Reg::X86_REG_RBX as u32,
		arch::x86::X86Reg::X86_REG_RBP as u32,
		arch::x86::X86Reg::X86_REG_RSP as u32,
		arch::x86::X86Reg::X86_REG_R12 as u32,
		arch::x86::X86Reg::X86_REG_R13 as u32,
		arch::x86::X86Reg::X86_REG_R14 as u32,
		arch::x86::X86Reg::X86_REG_R15 as u32,
	};

	// Try to load DWARF locations
	let dwarf_locs = super::dwarf::extract_l_locations(elf_data).ok();

	let mut fn_var_pos: Vec<FnVarPos> = Vec::new();
	let callee = collect_callee_addr(elf);
	let callers = collect_caller_code(elf, elf_data);
	for caller in callers.iter() {
		let mut mov_idx: usize = 0;
		let mut mov_ops: X86Operand = Default::default();
		let mut call_site_addr = 0;
		let mut found_call_site = false;

		let instructions = cs.disasm_all(caller.code, caller.addr).unwrap();
		for (i, instr) in instructions.iter().enumerate() {
			let (inst_name, ops) = instr_ops(&cs, instr);
			match inst_name.as_str() {
				"mov" => {
					if ops.len() == 2 && ops[1].op_type == X86OperandType::Reg(RegId(arch::x86::X86Reg::X86_REG_RDI as u16)) {
						mov_idx = i;
						mov_ops = ops[0].clone();
					}
					continue
				},
				"call" => {},
				_ => continue
			}
			match caller.name.as_str() {
				"luaD_call" | "luaD_callnoyield" => {
					let hit = match ops[0].op_type {
						X86OperandType::Imm(addr) => {
							let addr = addr as u64;
							callee.contains(&addr)
						}
						_ => false
					};
					if hit {
						call_site_addr = instr.address();
						found_call_site = true;
						break
					}
				},
				"luaD_rawrunprotected" => {
					// This logic seems specific to finding where L is being prepared for call?
					// Or checking if 'L' (arg1) is used?
					// Keeping original logic for break point
					let hit = ops[0].op_type == X86OperandType::Imm(arch::x86::X86Reg::X86_REG_RDI as i64);
					if hit {
						call_site_addr = instr.address();
						found_call_site = true;
						break
					}
				},
				_ => {}
			}
		}

		// Try DWARF lookup if we found a synchronization point
		if found_call_site {
		    if let Some(ref locs_map) = dwarf_locs {
			// Use helper from dwarf module to find precise location
			if let Some(pos) = super::dwarf::get_var_pos_at(&caller.name, call_site_addr, locs_map) {
			    info!("DWARF: Found L for {} at {:#x}: {:?}", caller.name, call_site_addr, pos.pos);
			    // Check if register is supported
			    if let VarPos::Reg(ref r) = pos.pos {
				if r != "rbx" && r != "rbp" && r != "rsp" {
				     warn!("L is in register {} which might not be fully supported by BPF unwinder yet.", r);
				}
			    }
			    fn_var_pos.push(pos);
			    continue; // Skip heuristic
			}
		    }
		}

		// Heuristic Fallback
		// println!("Heuristic: Tracing reg for {}", caller.name);
		trace_reg(&mut mov_ops, mov_idx, &callee_save_reg, instructions, &cs);
		let pos = match mov_ops.op_type {
			X86OperandType::Reg(reg_id) => {
				VarPos::Reg(cs.reg_name(reg_id).unwrap())
			},
			X86OperandType::Mem(mem) => {
				let base_reg = mem.base().0 as u32;
				if !callee_save_reg.contains(&base_reg) {
					panic!("unsupported mem address:{}", cs.reg_name(mem.base()).unwrap());
				}
				VarPos::Mem(cs.reg_name(mem.base()).unwrap(), mem.disp())
			}
			_ => panic!("unsupported mov ops:{:?}", mov_ops.op_type),
		};
		fn_var_pos.push(FnVarPos {
			addr: caller.addr,
			size: caller.size,
			pos,
		});
	}
	fn_var_pos
}