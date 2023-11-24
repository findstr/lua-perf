use std::vec::Vec;
use rustc_demangle::demangle;
use std::collections::HashMap;
use anyhow::{anyhow, Context};

use goblin::elf::Elf;
use goblin::elf::Sym;
use goblin::elf::SectionHeader;
use gimli::BaseAddresses;
use gimli::CallFrameInstruction;
use gimli::CieOrFde;
use gimli::EhFrame;
use gimli::Reader;
use gimli::Register;
use gimli::SectionBaseAddresses;
use gimli::UnwindSection;
use gimli::X86_64;

const MAX_REG: usize = X86_64::RA.0 as usize + 1;

fn register_name(r: Register) -> &'static str {
	X86_64::register_name(r).unwrap_or("???") 
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RegRule {
	Undefined,
	SameValue,
	Offset(i64),
	ValOffset(i64),
	Register(Register),
	Expression(Vec<u8>),
	ValExpression(Vec<u8>),
}

#[derive(Debug, Clone)]
pub enum CfaRule {
	Undefined,
	Register(Register),
	Expression(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct EhInstr {
	pub sym: String,
	pub loc: u64,
	pub size: u64,
   	pub cfa_reg: CfaRule,
    	pub cfa_off: i64,
	pub regs: [RegRule; MAX_REG],
}

#[derive(Debug, Clone)]
pub struct FdeDesc {
	pub loc: u64,
	pub size: u64,
}

pub struct EhInstrContext {
	code_align_factor: u64,
	data_align_factor: i64,
	fde_desc: HashMap<String, FdeDesc>,
	instr: EhInstr,
	init_regs: [RegRule; MAX_REG],
	instrs: Vec<EhInstr>,
	stack: Vec<EhInstr>,
}

impl EhInstr {
	fn new () -> Self {
		let instr = EhInstr {
			sym: String::new(),
			loc: 0,
			size: 0,
			cfa_reg: CfaRule::Undefined,
			cfa_off: 0,
			regs: std::array::from_fn(|_| RegRule::Undefined),
		};
		return instr;
	}
	fn reset(&mut self) {
		*self = EhInstr::new();
	}
}

impl std::fmt::Display for EhInstr {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		let cfa_reg = match &self.cfa_reg {
			CfaRule::Register(r) => String::from(register_name(*r)),
			CfaRule::Expression(e) => format!("exp:{:?}", e),
			CfaRule::Undefined => String::from("undefined"),
		};
		write!(f, "{} {:#x} {:#x} CFA_reg:{:?} CFA_off:{} {}:{:?} {}:{:?} {}:{:?}", 
			self.sym, self.loc, self.size, 
			cfa_reg, self.cfa_off,
			register_name(X86_64::RA), self.regs[X86_64::RA.0 as usize],
			register_name(X86_64::RBP),  self.regs[X86_64::RBP.0 as usize],
			register_name(X86_64::RSP), self.regs[X86_64::RSP.0 as usize],
		)
	}
}

impl<'a> EhInstrContext {
	pub fn from_elf(elf: &'a Elf<'a>, elf_data: &'a Vec<u8>) -> Self {
		let mut instr_ctx = EhInstrContext {
			code_align_factor: 0,
			data_align_factor: 1,
			fde_desc: HashMap::new(),
			init_regs: std::array::from_fn(|_| RegRule::Undefined),
			stack: Vec::new(),
			instrs: Vec::new(),
    			instr: EhInstr::new(),
		};
		let sh = instr_ctx.find_section(&elf, ".eh_frame")
			.or_else(||instr_ctx.find_section(&elf, ".debug_frame"))
			.ok_or_else(|| anyhow!("couldn't find section `.eh_frame` or `.debug_frame`")).unwrap();
		let range = sh.file_range()
			.ok_or_else(|| anyhow!("section has no content")).unwrap();
		instr_ctx.parse_eh_frame(&elf, sh.sh_addr, &elf_data[range]);
		return instr_ctx;
	}
	fn find_section(&self, elf: &'a Elf, name: &str) -> Option<&'a SectionHeader> {
    		elf.section_headers
		.iter()
		.find(|&s| {
			elf.shdr_strtab.get_at(s.sh_name)
				.map(|n| n == name)
				.unwrap_or(false)
		})
	}
	pub fn parse_eh_frame(&mut self, elf: &Elf, vaddr: u64, content: &[u8]) {
		let eh = EhFrame::new(content, gimli::LittleEndian); // TODO: endianness
		let base_addrs = BaseAddresses {
			eh_frame_hdr: SectionBaseAddresses::default(),
			eh_frame: SectionBaseAddresses {
				section: Some(vaddr),
				text: None,
				data: None,
			},
		};
		let mut cies = HashMap::new();
		let mut cfi_entries = eh.entries(&base_addrs);
		while let Some(entry) = cfi_entries.next().with_context(|| anyhow::anyhow!("failed to parse entry")).unwrap() {
			match entry {
				CieOrFde::Cie(cie) => {
					self.code_align_factor = cie.code_alignment_factor();
					self.data_align_factor = cie.data_alignment_factor();
					cies.insert(cie.offset(), cie);
				},
				CieOrFde::Fde(fde_unparsed) => {
					let fde = fde_unparsed.parse(|_, _, offset| {
						Ok(cies[&offset.0].clone())
					}).unwrap();
					//cfi instruction
					let func_name = self.addr_to_sym_name(elf, fde.initial_address());
					//println!("{} {:#x} {:#x}", func_name, fde.initial_address(), fde.len());
					self.fde_desc.insert(func_name, FdeDesc{
						loc: fde.initial_address(),
						size: fde.len(),
					});
					self.eval_begin(elf, fde.initial_address());
					let mut instr_iter = fde.cie().instructions(&eh, &base_addrs);
					while let Some(instr) = instr_iter.next().unwrap_or(None) {
						self.eval(elf, instr);
					}
					self.save_init();
					//fde instruction
					let mut instr_iter = fde.instructions(&eh, &base_addrs);
					while let Some(instr) = instr_iter.next().unwrap_or(None) {
						self.eval(elf, instr);
					}
					self.eval_end(elf, fde.initial_address() + fde.len());
				},
			}
		}
	}
	fn addr_to_sym(&self, elf: &Elf, addr: u64) -> Option<Sym> {
		let mut iter = elf.syms.iter();
		let mut curr_sym = iter.next()?;
   		for sym in iter {
			if !sym.is_function() {
				continue;
			}
			if sym.st_value <= addr && sym.st_value > curr_sym.st_value {
				curr_sym = sym;
			}
		}
		if curr_sym.st_value > addr {
			None
		} else {
			Some(curr_sym)
		}
	}
	fn addr_to_sym_name(&self, elf: &Elf, addr: u64) ->String {
		if let Some(sym) = self.addr_to_sym(elf, addr) {
 			let name = elf.strtab.get_at(sym.st_name).unwrap_or("???");
   			let name = demangle(name).to_string();
   			return format!("{}+{:#x}", name, addr - sym.st_value);
		}
		return format!("{:#x}", addr);
	}
	fn update_instr_sym(&mut self, elf: &Elf) {
		if self.instr.loc == 0 {
			self.instr.sym = String::from("cfi");
			return;
		}
		self.instr.sym = self.addr_to_sym_name(elf, self.instr.loc);
	}
	fn set_loc(&mut self, elf: &Elf, loc: u64) {
		if self.instr.loc != 0 {
			self.instr.size = loc - self.instr.loc;
			self.instrs.push(self.instr.clone());
		}
		self.instr.loc = loc;
		self.update_instr_sym(&elf);
	}
	fn eval_begin(&mut self, elf: &Elf, loc: u64) {
		self.instr.loc = loc;
		self.instr.size = 0;
		self.update_instr_sym(elf);
	}
	fn eval_end(&mut self, elf: &Elf, loc: u64) {
		self.set_loc(elf, loc);
		self.instr.reset();
	}
	fn save_init(&mut self) {
		for i in 0 .. self.instr.regs.len() {
			self.init_regs[i] = self.instr.regs[i].clone();
		}
	}
    	fn eval<R: Reader>(&mut self, elf: &Elf, instr: CallFrameInstruction<R>) {
    		use CallFrameInstruction::*;
        	match instr {
   			SetLoc { address } => {
				self.set_loc(elf, address);
   			},
            		AdvanceLoc { delta } => {
				self.set_loc(elf, self.instr.loc + delta as u64 * self.code_align_factor);
			},
            		DefCfa { register, offset } => {
				self.instr.cfa_reg = CfaRule::Register(register);
				self.instr.cfa_off = offset as i64;
			},
            		DefCfaSf { register, factored_offset } => {
				self.instr.cfa_reg = CfaRule::Register(register);
				self.instr.cfa_off = factored_offset * self.data_align_factor;
			},
            		DefCfaRegister { register } => {
				self.instr.cfa_reg = CfaRule::Register(register);
			},
            		DefCfaOffset { offset } => {
                		self.instr.cfa_off = offset as i64;
            		},
            		DefCfaOffsetSf { factored_offset } => {
				self.instr.cfa_off = factored_offset * self.data_align_factor;
            		},
			DefCfaExpression { expression } => {
				self.instr.cfa_off = 0;
				self.instr.cfa_reg = CfaRule::Expression(expression.0.to_slice().unwrap().to_vec());
     			},
	        	Undefined { register } => {
				let register = register.0 as usize;
				if register < MAX_REG {
					self.instr.regs[register] = RegRule::Undefined;
				}
			},
	        	SameValue { register } => {
				let register = register.0 as usize;
				if register < MAX_REG {
					self.instr.regs[register] = RegRule::SameValue;
				}
			},
			Offset { register, factored_offset } => {
				let register = register.0 as usize;
                		let off = factored_offset as i64 * self.data_align_factor;
				if register < MAX_REG {
					self.instr.regs[register] = RegRule::Offset(off);
				}
			},
			OffsetExtendedSf { register, factored_offset } => {
				let register = register.0 as usize;
				let off = factored_offset as i64 * self.data_align_factor;
				if register < MAX_REG {
					self.instr.regs[register] = RegRule::Offset(off);
				}
			},
			ValOffset { register, factored_offset } => {
				let register = register.0 as usize;
				let off = factored_offset as i64 * self.data_align_factor;
				if register < MAX_REG {
					self.instr.regs[register] = RegRule::ValOffset(off);
				}
			},
			ValOffsetSf { register, factored_offset } => {
				let register = register.0 as usize;
				let off = factored_offset as i64 * self.data_align_factor;
				if register < MAX_REG {
					self.instr.regs[register] = RegRule::ValOffset(off);
				}
			},
			Register { dest_register, src_register } => {
				let dest_register = dest_register.0 as usize;
				if dest_register < MAX_REG {
					if src_register.0 as usize >= MAX_REG {
						panic!("Unsupport Register instruction");
					}
					self.instr.regs[dest_register] = RegRule::Register(src_register);
				}
			},
			Expression { register, expression } => {
				let register = register.0 as usize;
				if register < MAX_REG {
					self.instr.regs[register] = RegRule::Expression(expression.0.to_slice().unwrap().to_vec());
				}
			},
			ValExpression { register, expression } => {
				let register = register.0 as usize;
				if register < MAX_REG {
					self.instr.regs[register] = RegRule::ValExpression(expression.0.to_slice().unwrap().to_vec());
				}
			},
			Restore { register } => {
				let register = register.0 as usize;
				if register < MAX_REG {
					self.instr.regs[register] = self.init_regs[register].clone();
				}
			},
            		RememberState => {
				self.stack.push(self.instr.clone());
			},
			RestoreState => {
				let loc = self.instr.loc;
				self.instr = self.stack.pop().unwrap();
				self.instr.loc = loc;
			},
			ArgsSize{ size: _ } => (),
			Nop => (),
			_ => panic!("unhandled instruction {:?}", instr),
		}
        }
	pub fn iter(&'a self) -> std::slice::Iter<'a, EhInstr> {
		self.instrs.iter()
	}
	pub fn get_fde_desc(&self, name: &String) -> Option<&FdeDesc> {
		self.fde_desc.get(name)
	}
}
