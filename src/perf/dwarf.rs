// DWARF-based variable location extraction
// This module attempts to extract the location of lua_State *L parameter
// from DWARF debug info, which is more accurate than heuristic disassembly.

use std::collections::HashMap;
use anyhow::{anyhow, Result};
use gimli::{
    AttributeValue, DW_AT_location, DW_AT_name, DW_AT_low_pc, DW_AT_high_pc,
    DW_TAG_subprogram, DW_TAG_formal_parameter,
    DebuggingInformationEntry, Dwarf, EndianSlice, LittleEndian, Unit,
    Reader, Operation, Expression,
};
use goblin::elf::Elf;
use super::var::{FnVarPos, VarPos};

/// Variable location for a specific PC range
#[derive(Debug, Clone)]
pub struct VarLocation {
    pub pc_begin: u64,
    pub pc_end: u64,
    pub loc: VarLoc,
}

#[derive(Debug, Clone)]
pub enum VarLoc {
    Register(u16),           // Variable is in a register
    FrameOffset(i64),        // Variable is at CFA + offset (memory)
    RegOffset(u16, i64),     // Variable is at reg + offset (memory)
    // Add more as needed
}

fn map_reg(reg: u16) -> Option<String> {
    match reg {
        3 => Some("rbx".to_string()),
        6 => Some("rbp".to_string()),
        7 => Some("rsp".to_string()),
        12 => Some("r12".to_string()),
        13 => Some("r13".to_string()),
        14 => Some("r14".to_string()),
        15 => Some("r15".to_string()),
        _ => None,
    }
}

#[allow(dead_code)]
pub fn get_lua_var_pos(elf_data: &[u8]) -> Result<Vec<FnVarPos>> {
    let locs_map = extract_l_locations(elf_data)?;
    let mut result = Vec::new();

    for (_func_name, locs) in locs_map {
        for loc in locs {
            let pos = match loc.loc {
                VarLoc::Register(r) => {
                    if let Some(name) = map_reg(r) {
                        VarPos::Reg(name)
                    } else {
                        continue;
                    }
                },
                VarLoc::RegOffset(r, offset) => {
                     if let Some(name) = map_reg(r) {
                        VarPos::Mem(name, offset)
                    } else {
                        continue;
                    }
                }
                VarLoc::FrameOffset(_offset) => {
                    // TODO: Support FrameOffset (requires knowing CFA register)
                    // For now, skip to avoid incorrect BPF behavior
                    continue;
                }
            };

            result.push(FnVarPos {
                addr: loc.pc_begin,
                size: loc.pc_end - loc.pc_begin,
                pos,
            });
        }
    }
    // Sort by address for consistent order
    result.sort_by_key(|v| v.addr);
    Ok(result)
}

pub fn get_var_pos_at(func_name: &str, addr: u64, locs_map: &HashMap<String, Vec<VarLocation>>) -> Option<FnVarPos> {
    if let Some(locs) = locs_map.get(func_name) {
        for loc in locs {
            if addr >= loc.pc_begin && addr < loc.pc_end {
                 let pos = match loc.loc {
                    VarLoc::Register(r) => {
                        map_reg(r).map(VarPos::Reg)
                    },
                    VarLoc::RegOffset(r, offset) => {
                        map_reg(r).map(|name| VarPos::Mem(name, offset))
                    },
                    _ => None,
                };

                if let Some(p) = pos {
                    return Some(FnVarPos {
                        addr: loc.pc_begin,
                        size: loc.pc_end - loc.pc_begin,
                        pos: p,
                    });
                }
            }
        }
    }
    None
}

/// Extract L variable locations for luaV_execute and related functions
#[allow(dead_code)]
pub fn extract_l_locations(elf_data: &[u8]) -> Result<HashMap<String, Vec<VarLocation>>> {
    let elf = Elf::parse(elf_data).map_err(|e| anyhow!("Failed to parse ELF: {}", e))?;
    // println!("ELF: Machine={:?}, 64bit={}, LittleEndian={}", elf.header.e_machine, elf.is_64, elf.little_endian);

    // Load DWARF using gimli::Dwarf::load which handles all sections automatically
    let dwarf = Dwarf::load(|id| -> Result<_, gimli::Error> {
        let name = id.name();
        // find_section returns Result<&[u8]>, match it
        let data = match find_section(&elf, elf_data, name) {
            Ok(d) => d,
            Err(_) => &[],
        };
        Ok(EndianSlice::new(data, LittleEndian))
    })?;

    let mut results: HashMap<String, Vec<VarLocation>> = HashMap::new();

    // Target functions we care about
    let target_funcs = ["luaV_execute", "luaD_call", "luaD_callnoyield", "luaD_rawrunprotected"];

    // Iterate compilation units
    let mut units = dwarf.units();
    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;
        let mut entries = unit.entries();

        while let Some((_, entry)) = entries.next_dfs()? {
            if entry.tag() != DW_TAG_subprogram {
                continue;
            }

            // Get function name
            let func_name = match get_string_attr(&dwarf, &unit, entry, DW_AT_name)? {
                Some(name) => name,
                None => continue,
            };

            if !target_funcs.contains(&func_name.as_str()) {
                continue;
            }

            // Get function address range
            let (low_pc, high_pc) = match get_func_range(&unit, entry)? {
                Some(range) => range,
                None => continue,
            };

            // println!("Found function: {} [{:#x} - {:#x}]", func_name, low_pc, high_pc);

            // Find L parameter (first parameter)
            let l_locations = find_l_parameter_locations(&dwarf, &unit, entry, low_pc, high_pc)?;

            if !l_locations.is_empty() {
                // println!("  L locations: {:?}", l_locations);
                results.insert(func_name, l_locations);
            }
        }
    }

    Ok(results)
}

fn find_section<'a>(elf: &Elf, data: &'a [u8], name: &str) -> Result<&'a [u8]> {
    for sh in &elf.section_headers {
        if let Some(sh_name) = elf.shdr_strtab.get_at(sh.sh_name) {
            if sh_name == name {
                let start = sh.sh_offset as usize;
                let end = start + sh.sh_size as usize;
                return Ok(&data[start..end]);
            }
        }
    }
    Err(anyhow!("Section {} not found", name))
}

fn get_string_attr<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    attr_name: gimli::DwAt,
) -> Result<Option<String>> {
    let attr = match entry.attr(attr_name)? {
        Some(attr) => attr,
        None => return Ok(None),
    };

    match attr.value() {
        AttributeValue::String(s) => Ok(Some(s.to_string_lossy()?.to_string())),
        AttributeValue::DebugStrRef(offset) => {
            let s = dwarf.debug_str.get_str(offset)?;
            Ok(Some(s.to_string_lossy()?.to_string()))
        }
        AttributeValue::DebugStrOffsetsIndex(index) => {
            let offset = dwarf.debug_str_offsets.get_str_offset(
                unit.header.format(),
                unit.str_offsets_base,
                index,
            )?;
            let s = dwarf.debug_str.get_str(offset)?;
            Ok(Some(s.to_string_lossy()?.to_string()))
        }
        _ => Ok(None),
    }
}

fn get_func_range<R: Reader>(
    _unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
) -> Result<Option<(u64, u64)>> {
    let low_pc = match entry.attr(DW_AT_low_pc)? {
        Some(attr) => match attr.value() {
            AttributeValue::Addr(addr) => addr,
            _ => return Ok(None),
        },
        None => return Ok(None),
    };

    let high_pc = match entry.attr(DW_AT_high_pc)? {
        Some(attr) => match attr.value() {
            AttributeValue::Addr(addr) => addr,
            AttributeValue::Udata(offset) => low_pc + offset,
            _ => return Ok(None),
        },
        None => return Ok(None),
    };

    Ok(Some((low_pc, high_pc)))
}

fn find_l_parameter_locations<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    func_entry: &DebuggingInformationEntry<R>,
    func_low_pc: u64,
    func_high_pc: u64,
) -> Result<Vec<VarLocation>> {
    let mut locations = Vec::new();

    // We need to iterate children to find DW_TAG_formal_parameter
    // The first parameter should be 'L' for these Lua functions
    let mut tree = unit.entries_tree(Some(func_entry.offset()))?;
    let root = tree.root()?;
    let mut children = root.children();

    while let Some(child) = children.next()? {
        let entry = child.entry();
        if entry.tag() != DW_TAG_formal_parameter {
            continue;
        }

        // Check if this is the L parameter (first param, or named "L")
        let param_name = get_string_attr(dwarf, unit, entry, DW_AT_name)?;
        // println!("  Found parameter: {:?}", param_name);

        // Get location attribute
        let loc_attr = match entry.attr(DW_AT_location)? {
            Some(attr) => attr,
            None => continue,
        };

        match loc_attr.value() {
            AttributeValue::Exprloc(expr) => {
                // Simple location expression - same location for entire scope
                if let Some(loc) = parse_location_expr(expr)? {
                    locations.push(VarLocation {
                        pc_begin: func_low_pc,
                        pc_end: func_high_pc,
                        loc,
                    });
                }
            }
            AttributeValue::LocationListsRef(offset) => {
                // Location list - different locations for different PC ranges
                let mut locs = dwarf.locations(unit, offset)?;
                while let Some(entry) = locs.next()? {
                    if let Some(loc) = parse_location_expr(entry.data)? {
                        let range = entry.range;
                        locations.push(VarLocation {
                            pc_begin: range.begin,
                            pc_end: range.end,
                            loc,
                        });
                    }
                }
            }
            AttributeValue::DebugLocListsIndex(index) => {
                // DWARF5 location list index
                let offset = dwarf.locations.get_offset(
                    unit.encoding(),
                    unit.loclists_base,
                    index,
                )?;
                let mut locs = dwarf.locations(unit, offset)?;
                while let Some(entry) = locs.next()? {
                    if let Some(loc) = parse_location_expr(entry.data)? {
                        let range = entry.range;
                        locations.push(VarLocation {
                            pc_begin: range.begin,
                            pc_end: range.end,
                            loc,
                        });
                    }
                }
            }
            _ => {
                // println!("  Unhandled location attribute: {:?}", loc_attr.value());
            }
        }

        // Only process first parameter (L)
        if param_name.as_deref() == Some("L") {
            break;
        }
    }

    Ok(locations)
}

fn parse_location_expr<R: Reader>(expr: Expression<R>) -> Result<Option<VarLoc>> {
    let mut ops = expr.operations(gimli::Encoding {
        address_size: 8,
        format: gimli::Format::Dwarf64,
        version: 4,
    });

    // Parse the first operation - this handles simple cases
    match ops.next()? {
        Some(Operation::Register { register }) => {
            Ok(Some(VarLoc::Register(register.0)))
        }
        Some(Operation::FrameOffset { offset }) => {
            Ok(Some(VarLoc::FrameOffset(offset)))
        }
        Some(Operation::RegisterOffset { register, offset, base_type: _ }) => {
            Ok(Some(VarLoc::RegOffset(register.0, offset)))
        }
        Some(Operation::EntryValue { expression }) => {
             // Handle EntryValue(Reg) -> Treat as Reg
             let mut inner_ops = gimli::Expression(expression).operations(gimli::Encoding {
                address_size: 8,
                format: gimli::Format::Dwarf64,
                version: 4,
            });
            if let Ok(Some(Operation::Register { register })) = inner_ops.next() {
                 Ok(Some(VarLoc::Register(register.0)))
            } else {
                 // println!("  Complex EntryValue: {:?}", expression);
                 Ok(None)
            }
        }
        Some(_op) => {
            // println!("  Unhandled DWARF operation: {:?}", _op);
            Ok(None)
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_locations() {
        // Test with a Lua binary that has debug info
        let paths = [
            "lua.gcc.o0",
            "lua.gcc.o2",
            "lua.clang.o0",
            "lua.clang.o2",
        ];

        for path in &paths {
            println!("Trying to read: {}", path);
            if let Ok(data) = std::fs::read(path) {
                println!("\n=== Testing {} ===", path);
                match extract_l_locations(&data) {
                    Ok(locs) => {
                        for (func, locations) in &locs {
                            println!("{}: {:?}", func, locations);
                        }
                    }
                    Err(e) => println!("Error: {:?}", e),
                }
            }
        }
    }
}