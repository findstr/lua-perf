use goblin::elf::Elf;
use std::fs;
use std::path::Path;
use anyhow::{anyhow, Result};

pub fn detect_lua_version<P: AsRef<Path>>(path: P) -> Result<String> {
    let data = fs::read(path)?;
    let elf = Elf::parse(&data).map_err(|e| anyhow!("Failed to parse ELF: {}", e))?;

    // 1. Try to find lua_ident symbol
    let mut ident_offset = None;

    // Check dynamic symbols first (if stripped but exported)
    for sym in &elf.dynsyms {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            // println!("DynSym: {}", name);
            if name == "lua_ident" {
                println!("Found lua_ident in dynsyms at vaddr: {:x}", sym.st_value);
                // Determine file offset from virtual address
                if let Some(offset) = vaddr_to_offset(&elf, sym.st_value) {
                    ident_offset = Some(offset);
                    break;
                }
            }
        }
    }

    // Check normal symbol table
    if ident_offset.is_none() {
        for sym in &elf.syms {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if name == "lua_ident" {
                    println!("Found lua_ident in syms at vaddr: {:x}", sym.st_value);
                    if let Some(offset) = vaddr_to_offset(&elf, sym.st_value) {
                        ident_offset = Some(offset);
                        break;
                    }
                }
            }
        }
    }

    if let Some(offset) = ident_offset {
        let s = extract_string(&data, offset as usize);
        // println!("Read lua_ident string: '{}'", s);

        // Normalize: Find "Lua " or "Lua: " followed by digit
        // Standard: "$Lua: 5.4.4"
        // Custom: "$LuaVersion: Lua 5.5.0"
        let version_part = if let Some(idx) = s.find("Lua: ") {
            &s[idx + 5..]
        } else if let Some(idx) = s.find("Lua ") {
            &s[idx + 4..]
        } else {
            return Err(anyhow!("Unknown lua_ident format: {}", s));
        };

        if version_part.starts_with("5.4") {
            return Ok("5.4".to_string());
        } else if version_part.starts_with("5.3") {
            return Ok("5.3".to_string());
        } else if version_part.starts_with("5.1") {
            return Ok("5.1".to_string());
        } else if version_part.starts_with("5.") {
             // Fallback for 5.5, 5.2, etc. return first 3 chars "5.x"
             return Ok(version_part.chars().take(3).collect());
        }
    }

    Err(anyhow!("Could not find lua_ident or parse version"))
}

fn vaddr_to_offset(elf: &Elf, vaddr: u64) -> Option<u64> {
    for ph in &elf.program_headers {
        if ph.p_type == goblin::elf::program_header::PT_LOAD {
            if vaddr >= ph.p_vaddr && vaddr < ph.p_vaddr + ph.p_filesz {
                return Some(vaddr - ph.p_vaddr + ph.p_offset);
            }
        }
    }
    None
}

fn extract_string(data: &[u8], offset: usize) -> String {
    let mut end = offset;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    String::from_utf8_lossy(&data[offset..end]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_version() {
        let path = "~/silly/silly";
        if std::path::Path::new(path).exists() {
            match detect_lua_version(path) {
                Ok(v) => println!("Detected Lua version: {}", v),
                Err(e) => println!("Detection failed: {}", e),
            }
        }
    }
}
