use std::collections::HashMap;
use procfs::process::{Process, MMapPath};
use libc::pid_t;

use goblin::elf::Elf;
use goblin::elf::program_header::*;

#[derive(Debug, Copy, Clone)]
pub struct Map {
	pub offset: u64,
	pub base: u64,
	pub vaddr: u64,
	pub size : u64,
}

pub struct FileMaps {
	path: String,
	maps: Vec<Map>
}

pub struct Files {
	files: HashMap<String, FileMaps>,
}

impl FileMaps {
	fn parse(&mut self) {
		println!("parse {}", self.path);
		let elf_data = std::fs::read(&self.path).unwrap();
		let elf = Elf::parse(&elf_data).unwrap();
		let headers = &elf.program_headers; // 获取程序头列表
		for map in &mut self.maps {
			let mut find = false;
			for ph in headers {
				if !ph.is_executable() {
					continue;
				}
				if ph.p_type != PT_LOAD {
					continue;
				}
				if map.offset == ph.p_offset {
					map.vaddr = ph.p_vaddr;
					if map.size < ph.p_memsz {
						panic!("base:{:X} va:{:X} offset:{:X} size:{:X} != {:X} {:X}", 
							map.base, ph.p_vaddr, ph.p_offset, ph.p_memsz, map.size, ph.p_filesz);
					}
					find = true;
					break
				}
			}
			if !find {
				panic!("offset:{} can't find map zone", map.offset);
			}

		}
	}
	pub fn translate(&self, vaddr: u64) ->u64 {
		for map in &self.maps {
			if vaddr >= map.vaddr && vaddr < (map.vaddr + map.size) {
				return vaddr - map.vaddr + map.base;
			}
		}
		panic!("{}: invalid {}", self.path, vaddr);
	}
}

impl Files {
	fn parse_files(pid: pid_t) ->HashMap<String, FileMaps> {
		let mut files = HashMap::new();
        // procfs 0.18
        if let Ok(process) = Process::new(pid) {
            if let Ok(maps) = process.maps() {
                for map in maps {
                    if !map.perms.contains(procfs::process::MMPermissions::EXECUTE) {
                        continue;
                    }
                    if let MMapPath::Path(path) = &map.pathname {
                        let path_str = path.to_string_lossy().into_owned();
                        if !path_str.starts_with("/") {
                            continue
                        }
                        let (start, end) = map.address;
                        files.entry(path_str.clone())
                            .or_insert(FileMaps{path: path_str, maps:Vec::new()}).maps
                            .push(Map {
                                vaddr: 0,
                                base : start,
                                offset: map.offset,
                                size: end - start,
                            });
                    }
                }
            }
        }
		
		for f in files.values_mut() {
			if f.path.contains("(deleted)") {
				continue
			}
			f.parse();
		}
		files
	}
	pub fn from_pid(pid: pid_t) -> Self {
		Files {
			files: Files::parse_files(pid),
		}
	}
	pub fn iter(&self) -> std::collections::hash_map::Iter::<'_, String, FileMaps> {
		self.files.iter()
	}
}
