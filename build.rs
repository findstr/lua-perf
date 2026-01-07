use std::env;
use std::fs::File;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;

extern crate libbpf_cargo;
use libbpf_cargo::SkeletonBuilder;

const BPF_SRC: &str = concat!("src/bpf/", "profile.bpf.c");

fn btf_dump() {
        // Check if we should skip BTF dump (e.g., vmlinux.h already exists in src/bpf/)
        if env::var("SKIP_BTF_DUMP").is_ok() {
                println!("cargo:warning=Skipping BTF dump, using existing vmlinux.h");
                return;
        }

        let mut out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
        out.push("vmlinux.h");
        let path = out.to_str().unwrap();
        let btf = File::create(&out).expect(format!("failed to open: {}", path).as_str());
        let mut cmd = Command::new("bpftool")
                .args(&["btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c"])
                .stdout(btf)
                .spawn()
                .expect("failed to generate vmlinux.h");
        cmd.wait().expect("fail to generate vmlinux.h");
        println!("cargo:rerun-if-changed={}", path);
}

fn output() ->String {
        let out_dir = env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script");
        let out_dir_str = out_dir.to_str().unwrap();
        String::from_str(out_dir_str).unwrap()
}
fn build_skel() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));

    // When SKIP_BTF_DUMP is set, vmlinux.h is in src/bpf/ instead of OUT_DIR
    let include_out = format!("-I{}", output());
    let include_src_bpf = "-Isrc/bpf".to_string();

    // Define versions: (suffix, clang_flags)
    // Suffix "" means default filename "profile.skel.rs" (Lua 5.4.0 default)
    let versions = vec![
        ("_5_5_0", vec!["-DLUA_VERSION_5_5_0"]),
        ("_5_4_0", vec!["-DLUA_VERSION_5_4_0"]),
        ("_5_3_6", vec!["-DLUA_VERSION_5_3_6"]),
    ];

    for (suffix, flags) in versions {
        let mut out = out_dir.clone();
        out.push(format!("profile{}.skel.rs", suffix));

        // Include both OUT_DIR (for normal builds) and src/bpf (for pre-generated vmlinux.h)
        let mut args = vec![include_out.clone(), include_src_bpf.clone()];
        for f in flags {
            args.push(f.to_string());
        }

        SkeletonBuilder::new()
                .clang_args(args)
                .source(BPF_SRC)
                .build_and_generate(&out)
                .unwrap();
    }

    println!("cargo:rerun-if-changed={BPF_SRC}");
    println!("cargo:rerun-if-changed=src/bpf/profile.h");
    println!("cargo:rerun-if-changed=src/bpf/hash.h");
    println!("cargo:rerun-if-changed=src/bpf/lua.h");
    println!("cargo:rerun-if-changed=src/bpf/lua_5_3_6.h");
    println!("cargo:rerun-if-changed=src/bpf/lua_5_4_0.h");
    println!("cargo:rerun-if-changed=src/bpf/lua_5_5_0.h");
}

fn main() {
        btf_dump();
        build_skel();
}
