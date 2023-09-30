use std::env;
use std::fs::File;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;

extern crate libbpf_cargo;
use libbpf_cargo::SkeletonBuilder;

const BPF_SRC: &str = concat!("src/bpf/", "profile.bpf.c");

fn btf_dump() {
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
        println!("cargo:cargo rerun-if-not-exists={}", path);
}

fn output() ->String {
        let out_dir = env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script");
        let out_dir_str = out_dir.to_str().unwrap().clone();
        String::from_str(out_dir_str).unwrap()
}
fn build_skel() {
        let mut out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
        out.push("profile.skel.rs");
        let include = format!("-I{}", output());
        SkeletonBuilder::new()
                .debug(true)
                .clang_args(include)
                .source(BPF_SRC)
                .build_and_generate(&out)
                .unwrap();
        println!("cargo:rerun-if-changed={BPF_SRC}");
        println!("cargo:rerun-if-changed=src/bpf/lstate.h");
        println!("cargo:rerun-if-changed=src/bpf/profile.h");
        println!("cargo:rerun-if-changed=src/bpf/hash.h");
}

fn main() {
        btf_dump();
        build_skel();
}
