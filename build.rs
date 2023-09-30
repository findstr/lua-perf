use std::env;
use std::fs::File;
use std::path::PathBuf;
use std::process::Command;

extern crate libbpf_cargo;
use libbpf_cargo::SkeletonBuilder;

const BPF_SRC: &str = concat!("src/bpf/", "profile.bpf.c");
const BPF_BTF: &str = concat!("src/bpf/", "vmlinux.h");

fn btf_dump() {
        let btf = File::create(BPF_BTF).expect(format!("failed to open: {}", BPF_BTF).as_str());
        let mut cmd = Command::new("bpftool")
                .args(&["btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c"])
                .stdout(btf)
                .spawn()
                .expect("failed to generate vmlinux.h");
        cmd.wait().expect("fail to generate vmlinux.h");
        println!("cargo:cargo rerun-if-not-exists={}", BPF_BTF);
}

fn build_skel() {
        let mut out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
        out.push("profile.skel.rs");
        SkeletonBuilder::new()
                .source(BPF_SRC)
                .build_and_generate(&out)
                .unwrap();
        println!("cargo:rerun-if-changed={BPF_SRC}");
        println!("cargo:rerun-if-changed=src/bpf/lstate.h");
        println!("cargo:rerun-if-changed=src/bpf/profile.h");
        println!("cargo:rerun-if-changed=src/bpf/jhash.h");
}

fn main() {
        btf_dump();
        build_skel();
}
