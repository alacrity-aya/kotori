use std::env;
use std::ffi::OsStr;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use libbpf_cargo::SkeletonBuilder;

const BPF_SRC: &str = "src/bpf/lb.bpf.c";
const VMLINUX: &str = "src/bpf/vmlinux.h";

fn main() {
    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("lb.skel.rs");

    // let _ = Command::new("rm").arg(VMLINUX).status();

    Command::new("bpftool")
        .arg("btf")
        .arg("dump")
        .arg("file")
        .arg("/sys/kernel/btf/vmlinux")
        .arg("format")
        .arg("c")
        .stdout(std::fs::File::create(VMLINUX).expect("Failed to create vmlinux.h file"))
        .status()
        .expect("Failed to execute bpftool. Is it installed and in PATH?");

    let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    SkeletonBuilder::new()
        .source(BPF_SRC)
        .clang_args([OsStr::new("-I"), Path::new(VMLINUX).join(arch).as_os_str()])
        .build_and_generate(out)
        .unwrap();
    println!("cargo:rerun-if-changed={}", BPF_SRC);
}
