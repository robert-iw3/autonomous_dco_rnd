use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::fs;

fn main() {
    let mut out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("sentinel.skel.rs");

    let bpf_dir = Path::new("src/bpf");
    let vmlinux_path = bpf_dir.join("vmlinux.h");

    // Dynamically generate vmlinux.h if it does not exist
    if !vmlinux_path.exists() {
        println!("cargo:warning=vmlinux.h not found. Attempting dynamic generation...");

        // Try bpftool (works on bare-metal or container with /sys/kernel/btf/vmlinux mounted)
        let btf_file = fs::File::create(&vmlinux_path).expect("Failed to create vmlinux.h output file");
        let bpftool_status = Command::new("bpftool")
            .args(&["btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c"])
            .stdout(btf_file)
            .status();

        // Fallback: If bpftool fails, pull the pre-downloaded Tracee vmlinux.h from the orchestration staging dir
        if bpftool_status.is_err() || !bpftool_status.unwrap().success() {
            println!("cargo:warning=bpftool BTF dump failed. Falling back to staged Tracee vmlinux.h");

            let staged_vmlinux = Path::new("intel_staging/bpf/vmlinux.h");
            if staged_vmlinux.exists() {
                fs::copy(staged_vmlinux, &vmlinux_path)
                    .expect("Failed to copy staged vmlinux.h to src/bpf/");
            } else {
                panic!("FATAL: bpftool failed and intel_staging/bpf/vmlinux.h not found. Cannot compile eBPF offline.");
            }
        }
    }

    SkeletonBuilder::new()
        .source("src/bpf/sentinel.bpf.c")
        .build_and_generate(&out)
        .expect("bpf compilation failed");

    println!("cargo:rerun-if-changed=src/bpf/sentinel.bpf.c");
}