use std::fs::create_dir_all;
use std::path::Path;

extern crate libbpf_cargo;
use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "./src/bpf/stack_pivot_poc.bpf.c";

fn main() {
    // It's unfortunate we cannot use `OUT_DIR` to store the generated skeleton.
    // Reasons are because the generated skeleton contains compiler attributes
    // that cannot be `include!()`ed via macro. And we cannot use the `#[path = "..."]`
    // trick either because you cannot yet `concat!(env!("OUT_DIR"), "/skel.rs")` inside
    // the path attribute either (see https://github.com/rust-lang/rust/pull/83366).
    //
    // However, there is hope! When the above feature stabilizes we can clean this
    // all up.
    create_dir_all("./src/bpf/.output").unwrap();
    let skel = Path::new("./src/bpf/.output/stack_pivot_poc.skel.rs");
    SkeletonBuilder::new(SRC)
        .generate(&skel)
        .expect("bpf compilation failed");
    println!("cargo:rerun-if-changed={}", SRC);
}
