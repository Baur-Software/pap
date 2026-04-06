fn main() {
    // Re-run if anything in src/ changes.
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");

    // Generate include/pap.h from the Rust source.
    // This is committed to the repo for convenience so C/C++/C# consumers
    // don't need the Rust toolchain to obtain the header.
    let crate_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is always set by cargo");
    let config =
        cbindgen::Config::from_file("cbindgen.toml").expect("unable to read cbindgen.toml");

    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("unable to generate C bindings")
        .write_to_file("include/pap.h");
}
