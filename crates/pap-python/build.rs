fn main() {
    // Python extension modules on macOS must not link against libpython at build
    // time — the symbols are resolved at load time by the embedding interpreter.
    // Without this flag the macOS linker rejects unresolved symbols.
    #[cfg(target_os = "macos")]
    {
        println!("cargo:rustc-link-arg=-undefined");
        println!("cargo:rustc-link-arg=dynamic_lookup");
    }
}
