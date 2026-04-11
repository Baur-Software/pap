fn main() {
    // ── DOCA hardware crypto ──────────────────────────────────────────────
    // When doca-crypto is requested, link against libdoca_crypto from the
    // NVIDIA DOCA SDK.  Set DOCA_SDK_PATH to a non-standard install prefix.
    if std::env::var("CARGO_FEATURE_DOCA_CRYPTO").is_ok() {
        let sdk =
            std::env::var("DOCA_SDK_PATH").unwrap_or_else(|_| "/opt/mellanox/doca".to_string());
        println!("cargo:rustc-link-search=native={sdk}/lib");
        println!("cargo:rustc-link-lib=doca_crypto");
        println!("cargo:rerun-if-env-changed=DOCA_SDK_PATH");
    }

    // ── Rerun triggers ────────────────────────────────────────────────────
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_DOCA_CRYPTO");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_RDMA");
}
