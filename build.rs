fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winresource::WindowsResource::new()
            .set_icon("assets/icon.ico")
            .compile()
            .expect("failed to embed the Windows application icon");

        if std::env::var("PROFILE").as_deref() == Ok("release") {
            // Scope elevation to the shipped app so `cargo test --release`
            // does not require an interactive UAC prompt.
            println!("cargo:rustc-link-arg-bin=rust-vpn-splitter=/MANIFEST:EMBED");
            println!(
                "cargo:rustc-link-arg-bin=rust-vpn-splitter=/MANIFESTUAC:level='requireAdministrator' uiAccess='false'"
            );
        }
    }
}
