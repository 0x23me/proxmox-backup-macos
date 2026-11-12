fn main() {
    // `mount` uses FUSE-T's libfuse3. It is linked weakly, so the client starts without FUSE-T
    // and only `mount` fails, see `proxmox_fuse::Fuse::builder`.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-arg=-Wl,-weak_library,/usr/local/lib/libfuse3.dylib");
        println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/local/lib");
    }
}
