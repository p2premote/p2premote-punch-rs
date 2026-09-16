fn main() {
    // p2p_diag_line writes to logcat on Android; std already links liblog
    // there, but be explicit so bare consumers link cleanly too.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        println!("cargo:rustc-link-lib=log");
    }
}
