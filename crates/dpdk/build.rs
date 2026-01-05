fn main() {
    if std::env::var("CARGO_FEATURE_DPDK").is_err() {
        return;
    }
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() != "linux" {
        return;
    }
    let lib = pkg_config::Config::new()
        .probe("libdpdk")
        .expect("libdpdk not found (install DPDK dev packages)");
    let mut build = cc::Build::new();
    build.file("src/shim.c");
    for inc in lib.include_paths {
        build.include(inc);
    }
    build.compile("aegis_dpdk_shim");
}
