fn main() {
    // Allow overriding libpcap location.
    if let Ok(path) = std::env::var("PCAP_LIB_DIR") {
        println!("cargo:rustc-link-search=native={path}");
    }
    println!("cargo:rustc-link-lib=pcap");
}
