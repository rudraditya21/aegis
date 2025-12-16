#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

pub fn config_root() -> PathBuf {
    std::env::var("AEGIS_CONFIG_ROOT")
        .ok()
        .or_else(|| std::env::var("FIREWALL_CONFIG_ROOT").ok())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/aegis"))
}

pub fn resolve_config_path(path: &str, allow_write: bool) -> Result<PathBuf, String> {
    let root = config_root();
    let root_canon = if root.exists() {
        root.canonicalize().unwrap_or_else(|_| root.clone())
    } else {
        root.clone()
    };
    let p = Path::new(path);
    let abs = if p.exists() {
        p.canonicalize()
            .map_err(|e| format!("canonicalize {path}: {e}"))?
    } else {
        let parent = p.parent().unwrap_or_else(|| Path::new("."));
        let base = if parent.exists() {
            parent
                .canonicalize()
                .map_err(|e| format!("canonicalize parent of {path}: {e}"))?
        } else {
            root_canon.clone()
        };
        base.join(p.file_name().ok_or_else(|| "invalid path".to_string())?)
    };
    if abs.components().count() == 0 || !abs.starts_with(&root_canon) {
        return Err(format!(
            "path {} must reside under config root {}",
            abs.display(),
            root_canon.display()
        ));
    }
    if allow_write {
        enforce_writable(&abs)?;
    }
    Ok(abs)
}

pub fn enforce_writable(path: &Path) -> Result<(), String> {
    let readonly = std::env::var("AEGIS_CONFIG_READONLY")
        .ok()
        .or_else(|| std::env::var("FIREWALL_CONFIG_READONLY").ok())
        .unwrap_or_default();
    if readonly == "1" {
        return Err("configuration is read-only (AEGIS_CONFIG_READONLY=1)".into());
    }
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.permissions().readonly() {
            return Err(format!("path {} is read-only", path.display()));
        }
    }
    Ok(())
}

pub fn hex_to_bytes(input: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() % 2 != 0 {
        return Err("hex string must have even length".into());
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for chunk in cleaned.as_bytes().chunks(2) {
        let hi = (chunk[0] as char)
            .to_digit(16)
            .ok_or("invalid hex character")?;
        let lo = (chunk[1] as char)
            .to_digit(16)
            .ok_or("invalid hex character")?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

pub fn hex_to_bytes_or_exit(input: &str) -> Vec<u8> {
    match hex_to_bytes(input) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
