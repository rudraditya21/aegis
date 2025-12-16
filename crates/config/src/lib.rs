#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_ROOT: &str = "/etc/aegis";
const MAX_BACKUPS_DEFAULT: usize = 5;

#[derive(Debug, Clone)]
pub struct ConfigPaths {
    pub root: PathBuf,
    pub rules_l3l4: PathBuf,
    pub rules_dpi: PathBuf,
    pub policies: PathBuf,
    pub intel_ip: PathBuf,
    pub intel_domain: PathBuf,
    pub state_dir: PathBuf,
    pub flows_snapshot: PathBuf,
    pub counters_bin: PathBuf,
    pub logs_alerts: PathBuf,
    pub logs_dpi: PathBuf,
    pub logs_audit: PathBuf,
    versions_dir: PathBuf,
    meta_file: PathBuf,
}

impl ConfigPaths {
    pub fn new(root: PathBuf) -> Self {
        let rules_dir = root.join("rules");
        let intel_dir = root.join("intel");
        let state_dir = root.join("state");
        let logs_dir = root.join("logs");
        let versions_dir = state_dir.join("versions");
        ConfigPaths {
            root: root.clone(),
            rules_l3l4: rules_dir.join("l3l4.rules"),
            rules_dpi: rules_dir.join("dpi.rules"),
            policies: rules_dir.join("policies.rules"),
            intel_ip: intel_dir.join("ip_blocklist.txt"),
            intel_domain: intel_dir.join("domain_blocklist.txt"),
            state_dir: state_dir.clone(),
            flows_snapshot: state_dir.join("flows.snapshot"),
            counters_bin: state_dir.join("counters.bin"),
            logs_alerts: logs_dir.join("alerts.log"),
            logs_dpi: logs_dir.join("dpi.log"),
            logs_audit: logs_dir.join("audit.log"),
            versions_dir: versions_dir.clone(),
            meta_file: state_dir.join("config_meta"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConfigMeta {
    pub version: u64,
    pub hash_hex: String,
    pub updated_at: u64,
}

#[derive(Debug, Clone)]
pub struct ConfigSnapshot {
    pub paths: ConfigPaths,
    pub version: u64,
    pub hash_hex: String,
    pub tampered: bool,
}

pub struct ConfigManager {
    pub paths: ConfigPaths,
    max_backups: usize,
}

impl ConfigManager {
    pub fn default_root() -> PathBuf {
        std::env::var("AEGIS_CONFIG_ROOT")
            .or_else(|_| std::env::var("FIREWALL_CONFIG_ROOT"))
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_ROOT))
    }

    pub fn new_with_backups(root: PathBuf, max_backups: usize) -> Result<Self, String> {
        let paths = ConfigPaths::new(root);
        let mgr = ConfigManager {
            paths,
            max_backups: max_backups.max(1),
        };
        mgr.ensure_layout()?;
        Ok(mgr)
    }

    pub fn new(root: PathBuf) -> Result<Self, String> {
        Self::new_with_backups(root, MAX_BACKUPS_DEFAULT)
    }

    fn ensure_layout(&self) -> Result<(), String> {
        let dirs = [
            self.paths.root.as_path(),
            self.paths.rules_l3l4.parent().unwrap(),
            self.paths.rules_dpi.parent().unwrap(),
            self.paths.intel_ip.parent().unwrap(),
            self.paths.state_dir.as_path(),
            self.paths.logs_alerts.parent().unwrap(),
            self.paths.versions_dir.as_path(),
        ];
        for d in dirs {
            fs::create_dir_all(d).map_err(|e| format!("create dir {}: {e}", d.display()))?;
        }
        Ok(())
    }

    fn load_meta(&self) -> ConfigMeta {
        if let Ok(mut f) = File::open(&self.paths.meta_file) {
            let mut buf = String::new();
            if f.read_to_string(&mut buf).is_ok() {
                let mut version = 0u64;
                let mut hash_hex = String::new();
                let mut updated_at = 0u64;
                for line in buf.lines() {
                    if let Some(rest) = line.strip_prefix("version=") {
                        version = rest.trim().parse().unwrap_or(0);
                    } else if let Some(rest) = line.strip_prefix("hash=") {
                        hash_hex = rest.trim().to_string();
                    } else if let Some(rest) = line.strip_prefix("updated_at=") {
                        updated_at = rest.trim().parse().unwrap_or(0);
                    }
                }
                return ConfigMeta {
                    version,
                    hash_hex,
                    updated_at,
                };
            }
        }
        ConfigMeta {
            version: 0,
            hash_hex: String::new(),
            updated_at: 0,
        }
    }

    fn write_meta(&self, meta: &ConfigMeta) -> Result<(), String> {
        let mut f = File::create(&self.paths.meta_file)
            .map_err(|e| format!("write meta {}: {e}", self.paths.meta_file.display()))?;
        let body = format!(
            "version={}\nhash={}\nupdated_at={}\n",
            meta.version, meta.hash_hex, meta.updated_at
        );
        f.write_all(body.as_bytes())
            .map_err(|e| format!("write meta {}: {e}", self.paths.meta_file.display()))
    }

    fn hash_files(&self, files: &[&Path]) -> String {
        let mut hasher = Sha256::new();
        for path in files {
            if let Ok(mut f) = File::open(path) {
                let _ = hasher.update(path.to_string_lossy().as_bytes());
                let mut buf = [0u8; 8192];
                loop {
                    match f.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            hasher.update(&buf[..n]);
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        let digest = hasher.finalize();
        hex::encode(digest)
    }

    fn tracked_files(&self) -> Vec<PathBuf> {
        vec![
            self.paths.rules_l3l4.clone(),
            self.paths.rules_dpi.clone(),
            self.paths.policies.clone(),
            self.paths.intel_ip.clone(),
            self.paths.intel_domain.clone(),
        ]
    }

    pub fn snapshot(&self) -> ConfigSnapshot {
        let meta = self.load_meta();
        let tracked = self.tracked_files();
        let hash = self.hash_files(&tracked.iter().map(|p| p.as_path()).collect::<Vec<_>>());
        let tampered = !meta.hash_hex.is_empty() && meta.hash_hex != hash;
        ConfigSnapshot {
            paths: self.paths.clone(),
            version: meta.version,
            hash_hex: hash,
            tampered,
        }
    }

    pub fn record_version(&self) -> Result<ConfigMeta, String> {
        let mut meta = self.load_meta();
        let tracked = self.tracked_files();
        let hash = self.hash_files(&tracked.iter().map(|p| p.as_path()).collect::<Vec<_>>());
        meta.version = meta.version.saturating_add(1);
        meta.hash_hex = hash.clone();
        meta.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let version_dir = self.paths.versions_dir.join(format!("{}", meta.version));
        fs::create_dir_all(&version_dir)
            .map_err(|e| format!("create version dir {}: {e}", version_dir.display()))?;
        for path in tracked {
            if path.exists() {
                let fname = path
                    .file_name()
                    .map(|n| n.to_owned())
                    .unwrap_or_else(|| "config".into());
                let dest = version_dir.join(fname);
                let _ = fs::copy(&path, dest);
            }
        }

        self.prune_backups()?;
        self.write_meta(&meta)?;
        Ok(meta)
    }

    fn prune_backups(&self) -> Result<(), String> {
        let mut entries: Vec<_> = fs::read_dir(&self.paths.versions_dir)
            .map_err(|e| format!("read versions dir {}: {e}", self.paths.versions_dir.display()))?
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                e.file_name()
                    .to_string_lossy()
                    .parse::<u64>()
                    .ok()
                    .map(|ver| (ver, e.path()))
            })
            .collect();
        entries.sort_by_key(|(ver, _)| *ver);
        while entries.len() > self.max_backups {
            if let Some((_, path)) = entries.first() {
                let _ = fs::remove_dir_all(path);
            }
            entries.remove(0);
        }
        Ok(())
    }

    pub fn rollback(&self) -> Result<ConfigSnapshot, String> {
        let meta = self.load_meta();
        if meta.version == 0 {
            return Err("no previous versions to rollback".into());
        }
        let target_version = meta.version.saturating_sub(1);
        let target_dir = self.paths.versions_dir.join(format!("{}", target_version));
        if !target_dir.exists() {
            return Err(format!(
                "backup version {} not found in {}",
                target_version,
                target_dir.display()
            ));
        }
        let tracked = self.tracked_files();
        for path in tracked {
            if let Some(fname) = path.file_name() {
                let backup = target_dir.join(fname);
                if backup.exists() {
                    if let Some(parent) = path.parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    let _ = fs::copy(backup, &path);
                }
            }
        }
        let snap = self.snapshot();
        self.write_meta(&ConfigMeta {
            version: target_version,
            hash_hex: snap.hash_hex.clone(),
            updated_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        })?;
        Ok(self.snapshot())
    }
}
