use dataplane::DataplaneConfig;
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RuntimeConfig {
    pub dataplane: DataplaneConfig,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        RuntimeConfig {
            dataplane: DataplaneConfig::default(),
        }
    }
}

pub fn load_runtime_config(root: &Path) -> Result<RuntimeConfig, String> {
    let path = root.join("aegis.yaml");
    if !path.exists() {
        return Ok(RuntimeConfig::default());
    }
    let body = fs::read_to_string(&path)
        .map_err(|e| format!("read runtime config {}: {e}", path.display()))?;
    if body.trim().is_empty() {
        return Ok(RuntimeConfig::default());
    }
    let cfg: RuntimeConfig = serde_yaml::from_str(&body)
        .map_err(|e| format!("parse runtime config {}: {e}", path.display()))?;
    Ok(cfg)
}
