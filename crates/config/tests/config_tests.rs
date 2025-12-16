#![forbid(unsafe_code)]

use aegis_config::{ConfigManager, ConfigPaths};
use std::fs;
use std::io::Write;
use tempfile::tempdir;

#[test]
fn records_and_detects_hash_changes() {
    let dir = tempdir().unwrap();
    let mgr = ConfigManager::new(dir.path().to_path_buf()).unwrap();
    // write a rule file
    fs::write(&mgr.paths.rules_l3l4, b"allow cidr 10.0.0.0/8 ingress").unwrap();
    let snap1 = mgr.snapshot();
    assert!(!snap1.tampered);
    mgr.record_version().unwrap();

    // mutate the file
    let mut f = fs::OpenOptions::new()
        .append(true)
        .open(&mgr.paths.rules_l3l4)
        .unwrap();
    writeln!(f, "deny port tcp 22 ingress").unwrap();

    let snap2 = mgr.snapshot();
    assert!(snap2.tampered);
}

#[test]
fn rollback_restores_previous_files() {
    let dir = tempdir().unwrap();
    let mgr = ConfigManager::new_with_backups(dir.path().to_path_buf(), 3).unwrap();
    fs::write(&mgr.paths.rules_l3l4, b"v1").unwrap();
    mgr.record_version().unwrap();

    fs::write(&mgr.paths.rules_l3l4, b"v2").unwrap();
    mgr.record_version().unwrap();
    let snap_before = mgr.snapshot();
    assert_eq!(snap_before.version, 2);

    let snap_after = mgr.rollback().unwrap();
    assert_eq!(snap_after.version, 1);
    let contents = fs::read_to_string(&mgr.paths.rules_l3l4).unwrap();
    assert_eq!(contents, "v1");
}
