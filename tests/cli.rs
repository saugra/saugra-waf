use std::process::Command;

#[test]
fn cli_cleanup_dry_run_prints_report_json() {
    let output = Command::new(env!("CARGO_BIN_EXE_saugra"))
        .args([
            "cleanup",
            "run",
            "--dry-run",
            "--config",
            "configs/saugra.example.yml",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["dry_run"], true);
    assert!(report["scanned_targets"].as_u64().unwrap() >= 1);
    assert!(report["files"].is_array());
}
