use crate::config::{errors::ConfigError, SaugraConfig};

#[test]
fn validates_example_config() {
    let config: SaugraConfig =
        serde_yaml::from_str(include_str!("../../../configs/saugra-waf.example.yml")).unwrap();

    assert!(config.validate().is_ok());
    assert_eq!(config.max_body_size_bytes().unwrap(), 2 * 1024 * 1024);
}

#[test]
fn validates_console_delivery_bounds() {
    let mut config: SaugraConfig =
        serde_yaml::from_str(include_str!("../../../configs/saugra-waf.example.yml")).unwrap();
    assert_eq!(config.console.heartbeat_interval_secs, 60);
    assert_eq!(config.console.delivery_interval_secs, 5);
    assert_eq!(config.console.batch_size, 100);
    assert_eq!(config.console.policy_poll_interval_secs, 30);

    config.console.batch_size = 501;
    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidConsoleBatchSize)
    ));
    config.console.batch_size = 100;
    config.console.delivery_interval_secs = 0;
    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidConsoleInterval)
    ));
    config.console.delivery_interval_secs = 5;
    config.console.policy_poll_interval_secs = 0;
    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidConsolePolicyPollInterval)
    ));
}

#[test]
fn accepts_storage_cleanup_config() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
storage_cleanup:
  enabled: true
  dry_run: false
  schedule: daily
  run_time: "03:30"
  targets:
    - name: summaries
      directory: /var/lib/saugra-waf/reports
      filename_prefix: saugra-waf-security-summary-
      filename_suffix: .json
      older_than: 14d
"#,
    )
    .unwrap();

    config.validate().unwrap();
    assert!(config.storage_cleanup.enabled);
    assert!(!config.storage_cleanup.dry_run);
    assert_eq!(config.storage_cleanup.targets[0].older_than, "14d");
}

#[test]
fn accepts_forwarded_headers_config() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
forwarded_headers:
  enabled: true
  trusted_proxies:
    - 127.0.0.1/32
    - 10.0.0.0/8
  real_ip_header: X-Forwarded-For
  proto_header: X-Forwarded-Proto
  expected_proto: https
  insecure_proto_score: 15
"#,
    )
    .unwrap();

    config.validate().unwrap();
    assert_eq!(config.forwarded_headers.trusted_proxies.len(), 2);
    assert_eq!(config.forwarded_headers.insecure_proto_score, 15);
}

#[test]
fn rejects_invalid_forwarded_header_name() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
forwarded_headers:
  proto_header: "X Forwarded Proto"
"#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidForwardedHeadersProtoHeader)
    ));
}

#[test]
fn rejects_invalid_forwarded_expected_proto() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
forwarded_headers:
  expected_proto: ftp
"#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidForwardedHeadersExpectedProto)
    ));
}

#[test]
fn rejects_invalid_storage_cleanup_schedule() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
storage_cleanup:
  schedule: hourly
"#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidStorageCleanupSchedule)
    ));
}

#[test]
fn rejects_invalid_storage_cleanup_run_time() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
storage_cleanup:
  run_time: "25:00"
"#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidStorageCleanupRunTime)
    ));
}

#[test]
fn rejects_storage_cleanup_target_without_pattern() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
storage_cleanup:
  targets:
    - name: unsafe
      directory: /var/log/saugra-waf
      older_than: 30d
"#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidStorageCleanupTargetPattern)
    ));
}

#[test]
fn rejects_invalid_storage_cleanup_older_than() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
storage_cleanup:
  targets:
    - name: summaries
      directory: /var/lib/saugra-waf/reports
      filename_suffix: .json
      older_than: forever
"#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidStorageCleanupOlderThan)
    ));
}

#[test]
fn from_file_merges_threat_path_catalogs_and_extra_paths() {
    let dir = tempfile::tempdir().unwrap();
    let catalog_path = dir.path().join("scanner-paths.yml");
    let config_path = dir.path().join("saugra-waf.yml");
    std::fs::write(
        &catalog_path,
        r#"
behavior_probe_paths:
  - /catalog-probe
bot_scanner_paths:
  - /catalog-scanner
"#,
    )
    .unwrap();
    std::fs::write(
        &config_path,
        format!(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
behavior:
  probe_path_catalog: {}
  probe_paths_extra:
    - /custom-probe
bot_protection:
  scanner_path_catalog: {}
  scanner_paths_extra:
    - /custom-scanner
"#,
            catalog_path.display(),
            catalog_path.display()
        ),
    )
    .unwrap();

    let config = SaugraConfig::from_file(&config_path).unwrap();

    config.validate().unwrap();
    assert!(config
        .behavior
        .probe_paths
        .contains(&"/catalog-probe".to_string()));
    assert!(config
        .behavior
        .probe_paths
        .contains(&"/custom-probe".to_string()));
    assert!(!config.behavior.probe_paths.contains(&"/.env".to_string()));
    assert!(config
        .bot_protection
        .scanner_paths
        .contains(&"/catalog-scanner".to_string()));
    assert!(config
        .bot_protection
        .scanner_paths
        .contains(&"/custom-scanner".to_string()));
    assert!(!config
        .bot_protection
        .scanner_paths
        .contains(&"/vendor/phpunit".to_string()));
}
