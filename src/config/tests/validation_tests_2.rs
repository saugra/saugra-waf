use std::fs;

use crate::config::{
    errors::ConfigError, helpers::is_local_http_url, AiConfig, BehaviorMode, RuntimePolicyConfig,
    SecuritySummaryConfig, SaugraConfig,
};

#[test]
fn rejects_invalid_unknown_threat_signal_catalogs() {
    let dir = tempfile::tempdir().unwrap();
    let catalog_path = dir.path().join("signals.yml");
    let config_path = dir.path().join("saugra.yml");
    fs::write(
        &config_path,
        format!(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
unknown_threats:
  signal_catalog: {}
"#,
            catalog_path.display()
        ),
    )
    .unwrap();

    fs::write(
        &catalog_path,
        r#"
version: 2
signals:
  unseen_method: { score: 20 }
  unseen_content_type: { score: 15 }
  unseen_query_parameter: { score: 10 }
  body_size_deviation: { score: 15 }
"#,
    )
    .unwrap();
    assert!(matches!(
        SaugraConfig::from_file(&config_path),
        Err(ConfigError::InvalidUnknownThreatSignalCatalogVersion)
    ));

    fs::write(
        &catalog_path,
        r#"
version: 1
signals:
  unseen_method: { score: 0 }
  unseen_content_type: { score: 15 }
  unseen_query_parameter: { score: 10 }
  body_size_deviation: { score: 15 }
"#,
    )
    .unwrap();
    assert!(matches!(
        SaugraConfig::from_file(&config_path),
        Err(ConfigError::InvalidUnknownThreatSignalScore)
    ));
}

#[test]
fn rejects_legacy_inline_unknown_threat_signal_scores() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
unknown_threats:
  unseen_method_score: 30
"#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::LegacyUnknownThreatSignalScores)
    ));
}

#[test]
fn rejects_unsafe_unknown_threat_learning_values() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
unknown_threats:
  minimum_observations: 0
"#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidUnknownThreatMinimumObservations)
    ));
}

#[test]
fn unknown_threat_block_mode_requires_completed_shadow_review() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
unknown_threats:
  mode: block
"#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::UnknownThreatShadowReviewRequired)
    ));
}

#[test]
fn accepts_guarded_unknown_threat_block_policy() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
  mode: block
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
unknown_threats:
  enabled: true
  mode: block
  shadow_review_completed: true
  minimum_observations: 100
  minimum_block_observations: 1000
  minimum_baseline_age: 7d
  minimum_independent_signals: 2
  routes:
    - path: /admin
      high_risk: true
      block_threshold: 50
"#,
    )
    .unwrap();

    config.validate().unwrap();
    assert!(config.unknown_threats.routes[0].high_risk);
}

#[test]
fn accepts_bounded_unknown_threat_route_policies() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
unknown_threats:
  enabled: true
  retention: 14d
  max_routes: 5000
  excluded_paths:
    - /health
  routes:
    - path: /uploads
      learning_enabled: false
    - path: /admin
      minimum_observations: 200
      monitor_threshold: 15
"#,
    )
    .unwrap();

    config.validate().unwrap();
    assert_eq!(config.unknown_threats.retention, "14d");
    assert_eq!(config.unknown_threats.max_routes, 5_000);
    assert_eq!(config.unknown_threats.routes.len(), 2);
    assert!(!config.unknown_threats.routes[0].learning_enabled);
}

#[test]
fn rejects_invalid_unknown_threat_retention_and_routes() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
unknown_threats:
  retention: forever
"#,
    )
    .unwrap();
    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidUnknownThreatRetention)
    ));

    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
unknown_threats:
  routes:
    - path: " "
"#,
    )
    .unwrap();
    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidUnknownThreatRoute)
    ));
}

#[test]
fn accepts_behavior_route_and_category_overrides() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
behavior:
  enabled: true
  mode: monitor
  score_window: 10m
  decay_window: 30m
  monitor_threshold: 40
  block_threshold: 80
  route_overrides:
    - path: /login
      monitor_threshold: 30
      block_threshold: 60
      score_window: 5m
  category_overrides:
    - category: scanner_behavior
      score_delta: 15
      monitor_threshold: 30
      block_threshold: 70
"#,
    )
    .unwrap();

    config.validate().unwrap();
    assert!(config.behavior.enabled);
    assert_eq!(config.behavior.mode, BehaviorMode::Monitor);
    assert_eq!(config.behavior.route_overrides.len(), 1);
    assert_eq!(config.behavior.category_overrides.len(), 1);
}

#[test]
fn rejects_invalid_behavior_score_window() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
behavior:
  score_window: soon
"#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidBehaviorScoreWindow)
    ));
}

#[test]
fn rejects_invalid_behavior_decay_window() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
behavior:
  decay_window: 0m
"#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidBehaviorDecayWindow)
    ));
}

#[test]
fn rejects_zero_behavior_monitor_threshold() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
behavior:
  monitor_threshold: 0
  block_threshold: 80
"#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidBehaviorMonitorThreshold)
    ));
}

#[test]
fn rejects_behavior_block_threshold_below_monitor_threshold() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
behavior:
  monitor_threshold: 80
  block_threshold: 40
"#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidBehaviorBlockThreshold)
    ));
}

#[test]
fn bot_protection_defaults_to_monitor_first_policy_shape() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
"#,
    )
    .unwrap();

    config.validate().unwrap();
    assert!(config.bot_protection.enabled);
    assert_eq!(config.bot_protection.mode, BehaviorMode::Monitor);
    assert_eq!(config.bot_protection.monitor_threshold, 40);
    assert_eq!(config.bot_protection.block_threshold, 80);
    assert_eq!(config.bot_protection.temporary_block_duration, "15m");
    assert!(config
        .bot_protection
        .scanner_paths
        .contains(&"/vendor/phpunit".to_string()));
    assert_eq!(config.bot_protection.rule.id, "SAUGRA-BOT-PROTECTION-001");
}

#[test]
fn accepts_bot_protection_lists_and_route_overrides() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
bot_protection:
  enabled: true
  mode: monitor
  backend: memory
  score_window: 10m
  monitor_threshold: 40
  block_threshold: 80
  temporary_block_duration: 15m
  allowlists:
    ip_ranges:
      - 203.0.113.0/24
    user_agents:
      - Googlebot
  blocklists:
    ip_ranges:
      - 198.51.100.10
    user_agents:
      - badbot
  routes:
    - path: /login
      monitor_threshold: 30
      block_threshold: 60
"#,
    )
    .unwrap();

    config.validate().unwrap();
    assert!(config.bot_protection.enabled);
    assert_eq!(config.bot_protection.routes.len(), 1);
}

#[test]
fn ai_defaults_to_local_llama_cpp_with_small_qwen3() {
    let config = AiConfig::default();

    assert_eq!(config.provider, "llama_cpp");
    assert_eq!(config.llama_cpp_url, "http://127.0.0.1:8080");
    assert_eq!(config.ollama_url, "http://127.0.0.1:11434");
    assert_eq!(config.model, "saugra-qwen3-0.6b");
    assert_eq!(config.timeout, "60s");
}

#[test]
fn accepts_custom_loopback_ollama_port() {
    assert!(is_local_http_url("http://localhost:11435"));
    assert!(is_local_http_url("http://127.0.0.1:11435/api"));
    assert!(is_local_http_url("http://[::1]:11435"));
}

#[test]
fn security_summary_config_validate_rejects_invalid_schedule() {
    let mut config = SecuritySummaryConfig::default();
    config.schedule = "weekly".to_string();
    let err = config.validate().unwrap_err();
    assert_eq!(err.to_string(), "security_summary.schedule must be daily");
}

#[test]
fn security_summary_config_validate_rejects_negative_duration() {
    let mut config = SecuritySummaryConfig::default();
    config.lookback = "-24h".to_string();
    let err = config.validate().unwrap_err();
    assert_eq!(
        err.to_string(),
        "security_summary.lookback must be a positive duration, for example 24h"
    );
}

#[test]
fn runtime_policy_config_validate_rejects_invalid_duration() {
    let mut config = RuntimePolicyConfig::default();
    config.reload_interval = "-5s".to_string();
    let err = config.validate().unwrap_err();
    assert_eq!(
        err.to_string(),
        "runtime_policy.reload_interval must be a positive duration, for example 5s"
    );
}

#[test]
fn rejects_unknown_fields_in_security_summary_config() {
    let yaml = r#"
schedule: daily
send_time: "08:00"
invalid_unknown_key: 123
"#;
    let res: Result<SecuritySummaryConfig, _> = serde_yaml::from_str(yaml);
    assert!(res.is_err());
}

#[test]
fn rejects_unknown_fields_in_runtime_policy_config() {
    let yaml = r#"
enabled: true
invalid_unknown_key: 123
"#;
    let res: Result<RuntimePolicyConfig, _> = serde_yaml::from_str(yaml);
    assert!(res.is_err());
}

