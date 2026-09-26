use std::fs;

use crate::config::{
    errors::ConfigError, BehaviorBackend, BehaviorMode, SaugraConfig, UnknownThreatMode,
};

const TEST_FIXTURE_REDIS_PASSWORD: &str = "fixture-redis-pass-val";

#[test]
fn rejects_blank_websocket_allowed_origin() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
websocket:
  allowed_origins:
    - " "
"#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidWebSocketAllowedOrigin)
    ));
}

#[test]
fn rejects_blank_websocket_allowed_host() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
websocket:
  allowed_hosts:
    - ""
"#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidWebSocketAllowedHost)
    ));
}

#[test]
fn rejects_missing_upstreams() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams: []
"#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::MissingUpstream)
    ));
}

#[test]
fn rejects_duplicate_upstream_names() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
  - name: app
    host: api.example.com
    target: http://127.0.0.1:8001
"#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::DuplicateUpstreamName)
    ));
}

#[test]
fn rejects_blank_route_path_prefix() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
routes:
  - path_prefix: ""
    upstream: app
"#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidRoutePathPrefix)
    ));
}

#[test]
fn rejects_route_with_unknown_upstream() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
routes:
  - path_prefix: /api/
    upstream: api
"#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::UnknownRouteUpstream {
            path_prefix,
            upstream
        }) if path_prefix == "/api/" && upstream == "api"
    ));
}

#[test]
fn rejects_zero_rate_limit() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
rate_limit:
  backend: memory
  requests_per_minute: 0
"#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidRateLimit)
    ));
}

#[test]
fn requires_redis_url_for_redis_rate_limit_backend() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
rate_limit:
  backend: redis
  requests_per_minute: 120
"#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::MissingRedisUrl)
    ));
}

#[test]
fn rejects_blank_redis_url_for_redis_rate_limit_backend() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
rate_limit:
  backend: redis
  redis_url: "   "
  requests_per_minute: 120
"#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::MissingRedisUrl)
    ));
}

#[test]
fn accepts_redis_password_for_redis_rate_limit_backend() {
    let yaml = format!(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
rate_limit:
  backend: redis
  redis_url: redis://127.0.0.1:6379
  redis_password: "{TEST_FIXTURE_REDIS_PASSWORD}"
  requests_per_minute: 120
"#
    );
    let config: SaugraConfig = serde_yaml::from_str(&yaml).unwrap();

    config.validate().unwrap();
    assert_eq!(
        config.rate_limit.redis_password.as_deref(),
        Some(TEST_FIXTURE_REDIS_PASSWORD)
    );
}

#[test]
fn rejects_blank_redis_password_when_provided() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
rate_limit:
  backend: redis
  redis_url: redis://127.0.0.1:6379
  redis_password: "   "
  requests_per_minute: 120
"#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidRedisPassword)
    ));
}

#[test]
fn rejects_blank_rate_limit_route_path() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
rate_limit:
  backend: memory
  requests_per_minute: 120
  routes:
    - path: " "
      requests_per_minute: 10
"#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidRateLimitRoute)
    ));
}

#[test]
fn rejects_zero_route_rate_limit() {
    let config: SaugraConfig = serde_yaml::from_str(
        r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
rate_limit:
  backend: memory
  requests_per_minute: 120
  routes:
    - path: /sensitive-action
      requests_per_minute: 0
"#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidRateLimit)
    ));
}

#[test]
fn behavior_config_defaults_to_monitor_first_policy_shape() {
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
    assert!(config.behavior.enabled);
    assert_eq!(config.behavior.mode, BehaviorMode::Monitor);
    assert_eq!(config.behavior.backend, BehaviorBackend::Local);
    assert_eq!(config.behavior.score_window, "10m");
    assert_eq!(config.behavior.decay_window, "30m");
    assert_eq!(config.behavior.monitor_threshold, 40);
    assert_eq!(config.behavior.block_threshold, 80);
    assert!(config.behavior.probe_paths.contains(&"/.env".to_string()));
}

#[test]
fn unknown_threat_config_defaults_to_disabled_monitoring() {
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
    assert!(!config.unknown_threats.enabled);
    assert_eq!(config.unknown_threats.minimum_observations, 100);
    assert_eq!(config.unknown_threats.monitor_threshold, 20);
    assert_eq!(config.unknown_threats.mode, UnknownThreatMode::Monitor);
    assert_eq!(config.unknown_threats.block_threshold, 40);
    assert_eq!(config.unknown_threats.minimum_independent_signals, 2);
    assert_eq!(config.unknown_threats.minimum_baseline_age, "7d");
    assert_eq!(config.unknown_threats.minimum_block_observations, 1_000);
    assert_eq!(config.unknown_threats.signal_catalog, "builtin");
    assert_eq!(config.unknown_threats.signals.unseen_method.score, 20);
}

#[test]
fn from_file_loads_external_unknown_threat_signal_catalog() {
    let dir = tempfile::tempdir().unwrap();
    let catalog_path = dir.path().join("signals.yml");
    let config_path = dir.path().join("saugra.yml");
    fs::write(
        &catalog_path,
        r#"
version: 1
signals:
  unseen_method:
    score: 31
  unseen_content_type:
    score: 17
  unseen_query_parameter:
    score: 11
  body_size_deviation:
    score: 19
"#,
    )
    .unwrap();
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

    let config = SaugraConfig::from_file(&config_path).unwrap();
    config.validate().unwrap();
    assert_eq!(config.unknown_threats.signals.unseen_method.score, 31);
    assert_eq!(config.unknown_threats.signals.body_size_deviation.score, 19);
}
