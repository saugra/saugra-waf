use std::fs;

use super::{
    super::{
        build_store,
        eval::{evaluate_with_state, prune_stale_routes},
        state::{RouteBaseline, UnknownThreatState},
        LocalUnknownThreatStore, MemoryUnknownThreatStore, UnknownThreatOutcome,
        UnknownThreatStore,
    },
    config, request,
};
use crate::{
    config::{BehaviorBackend, UnknownThreatRouteConfig},
    decision::WafAction,
};

#[test]
fn disabled_store_does_not_touch_local_state_path() {
    let temp_dir = tempfile::tempdir().unwrap();
    let blocked_parent = temp_dir.path().join("not-a-directory");
    fs::write(&blocked_parent, b"file").unwrap();

    let mut config = config();
    config.enabled = false;
    config.backend = BehaviorBackend::Local;
    config.state_path = blocked_parent.join("unknown-threats.json");

    let store = build_store(&config).unwrap();
    let outcome = store
        .evaluate(&config, request("GET", "/users/42"))
        .unwrap();

    assert!(!outcome.enabled);
    assert_eq!(outcome.storage_backend, "memory");
}

#[test]
fn learns_before_emitting_anomalies() {
    let store = MemoryUnknownThreatStore::default();
    store
        .evaluate(&config(), request("GET", "/users/42"))
        .unwrap();
    let learning = store
        .evaluate(&config(), request("GET", "/users/43"))
        .unwrap();
    let anomaly = store
        .evaluate(&config(), request("DELETE", "/users/44"))
        .unwrap();

    assert!(!learning.baseline_ready);
    assert_eq!(anomaly.route_shape, "/users/:id");
    assert_eq!(anomaly.action, WafAction::Monitor);
    assert_eq!(anomaly.signals[0].kind, "unseen_method");
}

#[test]
fn suspicious_requests_do_not_update_the_baseline() {
    let store = MemoryUnknownThreatStore::default();
    store
        .evaluate(&config(), request("GET", "/users/42"))
        .unwrap();
    store
        .evaluate(&config(), request("GET", "/users/43"))
        .unwrap();
    store
        .evaluate(&config(), request("DELETE", "/users/44"))
        .unwrap();
    let repeated = store
        .evaluate(&config(), request("DELETE", "/users/45"))
        .unwrap();

    assert_eq!(repeated.action, WafAction::Monitor);
}

#[test]
fn local_store_survives_restart() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("unknown-threats.json");
    let mut config = config();
    config.backend = BehaviorBackend::Local;
    config.state_path = path.clone();

    LocalUnknownThreatStore::open(&path)
        .unwrap()
        .evaluate(&config, request("GET", "/users/42"))
        .unwrap();
    LocalUnknownThreatStore::open(&path)
        .unwrap()
        .evaluate(&config, request("GET", "/users/43"))
        .unwrap();
    let outcome = LocalUnknownThreatStore::open(&path)
        .unwrap()
        .evaluate(&config, request("DELETE", "/users/44"))
        .unwrap();

    assert_eq!(outcome.action, WafAction::Monitor);
}

#[test]
fn excluded_routes_are_not_learned_or_monitored() {
    let store = MemoryUnknownThreatStore::default();
    let mut config = config();
    config.excluded_paths = vec!["/health".to_string()];

    let outcome = store
        .evaluate(&config, request("GET", "/health/ready"))
        .unwrap();

    assert!(outcome.route_excluded);
    assert!(!outcome.baseline_tracked);
    assert_eq!(outcome.action, WafAction::Allow);
}

#[test]
fn route_override_can_disable_learning() {
    let store = MemoryUnknownThreatStore::default();
    let mut config = config();
    config.routes = vec![UnknownThreatRouteConfig {
        path: "/uploads".to_string(),
        learning_enabled: false,
        minimum_observations: Some(1),
        monitor_threshold: Some(5),
        ..UnknownThreatRouteConfig::default()
    }];

    let outcome = store
        .evaluate(&config, request("POST", "/uploads/42"))
        .unwrap();

    assert!(!outcome.learning_enabled);
    assert!(!outcome.baseline_tracked);
}

#[test]
fn route_override_uses_longest_matching_policy() {
    let store = MemoryUnknownThreatStore::default();
    let mut config = config();
    config.routes = vec![
        UnknownThreatRouteConfig {
            path: "/api".to_string(),
            learning_enabled: true,
            minimum_observations: Some(10),
            monitor_threshold: Some(30),
            ..UnknownThreatRouteConfig::default()
        },
        UnknownThreatRouteConfig {
            path: "/api/admin".to_string(),
            learning_enabled: true,
            minimum_observations: Some(1),
            monitor_threshold: Some(5),
            ..UnknownThreatRouteConfig::default()
        },
    ];

    store
        .evaluate(&config, request("GET", "/api/admin/42"))
        .unwrap();
    let outcome = store
        .evaluate(&config, request("DELETE", "/api/admin/43"))
        .unwrap();

    assert_eq!(outcome.threshold, 5);
    assert!(outcome.baseline_ready);
    assert_eq!(outcome.action, WafAction::Monitor);
}

#[test]
fn route_cardinality_is_bounded() {
    let store = MemoryUnknownThreatStore::default();
    let mut config = config();
    config.max_routes = 1;

    store.evaluate(&config, request("GET", "/first")).unwrap();
    let outcome = store.evaluate(&config, request("GET", "/second")).unwrap();

    assert!(outcome.capacity_reached);
    assert!(!outcome.baseline_tracked);
}

#[test]
fn stale_routes_are_pruned_before_allocating_capacity() {
    let now = super::super::state::unix_seconds_now();
    let mut state = UnknownThreatState::default();
    state.routes.insert(
        "/stale".to_string(),
        RouteBaseline {
            observations: 2,
            first_observed_at: now.saturating_sub(10),
            last_observed_at: now.saturating_sub(10),
            ..RouteBaseline::default()
        },
    );
    let mut config = config();
    config.retention = "1s".to_string();
    config.max_routes = 1;

    let outcome = evaluate_with_state(&config, request("GET", "/current"), &mut state, "memory");

    assert_eq!(outcome.pruned_routes, 1);
    assert!(outcome.baseline_tracked);
    assert!(state.routes.contains_key("/current"));
}

#[test]
fn legacy_state_timestamps_are_migrated_without_data_loss() {
    let mut state = UnknownThreatState::default();
    state.routes.insert(
        "/legacy".to_string(),
        RouteBaseline {
            observations: 3,
            ..RouteBaseline::default()
        },
    );

    assert_eq!(prune_stale_routes(&mut state, 100, 1), 0);
    let baseline = state.routes.get("/legacy").unwrap();
    assert_eq!(baseline.first_observed_at, 100);
    assert_eq!(baseline.last_observed_at, 100);
}

#[test]
fn older_event_outcomes_remain_deserializable() {
    let outcome: UnknownThreatOutcome = serde_json::from_str(
        r#"{
            "enabled": true,
            "action": "monitor",
            "score": 20,
            "threshold": 20,
            "route_shape": "/users/:id",
            "baseline_observations": 100,
            "baseline_ready": true,
            "storage_backend": "local",
            "signals": []
        }"#,
    )
    .unwrap();

    assert!(outcome.learning_enabled);
    assert!(!outcome.capacity_reached);
}
