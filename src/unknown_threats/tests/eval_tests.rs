use super::{
    super::{
        eval::{cleanup_local_state_at, evaluate_with_state_at, shadow_report},
        state::{read_state, write_state, RouteBaseline, UnknownThreatState},
        LocalUnknownThreatStore, MemoryUnknownThreatStore, UnknownThreatStore,
    },
    anomalous_request, blocking_config, config, mature_state, request,
};
use crate::{
    config::{BehaviorBackend, UnknownThreatMode, WafMode},
    decision::WafAction,
    event_store::SecurityEvent,
};

#[test]
fn cleanup_reports_and_removes_stale_local_routes() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("unknown-threats.json");
    let mut config = config();
    config.backend = BehaviorBackend::Local;
    config.state_path = path.clone();
    config.retention = "10s".to_string();
    let mut state = UnknownThreatState::default();
    state.routes.insert(
        "/stale".to_string(),
        RouteBaseline {
            observations: 10,
            first_observed_at: 1,
            last_observed_at: 1,
            ..RouteBaseline::default()
        },
    );
    state.routes.insert(
        "/fresh".to_string(),
        RouteBaseline {
            observations: 10,
            first_observed_at: 95,
            last_observed_at: 95,
            ..RouteBaseline::default()
        },
    );
    write_state(&path, &state).unwrap();

    let preview = cleanup_local_state_at(&config, true, 100).unwrap();
    assert_eq!(preview.routes_removed, 1);
    assert_eq!(read_state(&path).unwrap().routes.len(), 2);

    let executed = cleanup_local_state_at(&config, false, 100).unwrap();
    assert_eq!(executed.routes_before, 2);
    assert_eq!(executed.routes_removed, 1);
    assert_eq!(executed.routes_after, 1);
    assert!(read_state(&path).unwrap().routes.contains_key("/fresh"));
}

#[test]
fn cleanup_reports_missing_state_without_creating_it() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mut config = config();
    config.backend = BehaviorBackend::Local;
    config.state_path = temp_dir.path().join("missing.json");

    let report = cleanup_local_state_at(&config, false, 100).unwrap();

    assert!(!report.state_found);
    assert!(!config.state_path.exists());
}

#[test]
fn local_store_reloads_state_changed_by_cleanup() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("unknown-threats.json");
    let mut config = config();
    config.backend = BehaviorBackend::Local;
    config.state_path = path.clone();
    config.retention = "1s".to_string();
    let store = LocalUnknownThreatStore::open(&path).unwrap();

    store.evaluate(&config, request("GET", "/old")).unwrap();
    let mut state = read_state(&path).unwrap();
    let baseline = state.routes.get_mut("/old").unwrap();
    baseline.first_observed_at = 1;
    baseline.last_observed_at = 1;
    write_state(&path, &state).unwrap();
    cleanup_local_state_at(&config, false, 100).unwrap();

    store.evaluate(&config, request("GET", "/current")).unwrap();
    let state = read_state(&path).unwrap();
    assert!(!state.routes.contains_key("/old"));
    assert!(state.routes.contains_key("/current"));
}

#[test]
fn shadow_mode_reports_would_block_without_enforcement() {
    let mut config = blocking_config(UnknownThreatMode::Shadow);
    let mut state = mature_state();
    let outcome = evaluate_with_state_at(
        &config,
        anomalous_request(WafMode::Block),
        &mut state,
        "memory",
        1_000_000,
    );

    assert!(outcome.would_block);
    assert!(outcome.block_eligible);
    assert_eq!(outcome.action, WafAction::Monitor);

    config.mode = UnknownThreatMode::Block;
    let outcome = evaluate_with_state_at(
        &config,
        anomalous_request(WafMode::Block),
        &mut state,
        "memory",
        1_000_000,
    );
    assert_eq!(outcome.action, WafAction::Block);
}

#[test]
fn blocking_requires_high_risk_route_age_volume_and_two_signals() {
    let config = blocking_config(UnknownThreatMode::Block);
    let mut state = mature_state();

    let single_signal = super::super::UnknownThreatRequest {
        content_type: "application/json",
        ..anomalous_request(WafMode::Block)
    };
    let outcome = evaluate_with_state_at(&config, single_signal, &mut state, "memory", 1_000_000);
    assert_eq!(outcome.action, WafAction::Monitor);
    assert!(outcome
        .enforcement_gates
        .contains(&"insufficient_independent_signals".to_string()));

    let outcome = evaluate_with_state_at(
        &config,
        anomalous_request(WafMode::Block),
        &mut state,
        "memory",
        100,
    );
    assert_eq!(outcome.action, WafAction::Monitor);
    assert!(outcome
        .enforcement_gates
        .contains(&"baseline_too_new".to_string()));
}

#[test]
fn ordinary_routes_never_auto_block() {
    let mut config = blocking_config(UnknownThreatMode::Block);
    config.routes.clear();
    let mut state = mature_state();

    let outcome = evaluate_with_state_at(
        &config,
        anomalous_request(WafMode::Block),
        &mut state,
        "memory",
        1_000_000,
    );

    assert_eq!(outcome.action, WafAction::Monitor);
    assert!(!outcome.block_eligible);
    assert!(outcome
        .enforcement_gates
        .contains(&"route_not_high_risk".to_string()));
}

#[test]
fn trusted_only_learning_rejects_untrusted_sources() {
    let store = MemoryUnknownThreatStore::default();
    let mut config = config();
    config.trusted_learning_only = true;
    config.trusted_learning_clients = vec!["10.0.0.0/8".to_string()];

    let untrusted = store
        .evaluate(&config, request("GET", "/users/42"))
        .unwrap();
    assert!(!untrusted.learning_source_allowed);
    assert!(!untrusted.baseline_tracked);

    let mut trusted_request = request("GET", "/users/42");
    trusted_request.client_id = "10.1.2.3";
    let trusted = store.evaluate(&config, trusted_request).unwrap();
    assert!(trusted.learning_source_trusted);
    assert!(trusted.baseline_tracked);
}

#[test]
fn novel_features_require_repeated_promotion_and_are_bounded() {
    let mut config = config();
    config.minimum_observations = 10;
    config.promotion_observations = 3;
    config.max_methods_per_route = 1;
    let mut state = UnknownThreatState::default();

    for _ in 0..2 {
        evaluate_with_state_at(
            &config,
            request("GET", "/bounded"),
            &mut state,
            "memory",
            100,
        );
    }
    assert!(state.routes["/bounded"].methods.is_empty());

    evaluate_with_state_at(
        &config,
        request("GET", "/bounded"),
        &mut state,
        "memory",
        100,
    );
    assert!(state.routes["/bounded"].methods.contains("GET"));

    for method in ["POST", "PUT", "PATCH"] {
        for _ in 0..3 {
            evaluate_with_state_at(
                &config,
                request(method, "/bounded"),
                &mut state,
                "memory",
                100,
            );
        }
    }
    assert_eq!(state.routes["/bounded"].methods.len(), 1);
}

#[test]
fn shadow_report_surfaces_false_positive_review_pressure() {
    let config = blocking_config(UnknownThreatMode::Shadow);
    let mut state = mature_state();
    let outcome = evaluate_with_state_at(
        &config,
        anomalous_request(WafMode::Block),
        &mut state,
        "memory",
        1_000_000,
    );
    let decision = crate::decision::WafDecision::from_matches(
        "shadow-request".to_string(),
        WafMode::Monitor,
        Vec::new(),
        5,
    )
    .with_unknown_threats(outcome);
    let event = SecurityEvent::new("DELETE", "/admin/42", "", decision);

    let report = shadow_report(&[event]);

    assert_eq!(report.monitor_candidates, 1);
    assert_eq!(report.would_block_candidates, 1);
    assert_eq!(report.enforced_blocks, 0);
    assert_eq!(report.routes[0].route_shape, "/admin/:id");
    assert_eq!(report.sample_request_ids, vec!["shadow-request"]);
}
