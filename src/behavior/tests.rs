use super::*;
use crate::config::BehaviorConfig;

#[test]
fn accumulates_behavior_score_in_memory() {
    let store = MemoryBehaviorStore::new();
    let config = BehaviorConfig {
        enabled: true,
        monitor_threshold: 10,
        block_threshold: 20,
        ..BehaviorConfig::default()
    };

    let outcome = store
        .evaluate(
            &config,
            BehaviorRequest {
                client_id: "203.0.113.10",
                path: "/.env",
                rule_matches: &[],
                server_mode: WafMode::Monitor,
            },
        )
        .unwrap();

    assert_eq!(outcome.score, 15);
    assert_eq!(outcome.action, WafAction::Monitor);
}

#[test]
fn blocks_when_behavior_mode_is_block_and_score_reaches_threshold() {
    let store = MemoryBehaviorStore::new();
    let config = BehaviorConfig {
        enabled: true,
        mode: BehaviorMode::Block,
        monitor_threshold: 10,
        block_threshold: 20,
        ..BehaviorConfig::default()
    };

    for _ in 0..2 {
        store
            .evaluate(
                &config,
                BehaviorRequest {
                    client_id: "203.0.113.10",
                    path: "/.env",
                    rule_matches: &[],
                    server_mode: WafMode::Block,
                },
            )
            .unwrap();
    }

    let outcome = store
        .evaluate(
            &config,
            BehaviorRequest {
                client_id: "203.0.113.10",
                path: "/.git/config",
                rule_matches: &[],
                server_mode: WafMode::Block,
            },
        )
        .unwrap();

    assert_eq!(outcome.action, WafAction::Block);
    assert!(outcome.score >= 20);
}

#[test]
fn local_store_survives_restart() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("behavior.json");
    let config = BehaviorConfig {
        enabled: true,
        backend: BehaviorBackend::Local,
        state_path: path.clone(),
        monitor_threshold: 20,
        block_threshold: 80,
        ..BehaviorConfig::default()
    };

    LocalBehaviorStore::open(&path)
        .unwrap()
        .evaluate(
            &config,
            BehaviorRequest {
                client_id: "203.0.113.10",
                path: "/.env",
                rule_matches: &[],
                server_mode: WafMode::Monitor,
            },
        )
        .unwrap();

    let outcome = LocalBehaviorStore::open(&path)
        .unwrap()
        .evaluate(
            &config,
            BehaviorRequest {
                client_id: "203.0.113.10",
                path: "/.git/config",
                rule_matches: &[],
                server_mode: WafMode::Monitor,
            },
        )
        .unwrap();

    assert_eq!(outcome.action, WafAction::Monitor);
    assert!(outcome.score >= 20);
}

#[test]
fn reset_client_removes_only_matching_local_behavior_state() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("behavior.json");
    let config = BehaviorConfig {
        enabled: true,
        backend: BehaviorBackend::Local,
        state_path: path.clone(),
        ..BehaviorConfig::default()
    };

    for client_id in ["203.0.113.10", "203.0.113.11"] {
        LocalBehaviorStore::open(&path)
            .unwrap()
            .evaluate(
                &config,
                BehaviorRequest {
                    client_id,
                    path: "/.env",
                    rule_matches: &[],
                    server_mode: WafMode::Monitor,
                },
            )
            .unwrap();
    }

    assert!(reset_client(&path, "203.0.113.10").unwrap());
    assert!(!reset_client(&path, "203.0.113.12").unwrap());
    let state = read_state(&path).unwrap();

    assert!(!state.clients.contains_key("203.0.113.10"));
    assert!(state.clients.contains_key("203.0.113.11"));
}

#[test]
fn route_override_can_lower_thresholds_for_sensitive_paths() {
    let store = MemoryBehaviorStore::new();
    let config = BehaviorConfig {
        enabled: true,
        monitor_threshold: 80,
        block_threshold: 100,
        route_overrides: vec![BehaviorRouteOverrideConfig {
            path: "/login".to_string(),
            monitor_threshold: Some(10),
            block_threshold: Some(80),
            score_window: None,
        }],
        ..BehaviorConfig::default()
    };

    let outcome = store
        .evaluate(
            &config,
            BehaviorRequest {
                client_id: "203.0.113.10",
                path: "/login",
                rule_matches: &[],
                server_mode: WafMode::Monitor,
            },
        )
        .unwrap();

    assert_eq!(outcome.action, WafAction::Allow);

    let outcome = store
        .evaluate(
            &config,
            BehaviorRequest {
                client_id: "203.0.113.10",
                path: "/login/.env",
                rule_matches: &[],
                server_mode: WafMode::Monitor,
            },
        )
        .unwrap();

    assert_eq!(outcome.monitor_threshold, 10);
}

#[test]
fn category_override_changes_score_delta() {
    let store = MemoryBehaviorStore::new();
    let config = BehaviorConfig {
        enabled: true,
        monitor_threshold: 20,
        block_threshold: 80,
        category_overrides: vec![BehaviorCategoryOverrideConfig {
            category: "scanner_behavior".to_string(),
            monitor_threshold: None,
            block_threshold: None,
            score_delta: Some(25),
        }],
        ..BehaviorConfig::default()
    };
    let rule_match = RuleMatch {
        rule_id: "SAUGRA-BOT-001".to_string(),
        rule_name: "Suspicious Scanner User Agent".to_string(),
        category: "scanner_behavior".to_string(),
        severity: RuleSeverity::Medium,
        matched_target: RuleTarget::UserAgent,
        paranoia_level: 1,
        explanation: "Scanner matched.".to_string(),
        owasp_category: None,
    };

    let outcome = store
        .evaluate(
            &config,
            BehaviorRequest {
                client_id: "203.0.113.10",
                path: "/",
                rule_matches: &[rule_match],
                server_mode: WafMode::Monitor,
            },
        )
        .unwrap();

    assert_eq!(outcome.score, 25);
    assert_eq!(outcome.action, WafAction::Monitor);
}

#[test]
fn custom_probe_paths_drive_behavior_scoring() {
    let store = MemoryBehaviorStore::new();
    let config = BehaviorConfig {
        enabled: true,
        monitor_threshold: 10,
        block_threshold: 80,
        probe_paths: vec!["/custom-probe".to_string()],
        ..BehaviorConfig::default()
    };

    let outcome = store
        .evaluate(
            &config,
            BehaviorRequest {
                client_id: "203.0.113.10",
                path: "/custom-probe/config",
                rule_matches: &[],
                server_mode: WafMode::Monitor,
            },
        )
        .unwrap();

    assert_eq!(outcome.action, WafAction::Monitor);
    assert!(outcome
        .contributors
        .iter()
        .any(|contributor| contributor.reason == "scanner_path_probe"));
}

#[test]
fn probe_path_exclusion_prevents_behavior_scoring() {
    let store = MemoryBehaviorStore::new();
    let config = BehaviorConfig {
        enabled: true,
        probe_paths: vec!["/admin".to_string()],
        probe_path_exclusions: vec!["/admin".to_string()],
        ..BehaviorConfig::default()
    };

    let outcome = store
        .evaluate(
            &config,
            BehaviorRequest {
                client_id: "203.0.113.10",
                path: "/admin/login/",
                rule_matches: &[],
                server_mode: WafMode::Block,
            },
        )
        .unwrap();

    assert_eq!(outcome.score, 0);
    assert_eq!(outcome.action, WafAction::Allow);
}

#[test]
fn score_window_ignores_expired_entries() {
    let mut state = BehaviorState::default();
    state.clients.insert(
        "203.0.113.10".to_string(),
        ClientBehaviorState {
            entries: vec![BehaviorEntry {
                timestamp_seconds: unix_seconds_now().saturating_sub(120),
                reason: "scanner_path_probe".to_string(),
                score_delta: 50,
                path: "/old-probe".to_string(),
            }],
        },
    );
    let config = BehaviorConfig {
        enabled: true,
        score_window: "1s".to_string(),
        decay_window: "1h".to_string(),
        monitor_threshold: 10,
        block_threshold: 80,
        ..BehaviorConfig::default()
    };

    let outcome = evaluate_with_state(
        &config,
        BehaviorRequest {
            client_id: "203.0.113.10",
            path: "/",
            rule_matches: &[],
            server_mode: WafMode::Monitor,
        },
        &mut state,
        "memory",
    );

    assert_eq!(outcome.score, 0);
    assert_eq!(outcome.action, WafAction::Allow);
}
