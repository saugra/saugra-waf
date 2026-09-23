use super::*;
use crate::config::{BotProtectionLists, BotProtectionRouteConfig};
use eval::{evaluate_with_state, read_state, unix_seconds_now, BotProtectionState, ClientBotProtectionState};

#[test]
fn monitors_deterministic_bot_signals() {
    let store = MemoryBotProtectionStore::new();
    let config = BotProtectionConfig {
        enabled: true,
        backend: BehaviorBackend::Memory,
        monitor_threshold: 20,
        block_threshold: 80,
        ..BotProtectionConfig::default()
    };

    let outcome = store
        .evaluate(
            &config,
            test_request("203.0.113.10", "/.env", "", "curl/8.0", WafMode::Monitor),
        )
        .unwrap();

    assert_eq!(outcome.action, WafAction::Monitor);
    assert!(outcome.score >= 20);
}

#[test]
fn blocklist_blocks_immediately() {
    let store = MemoryBotProtectionStore::new();
    let config = BotProtectionConfig {
        enabled: true,
        mode: BehaviorMode::Block,
        backend: BehaviorBackend::Memory,
        blocklists: BotProtectionLists {
            ip_ranges: vec!["203.0.113.10".to_string()],
            user_agents: Vec::new(),
        },
        ..BotProtectionConfig::default()
    };

    let outcome = store
        .evaluate(
            &config,
            test_request("203.0.113.10", "/", "", "Mozilla/5.0", WafMode::Block),
        )
        .unwrap();

    assert_eq!(outcome.action, WafAction::Block);
    assert!(outcome.blocklisted);
}

#[test]
fn allowlist_bypasses_bot_signals() {
    let store = MemoryBotProtectionStore::new();
    let config = BotProtectionConfig {
        enabled: true,
        mode: BehaviorMode::Block,
        backend: BehaviorBackend::Memory,
        allowlists: BotProtectionLists {
            ip_ranges: vec!["203.0.113.0/24".to_string()],
            user_agents: Vec::new(),
        },
        ..BotProtectionConfig::default()
    };

    let outcome = store
        .evaluate(
            &config,
            test_request("203.0.113.10", "/.env", "", "curl/8.0", WafMode::Block),
        )
        .unwrap();

    assert_eq!(outcome.action, WafAction::Allow);
    assert!(outcome.allowlisted);
}

#[test]
fn temporary_block_survives_local_restart() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("bot.json");
    let config = BotProtectionConfig {
        enabled: true,
        mode: BehaviorMode::Block,
        backend: BehaviorBackend::Local,
        state_path: path.clone(),
        monitor_threshold: 20,
        block_threshold: 40,
        temporary_block_duration: "15m".to_string(),
        ..BotProtectionConfig::default()
    };

    for _ in 0..2 {
        LocalBotProtectionStore::open(&path)
            .unwrap()
            .evaluate(
                &config,
                test_request("203.0.113.10", "/.env", "", "curl/8.0", WafMode::Block),
            )
            .unwrap();
    }

    let outcome = LocalBotProtectionStore::open(&path)
        .unwrap()
        .evaluate(
            &config,
            test_request("203.0.113.10", "/", "", "Mozilla/5.0", WafMode::Block),
        )
        .unwrap();

    assert_eq!(outcome.action, WafAction::Block);
    assert!(outcome
        .contributors
        .iter()
        .any(|contributor| contributor.reason == "temporary_block_active"));
}

#[test]
fn reset_client_removes_only_matching_local_bot_state() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("bot.json");
    let config = BotProtectionConfig {
        enabled: true,
        backend: BehaviorBackend::Local,
        state_path: path.clone(),
        ..BotProtectionConfig::default()
    };

    for client_id in ["203.0.113.10", "203.0.113.11"] {
        LocalBotProtectionStore::open(&path)
            .unwrap()
            .evaluate(
                &config,
                test_request(client_id, "/.env", "", "curl/8.0", WafMode::Monitor),
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
fn expired_temporary_block_allows_clean_request() {
    let mut state = BotProtectionState::default();
    state.clients.insert(
        "203.0.113.10".to_string(),
        ClientBotProtectionState {
            entries: Vec::new(),
            temporary_blocked_until: Some(unix_seconds_now().saturating_sub(1)),
        },
    );
    let config = BotProtectionConfig {
        enabled: true,
        mode: BehaviorMode::Block,
        ..BotProtectionConfig::default()
    };

    let outcome = evaluate_with_state(
        &config,
        test_request("203.0.113.10", "/", "", "Mozilla/5.0", WafMode::Block),
        &mut state,
        "memory",
    );

    assert_eq!(outcome.action, WafAction::Allow);
    assert!(outcome.temporary_blocked_until.is_none());
}

#[test]
fn route_override_changes_thresholds() {
    let store = MemoryBotProtectionStore::new();
    let config = BotProtectionConfig {
        enabled: true,
        backend: BehaviorBackend::Memory,
        monitor_threshold: 80,
        block_threshold: 100,
        routes: vec![BotProtectionRouteConfig {
            path: "/login".to_string(),
            monitor_threshold: Some(20),
            block_threshold: Some(40),
        }],
        ..BotProtectionConfig::default()
    };

    let outcome = store
        .evaluate(
            &config,
            test_request("203.0.113.10", "/login", "", "", WafMode::Monitor),
        )
        .unwrap();

    assert_eq!(outcome.monitor_threshold, 20);
    assert_eq!(outcome.action, WafAction::Monitor);
}

#[test]
fn custom_scanner_paths_drive_bot_scoring() {
    let store = MemoryBotProtectionStore::new();
    let config = BotProtectionConfig {
        enabled: true,
        backend: BehaviorBackend::Memory,
        monitor_threshold: 20,
        block_threshold: 80,
        scanner_paths: vec!["/custom-scanner".to_string()],
        ..BotProtectionConfig::default()
    };

    let outcome = store
        .evaluate(
            &config,
            test_request(
                "203.0.113.10",
                "/custom-scanner/run",
                "",
                "Mozilla/5.0",
                WafMode::Monitor,
            ),
        )
        .unwrap();

    assert_eq!(outcome.action, WafAction::Monitor);
    assert!(outcome
        .contributors
        .iter()
        .any(|contributor| contributor.reason == "scanner_path_probe"));
}

#[test]
fn scanner_path_exclusion_prevents_bot_scoring() {
    let store = MemoryBotProtectionStore::new();
    let config = BotProtectionConfig {
        enabled: true,
        scanner_paths: vec!["/admin".to_string()],
        scanner_path_exclusions: vec!["/admin".to_string()],
        ..BotProtectionConfig::default()
    };

    let outcome = store
        .evaluate(
            &config,
            test_request(
                "203.0.113.10",
                "/admin/login/",
                "",
                "Mozilla/5.0",
                WafMode::Block,
            ),
        )
        .unwrap();

    assert_eq!(outcome.score, 0);
    assert_eq!(outcome.action, WafAction::Allow);
}

#[test]
fn trusted_forwarded_proto_policy_scores_unexpected_proto() {
    let store = MemoryBotProtectionStore::new();
    let config = BotProtectionConfig {
        enabled: true,
        backend: BehaviorBackend::Memory,
        monitor_threshold: 10,
        block_threshold: 80,
        ..BotProtectionConfig::default()
    };

    let outcome = store
        .evaluate(
            &config,
            test_request(
                "203.0.113.10",
                "/",
                "x-forwarded-proto: http",
                "Mozilla/5.0",
                WafMode::Monitor,
            ),
        )
        .unwrap();

    assert_eq!(outcome.action, WafAction::Monitor);
    assert!(outcome
        .contributors
        .iter()
        .any(|contributor| contributor.reason == "insecure_forwarded_proto"));
}

#[test]
fn untrusted_forwarded_proto_header_is_not_scored() {
    let store = MemoryBotProtectionStore::new();
    let config = BotProtectionConfig {
        enabled: true,
        backend: BehaviorBackend::Memory,
        monitor_threshold: 10,
        block_threshold: 80,
        ..BotProtectionConfig::default()
    };

    let mut request = test_request(
        "203.0.113.10",
        "/",
        "x-forwarded-proto: http",
        "Mozilla/5.0",
        WafMode::Monitor,
    );
    request.trusted_forwarded_headers = false;
    let outcome = store.evaluate(&config, request).unwrap();

    assert_eq!(outcome.action, WafAction::Allow);
    assert!(outcome.contributors.is_empty());
}

#[test]
fn bot_rule_match_uses_configured_rule_metadata() {
    let config = BotProtectionConfig {
        rule: crate::config::BotProtectionRuleConfig {
            id: "CUSTOM-BOT-001".to_string(),
            name: "Custom Bot Threshold".to_string(),
            category: "custom_bot".to_string(),
            ..Default::default()
        },
        ..BotProtectionConfig::default()
    };
    let outcome = BotProtectionOutcome {
        enabled: true,
        action: WafAction::Monitor,
        score: 40,
        monitor_threshold: 40,
        block_threshold: 80,
        score_window_seconds: 600,
        temporary_block_duration_seconds: 900,
        temporary_blocked_until: None,
        storage_backend: "memory".to_string(),
        allowlisted: false,
        blocklisted: false,
        contributors: Vec::new(),
    };

    let rule_match = bot_rule_match(&config, &outcome).unwrap();

    assert_eq!(rule_match.rule_id, "CUSTOM-BOT-001");
    assert_eq!(rule_match.rule_name, "Custom Bot Threshold");
    assert_eq!(rule_match.category, "custom_bot");
}

fn test_request<'a>(
    client_id: &'a str,
    path: &'a str,
    headers: &'a str,
    user_agent: &'a str,
    server_mode: WafMode,
) -> BotProtectionRequest<'a> {
    BotProtectionRequest {
        client_id,
        path,
        headers,
        user_agent,
        forwarded_headers: &DEFAULT_FORWARDED_HEADERS,
        trusted_forwarded_headers: true,
        server_mode,
    }
}

static DEFAULT_FORWARDED_HEADERS: std::sync::LazyLock<ForwardedHeadersConfig> =
    std::sync::LazyLock::new(ForwardedHeadersConfig::default);
