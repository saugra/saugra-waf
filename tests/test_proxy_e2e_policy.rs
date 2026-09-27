mod common;

use std::{sync::Arc, time::Duration};

use axum::{
    body::Body,
    extract::State,
    http::{header, Method, Request, StatusCode},
};
use saugra_waf::{
    config::{
        BehaviorBackend, BehaviorMode, RuleExclusionConfig, RuntimeAllowlistEffect,
        RuntimePolicyConfig, UnknownThreatMode, UnknownThreatRouteConfig, WafMode,
    },
    decision::WafAction,
    event_store,
    proxy::{proxy_request, ProxyState},
    rate_limit::MemoryRateLimitStore,
    runtime_policy,
};

use common::*;

#[tokio::test]
async fn guarded_unknown_threat_policy_blocks_mature_high_risk_route() {
    let fake_upstream = Arc::new(FakeUpstreamTransport::new());
    let event_log_path = test_event_log_path();
    let retention = test_retention();
    let mut config = test_config(WafMode::Block, 120);
    config.unknown_threats.enabled = true;
    config.unknown_threats.mode = UnknownThreatMode::Block;
    config.unknown_threats.backend = BehaviorBackend::Memory;
    config.unknown_threats.shadow_review_completed = true;
    config.unknown_threats.minimum_observations = 2;
    config.unknown_threats.minimum_block_observations = 2;
    config.unknown_threats.minimum_baseline_age = "1s".to_string();
    config.unknown_threats.monitor_threshold = 10;
    config.unknown_threats.block_threshold = 20;
    config.unknown_threats.promotion_observations = 1;
    config.unknown_threats.routes = vec![UnknownThreatRouteConfig {
        path: "/admin".to_string(),
        high_risk: true,
        ..UnknownThreatRouteConfig::default()
    }];
    let state = ProxyState::with_transport(
        config,
        fake_upstream.clone(),
        Arc::new(MemoryRateLimitStore::new()),
        event_log_path.clone(),
        retention,
    )
    .unwrap();

    for id in [42, 43] {
        let request = Request::builder()
            .uri(format!("/admin/{id}?page=1"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{}"))
            .unwrap();
        assert_eq!(
            proxy_request(State(state.clone()), request)
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
    tokio::time::sleep(Duration::from_secs(2)).await;

    let request = Request::builder()
        .method(Method::DELETE)
        .uri("/admin/44?page=1")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from("ok"))
        .unwrap();
    let response = proxy_request(State(state), request).await.unwrap_err();
    let events = event_store::tail(&event_log_path, retention, 10).unwrap();
    let outcome = events
        .last()
        .unwrap()
        .decision
        .unknown_threats
        .as_ref()
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(events.last().unwrap().decision.action, WafAction::Block);
    assert!(outcome.would_block);
    assert!(outcome.block_eligible);
    assert_eq!(outcome.signals.len(), 2);
    assert!(events
        .last()
        .unwrap()
        .decision
        .matched_rules
        .iter()
        .any(|rule_match| rule_match.rule_id == "SAUGRA-UNKNOWN-THREAT-001"));
    assert_eq!(events.last().unwrap().decision.risk_score, 80);
    assert!(fake_upstream.requests.lock().unwrap().len() == 2);
}

#[tokio::test]
async fn scoped_rule_exclusion_prevents_false_positive_blocking() {
    let fake_upstream = Arc::new(FakeUpstreamTransport::new());
    let event_log_path = test_event_log_path();
    let retention = test_retention();
    let mut config = test_config(WafMode::Block, 120);
    config.rules.exclusions = vec![RuleExclusionConfig {
        rule_ids: vec!["SAUGRA-XSS-001".to_string()],
        path_prefixes: vec!["/api/articles".to_string()],
        query_params: vec!["content".to_string()],
        methods: vec!["POST".to_string()],
        targets: vec![saugra_waf::rules::RuleTarget::Query],
        content_types: vec!["application/json".to_string()],
        trusted_headers: vec![saugra_waf::config::RuleExclusionHeaderValueConfig {
            name: "X-Deployment".to_string(),
            values: vec!["internal".to_string()],
        }],
        ..RuleExclusionConfig::default()
    }];
    let state = ProxyState::with_transport(
        config,
        fake_upstream.clone(),
        Arc::new(MemoryRateLimitStore::new()),
        event_log_path.clone(),
        retention,
    )
    .unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/articles/preview?content=%3Cscript%3Ealert(1)%3C/script%3E")
        .header("content-type", "application/json; charset=utf-8")
        .header("x-deployment", "internal")
        .body(Body::empty())
        .unwrap();

    let response = proxy_request(State(state), request).await.unwrap();
    let events = event_store::tail(&event_log_path, retention, 10).unwrap();
    let recorded = fake_upstream.requests.lock().unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(recorded.len(), 1);
    assert_eq!(events[0].decision.action, WafAction::Allow);
    assert!(events[0].decision.matched_rules.is_empty());
    assert_eq!(events[0].decision.anomaly_score, 0);
    let evidence = events[0].evidence.as_ref().unwrap();
    assert_eq!(evidence.content_type, "application/json");
    assert_eq!(evidence.query_parameter_names, vec!["content"]);
    assert!(evidence.header_names.contains(&"content-type".to_string()));
    assert!(evidence.header_names.contains(&"x-deployment".to_string()));
    let encoded = serde_json::to_string(&events[0]).unwrap();
    assert!(!encoded.contains("internal"));
    assert!(!encoded.contains("charset=utf-8"));
}

#[tokio::test]
async fn runtime_allowlist_bypasses_bot_block_without_restart() {
    let fake_upstream = Arc::new(FakeUpstreamTransport::new());
    let event_log_path = test_event_log_path();
    let runtime_policy_file = tempfile::NamedTempFile::new().unwrap();
    let retention = test_retention();
    runtime_policy::add_ip_entry(
        runtime_policy_file.path(),
        "198.51.100.71",
        Some(3600),
        "admin verification",
        "test",
    )
    .unwrap();

    let mut config = test_config(WafMode::Block, 120);
    config.runtime_policy = RuntimePolicyConfig {
        enabled: true,
        path: runtime_policy_file.path().to_path_buf(),
        ..RuntimePolicyConfig::default()
    };
    config.bot_protection = saugra_waf::config::BotProtectionConfig {
        enabled: true,
        mode: BehaviorMode::Block,
        backend: BehaviorBackend::Memory,
        blocklists: saugra_waf::config::BotProtectionLists {
            ip_ranges: vec!["198.51.100.71".to_string()],
            user_agents: Vec::new(),
        },
        ..saugra_waf::config::BotProtectionConfig::default()
    };
    let state = ProxyState::with_transport(
        config,
        fake_upstream.clone(),
        Arc::new(MemoryRateLimitStore::new()),
        event_log_path.clone(),
        retention,
    )
    .unwrap();
    let request = Request::builder()
        .uri("/")
        .header("user-agent", "Mozilla/5.0")
        .header("x-real-ip", "198.51.100.71")
        .body(Body::empty())
        .unwrap();

    let response = proxy_request(State(state), request).await.unwrap();
    let events = event_store::tail(&event_log_path, retention, 10).unwrap();
    let recorded = fake_upstream.requests.lock().unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(recorded.len(), 1);
    assert_eq!(events[0].decision.action, WafAction::Allow);
    assert!(events[0].decision.bot_protection.is_none());
    assert_eq!(
        events[0]
            .decision
            .runtime_allowlist
            .as_ref()
            .map(|allowlist| allowlist.value.as_str()),
        Some("198.51.100.71/32")
    );
}

#[tokio::test]
async fn runtime_allowlist_reload_applies_policy_mutation_without_restart() {
    let fake_upstream = Arc::new(FakeUpstreamTransport::new());
    let event_log_path = test_event_log_path();
    let runtime_policy_file = tempfile::NamedTempFile::new().unwrap();
    let retention = test_retention();
    let mut config = test_config(WafMode::Block, 120);
    config.runtime_policy = RuntimePolicyConfig {
        enabled: true,
        path: runtime_policy_file.path().to_path_buf(),
        reload_interval: "1s".to_string(),
        ..RuntimePolicyConfig::default()
    };
    config.bot_protection = saugra_waf::config::BotProtectionConfig {
        enabled: true,
        mode: BehaviorMode::Block,
        backend: BehaviorBackend::Memory,
        blocklists: saugra_waf::config::BotProtectionLists {
            ip_ranges: vec!["198.51.100.74".to_string()],
            user_agents: Vec::new(),
        },
        ..saugra_waf::config::BotProtectionConfig::default()
    };
    let state = ProxyState::with_transport(
        config,
        fake_upstream.clone(),
        Arc::new(MemoryRateLimitStore::new()),
        event_log_path.clone(),
        retention,
    )
    .unwrap();
    let blocked_request = Request::builder()
        .uri("/")
        .header("user-agent", "Mozilla/5.0")
        .header("x-real-ip", "198.51.100.74")
        .body(Body::empty())
        .unwrap();

    let blocked_response = proxy_request(State(state.clone()), blocked_request)
        .await
        .unwrap_err();

    runtime_policy::add_ip_entry(
        runtime_policy_file.path(),
        "198.51.100.74",
        Some(3600),
        "reload verification",
        "test",
    )
    .unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let allowed_request = Request::builder()
        .uri("/")
        .header("user-agent", "Mozilla/5.0")
        .header("x-real-ip", "198.51.100.74")
        .body(Body::empty())
        .unwrap();

    let allowed_response = proxy_request(State(state), allowed_request).await.unwrap();
    let events = event_store::tail(&event_log_path, retention, 10).unwrap();
    let recorded = fake_upstream.requests.lock().unwrap();

    assert_eq!(blocked_response.status(), StatusCode::FORBIDDEN);
    assert_eq!(allowed_response.status(), StatusCode::OK);
    assert_eq!(recorded.len(), 1);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].decision.action, WafAction::Block);
    assert_eq!(events[1].decision.action, WafAction::Allow);
    assert_eq!(
        events[1]
            .decision
            .runtime_allowlist
            .as_ref()
            .map(|allowlist| allowlist.reason.as_str()),
        Some("reload verification")
    );
}

#[tokio::test]
async fn runtime_monitor_all_downgrades_waf_rule_block_without_restart() {
    let fake_upstream = Arc::new(FakeUpstreamTransport::new());
    let event_log_path = test_event_log_path();
    let runtime_policy_file = tempfile::NamedTempFile::new().unwrap();
    let retention = test_retention();
    runtime_policy::add_ip_entry(
        runtime_policy_file.path(),
        "198.51.100.72",
        Some(3600),
        "admin verification",
        "test",
    )
    .unwrap();

    let mut config = test_config(WafMode::Block, 120);
    config.runtime_policy = RuntimePolicyConfig {
        enabled: true,
        path: runtime_policy_file.path().to_path_buf(),
        allowlist_effect: RuntimeAllowlistEffect::MonitorAll,
        ..RuntimePolicyConfig::default()
    };
    config.bot_protection.enabled = false;
    config.behavior.enabled = false;
    let state = ProxyState::with_transport(
        config,
        fake_upstream.clone(),
        Arc::new(MemoryRateLimitStore::new()),
        event_log_path.clone(),
        retention,
    )
    .unwrap();
    let request = Request::builder()
        .uri("/search?q=%27%20OR%201%3D1--")
        .header("x-real-ip", "198.51.100.72")
        .body(Body::empty())
        .unwrap();

    let response = proxy_request(State(state), request).await.unwrap();
    let events = event_store::tail(&event_log_path, retention, 10).unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(fake_upstream.requests.lock().unwrap().len(), 1);
    assert_eq!(events[0].decision.action, WafAction::Monitor);
    assert!(events[0]
        .decision
        .matched_rules
        .iter()
        .any(|rule_match| rule_match.rule_id == "SAUGRA-SQLI-001"));
}

#[tokio::test]
async fn runtime_blocklist_blocks_clean_request_without_restart() {
    let fake_upstream = Arc::new(FakeUpstreamTransport::new());
    let event_log_path = test_event_log_path();
    let runtime_policy_file = tempfile::NamedTempFile::new().unwrap();
    let retention = test_retention();
    runtime_policy::add_block_ip_entry(
        runtime_policy_file.path(),
        "198.51.100.73",
        Some(3600),
        "emergency deny",
        "test",
    )
    .unwrap();

    let mut config = test_config(WafMode::Monitor, 120);
    config.runtime_policy = RuntimePolicyConfig {
        enabled: true,
        path: runtime_policy_file.path().to_path_buf(),
        ..RuntimePolicyConfig::default()
    };
    config.bot_protection.enabled = false;
    config.behavior.enabled = false;
    let state = ProxyState::with_transport(
        config,
        fake_upstream.clone(),
        Arc::new(MemoryRateLimitStore::new()),
        event_log_path.clone(),
        retention,
    )
    .unwrap();
    let request = Request::builder()
        .uri("/")
        .header("x-real-ip", "198.51.100.73")
        .body(Body::empty())
        .unwrap();

    let response = proxy_request(State(state), request).await.unwrap_err();
    let events = event_store::tail(&event_log_path, retention, 10).unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(fake_upstream.requests.lock().unwrap().is_empty());
    assert_eq!(events[0].decision.action, WafAction::Block);
    assert!(events[0]
        .decision
        .matched_rules
        .iter()
        .any(|rule_match| rule_match.rule_id == "SAUGRA-RUNTIME-BLOCKLIST-001"));
}
