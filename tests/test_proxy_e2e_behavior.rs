mod common;

use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{header, Method, Request, StatusCode},
};
use saugra_waf::{
    config::{
        BehaviorBackend, BehaviorConfig, BehaviorMode, BotProtectionConfig, BotProtectionLists,
        CampaignBackend, CampaignPolicyConfig, WafMode,
    },
    decision::WafAction,
    event_store,
    proxy::{proxy_request, ProxyState},
    rate_limit::MemoryRateLimitStore,
};

use common::*;

#[tokio::test]
async fn campaign_correlation_records_monitor_only_campaign_ids() {
    let fake_upstream = Arc::new(FakeUpstreamTransport::new());
    let event_log_path = test_event_log_path();
    let retention = test_retention();
    let mut config = test_config(WafMode::Block, 120);
    config.campaign_correlation.enabled = true;
    config.campaign_correlation.backend = CampaignBackend::Memory;
    config.campaign_correlation.policies = vec![CampaignPolicyConfig {
        kind: "endpoint_discovery".to_string(),
        scope: "client".to_string(),
        score: 50,
        minimum_events: 2,
        minimum_clients: 1,
        minimum_sessions: 1,
        minimum_routes: 2,
        categories: vec!["scanner_behavior".to_string()],
        path_prefixes: Vec::new(),
        stages: Vec::new(),
        minimum_stages: 0,
    }];
    let state = ProxyState::with_transport(
        config,
        fake_upstream.clone(),
        Arc::new(MemoryRateLimitStore::new()),
        event_log_path.clone(),
        retention,
    )
    .unwrap();

    for path in ["/.env", "/wp-admin"] {
        let request = Request::builder()
            .uri(path)
            .header(header::USER_AGENT, "sqlmap")
            .header(header::COOKIE, "session=campaign-test")
            .body(Body::empty())
            .unwrap();
        let response = proxy_request(State(state.clone()), request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    let events = event_store::tail(&event_log_path, retention, 10).unwrap();
    let campaign = events.last().unwrap().decision.campaign.as_ref().unwrap();
    assert_eq!(campaign.action, WafAction::Monitor);
    assert_eq!(campaign.matches[0].kind, "endpoint_discovery");
    assert!(campaign.campaign_ids[0].starts_with("cmp-"));
    assert_eq!(fake_upstream.requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn behavior_monitor_mode_records_score_and_still_forwards() {
    let fake_upstream = Arc::new(FakeUpstreamTransport::new());
    let event_log_path = test_event_log_path();
    let retention = test_retention();
    let mut config = test_config(WafMode::Block, 120);
    config.behavior = BehaviorConfig {
        enabled: true,
        backend: BehaviorBackend::Memory,
        monitor_threshold: 10,
        block_threshold: 80,
        ..BehaviorConfig::default()
    };
    config.bot_protection.enabled = false;
    let state = ProxyState::with_transport(
        config,
        fake_upstream.clone(),
        Arc::new(MemoryRateLimitStore::new()),
        event_log_path.clone(),
        retention,
    )
    .unwrap();
    let request = Request::builder()
        .uri("/.env")
        .header("x-real-ip", "198.51.100.44")
        .body(Body::empty())
        .unwrap();

    let response = proxy_request(State(state), request).await.unwrap();
    let events = event_store::tail(&event_log_path, retention, 10).unwrap();
    let recorded = fake_upstream.requests.lock().unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(recorded.len(), 1);
    assert_eq!(events[0].decision.action, WafAction::Monitor);
    let behavior = events[0].decision.behavior.as_ref().unwrap();
    assert_eq!(behavior.action, WafAction::Monitor);
    assert!(behavior.score >= 10);
    assert!(behavior
        .contributors
        .iter()
        .any(|contributor| contributor.reason == "scanner_path_probe"));
}

#[tokio::test]
async fn behavior_block_mode_blocks_after_threshold_and_persists_event_shape() {
    let fake_upstream = Arc::new(FakeUpstreamTransport::new());
    let event_log_path = test_event_log_path();
    let retention = test_retention();
    let mut config = test_config(WafMode::Monitor, 120);
    config.behavior = BehaviorConfig {
        enabled: true,
        mode: BehaviorMode::Block,
        backend: BehaviorBackend::Memory,
        monitor_threshold: 10,
        block_threshold: 20,
        ..BehaviorConfig::default()
    };
    let state = ProxyState::with_transport(
        config,
        fake_upstream.clone(),
        Arc::new(MemoryRateLimitStore::new()),
        event_log_path.clone(),
        retention,
    )
    .unwrap();

    for path in ["/.env", "/.git/config"] {
        let request = Request::builder()
            .uri(path)
            .header("x-real-ip", "198.51.100.45")
            .body(Body::empty())
            .unwrap();
        let _ = proxy_request(State(state.clone()), request).await;
    }

    let events = event_store::tail(&event_log_path, retention, 10).unwrap();
    let recorded = fake_upstream.requests.lock().unwrap();
    let blocked = events.last().unwrap();

    assert_eq!(recorded.len(), 1);
    assert_eq!(blocked.decision.action, WafAction::Block);
    assert!(blocked
        .decision
        .matched_rules
        .iter()
        .any(|rule_match| rule_match.rule_id == "SAUGRA-BEHAVIOR-001"));
    let behavior = blocked.decision.behavior.as_ref().unwrap();
    assert_eq!(behavior.action, WafAction::Block);
    assert_eq!(behavior.storage_backend, "memory");
    assert!(behavior.score >= behavior.block_threshold);
}

#[tokio::test]
async fn bot_protection_monitor_mode_records_score_and_still_forwards() {
    let fake_upstream = Arc::new(FakeUpstreamTransport::new());
    let event_log_path = test_event_log_path();
    let retention = test_retention();
    let mut config = test_config(WafMode::Block, 120);
    config.bot_protection = BotProtectionConfig {
        enabled: true,
        backend: BehaviorBackend::Memory,
        monitor_threshold: 20,
        block_threshold: 80,
        ..BotProtectionConfig::default()
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
        .uri("/.env")
        .header("user-agent", "curl/8.0")
        .header("x-real-ip", "198.51.100.70")
        .body(Body::empty())
        .unwrap();

    let response = proxy_request(State(state), request).await.unwrap();
    let events = event_store::tail(&event_log_path, retention, 10).unwrap();
    let recorded = fake_upstream.requests.lock().unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(recorded.len(), 1);
    assert_eq!(events[0].decision.action, WafAction::Monitor);
    let bot = events[0].decision.bot_protection.as_ref().unwrap();
    assert_eq!(bot.action, WafAction::Monitor);
    assert!(bot
        .contributors
        .iter()
        .any(|contributor| contributor.reason == "automation_user_agent"));
}

#[tokio::test]
async fn monitor_only_bot_and_behavior_findings_do_not_combine_into_block() {
    let fake_upstream = Arc::new(FakeUpstreamTransport::new());
    let event_log_path = test_event_log_path();
    let retention = test_retention();
    let mut config = test_config(WafMode::Block, 120);
    config.behavior = BehaviorConfig {
        enabled: true,
        backend: BehaviorBackend::Memory,
        monitor_threshold: 40,
        block_threshold: 80,
        probe_paths: vec!["/admin".to_string()],
        ..BehaviorConfig::default()
    };
    config.bot_protection = BotProtectionConfig {
        enabled: true,
        backend: BehaviorBackend::Memory,
        monitor_threshold: 40,
        block_threshold: 80,
        scanner_paths: vec!["/admin".to_string()],
        ..BotProtectionConfig::default()
    };
    let state = ProxyState::with_transport(
        config,
        fake_upstream.clone(),
        Arc::new(MemoryRateLimitStore::new()),
        event_log_path.clone(),
        retention,
    )
    .unwrap();

    for _ in 0..3 {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/admin/login/?next=/admin/meeting/")
            .header("user-agent", "Mozilla/5.0")
            .header("x-real-ip", "198.51.100.75")
            .body(Body::empty())
            .unwrap();
        let response = proxy_request(State(state.clone()), request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    let events = event_store::tail(&event_log_path, retention, 10).unwrap();
    let final_decision = &events.last().unwrap().decision;

    assert_eq!(fake_upstream.requests.lock().unwrap().len(), 3);
    assert_eq!(final_decision.action, WafAction::Monitor);
    assert_eq!(final_decision.anomaly_score, 6);
    assert_eq!(final_decision.blocking_anomaly_score, 0);
    assert_eq!(
        final_decision.bot_protection.as_ref().unwrap().action,
        WafAction::Monitor
    );
    assert_eq!(
        final_decision.behavior.as_ref().unwrap().action,
        WafAction::Monitor
    );
    assert!(!final_decision
        .behavior
        .as_ref()
        .unwrap()
        .contributors
        .iter()
        .any(|contributor| contributor.reason == "rule_match:bot_protection"));
}

#[tokio::test]
async fn bot_protection_blocklist_blocks_and_persists_event_shape() {
    let fake_upstream = Arc::new(FakeUpstreamTransport::new());
    let event_log_path = test_event_log_path();
    let retention = test_retention();
    let mut config = test_config(WafMode::Monitor, 120);
    config.bot_protection = BotProtectionConfig {
        enabled: true,
        mode: BehaviorMode::Block,
        backend: BehaviorBackend::Memory,
        blocklists: BotProtectionLists {
            ip_ranges: vec!["198.51.100.71".to_string()],
            user_agents: Vec::new(),
        },
        ..BotProtectionConfig::default()
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

    let response = proxy_request(State(state), request).await.unwrap_err();
    let events = event_store::tail(&event_log_path, retention, 10).unwrap();
    let recorded = fake_upstream.requests.lock().unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(recorded.is_empty());
    assert_eq!(events[0].decision.action, WafAction::Block);
    assert!(events[0]
        .decision
        .matched_rules
        .iter()
        .any(|rule_match| rule_match.rule_id == "SAUGRA-BOT-PROTECTION-001"));
    let bot = events[0].decision.bot_protection.as_ref().unwrap();
    assert_eq!(bot.action, WafAction::Block);
    assert!(bot.blocklisted);
}
