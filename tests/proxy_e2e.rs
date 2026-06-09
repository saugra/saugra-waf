use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Context;
use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{header, HeaderMap, Method, Request, Response, StatusCode, Uri},
};
use saugra_waf::{
    config::{
        AiConfig, BehaviorBackend, BehaviorConfig, BehaviorMode, BotProtectionConfig,
        BotProtectionLists, LoggingConfig, ProxyRouteConfig, RateLimitBackend, RateLimitConfig,
        RuleExclusionConfig, RuleSettings, RuntimeAllowlistEffect, RuntimePolicyConfig,
        SaugraConfig, SecurityConfig, ServerConfig, UpstreamConfig, WafMode,
    },
    decision::WafAction,
    event_store::{self, EventLogRetention},
    proxy::{proxy_request, ProxyState, UpstreamTransport},
    rate_limit::MemoryRateLimitStore,
    runtime_policy,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use uuid::Uuid;

#[tokio::test]
async fn forwards_clean_requests_to_upstream() {
    let fake_upstream = Arc::new(FakeUpstreamTransport::new());
    let state = test_state_with_transport(WafMode::Block, 120, fake_upstream.clone());
    let request = Request::builder()
        .method(Method::POST)
        .uri("/orders?status=new")
        .header(header::HOST, "public.example")
        .header(header::AUTHORIZATION, "Bearer secret")
        .body(Body::from("hello"))
        .unwrap();

    let response = proxy_request(State(state), request).await.unwrap();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let recorded = fake_upstream.requests.lock().unwrap();

    assert_eq!(&body[..], b"upstream-ok");
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].method, Method::POST);
    assert_eq!(recorded[0].uri, "http://127.0.0.1:1/orders?status=new");
    assert_eq!(
        recorded[0].headers.get(header::HOST).unwrap(),
        "example.com"
    );
    assert!(recorded[0].headers.get(header::AUTHORIZATION).is_some());
    assert_eq!(recorded[0].body, b"hello");
}

#[tokio::test]
async fn forwards_http_requests_to_longest_matching_upstream_route() {
    let fake_upstream = Arc::new(FakeUpstreamTransport::new());
    let event_log_path = test_event_log_path();
    let retention = test_retention();
    let mut config = test_config(WafMode::Block, 120);
    config.upstreams.push(UpstreamConfig {
        name: "api".to_string(),
        host: "api.example.com".to_string(),
        target: "http://127.0.0.1:2".to_string(),
    });
    config.upstreams.push(UpstreamConfig {
        name: "admin-api".to_string(),
        host: "admin-api.example.com".to_string(),
        target: "http://127.0.0.1:3".to_string(),
    });
    config.routes = vec![
        ProxyRouteConfig {
            path_prefix: "/api/".to_string(),
            upstream: "api".to_string(),
        },
        ProxyRouteConfig {
            path_prefix: "/api/admin/".to_string(),
            upstream: "admin-api".to_string(),
        },
        ProxyRouteConfig {
            path_prefix: "/".to_string(),
            upstream: "app".to_string(),
        },
    ];
    let state = ProxyState::with_transport(
        config,
        fake_upstream.clone(),
        Arc::new(MemoryRateLimitStore::new()),
        event_log_path.clone(),
        retention,
    )
    .unwrap();
    let request = Request::builder()
        .uri("/api/admin/users?active=true")
        .body(Body::empty())
        .unwrap();

    let response = proxy_request(State(state), request).await.unwrap();
    let recorded = fake_upstream.requests.lock().unwrap();
    let events = event_store::tail(&event_log_path, retention, 10).unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(recorded.len(), 1);
    assert_eq!(
        recorded[0].uri,
        "http://127.0.0.1:3/api/admin/users?active=true"
    );
    assert_eq!(
        recorded[0].headers.get(header::HOST).unwrap(),
        "admin-api.example.com"
    );
    let upstream = events[0].upstream.as_ref().unwrap();
    assert_eq!(upstream.name, "admin-api");
    assert_eq!(upstream.host, "admin-api.example.com");
    assert_eq!(upstream.target, "http://127.0.0.1:3");
}

#[tokio::test]
async fn monitor_mode_records_attack_and_still_forwards() {
    let fake_upstream = Arc::new(FakeUpstreamTransport::new());
    let event_log_path = test_event_log_path();
    let retention = test_retention();
    let state = test_state_with_path(
        WafMode::Monitor,
        120,
        fake_upstream.clone(),
        event_log_path.clone(),
        retention,
    );
    let request = Request::builder()
        .uri("/search?q=--")
        .header("x-forwarded-for", "203.0.113.10, 10.0.0.1")
        .body(Body::empty())
        .unwrap();

    let response = proxy_request(State(state), request).await.unwrap();
    let events = event_store::tail(&event_log_path, retention, 10).unwrap();
    let recorded = fake_upstream.requests.lock().unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(recorded.len(), 1);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].client_ip, "203.0.113.10");
    assert_eq!(events[0].upstream.as_ref().unwrap().name, "app");
    assert_eq!(events[0].decision.action, WafAction::Monitor);
    assert_eq!(
        events[0].decision.matched_rules[0].rule_id,
        "SAUGRA-SQLI-001"
    );
    assert!(event_store::find_by_request_id(
        &event_log_path,
        retention,
        &events[0].decision.request_id
    )
    .unwrap()
    .is_some());
}

#[tokio::test]
async fn block_mode_records_attack_and_does_not_forward() {
    let fake_upstream = Arc::new(FakeUpstreamTransport::new());
    let event_log_path = test_event_log_path();
    let retention = test_retention();
    let state = test_state_with_path(
        WafMode::Block,
        120,
        fake_upstream.clone(),
        event_log_path.clone(),
        retention,
    );
    let request = Request::builder()
        .uri("/search?q=--")
        .body(Body::empty())
        .unwrap();

    let response = proxy_request(State(state), request).await.unwrap_err();
    let events = event_store::tail(&event_log_path, retention, 10).unwrap();
    let recorded = fake_upstream.requests.lock().unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(recorded.is_empty());
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].upstream.as_ref().unwrap().name, "app");
    assert_eq!(events[0].decision.action, WafAction::Block);
    assert_eq!(
        events[0].decision.matched_rules[0].rule_id,
        "SAUGRA-SQLI-001"
    );
}

#[tokio::test]
async fn block_mode_blocks_path_traversal_in_query_string() {
    let fake_upstream = Arc::new(FakeUpstreamTransport::new());
    let event_log_path = test_event_log_path();
    let retention = test_retention();
    let state = test_state_with_path(
        WafMode::Block,
        120,
        fake_upstream.clone(),
        event_log_path.clone(),
        retention,
    );
    let request = Request::builder()
        .uri("/?file=../../../../etc/passwd")
        .body(Body::empty())
        .unwrap();

    let response = proxy_request(State(state), request).await.unwrap_err();
    let events = event_store::tail(&event_log_path, retention, 10).unwrap();
    let recorded = fake_upstream.requests.lock().unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(recorded.is_empty());
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].path, "/");
    assert_eq!(events[0].query, "file=../../../../etc/passwd");
    assert_eq!(events[0].decision.action, WafAction::Block);
    assert_eq!(
        events[0].decision.matched_rules[0].rule_id,
        "SAUGRA-PATH-002"
    );
}

#[tokio::test]
async fn block_mode_blocks_percent_encoded_sql_injection() {
    let fake_upstream = Arc::new(FakeUpstreamTransport::new());
    let event_log_path = test_event_log_path();
    let retention = test_retention();
    let state = test_state_with_path(
        WafMode::Block,
        120,
        fake_upstream.clone(),
        event_log_path.clone(),
        retention,
    );
    let request = Request::builder()
        .uri("/?id=1'%20OR%201=1")
        .body(Body::empty())
        .unwrap();

    let response = proxy_request(State(state), request).await.unwrap_err();
    let events = event_store::tail(&event_log_path, retention, 10).unwrap();
    let recorded = fake_upstream.requests.lock().unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(recorded.is_empty());
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].path, "/");
    assert_eq!(events[0].query, "id=1'%20OR%201=1");
    assert_eq!(events[0].decision.action, WafAction::Block);
    assert_eq!(
        events[0].decision.matched_rules[0].rule_id,
        "SAUGRA-SQLI-001"
    );
}

#[tokio::test]
async fn block_mode_returns_safe_json_response_for_attack_request() {
    let state = test_state(WafMode::Block, 120);
    let request = Request::builder()
        .uri("/search?q=--")
        .body(Body::empty())
        .unwrap();

    let response = proxy_request(State(state), request).await.unwrap_err();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(json["message"], "Denied");
    assert!(json["reference"].as_str().is_some());
    assert!(json.get("action").is_none());
    assert!(json.get("request_id").is_none());
    assert!(json.get("risk_score").is_none());
    assert!(json.get("owasp_category").is_none());
    assert!(json.get("owasp_categories").is_none());
    assert!(json.get("matched_rules").is_none());
    assert!(json.get("explanation").is_none());
}

#[tokio::test]
async fn block_mode_monitors_findings_below_anomaly_threshold() {
    let fake_upstream = Arc::new(FakeUpstreamTransport::new());
    let event_log_path = test_event_log_path();
    let retention = test_retention();
    let mut config = test_config(WafMode::Block, 120);
    config.rules.inbound_anomaly_threshold = 5;
    config.rules.files = vec![single_low_rule_file()];
    let state = ProxyState::with_transport(
        config,
        fake_upstream.clone(),
        Arc::new(MemoryRateLimitStore::new()),
        event_log_path.clone(),
        retention,
    )
    .unwrap();
    let request = Request::builder()
        .uri("/?signal=low-risk")
        .body(Body::empty())
        .unwrap();

    let response = proxy_request(State(state), request).await.unwrap();
    let events = event_store::tail(&event_log_path, retention, 10).unwrap();
    let recorded = fake_upstream.requests.lock().unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(recorded.len(), 1);
    assert_eq!(events[0].decision.action, WafAction::Monitor);
    assert_eq!(events[0].decision.anomaly_score, 2);
    assert_eq!(events[0].decision.anomaly_threshold, 5);
}

#[tokio::test]
async fn block_mode_blocks_combined_findings_at_anomaly_threshold() {
    let fake_upstream = Arc::new(FakeUpstreamTransport::new());
    let event_log_path = test_event_log_path();
    let retention = test_retention();
    let mut config = test_config(WafMode::Block, 120);
    config.rules.inbound_anomaly_threshold = 5;
    config.rules.files = vec![two_medium_rules_file()];
    let state = ProxyState::with_transport(
        config,
        fake_upstream.clone(),
        Arc::new(MemoryRateLimitStore::new()),
        event_log_path.clone(),
        retention,
    )
    .unwrap();
    let request = Request::builder()
        .uri("/?first=medium-one&second=medium-two")
        .body(Body::empty())
        .unwrap();

    let response = proxy_request(State(state), request).await.unwrap_err();
    let events = event_store::tail(&event_log_path, retention, 10).unwrap();
    let recorded = fake_upstream.requests.lock().unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(recorded.is_empty());
    assert_eq!(events[0].decision.action, WafAction::Block);
    assert_eq!(events[0].decision.anomaly_score, 6);
    assert_eq!(events[0].decision.matched_rules.len(), 2);
}

#[tokio::test]
async fn block_mode_monitors_detection_paranoia_above_blocking_paranoia() {
    let fake_upstream = Arc::new(FakeUpstreamTransport::new());
    let event_log_path = test_event_log_path();
    let retention = test_retention();
    let mut config = test_config(WafMode::Block, 120);
    config.rules.inbound_anomaly_threshold = 5;
    config.rules.detection_paranoia_level = Some(2);
    config.rules.blocking_paranoia_level = Some(1);
    config.rules.files = vec![single_high_paranoia_rule_file()];
    let state = ProxyState::with_transport(
        config,
        fake_upstream.clone(),
        Arc::new(MemoryRateLimitStore::new()),
        event_log_path.clone(),
        retention,
    )
    .unwrap();
    let request = Request::builder()
        .uri("/?signal=pl2")
        .body(Body::empty())
        .unwrap();

    let response = proxy_request(State(state), request).await.unwrap();
    let events = event_store::tail(&event_log_path, retention, 10).unwrap();
    let recorded = fake_upstream.requests.lock().unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(recorded.len(), 1);
    assert_eq!(events[0].decision.action, WafAction::Monitor);
    assert_eq!(events[0].decision.anomaly_score, 5);
    assert_eq!(events[0].decision.blocking_anomaly_score, 0);
    assert_eq!(events[0].decision.blocking_paranoia_level, 1);
    assert_eq!(events[0].decision.matched_rules[0].paranoia_level, 2);
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
        .uri("/api/articles/preview?content=%3Cscript%3Ealert(1)%3C/script%3E")
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
}

#[tokio::test]
async fn rate_limit_blocks_and_persists_event_before_forwarding() {
    let fake_upstream = Arc::new(FakeUpstreamTransport::new());
    let event_log_path = test_event_log_path();
    let retention = test_retention();
    let state = test_state_with_path(
        WafMode::Block,
        1,
        fake_upstream.clone(),
        event_log_path.clone(),
        retention,
    );
    let first_request = Request::builder()
        .uri("/")
        .header("x-real-ip", "198.51.100.80")
        .body(Body::empty())
        .unwrap();
    let second_request = Request::builder()
        .uri("/")
        .header("x-real-ip", "198.51.100.80")
        .body(Body::empty())
        .unwrap();

    let _ = proxy_request(State(state.clone()), first_request)
        .await
        .unwrap();
    let response = proxy_request(State(state), second_request)
        .await
        .unwrap_err();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let events = event_store::tail(&event_log_path, retention, 10).unwrap();
    let recorded = fake_upstream.requests.lock().unwrap();

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(json["message"], "Denied");
    assert!(json["reference"].as_str().is_some());
    assert!(json.get("action").is_none());
    assert!(json.get("request_id").is_none());
    assert!(json.get("retry_after_seconds").is_none());
    assert!(json.get("risk_score").is_none());
    assert!(json.get("matched_rules").is_none());
    assert!(json.get("explanation").is_none());
    assert_eq!(recorded.len(), 1);
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].upstream.as_ref().unwrap().name, "app");
    assert_eq!(events[1].decision.action, WafAction::Block);
    assert_eq!(
        events[1].decision.matched_rules[0].rule_id,
        "SAUGRA-RATE-001"
    );
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
    config.bot_protection = BotProtectionConfig {
        enabled: true,
        mode: BehaviorMode::Block,
        backend: BehaviorBackend::Memory,
        blocklists: BotProtectionLists {
            ip_ranges: vec!["198.51.100.74".to_string()],
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

#[tokio::test]
async fn websocket_handshake_is_inspected_forwarded_and_tunneled() {
    let upstream = spawn_raw_websocket_upstream().await;
    let event_log_path = test_event_log_path();
    let mut config = test_config(WafMode::Block, 120);
    config.server.listen = free_loopback_addr();
    config.upstreams.push(UpstreamConfig {
        name: "ws".to_string(),
        host: "ws.example.com".to_string(),
        target: format!("http://{}", upstream.addr),
    });
    config.routes = vec![
        ProxyRouteConfig {
            path_prefix: "/ws/".to_string(),
            upstream: "ws".to_string(),
        },
        ProxyRouteConfig {
            path_prefix: "/".to_string(),
            upstream: "app".to_string(),
        },
    ];
    config.logging.event_log_path = event_log_path.to_string_lossy().to_string();
    config.websocket.allowed_origins = vec!["https://example.com".to_string()];
    config.websocket.allowed_hosts = vec!["example.com".to_string()];
    let listen = config.server.listen.clone();
    let retention = EventLogRetention {
        max_size_bytes: config.event_log_max_size_bytes().unwrap(),
        max_files: config.logging.event_log_max_files,
    };

    let server = tokio::spawn(saugra_waf::proxy::run(config));
    let mut stream = connect_with_retry(&listen).await;
    stream
        .write_all(websocket_request("/ws/chat?room=main", "https://example.com").as_bytes())
        .await
        .unwrap();
    let response = read_until_headers(&mut stream).await;
    stream.write_all(b"hello").await.unwrap();
    let mut echoed = [0_u8; 10];
    stream.read_exact(&mut echoed).await.unwrap();
    server.abort();

    assert!(
        response.starts_with("HTTP/1.1 101 Switching Protocols"),
        "{response}"
    );
    assert_eq!(&echoed, b"echo:hello");
    let upstream_request = upstream.request_headers.lock().unwrap().to_lowercase();
    assert!(upstream_request.contains("upgrade: websocket"));
    assert!(upstream_request.contains("connection: upgrade"));
    assert!(upstream_request.contains("sec-websocket-key: dghlihnhbxbszsbub25jzq=="));
    assert!(upstream_request.contains("sec-websocket-version: 13"));
    let events = event_store::tail(&event_log_path, retention, 10).unwrap();
    assert_eq!(events[0].decision.action, WafAction::Allow);
    assert_eq!(events[0].upstream.as_ref().unwrap().name, "ws");
    assert_eq!(events[0].upstream.as_ref().unwrap().host, "ws.example.com");
    assert_eq!(events[0].websocket.as_ref().unwrap().outcome, "accepted");
    assert_eq!(
        events[0]
            .websocket
            .as_ref()
            .unwrap()
            .upstream_target
            .as_str(),
        format!("http://{}", upstream.addr)
    );
    assert_eq!(
        events[0].websocket.as_ref().unwrap().origin.as_deref(),
        Some("https://example.com")
    );
}

#[tokio::test]
async fn websocket_monitor_mode_records_attack_and_tunnels() {
    let upstream = spawn_raw_websocket_upstream().await;
    let event_log_path = test_event_log_path();
    let mut config = test_config(WafMode::Monitor, 120);
    config.server.listen = free_loopback_addr();
    config.upstreams[0].target = format!("http://{}", upstream.addr);
    config.logging.event_log_path = event_log_path.to_string_lossy().to_string();
    let listen = config.server.listen.clone();
    let retention = EventLogRetention {
        max_size_bytes: config.event_log_max_size_bytes().unwrap(),
        max_files: config.logging.event_log_max_files,
    };

    let server = tokio::spawn(saugra_waf::proxy::run(config));
    let mut stream = connect_with_retry(&listen).await;
    stream
        .write_all(websocket_request("/ws/chat?q=--", "https://example.com").as_bytes())
        .await
        .unwrap();
    let response = read_until_headers(&mut stream).await;
    stream.write_all(b"hello").await.unwrap();
    let mut echoed = [0_u8; 10];
    stream.read_exact(&mut echoed).await.unwrap();
    server.abort();

    assert!(
        response.starts_with("HTTP/1.1 101 Switching Protocols"),
        "{response}"
    );
    assert_eq!(&echoed, b"echo:hello");
    let events = event_store::tail(&event_log_path, retention, 10).unwrap();
    assert_eq!(events[0].decision.action, WafAction::Monitor);
    assert_eq!(events[0].websocket.as_ref().unwrap().outcome, "monitored");
    assert_eq!(
        events[0].decision.matched_rules[0].rule_id,
        "SAUGRA-SQLI-001"
    );
}

#[tokio::test]
async fn websocket_block_mode_blocks_disallowed_origin() {
    let fake_upstream = Arc::new(FakeUpstreamTransport::new());
    let event_log_path = test_event_log_path();
    let retention = test_retention();
    let mut config = test_config(WafMode::Block, 120);
    config.websocket.allowed_origins = vec!["https://example.com".to_string()];
    let state = ProxyState::with_transport(
        config,
        fake_upstream.clone(),
        Arc::new(MemoryRateLimitStore::new()),
        event_log_path.clone(),
        retention,
    )
    .unwrap();
    let request = websocket_axum_request("/ws/chat", "https://evil.example");

    let response = proxy_request(State(state), request).await.unwrap_err();
    let events = event_store::tail(&event_log_path, retention, 10).unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(fake_upstream.requests.lock().unwrap().is_empty());
    assert_eq!(events[0].decision.action, WafAction::Block);
    assert_eq!(
        events[0].decision.matched_rules[0].rule_id,
        "SAUGRA-WS-ORIGIN-001"
    );
    assert_eq!(events[0].websocket.as_ref().unwrap().outcome, "blocked");
}

#[tokio::test]
async fn websocket_rate_limit_blocks_handshake_before_forwarding() {
    let fake_upstream = Arc::new(FakeUpstreamTransport::new());
    let event_log_path = test_event_log_path();
    let retention = test_retention();
    let state = test_state_with_path(
        WafMode::Block,
        1,
        fake_upstream.clone(),
        event_log_path.clone(),
        retention,
    );

    let first = websocket_axum_request("/ws/chat", "https://example.com");
    let second = websocket_axum_request("/ws/chat", "https://example.com");
    let _ = proxy_request(State(state.clone()), first).await;
    let response = proxy_request(State(state), second).await.unwrap_err();
    let events = event_store::tail(&event_log_path, retention, 10).unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(fake_upstream.requests.lock().unwrap().is_empty());
    assert_eq!(events[1].decision.action, WafAction::Block);
    assert_eq!(
        events[1].decision.matched_rules[0].rule_id,
        "SAUGRA-RATE-001"
    );
    assert_eq!(
        events[1].websocket.as_ref().unwrap().outcome,
        "rate_limited"
    );
}

fn test_state(mode: WafMode, requests_per_minute: u32) -> ProxyState {
    test_state_with_transport(
        mode,
        requests_per_minute,
        Arc::new(FakeUpstreamTransport::new()),
    )
}

fn test_state_with_transport(
    mode: WafMode,
    requests_per_minute: u32,
    upstream_transport: Arc<dyn UpstreamTransport>,
) -> ProxyState {
    test_state_with_path(
        mode,
        requests_per_minute,
        upstream_transport,
        test_event_log_path(),
        test_retention(),
    )
}

fn test_state_with_path(
    mode: WafMode,
    requests_per_minute: u32,
    upstream_transport: Arc<dyn UpstreamTransport>,
    event_log_path: std::path::PathBuf,
    retention: EventLogRetention,
) -> ProxyState {
    ProxyState::with_transport(
        test_config(mode, requests_per_minute),
        upstream_transport,
        Arc::new(MemoryRateLimitStore::new()),
        event_log_path,
        retention,
    )
    .unwrap()
}

fn test_config(mode: WafMode, requests_per_minute: u32) -> SaugraConfig {
    SaugraConfig {
        server: ServerConfig {
            listen: "127.0.0.1:0".to_string(),
            mode,
        },
        upstreams: vec![UpstreamConfig {
            name: "app".to_string(),
            host: "example.com".to_string(),
            target: "http://127.0.0.1:1".to_string(),
        }],
        routes: Vec::new(),
        security: SecurityConfig {
            enable_rate_limiting: true,
            ..Default::default()
        },
        forwarded_headers: Default::default(),
        rate_limit: RateLimitConfig {
            backend: RateLimitBackend::Memory,
            redis_url: None,
            redis_password: None,
            requests_per_minute,
            burst: 0,
            routes: Vec::new(),
        },
        rules: RuleSettings::default(),
        behavior: BehaviorConfig {
            backend: BehaviorBackend::Memory,
            ..BehaviorConfig::default()
        },
        bot_protection: BotProtectionConfig {
            backend: BehaviorBackend::Memory,
            ..BotProtectionConfig::default()
        },
        runtime_policy: Default::default(),
        ai: AiConfig::default(),
        logging: LoggingConfig::default(),
        websocket: Default::default(),
        posture: Default::default(),
        reports: Default::default(),
        standards: Default::default(),
        security_summary: Default::default(),
        storage_cleanup: Default::default(),
    }
}

fn websocket_axum_request(path: &str, origin: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(path)
        .header(header::HOST, "example.com")
        .header(header::CONNECTION, "Upgrade")
        .header(header::UPGRADE, "websocket")
        .header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
        .header(header::SEC_WEBSOCKET_VERSION, "13")
        .header(header::ORIGIN, origin)
        .body(Body::empty())
        .unwrap()
}

fn websocket_request(path: &str, origin: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat\r\nOrigin: {origin}\r\nUser-Agent: saugra-waf-test\r\n\r\n"
    )
}

fn free_loopback_addr() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().to_string()
}

async fn connect_with_retry(addr: &str) -> TcpStream {
    for _ in 0..50 {
        if let Ok(stream) = TcpStream::connect(addr).await {
            return stream;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    TcpStream::connect(addr).await.unwrap()
}

async fn read_until_headers(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    timeout(Duration::from_secs(5), async {
        while !bytes.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            bytes.push(byte[0]);
        }
    })
    .await
    .unwrap();
    String::from_utf8(bytes).unwrap()
}

struct RawWebSocketUpstream {
    addr: SocketAddr,
    request_headers: Arc<Mutex<String>>,
}

async fn spawn_raw_websocket_upstream() -> RawWebSocketUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let request_headers = Arc::new(Mutex::new(String::new()));
    let request_headers_for_task = request_headers.clone();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        let mut byte = [0_u8; 1];
        while !bytes.ends_with(b"\r\n\r\n") {
            socket.read_exact(&mut byte).await.unwrap();
            bytes.push(byte[0]);
        }
        *request_headers_for_task.lock().unwrap() = String::from_utf8(bytes).unwrap();
        socket
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Protocol: chat\r\n\r\n",
            )
            .await
            .unwrap();
        let mut tunneled = [0_u8; 5];
        socket.read_exact(&mut tunneled).await.unwrap();
        socket.write_all(b"echo:hello").await.unwrap();
    });

    RawWebSocketUpstream {
        addr,
        request_headers,
    }
}

fn test_event_log_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("saugra-waf-test-{}.jsonl", Uuid::new_v4()))
}

fn test_retention() -> EventLogRetention {
    EventLogRetention {
        max_size_bytes: 1024 * 1024,
        max_files: 3,
    }
}

fn single_low_rule_file() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("saugra-waf-low-rule-{}.yml", Uuid::new_v4()));
    std::fs::write(
        &path,
        r#"
rules:
  - id: TEST-LOW-001
    name: Test Low Rule
    category: test
    severity: low
    targets:
      - query
    pattern: "low-risk"
    explanation: Low-risk test signal matched.
"#,
    )
    .unwrap();
    path
}

fn two_medium_rules_file() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("saugra-waf-medium-rules-{}.yml", Uuid::new_v4()));
    std::fs::write(
        &path,
        r#"
rules:
  - id: TEST-MEDIUM-001
    name: Test Medium Rule One
    category: test
    severity: medium
    targets:
      - query
    pattern: "medium-one"
    explanation: First medium-risk test signal matched.
  - id: TEST-MEDIUM-002
    name: Test Medium Rule Two
    category: test
    severity: medium
    targets:
      - query
    pattern: "medium-two"
    explanation: Second medium-risk test signal matched.
"#,
    )
    .unwrap();
    path
}

fn single_high_paranoia_rule_file() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("saugra-waf-pl2-rule-{}.yml", Uuid::new_v4()));
    std::fs::write(
        &path,
        r#"
rules:
  - id: TEST-PL2-001
    name: Test PL2 Rule
    category: test
    severity: high
    paranoia_level: 2
    targets:
      - query
    pattern: "pl2"
    explanation: Higher-paranoia test signal matched.
"#,
    )
    .unwrap();
    path
}

#[derive(Debug)]
struct RecordedUpstreamRequest {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Vec<u8>,
}

#[derive(Debug)]
struct FakeUpstreamTransport {
    requests: Mutex<Vec<RecordedUpstreamRequest>>,
}

impl FakeUpstreamTransport {
    fn new() -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl UpstreamTransport for FakeUpstreamTransport {
    async fn request(&self, request: Request<Body>) -> anyhow::Result<Response<Body>> {
        let (parts, body) = request.into_parts();
        let body = to_bytes(body, 1024 * 1024).await?;

        self.requests.lock().unwrap().push(RecordedUpstreamRequest {
            method: parts.method,
            uri: parts.uri,
            headers: parts.headers,
            body: body.to_vec(),
        });

        Response::builder()
            .status(StatusCode::OK)
            .header("x-upstream-test", "ok")
            .body(Body::from("upstream-ok"))
            .context("failed to build fake upstream response")
    }
}
