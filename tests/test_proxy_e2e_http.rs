mod common;

use std::sync::Arc;

use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{header, Method, Request, StatusCode},
};
use saugra_waf::{
    config::{ProxyRouteConfig, UpstreamConfig, WafMode},
    decision::WafAction,
    event_store,
    proxy::{proxy_request, ProxyState},
    rate_limit::MemoryRateLimitStore,
};

use common::*;

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
