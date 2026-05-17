use std::sync::{Arc, Mutex};

use anyhow::Context;
use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{header, HeaderMap, Method, Request, Response, StatusCode, Uri},
};
use saugra::{
    config::{
        AiConfig, LoggingConfig, RateLimitBackend, RateLimitConfig, RuleExclusionConfig,
        RuleSettings, SaugraConfig, SecurityConfig, ServerConfig, UpstreamConfig, WafMode,
    },
    decision::WafAction,
    event_store::{self, EventLogRetention},
    proxy::{proxy_request, ProxyState, UpstreamTransport},
    rate_limit::MemoryRateLimitStore,
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
        .body(Body::empty())
        .unwrap();

    let response = proxy_request(State(state), request).await.unwrap();
    let events = event_store::tail(&event_log_path, retention, 10).unwrap();
    let recorded = fake_upstream.requests.lock().unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(recorded.len(), 1);
    assert_eq!(events.len(), 1);
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
    assert_eq!(json["action"], "block");
    assert_eq!(json["risk_score"], 80);
    assert_eq!(json["matched_rules"][0]["rule_id"], "SAUGRA-SQLI-001");
    assert!(json["request_id"].as_str().is_some());
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
    let events = event_store::tail(&event_log_path, retention, 10).unwrap();
    let recorded = fake_upstream.requests.lock().unwrap();

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(recorded.len(), 1);
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].decision.action, WafAction::Block);
    assert_eq!(
        events[1].decision.matched_rules[0].rule_id,
        "SAUGRA-RATE-001"
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
        security: SecurityConfig {
            enable_rate_limiting: true,
            ..Default::default()
        },
        rate_limit: RateLimitConfig {
            backend: RateLimitBackend::Memory,
            redis_url: None,
            redis_password: None,
            requests_per_minute,
            burst: 0,
            routes: Vec::new(),
        },
        rules: RuleSettings::default(),
        ai: AiConfig::default(),
        logging: LoggingConfig::default(),
    }
}

fn test_event_log_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("saugra-test-{}.jsonl", Uuid::new_v4()))
}

fn test_retention() -> EventLogRetention {
    EventLogRetention {
        max_size_bytes: 1024 * 1024,
        max_files: 3,
    }
}

fn single_low_rule_file() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("saugra-low-rule-{}.yml", Uuid::new_v4()));
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
    let path = std::env::temp_dir().join(format!("saugra-medium-rules-{}.yml", Uuid::new_v4()));
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
