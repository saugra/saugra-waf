mod common;

use std::sync::Arc;

use axum::{extract::State, http::StatusCode};
use saugra_waf::{
    config::{ProxyRouteConfig, UpstreamConfig, WafMode},
    decision::WafAction,
    event_store::{self, EventLogRetention},
    proxy::{proxy_request, ProxyState},
    rate_limit::MemoryRateLimitStore,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use common::*;

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
    config.logging.event_log_path = event_log_path.clone();
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
    config.logging.event_log_path = event_log_path.clone();
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
