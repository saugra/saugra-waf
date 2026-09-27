#![allow(dead_code)]

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Context;
use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{header, HeaderMap, Method, Request, Response, StatusCode, Uri},
};
use saugra_waf::{
    config::{
        AiConfig, BehaviorBackend, BehaviorConfig, BotProtectionConfig, LoggingConfig,
        ProxyRouteConfig, RateLimitBackend, RateLimitConfig, RuleSettings, SaugraConfig,
        SecurityConfig, ServerConfig, UpstreamConfig, WafMode,
    },
    event_store::EventLogRetention,
    proxy::{ProxyState, UpstreamTransport},
    rate_limit::MemoryRateLimitStore,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use uuid::Uuid;

pub fn test_state(mode: WafMode, requests_per_minute: u32) -> ProxyState {
    test_state_with_transport(
        mode,
        requests_per_minute,
        Arc::new(FakeUpstreamTransport::new()),
    )
}

pub fn test_state_with_transport(
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

pub fn test_state_with_path(
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

pub fn test_config(mode: WafMode, requests_per_minute: u32) -> SaugraConfig {
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
        unknown_threats: Default::default(),
        campaign_correlation: Default::default(),
        bot_protection: BotProtectionConfig {
            backend: BehaviorBackend::Memory,
            ..BotProtectionConfig::default()
        },
        runtime_policy: Default::default(),
        ai: AiConfig::default(),
        logging: LoggingConfig::default(),
        console: Default::default(),
        websocket: Default::default(),
        posture: Default::default(),
        reports: Default::default(),
        standards: Default::default(),
        security_summary: Default::default(),
        storage_cleanup: Default::default(),
    }
}

pub fn websocket_axum_request(path: &str, origin: &str) -> Request<Body> {
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

pub fn websocket_request(path: &str, origin: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat\r\nOrigin: {origin}\r\nUser-Agent: saugra-waf-test\r\n\r\n"
    )
}

pub fn free_loopback_addr() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().to_string()
}

pub async fn connect_with_retry(addr: &str) -> TcpStream {
    for _ in 0..50 {
        if let Ok(stream) = TcpStream::connect(addr).await {
            return stream;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    TcpStream::connect(addr).await.unwrap()
}

pub async fn read_until_headers(stream: &mut TcpStream) -> String {
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

pub struct RawWebSocketUpstream {
    pub addr: SocketAddr,
    pub request_headers: Arc<Mutex<String>>,
}

pub async fn spawn_raw_websocket_upstream() -> RawWebSocketUpstream {
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

pub fn test_event_log_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("saugra-waf-test-{}.jsonl", Uuid::new_v4()))
}

pub fn test_retention() -> EventLogRetention {
    EventLogRetention {
        max_size_bytes: 1024 * 1024,
        max_files: 3,
    }
}

pub fn single_low_rule_file() -> std::path::PathBuf {
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

pub fn two_medium_rules_file() -> std::path::PathBuf {
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

pub fn single_high_paranoia_rule_file() -> std::path::PathBuf {
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
pub struct RecordedUpstreamRequest {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub struct FakeUpstreamTransport {
    pub requests: Mutex<Vec<RecordedUpstreamRequest>>,
}

impl FakeUpstreamTransport {
    pub fn new() -> Self {
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
