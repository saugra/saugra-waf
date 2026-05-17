use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::Context;
use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{
        header::{self, HeaderName},
        HeaderMap, Method, Request, Response, StatusCode, Uri,
    },
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use serde_json::json;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    ai,
    config::{RouteRateLimitConfig, SaugraConfig, UpstreamConfig, WafMode},
    decision::{WafAction, WafDecision},
    event_store::{self, EventLogRetention, SecurityEvent},
    rate_limit::{self, RateLimitExceeded, RateLimitPolicy, RateLimitStore},
    rules::{self, RequestParts, RuleMatch, RuleSet, RuleSeverity, RuleTarget},
};

#[derive(Clone)]
pub struct ProxyState {
    config: SaugraConfig,
    upstream_transport: Arc<dyn UpstreamTransport>,
    upstream: UpstreamConfig,
    max_body_size_bytes: usize,
    rate_limit_store: Arc<dyn RateLimitStore>,
    event_log_path: PathBuf,
    event_log_retention: EventLogRetention,
    rule_set: Arc<RuleSet>,
}

impl ProxyState {
    pub fn with_transport(
        config: SaugraConfig,
        upstream_transport: Arc<dyn UpstreamTransport>,
        rate_limit_store: Arc<dyn RateLimitStore>,
        event_log_path: PathBuf,
        event_log_retention: EventLogRetention,
    ) -> anyhow::Result<Self> {
        let upstream = config
            .upstreams
            .first()
            .context("config validation should require at least one upstream")?
            .clone();
        let max_body_size_bytes = config
            .max_body_size_bytes()?
            .try_into()
            .context("security.max_body_size is too large for this platform")?;
        let rule_set = Arc::new(rules::load_rule_set(&config.rules)?);

        Ok(Self {
            config,
            upstream_transport,
            upstream,
            max_body_size_bytes,
            rate_limit_store,
            event_log_path,
            event_log_retention,
            rule_set,
        })
    }
}

#[async_trait]
pub trait UpstreamTransport: Send + Sync {
    async fn request(&self, request: Request<Body>) -> anyhow::Result<Response<Body>>;
}

struct HyperUpstreamTransport {
    client: Client<HttpConnector, Body>,
}

#[async_trait]
impl UpstreamTransport for HyperUpstreamTransport {
    async fn request(&self, request: Request<Body>) -> anyhow::Result<Response<Body>> {
        self.client
            .request(request)
            .await
            .map(|response| response.map(Body::new))
            .context("upstream request failed")
    }
}

pub async fn run(config: SaugraConfig) -> anyhow::Result<()> {
    let listen_addr = config.listen_addr()?;
    let upstream = config
        .upstreams
        .first()
        .context("config validation should require at least one upstream")?;
    let max_body_size_bytes = config.max_body_size_bytes()?;

    info!(
        listen = %listen_addr,
        mode = ?config.server.mode,
        upstream = %upstream.target,
        upstream_host = %upstream.host,
        max_body_size = %config.security.max_body_size,
        max_body_size_bytes,
        rate_limiting = config.security.enable_rate_limiting,
        block_suspicious_user_agents = config.security.block_suspicious_user_agents,
        inspect_json_body = config.security.inspect_json_body,
        "starting Saugra service"
    );

    let rate_limit_store = rate_limit::build_store(&config.rate_limit).await?;
    let event_log_path = PathBuf::from(&config.logging.event_log_path);
    let event_log_retention = EventLogRetention {
        max_size_bytes: config.event_log_max_size_bytes()?,
        max_files: config.logging.event_log_max_files,
    };
    let state = ProxyState::with_transport(
        config,
        Arc::new(HyperUpstreamTransport {
            client: Client::builder(TokioExecutor::new()).build(HttpConnector::new()),
        }),
        rate_limit_store,
        event_log_path,
        event_log_retention,
    )?;

    let app = Router::new()
        .route("/_saugra/health", get(health))
        .fallback(proxy_request)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    info!("Saugra listening on http://{}", listen_addr);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "service": "saugra"
    }))
}

pub async fn proxy_request(
    State(state): State<ProxyState>,
    request: Request<Body>,
) -> Result<Response<Body>, Response<Body>> {
    let request_id = Uuid::new_v4().to_string();
    let (parts, body) = request.into_parts();

    if state.config.security.enable_rate_limiting {
        let client_id = client_id_from_headers(&parts.headers);
        let rate_limit = select_rate_limit(&state.config, parts.uri.path(), &client_id);
        let rate_limit_result = state
            .rate_limit_store
            .check(&rate_limit.key, &client_id, rate_limit.policy)
            .await
            .map_err(|error| {
                error!(request_id, %error, "rate-limit backend failed");
                json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    json!({
                        "request_id": request_id,
                        "error": "rate-limit backend unavailable"
                    }),
                )
            })?;

        if let Some(exceeded) = rate_limit_result {
            let decision = WafDecision::from_matches(
                request_id.clone(),
                WafMode::Strict,
                vec![rate_limit_match(&exceeded)],
                state.config.rules.inbound_anomaly_threshold,
            );
            log_decision(
                &parts.method,
                parts.uri.path(),
                parts.uri.query().unwrap_or_default(),
                &decision,
            );
            record_event(
                &state,
                parts.method.as_str(),
                parts.uri.path(),
                parts.uri.query().unwrap_or_default(),
                &decision,
            );

            if decision.action == WafAction::Block {
                return Err(rate_limit_response(&decision, exceeded.retry_after_seconds));
            }
        }
    }

    let body_bytes = to_bytes(body, state.max_body_size_bytes)
        .await
        .map_err(|error| {
            warn!(request_id, %error, "request body exceeded configured inspection limit");
            json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                json!({
                    "request_id": request_id,
                    "error": "request body exceeds configured max_body_size"
                }),
            )
        })?;

    let path = parts.uri.path().to_string();
    let query = parts.uri.query().unwrap_or_default().to_string();
    let headers = normalize_headers(&parts.headers);
    let user_agent = parts
        .headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let body_for_rules = String::from_utf8_lossy(&body_bytes);

    let request_parts = RequestParts {
        path: &path,
        query: &query,
        headers: &headers,
        body: &body_for_rules,
        user_agent: &user_agent,
    };
    let matches = state
        .rule_set
        .inspect_with_exclusions(&request_parts, &state.config.rules.exclusions);
    let decision = WafDecision::from_matches(
        request_id.clone(),
        state.config.server.mode,
        matches,
        state.config.rules.inbound_anomaly_threshold,
    );

    log_decision(&parts.method, &path, &query, &decision);
    record_event(&state, parts.method.as_str(), &path, &query, &decision);

    if decision.action == WafAction::Block {
        return Err(json_response(
            StatusCode::FORBIDDEN,
            json!({
                "request_id": request_id,
                "action": "block",
                "risk_score": decision.risk_score,
                "matched_rules": decision.matched_rules,
                "explanation": ai::explain(&decision)
            }),
        ));
    }

    let upstream_uri = build_upstream_uri(&state.upstream.target, &parts.uri).map_err(|error| {
        error!(request_id, %error, "failed to build upstream request URI");
        json_response(
            StatusCode::BAD_GATEWAY,
            json!({
                "request_id": request_id,
                "error": "invalid upstream target"
            }),
        )
    })?;

    let mut upstream_request = Request::builder()
        .method(parts.method)
        .uri(upstream_uri)
        .body(Body::from(body_bytes))
        .map_err(|error| {
            error!(request_id, %error, "failed to build upstream request");
            json_response(
                StatusCode::BAD_GATEWAY,
                json!({
                    "request_id": request_id,
                    "error": "failed to build upstream request"
                }),
            )
        })?;

    copy_forward_headers(
        &parts.headers,
        upstream_request.headers_mut(),
        &state.upstream.host,
        &request_id,
    );

    state
        .upstream_transport
        .request(upstream_request)
        .await
        .map_err(|error| {
            error!(request_id, %error, "upstream request failed");
            json_response(
                StatusCode::BAD_GATEWAY,
                json!({
                    "request_id": request_id,
                    "error": "upstream request failed"
                }),
            )
        })
}

fn build_upstream_uri(
    upstream_target: &str,
    original_uri: &Uri,
) -> Result<Uri, axum::http::uri::InvalidUri> {
    let base = upstream_target.trim_end_matches('/');
    let path_and_query = original_uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");

    format!("{base}{path_and_query}").parse()
}

fn copy_forward_headers(
    original: &HeaderMap,
    forwarded: &mut HeaderMap,
    upstream_host: &str,
    request_id: &str,
) {
    for (name, value) in original {
        if is_hop_by_hop_header(name) || name == header::HOST {
            continue;
        }
        forwarded.insert(name, value.clone());
    }

    match upstream_host.parse() {
        Ok(value) => {
            forwarded.insert(header::HOST, value);
        }
        Err(error) => {
            warn!(request_id, upstream_host, %error, "upstream host is not a valid header value");
        }
    }

    if let Ok(value) = request_id.parse() {
        forwarded.insert("x-saugra-request-id", value);
    }
}

fn client_id_from_headers(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .unwrap_or("unknown")
        .to_string()
}

struct SelectedRateLimit {
    key: String,
    policy: RateLimitPolicy,
}

fn select_rate_limit(config: &SaugraConfig, path: &str, client_id: &str) -> SelectedRateLimit {
    if let Some(route) = matching_rate_limit_route(&config.rate_limit.routes, path) {
        return SelectedRateLimit {
            key: format!("route:{}:{client_id}", route.path),
            policy: RateLimitPolicy {
                requests_per_minute: route.requests_per_minute,
                burst: route.burst,
            },
        };
    }

    SelectedRateLimit {
        key: format!("global:{client_id}"),
        policy: RateLimitPolicy {
            requests_per_minute: config.rate_limit.requests_per_minute,
            burst: config.rate_limit.burst,
        },
    }
}

fn matching_rate_limit_route<'a>(
    routes: &'a [RouteRateLimitConfig],
    path: &str,
) -> Option<&'a RouteRateLimitConfig> {
    routes
        .iter()
        .filter(|route| path_matches_route(path, &route.path))
        .max_by_key(|route| route.path.len())
}

fn path_matches_route(path: &str, route_path: &str) -> bool {
    let route_path = route_path.trim_end_matches('/');

    if route_path.is_empty() {
        return true;
    }

    path == route_path
        || path
            .strip_prefix(route_path)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn rate_limit_match(exceeded: &RateLimitExceeded) -> RuleMatch {
    RuleMatch {
        rule_id: "SAUGRA-RATE-001".to_string(),
        rule_name: "Per-Client Request Rate Limit".to_string(),
        category: "rate_limit_abuse".to_string(),
        severity: RuleSeverity::Medium,
        matched_target: RuleTarget::Headers,
        explanation: format!(
            "Client exceeded the configured rate limit of {} requests per minute with a burst of {}.",
            exceeded.limit, exceeded.burst
        ),
        owasp_category: Some("A06:2025-Insecure Design".to_string()),
    }
}

fn is_hop_by_hop_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn normalize_headers(headers: &HeaderMap) -> String {
    headers
        .iter()
        .map(|(name, value)| {
            let value = if is_sensitive_header(name) {
                "[masked]".to_string()
            } else {
                value.to_str().unwrap_or("[non-utf8]").to_string()
            };
            format!("{name}: {value}")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn is_sensitive_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "authorization" | "cookie" | "set-cookie" | "x-api-key" | "x-auth-token"
    )
}

fn log_decision(method: &Method, path: &str, query: &str, decision: &WafDecision) {
    info!(
        request_id = %decision.request_id,
        action = ?decision.action,
        risk_score = decision.risk_score,
        severity = %decision.severity,
        matched_rules = decision.matched_rules.len(),
        %method,
        path,
        query,
        explanation = %decision.explanation,
        "waf decision"
    );
}

fn record_event(state: &ProxyState, method: &str, path: &str, query: &str, decision: &WafDecision) {
    let event = SecurityEvent::new(method, path, query, decision.clone());

    if let Err(error) =
        event_store::append(&state.event_log_path, state.event_log_retention, &event)
    {
        warn!(
            request_id = %decision.request_id,
            path = %state.event_log_path.display(),
            %error,
            "failed to write security event"
        );
    }
}

fn json_response(status: StatusCode, body: serde_json::Value) -> Response<Body> {
    (status, Json(body)).into_response()
}

fn rate_limit_response(decision: &WafDecision, retry_after_seconds: u64) -> Response<Body> {
    let mut response = json_response(
        StatusCode::TOO_MANY_REQUESTS,
        json!({
            "request_id": decision.request_id,
            "action": "block",
            "risk_score": decision.risk_score,
            "matched_rules": decision.matched_rules,
            "explanation": ai::explain(decision),
            "retry_after_seconds": retry_after_seconds
        }),
    );

    if let Ok(value) = retry_after_seconds.to_string().parse() {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }

    response
}

#[allow(dead_code)]
fn _assert_socket_addr(_: SocketAddr) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RouteRateLimitConfig, ServerConfig, WafMode};

    #[test]
    fn builds_upstream_uri_with_path_and_query() {
        let original_uri = "/search?q=test".parse().unwrap();

        let upstream_uri = build_upstream_uri("http://127.0.0.1:8000/", &original_uri).unwrap();

        assert_eq!(upstream_uri, "http://127.0.0.1:8000/search?q=test");
    }

    #[test]
    fn masks_sensitive_headers_for_rule_input() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer secret".parse().unwrap());
        headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());

        let normalized = normalize_headers(&headers);

        assert!(normalized.contains("authorization: [masked]"));
        assert!(normalized.contains("content-type: application/json"));
        assert!(!normalized.contains("secret"));
    }

    #[test]
    fn extracts_client_id_from_forwarded_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.10, 10.0.0.1".parse().unwrap());

        assert_eq!(client_id_from_headers(&headers), "203.0.113.10");
    }

    #[test]
    fn selects_longest_matching_route_rate_limit() {
        let mut config = test_config(WafMode::Block, 120);
        config.rate_limit.routes = vec![
            RouteRateLimitConfig {
                path: "/sensitive".to_string(),
                requests_per_minute: 60,
                burst: 10,
            },
            RouteRateLimitConfig {
                path: "/sensitive/action".to_string(),
                requests_per_minute: 5,
                burst: 2,
            },
        ];

        let selected = select_rate_limit(&config, "/sensitive/action/confirm", "203.0.113.10");

        assert_eq!(selected.key, "route:/sensitive/action:203.0.113.10");
        assert_eq!(selected.policy.requests_per_minute, 5);
        assert_eq!(selected.policy.burst, 2);
    }

    #[test]
    fn selects_global_rate_limit_when_no_route_matches() {
        let mut config = test_config(WafMode::Block, 120);
        config.rate_limit.burst = 30;
        config.rate_limit.routes = vec![RouteRateLimitConfig {
            path: "/sensitive-action".to_string(),
            requests_per_minute: 10,
            burst: 5,
        }];

        let selected = select_rate_limit(&config, "/health", "203.0.113.10");

        assert_eq!(selected.key, "global:203.0.113.10");
        assert_eq!(selected.policy.requests_per_minute, 120);
        assert_eq!(selected.policy.burst, 30);
    }

    #[test]
    fn route_rate_limit_matching_respects_path_boundaries() {
        assert!(path_matches_route("/sensitive/action", "/sensitive"));
        assert!(path_matches_route("/sensitive", "/sensitive"));
        assert!(!path_matches_route("/sensitive-area", "/sensitive"));
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
            security: crate::config::SecurityConfig {
                enable_rate_limiting: true,
                ..Default::default()
            },
            rate_limit: crate::config::RateLimitConfig {
                backend: crate::config::RateLimitBackend::Memory,
                redis_url: None,
                redis_password: None,
                requests_per_minute,
                burst: 0,
                routes: Vec::new(),
            },
            rules: Default::default(),
            ai: Default::default(),
            logging: Default::default(),
            posture: Default::default(),
            standards: Default::default(),
        }
    }
}
