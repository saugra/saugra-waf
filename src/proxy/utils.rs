use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::{
    body::Body,
    http::{
        header::{self, HeaderName},
        HeaderMap, Method, Response, StatusCode, Uri,
    },
    response::{IntoResponse, Json},
};
use serde_json::json;
use tracing::info;

use crate::{
    config::{ForwardedHeadersConfig, SaugraConfig, UpstreamConfig},
    decision::WafDecision,
    event_store::{RequestEvidence, SecurityEvent, UpstreamEvent, WebSocketEvent},
    rate_limit::RateLimitPolicy,
    rules::{RuleMatch, RuleSeverity, RuleTarget},
};

use super::ProxyState;

pub fn build_upstream_uri(target: &str, uri: &Uri) -> anyhow::Result<Uri> {
    let mut base = target.trim_end_matches('/').to_string();
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(uri.path());

    if !path_and_query.starts_with('/') {
        base.push('/');
    }
    base.push_str(path_and_query);
    base.parse().map_err(Into::into)
}

pub fn normalize_headers(headers: &HeaderMap) -> String {
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

pub fn is_sensitive_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "authorization" | "cookie" | "set-cookie" | "x-api-key" | "x-auth-token"
    )
}

pub fn client_id_from_headers(
    headers: &HeaderMap,
    forwarded_headers: &ForwardedHeadersConfig,
    trusted_forwarded_headers: bool,
) -> String {
    if forwarded_headers.enabled && trusted_forwarded_headers {
        if let Some(client_ip) = configured_header_value(headers, &forwarded_headers.real_ip_header)
            .and_then(|value| value.split(',').next())
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return client_ip.to_string();
        }
    }

    headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_string()
}

fn configured_header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.iter().find_map(|(header_name, value)| {
        if header_name.as_str().eq_ignore_ascii_case(name.trim()) {
            value.to_str().ok()
        } else {
            None
        }
    })
}

pub fn forwarded_headers_are_trusted(
    peer_addr: Option<SocketAddr>,
    config: &ForwardedHeadersConfig,
    trust_when_peer_unavailable: bool,
) -> bool {
    if !config.enabled {
        return false;
    }

    let Some(peer_addr) = peer_addr else {
        return trust_when_peer_unavailable;
    };

    config
        .trusted_proxies
        .iter()
        .any(|entry| ip_matches_proxy_entry(peer_addr.ip(), entry))
}

fn ip_matches_proxy_entry(ip: IpAddr, entry: &str) -> bool {
    let entry = entry.trim();
    if entry.eq_ignore_ascii_case("any") {
        return true;
    }

    if let Ok(entry_ip) = entry.parse::<IpAddr>() {
        return entry_ip == ip;
    }

    let IpAddr::V4(ip) = ip else {
        return false;
    };

    ipv4_cidr_contains(entry, ip)
}

fn ipv4_cidr_contains(cidr: &str, ip: Ipv4Addr) -> bool {
    let Some((network, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u32>() else {
        return false;
    };
    if prefix > 32 {
        return false;
    }
    let Ok(network) = network.parse::<Ipv4Addr>() else {
        return false;
    };

    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(network) & mask) == (u32::from(ip) & mask)
}

pub struct SelectedRateLimit {
    pub key: String,
    pub policy: RateLimitPolicy,
}

pub fn select_rate_limit(config: &SaugraConfig, path: &str, client_id: &str) -> SelectedRateLimit {
    if let Some(route) = config
        .rate_limit
        .routes
        .iter()
        .filter(|route| path_matches_route(path, &route.path))
        .max_by_key(|route| route.path.trim_end_matches('/').len())
    {
        SelectedRateLimit {
            key: format!("route:{}:{}", route.path, client_id),
            policy: RateLimitPolicy {
                requests_per_minute: route.requests_per_minute,
                burst: route.burst,
            },
        }
    } else {
        SelectedRateLimit {
            key: format!("global:{}", client_id),
            policy: RateLimitPolicy {
                requests_per_minute: config.rate_limit.requests_per_minute,
                burst: config.rate_limit.burst,
            },
        }
    }
}

pub fn path_matches_route(path: &str, route_path: &str) -> bool {
    let route_path = route_path.trim().trim_end_matches('/');
    if route_path.is_empty() {
        return true;
    }

    path == route_path
        || path
            .strip_prefix(route_path)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

pub fn is_hop_by_hop_header(name: &HeaderName) -> bool {
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

pub fn is_websocket_hop_header(name: &HeaderName) -> bool {
    matches!(name.as_str(), "connection" | "upgrade")
}

pub fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    let connection_has_upgrade = headers
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("upgrade"))
        .unwrap_or(false);

    let upgrade_is_websocket = headers
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    connection_has_upgrade && upgrade_is_websocket
}

pub fn websocket_policy_matches(state: &ProxyState, headers: &HeaderMap) -> Vec<RuleMatch> {
    let mut matches = Vec::new();

    if !state.config.websocket.enabled {
        matches.push(RuleMatch {
            rule_id: "SAUGRA-WS-000".to_string(),
            rule_name: "WebSocket Proxying Disabled".to_string(),
            category: "websocket_policy".to_string(),
            severity: RuleSeverity::High,
            matched_target: RuleTarget::Headers,
            paranoia_level: 1,
            explanation: "WebSocket upgrade request was received while websocket.enabled is false."
                .to_string(),
            owasp_category: Some("A06:2025-Insecure Design".to_string()),
        });
    }

    if !state.config.websocket.allowed_origins.is_empty() {
        let origin = headers
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if !state
            .config
            .websocket
            .allowed_origins
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(origin))
        {
            matches.push(RuleMatch {
                rule_id: "SAUGRA-WS-ORIGIN-001".to_string(),
                rule_name: "WebSocket Origin Not Allowed".to_string(),
                category: "websocket_origin_policy".to_string(),
                severity: RuleSeverity::High,
                matched_target: RuleTarget::Headers,
                paranoia_level: 1,
                explanation:
                    "WebSocket handshake Origin header did not match configured allowed origins."
                        .to_string(),
                owasp_category: Some("A01:2025-Broken Access Control".to_string()),
            });
        }
    }

    if !state.config.websocket.allowed_hosts.is_empty() {
        let host = headers
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if !state
            .config
            .websocket
            .allowed_hosts
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(host))
        {
            matches.push(RuleMatch {
                rule_id: "SAUGRA-WS-HOST-001".to_string(),
                rule_name: "WebSocket Host Not Allowed".to_string(),
                category: "websocket_host_policy".to_string(),
                severity: RuleSeverity::High,
                matched_target: RuleTarget::Headers,
                paranoia_level: 1,
                explanation:
                    "WebSocket handshake Host header did not match configured allowed hosts."
                        .to_string(),
                owasp_category: Some("A05:2025-Security Misconfiguration".to_string()),
            });
        }
    }

    matches
}

pub fn websocket_event(
    upstream: &UpstreamConfig,
    headers: &HeaderMap,
    outcome: &str,
) -> Option<WebSocketEvent> {
    if !is_websocket_upgrade(headers) {
        return None;
    }

    Some(WebSocketEvent {
        upgrade: true,
        upstream_target: upstream.target.clone(),
        outcome: outcome.to_string(),
        origin: header_string(headers, header::ORIGIN),
        host: header_string(headers, header::HOST),
        protocol: header_string(headers, header::SEC_WEBSOCKET_PROTOCOL),
    })
}

pub fn header_string(headers: &HeaderMap, name: HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
}

pub fn runtime_blocklist_match(
    runtime_match: &crate::runtime_policy::RuntimeAllowlistMatch,
) -> RuleMatch {
    RuleMatch {
        rule_id: "SAUGRA-RUNTIME-BLOCKLIST-001".to_string(),
        rule_name: "Runtime Policy Blocklist".to_string(),
        category: "runtime_policy".to_string(),
        severity: RuleSeverity::High,
        matched_target: RuleTarget::Headers,
        paranoia_level: 1,
        explanation: format!(
            "Client matched runtime blocklist entry {} for {}. Reason: {}.",
            runtime_match.id, runtime_match.value, runtime_match.reason
        ),
        owasp_category: Some("A06:2025-Insecure Design".to_string()),
    }
}

pub fn effective_rule_exclusions(state: &ProxyState) -> Vec<crate::config::RuleExclusionConfig> {
    let mut exclusions = state.config.rules.exclusions.clone();
    exclusions.extend(state.managed_policy.exclusions());
    exclusions
}

pub fn log_decision(
    method: &Method,
    path: &str,
    query: &str,
    client_ip: &str,
    decision: &WafDecision,
    upstream: &UpstreamConfig,
    websocket_upgrade: bool,
) {
    info!(
        request_id = %decision.request_id,
        client_ip,
        action = ?decision.action,
        risk_score = decision.risk_score,
        behavior_score = decision.behavior.as_ref().map(|behavior| behavior.score).unwrap_or(0),
        behavior_action = ?decision.behavior.as_ref().map(|behavior| behavior.action),
        unknown_threat_score = decision.unknown_threats.as_ref().map(|outcome| outcome.score).unwrap_or(0),
        unknown_threat_action = ?decision.unknown_threats.as_ref().map(|outcome| outcome.action),
        unknown_threat_would_block = decision.unknown_threats.as_ref().map(|outcome| outcome.would_block).unwrap_or(false),
        unknown_threat_block_eligible = decision.unknown_threats.as_ref().map(|outcome| outcome.block_eligible).unwrap_or(false),
        unknown_threat_signals = decision.unknown_threats.as_ref().map(|outcome| outcome.signals.len()).unwrap_or(0),
        unknown_threat_baseline_age_seconds = decision.unknown_threats.as_ref().map(|outcome| outcome.baseline_age_seconds).unwrap_or(0),
        unknown_threat_route_excluded = decision.unknown_threats.as_ref().map(|outcome| outcome.route_excluded).unwrap_or(false),
        unknown_threat_capacity_reached = decision.unknown_threats.as_ref().map(|outcome| outcome.capacity_reached).unwrap_or(false),
        unknown_threat_pruned_routes = decision.unknown_threats.as_ref().map(|outcome| outcome.pruned_routes).unwrap_or(0),
        campaign_ids = %decision.campaign.as_ref().map(|outcome| outcome.campaign_ids.join(",")).unwrap_or_default(),
        campaign_matches = decision.campaign.as_ref().map(|outcome| outcome.matches.len()).unwrap_or(0),
        bot_protection_score = decision.bot_protection.as_ref().map(|bot| bot.score).unwrap_or(0),
        bot_protection_action = ?decision.bot_protection.as_ref().map(|bot| bot.action),
        severity = %decision.severity,
        matched_rules = decision.matched_rules.len(),
        owasp_category = decision.owasp_category.as_deref().unwrap_or("none"),
        owasp_categories = %decision.owasp_categories.join(","),
        %method,
        path,
        query,
        upstream_name = %upstream.name,
        upstream_host = %upstream.host,
        upstream_target = %upstream.target,
        websocket_upgrade,
        explanation = %decision.explanation,
        "waf decision"
    );
}

pub struct EventRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub client_ip: &'a str,
    pub evidence: RequestEvidence,
}

pub fn record_event(
    state: &ProxyState,
    request: EventRequest<'_>,
    decision: &WafDecision,
    upstream: &UpstreamConfig,
    websocket: Option<WebSocketEvent>,
) {
    let mut event = SecurityEvent::new_with_timezone(
        request.method,
        request.path,
        request.query,
        decision.clone(),
        request.client_ip,
        &state.config.logging.timezone,
    )
    .with_evidence(request.evidence);
    event = event.with_upstream(UpstreamEvent {
        name: upstream.name.clone(),
        host: upstream.host.clone(),
        target: upstream.target.clone(),
    });
    if let Some(websocket) = websocket {
        event = event.with_websocket(websocket);
    }

    if let Err(error) =
        crate::event_store::append(&state.event_log_path, state.event_log_retention, &event)
    {
        tracing::warn!(
            request_id = %decision.request_id,
            path = %state.event_log_path.display(),
            %error,
            "failed to write security event"
        );
    }
    if let Some(outbox) = &state.console_outbox {
        if let Err(error) = outbox.append(&event) {
            tracing::warn!(request_id = %decision.request_id, %error, "failed to persist event to Console outbox");
        }
    }
}

pub fn request_evidence(query: &str, headers: &HeaderMap, body_size: usize) -> RequestEvidence {
    let mut query_parameter_names = query
        .split('&')
        .filter_map(|pair| {
            let name = pair.split_once('=').map(|(name, _)| name).unwrap_or(pair);
            (!name.is_empty()).then(|| {
                percent_encoding::percent_decode_str(name)
                    .decode_utf8_lossy()
                    .into_owned()
            })
        })
        .collect::<Vec<_>>();
    query_parameter_names.sort();
    query_parameter_names.dedup();

    let mut header_names = headers
        .keys()
        .map(|name| name.as_str().to_ascii_lowercase())
        .collect::<Vec<_>>();
    header_names.sort();
    header_names.dedup();

    RequestEvidence {
        content_type: headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase(),
        body_size,
        query_parameter_names,
        header_names,
    }
}

pub fn json_response(status: StatusCode, body: serde_json::Value) -> Response<Body> {
    (status, Json(body)).into_response()
}

pub fn blocked_response(decision: &WafDecision) -> Response<Body> {
    json_response(
        StatusCode::FORBIDDEN,
        json!({
            "message": "Denied",
            "reference": &decision.request_id
        }),
    )
}
