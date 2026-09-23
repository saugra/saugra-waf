use std::{net::SocketAddr, sync::atomic::Ordering};

use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, State},
    http::{header, Request, Response, StatusCode},
};
use hyper::upgrade::OnUpgrade;
use serde_json::json;
use tracing::{error, warn};
use uuid::Uuid;

use crate::{
    campaign,
    decision::{WafAction, WafDecision},
    rules::RequestParts,
};

use super::{
    super::{
        utils::{
            blocked_response, build_upstream_uri, client_id_from_headers,
            effective_rule_exclusions, forwarded_headers_are_trusted, is_websocket_upgrade,
            json_response, log_decision, normalize_headers, record_event, request_evidence,
            select_rate_limit, websocket_event, EventRequest,
        },
        ProxyState,
    },
    helpers::{
        copy_forward_headers, decision_with_behavior_and_bot, rate_limit_match, DecisionRequest,
    },
    websocket::proxy_websocket_handshake,
};

pub fn track_decision(state: &ProxyState, action: WafAction) {
    state.requests_total.fetch_add(1, Ordering::Relaxed);
    match action {
        WafAction::Block => {
            state.blocked_total.fetch_add(1, Ordering::Relaxed);
        }
        WafAction::Monitor => {
            state.monitored_total.fetch_add(1, Ordering::Relaxed);
        }
        WafAction::Allow => {}
    }
}

pub async fn proxy_request(
    State(state): State<ProxyState>,
    request: Request<Body>,
) -> Result<Response<Body>, Response<Body>> {
    proxy_request_inner(state, None, request).await
}

pub async fn proxy_request_with_connect_info(
    State(state): State<ProxyState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Result<Response<Body>, Response<Body>> {
    proxy_request_inner(state, Some(peer_addr), request).await
}

async fn proxy_request_inner(
    mut state: ProxyState,
    peer_addr: Option<SocketAddr>,
    request: Request<Body>,
) -> Result<Response<Body>, Response<Body>> {
    state.config = state.managed_policy.effective_config(&state.config);
    let request_id = Uuid::new_v4().to_string();
    let (mut parts, body) = request.into_parts();
    let trusted_forwarded_headers =
        forwarded_headers_are_trusted(peer_addr, &state.config.forwarded_headers, true);
    let client_ip = client_id_from_headers(
        &parts.headers,
        &state.config.forwarded_headers,
        trusted_forwarded_headers,
    );
    let upstream = state
        .select_upstream(parts.uri.path())
        .cloned()
        .ok_or_else(|| {
            error!(
                request_id,
                path = parts.uri.path(),
                "no upstream matched request path"
            );
            json_response(
                StatusCode::BAD_GATEWAY,
                json!({
                    "request_id": request_id,
                    "error": "no upstream configured for request path"
                }),
            )
        })?;
    let websocket_handshake = is_websocket_upgrade(&parts.headers);
    let client_upgrade = if websocket_handshake {
        parts.extensions.remove::<OnUpgrade>()
    } else {
        None
    };

    if state.config.security.enable_rate_limiting {
        let rate_limit = select_rate_limit(&state.config, parts.uri.path(), &client_ip);
        let rate_limit_result = state
            .rate_limit_store
            .check(&rate_limit.key, &client_ip, rate_limit.policy)
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
                crate::config::WafMode::Strict,
                vec![rate_limit_match(&exceeded)],
                state.config.rules.inbound_anomaly_threshold,
            );
            log_decision(
                &parts.method,
                parts.uri.path(),
                parts.uri.query().unwrap_or_default(),
                &client_ip,
                &decision,
                &upstream,
                websocket_handshake,
            );
            record_event(
                &state,
                EventRequest {
                    method: parts.method.as_str(),
                    path: parts.uri.path(),
                    query: parts.uri.query().unwrap_or_default(),
                    client_ip: &client_ip,
                    evidence: request_evidence(
                        parts.uri.query().unwrap_or_default(),
                        &parts.headers,
                        0,
                    ),
                },
                &decision,
                &upstream,
                websocket_event(
                    &upstream,
                    &parts.headers,
                    if websocket_handshake {
                        "rate_limited"
                    } else {
                        "http"
                    },
                ),
            );

            track_decision(&state, decision.action);

            if decision.action == WafAction::Block {
                return Err(blocked_response(&decision));
            }
        }
    }

    if websocket_handshake {
        return proxy_websocket_handshake(
            state,
            upstream,
            parts,
            client_upgrade,
            request_id,
            client_ip,
            trusted_forwarded_headers,
        )
        .await;
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
    let content_type = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let body_for_rules = String::from_utf8_lossy(&body_bytes);

    let request_parts = RequestParts {
        method: parts.method.as_str(),
        path: &path,
        query: &query,
        headers: &headers,
        body: &body_for_rules,
        user_agent: &user_agent,
        content_type: &content_type,
        trusted_proxy: trusted_forwarded_headers,
    };
    let exclusions = effective_rule_exclusions(&state);
    let matches = state
        .rule_set
        .inspect_with_exclusions(&request_parts, &exclusions);
    let session_id = campaign::session_fingerprint(
        &client_ip,
        &user_agent,
        parts
            .headers
            .get(header::COOKIE)
            .map(|value| value.as_bytes()),
    );
    let decision = decision_with_behavior_and_bot(
        &state,
        DecisionRequest {
            request_id: request_id.clone(),
            matches,
            client_ip: &client_ip,
            path: &path,
            method: parts.method.as_str(),
            query: &query,
            content_type: &content_type,
            body_size: body_bytes.len(),
            headers: &headers,
            user_agent: &user_agent,
            trusted_forwarded_headers,
            session_id: &session_id,
        },
    )
    .await;

    log_decision(
        &parts.method,
        &path,
        &query,
        &client_ip,
        &decision,
        &upstream,
        false,
    );
    record_event(
        &state,
        EventRequest {
            method: parts.method.as_str(),
            path: &path,
            query: &query,
            client_ip: &client_ip,
            evidence: request_evidence(&query, &parts.headers, body_bytes.len()),
        },
        &decision,
        &upstream,
        None,
    );

    track_decision(&state, decision.action);

    if decision.action == WafAction::Block {
        return Err(blocked_response(&decision));
    }

    let upstream_uri = build_upstream_uri(&upstream.target, &parts.uri).map_err(|error| {
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
        &upstream.host,
        &request_id,
        false,
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
