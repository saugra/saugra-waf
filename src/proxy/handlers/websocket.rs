use axum::{
    body::Body,
    http::{header, Request, Response, StatusCode},
};
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use serde_json::json;
use tokio::io::copy_bidirectional;
use tracing::{error, info, warn};

use crate::{campaign, config::UpstreamConfig, decision::WafAction, rules::RequestParts};

use super::{
    super::{
        utils::{
            blocked_response, build_upstream_uri, effective_rule_exclusions, json_response,
            log_decision, normalize_headers, record_event, request_evidence, websocket_event,
            websocket_policy_matches, EventRequest,
        },
        ProxyState,
    },
    helpers::{copy_forward_headers, decision_with_behavior_and_bot, DecisionRequest},
};

pub async fn proxy_websocket_handshake(
    state: ProxyState,
    upstream: UpstreamConfig,
    parts: axum::http::request::Parts,
    client_upgrade: Option<OnUpgrade>,
    request_id: String,
    client_ip: String,
    trusted_forwarded_headers: bool,
) -> Result<Response<Body>, Response<Body>> {
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

    let request_parts = RequestParts {
        method: parts.method.as_str(),
        path: &path,
        query: &query,
        headers: &headers,
        body: "",
        user_agent: &user_agent,
        content_type: &content_type,
        trusted_proxy: trusted_forwarded_headers,
    };
    let exclusions = effective_rule_exclusions(&state);
    let mut matches = state
        .rule_set
        .inspect_with_exclusions(&request_parts, &exclusions);
    matches.extend(websocket_policy_matches(&state, &parts.headers));

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
            body_size: 0,
            headers: &headers,
            user_agent: &user_agent,
            trusted_forwarded_headers,
            session_id: &session_id,
        },
    )
    .await;
    let event = websocket_event(
        &upstream,
        &parts.headers,
        if decision.action == WafAction::Block {
            "blocked"
        } else if decision.action == WafAction::Monitor {
            "monitored"
        } else {
            "accepted"
        },
    );

    log_decision(
        &parts.method,
        &path,
        &query,
        &client_ip,
        &decision,
        &upstream,
        true,
    );
    record_event(
        &state,
        EventRequest {
            method: parts.method.as_str(),
            path: &path,
            query: &query,
            client_ip: &client_ip,
            evidence: request_evidence(&query, &parts.headers, 0),
        },
        &decision,
        &upstream,
        event,
    );

    if decision.action == WafAction::Block {
        return Err(blocked_response(&decision));
    }

    let Some(client_upgrade) = client_upgrade else {
        warn!(
            request_id,
            "websocket request missing server upgrade extension"
        );
        return Err(json_response(
            StatusCode::BAD_REQUEST,
            json!({
                "request_id": request_id,
                "error": "websocket upgrade unavailable"
            }),
        ));
    };

    let upstream_uri = build_upstream_uri(&upstream.target, &parts.uri).map_err(|error| {
        error!(request_id, %error, "failed to build websocket upstream URI");
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
        .body(Body::empty())
        .map_err(|error| {
            error!(request_id, %error, "failed to build websocket upstream request");
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
        true,
    );

    let mut upstream_response = state
        .upstream_transport
        .request(upstream_request)
        .await
        .map_err(|error| {
            error!(request_id, %error, "websocket upstream request failed");
            json_response(
                StatusCode::BAD_GATEWAY,
                json!({
                    "request_id": request_id,
                    "error": "upstream request failed"
                }),
            )
        })?;

    if upstream_response.status() != StatusCode::SWITCHING_PROTOCOLS {
        warn!(
            request_id,
            status = %upstream_response.status(),
            "websocket upstream did not switch protocols"
        );
        return Ok(upstream_response);
    }

    let upstream_upgrade = upstream_response.extensions_mut().remove::<OnUpgrade>();
    if let Some(upstream_upgrade) = upstream_upgrade {
        tokio::spawn(tunnel_websocket(
            request_id.clone(),
            client_upgrade,
            upstream_upgrade,
        ));
    } else {
        warn!(
            request_id,
            "websocket upstream response missing upgrade extension"
        );
        return Err(json_response(
            StatusCode::BAD_GATEWAY,
            json!({
                "request_id": request_id,
                "error": "upstream upgrade unavailable"
            }),
        ));
    }

    Ok(upstream_response)
}

pub async fn tunnel_websocket(
    request_id: String,
    client_upgrade: OnUpgrade,
    upstream_upgrade: OnUpgrade,
) {
    let (client, upstream) = match tokio::try_join!(client_upgrade, upstream_upgrade) {
        Ok(upgraded) => upgraded,
        Err(error) => {
            warn!(request_id, %error, "websocket upgrade failed before tunnel start");
            return;
        }
    };
    let mut client = TokioIo::new(client);
    let mut upstream = TokioIo::new(upstream);

    match copy_bidirectional(&mut client, &mut upstream).await {
        Ok((from_client, from_upstream)) => {
            info!(
                request_id,
                from_client,
                from_upstream,
                outcome = "closed",
                "websocket tunnel closed"
            );
        }
        Err(error) => {
            warn!(
                request_id,
                %error,
                outcome = "error",
                "websocket tunnel ended with error"
            );
        }
    }
}
