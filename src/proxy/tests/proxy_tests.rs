use std::{path::PathBuf, sync::Arc};

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{header, HeaderMap, Request, Response},
};

use crate::{
    config::{
        ForwardedHeadersConfig, ProxyRouteConfig, RouteRateLimitConfig, ServerConfig,
        UpstreamConfig, WafMode,
    },
    console::ManagedPolicyHandle,
    event_store::EventLogRetention,
};

use super::super::{
    utils::{
        build_upstream_uri, client_id_from_headers, effective_rule_exclusions,
        forwarded_headers_are_trusted, normalize_headers, path_matches_route, select_rate_limit,
    },
    ProxyState, UpstreamTransport,
};

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

    assert_eq!(
        client_id_from_headers(&headers, &ForwardedHeadersConfig::default(), true),
        "203.0.113.10"
    );
}

#[test]
fn ignores_forwarded_client_id_from_untrusted_proxy() {
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", "203.0.113.10, 10.0.0.1".parse().unwrap());
    headers.insert("x-real-ip", "198.51.100.20".parse().unwrap());

    assert_eq!(
        client_id_from_headers(&headers, &ForwardedHeadersConfig::default(), false),
        "198.51.100.20"
    );
}

#[test]
fn matches_trusted_proxy_cidr() {
    assert!(forwarded_headers_are_trusted(
        Some("127.0.0.1:4321".parse().unwrap()),
        &ForwardedHeadersConfig::default(),
        false
    ));
    assert!(!forwarded_headers_are_trusted(
        Some("203.0.113.10:4321".parse().unwrap()),
        &ForwardedHeadersConfig::default(),
        false
    ));
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

#[test]
fn selects_first_upstream_when_no_routes_are_configured() {
    let state = ProxyState::with_transport(
        test_config(WafMode::Block, 120),
        Arc::new(TestUpstreamTransport),
        Arc::new(crate::rate_limit::MemoryRateLimitStore::new()),
        PathBuf::from("logs/test-events.jsonl"),
        EventLogRetention {
            max_size_bytes: 1024 * 1024,
            max_files: 3,
        },
    )
    .unwrap();

    let upstream = state.select_upstream("/api/users").unwrap();

    assert_eq!(upstream.name, "app");
}

#[test]
fn selects_longest_matching_proxy_route() {
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
        Arc::new(TestUpstreamTransport),
        Arc::new(crate::rate_limit::MemoryRateLimitStore::new()),
        PathBuf::from("logs/test-events.jsonl"),
        EventLogRetention {
            max_size_bytes: 1024 * 1024,
            max_files: 3,
        },
    )
    .unwrap();

    assert_eq!(state.select_upstream("/api/users").unwrap().name, "api");
    assert_eq!(
        state.select_upstream("/api/admin/users").unwrap().name,
        "admin-api"
    );
    assert_eq!(state.select_upstream("/").unwrap().name, "app");
}

struct TestUpstreamTransport;

#[async_trait]
impl UpstreamTransport for TestUpstreamTransport {
    async fn request(&self, _request: Request<Body>) -> anyhow::Result<Response<Body>> {
        Ok(Response::new(Body::empty()))
    }
}

fn test_config(mode: WafMode, requests_per_minute: u32) -> crate::config::SaugraConfig {
    crate::config::SaugraConfig {
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
        security: crate::config::SecurityConfig {
            enable_rate_limiting: true,
            ..Default::default()
        },
        forwarded_headers: Default::default(),
        rate_limit: crate::config::RateLimitConfig {
            backend: crate::config::RateLimitBackend::Memory,
            redis_url: None,
            redis_password: None,
            requests_per_minute,
            burst: 0,
            routes: Vec::new(),
        },
        rules: Default::default(),
        behavior: Default::default(),
        unknown_threats: Default::default(),
        campaign_correlation: Default::default(),
        bot_protection: Default::default(),
        runtime_policy: Default::default(),
        ai: Default::default(),
        logging: Default::default(),
        console: Default::default(),
        websocket: Default::default(),
        posture: Default::default(),
        reports: Default::default(),
        standards: Default::default(),
        security_summary: Default::default(),
        storage_cleanup: Default::default(),
    }
}

#[test]
fn managed_policy_exclusions_are_combined_with_local_exclusions() {
    let mut config = test_config(WafMode::Monitor, 10);
    config
        .rules
        .exclusions
        .push(crate::config::RuleExclusionConfig {
            name: Some("Local exclusion".into()),
            rule_ids: vec!["LOCAL-001".into()],
            path_prefixes: vec!["/local".into()],
            ..Default::default()
        });
    let mut state = ProxyState::with_transport(
        config,
        Arc::new(TestUpstreamTransport),
        Arc::new(crate::rate_limit::MemoryRateLimitStore::new()),
        PathBuf::from("logs/test-managed-policy-events.jsonl"),
        EventLogRetention {
            max_size_bytes: 1024 * 1024,
            max_files: 3,
        },
    )
    .unwrap();
    state.managed_policy = ManagedPolicyHandle::default();
    state
        .managed_policy
        .activate(vec![crate::config::RuleExclusionConfig {
            name: Some("Managed exclusion".into()),
            rule_ids: vec!["MANAGED-001".into()],
            path_prefixes: vec!["/managed".into()],
            ..Default::default()
        }]);

    let exclusions = effective_rule_exclusions(&state);
    assert_eq!(exclusions.len(), 2);
    assert_eq!(exclusions[0].rule_ids, vec!["LOCAL-001"]);
    assert_eq!(exclusions[1].rule_ids, vec!["MANAGED-001"]);
}
