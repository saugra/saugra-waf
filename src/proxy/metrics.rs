use std::sync::atomic::Ordering;

use axum::{extract::State, response::IntoResponse};

use super::ProxyState;

pub async fn metrics_handler(State(state): State<ProxyState>) -> impl IntoResponse {
    let requests = state.requests_total.load(Ordering::Relaxed);
    let blocked = state.blocked_total.load(Ordering::Relaxed);
    let monitored = state.monitored_total.load(Ordering::Relaxed);

    let body = format!(
        "# HELP saugra_waf_requests_total Total number of HTTP requests inspected\n\
         # TYPE saugra_waf_requests_total counter\n\
         saugra_waf_requests_total {}\n\
         # HELP saugra_waf_blocked_total Total number of HTTP requests blocked\n\
         # TYPE saugra_waf_blocked_total counter\n\
         saugra_waf_blocked_total {}\n\
         # HELP saugra_waf_monitored_total Total number of HTTP requests monitored\n\
         # TYPE saugra_waf_monitored_total counter\n\
         saugra_waf_monitored_total {}\n",
        requests, blocked, monitored
    );

    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

#[cfg(test)]
mod tests {
    use super::metrics_handler;
    use crate::{
        config::WafMode,
        event_store::EventLogRetention,
        proxy::{ProxyState, UpstreamTransport},
    };
    use axum::extract::State;
    use std::{path::PathBuf, sync::Arc};

    struct DummyTransport;
    #[async_trait::async_trait]
    impl UpstreamTransport for DummyTransport {
        async fn request(
            &self,
            _req: axum::http::Request<axum::body::Body>,
        ) -> anyhow::Result<axum::http::Response<axum::body::Body>> {
            Ok(axum::http::Response::new(axum::body::Body::empty()))
        }
    }

    #[tokio::test]
    async fn renders_prometheus_metrics_format() {
        let config = crate::config::SaugraConfig {
            server: crate::config::ServerConfig {
                listen: "127.0.0.1:0".to_string(),
                mode: WafMode::Monitor,
            },
            upstreams: vec![crate::config::UpstreamConfig {
                name: "app".to_string(),
                host: "example.com".to_string(),
                target: "http://127.0.0.1:8000".to_string(),
            }],
            routes: Vec::new(),
            security: Default::default(),
            forwarded_headers: Default::default(),
            rate_limit: Default::default(),
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
        };
        let state = ProxyState::with_transport(
            config,
            Arc::new(DummyTransport),
            Arc::new(crate::rate_limit::MemoryRateLimitStore::new()),
            PathBuf::from("logs/events.jsonl"),
            EventLogRetention {
                max_size_bytes: 1024,
                max_files: 1,
            },
        )
        .unwrap();

        state
            .requests_total
            .store(10, std::sync::atomic::Ordering::Relaxed);
        state
            .blocked_total
            .store(2, std::sync::atomic::Ordering::Relaxed);
        state
            .monitored_total
            .store(3, std::sync::atomic::Ordering::Relaxed);

        let res = metrics_handler(State(state)).await;
        let response = axum::response::IntoResponse::into_response(res);
        let body_bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

        assert!(body_str.contains("saugra_waf_requests_total 10"));
        assert!(body_str.contains("saugra_waf_blocked_total 2"));
        assert!(body_str.contains("saugra_waf_monitored_total 3"));
    }
}
