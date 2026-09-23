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
