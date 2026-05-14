use std::net::SocketAddr;

use anyhow::Context;
use axum::{response::Json, routing::get, Router};
use serde_json::json;
use tracing::info;
use uuid::Uuid;

use crate::{
    ai,
    config::SaugraConfig,
    decision::WafDecision,
    rules::{self, RequestParts},
};

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

    let app = Router::new()
        .route("/_saugra/health", get(health))
        .route("/", get(root));

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

async fn root() -> Json<serde_json::Value> {
    let request_id = Uuid::new_v4().to_string();
    let matches = rules::inspect(&RequestParts::default()).unwrap_or_default();
    let decision = WafDecision::from_matches(request_id, crate::config::WafMode::Monitor, matches);

    Json(json!({
        "service": "saugra",
        "message": "reverse proxy inspection will be added next",
        "decision": decision,
        "explanation": ai::explain(&decision)
    }))
}

#[allow(dead_code)]
fn _assert_socket_addr(_: SocketAddr) {}
