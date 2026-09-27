use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{atomic::AtomicU64, Arc},
};

use anyhow::Context;
use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, Response},
    response::Json,
    routing::get,
    Router,
};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use serde_json::json;
use tracing::info;

use crate::{
    behavior::{self, BehaviorStore},
    bot::{self, BotProtectionStore},
    campaign::{self, CampaignStore},
    config::{SaugraConfig, UpstreamConfig},
    console::{self, ConsoleOutbox, ManagedPolicyHandle},
    event_store::EventLogRetention,
    rate_limit::{self, RateLimitStore},
    rules::{self, RuleSet},
    runtime_policy::RuntimePolicyHandle,
    unknown_threats::{self, UnknownThreatStore},
};

pub mod handlers;
pub mod metrics;
pub mod net;
#[cfg(test)]
mod tests;
pub mod utils;
pub mod validation;

pub use handlers::{proxy_request, proxy_request_with_connect_info, track_decision};
pub use metrics::metrics_handler;
pub use net::*;

#[async_trait]
pub trait UpstreamTransport: Send + Sync {
    async fn request(&self, request: Request<Body>) -> anyhow::Result<Response<Body>>;
}

pub struct HyperUpstreamTransport {
    pub client: Client<HttpConnector, Body>,
}

#[async_trait]
impl UpstreamTransport for HyperUpstreamTransport {
    async fn request(&self, request: Request<Body>) -> anyhow::Result<Response<Body>> {
        let response = self.client.request(request).await?;
        Ok(response.map(Body::new))
    }
}

#[derive(Clone)]
pub struct ProxyState {
    pub config: SaugraConfig,
    pub upstream_transport: Arc<dyn UpstreamTransport>,
    pub upstreams: Vec<UpstreamConfig>,
    pub max_body_size_bytes: usize,
    pub rate_limit_store: Arc<dyn RateLimitStore>,
    pub behavior_store: Arc<dyn BehaviorStore>,
    pub unknown_threat_store: Arc<dyn UnknownThreatStore>,
    pub campaign_store: Arc<dyn CampaignStore>,
    pub bot_protection_store: Arc<dyn BotProtectionStore>,
    pub runtime_policy: Arc<RuntimePolicyHandle>,
    pub event_log_path: PathBuf,
    pub event_log_retention: EventLogRetention,
    pub console_outbox: Option<ConsoleOutbox>,
    pub managed_policy: ManagedPolicyHandle,
    pub rule_set: Arc<RuleSet>,
    pub requests_total: Arc<AtomicU64>,
    pub blocked_total: Arc<AtomicU64>,
    pub monitored_total: Arc<AtomicU64>,
}

impl ProxyState {
    pub fn with_transport(
        config: SaugraConfig,
        upstream_transport: Arc<dyn UpstreamTransport>,
        rate_limit_store: Arc<dyn RateLimitStore>,
        event_log_path: PathBuf,
        event_log_retention: EventLogRetention,
    ) -> anyhow::Result<Self> {
        config
            .validate()
            .context("proxy state requires a valid Saugra config")?;
        config
            .upstreams
            .first()
            .context("config validation should require at least one upstream")?;
        let upstreams = config.upstreams.clone();
        let max_body_size_bytes = config
            .max_body_size_bytes()?
            .try_into()
            .context("security.max_body_size is too large for this platform")?;
        let rule_set = Arc::new(rules::load_rule_set(&config.rules)?);
        let behavior_store = Arc::from(behavior::build_store(&config.behavior)?);
        let unknown_threat_store =
            Arc::from(unknown_threats::build_store(&config.unknown_threats)?);
        let campaign_store = Arc::from(campaign::build_store_without_redis(
            &config.campaign_correlation,
        )?);
        let bot_protection_store = Arc::from(bot::build_store(&config.bot_protection)?);
        let runtime_policy = Arc::new(RuntimePolicyHandle::open(config.runtime_policy.clone()));

        Ok(Self {
            config,
            upstream_transport,
            upstreams,
            max_body_size_bytes,
            rate_limit_store,
            behavior_store,
            unknown_threat_store,
            campaign_store,
            bot_protection_store,
            runtime_policy,
            event_log_path,
            event_log_retention,
            console_outbox: None,
            managed_policy: ManagedPolicyHandle::default(),
            rule_set,
            requests_total: Arc::new(AtomicU64::new(0)),
            blocked_total: Arc::new(AtomicU64::new(0)),
            monitored_total: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn with_campaign_store(
        config: SaugraConfig,
        upstream_transport: Arc<dyn UpstreamTransport>,
        rate_limit_store: Arc<dyn RateLimitStore>,
        campaign_store: Arc<dyn CampaignStore>,
        event_log_path: PathBuf,
        event_log_retention: EventLogRetention,
    ) -> anyhow::Result<Self> {
        let original_config = config.clone();
        let mut bootstrap_config = config;
        bootstrap_config.campaign_correlation.enabled = false;
        let mut state = Self::with_transport(
            bootstrap_config,
            upstream_transport,
            rate_limit_store,
            event_log_path,
            event_log_retention,
        )?;
        state.config = original_config;
        state.campaign_store = campaign_store;
        Ok(state)
    }

    pub fn select_upstream(&self, path: &str) -> Option<&UpstreamConfig> {
        if let Some(route) = self
            .config
            .routes
            .iter()
            .filter(|route| path_matches_route_prefix(path, &route.path_prefix))
            .max_by_key(|route| route.path_prefix.len())
        {
            return self
                .upstreams
                .iter()
                .find(|upstream| upstream.name == route.upstream);
        }

        self.upstreams.first()
    }
}

pub fn path_matches_route_prefix(path: &str, prefix: &str) -> bool {
    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        return true;
    }

    path == prefix || path.starts_with(&format!("{prefix}/"))
}

pub async fn run(config: SaugraConfig) -> anyhow::Result<()> {
    let listen_addr: SocketAddr = config
        .server
        .listen
        .parse()
        .with_context(|| format!("invalid server.listen address: {}", config.server.listen))?;

    let max_body_size_bytes = config.max_body_size_bytes()?;
    info!(
        mode = ?config.server.mode,
        listen = %config.server.listen,
        upstreams = config.upstreams.len(),
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
    let campaign_store = Arc::from(campaign::build_store(&config.campaign_correlation).await?);
    let console_outbox = config
        .console
        .enabled
        .then(|| ConsoleOutbox::from_config(&config));
    let managed_policy = ManagedPolicyHandle::from_config(&config)?;
    let _console_task = console_outbox
        .as_ref()
        .map(|outbox| console::start_telemetry(&config, outbox.clone(), managed_policy.clone()))
        .transpose()?;
    let mut state = ProxyState::with_campaign_store(
        config,
        Arc::new(HyperUpstreamTransport {
            client: Client::builder(TokioExecutor::new()).build(HttpConnector::new()),
        }),
        rate_limit_store,
        campaign_store,
        event_log_path,
        event_log_retention,
    )?;
    state.console_outbox = console_outbox;
    state.managed_policy = managed_policy;

    let app = Router::new()
        .route("/_saugra-waf/health", get(health))
        .route("/_saugra-waf/metrics", get(metrics_handler))
        .fallback(proxy_request_with_connect_info)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind Saugra listener at {listen_addr}"))?;
    info!("Saugra listening on http://{}", listen_addr);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "service": "saugra-waf"
    }))
}
