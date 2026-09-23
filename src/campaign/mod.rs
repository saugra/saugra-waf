use std::{path::PathBuf, sync::Mutex};

use anyhow::Context;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    config::{CampaignBackend, CampaignCorrelationConfig, CampaignMode, WafMode},
    decision::WafAction,
    redis_connection,
};

mod eval;
#[cfg(test)]
mod tests;

use eval::{
    acquire_redis_lock, evaluate_with_state, parse_duration_seconds, read_state,
    release_redis_lock, write_state, StateFileLock,
};
pub use eval::{route_shape, session_fingerprint};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct CampaignOutcome {
    pub enabled: bool,
    pub action: WafAction,
    pub storage_backend: String,
    pub window_seconds: u64,
    pub campaign_ids: Vec<String>,
    pub matches: Vec<CampaignMatch>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct CampaignMatch {
    pub campaign_id: String,
    pub kind: String,
    pub score: u16,
    pub event_count: usize,
    pub client_count: usize,
    pub session_count: usize,
    pub route_count: usize,
    pub stages: Vec<String>,
    pub first_seen_at: u64,
    pub last_seen_at: u64,
}

#[derive(Debug, Clone)]
pub struct CampaignRequest<'a> {
    pub request_id: &'a str,
    pub client_id: &'a str,
    pub session_id: &'a str,
    pub path: &'a str,
    pub categories: &'a [String],
    pub server_mode: WafMode,
}

#[async_trait]
pub trait CampaignStore: Send + Sync {
    async fn evaluate(
        &self,
        config: &CampaignCorrelationConfig,
        request: CampaignRequest<'_>,
    ) -> anyhow::Result<CampaignOutcome>;
}

#[derive(Debug, Default)]
pub struct MemoryCampaignStore {
    state: Mutex<eval::CampaignState>,
}

#[async_trait]
impl CampaignStore for MemoryCampaignStore {
    async fn evaluate(
        &self,
        config: &CampaignCorrelationConfig,
        request: CampaignRequest<'_>,
    ) -> anyhow::Result<CampaignOutcome> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("campaign store lock poisoned"))?;
        Ok(evaluate_with_state(config, request, &mut state, "memory"))
    }
}

#[derive(Debug)]
pub struct LocalCampaignStore {
    path: PathBuf,
    access: Mutex<()>,
}

impl LocalCampaignStore {
    pub fn open(path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let path = path.into();
        let _lock = StateFileLock::acquire(&path)?;
        read_state(&path)?;
        Ok(Self {
            path,
            access: Mutex::new(()),
        })
    }
}

#[async_trait]
impl CampaignStore for LocalCampaignStore {
    async fn evaluate(
        &self,
        config: &CampaignCorrelationConfig,
        request: CampaignRequest<'_>,
    ) -> anyhow::Result<CampaignOutcome> {
        let _access = self
            .access
            .lock()
            .map_err(|_| anyhow::anyhow!("campaign store lock poisoned"))?;
        let _lock = StateFileLock::acquire(&self.path)?;
        let mut state = read_state(&self.path)?;
        let outcome = evaluate_with_state(config, request, &mut state, "local");
        write_state(&self.path, &state)?;
        Ok(outcome)
    }
}

#[derive(Clone)]
pub struct RedisCampaignStore {
    manager: redis::aio::ConnectionManager,
    state_key: String,
    lock_key: String,
}

impl RedisCampaignStore {
    async fn connect(
        redis_url: &str,
        redis_password: Option<&str>,
        key_prefix: &str,
    ) -> anyhow::Result<Self> {
        let connection_info = redis_connection::connection_info(
            redis_url,
            redis_password,
            "campaign_correlation.redis_url is not a valid Redis URL",
        )?;
        let client =
            redis::Client::open(connection_info).context("failed to create Redis client")?;
        let manager = client
            .get_connection_manager()
            .await
            .context("failed to connect to Redis for campaign correlation")?;
        let key_prefix = key_prefix.trim_end_matches(':');
        Ok(Self {
            manager,
            state_key: format!("{key_prefix}:state"),
            lock_key: format!("{key_prefix}:lock"),
        })
    }
}

#[async_trait]
impl CampaignStore for RedisCampaignStore {
    async fn evaluate(
        &self,
        config: &CampaignCorrelationConfig,
        request: CampaignRequest<'_>,
    ) -> anyhow::Result<CampaignOutcome> {
        let token = Uuid::new_v4().to_string();
        let mut connection = self.manager.clone();
        acquire_redis_lock(&mut connection, &self.lock_key, &token).await?;

        let result = async {
            let encoded: Option<String> = redis::cmd("GET")
                .arg(&self.state_key)
                .query_async(&mut connection)
                .await
                .context("failed to read Redis campaign state")?;
            let mut state = encoded
                .as_deref()
                .map(serde_json::from_str)
                .transpose()
                .context("Redis campaign state is invalid")?
                .unwrap_or_default();
            let outcome = evaluate_with_state(config, request, &mut state, "redis");
            let retention = parse_duration_seconds(&config.retention).unwrap_or(86_400);
            let _: () = redis::cmd("SETEX")
                .arg(&self.state_key)
                .arg(retention.saturating_mul(2))
                .arg(serde_json::to_string(&state)?)
                .query_async(&mut connection)
                .await
                .context("failed to persist Redis campaign state")?;
            Ok(outcome)
        }
        .await;

        release_redis_lock(&mut connection, &self.lock_key, &token).await;
        result
    }
}

pub async fn build_store(
    config: &CampaignCorrelationConfig,
) -> anyhow::Result<Box<dyn CampaignStore>> {
    if !config.enabled || config.mode == CampaignMode::Off {
        return Ok(Box::new(MemoryCampaignStore::default()));
    }

    match config.backend {
        CampaignBackend::Memory => Ok(Box::new(MemoryCampaignStore::default())),
        CampaignBackend::Local => Ok(Box::new(LocalCampaignStore::open(&config.state_path)?)),
        CampaignBackend::Redis => Ok(Box::new(
            RedisCampaignStore::connect(
                config.redis_url.as_deref().unwrap_or_default(),
                config.redis_password.as_deref(),
                &config.redis_key_prefix,
            )
            .await?,
        )),
    }
}

pub fn build_store_without_redis(
    config: &CampaignCorrelationConfig,
) -> anyhow::Result<Box<dyn CampaignStore>> {
    if !config.enabled || config.backend == CampaignBackend::Memory {
        return Ok(Box::new(MemoryCampaignStore::default()));
    }
    match config.backend {
        CampaignBackend::Local => Ok(Box::new(LocalCampaignStore::open(&config.state_path)?)),
        CampaignBackend::Redis => Err(anyhow::anyhow!(
            "Redis campaign correlation requires asynchronous store construction"
        )),
        CampaignBackend::Memory => unreachable!(),
    }
}
