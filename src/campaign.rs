use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::Mutex,
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use async_trait::async_trait;
use redis::IntoConnectionInfo;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    config::{
        CampaignBackend, CampaignCorrelationConfig, CampaignMode, CampaignPolicyConfig, WafMode,
    },
    decision::WafAction,
};

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

#[derive(Debug, Default, Deserialize, Serialize)]
struct CampaignState {
    events: Vec<CampaignEvent>,
    active: BTreeMap<String, ActiveCampaign>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CampaignEvent {
    request_id: String,
    timestamp_seconds: u64,
    client_id: String,
    session_id: String,
    route_shape: String,
    categories: BTreeSet<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ActiveCampaign {
    campaign_id: String,
    first_seen_at: u64,
    last_seen_at: u64,
}

#[derive(Debug, Default)]
pub struct MemoryCampaignStore {
    state: Mutex<CampaignState>,
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
        let mut connection_info = redis_url
            .into_connection_info()
            .context("campaign_correlation.redis_url is not a valid Redis URL")?;
        if let Some(password) = redis_password
            .map(str::trim)
            .filter(|password| !password.is_empty())
        {
            let redis_settings = connection_info
                .redis_settings()
                .clone()
                .set_password(password);
            connection_info = connection_info.set_redis_settings(redis_settings);
        }
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

fn evaluate_with_state(
    config: &CampaignCorrelationConfig,
    request: CampaignRequest<'_>,
    state: &mut CampaignState,
    storage_backend: &str,
) -> CampaignOutcome {
    let window_seconds = parse_duration_seconds(&config.window).unwrap_or(900);
    if !config.enabled
        || config.mode == CampaignMode::Off
        || request.server_mode == WafMode::Off
        || request.categories.is_empty()
    {
        return empty_outcome(config.enabled, storage_backend, window_seconds);
    }

    let now = unix_seconds_now();
    let retention_seconds = parse_duration_seconds(&config.retention).unwrap_or(86_400);
    state
        .events
        .retain(|event| now.saturating_sub(event.timestamp_seconds) <= retention_seconds);
    state.events.push(CampaignEvent {
        request_id: request.request_id.to_string(),
        timestamp_seconds: now,
        client_id: request.client_id.to_string(),
        session_id: request.session_id.to_string(),
        route_shape: route_shape(request.path),
        categories: request.categories.iter().cloned().collect(),
    });
    if state.events.len() > config.max_events {
        let remove = state.events.len() - config.max_events;
        state.events.drain(0..remove);
    }

    let window_start = now.saturating_sub(window_seconds);
    let current = state.events.last().expect("current event was appended");
    let mut matches = Vec::new();
    for policy in &config.policies {
        let evidence = state
            .events
            .iter()
            .filter(|event| event.timestamp_seconds >= window_start)
            .filter(|event| in_scope(policy, current, event))
            .filter(|event| policy_matches_event(policy, event))
            .collect::<Vec<_>>();
        let stages = matched_stages(policy, &evidence);
        let clients = distinct(&evidence, |event| event.client_id.as_str());
        let sessions = distinct(&evidence, |event| event.session_id.as_str());
        let routes = distinct(&evidence, |event| event.route_shape.as_str());
        if evidence.len() < policy.minimum_events
            || clients < policy.minimum_clients
            || sessions < policy.minimum_sessions
            || routes < policy.minimum_routes
            || stages.len() < policy.minimum_stages
        {
            continue;
        }

        let active_key = format!("{}:{}", policy.kind, scope_value(policy, current));
        let active = state
            .active
            .entry(active_key)
            .or_insert_with(|| ActiveCampaign {
                campaign_id: format!("cmp-{}", Uuid::new_v4()),
                first_seen_at: now,
                last_seen_at: now,
            });
        active.last_seen_at = now;
        matches.push(CampaignMatch {
            campaign_id: active.campaign_id.clone(),
            kind: policy.kind.clone(),
            score: policy.score,
            event_count: evidence.len(),
            client_count: clients,
            session_count: sessions,
            route_count: routes,
            stages,
            first_seen_at: active.first_seen_at,
            last_seen_at: active.last_seen_at,
        });
    }

    state
        .active
        .retain(|_, campaign| now.saturating_sub(campaign.last_seen_at) <= retention_seconds);
    matches.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.kind.cmp(&right.kind))
    });
    CampaignOutcome {
        enabled: true,
        action: if matches.is_empty() {
            WafAction::Allow
        } else {
            WafAction::Monitor
        },
        storage_backend: storage_backend.to_string(),
        window_seconds,
        campaign_ids: matches
            .iter()
            .map(|campaign| campaign.campaign_id.clone())
            .collect(),
        matches,
    }
}

fn empty_outcome(enabled: bool, storage_backend: &str, window_seconds: u64) -> CampaignOutcome {
    CampaignOutcome {
        enabled,
        action: WafAction::Allow,
        storage_backend: storage_backend.to_string(),
        window_seconds,
        campaign_ids: Vec::new(),
        matches: Vec::new(),
    }
}

fn in_scope(policy: &CampaignPolicyConfig, current: &CampaignEvent, event: &CampaignEvent) -> bool {
    match policy.scope.as_str() {
        "client" => event.client_id == current.client_id,
        "session" => event.session_id == current.session_id,
        "route" => event.route_shape == current.route_shape,
        _ => true,
    }
}

fn scope_value<'a>(policy: &CampaignPolicyConfig, event: &'a CampaignEvent) -> &'a str {
    match policy.scope.as_str() {
        "client" => &event.client_id,
        "session" => &event.session_id,
        "route" => &event.route_shape,
        _ => "global",
    }
}

fn policy_matches_event(policy: &CampaignPolicyConfig, event: &CampaignEvent) -> bool {
    let category_match = policy.categories.is_empty()
        || policy
            .categories
            .iter()
            .any(|category| event.categories.contains(category));
    let path_match = policy.path_prefixes.is_empty()
        || policy.path_prefixes.iter().any(|prefix| {
            event.route_shape == *prefix
                || event
                    .route_shape
                    .starts_with(&format!("{}/", prefix.trim_end_matches('/')))
        });
    let stage_match = policy.stages.is_empty()
        || policy.stages.iter().any(|stage| {
            stage
                .categories
                .iter()
                .any(|category| event.categories.contains(category))
        });
    category_match && path_match && stage_match
}

fn matched_stages(policy: &CampaignPolicyConfig, evidence: &[&CampaignEvent]) -> Vec<String> {
    policy
        .stages
        .iter()
        .filter(|stage| {
            evidence.iter().any(|event| {
                stage
                    .categories
                    .iter()
                    .any(|category| event.categories.contains(category))
            })
        })
        .map(|stage| stage.name.clone())
        .collect()
}

fn distinct<'a>(
    events: &[&'a CampaignEvent],
    value: impl Fn(&'a CampaignEvent) -> &'a str,
) -> usize {
    events
        .iter()
        .map(|event| value(event))
        .collect::<BTreeSet<_>>()
        .len()
}

pub fn route_shape(path: &str) -> String {
    let segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            let compact = segment.replace('-', "");
            if segment.chars().all(|character| character.is_ascii_digit())
                || (compact.len() >= 16
                    && compact
                        .chars()
                        .all(|character| character.is_ascii_hexdigit()))
            {
                ":id"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>();
    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}

pub fn session_fingerprint(
    client_id: &str,
    user_agent: &str,
    session_material: Option<&[u8]>,
) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in client_id
        .bytes()
        .chain(user_agent.bytes())
        .chain(session_material.unwrap_or_default().iter().copied())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn read_state(path: &Path) -> anyhow::Result<CampaignState> {
    if !path.exists() {
        return Ok(CampaignState::default());
    }
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn write_state(path: &Path, state: &CampaignState) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = PathBuf::from(format!("{}.{}.tmp", path.display(), unix_nanos_now()));
    fs::write(&temporary, serde_json::to_vec_pretty(state)?)?;
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    Ok(())
}

struct StateFileLock {
    path: PathBuf,
}

impl StateFileLock {
    fn acquire(state_path: &Path) -> anyhow::Result<Self> {
        let path = PathBuf::from(format!("{}.lock", state_path.display()));
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        for _ in 0..1_000 {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(_) => return Ok(Self { path }),
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                    if lock_is_stale(&path) {
                        match fs::remove_file(&path) {
                            Ok(()) => continue,
                            Err(error) if error.kind() == ErrorKind::NotFound => continue,
                            Err(_) => {}
                        }
                    }
                    thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(anyhow::anyhow!(
            "timed out waiting for campaign state lock {}",
            path.display()
        ))
    }
}

fn lock_is_stale(path: &Path) -> bool {
    path.metadata()
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
        .is_some_and(|age| age.as_secs() >= 30)
}

impl Drop for StateFileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

async fn acquire_redis_lock(
    connection: &mut redis::aio::ConnectionManager,
    lock_key: &str,
    token: &str,
) -> anyhow::Result<()> {
    for _ in 0..100 {
        let acquired: Option<String> = redis::cmd("SET")
            .arg(lock_key)
            .arg(token)
            .arg("NX")
            .arg("PX")
            .arg(5_000)
            .query_async(connection)
            .await
            .context("failed to acquire Redis campaign lock")?;
        if acquired.as_deref() == Some("OK") {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    Err(anyhow::anyhow!("timed out waiting for Redis campaign lock"))
}

async fn release_redis_lock(
    connection: &mut redis::aio::ConnectionManager,
    lock_key: &str,
    token: &str,
) {
    let _: redis::RedisResult<i32> = redis::Script::new(
        "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end return 0",
    )
    .key(lock_key)
    .arg(token)
    .invoke_async(connection)
    .await;
}

fn parse_duration_seconds(value: &str) -> Option<u64> {
    let value = value.trim().to_ascii_lowercase();
    let split = value.find(|character: char| !character.is_ascii_digit())?;
    let number = value[..split].parse::<u64>().ok()?;
    let multiplier = match value[split..].trim() {
        "s" => 1,
        "m" => 60,
        "h" => 3_600,
        "d" => 86_400,
        _ => return None,
    };
    number.checked_mul(multiplier).filter(|value| *value > 0)
}

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unix_nanos_now() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CampaignBackend, CampaignStageConfig};

    fn config(policy: CampaignPolicyConfig) -> CampaignCorrelationConfig {
        CampaignCorrelationConfig {
            enabled: true,
            backend: CampaignBackend::Memory,
            window: "15m".to_string(),
            retention: "24h".to_string(),
            max_events: 100,
            policies: vec![policy],
            ..CampaignCorrelationConfig::default()
        }
    }

    #[tokio::test]
    async fn correlates_distributed_scanning_across_clients_and_routes() {
        let store = MemoryCampaignStore::default();
        let config = config(CampaignPolicyConfig {
            kind: "distributed_scanning".to_string(),
            scope: "global".to_string(),
            score: 60,
            minimum_events: 3,
            minimum_clients: 3,
            minimum_sessions: 3,
            minimum_routes: 3,
            categories: vec!["scanner_behavior".to_string()],
            path_prefixes: Vec::new(),
            stages: Vec::new(),
            minimum_stages: 0,
        });

        for index in 0..2 {
            let outcome = store
                .evaluate(
                    &config,
                    CampaignRequest {
                        request_id: &format!("request-{index}"),
                        client_id: &format!("client-{index}"),
                        session_id: &format!("session-{index}"),
                        path: &format!("/probe-{index}"),
                        categories: &["scanner_behavior".to_string()],
                        server_mode: WafMode::Monitor,
                    },
                )
                .await
                .unwrap();
            assert_eq!(outcome.action, WafAction::Allow);
        }

        let outcome = store
            .evaluate(
                &config,
                CampaignRequest {
                    request_id: "request-2",
                    client_id: "client-2",
                    session_id: "session-2",
                    path: "/probe-2",
                    categories: &["scanner_behavior".to_string()],
                    server_mode: WafMode::Monitor,
                },
            )
            .await
            .unwrap();
        assert_eq!(outcome.action, WafAction::Monitor);
        assert_eq!(outcome.matches[0].client_count, 3);
        assert!(outcome.campaign_ids[0].starts_with("cmp-"));
    }

    #[tokio::test]
    async fn detects_multi_step_progression_within_one_session() {
        let store = MemoryCampaignStore::default();
        let config = config(CampaignPolicyConfig {
            kind: "multi_step_progression".to_string(),
            scope: "session".to_string(),
            score: 80,
            minimum_events: 3,
            minimum_clients: 1,
            minimum_sessions: 1,
            minimum_routes: 2,
            categories: Vec::new(),
            path_prefixes: Vec::new(),
            stages: vec![
                CampaignStageConfig {
                    name: "recon".to_string(),
                    categories: vec!["scanner_behavior".to_string()],
                },
                CampaignStageConfig {
                    name: "access".to_string(),
                    categories: vec!["authentication_abuse".to_string()],
                },
                CampaignStageConfig {
                    name: "exploit".to_string(),
                    categories: vec!["sql_injection".to_string()],
                },
            ],
            minimum_stages: 3,
        });
        for (index, category) in ["scanner_behavior", "authentication_abuse", "sql_injection"]
            .iter()
            .enumerate()
        {
            let outcome = store
                .evaluate(
                    &config,
                    CampaignRequest {
                        request_id: &format!("request-{index}"),
                        client_id: "client",
                        session_id: "session",
                        path: if index == 0 { "/probe" } else { "/login" },
                        categories: &[category.to_string()],
                        server_mode: WafMode::Monitor,
                    },
                )
                .await
                .unwrap();
            if index == 2 {
                assert_eq!(outcome.matches[0].stages.len(), 3);
            }
        }
    }

    #[tokio::test]
    async fn local_store_persists_campaign_state_and_builders_select_backends() {
        let temp_dir = tempfile::tempdir().unwrap();
        let state_path = temp_dir.path().join("campaign-state.json");
        let mut config = config(CampaignPolicyConfig {
            kind: "single-client-scan".to_string(),
            scope: "client".to_string(),
            score: 40,
            minimum_events: 1,
            minimum_clients: 1,
            minimum_sessions: 1,
            minimum_routes: 1,
            categories: vec!["scanner_behavior".to_string()],
            path_prefixes: Vec::new(),
            stages: Vec::new(),
            minimum_stages: 0,
        });
        config.backend = CampaignBackend::Local;
        config.state_path = state_path.clone();

        let store = build_store(&config).await.unwrap();
        let outcome = store
            .evaluate(
                &config,
                CampaignRequest {
                    request_id: "request-local",
                    client_id: "client-local",
                    session_id: "session-local",
                    path: "/probe/123",
                    categories: &["scanner_behavior".to_string()],
                    server_mode: WafMode::Monitor,
                },
            )
            .await
            .unwrap();

        assert_eq!(outcome.storage_backend, "local");
        assert_eq!(outcome.action, WafAction::Monitor);
        assert!(state_path.exists());

        let reopened = build_store_without_redis(&config).unwrap();
        let repeated = reopened
            .evaluate(
                &config,
                CampaignRequest {
                    request_id: "request-local-2",
                    client_id: "client-local",
                    session_id: "session-local",
                    path: "/probe/456",
                    categories: &["scanner_behavior".to_string()],
                    server_mode: WafMode::Monitor,
                },
            )
            .await
            .unwrap();
        assert_eq!(repeated.matches[0].event_count, 2);

        config.backend = CampaignBackend::Redis;
        let error = match build_store_without_redis(&config) {
            Ok(_) => panic!("Redis should require asynchronous store construction"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("asynchronous store construction"));
    }

    #[test]
    fn fingerprints_session_material_without_retaining_it() {
        let first = session_fingerprint("127.0.0.1", "browser", Some(b"session=secret"));
        let second = session_fingerprint("127.0.0.1", "browser", Some(b"session=other"));
        assert_ne!(first, second);
        assert!(!first.contains("secret"));
    }
}
