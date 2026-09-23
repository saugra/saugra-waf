use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::ErrorKind,
    path::{Path, PathBuf},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    config::{CampaignCorrelationConfig, CampaignMode, CampaignPolicyConfig, WafMode},
    decision::WafAction,
};

use super::{CampaignMatch, CampaignOutcome, CampaignRequest};

#[derive(Debug, Default, Deserialize, Serialize)]
pub(super) struct CampaignState {
    pub(super) events: Vec<CampaignEventInternal>,
    pub(super) active: BTreeMap<String, ActiveCampaign>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct CampaignEventInternal {
    request_id: String,
    timestamp_seconds: u64,
    client_id: String,
    session_id: String,
    route_shape: String,
    categories: BTreeSet<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct ActiveCampaign {
    campaign_id: String,
    first_seen_at: u64,
    last_seen_at: u64,
}

pub(super) fn evaluate_with_state(
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
    state.events.push(CampaignEventInternal {
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

fn in_scope(
    policy: &CampaignPolicyConfig,
    current: &CampaignEventInternal,
    event: &CampaignEventInternal,
) -> bool {
    match policy.scope.as_str() {
        "client" => event.client_id == current.client_id,
        "session" => event.session_id == current.session_id,
        "route" => event.route_shape == current.route_shape,
        _ => true,
    }
}

fn scope_value<'a>(policy: &CampaignPolicyConfig, event: &'a CampaignEventInternal) -> &'a str {
    match policy.scope.as_str() {
        "client" => &event.client_id,
        "session" => &event.session_id,
        "route" => &event.route_shape,
        _ => "global",
    }
}

fn policy_matches_event(policy: &CampaignPolicyConfig, event: &CampaignEventInternal) -> bool {
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

fn matched_stages(
    policy: &CampaignPolicyConfig,
    evidence: &[&CampaignEventInternal],
) -> Vec<String> {
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
    events: &[&'a CampaignEventInternal],
    value: impl Fn(&'a CampaignEventInternal) -> &'a str,
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

pub(super) fn read_state(path: &Path) -> anyhow::Result<CampaignState> {
    if !path.exists() {
        return Ok(CampaignState::default());
    }
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read campaign state {}", path.display()))?;
    serde_json::from_str(&contents)
        .with_context(|| format!("campaign state is not valid JSON at {}", path.display()))
}

pub(super) fn write_state(path: &Path, state: &CampaignState) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create campaign state directory {}",
                parent.display()
            )
        })?;
    }
    let temporary = PathBuf::from(format!("{}.{}.tmp", path.display(), unix_nanos_now()));
    fs::write(&temporary, serde_json::to_vec_pretty(state)?).with_context(|| {
        format!(
            "failed to write temporary campaign state {}",
            temporary.display()
        )
    })?;
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error)
            .with_context(|| format!("failed to replace campaign state {}", path.display()));
    }
    Ok(())
}

pub(super) struct StateFileLock {
    path: PathBuf,
}

impl StateFileLock {
    pub(super) fn acquire(state_path: &Path) -> anyhow::Result<Self> {
        let path = PathBuf::from(format!("{}.lock", state_path.display()));
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create campaign lock directory {}",
                    parent.display()
                )
            })?;
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
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to create campaign lock {}", path.display())
                    });
                }
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

pub(super) async fn acquire_redis_lock(
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

pub(super) async fn release_redis_lock(
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

pub(super) fn parse_duration_seconds(value: &str) -> Option<u64> {
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
