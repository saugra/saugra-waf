use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use serde::{Deserialize, Serialize};

use crate::{
    config::{BehaviorBackend, UnknownThreatConfig},
    decision::WafAction,
};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct UnknownThreatOutcome {
    pub enabled: bool,
    pub action: WafAction,
    pub score: u16,
    pub threshold: u16,
    pub route_shape: String,
    pub baseline_observations: u64,
    pub baseline_ready: bool,
    pub storage_backend: String,
    pub signals: Vec<UnknownThreatSignal>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct UnknownThreatSignal {
    pub kind: String,
    pub score_delta: u16,
    pub explanation: String,
}

#[derive(Debug, Clone)]
pub struct UnknownThreatRequest<'a> {
    pub path: &'a str,
    pub method: &'a str,
    pub content_type: &'a str,
    pub query: &'a str,
    pub body_size: usize,
    pub eligible_for_learning: bool,
}

pub trait UnknownThreatStore: Send + Sync {
    fn evaluate(
        &self,
        config: &UnknownThreatConfig,
        request: UnknownThreatRequest<'_>,
    ) -> anyhow::Result<UnknownThreatOutcome>;
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct UnknownThreatState {
    routes: BTreeMap<String, RouteBaseline>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct RouteBaseline {
    observations: u64,
    methods: BTreeSet<String>,
    content_types: BTreeSet<String>,
    query_parameters: BTreeSet<String>,
    maximum_body_size: usize,
}

#[derive(Debug, Default)]
pub struct MemoryUnknownThreatStore {
    state: Mutex<UnknownThreatState>,
}

impl UnknownThreatStore for MemoryUnknownThreatStore {
    fn evaluate(
        &self,
        config: &UnknownThreatConfig,
        request: UnknownThreatRequest<'_>,
    ) -> anyhow::Result<UnknownThreatOutcome> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("unknown-threat store lock poisoned"))?;
        Ok(evaluate_with_state(config, request, &mut state, "memory"))
    }
}

#[derive(Debug)]
pub struct LocalUnknownThreatStore {
    path: PathBuf,
    state: Mutex<UnknownThreatState>,
}

impl LocalUnknownThreatStore {
    pub fn open(path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let path = path.into();
        let state = read_state(&path)?;
        Ok(Self {
            path,
            state: Mutex::new(state),
        })
    }
}

impl UnknownThreatStore for LocalUnknownThreatStore {
    fn evaluate(
        &self,
        config: &UnknownThreatConfig,
        request: UnknownThreatRequest<'_>,
    ) -> anyhow::Result<UnknownThreatOutcome> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("unknown-threat store lock poisoned"))?;
        let outcome = evaluate_with_state(config, request, &mut state, "local");
        write_state(&self.path, &state)?;
        Ok(outcome)
    }
}

pub fn build_store(config: &UnknownThreatConfig) -> anyhow::Result<Box<dyn UnknownThreatStore>> {
    match config.backend {
        BehaviorBackend::Memory => Ok(Box::new(MemoryUnknownThreatStore::default())),
        BehaviorBackend::Local => Ok(Box::new(LocalUnknownThreatStore::open(&config.state_path)?)),
    }
}

fn evaluate_with_state(
    config: &UnknownThreatConfig,
    request: UnknownThreatRequest<'_>,
    state: &mut UnknownThreatState,
    storage_backend: &str,
) -> UnknownThreatOutcome {
    let route_shape = route_shape(request.path);
    let baseline = state.routes.entry(route_shape.clone()).or_default();
    let baseline_observations = baseline.observations;
    let baseline_ready = baseline_observations >= config.minimum_observations;
    let mut signals = Vec::new();

    if config.enabled && baseline_ready {
        let method = request.method.to_ascii_uppercase();
        if !baseline.methods.contains(&method) {
            signals.push(UnknownThreatSignal {
                kind: "unseen_method".to_string(),
                score_delta: config.unseen_method_score,
                explanation: format!(
                    "Method {method} was not present in the learned baseline for {route_shape}."
                ),
            });
        }

        let content_type = normalized_content_type(request.content_type);
        if !content_type.is_empty() && !baseline.content_types.contains(&content_type) {
            signals.push(UnknownThreatSignal {
                kind: "unseen_content_type".to_string(),
                score_delta: config.unseen_content_type_score,
                explanation: format!(
                    "Content type {content_type} was not present in the learned baseline for {route_shape}."
                ),
            });
        }

        let unseen_parameters = query_parameter_names(request.query)
            .difference(&baseline.query_parameters)
            .cloned()
            .collect::<Vec<_>>();
        if !unseen_parameters.is_empty() {
            signals.push(UnknownThreatSignal {
                kind: "unseen_query_parameter".to_string(),
                score_delta: config.unseen_query_parameter_score,
                explanation: format!(
                    "Query parameter(s) {} were not present in the learned baseline for {route_shape}.",
                    unseen_parameters.join(", ")
                ),
            });
        }

        let body_limit = baseline
            .maximum_body_size
            .saturating_mul(config.body_size_multiplier as usize);
        if baseline.maximum_body_size > 0 && request.body_size > body_limit {
            signals.push(UnknownThreatSignal {
                kind: "body_size_deviation".to_string(),
                score_delta: config.body_size_score,
                explanation: format!(
                    "Body size {} exceeded the learned maximum {} by more than the configured multiplier.",
                    request.body_size, baseline.maximum_body_size
                ),
            });
        }
    }

    let score = signals.iter().map(|signal| signal.score_delta).sum();
    let action = if config.enabled && baseline_ready && score >= config.monitor_threshold {
        WafAction::Monitor
    } else {
        WafAction::Allow
    };

    if config.enabled && request.eligible_for_learning && signals.is_empty() {
        learn(baseline, &request);
    }

    UnknownThreatOutcome {
        enabled: config.enabled,
        action,
        score,
        threshold: config.monitor_threshold,
        route_shape,
        baseline_observations,
        baseline_ready,
        storage_backend: storage_backend.to_string(),
        signals,
    }
}

fn learn(baseline: &mut RouteBaseline, request: &UnknownThreatRequest<'_>) {
    baseline.observations = baseline.observations.saturating_add(1);
    baseline.methods.insert(request.method.to_ascii_uppercase());

    let content_type = normalized_content_type(request.content_type);
    if !content_type.is_empty() {
        baseline.content_types.insert(content_type);
    }
    baseline
        .query_parameters
        .extend(query_parameter_names(request.query));
    baseline.maximum_body_size = baseline.maximum_body_size.max(request.body_size);
}

fn normalized_content_type(value: &str) -> String {
    value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

fn query_parameter_names(query: &str) -> BTreeSet<String> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('=').map(|(name, _)| name).or(Some(pair)))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| name.to_ascii_lowercase())
        .collect()
}

fn route_shape(path: &str) -> String {
    let segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            if looks_dynamic(segment) {
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

fn looks_dynamic(segment: &str) -> bool {
    let compact = segment.replace('-', "");
    (!segment.is_empty() && segment.chars().all(|character| character.is_ascii_digit()))
        || (compact.len() >= 16
            && compact
                .chars()
                .all(|character| character.is_ascii_hexdigit()))
}

fn read_state(path: &Path) -> anyhow::Result<UnknownThreatState> {
    if !path.exists() {
        return Ok(UnknownThreatState::default());
    }
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn write_state(path: &Path, state: &UnknownThreatState) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(state)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> UnknownThreatConfig {
        UnknownThreatConfig {
            enabled: true,
            backend: BehaviorBackend::Memory,
            minimum_observations: 2,
            monitor_threshold: 10,
            unseen_method_score: 10,
            ..UnknownThreatConfig::default()
        }
    }

    fn request<'a>(method: &'a str, path: &'a str) -> UnknownThreatRequest<'a> {
        UnknownThreatRequest {
            path,
            method,
            content_type: "application/json",
            query: "page=1",
            body_size: 20,
            eligible_for_learning: true,
        }
    }

    #[test]
    fn learns_before_emitting_anomalies() {
        let store = MemoryUnknownThreatStore::default();
        store
            .evaluate(&config(), request("GET", "/users/42"))
            .unwrap();
        let learning = store
            .evaluate(&config(), request("GET", "/users/43"))
            .unwrap();
        let anomaly = store
            .evaluate(&config(), request("DELETE", "/users/44"))
            .unwrap();

        assert!(!learning.baseline_ready);
        assert_eq!(anomaly.route_shape, "/users/:id");
        assert_eq!(anomaly.action, WafAction::Monitor);
        assert_eq!(anomaly.signals[0].kind, "unseen_method");
    }

    #[test]
    fn suspicious_requests_do_not_update_the_baseline() {
        let store = MemoryUnknownThreatStore::default();
        store
            .evaluate(&config(), request("GET", "/users/42"))
            .unwrap();
        store
            .evaluate(&config(), request("GET", "/users/43"))
            .unwrap();
        store
            .evaluate(&config(), request("DELETE", "/users/44"))
            .unwrap();
        let repeated = store
            .evaluate(&config(), request("DELETE", "/users/45"))
            .unwrap();

        assert_eq!(repeated.action, WafAction::Monitor);
    }

    #[test]
    fn local_store_survives_restart() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("unknown-threats.json");
        let mut config = config();
        config.backend = BehaviorBackend::Local;
        config.state_path = path.clone();

        LocalUnknownThreatStore::open(&path)
            .unwrap()
            .evaluate(&config, request("GET", "/users/42"))
            .unwrap();
        LocalUnknownThreatStore::open(&path)
            .unwrap()
            .evaluate(&config, request("GET", "/users/43"))
            .unwrap();
        let outcome = LocalUnknownThreatStore::open(&path)
            .unwrap()
            .evaluate(&config, request("DELETE", "/users/44"))
            .unwrap();

        assert_eq!(outcome.action, WafAction::Monitor);
    }
}
