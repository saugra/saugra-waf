use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    sync::Mutex,
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::{
    config::{
        BehaviorBackend, UnknownThreatConfig, UnknownThreatMode, UnknownThreatRouteConfig, WafMode,
    },
    decision::WafAction,
    event_store::SecurityEvent,
    rules::{RuleMatch, RuleSeverity, RuleTarget},
};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct UnknownThreatOutcome {
    pub enabled: bool,
    pub action: WafAction,
    pub score: u16,
    pub threshold: u16,
    #[serde(default)]
    pub block_threshold: u16,
    pub route_shape: String,
    pub baseline_observations: u64,
    pub baseline_ready: bool,
    #[serde(default)]
    pub baseline_age_seconds: u64,
    #[serde(default)]
    pub minimum_block_observations: u64,
    #[serde(default)]
    pub minimum_baseline_age_seconds: u64,
    #[serde(default)]
    pub minimum_independent_signals: usize,
    #[serde(default)]
    pub high_risk_route: bool,
    #[serde(default)]
    pub would_block: bool,
    #[serde(default)]
    pub block_eligible: bool,
    #[serde(default)]
    pub enforcement_gates: Vec<String>,
    #[serde(default)]
    pub baseline_tracked: bool,
    #[serde(default = "default_true")]
    pub learning_enabled: bool,
    #[serde(default)]
    pub learning_source_trusted: bool,
    #[serde(default = "default_true")]
    pub learning_source_allowed: bool,
    #[serde(default)]
    pub route_excluded: bool,
    #[serde(default)]
    pub capacity_reached: bool,
    #[serde(default)]
    pub pruned_routes: usize,
    pub storage_backend: String,
    pub signals: Vec<UnknownThreatSignal>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct UnknownThreatSignal {
    pub kind: String,
    pub score_delta: u16,
    pub explanation: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct UnknownThreatCleanupReport {
    pub path: PathBuf,
    pub dry_run: bool,
    pub state_found: bool,
    pub routes_before: usize,
    pub routes_removed: usize,
    pub routes_after: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct UnknownThreatShadowReport {
    pub total_events: usize,
    pub analyzed_events: usize,
    pub monitor_candidates: usize,
    pub would_block_candidates: usize,
    pub enforced_blocks: usize,
    pub gated_candidates: usize,
    pub single_signal_candidates: usize,
    pub new_baseline_candidates: usize,
    pub routes: Vec<UnknownThreatRouteReport>,
    pub sample_request_ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct UnknownThreatRouteReport {
    pub route_shape: String,
    pub candidates: usize,
    pub would_block: usize,
    pub enforced_blocks: usize,
}

#[derive(Debug, Clone)]
pub struct UnknownThreatRequest<'a> {
    pub path: &'a str,
    pub client_id: &'a str,
    pub method: &'a str,
    pub content_type: &'a str,
    pub query: &'a str,
    pub body_size: usize,
    pub eligible_for_learning: bool,
    pub server_mode: WafMode,
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
    #[serde(default)]
    first_observed_at: u64,
    #[serde(default)]
    last_observed_at: u64,
    methods: BTreeSet<String>,
    content_types: BTreeSet<String>,
    query_parameters: BTreeSet<String>,
    maximum_body_size: usize,
    #[serde(default)]
    pending_methods: BTreeMap<String, u64>,
    #[serde(default)]
    pending_content_types: BTreeMap<String, u64>,
    #[serde(default)]
    pending_query_parameters: BTreeMap<String, u64>,
    #[serde(default)]
    pending_body_size_buckets: BTreeMap<usize, u64>,
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
    access: Mutex<()>,
}

impl LocalUnknownThreatStore {
    pub fn open(path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let path = path.into();
        let _file_lock = StateFileLock::acquire(&path)?;
        read_state(&path)?;
        Ok(Self {
            path,
            access: Mutex::new(()),
        })
    }
}

impl UnknownThreatStore for LocalUnknownThreatStore {
    fn evaluate(
        &self,
        config: &UnknownThreatConfig,
        request: UnknownThreatRequest<'_>,
    ) -> anyhow::Result<UnknownThreatOutcome> {
        let _access = self
            .access
            .lock()
            .map_err(|_| anyhow::anyhow!("unknown-threat store lock poisoned"))?;
        let _file_lock = StateFileLock::acquire(&self.path)?;
        let mut state = read_state(&self.path)?;
        let outcome = evaluate_with_state(config, request, &mut state, "local");
        write_state(&self.path, &state)?;
        Ok(outcome)
    }
}

pub fn build_store(config: &UnknownThreatConfig) -> anyhow::Result<Box<dyn UnknownThreatStore>> {
    if !config.enabled || config.mode == UnknownThreatMode::Off {
        return Ok(Box::new(MemoryUnknownThreatStore::default()));
    }

    match config.backend {
        BehaviorBackend::Memory => Ok(Box::new(MemoryUnknownThreatStore::default())),
        BehaviorBackend::Local => Ok(Box::new(LocalUnknownThreatStore::open(&config.state_path)?)),
    }
}

pub fn cleanup_local_state(
    config: &UnknownThreatConfig,
    dry_run: bool,
) -> anyhow::Result<UnknownThreatCleanupReport> {
    cleanup_local_state_at(config, dry_run, unix_seconds_now())
}

pub fn shadow_report(events: &[SecurityEvent]) -> UnknownThreatShadowReport {
    let mut report = UnknownThreatShadowReport {
        total_events: events.len(),
        analyzed_events: 0,
        monitor_candidates: 0,
        would_block_candidates: 0,
        enforced_blocks: 0,
        gated_candidates: 0,
        single_signal_candidates: 0,
        new_baseline_candidates: 0,
        routes: Vec::new(),
        sample_request_ids: Vec::new(),
    };
    let mut routes = BTreeMap::<String, UnknownThreatRouteReport>::new();

    for event in events {
        let Some(outcome) = &event.decision.unknown_threats else {
            continue;
        };
        report.analyzed_events += 1;
        if outcome.score < outcome.threshold {
            continue;
        }

        report.monitor_candidates += 1;
        if outcome.would_block {
            report.would_block_candidates += 1;
        } else {
            report.gated_candidates += 1;
        }
        if outcome.action == WafAction::Block {
            report.enforced_blocks += 1;
        }
        if outcome.signals.len() == 1 {
            report.single_signal_candidates += 1;
        }
        if outcome
            .enforcement_gates
            .iter()
            .any(|gate| gate == "baseline_too_new")
        {
            report.new_baseline_candidates += 1;
        }
        if report.sample_request_ids.len() < 20 {
            report
                .sample_request_ids
                .push(event.decision.request_id.clone());
        }

        let route = routes
            .entry(outcome.route_shape.clone())
            .or_insert_with(|| UnknownThreatRouteReport {
                route_shape: outcome.route_shape.clone(),
                candidates: 0,
                would_block: 0,
                enforced_blocks: 0,
            });
        route.candidates += 1;
        route.would_block += usize::from(outcome.would_block);
        route.enforced_blocks += usize::from(outcome.action == WafAction::Block);
    }

    report.routes = routes.into_values().collect();
    report.routes.sort_by(|left, right| {
        right
            .candidates
            .cmp(&left.candidates)
            .then_with(|| left.route_shape.cmp(&right.route_shape))
    });
    report
}

pub fn unknown_threat_rule_match(outcome: &UnknownThreatOutcome) -> Option<RuleMatch> {
    if outcome.action == WafAction::Allow {
        return None;
    }

    Some(RuleMatch {
        rule_id: "SAUGRA-UNKNOWN-THREAT-001".to_string(),
        rule_name: "Route Request-Shape Anomaly".to_string(),
        category: "unknown_threat".to_string(),
        severity: if outcome.action == WafAction::Block {
            RuleSeverity::High
        } else {
            RuleSeverity::Medium
        },
        matched_target: RuleTarget::Headers,
        paranoia_level: 1,
        explanation: format!(
            "Route {} produced unknown-threat score {}/{} with {} independent signal(s). Would block: {}. Enforcement gates: {}.",
            outcome.route_shape,
            outcome.score,
            outcome.block_threshold,
            outcome.signals.len(),
            outcome.would_block,
            if outcome.enforcement_gates.is_empty() {
                "none".to_string()
            } else {
                outcome.enforcement_gates.join(", ")
            }
        ),
        owasp_category: Some("A06:2025-Insecure Design".to_string()),
    })
}

fn cleanup_local_state_at(
    config: &UnknownThreatConfig,
    dry_run: bool,
    now: u64,
) -> anyhow::Result<UnknownThreatCleanupReport> {
    let path = config.state_path.clone();
    if !path.exists() {
        return Ok(UnknownThreatCleanupReport {
            path,
            dry_run,
            state_found: false,
            routes_before: 0,
            routes_removed: 0,
            routes_after: 0,
        });
    }

    let _file_lock = StateFileLock::acquire(&path)?;
    let mut state = read_state(&path)?;
    let routes_before = state.routes.len();
    let retention_seconds = parse_duration_seconds(&config.retention).unwrap_or(30 * 86_400);
    let routes_removed = prune_stale_routes(&mut state, now, retention_seconds);
    if !dry_run && routes_removed > 0 {
        write_state(&path, &state)?;
    }

    Ok(UnknownThreatCleanupReport {
        path,
        dry_run,
        state_found: true,
        routes_before,
        routes_removed,
        routes_after: state.routes.len(),
    })
}

fn evaluate_with_state(
    config: &UnknownThreatConfig,
    request: UnknownThreatRequest<'_>,
    state: &mut UnknownThreatState,
    storage_backend: &str,
) -> UnknownThreatOutcome {
    evaluate_with_state_at(config, request, state, storage_backend, unix_seconds_now())
}

fn evaluate_with_state_at(
    config: &UnknownThreatConfig,
    request: UnknownThreatRequest<'_>,
    state: &mut UnknownThreatState,
    storage_backend: &str,
    now: u64,
) -> UnknownThreatOutcome {
    let retention_seconds = parse_duration_seconds(&config.retention).unwrap_or(30 * 86_400);
    let pruned_routes = prune_stale_routes(state, now, retention_seconds);
    let route_shape = route_shape(request.path);
    let route_policy = matching_route(&config.routes, request.path);
    let minimum_observations = route_policy
        .and_then(|route| route.minimum_observations)
        .unwrap_or(config.minimum_observations);
    let monitor_threshold = route_policy
        .and_then(|route| route.monitor_threshold)
        .unwrap_or(config.monitor_threshold);
    let block_threshold = route_policy
        .and_then(|route| route.block_threshold)
        .unwrap_or(config.block_threshold);
    let minimum_independent_signals = route_policy
        .and_then(|route| route.minimum_independent_signals)
        .unwrap_or(config.minimum_independent_signals);
    let minimum_baseline_age_seconds = route_policy
        .and_then(|route| route.minimum_baseline_age.as_deref())
        .and_then(parse_duration_seconds)
        .unwrap_or_else(|| {
            parse_duration_seconds(&config.minimum_baseline_age).unwrap_or(7 * 86_400)
        });
    let minimum_block_observations = route_policy
        .and_then(|route| route.minimum_block_observations)
        .unwrap_or(config.minimum_block_observations);
    let high_risk_route = route_policy.map(|route| route.high_risk).unwrap_or(false);
    let learning_enabled = route_policy
        .map(|route| route.learning_enabled)
        .unwrap_or(true);
    let route_excluded = path_matches_any(request.path, &config.excluded_paths);
    let analysis_active = config.enabled && config.mode != UnknownThreatMode::Off;
    let learning_source_trusted =
        client_matches_any(request.client_id, &config.trusted_learning_clients);
    let learning_source_allowed = !config.trusted_learning_only || learning_source_trusted;
    let can_allocate = state.routes.len() < config.max_routes;

    if analysis_active
        && !route_excluded
        && learning_enabled
        && request.eligible_for_learning
        && learning_source_allowed
        && !state.routes.contains_key(&route_shape)
        && can_allocate
    {
        state
            .routes
            .insert(route_shape.clone(), RouteBaseline::default());
    }

    let capacity_reached = !state.routes.contains_key(&route_shape) && !can_allocate;
    let baseline = state.routes.get_mut(&route_shape);
    let baseline_observations = baseline
        .as_ref()
        .map(|baseline| baseline.observations)
        .unwrap_or(0);
    let baseline_ready = baseline_observations >= minimum_observations;
    let baseline_age_seconds = baseline
        .as_ref()
        .map(|baseline| now.saturating_sub(baseline.first_observed_at))
        .unwrap_or(0);
    let mut signals = Vec::new();

    if config.enabled && !route_excluded && baseline_ready {
        if let Some(baseline) = baseline.as_ref() {
            let method = request.method.to_ascii_uppercase();
            if !baseline.methods.contains(&method) {
                signals.push(UnknownThreatSignal {
                    kind: "unseen_method".to_string(),
                    score_delta: config.signals.unseen_method.score,
                    explanation: format!(
                        "Method {method} was not present in the learned baseline for {route_shape}."
                    ),
                });
            }

            let content_type = normalized_content_type(request.content_type);
            if !content_type.is_empty() && !baseline.content_types.contains(&content_type) {
                signals.push(UnknownThreatSignal {
                    kind: "unseen_content_type".to_string(),
                    score_delta: config.signals.unseen_content_type.score,
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
                    score_delta: config.signals.unseen_query_parameter.score,
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
                    score_delta: config.signals.body_size_deviation.score,
                    explanation: format!(
                        "Body size {} exceeded the learned maximum {} by more than the configured multiplier.",
                        request.body_size, baseline.maximum_body_size
                    ),
                });
            }
        }
    }

    let score = signals.iter().map(|signal| signal.score_delta).sum();
    let active = analysis_active && !route_excluded;
    let monitor_candidate = active && baseline_ready && score >= monitor_threshold;
    let mut enforcement_gates = Vec::new();
    if !high_risk_route {
        enforcement_gates.push("route_not_high_risk".to_string());
    }
    if baseline_observations < minimum_block_observations {
        enforcement_gates.push("insufficient_observations".to_string());
    }
    if baseline_age_seconds < minimum_baseline_age_seconds {
        enforcement_gates.push("baseline_too_new".to_string());
    }
    if signals.len() < minimum_independent_signals {
        enforcement_gates.push("insufficient_independent_signals".to_string());
    }
    if score < block_threshold {
        enforcement_gates.push("score_below_block_threshold".to_string());
    }
    let block_eligible =
        active && baseline_ready && high_risk_route && enforcement_gates.is_empty();
    let would_block = block_eligible;
    let action = if would_block
        && config.mode == UnknownThreatMode::Block
        && matches!(request.server_mode, WafMode::Block | WafMode::Strict)
    {
        WafAction::Block
    } else if monitor_candidate {
        WafAction::Monitor
    } else {
        WafAction::Allow
    };

    if active
        && !route_excluded
        && learning_enabled
        && request.eligible_for_learning
        && learning_source_allowed
        && signals.is_empty()
    {
        if let Some(baseline) = baseline {
            learn(baseline, &request, config, now);
        }
    }

    let baseline_tracked = state.routes.contains_key(&route_shape);

    UnknownThreatOutcome {
        enabled: config.enabled,
        action,
        score,
        threshold: monitor_threshold,
        block_threshold,
        route_shape,
        baseline_observations,
        baseline_ready,
        baseline_age_seconds,
        minimum_block_observations,
        minimum_baseline_age_seconds,
        minimum_independent_signals,
        high_risk_route,
        would_block,
        block_eligible,
        enforcement_gates,
        baseline_tracked,
        learning_enabled,
        learning_source_trusted,
        learning_source_allowed,
        route_excluded,
        capacity_reached,
        pruned_routes,
        storage_backend: storage_backend.to_string(),
        signals,
    }
}

fn learn(
    baseline: &mut RouteBaseline,
    request: &UnknownThreatRequest<'_>,
    config: &UnknownThreatConfig,
    now: u64,
) {
    if baseline.first_observed_at == 0 {
        baseline.first_observed_at = now;
    }
    baseline.last_observed_at = now;
    baseline.observations = baseline.observations.saturating_add(1);
    observe_feature(
        &mut baseline.methods,
        &mut baseline.pending_methods,
        request.method.to_ascii_uppercase(),
        config.promotion_observations,
        config.max_methods_per_route,
    );

    let content_type = normalized_content_type(request.content_type);
    if !content_type.is_empty() {
        observe_feature(
            &mut baseline.content_types,
            &mut baseline.pending_content_types,
            content_type,
            config.promotion_observations,
            config.max_content_types_per_route,
        );
    }
    for parameter in query_parameter_names(request.query) {
        observe_feature(
            &mut baseline.query_parameters,
            &mut baseline.pending_query_parameters,
            parameter,
            config.promotion_observations,
            config.max_query_parameters_per_route,
        );
    }
    let body_bucket = body_size_bucket(request.body_size);
    if body_bucket > 0 && baseline.maximum_body_size < body_bucket {
        if !baseline
            .pending_body_size_buckets
            .contains_key(&body_bucket)
            && baseline.pending_body_size_buckets.len() >= 32
        {
            return;
        }
        let count = baseline
            .pending_body_size_buckets
            .entry(body_bucket)
            .or_default();
        *count = count.saturating_add(1);
        if *count >= config.promotion_observations {
            baseline.maximum_body_size = body_bucket;
            baseline
                .pending_body_size_buckets
                .retain(|bucket, _| *bucket > body_bucket);
        }
    }
}

fn observe_feature(
    active: &mut BTreeSet<String>,
    pending: &mut BTreeMap<String, u64>,
    value: String,
    promotion_observations: u64,
    maximum_active: usize,
) {
    if active.contains(&value) || active.len() >= maximum_active {
        return;
    }
    if !pending.contains_key(&value) && pending.len() >= maximum_active.saturating_mul(2) {
        return;
    }

    let count = pending.entry(value.clone()).or_default();
    *count = count.saturating_add(1);
    if *count >= promotion_observations {
        pending.remove(&value);
        active.insert(value);
    }
}

fn body_size_bucket(body_size: usize) -> usize {
    if body_size == 0 {
        0
    } else {
        body_size.checked_next_power_of_two().unwrap_or(usize::MAX)
    }
}

fn prune_stale_routes(state: &mut UnknownThreatState, now: u64, retention_seconds: u64) -> usize {
    for baseline in state.routes.values_mut() {
        if baseline.first_observed_at == 0 {
            baseline.first_observed_at = now;
        }
        if baseline.last_observed_at == 0 {
            baseline.last_observed_at = now;
        }
    }

    let before = state.routes.len();
    state
        .routes
        .retain(|_, baseline| now.saturating_sub(baseline.last_observed_at) <= retention_seconds);
    before.saturating_sub(state.routes.len())
}

fn matching_route<'a>(
    routes: &'a [UnknownThreatRouteConfig],
    path: &str,
) -> Option<&'a UnknownThreatRouteConfig> {
    routes
        .iter()
        .filter(|route| path_matches_route(path, &route.path))
        .max_by_key(|route| route.path.trim_end_matches('/').len())
}

fn path_matches_any(path: &str, configured_paths: &[String]) -> bool {
    configured_paths
        .iter()
        .any(|configured_path| path_matches_route(path, configured_path))
}

fn path_matches_route(path: &str, route_path: &str) -> bool {
    let route_path = route_path.trim().trim_end_matches('/');
    if route_path.is_empty() {
        return true;
    }

    path == route_path
        || path
            .strip_prefix(route_path)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn client_matches_any(client_id: &str, configured_clients: &[String]) -> bool {
    configured_clients
        .iter()
        .any(|configured| client_matches(client_id, configured))
}

fn client_matches(client_id: &str, configured: &str) -> bool {
    if configured.trim() == client_id {
        return true;
    }
    let Ok(IpAddr::V4(client_ip)) = client_id.parse::<IpAddr>() else {
        return false;
    };
    ipv4_cidr_contains(configured.trim(), client_ip)
}

fn ipv4_cidr_contains(cidr: &str, ip: Ipv4Addr) -> bool {
    let Some((network, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(network) = network.parse::<Ipv4Addr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    if prefix > 32 {
        return false;
    }

    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    u32::from(ip) & mask == u32::from(network) & mask
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
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read unknown-threat state {}", path.display()))?;
    serde_json::from_str(&contents).with_context(|| {
        format!(
            "unknown-threat state is not valid JSON at {}",
            path.display()
        )
    })
}

fn write_state(path: &Path, state: &UnknownThreatState) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create unknown-threat state directory {}",
                parent.display()
            )
        })?;
    }
    let temporary_path = temporary_state_path(path);
    fs::write(&temporary_path, serde_json::to_vec_pretty(state)?).with_context(|| {
        format!(
            "failed to write temporary unknown-threat state {}",
            temporary_path.display()
        )
    })?;
    if let Err(error) = fs::rename(&temporary_path, path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error)
            .with_context(|| format!("failed to replace unknown-threat state {}", path.display()));
    }
    Ok(())
}

struct StateFileLock {
    path: PathBuf,
}

impl StateFileLock {
    fn acquire(state_path: &Path) -> anyhow::Result<Self> {
        let path = lock_path(state_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create unknown-threat lock directory {}",
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
                Err(error) => return Err(error.into()),
            }
        }

        Err(anyhow::anyhow!(
            "timed out waiting for unknown-threat state lock {}",
            path.display()
        ))
    }
}

impl Drop for StateFileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn lock_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.lock", path.display()))
}

fn lock_is_stale(path: &Path) -> bool {
    path.metadata()
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
        .is_some_and(|age| age.as_secs() >= 30)
}

fn temporary_state_path(path: &Path) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    PathBuf::from(format!("{}.{}.tmp", path.display(), nonce))
}

fn parse_duration_seconds(value: &str) -> Option<u64> {
    let trimmed = value.trim().to_ascii_lowercase();
    let split_at = trimmed.find(|character: char| !character.is_ascii_digit())?;
    let (number, unit) = trimmed.split_at(split_at);
    let number = number.parse::<u64>().ok()?;
    if number == 0 {
        return None;
    }

    let multiplier = match unit.trim() {
        "s" | "sec" | "secs" | "second" | "seconds" => 1,
        "m" | "min" | "mins" | "minute" | "minutes" => 60,
        "h" | "hr" | "hrs" | "hour" | "hours" => 60 * 60,
        "d" | "day" | "days" => 24 * 60 * 60,
        _ => return None,
    };

    number.checked_mul(multiplier)
}

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn default_true() -> bool {
    true
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
            promotion_observations: 1,
            signals: crate::config::UnknownThreatSignals {
                unseen_method: crate::config::UnknownThreatSignalPolicy { score: 10 },
                unseen_content_type: crate::config::UnknownThreatSignalPolicy { score: 15 },
                unseen_query_parameter: crate::config::UnknownThreatSignalPolicy { score: 10 },
                body_size_deviation: crate::config::UnknownThreatSignalPolicy { score: 15 },
            },
            ..UnknownThreatConfig::default()
        }
    }

    fn request<'a>(method: &'a str, path: &'a str) -> UnknownThreatRequest<'a> {
        UnknownThreatRequest {
            path,
            client_id: "203.0.113.10",
            method,
            content_type: "application/json",
            query: "page=1",
            body_size: 20,
            eligible_for_learning: true,
            server_mode: WafMode::Monitor,
        }
    }

    #[test]
    fn disabled_store_does_not_touch_local_state_path() {
        let temp_dir = tempfile::tempdir().unwrap();
        let blocked_parent = temp_dir.path().join("not-a-directory");
        fs::write(&blocked_parent, b"file").unwrap();

        let mut config = config();
        config.enabled = false;
        config.backend = BehaviorBackend::Local;
        config.state_path = blocked_parent.join("unknown-threats.json");

        let store = build_store(&config).unwrap();
        let outcome = store
            .evaluate(&config, request("GET", "/users/42"))
            .unwrap();

        assert!(!outcome.enabled);
        assert_eq!(outcome.storage_backend, "memory");
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

    #[test]
    fn excluded_routes_are_not_learned_or_monitored() {
        let store = MemoryUnknownThreatStore::default();
        let mut config = config();
        config.excluded_paths = vec!["/health".to_string()];

        let outcome = store
            .evaluate(&config, request("GET", "/health/ready"))
            .unwrap();

        assert!(outcome.route_excluded);
        assert!(!outcome.baseline_tracked);
        assert_eq!(outcome.action, WafAction::Allow);
    }

    #[test]
    fn route_override_can_disable_learning() {
        let store = MemoryUnknownThreatStore::default();
        let mut config = config();
        config.routes = vec![UnknownThreatRouteConfig {
            path: "/uploads".to_string(),
            learning_enabled: false,
            minimum_observations: Some(1),
            monitor_threshold: Some(5),
            ..UnknownThreatRouteConfig::default()
        }];

        let outcome = store
            .evaluate(&config, request("POST", "/uploads/42"))
            .unwrap();

        assert!(!outcome.learning_enabled);
        assert!(!outcome.baseline_tracked);
    }

    #[test]
    fn route_override_uses_longest_matching_policy() {
        let store = MemoryUnknownThreatStore::default();
        let mut config = config();
        config.routes = vec![
            UnknownThreatRouteConfig {
                path: "/api".to_string(),
                learning_enabled: true,
                minimum_observations: Some(10),
                monitor_threshold: Some(30),
                ..UnknownThreatRouteConfig::default()
            },
            UnknownThreatRouteConfig {
                path: "/api/admin".to_string(),
                learning_enabled: true,
                minimum_observations: Some(1),
                monitor_threshold: Some(5),
                ..UnknownThreatRouteConfig::default()
            },
        ];

        store
            .evaluate(&config, request("GET", "/api/admin/42"))
            .unwrap();
        let outcome = store
            .evaluate(&config, request("DELETE", "/api/admin/43"))
            .unwrap();

        assert_eq!(outcome.threshold, 5);
        assert!(outcome.baseline_ready);
        assert_eq!(outcome.action, WafAction::Monitor);
    }

    #[test]
    fn route_cardinality_is_bounded() {
        let store = MemoryUnknownThreatStore::default();
        let mut config = config();
        config.max_routes = 1;

        store.evaluate(&config, request("GET", "/first")).unwrap();
        let outcome = store.evaluate(&config, request("GET", "/second")).unwrap();

        assert!(outcome.capacity_reached);
        assert!(!outcome.baseline_tracked);
    }

    #[test]
    fn stale_routes_are_pruned_before_allocating_capacity() {
        let now = unix_seconds_now();
        let mut state = UnknownThreatState::default();
        state.routes.insert(
            "/stale".to_string(),
            RouteBaseline {
                observations: 2,
                first_observed_at: now.saturating_sub(10),
                last_observed_at: now.saturating_sub(10),
                ..RouteBaseline::default()
            },
        );
        let mut config = config();
        config.retention = "1s".to_string();
        config.max_routes = 1;

        let outcome =
            evaluate_with_state(&config, request("GET", "/current"), &mut state, "memory");

        assert_eq!(outcome.pruned_routes, 1);
        assert!(outcome.baseline_tracked);
        assert!(state.routes.contains_key("/current"));
    }

    #[test]
    fn legacy_state_timestamps_are_migrated_without_data_loss() {
        let mut state = UnknownThreatState::default();
        state.routes.insert(
            "/legacy".to_string(),
            RouteBaseline {
                observations: 3,
                ..RouteBaseline::default()
            },
        );

        assert_eq!(prune_stale_routes(&mut state, 100, 1), 0);
        let baseline = state.routes.get("/legacy").unwrap();
        assert_eq!(baseline.first_observed_at, 100);
        assert_eq!(baseline.last_observed_at, 100);
    }

    #[test]
    fn older_event_outcomes_remain_deserializable() {
        let outcome: UnknownThreatOutcome = serde_json::from_str(
            r#"{
                "enabled": true,
                "action": "monitor",
                "score": 20,
                "threshold": 20,
                "route_shape": "/users/:id",
                "baseline_observations": 100,
                "baseline_ready": true,
                "storage_backend": "local",
                "signals": []
            }"#,
        )
        .unwrap();

        assert!(outcome.learning_enabled);
        assert!(!outcome.capacity_reached);
    }

    #[test]
    fn cleanup_reports_and_removes_stale_local_routes() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("unknown-threats.json");
        let mut config = config();
        config.backend = BehaviorBackend::Local;
        config.state_path = path.clone();
        config.retention = "10s".to_string();
        let mut state = UnknownThreatState::default();
        state.routes.insert(
            "/stale".to_string(),
            RouteBaseline {
                observations: 10,
                first_observed_at: 1,
                last_observed_at: 1,
                ..RouteBaseline::default()
            },
        );
        state.routes.insert(
            "/fresh".to_string(),
            RouteBaseline {
                observations: 10,
                first_observed_at: 95,
                last_observed_at: 95,
                ..RouteBaseline::default()
            },
        );
        write_state(&path, &state).unwrap();

        let preview = cleanup_local_state_at(&config, true, 100).unwrap();
        assert_eq!(preview.routes_removed, 1);
        assert_eq!(read_state(&path).unwrap().routes.len(), 2);

        let executed = cleanup_local_state_at(&config, false, 100).unwrap();
        assert_eq!(executed.routes_before, 2);
        assert_eq!(executed.routes_removed, 1);
        assert_eq!(executed.routes_after, 1);
        assert!(read_state(&path).unwrap().routes.contains_key("/fresh"));
    }

    #[test]
    fn cleanup_reports_missing_state_without_creating_it() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut config = config();
        config.backend = BehaviorBackend::Local;
        config.state_path = temp_dir.path().join("missing.json");

        let report = cleanup_local_state_at(&config, false, 100).unwrap();

        assert!(!report.state_found);
        assert!(!config.state_path.exists());
    }

    #[test]
    fn local_store_reloads_state_changed_by_cleanup() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("unknown-threats.json");
        let mut config = config();
        config.backend = BehaviorBackend::Local;
        config.state_path = path.clone();
        config.retention = "1s".to_string();
        let store = LocalUnknownThreatStore::open(&path).unwrap();

        store.evaluate(&config, request("GET", "/old")).unwrap();
        let mut state = read_state(&path).unwrap();
        let baseline = state.routes.get_mut("/old").unwrap();
        baseline.first_observed_at = 1;
        baseline.last_observed_at = 1;
        write_state(&path, &state).unwrap();
        cleanup_local_state_at(&config, false, 100).unwrap();

        store.evaluate(&config, request("GET", "/current")).unwrap();
        let state = read_state(&path).unwrap();
        assert!(!state.routes.contains_key("/old"));
        assert!(state.routes.contains_key("/current"));
    }

    #[test]
    fn shadow_mode_reports_would_block_without_enforcement() {
        let mut config = blocking_config(UnknownThreatMode::Shadow);
        let mut state = mature_state();
        let outcome = evaluate_with_state_at(
            &config,
            anomalous_request(WafMode::Block),
            &mut state,
            "memory",
            1_000_000,
        );

        assert!(outcome.would_block);
        assert!(outcome.block_eligible);
        assert_eq!(outcome.action, WafAction::Monitor);

        config.mode = UnknownThreatMode::Block;
        let outcome = evaluate_with_state_at(
            &config,
            anomalous_request(WafMode::Block),
            &mut state,
            "memory",
            1_000_000,
        );
        assert_eq!(outcome.action, WafAction::Block);
    }

    #[test]
    fn blocking_requires_high_risk_route_age_volume_and_two_signals() {
        let config = blocking_config(UnknownThreatMode::Block);
        let mut state = mature_state();

        let single_signal = UnknownThreatRequest {
            content_type: "application/json",
            ..anomalous_request(WafMode::Block)
        };
        let outcome =
            evaluate_with_state_at(&config, single_signal, &mut state, "memory", 1_000_000);
        assert_eq!(outcome.action, WafAction::Monitor);
        assert!(outcome
            .enforcement_gates
            .contains(&"insufficient_independent_signals".to_string()));

        let outcome = evaluate_with_state_at(
            &config,
            anomalous_request(WafMode::Block),
            &mut state,
            "memory",
            100,
        );
        assert_eq!(outcome.action, WafAction::Monitor);
        assert!(outcome
            .enforcement_gates
            .contains(&"baseline_too_new".to_string()));
    }

    #[test]
    fn ordinary_routes_never_auto_block() {
        let mut config = blocking_config(UnknownThreatMode::Block);
        config.routes.clear();
        let mut state = mature_state();

        let outcome = evaluate_with_state_at(
            &config,
            anomalous_request(WafMode::Block),
            &mut state,
            "memory",
            1_000_000,
        );

        assert_eq!(outcome.action, WafAction::Monitor);
        assert!(!outcome.block_eligible);
        assert!(outcome
            .enforcement_gates
            .contains(&"route_not_high_risk".to_string()));
    }

    #[test]
    fn trusted_only_learning_rejects_untrusted_sources() {
        let store = MemoryUnknownThreatStore::default();
        let mut config = config();
        config.trusted_learning_only = true;
        config.trusted_learning_clients = vec!["10.0.0.0/8".to_string()];

        let untrusted = store
            .evaluate(&config, request("GET", "/users/42"))
            .unwrap();
        assert!(!untrusted.learning_source_allowed);
        assert!(!untrusted.baseline_tracked);

        let mut trusted_request = request("GET", "/users/42");
        trusted_request.client_id = "10.1.2.3";
        let trusted = store.evaluate(&config, trusted_request).unwrap();
        assert!(trusted.learning_source_trusted);
        assert!(trusted.baseline_tracked);
    }

    #[test]
    fn novel_features_require_repeated_promotion_and_are_bounded() {
        let mut config = config();
        config.minimum_observations = 10;
        config.promotion_observations = 3;
        config.max_methods_per_route = 1;
        let mut state = UnknownThreatState::default();

        for _ in 0..2 {
            evaluate_with_state_at(
                &config,
                request("GET", "/bounded"),
                &mut state,
                "memory",
                100,
            );
        }
        assert!(state.routes["/bounded"].methods.is_empty());

        evaluate_with_state_at(
            &config,
            request("GET", "/bounded"),
            &mut state,
            "memory",
            100,
        );
        assert!(state.routes["/bounded"].methods.contains("GET"));

        for method in ["POST", "PUT", "PATCH"] {
            for _ in 0..3 {
                evaluate_with_state_at(
                    &config,
                    request(method, "/bounded"),
                    &mut state,
                    "memory",
                    100,
                );
            }
        }
        assert_eq!(state.routes["/bounded"].methods.len(), 1);
    }

    #[test]
    fn shadow_report_surfaces_false_positive_review_pressure() {
        let config = blocking_config(UnknownThreatMode::Shadow);
        let mut state = mature_state();
        let outcome = evaluate_with_state_at(
            &config,
            anomalous_request(WafMode::Block),
            &mut state,
            "memory",
            1_000_000,
        );
        let decision = crate::decision::WafDecision::from_matches(
            "shadow-request".to_string(),
            WafMode::Monitor,
            Vec::new(),
            5,
        )
        .with_unknown_threats(outcome);
        let event = SecurityEvent::new("DELETE", "/admin/42", "", decision);

        let report = shadow_report(&[event]);

        assert_eq!(report.monitor_candidates, 1);
        assert_eq!(report.would_block_candidates, 1);
        assert_eq!(report.enforced_blocks, 0);
        assert_eq!(report.routes[0].route_shape, "/admin/:id");
        assert_eq!(report.sample_request_ids, vec!["shadow-request"]);
    }

    fn blocking_config(mode: UnknownThreatMode) -> UnknownThreatConfig {
        UnknownThreatConfig {
            enabled: true,
            mode,
            minimum_observations: 10,
            monitor_threshold: 10,
            block_threshold: 20,
            minimum_independent_signals: 2,
            minimum_baseline_age: "1d".to_string(),
            minimum_block_observations: 100,
            promotion_observations: 1,
            routes: vec![UnknownThreatRouteConfig {
                path: "/admin".to_string(),
                high_risk: true,
                ..UnknownThreatRouteConfig::default()
            }],
            ..config()
        }
    }

    fn mature_state() -> UnknownThreatState {
        let mut state = UnknownThreatState::default();
        state.routes.insert(
            "/admin/:id".to_string(),
            RouteBaseline {
                observations: 1_000,
                first_observed_at: 1,
                last_observed_at: 999_999,
                methods: BTreeSet::from(["GET".to_string()]),
                content_types: BTreeSet::from(["application/json".to_string()]),
                query_parameters: BTreeSet::from(["page".to_string()]),
                maximum_body_size: 32,
                ..RouteBaseline::default()
            },
        );
        state
    }

    fn anomalous_request(server_mode: WafMode) -> UnknownThreatRequest<'static> {
        UnknownThreatRequest {
            path: "/admin/42",
            client_id: "203.0.113.10",
            method: "DELETE",
            content_type: "text/plain",
            query: "page=1",
            body_size: 20,
            eligible_for_learning: true,
            server_mode,
        }
    }
}
