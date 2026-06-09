use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{
    config::{
        BehaviorBackend, BehaviorCategoryOverrideConfig, BehaviorConfig, BehaviorMode,
        BehaviorRouteOverrideConfig, WafMode,
    },
    decision::WafAction,
    rules::{RuleMatch, RuleSeverity, RuleTarget},
};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct BehaviorOutcome {
    pub enabled: bool,
    pub action: WafAction,
    pub score: u16,
    pub monitor_threshold: u16,
    pub block_threshold: u16,
    pub score_window_seconds: u64,
    pub decay_window_seconds: u64,
    pub storage_backend: String,
    pub contributors: Vec<BehaviorContributor>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct BehaviorContributor {
    pub reason: String,
    pub score_delta: u16,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct BehaviorRequest<'a> {
    pub client_id: &'a str,
    pub path: &'a str,
    pub rule_matches: &'a [RuleMatch],
    pub server_mode: WafMode,
}

pub trait BehaviorStore: Send + Sync {
    fn evaluate(
        &self,
        config: &BehaviorConfig,
        request: BehaviorRequest<'_>,
    ) -> anyhow::Result<BehaviorOutcome>;
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct BehaviorState {
    clients: BTreeMap<String, ClientBehaviorState>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct ClientBehaviorState {
    entries: Vec<BehaviorEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct BehaviorEntry {
    timestamp_seconds: u64,
    reason: String,
    score_delta: u16,
    #[serde(default)]
    path: String,
}

#[derive(Debug)]
pub struct MemoryBehaviorStore {
    state: Mutex<BehaviorState>,
}

impl MemoryBehaviorStore {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(BehaviorState::default()),
        }
    }
}

impl Default for MemoryBehaviorStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BehaviorStore for MemoryBehaviorStore {
    fn evaluate(
        &self,
        config: &BehaviorConfig,
        request: BehaviorRequest<'_>,
    ) -> anyhow::Result<BehaviorOutcome> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("behavior store lock poisoned"))?;
        Ok(evaluate_with_state(config, request, &mut state, "memory"))
    }
}

#[derive(Debug)]
pub struct LocalBehaviorStore {
    path: PathBuf,
    state: Mutex<BehaviorState>,
}

impl LocalBehaviorStore {
    pub fn open(path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let path = path.into();
        let state = read_state(&path)?;
        Ok(Self {
            path,
            state: Mutex::new(state),
        })
    }
}

impl BehaviorStore for LocalBehaviorStore {
    fn evaluate(
        &self,
        config: &BehaviorConfig,
        request: BehaviorRequest<'_>,
    ) -> anyhow::Result<BehaviorOutcome> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("behavior store lock poisoned"))?;
        let outcome = evaluate_with_state(config, request, &mut state, "local");
        write_state(&self.path, &state)?;
        Ok(outcome)
    }
}

pub fn build_store(config: &BehaviorConfig) -> anyhow::Result<Box<dyn BehaviorStore>> {
    match config.backend {
        BehaviorBackend::Memory => Ok(Box::new(MemoryBehaviorStore::new())),
        BehaviorBackend::Local => Ok(Box::new(LocalBehaviorStore::open(&config.state_path)?)),
    }
}

pub fn reset_client(path: &Path, client_id: &str) -> anyhow::Result<bool> {
    let mut state = read_state(path)?;
    let removed = state.clients.remove(client_id).is_some();
    if removed {
        write_state(path, &state)?;
    }
    Ok(removed)
}

pub fn behavior_rule_match(outcome: &BehaviorOutcome) -> Option<RuleMatch> {
    if outcome.action == WafAction::Allow {
        return None;
    }

    let contributor_summary = if outcome.contributors.is_empty() {
        "No behavior contributors were recorded.".to_string()
    } else {
        outcome
            .contributors
            .iter()
            .map(|contributor| {
                if contributor.path.is_empty() {
                    format!("{} (+{})", contributor.reason, contributor.score_delta)
                } else {
                    format!(
                        "{} at {} (+{})",
                        contributor.reason, contributor.path, contributor.score_delta
                    )
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    };

    Some(RuleMatch {
        rule_id: "SAUGRA-BEHAVIOR-001".to_string(),
        rule_name: "Behavior Score Threshold".to_string(),
        category: "behavior_abuse".to_string(),
        severity: if outcome.action == WafAction::Block {
            RuleSeverity::High
        } else {
            RuleSeverity::Medium
        },
        matched_target: RuleTarget::Headers,
        paranoia_level: 1,
        explanation: format!(
            "Client behavior score {} reached the {:?} threshold. Contributors: {}.",
            outcome.score, outcome.action, contributor_summary
        ),
        owasp_category: Some("A06:2025-Insecure Design".to_string()),
    })
}

fn evaluate_with_state(
    config: &BehaviorConfig,
    request: BehaviorRequest<'_>,
    state: &mut BehaviorState,
    storage_backend: &str,
) -> BehaviorOutcome {
    let now = unix_seconds_now();
    let score_window_seconds = parse_duration_seconds(&config.score_window).unwrap_or(600);
    let decay_window_seconds = parse_duration_seconds(&config.decay_window).unwrap_or(1_800);
    let thresholds = select_thresholds(config, request.path);
    let new_contributors = contributors_for_request(config, &request);
    let client_state = state
        .clients
        .entry(request.client_id.to_string())
        .or_default();

    client_state.entries.retain(|entry| {
        now.saturating_sub(entry.timestamp_seconds)
            <= score_window_seconds.saturating_add(decay_window_seconds)
    });

    for contributor in &new_contributors {
        client_state.entries.push(BehaviorEntry {
            timestamp_seconds: now,
            reason: contributor.reason.clone(),
            score_delta: contributor.score_delta,
            path: contributor.path.clone(),
        });
    }

    let window_start = now.saturating_sub(score_window_seconds);
    let contributors = client_state
        .entries
        .iter()
        .filter(|entry| entry.timestamp_seconds >= window_start)
        .map(|entry| BehaviorContributor {
            reason: entry.reason.clone(),
            score_delta: entry.score_delta,
            path: entry.path.clone(),
        })
        .collect::<Vec<_>>();
    let score = contributors
        .iter()
        .map(|contributor| contributor.score_delta)
        .sum();
    let action = behavior_action(
        config,
        request.server_mode,
        score,
        thresholds.monitor_threshold,
        thresholds.block_threshold,
    );

    BehaviorOutcome {
        enabled: config.enabled,
        action,
        score,
        monitor_threshold: thresholds.monitor_threshold,
        block_threshold: thresholds.block_threshold,
        score_window_seconds,
        decay_window_seconds,
        storage_backend: storage_backend.to_string(),
        contributors,
    }
}

fn behavior_action(
    config: &BehaviorConfig,
    server_mode: WafMode,
    score: u16,
    monitor_threshold: u16,
    block_threshold: u16,
) -> WafAction {
    if !config.enabled || config.mode == BehaviorMode::Off || server_mode == WafMode::Off {
        return WafAction::Allow;
    }

    if config.mode == BehaviorMode::Block && score >= block_threshold {
        WafAction::Block
    } else if score >= monitor_threshold {
        WafAction::Monitor
    } else {
        WafAction::Allow
    }
}

struct BehaviorThresholds {
    monitor_threshold: u16,
    block_threshold: u16,
}

fn select_thresholds(config: &BehaviorConfig, path: &str) -> BehaviorThresholds {
    let mut thresholds = BehaviorThresholds {
        monitor_threshold: config.monitor_threshold,
        block_threshold: config.block_threshold,
    };

    if let Some(route) = matching_behavior_route(&config.route_overrides, path) {
        thresholds.monitor_threshold = route
            .monitor_threshold
            .unwrap_or(thresholds.monitor_threshold);
        thresholds.block_threshold = route.block_threshold.unwrap_or(thresholds.block_threshold);
    }

    thresholds
}

fn matching_behavior_route<'a>(
    routes: &'a [BehaviorRouteOverrideConfig],
    path: &str,
) -> Option<&'a BehaviorRouteOverrideConfig> {
    routes
        .iter()
        .filter(|route| path_matches_route(path, &route.path))
        .max_by_key(|route| route.path.trim_end_matches('/').len())
}

fn contributors_for_request(
    config: &BehaviorConfig,
    request: &BehaviorRequest<'_>,
) -> Vec<BehaviorContributor> {
    let mut contributors = Vec::new();

    if path_matches_any(request.path, &config.probe_paths)
        && !path_matches_any(request.path, &config.probe_path_exclusions)
    {
        contributors.push(BehaviorContributor {
            reason: "scanner_path_probe".to_string(),
            score_delta: 15,
            path: request.path.to_string(),
        });
    }

    for rule_match in request.rule_matches {
        let score_delta = category_score_delta(&config.category_overrides, &rule_match.category)
            .unwrap_or_else(|| rule_match.severity.anomaly_points());
        contributors.push(BehaviorContributor {
            reason: format!("rule_match:{}", rule_match.category),
            score_delta,
            path: request.path.to_string(),
        });
    }

    contributors
}

fn category_score_delta(
    categories: &[BehaviorCategoryOverrideConfig],
    category: &str,
) -> Option<u16> {
    categories
        .iter()
        .find(|override_config| override_config.category == category)
        .and_then(|override_config| override_config.score_delta)
}

fn path_matches_any(path: &str, configured_paths: &[String]) -> bool {
    let path = path.to_ascii_lowercase();
    configured_paths.iter().any(|probe| {
        let probe = probe.trim().trim_end_matches('/').to_ascii_lowercase();
        path == probe || path.starts_with(&format!("{probe}/"))
    })
}

fn path_matches_route(path: &str, route_path: &str) -> bool {
    let route_path = route_path.trim_end_matches('/');

    if route_path.is_empty() {
        return true;
    }

    path == route_path
        || path
            .strip_prefix(route_path)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn read_state(path: &Path) -> anyhow::Result<BehaviorState> {
    if !path.exists() {
        return Ok(BehaviorState::default());
    }

    let contents = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&contents)?)
}

fn write_state(path: &Path, state: &BehaviorState) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(state)?)?;
    Ok(())
}

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn parse_duration_seconds(value: &str) -> Option<u64> {
    let trimmed = value.trim().to_ascii_lowercase();
    let split_at = trimmed.find(|c: char| !c.is_ascii_digit())?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BehaviorConfig;

    #[test]
    fn accumulates_behavior_score_in_memory() {
        let store = MemoryBehaviorStore::new();
        let config = BehaviorConfig {
            enabled: true,
            monitor_threshold: 10,
            block_threshold: 20,
            ..BehaviorConfig::default()
        };

        let outcome = store
            .evaluate(
                &config,
                BehaviorRequest {
                    client_id: "203.0.113.10",
                    path: "/.env",
                    rule_matches: &[],
                    server_mode: WafMode::Monitor,
                },
            )
            .unwrap();

        assert_eq!(outcome.score, 15);
        assert_eq!(outcome.action, WafAction::Monitor);
    }

    #[test]
    fn blocks_when_behavior_mode_is_block_and_score_reaches_threshold() {
        let store = MemoryBehaviorStore::new();
        let config = BehaviorConfig {
            enabled: true,
            mode: BehaviorMode::Block,
            monitor_threshold: 10,
            block_threshold: 20,
            ..BehaviorConfig::default()
        };

        for _ in 0..2 {
            store
                .evaluate(
                    &config,
                    BehaviorRequest {
                        client_id: "203.0.113.10",
                        path: "/.env",
                        rule_matches: &[],
                        server_mode: WafMode::Block,
                    },
                )
                .unwrap();
        }

        let outcome = store
            .evaluate(
                &config,
                BehaviorRequest {
                    client_id: "203.0.113.10",
                    path: "/.git/config",
                    rule_matches: &[],
                    server_mode: WafMode::Block,
                },
            )
            .unwrap();

        assert_eq!(outcome.action, WafAction::Block);
        assert!(outcome.score >= 20);
    }

    #[test]
    fn local_store_survives_restart() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("behavior.json");
        let config = BehaviorConfig {
            enabled: true,
            backend: BehaviorBackend::Local,
            state_path: path.clone(),
            monitor_threshold: 20,
            block_threshold: 80,
            ..BehaviorConfig::default()
        };

        LocalBehaviorStore::open(&path)
            .unwrap()
            .evaluate(
                &config,
                BehaviorRequest {
                    client_id: "203.0.113.10",
                    path: "/.env",
                    rule_matches: &[],
                    server_mode: WafMode::Monitor,
                },
            )
            .unwrap();

        let outcome = LocalBehaviorStore::open(&path)
            .unwrap()
            .evaluate(
                &config,
                BehaviorRequest {
                    client_id: "203.0.113.10",
                    path: "/.git/config",
                    rule_matches: &[],
                    server_mode: WafMode::Monitor,
                },
            )
            .unwrap();

        assert_eq!(outcome.action, WafAction::Monitor);
        assert!(outcome.score >= 20);
    }

    #[test]
    fn reset_client_removes_only_matching_local_behavior_state() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("behavior.json");
        let config = BehaviorConfig {
            enabled: true,
            backend: BehaviorBackend::Local,
            state_path: path.clone(),
            ..BehaviorConfig::default()
        };

        for client_id in ["203.0.113.10", "203.0.113.11"] {
            LocalBehaviorStore::open(&path)
                .unwrap()
                .evaluate(
                    &config,
                    BehaviorRequest {
                        client_id,
                        path: "/.env",
                        rule_matches: &[],
                        server_mode: WafMode::Monitor,
                    },
                )
                .unwrap();
        }

        assert!(reset_client(&path, "203.0.113.10").unwrap());
        assert!(!reset_client(&path, "203.0.113.12").unwrap());
        let state = read_state(&path).unwrap();

        assert!(!state.clients.contains_key("203.0.113.10"));
        assert!(state.clients.contains_key("203.0.113.11"));
    }

    #[test]
    fn route_override_can_lower_thresholds_for_sensitive_paths() {
        let store = MemoryBehaviorStore::new();
        let config = BehaviorConfig {
            enabled: true,
            monitor_threshold: 80,
            block_threshold: 100,
            route_overrides: vec![BehaviorRouteOverrideConfig {
                path: "/login".to_string(),
                monitor_threshold: Some(10),
                block_threshold: Some(80),
                score_window: None,
            }],
            ..BehaviorConfig::default()
        };

        let outcome = store
            .evaluate(
                &config,
                BehaviorRequest {
                    client_id: "203.0.113.10",
                    path: "/login",
                    rule_matches: &[],
                    server_mode: WafMode::Monitor,
                },
            )
            .unwrap();

        assert_eq!(outcome.action, WafAction::Allow);

        let outcome = store
            .evaluate(
                &config,
                BehaviorRequest {
                    client_id: "203.0.113.10",
                    path: "/login/.env",
                    rule_matches: &[],
                    server_mode: WafMode::Monitor,
                },
            )
            .unwrap();

        assert_eq!(outcome.monitor_threshold, 10);
    }

    #[test]
    fn category_override_changes_score_delta() {
        let store = MemoryBehaviorStore::new();
        let config = BehaviorConfig {
            enabled: true,
            monitor_threshold: 20,
            block_threshold: 80,
            category_overrides: vec![BehaviorCategoryOverrideConfig {
                category: "scanner_behavior".to_string(),
                monitor_threshold: None,
                block_threshold: None,
                score_delta: Some(25),
            }],
            ..BehaviorConfig::default()
        };
        let rule_match = RuleMatch {
            rule_id: "SAUGRA-BOT-001".to_string(),
            rule_name: "Suspicious Scanner User Agent".to_string(),
            category: "scanner_behavior".to_string(),
            severity: RuleSeverity::Medium,
            matched_target: RuleTarget::UserAgent,
            paranoia_level: 1,
            explanation: "Scanner matched.".to_string(),
            owasp_category: None,
        };

        let outcome = store
            .evaluate(
                &config,
                BehaviorRequest {
                    client_id: "203.0.113.10",
                    path: "/",
                    rule_matches: &[rule_match],
                    server_mode: WafMode::Monitor,
                },
            )
            .unwrap();

        assert_eq!(outcome.score, 25);
        assert_eq!(outcome.action, WafAction::Monitor);
    }

    #[test]
    fn custom_probe_paths_drive_behavior_scoring() {
        let store = MemoryBehaviorStore::new();
        let config = BehaviorConfig {
            enabled: true,
            monitor_threshold: 10,
            block_threshold: 80,
            probe_paths: vec!["/custom-probe".to_string()],
            ..BehaviorConfig::default()
        };

        let outcome = store
            .evaluate(
                &config,
                BehaviorRequest {
                    client_id: "203.0.113.10",
                    path: "/custom-probe/config",
                    rule_matches: &[],
                    server_mode: WafMode::Monitor,
                },
            )
            .unwrap();

        assert_eq!(outcome.action, WafAction::Monitor);
        assert!(outcome
            .contributors
            .iter()
            .any(|contributor| contributor.reason == "scanner_path_probe"));
    }

    #[test]
    fn probe_path_exclusion_prevents_behavior_scoring() {
        let store = MemoryBehaviorStore::new();
        let config = BehaviorConfig {
            enabled: true,
            probe_paths: vec!["/admin".to_string()],
            probe_path_exclusions: vec!["/admin".to_string()],
            ..BehaviorConfig::default()
        };

        let outcome = store
            .evaluate(
                &config,
                BehaviorRequest {
                    client_id: "203.0.113.10",
                    path: "/admin/login/",
                    rule_matches: &[],
                    server_mode: WafMode::Block,
                },
            )
            .unwrap();

        assert_eq!(outcome.score, 0);
        assert_eq!(outcome.action, WafAction::Allow);
    }

    #[test]
    fn score_window_ignores_expired_entries() {
        let mut state = BehaviorState::default();
        state.clients.insert(
            "203.0.113.10".to_string(),
            ClientBehaviorState {
                entries: vec![BehaviorEntry {
                    timestamp_seconds: unix_seconds_now().saturating_sub(120),
                    reason: "scanner_path_probe".to_string(),
                    score_delta: 50,
                    path: "/old-probe".to_string(),
                }],
            },
        );
        let config = BehaviorConfig {
            enabled: true,
            score_window: "1s".to_string(),
            decay_window: "1h".to_string(),
            monitor_threshold: 10,
            block_threshold: 80,
            ..BehaviorConfig::default()
        };

        let outcome = evaluate_with_state(
            &config,
            BehaviorRequest {
                client_id: "203.0.113.10",
                path: "/",
                rule_matches: &[],
                server_mode: WafMode::Monitor,
            },
            &mut state,
            "memory",
        );

        assert_eq!(outcome.score, 0);
        assert_eq!(outcome.action, WafAction::Allow);
    }
}
