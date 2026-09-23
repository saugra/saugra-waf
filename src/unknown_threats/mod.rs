use std::{path::PathBuf, sync::Mutex};

use serde::{Deserialize, Serialize};

use crate::{
    config::{BehaviorBackend, UnknownThreatConfig, UnknownThreatMode, WafMode},
    decision::WafAction,
    rules::{RuleMatch, RuleSeverity, RuleTarget},
};

mod eval;
mod helpers;
mod state;
#[cfg(test)]
mod tests;

pub use eval::{cleanup_local_state_at, shadow_report};
pub use state::{RouteBaseline, StateFileLock, UnknownThreatState};

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

fn default_true() -> bool {
    true
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

#[derive(Debug, Default)]
pub struct MemoryUnknownThreatStore {
    state: Mutex<state::UnknownThreatState>,
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
        Ok(eval::evaluate_with_state(
            config, request, &mut state, "memory",
        ))
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
        let _file_lock = state::StateFileLock::acquire(&path)?;
        state::read_state(&path)?;
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
        let _file_lock = state::StateFileLock::acquire(&self.path)?;
        let mut state = state::read_state(&self.path)?;
        let outcome = eval::evaluate_with_state(config, request, &mut state, "local");
        state::write_state(&self.path, &state)?;
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
    cleanup_local_state_at(config, dry_run, state::unix_seconds_now())
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
