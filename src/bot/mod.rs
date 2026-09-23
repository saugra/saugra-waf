use std::{
    path::{Path, PathBuf},
    sync::Mutex,
};

use serde::{Deserialize, Serialize};

use crate::{
    behavior::BehaviorContributor,
    config::{BehaviorBackend, BehaviorMode, BotProtectionConfig, ForwardedHeadersConfig, WafMode},
    decision::WafAction,
    rules::{RuleMatch, RuleTarget},
};

mod eval;
#[cfg(test)]
mod tests;

pub use eval::evaluate_with_state;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct BotProtectionOutcome {
    pub enabled: bool,
    pub action: WafAction,
    pub score: u16,
    pub monitor_threshold: u16,
    pub block_threshold: u16,
    pub score_window_seconds: u64,
    pub temporary_block_duration_seconds: u64,
    pub temporary_blocked_until: Option<u64>,
    pub storage_backend: String,
    pub allowlisted: bool,
    pub blocklisted: bool,
    pub contributors: Vec<BehaviorContributor>,
}

#[derive(Debug, Clone)]
pub struct BotProtectionRequest<'a> {
    pub client_id: &'a str,
    pub path: &'a str,
    pub headers: &'a str,
    pub user_agent: &'a str,
    pub forwarded_headers: &'a ForwardedHeadersConfig,
    pub trusted_forwarded_headers: bool,
    pub server_mode: WafMode,
}

pub trait BotProtectionStore: Send + Sync {
    fn evaluate(
        &self,
        config: &BotProtectionConfig,
        request: BotProtectionRequest<'_>,
    ) -> anyhow::Result<BotProtectionOutcome>;
}

#[derive(Debug)]
pub struct MemoryBotProtectionStore {
    state: Mutex<eval::BotProtectionState>,
}

impl MemoryBotProtectionStore {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(eval::BotProtectionState::default()),
        }
    }
}

impl Default for MemoryBotProtectionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BotProtectionStore for MemoryBotProtectionStore {
    fn evaluate(
        &self,
        config: &BotProtectionConfig,
        request: BotProtectionRequest<'_>,
    ) -> anyhow::Result<BotProtectionOutcome> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("bot protection store lock poisoned"))?;
        Ok(evaluate_with_state(config, request, &mut state, "memory"))
    }
}

#[derive(Debug)]
pub struct LocalBotProtectionStore {
    path: PathBuf,
    state: Mutex<eval::BotProtectionState>,
}

impl LocalBotProtectionStore {
    pub fn open(path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let path = path.into();
        let state = eval::read_state(&path)?;
        Ok(Self {
            path,
            state: Mutex::new(state),
        })
    }
}

impl BotProtectionStore for LocalBotProtectionStore {
    fn evaluate(
        &self,
        config: &BotProtectionConfig,
        request: BotProtectionRequest<'_>,
    ) -> anyhow::Result<BotProtectionOutcome> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("bot protection store lock poisoned"))?;
        let outcome = evaluate_with_state(config, request, &mut state, "local");
        eval::write_state(&self.path, &state)?;
        Ok(outcome)
    }
}

pub fn build_store(config: &BotProtectionConfig) -> anyhow::Result<Box<dyn BotProtectionStore>> {
    if !config.enabled || config.mode == BehaviorMode::Off {
        return Ok(Box::new(MemoryBotProtectionStore::new()));
    }

    match config.backend {
        BehaviorBackend::Memory => Ok(Box::new(MemoryBotProtectionStore::new())),
        BehaviorBackend::Local => Ok(Box::new(LocalBotProtectionStore::open(&config.state_path)?)),
    }
}

pub fn reset_client(path: &Path, client_id: &str) -> anyhow::Result<bool> {
    let mut state = eval::read_state(path)?;
    let removed = state.clients.remove(client_id).is_some();
    if removed {
        eval::write_state(path, &state)?;
    }
    Ok(removed)
}

pub fn bot_rule_match(
    config: &BotProtectionConfig,
    outcome: &BotProtectionOutcome,
) -> Option<RuleMatch> {
    if outcome.action == WafAction::Allow {
        return None;
    }

    Some(RuleMatch {
        rule_id: config.rule.id.clone(),
        rule_name: config.rule.name.clone(),
        category: config.rule.category.clone(),
        severity: if outcome.action == WafAction::Block {
            config.rule.block_severity
        } else {
            config.rule.monitor_severity
        },
        matched_target: RuleTarget::Headers,
        paranoia_level: config.rule.paranoia_level,
        explanation: format!(
            "{} Bot protection score {} reached the {:?} threshold with {} contributor(s).",
            config.rule.explanation,
            outcome.score,
            outcome.action,
            outcome.contributors.len()
        ),
        owasp_category: config.rule.owasp_category.clone(),
    })
}
