use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
};

use anyhow::{Context, Result};
use saugra_console_contracts::EffectivePolicyResponse;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::config::{RuleExclusionConfig, SaugraConfig, WafMode};

use super::{now_unix_secs, protect_file};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTransition {
    pub transition_id: String,
    pub lifecycle: String,
    pub policy_key: Option<String>,
    pub revision: Option<i64>,
    pub digest: Option<String>,
    pub reason: Option<String>,
    pub occurred_at_unix_secs: u64,
}

#[derive(Clone, Default)]
pub struct ManagedPolicyHandle {
    state: Arc<RwLock<ManagedPolicyState>>,
    transitions: Arc<Mutex<Vec<PolicyTransition>>>,
    transition_path: Option<Arc<PathBuf>>,
}

#[derive(Default)]
struct ManagedPolicyState {
    exclusions: Vec<RuleExclusionConfig>,
    policy_key: Option<String>,
    revision: Option<i64>,
    digest: Option<String>,
    lifecycle: String,
    reason: Option<String>,
    updated_at_unix_secs: u64,
    mode: Option<WafMode>,
    anomaly_threshold: Option<u16>,
    detection_paranoia_level: Option<u8>,
    blocking_paranoia_level: Option<u8>,
}

impl ManagedPolicyHandle {
    pub fn from_config(config: &SaugraConfig) -> Result<Self> {
        let path = config
            .console
            .policy_transition_path(&config.logging.event_log_path);
        let transitions = if path.exists() {
            serde_json::from_slice(&fs::read(&path)?)
                .context("invalid Console policy transition journal")?
        } else {
            Vec::new()
        };
        Ok(Self {
            state: Arc::default(),
            transitions: Arc::new(Mutex::new(transitions)),
            transition_path: Some(Arc::new(path)),
        })
    }

    fn persist_transition(&self, transition: PolicyTransition) {
        let Ok(mut transitions) = self.transitions.lock() else {
            return;
        };
        if transitions.last().is_some_and(|previous| {
            previous.lifecycle == transition.lifecycle
                && previous.policy_key == transition.policy_key
                && previous.revision == transition.revision
                && previous.digest == transition.digest
                && previous.reason == transition.reason
        }) {
            return;
        }
        transitions.push(transition);
        if let Some(path) = &self.transition_path {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let temporary = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
            if fs::write(
                &temporary,
                serde_json::to_vec_pretty(&*transitions).unwrap_or_default(),
            )
            .is_ok()
            {
                let _ = protect_file(&temporary);
                let _ = fs::rename(temporary, path.as_ref());
            }
        }
    }

    pub fn pending_transitions(&self) -> Vec<PolicyTransition> {
        self.transitions
            .lock()
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    pub fn acknowledge_transitions(&self) {
        if let Ok(mut transitions) = self.transitions.lock() {
            transitions.clear();
            if let Some(path) = &self.transition_path {
                let _ = fs::write(path.as_ref(), b"[]");
                let _ = protect_file(path);
            }
        }
    }

    pub fn exclusions(&self) -> Vec<RuleExclusionConfig> {
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .exclusions
            .clone()
    }

    #[cfg(test)]
    pub(crate) fn activate(&self, exclusions: Vec<RuleExclusionConfig>) {
        self.state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .exclusions = exclusions;
    }

    pub fn activate_verified(
        &self,
        response: &EffectivePolicyResponse,
        exclusions: Vec<RuleExclusionConfig>,
    ) {
        let policy = response.bundle.get("policy").unwrap_or(&Value::Null);
        *self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = ManagedPolicyState {
            exclusions,
            policy_key: Some(response.policy_key.clone()),
            revision: Some(response.revision),
            digest: Some(response.signature.sha256.clone()),
            lifecycle: "activated".to_string(),
            reason: None,
            updated_at_unix_secs: now_unix_secs(),
            mode: policy
                .get("mode")
                .and_then(Value::as_str)
                .and_then(parse_managed_mode),
            anomaly_threshold: policy
                .get("anomaly_threshold")
                .and_then(Value::as_u64)
                .and_then(|v| u16::try_from(v).ok()),
            detection_paranoia_level: policy
                .get("detection_paranoia_level")
                .and_then(Value::as_u64)
                .and_then(|v| u8::try_from(v).ok()),
            blocking_paranoia_level: policy
                .get("blocking_paranoia_level")
                .and_then(Value::as_u64)
                .and_then(|v| u8::try_from(v).ok()),
        };
        self.persist_transition(PolicyTransition {
            transition_id: uuid::Uuid::new_v4().to_string(),
            lifecycle: "activated".into(),
            policy_key: Some(response.policy_key.clone()),
            revision: Some(response.revision),
            digest: Some(response.signature.sha256.clone()),
            reason: None,
            occurred_at_unix_secs: now_unix_secs(),
        });
    }

    pub fn effective_config(&self, local: &SaugraConfig) -> SaugraConfig {
        let state = self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut effective = local.clone();
        if let Some(value) = state.mode {
            effective.server.mode = value;
        }
        if let Some(value) = state.anomaly_threshold {
            effective.rules.inbound_anomaly_threshold = value;
        }
        if let Some(value) = state.detection_paranoia_level {
            effective.rules.detection_paranoia_level = Some(value);
        }
        if let Some(value) = state.blocking_paranoia_level {
            effective.rules.blocking_paranoia_level = Some(value);
        }
        effective
    }

    pub fn record_lifecycle(&self, lifecycle: &str, reason: Option<String>) {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.lifecycle = lifecycle.to_string();
        state.reason = reason;
        state.updated_at_unix_secs = now_unix_secs();
        let transition = PolicyTransition {
            transition_id: uuid::Uuid::new_v4().to_string(),
            lifecycle: lifecycle.to_string(),
            policy_key: state.policy_key.clone(),
            revision: state.revision,
            digest: state.digest.clone(),
            reason: state.reason.clone(),
            occurred_at_unix_secs: state.updated_at_unix_secs,
        };
        drop(state);
        self.persist_transition(transition);
    }

    pub fn record_policy_lifecycle(
        &self,
        response: &EffectivePolicyResponse,
        lifecycle: &str,
        reason: Option<String>,
    ) {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.policy_key = Some(response.policy_key.clone());
        state.revision = Some(response.revision);
        state.digest = Some(response.signature.sha256.clone());
        state.lifecycle = lifecycle.to_string();
        state.reason = reason;
        state.updated_at_unix_secs = now_unix_secs();
        let transition = PolicyTransition {
            transition_id: uuid::Uuid::new_v4().to_string(),
            lifecycle: lifecycle.to_string(),
            policy_key: state.policy_key.clone(),
            revision: state.revision,
            digest: state.digest.clone(),
            reason: state.reason.clone(),
            occurred_at_unix_secs: state.updated_at_unix_secs,
        };
        drop(state);
        self.persist_transition(transition);
    }

    pub fn activate_emergency_override(&self, reason: String) {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let policy_key = state.policy_key.clone();
        let revision = state.revision;
        let digest = state.digest.clone();
        *state = ManagedPolicyState {
            lifecycle: "rolled_back".to_string(),
            reason: Some(reason.clone()),
            updated_at_unix_secs: now_unix_secs(),
            ..ManagedPolicyState::default()
        };
        drop(state);
        self.persist_transition(PolicyTransition {
            transition_id: uuid::Uuid::new_v4().to_string(),
            lifecycle: "rolled_back".into(),
            policy_key,
            revision,
            digest,
            reason: Some(reason),
            occurred_at_unix_secs: now_unix_secs(),
        });
    }

    pub fn status(&self) -> Value {
        let state = self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        json!({
            "policy_key": state.policy_key,
            "revision": state.revision,
            "digest": state.digest,
            "managed_exclusions": state.exclusions.len(),
            "status": if state.policy_key.is_some() { "active" } else { "local" },
            "lifecycle": if state.lifecycle.is_empty() { "local" } else { &state.lifecycle },
            "reason": state.reason,
            "updated_at_unix_secs": state.updated_at_unix_secs,
            "pending_transitions": self.pending_transitions()
        })
    }
}

pub fn parse_managed_mode(value: &str) -> Option<WafMode> {
    match value {
        "monitor" => Some(WafMode::Monitor),
        "block" => Some(WafMode::Block),
        "strict" => Some(WafMode::Strict),
        _ => None,
    }
}
