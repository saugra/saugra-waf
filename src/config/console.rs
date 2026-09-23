use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConsoleConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub transport: ConsoleTransport,
    #[serde(default)]
    pub management_url: Option<String>,
    #[serde(default)]
    pub external_id: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub credential_path: Option<PathBuf>,
    #[serde(default)]
    pub outbox_path: Option<PathBuf>,
    #[serde(default = "default_console_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,
    #[serde(default = "default_console_delivery_interval_secs")]
    pub delivery_interval_secs: u64,
    #[serde(default = "default_console_batch_size")]
    pub batch_size: usize,
    #[serde(default = "default_console_policy_poll_interval_secs")]
    pub policy_poll_interval_secs: u64,
    #[serde(default)]
    pub policy_cache_path: Option<PathBuf>,
    #[serde(default)]
    pub emergency_override_path: Option<PathBuf>,
    #[serde(default)]
    pub policy_transition_path: Option<PathBuf>,
    #[serde(default)]
    pub trusted_signing_keys: std::collections::BTreeMap<String, String>,
}

fn default_console_heartbeat_interval_secs() -> u64 {
    60
}
fn default_console_delivery_interval_secs() -> u64 {
    5
}
fn default_console_batch_size() -> usize {
    100
}
fn default_console_policy_poll_interval_secs() -> u64 {
    30
}

impl Default for ConsoleConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            transport: ConsoleTransport::Direct,
            management_url: None,
            external_id: None,
            display_name: None,
            credential_path: None,
            outbox_path: None,
            heartbeat_interval_secs: default_console_heartbeat_interval_secs(),
            delivery_interval_secs: default_console_delivery_interval_secs(),
            batch_size: default_console_batch_size(),
            policy_poll_interval_secs: default_console_policy_poll_interval_secs(),
            policy_cache_path: None,
            emergency_override_path: None,
            policy_transition_path: None,
            trusted_signing_keys: std::collections::BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConsoleTransport {
    #[default]
    Direct,
    Relay,
}

use std::path::Path;

impl ConsoleConfig {
    pub fn credential_path(&self, event_log_path: &Path) -> PathBuf {
        self.credential_path.clone().unwrap_or_else(|| {
            PathBuf::from(format!(
                "{}.console-credential.json",
                event_log_path.display()
            ))
        })
    }

    pub fn outbox_path(&self, event_log_path: &Path) -> PathBuf {
        self.outbox_path.clone().unwrap_or_else(|| {
            PathBuf::from(format!("{}.console-outbox.jsonl", event_log_path.display()))
        })
    }

    pub fn policy_cache_path(&self, event_log_path: &Path) -> PathBuf {
        self.policy_cache_path.clone().unwrap_or_else(|| {
            PathBuf::from(format!("{}.console-policy.json", event_log_path.display()))
        })
    }

    pub fn emergency_override_path(&self, event_log_path: &Path) -> PathBuf {
        self.emergency_override_path.clone().unwrap_or_else(|| {
            PathBuf::from(format!(
                "{}.console-emergency-override.json",
                event_log_path.display()
            ))
        })
    }

    pub fn policy_transition_path(&self, event_log_path: &Path) -> PathBuf {
        self.policy_transition_path.clone().unwrap_or_else(|| {
            PathBuf::from(format!(
                "{}.console-policy-transitions.json",
                event_log_path.display()
            ))
        })
    }
}
