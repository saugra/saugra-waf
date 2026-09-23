use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct BehaviorConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: BehaviorMode,
    #[serde(default)]
    pub backend: BehaviorBackend,
    #[serde(default = "default_behavior_state_path")]
    pub state_path: PathBuf,
    #[serde(default = "default_behavior_score_window")]
    pub score_window: String,
    #[serde(default = "default_behavior_decay_window")]
    pub decay_window: String,
    #[serde(default = "default_behavior_monitor_threshold")]
    pub monitor_threshold: u16,
    #[serde(default = "default_behavior_block_threshold")]
    pub block_threshold: u16,
    #[serde(default)]
    pub route_overrides: Vec<BehaviorRouteOverrideConfig>,
    #[serde(default)]
    pub category_overrides: Vec<BehaviorCategoryOverrideConfig>,
    #[serde(default)]
    pub probe_path_catalog: Option<String>,
    #[serde(default = "default_probe_paths")]
    pub probe_paths: Vec<String>,
    #[serde(default)]
    pub probe_paths_extra: Vec<String>,
    #[serde(default)]
    pub probe_path_exclusions: Vec<String>,
}

fn default_behavior_state_path() -> PathBuf {
    PathBuf::from("logs/saugra-waf-behavior-state.json")
}
fn default_behavior_score_window() -> String {
    "10m".to_string()
}
fn default_behavior_decay_window() -> String {
    "30m".to_string()
}
fn default_behavior_monitor_threshold() -> u16 {
    40
}
fn default_behavior_block_threshold() -> u16 {
    80
}

fn default_probe_paths() -> Vec<String> {
    load_builtin_threat_path_catalog().behavior_probe_paths
}

impl Default for BehaviorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: BehaviorMode::Monitor,
            backend: BehaviorBackend::Local,
            state_path: default_behavior_state_path(),
            score_window: default_behavior_score_window(),
            decay_window: default_behavior_decay_window(),
            monitor_threshold: default_behavior_monitor_threshold(),
            block_threshold: default_behavior_block_threshold(),
            route_overrides: Vec::new(),
            category_overrides: Vec::new(),
            probe_path_catalog: None,
            probe_paths: default_probe_paths(),
            probe_paths_extra: Vec::new(),
            probe_path_exclusions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorMode {
    Off,
    #[default]
    Monitor,
    Block,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorBackend {
    Memory,
    #[default]
    Local,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct BehaviorRouteOverrideConfig {
    pub path: String,
    #[serde(default)]
    pub monitor_threshold: Option<u16>,
    #[serde(default)]
    pub block_threshold: Option<u16>,
    #[serde(default)]
    pub score_window: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct BehaviorCategoryOverrideConfig {
    pub category: String,
    #[serde(default)]
    pub monitor_threshold: Option<u16>,
    #[serde(default)]
    pub block_threshold: Option<u16>,
    #[serde(default)]
    pub score_delta: Option<u16>,
}

use crate::config::campaign_bot::load_builtin_threat_path_catalog;
