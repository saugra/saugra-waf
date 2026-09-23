use std::path::PathBuf;

use serde::Deserialize;

use crate::config::{errors::ConfigError, BehaviorBackend};

#[derive(Debug, Clone, Deserialize)]
pub struct UnknownThreatConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: UnknownThreatMode,
    #[serde(default)]
    pub shadow_review_completed: bool,
    #[serde(default)]
    pub backend: BehaviorBackend,
    #[serde(default = "default_unknown_threat_state_path")]
    pub state_path: PathBuf,
    #[serde(default = "default_unknown_threat_minimum_observations")]
    pub minimum_observations: u64,
    #[serde(default = "default_unknown_threat_monitor_threshold")]
    pub monitor_threshold: u16,
    #[serde(default = "default_unknown_threat_block_threshold")]
    pub block_threshold: u16,
    #[serde(default = "default_unknown_threat_minimum_independent_signals")]
    pub minimum_independent_signals: usize,
    #[serde(default = "default_unknown_threat_minimum_baseline_age")]
    pub minimum_baseline_age: String,
    #[serde(default = "default_unknown_threat_minimum_block_observations")]
    pub minimum_block_observations: u64,
    #[serde(default = "default_unknown_threat_signal_catalog")]
    pub signal_catalog: String,
    #[serde(skip, default = "default_unknown_threat_signals")]
    pub signals: UnknownThreatSignals,
    #[serde(default)]
    pub(crate) unseen_method_score: Option<u16>,
    #[serde(default)]
    pub(crate) unseen_content_type_score: Option<u16>,
    #[serde(default)]
    pub(crate) unseen_query_parameter_score: Option<u16>,
    #[serde(default)]
    pub(crate) body_size_score: Option<u16>,
    #[serde(default = "default_unknown_threat_body_size_multiplier")]
    pub body_size_multiplier: u16,
    #[serde(default = "default_unknown_threat_promotion_observations")]
    pub promotion_observations: u64,
    #[serde(default)]
    pub trusted_learning_only: bool,
    #[serde(default)]
    pub trusted_learning_clients: Vec<String>,
    #[serde(default = "default_unknown_threat_max_methods")]
    pub max_methods_per_route: usize,
    #[serde(default = "default_unknown_threat_max_content_types")]
    pub max_content_types_per_route: usize,
    #[serde(default = "default_unknown_threat_max_query_parameters")]
    pub max_query_parameters_per_route: usize,
    #[serde(default = "default_unknown_threat_retention")]
    pub retention: String,
    #[serde(default = "default_unknown_threat_max_routes")]
    pub max_routes: usize,
    #[serde(default)]
    pub excluded_paths: Vec<String>,
    #[serde(default)]
    pub routes: Vec<UnknownThreatRouteConfig>,
}

impl Default for UnknownThreatConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: UnknownThreatMode::Monitor,
            shadow_review_completed: false,
            backend: BehaviorBackend::Local,
            state_path: default_unknown_threat_state_path(),
            minimum_observations: default_unknown_threat_minimum_observations(),
            monitor_threshold: default_unknown_threat_monitor_threshold(),
            block_threshold: default_unknown_threat_block_threshold(),
            minimum_independent_signals: default_unknown_threat_minimum_independent_signals(),
            minimum_baseline_age: default_unknown_threat_minimum_baseline_age(),
            minimum_block_observations: default_unknown_threat_minimum_block_observations(),
            signal_catalog: default_unknown_threat_signal_catalog(),
            signals: default_unknown_threat_signals(),
            unseen_method_score: None,
            unseen_content_type_score: None,
            unseen_query_parameter_score: None,
            body_size_score: None,
            body_size_multiplier: default_unknown_threat_body_size_multiplier(),
            promotion_observations: default_unknown_threat_promotion_observations(),
            trusted_learning_only: false,
            trusted_learning_clients: Vec::new(),
            max_methods_per_route: default_unknown_threat_max_methods(),
            max_content_types_per_route: default_unknown_threat_max_content_types(),
            max_query_parameters_per_route: default_unknown_threat_max_query_parameters(),
            retention: default_unknown_threat_retention(),
            max_routes: default_unknown_threat_max_routes(),
            excluded_paths: Vec::new(),
            routes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnknownThreatMode {
    Off,
    #[default]
    Monitor,
    Shadow,
    Block,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UnknownThreatSignalCatalog {
    pub version: u16,
    pub signals: UnknownThreatSignals,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UnknownThreatSignals {
    pub unseen_method: UnknownThreatSignalPolicy,
    pub unseen_content_type: UnknownThreatSignalPolicy,
    pub unseen_query_parameter: UnknownThreatSignalPolicy,
    pub body_size_deviation: UnknownThreatSignalPolicy,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UnknownThreatSignalPolicy {
    pub score: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UnknownThreatRouteConfig {
    pub path: String,
    #[serde(default = "default_true")]
    pub learning_enabled: bool,
    #[serde(default)]
    pub minimum_observations: Option<u64>,
    #[serde(default)]
    pub monitor_threshold: Option<u16>,
    #[serde(default)]
    pub high_risk: bool,
    #[serde(default)]
    pub block_threshold: Option<u16>,
    #[serde(default)]
    pub minimum_independent_signals: Option<usize>,
    #[serde(default)]
    pub minimum_baseline_age: Option<String>,
    #[serde(default)]
    pub minimum_block_observations: Option<u64>,
}

fn default_true() -> bool {
    true
}

impl Default for UnknownThreatRouteConfig {
    fn default() -> Self {
        Self {
            path: String::new(),
            learning_enabled: true,
            minimum_observations: None,
            monitor_threshold: None,
            high_risk: false,
            block_threshold: None,
            minimum_independent_signals: None,
            minimum_baseline_age: None,
            minimum_block_observations: None,
        }
    }
}

fn default_unknown_threat_state_path() -> PathBuf {
    PathBuf::from("logs/saugra-waf-unknown-threat-state.json")
}

fn default_unknown_threat_minimum_observations() -> u64 {
    100
}

fn default_unknown_threat_monitor_threshold() -> u16 {
    20
}

fn default_unknown_threat_block_threshold() -> u16 {
    40
}

fn default_unknown_threat_minimum_independent_signals() -> usize {
    2
}

fn default_unknown_threat_minimum_baseline_age() -> String {
    "7d".to_string()
}

fn default_unknown_threat_minimum_block_observations() -> u64 {
    1_000
}

fn default_unknown_threat_signal_catalog() -> String {
    "builtin".to_string()
}

fn default_unknown_threat_signals() -> UnknownThreatSignals {
    load_builtin_unknown_threat_signal_catalog().signals
}

fn default_unknown_threat_body_size_multiplier() -> u16 {
    4
}

fn default_unknown_threat_promotion_observations() -> u64 {
    3
}

fn default_unknown_threat_max_methods() -> usize {
    16
}

fn default_unknown_threat_max_content_types() -> usize {
    32
}

fn default_unknown_threat_max_query_parameters() -> usize {
    256
}

fn default_unknown_threat_retention() -> String {
    "30d".to_string()
}

fn default_unknown_threat_max_routes() -> usize {
    10_000
}

pub fn load_builtin_unknown_threat_signal_catalog() -> UnknownThreatSignalCatalog {
    serde_yaml::from_str(include_str!(
        "../../configs/intelligence/unknown-threat-signals.yml"
    ))
    .expect("builtin unknown threat signal catalog must be valid YAML")
}

pub fn load_unknown_threat_signal_catalog(
    path: &str,
) -> Result<UnknownThreatSignalCatalog, ConfigError> {
    let catalog: UnknownThreatSignalCatalog = if path == "builtin" {
        load_builtin_unknown_threat_signal_catalog()
    } else {
        let contents = std::fs::read_to_string(path)?;
        serde_yaml::from_str(&contents).map_err(|source| {
            ConfigError::InvalidUnknownThreatSignalCatalog {
                path: path.to_string(),
                source,
            }
        })?
    };

    if catalog.version != 1 {
        return Err(ConfigError::InvalidUnknownThreatSignalCatalogVersion);
    }
    if [
        catalog.signals.unseen_method.score,
        catalog.signals.unseen_content_type.score,
        catalog.signals.unseen_query_parameter.score,
        catalog.signals.body_size_deviation.score,
    ]
    .contains(&0)
    {
        return Err(ConfigError::InvalidUnknownThreatSignalScore);
    }

    Ok(catalog)
}
