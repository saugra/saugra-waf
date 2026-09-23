use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UnknownThreatConfig {
    #[serde(default = "default_unknown_threat_mode")]
    pub mode: UnknownThreatMode,
    #[serde(default = "default_unknown_threat_backend")]
    pub backend: UnknownThreatBackend,
    #[serde(default = "default_unknown_threat_state_path")]
    pub state_path: String,
    #[serde(default = "default_minimum_observations")]
    pub minimum_observations: u32,
    #[serde(default = "default_monitor_threshold")]
    pub monitor_threshold: u16,
    #[serde(default = "default_body_size_multiplier")]
    pub body_size_multiplier: u32,
    #[serde(default = "default_retention")]
    pub retention: String,
    #[serde(default = "default_max_routes")]
    pub max_routes: usize,
    #[serde(default = "default_max_features_per_route")]
    pub max_features_per_route: usize,
    pub signal_catalog: Option<String>,
    #[serde(default)]
    pub signal_policy: UnknownThreatSignals,
    #[serde(default)]
    pub route_overrides: Vec<UnknownThreatRouteConfig>,
    #[serde(default)]
    pub excluded_routes: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnknownThreatBackend {
    Local,
}

fn default_unknown_threat_backend() -> UnknownThreatBackend {
    UnknownThreatBackend::Local
}

fn default_unknown_threat_mode() -> UnknownThreatMode {
    UnknownThreatMode::Shadow
}

fn default_unknown_threat_state_path() -> String {
    "/var/lib/saugra-waf/unknown-threats-state.json".to_string()
}

fn default_minimum_observations() -> u32 {
    50
}

fn default_monitor_threshold() -> u16 {
    100
}

fn default_body_size_multiplier() -> u32 {
    3
}

fn default_retention() -> String {
    "30d".to_string()
}

fn default_max_routes() -> usize {
    5000
}

fn default_max_features_per_route() -> usize {
    256
}

impl Default for UnknownThreatConfig {
    fn default() -> Self {
        Self {
            mode: default_unknown_threat_mode(),
            backend: default_unknown_threat_backend(),
            state_path: default_unknown_threat_state_path(),
            minimum_observations: default_minimum_observations(),
            monitor_threshold: default_monitor_threshold(),
            body_size_multiplier: default_body_size_multiplier(),
            retention: default_retention(),
            max_routes: default_max_routes(),
            max_features_per_route: default_max_features_per_route(),
            signal_catalog: None,
            signal_policy: UnknownThreatSignals::default(),
            route_overrides: Vec::new(),
            excluded_routes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnknownThreatMode {
    Off,
    Shadow,
    Enforce,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UnknownThreatSignalCatalog {
    #[serde(default)]
    pub signals: UnknownThreatSignals,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UnknownThreatSignals {
    #[serde(default = "default_signal_policy")]
    pub novel_parameter: UnknownThreatSignalPolicy,
    #[serde(default = "default_signal_policy")]
    pub missing_expected_header: UnknownThreatSignalPolicy,
    #[serde(default = "default_signal_policy")]
    pub structural_body_mutation: UnknownThreatSignalPolicy,
    #[serde(default = "default_signal_policy")]
    pub oversized_body: UnknownThreatSignalPolicy,
    #[serde(default = "default_signal_policy")]
    pub repeated_character_spike: UnknownThreatSignalPolicy,
    #[serde(default = "default_signal_policy")]
    pub encoding_anomaly: UnknownThreatSignalPolicy,
    #[serde(default = "default_signal_policy")]
    pub high_entropy_value: UnknownThreatSignalPolicy,
}

fn default_signal_policy() -> UnknownThreatSignalPolicy {
    UnknownThreatSignalPolicy {
        enabled: true,
        weight: 25,
    }
}

impl Default for UnknownThreatSignals {
    fn default() -> Self {
        Self {
            novel_parameter: default_signal_policy(),
            missing_expected_header: default_signal_policy(),
            structural_body_mutation: default_signal_policy(),
            oversized_body: default_signal_policy(),
            repeated_character_spike: default_signal_policy(),
            encoding_anomaly: default_signal_policy(),
            high_entropy_value: default_signal_policy(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UnknownThreatSignalPolicy {
    #[serde(default = "default_signal_enabled")]
    pub enabled: bool,
    #[serde(default = "default_signal_weight")]
    pub weight: u16,
}

fn default_signal_enabled() -> bool {
    true
}

fn default_signal_weight() -> u16 {
    25
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UnknownThreatRouteConfig {
    pub path: String,
    pub mode: Option<UnknownThreatMode>,
    pub minimum_observations: Option<u32>,
    pub monitor_threshold: Option<u16>,
    pub body_size_multiplier: Option<u32>,
}
