use std::path::PathBuf;

use serde::Deserialize;

use crate::rules::RuleTarget;

#[derive(Debug, Clone, Deserialize)]
pub struct RuleSettings {
    #[serde(default = "default_true")]
    pub owasp_crs: bool,
    #[serde(default = "default_paranoia_level")]
    pub paranoia_level: u8,
    #[serde(default)]
    pub detection_paranoia_level: Option<u8>,
    #[serde(default)]
    pub blocking_paranoia_level: Option<u8>,
    #[serde(default = "default_inbound_anomaly_threshold")]
    pub inbound_anomaly_threshold: u16,
    #[serde(default = "default_rule_files")]
    pub files: Vec<PathBuf>,
    #[serde(default)]
    pub exclusions: Vec<RuleExclusionConfig>,
}

fn default_true() -> bool {
    true
}
fn default_paranoia_level() -> u8 {
    1
}
fn default_inbound_anomaly_threshold() -> u16 {
    5
}
fn default_rule_files() -> Vec<PathBuf> {
    vec![
        PathBuf::from("configs/rules/REQUEST-913-SCANNER-DETECTION.yml"),
        PathBuf::from("configs/rules/REQUEST-914-AUTHENTICATION-ABUSE.yml"),
        PathBuf::from("configs/rules/REQUEST-916-INSECURE-DESIGN.yml"),
        PathBuf::from("configs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.yml"),
        PathBuf::from("configs/rules/REQUEST-921-CRYPTO-TRANSPORT.yml"),
        PathBuf::from("configs/rules/REQUEST-932-APPLICATION-ATTACK-RCE.yml"),
        PathBuf::from("configs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.yml"),
        PathBuf::from("configs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.yml"),
        PathBuf::from("configs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.yml"),
        PathBuf::from("configs/rules/REQUEST-944-SUPPLY-CHAIN.yml"),
        PathBuf::from("configs/rules/REQUEST-945-INTEGRITY.yml"),
        PathBuf::from("configs/rules/REQUEST-949-LOGGING-ALERTING.yml"),
        PathBuf::from("configs/rules/REQUEST-950-EXCEPTIONAL-CONDITIONS.yml"),
    ]
}

impl Default for RuleSettings {
    fn default() -> Self {
        Self {
            owasp_crs: true,
            paranoia_level: default_paranoia_level(),
            detection_paranoia_level: None,
            blocking_paranoia_level: None,
            inbound_anomaly_threshold: default_inbound_anomaly_threshold(),
            files: default_rule_files(),
            exclusions: Vec::new(),
        }
    }
}

impl RuleSettings {
    pub fn detection_paranoia_level(&self) -> u8 {
        self.detection_paranoia_level.unwrap_or(self.paranoia_level)
    }

    pub fn blocking_paranoia_level(&self) -> u8 {
        self.blocking_paranoia_level.unwrap_or(self.paranoia_level)
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuleExclusionConfig {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub rule_ids: Vec<String>,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    pub path_prefixes: Vec<String>,
    #[serde(default)]
    pub query_params: Vec<String>,
    #[serde(default)]
    pub headers: Vec<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub targets: Vec<RuleTarget>,
    #[serde(default)]
    pub content_types: Vec<String>,
    #[serde(default)]
    pub trusted_headers: Vec<RuleExclusionHeaderValueConfig>,
    #[serde(default)]
    pub identities: Vec<RuleExclusionHeaderValueConfig>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuleExclusionHeaderValueConfig {
    pub name: String,
    #[serde(default)]
    pub values: Vec<String>,
}
