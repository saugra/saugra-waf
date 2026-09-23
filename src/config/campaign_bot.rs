use std::path::PathBuf;

use serde::Deserialize;

use crate::{
    config::{errors::ConfigError, BehaviorBackend, BehaviorMode},
    rules::RuleSeverity,
};

#[derive(Debug, Clone, Deserialize)]
pub struct CampaignCorrelationConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: CampaignMode,
    #[serde(default)]
    pub backend: CampaignBackend,
    #[serde(default = "default_campaign_state_path")]
    pub state_path: PathBuf,
    #[serde(default)]
    pub redis_url: Option<String>,
    #[serde(default)]
    pub redis_password: Option<String>,
    #[serde(default = "default_campaign_redis_key_prefix")]
    pub redis_key_prefix: String,
    #[serde(default = "default_campaign_window")]
    pub window: String,
    #[serde(default = "default_campaign_retention")]
    pub retention: String,
    #[serde(default = "default_campaign_max_events")]
    pub max_events: usize,
    #[serde(default = "default_campaign_policy_catalog")]
    pub policy_catalog: String,
    #[serde(skip, default = "default_campaign_policies")]
    pub policies: Vec<CampaignPolicyConfig>,
}

impl Default for CampaignCorrelationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: CampaignMode::Monitor,
            backend: CampaignBackend::Local,
            state_path: default_campaign_state_path(),
            redis_url: None,
            redis_password: None,
            redis_key_prefix: default_campaign_redis_key_prefix(),
            window: default_campaign_window(),
            retention: default_campaign_retention(),
            max_events: default_campaign_max_events(),
            policy_catalog: default_campaign_policy_catalog(),
            policies: default_campaign_policies(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CampaignMode {
    Off,
    #[default]
    Monitor,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CampaignBackend {
    Memory,
    #[default]
    Local,
    Redis,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CampaignPolicyCatalog {
    pub version: u16,
    pub campaigns: Vec<CampaignPolicyConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CampaignPolicyConfig {
    pub kind: String,
    #[serde(default = "default_campaign_scope")]
    pub scope: String,
    pub score: u16,
    #[serde(default = "default_campaign_minimum")]
    pub minimum_events: usize,
    #[serde(default = "default_campaign_minimum")]
    pub minimum_clients: usize,
    #[serde(default = "default_campaign_minimum")]
    pub minimum_sessions: usize,
    #[serde(default = "default_campaign_minimum")]
    pub minimum_routes: usize,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    pub path_prefixes: Vec<String>,
    #[serde(default)]
    pub stages: Vec<CampaignStageConfig>,
    #[serde(default)]
    pub minimum_stages: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CampaignStageConfig {
    pub name: String,
    #[serde(default)]
    pub categories: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BotProtectionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: BehaviorMode,
    #[serde(default)]
    pub backend: BehaviorBackend,
    #[serde(default = "default_bot_protection_state_path")]
    pub state_path: PathBuf,
    #[serde(default = "default_behavior_score_window")]
    pub score_window: String,
    #[serde(default = "default_bot_protection_monitor_threshold")]
    pub monitor_threshold: u16,
    #[serde(default = "default_bot_protection_block_threshold")]
    pub block_threshold: u16,
    #[serde(default = "default_bot_protection_temporary_block_duration")]
    pub temporary_block_duration: String,
    #[serde(default)]
    pub allowlists: BotProtectionLists,
    #[serde(default)]
    pub blocklists: BotProtectionLists,
    #[serde(default)]
    pub routes: Vec<BotProtectionRouteConfig>,
    #[serde(default)]
    pub scanner_path_catalog: Option<String>,
    #[serde(default = "default_scanner_paths")]
    pub scanner_paths: Vec<String>,
    #[serde(default)]
    pub scanner_paths_extra: Vec<String>,
    #[serde(default)]
    pub scanner_path_exclusions: Vec<String>,
    #[serde(default)]
    pub rule: BotProtectionRuleConfig,
}

impl Default for BotProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: BehaviorMode::Monitor,
            backend: BehaviorBackend::Local,
            state_path: default_bot_protection_state_path(),
            score_window: default_behavior_score_window(),
            monitor_threshold: default_bot_protection_monitor_threshold(),
            block_threshold: default_bot_protection_block_threshold(),
            temporary_block_duration: default_bot_protection_temporary_block_duration(),
            allowlists: BotProtectionLists::default(),
            blocklists: BotProtectionLists::default(),
            routes: Vec::new(),
            scanner_path_catalog: None,
            scanner_paths: default_scanner_paths(),
            scanner_paths_extra: Vec::new(),
            scanner_path_exclusions: Vec::new(),
            rule: BotProtectionRuleConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ThreatPathCatalog {
    #[serde(default)]
    pub behavior_probe_paths: Vec<String>,
    #[serde(default)]
    pub bot_scanner_paths: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BotProtectionRuleConfig {
    #[serde(default = "default_bot_protection_rule_id")]
    pub id: String,
    #[serde(default = "default_bot_protection_rule_name")]
    pub name: String,
    #[serde(default = "default_bot_protection_rule_category")]
    pub category: String,
    #[serde(default = "default_bot_protection_monitor_severity")]
    pub monitor_severity: RuleSeverity,
    #[serde(default = "default_bot_protection_block_severity")]
    pub block_severity: RuleSeverity,
    #[serde(default = "default_rule_paranoia_level")]
    pub paranoia_level: u8,
    #[serde(default = "default_bot_protection_rule_explanation")]
    pub explanation: String,
    #[serde(default = "default_bot_protection_owasp_category")]
    pub owasp_category: Option<String>,
}

impl Default for BotProtectionRuleConfig {
    fn default() -> Self {
        Self {
            id: default_bot_protection_rule_id(),
            name: default_bot_protection_rule_name(),
            category: default_bot_protection_rule_category(),
            monitor_severity: default_bot_protection_monitor_severity(),
            block_severity: default_bot_protection_block_severity(),
            paranoia_level: default_rule_paranoia_level(),
            explanation: default_bot_protection_rule_explanation(),
            owasp_category: default_bot_protection_owasp_category(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct BotProtectionLists {
    #[serde(default)]
    pub ip_ranges: Vec<String>,
    #[serde(default)]
    pub user_agents: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct BotProtectionRouteConfig {
    pub path: String,
    #[serde(default)]
    pub monitor_threshold: Option<u16>,
    #[serde(default)]
    pub block_threshold: Option<u16>,
}

fn default_campaign_state_path() -> PathBuf {
    PathBuf::from("logs/saugra-waf-campaign-state.json")
}
fn default_campaign_redis_key_prefix() -> String {
    "saugra-waf:campaign-correlation".to_string()
}
fn default_campaign_window() -> String {
    "15m".to_string()
}
fn default_campaign_retention() -> String {
    "24h".to_string()
}
fn default_campaign_max_events() -> usize {
    50_000
}
fn default_campaign_policy_catalog() -> String {
    "builtin".to_string()
}
fn default_campaign_policies() -> Vec<CampaignPolicyConfig> {
    load_builtin_campaign_policy_catalog().campaigns
}
fn default_campaign_scope() -> String {
    "client".to_string()
}
fn default_campaign_minimum() -> usize {
    1
}

fn default_bot_protection_state_path() -> PathBuf {
    PathBuf::from("logs/saugra-waf-bot-protection-state.json")
}
fn default_behavior_score_window() -> String {
    "10m".to_string()
}
fn default_bot_protection_monitor_threshold() -> u16 {
    40
}
fn default_bot_protection_block_threshold() -> u16 {
    80
}
fn default_bot_protection_temporary_block_duration() -> String {
    "15m".to_string()
}
fn default_scanner_paths() -> Vec<String> {
    load_builtin_threat_path_catalog().bot_scanner_paths
}
fn default_bot_protection_rule_id() -> String {
    "SAUGRA-BOT-PROTECTION-001".to_string()
}
fn default_bot_protection_rule_name() -> String {
    "Automated Threat Behavior Score Exceeded".to_string()
}
fn default_bot_protection_rule_category() -> String {
    "bot_protection".to_string()
}
fn default_bot_protection_monitor_severity() -> RuleSeverity {
    RuleSeverity::Medium
}
fn default_bot_protection_block_severity() -> RuleSeverity {
    RuleSeverity::High
}
fn default_rule_paranoia_level() -> u8 {
    1
}
fn default_bot_protection_rule_explanation() -> String {
    "client accumulated a bot protection score above configured thresholds".to_string()
}
fn default_bot_protection_owasp_category() -> Option<String> {
    Some("A04:2021-Insecure Design".to_string())
}

pub fn load_builtin_threat_path_catalog() -> ThreatPathCatalog {
    serde_yaml::from_str(include_str!("../../configs/intelligence/scanner-paths.yml"))
        .expect("builtin threat path catalog must be valid YAML")
}

pub fn load_threat_path_catalog(path: &str) -> Result<ThreatPathCatalog, ConfigError> {
    if path == "builtin" {
        return Ok(load_builtin_threat_path_catalog());
    }

    let contents = std::fs::read_to_string(path)?;
    serde_yaml::from_str(&contents).map_err(|source| ConfigError::InvalidThreatPathCatalog {
        path: path.to_string(),
        source,
    })
}

pub fn merge_unique_paths(target: &mut Vec<String>, source: Vec<String>) {
    for path in source {
        if !target.iter().any(|existing| existing == &path) {
            target.push(path);
        }
    }
}

pub fn load_builtin_campaign_policy_catalog() -> CampaignPolicyCatalog {
    serde_yaml::from_str(include_str!(
        "../../configs/intelligence/campaign-policies.yml"
    ))
    .expect("builtin campaign policy catalog must be valid YAML")
}

pub fn load_campaign_policy_catalog(path: &str) -> Result<CampaignPolicyCatalog, ConfigError> {
    let catalog: CampaignPolicyCatalog = if path == "builtin" {
        load_builtin_campaign_policy_catalog()
    } else {
        let contents = std::fs::read_to_string(path)?;
        serde_yaml::from_str(&contents).map_err(|source| {
            ConfigError::InvalidCampaignPolicyCatalog {
                path: path.to_string(),
                source,
            }
        })?
    };

    if catalog.version != 1 {
        return Err(ConfigError::InvalidCampaignPolicyCatalogVersion);
    }
    validate_campaign_policies(&catalog.campaigns)?;
    Ok(catalog)
}

pub fn validate_campaign_policies(policies: &[CampaignPolicyConfig]) -> Result<(), ConfigError> {
    for campaign in policies {
        if campaign.kind.trim().is_empty() {
            return Err(ConfigError::InvalidCampaignPolicyKind);
        }
        if !matches!(campaign.scope.trim(), "client" | "session" | "global") {
            return Err(ConfigError::InvalidCampaignPolicyScope);
        }
        if campaign.score == 0 {
            return Err(ConfigError::InvalidCampaignPolicyScore);
        }
        if campaign.minimum_events == 0
            || campaign.minimum_clients == 0
            || campaign.minimum_sessions == 0
            || campaign.minimum_routes == 0
        {
            return Err(ConfigError::InvalidCampaignPolicyThreshold);
        }
        if campaign
            .categories
            .iter()
            .chain(campaign.path_prefixes.iter())
            .any(|value| value.trim().is_empty())
        {
            return Err(ConfigError::InvalidCampaignPolicyFilter);
        }
        for stage in &campaign.stages {
            if stage.name.trim().is_empty()
                || stage
                    .categories
                    .iter()
                    .any(|category| category.trim().is_empty())
            {
                return Err(ConfigError::InvalidCampaignPolicyStage);
            }
        }
    }
    Ok(())
}
