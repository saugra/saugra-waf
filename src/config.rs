use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    path::PathBuf,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::rules::RuleSeverity;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config file is not valid YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("server.listen must be a valid socket address")]
    InvalidListenAddress,
    #[error("at least one upstream is required")]
    MissingUpstream,
    #[error("upstream '{name}' target must start with http:// or https://")]
    InvalidUpstreamTarget { name: String },
    #[error("upstream names must not be blank")]
    InvalidUpstreamName,
    #[error("upstream names must be unique")]
    DuplicateUpstreamName,
    #[error("routes entries must include a non-empty path_prefix")]
    InvalidRoutePathPrefix,
    #[error("route for path_prefix '{path_prefix}' references unknown upstream '{upstream}'")]
    UnknownRouteUpstream {
        path_prefix: String,
        upstream: String,
    },
    #[error("security.max_body_size must be a positive byte size, for example 2mb")]
    InvalidMaxBodySize,
    #[error("logging.event_log_max_size must be a positive byte size, for example 100mb")]
    InvalidEventLogMaxSize,
    #[error("logging.event_log_max_files must be greater than zero")]
    InvalidEventLogMaxFiles,
    #[error("logging.timezone must be UTC, Africa/Nairobi, or a fixed offset such as +03:00")]
    InvalidLoggingTimezone,
    #[error("rate_limit.requests_per_minute must be greater than zero")]
    InvalidRateLimit,
    #[error("rate_limit.routes entries must include a non-empty path")]
    InvalidRateLimitRoute,
    #[error("rate_limit.redis_url is required when rate_limit.backend is redis")]
    MissingRedisUrl,
    #[error("rate_limit.redis_password must not be blank when provided")]
    InvalidRedisPassword,
    #[error("behavior.score_window must be a positive duration, for example 10m")]
    InvalidBehaviorScoreWindow,
    #[error("behavior.decay_window must be a positive duration, for example 30m")]
    InvalidBehaviorDecayWindow,
    #[error("behavior.state_path must not be blank when behavior.backend is local")]
    InvalidBehaviorStatePath,
    #[error("behavior.monitor_threshold must be greater than zero")]
    InvalidBehaviorMonitorThreshold,
    #[error(
        "behavior.block_threshold must be greater than or equal to behavior.monitor_threshold"
    )]
    InvalidBehaviorBlockThreshold,
    #[error("behavior.route_overrides entries must include a non-empty path")]
    InvalidBehaviorRouteOverride,
    #[error("behavior.category_overrides entries must include a non-empty category")]
    InvalidBehaviorCategoryOverride,
    #[error("behavior.probe_path_catalog must not be blank when provided")]
    InvalidBehaviorProbePathCatalog,
    #[error("behavior.probe_paths entries must not be blank")]
    InvalidBehaviorProbePath,
    #[error("unknown_threats.state_path must not be blank when unknown_threats.backend is local")]
    InvalidUnknownThreatStatePath,
    #[error("unknown_threats.minimum_observations must be greater than zero")]
    InvalidUnknownThreatMinimumObservations,
    #[error("unknown_threats.monitor_threshold must be greater than zero")]
    InvalidUnknownThreatMonitorThreshold,
    #[error("unknown_threats.body_size_multiplier must be at least 2")]
    InvalidUnknownThreatBodySizeMultiplier,
    #[error("unknown_threats.retention must be a positive duration, for example 30d")]
    InvalidUnknownThreatRetention,
    #[error("unknown_threats.max_routes must be greater than zero")]
    InvalidUnknownThreatMaxRoutes,
    #[error("unknown_threats.excluded_paths entries must not be blank")]
    InvalidUnknownThreatExcludedPath,
    #[error("unknown_threats.routes entries must include a non-empty path")]
    InvalidUnknownThreatRoute,
    #[error("unknown_threats.signal_catalog must not be blank")]
    InvalidUnknownThreatSignalCatalogPath,
    #[error("failed to parse unknown-threat signal catalog {path}: {source}")]
    InvalidUnknownThreatSignalCatalog {
        path: String,
        source: serde_yaml::Error,
    },
    #[error("unknown-threat signal catalog version must be 1")]
    InvalidUnknownThreatSignalCatalogVersion,
    #[error("unknown-threat signal catalog scores must be greater than zero")]
    InvalidUnknownThreatSignalScore,
    #[error(
        "inline unknown-threat signal scores are no longer supported; configure unknown_threats.signal_catalog"
    )]
    LegacyUnknownThreatSignalScores,
    #[error("unknown_threats.block_threshold must be greater than or equal to monitor_threshold")]
    InvalidUnknownThreatBlockThreshold,
    #[error("unknown_threats.minimum_independent_signals must be at least 2")]
    InvalidUnknownThreatMinimumSignals,
    #[error("unknown_threats.minimum_baseline_age must be a positive duration")]
    InvalidUnknownThreatMinimumBaselineAge,
    #[error("unknown_threats.minimum_block_observations must be at least minimum_observations")]
    InvalidUnknownThreatBlockObservations,
    #[error("unknown_threats.max_methods_per_route must be greater than zero")]
    InvalidUnknownThreatMaxMethods,
    #[error("unknown_threats.max_content_types_per_route must be greater than zero")]
    InvalidUnknownThreatMaxContentTypes,
    #[error("unknown_threats.max_query_parameters_per_route must be greater than zero")]
    InvalidUnknownThreatMaxQueryParameters,
    #[error("unknown_threats.trusted_learning_clients entries must be valid IPs or CIDRs")]
    InvalidUnknownThreatTrustedLearningClient,
    #[error("unknown_threats.shadow_review_completed must be true before mode can be block")]
    UnknownThreatShadowReviewRequired,
    #[error("campaign_correlation.state_path must not be blank when backend is local")]
    InvalidCampaignStatePath,
    #[error("campaign_correlation.redis_url is required when backend is redis")]
    MissingCampaignRedisUrl,
    #[error("campaign_correlation.redis_password must not be blank when provided")]
    InvalidCampaignRedisPassword,
    #[error("campaign_correlation.redis_key_prefix must not be blank")]
    InvalidCampaignRedisKeyPrefix,
    #[error("campaign_correlation.window and retention must be positive durations")]
    InvalidCampaignDuration,
    #[error("campaign_correlation.retention must be greater than or equal to window")]
    InvalidCampaignRetention,
    #[error("campaign_correlation.max_events must be greater than zero")]
    InvalidCampaignMaxEvents,
    #[error("campaign_correlation.policy_catalog must not be blank")]
    InvalidCampaignPolicyCatalogPath,
    #[error("failed to parse campaign policy catalog {path}: {source}")]
    InvalidCampaignPolicyCatalog {
        path: String,
        source: serde_yaml::Error,
    },
    #[error("campaign policy catalog version must be 1")]
    InvalidCampaignPolicyCatalogVersion,
    #[error("campaign policies must have unique non-empty kinds and positive thresholds")]
    InvalidCampaignPolicy,
    #[error("bot_protection.score_window must be a positive duration, for example 10m")]
    InvalidBotProtectionScoreWindow,
    #[error(
        "bot_protection.temporary_block_duration must be a positive duration, for example 15m"
    )]
    InvalidBotProtectionTemporaryBlockDuration,
    #[error("bot_protection.state_path must not be blank when bot_protection.backend is local")]
    InvalidBotProtectionStatePath,
    #[error("bot_protection.monitor_threshold must be greater than zero")]
    InvalidBotProtectionMonitorThreshold,
    #[error("bot_protection.block_threshold must be greater than or equal to bot_protection.monitor_threshold")]
    InvalidBotProtectionBlockThreshold,
    #[error("bot_protection.routes entries must include a non-empty path")]
    InvalidBotProtectionRoute,
    #[error("bot_protection allowlist and blocklist entries must not be blank")]
    InvalidBotProtectionListEntry,
    #[error("bot_protection.scanner_path_catalog must not be blank when provided")]
    InvalidBotProtectionScannerPathCatalog,
    #[error("bot_protection.scanner_paths entries must not be blank")]
    InvalidBotProtectionScannerPath,
    #[error("bot_protection.rule id, name, category, and explanation must not be blank")]
    InvalidBotProtectionRule,
    #[error("bot_protection.rule.paranoia_level must be greater than zero")]
    InvalidBotProtectionRuleParanoiaLevel,
    #[error("runtime_policy.path must not be blank when runtime policy is enabled")]
    InvalidRuntimePolicyPath,
    #[error("runtime_policy.reload_interval must be a positive duration, for example 5s")]
    InvalidRuntimePolicyReloadInterval,
    #[error("runtime_policy.default_duration must be a positive duration, for example 2h")]
    InvalidRuntimePolicyDefaultDuration,
    #[error("ai.mode must be explain_only when AI is enabled")]
    InvalidAiMode,
    #[error("ai.provider must be ollama, local, or command")]
    InvalidAiProvider,
    #[error("ai.ollama_url must be a local HTTP URL")]
    InvalidAiOllamaUrl,
    #[error("ai.command must not be blank when ai.provider is command")]
    MissingAiCommand,
    #[error("ai.prompt_version, ai.model, and ai.audit_log_path must not be blank")]
    InvalidAiMetadata,
    #[error("ai.audit_log_max_size must be a positive byte size")]
    InvalidAiAuditLogMaxSize,
    #[error("ai.audit_log_max_files must be greater than zero")]
    InvalidAiAuditLogMaxFiles,
    #[error("ai.timeout must be a positive duration")]
    InvalidAiTimeout,
    #[error("ai.max_tuning_suggestions must be greater than zero")]
    InvalidAiSuggestionLimit,
    #[error("rules.inbound_anomaly_threshold must be greater than zero")]
    InvalidAnomalyThreshold,
    #[error("rules paranoia levels must be greater than zero")]
    InvalidParanoiaLevel,
    #[error("rules.blocking_paranoia_level must be less than or equal to rules.detection_paranoia_level")]
    InvalidBlockingParanoiaLevel,
    #[error("rules.exclusions entries must include at least one rule_id or category")]
    InvalidRuleExclusion,
    #[error("posture.expected_external_scheme must be http or https")]
    InvalidPostureScheme,
    #[error(
        "posture.allowed_methods must include at least one method when posture checks are enabled"
    )]
    InvalidPostureAllowedMethods,
    #[error("posture.allowed_methods entries must not be blank")]
    InvalidPostureMethod,
    #[error("posture.dependency_report_path must not be blank when provided")]
    InvalidPostureDependencyReportPath,
    #[error("reports.dependency_report_paths entries must not be blank")]
    InvalidReportPath,
    #[error("standards.owasp_catalog must not be blank when provided")]
    InvalidOwaspCatalogPath,
    #[error("security_summary.schedule must be daily")]
    InvalidSecuritySummarySchedule,
    #[error("security_summary.send_time must use HH:MM 24-hour format")]
    InvalidSecuritySummarySendTime,
    #[error(
        "security_summary.timezone must be UTC, Africa/Nairobi, or a fixed offset such as +03:00"
    )]
    InvalidSecuritySummaryTimezone,
    #[error("security_summary.lookback must be a positive duration, for example 24h")]
    InvalidSecuritySummaryLookback,
    #[error("security_summary.output_path must not be blank")]
    InvalidSecuritySummaryOutputPath,
    #[error("security_summary.channels entries must use type file or email")]
    InvalidSecuritySummaryChannel,
    #[error("security_summary email channels must include at least one recipient")]
    InvalidSecuritySummaryRecipient,
    #[error("storage_cleanup.schedule must be daily")]
    InvalidStorageCleanupSchedule,
    #[error("storage_cleanup.run_time must use HH:MM 24-hour format")]
    InvalidStorageCleanupRunTime,
    #[error("storage_cleanup.targets entries must include a name")]
    InvalidStorageCleanupTargetName,
    #[error("storage_cleanup.targets entries must include a non-empty directory")]
    InvalidStorageCleanupTargetDirectory,
    #[error("storage_cleanup.targets entries must include filename_prefix or filename_suffix")]
    InvalidStorageCleanupTargetPattern,
    #[error("storage_cleanup.targets older_than must be a positive duration, for example 30d")]
    InvalidStorageCleanupOlderThan,
    #[error("forwarded_headers.trusted_proxies entries must not be blank")]
    InvalidForwardedHeadersTrustedProxy,
    #[error("forwarded_headers.real_ip_header must be a valid HTTP header name")]
    InvalidForwardedHeadersRealIpHeader,
    #[error("forwarded_headers.proto_header must be a valid HTTP header name")]
    InvalidForwardedHeadersProtoHeader,
    #[error("forwarded_headers.expected_proto must be http or https")]
    InvalidForwardedHeadersExpectedProto,
    #[error("forwarded_headers.insecure_proto_score must be greater than zero")]
    InvalidForwardedHeadersInsecureProtoScore,
    #[error("websocket.allowed_origins entries must not be blank")]
    InvalidWebSocketAllowedOrigin,
    #[error("websocket.allowed_hosts entries must not be blank")]
    InvalidWebSocketAllowedHost,
    #[error("failed to parse threat path catalog {path}: {source}")]
    InvalidThreatPathCatalog {
        path: String,
        source: serde_yaml::Error,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct SaugraConfig {
    pub server: ServerConfig,
    pub upstreams: Vec<UpstreamConfig>,
    #[serde(default)]
    pub routes: Vec<ProxyRouteConfig>,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub forwarded_headers: ForwardedHeadersConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub behavior: BehaviorConfig,
    #[serde(default)]
    pub unknown_threats: UnknownThreatConfig,
    #[serde(default)]
    pub campaign_correlation: CampaignCorrelationConfig,
    #[serde(default)]
    pub bot_protection: BotProtectionConfig,
    #[serde(default)]
    pub runtime_policy: RuntimePolicyConfig,
    #[serde(default)]
    pub rules: RuleSettings,
    #[serde(default)]
    pub ai: AiConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub websocket: WebSocketConfig,
    #[serde(default)]
    pub posture: PostureConfig,
    #[serde(default)]
    pub reports: ReportConfig,
    #[serde(default)]
    pub standards: StandardsConfig,
    #[serde(default)]
    pub security_summary: SecuritySummaryConfig,
    #[serde(default)]
    pub storage_cleanup: StorageCleanupConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub listen: String,
    #[serde(default)]
    pub mode: WafMode,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WafMode {
    Off,
    #[default]
    Monitor,
    Block,
    Strict,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
    pub name: String,
    pub host: String,
    pub target: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyRouteConfig {
    pub path_prefix: String,
    pub upstream: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    #[serde(default = "default_max_body_size")]
    pub max_body_size: String,
    #[serde(default = "default_true")]
    pub enable_rate_limiting: bool,
    #[serde(default = "default_true")]
    pub block_suspicious_user_agents: bool,
    #[serde(default = "default_true")]
    pub inspect_json_body: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_body_size: default_max_body_size(),
            enable_rate_limiting: true,
            block_suspicious_user_agents: true,
            inspect_json_body: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ForwardedHeadersConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_trusted_proxies")]
    pub trusted_proxies: Vec<String>,
    #[serde(default = "default_real_ip_header")]
    pub real_ip_header: String,
    #[serde(default = "default_proto_header")]
    pub proto_header: String,
    #[serde(default = "default_expected_proto")]
    pub expected_proto: String,
    #[serde(default = "default_insecure_proto_score")]
    pub insecure_proto_score: u16,
}

impl Default for ForwardedHeadersConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            trusted_proxies: default_trusted_proxies(),
            real_ip_header: default_real_ip_header(),
            proto_header: default_proto_header(),
            expected_proto: default_expected_proto(),
            insecure_proto_score: default_insecure_proto_score(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default)]
    pub backend: RateLimitBackend,
    #[serde(default)]
    pub redis_url: Option<String>,
    #[serde(default)]
    pub redis_password: Option<String>,
    #[serde(default = "default_requests_per_minute")]
    pub requests_per_minute: u32,
    #[serde(default = "default_rate_limit_burst")]
    pub burst: u32,
    #[serde(default)]
    pub routes: Vec<RouteRateLimitConfig>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            backend: RateLimitBackend::Memory,
            redis_url: None,
            redis_password: None,
            requests_per_minute: default_requests_per_minute(),
            burst: default_rate_limit_burst(),
            routes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RouteRateLimitConfig {
    pub path: String,
    #[serde(default = "default_requests_per_minute")]
    pub requests_per_minute: u32,
    #[serde(default = "default_rate_limit_burst")]
    pub burst: u32,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitBackend {
    #[default]
    Memory,
    Redis,
}

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

#[derive(Debug, Clone, Deserialize)]
pub struct RuntimePolicyConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_runtime_policy_path")]
    pub path: PathBuf,
    #[serde(default = "default_runtime_policy_reload_interval")]
    pub reload_interval: String,
    #[serde(default = "default_runtime_policy_default_duration")]
    pub default_duration: String,
    #[serde(default)]
    pub allowlist_effect: RuntimeAllowlistEffect,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecuritySummaryConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_security_summary_schedule")]
    pub schedule: String,
    #[serde(default = "default_security_summary_send_time")]
    pub send_time: String,
    #[serde(default = "default_logging_timezone")]
    pub timezone: String,
    #[serde(default = "default_security_summary_lookback")]
    pub lookback: String,
    #[serde(default = "default_security_summary_output_path")]
    pub output_path: PathBuf,
    #[serde(default = "default_security_summary_channels")]
    pub channels: Vec<SecuritySummaryChannelConfig>,
}

impl Default for SecuritySummaryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            schedule: default_security_summary_schedule(),
            send_time: default_security_summary_send_time(),
            timezone: default_logging_timezone(),
            lookback: default_security_summary_lookback(),
            output_path: default_security_summary_output_path(),
            channels: default_security_summary_channels(),
        }
    }
}

impl SecuritySummaryConfig {
    pub fn lookback_seconds(&self) -> u64 {
        parse_duration_seconds(&self.lookback).unwrap_or(24 * 60 * 60)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecuritySummaryChannelConfig {
    #[serde(rename = "type")]
    pub channel_type: String,
    #[serde(default)]
    pub to: Vec<String>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default = "default_sendmail_path")]
    pub sendmail_path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageCleanupConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_storage_cleanup_schedule")]
    pub schedule: String,
    #[serde(default = "default_storage_cleanup_run_time")]
    pub run_time: String,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default = "default_storage_cleanup_targets")]
    pub targets: Vec<StorageCleanupTargetConfig>,
}

impl Default for StorageCleanupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            schedule: default_storage_cleanup_schedule(),
            run_time: default_storage_cleanup_run_time(),
            dry_run: false,
            targets: default_storage_cleanup_targets(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageCleanupTargetConfig {
    pub name: String,
    pub directory: PathBuf,
    #[serde(default)]
    pub filename_prefix: Option<String>,
    #[serde(default)]
    pub filename_suffix: Option<String>,
    #[serde(default = "default_storage_cleanup_older_than")]
    pub older_than: String,
}

impl Default for SecuritySummaryChannelConfig {
    fn default() -> Self {
        Self {
            channel_type: "file".to_string(),
            to: Vec::new(),
            from: None,
            sendmail_path: default_sendmail_path(),
        }
    }
}

impl Default for RuntimePolicyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_runtime_policy_path(),
            reload_interval: default_runtime_policy_reload_interval(),
            default_duration: default_runtime_policy_default_duration(),
            allowlist_effect: RuntimeAllowlistEffect::SkipBotAndBehaviorBlock,
        }
    }
}

impl RuntimePolicyConfig {
    pub fn reload_interval_seconds(&self) -> u64 {
        parse_duration_seconds(&self.reload_interval).unwrap_or(5)
    }

    pub fn default_duration_seconds(&self) -> u64 {
        parse_duration_seconds(&self.default_duration).unwrap_or(2 * 60 * 60)
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAllowlistEffect {
    #[default]
    SkipBotAndBehaviorBlock,
    MonitorAll,
    AllowAll,
    Block,
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
struct ThreatPathCatalog {
    #[serde(default)]
    behavior_probe_paths: Vec<String>,
    #[serde(default)]
    bot_scanner_paths: Vec<String>,
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct AiConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_ai_mode")]
    pub mode: String,
    #[serde(default = "default_ai_provider")]
    pub provider: String,
    #[serde(default = "default_ai_ollama_url")]
    pub ollama_url: String,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub command_args: Vec<String>,
    #[serde(default = "default_ai_model")]
    pub model: String,
    #[serde(default = "default_ai_prompt_version")]
    pub prompt_version: String,
    #[serde(default = "default_ai_timeout")]
    pub timeout: String,
    #[serde(default = "default_ai_audit_log_path")]
    pub audit_log_path: PathBuf,
    #[serde(default = "default_ai_audit_log_max_size")]
    pub audit_log_max_size: String,
    #[serde(default = "default_ai_audit_log_max_files")]
    pub audit_log_max_files: usize,
    #[serde(default = "default_ai_max_tuning_suggestions")]
    pub max_tuning_suggestions: usize,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: default_ai_mode(),
            provider: default_ai_provider(),
            ollama_url: default_ai_ollama_url(),
            command: None,
            command_args: Vec::new(),
            model: default_ai_model(),
            prompt_version: default_ai_prompt_version(),
            timeout: default_ai_timeout(),
            audit_log_path: default_ai_audit_log_path(),
            audit_log_max_size: default_ai_audit_log_max_size(),
            audit_log_max_files: default_ai_audit_log_max_files(),
            max_tuning_suggestions: default_ai_max_tuning_suggestions(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_format")]
    pub format: String,
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_event_log_path")]
    pub event_log_path: String,
    #[serde(default = "default_event_log_max_size")]
    pub event_log_max_size: String,
    #[serde(default = "default_event_log_max_files")]
    pub event_log_max_files: usize,
    #[serde(default = "default_logging_timezone")]
    pub timezone: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            format: default_log_format(),
            level: default_log_level(),
            event_log_path: default_event_log_path(),
            event_log_max_size: default_event_log_max_size(),
            event_log_max_files: default_event_log_max_files(),
            timezone: default_logging_timezone(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebSocketConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_origins: Vec::new(),
            allowed_hosts: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PostureConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_expected_external_scheme")]
    pub expected_external_scheme: String,
    #[serde(default = "default_true")]
    pub require_secure_cookies: bool,
    #[serde(default = "default_true")]
    pub require_security_headers: bool,
    #[serde(default = "default_allowed_methods")]
    pub allowed_methods: Vec<String>,
    #[serde(default)]
    pub dependency_report_path: Option<PathBuf>,
}

impl Default for PostureConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            expected_external_scheme: default_expected_external_scheme(),
            require_secure_cookies: true,
            require_security_headers: true,
            allowed_methods: default_allowed_methods(),
            dependency_report_path: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct StandardsConfig {
    #[serde(default = "default_owasp_catalog")]
    pub owasp_catalog: PathBuf,
}

impl Default for StandardsConfig {
    fn default() -> Self {
        Self {
            owasp_catalog: default_owasp_catalog(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ReportConfig {
    #[serde(default)]
    pub dependency_report_paths: Vec<PathBuf>,
}

impl SaugraConfig {
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let contents = fs::read_to_string(path)?;
        let mut config: Self = serde_yaml::from_str(&contents)?;
        config.resolve_threat_path_catalogs()?;
        config.resolve_unknown_threat_signal_catalog()?;
        config.resolve_campaign_policy_catalog()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        self.listen_addr()?;

        if self.upstreams.is_empty() {
            return Err(ConfigError::MissingUpstream);
        }

        let mut upstream_names = std::collections::BTreeSet::new();
        for upstream in &self.upstreams {
            if upstream.name.trim().is_empty() {
                return Err(ConfigError::InvalidUpstreamName);
            }

            if !upstream_names.insert(upstream.name.as_str()) {
                return Err(ConfigError::DuplicateUpstreamName);
            }

            if !(upstream.target.starts_with("http://") || upstream.target.starts_with("https://"))
            {
                return Err(ConfigError::InvalidUpstreamTarget {
                    name: upstream.name.clone(),
                });
            }
        }

        for route in &self.routes {
            if route.path_prefix.trim().is_empty() {
                return Err(ConfigError::InvalidRoutePathPrefix);
            }

            if !upstream_names.contains(route.upstream.as_str()) {
                return Err(ConfigError::UnknownRouteUpstream {
                    path_prefix: route.path_prefix.clone(),
                    upstream: route.upstream.clone(),
                });
            }
        }

        if parse_byte_size(&self.security.max_body_size).is_none() {
            return Err(ConfigError::InvalidMaxBodySize);
        }

        if parse_byte_size(&self.logging.event_log_max_size).is_none() {
            return Err(ConfigError::InvalidEventLogMaxSize);
        }

        if self.logging.event_log_max_files == 0 {
            return Err(ConfigError::InvalidEventLogMaxFiles);
        }

        if !crate::event_store::is_supported_timestamp_timezone(&self.logging.timezone) {
            return Err(ConfigError::InvalidLoggingTimezone);
        }

        if self.rate_limit.requests_per_minute == 0 {
            return Err(ConfigError::InvalidRateLimit);
        }

        for route in &self.rate_limit.routes {
            if route.path.trim().is_empty() {
                return Err(ConfigError::InvalidRateLimitRoute);
            }

            if route.requests_per_minute == 0 {
                return Err(ConfigError::InvalidRateLimit);
            }
        }

        self.validate_unknown_threats()?;
        self.validate_campaign_correlation()?;

        if self.rate_limit.backend == RateLimitBackend::Redis
            && self
                .rate_limit
                .redis_url
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
        {
            return Err(ConfigError::MissingRedisUrl);
        }

        if self
            .rate_limit
            .redis_password
            .as_deref()
            .is_some_and(|password| password.trim().is_empty())
        {
            return Err(ConfigError::InvalidRedisPassword);
        }

        self.validate_behavior()?;
        self.validate_bot_protection()?;
        self.validate_runtime_policy()?;
        self.validate_forwarded_headers()?;

        if self.ai.enabled && self.ai.mode != "explain_only" {
            return Err(ConfigError::InvalidAiMode);
        }
        if !matches!(self.ai.provider.as_str(), "ollama" | "local" | "command") {
            return Err(ConfigError::InvalidAiProvider);
        }
        if !is_local_ollama_url(&self.ai.ollama_url) {
            return Err(ConfigError::InvalidAiOllamaUrl);
        }
        if self.ai.enabled
            && self.ai.provider == "command"
            && self
                .ai
                .command
                .as_deref()
                .unwrap_or_default()
                .trim()
                .is_empty()
        {
            return Err(ConfigError::MissingAiCommand);
        }
        if self.ai.prompt_version.trim().is_empty()
            || self.ai.model.trim().is_empty()
            || self.ai.audit_log_path.as_os_str().is_empty()
        {
            return Err(ConfigError::InvalidAiMetadata);
        }
        if parse_byte_size(&self.ai.audit_log_max_size).is_none() {
            return Err(ConfigError::InvalidAiAuditLogMaxSize);
        }
        if self.ai.audit_log_max_files == 0 {
            return Err(ConfigError::InvalidAiAuditLogMaxFiles);
        }
        if parse_duration_seconds(&self.ai.timeout).is_none() {
            return Err(ConfigError::InvalidAiTimeout);
        }
        if self.ai.max_tuning_suggestions == 0 {
            return Err(ConfigError::InvalidAiSuggestionLimit);
        }

        if self.rules.inbound_anomaly_threshold == 0 {
            return Err(ConfigError::InvalidAnomalyThreshold);
        }

        if self.rules.paranoia_level == 0
            || self.rules.detection_paranoia_level() == 0
            || self.rules.blocking_paranoia_level() == 0
        {
            return Err(ConfigError::InvalidParanoiaLevel);
        }

        if self.rules.blocking_paranoia_level() > self.rules.detection_paranoia_level() {
            return Err(ConfigError::InvalidBlockingParanoiaLevel);
        }

        for exclusion in &self.rules.exclusions {
            if exclusion.rule_ids.is_empty() && exclusion.categories.is_empty() {
                return Err(ConfigError::InvalidRuleExclusion);
            }

            let has_blank = exclusion
                .rule_ids
                .iter()
                .chain(exclusion.categories.iter())
                .chain(exclusion.path_prefixes.iter())
                .chain(exclusion.query_params.iter())
                .chain(exclusion.headers.iter())
                .any(|value| value.trim().is_empty());

            if has_blank {
                return Err(ConfigError::InvalidRuleExclusion);
            }
        }

        if self.posture.enabled {
            let scheme = self.posture.expected_external_scheme.trim();
            if !matches!(scheme, "http" | "https") {
                return Err(ConfigError::InvalidPostureScheme);
            }

            if self.posture.allowed_methods.is_empty() {
                return Err(ConfigError::InvalidPostureAllowedMethods);
            }
        }

        if self
            .posture
            .allowed_methods
            .iter()
            .any(|method| method.trim().is_empty())
        {
            return Err(ConfigError::InvalidPostureMethod);
        }

        if self
            .posture
            .dependency_report_path
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(ConfigError::InvalidPostureDependencyReportPath);
        }

        if self
            .reports
            .dependency_report_paths
            .iter()
            .any(|path| path.as_os_str().is_empty())
        {
            return Err(ConfigError::InvalidReportPath);
        }

        if self.standards.owasp_catalog.as_os_str().is_empty() {
            return Err(ConfigError::InvalidOwaspCatalogPath);
        }

        self.validate_security_summary()?;
        self.validate_storage_cleanup()?;

        if self
            .websocket
            .allowed_origins
            .iter()
            .any(|origin| origin.trim().is_empty())
        {
            return Err(ConfigError::InvalidWebSocketAllowedOrigin);
        }

        if self
            .websocket
            .allowed_hosts
            .iter()
            .any(|host| host.trim().is_empty())
        {
            return Err(ConfigError::InvalidWebSocketAllowedHost);
        }

        Ok(())
    }

    fn validate_forwarded_headers(&self) -> Result<(), ConfigError> {
        if self
            .forwarded_headers
            .trusted_proxies
            .iter()
            .any(|proxy| proxy.trim().is_empty())
        {
            return Err(ConfigError::InvalidForwardedHeadersTrustedProxy);
        }

        if !is_valid_header_name(&self.forwarded_headers.real_ip_header) {
            return Err(ConfigError::InvalidForwardedHeadersRealIpHeader);
        }

        if !is_valid_header_name(&self.forwarded_headers.proto_header) {
            return Err(ConfigError::InvalidForwardedHeadersProtoHeader);
        }

        if !matches!(
            self.forwarded_headers.expected_proto.trim(),
            "http" | "https"
        ) {
            return Err(ConfigError::InvalidForwardedHeadersExpectedProto);
        }

        if self.forwarded_headers.insecure_proto_score == 0 {
            return Err(ConfigError::InvalidForwardedHeadersInsecureProtoScore);
        }

        Ok(())
    }

    fn validate_storage_cleanup(&self) -> Result<(), ConfigError> {
        if self.storage_cleanup.schedule.trim() != "daily" {
            return Err(ConfigError::InvalidStorageCleanupSchedule);
        }

        if !is_valid_send_time(&self.storage_cleanup.run_time) {
            return Err(ConfigError::InvalidStorageCleanupRunTime);
        }

        for target in &self.storage_cleanup.targets {
            if target.name.trim().is_empty() {
                return Err(ConfigError::InvalidStorageCleanupTargetName);
            }

            if target.directory.as_os_str().is_empty() {
                return Err(ConfigError::InvalidStorageCleanupTargetDirectory);
            }

            let has_prefix = target
                .filename_prefix
                .as_deref()
                .is_some_and(|prefix| !prefix.trim().is_empty());
            let has_suffix = target
                .filename_suffix
                .as_deref()
                .is_some_and(|suffix| !suffix.trim().is_empty());
            if !has_prefix && !has_suffix {
                return Err(ConfigError::InvalidStorageCleanupTargetPattern);
            }

            if target
                .filename_prefix
                .as_deref()
                .is_some_and(|prefix| prefix.trim().is_empty())
                || target
                    .filename_suffix
                    .as_deref()
                    .is_some_and(|suffix| suffix.trim().is_empty())
            {
                return Err(ConfigError::InvalidStorageCleanupTargetPattern);
            }

            if parse_duration_seconds(&target.older_than).is_none() {
                return Err(ConfigError::InvalidStorageCleanupOlderThan);
            }
        }

        Ok(())
    }

    fn validate_security_summary(&self) -> Result<(), ConfigError> {
        if self.security_summary.schedule.trim() != "daily" {
            return Err(ConfigError::InvalidSecuritySummarySchedule);
        }

        if !is_valid_send_time(&self.security_summary.send_time) {
            return Err(ConfigError::InvalidSecuritySummarySendTime);
        }

        if !crate::event_store::is_supported_timestamp_timezone(&self.security_summary.timezone) {
            return Err(ConfigError::InvalidSecuritySummaryTimezone);
        }

        if parse_duration_seconds(&self.security_summary.lookback).is_none() {
            return Err(ConfigError::InvalidSecuritySummaryLookback);
        }

        if self.security_summary.output_path.as_os_str().is_empty() {
            return Err(ConfigError::InvalidSecuritySummaryOutputPath);
        }

        for channel in &self.security_summary.channels {
            match channel.channel_type.trim() {
                "file" => {}
                "email" => {
                    if channel.to.is_empty()
                        || channel
                            .to
                            .iter()
                            .any(|recipient| recipient.trim().is_empty())
                        || channel
                            .from
                            .as_deref()
                            .is_some_and(|from| from.trim().is_empty())
                    {
                        return Err(ConfigError::InvalidSecuritySummaryRecipient);
                    }
                }
                _ => return Err(ConfigError::InvalidSecuritySummaryChannel),
            }
        }

        Ok(())
    }

    fn resolve_threat_path_catalogs(&mut self) -> Result<(), ConfigError> {
        if let Some(catalog_path) = self.behavior.probe_path_catalog.as_deref() {
            if catalog_path.trim().is_empty() {
                return Err(ConfigError::InvalidBehaviorProbePathCatalog);
            }
            let catalog = load_threat_path_catalog(catalog_path)?;
            self.behavior.probe_paths.clear();
            merge_unique_paths(&mut self.behavior.probe_paths, catalog.behavior_probe_paths);
        }
        merge_unique_paths(
            &mut self.behavior.probe_paths,
            self.behavior.probe_paths_extra.clone(),
        );

        if let Some(catalog_path) = self.bot_protection.scanner_path_catalog.as_deref() {
            if catalog_path.trim().is_empty() {
                return Err(ConfigError::InvalidBotProtectionScannerPathCatalog);
            }
            let catalog = load_threat_path_catalog(catalog_path)?;
            self.bot_protection.scanner_paths.clear();
            merge_unique_paths(
                &mut self.bot_protection.scanner_paths,
                catalog.bot_scanner_paths,
            );
        }
        merge_unique_paths(
            &mut self.bot_protection.scanner_paths,
            self.bot_protection.scanner_paths_extra.clone(),
        );

        Ok(())
    }

    fn resolve_unknown_threat_signal_catalog(&mut self) -> Result<(), ConfigError> {
        let path = self.unknown_threats.signal_catalog.trim();
        if path.is_empty() {
            return Err(ConfigError::InvalidUnknownThreatSignalCatalogPath);
        }
        self.unknown_threats.signals = load_unknown_threat_signal_catalog(path)?.signals;
        Ok(())
    }

    fn resolve_campaign_policy_catalog(&mut self) -> Result<(), ConfigError> {
        let path = self.campaign_correlation.policy_catalog.trim();
        if path.is_empty() {
            return Err(ConfigError::InvalidCampaignPolicyCatalogPath);
        }
        self.campaign_correlation.policies = load_campaign_policy_catalog(path)?.campaigns;
        Ok(())
    }

    fn validate_behavior(&self) -> Result<(), ConfigError> {
        if parse_duration_seconds(&self.behavior.score_window).is_none() {
            return Err(ConfigError::InvalidBehaviorScoreWindow);
        }

        if parse_duration_seconds(&self.behavior.decay_window).is_none() {
            return Err(ConfigError::InvalidBehaviorDecayWindow);
        }

        if self.behavior.backend == BehaviorBackend::Local
            && self.behavior.state_path.as_os_str().is_empty()
        {
            return Err(ConfigError::InvalidBehaviorStatePath);
        }

        validate_behavior_thresholds(
            self.behavior.monitor_threshold,
            self.behavior.block_threshold,
        )?;

        for route in &self.behavior.route_overrides {
            if route.path.trim().is_empty() {
                return Err(ConfigError::InvalidBehaviorRouteOverride);
            }

            validate_optional_behavior_thresholds(
                route.monitor_threshold,
                route.block_threshold,
                self.behavior.monitor_threshold,
                self.behavior.block_threshold,
            )?;

            if route
                .score_window
                .as_deref()
                .is_some_and(|duration| parse_duration_seconds(duration).is_none())
            {
                return Err(ConfigError::InvalidBehaviorScoreWindow);
            }
        }

        for category in &self.behavior.category_overrides {
            if category.category.trim().is_empty() {
                return Err(ConfigError::InvalidBehaviorCategoryOverride);
            }

            validate_optional_behavior_thresholds(
                category.monitor_threshold,
                category.block_threshold,
                self.behavior.monitor_threshold,
                self.behavior.block_threshold,
            )?;
        }

        if self
            .behavior
            .probe_path_catalog
            .as_deref()
            .is_some_and(|path| path.trim().is_empty())
        {
            return Err(ConfigError::InvalidBehaviorProbePathCatalog);
        }

        if self
            .behavior
            .probe_paths
            .iter()
            .chain(self.behavior.probe_paths_extra.iter())
            .chain(self.behavior.probe_path_exclusions.iter())
            .any(|path| path.trim().is_empty())
        {
            return Err(ConfigError::InvalidBehaviorProbePath);
        }

        Ok(())
    }

    fn validate_unknown_threats(&self) -> Result<(), ConfigError> {
        if self.unknown_threats.backend == BehaviorBackend::Local
            && self.unknown_threats.state_path.as_os_str().is_empty()
        {
            return Err(ConfigError::InvalidUnknownThreatStatePath);
        }
        if self.unknown_threats.minimum_observations == 0 {
            return Err(ConfigError::InvalidUnknownThreatMinimumObservations);
        }
        if self.unknown_threats.mode == UnknownThreatMode::Block
            && !self.unknown_threats.shadow_review_completed
        {
            return Err(ConfigError::UnknownThreatShadowReviewRequired);
        }
        if self.unknown_threats.monitor_threshold == 0 {
            return Err(ConfigError::InvalidUnknownThreatMonitorThreshold);
        }
        if self.unknown_threats.block_threshold < self.unknown_threats.monitor_threshold {
            return Err(ConfigError::InvalidUnknownThreatBlockThreshold);
        }
        if self.unknown_threats.minimum_independent_signals < 2 {
            return Err(ConfigError::InvalidUnknownThreatMinimumSignals);
        }
        if parse_duration_seconds(&self.unknown_threats.minimum_baseline_age).is_none() {
            return Err(ConfigError::InvalidUnknownThreatMinimumBaselineAge);
        }
        if self.unknown_threats.minimum_block_observations
            < self.unknown_threats.minimum_observations
        {
            return Err(ConfigError::InvalidUnknownThreatBlockObservations);
        }
        if self.unknown_threats.body_size_multiplier < 2 {
            return Err(ConfigError::InvalidUnknownThreatBodySizeMultiplier);
        }
        if self.unknown_threats.promotion_observations == 0 {
            return Err(ConfigError::InvalidUnknownThreatMinimumObservations);
        }
        if self.unknown_threats.promotion_observations > self.unknown_threats.minimum_observations {
            return Err(ConfigError::InvalidUnknownThreatMinimumObservations);
        }
        if self.unknown_threats.max_methods_per_route == 0 {
            return Err(ConfigError::InvalidUnknownThreatMaxMethods);
        }
        if self.unknown_threats.max_content_types_per_route == 0 {
            return Err(ConfigError::InvalidUnknownThreatMaxContentTypes);
        }
        if self.unknown_threats.max_query_parameters_per_route == 0 {
            return Err(ConfigError::InvalidUnknownThreatMaxQueryParameters);
        }
        if self
            .unknown_threats
            .trusted_learning_clients
            .iter()
            .any(|value| !is_valid_ip_or_cidr(value))
        {
            return Err(ConfigError::InvalidUnknownThreatTrustedLearningClient);
        }
        if self.unknown_threats.signal_catalog.trim().is_empty() {
            return Err(ConfigError::InvalidUnknownThreatSignalCatalogPath);
        }
        if self.unknown_threats.unseen_method_score.is_some()
            || self.unknown_threats.unseen_content_type_score.is_some()
            || self.unknown_threats.unseen_query_parameter_score.is_some()
            || self.unknown_threats.body_size_score.is_some()
        {
            return Err(ConfigError::LegacyUnknownThreatSignalScores);
        }
        if [
            self.unknown_threats.signals.unseen_method.score,
            self.unknown_threats.signals.unseen_content_type.score,
            self.unknown_threats.signals.unseen_query_parameter.score,
            self.unknown_threats.signals.body_size_deviation.score,
        ]
        .contains(&0)
        {
            return Err(ConfigError::InvalidUnknownThreatSignalScore);
        }
        if parse_duration_seconds(&self.unknown_threats.retention).is_none() {
            return Err(ConfigError::InvalidUnknownThreatRetention);
        }
        if self.unknown_threats.max_routes == 0 {
            return Err(ConfigError::InvalidUnknownThreatMaxRoutes);
        }
        if self
            .unknown_threats
            .excluded_paths
            .iter()
            .any(|path| path.trim().is_empty())
        {
            return Err(ConfigError::InvalidUnknownThreatExcludedPath);
        }
        for route in &self.unknown_threats.routes {
            if route.path.trim().is_empty() {
                return Err(ConfigError::InvalidUnknownThreatRoute);
            }
            if route.minimum_observations == Some(0) {
                return Err(ConfigError::InvalidUnknownThreatMinimumObservations);
            }
            if route.monitor_threshold == Some(0) {
                return Err(ConfigError::InvalidUnknownThreatMonitorThreshold);
            }
            let monitor_threshold = route
                .monitor_threshold
                .unwrap_or(self.unknown_threats.monitor_threshold);
            if route
                .block_threshold
                .is_some_and(|threshold| threshold < monitor_threshold)
            {
                return Err(ConfigError::InvalidUnknownThreatBlockThreshold);
            }
            if route
                .minimum_independent_signals
                .is_some_and(|signals| signals < 2)
            {
                return Err(ConfigError::InvalidUnknownThreatMinimumSignals);
            }
            if route
                .minimum_baseline_age
                .as_deref()
                .is_some_and(|duration| parse_duration_seconds(duration).is_none())
            {
                return Err(ConfigError::InvalidUnknownThreatMinimumBaselineAge);
            }
            let minimum_observations = route
                .minimum_observations
                .unwrap_or(self.unknown_threats.minimum_observations);
            if route
                .minimum_block_observations
                .is_some_and(|observations| observations < minimum_observations)
            {
                return Err(ConfigError::InvalidUnknownThreatBlockObservations);
            }
        }

        Ok(())
    }

    fn validate_campaign_correlation(&self) -> Result<(), ConfigError> {
        let config = &self.campaign_correlation;
        if config.backend == CampaignBackend::Local && config.state_path.as_os_str().is_empty() {
            return Err(ConfigError::InvalidCampaignStatePath);
        }
        if config.backend == CampaignBackend::Redis
            && config.redis_url.as_deref().unwrap_or("").trim().is_empty()
        {
            return Err(ConfigError::MissingCampaignRedisUrl);
        }
        if config
            .redis_password
            .as_deref()
            .is_some_and(|password| password.trim().is_empty())
        {
            return Err(ConfigError::InvalidCampaignRedisPassword);
        }
        if config.redis_key_prefix.trim().is_empty() {
            return Err(ConfigError::InvalidCampaignRedisKeyPrefix);
        }
        let window =
            parse_duration_seconds(&config.window).ok_or(ConfigError::InvalidCampaignDuration)?;
        let retention = parse_duration_seconds(&config.retention)
            .ok_or(ConfigError::InvalidCampaignDuration)?;
        if retention < window {
            return Err(ConfigError::InvalidCampaignRetention);
        }
        if config.max_events == 0 {
            return Err(ConfigError::InvalidCampaignMaxEvents);
        }
        if config.policy_catalog.trim().is_empty() {
            return Err(ConfigError::InvalidCampaignPolicyCatalogPath);
        }
        validate_campaign_policies(&config.policies)?;
        Ok(())
    }

    fn validate_bot_protection(&self) -> Result<(), ConfigError> {
        if parse_duration_seconds(&self.bot_protection.score_window).is_none() {
            return Err(ConfigError::InvalidBotProtectionScoreWindow);
        }

        if parse_duration_seconds(&self.bot_protection.temporary_block_duration).is_none() {
            return Err(ConfigError::InvalidBotProtectionTemporaryBlockDuration);
        }

        if self.bot_protection.backend == BehaviorBackend::Local
            && self.bot_protection.state_path.as_os_str().is_empty()
        {
            return Err(ConfigError::InvalidBotProtectionStatePath);
        }

        validate_bot_protection_thresholds(
            self.bot_protection.monitor_threshold,
            self.bot_protection.block_threshold,
        )?;

        if bot_list_has_blank(&self.bot_protection.allowlists)
            || bot_list_has_blank(&self.bot_protection.blocklists)
        {
            return Err(ConfigError::InvalidBotProtectionListEntry);
        }

        for route in &self.bot_protection.routes {
            if route.path.trim().is_empty() {
                return Err(ConfigError::InvalidBotProtectionRoute);
            }

            validate_optional_bot_protection_thresholds(
                route.monitor_threshold,
                route.block_threshold,
                self.bot_protection.monitor_threshold,
                self.bot_protection.block_threshold,
            )?;
        }

        if self
            .bot_protection
            .scanner_path_catalog
            .as_deref()
            .is_some_and(|path| path.trim().is_empty())
        {
            return Err(ConfigError::InvalidBotProtectionScannerPathCatalog);
        }

        if self
            .bot_protection
            .scanner_paths
            .iter()
            .chain(self.bot_protection.scanner_paths_extra.iter())
            .chain(self.bot_protection.scanner_path_exclusions.iter())
            .any(|path| path.trim().is_empty())
        {
            return Err(ConfigError::InvalidBotProtectionScannerPath);
        }

        if self.bot_protection.rule.id.trim().is_empty()
            || self.bot_protection.rule.name.trim().is_empty()
            || self.bot_protection.rule.category.trim().is_empty()
            || self.bot_protection.rule.explanation.trim().is_empty()
            || self
                .bot_protection
                .rule
                .owasp_category
                .as_deref()
                .is_some_and(|category| category.trim().is_empty())
        {
            return Err(ConfigError::InvalidBotProtectionRule);
        }

        if self.bot_protection.rule.paranoia_level == 0 {
            return Err(ConfigError::InvalidBotProtectionRuleParanoiaLevel);
        }

        Ok(())
    }

    fn validate_runtime_policy(&self) -> Result<(), ConfigError> {
        if self.runtime_policy.enabled && self.runtime_policy.path.as_os_str().is_empty() {
            return Err(ConfigError::InvalidRuntimePolicyPath);
        }

        if parse_duration_seconds(&self.runtime_policy.reload_interval).is_none() {
            return Err(ConfigError::InvalidRuntimePolicyReloadInterval);
        }

        if parse_duration_seconds(&self.runtime_policy.default_duration).is_none() {
            return Err(ConfigError::InvalidRuntimePolicyDefaultDuration);
        }

        Ok(())
    }

    pub fn listen_addr(&self) -> Result<SocketAddr, ConfigError> {
        self.server
            .listen
            .parse()
            .map_err(|_| ConfigError::InvalidListenAddress)
    }

    pub fn max_body_size_bytes(&self) -> Result<u64, ConfigError> {
        parse_byte_size(&self.security.max_body_size).ok_or(ConfigError::InvalidMaxBodySize)
    }

    pub fn event_log_max_size_bytes(&self) -> Result<u64, ConfigError> {
        parse_byte_size(&self.logging.event_log_max_size).ok_or(ConfigError::InvalidEventLogMaxSize)
    }

    pub fn summary(&self) -> String {
        let upstreams = self
            .upstreams
            .iter()
            .map(|upstream| format!("{}@{}->{}", upstream.name, upstream.host, upstream.target))
            .collect::<Vec<_>>()
            .join(",");

        format!(
            "listen={}, mode={:?}, upstreams=[{}], routes={}, max_body_size={}, rate_limiting={}, rate_limit_backend={:?}, requests_per_minute={}, burst={}, route_limits={}, behavior_enabled={}, behavior_mode={:?}, behavior_backend={:?}, behavior_state_path={}, behavior_score_window={}, behavior_decay_window={}, behavior_monitor_threshold={}, behavior_block_threshold={}, behavior_route_overrides={}, behavior_category_overrides={}, unknown_threats_enabled={}, unknown_threats_mode={:?}, unknown_threats_backend={:?}, unknown_threats_state_path={}, unknown_threats_signal_catalog={}, unknown_threats_minimum_observations={}, unknown_threats_monitor_threshold={}, unknown_threats_block_threshold={}, unknown_threats_minimum_independent_signals={}, unknown_threats_minimum_baseline_age={}, unknown_threats_minimum_block_observations={}, unknown_threats_retention={}, unknown_threats_max_routes={}, unknown_threats_excluded_paths={}, unknown_threats_route_overrides={}, bot_protection_enabled={}, bot_protection_mode={:?}, bot_protection_backend={:?}, bot_protection_state_path={}, bot_protection_monitor_threshold={}, bot_protection_block_threshold={}, bot_protection_routes={}, runtime_policy_enabled={}, runtime_policy_path={}, runtime_policy_reload_interval={}, runtime_policy_allowlist_effect={:?}, inspect_json_body={}, websocket_enabled={}, websocket_allowed_origins={}, websocket_allowed_hosts={}, owasp_crs={}, paranoia_level={}, detection_paranoia_level={}, blocking_paranoia_level={}",
            self.server.listen,
            self.server.mode,
            upstreams,
            self.routes.len(),
            self.security.max_body_size,
            self.security.enable_rate_limiting,
            self.rate_limit.backend,
            self.rate_limit.requests_per_minute,
            self.rate_limit.burst,
            self.rate_limit.routes.len(),
            self.behavior.enabled,
            self.behavior.mode,
            self.behavior.backend,
            self.behavior.state_path.display(),
            self.behavior.score_window,
            self.behavior.decay_window,
            self.behavior.monitor_threshold,
            self.behavior.block_threshold,
            self.behavior.route_overrides.len(),
            self.behavior.category_overrides.len(),
            self.unknown_threats.enabled,
            self.unknown_threats.mode,
            self.unknown_threats.backend,
            self.unknown_threats.state_path.display(),
            self.unknown_threats.signal_catalog,
            self.unknown_threats.minimum_observations,
            self.unknown_threats.monitor_threshold,
            self.unknown_threats.block_threshold,
            self.unknown_threats.minimum_independent_signals,
            self.unknown_threats.minimum_baseline_age,
            self.unknown_threats.minimum_block_observations,
            self.unknown_threats.retention,
            self.unknown_threats.max_routes,
            self.unknown_threats.excluded_paths.len(),
            self.unknown_threats.routes.len(),
            self.bot_protection.enabled,
            self.bot_protection.mode,
            self.bot_protection.backend,
            self.bot_protection.state_path.display(),
            self.bot_protection.monitor_threshold,
            self.bot_protection.block_threshold,
            self.bot_protection.routes.len(),
            self.runtime_policy.enabled,
            self.runtime_policy.path.display(),
            self.runtime_policy.reload_interval,
            self.runtime_policy.allowlist_effect,
            self.security.inspect_json_body,
            self.websocket.enabled,
            self.websocket.allowed_origins.len(),
            self.websocket.allowed_hosts.len(),
            self.rules.owasp_crs,
            self.rules.paranoia_level,
            self.rules.detection_paranoia_level(),
            self.rules.blocking_paranoia_level()
        )
    }

    pub fn dependency_report_paths(&self) -> Vec<PathBuf> {
        let mut paths = self.reports.dependency_report_paths.clone();
        if let Some(path) = &self.posture.dependency_report_path {
            if !paths.iter().any(|existing| existing == path) {
                paths.push(path.clone());
            }
        }
        paths
    }
}

fn parse_byte_size(value: &str) -> Option<u64> {
    let trimmed = value.trim().to_ascii_lowercase();
    let split_at = trimmed.find(|c: char| !c.is_ascii_digit())?;
    let (number, unit) = trimmed.split_at(split_at);
    let number = number.parse::<u64>().ok()?;
    let multiplier = match unit.trim() {
        "b" | "" => 1,
        "kb" | "kib" => 1024,
        "mb" | "mib" => 1024 * 1024,
        "gb" | "gib" => 1024 * 1024 * 1024,
        _ => return None,
    };

    number.checked_mul(multiplier)
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

fn validate_behavior_thresholds(
    monitor_threshold: u16,
    block_threshold: u16,
) -> Result<(), ConfigError> {
    if monitor_threshold == 0 {
        return Err(ConfigError::InvalidBehaviorMonitorThreshold);
    }

    if block_threshold < monitor_threshold {
        return Err(ConfigError::InvalidBehaviorBlockThreshold);
    }

    Ok(())
}

fn validate_optional_behavior_thresholds(
    monitor_threshold: Option<u16>,
    block_threshold: Option<u16>,
    default_monitor_threshold: u16,
    default_block_threshold: u16,
) -> Result<(), ConfigError> {
    let monitor_threshold = monitor_threshold.unwrap_or(default_monitor_threshold);
    let block_threshold = block_threshold.unwrap_or(default_block_threshold);
    validate_behavior_thresholds(monitor_threshold, block_threshold)
}

fn validate_bot_protection_thresholds(
    monitor_threshold: u16,
    block_threshold: u16,
) -> Result<(), ConfigError> {
    if monitor_threshold == 0 {
        return Err(ConfigError::InvalidBotProtectionMonitorThreshold);
    }

    if block_threshold < monitor_threshold {
        return Err(ConfigError::InvalidBotProtectionBlockThreshold);
    }

    Ok(())
}

fn validate_optional_bot_protection_thresholds(
    monitor_threshold: Option<u16>,
    block_threshold: Option<u16>,
    default_monitor_threshold: u16,
    default_block_threshold: u16,
) -> Result<(), ConfigError> {
    let monitor_threshold = monitor_threshold.unwrap_or(default_monitor_threshold);
    let block_threshold = block_threshold.unwrap_or(default_block_threshold);
    validate_bot_protection_thresholds(monitor_threshold, block_threshold)
}

fn bot_list_has_blank(list: &BotProtectionLists) -> bool {
    list.ip_ranges
        .iter()
        .chain(list.user_agents.iter())
        .any(|value| value.trim().is_empty())
}

fn is_valid_header_name(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.bytes().all(|byte| {
            matches!(
                byte,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
                    | b'0'..=b'9'
                    | b'a'..=b'z'
                    | b'A'..=b'Z'
            )
        })
}

fn default_true() -> bool {
    true
}

fn is_valid_ip_or_cidr(value: &str) -> bool {
    let value = value.trim();
    if value.parse::<IpAddr>().is_ok() {
        return true;
    }

    let Some((network, prefix)) = value.split_once('/') else {
        return false;
    };
    network.parse::<Ipv4Addr>().is_ok()
        && prefix
            .parse::<u8>()
            .is_ok_and(|prefix_length| prefix_length <= 32)
}

fn default_max_body_size() -> String {
    "2mb".to_string()
}

fn default_trusted_proxies() -> Vec<String> {
    vec!["127.0.0.1/32".to_string(), "::1".to_string()]
}

fn default_real_ip_header() -> String {
    "X-Forwarded-For".to_string()
}

fn default_proto_header() -> String {
    "X-Forwarded-Proto".to_string()
}

fn default_expected_proto() -> String {
    "https".to_string()
}

fn default_insecure_proto_score() -> u16 {
    10
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

fn default_requests_per_minute() -> u32 {
    120
}

fn default_rate_limit_burst() -> u32 {
    30
}

fn default_behavior_score_window() -> String {
    "10m".to_string()
}

fn default_behavior_state_path() -> PathBuf {
    PathBuf::from("logs/saugra-waf-behavior-state.json")
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

fn default_unknown_threat_signals() -> UnknownThreatSignals {
    load_builtin_unknown_threat_signal_catalog().signals
}

fn default_unknown_threat_retention() -> String {
    "30d".to_string()
}

fn default_unknown_threat_max_routes() -> usize {
    10_000
}

fn default_campaign_state_path() -> PathBuf {
    PathBuf::from("logs/saugra-waf-campaign-state.json")
}

fn default_campaign_window() -> String {
    "15m".to_string()
}

fn default_campaign_redis_key_prefix() -> String {
    "saugra-waf:campaign-correlation".to_string()
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

fn default_campaign_minimum() -> usize {
    1
}

fn default_campaign_scope() -> String {
    "global".to_string()
}

fn default_bot_protection_state_path() -> PathBuf {
    PathBuf::from("logs/saugra-waf-bot-state.json")
}

fn default_runtime_policy_path() -> PathBuf {
    PathBuf::from("logs/runtime-policy.json")
}

fn default_runtime_policy_reload_interval() -> String {
    "5s".to_string()
}

fn default_runtime_policy_default_duration() -> String {
    "2h".to_string()
}

fn default_security_summary_schedule() -> String {
    "daily".to_string()
}

fn default_security_summary_send_time() -> String {
    "08:00".to_string()
}

fn default_security_summary_lookback() -> String {
    "24h".to_string()
}

fn default_security_summary_output_path() -> PathBuf {
    PathBuf::from("logs/saugra-waf-security-summary.json")
}

fn default_security_summary_channels() -> Vec<SecuritySummaryChannelConfig> {
    vec![SecuritySummaryChannelConfig::default()]
}

fn default_storage_cleanup_schedule() -> String {
    "daily".to_string()
}

fn default_storage_cleanup_run_time() -> String {
    "02:30".to_string()
}

fn default_storage_cleanup_older_than() -> String {
    "30d".to_string()
}

fn default_storage_cleanup_targets() -> Vec<StorageCleanupTargetConfig> {
    vec![StorageCleanupTargetConfig {
        name: "security summaries".to_string(),
        directory: PathBuf::from("logs"),
        filename_prefix: Some("saugra-waf-security-summary-".to_string()),
        filename_suffix: Some(".json".to_string()),
        older_than: default_storage_cleanup_older_than(),
    }]
}

fn default_sendmail_path() -> String {
    "/usr/sbin/sendmail".to_string()
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

fn default_bot_protection_monitor_threshold() -> u16 {
    40
}

fn default_bot_protection_block_threshold() -> u16 {
    80
}

fn default_bot_protection_temporary_block_duration() -> String {
    "15m".to_string()
}

fn default_bot_protection_rule_id() -> String {
    "SAUGRA-BOT-PROTECTION-001".to_string()
}

fn default_bot_protection_rule_name() -> String {
    "Bot Protection Threshold".to_string()
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
    "Bot protection score reached the configured threshold.".to_string()
}

fn default_bot_protection_owasp_category() -> Option<String> {
    Some("A06:2025-Insecure Design".to_string())
}

const BUILTIN_THREAT_PATH_CATALOG: &str = include_str!("../configs/intelligence/scanner-paths.yml");
const BUILTIN_UNKNOWN_THREAT_SIGNAL_CATALOG: &str =
    include_str!("../configs/intelligence/unknown-threat-signals.yml");
const BUILTIN_CAMPAIGN_POLICY_CATALOG: &str =
    include_str!("../configs/intelligence/campaign-policies.yml");

fn load_builtin_threat_path_catalog() -> ThreatPathCatalog {
    serde_yaml::from_str(BUILTIN_THREAT_PATH_CATALOG)
        .expect("bundled threat path catalog must be valid YAML")
}

fn load_builtin_unknown_threat_signal_catalog() -> UnknownThreatSignalCatalog {
    serde_yaml::from_str(BUILTIN_UNKNOWN_THREAT_SIGNAL_CATALOG)
        .expect("bundled unknown-threat signal catalog must be valid YAML")
}

fn load_builtin_campaign_policy_catalog() -> CampaignPolicyCatalog {
    serde_yaml::from_str(BUILTIN_CAMPAIGN_POLICY_CATALOG)
        .expect("bundled campaign policy catalog must be valid YAML")
}

fn load_campaign_policy_catalog(path: &str) -> Result<CampaignPolicyCatalog, ConfigError> {
    let catalog = if path == "builtin" {
        load_builtin_campaign_policy_catalog()
    } else {
        let contents = fs::read_to_string(path)?;
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

fn validate_campaign_policies(policies: &[CampaignPolicyConfig]) -> Result<(), ConfigError> {
    let mut kinds = std::collections::BTreeSet::new();
    for policy in policies {
        if policy.kind.trim().is_empty()
            || !matches!(
                policy.scope.as_str(),
                "global" | "client" | "session" | "route"
            )
            || policy.score == 0
            || policy.minimum_events == 0
            || policy.minimum_clients == 0
            || policy.minimum_sessions == 0
            || policy.minimum_routes == 0
            || !kinds.insert(policy.kind.trim())
            || policy
                .categories
                .iter()
                .any(|value| value.trim().is_empty())
            || policy
                .path_prefixes
                .iter()
                .any(|value| value.trim().is_empty())
            || policy.stages.iter().any(|stage| {
                stage.name.trim().is_empty()
                    || stage.categories.is_empty()
                    || stage.categories.iter().any(|value| value.trim().is_empty())
            })
            || (!policy.stages.is_empty()
                && (policy.minimum_stages == 0 || policy.minimum_stages > policy.stages.len()))
        {
            return Err(ConfigError::InvalidCampaignPolicy);
        }
    }
    Ok(())
}

fn load_unknown_threat_signal_catalog(
    path: &str,
) -> Result<UnknownThreatSignalCatalog, ConfigError> {
    let catalog = if path == "builtin" {
        load_builtin_unknown_threat_signal_catalog()
    } else {
        let contents = fs::read_to_string(path)?;
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

fn load_threat_path_catalog(path: &str) -> Result<ThreatPathCatalog, ConfigError> {
    if path == "builtin" {
        return Ok(load_builtin_threat_path_catalog());
    }

    let contents = fs::read_to_string(path)?;
    serde_yaml::from_str(&contents).map_err(|source| ConfigError::InvalidThreatPathCatalog {
        path: path.to_string(),
        source,
    })
}

fn merge_unique_paths(paths: &mut Vec<String>, additions: Vec<String>) {
    for addition in additions {
        if !paths.iter().any(|path| path == &addition) {
            paths.push(addition);
        }
    }
}

fn default_probe_paths() -> Vec<String> {
    load_builtin_threat_path_catalog().behavior_probe_paths
}

fn default_scanner_paths() -> Vec<String> {
    load_builtin_threat_path_catalog().bot_scanner_paths
}

fn default_ai_mode() -> String {
    "explain_only".to_string()
}

fn default_ai_provider() -> String {
    "ollama".to_string()
}

fn default_ai_model() -> String {
    "qwen3:4b".to_string()
}

fn default_ai_ollama_url() -> String {
    "http://127.0.0.1:11434".to_string()
}

fn default_ai_prompt_version() -> String {
    "saugra-explain-v1".to_string()
}

fn default_ai_timeout() -> String {
    "60s".to_string()
}

fn default_ai_audit_log_path() -> PathBuf {
    PathBuf::from("logs/saugra-waf-ai-audit.jsonl")
}

fn default_ai_audit_log_max_size() -> String {
    "100mb".to_string()
}

fn default_ai_audit_log_max_files() -> usize {
    10
}

fn default_ai_max_tuning_suggestions() -> usize {
    3
}

fn is_local_ollama_url(value: &str) -> bool {
    let value = value.trim().trim_end_matches('/');
    let Some(authority) = value.strip_prefix("http://") else {
        return false;
    };
    let authority = authority.split('/').next().unwrap_or_default();
    if matches!(authority, "localhost" | "127.0.0.1" | "[::1]") {
        return true;
    }
    ["localhost:", "127.0.0.1:", "[::1]:"]
        .iter()
        .find_map(|prefix| authority.strip_prefix(prefix))
        .is_some_and(|port| port.parse::<u16>().is_ok())
}

fn default_log_format() -> String {
    "json".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_event_log_path() -> String {
    "logs/saugra-waf-events.jsonl".to_string()
}

fn default_event_log_max_size() -> String {
    "100mb".to_string()
}

fn default_event_log_max_files() -> usize {
    10
}

fn default_logging_timezone() -> String {
    "UTC".to_string()
}

fn default_expected_external_scheme() -> String {
    "https".to_string()
}

fn default_allowed_methods() -> Vec<String> {
    ["GET", "POST", "PUT", "PATCH", "DELETE"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn default_owasp_catalog() -> PathBuf {
    PathBuf::from("configs/standards/owasp-top-10-2025.yml")
}

fn is_valid_send_time(value: &str) -> bool {
    let Some((hour, minute)) = value.split_once(':') else {
        return false;
    };
    if hour.len() != 2 || minute.len() != 2 {
        return false;
    }
    let Ok(hour) = hour.parse::<u8>() else {
        return false;
    };
    let Ok(minute) = minute.parse::<u8>() else {
        return false;
    };

    hour <= 23 && minute <= 59
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_example_config() {
        let config: SaugraConfig =
            serde_yaml::from_str(include_str!("../configs/saugra-waf.example.yml")).unwrap();

        assert!(config.validate().is_ok());
        assert_eq!(config.max_body_size_bytes().unwrap(), 2 * 1024 * 1024);
    }

    #[test]
    fn accepts_storage_cleanup_config() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
storage_cleanup:
  enabled: true
  dry_run: false
  schedule: daily
  run_time: "03:30"
  targets:
    - name: summaries
      directory: /var/lib/saugra-waf/reports
      filename_prefix: saugra-waf-security-summary-
      filename_suffix: .json
      older_than: 14d
"#,
        )
        .unwrap();

        config.validate().unwrap();
        assert!(config.storage_cleanup.enabled);
        assert!(!config.storage_cleanup.dry_run);
        assert_eq!(config.storage_cleanup.targets[0].older_than, "14d");
    }

    #[test]
    fn accepts_forwarded_headers_config() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
forwarded_headers:
  enabled: true
  trusted_proxies:
    - 127.0.0.1/32
    - 10.0.0.0/8
  real_ip_header: X-Forwarded-For
  proto_header: X-Forwarded-Proto
  expected_proto: https
  insecure_proto_score: 15
"#,
        )
        .unwrap();

        config.validate().unwrap();
        assert_eq!(config.forwarded_headers.trusted_proxies.len(), 2);
        assert_eq!(config.forwarded_headers.insecure_proto_score, 15);
    }

    #[test]
    fn rejects_invalid_forwarded_header_name() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
forwarded_headers:
  proto_header: "X Forwarded Proto"
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidForwardedHeadersProtoHeader)
        ));
    }

    #[test]
    fn rejects_invalid_forwarded_expected_proto() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
forwarded_headers:
  expected_proto: ftp
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidForwardedHeadersExpectedProto)
        ));
    }

    #[test]
    fn rejects_invalid_storage_cleanup_schedule() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
storage_cleanup:
  schedule: hourly
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidStorageCleanupSchedule)
        ));
    }

    #[test]
    fn rejects_invalid_storage_cleanup_run_time() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
storage_cleanup:
  run_time: "25:00"
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidStorageCleanupRunTime)
        ));
    }

    #[test]
    fn rejects_storage_cleanup_target_without_pattern() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
storage_cleanup:
  targets:
    - name: unsafe
      directory: /var/log/saugra-waf
      older_than: 30d
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidStorageCleanupTargetPattern)
        ));
    }

    #[test]
    fn rejects_invalid_storage_cleanup_older_than() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
storage_cleanup:
  targets:
    - name: summaries
      directory: /var/lib/saugra-waf/reports
      filename_suffix: .json
      older_than: forever
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidStorageCleanupOlderThan)
        ));
    }

    #[test]
    fn from_file_merges_threat_path_catalogs_and_extra_paths() {
        let dir = tempfile::tempdir().unwrap();
        let catalog_path = dir.path().join("scanner-paths.yml");
        let config_path = dir.path().join("saugra-waf.yml");
        std::fs::write(
            &catalog_path,
            r#"
behavior_probe_paths:
  - /catalog-probe
bot_scanner_paths:
  - /catalog-scanner
"#,
        )
        .unwrap();
        std::fs::write(
            &config_path,
            format!(
                r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
behavior:
  probe_path_catalog: {}
  probe_paths_extra:
    - /custom-probe
bot_protection:
  scanner_path_catalog: {}
  scanner_paths_extra:
    - /custom-scanner
"#,
                catalog_path.display(),
                catalog_path.display()
            ),
        )
        .unwrap();

        let config = SaugraConfig::from_file(&config_path).unwrap();

        config.validate().unwrap();
        assert!(config
            .behavior
            .probe_paths
            .contains(&"/catalog-probe".to_string()));
        assert!(config
            .behavior
            .probe_paths
            .contains(&"/custom-probe".to_string()));
        assert!(!config.behavior.probe_paths.contains(&"/.env".to_string()));
        assert!(config
            .bot_protection
            .scanner_paths
            .contains(&"/catalog-scanner".to_string()));
        assert!(config
            .bot_protection
            .scanner_paths
            .contains(&"/custom-scanner".to_string()));
        assert!(!config
            .bot_protection
            .scanner_paths
            .contains(&"/vendor/phpunit".to_string()));
    }

    #[test]
    fn rejects_blank_websocket_allowed_origin() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
websocket:
  allowed_origins:
    - " "
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidWebSocketAllowedOrigin)
        ));
    }

    #[test]
    fn rejects_blank_websocket_allowed_host() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
websocket:
  allowed_hosts:
    - ""
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidWebSocketAllowedHost)
        ));
    }

    #[test]
    fn rejects_missing_upstreams() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams: []
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::MissingUpstream)
        ));
    }

    #[test]
    fn rejects_duplicate_upstream_names() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
  - name: app
    host: api.example.com
    target: http://127.0.0.1:8001
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::DuplicateUpstreamName)
        ));
    }

    #[test]
    fn rejects_blank_route_path_prefix() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
routes:
  - path_prefix: ""
    upstream: app
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidRoutePathPrefix)
        ));
    }

    #[test]
    fn rejects_route_with_unknown_upstream() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
routes:
  - path_prefix: /api/
    upstream: api
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnknownRouteUpstream {
                path_prefix,
                upstream
            }) if path_prefix == "/api/" && upstream == "api"
        ));
    }

    #[test]
    fn rejects_zero_rate_limit() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
rate_limit:
  backend: memory
  requests_per_minute: 0
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidRateLimit)
        ));
    }

    #[test]
    fn requires_redis_url_for_redis_rate_limit_backend() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
rate_limit:
  backend: redis
  requests_per_minute: 120
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::MissingRedisUrl)
        ));
    }

    #[test]
    fn rejects_blank_redis_url_for_redis_rate_limit_backend() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
rate_limit:
  backend: redis
  redis_url: "   "
  requests_per_minute: 120
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::MissingRedisUrl)
        ));
    }

    #[test]
    fn accepts_redis_password_for_redis_rate_limit_backend() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
rate_limit:
  backend: redis
  redis_url: redis://127.0.0.1:6379
  redis_password: "secret-password"
  requests_per_minute: 120
"#,
        )
        .unwrap();

        config.validate().unwrap();
        assert_eq!(
            config.rate_limit.redis_password.as_deref(),
            Some("secret-password")
        );
    }

    #[test]
    fn rejects_blank_redis_password_when_provided() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
rate_limit:
  backend: redis
  redis_url: redis://127.0.0.1:6379
  redis_password: "   "
  requests_per_minute: 120
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidRedisPassword)
        ));
    }

    #[test]
    fn rejects_blank_rate_limit_route_path() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
rate_limit:
  backend: memory
  requests_per_minute: 120
  routes:
    - path: " "
      requests_per_minute: 10
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidRateLimitRoute)
        ));
    }

    #[test]
    fn rejects_zero_route_rate_limit() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
rate_limit:
  backend: memory
  requests_per_minute: 120
  routes:
    - path: /sensitive-action
      requests_per_minute: 0
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidRateLimit)
        ));
    }

    #[test]
    fn behavior_config_defaults_to_monitor_first_policy_shape() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
"#,
        )
        .unwrap();

        config.validate().unwrap();
        assert!(config.behavior.enabled);
        assert_eq!(config.behavior.mode, BehaviorMode::Monitor);
        assert_eq!(config.behavior.backend, BehaviorBackend::Local);
        assert_eq!(
            config.behavior.state_path,
            PathBuf::from("logs/saugra-waf-behavior-state.json")
        );
        assert_eq!(config.behavior.score_window, "10m");
        assert_eq!(config.behavior.decay_window, "30m");
        assert_eq!(config.behavior.monitor_threshold, 40);
        assert_eq!(config.behavior.block_threshold, 80);
        assert!(config.behavior.probe_paths.contains(&"/.env".to_string()));
    }

    #[test]
    fn unknown_threat_config_defaults_to_disabled_monitoring() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
"#,
        )
        .unwrap();

        config.validate().unwrap();
        assert!(!config.unknown_threats.enabled);
        assert_eq!(config.unknown_threats.minimum_observations, 100);
        assert_eq!(config.unknown_threats.monitor_threshold, 20);
        assert_eq!(config.unknown_threats.mode, UnknownThreatMode::Monitor);
        assert_eq!(config.unknown_threats.block_threshold, 40);
        assert_eq!(config.unknown_threats.minimum_independent_signals, 2);
        assert_eq!(config.unknown_threats.minimum_baseline_age, "7d");
        assert_eq!(config.unknown_threats.minimum_block_observations, 1_000);
        assert_eq!(config.unknown_threats.signal_catalog, "builtin");
        assert_eq!(config.unknown_threats.signals.unseen_method.score, 20);
    }

    #[test]
    fn from_file_loads_external_unknown_threat_signal_catalog() {
        let dir = tempfile::tempdir().unwrap();
        let catalog_path = dir.path().join("signals.yml");
        let config_path = dir.path().join("saugra.yml");
        fs::write(
            &catalog_path,
            r#"
version: 1
signals:
  unseen_method:
    score: 31
  unseen_content_type:
    score: 17
  unseen_query_parameter:
    score: 11
  body_size_deviation:
    score: 19
"#,
        )
        .unwrap();
        fs::write(
            &config_path,
            format!(
                r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
unknown_threats:
  signal_catalog: {}
"#,
                catalog_path.display()
            ),
        )
        .unwrap();

        let config = SaugraConfig::from_file(&config_path).unwrap();
        config.validate().unwrap();
        assert_eq!(config.unknown_threats.signals.unseen_method.score, 31);
        assert_eq!(config.unknown_threats.signals.body_size_deviation.score, 19);
    }

    #[test]
    fn rejects_invalid_unknown_threat_signal_catalogs() {
        let dir = tempfile::tempdir().unwrap();
        let catalog_path = dir.path().join("signals.yml");
        let config_path = dir.path().join("saugra.yml");
        fs::write(
            &config_path,
            format!(
                r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
unknown_threats:
  signal_catalog: {}
"#,
                catalog_path.display()
            ),
        )
        .unwrap();

        fs::write(
            &catalog_path,
            r#"
version: 2
signals:
  unseen_method: { score: 20 }
  unseen_content_type: { score: 15 }
  unseen_query_parameter: { score: 10 }
  body_size_deviation: { score: 15 }
"#,
        )
        .unwrap();
        assert!(matches!(
            SaugraConfig::from_file(&config_path),
            Err(ConfigError::InvalidUnknownThreatSignalCatalogVersion)
        ));

        fs::write(
            &catalog_path,
            r#"
version: 1
signals:
  unseen_method: { score: 0 }
  unseen_content_type: { score: 15 }
  unseen_query_parameter: { score: 10 }
  body_size_deviation: { score: 15 }
"#,
        )
        .unwrap();
        assert!(matches!(
            SaugraConfig::from_file(&config_path),
            Err(ConfigError::InvalidUnknownThreatSignalScore)
        ));
    }

    #[test]
    fn rejects_legacy_inline_unknown_threat_signal_scores() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
unknown_threats:
  unseen_method_score: 30
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::LegacyUnknownThreatSignalScores)
        ));
    }

    #[test]
    fn rejects_unsafe_unknown_threat_learning_values() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
unknown_threats:
  minimum_observations: 0
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidUnknownThreatMinimumObservations)
        ));
    }

    #[test]
    fn unknown_threat_block_mode_requires_completed_shadow_review() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
unknown_threats:
  mode: block
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnknownThreatShadowReviewRequired)
        ));
    }

    #[test]
    fn accepts_guarded_unknown_threat_block_policy() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
  mode: block
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
unknown_threats:
  enabled: true
  mode: block
  shadow_review_completed: true
  minimum_observations: 100
  minimum_block_observations: 1000
  minimum_baseline_age: 7d
  minimum_independent_signals: 2
  routes:
    - path: /admin
      high_risk: true
      block_threshold: 50
"#,
        )
        .unwrap();

        config.validate().unwrap();
        assert!(config.unknown_threats.routes[0].high_risk);
    }

    #[test]
    fn accepts_bounded_unknown_threat_route_policies() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
unknown_threats:
  enabled: true
  retention: 14d
  max_routes: 5000
  excluded_paths:
    - /health
  routes:
    - path: /uploads
      learning_enabled: false
    - path: /admin
      minimum_observations: 200
      monitor_threshold: 15
"#,
        )
        .unwrap();

        config.validate().unwrap();
        assert_eq!(config.unknown_threats.retention, "14d");
        assert_eq!(config.unknown_threats.max_routes, 5_000);
        assert_eq!(config.unknown_threats.routes.len(), 2);
        assert!(!config.unknown_threats.routes[0].learning_enabled);
    }

    #[test]
    fn rejects_invalid_unknown_threat_retention_and_routes() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
unknown_threats:
  retention: forever
"#,
        )
        .unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidUnknownThreatRetention)
        ));

        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
unknown_threats:
  routes:
    - path: " "
"#,
        )
        .unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidUnknownThreatRoute)
        ));
    }

    #[test]
    fn accepts_behavior_route_and_category_overrides() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
behavior:
  enabled: true
  mode: monitor
  score_window: 10m
  decay_window: 30m
  monitor_threshold: 40
  block_threshold: 80
  route_overrides:
    - path: /login
      monitor_threshold: 30
      block_threshold: 60
      score_window: 5m
  category_overrides:
    - category: scanner_behavior
      score_delta: 15
      monitor_threshold: 30
      block_threshold: 70
"#,
        )
        .unwrap();

        config.validate().unwrap();
        assert!(config.behavior.enabled);
        assert_eq!(config.behavior.mode, BehaviorMode::Monitor);
        assert_eq!(config.behavior.route_overrides.len(), 1);
        assert_eq!(config.behavior.category_overrides.len(), 1);
    }

    #[test]
    fn rejects_invalid_behavior_score_window() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
behavior:
  score_window: soon
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidBehaviorScoreWindow)
        ));
    }

    #[test]
    fn rejects_invalid_behavior_decay_window() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
behavior:
  decay_window: 0m
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidBehaviorDecayWindow)
        ));
    }

    #[test]
    fn rejects_zero_behavior_monitor_threshold() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
behavior:
  monitor_threshold: 0
  block_threshold: 80
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidBehaviorMonitorThreshold)
        ));
    }

    #[test]
    fn rejects_behavior_block_threshold_below_monitor_threshold() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
behavior:
  monitor_threshold: 80
  block_threshold: 40
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidBehaviorBlockThreshold)
        ));
    }

    #[test]
    fn rejects_blank_behavior_route_override_path() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
behavior:
  route_overrides:
    - path: " "
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidBehaviorRouteOverride)
        ));
    }

    #[test]
    fn rejects_blank_behavior_category_override() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
behavior:
  category_overrides:
    - category: ""
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidBehaviorCategoryOverride)
        ));
    }

    #[test]
    fn bot_protection_defaults_to_monitor_first_policy_shape() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
"#,
        )
        .unwrap();

        config.validate().unwrap();
        assert!(config.bot_protection.enabled);
        assert_eq!(config.bot_protection.mode, BehaviorMode::Monitor);
        assert_eq!(config.bot_protection.backend, BehaviorBackend::Local);
        assert_eq!(config.bot_protection.monitor_threshold, 40);
        assert_eq!(config.bot_protection.block_threshold, 80);
        assert_eq!(config.bot_protection.temporary_block_duration, "15m");
        assert!(config
            .bot_protection
            .scanner_paths
            .contains(&"/vendor/phpunit".to_string()));
        assert_eq!(config.bot_protection.rule.id, "SAUGRA-BOT-PROTECTION-001");
    }

    #[test]
    fn accepts_bot_protection_lists_and_route_overrides() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
bot_protection:
  enabled: true
  mode: monitor
  backend: memory
  score_window: 10m
  monitor_threshold: 40
  block_threshold: 80
  temporary_block_duration: 15m
  allowlists:
    ip_ranges:
      - 203.0.113.0/24
    user_agents:
      - Googlebot
  blocklists:
    ip_ranges:
      - 198.51.100.10
    user_agents:
      - badbot
  routes:
    - path: /login
      monitor_threshold: 30
      block_threshold: 60
"#,
        )
        .unwrap();

        config.validate().unwrap();
        assert!(config.bot_protection.enabled);
        assert_eq!(config.bot_protection.routes.len(), 1);
    }

    #[test]
    fn rejects_invalid_bot_protection_thresholds() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
bot_protection:
  monitor_threshold: 80
  block_threshold: 40
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidBotProtectionBlockThreshold)
        ));
    }

    #[test]
    fn rejects_blank_bot_protection_list_entry() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
bot_protection:
  allowlists:
    user_agents:
      - " "
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidBotProtectionListEntry)
        ));
    }

    #[test]
    fn rejects_blank_behavior_probe_path() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
behavior:
  probe_paths:
    - ""
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidBehaviorProbePath)
        ));
    }

    #[test]
    fn rejects_blank_bot_protection_scanner_path() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
bot_protection:
  scanner_paths:
    - " "
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidBotProtectionScannerPath)
        ));
    }

    #[test]
    fn rejects_blank_bot_protection_rule_metadata() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
bot_protection:
  rule:
    id: ""
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidBotProtectionRule)
        ));
    }

    #[test]
    fn rejects_zero_bot_protection_rule_paranoia_level() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
bot_protection:
  rule:
    paranoia_level: 0
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidBotProtectionRuleParanoiaLevel)
        ));
    }

    #[test]
    fn rejects_zero_inbound_anomaly_threshold() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
rules:
  inbound_anomaly_threshold: 0
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidAnomalyThreshold)
        ));
    }

    #[test]
    fn accepts_split_detection_and_blocking_paranoia_levels() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
rules:
  paranoia_level: 1
  detection_paranoia_level: 2
  blocking_paranoia_level: 1
"#,
        )
        .unwrap();

        config.validate().unwrap();
        assert_eq!(config.rules.detection_paranoia_level(), 2);
        assert_eq!(config.rules.blocking_paranoia_level(), 1);
    }

    #[test]
    fn rejects_blocking_paranoia_above_detection_paranoia() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
rules:
  detection_paranoia_level: 1
  blocking_paranoia_level: 2
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidBlockingParanoiaLevel)
        ));
    }

    #[test]
    fn rejects_zero_paranoia_level() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
rules:
  detection_paranoia_level: 0
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidParanoiaLevel)
        ));
    }

    #[test]
    fn rejects_rule_exclusion_without_rule_or_category_scope() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
rules:
  exclusions:
    - name: Missing rule scope
      path_prefixes:
        - /api/articles
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidRuleExclusion)
        ));
    }

    #[test]
    fn accepts_rule_exclusion_with_rule_and_path_scope() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
rules:
  exclusions:
    - name: Allow article HTML previews
      rule_ids:
        - SAUGRA-XSS-001
      path_prefixes:
        - /api/articles
      query_params:
        - content
"#,
        )
        .unwrap();

        config.validate().unwrap();
    }

    #[test]
    fn rejects_invalid_event_log_max_size() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
logging:
  event_log_max_size: nope
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidEventLogMaxSize)
        ));
    }

    #[test]
    fn rejects_zero_event_log_max_files() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
logging:
  event_log_max_files: 0
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidEventLogMaxFiles)
        ));
    }

    #[test]
    fn accepts_logging_timezone() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
logging:
  timezone: Africa/Nairobi
"#,
        )
        .unwrap();

        config.validate().unwrap();
        assert_eq!(config.logging.timezone, "Africa/Nairobi");
    }

    #[test]
    fn rejects_invalid_logging_timezone() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
logging:
  timezone: Mars/Olympus
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidLoggingTimezone)
        ));
    }

    #[test]
    fn rejects_invalid_posture_external_scheme() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
posture:
  expected_external_scheme: ftp
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidPostureScheme)
        ));
    }

    #[test]
    fn rejects_empty_enabled_posture_allowed_methods() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
posture:
  enabled: true
  allowed_methods: []
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidPostureAllowedMethods)
        ));
    }

    #[test]
    fn campaign_redis_backend_requires_a_url() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
campaign_correlation:
  enabled: true
  backend: redis
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::MissingCampaignRedisUrl)
        ));
    }

    #[test]
    fn command_ai_provider_requires_a_command() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
ai:
  enabled: true
  mode: explain_only
  provider: command
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::MissingAiCommand)
        ));
    }

    #[test]
    fn ai_defaults_to_local_ollama_with_qwen3() {
        let config = AiConfig::default();

        assert_eq!(config.provider, "ollama");
        assert_eq!(config.ollama_url, "http://127.0.0.1:11434");
        assert_eq!(config.model, "qwen3:4b");
        assert_eq!(config.timeout, "60s");
    }

    #[test]
    fn rejects_non_local_ollama_url() {
        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
ai:
  provider: ollama
  ollama_url: https://models.example.com
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidAiOllamaUrl)
        ));
    }

    #[test]
    fn accepts_custom_loopback_ollama_port() {
        assert!(is_local_ollama_url("http://localhost:11435"));
        assert!(is_local_ollama_url("http://127.0.0.1:11435/api"));
        assert!(is_local_ollama_url("http://[::1]:11435"));
    }
}
