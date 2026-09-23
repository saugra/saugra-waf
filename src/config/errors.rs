use thiserror::Error;

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
    #[error("console.management_url must be an http:// or https:// URL when configured")]
    InvalidConsoleManagementUrl,
    #[error("console.external_id must not be blank when console is enabled")]
    InvalidConsoleExternalId,
    #[error("console.credential_path must not be blank when configured")]
    InvalidConsoleCredentialPath,
    #[error("console.outbox_path must not be blank when configured")]
    InvalidConsoleOutboxPath,
    #[error("console heartbeat and delivery intervals must be greater than zero")]
    InvalidConsoleInterval,
    #[error("console.batch_size must be between 1 and 500")]
    InvalidConsoleBatchSize,
    #[error("console.policy_poll_interval_secs must be greater than zero")]
    InvalidConsolePolicyPollInterval,
    #[error("console.policy_cache_path must not be blank when configured")]
    InvalidConsolePolicyCachePath,
    #[error("console.trusted_signing_keys must use non-blank key IDs and public keys")]
    InvalidConsoleTrustedSigningKey,
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
    #[error("unknown_threats.mode must not be block without completed shadow review")]
    UnknownThreatShadowReviewRequired,
    #[error("unknown_threats.block_threshold must be greater than or equal to unknown_threats.monitor_threshold")]
    InvalidUnknownThreatBlockThreshold,
    #[error("unknown_threats.minimum_independent_signals must be at least 2")]
    InvalidUnknownThreatMinimumSignals,
    #[error("unknown_threats.minimum_baseline_age must be a positive duration")]
    InvalidUnknownThreatMinimumBaselineAge,
    #[error("unknown_threats.minimum_block_observations must be greater than or equal to minimum_observations")]
    InvalidUnknownThreatBlockObservations,
    #[error("unknown_threats.trusted_learning_clients entries must be valid IP addresses or CIDR blocks")]
    InvalidUnknownThreatTrustedLearningClient,
    #[error("unknown_threats.signal_catalog must not be blank")]
    InvalidUnknownThreatSignalCatalogPath,
    #[error("unknown_threats legacy inline signal scores are deprecated; use unknown_threats.signal_catalog")]
    LegacyUnknownThreatSignalScores,
    #[error("failed to parse unknown threat signal catalog {path}: {source}")]
    InvalidUnknownThreatSignalCatalog {
        path: String,
        source: serde_yaml::Error,
    },
    #[error("unknown threat signal catalog version must be 1")]
    InvalidUnknownThreatSignalCatalogVersion,
    #[error("unknown threat signal scores must be greater than zero")]
    InvalidUnknownThreatSignalScore,
    #[error("unknown_threats.max_methods_per_route must be greater than zero")]
    InvalidUnknownThreatMaxMethods,
    #[error("unknown_threats.max_content_types_per_route must be greater than zero")]
    InvalidUnknownThreatMaxContentTypes,
    #[error("unknown_threats.max_query_parameters_per_route must be greater than zero")]
    InvalidUnknownThreatMaxQueryParameters,
    #[error("unknown_threats.excluded_paths entries must not be blank")]
    InvalidUnknownThreatExcludedPath,
    #[error("unknown_threats.routes entries must include a non-empty path")]
    InvalidUnknownThreatRoute,
    #[error("campaign_correlation.state_path must not be blank when campaign_correlation.backend is local")]
    InvalidCampaignStatePath,
    #[error("campaign_correlation.redis_url is required when backend is redis")]
    MissingCampaignRedisUrl,
    #[error("campaign_correlation.redis_password must not be blank when provided")]
    InvalidCampaignRedisPassword,
    #[error("campaign_correlation.redis_key_prefix must not be blank")]
    InvalidCampaignRedisKeyPrefix,
    #[error("campaign_correlation durations must be positive, for example 15m or 24h")]
    InvalidCampaignDuration,
    #[error("campaign_correlation.retention must be greater than or equal to campaign_correlation.window")]
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
    #[error("campaign policy kinds must not be blank")]
    InvalidCampaignPolicyKind,
    #[error("campaign policy scopes must be client, session, or global")]
    InvalidCampaignPolicyScope,
    #[error("campaign policy scores must be greater than zero")]
    InvalidCampaignPolicyScore,
    #[error("campaign policy minimum thresholds must be greater than zero")]
    InvalidCampaignPolicyThreshold,
    #[error("campaign policy filters must not contain blank entries")]
    InvalidCampaignPolicyFilter,
    #[error("campaign policy stages must use non-blank names and categories")]
    InvalidCampaignPolicyStage,
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
    #[error("ai.provider must be llama_cpp, ollama, openai_compatible, gemini, local, or command")]
    InvalidAiProvider,
    #[error("ai.ollama_url must be a local HTTP URL")]
    InvalidAiOllamaUrl,
    #[error("ai.llama_cpp_url must be a local HTTP URL")]
    InvalidAiLlamaCppUrl,
    #[error("remote AI providers require ai.allow_remote: true and ai.local_only: false")]
    RemoteAiNotEnabled,
    #[error("ai.endpoint must be an allowlisted HTTPS URL for remote providers")]
    InvalidAiRemoteEndpoint,
    #[error("ai.api_key_env must name a non-empty environment variable for remote providers")]
    InvalidAiApiKeyEnv,
    #[error(
        "ai.data_region and ai.retention_policy must be explicitly documented for remote providers"
    )]
    InvalidAiPrivacyPolicy,
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
    #[error("rules.exclusions methods must be valid HTTP methods")]
    InvalidRuleExclusionMethod,
    #[error("rules.exclusions trusted_headers must use valid non-sensitive header names and non-empty values")]
    InvalidRuleExclusionTrustedHeader,
    #[error("rules.exclusions identities must reference a header configured in forwarded_headers.identity_assertions")]
    InvalidRuleExclusionIdentity,
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
    #[error("forwarded_headers.identity_assertions entries must be valid non-sensitive HTTP header names")]
    InvalidForwardedHeadersIdentityAssertion,
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
