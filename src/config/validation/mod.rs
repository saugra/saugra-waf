mod behavior;
mod other;
mod threats;

use serde_yaml;
use std::path::Path;

use crate::config::{errors::ConfigError, helpers::*, SaugraConfig};

impl SaugraConfig {
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)?;
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

        if let Some(url) = self.console.management_url.as_deref() {
            if url.trim().is_empty() || !(url.starts_with("http://") || url.starts_with("https://"))
            {
                return Err(ConfigError::InvalidConsoleManagementUrl);
            }
        }
        if self.console.enabled
            && self
                .console
                .external_id
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
        {
            return Err(ConfigError::InvalidConsoleExternalId);
        }
        if self
            .console
            .credential_path
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(ConfigError::InvalidConsoleCredentialPath);
        }
        if self
            .console
            .outbox_path
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(ConfigError::InvalidConsoleOutboxPath);
        }
        if self.console.heartbeat_interval_secs == 0 || self.console.delivery_interval_secs == 0 {
            return Err(ConfigError::InvalidConsoleInterval);
        }
        if !(1..=500).contains(&self.console.batch_size) {
            return Err(ConfigError::InvalidConsoleBatchSize);
        }
        if self.console.policy_poll_interval_secs == 0 {
            return Err(ConfigError::InvalidConsolePolicyPollInterval);
        }
        if self
            .console
            .policy_cache_path
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(ConfigError::InvalidConsolePolicyCachePath);
        }
        if self.console.trusted_signing_keys.iter().any(|(id, key)| {
            id.trim().is_empty()
                || id.len() > 80
                || key.trim().is_empty()
                || key.chars().any(char::is_whitespace)
        }) {
            return Err(ConfigError::InvalidConsoleTrustedSigningKey);
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

        if self.rate_limit.backend == crate::config::RateLimitBackend::Redis
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
        if !matches!(
            self.ai.provider.as_str(),
            "llama_cpp" | "ollama" | "openai_compatible" | "gemini" | "local" | "command"
        ) {
            return Err(ConfigError::InvalidAiProvider);
        }
        if self.ai.provider == "ollama" && !is_local_http_url(&self.ai.ollama_url) {
            return Err(ConfigError::InvalidAiOllamaUrl);
        }
        if self.ai.provider == "llama_cpp" && !is_local_http_url(&self.ai.llama_cpp_url) {
            return Err(ConfigError::InvalidAiLlamaCppUrl);
        }
        if matches!(self.ai.provider.as_str(), "openai_compatible" | "gemini") {
            if !self.ai.allow_remote || self.ai.local_only {
                return Err(ConfigError::RemoteAiNotEnabled);
            }
            let endpoint = self.ai.endpoint.as_deref().unwrap_or_default();
            if !is_allowlisted_https_url(endpoint, &self.ai.endpoint_allowlist) {
                return Err(ConfigError::InvalidAiRemoteEndpoint);
            }
            if self
                .ai
                .api_key_env
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err(ConfigError::InvalidAiApiKeyEnv);
            }
            if self
                .ai
                .data_region
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
                || self
                    .ai
                    .retention_policy
                    .as_deref()
                    .is_none_or(|value| value.trim().is_empty())
            {
                return Err(ConfigError::InvalidAiPrivacyPolicy);
            }
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
                .chain(exclusion.methods.iter())
                .chain(exclusion.content_types.iter())
                .any(|value| value.trim().is_empty());

            if has_blank {
                return Err(ConfigError::InvalidRuleExclusion);
            }

            if exclusion.methods.iter().any(|method| {
                method
                    .bytes()
                    .any(|byte| !byte.is_ascii_uppercase() && byte != b'-')
            }) {
                return Err(ConfigError::InvalidRuleExclusionMethod);
            }

            if exclusion.trusted_headers.iter().any(|condition| {
                !is_valid_trusted_assertion_header(&condition.name)
                    || condition.values.is_empty()
                    || condition.values.iter().any(|value| value.trim().is_empty())
            }) {
                return Err(ConfigError::InvalidRuleExclusionTrustedHeader);
            }

            if exclusion.identities.iter().any(|condition| {
                !is_valid_trusted_assertion_header(&condition.name)
                    || condition.values.is_empty()
                    || condition.values.iter().any(|value| value.trim().is_empty())
                    || !self
                        .forwarded_headers
                        .identity_assertions
                        .iter()
                        .any(|header| header.eq_ignore_ascii_case(&condition.name))
            }) || (!exclusion.identities.is_empty() && !self.forwarded_headers.enabled)
            {
                return Err(ConfigError::InvalidRuleExclusionIdentity);
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
}
