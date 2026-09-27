use crate::config::{errors::ConfigError, helpers::*, SaugraConfig};

impl SaugraConfig {
    pub(crate) fn validate_forwarded_headers(&self) -> Result<(), ConfigError> {
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
        if self
            .forwarded_headers
            .identity_assertions
            .iter()
            .any(|header| !is_valid_trusted_assertion_header(header))
        {
            return Err(ConfigError::InvalidForwardedHeadersIdentityAssertion);
        }

        Ok(())
    }

    pub(crate) fn validate_storage_cleanup(&self) -> Result<(), ConfigError> {
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

    pub(crate) fn validate_security_summary(&self) -> Result<(), ConfigError> {
        if let Err(err) = self.security_summary.validate() {
            return Err(match err.to_string().as_str() {
                "security_summary.schedule must be daily" => {
                    ConfigError::InvalidSecuritySummarySchedule
                }
                "security_summary.send_time must use HH:MM 24-hour format" => {
                    ConfigError::InvalidSecuritySummarySendTime
                }
                "security_summary.timezone must be UTC, Africa/Nairobi, or a fixed offset such as +03:00" => {
                    ConfigError::InvalidSecuritySummaryTimezone
                }
                "security_summary.lookback must be a positive duration, for example 24h" => {
                    ConfigError::InvalidSecuritySummaryLookback
                }
                "security_summary.output_path must not be blank" => {
                    ConfigError::InvalidSecuritySummaryOutputPath
                }
                "security_summary.channels entries must use type file or email" => {
                    ConfigError::InvalidSecuritySummaryChannel
                }
                "security_summary email channels must include at least one recipient" => {
                    ConfigError::InvalidSecuritySummaryRecipient
                }
                _ => ConfigError::InvalidSecuritySummarySchedule,
            });
        }

        Ok(())
    }

    pub(crate) fn validate_runtime_policy(&self) -> Result<(), ConfigError> {
        if let Err(err) = self.runtime_policy.validate() {
            return Err(match err.to_string().as_str() {
                "runtime_policy.path must not be blank when runtime policy is enabled" => {
                    ConfigError::InvalidRuntimePolicyPath
                }
                "runtime_policy.reload_interval must be a positive duration, for example 5s" => {
                    ConfigError::InvalidRuntimePolicyReloadInterval
                }
                "runtime_policy.default_duration must be a positive duration, for example 2h" => {
                    ConfigError::InvalidRuntimePolicyDefaultDuration
                }
                _ => ConfigError::InvalidRuntimePolicyPath,
            });
        }

        Ok(())
    }
}
