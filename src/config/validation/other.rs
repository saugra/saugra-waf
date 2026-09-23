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

    pub(crate) fn validate_runtime_policy(&self) -> Result<(), ConfigError> {
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
}
