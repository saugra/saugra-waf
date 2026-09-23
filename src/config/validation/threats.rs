use crate::config::{
    campaign_bot::{load_campaign_policy_catalog, validate_campaign_policies},
    errors::ConfigError,
    helpers::*,
    unknown_threats::load_unknown_threat_signal_catalog,
    BehaviorBackend, CampaignBackend, SaugraConfig, UnknownThreatMode,
};

impl SaugraConfig {
    pub(crate) fn resolve_unknown_threat_signal_catalog(&mut self) -> Result<(), ConfigError> {
        let path = self.unknown_threats.signal_catalog.trim();
        if path.is_empty() {
            return Err(ConfigError::InvalidUnknownThreatSignalCatalogPath);
        }
        self.unknown_threats.signals = load_unknown_threat_signal_catalog(path)?.signals;
        Ok(())
    }

    pub(crate) fn resolve_campaign_policy_catalog(&mut self) -> Result<(), ConfigError> {
        let path = self.campaign_correlation.policy_catalog.trim();
        if path.is_empty() {
            return Err(ConfigError::InvalidCampaignPolicyCatalogPath);
        }
        self.campaign_correlation.policies = load_campaign_policy_catalog(path)?.campaigns;
        Ok(())
    }

    pub(crate) fn validate_unknown_threats(&self) -> Result<(), ConfigError> {
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

    pub(crate) fn validate_campaign_correlation(&self) -> Result<(), ConfigError> {
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
}
