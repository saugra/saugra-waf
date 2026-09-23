use crate::config::{
    campaign_bot::{load_threat_path_catalog, merge_unique_paths},
    errors::ConfigError,
    helpers::*,
    BehaviorBackend, SaugraConfig,
};

impl SaugraConfig {
    pub(crate) fn resolve_threat_path_catalogs(&mut self) -> Result<(), ConfigError> {
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

    pub(crate) fn validate_behavior(&self) -> Result<(), ConfigError> {
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

    pub(crate) fn validate_bot_protection(&self) -> Result<(), ConfigError> {
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
}
