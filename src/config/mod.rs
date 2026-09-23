use std::{net::SocketAddr, path::PathBuf};

use serde::Deserialize;

pub mod behavior;
pub mod campaign_bot;
pub mod console;
pub mod errors;
pub mod helpers;
pub mod other;
pub mod rate_limit;
pub mod rules_posture;
pub mod server;
pub mod unknown_threats;
pub mod validation;

#[cfg(test)]
mod tests;

pub use behavior::*;
pub use campaign_bot::*;
pub use console::*;
pub use errors::*;
pub use helpers::*;
pub use other::*;
pub use rate_limit::*;
pub use rules_posture::*;
pub use server::*;
pub use unknown_threats::*;

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
    pub console: ConsoleConfig,
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

impl SaugraConfig {
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
            .map(|upstream| format!("{}@{:?}->{}", upstream.name, upstream.host, upstream.target))
            .collect::<Vec<_>>()
            .join(",");

        format!(
            "listen={}, mode={:?}, upstreams=[{}], routes={}, max_body_size={}, rate_limiting={}, rate_limit_backend={:?}, requests_per_minute={}, burst={}, route_limits={}, behavior_enabled={}, behavior_mode={:?}, behavior_backend={:?}, behavior_state_path={}, behavior_score_window={}, behavior_decay_window={}, behavior_monitor_threshold={}, behavior_block_threshold={}, behavior_route_overrides={}, behavior_category_overrides={}, unknown_threats_enabled={}, unknown_threats_mode={:?}, unknown_threats_backend={:?}, unknown_threats_state_path={}, unknown_threats_signal_catalog={}, unknown_threats_minimum_observations={}, unknown_threats_monitor_threshold={}, unknown_threats_block_threshold={}, unknown_threats_minimum_independent_signals={}, unknown_threats_minimum_baseline_age={}, unknown_threats_minimum_block_observations={}, unknown_threats_retention={}, unknown_threats_max_routes={}, unknown_threats_excluded_paths={}, unknown_threats_route_overrides={}, bot_protection_enabled={}, bot_protection_mode={:?}, bot_protection_backend={:?}, bot_protection_state_path={}, bot_protection_monitor_threshold={}, bot_protection_block_threshold={}, bot_protection_routes={}, runtime_policy_enabled={}, runtime_policy_path={:?}, runtime_policy_reload_interval={}, runtime_policy_allowlist_effect={:?}, inspect_json_body={}, websocket_enabled={}, websocket_allowed_origins={}, websocket_allowed_hosts={}, owasp_crs={}, paranoia_level={}, detection_paranoia_level={}, blocking_paranoia_level={}",
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
