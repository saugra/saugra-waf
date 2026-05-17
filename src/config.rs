use std::{fs, net::SocketAddr, path::Path, path::PathBuf};

use serde::Deserialize;
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
    #[error("ai.mode must be explain_only when AI is enabled")]
    InvalidAiMode,
    #[error("rules.inbound_anomaly_threshold must be greater than zero")]
    InvalidAnomalyThreshold,
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct SaugraConfig {
    pub server: ServerConfig,
    pub upstreams: Vec<UpstreamConfig>,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub rules: RuleSettings,
    #[serde(default)]
    pub ai: AiConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub posture: PostureConfig,
    #[serde(default)]
    pub reports: ReportConfig,
    #[serde(default)]
    pub standards: StandardsConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub listen: String,
    #[serde(default)]
    pub mode: WafMode,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WafMode {
    Off,
    Monitor,
    Block,
    Strict,
}

impl Default for WafMode {
    fn default() -> Self {
        Self::Monitor
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
    pub name: String,
    pub host: String,
    pub target: String,
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

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitBackend {
    Memory,
    Redis,
}

impl Default for RateLimitBackend {
    fn default() -> Self {
        Self::Memory
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleSettings {
    #[serde(default = "default_true")]
    pub owasp_crs: bool,
    #[serde(default = "default_paranoia_level")]
    pub paranoia_level: u8,
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
            inbound_anomaly_threshold: default_inbound_anomaly_threshold(),
            files: default_rule_files(),
            exclusions: Vec::new(),
        }
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
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: default_ai_mode(),
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
        Ok(serde_yaml::from_str(&contents)?)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        self.listen_addr()?;

        if self.upstreams.is_empty() {
            return Err(ConfigError::MissingUpstream);
        }

        for upstream in &self.upstreams {
            if !(upstream.target.starts_with("http://") || upstream.target.starts_with("https://"))
            {
                return Err(ConfigError::InvalidUpstreamTarget {
                    name: upstream.name.clone(),
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

        if self.ai.enabled && self.ai.mode != "explain_only" {
            return Err(ConfigError::InvalidAiMode);
        }

        if self.rules.inbound_anomaly_threshold == 0 {
            return Err(ConfigError::InvalidAnomalyThreshold);
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
            "listen={}, mode={:?}, upstreams=[{}], max_body_size={}, rate_limiting={}, rate_limit_backend={:?}, requests_per_minute={}, burst={}, route_limits={}, inspect_json_body={}, owasp_crs={}, paranoia_level={}",
            self.server.listen,
            self.server.mode,
            upstreams,
            self.security.max_body_size,
            self.security.enable_rate_limiting,
            self.rate_limit.backend,
            self.rate_limit.requests_per_minute,
            self.rate_limit.burst,
            self.rate_limit.routes.len(),
            self.security.inspect_json_body,
            self.rules.owasp_crs,
            self.rules.paranoia_level
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

fn default_true() -> bool {
    true
}

fn default_max_body_size() -> String {
    "2mb".to_string()
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

fn default_ai_mode() -> String {
    "explain_only".to_string()
}

fn default_log_format() -> String {
    "json".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_event_log_path() -> String {
    "logs/saugra-events.jsonl".to_string()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_example_config() {
        let config: SaugraConfig =
            serde_yaml::from_str(include_str!("../configs/saugra.example.yml")).unwrap();

        assert!(config.validate().is_ok());
        assert_eq!(config.max_body_size_bytes().unwrap(), 2 * 1024 * 1024);
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
}
