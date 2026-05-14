use std::{fs, net::SocketAddr, path::Path};

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
    #[error("ai.mode must be explain_only when AI is enabled")]
    InvalidAiMode,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SaugraConfig {
    pub server: ServerConfig,
    pub upstreams: Vec<UpstreamConfig>,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub rules: RuleSettings,
    #[serde(default)]
    pub ai: AiConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
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
pub struct RuleSettings {
    #[serde(default = "default_true")]
    pub owasp_crs: bool,
    #[serde(default = "default_paranoia_level")]
    pub paranoia_level: u8,
}

impl Default for RuleSettings {
    fn default() -> Self {
        Self {
            owasp_crs: true,
            paranoia_level: default_paranoia_level(),
        }
    }
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
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            format: default_log_format(),
            level: default_log_level(),
        }
    }
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

        if self.ai.enabled && self.ai.mode != "explain_only" {
            return Err(ConfigError::InvalidAiMode);
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

    pub fn summary(&self) -> String {
        let upstreams = self
            .upstreams
            .iter()
            .map(|upstream| format!("{}@{}->{}", upstream.name, upstream.host, upstream.target))
            .collect::<Vec<_>>()
            .join(",");

        format!(
            "listen={}, mode={:?}, upstreams=[{}], max_body_size={}, rate_limiting={}, inspect_json_body={}, owasp_crs={}, paranoia_level={}",
            self.server.listen,
            self.server.mode,
            upstreams,
            self.security.max_body_size,
            self.security.enable_rate_limiting,
            self.security.inspect_json_body,
            self.rules.owasp_crs,
            self.rules.paranoia_level
        )
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

fn default_ai_mode() -> String {
    "explain_only".to_string()
}

fn default_log_format() -> String {
    "json".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
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
}
