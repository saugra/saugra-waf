use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::helpers::parse_duration_seconds;

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAllowlistEffect {
    #[default]
    SkipBotAndBehaviorBlock,
    MonitorAll,
    AllowAll,
    Block,
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
        parse_duration_seconds(&self.default_duration).unwrap_or(3600)
    }
}

fn default_runtime_policy_path() -> PathBuf {
    PathBuf::from("logs/saugra-waf-runtime-policy.json")
}
fn default_runtime_policy_reload_interval() -> String {
    "5s".to_string()
}
fn default_runtime_policy_default_duration() -> String {
    "1h".to_string()
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
    PathBuf::from("/var/log/saugra-waf/reports/saugra-waf-security-summary-{date}.json")
}
fn default_security_summary_channels() -> Vec<SecuritySummaryChannelConfig> {
    vec![SecuritySummaryChannelConfig {
        channel_type: "file".to_string(),
        to: Vec::new(),
        from: None,
        sendmail_path: default_sendmail_path(),
    }]
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

fn default_sendmail_path() -> String {
    "/usr/sbin/sendmail".to_string()
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

fn default_storage_cleanup_schedule() -> String {
    "daily".to_string()
}
fn default_storage_cleanup_run_time() -> String {
    "03:00".to_string()
}
fn default_storage_cleanup_targets() -> Vec<StorageCleanupTargetConfig> {
    vec![
        StorageCleanupTargetConfig {
            name: "event_logs".to_string(),
            directory: PathBuf::from("/var/log/saugra-waf"),
            filename_prefix: Some("saugra-waf-events-".to_string()),
            filename_suffix: Some(".jsonl".to_string()),
            older_than: "30d".to_string(),
        },
        StorageCleanupTargetConfig {
            name: "security_summaries".to_string(),
            directory: PathBuf::from("/var/log/saugra-waf/reports"),
            filename_prefix: Some("saugra-waf-security-summary-".to_string()),
            filename_suffix: Some(".json".to_string()),
            older_than: "30d".to_string(),
        },
    ]
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

fn default_storage_cleanup_older_than() -> String {
    "30d".to_string()
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
    #[serde(default = "default_ai_llama_cpp_url")]
    pub llama_cpp_url: String,
    #[serde(default)]
    pub allow_remote: bool,
    #[serde(default = "default_true")]
    pub local_only: bool,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub endpoint_allowlist: Vec<String>,
    #[serde(default)]
    pub api_key_env: Option<String>,
    #[serde(default)]
    pub data_region: Option<String>,
    #[serde(default)]
    pub retention_policy: Option<String>,
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

fn default_true() -> bool {
    true
}

fn default_ai_mode() -> String {
    "explain_only".to_string()
}
fn default_ai_provider() -> String {
    "llama_cpp".to_string()
}
fn default_ai_ollama_url() -> String {
    "http://127.0.0.1:11434".to_string()
}
fn default_ai_llama_cpp_url() -> String {
    "http://127.0.0.1:8080".to_string()
}
fn default_ai_model() -> String {
    "saugra-qwen3-0.6b".to_string()
}
fn default_ai_prompt_version() -> String {
    "v1".to_string()
}
fn default_ai_timeout() -> String {
    "60s".to_string()
}
fn default_ai_audit_log_path() -> PathBuf {
    PathBuf::from("/var/log/saugra-waf/saugra-waf-ai-audit.jsonl")
}
fn default_ai_audit_log_max_size() -> String {
    "50mb".to_string()
}
fn default_ai_audit_log_max_files() -> usize {
    10
}
fn default_ai_max_tuning_suggestions() -> usize {
    5
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: default_ai_mode(),
            provider: default_ai_provider(),
            ollama_url: default_ai_ollama_url(),
            llama_cpp_url: default_ai_llama_cpp_url(),
            allow_remote: false,
            local_only: true,
            endpoint: None,
            endpoint_allowlist: Vec::new(),
            api_key_env: None,
            data_region: None,
            retention_policy: None,
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
    pub event_log_path: PathBuf,
    #[serde(default = "default_event_log_max_size")]
    pub event_log_max_size: String,
    #[serde(default = "default_event_log_max_files")]
    pub event_log_max_files: usize,
    #[serde(default = "default_logging_timezone")]
    pub timezone: String,
}

fn default_log_format() -> String {
    "json".to_string()
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_event_log_path() -> PathBuf {
    PathBuf::from("/var/log/saugra-waf/saugra-waf-events.jsonl")
}
fn default_event_log_max_size() -> String {
    "100mb".to_string()
}
fn default_event_log_max_files() -> usize {
    30
}
fn default_logging_timezone() -> String {
    "UTC".to_string()
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

fn default_expected_external_scheme() -> String {
    "https".to_string()
}
fn default_allowed_methods() -> Vec<String> {
    vec!["GET".to_string(), "HEAD".to_string(), "POST".to_string()]
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

fn default_owasp_catalog() -> PathBuf {
    PathBuf::from("configs/catalogs/owasp-top-10-2021.json")
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
