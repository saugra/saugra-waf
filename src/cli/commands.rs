use clap::{Parser, Subcommand};
use std::{env, path::PathBuf};

const INSTALLED_CONFIG_PATH: &str = "/etc/saugra-waf/saugra-waf.yml";
const DEVELOPMENT_CONFIG_PATH: &str = "configs/saugra-waf.example.yml";
const CONFIG_ENV_VAR: &str = "SAUGRA_WAF_CONFIG";

pub fn default_config_path() -> PathBuf {
    if let Some(path) = env::var_os(CONFIG_ENV_VAR).filter(|value| !value.is_empty()) {
        return PathBuf::from(path);
    }

    [INSTALLED_CONFIG_PATH, DEVELOPMENT_CONFIG_PATH]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .unwrap_or_else(|| PathBuf::from(INSTALLED_CONFIG_PATH))
}

#[derive(Debug, Parser)]
#[command(name = "saugra-waf")]
#[command(version)]
#[command(about = "A lightweight rule-based + AI-assisted Web Application Firewall.")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Create starter configuration or proxy integration snippets.
    Init {
        #[command(subcommand)]
        target: Option<InitTarget>,
    },
    /// Validate a Saugra YAML configuration file.
    TestConfig {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Start the Saugra service.
    Run {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Inspect built-in rules.
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
    /// Read local Saugra security events.
    Logs {
        #[command(subcommand)]
        command: LogsCommand,
    },
    /// Explain a recorded request decision.
    Explain {
        request_id: String,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Inspect OWASP Top 10 coverage.
    Owasp {
        #[command(subcommand)]
        command: OwaspCommand,
    },
    /// Inspect deployment posture assumptions.
    Posture {
        #[command(subcommand)]
        command: PostureCommand,
    },
    /// Read local security reports such as SBOM or dependency scan outputs.
    Reports {
        #[command(subcommand)]
        command: ReportsCommand,
    },
    /// Manage local runtime allowlists without restarting Saugra.
    Allowlist {
        #[command(subcommand)]
        command: AllowlistCommand,
    },
    /// Manage local Saugra state files.
    State {
        #[command(subcommand)]
        command: StateCommand,
    },
    /// Generate or deliver local security summaries.
    Summary {
        #[command(subcommand)]
        command: SummaryCommand,
    },
    /// Remove stale generated files and local baseline entries.
    Cleanup {
        #[command(subcommand)]
        command: CleanupCommand,
    },
    /// Review unknown-threat shadow and enforcement candidates.
    UnknownThreats {
        #[command(subcommand)]
        command: UnknownThreatCommand,
    },
    /// Evaluate configured explanation providers against sanitized fixtures.
    Ai {
        #[command(subcommand)]
        command: AiCommand,
    },
    /// Enroll and connect this WAF node to Saugra Console.
    Console {
        #[command(subcommand)]
        command: ConsoleCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum ConsoleCommand {
    /// Enroll using a one-time WAF enrollment token from Saugra Console.
    Enroll {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long, env = "SAUGRA_CONSOLE_ENROLLMENT_TOKEN", hide_env_values = true)]
        enrollment_token: String,
        #[arg(long)]
        display_name: Option<String>,
    },
    /// Inspect or change the local managed-policy emergency override.
    PolicyOverride {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[command(subcommand)]
        command: PolicyOverrideCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum PolicyOverrideCommand {
    Status,
    Enable {
        #[arg(long)]
        reason: String,
    },
    Disable,
}

#[derive(Debug, Subcommand)]
pub enum InitTarget {
    /// Print an Nginx reverse proxy snippet.
    Nginx,
    /// Print an Apache reverse proxy snippet.
    Apache,
}

#[derive(Debug, Subcommand)]
pub enum RulesCommand {
    /// List configured WAF rules.
    List {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// View metadata and design details for one active WAF rule.
    View {
        rule_id: String,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Validate and compile one inactive Saugra YAML rule pack.
    Validate {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(long, default_value_t = u8::MAX)]
        paranoia_level: u8,
    },
    /// Replay one inactive rule pack against retained security events.
    Replay {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(short, long, default_value_t = 1000)]
        limit: usize,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        fixtures: Option<PathBuf>,
    },
    /// Create a deterministic draft rule from repeated reviewed anomalies.
    Draft {
        #[arg(long = "request-id", required = true, action = clap::ArgAction::Append)]
        request_ids: Vec<String>,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Record human approval and bind a replay report to a draft manifest.
    Approve {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(long)]
        reviewer: String,
        #[arg(long)]
        replay_report: PathBuf,
    },
    /// Publish an approved draft while the configured server remains in monitor mode.
    Publish {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        destination: PathBuf,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Convert supported OWASP CRS regex rules into Saugra YAML.
    ConvertCrs {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum AiCommand {
    /// Run versioned sanitized explanation evaluation cases.
    Evaluate {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long, default_value = "configs/ai/evaluation-cases.jsonl")]
        cases: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Produce an offline advisory review of retained unknown-threat events.
    AnomalyShadow {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(short, long, default_value_t = 100)]
        limit: usize,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
pub enum LogsCommand {
    /// Print recent local security events.
    Tail {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(short, long, default_value_t = 20)]
        limit: usize,
    },
    /// Summarize local security events by action and OWASP category.
    Summary {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(short, long, default_value_t = 200)]
        limit: usize,
    },
}

#[derive(Debug, Subcommand)]
pub enum OwaspCommand {
    /// Print current OWASP Top 10 coverage from loaded rules and config controls.
    Coverage {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum PostureCommand {
    /// Run local deterministic posture checks.
    Check {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum ReportsCommand {
    /// Normalize and summarize configured local security reports.
    Summary {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum AllowlistCommand {
    /// Add an IP or CIDR runtime allowlist entry.
    Add {
        #[command(subcommand)]
        target: AllowlistAddTarget,
    },
    /// Remove a runtime allowlist entry by ID.
    Remove {
        id: String,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// List runtime allowlist entries.
    List {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Remove expired runtime allowlist entries.
    Prune {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Manage runtime blocklist entries.
    Block {
        #[command(subcommand)]
        command: BlocklistCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum AllowlistAddTarget {
    /// Add a single IP address.
    Ip {
        value: String,
        #[arg(short, long)]
        duration: Option<String>,
        #[arg(short, long)]
        reason: String,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Add a CIDR range.
    Cidr {
        value: String,
        #[arg(short, long)]
        duration: Option<String>,
        #[arg(short, long)]
        reason: String,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum BlocklistCommand {
    /// Add an IP or CIDR runtime blocklist entry.
    Add {
        value: String,
        #[arg(short, long)]
        duration: Option<String>,
        #[arg(short, long)]
        reason: String,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum StateCommand {
    /// Reset local behavior or bot state for one client ID.
    Reset {
        #[command(subcommand)]
        target: StateResetTarget,
    },
}

#[derive(Debug, Subcommand)]
pub enum StateResetTarget {
    /// Remove one client from local behavior scoring state.
    Behavior {
        client_id: String,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Remove one client from local bot-protection state.
    Bot {
        client_id: String,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum SummaryCommand {
    /// Generate a daily summary over the configured lookback and print JSON.
    Daily {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Generate and deliver a summary through configured channels.
    Send {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum CleanupCommand {
    /// Scan cleanup targets and optionally delete stale files.
    Run {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        /// Preview removals without deleting files.
        #[arg(long)]
        dry_run: bool,
        /// Delete stale files. Without this flag, cleanup uses config dry_run.
        #[arg(long)]
        execute: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum UnknownThreatCommand {
    /// Summarize retained unknown-threat candidates for false-positive review.
    Report {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(short, long, default_value_t = 1000)]
        limit: usize,
    },
}
