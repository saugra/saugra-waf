use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::{Parser, Subcommand};
use saugra::{
    ai, behavior, bot, config::SaugraConfig, crs_convert, event_store,
    event_store::EventLogRetention, logging, owasp, posture, proxy, reports, rules, runtime_policy,
    security_summary, standards,
};

#[derive(Debug, Parser)]
#[command(name = "saugra")]
#[command(about = "A lightweight rule-based + AI-assisted Web Application Firewall.")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Create starter configuration or proxy integration snippets.
    Init {
        #[command(subcommand)]
        target: Option<InitTarget>,
    },
    /// Validate a Saugra YAML configuration file.
    TestConfig {
        #[arg(short, long, default_value = "configs/saugra.example.yml")]
        config: PathBuf,
    },
    /// Start the Saugra service.
    Run {
        #[arg(short, long, default_value = "configs/saugra.example.yml")]
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
        #[arg(short, long, default_value = "configs/saugra.example.yml")]
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
}

#[derive(Debug, Subcommand)]
enum InitTarget {
    /// Print an Nginx reverse proxy snippet.
    Nginx,
    /// Print an Apache reverse proxy snippet.
    Apache,
}

#[derive(Debug, Subcommand)]
enum RulesCommand {
    /// List configured WAF rules.
    List {
        #[arg(short, long, default_value = "configs/saugra.example.yml")]
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
enum LogsCommand {
    /// Print recent local security events.
    Tail {
        #[arg(short, long, default_value = "configs/saugra.example.yml")]
        config: PathBuf,
        #[arg(short, long, default_value_t = 20)]
        limit: usize,
    },
    /// Summarize local security events by action and OWASP category.
    Summary {
        #[arg(short, long, default_value = "configs/saugra.example.yml")]
        config: PathBuf,
        #[arg(short, long, default_value_t = 200)]
        limit: usize,
    },
}

#[derive(Debug, Subcommand)]
enum OwaspCommand {
    /// Print current OWASP Top 10 coverage from loaded rules and config controls.
    Coverage {
        #[arg(short, long, default_value = "configs/saugra.example.yml")]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum PostureCommand {
    /// Run local deterministic posture checks.
    Check {
        #[arg(short, long, default_value = "configs/saugra.example.yml")]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ReportsCommand {
    /// Normalize and summarize configured local security reports.
    Summary {
        #[arg(short, long, default_value = "configs/saugra.example.yml")]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum AllowlistCommand {
    /// Add an IP or CIDR runtime allowlist entry.
    Add {
        #[command(subcommand)]
        target: AllowlistAddTarget,
    },
    /// Remove a runtime allowlist entry by ID.
    Remove {
        id: String,
        #[arg(short, long, default_value = "configs/saugra.example.yml")]
        config: PathBuf,
    },
    /// List runtime allowlist entries.
    List {
        #[arg(short, long, default_value = "configs/saugra.example.yml")]
        config: PathBuf,
    },
    /// Remove expired runtime allowlist entries.
    Prune {
        #[arg(short, long, default_value = "configs/saugra.example.yml")]
        config: PathBuf,
    },
    /// Manage runtime blocklist entries.
    Block {
        #[command(subcommand)]
        command: BlocklistCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AllowlistAddTarget {
    /// Add a single IP address.
    Ip {
        value: String,
        #[arg(short, long)]
        duration: Option<String>,
        #[arg(short, long)]
        reason: String,
        #[arg(short, long, default_value = "configs/saugra.example.yml")]
        config: PathBuf,
    },
    /// Add a CIDR range.
    Cidr {
        value: String,
        #[arg(short, long)]
        duration: Option<String>,
        #[arg(short, long)]
        reason: String,
        #[arg(short, long, default_value = "configs/saugra.example.yml")]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum BlocklistCommand {
    /// Add an IP or CIDR runtime blocklist entry.
    Add {
        value: String,
        #[arg(short, long)]
        duration: Option<String>,
        #[arg(short, long)]
        reason: String,
        #[arg(short, long, default_value = "configs/saugra.example.yml")]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum StateCommand {
    /// Reset local behavior or bot state for one client ID.
    Reset {
        #[command(subcommand)]
        target: StateResetTarget,
    },
}

#[derive(Debug, Subcommand)]
enum StateResetTarget {
    /// Remove one client from local behavior scoring state.
    Behavior {
        client_id: String,
        #[arg(short, long, default_value = "configs/saugra.example.yml")]
        config: PathBuf,
    },
    /// Remove one client from local bot-protection state.
    Bot {
        client_id: String,
        #[arg(short, long, default_value = "configs/saugra.example.yml")]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum SummaryCommand {
    /// Generate a daily summary over the configured lookback and print JSON.
    Daily {
        #[arg(short, long, default_value = "configs/saugra.example.yml")]
        config: PathBuf,
    },
    /// Generate and deliver a summary through configured channels.
    Send {
        #[arg(short, long, default_value = "configs/saugra.example.yml")]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { target } => print_init(target),
        Commands::TestConfig { config } => {
            let config = SaugraConfig::from_file(&config)
                .with_context(|| format!("failed to load config {}", config.display()))?;
            config.validate()?;
            let (_rule_set, report) = rules::load_rule_set_with_report(&config.rules)?;
            println!("config OK: {}", config.summary());
            print_rule_load_report(&report);
            Ok(())
        }
        Commands::Run { config } => {
            let config = SaugraConfig::from_file(&config)
                .with_context(|| format!("failed to load config {}", config.display()))?;
            config.validate()?;
            logging::init(&config.logging)?;
            proxy::run(config).await
        }
        Commands::Rules { command } => match command {
            RulesCommand::List { config } => {
                let config = load_valid_config(&config)?;
                let rule_set = rules::load_rule_set(&config.rules)?;
                for rule in rule_set.rules() {
                    let transforms = if rule.transforms.is_empty() {
                        "none".to_string()
                    } else {
                        rule.transforms
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(",")
                    };
                    println!(
                        "{}\t{}\t{}\t{}\tPL{}\t{}\t{}",
                        rule.id,
                        rule.severity,
                        rule.category,
                        rule.target,
                        rule.paranoia_level,
                        transforms,
                        rule.name
                    );
                }
                Ok(())
            }
            RulesCommand::ConvertCrs { input, output } => {
                let summary = crs_convert::convert_crs_path(&input, &output)?;
                println!(
                    "converted CRS rules: {} written, {} skipped",
                    summary.converted, summary.skipped
                );
                Ok(())
            }
        },
        Commands::Logs { command } => match command {
            LogsCommand::Tail { config, limit } => {
                let config = load_valid_config(&config)?;
                let retention = event_log_retention(&config)?;
                let events = event_store::tail(
                    PathBuf::from(config.logging.event_log_path).as_path(),
                    retention,
                    limit,
                )?;
                for event in events {
                    println!("{}", serde_json::to_string(&event)?);
                }
                Ok(())
            }
            LogsCommand::Summary { config, limit } => {
                let config = load_valid_config(&config)?;
                let retention = event_log_retention(&config)?;
                let events = event_store::tail(
                    PathBuf::from(config.logging.event_log_path).as_path(),
                    retention,
                    limit,
                )?;
                print_security_event_summary(&event_store::summarize(&events));
                Ok(())
            }
        },
        Commands::Explain { request_id, config } => {
            let config = load_valid_config(&config)?;
            let retention = event_log_retention(&config)?;
            let event = event_store::find_by_request_id(
                PathBuf::from(config.logging.event_log_path).as_path(),
                retention,
                &request_id,
            )?
            .with_context(|| format!("request ID not found: {request_id}"))?;

            println!("{}", ai::explain(&event.decision));
            println!("{}", serde_json::to_string_pretty(&event.decision)?);
            Ok(())
        }
        Commands::Owasp { command } => match command {
            OwaspCommand::Coverage { config } => {
                let config = load_valid_config(&config)?;
                let rule_set = rules::load_rule_set(&config.rules)?;
                let catalog = standards::load_catalog_or_builtin(&config.standards.owasp_catalog)?;
                let security_reports = reports::load_configured_reports(&config)?;
                let report =
                    owasp::coverage_report(&config, &rule_set, &catalog, Some(&security_reports));
                print_owasp_coverage(&report);
                Ok(())
            }
        },
        Commands::Posture { command } => match command {
            PostureCommand::Check { config } => {
                let config = load_valid_config(&config)?;
                let catalog = standards::load_catalog_or_builtin(&config.standards.owasp_catalog)?;
                let security_reports = reports::load_configured_reports(&config)?;
                let report =
                    posture::check_with_reports(&config, &catalog, Some(&security_reports));
                print_posture_report(&report);
                Ok(())
            }
        },
        Commands::Reports { command } => match command {
            ReportsCommand::Summary { config } => {
                let config = load_valid_config(&config)?;
                let summary = reports::load_configured_reports(&config)?;
                print_security_report_summary(&summary);
                Ok(())
            }
        },
        Commands::Allowlist { command } => handle_allowlist(command),
        Commands::State { command } => handle_state(command),
        Commands::Summary { command } => handle_summary(command),
    }
}

fn handle_summary(command: SummaryCommand) -> anyhow::Result<()> {
    match command {
        SummaryCommand::Daily { config } => {
            let config = load_valid_config(&config)?;
            let summary = security_summary::generate_from_config(&config)?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        SummaryCommand::Send { config } => {
            let config = load_valid_config(&config)?;
            let report = security_summary::send_from_config(&config)?;
            if let Some(path) = report.output_path {
                println!("wrote security summary to {}", path.display());
            }
            if !report.email_recipients.is_empty() {
                println!(
                    "sent security summary email to {}",
                    report.email_recipients.join(",")
                );
            }
            Ok(())
        }
    }
}

fn handle_state(command: StateCommand) -> anyhow::Result<()> {
    match command {
        StateCommand::Reset { target } => match target {
            StateResetTarget::Behavior { client_id, config } => {
                let config = load_valid_config(&config)?;
                let removed = behavior::reset_client(&config.behavior.state_path, &client_id)?;
                print_reset_result("behavior", &client_id, removed);
                Ok(())
            }
            StateResetTarget::Bot { client_id, config } => {
                let config = load_valid_config(&config)?;
                let removed = bot::reset_client(&config.bot_protection.state_path, &client_id)?;
                print_reset_result("bot", &client_id, removed);
                Ok(())
            }
        },
    }
}

fn print_reset_result(state_name: &str, client_id: &str, removed: bool) {
    if removed {
        println!("reset {state_name} state for client {client_id}");
    } else {
        println!("no {state_name} state found for client {client_id}");
    }
}

fn handle_allowlist(command: AllowlistCommand) -> anyhow::Result<()> {
    match command {
        AllowlistCommand::Add { target } => {
            let (value, duration, reason, config_path) = match target {
                AllowlistAddTarget::Ip {
                    value,
                    duration,
                    reason,
                    config,
                }
                | AllowlistAddTarget::Cidr {
                    value,
                    duration,
                    reason,
                    config,
                } => (value, duration, reason, config),
            };
            let config = load_valid_config(&config_path)?;
            let duration_seconds = if let Some(duration) = duration.as_deref() {
                runtime_policy::parse_duration_seconds(duration)
                    .with_context(|| "allowlist duration must look like 30m, 2h, or 1d")?
            } else {
                config.runtime_policy.default_duration_seconds()
            };
            let entry = runtime_policy::add_ip_entry(
                &config.runtime_policy.path,
                &value,
                Some(duration_seconds),
                &reason,
                "cli",
            )?;
            println!("{}", serde_json::to_string_pretty(&entry)?);
            Ok(())
        }
        AllowlistCommand::Remove { id, config } => {
            let config = load_valid_config(&config)?;
            let removed = runtime_policy::remove_entry(&config.runtime_policy.path, &id)?;
            if removed {
                println!("removed allowlist entry {id}");
            } else {
                println!("allowlist entry not found: {id}");
            }
            Ok(())
        }
        AllowlistCommand::List { config } => {
            let config = load_valid_config(&config)?;
            let policy = runtime_policy::list_policy(&config.runtime_policy.path)?;
            println!("{}", serde_json::to_string_pretty(&policy)?);
            Ok(())
        }
        AllowlistCommand::Prune { config } => {
            let config = load_valid_config(&config)?;
            let pruned = runtime_policy::prune_expired(&config.runtime_policy.path)?;
            println!("pruned {pruned} expired allowlist entrie(s)");
            Ok(())
        }
        AllowlistCommand::Block { command } => match command {
            BlocklistCommand::Add {
                value,
                duration,
                reason,
                config,
            } => {
                let config = load_valid_config(&config)?;
                let duration_seconds = if let Some(duration) = duration.as_deref() {
                    runtime_policy::parse_duration_seconds(duration)
                        .with_context(|| "blocklist duration must look like 30m, 2h, or 1d")?
                } else {
                    config.runtime_policy.default_duration_seconds()
                };
                let entry = runtime_policy::add_block_ip_entry(
                    &config.runtime_policy.path,
                    &value,
                    Some(duration_seconds),
                    &reason,
                    "cli",
                )?;
                println!("{}", serde_json::to_string_pretty(&entry)?);
                Ok(())
            }
        },
    }
}

fn load_valid_config(path: &Path) -> anyhow::Result<SaugraConfig> {
    let config = SaugraConfig::from_file(path)
        .with_context(|| format!("failed to load config {}", path.display()))?;
    config.validate()?;
    Ok(config)
}

fn event_log_retention(config: &SaugraConfig) -> anyhow::Result<EventLogRetention> {
    Ok(EventLogRetention {
        max_size_bytes: config.event_log_max_size_bytes()?,
        max_files: config.logging.event_log_max_files,
    })
}

fn print_rule_load_report(report: &rules::RuleLoadReport) {
    if !report.standards.is_empty() {
        println!("rule standards: {}", report.standards.join(","));
    }
    println!("rule files: {}", report.files.len());
    for file in &report.files {
        println!(
            "  {}: name={}, version={}, standards={}, entries={}, enabled={}, disabled={}, active_rules={}, transform_pipelines={}, filtered_by_detection_paranoia={}, unsupported_imports={}",
            file.path,
            file.name.as_deref().unwrap_or("unknown"),
            file.version.as_deref().unwrap_or("unknown"),
            if file.standards.is_empty() {
                "none".to_string()
            } else {
                file.standards.join(",")
            },
            file.entries,
            file.enabled_entries,
            file.disabled_entries,
            file.active_rules,
            file.transform_pipelines,
            file.filtered_by_paranoia,
            file.unsupported_imports
        );
        for warning in &file.warnings {
            println!("    warning: {warning}");
        }
    }
    println!(
        "rules: entries={}, enabled={}, disabled={}, compiled={}, active={}, transform_pipelines={}, filtered_by_detection_paranoia={}",
        report.total_entries,
        report.enabled_entries,
        report.disabled_entries,
        report.compiled_rules,
        report.active_rules,
        report.transform_pipelines,
        report.filtered_by_paranoia
    );
    println!(
        "rule exclusions: configured={}, scoped={}, global={}",
        report.exclusions.configured, report.exclusions.scoped, report.exclusions.global
    );

    if !report.exclusions.disabled_rule_ids.is_empty() {
        println!(
            "disabled rule IDs: {}",
            report.exclusions.disabled_rule_ids.join(",")
        );
    }

    if !report.exclusions.disabled_categories.is_empty() {
        println!(
            "disabled categories: {}",
            report.exclusions.disabled_categories.join(",")
        );
    }

    for warning in &report.warnings {
        println!("warning: {warning}");
    }
}

fn print_owasp_coverage(report: &owasp::OwaspCoverageReport) {
    println!("OWASP coverage standard: {}", report.standard);
    for category in &report.categories {
        println!(
            "{} {}: status={}, request_rules={}",
            category.id, category.name, category.status, category.rule_count
        );

        if category.controls.is_empty() {
            println!("  active controls: none");
        } else {
            println!("  active controls:");
            for control in &category.controls {
                println!("    - {control}");
            }
        }

        if !category.planned_controls.is_empty() {
            println!("  planned controls:");
            for control in &category.planned_controls {
                println!("    - {control}");
            }
        }
    }
}

fn print_posture_report(report: &posture::PostureReport) {
    println!("posture checks enabled: {}", report.enabled);
    for check in &report.checks {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            check.status, check.id, check.owasp_category, check.name, check.message
        );
    }
}

fn print_security_report_summary(summary: &reports::SecurityReportSummary) {
    println!("security reports: {}", summary.reports.len());
    println!("findings: {}", summary.finding_count());

    for missing_path in &summary.missing_paths {
        println!("missing\t{}", missing_path.display());
    }

    for report in &summary.reports {
        println!(
            "report\t{}\tformat={}\tfindings={}",
            report.path.display(),
            report.format,
            report.findings.len()
        );
        for finding in &report.findings {
            println!(
                "finding\t{}\t{}\t{}\t{}\t{}",
                finding.id,
                finding.severity.as_deref().unwrap_or("unknown"),
                finding.package.as_deref().unwrap_or("unknown"),
                finding.owasp_category,
                finding.summary
            );
        }
    }
}

fn print_security_event_summary(summary: &event_store::SecurityEventSummary) {
    println!("security events: {}", summary.total_events);

    println!("actions:");
    if summary.actions.is_empty() {
        println!("  none\t0");
    } else {
        for action in &summary.actions {
            println!("  {}\t{}", action.name, action.count);
        }
    }

    println!("owasp categories:");
    if summary.owasp_categories.is_empty() {
        println!("  none\t0");
    } else {
        for category in &summary.owasp_categories {
            println!("  {}\t{}", category.name, category.count);
        }
    }

    println!("behavior actions:");
    if summary.behavior_actions.is_empty() {
        println!("  none\t0");
    } else {
        for action in &summary.behavior_actions {
            println!("  {}\t{}", action.name, action.count);
        }
    }
}

fn print_init(target: Option<InitTarget>) -> anyhow::Result<()> {
    match target {
        None => {
            println!("{}", include_str!("../configs/saugra.example.yml"));
        }
        Some(InitTarget::Nginx) => {
            println!(
                r#"location / {{
    proxy_pass http://127.0.0.1:8787;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}}"#
            );
        }
        Some(InitTarget::Apache) => {
            println!(
                r#"ProxyPass / http://127.0.0.1:8787/
ProxyPassReverse / http://127.0.0.1:8787/
RequestHeader set X-Forwarded-Proto "https""#
            );
        }
    }

    Ok(())
}
