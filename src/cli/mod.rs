use std::path::Path;

use anyhow::Context;
use clap::Parser;
use saugra_waf::{
    ai, config::SaugraConfig, console, event_store, logging, owasp, posture, proxy, reports, rules,
    security_summary, standards, storage_cleanup, unknown_threats,
};

pub mod commands;
pub mod handlers;
pub mod printers;

use commands::*;
use handlers::*;
use printers::*;

pub async fn run() -> anyhow::Result<()> {
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
        Commands::Console { command } => match command {
            ConsoleCommand::Enroll {
                config,
                enrollment_token,
                display_name,
            } => {
                let config = load_valid_config(&config)?;
                let credential = console::enroll_with_console(
                    &config,
                    &enrollment_token,
                    display_name.as_deref(),
                )
                .await?;
                println!(
                    "enrolled with Saugra Console as node {} (tenant {}, credential fingerprint {})",
                    credential.node_id, credential.tenant_id, credential.credential_fingerprint
                );
                Ok(())
            }
            ConsoleCommand::PolicyOverride { config, command } => {
                let config = load_valid_config(&config)?;
                match command {
                    PolicyOverrideCommand::Status => match console::emergency_override(&config)? {
                        Some(state) => println!(
                            "enabled since {}: {}",
                            state.enabled_at_unix_secs, state.reason
                        ),
                        None => println!("disabled; verified managed policy may activate"),
                    },
                    PolicyOverrideCommand::Enable { reason } => {
                        console::enable_emergency_override(&config, &reason)?;
                        println!("enabled; restart or wait for the next policy poll to suspend managed policy");
                    }
                    PolicyOverrideCommand::Disable => {
                        let removed = console::disable_emergency_override(&config)?;
                        println!("{}; restart or wait for the next policy poll to reactivate the verified policy", if removed { "disabled" } else { "already disabled" });
                    }
                }
                Ok(())
            }
        },
        Commands::Rules { command } => handle_rules(command),
        Commands::Logs { command } => match command {
            LogsCommand::Tail { config, limit } => {
                let config = load_valid_config(&config)?;
                let retention = event_log_retention(&config)?;
                let events = event_store::tail(
                    std::path::Path::new(&config.logging.event_log_path),
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
                    std::path::Path::new(&config.logging.event_log_path),
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
                std::path::Path::new(&config.logging.event_log_path),
                retention,
                &request_id,
            )?
            .with_context(|| format!("request ID not found: {request_id}"))?;

            println!("Request ID: {}", event.decision.request_id);
            println!("Client IP: {}", event.client_ip);
            println!("Request: {} {}", event.method, event.path);
            if !event.query.is_empty() {
                println!("Query: {}", event.query);
            }
            if let Some(upstream) = &event.upstream {
                println!(
                    "Upstream: {}@{} -> {}",
                    upstream.name, upstream.host, upstream.target
                );
            }
            let explanation = ai::explain_event(&config.ai, &event).await?;
            println!();
            println!("{}", explanation.explanation);
            if !explanation.tuning_suggestions.is_empty() {
                println!();
                println!("Tuning suggestions (review before applying):");
                for suggestion in &explanation.tuning_suggestions {
                    println!(
                        "- {} at {}: {} Proposed value: {}",
                        suggestion.kind,
                        suggestion.config_path,
                        suggestion.rationale,
                        suggestion.proposed_value.replace('\n', "; ")
                    );
                }
            }
            println!();
            println!(
                "Explanation provider: {} model={} prompt={} digest={} latency_ms={} fallback={}",
                explanation.provider,
                explanation.model,
                explanation.prompt_version,
                explanation.input_digest,
                explanation.latency_ms,
                explanation.fallback_used
            );
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
        Commands::Summary { command } => match command {
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
        },
        Commands::Cleanup { command } => match command {
            CleanupCommand::Run {
                config,
                dry_run,
                execute,
            } => {
                let config = load_valid_config(&config)?;
                let dry_run_override = if dry_run {
                    Some(true)
                } else if execute {
                    Some(false)
                } else {
                    None
                };
                let report = storage_cleanup::run_from_config(&config, dry_run_override)?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                Ok(())
            }
        },
        Commands::UnknownThreats { command } => match command {
            UnknownThreatCommand::Report { config, limit } => {
                let config = load_valid_config(&config)?;
                let events = event_store::tail(
                    Path::new(&config.logging.event_log_path),
                    event_log_retention(&config)?,
                    limit,
                )?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&unknown_threats::shadow_report(&events))?
                );
                Ok(())
            }
        },
        Commands::Ai { command } => match command {
            AiCommand::Evaluate {
                config,
                cases,
                output,
            } => {
                let config = load_valid_config(&config)?;
                let report = ai::evaluate_provider(&config.ai, &cases).await?;
                let encoded = serde_json::to_string_pretty(&report)?;
                if let Some(output) = output {
                    std::fs::write(&output, format!("{encoded}\n"))?;
                    println!("AI evaluation report written: {}", output.display());
                } else {
                    println!("{encoded}");
                }
                anyhow::ensure!(
                    report.failed_cases == 0,
                    "{} AI evaluation cases failed",
                    report.failed_cases
                );
                Ok(())
            }
            AiCommand::AnomalyShadow {
                config,
                limit,
                output,
            } => {
                let config = load_valid_config(&config)?;
                let events = event_store::tail(
                    Path::new(&config.logging.event_log_path),
                    event_log_retention(&config)?,
                    limit,
                )?;
                let report = ai::anomaly_shadow_review(&config.ai, &events).await?;
                let encoded = serde_json::to_string_pretty(&report)?;
                if let Some(output) = output {
                    std::fs::write(&output, format!("{encoded}\n"))?;
                    println!("AI shadow review report written: {}", output.display());
                } else {
                    println!("{encoded}");
                }
                Ok(())
            }
        },
    }
}
