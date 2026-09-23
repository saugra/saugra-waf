use std::path::Path;

use anyhow::Context;
use saugra_waf::{
    behavior, bot, config::SaugraConfig, crs_convert, event_store, event_store::EventLogRetention,
    rule_drafts, rules, runtime_policy,
};

use super::commands::{
    AllowlistAddTarget, AllowlistCommand, BlocklistCommand, RulesCommand, StateCommand,
    StateResetTarget,
};
use super::printers::print_reset_result;

pub fn load_valid_config(path: &Path) -> anyhow::Result<SaugraConfig> {
    let config = SaugraConfig::from_file(path)
        .with_context(|| format!("failed to load config {}", path.display()))?;
    config.validate()?;
    Ok(config)
}

pub fn event_log_retention(config: &SaugraConfig) -> anyhow::Result<EventLogRetention> {
    Ok(EventLogRetention {
        max_size_bytes: config.event_log_max_size_bytes()?,
        max_files: config.logging.event_log_max_files,
    })
}

pub fn handle_rules(command: RulesCommand) -> anyhow::Result<()> {
    match command {
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
        RulesCommand::View { rule_id, config } => {
            let config = load_valid_config(&config)?;
            let rule_set = rules::load_rule_set(&config.rules)?;
            let matching_rules = rule_set.rules_by_id(&rule_id);
            let Some(rule) = matching_rules.first() else {
                anyhow::bail!("active rule {rule_id} was not found");
            };
            let mut targets = matching_rules
                .iter()
                .map(|rule| rule.target.to_string())
                .collect::<Vec<_>>();
            targets.sort();
            targets.dedup();
            let transforms = if rule.transforms.is_empty() {
                "none".to_string()
            } else {
                rule.transforms
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            };

            println!("Rule ID: {}", rule.id);
            println!("Name: {}", rule.name);
            println!("Status: active");
            println!("Baseline severity: {}", rule.severity);
            println!("Category: {}", rule.category);
            println!(
                "OWASP category: {}",
                rule.owasp_category.as_deref().unwrap_or("not specified")
            );
            println!("Paranoia level: {}", rule.paranoia_level);
            println!(
                "Performance cost tier: {}",
                rule.performance_cost
                    .map(|cost| cost.to_string())
                    .unwrap_or_else(|| "not specified".to_string())
            );
            println!("Targets: {}", targets.join(", "));
            println!("Transforms: {transforms}");
            println!("Pattern: {}", rule.pattern.as_str());
            println!(
                "Design intent: {}",
                rule.design_intent.as_deref().unwrap_or("not specified")
            );
            println!("Match explanation: {}", rule.explanation);
            Ok(())
        }
        RulesCommand::Validate {
            input,
            paranoia_level,
        } => {
            let (_rule_set, report) = rules::validate_rule_file(&input, paranoia_level)?;
            println!("rule pack OK: {}", input.display());
            println!(
                "entries={} enabled={} disabled={} compiled={} active={} filtered={}",
                report.entries,
                report.enabled_entries,
                report.disabled_entries,
                report.compiled_rules,
                report.active_rules,
                report.filtered_by_paranoia
            );
            for warning in report.warnings {
                println!("warning: {warning}");
            }
            Ok(())
        }
        RulesCommand::Replay {
            input,
            config,
            limit,
            output,
            fixtures,
        } => {
            let config = load_valid_config(&config)?;
            let (rule_set, _report) = rules::validate_rule_file(&input, u8::MAX)?;
            let events = event_store::tail(
                Path::new(&config.logging.event_log_path),
                event_log_retention(&config)?,
                limit,
            )?;
            let mut report =
                rules::replay_events_with_exclusions(&rule_set, &events, &config.rules.exclusions);
            if let Some(fixtures) = fixtures {
                rules::attach_labeled_replay(
                    &mut report,
                    &rule_set,
                    &config.rules.exclusions,
                    &fixtures,
                )?;
            }
            let encoded = serde_json::to_string_pretty(&report)?;
            if let Some(output) = output {
                std::fs::write(&output, format!("{encoded}\n"))?;
                println!("replay report written: {}", output.display());
            } else {
                println!("{encoded}");
            }
            Ok(())
        }
        RulesCommand::Draft {
            request_ids,
            output,
            config,
        } => {
            let config = load_valid_config(&config)?;
            let events = event_store::read_all(
                Path::new(&config.logging.event_log_path),
                event_log_retention(&config)?,
            )?;
            let manifest = rule_drafts::create_draft(
                &events,
                &request_ids,
                &output,
                &config.ai.provider,
                &config.ai.model,
                &config.ai.prompt_version,
            )?;
            println!("draft rule written: {}", output.display());
            println!("draft manifest written: {}", manifest.display());
            Ok(())
        }
        RulesCommand::Approve {
            input,
            reviewer,
            replay_report,
        } => {
            rule_drafts::approve_draft(&input, &reviewer, &replay_report)?;
            println!("draft approved: {}", input.display());
            Ok(())
        }
        RulesCommand::Publish {
            input,
            destination,
            config,
        } => {
            let config = load_valid_config(&config)?;
            rule_drafts::publish_draft(&input, &destination, &config)?;
            println!(
                "draft published for monitor rollout: {}",
                destination.display()
            );
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
    }
}

pub fn handle_state(command: StateCommand) -> anyhow::Result<()> {
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

pub fn handle_allowlist(command: AllowlistCommand) -> anyhow::Result<()> {
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
