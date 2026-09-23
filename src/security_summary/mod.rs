use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    config::SaugraConfig,
    decision::WafAction,
    event_store::{self, EventLogRetention, SecurityEvent},
};

mod date;
mod html;
#[cfg(test)]
mod tests;

use date::{event_unix_seconds, unix_seconds_now};
pub use date::{render_output_path, rfc3339_to_unix_seconds};
pub use html::{build_email_message, summary_email_subject};
use html::{deliver, send_from_config_internal};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecuritySummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_hostname: Option<String>,
    pub generated_at_unix_seconds: u64,
    pub timezone: String,
    pub lookback_seconds: u64,
    pub window_start_unix_seconds: u64,
    pub window_end_unix_seconds: u64,
    pub total_security_events: usize,
    pub blocked_events: usize,
    pub monitored_events: usize,
    pub allowed_runtime_policy_events: usize,
    pub rate_limit_events: usize,
    pub bot_events: usize,
    pub behavior_threshold_events: usize,
    pub top_attack_categories: Vec<SummaryCount>,
    pub top_matched_rules: Vec<SummaryCount>,
    pub top_source_ips: Vec<SummaryCount>,
    pub top_targeted_paths: Vec<SummaryCount>,
    pub important_blocked_request_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_log_max_size: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_log_max_files: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SummaryCount {
    pub name: String,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryReport {
    pub output_path: Option<PathBuf>,
    pub email_recipients: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SummaryAdminEvent {
    pub timestamp_unix_seconds: u64,
    pub event_type: String,
    pub message: String,
}

pub fn generate_from_config(config: &SaugraConfig) -> anyhow::Result<SecuritySummary> {
    let retention = EventLogRetention {
        max_size_bytes: config.event_log_max_size_bytes()?,
        max_files: config.logging.event_log_max_files,
    };
    let events = event_store::read_all(Path::new(&config.logging.event_log_path), retention)?;
    let mut summary = generate(
        &events,
        config.security_summary.lookback_seconds(),
        unix_seconds_now(),
        &config.security_summary.timezone,
    );
    summary.app_hostname = summary_app_hostname(config);
    summary.event_log_max_size = Some(config.logging.event_log_max_size.clone());
    summary.event_log_max_files = Some(config.logging.event_log_max_files);
    Ok(summary)
}

pub fn generate(
    events: &[SecurityEvent],
    lookback_seconds: u64,
    now: u64,
    timezone: &str,
) -> SecuritySummary {
    let window_start = now.saturating_sub(lookback_seconds);
    let mut total_security_events = 0;
    let mut blocked_events = 0;
    let mut monitored_events = 0;
    let mut allowed_runtime_policy_events = 0;
    let mut rate_limit_events = 0;
    let mut bot_events = 0;
    let mut behavior_threshold_events = 0;
    let mut categories = BTreeMap::<String, usize>::new();
    let mut rules = BTreeMap::<String, usize>::new();
    let mut source_ips = BTreeMap::<String, usize>::new();
    let mut paths = BTreeMap::<String, usize>::new();
    let mut important_blocked_request_ids = Vec::new();

    for event in events
        .iter()
        .filter(|event| event_unix_seconds(event).is_some_and(|ts| ts >= window_start && ts <= now))
    {
        total_security_events += 1;
        *source_ips.entry(event.client_ip.clone()).or_default() += 1;
        *paths.entry(event.path.clone()).or_default() += 1;

        match event.decision.action {
            WafAction::Block => {
                blocked_events += 1;
                if important_blocked_request_ids.len() < 10 {
                    important_blocked_request_ids.push(event.decision.request_id.clone());
                }
            }
            WafAction::Monitor => monitored_events += 1,
            WafAction::Allow => {}
        }

        if event.decision.runtime_allowlist.is_some() && event.decision.action == WafAction::Allow {
            allowed_runtime_policy_events += 1;
        }

        if event.decision.bot_protection.is_some() {
            bot_events += 1;
        }

        if event.decision.behavior.is_some() {
            behavior_threshold_events += 1;
        }

        if event.owasp_categories.is_empty() {
            *categories.entry("none".to_string()).or_default() += 1;
        } else {
            for category in &event.owasp_categories {
                *categories.entry(category.clone()).or_default() += 1;
            }
        }

        for rule_match in &event.decision.matched_rules {
            *rules.entry(rule_match.rule_id.clone()).or_default() += 1;
            if matches!(
                rule_match.category.as_str(),
                "rate_limit" | "rate_limit_abuse"
            ) {
                rate_limit_events += 1;
            }
        }
    }

    SecuritySummary {
        app_hostname: None,
        generated_at_unix_seconds: now,
        timezone: timezone.to_string(),
        lookback_seconds,
        window_start_unix_seconds: window_start,
        window_end_unix_seconds: now,
        total_security_events,
        blocked_events,
        monitored_events,
        allowed_runtime_policy_events,
        rate_limit_events,
        bot_events,
        behavior_threshold_events,
        top_attack_categories: top_counts(categories, 10),
        top_matched_rules: top_counts(rules, 10),
        top_source_ips: top_counts(source_ips, 10),
        top_targeted_paths: top_counts(paths, 10),
        important_blocked_request_ids,
        event_log_max_size: None,
        event_log_max_files: None,
    }
}

pub fn send_from_config(config: &SaugraConfig) -> anyhow::Result<DeliveryReport> {
    send_from_config_internal(config)
}

pub fn deliver_report(
    config: &SaugraConfig,
    summary: &SecuritySummary,
) -> anyhow::Result<DeliveryReport> {
    deliver(config, summary)
}

fn summary_app_hostname(config: &SaugraConfig) -> Option<String> {
    config
        .upstreams
        .iter()
        .map(|upstream| upstream.host.trim())
        .find(|host| !host.is_empty())
        .map(|host| host.to_ascii_uppercase())
}

fn top_counts(counts: BTreeMap<String, usize>, limit: usize) -> Vec<SummaryCount> {
    let mut counts = counts
        .into_iter()
        .map(|(name, count)| SummaryCount { name, count })
        .collect::<Vec<_>>();
    counts.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.name.cmp(&right.name))
    });
    counts.truncate(limit);
    counts
}
