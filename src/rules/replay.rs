use std::{collections::BTreeMap, fs, path::Path};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::{config::RuleExclusionConfig, decision::WafAction, event_store::SecurityEvent};

use super::{
    types::{RequestParts, RuleTarget},
    RuleSet,
};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RuleReplayReport {
    pub total_events: usize,
    pub matched_events: usize,
    pub unmatched_events: usize,
    pub excluded_events: usize,
    pub matches_before_exclusions: usize,
    pub matches_after_exclusions: usize,
    pub previously_allowed_review_candidates: usize,
    pub previously_monitored_matches: usize,
    pub previously_blocked_matches: usize,
    pub prior_rule_detection_events: usize,
    pub prior_rule_detection_overlap: usize,
    pub rule_match_counts: BTreeMap<String, usize>,
    pub replayed_targets: Vec<String>,
    pub unavailable_targets: Vec<String>,
    pub limitations: Vec<String>,
    pub labeled_total_cases: usize,
    pub labeled_legitimate_cases: usize,
    pub labeled_attack_cases: usize,
    pub labeled_legitimate_matches: usize,
    pub labeled_attack_matches: usize,
}

#[derive(Debug, Deserialize)]
struct LabeledReplayCase {
    id: String,
    label: String,
    #[serde(default = "default_replay_method")]
    method: String,
    path: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    headers: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    user_agent: String,
    #[serde(default)]
    content_type: String,
}

fn default_replay_method() -> String {
    "GET".to_string()
}

pub fn replay_events(rule_set: &RuleSet, events: &[SecurityEvent]) -> RuleReplayReport {
    replay_events_with_exclusions(rule_set, events, &[])
}

pub fn replay_events_with_exclusions(
    rule_set: &RuleSet,
    events: &[SecurityEvent],
    exclusions: &[RuleExclusionConfig],
) -> RuleReplayReport {
    let mut matched_events = 0;
    let mut excluded_events = 0;
    let mut matches_before_exclusions = 0;
    let mut matches_after_exclusions = 0;
    let mut previously_allowed_review_candidates = 0;
    let mut previously_monitored_matches = 0;
    let mut previously_blocked_matches = 0;
    let mut prior_rule_detection_events = 0;
    let mut prior_rule_detection_overlap = 0;
    let mut rule_match_counts = BTreeMap::new();

    for event in events {
        let prior_rule_detection = !event.decision.matched_rules.is_empty();
        if prior_rule_detection {
            prior_rule_detection_events += 1;
        }

        let headers = event
            .evidence
            .as_ref()
            .map(|evidence| {
                evidence
                    .header_names
                    .iter()
                    .map(|name| format!("{name}: [retained-value-unavailable]"))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        let content_type = event
            .evidence
            .as_ref()
            .map(|evidence| evidence.content_type.as_str())
            .unwrap_or_default();
        let parts = RequestParts {
            method: &event.method,
            path: &event.path,
            query: &event.query,
            headers: &headers,
            content_type,
            ..RequestParts::default()
        };
        let all_matches = rule_set.inspect(&parts);
        matches_before_exclusions += all_matches.len();
        let matches = rule_set.inspect_with_exclusions(&parts, exclusions);
        matches_after_exclusions += matches.len();
        if !all_matches.is_empty() && matches.is_empty() {
            excluded_events += 1;
        }
        if matches.is_empty() {
            continue;
        }

        matched_events += 1;
        if prior_rule_detection {
            prior_rule_detection_overlap += 1;
        }
        match event.decision.action {
            WafAction::Allow => previously_allowed_review_candidates += 1,
            WafAction::Monitor => previously_monitored_matches += 1,
            WafAction::Block => previously_blocked_matches += 1,
        }
        for rule_match in matches {
            *rule_match_counts.entry(rule_match.rule_id).or_insert(0) += 1;
        }
    }

    let mut replayed_targets = Vec::new();
    let mut unavailable_targets = Vec::new();
    for rule in rule_set.rules() {
        let target = rule.target.to_string();
        let destination = match rule.target {
            RuleTarget::Path | RuleTarget::Query => &mut replayed_targets,
            RuleTarget::Headers | RuleTarget::Body | RuleTarget::UserAgent => {
                &mut unavailable_targets
            }
        };
        destination.push(target);
    }
    replayed_targets.sort();
    replayed_targets.dedup();
    unavailable_targets.sort();
    unavailable_targets.dedup();

    let mut limitations = vec![
        "Previously allowed matches are review candidates, not confirmed false positives."
            .to_string(),
        "Prior rule-detection overlap is not a labeled attack-case coverage metric.".to_string(),
    ];
    if !unavailable_targets.is_empty() {
        limitations.push(format!(
            "Retained security events cannot replay these request targets: {}.",
            unavailable_targets.join(", ")
        ));
    }
    if exclusions
        .iter()
        .any(|exclusion| !exclusion.trusted_headers.is_empty() || !exclusion.identities.is_empty())
    {
        limitations.push(
            "Retained events do not preserve trusted header values, so value and identity exclusion conditions are not replayed."
                .to_string(),
        );
    }

    RuleReplayReport {
        total_events: events.len(),
        matched_events,
        unmatched_events: events.len().saturating_sub(matched_events),
        excluded_events,
        matches_before_exclusions,
        matches_after_exclusions,
        previously_allowed_review_candidates,
        previously_monitored_matches,
        previously_blocked_matches,
        prior_rule_detection_events,
        prior_rule_detection_overlap,
        rule_match_counts,
        replayed_targets,
        unavailable_targets,
        limitations,
        labeled_total_cases: 0,
        labeled_legitimate_cases: 0,
        labeled_attack_cases: 0,
        labeled_legitimate_matches: 0,
        labeled_attack_matches: 0,
    }
}

pub fn attach_labeled_replay(
    report: &mut RuleReplayReport,
    rule_set: &RuleSet,
    exclusions: &[RuleExclusionConfig],
    fixture_path: &Path,
) -> anyhow::Result<()> {
    let contents = fs::read_to_string(fixture_path)?;
    for line in contents.lines().filter(|line| !line.trim().is_empty()) {
        let case: LabeledReplayCase =
            serde_json::from_str(line).context("labeled replay fixture must be valid JSONL")?;
        anyhow::ensure!(
            matches!(case.label.as_str(), "legitimate" | "attack"),
            "labeled replay case {} must use label legitimate or attack",
            case.id
        );
        let matches = rule_set.inspect_with_exclusions(
            &RequestParts {
                method: &case.method,
                path: &case.path,
                query: &case.query,
                headers: &case.headers,
                body: &case.body,
                user_agent: &case.user_agent,
                content_type: &case.content_type,
                trusted_proxy: false,
            },
            exclusions,
        );
        report.labeled_total_cases += 1;
        if case.label == "legitimate" {
            report.labeled_legitimate_cases += 1;
            if !matches.is_empty() {
                report.labeled_legitimate_matches += 1;
            }
        } else {
            report.labeled_attack_cases += 1;
            if !matches.is_empty() {
                report.labeled_attack_matches += 1;
            }
        }
    }
    Ok(())
}
