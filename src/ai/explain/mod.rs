use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::{
    config::AiConfig,
    decision::{WafAction, WafDecision},
    event_store::SecurityEvent,
};

use super::{
    build_provider, local_output, ExplanationAuditRecord, ExplanationInput, ExplanationResult,
    TuningSuggestion,
};

mod audit;
mod sanitized;

pub use audit::{content_digest, rotated_audit_path, sha256};
use audit::{append_audit, digest};
pub use sanitized::{sanitized_identifier, sanitized_input, sanitized_route_shape};

pub async fn explain_event(
    config: &AiConfig,
    event: &SecurityEvent,
) -> anyhow::Result<ExplanationResult> {
    let input = sanitized_input(config, event);
    let encoded = serde_json::to_vec(&input)?;
    let input_digest = digest(&encoded);
    let provider = build_provider(config);
    let provider_name = provider.name().to_string();
    let model = provider.model().to_string();

    let started = Instant::now();
    let timeout = parse_duration(config.timeout.as_str());
    let provider_result = tokio::time::timeout(timeout, provider.explain(&input)).await;
    let latency_ms = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);

    let (output, failure, fallback_used) = match provider_result {
        Ok(Ok(output))
            if !output.explanation.trim().is_empty()
                && validate_provider_explanation(&output.explanation, &input).is_ok() =>
        {
            (output, None, false)
        }
        Ok(Ok(_)) => (
            local_output(&input),
            Some("provider returned an empty or ungrounded explanation".to_string()),
            true,
        ),
        Ok(Err(error)) => (
            local_output(&input),
            Some(sanitize_failure(&format!("{error:#}"))),
            true,
        ),
        Err(_) => (
            local_output(&input),
            Some(format!("provider timed out after {}", config.timeout)),
            true,
        ),
    };
    let explanation = output.explanation.chars().take(16_384).collect();
    let mut suggestions = narrow_tuning_suggestions(output.tuning_suggestions);
    suggestions.retain(|suggestion| suggestion_matches_input(suggestion, &input));
    suggestions.truncate(config.max_tuning_suggestions);
    let result = ExplanationResult {
        explanation,
        tuning_suggestions: suggestions,
        provider: provider_name.clone(),
        model: model.clone(),
        prompt_version: config.prompt_version.clone(),
        input_digest: input_digest.clone(),
        latency_ms,
        fallback_used,
    };
    append_audit(
        config,
        &ExplanationAuditRecord {
            timestamp_unix_seconds: unix_seconds_now(),
            request_id: event.decision.request_id.clone(),
            provider: provider_name,
            model,
            prompt_version: config.prompt_version.clone(),
            input_digest,
            output: result.explanation.clone(),
            tuning_suggestions: result.tuning_suggestions.clone(),
            latency_ms,
            success: failure.is_none(),
            fallback_used,
            api_key_env: config.api_key_env.clone(),
            data_region: config.data_region.clone(),
            retention_policy: config.retention_policy.clone(),
            failure,
        },
    )?;
    Ok(result)
}

pub fn validate_provider_explanation(
    explanation: &str,
    input: &ExplanationInput,
) -> anyhow::Result<()> {
    let normalized = explanation.to_ascii_lowercase();
    if normalized.contains("score") || normalized.contains("threshold") {
        anyhow::bail!("model explanation restated deterministic score data");
    }

    let action = match input.action {
        WafAction::Allow => "allow",
        WafAction::Monitor => "monitor",
        WafAction::Block => "block",
    };
    if !normalized.contains(action) {
        anyhow::bail!("model explanation omitted deterministic action {action}");
    }

    for rule in &input.rules {
        if !normalized.contains(&rule.id.to_ascii_lowercase()) {
            anyhow::bail!("model explanation omitted rule ID {}", rule.id);
        }
    }

    if let Some(behavior) = &input.behavior {
        for reason in &behavior.contributor_reasons {
            if !normalized.contains(&reason.to_ascii_lowercase()) {
                anyhow::bail!("model explanation omitted behavior contributor {reason}");
            }
        }
    }

    if let Some(unknown) = &input.unknown_threat {
        if !normalized.contains("baseline") {
            anyhow::bail!("model explanation omitted route baseline context");
        }
        for signal in &unknown.signals {
            if !normalized.contains(&signal.to_ascii_lowercase()) {
                anyhow::bail!("model explanation omitted unknown-threat signal {signal}");
            }
        }
    }

    for campaign in &input.campaigns {
        if !normalized.contains(&campaign.campaign_id.to_ascii_lowercase()) {
            anyhow::bail!(
                "model explanation omitted campaign ID {}",
                campaign.campaign_id
            );
        }
        if !normalized.contains(&campaign.kind.to_ascii_lowercase()) {
            anyhow::bail!("model explanation omitted campaign kind {}", campaign.kind);
        }
    }
    Ok(())
}

pub fn suggestion_matches_input(suggestion: &TuningSuggestion, input: &ExplanationInput) -> bool {
    match suggestion.kind.as_str() {
        "route_threshold_review" => return input.unknown_threat.is_some(),
        "behavior_threshold_review" => return input.behavior.is_some(),
        "scoped_rule_exclusion_review" => {}
        _ => return false,
    }

    let text = format!(
        "{} {}",
        suggestion.rationale.to_ascii_lowercase(),
        suggestion.proposed_value.to_ascii_lowercase()
    );
    let names_route = text.contains(&input.route_shape.to_ascii_lowercase());
    let names_rule = input
        .rules
        .iter()
        .any(|rule| text.contains(&rule.id.to_ascii_lowercase()));
    names_route && names_rule
}

pub fn narrow_tuning_suggestions(suggestions: Vec<TuningSuggestion>) -> Vec<TuningSuggestion> {
    suggestions
        .into_iter()
        .filter(|suggestion| {
            matches!(
                (suggestion.kind.as_str(), suggestion.config_path.as_str()),
                ("route_threshold_review", "unknown_threats.routes")
                    | ("scoped_rule_exclusion_review", "rules.exclusions")
                    | ("behavior_threshold_review", "behavior.route_overrides")
            )
        })
        .map(|mut suggestion| {
            suggestion.rationale = suggestion.rationale.chars().take(1_024).collect();
            suggestion.proposed_value = suggestion.proposed_value.chars().take(1_024).collect();
            suggestion
        })
        .collect()
}

fn sanitize_failure(failure: &str) -> String {
    failure
        .replace(['\n', '\r'], " ")
        .chars()
        .take(512)
        .collect()
}

pub fn parse_duration(value: &str) -> std::time::Duration {
    let value = value.trim().to_ascii_lowercase();
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    let number = value[..split].parse::<u64>().unwrap_or(10);
    let multiplier = match value[split..].trim() {
        "m" | "min" | "mins" | "minute" | "minutes" => 60,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3_600,
        _ => 1,
    };
    std::time::Duration::from_secs(number.saturating_mul(multiplier))
}

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn explain(decision: &WafDecision) -> String {
    let campaign_context = decision
        .campaign
        .as_ref()
        .filter(|outcome| !outcome.matches.is_empty())
        .map(|outcome| {
            let matches = outcome
                .matches
                .iter()
                .map(|campaign| {
                    format!(
                        "{} ({}, score {}, {} events, {} clients, {} sessions, {} routes)",
                        campaign.campaign_id,
                        campaign.kind,
                        campaign.score,
                        campaign.event_count,
                        campaign.client_count,
                        campaign.session_count,
                        campaign.route_count
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            format!(" Campaign correlation matched: {matches}.")
        })
        .unwrap_or_default();
    let allowlist_context = decision
        .runtime_allowlist
        .as_ref()
        .map(|allowlist| {
            format!(
                " Runtime allowlist entry {} matched {} with effect {:?}.",
                allowlist.id, allowlist.value, allowlist.effect
            )
        })
        .unwrap_or_default();

    if decision.matched_rules.is_empty() {
        if let Some(bot_protection) = &decision.bot_protection {
            return format!(
                "No request rules matched. Bot protection score is {}/{} for monitor and {}/{} for block with {} contributor(s).",
                bot_protection.score,
                bot_protection.monitor_threshold,
                bot_protection.score,
                bot_protection.block_threshold,
                bot_protection.contributors.len(),
            ) + &contributor_path_context(&bot_protection.contributors)
                + &campaign_context
                + &allowlist_context;
        }
        if let Some(behavior) = &decision.behavior {
            return format!(
                "No request rules matched. Behavior score is {}/{} for monitor and {}/{} for block.",
                behavior.score,
                behavior.monitor_threshold,
                behavior.score,
                behavior.block_threshold
            ) + &contributor_path_context(&behavior.contributors)
                + &campaign_context
                + &allowlist_context;
        }
        if let Some(outcome) = decision
            .unknown_threats
            .as_ref()
            .filter(|outcome| !outcome.signals.is_empty())
        {
            return format!(
                "No request rules matched. Unknown-threat score is {}/{} for monitor and {}/{} for block on route {} with {} signal(s). Would block: {}. Enforcement gates: {}. {}",
                outcome.score,
                outcome.threshold,
                outcome.score,
                outcome.block_threshold,
                outcome.route_shape,
                outcome.signals.len(),
                outcome.would_block,
                if outcome.enforcement_gates.is_empty() {
                    "none".to_string()
                } else {
                    outcome.enforcement_gates.join(", ")
                },
                outcome
                    .signals
                    .iter()
                    .map(|signal| signal.explanation.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            ) + &campaign_context
                + &allowlist_context;
        }
        return "No rules matched this request, so Saugra allowed it.".to_string()
            + &campaign_context
            + &allowlist_context;
    }

    let rule = &decision.matched_rules[0];
    let owasp_context = if decision.owasp_categories.is_empty() {
        "It is not mapped to a specific OWASP category.".to_string()
    } else {
        format!(
            "It maps to OWASP category {}.",
            decision.owasp_categories.join(", ")
        )
    };

    let behavior_context = decision
        .behavior
        .as_ref()
        .map(|behavior| {
            format!(
                " Behavior score is {}/{} for monitor and {}/{} for block with {} contributor(s).",
                behavior.score,
                behavior.monitor_threshold,
                behavior.score,
                behavior.block_threshold,
                behavior.contributors.len()
            ) + &contributor_path_context(&behavior.contributors)
        })
        .unwrap_or_default();
    let unknown_threat_context = decision
        .unknown_threats
        .as_ref()
        .filter(|outcome| !outcome.signals.is_empty())
        .map(|outcome| {
            format!(
                " Unknown-threat score is {}/{} for monitor and {}/{} for block on route {} with {} signal(s). Would block: {}. Enforcement gates: {}. {}",
                outcome.score,
                outcome.threshold,
                outcome.score,
                outcome.block_threshold,
                outcome.route_shape,
                outcome.signals.len(),
                outcome.would_block,
                if outcome.enforcement_gates.is_empty() {
                    "none".to_string()
                } else {
                    outcome.enforcement_gates.join(", ")
                },
                outcome
                    .signals
                    .iter()
                    .map(|signal| signal.explanation.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        })
        .unwrap_or_default();
    let bot_context = decision
        .bot_protection
        .as_ref()
        .map(|bot_protection| {
            format!(
                " Bot protection score is {}/{} for monitor and {}/{} for block with {} contributor(s).",
                bot_protection.score,
                bot_protection.monitor_threshold,
                bot_protection.score,
                bot_protection.block_threshold,
                bot_protection.contributors.len()
            ) + &contributor_path_context(&bot_protection.contributors)
        })
        .unwrap_or_default();

    format!(
        "This request was flagged because {} matched rule {} ({}) with {} severity. {} Anomaly score is {}/{}; blocking-eligible score is {}/{}.",
        rule.matched_target,
        rule.rule_id,
        rule.rule_name,
        rule.severity,
        owasp_context,
        decision.anomaly_score,
        decision.anomaly_threshold,
        decision.blocking_anomaly_score,
        decision.anomaly_threshold
    ) + &behavior_context
        + &unknown_threat_context
        + &bot_context
        + &campaign_context
        + &allowlist_context
}

fn contributor_path_context(contributors: &[crate::behavior::BehaviorContributor]) -> String {
    let mut paths = contributors
        .iter()
        .map(|contributor| contributor.path.as_str())
        .filter(|path| !path.is_empty())
        .collect::<Vec<_>>();
    paths.sort_unstable();
    paths.dedup();

    if paths.is_empty() {
        String::new()
    } else {
        format!(" Contributor paths: {}.", paths.join(", "))
    }
}
