use crate::{campaign, config::AiConfig, decision::WafAction, event_store::SecurityEvent};

use super::super::{
    ExplanationBehavior, ExplanationCampaign, ExplanationInput, ExplanationRule,
    ExplanationUnknownThreat, TuningSuggestion,
};
use super::explain;

pub fn sanitized_input(config: &AiConfig, event: &SecurityEvent) -> ExplanationInput {
    let decision = &event.decision;
    ExplanationInput {
        prompt_version: config.prompt_version.clone(),
        request_id: decision.request_id.clone(),
        method: event.method.clone(),
        route_shape: sanitized_route_shape(&event.path),
        query_parameters: query_parameter_names(&event.query),
        action: decision.action,
        severity: decision.severity.clone(),
        risk_score: decision.risk_score,
        anomaly_score: decision.anomaly_score,
        anomaly_threshold: decision.anomaly_threshold,
        rules: decision
            .matched_rules
            .iter()
            .map(|rule| ExplanationRule {
                id: rule.rule_id.clone(),
                name: rule.rule_name.clone(),
                category: rule.category.clone(),
                severity: rule.severity.to_string(),
                target: rule.matched_target.to_string(),
            })
            .collect(),
        behavior: decision.behavior.as_ref().map(|behavior| {
            let mut routes = behavior
                .contributors
                .iter()
                .map(|contributor| sanitized_route_shape(&contributor.path))
                .filter(|route| route != "/")
                .collect::<Vec<_>>();
            routes.sort();
            routes.dedup();
            ExplanationBehavior {
                score: behavior.score,
                monitor_threshold: behavior.monitor_threshold,
                block_threshold: behavior.block_threshold,
                contributor_reasons: behavior
                    .contributors
                    .iter()
                    .map(|contributor| contributor.reason.clone())
                    .collect(),
                contributor_routes: routes,
            }
        }),
        unknown_threat: decision
            .unknown_threats
            .as_ref()
            .map(|outcome| ExplanationUnknownThreat {
                route_shape: sanitized_route_shape(&outcome.route_shape),
                score: outcome.score,
                monitor_threshold: outcome.threshold,
                block_threshold: outcome.block_threshold,
                baseline_observations: outcome.baseline_observations,
                baseline_age_seconds: outcome.baseline_age_seconds,
                signals: outcome
                    .signals
                    .iter()
                    .map(|signal| signal.kind.clone())
                    .collect(),
                enforcement_gates: outcome.enforcement_gates.clone(),
            }),
        campaigns: decision
            .campaign
            .as_ref()
            .map(|outcome| {
                outcome
                    .matches
                    .iter()
                    .map(|campaign| ExplanationCampaign {
                        campaign_id: campaign.campaign_id.clone(),
                        kind: campaign.kind.clone(),
                        score: campaign.score,
                        event_count: campaign.event_count,
                        client_count: campaign.client_count,
                        session_count: campaign.session_count,
                        route_count: campaign.route_count,
                        stages: campaign.stages.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        deterministic_explanation: explain(decision),
        deterministic_tuning_suggestions: tuning_suggestions(event),
    }
}

pub(super) fn tuning_suggestions(event: &SecurityEvent) -> Vec<TuningSuggestion> {
    let decision = &event.decision;
    let route = campaign::route_shape(&event.path);
    let mut suggestions = Vec::new();

    if let Some(outcome) = decision
        .unknown_threats
        .as_ref()
        .filter(|outcome| outcome.action == WafAction::Monitor && !outcome.signals.is_empty())
    {
        suggestions.push(TuningSuggestion {
            kind: "route_threshold_review".to_string(),
            config_path: "unknown_threats.routes".to_string(),
            rationale: format!(
                "Route {} produced score {} against monitor threshold {}. Review several events before changing policy.",
                outcome.route_shape, outcome.score, outcome.threshold
            ),
            proposed_value: format!(
                "path: {}\nmonitor_threshold: {}",
                outcome.route_shape,
                outcome.threshold.saturating_add(5)
            ),
        });
    }

    if decision.action == WafAction::Monitor {
        if let Some(rule) = decision.matched_rules.first() {
            suggestions.push(TuningSuggestion {
                kind: "scoped_rule_exclusion_review".to_string(),
                config_path: "rules.exclusions".to_string(),
                rationale: format!(
                    "If reviewed traffic on {} is legitimate, scope any exception to this route and rule; do not disable the category globally.",
                    route
                ),
                proposed_value: format!(
                    "rule_ids: [{}]\npath_prefixes: [{}]",
                    rule.rule_id, route
                ),
            });
        }
    }

    if let Some(behavior) = decision.behavior.as_ref().filter(|behavior| {
        behavior.action == WafAction::Monitor && behavior.score >= behavior.monitor_threshold
    }) {
        suggestions.push(TuningSuggestion {
            kind: "behavior_threshold_review".to_string(),
            config_path: "behavior.route_overrides".to_string(),
            rationale: format!(
                "Behavior score {} reached the monitor threshold {} on {}. Raise only after reviewing repeated legitimate traffic.",
                behavior.score, behavior.monitor_threshold, route
            ),
            proposed_value: format!(
                "path: {}\nmonitor_threshold: {}",
                route,
                behavior.monitor_threshold.saturating_add(10)
            ),
        });
    }

    suggestions
}

fn query_parameter_names(query: &str) -> Vec<String> {
    let mut names = query
        .split('&')
        .filter_map(|pair| pair.split_once('=').map(|(name, _)| name).or(Some(pair)))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| sanitized_identifier(name, 64))
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    names.truncate(64);
    names
}

pub fn sanitized_identifier(value: &str, max_chars: usize) -> String {
    value
        .chars()
        .take(max_chars)
        .map(|character| {
            if character.is_ascii_alphanumeric()
                || matches!(character, '_' | '-' | '.' | ':' | '[' | ']')
            {
                character
            } else {
                '_'
            }
        })
        .collect()
}

pub fn sanitized_route_shape(path: &str) -> String {
    let route = campaign::route_shape(path);
    let segments = route
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            if segment == ":id" || segment.len() > 12 {
                ":id"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>();
    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}
