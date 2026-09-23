use std::{fs, path::Path, time::Instant};

use anyhow::Context;
use serde::Deserialize;

use crate::{
    ai::{
        providers::build_provider,
        sanitized_route_shape,
        types::{
            EvaluationCaseReport, EvaluationReport, ExplanationBehavior, ExplanationCampaign,
            ExplanationInput, ExplanationRule, ExplanationUnknownThreat,
        },
        validate_provider_explanation,
    },
    config::AiConfig,
    decision::WafAction,
};

#[derive(Debug, Deserialize)]
pub(crate) struct EvaluationCase {
    pub(crate) id: String,
    pub(crate) input: serde_json::Value,
    pub(crate) expected: EvaluationExpected,
}

#[derive(Debug, Deserialize)]
pub(crate) struct EvaluationExpected {
    #[serde(default)]
    pub(crate) must_include: Vec<String>,
    #[serde(default)]
    pub(crate) must_not_include: Vec<String>,
    #[serde(default)]
    pub(crate) allowed_suggestion_kinds: Vec<String>,
    pub(crate) maximum_suggestions: usize,
}

pub async fn evaluate_provider(
    config: &AiConfig,
    cases_path: &Path,
) -> anyhow::Result<EvaluationReport> {
    let contents = fs::read_to_string(cases_path)?;
    let cases = contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str::<EvaluationCase>)
        .collect::<Result<Vec<_>, _>>()
        .context("AI evaluation cases must be valid JSONL")?;
    let provider = build_provider(config);
    let mut reports = Vec::new();
    let mut maximum_latency_ms = 0;

    for case in cases {
        let input = evaluation_input(config, &case);
        let encoded = serde_json::to_string(&input)?;
        let started = Instant::now();
        let result = tokio::time::timeout(
            crate::ai::parse_duration(&config.timeout),
            provider.explain(&input),
        )
        .await;
        let latency_ms = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
        maximum_latency_ms = maximum_latency_ms.max(latency_ms);
        let mut failures = Vec::new();
        let mut explanation = None;
        let mut suggestion_kinds = Vec::new();
        if contains_private_evaluation_fields(&case.input) {
            failures.push("input contains a forbidden raw or secret-bearing field".to_string());
        }
        if encoded.contains("authorization")
            || encoded.contains("cookie")
            || encoded.contains("client_ip")
            || encoded.contains("request_body")
        {
            failures.push("sanitized provider input contains forbidden privacy fields".to_string());
        }
        match result {
            Ok(Ok(output)) => {
                explanation = Some(output.explanation.clone());
                suggestion_kinds = output
                    .tuning_suggestions
                    .iter()
                    .map(|suggestion| suggestion.kind.clone())
                    .collect();
                if let Err(error) = validate_provider_explanation(&output.explanation, &input) {
                    failures.push(format!("grounding: {error}"));
                }
                let normalized = output.explanation.to_ascii_lowercase();
                for required in &case.expected.must_include {
                    if !normalized.contains(&required.to_ascii_lowercase()) {
                        failures.push(format!("missing required text: {required}"));
                    }
                }
                for forbidden in &case.expected.must_not_include {
                    if normalized.contains(&forbidden.to_ascii_lowercase()) {
                        failures.push(format!("included forbidden text: {forbidden}"));
                    }
                }
                if output.tuning_suggestions.len() > case.expected.maximum_suggestions {
                    failures.push("too many tuning suggestions".to_string());
                }
                if output.tuning_suggestions.iter().any(|suggestion| {
                    !case
                        .expected
                        .allowed_suggestion_kinds
                        .contains(&suggestion.kind)
                }) {
                    failures.push("suggestion kind is outside the case allowlist".to_string());
                }
            }
            Ok(Err(error)) => failures.push(format!("provider failure: {error:#}")),
            Err(_) => failures.push(format!("provider timed out after {}", config.timeout)),
        }
        reports.push(EvaluationCaseReport {
            id: case.id,
            passed: failures.is_empty(),
            latency_ms,
            explanation,
            suggestion_kinds,
            failures,
        });
    }

    let passed_cases = reports.iter().filter(|case| case.passed).count();
    Ok(EvaluationReport {
        version: 1,
        provider: provider.name().to_string(),
        model: provider.model().to_string(),
        prompt_version: config.prompt_version.clone(),
        total_cases: reports.len(),
        passed_cases,
        failed_cases: reports.len().saturating_sub(passed_cases),
        maximum_latency_ms,
        cases: reports,
    })
}

pub(crate) fn evaluation_input(config: &AiConfig, case: &EvaluationCase) -> ExplanationInput {
    let input = &case.input;
    let mut evaluation = ExplanationInput {
        prompt_version: config.prompt_version.clone(),
        request_id: format!("evaluation-{}", case.id),
        method: crate::ai::sanitized_identifier(&string_value(input, "method", "GET"), 16),
        route_shape: sanitized_route_shape(&string_value(input, "route_shape", "/")),
        query_parameters: string_array(input, "query_parameters")
            .into_iter()
            .map(|name| crate::ai::sanitized_identifier(&name, 64))
            .collect(),
        action: match string_value(input, "action", "monitor").as_str() {
            "allow" => WafAction::Allow,
            "block" => WafAction::Block,
            _ => WafAction::Monitor,
        },
        severity: string_value(input, "severity", "none"),
        risk_score: integer_value(input, "risk_score").min(u8::MAX as u64) as u8,
        anomaly_score: integer_value(input, "anomaly_score").min(u16::MAX as u64) as u16,
        anomaly_threshold: integer_value(input, "anomaly_threshold").min(u16::MAX as u64) as u16,
        rules: input["rules"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|rule| ExplanationRule {
                id: string_value(rule, "id", "unknown"),
                name: string_value(rule, "name", "Unknown rule"),
                category: string_value(rule, "category", "unknown"),
                severity: string_value(rule, "severity", "medium"),
                target: string_value(rule, "target", "query"),
            })
            .collect(),
        behavior: input["behavior"]
            .as_object()
            .map(|behavior| ExplanationBehavior {
                score: value_u16(behavior.get("score")),
                monitor_threshold: behavior
                    .get("monitor_threshold")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or_default()
                    .min(u16::MAX as u64) as u16,
                block_threshold: behavior
                    .get("block_threshold")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or_default()
                    .min(u16::MAX as u64) as u16,
                contributor_reasons: string_array(&input["behavior"], "contributor_reasons"),
                contributor_routes: string_array(&input["behavior"], "contributor_routes")
                    .into_iter()
                    .map(|route| sanitized_route_shape(&route))
                    .collect(),
            }),
        unknown_threat: input["unknown_threat"].as_object().map(|unknown| {
            ExplanationUnknownThreat {
                route_shape: sanitized_route_shape(&string_value(
                    &input["unknown_threat"],
                    "route_shape",
                    &string_value(input, "route_shape", "/"),
                )),
                score: value_u16(unknown.get("score")),
                monitor_threshold: value_u16(unknown.get("monitor_threshold")),
                block_threshold: value_u16(unknown.get("block_threshold")),
                baseline_observations: value_u64(unknown.get("baseline_observations")),
                baseline_age_seconds: value_u64(unknown.get("baseline_age_seconds")),
                signals: string_array(&input["unknown_threat"], "signals"),
                enforcement_gates: string_array(&input["unknown_threat"], "enforcement_gates"),
            }
        }),
        campaigns: input["campaigns"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|campaign| ExplanationCampaign {
                campaign_id: string_value(campaign, "campaign_id", "unknown"),
                kind: string_value(campaign, "kind", "unknown"),
                score: integer_value(campaign, "score").min(u16::MAX as u64) as u16,
                event_count: integer_value(campaign, "event_count")
                    .try_into()
                    .unwrap_or(usize::MAX),
                client_count: integer_value(campaign, "client_count")
                    .try_into()
                    .unwrap_or(usize::MAX),
                session_count: integer_value(campaign, "session_count")
                    .try_into()
                    .unwrap_or(usize::MAX),
                route_count: integer_value(campaign, "route_count")
                    .try_into()
                    .unwrap_or(usize::MAX),
                stages: string_array(campaign, "stages"),
            })
            .collect(),
        deterministic_explanation: "Evaluation fallback.".to_string(),
        deterministic_tuning_suggestions: Vec::new(),
    };
    evaluation.deterministic_explanation = evaluation_fallback(&evaluation);
    evaluation
}

fn evaluation_fallback(input: &ExplanationInput) -> String {
    let action = match input.action {
        WafAction::Allow => "Allow",
        WafAction::Monitor => "Monitor",
        WafAction::Block => "Block",
    };
    let mut evidence = input
        .rules
        .iter()
        .map(|rule| format!("rule {}", rule.id))
        .collect::<Vec<_>>();
    if let Some(behavior) = &input.behavior {
        evidence.extend(
            behavior
                .contributor_reasons
                .iter()
                .map(|reason| format!("behavior contributor {reason}")),
        );
    }
    if let Some(unknown) = &input.unknown_threat {
        evidence.push(format!(
            "route baseline signals {}",
            unknown.signals.join(", ")
        ));
    }
    evidence.extend(
        input
            .campaigns
            .iter()
            .map(|campaign| format!("campaign {} kind {}", campaign.campaign_id, campaign.kind)),
    );
    if evidence.is_empty() {
        format!("{action} action. Evaluation fallback.")
    } else {
        format!(
            "{action} action with {}. Evaluation fallback.",
            evidence.join("; ")
        )
    }
}

fn string_value(value: &serde_json::Value, key: &str, default: &str) -> String {
    value[key].as_str().unwrap_or(default).to_string()
}

fn integer_value(value: &serde_json::Value, key: &str) -> u64 {
    value[key].as_u64().unwrap_or_default()
}

fn value_u64(value: Option<&serde_json::Value>) -> u64 {
    value
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default()
}

fn value_u16(value: Option<&serde_json::Value>) -> u16 {
    value_u64(value).min(u16::MAX as u64) as u16
}

fn string_array(value: &serde_json::Value, key: &str) -> Vec<String> {
    value[key]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str().map(ToString::to_string))
        .collect()
}

fn contains_private_evaluation_fields(value: &serde_json::Value) -> bool {
    const FORBIDDEN: &[&str] = &[
        "body",
        "request_body",
        "query",
        "authorization",
        "cookie",
        "client_ip",
        "token",
        "password",
    ];
    value.as_object().is_some_and(|object| {
        object.keys().any(|key| FORBIDDEN.contains(&key.as_str()))
            || object.values().any(contains_private_evaluation_fields)
    }) || value
        .as_array()
        .is_some_and(|values| values.iter().any(contains_private_evaluation_fields))
}
