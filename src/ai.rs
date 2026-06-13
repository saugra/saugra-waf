use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    process::Stdio,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::io::AsyncWriteExt;

use crate::{
    campaign,
    config::AiConfig,
    decision::{WafAction, WafDecision},
    event_store::SecurityEvent,
};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ExplanationResult {
    pub explanation: String,
    pub tuning_suggestions: Vec<TuningSuggestion>,
    pub provider: String,
    pub model: String,
    pub prompt_version: String,
    pub input_digest: String,
    pub latency_ms: u64,
    pub fallback_used: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct TuningSuggestion {
    pub kind: String,
    pub config_path: String,
    pub rationale: String,
    pub proposed_value: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExplanationAuditRecord {
    pub timestamp_unix_seconds: u64,
    pub request_id: String,
    pub provider: String,
    pub model: String,
    pub prompt_version: String,
    pub input_digest: String,
    pub output: String,
    pub tuning_suggestions: Vec<TuningSuggestion>,
    pub latency_ms: u64,
    pub success: bool,
    pub fallback_used: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExplanationInput {
    pub prompt_version: String,
    pub request_id: String,
    pub method: String,
    pub route_shape: String,
    pub query_parameters: Vec<String>,
    pub action: WafAction,
    pub severity: String,
    pub risk_score: u8,
    pub anomaly_score: u16,
    pub anomaly_threshold: u16,
    pub rules: Vec<ExplanationRule>,
    pub behavior: Option<ExplanationBehavior>,
    pub unknown_threat: Option<ExplanationUnknownThreat>,
    pub campaigns: Vec<ExplanationCampaign>,
    #[serde(skip_serializing)]
    pub deterministic_explanation: String,
    #[serde(skip_serializing)]
    pub deterministic_tuning_suggestions: Vec<TuningSuggestion>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExplanationRule {
    pub id: String,
    pub name: String,
    pub category: String,
    pub severity: String,
    pub target: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExplanationBehavior {
    pub score: u16,
    pub monitor_threshold: u16,
    pub block_threshold: u16,
    pub contributor_reasons: Vec<String>,
    pub contributor_routes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExplanationUnknownThreat {
    pub route_shape: String,
    pub score: u16,
    pub monitor_threshold: u16,
    pub block_threshold: u16,
    pub baseline_observations: u64,
    pub baseline_age_seconds: u64,
    pub signals: Vec<String>,
    pub enforcement_gates: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExplanationCampaign {
    pub campaign_id: String,
    pub kind: String,
    pub score: u16,
    pub event_count: usize,
    pub client_count: usize,
    pub session_count: usize,
    pub route_count: usize,
    pub stages: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProviderOutput {
    pub explanation: String,
    #[serde(default)]
    pub tuning_suggestions: Vec<TuningSuggestion>,
}

#[async_trait]
pub trait ExplanationProvider: Send + Sync {
    fn name(&self) -> &str;
    fn model(&self) -> &str;
    async fn explain(&self, input: &ExplanationInput) -> anyhow::Result<ProviderOutput>;
}

struct LocalExplanationProvider {
    model: String,
}

#[async_trait]
impl ExplanationProvider for LocalExplanationProvider {
    fn name(&self) -> &str {
        "local"
    }

    fn model(&self) -> &str {
        &self.model
    }

    async fn explain(&self, input: &ExplanationInput) -> anyhow::Result<ProviderOutput> {
        Ok(ProviderOutput {
            explanation: input.deterministic_explanation.clone(),
            tuning_suggestions: input.deterministic_tuning_suggestions.clone(),
        })
    }
}

struct CommandExplanationProvider {
    program: String,
    args: Vec<String>,
    model: String,
}

struct OllamaExplanationProvider {
    base_url: String,
    model: String,
}

#[derive(Debug, Deserialize)]
struct OllamaGenerateResponse {
    response: String,
}

#[async_trait]
impl ExplanationProvider for OllamaExplanationProvider {
    fn name(&self) -> &str {
        "ollama"
    }

    fn model(&self) -> &str {
        &self.model
    }

    async fn explain(&self, input: &ExplanationInput) -> anyhow::Result<ProviderOutput> {
        let payload = ollama_request_payload(&self.model, input)?;
        let uri = ollama_generate_url(&self.base_url);
        let request = Request::post(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&payload)?))
            .context("failed to build Ollama request")?;
        let client: Client<HttpConnector, Body> =
            Client::builder(TokioExecutor::new()).build(HttpConnector::new());
        let response = client
            .request(request)
            .await
            .context("failed to connect to local Ollama")?;
        let status = response.status();
        let body = to_bytes(response.map(Body::new).into_body(), 1024 * 1024)
            .await
            .context("failed to read Ollama response")?;
        if status != StatusCode::OK {
            return Err(anyhow::anyhow!(
                "Ollama returned HTTP {}: {}",
                status,
                String::from_utf8_lossy(&body)
            ));
        }
        parse_ollama_response(&body)
    }
}

#[async_trait]
impl ExplanationProvider for CommandExplanationProvider {
    fn name(&self) -> &str {
        "command"
    }

    fn model(&self) -> &str {
        &self.model
    }

    async fn explain(&self, input: &ExplanationInput) -> anyhow::Result<ProviderOutput> {
        let encoded = serde_json::to_vec(input)?;
        run_provider_command(&self.program, &self.args, &encoded).await
    }
}

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
            failure,
        },
    )?;
    Ok(result)
}

fn build_provider(config: &AiConfig) -> Box<dyn ExplanationProvider> {
    if config.enabled {
        match config.provider.as_str() {
            "ollama" => {
                return Box::new(OllamaExplanationProvider {
                    base_url: config.ollama_url.clone(),
                    model: config.model.clone(),
                });
            }
            "command" => {
                return Box::new(CommandExplanationProvider {
                    program: config.command.clone().unwrap_or_default(),
                    args: config.command_args.clone(),
                    model: config.model.clone(),
                });
            }
            _ => {}
        }
    }
    Box::new(LocalExplanationProvider {
        model: "deterministic-local".to_string(),
    })
}

fn local_output(input: &ExplanationInput) -> ProviderOutput {
    ProviderOutput {
        explanation: input.deterministic_explanation.clone(),
        tuning_suggestions: input.deterministic_tuning_suggestions.clone(),
    }
}

fn sanitized_input(config: &AiConfig, event: &SecurityEvent) -> ExplanationInput {
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

fn tuning_suggestions(event: &SecurityEvent) -> Vec<TuningSuggestion> {
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
        .map(|name| name.chars().take(64).collect::<String>())
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    names.truncate(64);
    names
}

fn sanitized_route_shape(path: &str) -> String {
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

fn ollama_request_payload(
    model: &str,
    input: &ExplanationInput,
) -> anyhow::Result<serde_json::Value> {
    Ok(json!({
        "model": model,
        "system": "You are Saugra WAF's explain-only security analyst. Explain only the supplied deterministic evidence. Never claim to have blocked traffic, never invent request data, and return only JSON matching the supplied schema. Do not restate numeric scores or thresholds; Saugra reports those deterministically. Never infer a false positive from one event. Tuning suggestions must be narrow review actions after confirmed legitimate traffic, must name the supplied rule and route, and must never disable the WAF or a complete rule category.",
        "prompt": format!(
            "Explain this sanitized Saugra security event in at most 80 words. Provide at most one concise tuning review suggestion when justified:\n{}",
            serde_json::to_string(input)?
        ),
        "stream": false,
        "think": false,
        "format": {
            "type": "object",
            "properties": {
                "explanation": {"type": "string", "maxLength": 600},
                "tuning_suggestions": {
                    "type": "array",
                    "maxItems": 1,
                    "items": {
                        "type": "object",
                        "properties": {
                            "kind": {
                                "type": "string",
                                "enum": [
                                    "route_threshold_review",
                                    "scoped_rule_exclusion_review",
                                    "behavior_threshold_review"
                                ]
                            },
                            "config_path": {
                                "type": "string",
                                "enum": [
                                    "unknown_threats.routes",
                                    "rules.exclusions",
                                    "behavior.route_overrides"
                                ]
                            },
                            "rationale": {"type": "string", "maxLength": 240},
                            "proposed_value": {"type": "string", "maxLength": 240}
                        },
                        "required": ["kind", "config_path", "rationale", "proposed_value"]
                    }
                }
            },
            "required": ["explanation", "tuning_suggestions"]
        },
        "options": {
            "temperature": 0,
            "num_predict": 256
        }
    }))
}

fn ollama_generate_url(base_url: &str) -> String {
    let base_url = base_url.trim_end_matches('/');
    if base_url.ends_with("/api") {
        format!("{base_url}/generate")
    } else {
        format!("{base_url}/api/generate")
    }
}

fn parse_ollama_response(body: &[u8]) -> anyhow::Result<ProviderOutput> {
    let response: OllamaGenerateResponse =
        serde_json::from_slice(body).context("Ollama response must be valid JSON")?;
    let output: ProviderOutput = serde_json::from_str(&response.response)
        .context("Ollama generated response must match the explanation JSON schema")?;
    Ok(output)
}

fn validate_provider_explanation(
    explanation: &str,
    input: &ExplanationInput,
) -> anyhow::Result<()> {
    let normalized = explanation.to_ascii_lowercase();
    let links_risk_to_threshold = normalized.contains("threshold")
        && (normalized.contains("risk_score") || normalized.contains("risk score"));
    let calls_equal_score_above = input.anomaly_score == input.anomaly_threshold
        && normalized.contains("anomaly")
        && normalized.contains("threshold")
        && normalized.contains("above");
    if links_risk_to_threshold || calls_equal_score_above {
        anyhow::bail!("Ollama explanation contradicted deterministic score data");
    }
    Ok(())
}

fn suggestion_matches_input(suggestion: &TuningSuggestion, input: &ExplanationInput) -> bool {
    if suggestion.kind != "scoped_rule_exclusion_review" {
        return true;
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

async fn run_provider_command(
    program: &str,
    args: &[String],
    input: &[u8],
) -> anyhow::Result<ProviderOutput> {
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("failed to start AI provider command {program}"))?;
    child
        .stdin
        .take()
        .context("AI provider stdin unavailable")?
        .write_all(input)
        .await?;
    let output = child.wait_with_output().await?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "AI provider exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    serde_json::from_slice(&output.stdout).context("AI provider output must be valid JSON")
}

fn narrow_tuning_suggestions(suggestions: Vec<TuningSuggestion>) -> Vec<TuningSuggestion> {
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

fn append_audit(config: &AiConfig, record: &ExplanationAuditRecord) -> anyhow::Result<()> {
    let path = &config.audit_log_path;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut encoded = serde_json::to_vec(record)?;
    encoded.push(b'\n');
    rotate_audit_if_needed(
        path,
        parse_byte_size(&config.audit_log_max_size).unwrap_or(100 * 1024 * 1024),
        config.audit_log_max_files,
        encoded.len() as u64,
    )?;
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?
        .write_all(&encoded)?;
    Ok(())
}

fn rotate_audit_if_needed(
    path: &Path,
    max_size_bytes: u64,
    max_files: usize,
    incoming_bytes: u64,
) -> anyhow::Result<()> {
    if !path.exists() || fs::metadata(path)?.len().saturating_add(incoming_bytes) <= max_size_bytes
    {
        return Ok(());
    }
    let oldest = rotated_audit_path(path, max_files);
    if oldest.exists() {
        fs::remove_file(oldest)?;
    }
    for index in (1..max_files).rev() {
        let source = rotated_audit_path(path, index);
        if source.exists() {
            fs::rename(source, rotated_audit_path(path, index + 1))?;
        }
    }
    fs::rename(path, rotated_audit_path(path, 1))?;
    Ok(())
}

fn rotated_audit_path(path: &Path, index: usize) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("{}.{}", path.display(), index))
}

fn parse_byte_size(value: &str) -> Option<u64> {
    let value = value.trim().to_ascii_lowercase();
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    let number = value[..split].parse::<u64>().ok()?;
    let multiplier = match value[split..].trim() {
        "b" | "" => 1,
        "kb" | "kib" => 1024,
        "mb" | "mib" => 1024 * 1024,
        "gb" | "gib" => 1024 * 1024 * 1024,
        _ => return None,
    };
    number.checked_mul(multiplier).filter(|value| *value > 0)
}

fn digest(input: &[u8]) -> String {
    format!("sha256:{}", sha256(input))
}

fn sha256(input: &[u8]) -> String {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut message = input.to_vec();
    let bit_len = (message.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());
    let mut state = INITIAL;
    for chunk in message.chunks_exact(64) {
        let mut words = [0_u32; 64];
        for (index, word) in words.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes(chunk[index * 4..index * 4 + 4].try_into().unwrap());
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h].into_iter()) {
            *slot = slot.wrapping_add(value);
        }
    }
    state.iter().map(|word| format!("{word:08x}")).collect()
}

fn sanitize_failure(failure: &str) -> String {
    failure
        .replace('\n', " ")
        .replace('\r', " ")
        .chars()
        .take(512)
        .collect()
}

fn parse_duration(value: &str) -> std::time::Duration {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        behavior::{BehaviorContributor, BehaviorOutcome},
        bot::BotProtectionOutcome,
        campaign::{CampaignMatch, CampaignOutcome},
        config::{RuntimeAllowlistEffect, WafMode},
        decision::{WafAction, WafDecision},
        rules::{RuleMatch, RuleSeverity, RuleTarget},
        runtime_policy::RuntimeAllowlistMatch,
    };
    use std::fs;

    #[test]
    fn explanation_includes_owasp_category_context() {
        let decision = WafDecision::from_matches(
            "request-1".to_string(),
            WafMode::Block,
            vec![RuleMatch {
                rule_id: "SAUGRA-SQLI-001".to_string(),
                rule_name: "Basic SQL Injection Pattern".to_string(),
                category: "sql_injection".to_string(),
                severity: RuleSeverity::High,
                matched_target: RuleTarget::Query,
                paranoia_level: 1,
                explanation: "SQLi matched.".to_string(),
                owasp_category: Some("A05:2025-Injection".to_string()),
            }],
            5,
        );

        let explanation = explain(&decision);

        assert!(explanation.contains("A05:2025-Injection"));
        assert!(explanation.contains("Anomaly score is 5/5"));
    }

    #[test]
    fn explanation_for_clean_request_reports_allow_decision() {
        let decision =
            WafDecision::from_matches("request-1".to_string(), WafMode::Block, Vec::new(), 5);

        let explanation = explain(&decision);

        assert_eq!(
            explanation,
            "No rules matched this request, so Saugra allowed it."
        );
    }

    #[test]
    fn explanation_for_clean_request_includes_runtime_allowlist_context() {
        let decision =
            WafDecision::from_matches("request-1".to_string(), WafMode::Block, Vec::new(), 5)
                .with_runtime_allowlist(runtime_allowlist_match(RuntimeAllowlistEffect::AllowAll));

        let explanation = explain(&decision);

        assert!(explanation.contains("No rules matched this request"));
        assert!(explanation.contains("Runtime allowlist entry test-ip matched 203.0.113.10"));
        assert!(explanation.contains("AllowAll"));
    }

    #[test]
    fn explanation_for_bot_only_decision_reports_thresholds_and_contributors() {
        let decision =
            WafDecision::from_matches("request-1".to_string(), WafMode::Block, Vec::new(), 5)
                .with_bot_protection(bot_outcome());

        let explanation = explain(&decision);

        assert!(explanation.contains("No request rules matched."));
        assert!(
            explanation.contains("Bot protection score is 80/40 for monitor and 80/80 for block")
        );
        assert!(explanation.contains("with 2 contributor(s)"));
        assert!(explanation.contains("Contributor paths: /.env, /protected-area/sign-in/"));
    }

    #[test]
    fn explanation_for_behavior_only_decision_reports_thresholds() {
        let decision =
            WafDecision::from_matches("request-1".to_string(), WafMode::Block, Vec::new(), 5)
                .with_behavior(behavior_outcome());

        let explanation = explain(&decision);

        assert!(explanation.contains("No request rules matched."));
        assert!(explanation.contains("Behavior score is 93/40 for monitor and 93/80 for block."));
    }

    #[test]
    fn explanation_for_unmapped_rule_says_no_specific_owasp_category() {
        let decision = WafDecision::from_matches(
            "request-1".to_string(),
            WafMode::Monitor,
            vec![RuleMatch {
                owasp_category: None,
                ..rule_match()
            }],
            5,
        );

        let explanation = explain(&decision);

        assert!(explanation.contains("It is not mapped to a specific OWASP category."));
        assert!(explanation.contains("SAUGRA-TEST-001"));
    }

    #[test]
    fn explanation_for_matched_rule_includes_behavior_bot_and_allowlist_context() {
        let decision = WafDecision::from_matches(
            "request-1".to_string(),
            WafMode::Block,
            vec![rule_match()],
            5,
        )
        .with_behavior(behavior_outcome())
        .with_bot_protection(bot_outcome())
        .with_runtime_allowlist(runtime_allowlist_match(
            RuntimeAllowlistEffect::SkipBotAndBehaviorBlock,
        ));

        let explanation = explain(&decision);

        assert!(explanation.contains("headers matched rule SAUGRA-TEST-001"));
        assert!(explanation.contains(
            "Behavior score is 93/40 for monitor and 93/80 for block with 2 contributor(s)."
        ));
        assert!(explanation.contains(
            "Bot protection score is 80/40 for monitor and 80/80 for block with 2 contributor(s)."
        ));
        assert!(explanation.contains("Runtime allowlist entry test-ip matched 203.0.113.10"));
        assert!(explanation.contains("SkipBotAndBehaviorBlock"));
    }

    #[test]
    fn explanation_includes_campaign_id_and_evidence_counts() {
        let decision = WafDecision::from_matches(
            "request-1".to_string(),
            WafMode::Monitor,
            vec![rule_match()],
            5,
        )
        .with_campaign(CampaignOutcome {
            enabled: true,
            action: WafAction::Monitor,
            storage_backend: "redis".to_string(),
            window_seconds: 900,
            campaign_ids: vec!["cmp-test".to_string()],
            matches: vec![CampaignMatch {
                campaign_id: "cmp-test".to_string(),
                kind: "distributed_scanning".to_string(),
                score: 60,
                event_count: 8,
                client_count: 4,
                session_count: 4,
                route_count: 6,
                stages: Vec::new(),
                first_seen_at: 1,
                last_seen_at: 2,
            }],
        });

        let explanation = explain(&decision);

        assert!(explanation.contains("cmp-test"));
        assert!(explanation.contains("distributed_scanning"));
        assert!(explanation.contains("8 events, 4 clients, 4 sessions, 6 routes"));
    }

    #[test]
    fn sanitized_input_keeps_query_names_and_removes_values() {
        let event = SecurityEvent::new(
            "GET",
            "/reset/supersecrettoken",
            "token=secret-value&page=2",
            WafDecision::from_matches(
                "request-1".to_string(),
                WafMode::Monitor,
                vec![rule_match()],
                5,
            ),
        );

        let input = sanitized_input(&AiConfig::default(), &event);
        let encoded = serde_json::to_string(&input).unwrap();

        assert_eq!(input.route_shape, "/reset/:id");
        assert_eq!(input.query_parameters, vec!["page", "token"]);
        assert!(!encoded.contains("secret-value"));
        assert!(!encoded.contains("page=2"));
        assert!(!encoded.contains("deterministic_explanation"));
        assert!(!encoded.contains("Test rule matched"));
    }

    #[tokio::test]
    async fn provider_failure_is_audited_and_uses_local_fallback() {
        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("ai-audit.jsonl");
        let config = AiConfig {
            provider: "command".to_string(),
            command: Some("/does/not/exist/saugra-ai-adapter".to_string()),
            model: "test-model".to_string(),
            audit_log_path: audit_path.clone(),
            ..AiConfig::default()
        };
        let event = SecurityEvent::new(
            "GET",
            "/search",
            "q=secret",
            WafDecision::from_matches(
                "request-fallback".to_string(),
                WafMode::Monitor,
                vec![rule_match()],
                5,
            ),
        );

        let result = explain_event(&config, &event).await.unwrap();
        let audit: ExplanationAuditRecord =
            serde_json::from_str(fs::read_to_string(audit_path).unwrap().trim()).unwrap();

        assert!(result.fallback_used);
        assert!(result.explanation.contains("SAUGRA-TEST-001"));
        assert!(!audit.success);
        assert!(audit.fallback_used);
        assert!(audit
            .failure
            .unwrap()
            .contains("failed to start AI provider"));
        assert!(!fs::read_to_string(temp_dir.path().join("ai-audit.jsonl"))
            .unwrap()
            .contains("secret"));
    }

    #[tokio::test]
    async fn command_provider_returns_structured_explanation_and_suggestion() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = AiConfig {
            provider: "command".to_string(),
            command: Some("sh".to_string()),
            command_args: vec![
                "-c".to_string(),
                "cat >/dev/null; printf '%s' '{\"explanation\":\"Provider explanation.\",\"tuning_suggestions\":[{\"kind\":\"route_threshold_review\",\"config_path\":\"unknown_threats.routes\",\"rationale\":\"Reviewed evidence.\",\"proposed_value\":\"monitor_threshold: 25\"}]}'".to_string(),
            ],
            model: "adapter-model".to_string(),
            audit_log_path: temp_dir.path().join("ai-audit.jsonl"),
            ..AiConfig::default()
        };
        let event = SecurityEvent::new(
            "GET",
            "/search",
            "",
            WafDecision::from_matches(
                "request-provider".to_string(),
                WafMode::Monitor,
                vec![rule_match()],
                5,
            ),
        );

        let result = explain_event(&config, &event).await.unwrap();

        assert_eq!(result.explanation, "Provider explanation.");
        assert_eq!(result.tuning_suggestions.len(), 1);
        assert!(!result.fallback_used);
        assert_eq!(result.provider, "command");
        assert!(result.input_digest.starts_with("sha256:"));
    }

    #[test]
    fn provider_suggestions_are_restricted_to_reviewable_config_paths() {
        let suggestions = narrow_tuning_suggestions(vec![
            TuningSuggestion {
                kind: "disable_waf".to_string(),
                config_path: "server.mode".to_string(),
                rationale: "unsafe".to_string(),
                proposed_value: "off".to_string(),
            },
            TuningSuggestion {
                kind: "scoped_rule_exclusion_review".to_string(),
                config_path: "rules.exclusions".to_string(),
                rationale: "reviewed false positive".to_string(),
                proposed_value: "rule_ids: [SAUGRA-TEST-001]".to_string(),
            },
        ]);

        assert_eq!(suggestions.len(), 1);
        assert_eq!(suggestions[0].config_path, "rules.exclusions");
    }

    #[test]
    fn sha256_matches_standard_test_vector() {
        assert_eq!(
            sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn ollama_payload_requests_non_streaming_structured_output() {
        let event = SecurityEvent::new(
            "GET",
            "/search",
            "q=secret",
            WafDecision::from_matches(
                "request-ollama".to_string(),
                WafMode::Monitor,
                vec![rule_match()],
                5,
            ),
        );
        let input = sanitized_input(&AiConfig::default(), &event);
        let payload = ollama_request_payload("qwen3:4b", &input).unwrap();

        assert_eq!(payload["model"], "qwen3:4b");
        assert_eq!(payload["stream"], false);
        assert_eq!(payload["think"], false);
        assert_eq!(payload["options"]["temperature"], 0);
        assert_eq!(payload["options"]["num_predict"], 256);
        assert_eq!(payload["format"]["type"], "object");
        assert_eq!(
            payload["format"]["properties"]["tuning_suggestions"]["maxItems"],
            1
        );
        assert!(payload["system"]
            .as_str()
            .unwrap()
            .contains("Do not restate numeric scores or thresholds"));
        assert!(!payload["prompt"].as_str().unwrap().contains("secret"));
    }

    #[test]
    fn rejects_provider_explanations_that_reinterpret_scores() {
        let event = SecurityEvent::new(
            "GET",
            "/search",
            "",
            WafDecision::from_matches(
                "request-score-grounding".to_string(),
                WafMode::Monitor,
                vec![rule_match()],
                5,
            ),
        );
        let input = sanitized_input(&AiConfig::default(), &event);
        let error = validate_provider_explanation(
            "The anomaly score is above the configured threshold.",
            &input,
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("contradicted deterministic score data"));
        assert!(validate_provider_explanation(
            "The anomaly score matches the configured threshold.",
            &input
        )
        .is_ok());
    }

    #[test]
    fn scoped_exclusion_suggestion_must_name_rule_and_route() {
        let event = SecurityEvent::new(
            "GET",
            "/search",
            "q=secret",
            WafDecision::from_matches(
                "request-grounding".to_string(),
                WafMode::Monitor,
                vec![rule_match()],
                5,
            ),
        );
        let input = sanitized_input(&AiConfig::default(), &event);
        let incomplete = TuningSuggestion {
            kind: "scoped_rule_exclusion_review".to_string(),
            config_path: "rules.exclusions".to_string(),
            rationale: "Review legitimate traffic on /search.".to_string(),
            proposed_value: "path_prefixes: [/search]".to_string(),
        };
        let grounded = TuningSuggestion {
            proposed_value: "rule_ids: [SAUGRA-TEST-001]\npath_prefixes: [/search]".to_string(),
            ..incomplete.clone()
        };

        assert!(!suggestion_matches_input(&incomplete, &input));
        assert!(suggestion_matches_input(&grounded, &input));
    }

    #[tokio::test]
    async fn disabled_ai_uses_deterministic_local_provider() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = AiConfig {
            enabled: false,
            provider: "ollama".to_string(),
            audit_log_path: temp_dir.path().join("ai-audit.jsonl"),
            ..AiConfig::default()
        };
        let event = SecurityEvent::new(
            "GET",
            "/health",
            "",
            WafDecision::from_matches(
                "request-ai-disabled".to_string(),
                WafMode::Monitor,
                Vec::new(),
                5,
            ),
        );

        let result = explain_event(&config, &event).await.unwrap();

        assert_eq!(result.provider, "local");
        assert_eq!(result.model, "deterministic-local");
        assert!(!result.fallback_used);
        assert_eq!(
            result.explanation,
            "No rules matched this request, so Saugra allowed it."
        );
    }

    #[test]
    fn parses_ollama_structured_generate_response() {
        let body = br#"{
          "model": "qwen3:4b",
          "response": "{\"explanation\":\"Local Ollama explanation.\",\"tuning_suggestions\":[]}",
          "done": true
        }"#;

        let output = parse_ollama_response(body).unwrap();

        assert_eq!(output.explanation, "Local Ollama explanation.");
        assert!(output.tuning_suggestions.is_empty());
    }

    #[test]
    fn builds_ollama_generate_url_from_host_or_api_base() {
        assert_eq!(
            ollama_generate_url("http://127.0.0.1:11434"),
            "http://127.0.0.1:11434/api/generate"
        );
        assert_eq!(
            ollama_generate_url("http://127.0.0.1:11434/api/"),
            "http://127.0.0.1:11434/api/generate"
        );
    }

    #[test]
    fn bundled_ollama_evaluation_cases_are_valid_jsonl() {
        let cases = include_str!("../configs/ollama/evaluation-cases.jsonl");
        let mut count = 0;

        for line in cases.lines().filter(|line| !line.trim().is_empty()) {
            let case: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(case["id"].is_string());
            assert!(case["input"].is_object());
            assert!(case["expected"]["must_include"].is_array());
            assert!(case["expected"]["must_not_include"].is_array());
            assert!(case["expected"]["allowed_suggestion_kinds"].is_array());
            assert!(case["expected"]["maximum_suggestions"].is_number());
            count += 1;
        }

        assert!(count >= 4);
    }

    #[test]
    fn bundled_ollama_modelfile_keeps_explain_only_policy() {
        let modelfile = include_str!("../configs/ollama/Modelfile");

        assert!(modelfile.contains("FROM qwen3:4b"));
        assert!(modelfile.contains("PARAMETER temperature 0"));
        assert!(modelfile.contains("Never claim that AI blocked"));
        assert!(modelfile.contains("Never request or reveal"));
    }

    #[tokio::test]
    async fn audit_log_rotates_at_configured_size() {
        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("ai-audit.jsonl");
        let config = AiConfig {
            provider: "local".to_string(),
            audit_log_path: audit_path.clone(),
            audit_log_max_size: "1b".to_string(),
            audit_log_max_files: 2,
            ..AiConfig::default()
        };
        let event = SecurityEvent::new(
            "GET",
            "/",
            "",
            WafDecision::from_matches(
                "request-rotation".to_string(),
                WafMode::Monitor,
                Vec::new(),
                5,
            ),
        );

        explain_event(&config, &event).await.unwrap();
        explain_event(&config, &event).await.unwrap();

        assert!(audit_path.exists());
        assert!(rotated_audit_path(&audit_path, 1).exists());
    }

    fn rule_match() -> RuleMatch {
        RuleMatch {
            rule_id: "SAUGRA-TEST-001".to_string(),
            rule_name: "Test Rule".to_string(),
            category: "test".to_string(),
            severity: RuleSeverity::High,
            matched_target: RuleTarget::Headers,
            paranoia_level: 1,
            explanation: "Test rule matched.".to_string(),
            owasp_category: Some("A06:2025-Insecure Design".to_string()),
        }
    }

    fn behavior_outcome() -> BehaviorOutcome {
        BehaviorOutcome {
            enabled: true,
            action: WafAction::Monitor,
            score: 93,
            monitor_threshold: 40,
            block_threshold: 80,
            score_window_seconds: 600,
            decay_window_seconds: 1_800,
            storage_backend: "local".to_string(),
            contributors: contributors(),
        }
    }

    fn bot_outcome() -> BotProtectionOutcome {
        BotProtectionOutcome {
            enabled: true,
            action: WafAction::Block,
            score: 80,
            monitor_threshold: 40,
            block_threshold: 80,
            score_window_seconds: 600,
            temporary_block_duration_seconds: 900,
            temporary_blocked_until: None,
            storage_backend: "local".to_string(),
            allowlisted: false,
            blocklisted: false,
            contributors: contributors(),
        }
    }

    fn contributors() -> Vec<BehaviorContributor> {
        vec![
            BehaviorContributor {
                reason: "scanner_path".to_string(),
                score_delta: 40,
                path: "/.env".to_string(),
            },
            BehaviorContributor {
                reason: "rule_match:bot_protection".to_string(),
                score_delta: 40,
                path: "/protected-area/sign-in/".to_string(),
            },
        ]
    }

    fn runtime_allowlist_match(effect: RuntimeAllowlistEffect) -> RuntimeAllowlistMatch {
        RuntimeAllowlistMatch {
            id: "test-ip".to_string(),
            match_type: "ip".to_string(),
            value: "203.0.113.10".to_string(),
            effect,
            reason: "admin access".to_string(),
            expires_at_unix_seconds: None,
        }
    }
}
