use crate::decision::WafAction;
use serde::{Deserialize, Serialize};

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
    pub api_key_env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_policy: Option<String>,
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

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EvaluationReport {
    pub version: u8,
    pub provider: String,
    pub model: String,
    pub prompt_version: String,
    pub total_cases: usize,
    pub passed_cases: usize,
    pub failed_cases: usize,
    pub maximum_latency_ms: u64,
    pub cases: Vec<EvaluationCaseReport>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EvaluationCaseReport {
    pub id: String,
    pub passed: bool,
    pub latency_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
    pub suggestion_kinds: Vec<String>,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AnomalyShadowReport {
    pub version: u8,
    pub authority: String,
    pub enforcement_changes: usize,
    pub reviewed_events: usize,
    pub candidates: Vec<AnomalyShadowCandidate>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AnomalyShadowCandidate {
    pub request_id: String,
    pub route_shape: String,
    pub deterministic_action: WafAction,
    pub deterministic_signals: Vec<String>,
    pub provider: String,
    pub model: String,
    pub explanation: String,
    pub fallback_used: bool,
}
