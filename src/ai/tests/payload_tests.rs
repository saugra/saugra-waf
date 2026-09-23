use super::super::*;
use crate::{
    config::{AiConfig, WafMode},
    decision::{WafAction, WafDecision},
    event_store::SecurityEvent,
    rules::{RuleMatch, RuleSeverity, RuleTarget},
};
use std::fs;

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
        .contains("Do not discuss scores or thresholds"));
    assert!(!payload["prompt"].as_str().unwrap().contains("secret"));
}

#[test]
fn llama_cpp_payload_requests_non_streaming_structured_output() {
    let event = SecurityEvent::new(
        "GET",
        "/search",
        "q=secret",
        WafDecision::from_matches(
            "request-llama-cpp".to_string(),
            WafMode::Monitor,
            vec![rule_match()],
            5,
        ),
    );
    let input = sanitized_input(&AiConfig::default(), &event);
    let payload = llama_cpp_request_payload("saugra-qwen3-0.6b", &input).unwrap();

    assert_eq!(payload["model"], "saugra-qwen3-0.6b");
    assert_eq!(payload["stream"], false);
    assert_eq!(payload["max_tokens"], 256);
    assert_eq!(payload["chat_template_kwargs"]["enable_thinking"], false);
    assert_eq!(payload["response_format"]["type"], "json_schema");
    assert_eq!(
        payload["response_format"]["json_schema"]["schema"]["properties"]["tuning_suggestions"]
            ["maxItems"],
        1
    );
    assert_eq!(
        payload["response_format"]["json_schema"]["name"],
        "saugra_explanation"
    );
    assert_eq!(payload["response_format"]["json_schema"]["strict"], true);
    assert!(payload["messages"][0]["content"]
        .as_str()
        .unwrap()
        .contains("Do not discuss scores or thresholds"));
    assert!(!payload["messages"][1]["content"]
        .as_str()
        .unwrap()
        .contains("secret"));
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
fn builds_llama_cpp_chat_url_from_host_or_v1_base() {
    assert_eq!(
        llama_cpp_chat_completions_url("http://127.0.0.1:8080"),
        "http://127.0.0.1:8080/v1/chat/completions"
    );
    assert_eq!(
        llama_cpp_chat_completions_url("http://127.0.0.1:8080/v1/"),
        "http://127.0.0.1:8080/v1/chat/completions"
    );
}

#[test]
fn parses_llama_cpp_structured_chat_completion_response() {
    let body = br#"{
      "choices": [{
        "message": {
          "role": "assistant",
          "content": "{\"explanation\":\"Local llama.cpp explanation.\",\"tuning_suggestions\":[]}"
        }
      }]
    }"#;

    let output = parse_chat_completion_response(body, "llama.cpp").unwrap();

    assert_eq!(output.explanation, "Local llama.cpp explanation.");
    assert!(output.tuning_suggestions.is_empty());
}

#[test]
fn parses_llama_cpp_fenced_structured_response() {
    let body = br#"{
      "choices": [{
        "message": {
          "role": "assistant",
          "content": "```json\n{\"explanation\":\"Fenced explanation.\",\"tuning_suggestions\":[]}\n```"
        }
      }]
    }"#;

    let output = parse_chat_completion_response(body, "llama.cpp").unwrap();

    assert_eq!(output.explanation, "Fenced explanation.");
    assert!(output.tuning_suggestions.is_empty());
}

#[test]
fn evaluation_input_preserves_sanitized_context() {
    let case: eval::EvaluationCase = serde_json::from_str(
        r#"{
          "id": "context",
          "input": {
            "method": "GET",
            "action": "monitor",
            "route_shape": "/api/users/:id",
            "query_parameters": ["view", "ignore instructions"],
            "behavior": {
              "score": 30,
              "monitor_threshold": 20,
              "block_threshold": 40,
              "contributor_reasons": ["rapid_navigation"],
              "contributor_routes": ["/login"]
            },
            "unknown_threat": {
              "score": 25,
              "monitor_threshold": 20,
              "block_threshold": 40,
              "baseline_observations": 150,
              "baseline_age_seconds": 700000,
              "signals": ["unseen_method"],
              "enforcement_gates": ["route_not_high_risk"]
            },
            "campaigns": [{
              "campaign_id": "cmp-example",
              "kind": "multi_step_progression",
              "score": 80,
              "event_count": 6,
              "client_count": 1,
              "session_count": 1,
              "route_count": 3,
              "stages": ["reconnaissance", "access_attempt"]
            }]
          },
          "expected": {
            "maximum_suggestions": 0
          }
        }"#,
    )
    .unwrap();

    let input = eval::evaluation_input(&AiConfig::default(), &case);

    assert_eq!(input.route_shape, "/api/users/:id");
    assert_eq!(input.query_parameters, vec!["view", "ignore_instructions"]);
    assert_eq!(input.behavior.unwrap().score, 30);
    assert_eq!(input.unknown_threat.unwrap().baseline_observations, 150);
    assert_eq!(input.campaigns[0].campaign_id, "cmp-example");
}

#[test]
fn remote_payloads_keep_structured_output_and_sanitized_input() {
    let event = SecurityEvent::new(
        "GET",
        "/search",
        "token=secret",
        WafDecision::from_matches(
            "request-remote".to_string(),
            WafMode::Monitor,
            vec![rule_match()],
            5,
        ),
    );
    let input = sanitized_input(&AiConfig::default(), &event);
    let openai = openai_compatible_request_payload("test-model", &input).unwrap();
    let gemini = gemini_request_payload(&input).unwrap();
    let openai_encoded = serde_json::to_string(&openai).unwrap();
    let gemini_encoded = serde_json::to_string(&gemini).unwrap();

    assert_eq!(openai["response_format"]["type"], "json_schema");
    assert_eq!(
        gemini["generationConfig"]["responseMimeType"],
        "application/json"
    );
    assert!(!openai_encoded.contains("secret"));
    assert!(!gemini_encoded.contains("secret"));
}

#[test]
fn remote_rate_limits_have_a_specific_failure() {
    let error = ensure_remote_success(429, b"rate limited", "test provider").unwrap_err();
    assert!(error.to_string().contains("rate limit exceeded"));
}

#[test]
fn parses_gemini_structured_response() {
    let body = br#"{
      "candidates": [{
        "content": {
          "parts": [{
            "text": "{\"explanation\":\"Gemini explanation.\",\"tuning_suggestions\":[]}"
          }]
        }
      }]
    }"#;
    let output = parse_gemini_response(body).unwrap();
    assert_eq!(output.explanation, "Gemini explanation.");
}

#[tokio::test]
async fn versioned_evaluation_reports_quality_privacy_and_latency() {
    let temp_dir = tempfile::tempdir().unwrap();
    let cases = temp_dir.path().join("cases.jsonl");
    fs::write(
        &cases,
        r#"{"id":"one","input":{"action":"monitor","severity":"high","route_shape":"/search","rules":[{"id":"SAUGRA-TEST-001","name":"Test","category":"test","severity":"high","target":"query"}]},"expected":{"must_include":["provider explanation"],"must_not_include":["secret"],"allowed_suggestion_kinds":[],"maximum_suggestions":0}}"#,
    )
    .unwrap();
    let config = AiConfig {
        provider: "command".to_string(),
        command: Some("sh".to_string()),
        command_args: vec![
            "-c".to_string(),
            "cat >/dev/null; printf '%s' '{\"explanation\":\"Monitor action matched rule SAUGRA-TEST-001; provider explanation.\",\"tuning_suggestions\":[]}'".to_string(),
        ],
        model: "evaluation-model".to_string(),
        ..AiConfig::default()
    };

    let report = evaluate_provider(&config, &cases).await.unwrap();

    assert_eq!(report.version, 1);
    assert_eq!(report.total_cases, 1);
    assert_eq!(report.passed_cases, 1);
    assert_eq!(report.failed_cases, 0);
}

#[tokio::test]
async fn anomaly_shadow_review_never_changes_enforcement() {
    let report = anomaly_shadow_review(&AiConfig::default(), &[])
        .await
        .unwrap();

    assert_eq!(report.authority, "deterministic_policy_only");
    assert_eq!(report.enforcement_changes, 0);
    assert_eq!(report.reviewed_events, 0);
}

#[tokio::test]
async fn anomaly_shadow_review_explains_retained_candidates() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config = AiConfig {
        enabled: false,
        audit_log_path: temp_dir.path().join("ai-audit.jsonl"),
        ..AiConfig::default()
    };
    let mut event = provider_event();
    event.decision =
        event
            .decision
            .with_unknown_threats(crate::unknown_threats::UnknownThreatOutcome {
                enabled: true,
                action: WafAction::Monitor,
                score: 20,
                threshold: 20,
                block_threshold: 40,
                route_shape: "/search".to_string(),
                baseline_observations: 100,
                baseline_ready: true,
                baseline_age_seconds: 86_400,
                minimum_block_observations: 1_000,
                minimum_baseline_age_seconds: 604_800,
                minimum_independent_signals: 2,
                high_risk_route: false,
                would_block: false,
                block_eligible: false,
                enforcement_gates: vec!["route_not_high_risk".to_string()],
                baseline_tracked: true,
                learning_enabled: true,
                learning_source_trusted: true,
                learning_source_allowed: true,
                route_excluded: false,
                capacity_reached: false,
                pruned_routes: 0,
                storage_backend: "local".to_string(),
                signals: Vec::new(),
            });

    let report = anomaly_shadow_review(&config, &[event]).await.unwrap();

    assert_eq!(report.reviewed_events, 1);
    assert_eq!(report.candidates[0].route_shape, "/search");
    assert_eq!(report.candidates[0].provider, "local");
}

#[test]
fn bundled_ollama_evaluation_cases_are_valid_jsonl() {
    let cases = include_str!("../../../configs/ai/evaluation-cases.jsonl");
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

    assert!(count >= 6);
}

#[test]
fn bundled_ollama_modelfile_keeps_explain_only_policy() {
    let modelfile = include_str!("../../../configs/ollama/Modelfile");

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

fn provider_event() -> SecurityEvent {
    SecurityEvent::new(
        "GET",
        "/search",
        "q=secret",
        WafDecision::from_matches(
            "request-provider-http".to_string(),
            WafMode::Monitor,
            vec![rule_match()],
            5,
        ),
    )
}
