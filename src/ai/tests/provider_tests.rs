use super::super::*;
use crate::{
    config::{AiConfig, WafMode},
    decision::WafDecision,
    event_store::SecurityEvent,
    rules::{RuleMatch, RuleSeverity, RuleTarget},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[tokio::test]
async fn command_provider_returns_structured_explanation_and_suggestion() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config = AiConfig {
        provider: "command".to_string(),
        command: Some("sh".to_string()),
        command_args: vec![
            "-c".to_string(),
            "cat >/dev/null; printf '%s' '{\"explanation\":\"Monitor action matched rule SAUGRA-TEST-001.\",\"tuning_suggestions\":[{\"kind\":\"scoped_rule_exclusion_review\",\"config_path\":\"rules.exclusions\",\"rationale\":\"Review SAUGRA-TEST-001 on /search after confirming legitimate traffic.\",\"proposed_value\":\"rule_ids: [SAUGRA-TEST-001], path_prefixes: [/search]\"}]}'".to_string(),
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

    assert_eq!(
        result.explanation,
        "Monitor action matched rule SAUGRA-TEST-001."
    );
    assert_eq!(result.tuning_suggestions.len(), 1);
    assert!(!result.fallback_used);
    assert_eq!(result.provider, "command");
    assert!(result.input_digest.starts_with("sha256:"));
}

#[tokio::test]
async fn local_http_providers_send_requests_and_parse_responses() {
    let input = provider_input();
    let llama_url = mock_http_response(
        200,
        r#"{"choices":[{"message":{"content":"{\"explanation\":\"Monitor action matched rule SAUGRA-TEST-001.\",\"tuning_suggestions\":[]}"}}]}"#,
    )
    .await;
    let llama = LlamaCppExplanationProvider {
        base_url: llama_url,
        model: "test-llama".to_string(),
    };

    assert_eq!(llama.name(), "llama_cpp");
    assert_eq!(llama.model(), "test-llama");
    assert!(llama
        .explain(&input)
        .await
        .unwrap()
        .explanation
        .contains("SAUGRA-TEST-001"));

    let ollama_url = mock_http_response(
        200,
        r#"{"response":"{\"explanation\":\"Monitor action matched rule SAUGRA-TEST-001.\",\"tuning_suggestions\":[]}"}"#,
    )
    .await;
    let ollama = OllamaExplanationProvider {
        base_url: ollama_url,
        model: "test-ollama".to_string(),
    };

    assert_eq!(ollama.name(), "ollama");
    assert_eq!(ollama.model(), "test-ollama");
    assert!(ollama
        .explain(&input)
        .await
        .unwrap()
        .explanation
        .contains("SAUGRA-TEST-001"));
}

#[tokio::test]
async fn remote_http_providers_send_credentials_and_parse_responses() {
    const OPENAI_KEY: &str = "SAUGRA_TEST_OPENAI_KEY";
    const GEMINI_KEY: &str = "SAUGRA_TEST_GEMINI_KEY";
    std::env::set_var(OPENAI_KEY, "openai-secret");
    std::env::set_var(GEMINI_KEY, "gemini-secret");
    let input = provider_input();

    let openai = OpenAiCompatibleExplanationProvider {
        endpoint: mock_http_response(
            200,
            r#"{"choices":[{"message":{"content":"{\"explanation\":\"Monitor action matched rule SAUGRA-TEST-001.\",\"tuning_suggestions\":[]}"}}]}"#,
        )
        .await,
        api_key_env: OPENAI_KEY.to_string(),
        model: "test-openai".to_string(),
    };
    assert_eq!(openai.name(), "openai_compatible");
    assert_eq!(openai.model(), "test-openai");
    assert!(openai
        .explain(&input)
        .await
        .unwrap()
        .explanation
        .contains("SAUGRA-TEST-001"));

    let gemini_base = mock_http_response(
        200,
        r#"{"candidates":[{"content":{"parts":[{"text":"{\"explanation\":\"Monitor action matched rule SAUGRA-TEST-001.\",\"tuning_suggestions\":[]}" }]}}]}"#,
    )
    .await;
    let gemini = GeminiExplanationProvider {
        endpoint: format!("{gemini_base}/models/{{model}}"),
        api_key_env: GEMINI_KEY.to_string(),
        model: "test-gemini".to_string(),
    };
    assert_eq!(gemini.name(), "gemini");
    assert_eq!(gemini.model(), "test-gemini");
    assert!(gemini
        .explain(&input)
        .await
        .unwrap()
        .explanation
        .contains("SAUGRA-TEST-001"));

    std::env::remove_var(OPENAI_KEY);
    std::env::remove_var(GEMINI_KEY);
}

#[tokio::test]
async fn http_provider_errors_are_reported_and_fall_back() {
    let input = provider_input();
    let llama = LlamaCppExplanationProvider {
        base_url: mock_http_response(503, "llama unavailable").await,
        model: "test-llama".to_string(),
    };
    assert!(llama
        .explain(&input)
        .await
        .unwrap_err()
        .to_string()
        .contains("HTTP 503"));

    let ollama = OllamaExplanationProvider {
        base_url: mock_http_response(500, "ollama unavailable").await,
        model: "test-ollama".to_string(),
    };
    assert!(ollama
        .explain(&input)
        .await
        .unwrap_err()
        .to_string()
        .contains("HTTP 500"));

    let temp_dir = tempfile::tempdir().unwrap();
    let config = AiConfig {
        provider: "command".to_string(),
        command: Some("sh".to_string()),
        command_args: vec![
            "-c".to_string(),
            "cat >/dev/null; printf '%s' '{\"explanation\":\"invented text\",\"tuning_suggestions\":[]}'"
                .to_string(),
        ],
        audit_log_path: temp_dir.path().join("ai-audit.jsonl"),
        ..AiConfig::default()
    };
    let result = explain_event(&config, &provider_event()).await.unwrap();
    assert!(result.fallback_used);
    assert!(result.explanation.contains("SAUGRA-TEST-001"));
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

fn provider_input() -> ExplanationInput {
    sanitized_input(&AiConfig::default(), &provider_event())
}

async fn mock_http_response(status: u16, body: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let body = body.to_string();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = vec![0; 64 * 1024];
        let _ = socket.read(&mut request).await.unwrap();
        let reason = if status == 200 { "OK" } else { "Error" };
        let response = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        socket.write_all(response.as_bytes()).await.unwrap();
    });
    format!("http://{address}")
}
