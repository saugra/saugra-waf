use super::super::*;
use crate::{
    behavior::{BehaviorContributor, BehaviorOutcome},
    bot::BotProtectionOutcome,
    campaign::{CampaignMatch, CampaignOutcome},
    config::{AiConfig, RuntimeAllowlistEffect, WafMode},
    decision::{WafAction, WafDecision},
    event_store::SecurityEvent,
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
    assert!(explanation.contains("Bot protection score is 80/40 for monitor and 80/80 for block"));
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
fn rejects_provider_score_narration_and_accepts_grounded_evidence() {
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
        .contains("restated deterministic score data"));
    assert!(
        validate_provider_explanation("Monitor action matched rule SAUGRA-TEST-001.", &input)
            .is_ok()
    );
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
