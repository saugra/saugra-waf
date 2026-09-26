use super::*;
use std::path::{Path, PathBuf};

use crate::{
    behavior::BehaviorOutcome,
    bot::BotProtectionOutcome,
    decision::{WafAction, WafDecision},
    event_store::SecurityEvent,
    rules::{RuleMatch, RuleSeverity, RuleTarget},
};
use date::rfc3339_to_unix_seconds;

mod html_tests;

#[test]
fn daily_summary_filters_to_lookback_and_aggregates_top_values() {
    let now = rfc3339_to_unix_seconds("2026-05-22T08:00:00Z").unwrap();
    let events = vec![
        event(
            "2026-05-22T07:00:00Z",
            "1",
            "203.0.113.10",
            "/login",
            WafAction::Block,
            "SAUGRA-SQLI-001",
            "sql_injection",
        ),
        event(
            "2026-05-22T06:00:00Z",
            "2",
            "203.0.113.10",
            "/login",
            WafAction::Monitor,
            "SAUGRA-RATE-001",
            "rate_limit",
        ),
        event(
            "2026-05-20T06:00:00Z",
            "old",
            "203.0.113.11",
            "/old",
            WafAction::Block,
            "OLD",
            "sql_injection",
        ),
    ];

    let summary = generate(&events, 24 * 60 * 60, now, "UTC");

    assert_eq!(summary.total_security_events, 2);
    assert_eq!(summary.blocked_events, 1);
    assert_eq!(summary.monitored_events, 1);
    assert_eq!(summary.rate_limit_events, 1);
    assert_eq!(summary.top_source_ips[0].name, "203.0.113.10");
    assert_eq!(summary.top_source_ips[0].count, 2);
    assert_eq!(summary.top_targeted_paths[0].name, "/login");
    assert_eq!(summary.important_blocked_request_ids, vec!["1"]);
}

#[test]
fn empty_day_summary_has_zero_counts() {
    let summary = generate(&[], 24 * 60 * 60, 1_779_439_200, "Africa/Nairobi");

    assert_eq!(summary.total_security_events, 0);
    assert!(summary.top_attack_categories.is_empty());
    assert!(summary.important_blocked_request_ids.is_empty());
    assert_eq!(summary.timezone, "Africa/Nairobi");
}

#[test]
fn output_path_replaces_local_date_token() {
    let path = render_output_path(
        Path::new("/tmp/saugra-waf-security-summary-YYYY-MM-DD.json"),
        rfc3339_to_unix_seconds("2026-05-21T22:30:00Z").unwrap(),
        "Africa/Nairobi",
    );

    assert_eq!(
        path,
        PathBuf::from("/tmp/saugra-waf-security-summary-2026-05-22.json")
    );
}

pub(super) fn event(
    timestamp: &str,
    request_id: &str,
    client_ip: &str,
    path: &str,
    action: WafAction,
    rule_id: &str,
    category: &str,
) -> SecurityEvent {
    let decision = WafDecision {
        request_id: request_id.to_string(),
        action,
        matched_rules: vec![RuleMatch {
            rule_id: rule_id.to_string(),
            rule_name: rule_id.to_string(),
            category: category.to_string(),
            severity: RuleSeverity::High,
            matched_target: RuleTarget::Headers,
            paranoia_level: 1,
            explanation: "test".to_string(),
            owasp_category: Some("A06:2025-Insecure Design".to_string()),
        }],
        severity: "high".to_string(),
        risk_score: 80,
        anomaly_score: 5,
        blocking_anomaly_score: 5,
        anomaly_threshold: 5,
        blocking_paranoia_level: 1,
        explanation: "test".to_string(),
        owasp_category: Some("A06:2025-Insecure Design".to_string()),
        owasp_categories: vec!["A06:2025-Insecure Design".to_string()],
        behavior: if category == "behavior_abuse" {
            Some(BehaviorOutcome {
                enabled: true,
                action,
                score: 80,
                monitor_threshold: 40,
                block_threshold: 80,
                score_window_seconds: 600,
                decay_window_seconds: 1_800,
                storage_backend: "local".to_string(),
                contributors: Vec::new(),
            })
        } else {
            None
        },
        unknown_threats: None,
        campaign: None,
        bot_protection: if category == "bot_protection" {
            Some(BotProtectionOutcome {
                enabled: true,
                action,
                score: 80,
                monitor_threshold: 40,
                block_threshold: 80,
                score_window_seconds: 600,
                temporary_block_duration_seconds: 900,
                temporary_blocked_until: None,
                storage_backend: "local".to_string(),
                allowlisted: false,
                blocklisted: false,
                contributors: Vec::new(),
            })
        } else {
            None
        },
        runtime_allowlist: None,
    };

    SecurityEvent {
        timestamp: timestamp.to_string(),
        client_ip: client_ip.to_string(),
        method: "GET".to_string(),
        path: path.to_string(),
        query: String::new(),
        evidence: None,
        owasp_categories: decision.owasp_categories.clone(),
        upstream: None,
        websocket: None,
        decision,
    }
}
