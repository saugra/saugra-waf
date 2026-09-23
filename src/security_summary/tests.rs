use super::*;
use std::path::{Path, PathBuf};

use crate::{
    behavior::BehaviorOutcome,
    bot::BotProtectionOutcome,
    config::SaugraConfig,
    decision::{WafAction, WafDecision},
    event_store::SecurityEvent,
    rules::{RuleMatch, RuleSeverity, RuleTarget},
};
use date::rfc3339_to_unix_seconds;

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

#[test]
fn email_message_uses_html_body_instead_of_json_attachment_style() {
    let summary = SecuritySummary {
        app_hostname: Some("example.com".to_string()),
        generated_at_unix_seconds: rfc3339_to_unix_seconds("2026-05-22T08:00:00Z").unwrap(),
        timezone: "Africa/Nairobi".to_string(),
        lookback_seconds: 86_400,
        window_start_unix_seconds: rfc3339_to_unix_seconds("2026-05-21T08:00:00Z").unwrap(),
        window_end_unix_seconds: rfc3339_to_unix_seconds("2026-05-22T08:00:00Z").unwrap(),
        total_security_events: 41_408,
        blocked_events: 0,
        monitored_events: 29_498,
        allowed_runtime_policy_events: 0,
        rate_limit_events: 0,
        bot_events: 41_408,
        behavior_threshold_events: 41_408,
        top_attack_categories: vec![SummaryCount {
            name: "A06:2025-Insecure Design".to_string(),
            count: 29_493,
        }],
        top_matched_rules: vec![SummaryCount {
            name: "SAUGRA-BOT-PROTECTION-001".to_string(),
            count: 29_469,
        }],
        top_source_ips: vec![SummaryCount {
            name: "62.164.177.222".to_string(),
            count: 4_218,
        }],
        top_targeted_paths: vec![SummaryCount {
            name: "/altcha/challenge/".to_string(),
            count: 4_969,
        }],
        important_blocked_request_ids: Vec::new(),
        event_log_max_size: Some("100mb".to_string()),
        event_log_max_files: Some(10),
    };

    let message = build_email_message(
        "saugra-waf@example.com",
        &["security@example.com".to_string()],
        &summary_email_subject(&summary),
        &summary,
    );

    assert!(message.contains("Content-Type: multipart/alternative"));
    assert!(message.contains("Content-Type: text/html; charset=UTF-8"));
    assert!(message.contains("Saugra WAF - EXAMPLE.COM"));
    assert!(message.contains("text-align:center"));
    assert!(message.contains("saugra-waf explain &lt;request-id&gt;"));
    assert!(message.contains("saugra-waf explain <request-id>"));
    assert!(message.contains("font-family:'Courier New',Courier,monospace"));
    assert!(message.contains("<strong>Warning:</strong>"));
    assert!(message.contains("Warning: Request IDs remain explainable"));
    assert!(message.contains("active log or 10 retained rotated files of up to 100mb each"));
    assert!(message.contains("Retention is volume-based, not a fixed number of days."));
    assert!(!message.contains("--config /etc/saugra-waf/saugra-waf.yml"));
    assert!(message.contains("41,408"));
    assert!(message.contains("SAUGRA-BOT-PROTECTION-001"));
    assert!(!message.contains("Content-Type: application/json"));
    assert!(!message.contains("\"generated_at_unix_seconds\""));
}

#[test]
fn delivery_failure_records_local_admin_event() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config = SaugraConfig {
        server: crate::config::ServerConfig {
            listen: "127.0.0.1:0".to_string(),
            mode: crate::config::WafMode::Monitor,
        },
        upstreams: vec![crate::config::UpstreamConfig {
            name: "app".to_string(),
            host: "example.com".to_string(),
            target: "http://127.0.0.1:8000".to_string(),
        }],
        routes: Vec::new(),
        security: Default::default(),
        forwarded_headers: Default::default(),
        rate_limit: Default::default(),
        behavior: Default::default(),
        unknown_threats: Default::default(),
        campaign_correlation: Default::default(),
        bot_protection: Default::default(),
        runtime_policy: Default::default(),
        rules: Default::default(),
        ai: Default::default(),
        logging: crate::config::LoggingConfig {
            event_log_path: temp_dir.path().join("events.jsonl"),
            ..Default::default()
        },
        console: Default::default(),
        websocket: Default::default(),
        posture: Default::default(),
        reports: Default::default(),
        standards: Default::default(),
        security_summary: crate::config::SecuritySummaryConfig {
            output_path: temp_dir.path().join("summary.json"),
            channels: vec![crate::config::SecuritySummaryChannelConfig {
                channel_type: "email".to_string(),
                to: vec!["security@example.com".to_string()],
                from: Some("saugra-waf@example.com".to_string()),
                sendmail_path: temp_dir
                    .path()
                    .join("missing-sendmail")
                    .display()
                    .to_string(),
            }],
            ..Default::default()
        },
        storage_cleanup: Default::default(),
    };

    assert!(send_from_config(&config).is_err());
    let admin_events = std::fs::read_to_string(
        temp_dir
            .path()
            .join("saugra-waf-security-summary-admin-events.jsonl"),
    )
    .unwrap();

    assert!(admin_events.contains("security_summary_delivery_failed"));
}

fn event(
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
