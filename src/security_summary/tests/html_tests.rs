use std::path::{Path, PathBuf};

use super::super::*;
use crate::config::SaugraConfig;
use date::rfc3339_to_unix_seconds;

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

#[test]
fn deliver_file_channel_writes_summary_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let summary_path = temp_dir.path().join("summary.json");
    let mut config = SaugraConfig::from_file(Path::new("configs/saugra-waf.example.yml")).unwrap();
    config.security_summary.output_path = summary_path.clone();
    config.security_summary.channels = vec![crate::config::SecuritySummaryChannelConfig {
        channel_type: "file".to_string(),
        to: Vec::new(),
        from: None,
        sendmail_path: "/usr/sbin/sendmail".to_string(),
    }];

    let summary = generate(&[], 86_400, 1_700_000_000, "UTC");
    let report = deliver(&config, &summary).unwrap();

    assert_eq!(report.output_path, Some(summary_path.clone()));
    assert!(summary_path.exists());
    let content = std::fs::read_to_string(&summary_path).unwrap();
    assert!(content.contains("\"generated_at_unix_seconds\": 1700000000"));
}

#[test]
fn deliver_email_channel_failure_returns_error() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mut config = SaugraConfig::from_file(Path::new("configs/saugra-waf.example.yml")).unwrap();
    config.security_summary.channels = vec![crate::config::SecuritySummaryChannelConfig {
        channel_type: "email".to_string(),
        to: vec!["admin@example.com".to_string()],
        from: Some("waf@example.com".to_string()),
        sendmail_path: temp_dir
            .path()
            .join("nonexistent-sendmail")
            .display()
            .to_string(),
    }];

    let summary = generate(&[], 86_400, 1_700_000_000, "UTC");
    let result = deliver(&config, &summary);
    assert!(result.is_err());
}

#[test]
fn deliver_handles_unknown_channel_type() {
    let mut config = SaugraConfig::from_file(Path::new("configs/saugra-waf.example.yml")).unwrap();
    config.security_summary.channels = vec![crate::config::SecuritySummaryChannelConfig {
        channel_type: "unsupported".to_string(),
        to: Vec::new(),
        from: None,
        sendmail_path: "/usr/sbin/sendmail".to_string(),
    }];

    let summary = generate(&[], 86_400, 1_700_000_000, "UTC");
    let report = deliver(&config, &summary).unwrap();
    assert_eq!(report.output_path, None);
    assert!(report.email_recipients.is_empty());
}

#[test]
fn admin_event_path_handles_relative_and_absolute_paths() {
    let path = Path::new("summary.json");
    let admin_path = html::admin_event_path(path);
    assert_eq!(
        admin_path,
        PathBuf::from("saugra-waf-security-summary-admin-events.jsonl")
    );

    let nested_path = Path::new("/var/log/saugra/summary.json");
    let nested_admin = html::admin_event_path(nested_path);
    assert_eq!(
        nested_admin,
        PathBuf::from("/var/log/saugra/saugra-waf-security-summary-admin-events.jsonl")
    );
}
