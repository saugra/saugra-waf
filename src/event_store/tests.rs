use super::*;
use crate::{
    behavior::BehaviorOutcome,
    bot::BotProtectionOutcome,
    decision::{WafAction, WafDecision},
};

#[test]
fn appends_tails_and_finds_events() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("events.jsonl");
    let retention = EventLogRetention {
        max_size_bytes: 1024,
        max_files: 3,
    };
    let event = SecurityEvent::new("GET", "/search", "q=test", decision("request-1"));

    append(&path, retention, &event).unwrap();

    let events = tail(&path, retention, 10).unwrap();
    let found = find_by_request_id(&path, retention, "request-1")
        .unwrap()
        .unwrap();

    assert_eq!(events.len(), 1);
    assert_eq!(found.decision.request_id, "request-1");
}

#[test]
fn rotates_event_logs_and_reads_rotated_files() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("events.jsonl");
    let retention = EventLogRetention {
        max_size_bytes: 220,
        max_files: 2,
    };

    append(
        &path,
        retention,
        &SecurityEvent::new("GET", "/one", "", decision("request-1")),
    )
    .unwrap();
    append(
        &path,
        retention,
        &SecurityEvent::new("GET", "/two", "", decision("request-2")),
    )
    .unwrap();

    let events = tail(&path, retention, 10).unwrap();

    assert!(rotated_path(&path, 1).exists());
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].decision.request_id, "request-1");
    assert_eq!(events[1].decision.request_id, "request-2");
}

#[test]
fn serializes_security_event_with_expected_json_shape() {
    let event = SecurityEvent {
        timestamp: "2026-05-14T00:00:00Z".to_string(),
        client_ip: "203.0.113.10".to_string(),
        method: "GET".to_string(),
        path: "/search".to_string(),
        query: "q=test".to_string(),
        evidence: None,
        owasp_categories: Vec::new(),
        upstream: None,
        websocket: None,
        decision: decision("request-1"),
    };

    let json = serde_json::to_value(event).unwrap();

    assert_eq!(json["timestamp"], "2026-05-14T00:00:00Z");
    assert!(json["timestamp_unix_seconds"].is_null());
    assert_eq!(json["client_ip"], "203.0.113.10");
    assert_eq!(json["method"], "GET");
    assert_eq!(json["path"], "/search");
    assert_eq!(json["query"], "q=test");
    assert!(json["upstream"].is_null());
    assert!(json["websocket"].is_null());
    assert!(json["owasp_categories"].as_array().unwrap().is_empty());
    assert_eq!(json["decision"]["request_id"], "request-1");
    assert_eq!(json["decision"]["action"], "allow");
    assert_eq!(json["decision"]["risk_score"], 0);
}

#[test]
fn reads_legacy_unix_timestamp_events() {
    let line = r#"{
        "timestamp_unix_seconds": 1778889600,
        "method": "GET",
        "path": "/search",
        "query": "q=test",
        "owasp_categories": [],
        "decision": {
            "request_id": "request-1",
            "action": "allow",
            "matched_rules": [],
            "severity": "none",
            "risk_score": 0,
            "anomaly_score": 0,
            "anomaly_threshold": 5,
            "explanation": "No security rules matched this request.",
            "owasp_category": null,
            "owasp_categories": []
        }
    }"#;

    let event: SecurityEvent = serde_json::from_str(line).unwrap();

    assert_eq!(event.timestamp, "2026-05-16T00:00:00Z");
    assert_eq!(event.client_ip, "unknown");
}

#[test]
fn summarizes_events_by_action_and_owasp_category() {
    let mut injection = decision("request-1");
    injection.action = WafAction::Block;
    injection.owasp_categories = vec!["A05:2025-Injection".to_string()];
    let mut auth = decision("request-2");
    auth.action = WafAction::Monitor;
    auth.owasp_categories = vec!["A07:2025-Identification and Authentication Failures".to_string()];

    let events = vec![
        SecurityEvent::new("GET", "/search", "q=--", injection),
        SecurityEvent::new("GET", "/login", "", auth),
        SecurityEvent::new("GET", "/", "", decision("request-3")),
    ];

    let summary = summarize(&events);

    assert_eq!(summary.total_events, 3);
    assert_eq!(
        summary.actions,
        vec![
            EventCount {
                name: "allow".to_string(),
                count: 1,
            },
            EventCount {
                name: "block".to_string(),
                count: 1,
            },
            EventCount {
                name: "monitor".to_string(),
                count: 1,
            },
        ]
    );
    assert_eq!(
        summary.owasp_categories,
        vec![
            EventCount {
                name: "A05:2025-Injection".to_string(),
                count: 1,
            },
            EventCount {
                name: "A07:2025-Identification and Authentication Failures".to_string(),
                count: 1,
            },
            EventCount {
                name: "none".to_string(),
                count: 1,
            },
        ]
    );
    assert!(summary.behavior_actions.is_empty());
}

#[test]
fn summarizes_behavior_actions() {
    let mut decision = decision("request-1");
    decision.behavior = Some(BehaviorOutcome {
        enabled: true,
        action: WafAction::Monitor,
        score: 40,
        monitor_threshold: 40,
        block_threshold: 80,
        score_window_seconds: 600,
        decay_window_seconds: 1_800,
        storage_backend: "memory".to_string(),
        contributors: Vec::new(),
    });
    let events = vec![SecurityEvent::new("GET", "/.env", "", decision)];

    let summary = summarize(&events);

    assert_eq!(
        summary.behavior_actions,
        vec![EventCount {
            name: "monitor".to_string(),
            count: 1,
        }]
    );
}

#[test]
fn summarizes_bot_protection_actions() {
    let mut decision = decision("request-1");
    decision.bot_protection = Some(BotProtectionOutcome {
        enabled: true,
        action: WafAction::Block,
        score: 80,
        monitor_threshold: 40,
        block_threshold: 80,
        score_window_seconds: 600,
        temporary_block_duration_seconds: 900,
        temporary_blocked_until: Some(1_779_035_662),
        storage_backend: "memory".to_string(),
        allowlisted: false,
        blocklisted: true,
        contributors: Vec::new(),
    });
    let events = vec![SecurityEvent::new("GET", "/.env", "", decision)];

    let summary = summarize(&events);

    assert_eq!(
        summary.behavior_actions,
        vec![EventCount {
            name: "bot_block".to_string(),
            count: 1,
        }]
    );
}

#[test]
fn formats_unix_seconds_as_rfc3339_utc() {
    assert_eq!(unix_seconds_to_rfc3339(0, "UTC"), "1970-01-01T00:00:00Z");
    assert_eq!(
        unix_seconds_to_rfc3339(1_779_035_662, "UTC"),
        "2026-05-17T16:34:22Z"
    );
}

#[test]
fn formats_unix_seconds_for_africa_nairobi() {
    assert_eq!(
        unix_seconds_to_rfc3339(1_779_035_662, "Africa/Nairobi"),
        "2026-05-17T19:34:22+03:00"
    );
}

#[test]
fn formats_unix_seconds_for_fixed_offsets() {
    assert_eq!(
        unix_seconds_to_rfc3339(0, "+03:00"),
        "1970-01-01T03:00:00+03:00"
    );
    assert_eq!(
        unix_seconds_to_rfc3339(0, "-01:00"),
        "1969-12-31T23:00:00-01:00"
    );
}

#[test]
fn validates_supported_timestamp_timezones() {
    assert!(is_supported_timestamp_timezone("UTC"));
    assert!(is_supported_timestamp_timezone("Africa/Nairobi"));
    assert!(is_supported_timestamp_timezone("+03:00"));
    assert!(!is_supported_timestamp_timezone("Mars/Olympus"));
}

fn decision(request_id: &str) -> WafDecision {
    WafDecision {
        request_id: request_id.to_string(),
        action: WafAction::Allow,
        matched_rules: Vec::new(),
        severity: "none".to_string(),
        risk_score: 0,
        anomaly_score: 0,
        blocking_anomaly_score: 0,
        anomaly_threshold: 5,
        blocking_paranoia_level: u8::MAX,
        explanation: "No security rules matched this request.".to_string(),
        owasp_category: None,
        owasp_categories: Vec::new(),
        behavior: None,
        unknown_threats: None,
        campaign: None,
        bot_protection: None,
        runtime_allowlist: None,
    }
}
