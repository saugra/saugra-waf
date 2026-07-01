use saugra_waf::{
    console,
    decision::{WafAction, WafDecision},
    event_store::SecurityEvent,
};

#[test]
fn waf_security_events_convert_to_console_valid_ingest_batches() {
    let event = SecurityEvent::new("GET", "/login", "next=/admin", decision("request-1"));

    let request =
        console::event_ingest_request("tenant-a", "waf-node-a", std::slice::from_ref(&event))
            .unwrap();

    request.validate(500).unwrap();
    assert_eq!(
        request.source.product,
        saugra_console_contracts::SaugraProduct::Waf
    );
    assert_eq!(request.deduplication_keys, vec!["request-1"]);
    assert_eq!(request.records[0]["event_family"], "waf_request");
    assert_eq!(request.records[0]["event_id"], "request-1");
    assert_eq!(request.records[0]["severity"], "medium");
    assert_eq!(request.records[0]["action"], "monitor");
}

#[test]
fn waf_inventory_converts_to_console_valid_heartbeat() {
    let heartbeat = console::heartbeat_request(
        "tenant-a",
        "waf-node-a",
        1_710_000_000,
        "healthy",
        serde_json::json!({
            "platform": "linux",
            "agent_version": env!("CARGO_PKG_VERSION"),
            "capabilities": ["waf.request.inspect", "waf.request.block"]
        }),
    );

    heartbeat.validate().unwrap();
    assert_eq!(
        heartbeat.node.product,
        saugra_console_contracts::SaugraProduct::Waf
    );
    assert!(heartbeat.endpoint_inventory.unwrap().is_object());
}

fn decision(request_id: &str) -> WafDecision {
    WafDecision {
        request_id: request_id.to_string(),
        action: WafAction::Monitor,
        matched_rules: Vec::new(),
        severity: "medium".to_string(),
        risk_score: 50,
        anomaly_score: 5,
        blocking_anomaly_score: 0,
        anomaly_threshold: 5,
        blocking_paranoia_level: u8::MAX,
        explanation: "test WAF event".to_string(),
        owasp_category: None,
        owasp_categories: Vec::new(),
        behavior: None,
        unknown_threats: None,
        campaign: None,
        bot_protection: None,
        runtime_allowlist: None,
    }
}
