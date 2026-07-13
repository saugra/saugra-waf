use saugra_waf::{
    config::SaugraConfig,
    console,
    decision::{WafAction, WafDecision},
    event_store::SecurityEvent,
};
use std::fs;

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

#[test]
fn enrollment_request_and_protected_credential_use_waf_identity() {
    let mut config =
        SaugraConfig::from_file(std::path::Path::new("configs/saugra-waf.example.yml")).unwrap();
    config.console.enabled = true;
    config.console.management_url = Some("https://console.saugra.test".to_string());
    config.console.external_id = Some("waf-node-a".to_string());
    config.validate().unwrap();

    let request = console::enrollment_request(&config, Some("Public WAF")).unwrap();
    request.validate().unwrap();
    assert_eq!(
        request.product,
        saugra_console_contracts::SaugraProduct::Waf
    );
    assert_eq!(request.external_id, "waf-node-a");
    assert_eq!(request.display_name, "Public WAF");

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("console-credential.json");
    let store = console::ConsoleCredentialStore::new(&path);
    let credential = console::ConsoleCredential::from_enrollment_response(
        saugra_console_contracts::EnrollmentResponse {
            protocol_version: 1,
            node_id: "console-node-a".to_string(),
            tenant_id: "tenant-a".to_string(),
            product: saugra_console_contracts::SaugraProduct::Waf,
            credential: "secret-node-credential".to_string(),
            credential_fingerprint: "sha256:fingerprint".to_string(),
            credential_expires_at: "2027-01-01T00:00:00Z".to_string(),
        },
    )
    .unwrap();
    store.save(&credential).unwrap();
    assert_eq!(store.load().unwrap().node_id, "console-node-a");
    assert!(fs::read_to_string(path)
        .unwrap()
        .contains("secret-node-credential"));
}

#[test]
fn enrollment_rejects_an_edr_credential() {
    let error = console::ConsoleCredential::from_enrollment_response(
        saugra_console_contracts::EnrollmentResponse {
            protocol_version: 1,
            node_id: "node-a".to_string(),
            tenant_id: "tenant-a".to_string(),
            product: saugra_console_contracts::SaugraProduct::Edr,
            credential: "credential".to_string(),
            credential_fingerprint: "fingerprint".to_string(),
            credential_expires_at: "2027-01-01T00:00:00Z".to_string(),
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("not for a WAF node"));
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
