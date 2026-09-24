use std::{collections::HashSet, path::Path};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use reqwest::Client;
use saugra_console_contracts::{
    DeliveryAcknowledgement, EffectivePolicyResponse, PolicyBundleSignature, PolicyStage,
    ResponseActionKind, ResponseCommand, SaugraProduct,
};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    config::{RuleExclusionConfig, SaugraConfig},
    decision::{WafAction, WafDecision},
    event_store::SecurityEvent,
    runtime_policy,
};

use super::super::{
    authenticated, console_endpoint, disable_emergency_override, emergency_override,
    enable_emergency_override, execute_response_command, now_unix_secs, rule_inventory,
    sync_effective_policy, terminal_acknowledgement_keys, verify_effective_policy,
    ConsoleCredential, ConsoleOutbox, ManagedPolicyHandle,
};

fn event(id: &str, action: WafAction) -> SecurityEvent {
    SecurityEvent::new(
        "GET",
        "/test",
        "",
        WafDecision {
            request_id: id.to_string(),
            action,
            matched_rules: Vec::new(),
            severity: "low".to_string(),
            risk_score: 0,
            anomaly_score: 0,
            blocking_anomaly_score: 0,
            anomaly_threshold: 5,
            blocking_paranoia_level: u8::MAX,
            explanation: "test decision".to_string(),
            owasp_category: None,
            owasp_categories: Vec::new(),
            behavior: None,
            unknown_threats: None,
            campaign: None,
            bot_protection: None,
            runtime_allowlist: None,
        },
    )
}

#[test]
fn durable_outbox_preserves_order_and_only_removes_terminal_events() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("console-outbox.jsonl");
    let outbox = ConsoleOutbox::new(&path);
    outbox.append(&event("allow-1", WafAction::Allow)).unwrap();
    outbox
        .append(&event("monitor-1", WafAction::Monitor))
        .unwrap();
    outbox.append(&event("block-1", WafAction::Block)).unwrap();

    let batch = outbox.batch(2).unwrap();
    assert_eq!(batch.len(), 2);
    assert_eq!(batch[0].decision.action, WafAction::Allow);
    assert_eq!(batch[1].decision.action, WafAction::Monitor);

    outbox
        .remove_terminal(&HashSet::from([
            "allow-1".to_string(),
            "block-1".to_string(),
        ]))
        .unwrap();
    let remaining = outbox.batch(10).unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].decision.request_id, "monitor-1");
    assert_eq!(ConsoleOutbox::new(path).batch(10).unwrap().len(), 1);
}

#[test]
fn acknowledgement_outcomes_only_remove_terminal_batch_events() {
    let directory = tempfile::tempdir().unwrap();
    let outbox = ConsoleOutbox::new(directory.path().join("outbox.jsonl"));
    for id in ["accepted", "duplicate", "rejected", "retry"] {
        outbox.append(&event(id, WafAction::Monitor)).unwrap();
    }
    let events = outbox.batch(10).unwrap();
    let request =
        super::super::client::event_ingest_request("tenant-a", "node-a", &events).unwrap();
    let acknowledgement = DeliveryAcknowledgement {
        batch_id: request.batch_id.clone(),
        accepted_keys: vec!["accepted".into()],
        duplicate_keys: vec!["duplicate".into()],
        rejected_keys: vec!["rejected".into()],
        retry_keys: vec!["retry".into()],
        retry_after_seconds: Some(10),
    };
    let terminal = terminal_acknowledgement_keys(&request, &acknowledgement).unwrap();
    outbox.remove_terminal(&terminal).unwrap();
    let remaining = outbox.batch(10).unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].decision.request_id, "retry");

    let mut invalid = acknowledgement;
    invalid.retry_keys = vec!["accepted".into()];
    assert!(terminal_acknowledgement_keys(&request, &invalid).is_err());
    invalid.retry_keys = vec!["not-in-batch".into()];
    assert!(terminal_acknowledgement_keys(&request, &invalid).is_err());
}

#[test]
fn authenticated_requests_have_replay_protection_headers() {
    let credential = ConsoleCredential {
        protocol_version: 1,
        node_id: "node-a".into(),
        tenant_id: "tenant-a".into(),
        product: SaugraProduct::Waf,
        credential: "node-secret".into(),
        credential_fingerprint: "fingerprint".into(),
        credential_expires_at: "2027-01-01T00:00:00Z".into(),
        stored_at_unix_secs: 0,
    };
    let request = authenticated(Client::new().get("http://localhost/test"), &credential)
        .build()
        .unwrap();
    assert_eq!(request.headers()["authorization"], "Bearer node-secret");
    assert!(request.headers()["x-saugra-timestamp"]
        .to_str()
        .unwrap()
        .parse::<u64>()
        .is_ok());
    assert!((16..=128).contains(&request.headers()["x-saugra-nonce"].len()));
}

#[test]
fn active_rule_inventory_is_console_displayable() {
    let config =
        SaugraConfig::from_file(std::path::Path::new("configs/saugra-waf.example.yml")).unwrap();
    let inventory = rule_inventory(&config, &ManagedPolicyHandle::default()).unwrap();
    let rules = inventory["rule_inventory"].as_array().unwrap();

    assert!(!rules.is_empty());
    assert_eq!(inventory["mode"], "monitor");
    assert!(rules.iter().all(|rule| {
        rule["id"].as_str().is_some_and(|value| !value.is_empty())
            && rule["name"].as_str().is_some_and(|value| !value.is_empty())
            && rule["severity"].is_string()
            && rule["risk_score"].is_number()
            && rule["enabled"] == true
    }));
    assert!(inventory["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == "waf.rules.inventory"));

    let managed = ManagedPolicyHandle::default();
    managed.activate(vec![RuleExclusionConfig {
        name: Some("Disable one rule".into()),
        rule_ids: vec![rules[0]["id"].as_str().unwrap().to_string()],
        ..RuleExclusionConfig::default()
    }]);
    let updated = rule_inventory(&config, &managed).unwrap();
    assert_eq!(updated["managed_exclusions"], 1);
    assert_eq!(updated["rule_inventory"][0]["enabled"], false);
}

#[test]
fn managed_policy_lifecycle_is_reported_without_discarding_active_policy() {
    let handle = ManagedPolicyHandle::default();
    handle.record_lifecycle("rejected", Some("signature verification failed".into()));

    let status = handle.status();
    assert_eq!(status["status"], "local");
    assert_eq!(status["lifecycle"], "rejected");
    assert_eq!(status["reason"], "signature verification failed");
    assert!(status["updated_at_unix_secs"].as_u64().unwrap() > 0);
    assert_eq!(status["pending_transitions"].as_array().unwrap().len(), 1);
}

#[test]
fn policy_transition_journal_survives_restart_until_acknowledged() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = SaugraConfig::from_file(Path::new("configs/saugra-waf.example.yml")).unwrap();
    config.console.policy_transition_path = Some(directory.path().join("transitions.json"));
    let handle = ManagedPolicyHandle::from_config(&config).unwrap();
    handle.record_lifecycle("downloaded", Some("verified bundle".into()));
    let restored = ManagedPolicyHandle::from_config(&config).unwrap();
    assert_eq!(restored.pending_transitions().len(), 1);
    restored.acknowledge_transitions();
    assert!(ManagedPolicyHandle::from_config(&config)
        .unwrap()
        .pending_transitions()
        .is_empty());
}

#[test]
fn waf_response_execution_is_idempotent_and_bounded() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = SaugraConfig::from_file(Path::new("configs/saugra-waf.example.yml")).unwrap();
    config.runtime_policy.enabled = true;
    config.runtime_policy.path = directory.path().join("runtime-policy.json");
    let request_id = uuid::Uuid::new_v4().to_string();
    let command = ResponseCommand {
        protocol_version: 1,
        request_id: request_id.clone(),
        idempotency_key: format!("console-{request_id}"),
        action: ResponseActionKind::WafBlockIp,
        target: json!({"value": "198.51.100.0/24", "duration_seconds": 3600}),
        policy_mode: "enforce".into(),
        expires_at: (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339(),
        rollback_guidance: "remove the entry after review".into(),
    };
    assert_eq!(
        execute_response_command(&config, &command).outcome,
        "succeeded"
    );
    assert_eq!(
        execute_response_command(&config, &command).outcome,
        "succeeded"
    );
    let policy = runtime_policy::list_policy(&config.runtime_policy.path).unwrap();
    assert_eq!(policy.blocklisted_ips.len(), 1);
    assert_eq!(policy.blocklisted_ips[0].id, request_id);
}

#[test]
fn console_transport_selects_direct_or_relay_contract_routes() {
    let mut config = SaugraConfig::from_file(Path::new("configs/saugra-waf.example.yml")).unwrap();
    assert_eq!(
        console_endpoint(&config, "https://management.test", "ingest/events")
            .unwrap()
            .path(),
        "/api/v1/ingest/events"
    );
    config.console.transport = crate::config::ConsoleTransport::Relay;
    assert_eq!(
        console_endpoint(&config, "https://relay.test", "ingest/events")
            .unwrap()
            .path(),
        "/v1/ingest/events"
    );
}

#[tokio::test]
async fn emergency_override_rolls_back_active_policy_without_network_access() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = SaugraConfig::from_file(Path::new("configs/saugra-waf.example.yml")).unwrap();
    config.console.emergency_override_path = Some(directory.path().join("override.json"));
    let handle = ManagedPolicyHandle::default();
    handle.activate(vec![RuleExclusionConfig {
        name: Some("managed".into()),
        rule_ids: vec!["SAUGRA-SQLI-001".into()],
        ..Default::default()
    }]);
    enable_emergency_override(&config, "Console policy caused a production false positive")
        .unwrap();
    let credential = ConsoleCredential {
        protocol_version: 1,
        node_id: "node-a".into(),
        tenant_id: "tenant-a".into(),
        product: SaugraProduct::Waf,
        credential: "secret".into(),
        credential_fingerprint: "fingerprint".into(),
        credential_expires_at: "2027-01-01T00:00:00Z".into(),
        stored_at_unix_secs: now_unix_secs(),
    };
    let result = sync_effective_policy(
        &Client::new(),
        "http://127.0.0.1:1",
        &credential,
        &config,
        &handle,
    )
    .await
    .unwrap();
    assert!(result.is_none());
    assert!(handle.exclusions().is_empty());
    assert_eq!(handle.status()["lifecycle"], "rolled_back");
    assert!(disable_emergency_override(&config).unwrap());
    assert!(emergency_override(&config).unwrap().is_none());
}

#[test]
fn signed_waf_policy_requires_trust_and_produces_valid_exclusions() {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let public_key = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
    let bundle = json!({
        "protocol_version": 1,
        "tenant_id": "tenant-a",
        "policy_key": "waf-default",
        "revision": 2,
        "product": "waf",
        "schema_version": 1,
        "minimum_agent_version": "1.1.6",
        "required_capabilities": [],
        "policy": {
            "mode": "block",
            "anomaly_threshold": 9,
            "detection_paranoia_level": 1,
            "blocking_paranoia_level": 1,
            "rules": {
                "disabled_rule_ids": ["SAUGRA-XSS-001"],
                "exclusions": [{
                    "name": "Allow article previews",
                    "rule_ids": ["SAUGRA-XSS-001"],
                    "path_prefixes": ["/preview"]
                }]
            }
        },
        "rule_pack": null
    });
    let payload = serde_json::to_vec(&bundle).unwrap();
    let response = EffectivePolicyResponse {
        policy_key: "waf-default".into(),
        revision: 2,
        stage: PolicyStage::Monitor,
        pinned: true,
        assignment_source: "node".into(),
        bundle,
        signature: PolicyBundleSignature {
            algorithm: "ed25519".into(),
            key_id: "test-key".into(),
            public_key: public_key.clone(),
            signed_payload: URL_SAFE_NO_PAD.encode(&payload),
            signature: URL_SAFE_NO_PAD.encode(signing_key.sign(&payload).to_bytes()),
            sha256: format!("{:x}", Sha256::digest(&payload)),
            signed_at: "2026-07-14T00:00:00Z".into(),
        },
    };
    let mut config =
        SaugraConfig::from_file(std::path::Path::new("configs/saugra-waf.example.yml")).unwrap();
    config
        .console
        .trusted_signing_keys
        .insert("test-key".into(), public_key);
    let credential = ConsoleCredential {
        protocol_version: 1,
        node_id: "node-a".into(),
        tenant_id: "tenant-a".into(),
        product: SaugraProduct::Waf,
        credential: "secret".into(),
        credential_fingerprint: "fingerprint".into(),
        credential_expires_at: "2027-01-01T00:00:00Z".into(),
        stored_at_unix_secs: 0,
    };

    let exclusions = verify_effective_policy(&response, &credential, &config).unwrap();
    assert_eq!(exclusions.len(), 2);
    assert_eq!(exclusions[0].path_prefixes, vec!["/preview"]);
    assert_eq!(exclusions[1].rule_ids, vec!["SAUGRA-XSS-001"]);
    let handle = ManagedPolicyHandle::default();
    handle.activate_verified(&response, exclusions);
    let effective = handle.effective_config(&config);
    assert_eq!(effective.server.mode, crate::config::WafMode::Block);
    assert_eq!(effective.rules.inbound_anomaly_threshold, 9);

    config.console.trusted_signing_keys.clear();
    assert!(verify_effective_policy(&response, &credential, &config)
        .unwrap_err()
        .to_string()
        .contains("not trusted"));
}
