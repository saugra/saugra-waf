use axum::{
    extract::State,
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use saugra_console_contracts::{
    DeliveryAcknowledgement, EventIngestRequest, HeartbeatAcknowledgement, HeartbeatRequest,
    ResponseCommandBatch,
};
use saugra_waf::{
    config::SaugraConfig,
    console::{
        self, ConsoleCredential, ConsoleCredentialStore, ConsoleOutbox, ManagedPolicyHandle,
    },
    decision::{WafAction, WafDecision},
    event_store::SecurityEvent,
};
use std::{fs, sync::Arc, time::Duration};

#[derive(Clone)]
struct MockState {
    outcome: &'static str,
}

async fn ingest_events(
    State(state): State<Arc<MockState>>,
    headers: HeaderMap,
    Json(request): Json<EventIngestRequest>,
) -> Json<DeliveryAcknowledgement> {
    assert_authenticated(&headers);
    request.validate(500).unwrap();
    let keys = request.deduplication_keys.clone();
    let mut acknowledgement = DeliveryAcknowledgement {
        batch_id: request.batch_id,
        accepted_keys: vec![],
        duplicate_keys: vec![],
        rejected_keys: vec![],
        retry_keys: vec![],
        retry_after_seconds: None,
    };
    match state.outcome {
        "accepted" => acknowledgement.accepted_keys = keys,
        "duplicate" => acknowledgement.duplicate_keys = keys,
        "rejected" => acknowledgement.rejected_keys = keys,
        "retry" => {
            acknowledgement.retry_keys = keys;
            acknowledgement.retry_after_seconds = Some(1);
        }
        _ => unreachable!(),
    }
    Json(acknowledgement)
}

async fn heartbeat(
    headers: HeaderMap,
    Json(request): Json<HeartbeatRequest>,
) -> Json<HeartbeatAcknowledgement> {
    assert_authenticated(&headers);
    request.validate().unwrap();
    Json(HeartbeatAcknowledgement {
        node_id: request.node.node_id,
        observed_at_unix_secs: request.observed_at_unix_secs,
        stale: false,
    })
}

async fn responses(headers: HeaderMap) -> Json<ResponseCommandBatch> {
    assert_authenticated(&headers);
    Json(ResponseCommandBatch {
        commands: vec![],
        poll_after_seconds: 15,
    })
}

fn assert_authenticated(headers: &HeaderMap) {
    assert_eq!(headers.get("authorization").unwrap(), "Bearer node-secret");
    assert!(headers.get("x-saugra-timestamp").is_some());
    assert!((16..=128).contains(&headers.get("x-saugra-nonce").unwrap().as_bytes().len()));
}

fn event(id: &str) -> SecurityEvent {
    SecurityEvent::new(
        "GET",
        "/live",
        "",
        WafDecision {
            request_id: id.into(),
            action: WafAction::Monitor,
            matched_rules: vec![],
            severity: "low".into(),
            risk_score: 1,
            anomaly_score: 0,
            blocking_anomaly_score: 0,
            anomaly_threshold: 5,
            blocking_paranoia_level: 1,
            explanation: "live integration".into(),
            owasp_category: None,
            owasp_categories: vec![],
            behavior: None,
            unknown_threats: None,
            campaign: None,
            bot_protection: None,
            runtime_allowlist: None,
        },
    )
}

async fn run_outcome(outcome: &'static str) -> usize {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/api/v1/ingest/events", post(ingest_events))
        .route("/api/v1/ingest/health", post(heartbeat))
        .route("/api/v1/responses/commands", get(responses))
        .with_state(Arc::new(MockState { outcome }));
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let directory = tempfile::tempdir().unwrap();
    let mut config =
        SaugraConfig::from_file(std::path::Path::new("configs/saugra-waf.example.yml")).unwrap();
    config.console.enabled = true;
    config.console.management_url = Some(format!("http://{address}"));
    config.console.delivery_interval_secs = 1;
    config.console.heartbeat_interval_secs = 60;
    config.logging.event_log_path = directory.path().join("events.jsonl").display().to_string();
    let credential = ConsoleCredential {
        protocol_version: 1,
        node_id: "node-live".into(),
        tenant_id: "tenant-live".into(),
        product: saugra_console_contracts::SaugraProduct::Waf,
        credential: "node-secret".into(),
        credential_fingerprint: "fingerprint".into(),
        credential_expires_at: "2027-01-01T00:00:00Z".into(),
        stored_at_unix_secs: 1,
    };
    ConsoleCredentialStore::from_config(&config)
        .save(&credential)
        .unwrap();
    let outbox = ConsoleOutbox::from_config(&config);
    outbox.append(&event(&format!("{outcome}-event"))).unwrap();
    let task = console::start_telemetry(
        &config,
        outbox,
        ManagedPolicyHandle::from_config(&config).unwrap(),
    )
    .unwrap();
    tokio::time::sleep(Duration::from_millis(350)).await;
    task.abort();
    server.abort();
    let path = config.console.outbox_path(&config.logging.event_log_path);
    fs::read_to_string(path).unwrap_or_default().lines().count()
}

#[tokio::test]
async fn live_console_http_acknowledgements_preserve_only_retry_events() {
    assert_eq!(run_outcome("accepted").await, 0);
    assert_eq!(run_outcome("duplicate").await, 0);
    assert_eq!(run_outcome("rejected").await, 0);
    assert_eq!(run_outcome("retry").await, 1);
}
