use anyhow::Result;
use saugra_console_contracts::{
    EventIngestRequest, HeartbeatRequest, ManagedNodeRef, SaugraProduct,
};
use serde::Serialize;
use serde_json::{json, Value};

use crate::event_store::SecurityEvent;

pub fn event_ingest_request(
    tenant_id: impl Into<String>,
    console_node_id: impl Into<String>,
    events: &[SecurityEvent],
) -> Result<EventIngestRequest> {
    let tenant_id = tenant_id.into();
    let console_node_id = console_node_id.into();
    let records = events
        .iter()
        .map(console_event_record)
        .collect::<Result<Vec<_>>>()?;

    Ok(EventIngestRequest {
        tenant_id,
        source: ManagedNodeRef {
            product: SaugraProduct::Waf,
            node_id: console_node_id,
        },
        batch_id: uuid::Uuid::new_v4().to_string(),
        deduplication_keys: events
            .iter()
            .map(|event| event.decision.request_id.clone())
            .collect(),
        records,
    })
}

pub fn console_event_record(event: &SecurityEvent) -> Result<Value> {
    Ok(json!({
        "event_family": "waf_request",
        "occurred_at": event.timestamp,
        "event_id": event.decision.request_id,
        "severity": event.decision.severity,
        "action": enum_string(event.decision.action)?,
        "risk_score": event.decision.risk_score,
        "method": event.method,
        "path": event.path,
        "client_ip": event.client_ip,
        "owasp_categories": event.owasp_categories,
        "matched_rules": event.decision.matched_rules,
        "explanation": event.decision.explanation,
        "source_schema": "saugra_waf.security_event.v1",
        "payload": event,
    }))
}

pub fn heartbeat_request(
    tenant_id: impl Into<String>,
    console_node_id: impl Into<String>,
    observed_at_unix_secs: u64,
    health_status: impl Into<String>,
    inventory: Value,
) -> HeartbeatRequest {
    HeartbeatRequest {
        tenant_id: tenant_id.into(),
        node: ManagedNodeRef {
            product: SaugraProduct::Waf,
            node_id: console_node_id.into(),
        },
        observed_at_unix_secs,
        health_status: health_status.into(),
        endpoint_inventory: Some(inventory),
        ransomware_alerts: Vec::new(),
    }
}

fn enum_string(value: impl Serialize) -> Result<String> {
    Ok(serde_json::to_value(value)?
        .as_str()
        .unwrap_or("unknown")
        .to_string())
}
