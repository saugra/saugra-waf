use std::collections::HashSet;

use anyhow::{bail, Context, Result};
use reqwest::{Client, Url};
use saugra_console_contracts::{
    DeliveryAcknowledgement, EnrollmentRequest, EventIngestRequest, HeartbeatAcknowledgement,
    HeartbeatRequest, ManagedNodeRef, SaugraProduct,
};
use serde::Serialize;
use serde_json::{json, Value};
use tracing::warn;

use crate::{config::SaugraConfig, event_store::SecurityEvent, rules};

use super::{
    now_unix_secs, ConsoleCredential, ConsoleOutbox, ManagedPolicyHandle, CONSOLE_PROTOCOL_VERSION,
};

pub fn enrollment_request(
    config: &SaugraConfig,
    display_name: Option<&str>,
) -> Result<EnrollmentRequest> {
    let external_id = config
        .console
        .external_id
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("console.external_id is not configured"))?;
    let request = EnrollmentRequest {
        protocol_version: CONSOLE_PROTOCOL_VERSION,
        product: SaugraProduct::Waf,
        external_id: external_id.to_string(),
        display_name: display_name
            .or(config.console.display_name.as_deref())
            .unwrap_or(external_id)
            .to_string(),
        platform: std::env::consts::OS.to_string(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        capabilities: json!({
            "request_inspection": true,
            "request_blocking": true,
            "monitor_mode": true,
            "security_event_storage": true,
            "rule_inventory": true,
            "managed_policy": true,
            "response_capabilities": [
                "response.waf.ip.block", "response.waf.ip.allow",
                "response.waf.runtime.remove"
            ],
            "managed_exclusions": true
        }),
    };
    request.validate()?;
    Ok(request)
}

pub async fn enroll_with_console(
    config: &SaugraConfig,
    enrollment_token: &str,
    display_name: Option<&str>,
) -> Result<ConsoleCredential> {
    if enrollment_token.trim().is_empty() {
        bail!("Console enrollment token must not be empty");
    }
    let base = config
        .console
        .management_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("console.management_url is not configured"))?;
    let url = console_endpoint(config, base, "nodes/enroll")?;
    let response = reqwest::Client::new()
        .post(url)
        .bearer_auth(enrollment_token)
        .json(&enrollment_request(config, display_name)?)
        .send()
        .await
        .context("failed to send Console enrollment request")?;
    let status = response.status();
    let body = response
        .bytes()
        .await
        .context("failed to read Console enrollment response")?;
    if !status.is_success() {
        bail!(
            "Console enrollment failed with HTTP {status}: {}",
            String::from_utf8_lossy(&body)
        );
    }
    let credential = ConsoleCredential::from_enrollment_response(
        serde_json::from_slice(&body)
            .context("failed to parse Console enrollment response JSON")?,
    )?;
    Ok(credential)
}

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

pub fn endpoint(base: &str, path: &str) -> Result<Url> {
    let base = if base.ends_with('/') {
        base.to_string()
    } else {
        format!("{base}/")
    };
    Url::parse(&base)?
        .join(path)
        .context("invalid Console endpoint URL")
}

pub fn console_endpoint(config: &SaugraConfig, base: &str, resource: &str) -> Result<Url> {
    let prefix = match config.console.transport {
        crate::config::ConsoleTransport::Direct => "api/v1/",
        crate::config::ConsoleTransport::Relay => "v1/",
    };
    endpoint(base, &format!("{prefix}{resource}"))
}

pub fn authenticated(
    request: reqwest::RequestBuilder,
    credential: &ConsoleCredential,
) -> reqwest::RequestBuilder {
    request
        .bearer_auth(&credential.credential)
        .header("X-Saugra-Timestamp", now_unix_secs().to_string())
        .header("X-Saugra-Nonce", uuid::Uuid::new_v4().to_string())
}

pub async fn send_heartbeat(
    client: &Client,
    base: &str,
    credential: &ConsoleCredential,
    config: &SaugraConfig,
    managed_policy: &ManagedPolicyHandle,
) -> Result<()> {
    let inventory = rule_inventory(config, managed_policy)?;
    let heartbeat = heartbeat_request(
        &credential.tenant_id,
        &credential.node_id,
        now_unix_secs(),
        "healthy",
        inventory,
    );
    let response = authenticated(
        client.post(console_endpoint(config, base, "ingest/health")?),
        credential,
    )
    .json(&heartbeat)
    .send()
    .await
    .context("failed to send Console heartbeat")?;
    let status = response.status();
    let body = response.bytes().await?;
    if !status.is_success() {
        bail!(
            "Console heartbeat failed with HTTP {status}: {}",
            String::from_utf8_lossy(&body)
        );
    }
    let acknowledgement: HeartbeatAcknowledgement =
        serde_json::from_slice(&body).context("invalid Console heartbeat acknowledgement")?;
    if acknowledgement.node_id != credential.node_id {
        bail!("Console heartbeat acknowledgement node mismatch");
    }
    managed_policy.acknowledge_transitions();
    Ok(())
}

pub fn rule_inventory(
    config: &SaugraConfig,
    managed_policy: &ManagedPolicyHandle,
) -> Result<Value> {
    let rule_set = rules::load_rule_set(&config.rules)
        .context("failed to build Console inventory from active WAF rules")?;
    let source_paths = config
        .rules
        .files
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let default_action = match config.server.mode {
        crate::config::WafMode::Off => "allow",
        crate::config::WafMode::Monitor => "monitor",
        crate::config::WafMode::Block | crate::config::WafMode::Strict => "block",
    };
    let managed_exclusions = managed_policy.exclusions();
    let inventory = rule_set
        .rules()
        .iter()
        .map(|rule| {
            let disabled = managed_exclusions.iter().any(|exclusion| {
                let targets_rule = exclusion.rule_ids.iter().any(|id| id == &rule.id)
                    || exclusion
                        .categories
                        .iter()
                        .any(|category| category == &rule.category);
                let global = exclusion.path_prefixes.is_empty()
                    && exclusion.query_params.is_empty()
                    && exclusion.headers.is_empty()
                    && exclusion.methods.is_empty()
                    && exclusion.targets.is_empty()
                    && exclusion.content_types.is_empty()
                    && exclusion.trusted_headers.is_empty()
                    && exclusion.identities.is_empty();
                targets_rule && global
            });
            json!({
                "id": rule.id,
                "name": rule.name,
                "source_path": source_paths,
                "source_kind": "local_rule_pack",
                "source_version": env!("CARGO_PKG_VERSION"),
                "severity": rule.severity.to_string(),
                "risk_score": rule.severity.risk_score(),
                "action": default_action,
                "enabled": !disabled,
                "category": rule.category,
                "target": rule.target.to_string(),
                "paranoia_level": rule.paranoia_level,
                "owasp_category": rule.owasp_category,
                "tags": [rule.category.clone(), rule.target.to_string()]
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "platform": std::env::consts::OS,
        "agent_version": env!("CARGO_PKG_VERSION"),
        "mode": format!("{:?}", config.server.mode).to_ascii_lowercase(),
        "detection_paranoia_level": config.rules.detection_paranoia_level(),
        "blocking_paranoia_level": config.rules.blocking_paranoia_level(),
        "inbound_anomaly_threshold": config.rules.inbound_anomaly_threshold,
        "managed_exclusions": managed_exclusions.len(),
        "managed_policy": managed_policy.status(),
        "capabilities": [
            "waf.request.inspect", "waf.request.monitor", "waf.request.block",
            "waf.telemetry.events", "waf.rules.inventory", "waf.policy.signed",
            "waf.policy.exclusions"
        ],
        "rule_inventory": inventory
    }))
}

pub async fn deliver_batch(
    client: &Client,
    base: &str,
    config: &SaugraConfig,
    credential: &ConsoleCredential,
    outbox: &ConsoleOutbox,
    batch_size: usize,
) -> Result<usize> {
    let events = outbox.batch(batch_size)?;
    if events.is_empty() {
        return Ok(0);
    }
    let request = event_ingest_request(&credential.tenant_id, &credential.node_id, &events)?;
    request.validate(500)?;
    let response = authenticated(
        client.post(console_endpoint(config, base, "ingest/events")?),
        credential,
    )
    .json(&request)
    .send()
    .await
    .context("failed to send Console event batch")?;
    let status = response.status();
    let body = response.bytes().await?;
    if !(status.is_success() || status.as_u16() == 429 || status.as_u16() == 503) {
        bail!(
            "Console event delivery failed with HTTP {status}: {}",
            String::from_utf8_lossy(&body)
        );
    }
    let acknowledgement: DeliveryAcknowledgement =
        serde_json::from_slice(&body).context("invalid Console delivery acknowledgement")?;
    if acknowledgement.batch_id != request.batch_id {
        bail!("Console delivery acknowledgement batch mismatch");
    }
    let terminal = terminal_acknowledgement_keys(&request, &acknowledgement)?;
    if !acknowledgement.rejected_keys.is_empty() {
        warn!(
            rejected = acknowledgement.rejected_keys.len(),
            "Console permanently rejected WAF events"
        );
    }
    let delivered = terminal.len();
    outbox.remove_terminal(&terminal)?;
    Ok(delivered)
}

pub fn terminal_acknowledgement_keys(
    request: &EventIngestRequest,
    acknowledgement: &DeliveryAcknowledgement,
) -> Result<HashSet<String>> {
    if acknowledgement.batch_id != request.batch_id {
        bail!("Console delivery acknowledgement batch mismatch");
    }
    let requested: HashSet<&str> = request
        .deduplication_keys
        .iter()
        .map(String::as_str)
        .collect();
    let mut observed = HashSet::new();
    let mut terminal = HashSet::new();
    for (keys, is_terminal) in [
        (&acknowledgement.accepted_keys, true),
        (&acknowledgement.duplicate_keys, true),
        (&acknowledgement.rejected_keys, true),
        (&acknowledgement.retry_keys, false),
    ] {
        for key in keys {
            if !requested.contains(key.as_str()) {
                bail!("Console acknowledgement contains an unknown event key");
            }
            if !observed.insert(key.as_str()) {
                bail!("Console acknowledgement assigns an event to multiple outcomes");
            }
            if is_terminal {
                terminal.insert(key.clone());
            }
        }
    }
    Ok(terminal)
}
