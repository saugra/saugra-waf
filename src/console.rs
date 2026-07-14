use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use reqwest::{Client, Url};
use saugra_console_contracts::{
    DeliveryAcknowledgement, EnrollmentRequest, EnrollmentResponse, EventIngestRequest,
    HeartbeatAcknowledgement, HeartbeatRequest, ManagedNodeRef, SaugraProduct,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{config::SaugraConfig, event_store::SecurityEvent};
use tracing::{info, warn};

pub const CONSOLE_PROTOCOL_VERSION: u16 = 1;

#[derive(Clone)]
pub struct ConsoleOutbox {
    path: PathBuf,
    lock: Arc<Mutex<()>>,
}

impl ConsoleOutbox {
    pub fn from_config(config: &SaugraConfig) -> Self {
        Self::new(config.console.outbox_path(&config.logging.event_log_path))
    }

    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn append(&self, event: &SecurityEvent) -> Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| anyhow::anyhow!("Console outbox lock poisoned"))?;
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("failed to open Console outbox {}", self.path.display()))?;
        protect_file(&self.path)?;
        serde_json::to_writer(&mut file, event)?;
        file.write_all(b"\n")?;
        file.sync_data()?;
        Ok(())
    }

    fn batch(&self, limit: usize) -> Result<Vec<SecurityEvent>> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| anyhow::anyhow!("Console outbox lock poisoned"))?;
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let file = fs::File::open(&self.path)?;
        BufReader::new(file)
            .lines()
            .take(limit)
            .map(|line| serde_json::from_str(&line?).context("invalid event in Console outbox"))
            .collect()
    }

    fn remove_terminal(&self, keys: &HashSet<String>) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }
        let _guard = self
            .lock
            .lock()
            .map_err(|_| anyhow::anyhow!("Console outbox lock poisoned"))?;
        if !self.path.exists() {
            return Ok(());
        }
        let temporary = self
            .path
            .with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
        let source = fs::File::open(&self.path)?;
        let mut target = fs::File::create(&temporary)?;
        protect_file(&temporary)?;
        for line in BufReader::new(source).lines() {
            let line = line?;
            let event: SecurityEvent =
                serde_json::from_str(&line).context("invalid event in Console outbox")?;
            if !keys.contains(&event.decision.request_id) {
                target.write_all(line.as_bytes())?;
                target.write_all(b"\n")?;
            }
        }
        target.sync_all()?;
        fs::rename(&temporary, &self.path)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleCredential {
    pub protocol_version: u16,
    pub node_id: String,
    pub tenant_id: String,
    pub product: SaugraProduct,
    pub credential: String,
    pub credential_fingerprint: String,
    pub credential_expires_at: String,
    pub stored_at_unix_secs: u64,
}

impl ConsoleCredential {
    pub fn from_enrollment_response(response: EnrollmentResponse) -> Result<Self> {
        if response.protocol_version != CONSOLE_PROTOCOL_VERSION {
            bail!(
                "unsupported Console enrollment protocol version {}",
                response.protocol_version
            );
        }
        if response.product != SaugraProduct::Waf {
            bail!("Console enrollment response is not for a WAF node");
        }
        if response.node_id.trim().is_empty()
            || response.tenant_id.trim().is_empty()
            || response.credential.trim().is_empty()
            || response.credential_fingerprint.trim().is_empty()
            || response.credential_expires_at.trim().is_empty()
        {
            bail!("Console enrollment response contains empty credential fields");
        }
        Ok(Self {
            protocol_version: response.protocol_version,
            node_id: response.node_id,
            tenant_id: response.tenant_id,
            product: response.product,
            credential: response.credential,
            credential_fingerprint: response.credential_fingerprint,
            credential_expires_at: response.credential_expires_at,
            stored_at_unix_secs: now_unix_secs(),
        })
    }
}

pub struct ConsoleCredentialStore {
    path: PathBuf,
}

impl ConsoleCredentialStore {
    pub fn from_config(config: &SaugraConfig) -> Self {
        Self {
            path: config
                .console
                .credential_path(&config.logging.event_log_path),
        }
    }

    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn save(&self, credential: &ConsoleCredential) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary = self
            .path
            .with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
        fs::write(&temporary, serde_json::to_vec_pretty(credential)?)?;
        protect_file(&temporary)?;
        fs::rename(&temporary, &self.path).with_context(|| {
            format!("failed to store Console credential {}", self.path.display())
        })?;
        Ok(())
    }

    pub fn load(&self) -> Result<ConsoleCredential> {
        serde_json::from_slice(&fs::read(&self.path)?)
            .with_context(|| format!("failed to read Console credential {}", self.path.display()))
    }
}

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
            "security_event_storage": true
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
    let base = if base.ends_with('/') {
        base.to_string()
    } else {
        format!("{base}/")
    };
    let url = Url::parse(&base)
        .context("invalid console.management_url")?
        .join("api/v1/nodes/enroll")
        .context("invalid Console enrollment URL")?;
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
    ConsoleCredentialStore::from_config(config).save(&credential)?;
    Ok(credential)
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn protect_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
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

fn endpoint(base: &str, path: &str) -> Result<Url> {
    let base = if base.ends_with('/') {
        base.to_string()
    } else {
        format!("{base}/")
    };
    Url::parse(&base)?
        .join(path)
        .context("invalid Console endpoint URL")
}

fn authenticated(
    request: reqwest::RequestBuilder,
    credential: &ConsoleCredential,
) -> reqwest::RequestBuilder {
    request
        .bearer_auth(&credential.credential)
        .header("X-Saugra-Timestamp", now_unix_secs().to_string())
        .header("X-Saugra-Nonce", uuid::Uuid::new_v4().to_string())
}

async fn send_heartbeat(client: &Client, base: &str, credential: &ConsoleCredential) -> Result<()> {
    let heartbeat = heartbeat_request(
        &credential.tenant_id,
        &credential.node_id,
        now_unix_secs(),
        "healthy",
        json!({
            "platform": std::env::consts::OS,
            "agent_version": env!("CARGO_PKG_VERSION"),
            "capabilities": ["waf.request.inspect", "waf.request.monitor", "waf.request.block", "waf.telemetry.events"]
        }),
    );
    let response = authenticated(
        client.post(endpoint(base, "api/v1/ingest/health")?),
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
    Ok(())
}

async fn deliver_batch(
    client: &Client,
    base: &str,
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
        client.post(endpoint(base, "api/v1/ingest/events")?),
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
    let mut terminal = acknowledgement
        .accepted_keys
        .into_iter()
        .collect::<HashSet<_>>();
    terminal.extend(acknowledgement.duplicate_keys);
    if !acknowledgement.rejected_keys.is_empty() {
        warn!(
            rejected = acknowledgement.rejected_keys.len(),
            "Console permanently rejected WAF events"
        );
        terminal.extend(acknowledgement.rejected_keys);
    }
    let delivered = terminal.len();
    outbox.remove_terminal(&terminal)?;
    Ok(delivered)
}

pub fn start_telemetry(
    config: &SaugraConfig,
    outbox: ConsoleOutbox,
) -> Result<tokio::task::JoinHandle<()>> {
    let credential = ConsoleCredentialStore::from_config(config).load()
        .context("Console is enabled but its node credential could not be loaded; run `saugra-waf console enroll`")?;
    let base = config.console.management_url.clone().ok_or_else(|| {
        anyhow::anyhow!("console.management_url is required when Console is enabled")
    })?;
    let heartbeat_interval = config.console.heartbeat_interval_secs;
    let delivery_interval = config.console.delivery_interval_secs;
    let batch_size = config.console.batch_size;
    Ok(tokio::spawn(async move {
        let client = Client::new();
        let mut heartbeats =
            tokio::time::interval(std::time::Duration::from_secs(heartbeat_interval));
        let mut deliveries =
            tokio::time::interval(std::time::Duration::from_secs(delivery_interval));
        loop {
            tokio::select! {
                _ = heartbeats.tick() => match send_heartbeat(&client, &base, &credential).await {
                    Ok(()) => info!(node_id = %credential.node_id, "Console heartbeat acknowledged"),
                    Err(error) => warn!(%error, "Console heartbeat failed; local WAF protection remains active"),
                },
                _ = deliveries.tick() => match deliver_batch(&client, &base, &credential, &outbox, batch_size).await {
                    Ok(count) if count > 0 => info!(count, "Console WAF events acknowledged"),
                    Ok(_) => {},
                    Err(error) => warn!(%error, "Console event delivery failed; events remain in the durable outbox"),
                }
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{WafAction, WafDecision};

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
}
