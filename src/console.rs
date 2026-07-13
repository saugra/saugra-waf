use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use reqwest::Url;
use saugra_console_contracts::{
    EnrollmentRequest, EnrollmentResponse, EventIngestRequest, HeartbeatRequest, ManagedNodeRef,
    SaugraProduct,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{config::SaugraConfig, event_store::SecurityEvent};

pub const CONSOLE_PROTOCOL_VERSION: u16 = 1;

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
