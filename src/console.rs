use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use reqwest::{Client, Url};
use saugra_console_contracts::{
    DeliveryAcknowledgement, EffectivePolicyResponse, EnrollmentRequest, EnrollmentResponse,
    EventIngestRequest, HeartbeatAcknowledgement, HeartbeatRequest, ManagedNodeRef, SaugraProduct,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    config::{RuleExclusionConfig, SaugraConfig},
    event_store::SecurityEvent,
    rules,
};
use tracing::{info, warn};

pub const CONSOLE_PROTOCOL_VERSION: u16 = 1;

#[derive(Clone, Default)]
pub struct ManagedPolicyHandle {
    state: Arc<RwLock<ManagedPolicyState>>,
}

#[derive(Default)]
struct ManagedPolicyState {
    exclusions: Vec<RuleExclusionConfig>,
    policy_key: Option<String>,
    revision: Option<i64>,
    digest: Option<String>,
}

impl ManagedPolicyHandle {
    pub fn exclusions(&self) -> Vec<RuleExclusionConfig> {
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .exclusions
            .clone()
    }

    #[cfg(test)]
    pub(crate) fn activate(&self, exclusions: Vec<RuleExclusionConfig>) {
        self.state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .exclusions = exclusions;
    }

    fn activate_verified(
        &self,
        response: &EffectivePolicyResponse,
        exclusions: Vec<RuleExclusionConfig>,
    ) {
        *self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = ManagedPolicyState {
            exclusions,
            policy_key: Some(response.policy_key.clone()),
            revision: Some(response.revision),
            digest: Some(response.signature.sha256.clone()),
        };
    }

    fn status(&self) -> Value {
        let state = self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        json!({
            "policy_key": state.policy_key,
            "revision": state.revision,
            "digest": state.digest,
            "managed_exclusions": state.exclusions.len(),
            "status": if state.policy_key.is_some() { "active" } else { "local" }
        })
    }
}

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
            "security_event_storage": true,
            "rule_inventory": true,
            "managed_policy": true,
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

async fn send_heartbeat(
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

fn verify_effective_policy(
    response: &EffectivePolicyResponse,
    credential: &ConsoleCredential,
    config: &SaugraConfig,
) -> Result<Vec<RuleExclusionConfig>> {
    if response.signature.algorithm != "ed25519" {
        bail!("unsupported Console policy signature algorithm");
    }
    let trusted_key = config
        .console
        .trusted_signing_keys
        .get(&response.signature.key_id)
        .ok_or_else(|| anyhow::anyhow!("Console policy signing key is not trusted"))?;
    if trusted_key != &response.signature.public_key {
        bail!("Console policy embedded public key does not match the trusted key");
    }
    let payload = URL_SAFE_NO_PAD
        .decode(&response.signature.signed_payload)
        .context("Console policy signed payload is not valid base64url")?;
    let digest = format!("{:x}", Sha256::digest(&payload));
    if digest != response.signature.sha256 {
        bail!("Console policy digest verification failed");
    }
    let signed_bundle: Value =
        serde_json::from_slice(&payload).context("Console policy signed payload is not JSON")?;
    if signed_bundle != response.bundle {
        bail!("Console policy bundle differs from its signed payload");
    }
    let public_key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(trusted_key)
        .context("trusted Console signing key is not valid base64url")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("trusted Console signing key must contain 32 bytes"))?;
    let signature: [u8; 64] = URL_SAFE_NO_PAD
        .decode(&response.signature.signature)
        .context("Console policy signature is not valid base64url")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Console policy signature must contain 64 bytes"))?;
    VerifyingKey::from_bytes(&public_key)
        .context("trusted Console signing key is invalid")?
        .verify(&payload, &Signature::from_bytes(&signature))
        .context("Console policy signature verification failed")?;

    if response.bundle["protocol_version"] != 1
        || response.bundle["tenant_id"] != credential.tenant_id
        || response.bundle["product"] != "waf"
        || response.bundle["policy_key"] != response.policy_key
        || response.bundle["revision"] != response.revision
    {
        bail!("Console policy identity does not match this WAF assignment");
    }
    if response.bundle["schema_version"] != 1 {
        bail!("Console policy schema version is not supported by this WAF");
    }
    let minimum_agent_version = response.bundle["minimum_agent_version"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Console policy minimum agent version is missing"))?;
    if !version_at_least(env!("CARGO_PKG_VERSION"), minimum_agent_version)? {
        bail!("Console policy requires a newer WAF agent");
    }

    let rules = response.bundle.pointer("/policy/rules");
    let mut exclusions = rules
        .and_then(|rules| rules.get("exclusions"))
        .cloned()
        .map(serde_json::from_value::<Vec<RuleExclusionConfig>>)
        .transpose()
        .context("Console policy contains invalid WAF rule exclusions")?
        .unwrap_or_default();
    if let Some(value) = rules.and_then(|rules| rules.get("disabled_rule_ids")) {
        let rule_ids = value
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("disabled_rule_ids must be an array"))?;
        exclusions.push(RuleExclusionConfig {
            name: Some("Console-managed disabled rules".to_string()),
            rule_ids: rule_ids
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .filter(|value| !value.trim().is_empty())
                        .map(ToOwned::to_owned)
                        .ok_or_else(|| anyhow::anyhow!("disabled rule IDs must be strings"))
                })
                .collect::<Result<Vec<_>>>()?,
            ..RuleExclusionConfig::default()
        });
    }
    if let Some(value) = rules.and_then(|rules| rules.get("disabled_categories")) {
        let categories = value
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("disabled_categories must be an array"))?;
        exclusions.push(RuleExclusionConfig {
            name: Some("Console-managed disabled categories".to_string()),
            categories: categories
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .filter(|value| !value.trim().is_empty())
                        .map(ToOwned::to_owned)
                        .ok_or_else(|| anyhow::anyhow!("disabled categories must be strings"))
                })
                .collect::<Result<Vec<_>>>()?,
            ..RuleExclusionConfig::default()
        });
    }
    exclusions
        .retain(|exclusion| !exclusion.rule_ids.is_empty() || !exclusion.categories.is_empty());
    let active_rules = rules::load_rule_set(&config.rules)
        .context("failed to load active rules while validating Console policy")?;
    for exclusion in &exclusions {
        for rule_id in &exclusion.rule_ids {
            if active_rules.rules_by_id(rule_id).is_empty() {
                bail!("Console policy references unknown or inactive rule ID {rule_id}");
            }
        }
        for category in &exclusion.categories {
            if !active_rules
                .rules()
                .iter()
                .any(|rule| &rule.category == category)
            {
                bail!("Console policy references unknown or inactive category {category}");
            }
        }
    }
    let mut validation = config.clone();
    validation.rules.exclusions.extend(exclusions.clone());
    validation
        .validate()
        .context("Console policy failed local WAF configuration validation")?;
    rules::load_rule_set_with_report(&validation.rules)
        .context("Console policy failed local WAF rule validation")?;
    Ok(exclusions)
}

fn version_at_least(actual: &str, minimum: &str) -> Result<bool> {
    fn parts(value: &str) -> Result<Vec<u64>> {
        value
            .split('.')
            .map(|part| {
                part.split_once('-')
                    .map(|(number, _)| number)
                    .unwrap_or(part)
                    .parse::<u64>()
                    .with_context(|| format!("invalid semantic version {value}"))
            })
            .collect()
    }
    let mut actual = parts(actual)?;
    let mut minimum = parts(minimum)?;
    let length = actual.len().max(minimum.len());
    actual.resize(length, 0);
    minimum.resize(length, 0);
    Ok(actual >= minimum)
}

fn persist_effective_policy(
    config: &SaugraConfig,
    response: &EffectivePolicyResponse,
) -> Result<()> {
    let path = config
        .console
        .policy_cache_path(&config.logging.event_log_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    fs::write(&temporary, serde_json::to_vec_pretty(response)?)?;
    protect_file(&temporary)?;
    fs::rename(&temporary, &path)
        .with_context(|| format!("failed to store verified Console policy {}", path.display()))?;
    Ok(())
}

fn load_cached_policy(
    config: &SaugraConfig,
    credential: &ConsoleCredential,
) -> Result<Option<(EffectivePolicyResponse, Vec<RuleExclusionConfig>)>> {
    let path = config
        .console
        .policy_cache_path(&config.logging.event_log_path);
    if !path.exists() {
        return Ok(None);
    }
    let response: EffectivePolicyResponse = serde_json::from_slice(
        &fs::read(&path)
            .with_context(|| format!("failed to read cached Console policy {}", path.display()))?,
    )
    .context("cached Console policy is not valid JSON")?;
    let exclusions = verify_effective_policy(&response, credential, config)
        .context("cached Console policy verification failed")?;
    Ok(Some((response, exclusions)))
}

async fn fetch_effective_policy(
    client: &Client,
    base: &str,
    credential: &ConsoleCredential,
    config: &SaugraConfig,
    managed_policy: &ManagedPolicyHandle,
) -> Result<Option<(String, i64, usize)>> {
    let response = authenticated(
        client.get(endpoint(base, "api/v1/policy/effective")?),
        credential,
    )
    .send()
    .await
    .context("failed to fetch effective Console policy")?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let status = response.status();
    let body = response.bytes().await?;
    if !status.is_success() {
        bail!(
            "Console effective policy fetch failed with HTTP {status}: {}",
            String::from_utf8_lossy(&body)
        );
    }
    let response: EffectivePolicyResponse =
        serde_json::from_slice(&body).context("invalid Console effective policy response")?;
    let exclusions = verify_effective_policy(&response, credential, config)?;
    persist_effective_policy(config, &response)?;
    let count = exclusions.len();
    managed_policy.activate_verified(&response, exclusions);
    Ok(Some((response.policy_key, response.revision, count)))
}

pub fn start_telemetry(
    config: &SaugraConfig,
    outbox: ConsoleOutbox,
    managed_policy: ManagedPolicyHandle,
) -> Result<tokio::task::JoinHandle<()>> {
    let credential = ConsoleCredentialStore::from_config(config).load()
        .context("Console is enabled but its node credential could not be loaded; run `saugra-waf console enroll`")?;
    let base = config.console.management_url.clone().ok_or_else(|| {
        anyhow::anyhow!("console.management_url is required when Console is enabled")
    })?;
    let heartbeat_interval = config.console.heartbeat_interval_secs;
    let delivery_interval = config.console.delivery_interval_secs;
    let batch_size = config.console.batch_size;
    rule_inventory(config, &managed_policy)?;
    let policy_interval = config.console.policy_poll_interval_secs;
    let policy_enabled = !config.console.trusted_signing_keys.is_empty();
    let policy_config = config.clone();
    let heartbeat_config = config.clone();
    if policy_enabled {
        match load_cached_policy(config, &credential) {
            Ok(Some((response, exclusions))) => {
                let count = exclusions.len();
                managed_policy.activate_verified(&response, exclusions);
                info!(
                    policy_key = %response.policy_key,
                    revision = response.revision,
                    exclusions = count,
                    "verified cached Console WAF policy activated"
                );
            }
            Ok(None) => {}
            Err(error) => warn!(
                %error,
                "cached Console WAF policy rejected; local configuration remains active"
            ),
        }
    }
    Ok(tokio::spawn(async move {
        let client = Client::new();
        let mut heartbeats =
            tokio::time::interval(std::time::Duration::from_secs(heartbeat_interval));
        let mut deliveries =
            tokio::time::interval(std::time::Duration::from_secs(delivery_interval));
        let mut policies = tokio::time::interval(std::time::Duration::from_secs(policy_interval));
        loop {
            tokio::select! {
                _ = heartbeats.tick() => match send_heartbeat(&client, &base, &credential, &heartbeat_config, &managed_policy).await {
                    Ok(()) => info!(node_id = %credential.node_id, "Console heartbeat acknowledged"),
                    Err(error) => warn!(%error, "Console heartbeat failed; local WAF protection remains active"),
                },
                _ = deliveries.tick() => match deliver_batch(&client, &base, &credential, &outbox, batch_size).await {
                    Ok(count) if count > 0 => info!(count, "Console WAF events acknowledged"),
                    Ok(_) => {},
                    Err(error) => warn!(%error, "Console event delivery failed; events remain in the durable outbox"),
                },
                _ = policies.tick(), if policy_enabled => match fetch_effective_policy(&client, &base, &credential, &policy_config, &managed_policy).await {
                    Ok(Some((policy_key, revision, exclusions))) => info!(%policy_key, revision, exclusions, "verified Console WAF policy activated"),
                    Ok(None) => {},
                    Err(error) => warn!(%error, "Console WAF policy rejected; last-known-good policy remains active"),
                },
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{WafAction, WafDecision};
    use ed25519_dalek::{Signer, SigningKey};
    use saugra_console_contracts::{PolicyBundleSignature, PolicyStage};

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

    #[test]
    fn active_rule_inventory_is_console_displayable() {
        let config =
            SaugraConfig::from_file(std::path::Path::new("configs/saugra-waf.example.yml"))
                .unwrap();
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
                "mode": "monitor",
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
            SaugraConfig::from_file(std::path::Path::new("configs/saugra-waf.example.yml"))
                .unwrap();
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

        config.console.trusted_signing_keys.clear();
        assert!(verify_effective_policy(&response, &credential, &config)
            .unwrap_err()
            .to_string()
            .contains("not trusted"));
    }
}
