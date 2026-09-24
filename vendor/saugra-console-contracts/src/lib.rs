#![allow(clippy::all)]

use std::collections::HashSet;

use chrono::DateTime;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SaugraProduct {
    Edr,
    Waf,
    Server,
    Relay,
}

impl SaugraProduct {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Edr => "edr",
            Self::Waf => "waf",
            Self::Server => "server",
            Self::Relay => "relay",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedNodeRef {
    pub product: SaugraProduct,
    pub node_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentRequest {
    pub protocol_version: u16,
    pub product: SaugraProduct,
    pub external_id: String,
    pub display_name: String,
    pub platform: String,
    pub agent_version: String,
    #[serde(default)]
    pub capabilities: Value,
}

impl EnrollmentRequest {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.protocol_version != 1 {
            return Err(ContractError::UnsupportedProtocolVersion(
                self.protocol_version,
            ));
        }
        validate_identifier(&self.external_id, "external_id")?;
        validate_text(&self.display_name, "display_name", 160)?;
        validate_text(&self.platform, "platform", 80)?;
        validate_text(&self.agent_version, "agent_version", 80)?;
        if !self.capabilities.is_object() {
            return Err(ContractError::InvalidObject("capabilities".to_string()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentResponse {
    pub protocol_version: u16,
    pub node_id: String,
    pub tenant_id: String,
    pub product: SaugraProduct,
    pub credential: String,
    pub credential_fingerprint: String,
    pub credential_expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRotationResponse {
    pub credential: String,
    pub credential_fingerprint: String,
    pub credential_expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventIngestRequest {
    pub tenant_id: String,
    pub source: ManagedNodeRef,
    pub batch_id: String,
    pub deduplication_keys: Vec<String>,
    pub records: Vec<Value>,
}

impl EventIngestRequest {
    pub fn validate(&self, maximum_records: usize) -> Result<(), ContractError> {
        validate_identifier(&self.tenant_id, "tenant_id")?;
        validate_identifier(&self.source.node_id, "source.node_id")?;
        validate_identifier(&self.batch_id, "batch_id")?;
        if self.deduplication_keys.len() != self.records.len() {
            return Err(ContractError::MismatchedBatchLengths);
        }
        if self.records.is_empty() {
            return Err(ContractError::EmptyBatch);
        }
        if self.records.len() > maximum_records {
            return Err(ContractError::BatchTooLarge {
                actual: self.records.len(),
                maximum: maximum_records,
            });
        }
        let mut unique_keys = HashSet::with_capacity(self.deduplication_keys.len());
        for key in &self.deduplication_keys {
            validate_identifier(key, "deduplication_keys")?;
            if !unique_keys.insert(key) {
                return Err(ContractError::DuplicateDeduplicationKey);
            }
        }
        for record in &self.records {
            let object = record
                .as_object()
                .ok_or_else(|| ContractError::InvalidObject("records".to_string()))?;
            let family = object
                .get("event_family")
                .and_then(Value::as_str)
                .ok_or_else(|| ContractError::MissingField("event_family".to_string()))?;
            validate_identifier(family, "event_family")?;
            let occurred_at = object
                .get("occurred_at")
                .and_then(Value::as_str)
                .ok_or_else(|| ContractError::MissingField("occurred_at".to_string()))?;
            DateTime::parse_from_rfc3339(occurred_at)
                .map_err(|_| ContractError::InvalidTimestamp("occurred_at".to_string()))?;
            for field in ["event_id", "severity", "action"] {
                if let Some(value) = object.get(field) {
                    let value = value
                        .as_str()
                        .ok_or_else(|| ContractError::InvalidText(field.to_string()))?;
                    validate_text(value, field, 128)?;
                }
            }
            if let Some(value) = object.get("risk_score") {
                let score = value
                    .as_f64()
                    .ok_or_else(|| ContractError::InvalidNumber("risk_score".to_string()))?;
                if !score.is_finite() || !(0.0..=100.0).contains(&score) {
                    return Err(ContractError::InvalidNumber("risk_score".to_string()));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryAcknowledgement {
    pub batch_id: String,
    pub accepted_keys: Vec<String>,
    #[serde(default)]
    pub duplicate_keys: Vec<String>,
    #[serde(default)]
    pub rejected_keys: Vec<String>,
    pub retry_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub tenant_id: String,
    pub node: ManagedNodeRef,
    pub observed_at_unix_secs: u64,
    pub health_status: String,
    #[serde(default)]
    pub endpoint_inventory: Option<Value>,
    #[serde(default)]
    pub ransomware_alerts: Vec<Value>,
}

impl HeartbeatRequest {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_identifier(&self.tenant_id, "tenant_id")?;
        validate_identifier(&self.node.node_id, "node.node_id")?;
        validate_text(&self.health_status, "health_status", 64)?;
        if self
            .endpoint_inventory
            .as_ref()
            .is_some_and(|inventory| !inventory.is_object())
        {
            return Err(ContractError::InvalidObject(
                "endpoint_inventory".to_string(),
            ));
        }
        if self.ransomware_alerts.len() > 100
            || self
                .ransomware_alerts
                .iter()
                .any(|alert| !alert.is_object())
        {
            return Err(ContractError::InvalidObject(
                "ransomware_alerts".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatAcknowledgement {
    pub node_id: String,
    pub observed_at_unix_secs: u64,
    pub stale: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutStage {
    Monitor,
    TunedMonitor,
    LimitedBlock,
    BroaderBlock,
    HighConfidenceIsolation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStage {
    Draft,
    Monitor,
    Canary,
    Enforce,
    RolledBack,
}

impl PolicyStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Monitor => "monitor",
            Self::Canary => "canary",
            Self::Enforce => "enforce",
            Self::RolledBack => "rolled_back",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyBundleSignature {
    pub algorithm: String,
    pub key_id: String,
    pub public_key: String,
    pub signed_payload: String,
    pub signature: String,
    pub sha256: String,
    pub signed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitlementDocument {
    pub protocol_version: u16,
    pub entitlement_id: String,
    pub tenant_id: String,
    pub issuer: String,
    pub issued_at: String,
    pub valid_from: String,
    pub valid_until: String,
    pub grace_until: String,
    pub protected_node_limit: Option<u64>,
    pub managed_content: bool,
    #[serde(default)]
    pub features: Vec<String>,
}

impl EntitlementDocument {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.protocol_version != 1 {
            return Err(ContractError::UnsupportedProtocolVersion(
                self.protocol_version,
            ));
        }
        validate_identifier(&self.entitlement_id, "entitlement_id")?;
        validate_identifier(&self.tenant_id, "tenant_id")?;
        validate_text(&self.issuer, "issuer", 160)?;
        let issued_at = parse_contract_timestamp(&self.issued_at, "issued_at")?;
        let valid_from = parse_contract_timestamp(&self.valid_from, "valid_from")?;
        let valid_until = parse_contract_timestamp(&self.valid_until, "valid_until")?;
        let grace_until = parse_contract_timestamp(&self.grace_until, "grace_until")?;
        if valid_until < valid_from || grace_until < valid_until || issued_at > grace_until {
            return Err(ContractError::InvalidTimestamp(
                "entitlement validity window".into(),
            ));
        }
        if self.features.len() > 128 {
            return Err(ContractError::InvalidObject("features".into()));
        }
        for feature in &self.features {
            validate_identifier(feature, "features")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEntitlement {
    pub document: EntitlementDocument,
    pub signing_key_id: String,
    pub signature_algorithm: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedContentDocument {
    pub protocol_version: u16,
    pub content_key: String,
    pub revision: u64,
    pub product: SaugraProduct,
    pub content_type: String,
    pub provenance: String,
    pub minimum_agent_version: String,
    pub schema_version: u32,
    pub published_at: String,
    pub expires_at: Option<String>,
    pub rollback_of: Option<String>,
    pub payload: Value,
}

impl ManagedContentDocument {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.protocol_version != 1 {
            return Err(ContractError::UnsupportedProtocolVersion(
                self.protocol_version,
            ));
        }
        validate_identifier(&self.content_key, "content_key")?;
        if self.revision == 0 || self.schema_version == 0 {
            return Err(ContractError::InvalidNumber("revision".into()));
        }
        if self.product == SaugraProduct::Relay {
            return Err(ContractError::InvalidIdentifier("product".into()));
        }
        if !matches!(
            self.content_type.as_str(),
            "rule_pack" | "threat_intelligence" | "behavior_profile" | "policy_template"
        ) {
            return Err(ContractError::InvalidIdentifier("content_type".into()));
        }
        validate_text(&self.provenance, "provenance", 500)?;
        validate_text(&self.minimum_agent_version, "minimum_agent_version", 80)?;
        let published_at = parse_contract_timestamp(&self.published_at, "published_at")?;
        if let Some(expires_at) = &self.expires_at {
            if parse_contract_timestamp(expires_at, "expires_at")? <= published_at {
                return Err(ContractError::InvalidTimestamp("expires_at".into()));
            }
        }
        if !self.payload.is_object() {
            return Err(ContractError::InvalidObject("payload".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedManagedContent {
    pub document: ManagedContentDocument,
    pub signing_key_id: String,
    pub signature_algorithm: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectivePolicyResponse {
    pub policy_key: String,
    pub revision: i64,
    pub stage: PolicyStage,
    pub pinned: bool,
    pub assignment_source: String,
    pub bundle: Value,
    pub signature: PolicyBundleSignature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseActionKind {
    KillProcess,
    QuarantineFile,
    IsolateHost,
    ReleaseHost,
    Rollback,
    WafBlockIp,
    WafAllowIp,
    WafRemoveRuntimeEntry,
}

impl ResponseActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KillProcess => "kill_process",
            Self::QuarantineFile => "quarantine_file",
            Self::IsolateHost => "isolate_host",
            Self::ReleaseHost => "release_host",
            Self::Rollback => "rollback",
            Self::WafBlockIp => "waf_block_ip",
            Self::WafAllowIp => "waf_allow_ip",
            Self::WafRemoveRuntimeEntry => "waf_remove_runtime_entry",
        }
    }

    pub fn capability(self) -> &'static str {
        match self {
            Self::KillProcess => "response.process.kill",
            Self::QuarantineFile => "response.file.quarantine",
            Self::IsolateHost => "response.host.isolate",
            Self::ReleaseHost => "response.host.release",
            Self::Rollback => "response.rollback",
            Self::WafBlockIp => "response.waf.ip.block",
            Self::WafAllowIp => "response.waf.ip.allow",
            Self::WafRemoveRuntimeEntry => "response.waf.runtime.remove",
        }
    }

    pub fn requires_second_approval(self) -> bool {
        matches!(
            self,
            Self::IsolateHost
                | Self::ReleaseHost
                | Self::Rollback
                | Self::WafAllowIp
                | Self::WafRemoveRuntimeEntry
        )
    }
}

impl std::str::FromStr for ResponseActionKind {
    type Err = ContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "kill_process" => Ok(Self::KillProcess),
            "quarantine_file" => Ok(Self::QuarantineFile),
            "isolate_host" => Ok(Self::IsolateHost),
            "release_host" => Ok(Self::ReleaseHost),
            "rollback" => Ok(Self::Rollback),
            "waf_block_ip" => Ok(Self::WafBlockIp),
            "waf_allow_ip" => Ok(Self::WafAllowIp),
            "waf_remove_runtime_entry" => Ok(Self::WafRemoveRuntimeEntry),
            _ => Err(ContractError::InvalidResponseAction),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseCommand {
    pub protocol_version: u16,
    pub request_id: String,
    pub idempotency_key: String,
    pub action: ResponseActionKind,
    pub target: Value,
    pub policy_mode: String,
    pub expires_at: String,
    pub rollback_guidance: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseCommandBatch {
    pub commands: Vec<ResponseCommand>,
    pub poll_after_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseResultRequest {
    pub protocol_version: u16,
    pub request_id: String,
    pub idempotency_key: String,
    pub outcome: String,
    pub message: String,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub rollback_guidance: Option<String>,
}

impl ResponseResultRequest {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.protocol_version != 1 {
            return Err(ContractError::UnsupportedProtocolVersion(
                self.protocol_version,
            ));
        }
        validate_identifier(&self.request_id, "request_id")?;
        validate_identifier(&self.idempotency_key, "idempotency_key")?;
        if !matches!(
            self.outcome.as_str(),
            "succeeded" | "failed" | "unsupported" | "monitor_only" | "rolled_back"
        ) {
            return Err(ContractError::InvalidResponseOutcome);
        }
        validate_text(&self.message, "message", 2000)?;
        if let Some(error) = &self.error {
            validate_text(error, "error", 2000)?;
        }
        if let Some(guidance) = &self.rollback_guidance {
            validate_text(guidance, "rollback_guidance", 4000)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseResultAcknowledgement {
    pub request_id: String,
    pub status: String,
    pub duplicate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayForwardRequest {
    pub protocol_version: u16,
    pub queue_id: String,
    pub sequence: u64,
    pub downstream: ManagedNodeRef,
    pub protocol_kind: String,
    pub deduplication_key: String,
    pub payload_sha256: String,
    pub payload: Value,
}

impl RelayForwardRequest {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.protocol_version != 1 {
            return Err(ContractError::UnsupportedProtocolVersion(
                self.protocol_version,
            ));
        }
        validate_identifier(&self.queue_id, "queue_id")?;
        if self.sequence == 0 {
            return Err(ContractError::InvalidNumber("sequence".into()));
        }
        validate_identifier(&self.downstream.node_id, "downstream.node_id")?;
        validate_identifier(&self.deduplication_key, "deduplication_key")?;
        if !matches!(
            self.protocol_kind.as_str(),
            "events" | "health" | "response_result"
        ) {
            return Err(ContractError::InvalidRelayProtocolKind);
        }
        if self.payload_sha256.len() != 64
            || !self
                .payload_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ContractError::InvalidText("payload_sha256".into()));
        }
        if !self.payload.is_object() {
            return Err(ContractError::InvalidObject("payload".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayForwardAcknowledgement {
    pub queue_id: String,
    pub status: String,
    pub duplicate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayQueueAcknowledgement {
    pub queue_id: String,
    pub sequence: u64,
    pub duplicate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayHealthRequest {
    pub protocol_version: u16,
    pub observed_at_unix_secs: u64,
    pub upstream_reachable: bool,
    pub upstream_queue_depth: u64,
    pub downstream_queue_depth: u64,
    pub oldest_queued_at: Option<String>,
    pub failed_items: u64,
    pub delivery_latency_ms: Option<u64>,
    #[serde(default)]
    pub detail: Value,
}

impl RelayHealthRequest {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.protocol_version != 1 {
            return Err(ContractError::UnsupportedProtocolVersion(
                self.protocol_version,
            ));
        }
        if match self.detail.as_object() {
            Some(value) => value.len() > 64,
            None => true,
        } {
            return Err(ContractError::InvalidObject("detail".into()));
        }
        if let Some(timestamp) = &self.oldest_queued_at {
            DateTime::parse_from_rfc3339(timestamp)
                .map_err(|_| ContractError::InvalidTimestamp("oldest_queued_at".into()))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayBundleManifest {
    pub protocol_version: u16,
    pub bundle_id: String,
    pub tenant_id: String,
    pub relay_node_id: String,
    pub created_at: String,
    pub expires_at: String,
    pub sequence_start: u64,
    pub sequence_end: u64,
    pub item_hashes: Vec<String>,
    pub signing_key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayBundle {
    pub manifest: RelayBundleManifest,
    pub items: Vec<RelayForwardRequest>,
    pub signature_algorithm: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ContractError {
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),
    #[error("deduplication_keys and records must have equal lengths")]
    MismatchedBatchLengths,
    #[error("batch contains {actual} records; maximum is {maximum}")]
    BatchTooLarge { actual: usize, maximum: usize },
    #[error("event batch must contain at least one record")]
    EmptyBatch,
    #[error("unsupported protocol version: {0}")]
    UnsupportedProtocolVersion(u16),
    #[error("invalid text field: {0}")]
    InvalidText(String),
    #[error("invalid object field: {0}")]
    InvalidObject(String),
    #[error("missing required field: {0}")]
    MissingField(String),
    #[error("invalid timestamp field: {0}")]
    InvalidTimestamp(String),
    #[error("invalid numeric field: {0}")]
    InvalidNumber(String),
    #[error("deduplication keys must be unique within a batch")]
    DuplicateDeduplicationKey,
    #[error("invalid response action")]
    InvalidResponseAction,
    #[error("invalid response outcome")]
    InvalidResponseOutcome,
    #[error("invalid relay protocol kind")]
    InvalidRelayProtocolKind,
}

fn validate_identifier(value: &str, field: &str) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ContractError::InvalidIdentifier(field.to_string()));
    }
    Ok(())
}

fn validate_text(value: &str, field: &str, maximum: usize) -> Result<(), ContractError> {
    if value.trim().is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(ContractError::InvalidText(field.to_string()));
    }
    Ok(())
}

fn parse_contract_timestamp(
    value: &str,
    field: &str,
) -> Result<DateTime<chrono::FixedOffset>, ContractError> {
    DateTime::parse_from_rfc3339(value)
        .map_err(|_| ContractError::InvalidTimestamp(field.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_batch_requires_one_key_per_record() {
        let request = EventIngestRequest {
            tenant_id: "tenant-a".to_string(),
            source: ManagedNodeRef {
                product: SaugraProduct::Edr,
                node_id: "endpoint-a".to_string(),
            },
            batch_id: "batch-a".to_string(),
            deduplication_keys: vec![],
            records: vec![serde_json::json!({"event_id": "event-a"})],
        };

        assert_eq!(
            request.validate(500),
            Err(ContractError::MismatchedBatchLengths)
        );
    }

    #[test]
    fn enrollment_supports_every_node_product() {
        for product in [
            SaugraProduct::Edr,
            SaugraProduct::Waf,
            SaugraProduct::Server,
            SaugraProduct::Relay,
        ] {
            let request = EnrollmentRequest {
                protocol_version: 1,
                product,
                external_id: "node-a".into(),
                display_name: "Node A".into(),
                platform: "linux".into(),
                agent_version: "0.1.0".into(),
                capabilities: serde_json::json!({}),
            };
            assert!(request.validate().is_ok());
        }
    }

    #[test]
    fn commercial_documents_validate_bounded_offline_contracts() {
        let entitlement = EntitlementDocument {
            protocol_version: 1,
            entitlement_id: "enterprise-2026".into(),
            tenant_id: "11111111-1111-1111-1111-111111111111".into(),
            issuer: "Saugra".into(),
            issued_at: "2026-01-01T00:00:00Z".into(),
            valid_from: "2026-01-01T00:00:00Z".into(),
            valid_until: "2027-01-01T00:00:00Z".into(),
            grace_until: "2027-02-01T00:00:00Z".into(),
            protected_node_limit: Some(1000),
            managed_content: true,
            features: vec!["offline_updates".into()],
        };
        assert!(entitlement.validate().is_ok());
        let mut invalid = entitlement.clone();
        invalid.grace_until = "2026-12-01T00:00:00Z".into();
        assert!(invalid.validate().is_err());

        let content = ManagedContentDocument {
            protocol_version: 1,
            content_key: "emergency-indicators".into(),
            revision: 1,
            product: SaugraProduct::Edr,
            content_type: "threat_intelligence".into(),
            provenance: "Saugra threat research".into(),
            minimum_agent_version: "0.1.0".into(),
            schema_version: 1,
            published_at: "2026-01-01T00:00:00Z".into(),
            expires_at: Some("2026-02-01T00:00:00Z".into()),
            rollback_of: None,
            payload: serde_json::json!({"indicators":[]}),
        };
        assert!(content.validate().is_ok());
    }

    #[test]
    fn event_batch_requires_unique_keys_and_normalizable_records() {
        let mut request = EventIngestRequest {
            tenant_id: "tenant-a".into(),
            source: ManagedNodeRef {
                product: SaugraProduct::Edr,
                node_id: "node-a".into(),
            },
            batch_id: "batch-a".into(),
            deduplication_keys: vec!["event-a".into(), "event-a".into()],
            records: vec![
                serde_json::json!({
                    "event_family": "process",
                    "occurred_at": "2026-06-21T12:00:00Z"
                }),
                serde_json::json!({
                    "event_family": "process",
                    "occurred_at": "2026-06-21T12:00:01Z"
                }),
            ],
        };
        assert_eq!(
            request.validate(500),
            Err(ContractError::DuplicateDeduplicationKey)
        );
        request.deduplication_keys[1] = "event-b".into();
        assert!(request.validate(500).is_ok());
        request.records[1] = serde_json::json!({"event_family": "process"});
        assert_eq!(
            request.validate(500),
            Err(ContractError::MissingField("occurred_at".into()))
        );
    }

    #[test]
    fn heartbeat_inventory_is_bounded_and_structured() {
        let request = HeartbeatRequest {
            tenant_id: "tenant-a".into(),
            node: ManagedNodeRef {
                product: SaugraProduct::Edr,
                node_id: "node-a".into(),
            },
            observed_at_unix_secs: 1,
            health_status: "healthy".into(),
            endpoint_inventory: Some(serde_json::json!({"packages": 42})),
            ransomware_alerts: vec![serde_json::json!({"rule": "canary"})],
        };
        assert!(request.validate().is_ok());
    }

    #[test]
    fn response_results_are_versioned_and_bounded() {
        let valid = ResponseResultRequest {
            protocol_version: 1,
            request_id: "2f175f4e-2745-48b4-85b8-f647c3447816".into(),
            idempotency_key: "response-123".into(),
            outcome: "succeeded".into(),
            message: "process terminated".into(),
            error: None,
            rollback_guidance: Some("restart only after validation".into()),
        };
        assert!(valid.validate().is_ok());
        let mut invalid = valid;
        invalid.outcome = "executed_anyway".into();
        assert_eq!(
            invalid.validate(),
            Err(ContractError::InvalidResponseOutcome)
        );
    }

    #[test]
    fn relay_forwarding_requires_versioned_hashed_payloads() {
        let request = RelayForwardRequest {
            protocol_version: 1,
            queue_id: "2f175f4e-2745-48b4-85b8-f647c3447816".into(),
            sequence: 1,
            downstream: ManagedNodeRef {
                product: SaugraProduct::Edr,
                node_id: "77cdffb0-18ab-4334-a4a1-808141bbcc96".into(),
            },
            protocol_kind: "events".into(),
            deduplication_key: "batch-a".into(),
            payload_sha256: "a".repeat(64),
            payload: serde_json::json!({"batch_id": "batch-a"}),
        };
        assert!(request.validate().is_ok());
    }
}
