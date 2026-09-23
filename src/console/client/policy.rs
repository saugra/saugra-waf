use std::fs;

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use reqwest::Client;
use saugra_console_contracts::EffectivePolicyResponse;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::{
    config::{RuleExclusionConfig, SaugraConfig},
    rules,
};

use super::{
    authenticated, console_endpoint, deliver_batch, emergency_override, parse_managed_mode,
    process_response_commands, protect_file, rule_inventory, send_heartbeat, ConsoleCredential,
    ConsoleCredentialStore, ConsoleOutbox, ManagedPolicyHandle,
};

pub fn verify_effective_policy(
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
    let policy = response.bundle.get("policy").unwrap_or(&Value::Null);
    if let Some(mode) = policy.get("mode").and_then(Value::as_str) {
        validation.server.mode =
            parse_managed_mode(mode).context("Console policy contains an invalid WAF mode")?;
    }
    if let Some(value) = policy.get("anomaly_threshold").and_then(Value::as_u64) {
        validation.rules.inbound_anomaly_threshold =
            u16::try_from(value).context("Console anomaly threshold exceeds supported range")?;
    }
    if let Some(value) = policy
        .get("detection_paranoia_level")
        .and_then(Value::as_u64)
    {
        let value =
            u8::try_from(value).context("Console detection paranoia exceeds supported range")?;
        if value > config.rules.detection_paranoia_level() {
            bail!("Console policy cannot enable rules above the locally loaded detection paranoia level");
        }
        validation.rules.detection_paranoia_level = Some(value);
    }
    if let Some(value) = policy
        .get("blocking_paranoia_level")
        .and_then(Value::as_u64)
    {
        validation.rules.blocking_paranoia_level =
            Some(u8::try_from(value).context("Console blocking paranoia exceeds supported range")?);
    }
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

pub fn persist_effective_policy(
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

pub fn load_cached_policy(
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

pub async fn fetch_effective_policy(
    client: &Client,
    base: &str,
    credential: &ConsoleCredential,
    config: &SaugraConfig,
    managed_policy: &ManagedPolicyHandle,
) -> Result<Option<(String, i64, usize)>> {
    managed_policy.record_lifecycle("resolving", None);
    let response = authenticated(
        client.get(console_endpoint(config, base, "policy/effective")?),
        credential,
    )
    .send()
    .await
    .context("failed to fetch effective Console policy")?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        managed_policy.record_lifecycle(
            "resolved",
            Some("no managed policy is currently assigned; retaining local or last-known-good protection".to_string()),
        );
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
    managed_policy.record_policy_lifecycle(&response, "downloaded", None);
    let exclusions = verify_effective_policy(&response, credential, config)?;
    persist_effective_policy(config, &response)?;
    let count = exclusions.len();
    if let Some(override_state) = emergency_override(config)? {
        managed_policy.activate_emergency_override(override_state.reason);
        return Ok(Some((response.policy_key, response.revision, 0)));
    }
    managed_policy.activate_verified(&response, exclusions);
    Ok(Some((response.policy_key, response.revision, count)))
}

pub async fn sync_effective_policy(
    client: &Client,
    base: &str,
    credential: &ConsoleCredential,
    config: &SaugraConfig,
    managed_policy: &ManagedPolicyHandle,
) -> Result<Option<(String, i64, usize)>> {
    if let Some(override_state) = emergency_override(config)? {
        managed_policy.activate_emergency_override(override_state.reason);
        return Ok(None);
    }
    fetch_effective_policy(client, base, credential, config, managed_policy).await
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
        let local_override = emergency_override(config)?;
        if let Some(override_state) = local_override.as_ref() {
            managed_policy.activate_emergency_override(override_state.reason.clone());
            warn!("Console managed policy is suspended by the local emergency override");
        }
        match load_cached_policy(config, &credential) {
            Ok(Some((response, exclusions))) => {
                if local_override.is_none() {
                    let count = exclusions.len();
                    managed_policy.activate_verified(&response, exclusions);
                    info!(policy_key = %response.policy_key, revision = response.revision, exclusions = count, "verified cached Console WAF policy activated");
                }
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
        let mut responses = tokio::time::interval(std::time::Duration::from_secs(15));
        loop {
            tokio::select! {
                _ = heartbeats.tick() => match send_heartbeat(&client, &base, &credential, &heartbeat_config, &managed_policy).await {
                    Ok(()) => info!(node_id = %credential.node_id, "Console heartbeat acknowledged"),
                    Err(error) => warn!(%error, "Console heartbeat failed; local WAF protection remains active"),
                },
                _ = deliveries.tick() => match deliver_batch(&client, &base, &heartbeat_config, &credential, &outbox, batch_size).await {
                    Ok(count) if count > 0 => info!(count, "Console WAF events acknowledged"),
                    Ok(_) => {},
                    Err(error) => warn!(%error, "Console event delivery failed; events remain in the durable outbox"),
                },
                _ = policies.tick(), if policy_enabled => match sync_effective_policy(&client, &base, &credential, &policy_config, &managed_policy).await {
                    Ok(Some((policy_key, revision, exclusions))) => info!(%policy_key, revision, exclusions, "verified Console WAF policy activated"),
                    Ok(None) => {},
                    Err(error) => {
                        managed_policy.record_lifecycle("rejected", Some(error.to_string()));
                        warn!(%error, "Console WAF policy rejected; last-known-good policy remains active");
                    },
                },
                _ = responses.tick() => match process_response_commands(&client, &base, &credential, &heartbeat_config).await {
                    Ok(count) if count > 0 => info!(count, "Console WAF response commands acknowledged"),
                    Ok(_) => {},
                    Err(error) => warn!(%error, "Console WAF response processing failed; commands remain retryable"),
                },
            }
        }
    }))
}
