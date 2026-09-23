use anyhow::{bail, Context, Result};
use reqwest::Client;
use saugra_console_contracts::{
    ResponseActionKind, ResponseCommand, ResponseCommandBatch, ResponseResultAcknowledgement,
    ResponseResultRequest,
};

use crate::{config::SaugraConfig, runtime_policy};

use super::{authenticated, console_endpoint, ConsoleCredential, CONSOLE_PROTOCOL_VERSION};

pub fn execute_response_command(
    config: &SaugraConfig,
    command: &ResponseCommand,
) -> ResponseResultRequest {
    let result = || -> Result<String> {
        if !config.runtime_policy.enabled {
            bail!("runtime policy is disabled")
        }
        let expires_at = chrono::DateTime::parse_from_rfc3339(&command.expires_at)
            .context("invalid response command expiry")?;
        if expires_at <= chrono::Utc::now() {
            bail!("response command expired")
        }
        match command.action {
            ResponseActionKind::WafBlockIp | ResponseActionKind::WafAllowIp => {
                let value = command.target["value"]
                    .as_str()
                    .context("missing IP target")?;
                let duration = command.target["duration_seconds"]
                    .as_u64()
                    .filter(|value| (60..=2_592_000).contains(value))
                    .context("invalid response duration")?;
                runtime_policy::upsert_console_ip_entry(
                    &config.runtime_policy.path,
                    &command.request_id,
                    value,
                    duration,
                    "Console-managed bounded response",
                    command.action == ResponseActionKind::WafBlockIp,
                )?;
                Ok(format!("runtime entry {} applied", command.request_id))
            }
            ResponseActionKind::WafRemoveRuntimeEntry => {
                let entry_id = command.target["entry_id"]
                    .as_str()
                    .context("missing entry id")?;
                runtime_policy::remove_entry(&config.runtime_policy.path, entry_id)?;
                Ok(format!("runtime entry {entry_id} is absent"))
            }
            _ => bail!("response action is not supported by Saugra WAF"),
        }
    }();
    let (outcome, message, error) = match result {
        Ok(message) => ("succeeded", message, None),
        Err(error)
            if error.to_string().contains("not supported")
                || error.to_string().contains("disabled") =>
        {
            (
                "unsupported",
                "command was not executed".to_string(),
                Some(error.to_string()),
            )
        }
        Err(error) => (
            "failed",
            "command was not executed".to_string(),
            Some(error.to_string()),
        ),
    };
    ResponseResultRequest {
        protocol_version: CONSOLE_PROTOCOL_VERSION,
        request_id: command.request_id.clone(),
        idempotency_key: command.idempotency_key.clone(),
        outcome: outcome.to_string(),
        message,
        error,
        rollback_guidance: Some(command.rollback_guidance.clone()),
    }
}

pub async fn process_response_commands(
    client: &Client,
    base: &str,
    credential: &ConsoleCredential,
    config: &SaugraConfig,
) -> Result<usize> {
    let response = authenticated(
        client.get(console_endpoint(
            config,
            base,
            "responses/commands?limit=10",
        )?),
        credential,
    )
    .send()
    .await?;
    let status = response.status();
    let body = response.bytes().await?;
    if !status.is_success() {
        bail!("Console response poll failed with HTTP {status}")
    }
    let batch: ResponseCommandBatch =
        serde_json::from_slice(&body).context("invalid Console response batch")?;
    for command in &batch.commands {
        let result = execute_response_command(config, command);
        result.validate().context("invalid local response result")?;
        let response = authenticated(
            client.post(console_endpoint(config, base, "responses/results")?),
            credential,
        )
        .json(&result)
        .send()
        .await?;
        let status = response.status();
        let body = response.bytes().await?;
        if !status.is_success() {
            bail!("Console response result failed with HTTP {status}")
        }
        let acknowledgement: ResponseResultAcknowledgement = serde_json::from_slice(&body)?;
        if acknowledgement.request_id != command.request_id {
            bail!("Console response acknowledgement mismatch")
        }
    }
    Ok(batch.commands.len())
}
