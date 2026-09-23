use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::SaugraConfig;

mod client;
mod outbox;
mod policy;
#[cfg(test)]
mod tests;

pub use client::{
    authenticated, console_endpoint, enroll_with_console, enrollment_request,
    execute_response_command, rule_inventory, start_telemetry, sync_effective_policy,
    terminal_acknowledgement_keys, verify_effective_policy,
};
pub use outbox::{ConsoleCredential, ConsoleCredentialStore, ConsoleOutbox};
pub use policy::{parse_managed_mode, ManagedPolicyHandle, PolicyTransition};

pub const CONSOLE_PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Serialize, Deserialize)]
pub struct EmergencyOverride {
    pub enabled_at_unix_secs: u64,
    pub reason: String,
}

pub fn emergency_override(config: &SaugraConfig) -> Result<Option<EmergencyOverride>> {
    let path = config
        .console
        .emergency_override_path(&config.logging.event_log_path);
    if !path.exists() {
        return Ok(None);
    }
    serde_json::from_slice(&fs::read(&path)?)
        .context("invalid Console emergency override file")
        .map(Some)
}

pub fn enable_emergency_override(config: &SaugraConfig, reason: &str) -> Result<()> {
    let reason = reason.trim();
    if reason.is_empty() || reason.len() > 500 {
        bail!("emergency override reason must contain 1-500 characters");
    }
    let path = config
        .console
        .emergency_override_path(&config.logging.event_log_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    fs::write(
        &temporary,
        serde_json::to_vec_pretty(&EmergencyOverride {
            enabled_at_unix_secs: now_unix_secs(),
            reason: reason.to_string(),
        })?,
    )?;
    protect_file(&temporary)?;
    fs::rename(temporary, path)?;
    Ok(())
}

pub fn disable_emergency_override(config: &SaugraConfig) -> Result<bool> {
    let path = config
        .console
        .emergency_override_path(&config.logging.event_log_path);
    if !path.exists() {
        return Ok(false);
    }
    fs::remove_file(path)?;
    Ok(true)
}

pub(crate) fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn protect_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
