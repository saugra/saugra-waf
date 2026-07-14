use std::{
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::{RuntimeAllowlistEffect, RuntimePolicyConfig};

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct RuntimePolicy {
    #[serde(default = "default_version")]
    pub version: u8,
    #[serde(default)]
    pub allowlisted_ips: Vec<RuntimeAllowlistEntry>,
    #[serde(default)]
    pub blocklisted_ips: Vec<RuntimeAllowlistEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuntimeAllowlistEntry {
    pub id: String,
    pub value: String,
    pub reason: String,
    pub created_by: String,
    pub created_at_unix_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix_seconds: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct RuntimeAllowlistMatch {
    pub id: String,
    #[serde(rename = "type")]
    pub match_type: String,
    pub value: String,
    pub effect: RuntimeAllowlistEffect,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix_seconds: Option<u64>,
}

#[derive(Debug)]
pub struct RuntimePolicyHandle {
    config: RuntimePolicyConfig,
    state: Mutex<RuntimePolicyState>,
}

#[derive(Debug)]
struct RuntimePolicyState {
    policy: RuntimePolicy,
    last_loaded_metadata: Option<FileMetadata>,
    last_checked: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileMetadata {
    modified_unix_seconds: u64,
    len: u64,
}

impl RuntimePolicyHandle {
    pub fn open(config: RuntimePolicyConfig) -> Self {
        let policy = read_policy(&config.path).unwrap_or_default();
        let metadata = file_metadata(&config.path);

        Self {
            config,
            state: Mutex::new(RuntimePolicyState {
                policy,
                last_loaded_metadata: metadata,
                last_checked: Instant::now(),
            }),
        }
    }

    pub fn match_ip(&self, client_ip: &str) -> Option<RuntimeAllowlistMatch> {
        if !self.config.enabled {
            return None;
        }

        self.reload_if_needed();

        let now = unix_seconds_now();
        let ip = client_ip.parse::<Ipv4Addr>().ok()?;
        let state = self.state.lock().ok()?;

        state
            .policy
            .allowlisted_ips
            .iter()
            .find(|entry| !entry_is_expired(entry, now) && ip_matches_entry(ip, entry.value.trim()))
            .map(|entry| RuntimeAllowlistMatch {
                id: entry.id.clone(),
                match_type: "ip".to_string(),
                value: entry.value.clone(),
                effect: self.config.allowlist_effect,
                reason: entry.reason.clone(),
                expires_at_unix_seconds: entry.expires_at_unix_seconds,
            })
    }

    fn reload_if_needed(&self) {
        let reload_interval = Duration::from_secs(self.config.reload_interval_seconds());
        let Ok(mut state) = self.state.lock() else {
            return;
        };

        if state.last_checked.elapsed() < reload_interval {
            return;
        }

        state.last_checked = Instant::now();
        let metadata = file_metadata(&self.config.path);
        if metadata == state.last_loaded_metadata {
            return;
        }

        match read_policy(&self.config.path) {
            Ok(policy) => {
                state.policy = policy;
                state.last_loaded_metadata = metadata;
            }
            Err(error) => {
                tracing::warn!(
                    path = %self.config.path.display(),
                    %error,
                    "failed to reload runtime policy; keeping last known good policy"
                );
            }
        }
    }

    pub fn match_blocked_ip(&self, client_ip: &str) -> Option<RuntimeAllowlistMatch> {
        if !self.config.enabled {
            return None;
        }

        self.reload_if_needed();

        let now = unix_seconds_now();
        let ip = client_ip.parse::<Ipv4Addr>().ok()?;
        let state = self.state.lock().ok()?;

        state
            .policy
            .blocklisted_ips
            .iter()
            .find(|entry| !entry_is_expired(entry, now) && ip_matches_entry(ip, entry.value.trim()))
            .map(|entry| RuntimeAllowlistMatch {
                id: entry.id.clone(),
                match_type: "blocklist".to_string(),
                value: entry.value.clone(),
                effect: RuntimeAllowlistEffect::Block,
                reason: entry.reason.clone(),
                expires_at_unix_seconds: entry.expires_at_unix_seconds,
            })
    }
}

pub fn add_ip_entry(
    path: &Path,
    value: &str,
    duration_seconds: Option<u64>,
    reason: &str,
    created_by: &str,
) -> anyhow::Result<RuntimeAllowlistEntry> {
    validate_ip_or_cidr(value)?;
    let mut policy = read_policy(path).unwrap_or_default();
    let now = unix_seconds_now();
    let entry = RuntimeAllowlistEntry {
        id: Uuid::new_v4().to_string(),
        value: normalize_ip_value(value),
        reason: reason.trim().to_string(),
        created_by: created_by.trim().to_string(),
        created_at_unix_seconds: now,
        expires_at_unix_seconds: duration_seconds.map(|duration| now.saturating_add(duration)),
    };
    policy.allowlisted_ips.push(entry.clone());
    write_policy_atomic(path, &policy)?;
    Ok(entry)
}

pub fn add_block_ip_entry(
    path: &Path,
    value: &str,
    duration_seconds: Option<u64>,
    reason: &str,
    created_by: &str,
) -> anyhow::Result<RuntimeAllowlistEntry> {
    validate_ip_or_cidr(value)?;
    let mut policy = read_policy(path).unwrap_or_default();
    let now = unix_seconds_now();
    let entry = RuntimeAllowlistEntry {
        id: Uuid::new_v4().to_string(),
        value: normalize_ip_value(value),
        reason: reason.trim().to_string(),
        created_by: created_by.trim().to_string(),
        created_at_unix_seconds: now,
        expires_at_unix_seconds: duration_seconds.map(|duration| now.saturating_add(duration)),
    };
    policy.blocklisted_ips.push(entry.clone());
    write_policy_atomic(path, &policy)?;
    Ok(entry)
}

pub fn upsert_console_ip_entry(
    path: &Path,
    id: &str,
    value: &str,
    duration_seconds: u64,
    reason: &str,
    block: bool,
) -> anyhow::Result<RuntimeAllowlistEntry> {
    Uuid::parse_str(id).context("Console runtime entry id must be a UUID")?;
    validate_ip_or_cidr(value)?;
    let mut policy = read_policy(path).unwrap_or_default();
    policy.allowlisted_ips.retain(|entry| entry.id != id);
    policy.blocklisted_ips.retain(|entry| entry.id != id);
    let now = unix_seconds_now();
    let entry = RuntimeAllowlistEntry {
        id: id.to_string(),
        value: normalize_ip_value(value),
        reason: reason.trim().to_string(),
        created_by: "saugra-console".to_string(),
        created_at_unix_seconds: now,
        expires_at_unix_seconds: Some(now.saturating_add(duration_seconds)),
    };
    if block {
        policy.blocklisted_ips.push(entry.clone());
    } else {
        policy.allowlisted_ips.push(entry.clone());
    }
    write_policy_atomic(path, &policy)?;
    Ok(entry)
}

pub fn remove_entry(path: &Path, id: &str) -> anyhow::Result<bool> {
    let mut policy = read_policy(path).unwrap_or_default();
    let before = policy.allowlisted_ips.len() + policy.blocklisted_ips.len();
    policy.allowlisted_ips.retain(|entry| entry.id != id);
    policy.blocklisted_ips.retain(|entry| entry.id != id);
    let after = policy.allowlisted_ips.len() + policy.blocklisted_ips.len();
    let removed = after != before;
    write_policy_atomic(path, &policy)?;
    Ok(removed)
}

pub fn prune_expired(path: &Path) -> anyhow::Result<usize> {
    let mut policy = read_policy(path).unwrap_or_default();
    let now = unix_seconds_now();
    let before = policy.allowlisted_ips.len() + policy.blocklisted_ips.len();
    policy
        .allowlisted_ips
        .retain(|entry| !entry_is_expired(entry, now));
    policy
        .blocklisted_ips
        .retain(|entry| !entry_is_expired(entry, now));
    let after = policy.allowlisted_ips.len() + policy.blocklisted_ips.len();
    let pruned = before.saturating_sub(after);
    write_policy_atomic(path, &policy)?;
    Ok(pruned)
}

pub fn list_policy(path: &Path) -> anyhow::Result<RuntimePolicy> {
    read_policy(path).or_else(|error| {
        if error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_error| io_error.kind() == std::io::ErrorKind::NotFound)
        {
            Ok(RuntimePolicy::default())
        } else {
            Err(error)
        }
    })
}

pub fn parse_duration_seconds(value: &str) -> Option<u64> {
    let trimmed = value.trim().to_ascii_lowercase();
    let split_at = trimmed.find(|c: char| !c.is_ascii_digit())?;
    let (number, unit) = trimmed.split_at(split_at);
    let number = number.parse::<u64>().ok()?;
    if number == 0 {
        return None;
    }

    let multiplier = match unit.trim() {
        "s" | "sec" | "secs" | "second" | "seconds" => 1,
        "m" | "min" | "mins" | "minute" | "minutes" => 60,
        "h" | "hr" | "hrs" | "hour" | "hours" => 60 * 60,
        "d" | "day" | "days" => 24 * 60 * 60,
        _ => return None,
    };

    number.checked_mul(multiplier)
}

fn read_policy(path: &Path) -> anyhow::Result<RuntimePolicy> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).context("runtime policy is not valid JSON")
}

fn write_policy_atomic(path: &Path, policy: &RuntimePolicy) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let tmp_path = temp_path(path);
    let bytes = serde_json::to_vec_pretty(policy)?;
    fs::write(&tmp_path, bytes)?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

fn temp_path(path: &Path) -> PathBuf {
    let mut file_name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| "runtime-policy.json".into());
    file_name.push(format!(".{}.tmp", Uuid::new_v4()));
    path.with_file_name(file_name)
}

fn file_metadata(path: &Path) -> Option<FileMetadata> {
    let metadata = fs::metadata(path).ok()?;
    let modified_unix_seconds = metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs())
        .unwrap_or_default();

    Some(FileMetadata {
        modified_unix_seconds,
        len: metadata.len(),
    })
}

fn validate_ip_or_cidr(value: &str) -> anyhow::Result<()> {
    let value = value.trim();
    if let Some((ip, prefix)) = value.split_once('/') {
        ip.parse::<Ipv4Addr>()
            .with_context(|| format!("invalid IPv4 CIDR address: {value}"))?;
        let prefix = prefix
            .parse::<u8>()
            .with_context(|| format!("invalid IPv4 CIDR prefix: {value}"))?;
        if prefix > 32 {
            anyhow::bail!("invalid IPv4 CIDR prefix: {value}");
        }
        return Ok(());
    }

    value
        .parse::<Ipv4Addr>()
        .with_context(|| format!("invalid IPv4 address: {value}"))?;
    Ok(())
}

fn normalize_ip_value(value: &str) -> String {
    let value = value.trim();
    if value.contains('/') {
        value.to_string()
    } else {
        format!("{value}/32")
    }
}

fn ip_matches_entry(ip: Ipv4Addr, entry: &str) -> bool {
    let Some((network, prefix)) = entry.split_once('/') else {
        return entry
            .parse::<Ipv4Addr>()
            .is_ok_and(|entry_ip| entry_ip == ip);
    };
    let Ok(network) = network.parse::<Ipv4Addr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    if prefix > 32 {
        return false;
    }

    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    u32::from(ip) & mask == u32::from(network) & mask
}

fn entry_is_expired(entry: &RuntimeAllowlistEntry, now: u64) -> bool {
    entry
        .expires_at_unix_seconds
        .is_some_and(|expires_at| expires_at <= now)
}

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn default_version() -> u8 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn cidr_matches_ip_inside_range() {
        assert!(ip_matches_entry(
            "203.0.113.10".parse().unwrap(),
            "203.0.113.0/24"
        ));
        assert!(!ip_matches_entry(
            "203.0.114.10".parse().unwrap(),
            "203.0.113.0/24"
        ));
    }

    #[test]
    fn add_and_remove_entry_updates_policy_file() {
        let file = NamedTempFile::new().unwrap();
        let entry = add_ip_entry(
            file.path(),
            "203.0.113.10",
            Some(60),
            "admin testing",
            "test",
        )
        .unwrap();

        let policy = list_policy(file.path()).unwrap();
        assert_eq!(policy.allowlisted_ips.len(), 1);
        assert_eq!(policy.allowlisted_ips[0].value, "203.0.113.10/32");

        assert!(remove_entry(file.path(), &entry.id).unwrap());
        let policy = list_policy(file.path()).unwrap();
        assert!(policy.allowlisted_ips.is_empty());
    }

    #[test]
    fn expired_entries_do_not_match() {
        let handle = RuntimePolicyHandle {
            config: RuntimePolicyConfig::default(),
            state: Mutex::new(RuntimePolicyState {
                policy: RuntimePolicy {
                    version: 1,
                    allowlisted_ips: vec![RuntimeAllowlistEntry {
                        id: "expired".to_string(),
                        value: "203.0.113.10/32".to_string(),
                        reason: "expired".to_string(),
                        created_by: "test".to_string(),
                        created_at_unix_seconds: 1,
                        expires_at_unix_seconds: Some(1),
                    }],
                    blocklisted_ips: Vec::new(),
                },
                last_loaded_metadata: None,
                last_checked: Instant::now(),
            }),
        };

        assert!(handle.match_ip("203.0.113.10").is_none());
    }

    #[test]
    fn malformed_reload_keeps_last_known_good_policy() {
        let file = NamedTempFile::new().unwrap();
        add_ip_entry(
            file.path(),
            "198.51.100.25",
            Some(60),
            "rollout safety",
            "test",
        )
        .unwrap();
        let handle = RuntimePolicyHandle::open(RuntimePolicyConfig {
            enabled: true,
            path: file.path().to_path_buf(),
            reload_interval: "1s".to_string(),
            ..RuntimePolicyConfig::default()
        });

        assert!(handle.match_ip("198.51.100.25").is_some());

        fs::write(file.path(), b"{not-valid-json").unwrap();
        {
            let mut state = handle.state.lock().unwrap();
            state.last_checked = Instant::now() - Duration::from_secs(2);
        }

        let runtime_match = handle.match_ip("198.51.100.25").unwrap();

        assert_eq!(runtime_match.value, "198.51.100.25/32");
        assert_eq!(runtime_match.reason, "rollout safety");
    }
}
