use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::ErrorKind,
    path::{Path, PathBuf},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct UnknownThreatState {
    pub routes: BTreeMap<String, RouteBaseline>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct RouteBaseline {
    pub observations: u64,
    pub first_observed_at: u64,
    pub last_observed_at: u64,
    pub methods: BTreeSet<String>,
    pub pending_methods: BTreeMap<String, u64>,
    pub content_types: BTreeSet<String>,
    pub pending_content_types: BTreeMap<String, u64>,
    pub query_parameters: BTreeSet<String>,
    pub pending_query_parameters: BTreeMap<String, u64>,
    pub maximum_body_size: usize,
    pub pending_body_size_buckets: BTreeMap<usize, u64>,
}

pub fn read_state(path: &Path) -> anyhow::Result<UnknownThreatState> {
    if !path.exists() {
        return Ok(UnknownThreatState::default());
    }
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read unknown-threat state {}", path.display()))?;
    serde_json::from_str(&contents).with_context(|| {
        format!(
            "unknown-threat state is not valid JSON at {}",
            path.display()
        )
    })
}

pub fn write_state(path: &Path, state: &UnknownThreatState) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create unknown-threat state directory {}",
                parent.display()
            )
        })?;
    }
    let temporary_path = temporary_state_path(path);
    fs::write(&temporary_path, serde_json::to_vec_pretty(state)?).with_context(|| {
        format!(
            "failed to write temporary unknown-threat state {}",
            temporary_path.display()
        )
    })?;
    if let Err(error) = fs::rename(&temporary_path, path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error)
            .with_context(|| format!("failed to replace unknown-threat state {}", path.display()));
    }
    Ok(())
}

pub struct StateFileLock {
    path: PathBuf,
}

impl StateFileLock {
    pub fn acquire(state_path: &Path) -> anyhow::Result<Self> {
        let path = lock_path(state_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create unknown-threat lock directory {}",
                    parent.display()
                )
            })?;
        }

        for _ in 0..1_000 {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(_) => return Ok(Self { path }),
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                    if lock_is_stale(&path) {
                        match fs::remove_file(&path) {
                            Ok(()) => continue,
                            Err(error) if error.kind() == ErrorKind::NotFound => continue,
                            Err(_) => {}
                        }
                    }
                    thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => return Err(error.into()),
            }
        }

        Err(anyhow::anyhow!(
            "timed out waiting for unknown-threat state lock {}",
            path.display()
        ))
    }
}

impl Drop for StateFileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn lock_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.lock", path.display()))
}

fn lock_is_stale(path: &Path) -> bool {
    path.metadata()
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
        .is_some_and(|age| age.as_secs() >= 30)
}

fn temporary_state_path(path: &Path) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    PathBuf::from(format!("{}.{}.tmp", path.display(), nonce))
}

pub fn parse_duration_seconds(value: &str) -> Option<u64> {
    let trimmed = value.trim().to_ascii_lowercase();
    let split_at = trimmed.find(|character: char| !character.is_ascii_digit())?;
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

pub fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
