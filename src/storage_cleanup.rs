use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::config::{SaugraConfig, StorageCleanupTargetConfig};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageCleanupReport {
    pub dry_run: bool,
    pub scanned_targets: usize,
    pub matched_files: usize,
    pub removed_files: usize,
    pub skipped_files: usize,
    pub freed_bytes: u64,
    pub files: Vec<StorageCleanupFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageCleanupFile {
    pub target: String,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub age_seconds: u64,
    pub action: StorageCleanupAction,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StorageCleanupAction {
    WouldRemove,
    Removed,
    Skipped,
}

pub fn run_from_config(
    config: &SaugraConfig,
    dry_run_override: Option<bool>,
) -> anyhow::Result<StorageCleanupReport> {
    let dry_run = dry_run_override.unwrap_or(config.storage_cleanup.dry_run);
    run(&config.storage_cleanup.targets, dry_run, unix_seconds_now())
}

pub fn run(
    targets: &[StorageCleanupTargetConfig],
    dry_run: bool,
    now: u64,
) -> anyhow::Result<StorageCleanupReport> {
    let mut report = StorageCleanupReport {
        dry_run,
        scanned_targets: targets.len(),
        matched_files: 0,
        removed_files: 0,
        skipped_files: 0,
        freed_bytes: 0,
        files: Vec::new(),
    };

    for target in targets {
        scan_target(target, dry_run, now, &mut report)?;
    }

    Ok(report)
}

fn scan_target(
    target: &StorageCleanupTargetConfig,
    dry_run: bool,
    now: u64,
    report: &mut StorageCleanupReport,
) -> anyhow::Result<()> {
    let older_than_seconds = parse_duration_seconds(&target.older_than).unwrap_or(30 * 86_400);
    let cutoff = now.saturating_sub(older_than_seconds);
    let entries = match fs::read_dir(&target.directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() {
            continue;
        }

        let Some(file_name) = path.file_name().and_then(|file_name| file_name.to_str()) else {
            continue;
        };
        if !matches_target(file_name, target) {
            continue;
        }

        report.matched_files += 1;
        let modified = metadata
            .modified()
            .ok()
            .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs())
            .unwrap_or(now);
        let age_seconds = now.saturating_sub(modified);
        let size_bytes = metadata.len();
        let is_stale = modified <= cutoff;

        if !is_stale {
            report.skipped_files += 1;
            report.files.push(StorageCleanupFile {
                target: target.name.clone(),
                path,
                size_bytes,
                age_seconds,
                action: StorageCleanupAction::Skipped,
            });
            continue;
        }

        let action = if dry_run {
            StorageCleanupAction::WouldRemove
        } else {
            fs::remove_file(&path)?;
            report.removed_files += 1;
            report.freed_bytes = report.freed_bytes.saturating_add(size_bytes);
            StorageCleanupAction::Removed
        };

        report.files.push(StorageCleanupFile {
            target: target.name.clone(),
            path,
            size_bytes,
            age_seconds,
            action,
        });
    }

    Ok(())
}

fn matches_target(file_name: &str, target: &StorageCleanupTargetConfig) -> bool {
    let prefix_matches = target
        .filename_prefix
        .as_deref()
        .map(|prefix| file_name.starts_with(prefix))
        .unwrap_or(true);
    let suffix_matches = target
        .filename_suffix
        .as_deref()
        .map(|suffix| file_name.ends_with(suffix))
        .unwrap_or(true);

    prefix_matches && suffix_matches
}

fn parse_duration_seconds(value: &str) -> Option<u64> {
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

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{path::Path, thread, time::Duration};

    #[test]
    fn dry_run_reports_stale_matching_files_without_deleting() {
        let temp_dir = tempfile::tempdir().unwrap();
        let stale = temp_dir
            .path()
            .join("saugra-security-summary-2026-05-01.json");
        fs::write(&stale, b"summary").unwrap();
        thread::sleep(Duration::from_secs(2));
        let target = test_target(temp_dir.path(), "1s");

        let report = run(&[target], true, unix_seconds_now()).unwrap();

        assert_eq!(report.matched_files, 1);
        assert_eq!(report.removed_files, 0);
        assert_eq!(report.files[0].action, StorageCleanupAction::WouldRemove);
        assert!(stale.exists());
    }

    #[test]
    fn cleanup_removes_only_stale_matching_files() {
        let temp_dir = tempfile::tempdir().unwrap();
        let stale = temp_dir
            .path()
            .join("saugra-security-summary-2026-05-01.json");
        let other = temp_dir.path().join("keep-me.json");
        fs::write(&stale, b"summary").unwrap();
        fs::write(&other, b"other").unwrap();
        thread::sleep(Duration::from_secs(2));
        let target = test_target(temp_dir.path(), "1s");

        let report = run(&[target], false, unix_seconds_now()).unwrap();

        assert_eq!(report.matched_files, 1);
        assert_eq!(report.removed_files, 1);
        assert!(!stale.exists());
        assert!(other.exists());
    }

    fn test_target(directory: &Path, older_than: &str) -> StorageCleanupTargetConfig {
        StorageCleanupTargetConfig {
            name: "summaries".to_string(),
            directory: directory.to_path_buf(),
            filename_prefix: Some("saugra-security-summary-".to_string()),
            filename_suffix: Some(".json".to_string()),
            older_than: older_than.to_string(),
        }
    }
}
