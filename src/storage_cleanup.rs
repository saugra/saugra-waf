use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{
    config::{BehaviorBackend, SaugraConfig, StorageCleanupTargetConfig},
    unknown_threats::{self, UnknownThreatCleanupReport},
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageCleanupReport {
    pub dry_run: bool,
    pub scanned_targets: usize,
    pub matched_files: usize,
    pub removed_files: usize,
    pub skipped_files: usize,
    pub freed_bytes: u64,
    pub files: Vec<StorageCleanupFile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unknown_threats: Option<UnknownThreatCleanupReport>,
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
    let mut report = run(&config.storage_cleanup.targets, dry_run, unix_seconds_now())?;
    if config.unknown_threats.backend == BehaviorBackend::Local {
        report.unknown_threats = Some(unknown_threats::cleanup_local_state(
            &config.unknown_threats,
            dry_run,
        )?);
    }
    Ok(report)
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
        unknown_threats: None,
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
    use std::path::Path;

    #[test]
    fn dry_run_reports_stale_matching_files_without_deleting() {
        let temp_dir = tempfile::tempdir().unwrap();
        let stale = temp_dir
            .path()
            .join("saugra-waf-security-summary-2026-05-01.json");
        fs::write(&stale, b"summary").unwrap();
        let target = test_target(temp_dir.path(), "1s");

        let report = run(&[target], true, unix_seconds_now() + 2).unwrap();

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
            .join("saugra-waf-security-summary-2026-05-01.json");
        let other = temp_dir.path().join("keep-me.json");
        fs::write(&stale, b"summary").unwrap();
        fs::write(&other, b"other").unwrap();
        let target = test_target(temp_dir.path(), "1s");

        let report = run(&[target], false, unix_seconds_now() + 2).unwrap();

        assert_eq!(report.matched_files, 1);
        assert_eq!(report.removed_files, 1);
        assert!(!stale.exists());
        assert!(other.exists());
    }

    #[test]
    fn fresh_matching_files_are_reported_as_skipped() {
        let temp_dir = tempfile::tempdir().unwrap();
        let fresh = temp_dir
            .path()
            .join("saugra-waf-security-summary-2026-05-22.json");
        fs::write(&fresh, b"summary").unwrap();
        let target = test_target(temp_dir.path(), "30d");

        let report = run(&[target], false, unix_seconds_now()).unwrap();

        assert_eq!(report.matched_files, 1);
        assert_eq!(report.removed_files, 0);
        assert_eq!(report.skipped_files, 1);
        assert_eq!(report.files[0].action, StorageCleanupAction::Skipped);
        assert!(fresh.exists());
    }

    #[test]
    fn missing_target_directory_is_ignored() {
        let temp_dir = tempfile::tempdir().unwrap();
        let target = test_target(&temp_dir.path().join("missing"), "1s");

        let report = run(&[target], false, unix_seconds_now()).unwrap();

        assert_eq!(report.scanned_targets, 1);
        assert_eq!(report.matched_files, 0);
        assert_eq!(report.removed_files, 0);
    }

    #[test]
    fn prefix_only_target_matches_stale_files() {
        let temp_dir = tempfile::tempdir().unwrap();
        let stale = temp_dir.path().join("saugra-waf-access.log.1");
        fs::write(&stale, b"log").unwrap();
        let mut target = test_target(temp_dir.path(), "1s");
        target.filename_prefix = Some("saugra-waf-".to_string());
        target.filename_suffix = None;

        let report = run(&[target], true, unix_seconds_now() + 2).unwrap();

        assert_eq!(report.matched_files, 1);
        assert_eq!(report.files[0].action, StorageCleanupAction::WouldRemove);
    }

    fn test_target(directory: &Path, older_than: &str) -> StorageCleanupTargetConfig {
        StorageCleanupTargetConfig {
            name: "summaries".to_string(),
            directory: directory.to_path_buf(),
            filename_prefix: Some("saugra-waf-security-summary-".to_string()),
            filename_suffix: Some(".json".to_string()),
            older_than: older_than.to_string(),
        }
    }
}
