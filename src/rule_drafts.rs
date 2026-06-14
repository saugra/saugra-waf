use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use regex::escape;
use serde::{Deserialize, Serialize};

use crate::{
    ai,
    config::{SaugraConfig, WafMode},
    event_store::SecurityEvent,
    rules,
};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DraftManifest {
    pub version: u8,
    pub rule_file: String,
    pub source_anomaly_ids: Vec<String>,
    pub generator_provider: String,
    pub generator_model: String,
    pub prompt_version: String,
    pub input_digest: String,
    pub reviewer: Option<String>,
    pub approval_timestamp: Option<u64>,
    pub replay_report_digest: Option<String>,
    pub publication_state: String,
}

pub fn create_draft(
    events: &[SecurityEvent],
    request_ids: &[String],
    output: &Path,
    provider: &str,
    model: &str,
    prompt_version: &str,
) -> anyhow::Result<PathBuf> {
    let selected = request_ids
        .iter()
        .map(|request_id| {
            events
                .iter()
                .find(|event| &event.decision.request_id == request_id)
                .with_context(|| format!("source anomaly request ID not found: {request_id}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    anyhow::ensure!(
        selected.len() >= 2,
        "draft creation requires at least two reviewed anomaly request IDs"
    );
    let path = &selected[0].path;
    anyhow::ensure!(
        selected.iter().all(|event| event.path == *path),
        "reviewed anomalies must share one exact path for deterministic drafting"
    );
    let rule_id = format!(
        "DRAFT-{}",
        ai::content_digest(request_ids.join("\n").as_bytes())
            .trim_start_matches("sha256:")
            .chars()
            .take(12)
            .collect::<String>()
            .to_ascii_uppercase()
    );
    let yaml = format!(
        "metadata:\n  name: reviewed-anomaly-draft\n  version: draft-1\nrules:\n  - id: {rule_id}\n    name: Reviewed repeated route anomaly\n    category: reviewed_anomaly\n    severity: medium\n    targets:\n      - path\n    pattern: \"^{}$\"\n    explanation: Repeated reviewed anomaly matched the drafted route signature.\n",
        escape(path).replace('\\', "\\\\").replace('"', "\\\"")
    );
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, &yaml)?;
    let manifest_path = manifest_path(output);
    let manifest = DraftManifest {
        version: 1,
        rule_file: output.display().to_string(),
        source_anomaly_ids: request_ids.to_vec(),
        generator_provider: provider.to_string(),
        generator_model: model.to_string(),
        prompt_version: prompt_version.to_string(),
        input_digest: ai::content_digest(
            serde_json::to_vec(&selected.iter().map(|event| &event.path).collect::<Vec<_>>())?
                .as_slice(),
        ),
        reviewer: None,
        approval_timestamp: None,
        replay_report_digest: None,
        publication_state: "draft".to_string(),
    };
    write_manifest(&manifest_path, &manifest)?;
    Ok(manifest_path)
}

pub fn approve_draft(rule_file: &Path, reviewer: &str, replay_report: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(!reviewer.trim().is_empty(), "reviewer must not be blank");
    rules::validate_rule_file(rule_file, u8::MAX)?;
    let replay = fs::read(replay_report)
        .with_context(|| format!("failed to read replay report {}", replay_report.display()))?;
    let mut manifest = read_manifest(&manifest_path(rule_file))?;
    manifest.reviewer = Some(reviewer.trim().to_string());
    manifest.approval_timestamp = Some(unix_seconds_now());
    manifest.replay_report_digest = Some(ai::content_digest(&replay));
    manifest.publication_state = "approved".to_string();
    write_manifest(&manifest_path(rule_file), &manifest)
}

pub fn publish_draft(
    rule_file: &Path,
    destination: &Path,
    config: &SaugraConfig,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        config.server.mode == WafMode::Monitor,
        "generated rules may be published only while server.mode is monitor"
    );
    rules::validate_rule_file(rule_file, u8::MAX)?;
    let manifest_path = manifest_path(rule_file);
    let mut manifest = read_manifest(&manifest_path)?;
    anyhow::ensure!(
        manifest.publication_state == "approved"
            && manifest.reviewer.is_some()
            && manifest.approval_timestamp.is_some()
            && manifest.replay_report_digest.is_some(),
        "draft must be approved with a replay report before publication"
    );
    anyhow::ensure!(
        !config.rules.files.iter().any(|active| active == rule_file),
        "draft source must remain outside configured active rule files"
    );
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(rule_file, destination)?;
    manifest.publication_state = "published_monitor".to_string();
    write_manifest(&manifest_path, &manifest)
}

pub fn manifest_path(rule_file: &Path) -> PathBuf {
    PathBuf::from(format!("{}.manifest.json", rule_file.display()))
}

fn read_manifest(path: &Path) -> anyhow::Result<DraftManifest> {
    serde_json::from_slice(&fs::read(path)?).context("draft manifest must be valid JSON")
}

fn write_manifest(path: &Path, manifest: &DraftManifest) -> anyhow::Result<()> {
    fs::write(path, serde_json::to_vec_pretty(manifest)?)?;
    Ok(())
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
    use crate::{config::SaugraConfig, decision::WafDecision, event_store::SecurityEvent};

    #[test]
    fn draft_requires_review_replay_and_monitor_mode_before_publish() {
        let temp_dir = tempfile::tempdir().unwrap();
        let draft = temp_dir.path().join("drafts").join("route.yml");
        let published = temp_dir.path().join("published").join("route.yml");
        let events = vec![
            SecurityEvent::new(
                "GET",
                "/reviewed/path",
                "",
                WafDecision::from_matches("one".to_string(), WafMode::Monitor, vec![], 5),
            ),
            SecurityEvent::new(
                "GET",
                "/reviewed/path",
                "",
                WafDecision::from_matches("two".to_string(), WafMode::Monitor, vec![], 5),
            ),
        ];
        create_draft(
            &events,
            &["one".to_string(), "two".to_string()],
            &draft,
            "local",
            "deterministic",
            "test-v1",
        )
        .unwrap();
        let replay = temp_dir.path().join("replay.json");
        fs::write(&replay, r#"{"matched_events":2}"#).unwrap();
        approve_draft(&draft, "reviewer@example.com", &replay).unwrap();

        let config: SaugraConfig = serde_yaml::from_str(
            r#"
server:
  listen: 127.0.0.1:8787
  mode: monitor
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
"#,
        )
        .unwrap();
        config.validate().unwrap();
        publish_draft(&draft, &published, &config).unwrap();

        assert!(published.exists());
        let manifest = read_manifest(&manifest_path(&draft)).unwrap();
        assert_eq!(manifest.publication_state, "published_monitor");
        assert_eq!(manifest.reviewer.as_deref(), Some("reviewer@example.com"));
    }
}
