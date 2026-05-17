use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::decision::WafDecision;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityEvent {
    pub timestamp_unix_seconds: u64,
    pub method: String,
    pub path: String,
    pub query: String,
    pub owasp_categories: Vec<String>,
    pub decision: WafDecision,
}

impl SecurityEvent {
    pub fn new(method: &str, path: &str, query: &str, decision: WafDecision) -> Self {
        let owasp_categories = decision.owasp_categories.clone();

        Self {
            timestamp_unix_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            method: method.to_string(),
            path: path.to_string(),
            query: query.to_string(),
            owasp_categories,
            decision,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EventLogRetention {
    pub max_size_bytes: u64,
    pub max_files: usize,
}

pub fn append(
    path: &Path,
    retention: EventLogRetention,
    event: &SecurityEvent,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut encoded = serde_json::to_vec(event)?;
    encoded.push(b'\n');
    rotate_if_needed(path, retention, encoded.len() as u64)?;

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(&encoded)?;
    Ok(())
}

pub fn tail(
    path: &Path,
    retention: EventLogRetention,
    limit: usize,
) -> anyhow::Result<Vec<SecurityEvent>> {
    let lines = read_event_lines(path, retention)?;

    Ok(lines
        .into_iter()
        .rev()
        .take(limit)
        .rev()
        .filter_map(|line| serde_json::from_str(&line).ok())
        .collect())
}

pub fn find_by_request_id(
    path: &Path,
    retention: EventLogRetention,
    request_id: &str,
) -> anyhow::Result<Option<SecurityEvent>> {
    for line in read_event_lines(path, retention)?.into_iter().rev() {
        let event: SecurityEvent = serde_json::from_str(&line)?;
        if event.decision.request_id == request_id {
            return Ok(Some(event));
        }
    }

    Ok(None)
}

fn rotate_if_needed(
    path: &Path,
    retention: EventLogRetention,
    incoming_bytes: u64,
) -> anyhow::Result<()> {
    if retention.max_files == 0 || retention.max_size_bytes == 0 || !path.exists() {
        return Ok(());
    }

    let current_size = fs::metadata(path)?.len();
    if current_size.saturating_add(incoming_bytes) <= retention.max_size_bytes {
        return Ok(());
    }

    let oldest = rotated_path(path, retention.max_files);
    if oldest.exists() {
        fs::remove_file(oldest)?;
    }

    for index in (1..retention.max_files).rev() {
        let source = rotated_path(path, index);
        if source.exists() {
            fs::rename(source, rotated_path(path, index + 1))?;
        }
    }

    fs::rename(path, rotated_path(path, 1))?;
    Ok(())
}

fn read_event_lines(path: &Path, retention: EventLogRetention) -> anyhow::Result<Vec<String>> {
    let mut lines = Vec::new();

    for path in event_paths_oldest_first(path, retention.max_files) {
        if !path.exists() {
            continue;
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        lines.extend(reader.lines().collect::<Result<Vec<_>, _>>()?);
    }

    Ok(lines)
}

fn event_paths_oldest_first(path: &Path, max_files: usize) -> Vec<PathBuf> {
    let mut paths = (1..=max_files)
        .rev()
        .map(|index| rotated_path(path, index))
        .collect::<Vec<_>>();
    paths.push(path.to_path_buf());
    paths
}

fn rotated_path(path: &Path, index: usize) -> PathBuf {
    PathBuf::from(format!("{}.{}", path.display(), index))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{WafAction, WafDecision};

    #[test]
    fn appends_tails_and_finds_events() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("events.jsonl");
        let retention = EventLogRetention {
            max_size_bytes: 1024,
            max_files: 3,
        };
        let event = SecurityEvent::new("GET", "/search", "q=test", decision("request-1"));

        append(&path, retention, &event).unwrap();

        let events = tail(&path, retention, 10).unwrap();
        let found = find_by_request_id(&path, retention, "request-1")
            .unwrap()
            .unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(found.decision.request_id, "request-1");
    }

    #[test]
    fn rotates_event_logs_and_reads_rotated_files() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("events.jsonl");
        let retention = EventLogRetention {
            max_size_bytes: 220,
            max_files: 2,
        };

        append(
            &path,
            retention,
            &SecurityEvent::new("GET", "/one", "", decision("request-1")),
        )
        .unwrap();
        append(
            &path,
            retention,
            &SecurityEvent::new("GET", "/two", "", decision("request-2")),
        )
        .unwrap();

        let events = tail(&path, retention, 10).unwrap();

        assert!(rotated_path(&path, 1).exists());
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].decision.request_id, "request-1");
        assert_eq!(events[1].decision.request_id, "request-2");
    }

    #[test]
    fn serializes_security_event_with_expected_json_shape() {
        let event = SecurityEvent {
            timestamp_unix_seconds: 1_778_889_600,
            method: "GET".to_string(),
            path: "/search".to_string(),
            query: "q=test".to_string(),
            owasp_categories: Vec::new(),
            decision: decision("request-1"),
        };

        let json = serde_json::to_value(event).unwrap();

        assert_eq!(json["timestamp_unix_seconds"], 1_778_889_600);
        assert_eq!(json["method"], "GET");
        assert_eq!(json["path"], "/search");
        assert_eq!(json["query"], "q=test");
        assert!(json["owasp_categories"].as_array().unwrap().is_empty());
        assert_eq!(json["decision"]["request_id"], "request-1");
        assert_eq!(json["decision"]["action"], "allow");
        assert_eq!(json["decision"]["risk_score"], 0);
    }

    fn decision(request_id: &str) -> WafDecision {
        WafDecision {
            request_id: request_id.to_string(),
            action: WafAction::Allow,
            matched_rules: Vec::new(),
            severity: "none".to_string(),
            risk_score: 0,
            anomaly_score: 0,
            anomaly_threshold: 5,
            explanation: "No security rules matched this request.".to_string(),
            owasp_category: None,
            owasp_categories: Vec::new(),
        }
    }
}
