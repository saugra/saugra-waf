use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Deserializer, Serialize};

use crate::decision::WafDecision;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityEvent {
    #[serde(
        default = "current_timestamp_for_utc",
        alias = "timestamp_unix_seconds",
        deserialize_with = "deserialize_timestamp"
    )]
    pub timestamp: String,
    #[serde(default = "unknown_client_ip")]
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub query: String,
    pub owasp_categories: Vec<String>,
    pub decision: WafDecision,
}

impl SecurityEvent {
    pub fn new(method: &str, path: &str, query: &str, decision: WafDecision) -> Self {
        Self::new_with_timezone(method, path, query, decision, "unknown", "UTC")
    }

    pub fn new_with_timezone(
        method: &str,
        path: &str,
        query: &str,
        decision: WafDecision,
        client_ip: &str,
        timezone: &str,
    ) -> Self {
        let owasp_categories = decision.owasp_categories.clone();

        Self {
            timestamp: current_timestamp_for_timezone(timezone),
            client_ip: client_ip.to_string(),
            method: method.to_string(),
            path: path.to_string(),
            query: query.to_string(),
            owasp_categories,
            decision,
        }
    }
}

fn unknown_client_ip() -> String {
    "unknown".to_string()
}

pub fn is_supported_timestamp_timezone(timezone: &str) -> bool {
    parse_timezone_offset(timezone).is_some()
}

fn current_timestamp_for_timezone(timezone: &str) -> String {
    let unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    unix_seconds_to_rfc3339(unix_seconds, timezone)
}

fn current_timestamp_for_utc() -> String {
    current_timestamp_for_timezone("UTC")
}

fn deserialize_timestamp<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::String(timestamp) => Ok(timestamp),
        serde_json::Value::Number(number) => number
            .as_u64()
            .map(|unix_seconds| unix_seconds_to_rfc3339(unix_seconds, "UTC"))
            .ok_or_else(|| serde::de::Error::custom("timestamp must be a string or unix seconds")),
        _ => Err(serde::de::Error::custom(
            "timestamp must be a string or unix seconds",
        )),
    }
}

fn unix_seconds_to_rfc3339(unix_seconds: u64, timezone: &str) -> String {
    let timezone = parse_timezone_offset(timezone).unwrap_or(TimezoneOffset {
        seconds: 0,
        suffix: "Z".to_string(),
    });
    let local_seconds = unix_seconds as i64 + timezone.seconds as i64;
    let days = local_seconds.div_euclid(86_400);
    let seconds_of_day = local_seconds.rem_euclid(86_400) as u64;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;

    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}{}",
        timezone.suffix
    )
}

struct TimezoneOffset {
    seconds: i32,
    suffix: String,
}

fn parse_timezone_offset(timezone: &str) -> Option<TimezoneOffset> {
    let timezone = timezone.trim();

    match timezone {
        "UTC" | "Etc/UTC" | "Z" => {
            return Some(TimezoneOffset {
                seconds: 0,
                suffix: "Z".to_string(),
            });
        }
        "Africa/Nairobi" => {
            return Some(TimezoneOffset {
                seconds: 3 * 3_600,
                suffix: "+03:00".to_string(),
            });
        }
        _ => {}
    }

    parse_fixed_offset(timezone)
}

fn parse_fixed_offset(offset: &str) -> Option<TimezoneOffset> {
    if offset.len() != 6 {
        return None;
    }

    let sign = match &offset[0..1] {
        "+" => 1,
        "-" => -1,
        _ => return None,
    };

    if &offset[3..4] != ":" {
        return None;
    }

    let hours = offset[1..3].parse::<i32>().ok()?;
    let minutes = offset[4..6].parse::<i32>().ok()?;

    if hours > 23 || minutes > 59 {
        return None;
    }

    Some(TimezoneOffset {
        seconds: sign * (hours * 3_600 + minutes * 60),
        suffix: offset.to_string(),
    })
}

fn civil_from_days(days_since_unix_epoch: i64) -> (i32, u32, u32) {
    let shifted_days = days_since_unix_epoch + 719_468;
    let era = if shifted_days >= 0 {
        shifted_days
    } else {
        shifted_days - 146_096
    } / 146_097;
    let day_of_era = shifted_days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let adjusted_year = year + if month <= 2 { 1 } else { 0 };

    (adjusted_year as i32, month as u32, day as u32)
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
            timestamp: "2026-05-14T00:00:00Z".to_string(),
            client_ip: "203.0.113.10".to_string(),
            method: "GET".to_string(),
            path: "/search".to_string(),
            query: "q=test".to_string(),
            owasp_categories: Vec::new(),
            decision: decision("request-1"),
        };

        let json = serde_json::to_value(event).unwrap();

        assert_eq!(json["timestamp"], "2026-05-14T00:00:00Z");
        assert!(json["timestamp_unix_seconds"].is_null());
        assert_eq!(json["client_ip"], "203.0.113.10");
        assert_eq!(json["method"], "GET");
        assert_eq!(json["path"], "/search");
        assert_eq!(json["query"], "q=test");
        assert!(json["owasp_categories"].as_array().unwrap().is_empty());
        assert_eq!(json["decision"]["request_id"], "request-1");
        assert_eq!(json["decision"]["action"], "allow");
        assert_eq!(json["decision"]["risk_score"], 0);
    }

    #[test]
    fn reads_legacy_unix_timestamp_events() {
        let line = r#"{
            "timestamp_unix_seconds": 1778889600,
            "method": "GET",
            "path": "/search",
            "query": "q=test",
            "owasp_categories": [],
            "decision": {
                "request_id": "request-1",
                "action": "allow",
                "matched_rules": [],
                "severity": "none",
                "risk_score": 0,
                "anomaly_score": 0,
                "anomaly_threshold": 5,
                "explanation": "No security rules matched this request.",
                "owasp_category": null,
                "owasp_categories": []
            }
        }"#;

        let event: SecurityEvent = serde_json::from_str(line).unwrap();

        assert_eq!(event.timestamp, "2026-05-16T00:00:00Z");
        assert_eq!(event.client_ip, "unknown");
    }

    #[test]
    fn formats_unix_seconds_as_rfc3339_utc() {
        assert_eq!(unix_seconds_to_rfc3339(0, "UTC"), "1970-01-01T00:00:00Z");
        assert_eq!(
            unix_seconds_to_rfc3339(1_779_035_662, "UTC"),
            "2026-05-17T16:34:22Z"
        );
    }

    #[test]
    fn formats_unix_seconds_for_africa_nairobi() {
        assert_eq!(
            unix_seconds_to_rfc3339(1_779_035_662, "Africa/Nairobi"),
            "2026-05-17T19:34:22+03:00"
        );
    }

    #[test]
    fn formats_unix_seconds_for_fixed_offsets() {
        assert_eq!(
            unix_seconds_to_rfc3339(0, "+03:00"),
            "1970-01-01T03:00:00+03:00"
        );
        assert_eq!(
            unix_seconds_to_rfc3339(0, "-01:00"),
            "1969-12-31T23:00:00-01:00"
        );
    }

    #[test]
    fn validates_supported_timestamp_timezones() {
        assert!(is_supported_timestamp_timezone("UTC"));
        assert!(is_supported_timestamp_timezone("Africa/Nairobi"));
        assert!(is_supported_timestamp_timezone("+03:00"));
        assert!(!is_supported_timestamp_timezone("Mars/Olympus"));
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
