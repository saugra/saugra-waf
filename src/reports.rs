use std::{fs, path::PathBuf};

use serde::Deserialize;
use thiserror::Error;

use crate::config::SaugraConfig;

#[derive(Debug, Error)]
pub enum SecurityReportError {
    #[error("failed to read security report {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("security report {path} is not valid JSON/YAML: {source}")]
    Parse {
        path: String,
        source: serde_yaml::Error,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityReportSummary {
    pub reports: Vec<SecurityReport>,
    pub missing_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityReport {
    pub path: PathBuf,
    pub format: SecurityReportFormat,
    pub findings: Vec<SecurityFinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityReportFormat {
    Saugra,
    CycloneDx,
    Unknown,
}

impl std::fmt::Display for SecurityReportFormat {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Saugra => "saugra",
            Self::CycloneDx => "cyclonedx",
            Self::Unknown => "unknown",
        };
        formatter.write_str(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityFinding {
    pub id: String,
    pub package: Option<String>,
    pub severity: Option<String>,
    pub owasp_category: String,
    pub summary: String,
}

pub fn load_configured_reports(
    config: &SaugraConfig,
) -> Result<SecurityReportSummary, SecurityReportError> {
    load_reports(config.dependency_report_paths())
}

pub fn load_reports(paths: Vec<PathBuf>) -> Result<SecurityReportSummary, SecurityReportError> {
    let mut reports = Vec::new();
    let mut missing_paths = Vec::new();

    for path in paths {
        if !path.exists() {
            missing_paths.push(path);
            continue;
        }
        reports.push(load_report(path)?);
    }

    Ok(SecurityReportSummary {
        reports,
        missing_paths,
    })
}

fn load_report(path: PathBuf) -> Result<SecurityReport, SecurityReportError> {
    let path_display = path.display().to_string();
    let contents = fs::read_to_string(&path).map_err(|source| SecurityReportError::Io {
        path: path_display.clone(),
        source,
    })?;
    let value: serde_yaml::Value =
        serde_yaml::from_str(&contents).map_err(|source| SecurityReportError::Parse {
            path: path_display,
            source,
        })?;

    Ok(normalize_report(path, value))
}

fn normalize_report(path: PathBuf, value: serde_yaml::Value) -> SecurityReport {
    if is_cyclonedx(&value) {
        return normalize_cyclonedx(path, value);
    }

    if let Ok(report) = serde_yaml::from_value::<SaugraReportDocument>(value.clone()) {
        return SecurityReport {
            path,
            format: SecurityReportFormat::Saugra,
            findings: report
                .findings
                .into_iter()
                .map(|finding| SecurityFinding {
                    id: finding.id,
                    package: finding.package,
                    severity: finding.severity,
                    owasp_category: finding
                        .owasp_category
                        .unwrap_or_else(|| "A03:2025-Software Supply Chain Failures".to_string()),
                    summary: finding.summary,
                })
                .collect(),
        };
    }

    SecurityReport {
        path,
        format: SecurityReportFormat::Unknown,
        findings: Vec::new(),
    }
}

fn is_cyclonedx(value: &serde_yaml::Value) -> bool {
    value
        .get("bomFormat")
        .and_then(serde_yaml::Value::as_str)
        .is_some_and(|format| format.eq_ignore_ascii_case("CycloneDX"))
}

fn normalize_cyclonedx(path: PathBuf, value: serde_yaml::Value) -> SecurityReport {
    let document = serde_yaml::from_value::<CycloneDxDocument>(value).unwrap_or_default();
    let findings = document
        .vulnerabilities
        .into_iter()
        .map(|vulnerability| {
            let severity = vulnerability
                .ratings
                .first()
                .and_then(|rating| rating.severity.clone());
            let package = vulnerability
                .affects
                .first()
                .map(|affected| affected.reference.clone());
            let summary = vulnerability
                .description
                .or(vulnerability.detail)
                .unwrap_or_else(|| "CycloneDX vulnerability finding".to_string());

            SecurityFinding {
                id: vulnerability.id,
                package,
                severity,
                owasp_category: "A03:2025-Software Supply Chain Failures".to_string(),
                summary,
            }
        })
        .collect();

    SecurityReport {
        path,
        format: SecurityReportFormat::CycloneDx,
        findings,
    }
}

impl SecurityReportSummary {
    pub fn finding_count(&self) -> usize {
        self.reports
            .iter()
            .map(|report| report.findings.len())
            .sum()
    }

    pub fn finding_count_for_category(&self, category_id: &str) -> usize {
        self.reports
            .iter()
            .flat_map(|report| report.findings.iter())
            .filter(|finding| {
                finding
                    .owasp_category
                    .split_once('-')
                    .map(|(id, _)| id)
                    .unwrap_or(&finding.owasp_category)
                    == category_id
            })
            .count()
    }
}

#[derive(Debug, Deserialize)]
struct SaugraReportDocument {
    findings: Vec<SaugraFinding>,
}

#[derive(Debug, Deserialize)]
struct SaugraFinding {
    id: String,
    #[serde(default)]
    package: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    owasp_category: Option<String>,
    summary: String,
}

#[derive(Debug, Deserialize, Default)]
struct CycloneDxDocument {
    #[serde(default)]
    vulnerabilities: Vec<CycloneDxVulnerability>,
}

#[derive(Debug, Deserialize)]
struct CycloneDxVulnerability {
    id: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    detail: Option<String>,
    #[serde(default)]
    ratings: Vec<CycloneDxRating>,
    #[serde(default)]
    affects: Vec<CycloneDxAffects>,
}

#[derive(Debug, Deserialize)]
struct CycloneDxRating {
    #[serde(default)]
    severity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CycloneDxAffects {
    #[serde(rename = "ref")]
    reference: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn normalizes_saugra_report_findings() {
        let path = temp_report_path();
        std::fs::write(
            &path,
            r#"
findings:
  - id: CVE-TEST-1
    package: example-lib
    severity: high
    owasp_category: A08:2025-Software or Data Integrity Failures
    summary: Integrity finding.
"#,
        )
        .unwrap();

        let summary = load_reports(vec![path]).unwrap();

        assert_eq!(summary.finding_count(), 1);
        assert_eq!(summary.finding_count_for_category("A08:2025"), 1);
        assert_eq!(summary.reports[0].format, SecurityReportFormat::Saugra);
    }

    #[test]
    fn normalizes_cyclonedx_vulnerabilities() {
        let path = temp_report_path();
        std::fs::write(
            &path,
            r#"
bomFormat: CycloneDX
vulnerabilities:
  - id: CVE-2026-0001
    description: vulnerable package
    ratings:
      - severity: critical
    affects:
      - ref: pkg:cargo/example@1.0.0
"#,
        )
        .unwrap();

        let summary = load_reports(vec![path]).unwrap();

        assert_eq!(summary.finding_count(), 1);
        assert_eq!(summary.finding_count_for_category("A03:2025"), 1);
        assert_eq!(summary.reports[0].format, SecurityReportFormat::CycloneDx);
    }

    #[test]
    fn reports_missing_paths_without_failing() {
        let path = temp_report_path();
        let summary = load_reports(vec![path.clone()]).unwrap();

        assert!(summary.reports.is_empty());
        assert_eq!(summary.missing_paths, vec![path]);
    }

    fn temp_report_path() -> PathBuf {
        std::env::temp_dir().join(format!("saugra-report-{}.yml", Uuid::new_v4()))
    }
}
