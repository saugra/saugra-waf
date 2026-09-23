use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuleError {
    #[error("invalid built-in rule regex for {rule_id}: {source}")]
    InvalidRegex {
        rule_id: String,
        source: regex::Error,
    },
    #[error("failed to read rule file {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("rule file {path} is not valid YAML: {source}")]
    Yaml {
        path: String,
        source: serde_yaml::Error,
    },
    #[error("rule file {path} does not contain any rules")]
    EmptyRuleFile { path: String },
    #[error("no enabled rules were loaded")]
    EmptyRuleSet,
    #[error("rule {rule_id} must target at least one request component")]
    MissingTargets { rule_id: String },
    #[error("rule file {path} metadata.{field} must not be blank when metadata is provided")]
    InvalidMetadata { path: String, field: String },
    #[error("rule {rule_id} field {field} must not be blank when provided")]
    InvalidRuleMetadata { rule_id: String, field: String },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl RuleSeverity {
    pub fn risk_score(self) -> u8 {
        match self {
            Self::Low => 25,
            Self::Medium => 50,
            Self::High => 80,
            Self::Critical => 95,
        }
    }

    pub fn anomaly_points(self) -> u16 {
        match self {
            Self::Low => 2,
            Self::Medium => 3,
            Self::High => 5,
            Self::Critical => 5,
        }
    }
}

impl std::fmt::Display for RuleSeverity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        formatter.write_str(value)
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceCostTier {
    Low,
    Moderate,
    High,
}

impl std::fmt::Display for PerformanceCostTier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Low => "low",
            Self::Moderate => "moderate",
            Self::High => "high",
        };
        formatter.write_str(value)
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleTarget {
    Path,
    Query,
    Headers,
    Body,
    UserAgent,
}

impl std::fmt::Display for RuleTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Path => "path",
            Self::Query => "query",
            Self::Headers => "headers",
            Self::Body => "body",
            Self::UserAgent => "user_agent",
        };
        formatter.write_str(value)
    }
}

fn default_rule_paranoia_level() -> u8 {
    1
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleMatch {
    pub rule_id: String,
    pub rule_name: String,
    pub category: String,
    pub severity: RuleSeverity,
    pub matched_target: RuleTarget,
    #[serde(default = "default_rule_paranoia_level")]
    pub paranoia_level: u8,
    pub explanation: String,
    pub owasp_category: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BuiltinRule {
    pub id: String,
    pub name: String,
    pub category: String,
    pub severity: RuleSeverity,
    pub performance_cost: Option<PerformanceCostTier>,
    pub target: RuleTarget,
    pub pattern: Regex,
    pub transforms: Vec<RuleTransform>,
    pub paranoia_level: u8,
    pub explanation: String,
    pub owasp_category: Option<String>,
    pub design_intent: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleTransform {
    Lowercase,
    UrlDecode,
    PlusToSpace,
}

impl std::fmt::Display for RuleTransform {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Lowercase => "lowercase",
            Self::UrlDecode => "url_decode",
            Self::PlusToSpace => "plus_to_space",
        };
        formatter.write_str(value)
    }
}

#[derive(Debug, Clone, Default)]
pub struct RequestParts<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub headers: &'a str,
    pub body: &'a str,
    pub user_agent: &'a str,
    pub content_type: &'a str,
    pub trusted_proxy: bool,
}
