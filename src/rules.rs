use std::{fs, path::Path};

use percent_encoding::percent_decode_str;
use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::RuleSettings;

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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleMatch {
    pub rule_id: String,
    pub rule_name: String,
    pub category: String,
    pub severity: RuleSeverity,
    pub matched_target: RuleTarget,
    pub explanation: String,
    pub owasp_category: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BuiltinRule {
    pub id: String,
    pub name: String,
    pub category: String,
    pub severity: RuleSeverity,
    pub target: RuleTarget,
    pub pattern: Regex,
    pub transforms: Vec<RuleTransform>,
    pub paranoia_level: u8,
    pub explanation: String,
    pub owasp_category: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RuleSet {
    rules: Vec<BuiltinRule>,
}

impl RuleSet {
    pub fn rules(&self) -> &[BuiltinRule] {
        &self.rules
    }

    pub fn inspect(&self, parts: &RequestParts<'_>) -> Vec<RuleMatch> {
        let mut matches = Vec::new();

        for rule in &self.rules {
            let raw_haystack = match rule.target {
                RuleTarget::Path => parts.path,
                RuleTarget::Query => parts.query,
                RuleTarget::Headers => parts.headers,
                RuleTarget::Body => parts.body,
                RuleTarget::UserAgent => parts.user_agent,
            };
            let haystack = normalize_rule_input(rule.target, raw_haystack, &rule.transforms);

            if rule.pattern.is_match(&haystack) {
                matches.push(RuleMatch {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    category: rule.category.clone(),
                    severity: rule.severity,
                    matched_target: rule.target,
                    explanation: rule.explanation.clone(),
                    owasp_category: rule.owasp_category.clone(),
                });
            }
        }

        matches
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleTransform {
    UrlDecode,
    PlusToSpace,
    Lowercase,
}

#[derive(Debug, Default)]
pub struct RequestParts<'a> {
    pub path: &'a str,
    pub query: &'a str,
    pub headers: &'a str,
    pub body: &'a str,
    pub user_agent: &'a str,
}

const DEFAULT_RULE_PACKS: &[&str] = &[
    include_str!("../configs/rules/REQUEST-913-SCANNER-DETECTION.yml"),
    include_str!("../configs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.yml"),
    include_str!("../configs/rules/REQUEST-932-APPLICATION-ATTACK-RCE.yml"),
    include_str!("../configs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.yml"),
    include_str!("../configs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.yml"),
    include_str!("../configs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.yml"),
];

pub fn builtin_rules() -> Result<Vec<BuiltinRule>, RuleError> {
    let mut rules = Vec::new();

    for contents in DEFAULT_RULE_PACKS {
        rules.extend(compile_rule_pack(contents, "<embedded saugra rule pack>")?);
    }

    Ok(rules)
}

pub fn load_rule_set(settings: &RuleSettings) -> Result<RuleSet, RuleError> {
    let mut rules = Vec::new();

    for path in &settings.files {
        rules.extend(load_rule_file(path)?);
    }

    rules.retain(|rule| rule.paranoia_level <= settings.paranoia_level);

    if rules.is_empty() {
        return Err(RuleError::EmptyRuleSet);
    }

    Ok(RuleSet { rules })
}

pub fn inspect(parts: &RequestParts<'_>) -> Result<Vec<RuleMatch>, RuleError> {
    Ok(RuleSet {
        rules: builtin_rules()?,
    }
    .inspect(parts))
}

fn load_rule_file(path: &Path) -> Result<Vec<BuiltinRule>, RuleError> {
    let path_display = path.display().to_string();
    let contents = fs::read_to_string(path).map_err(|source| RuleError::Io {
        path: path_display.clone(),
        source,
    })?;

    compile_rule_pack(&contents, &path_display)
}

fn compile_rule_pack(contents: &str, source_name: &str) -> Result<Vec<BuiltinRule>, RuleError> {
    let rule_file: RuleFile = serde_yaml::from_str(contents).map_err(|source| RuleError::Yaml {
        path: source_name.to_string(),
        source,
    })?;

    if rule_file.rules.is_empty() {
        return Err(RuleError::EmptyRuleFile {
            path: source_name.to_string(),
        });
    }

    let mut rules = Vec::new();

    for entry in rule_file.rules {
        if entry.enabled && entry.targets.is_empty() {
            return Err(RuleError::MissingTargets { rule_id: entry.id });
        }

        for definition in Vec::<RuleDefinition>::from(entry) {
            rules.push(BuiltinRule::try_from(definition)?);
        }
    }

    Ok(rules)
}

fn normalize_rule_input(target: RuleTarget, input: &str, transforms: &[RuleTransform]) -> String {
    let mut value = input.to_string();

    for transform in transforms {
        value = match transform {
            RuleTransform::UrlDecode => percent_decode_str(&value).decode_utf8_lossy().into_owned(),
            RuleTransform::PlusToSpace if target == RuleTarget::Query && value.contains('+') => {
                value.replace('+', " ")
            }
            RuleTransform::PlusToSpace => value,
            RuleTransform::Lowercase => value.to_lowercase(),
        };
    }

    value
}

struct RuleDefinition {
    id: String,
    name: String,
    category: String,
    severity: RuleSeverity,
    target: RuleTarget,
    pattern: String,
    transforms: Vec<RuleTransform>,
    paranoia_level: u8,
    explanation: String,
    owasp_category: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RuleFile {
    rules: Vec<RuleFileEntry>,
}

#[derive(Debug, Deserialize)]
struct RuleFileEntry {
    id: String,
    name: String,
    category: String,
    severity: RuleSeverity,
    targets: Vec<RuleTarget>,
    pattern: String,
    #[serde(default)]
    transforms: Vec<RuleTransform>,
    #[serde(default = "default_rule_paranoia_level")]
    paranoia_level: u8,
    explanation: String,
    #[serde(default)]
    owasp_category: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_rule_paranoia_level() -> u8 {
    1
}

fn default_true() -> bool {
    true
}

impl From<RuleFileEntry> for Vec<RuleDefinition> {
    fn from(entry: RuleFileEntry) -> Self {
        if !entry.enabled {
            return Vec::new();
        }

        entry
            .targets
            .into_iter()
            .map(|target| RuleDefinition {
                id: entry.id.clone(),
                name: entry.name.clone(),
                category: entry.category.clone(),
                severity: entry.severity,
                target,
                pattern: entry.pattern.clone(),
                transforms: entry.transforms.clone(),
                paranoia_level: entry.paranoia_level,
                explanation: entry.explanation.clone(),
                owasp_category: entry.owasp_category.clone(),
            })
            .collect()
    }
}

impl TryFrom<RuleDefinition> for BuiltinRule {
    type Error = RuleError;

    fn try_from(definition: RuleDefinition) -> Result<Self, Self::Error> {
        let pattern =
            Regex::new(&definition.pattern).map_err(|source| RuleError::InvalidRegex {
                rule_id: definition.id.clone(),
                source,
            })?;

        Ok(Self {
            id: definition.id,
            name: definition.name,
            category: definition.category,
            severity: definition.severity,
            target: definition.target,
            pattern,
            transforms: definition.transforms,
            paranoia_level: definition.paranoia_level,
            explanation: definition.explanation,
            owasp_category: definition.owasp_category,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RuleSettings;

    #[test]
    fn detects_sql_injection() {
        let matches = inspect(&RequestParts {
            query: "q=' OR 1=1--",
            ..RequestParts::default()
        })
        .unwrap();

        assert_eq!(matches[0].rule_id, "SAUGRA-SQLI-001");
    }

    #[test]
    fn detects_percent_encoded_sql_injection() {
        let matches = inspect(&RequestParts {
            query: "id=1'%20OR%201=1",
            ..RequestParts::default()
        })
        .unwrap();

        assert_eq!(matches[0].rule_id, "SAUGRA-SQLI-001");
    }

    #[test]
    fn treats_plus_as_space_in_query_strings() {
        let matches = inspect(&RequestParts {
            query: "id=1'+OR+1=1",
            ..RequestParts::default()
        })
        .unwrap();

        assert_eq!(matches[0].rule_id, "SAUGRA-SQLI-001");
    }

    #[test]
    fn detects_xss() {
        let matches = inspect(&RequestParts {
            query: "text=<script>alert(1)</script>",
            ..RequestParts::default()
        })
        .unwrap();

        assert_eq!(matches[0].rule_id, "SAUGRA-XSS-001");
    }

    #[test]
    fn detects_path_traversal() {
        let matches = inspect(&RequestParts {
            path: "/download/../../../../etc/passwd",
            ..RequestParts::default()
        })
        .unwrap();

        assert_eq!(matches[0].rule_id, "SAUGRA-PATH-001");
    }

    #[test]
    fn detects_path_traversal_in_query_string() {
        let matches = inspect(&RequestParts {
            query: "file=../../../../etc/passwd",
            ..RequestParts::default()
        })
        .unwrap();

        assert_eq!(matches[0].rule_id, "SAUGRA-PATH-002");
        assert_eq!(matches[0].matched_target, RuleTarget::Query);
    }

    #[test]
    fn detects_command_injection() {
        let matches = inspect(&RequestParts {
            query: "cmd=whoami; cat /etc/passwd",
            ..RequestParts::default()
        })
        .unwrap();

        assert_eq!(matches[0].rule_id, "SAUGRA-CMD-001");
    }

    #[test]
    fn loads_rules_from_configured_yaml_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rule_path = temp_dir.path().join("custom-rules.yml");
        std::fs::write(
            &rule_path,
            r#"
rules:
  - id: LOCAL-HEADER-001
    name: Local Header Rule
    category: local_policy
    severity: low
    targets:
      - headers
    pattern: "(?i)x-local-test:\\s*blocked"
    explanation: Local header policy matched.
"#,
        )
        .unwrap();

        let rule_set = load_rule_set(&RuleSettings {
            files: vec![rule_path],
            ..RuleSettings::default()
        })
        .unwrap();
        let matches = rule_set.inspect(&RequestParts {
            headers: "x-local-test: blocked",
            ..RequestParts::default()
        });

        assert_eq!(rule_set.rules().len(), 1);
        assert_eq!(matches[0].rule_id, "LOCAL-HEADER-001");
    }

    #[test]
    fn rejects_invalid_regex_in_configured_rule_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rule_path = temp_dir.path().join("bad-rules.yml");
        std::fs::write(
            &rule_path,
            r#"
rules:
  - id: LOCAL-BAD-001
    name: Bad Regex
    category: local_policy
    severity: low
    targets:
      - query
    pattern: "["
    explanation: Bad regex should fail startup.
"#,
        )
        .unwrap();

        let error = load_rule_set(&RuleSettings {
            files: vec![rule_path],
            ..RuleSettings::default()
        })
        .unwrap_err();

        assert!(matches!(error, RuleError::InvalidRegex { .. }));
    }

    #[test]
    fn filters_rules_above_configured_paranoia_level() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rule_path = temp_dir.path().join("paranoia-rules.yml");
        std::fs::write(
            &rule_path,
            r#"
rules:
  - id: LOCAL-PL1-001
    name: PL1 Rule
    category: local_policy
    severity: low
    paranoia_level: 1
    targets:
      - query
    pattern: "pl1"
    explanation: PL1 rule matched.
  - id: LOCAL-PL2-001
    name: PL2 Rule
    category: local_policy
    severity: low
    paranoia_level: 2
    targets:
      - query
    pattern: "pl2"
    explanation: PL2 rule matched.
"#,
        )
        .unwrap();

        let rule_set = load_rule_set(&RuleSettings {
            files: vec![rule_path],
            paranoia_level: 1,
            ..RuleSettings::default()
        })
        .unwrap();

        assert_eq!(rule_set.rules().len(), 1);
        assert_eq!(rule_set.rules()[0].id, "LOCAL-PL1-001");
    }
}
