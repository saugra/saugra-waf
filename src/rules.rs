use regex::Regex;
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuleError {
    #[error("invalid built-in rule regex for {rule_id}: {source}")]
    InvalidRegex {
        rule_id: &'static str,
        source: regex::Error,
    },
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Serialize)]
pub struct RuleMatch {
    pub rule_id: String,
    pub rule_name: String,
    pub category: String,
    pub severity: RuleSeverity,
    pub matched_target: RuleTarget,
    pub explanation: String,
    pub owasp_category: Option<String>,
}

pub struct BuiltinRule {
    pub id: &'static str,
    pub name: &'static str,
    pub category: &'static str,
    pub severity: RuleSeverity,
    pub target: RuleTarget,
    pub pattern: Regex,
    pub explanation: &'static str,
    pub owasp_category: Option<&'static str>,
}

#[derive(Debug, Default)]
pub struct RequestParts<'a> {
    pub path: &'a str,
    pub query: &'a str,
    pub headers: &'a str,
    pub body: &'a str,
    pub user_agent: &'a str,
}

pub fn builtin_rules() -> Result<Vec<BuiltinRule>, RuleError> {
    let definitions = [
        RuleDefinition {
            id: "SAUGRA-SQLI-001",
            name: "Basic SQL Injection Pattern",
            category: "sql_injection",
            severity: RuleSeverity::High,
            target: RuleTarget::Query,
            pattern: r"(?i)(union\s+select|or\s+1\s*=\s*1|drop\s+table|--|/\*)",
            explanation: "Query data matched a common SQL injection pattern.",
            owasp_category: Some("A03:2021-Injection"),
        },
        RuleDefinition {
            id: "SAUGRA-XSS-001",
            name: "Basic Cross-Site Scripting Pattern",
            category: "cross_site_scripting",
            severity: RuleSeverity::High,
            target: RuleTarget::Query,
            pattern: r"(?i)(<script|javascript:|onerror\s*=|onload\s*=)",
            explanation: "Request data matched a common cross-site scripting pattern.",
            owasp_category: Some("A03:2021-Injection"),
        },
        RuleDefinition {
            id: "SAUGRA-PATH-001",
            name: "Path Traversal Pattern",
            category: "path_traversal",
            severity: RuleSeverity::High,
            target: RuleTarget::Path,
            pattern: r"(?i)(\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f|/etc/passwd)",
            explanation: "Request path matched a directory traversal pattern.",
            owasp_category: Some("A01:2021-Broken Access Control"),
        },
        RuleDefinition {
            id: "SAUGRA-CMD-001",
            name: "Command Injection Pattern",
            category: "command_injection",
            severity: RuleSeverity::Critical,
            target: RuleTarget::Query,
            pattern: r"(?i)(;\s*(cat|bash|sh|curl|wget)\b|`[^`]+`|\|\s*(cat|bash|sh)\b)",
            explanation: "Request data matched a command injection pattern.",
            owasp_category: Some("A03:2021-Injection"),
        },
        RuleDefinition {
            id: "SAUGRA-BOT-001",
            name: "Suspicious Scanner User Agent",
            category: "scanner_behavior",
            severity: RuleSeverity::Medium,
            target: RuleTarget::UserAgent,
            pattern: r"(?i)(sqlmap|nikto|nmap|masscan|acunetix|nessus|wpscan)",
            explanation: "User-Agent matched a known scanner or security testing tool.",
            owasp_category: Some("A06:2021-Vulnerable and Outdated Components"),
        },
        RuleDefinition {
            id: "SAUGRA-CT-001",
            name: "Suspicious Content Type",
            category: "suspicious_content_type",
            severity: RuleSeverity::Low,
            target: RuleTarget::Headers,
            pattern: r"(?i)(content-type:\s*application/x-msdownload|content-type:\s*application/x-sh)",
            explanation: "Request headers matched a suspicious executable content type.",
            owasp_category: Some("A05:2021-Security Misconfiguration"),
        },
        RuleDefinition {
            id: "SAUGRA-BODY-001",
            name: "Suspicious Body Script Pattern",
            category: "cross_site_scripting",
            severity: RuleSeverity::Medium,
            target: RuleTarget::Body,
            pattern: r"(?i)(<script|javascript:|onerror\s*=|onload\s*=)",
            explanation: "Request body matched a script injection pattern.",
            owasp_category: Some("A03:2021-Injection"),
        },
    ];

    definitions
        .into_iter()
        .map(BuiltinRule::try_from)
        .collect::<Result<Vec<_>, _>>()
}

pub fn inspect(parts: &RequestParts<'_>) -> Result<Vec<RuleMatch>, RuleError> {
    let mut matches = Vec::new();

    for rule in builtin_rules()? {
        let haystack = match rule.target {
            RuleTarget::Path => parts.path,
            RuleTarget::Query => parts.query,
            RuleTarget::Headers => parts.headers,
            RuleTarget::Body => parts.body,
            RuleTarget::UserAgent => parts.user_agent,
        };

        if rule.pattern.is_match(haystack) {
            matches.push(RuleMatch {
                rule_id: rule.id.to_string(),
                rule_name: rule.name.to_string(),
                category: rule.category.to_string(),
                severity: rule.severity,
                matched_target: rule.target,
                explanation: rule.explanation.to_string(),
                owasp_category: rule.owasp_category.map(str::to_string),
            });
        }
    }

    Ok(matches)
}

struct RuleDefinition {
    id: &'static str,
    name: &'static str,
    category: &'static str,
    severity: RuleSeverity,
    target: RuleTarget,
    pattern: &'static str,
    explanation: &'static str,
    owasp_category: Option<&'static str>,
}

impl TryFrom<RuleDefinition> for BuiltinRule {
    type Error = RuleError;

    fn try_from(definition: RuleDefinition) -> Result<Self, Self::Error> {
        let pattern = Regex::new(definition.pattern).map_err(|source| RuleError::InvalidRegex {
            rule_id: definition.id,
            source,
        })?;

        Ok(Self {
            id: definition.id,
            name: definition.name,
            category: definition.category,
            severity: definition.severity,
            target: definition.target,
            pattern,
            explanation: definition.explanation,
            owasp_category: definition.owasp_category,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn detects_command_injection() {
        let matches = inspect(&RequestParts {
            query: "cmd=whoami; cat /etc/passwd",
            ..RequestParts::default()
        })
        .unwrap();

        assert_eq!(matches[0].rule_id, "SAUGRA-CMD-001");
    }
}
