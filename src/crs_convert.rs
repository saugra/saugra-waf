use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::Context;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConversionSummary {
    pub converted: usize,
    pub skipped: usize,
}

#[derive(Debug, Serialize)]
struct SaugraRuleFile {
    metadata: SaugraRuleMetadata,
    rules: Vec<SaugraRule>,
}

#[derive(Debug, Serialize)]
struct SaugraRuleMetadata {
    name: String,
    version: String,
}

#[derive(Debug, Serialize)]
struct SaugraRule {
    id: String,
    name: String,
    category: String,
    severity: String,
    paranoia_level: u8,
    targets: Vec<String>,
    transforms: Vec<String>,
    pattern: String,
    explanation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    owasp_category: Option<String>,
}

pub fn convert_crs_path(input: &Path, output: &Path) -> anyhow::Result<ConversionSummary> {
    let input_files = crs_input_files(input)?;
    let mut rules = Vec::new();
    let mut skipped = 0;

    for input_file in input_files {
        let contents = fs::read_to_string(&input_file)
            .with_context(|| format!("failed to read CRS rule file {}", input_file.display()))?;
        let (mut converted_rules, skipped_rules) = convert_crs_contents(&contents);
        rules.append(&mut converted_rules);
        skipped += skipped_rules;
    }

    let converted = rules.len();
    let rule_file = SaugraRuleFile {
        metadata: SaugraRuleMetadata {
            name: "converted-owasp-crs-rules".to_string(),
            version: "generated".to_string(),
        },
        rules,
    };
    let yaml = serde_yaml::to_string(&rule_file).context("failed to serialize converted rules")?;

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output directory {}", parent.display()))?;
    }
    fs::write(output, yaml)
        .with_context(|| format!("failed to write converted rules to {}", output.display()))?;

    Ok(ConversionSummary { converted, skipped })
}

fn crs_input_files(input: &Path) -> anyhow::Result<Vec<PathBuf>> {
    if input.is_file() {
        return Ok(vec![input.to_path_buf()]);
    }

    let mut files = Vec::new();
    for entry in fs::read_dir(input)
        .with_context(|| format!("failed to read CRS directory {}", input.display()))?
    {
        let path = entry?.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("conf") {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn convert_crs_contents(contents: &str) -> (Vec<SaugraRule>, usize) {
    let mut converted = Vec::new();
    let mut skipped = 0;

    for statement in sec_rule_statements(contents) {
        match parse_sec_rule(&statement) {
            Some(rule) => converted.push(rule),
            None => skipped += 1,
        }
    }

    (converted, skipped)
}

fn sec_rule_statements(contents: &str) -> Vec<String> {
    let mut statements = Vec::new();
    let mut current = String::new();

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with("SecRule ") && !current.is_empty() {
            statements.push(current.trim().to_string());
            current.clear();
        }

        if trimmed.starts_with("SecRule ") || !current.is_empty() {
            let continued = trimmed.ends_with('\\');
            current.push_str(trimmed.trim_end_matches('\\').trim_end());
            current.push(' ');

            if !continued {
                statements.push(current.trim().to_string());
                current.clear();
            }
        }
    }

    if !current.trim().is_empty() {
        statements.push(current.trim().to_string());
    }

    statements
}

fn parse_sec_rule(statement: &str) -> Option<SaugraRule> {
    let rest = statement.strip_prefix("SecRule ")?;
    let operator_start = rest.find('"')?;
    let variables = rest[..operator_start].trim();
    let (operator, after_operator) = read_quoted(&rest[operator_start..])?;
    let actions_start = after_operator.find('"')?;
    let (actions, _) = read_quoted(&after_operator[actions_start..])?;
    let pattern = operator.strip_prefix("@rx ")?.to_string();
    let id = action_value(&actions, "id")?;
    let message = action_value(&actions, "msg").unwrap_or_else(|| "Converted CRS rule".to_string());
    let severity = normalize_severity(
        &action_value(&actions, "severity").unwrap_or_else(|| "WARNING".to_string()),
    );
    let tags = action_values(&actions, "tag");
    let category = category_from_tags(&tags);
    let paranoia_level = paranoia_level_from_tags(&tags);
    let targets = targets_from_variables(variables);

    if targets.is_empty() {
        return None;
    }

    Some(SaugraRule {
        id: format!("CRS-{id}"),
        name: message.clone(),
        category,
        severity,
        paranoia_level,
        targets,
        transforms: vec!["url_decode".to_string(), "plus_to_space".to_string()],
        pattern,
        explanation: message,
        owasp_category: None,
    })
}

fn read_quoted(input: &str) -> Option<(String, &str)> {
    let mut escaped = false;
    let mut value = String::new();
    let mut chars = input.char_indices();

    if chars.next()?.1 != '"' {
        return None;
    }

    for (index, character) in chars {
        if escaped {
            value.push(character);
            escaped = false;
            continue;
        }

        match character {
            '\\' => escaped = true,
            '"' => return Some((value, &input[index + 1..])),
            _ => value.push(character),
        }
    }

    None
}

fn action_value(actions: &str, key: &str) -> Option<String> {
    action_values(actions, key).into_iter().next()
}

fn action_values(actions: &str, key: &str) -> Vec<String> {
    let prefix = format!("{key}:");

    actions
        .split(',')
        .filter_map(|action| {
            let action = action.trim();
            action
                .strip_prefix(&prefix)
                .map(|value| value.trim_matches('\'').trim_matches('"').to_string())
        })
        .collect()
}

fn normalize_severity(severity: &str) -> String {
    match severity.trim_matches('\'').to_ascii_uppercase().as_str() {
        "CRITICAL" => "critical",
        "ERROR" => "high",
        "WARNING" => "medium",
        "NOTICE" => "low",
        _ => "medium",
    }
    .to_string()
}

fn category_from_tags(tags: &[String]) -> String {
    for tag in tags {
        match tag.as_str() {
            "attack-sqli" | "OWASP_CRS/ATTACK-SQLI" => return "sql_injection".to_string(),
            "attack-xss" | "OWASP_CRS/ATTACK-XSS" => return "cross_site_scripting".to_string(),
            "attack-lfi" | "OWASP_CRS/ATTACK-LFI" => return "path_traversal".to_string(),
            "attack-rce" | "OWASP_CRS/ATTACK-RCE" => return "command_injection".to_string(),
            "attack-scanner" => return "scanner_behavior".to_string(),
            _ => {}
        }
    }

    "crs_import".to_string()
}

fn paranoia_level_from_tags(tags: &[String]) -> u8 {
    tags.iter()
        .find_map(|tag| tag.strip_prefix("paranoia-level/"))
        .and_then(|level| level.parse::<u8>().ok())
        .unwrap_or(1)
}

fn targets_from_variables(variables: &str) -> Vec<String> {
    let mut targets = Vec::new();

    if variables.contains("REQUEST_FILENAME") || variables.contains("REQUEST_BASENAME") {
        targets.push("path".to_string());
    }
    if variables.contains("ARGS") || variables.contains("REQUEST_COOKIES") {
        targets.push("query".to_string());
    }
    if variables.contains("REQUEST_HEADERS") {
        targets.push("headers".to_string());
    }
    if variables.contains("REQUEST_BODY") || variables.contains("XML:") {
        targets.push("body".to_string());
    }

    targets.sort();
    targets.dedup();
    targets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_crs_regex_rule() {
        let contents = r#"
SecRule ARGS "@rx (?i)union.*?select" \
    "id:942270,\
    phase:2,\
    block,\
    t:none,t:urlDecodeUni,\
    msg:'Looking for basic sql injection',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    severity:'CRITICAL'"
"#;

        let (rules, skipped) = convert_crs_contents(contents);

        assert_eq!(skipped, 0);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "CRS-942270");
        assert_eq!(rules[0].category, "sql_injection");
        assert_eq!(rules[0].severity, "critical");
        assert_eq!(rules[0].targets, vec!["query"]);
    }

    #[test]
    fn skips_unsupported_crs_operator() {
        let contents = r#"
SecRule ARGS "@detectSQLi" "id:942100,phase:2,block,msg:'libinjection',severity:'CRITICAL'"
"#;

        let (rules, skipped) = convert_crs_contents(contents);

        assert!(rules.is_empty());
        assert_eq!(skipped, 1);
    }
}
