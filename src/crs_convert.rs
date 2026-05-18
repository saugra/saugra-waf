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
    unsupported_imports: Vec<UnsupportedImport>,
    rules: Vec<SaugraRule>,
}

#[derive(Debug, Serialize)]
struct SaugraRuleMetadata {
    name: String,
    version: String,
    standards: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct UnsupportedImport {
    id: Option<String>,
    reason: String,
    statement: String,
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
    let mut unsupported_imports = Vec::new();
    let base_dir = if input.is_file() {
        input.parent().unwrap_or_else(|| Path::new("."))
    } else {
        input
    };

    for input_file in input_files {
        let contents = fs::read_to_string(&input_file)
            .with_context(|| format!("failed to read CRS rule file {}", input_file.display()))?;
        let (mut converted_rules, mut skipped_rules) =
            convert_crs_contents_with_base(&contents, Some(base_dir));
        rules.append(&mut converted_rules);
        unsupported_imports.append(&mut skipped_rules);
    }

    let converted = rules.len();
    let skipped = unsupported_imports.len();
    let rule_file = SaugraRuleFile {
        metadata: SaugraRuleMetadata {
            name: "converted-owasp-crs-rules".to_string(),
            version: "generated".to_string(),
            standards: vec!["owasp-crs-converted".to_string()],
        },
        unsupported_imports,
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

#[cfg(test)]
fn convert_crs_contents(contents: &str) -> (Vec<SaugraRule>, Vec<UnsupportedImport>) {
    convert_crs_contents_with_base(contents, None)
}

fn convert_crs_contents_with_base(
    contents: &str,
    base_dir: Option<&Path>,
) -> (Vec<SaugraRule>, Vec<UnsupportedImport>) {
    let mut converted = Vec::new();
    let mut unsupported_imports = Vec::new();

    for statement in sec_rule_statements(contents) {
        match parse_sec_rule(&statement, base_dir) {
            Some(rule) => converted.push(rule),
            None => unsupported_imports.push(unsupported_import(&statement, base_dir)),
        }
    }

    (converted, unsupported_imports)
}

fn unsupported_import(statement: &str, base_dir: Option<&Path>) -> UnsupportedImport {
    UnsupportedImport {
        id: crs_rule_id(statement).map(|id| format!("CRS-{id}")),
        reason: unsupported_reason(statement, base_dir),
        statement: statement.to_string(),
    }
}

fn crs_rule_id(statement: &str) -> Option<String> {
    let rest = statement.strip_prefix("SecRule ")?;
    let operator_start = rest.find('"')?;
    let (_, after_operator) = read_quoted(&rest[operator_start..])?;
    let actions_start = after_operator.find('"')?;
    let (actions, _) = read_quoted(&after_operator[actions_start..])?;
    action_value(&actions, "id")
}

fn unsupported_reason(statement: &str, base_dir: Option<&Path>) -> String {
    if !statement.starts_with("SecRule ") {
        return "unsupported CRS statement".to_string();
    }

    let Some(operator_start) = statement.find('"') else {
        return "missing operator".to_string();
    };
    let Some((operator, after_operator)) = read_quoted(&statement[operator_start..]) else {
        return "invalid quoted operator".to_string();
    };

    if !(operator.starts_with("@rx ") || operator.starts_with("@pmFromFile ")) {
        return format!(
            "unsupported operator {}; only @rx and @pmFromFile are currently converted",
            operator.split_whitespace().next().unwrap_or(&operator)
        );
    }

    if after_operator.find('"').is_none() {
        return "missing action list".to_string();
    }

    let actions_start = after_operator.find('"').unwrap_or_default();
    if let Some((actions, _)) = read_quoted(&after_operator[actions_start..]) {
        if has_chain_action(&actions) {
            return "chained CRS rules are not yet converted; import the rule as a custom Saugra rule or keep it in unsupported_imports".to_string();
        }

        if let Some(transform) = unsupported_transform(&actions) {
            return format!(
                "unsupported transform {transform}; supported transforms are t:none, t:urlDecode, t:urlDecodeUni, and t:lowercase"
            );
        }
    }

    let variables = statement
        .strip_prefix("SecRule ")
        .map(|rest| rest[..operator_start - "SecRule ".len()].trim())
        .unwrap_or_default();
    if targets_from_variables(variables).is_empty() {
        return "unsupported CRS variables; no Saugra request target mapping".to_string();
    }

    if let Some(data_file) = operator.strip_prefix("@pmFromFile ") {
        return match pm_from_file_pattern(data_file, base_dir) {
            Some(_) => "unsupported CRS rule shape".to_string(),
            None => format!("unable to read @pmFromFile data file {}", data_file.trim()),
        };
    }

    "unsupported CRS rule shape".to_string()
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

fn parse_sec_rule(statement: &str, base_dir: Option<&Path>) -> Option<SaugraRule> {
    let rest = statement.strip_prefix("SecRule ")?;
    let operator_start = rest.find('"')?;
    let variables = rest[..operator_start].trim();
    let (operator, after_operator) = read_quoted(&rest[operator_start..])?;
    let actions_start = after_operator.find('"')?;
    let (actions, _) = read_quoted(&after_operator[actions_start..])?;
    if has_chain_action(&actions) {
        return None;
    }

    let pattern = operator_pattern(&operator, base_dir)?;
    let id = action_value(&actions, "id")?;
    let message = action_value(&actions, "msg").unwrap_or_else(|| "Converted CRS rule".to_string());
    let severity = normalize_severity(
        &action_value(&actions, "severity").unwrap_or_else(|| "WARNING".to_string()),
    );
    let tags = action_values(&actions, "tag");
    let category = category_from_tags(&tags);
    let paranoia_level = paranoia_level_from_tags(&tags);
    let targets = targets_from_variables(variables);
    let transforms = transforms_from_actions(&actions)?;

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
        transforms,
        pattern,
        explanation: message,
        owasp_category: None,
    })
}

fn operator_pattern(operator: &str, base_dir: Option<&Path>) -> Option<String> {
    if let Some(pattern) = operator.strip_prefix("@rx ") {
        return Some(pattern.to_string());
    }

    if let Some(data_file) = operator.strip_prefix("@pmFromFile ") {
        return pm_from_file_pattern(data_file, base_dir);
    }

    None
}

fn pm_from_file_pattern(data_file: &str, base_dir: Option<&Path>) -> Option<String> {
    let data_file = data_file.trim().trim_matches('\'').trim_matches('"');
    let path = Path::new(data_file);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir?.join(path)
    };
    let contents = fs::read_to_string(path).ok()?;
    let terms = contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(regex::escape)
        .collect::<Vec<_>>();

    if terms.is_empty() {
        return None;
    }

    Some(format!("(?:{})", terms.join("|")))
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

fn has_chain_action(actions: &str) -> bool {
    actions
        .split(',')
        .map(str::trim)
        .any(|action| action == "chain")
}

fn transforms_from_actions(actions: &str) -> Option<Vec<String>> {
    if unsupported_transform(actions).is_some() {
        return None;
    }

    let mut transforms = Vec::new();

    for action in actions.split(',').map(str::trim) {
        match action {
            "t:none" => transforms.clear(),
            "t:urlDecode" | "t:urlDecodeUni" => transforms.push("url_decode".to_string()),
            "t:lowercase" => transforms.push("lowercase".to_string()),
            _ => {}
        }
    }

    Some(transforms)
}

fn unsupported_transform(actions: &str) -> Option<String> {
    actions.split(',').map(str::trim).find_map(|action| {
        if action.starts_with("t:")
            && !matches!(
                action,
                "t:none" | "t:urlDecode" | "t:urlDecodeUni" | "t:lowercase"
            )
        {
            Some(action.to_string())
        } else {
            None
        }
    })
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
            "protocol-violation" | "OWASP_CRS/PROTOCOL-VIOLATION" => {
                return "protocol_enforcement".to_string()
            }
            "attack-file-upload" | "OWASP_CRS/ATTACK-FILE-UPLOAD" => {
                return "file_upload".to_string()
            }
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
    if variables.contains("FILES_NAMES") || variables.contains("FILES_TMPNAMES") {
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

        assert!(skipped.is_empty());
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "CRS-942270");
        assert_eq!(rules[0].category, "sql_injection");
        assert_eq!(rules[0].severity, "critical");
        assert_eq!(rules[0].targets, vec!["query"]);
        assert_eq!(rules[0].transforms, vec!["url_decode"]);
    }

    #[test]
    fn converts_supported_crs_transforms_in_order() {
        let contents = r#"
SecRule ARGS "@rx union" "id:942271,phase:2,block,t:none,t:urlDecode,t:lowercase,msg:'Transform order',severity:'WARNING'"
"#;

        let (rules, skipped) = convert_crs_contents(contents);

        assert!(skipped.is_empty());
        assert_eq!(rules[0].transforms, vec!["url_decode", "lowercase"]);
    }

    #[test]
    fn skips_unsupported_crs_transform() {
        let contents = r#"
SecRule ARGS "@rx union" "id:942272,phase:2,block,t:none,t:cmdLine,msg:'Unsupported transform',severity:'WARNING'"
"#;

        let (rules, skipped) = convert_crs_contents(contents);

        assert!(rules.is_empty());
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].id.as_deref(), Some("CRS-942272"));
        assert!(skipped[0]
            .reason
            .contains("unsupported transform t:cmdLine"));
    }

    #[test]
    fn converts_pm_from_file_rule_with_data_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let data_dir = temp_dir.path().join("util").join("regexp-assemble");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(
            data_dir.join("sql-keywords.data"),
            r#"
# comments are ignored
union select
sleep(
"#,
        )
        .unwrap();
        let contents = r#"
SecRule ARGS "@pmFromFile util/regexp-assemble/sql-keywords.data" \
    "id:942400,\
    phase:2,\
    block,\
    t:none,t:lowercase,\
    msg:'SQL keywords from data file',\
    tag:'attack-sqli',\
    severity:'CRITICAL'"
"#;

        let (rules, skipped) = convert_crs_contents_with_base(contents, Some(temp_dir.path()));

        assert!(skipped.is_empty());
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "CRS-942400");
        assert_eq!(rules[0].category, "sql_injection");
        assert_eq!(rules[0].transforms, vec!["lowercase"]);
        assert!(rules[0].pattern.contains("union select"));
        assert!(rules[0].pattern.contains("sleep\\("));
    }

    #[test]
    fn reports_missing_pm_from_file_data_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let contents = r#"
SecRule ARGS "@pmFromFile missing.data" "id:942401,phase:2,block,msg:'missing data file',severity:'CRITICAL'"
"#;

        let (rules, skipped) = convert_crs_contents_with_base(contents, Some(temp_dir.path()));

        assert!(rules.is_empty());
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].id.as_deref(), Some("CRS-942401"));
        assert!(skipped[0].reason.contains("unable to read @pmFromFile"));
    }

    #[test]
    fn reports_chained_rules_as_unsupported() {
        let contents = r#"
SecRule ARGS "@rx first" "id:942402,phase:2,block,chain,msg:'chain starter',severity:'CRITICAL'"
SecRule ARGS "@rx second" "t:none"
"#;

        let (rules, skipped) = convert_crs_contents(contents);

        assert!(rules.is_empty());
        assert_eq!(skipped.len(), 2);
        assert_eq!(skipped[0].id.as_deref(), Some("CRS-942402"));
        assert!(skipped[0].reason.contains("chained CRS rules"));
    }

    #[test]
    fn converts_representative_crs_categories() {
        let contents = r#"
SecRule ARGS "@rx <script" "id:941100,phase:2,block,msg:'xss',tag:'attack-xss',severity:'CRITICAL'"
SecRule REQUEST_FILENAME "@rx \.\./" "id:930100,phase:2,block,msg:'lfi',tag:'attack-lfi',severity:'CRITICAL'"
SecRule ARGS "@rx ;id" "id:932100,phase:2,block,msg:'rce',tag:'attack-rce',severity:'CRITICAL'"
SecRule REQUEST_HEADERS "@rx nikto" "id:913100,phase:1,block,msg:'scanner',tag:'attack-scanner',severity:'WARNING'"
SecRule REQUEST_HEADERS "@rx bad-protocol" "id:920100,phase:1,block,msg:'protocol',tag:'protocol-violation',severity:'WARNING'"
SecRule FILES_NAMES "@rx \.php$" "id:933100,phase:2,block,msg:'file upload',tag:'attack-file-upload',severity:'CRITICAL'"
"#;

        let (rules, skipped) = convert_crs_contents(contents);
        let categories = rules
            .iter()
            .map(|rule| {
                (
                    rule.id.as_str(),
                    rule.category.as_str(),
                    rule.targets.clone(),
                )
            })
            .collect::<Vec<_>>();

        assert!(skipped.is_empty());
        assert_eq!(rules.len(), 6);
        assert!(categories.contains(&(
            "CRS-941100",
            "cross_site_scripting",
            vec!["query".to_string()]
        )));
        assert!(categories.contains(&("CRS-930100", "path_traversal", vec!["path".to_string()])));
        assert!(categories.contains(&(
            "CRS-932100",
            "command_injection",
            vec!["query".to_string()]
        )));
        assert!(categories.contains(&(
            "CRS-913100",
            "scanner_behavior",
            vec!["headers".to_string()]
        )));
        assert!(categories.contains(&(
            "CRS-920100",
            "protocol_enforcement",
            vec!["headers".to_string()]
        )));
        assert!(categories.contains(&("CRS-933100", "file_upload", vec!["body".to_string()])));
    }

    #[test]
    fn skips_unsupported_crs_operator() {
        let contents = r#"
SecRule ARGS "@detectSQLi" "id:942100,phase:2,block,msg:'libinjection',severity:'CRITICAL'"
"#;

        let (rules, skipped) = convert_crs_contents(contents);

        assert!(rules.is_empty());
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].id.as_deref(), Some("CRS-942100"));
        assert!(skipped[0].reason.contains("unsupported operator"));
    }
}
