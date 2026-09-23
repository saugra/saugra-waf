use std::{fs, path::Path};

use regex::Regex;
use serde::Deserialize;

use crate::config::{RuleExclusionConfig, RuleSettings};

use super::{
    reports::{RuleExclusionReport, RuleFileLoadReport, RuleLoadReport},
    types::{BuiltinRule, PerformanceCostTier, RuleError, RuleSeverity, RuleTarget, RuleTransform},
    RuleSet,
};

const DEFAULT_RULE_PACKS: &[&str] = &[
    include_str!("../../configs/rules/REQUEST-913-SCANNER-DETECTION.yml"),
    include_str!("../../configs/rules/REQUEST-914-AUTHENTICATION-ABUSE.yml"),
    include_str!("../../configs/rules/REQUEST-916-INSECURE-DESIGN.yml"),
    include_str!("../../configs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.yml"),
    include_str!("../../configs/rules/REQUEST-921-CRYPTO-TRANSPORT.yml"),
    include_str!("../../configs/rules/REQUEST-932-APPLICATION-ATTACK-RCE.yml"),
    include_str!("../../configs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.yml"),
    include_str!("../../configs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.yml"),
    include_str!("../../configs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.yml"),
    include_str!("../../configs/rules/REQUEST-944-SUPPLY-CHAIN.yml"),
    include_str!("../../configs/rules/REQUEST-945-INTEGRITY.yml"),
    include_str!("../../configs/rules/REQUEST-949-LOGGING-ALERTING.yml"),
    include_str!("../../configs/rules/REQUEST-950-EXCEPTIONAL-CONDITIONS.yml"),
];

pub fn builtin_rules() -> Result<Vec<BuiltinRule>, RuleError> {
    let mut rules = Vec::new();

    for contents in DEFAULT_RULE_PACKS {
        let (mut pack_rules, _report) =
            compile_rule_pack(contents, "<embedded saugra-waf rule pack>", u8::MAX)?;
        rules.append(&mut pack_rules);
    }

    Ok(rules)
}

pub fn load_rule_set(settings: &RuleSettings) -> Result<RuleSet, RuleError> {
    load_rule_set_with_report(settings).map(|(rule_set, _report)| rule_set)
}

pub fn load_rule_set_with_report(
    settings: &RuleSettings,
) -> Result<(RuleSet, RuleLoadReport), RuleError> {
    let mut rules = Vec::new();
    let mut report = RuleLoadReport {
        files: Vec::new(),
        standards: Vec::new(),
        total_entries: 0,
        enabled_entries: 0,
        disabled_entries: 0,
        compiled_rules: 0,
        filtered_by_paranoia: 0,
        active_rules: 0,
        transform_pipelines: 0,
        exclusions: RuleExclusionReport::from_exclusions(&settings.exclusions),
        warnings: Vec::new(),
    };
    report
        .warnings
        .extend(exclusion_warnings(&settings.exclusions));

    for path in &settings.files {
        let (mut file_rules, file_report) =
            load_rule_file(path, settings.detection_paranoia_level())?;
        report.total_entries += file_report.entries;
        report.enabled_entries += file_report.enabled_entries;
        report.disabled_entries += file_report.disabled_entries;
        report.compiled_rules += file_report.compiled_rules;
        report.filtered_by_paranoia += file_report.filtered_by_paranoia;
        report.active_rules += file_report.active_rules;
        report.transform_pipelines += file_report.transform_pipelines;
        report.warnings.extend(file_report.warnings.iter().cloned());
        report
            .standards
            .extend(file_report.standards.iter().cloned());
        report.files.push(file_report);
        rules.append(&mut file_rules);
    }

    report.standards.sort();
    report.standards.dedup();
    report
        .warnings
        .extend(contextual_exclusion_warnings(&settings.exclusions, &rules));

    if rules.is_empty() {
        return Err(RuleError::EmptyRuleSet);
    }

    Ok((RuleSet::new(rules), report))
}

pub fn validate_rule_file(
    path: &Path,
    paranoia_level: u8,
) -> Result<(RuleSet, RuleFileLoadReport), RuleError> {
    let (rules, report) = load_rule_file(path, paranoia_level)?;
    Ok((RuleSet::new(rules), report))
}

fn load_rule_file(
    path: &Path,
    paranoia_level: u8,
) -> Result<(Vec<BuiltinRule>, RuleFileLoadReport), RuleError> {
    let path_display = path.display().to_string();
    let contents = fs::read_to_string(path).map_err(|source| RuleError::Io {
        path: path_display.clone(),
        source,
    })?;

    compile_rule_pack(&contents, &path_display, paranoia_level)
}

fn compile_rule_pack(
    contents: &str,
    source_name: &str,
    paranoia_level: u8,
) -> Result<(Vec<BuiltinRule>, RuleFileLoadReport), RuleError> {
    let rule_file: RuleFile = serde_yaml::from_str(contents).map_err(|source| RuleError::Yaml {
        path: source_name.to_string(),
        source,
    })?;

    validate_rule_file_metadata(&rule_file, source_name)?;

    if rule_file.rules.is_empty() {
        return Err(RuleError::EmptyRuleFile {
            path: source_name.to_string(),
        });
    }

    let mut rules = Vec::new();
    let mut report = RuleFileLoadReport {
        path: source_name.to_string(),
        name: rule_file
            .metadata
            .as_ref()
            .map(|metadata| metadata.name.clone()),
        version: rule_file
            .metadata
            .as_ref()
            .map(|metadata| metadata.version.clone()),
        standards: rule_file
            .metadata
            .as_ref()
            .map(|metadata| metadata.standards.clone())
            .unwrap_or_default(),
        entries: rule_file.rules.len(),
        enabled_entries: 0,
        disabled_entries: 0,
        compiled_rules: 0,
        filtered_by_paranoia: 0,
        active_rules: 0,
        transform_pipelines: 0,
        unsupported_imports: rule_file.unsupported_imports.len(),
        warnings: rule_file_warnings(&rule_file, source_name),
    };

    for entry in rule_file.rules {
        if !entry.enabled {
            report.disabled_entries += 1;
            continue;
        }

        report.enabled_entries += 1;
        if entry.enabled && entry.targets.is_empty() {
            return Err(RuleError::MissingTargets { rule_id: entry.id });
        }
        if entry
            .design_intent
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(RuleError::InvalidRuleMetadata {
                rule_id: entry.id,
                field: "design_intent".to_string(),
            });
        }

        for definition in Vec::<RuleDefinition>::from(entry) {
            let rule = BuiltinRule::try_from(definition)?;
            report.compiled_rules += 1;
            if !rule.transforms.is_empty() {
                report.transform_pipelines += 1;
            }
            if rule.paranoia_level > paranoia_level {
                report.filtered_by_paranoia += 1;
                continue;
            }

            rules.push(rule);
            report.active_rules += 1;
        }
    }

    Ok((rules, report))
}

fn validate_rule_file_metadata(rule_file: &RuleFile, source_name: &str) -> Result<(), RuleError> {
    if let Some(metadata) = &rule_file.metadata {
        if metadata.name.trim().is_empty() {
            return Err(RuleError::InvalidMetadata {
                path: source_name.to_string(),
                field: "name".to_string(),
            });
        }

        if metadata.version.trim().is_empty() {
            return Err(RuleError::InvalidMetadata {
                path: source_name.to_string(),
                field: "version".to_string(),
            });
        }

        if metadata
            .standards
            .iter()
            .any(|standard| standard.trim().is_empty())
        {
            return Err(RuleError::InvalidMetadata {
                path: source_name.to_string(),
                field: "standards".to_string(),
            });
        }
    }

    Ok(())
}

fn rule_file_warnings(rule_file: &RuleFile, source_name: &str) -> Vec<String> {
    let mut warnings = Vec::new();

    if rule_file.metadata.is_none() {
        warnings.push(format!(
            "rule file {source_name} has no metadata.name or metadata.version"
        ));
    }

    for unsupported_import in &rule_file.unsupported_imports {
        warnings.push(format!(
            "rule file {source_name} skipped import {}: {}",
            unsupported_import
                .id
                .as_deref()
                .unwrap_or("unknown-rule-id"),
            unsupported_import.reason
        ));
    }

    warnings
}

fn contextual_exclusion_warnings(
    exclusions: &[RuleExclusionConfig],
    rules: &[BuiltinRule],
) -> Vec<String> {
    let mut warnings = Vec::new();

    for (index, exclusion) in exclusions.iter().enumerate() {
        let label = exclusion
            .name
            .as_deref()
            .filter(|name| !name.trim().is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| format!("#{}", index + 1));

        for rule_id in &exclusion.rule_ids {
            let matching_rules = rules
                .iter()
                .filter(|rule| &rule.id == rule_id)
                .collect::<Vec<_>>();
            if matching_rules.is_empty() {
                warnings.push(format!(
                    "rule exclusion {label} references unknown or inactive rule ID {rule_id}"
                ));
            } else if !exclusion.targets.is_empty()
                && !matching_rules
                    .iter()
                    .any(|rule| exclusion.targets.contains(&rule.target))
            {
                warnings.push(format!(
                    "rule exclusion {label} cannot match rule {rule_id} because their targets do not overlap"
                ));
            }
        }
    }

    warnings
}

fn exclusion_warnings(exclusions: &[RuleExclusionConfig]) -> Vec<String> {
    let mut warnings = Vec::new();

    for (index, exclusion) in exclusions.iter().enumerate() {
        let label = exclusion
            .name
            .as_deref()
            .filter(|name| !name.trim().is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| format!("#{}", index + 1));
        let has_context_scope = !exclusion.path_prefixes.is_empty()
            || !exclusion.query_params.is_empty()
            || !exclusion.headers.is_empty()
            || !exclusion.methods.is_empty()
            || !exclusion.targets.is_empty()
            || !exclusion.content_types.is_empty()
            || !exclusion.trusted_headers.is_empty()
            || !exclusion.identities.is_empty();

        if !has_context_scope {
            warnings.push(format!(
                "rule exclusion {label} is global and disables matching protection across all requests"
            ));
        }
        if !exclusion.trusted_headers.is_empty() || !exclusion.identities.is_empty() {
            warnings.push(format!(
                "rule exclusion {label} depends on trusted proxy assertions and will not match direct or untrusted peers"
            ));
        }
    }

    warnings
}

struct RuleDefinition {
    id: String,
    name: String,
    category: String,
    severity: RuleSeverity,
    performance_cost: Option<PerformanceCostTier>,
    target: RuleTarget,
    pattern: String,
    transforms: Vec<RuleTransform>,
    paranoia_level: u8,
    explanation: String,
    design_intent: Option<String>,
    owasp_category: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RuleFile {
    #[serde(default)]
    metadata: Option<RuleFileMetadata>,
    #[serde(default)]
    unsupported_imports: Vec<UnsupportedImport>,
    rules: Vec<RuleFileEntry>,
}

#[derive(Debug, Deserialize)]
struct RuleFileMetadata {
    name: String,
    version: String,
    #[serde(default)]
    standards: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct UnsupportedImport {
    #[serde(default)]
    id: Option<String>,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct RuleFileEntry {
    id: String,
    name: String,
    category: String,
    severity: RuleSeverity,
    #[serde(default)]
    performance_cost: Option<PerformanceCostTier>,
    targets: Vec<RuleTarget>,
    pattern: String,
    #[serde(default)]
    transforms: Vec<RuleTransform>,
    #[serde(default = "default_rule_paranoia_level")]
    paranoia_level: u8,
    explanation: String,
    #[serde(default)]
    design_intent: Option<String>,
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
                performance_cost: entry.performance_cost,
                target,
                pattern: entry.pattern.clone(),
                transforms: entry.transforms.clone(),
                paranoia_level: entry.paranoia_level,
                explanation: entry.explanation.clone(),
                design_intent: entry.design_intent.clone(),
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
            performance_cost: definition.performance_cost,
            target: definition.target,
            pattern,
            transforms: definition.transforms,
            paranoia_level: definition.paranoia_level,
            explanation: definition.explanation,
            owasp_category: definition.owasp_category,
            design_intent: definition.design_intent,
        })
    }
}
