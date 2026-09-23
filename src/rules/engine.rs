use percent_encoding::percent_decode_str;

use crate::config::RuleExclusionConfig;

use super::{
    types::{BuiltinRule, RequestParts, RuleMatch, RuleTarget, RuleTransform},
    RuleSet,
};

impl RuleSet {
    pub fn new(rules: Vec<BuiltinRule>) -> Self {
        Self { rules }
    }

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

pub fn normalize_rule_input(
    target: RuleTarget,
    input: &str,
    transforms: &[RuleTransform],
) -> String {
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

pub fn is_excluded(
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
