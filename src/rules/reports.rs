use crate::config::RuleExclusionConfig;

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

impl RuleExclusionReport {
    pub fn from_exclusions(exclusions: &[RuleExclusionConfig]) -> Self {
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
