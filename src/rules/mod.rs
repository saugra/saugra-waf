mod engine;
mod pack;
mod replay;
mod reports;
#[cfg(test)]
mod tests;
mod types;

pub use pack::{builtin_rules, load_rule_set, load_rule_set_with_report, validate_rule_file};
pub use replay::{
    attach_labeled_replay, replay_events, replay_events_with_exclusions, RuleReplayReport,
};
pub use reports::{RuleExclusionReport, RuleFileLoadReport, RuleLoadReport};
pub use types::{
    BuiltinRule, PerformanceCostTier, RequestParts, RuleError, RuleMatch, RuleSeverity, RuleTarget,
    RuleTransform,
};

#[derive(Debug, Clone)]
pub struct RuleSet {
    rules: Vec<BuiltinRule>,
}
