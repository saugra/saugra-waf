use crate::decision::WafDecision;

pub fn explain(decision: &WafDecision) -> String {
    if decision.matched_rules.is_empty() {
        return "No rules matched this request, so Saugra allowed it.".to_string();
    }

    let rule = &decision.matched_rules[0];
    format!(
        "This request was flagged because {} matched rule {} ({}) with {} severity.",
        rule.matched_target, rule.rule_id, rule.rule_name, rule.severity
    )
}
