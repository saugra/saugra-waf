use crate::decision::WafDecision;

pub fn explain(decision: &WafDecision) -> String {
    if decision.matched_rules.is_empty() {
        return "No rules matched this request, so Saugra allowed it.".to_string();
    }

    let rule = &decision.matched_rules[0];
    let owasp_context = if decision.owasp_categories.is_empty() {
        "It is not mapped to a specific OWASP category.".to_string()
    } else {
        format!(
            "It maps to OWASP category {}.",
            decision.owasp_categories.join(", ")
        )
    };

    format!(
        "This request was flagged because {} matched rule {} ({}) with {} severity. {} Anomaly score is {}/{}.",
        rule.matched_target,
        rule.rule_id,
        rule.rule_name,
        rule.severity,
        owasp_context,
        decision.anomaly_score,
        decision.anomaly_threshold
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::WafMode,
        decision::WafDecision,
        rules::{RuleMatch, RuleSeverity, RuleTarget},
    };

    #[test]
    fn explanation_includes_owasp_category_context() {
        let decision = WafDecision::from_matches(
            "request-1".to_string(),
            WafMode::Block,
            vec![RuleMatch {
                rule_id: "SAUGRA-SQLI-001".to_string(),
                rule_name: "Basic SQL Injection Pattern".to_string(),
                category: "sql_injection".to_string(),
                severity: RuleSeverity::High,
                matched_target: RuleTarget::Query,
                explanation: "SQLi matched.".to_string(),
                owasp_category: Some("A05:2025-Injection".to_string()),
            }],
            5,
        );

        let explanation = explain(&decision);

        assert!(explanation.contains("A05:2025-Injection"));
        assert!(explanation.contains("Anomaly score is 5/5"));
    }
}
