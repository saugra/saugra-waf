use crate::decision::WafDecision;

pub fn explain(decision: &WafDecision) -> String {
    let allowlist_context = decision
        .runtime_allowlist
        .as_ref()
        .map(|allowlist| {
            format!(
                " Runtime allowlist entry {} matched {} with effect {:?}.",
                allowlist.id, allowlist.value, allowlist.effect
            )
        })
        .unwrap_or_default();

    if decision.matched_rules.is_empty() {
        if let Some(bot_protection) = &decision.bot_protection {
            return format!(
                "No request rules matched. Bot protection score is {}/{} for monitor and {}/{} for block with {} contributor(s).",
                bot_protection.score,
                bot_protection.monitor_threshold,
                bot_protection.score,
                bot_protection.block_threshold,
                bot_protection.contributors.len()
            ) + &allowlist_context;
        }
        if let Some(behavior) = &decision.behavior {
            return format!(
                "No request rules matched. Behavior score is {}/{} for monitor and {}/{} for block.",
                behavior.score,
                behavior.monitor_threshold,
                behavior.score,
                behavior.block_threshold
            ) + &allowlist_context;
        }
        return "No rules matched this request, so Saugra allowed it.".to_string()
            + &allowlist_context;
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

    let behavior_context = decision
        .behavior
        .as_ref()
        .map(|behavior| {
            format!(
                " Behavior score is {}/{} for monitor and {}/{} for block with {} contributor(s).",
                behavior.score,
                behavior.monitor_threshold,
                behavior.score,
                behavior.block_threshold,
                behavior.contributors.len()
            )
        })
        .unwrap_or_default();
    let bot_context = decision
        .bot_protection
        .as_ref()
        .map(|bot_protection| {
            format!(
                " Bot protection score is {}/{} for monitor and {}/{} for block with {} contributor(s).",
                bot_protection.score,
                bot_protection.monitor_threshold,
                bot_protection.score,
                bot_protection.block_threshold,
                bot_protection.contributors.len()
            )
        })
        .unwrap_or_default();

    format!(
        "This request was flagged because {} matched rule {} ({}) with {} severity. {} Anomaly score is {}/{}.",
        rule.matched_target,
        rule.rule_id,
        rule.rule_name,
        rule.severity,
        owasp_context,
        decision.anomaly_score,
        decision.anomaly_threshold
    ) + &behavior_context
        + &bot_context
        + &allowlist_context
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
                paranoia_level: 1,
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
