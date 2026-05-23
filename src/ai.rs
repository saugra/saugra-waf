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
        behavior::{BehaviorContributor, BehaviorOutcome},
        bot::BotProtectionOutcome,
        config::{RuntimeAllowlistEffect, WafMode},
        decision::{WafAction, WafDecision},
        rules::{RuleMatch, RuleSeverity, RuleTarget},
        runtime_policy::RuntimeAllowlistMatch,
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

    #[test]
    fn explanation_for_clean_request_reports_allow_decision() {
        let decision =
            WafDecision::from_matches("request-1".to_string(), WafMode::Block, Vec::new(), 5);

        let explanation = explain(&decision);

        assert_eq!(
            explanation,
            "No rules matched this request, so Saugra allowed it."
        );
    }

    #[test]
    fn explanation_for_clean_request_includes_runtime_allowlist_context() {
        let decision =
            WafDecision::from_matches("request-1".to_string(), WafMode::Block, Vec::new(), 5)
                .with_runtime_allowlist(runtime_allowlist_match(RuntimeAllowlistEffect::AllowAll));

        let explanation = explain(&decision);

        assert!(explanation.contains("No rules matched this request"));
        assert!(explanation.contains("Runtime allowlist entry admin-ip matched 203.0.113.10"));
        assert!(explanation.contains("AllowAll"));
    }

    #[test]
    fn explanation_for_bot_only_decision_reports_thresholds_and_contributors() {
        let decision =
            WafDecision::from_matches("request-1".to_string(), WafMode::Block, Vec::new(), 5)
                .with_bot_protection(bot_outcome());

        let explanation = explain(&decision);

        assert!(explanation.contains("No request rules matched."));
        assert!(
            explanation.contains("Bot protection score is 80/40 for monitor and 80/80 for block")
        );
        assert!(explanation.contains("with 2 contributor(s)"));
    }

    #[test]
    fn explanation_for_behavior_only_decision_reports_thresholds() {
        let decision =
            WafDecision::from_matches("request-1".to_string(), WafMode::Block, Vec::new(), 5)
                .with_behavior(behavior_outcome());

        let explanation = explain(&decision);

        assert!(explanation.contains("No request rules matched."));
        assert!(explanation.contains("Behavior score is 93/40 for monitor and 93/80 for block."));
    }

    #[test]
    fn explanation_for_unmapped_rule_says_no_specific_owasp_category() {
        let decision = WafDecision::from_matches(
            "request-1".to_string(),
            WafMode::Monitor,
            vec![RuleMatch {
                owasp_category: None,
                ..rule_match()
            }],
            5,
        );

        let explanation = explain(&decision);

        assert!(explanation.contains("It is not mapped to a specific OWASP category."));
        assert!(explanation.contains("SAUGRA-TEST-001"));
    }

    #[test]
    fn explanation_for_matched_rule_includes_behavior_bot_and_allowlist_context() {
        let decision = WafDecision::from_matches(
            "request-1".to_string(),
            WafMode::Block,
            vec![rule_match()],
            5,
        )
        .with_behavior(behavior_outcome())
        .with_bot_protection(bot_outcome())
        .with_runtime_allowlist(runtime_allowlist_match(
            RuntimeAllowlistEffect::SkipBotAndBehaviorBlock,
        ));

        let explanation = explain(&decision);

        assert!(explanation.contains("headers matched rule SAUGRA-TEST-001"));
        assert!(explanation.contains(
            "Behavior score is 93/40 for monitor and 93/80 for block with 2 contributor(s)."
        ));
        assert!(explanation.contains(
            "Bot protection score is 80/40 for monitor and 80/80 for block with 2 contributor(s)."
        ));
        assert!(explanation.contains("Runtime allowlist entry admin-ip matched 203.0.113.10"));
        assert!(explanation.contains("SkipBotAndBehaviorBlock"));
    }

    fn rule_match() -> RuleMatch {
        RuleMatch {
            rule_id: "SAUGRA-TEST-001".to_string(),
            rule_name: "Test Rule".to_string(),
            category: "test".to_string(),
            severity: RuleSeverity::High,
            matched_target: RuleTarget::Headers,
            paranoia_level: 1,
            explanation: "Test rule matched.".to_string(),
            owasp_category: Some("A06:2025-Insecure Design".to_string()),
        }
    }

    fn behavior_outcome() -> BehaviorOutcome {
        BehaviorOutcome {
            enabled: true,
            action: WafAction::Monitor,
            score: 93,
            monitor_threshold: 40,
            block_threshold: 80,
            score_window_seconds: 600,
            decay_window_seconds: 1_800,
            storage_backend: "local".to_string(),
            contributors: contributors(),
        }
    }

    fn bot_outcome() -> BotProtectionOutcome {
        BotProtectionOutcome {
            enabled: true,
            action: WafAction::Block,
            score: 80,
            monitor_threshold: 40,
            block_threshold: 80,
            score_window_seconds: 600,
            temporary_block_duration_seconds: 900,
            temporary_blocked_until: None,
            storage_backend: "local".to_string(),
            allowlisted: false,
            blocklisted: false,
            contributors: contributors(),
        }
    }

    fn contributors() -> Vec<BehaviorContributor> {
        vec![
            BehaviorContributor {
                reason: "scanner_path".to_string(),
                score_delta: 40,
            },
            BehaviorContributor {
                reason: "rule_match:bot_protection".to_string(),
                score_delta: 40,
            },
        ]
    }

    fn runtime_allowlist_match(effect: RuntimeAllowlistEffect) -> RuntimeAllowlistMatch {
        RuntimeAllowlistMatch {
            id: "admin-ip".to_string(),
            match_type: "ip".to_string(),
            value: "203.0.113.10".to_string(),
            effect,
            reason: "admin access".to_string(),
            expires_at_unix_seconds: None,
        }
    }
}
