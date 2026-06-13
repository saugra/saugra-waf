use serde::{Deserialize, Serialize};

use crate::{
    behavior::BehaviorOutcome, bot::BotProtectionOutcome, config::WafMode, rules::RuleMatch,
    runtime_policy::RuntimeAllowlistMatch, unknown_threats::UnknownThreatOutcome,
};

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WafAction {
    Allow,
    Monitor,
    Block,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WafDecision {
    pub request_id: String,
    pub action: WafAction,
    pub matched_rules: Vec<RuleMatch>,
    pub severity: String,
    pub risk_score: u8,
    pub anomaly_score: u16,
    #[serde(default)]
    pub blocking_anomaly_score: u16,
    pub anomaly_threshold: u16,
    #[serde(default = "default_blocking_paranoia_level")]
    pub blocking_paranoia_level: u8,
    pub explanation: String,
    pub owasp_category: Option<String>,
    pub owasp_categories: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behavior: Option<BehaviorOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unknown_threats: Option<UnknownThreatOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bot_protection: Option<BotProtectionOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_allowlist: Option<RuntimeAllowlistMatch>,
}

fn default_blocking_paranoia_level() -> u8 {
    u8::MAX
}

impl WafDecision {
    pub fn from_matches(
        request_id: String,
        mode: WafMode,
        matches: Vec<RuleMatch>,
        anomaly_threshold: u16,
    ) -> Self {
        Self::from_matches_with_blocking_paranoia(
            request_id,
            mode,
            matches,
            anomaly_threshold,
            u8::MAX,
        )
    }

    pub fn from_matches_with_blocking_paranoia(
        request_id: String,
        mode: WafMode,
        matches: Vec<RuleMatch>,
        anomaly_threshold: u16,
        blocking_paranoia_level: u8,
    ) -> Self {
        Self::from_matches_with_blocking_policy(
            request_id,
            mode,
            matches,
            anomaly_threshold,
            blocking_paranoia_level,
            &[],
        )
    }

    pub fn from_matches_with_blocking_policy(
        request_id: String,
        mode: WafMode,
        matches: Vec<RuleMatch>,
        anomaly_threshold: u16,
        blocking_paranoia_level: u8,
        non_blocking_match_indices: &[usize],
    ) -> Self {
        if matches.is_empty() || mode == WafMode::Off {
            return Self {
                request_id,
                action: WafAction::Allow,
                matched_rules: Vec::new(),
                severity: "none".to_string(),
                risk_score: 0,
                anomaly_score: 0,
                blocking_anomaly_score: 0,
                anomaly_threshold,
                blocking_paranoia_level,
                explanation: "No security rules matched this request.".to_string(),
                owasp_category: None,
                owasp_categories: Vec::new(),
                behavior: None,
                unknown_threats: None,
                bot_protection: None,
                runtime_allowlist: None,
            };
        }

        let anomaly_score = matches
            .iter()
            .map(|rule_match| rule_match.severity.anomaly_points())
            .sum();
        let blocking_anomaly_score = matches
            .iter()
            .enumerate()
            .filter(|(index, rule_match)| {
                rule_match.paranoia_level <= blocking_paranoia_level
                    && !non_blocking_match_indices.contains(index)
            })
            .map(|(_, rule_match)| rule_match.severity.anomaly_points())
            .sum();
        let has_blocking_eligible_match = matches.iter().enumerate().any(|(index, rule_match)| {
            rule_match.paranoia_level <= blocking_paranoia_level
                && !non_blocking_match_indices.contains(&index)
        });
        let risk_score = matches
            .iter()
            .map(|rule_match| rule_match.severity.risk_score())
            .max()
            .unwrap_or(0);
        let severity = matches
            .iter()
            .max_by_key(|rule_match| rule_match.severity.risk_score())
            .map(|rule_match| rule_match.severity.to_string())
            .unwrap_or_else(|| "none".to_string());
        let owasp_category = matches
            .iter()
            .find_map(|rule_match| rule_match.owasp_category.clone());
        let mut owasp_categories = matches
            .iter()
            .filter_map(|rule_match| rule_match.owasp_category.clone())
            .collect::<Vec<_>>();
        owasp_categories.sort();
        owasp_categories.dedup();
        let explanation = matches
            .first()
            .map(|rule_match| rule_match.explanation.clone())
            .unwrap_or_else(|| "A security rule matched this request.".to_string());

        Self {
            request_id,
            action: match mode {
                WafMode::Monitor => WafAction::Monitor,
                WafMode::Block if blocking_anomaly_score >= anomaly_threshold => WafAction::Block,
                WafMode::Block => WafAction::Monitor,
                WafMode::Strict if has_blocking_eligible_match => WafAction::Block,
                WafMode::Strict => WafAction::Monitor,
                WafMode::Off => WafAction::Allow,
            },
            matched_rules: matches,
            severity,
            risk_score,
            anomaly_score,
            blocking_anomaly_score,
            anomaly_threshold,
            blocking_paranoia_level,
            explanation,
            owasp_category,
            owasp_categories,
            behavior: None,
            unknown_threats: None,
            bot_protection: None,
            runtime_allowlist: None,
        }
    }

    pub fn with_behavior(mut self, behavior: BehaviorOutcome) -> Self {
        self.behavior = Some(behavior);
        self
    }

    pub fn with_unknown_threats(mut self, unknown_threats: UnknownThreatOutcome) -> Self {
        self.unknown_threats = Some(unknown_threats);
        self
    }

    pub fn with_bot_protection(mut self, bot_protection: BotProtectionOutcome) -> Self {
        self.bot_protection = Some(bot_protection);
        self
    }

    pub fn with_runtime_allowlist(mut self, runtime_allowlist: RuntimeAllowlistMatch) -> Self {
        self.runtime_allowlist = Some(runtime_allowlist);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{RuleMatch, RuleSeverity, RuleTarget};

    #[test]
    fn monitor_mode_marks_matched_requests_for_monitoring() {
        let decision = WafDecision::from_matches(
            "request-1".to_string(),
            WafMode::Monitor,
            vec![rule_match()],
            5,
        );

        assert_eq!(decision.action, WafAction::Monitor);
        assert_eq!(decision.risk_score, 80);
        assert_eq!(decision.severity, "high");
        assert_eq!(decision.matched_rules.len(), 1);
    }

    #[test]
    fn block_mode_blocks_matched_requests() {
        let decision = WafDecision::from_matches(
            "request-1".to_string(),
            WafMode::Block,
            vec![rule_match()],
            5,
        );

        assert_eq!(decision.action, WafAction::Block);
        assert_eq!(decision.risk_score, 80);
        assert_eq!(decision.anomaly_score, 5);
        assert_eq!(decision.blocking_anomaly_score, 5);
        assert_eq!(decision.anomaly_threshold, 5);
        assert_eq!(
            decision.owasp_category.as_deref(),
            Some("A05:2025-Injection")
        );
    }

    #[test]
    fn block_mode_monitors_matches_below_anomaly_threshold() {
        let decision = WafDecision::from_matches(
            "request-1".to_string(),
            WafMode::Block,
            vec![medium_rule_match()],
            5,
        );

        assert_eq!(decision.action, WafAction::Monitor);
        assert_eq!(decision.anomaly_score, 3);
        assert_eq!(decision.anomaly_threshold, 5);
    }

    #[test]
    fn block_mode_blocks_combined_matches_at_anomaly_threshold() {
        let decision = WafDecision::from_matches(
            "request-1".to_string(),
            WafMode::Block,
            vec![medium_rule_match(), medium_rule_match()],
            5,
        );

        assert_eq!(decision.action, WafAction::Block);
        assert_eq!(decision.anomaly_score, 6);
    }

    #[test]
    fn strict_mode_blocks_matched_requests() {
        let decision = WafDecision::from_matches(
            "request-1".to_string(),
            WafMode::Strict,
            vec![medium_rule_match()],
            5,
        );

        assert_eq!(decision.action, WafAction::Block);
        assert_eq!(decision.anomaly_score, 3);
    }

    #[test]
    fn block_mode_monitors_matches_above_blocking_paranoia_level() {
        let decision = WafDecision::from_matches_with_blocking_paranoia(
            "request-1".to_string(),
            WafMode::Block,
            vec![paranoia_two_rule_match()],
            5,
            1,
        );

        assert_eq!(decision.action, WafAction::Monitor);
        assert_eq!(decision.anomaly_score, 5);
        assert_eq!(decision.blocking_anomaly_score, 0);
        assert_eq!(decision.blocking_paranoia_level, 1);
    }

    #[test]
    fn strict_mode_monitors_matches_above_blocking_paranoia_level() {
        let decision = WafDecision::from_matches_with_blocking_paranoia(
            "request-1".to_string(),
            WafMode::Strict,
            vec![paranoia_two_rule_match()],
            5,
            1,
        );

        assert_eq!(decision.action, WafAction::Monitor);
        assert_eq!(decision.blocking_anomaly_score, 0);
    }

    #[test]
    fn block_mode_does_not_block_non_blocking_monitor_findings() {
        let matches = vec![medium_rule_match(), medium_rule_match()];
        let decision = WafDecision::from_matches_with_blocking_policy(
            "request-1".to_string(),
            WafMode::Block,
            matches,
            5,
            1,
            &[0, 1],
        );

        assert_eq!(decision.action, WafAction::Monitor);
        assert_eq!(decision.anomaly_score, 6);
        assert_eq!(decision.blocking_anomaly_score, 0);
    }

    #[test]
    fn off_mode_allows_even_when_rules_match() {
        let decision =
            WafDecision::from_matches("request-1".to_string(), WafMode::Off, vec![rule_match()], 5);

        assert_eq!(decision.action, WafAction::Allow);
        assert!(decision.matched_rules.is_empty());
        assert_eq!(decision.risk_score, 0);
        assert_eq!(decision.anomaly_score, 0);
    }

    #[test]
    fn requests_without_matches_are_allowed() {
        let decision =
            WafDecision::from_matches("request-1".to_string(), WafMode::Block, vec![], 5);

        assert_eq!(decision.action, WafAction::Allow);
        assert_eq!(
            decision.explanation,
            "No security rules matched this request."
        );
    }

    #[test]
    fn serializes_decision_with_expected_json_shape() {
        let decision = WafDecision::from_matches(
            "request-1".to_string(),
            WafMode::Block,
            vec![rule_match()],
            5,
        );
        let json = serde_json::to_value(decision).unwrap();

        assert_eq!(json["request_id"], "request-1");
        assert_eq!(json["action"], "block");
        assert_eq!(json["severity"], "high");
        assert_eq!(json["risk_score"], 80);
        assert_eq!(json["anomaly_score"], 5);
        assert_eq!(json["blocking_anomaly_score"], 5);
        assert_eq!(json["anomaly_threshold"], 5);
        assert_eq!(json["blocking_paranoia_level"], 255);
        assert_eq!(json["matched_rules"][0]["rule_id"], "SAUGRA-SQLI-001");
        assert_eq!(json["matched_rules"][0]["paranoia_level"], 1);
        assert_eq!(json["owasp_category"], "A05:2025-Injection");
        assert_eq!(json["owasp_categories"][0], "A05:2025-Injection");
    }

    fn rule_match() -> RuleMatch {
        RuleMatch {
            rule_id: "SAUGRA-SQLI-001".to_string(),
            rule_name: "Basic SQL Injection Pattern".to_string(),
            category: "sql_injection".to_string(),
            severity: RuleSeverity::High,
            matched_target: RuleTarget::Query,
            paranoia_level: 1,
            explanation: "Query data matched a common SQL injection pattern.".to_string(),
            owasp_category: Some("A05:2025-Injection".to_string()),
        }
    }

    fn medium_rule_match() -> RuleMatch {
        RuleMatch {
            severity: RuleSeverity::Medium,
            ..rule_match()
        }
    }

    fn paranoia_two_rule_match() -> RuleMatch {
        RuleMatch {
            rule_id: "SAUGRA-PL2-001".to_string(),
            rule_name: "Higher Paranoia Rule".to_string(),
            category: "local_policy".to_string(),
            severity: RuleSeverity::High,
            matched_target: RuleTarget::Query,
            paranoia_level: 2,
            explanation: "Higher paranoia rule matched.".to_string(),
            owasp_category: None,
        }
    }
}
