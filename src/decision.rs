use serde::{Deserialize, Serialize};

use crate::{config::WafMode, rules::RuleMatch};

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
    pub anomaly_threshold: u16,
    pub explanation: String,
    pub owasp_category: Option<String>,
}

impl WafDecision {
    pub fn from_matches(
        request_id: String,
        mode: WafMode,
        matches: Vec<RuleMatch>,
        anomaly_threshold: u16,
    ) -> Self {
        if matches.is_empty() || mode == WafMode::Off {
            return Self {
                request_id,
                action: WafAction::Allow,
                matched_rules: Vec::new(),
                severity: "none".to_string(),
                risk_score: 0,
                anomaly_score: 0,
                anomaly_threshold,
                explanation: "No security rules matched this request.".to_string(),
                owasp_category: None,
            };
        }

        let anomaly_score = matches
            .iter()
            .map(|rule_match| rule_match.severity.anomaly_points())
            .sum();
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
        let explanation = matches
            .first()
            .map(|rule_match| rule_match.explanation.clone())
            .unwrap_or_else(|| "A security rule matched this request.".to_string());

        Self {
            request_id,
            action: match mode {
                WafMode::Monitor => WafAction::Monitor,
                WafMode::Block if anomaly_score >= anomaly_threshold => WafAction::Block,
                WafMode::Block => WafAction::Monitor,
                WafMode::Strict => WafAction::Block,
                WafMode::Off => WafAction::Allow,
            },
            matched_rules: matches,
            severity,
            risk_score,
            anomaly_score,
            anomaly_threshold,
            explanation,
            owasp_category,
        }
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
        assert_eq!(json["anomaly_threshold"], 5);
        assert_eq!(json["matched_rules"][0]["rule_id"], "SAUGRA-SQLI-001");
        assert_eq!(json["owasp_category"], "A05:2025-Injection");
    }

    fn rule_match() -> RuleMatch {
        RuleMatch {
            rule_id: "SAUGRA-SQLI-001".to_string(),
            rule_name: "Basic SQL Injection Pattern".to_string(),
            category: "sql_injection".to_string(),
            severity: RuleSeverity::High,
            matched_target: RuleTarget::Query,
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
}
