use serde::Serialize;

use crate::{config::WafMode, rules::RuleMatch};

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WafAction {
    Allow,
    Monitor,
    Block,
}

#[derive(Debug, Clone, Serialize)]
pub struct WafDecision {
    pub request_id: String,
    pub action: WafAction,
    pub matched_rules: Vec<RuleMatch>,
    pub severity: String,
    pub risk_score: u8,
    pub explanation: String,
    pub owasp_category: Option<String>,
}

impl WafDecision {
    pub fn from_matches(request_id: String, mode: WafMode, matches: Vec<RuleMatch>) -> Self {
        if matches.is_empty() || mode == WafMode::Off {
            return Self {
                request_id,
                action: WafAction::Allow,
                matched_rules: Vec::new(),
                severity: "none".to_string(),
                risk_score: 0,
                explanation: "No security rules matched this request.".to_string(),
                owasp_category: None,
            };
        }

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
                WafMode::Block | WafMode::Strict => WafAction::Block,
                WafMode::Off => WafAction::Allow,
            },
            matched_rules: matches,
            severity,
            risk_score,
            explanation,
            owasp_category,
        }
    }
}
