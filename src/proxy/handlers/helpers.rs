use axum::http::{header, HeaderMap};
use tracing::warn;

use crate::{
    behavior::{self, BehaviorRequest},
    bot::{self, BotProtectionRequest},
    campaign::CampaignRequest,
    config::{RuntimeAllowlistEffect, WafMode},
    decision::{WafAction, WafDecision},
    rate_limit::RateLimitExceeded,
    rules::{RuleMatch, RuleSeverity, RuleTarget},
    unknown_threats::{self, UnknownThreatRequest},
};

use super::super::{
    utils::{is_hop_by_hop_header, is_websocket_hop_header, runtime_blocklist_match},
    ProxyState,
};

pub fn copy_forward_headers(
    original: &HeaderMap,
    forwarded: &mut HeaderMap,
    upstream_host: &str,
    request_id: &str,
    preserve_upgrade: bool,
) {
    for (name, value) in original {
        if (is_hop_by_hop_header(name) && !(preserve_upgrade && is_websocket_hop_header(name)))
            || name == header::HOST
        {
            continue;
        }
        forwarded.insert(name, value.clone());
    }

    match upstream_host.parse() {
        Ok(value) => {
            forwarded.insert(header::HOST, value);
        }
        Err(error) => {
            warn!(request_id, upstream_host, %error, "upstream host is not a valid header value");
        }
    }

    if let Ok(value) = request_id.parse() {
        forwarded.insert("x-saugra-waf-request-id", value);
    }
}

pub fn rate_limit_match(exceeded: &RateLimitExceeded) -> RuleMatch {
    RuleMatch {
        rule_id: "SAUGRA-RATE-001".to_string(),
        rule_name: "Per-Client Request Rate Limit".to_string(),
        category: "rate_limit_abuse".to_string(),
        severity: RuleSeverity::Medium,
        matched_target: RuleTarget::Headers,
        paranoia_level: 1,
        explanation: format!(
            "Client exceeded the configured rate limit of {} requests per minute with a burst of {}.",
            exceeded.limit, exceeded.burst
        ),
        owasp_category: Some("A06:2025-Insecure Design".to_string()),
    }
}

pub struct DecisionRequest<'a> {
    pub request_id: String,
    pub matches: Vec<RuleMatch>,
    pub client_ip: &'a str,
    pub path: &'a str,
    pub method: &'a str,
    pub query: &'a str,
    pub content_type: &'a str,
    pub body_size: usize,
    pub headers: &'a str,
    pub user_agent: &'a str,
    pub trusted_forwarded_headers: bool,
    pub session_id: &'a str,
}

pub async fn decision_with_behavior_and_bot(
    state: &ProxyState,
    request: DecisionRequest<'_>,
) -> WafDecision {
    let DecisionRequest {
        request_id,
        mut matches,
        client_ip,
        path,
        method,
        query,
        content_type,
        body_size,
        headers,
        user_agent,
        trusted_forwarded_headers,
        session_id,
    } = request;
    let deterministic_matches = matches.clone();
    let mut non_blocking_match_indices = Vec::new();

    if let Some(runtime_blocklist) = state.runtime_policy.match_blocked_ip(client_ip) {
        let mut decision = WafDecision::from_matches_with_blocking_paranoia(
            request_id,
            WafMode::Strict,
            vec![runtime_blocklist_match(&runtime_blocklist)],
            state.config.rules.inbound_anomaly_threshold,
            state.config.rules.blocking_paranoia_level(),
        );
        decision.action = WafAction::Block;
        return decision.with_runtime_allowlist(runtime_blocklist);
    }

    let runtime_allowlist = state.runtime_policy.match_ip(client_ip);
    let allowlist_effect = runtime_allowlist.as_ref().map(|allowlist| allowlist.effect);
    let skip_bot_and_behavior = matches!(
        allowlist_effect,
        Some(
            RuntimeAllowlistEffect::SkipBotAndBehaviorBlock
                | RuntimeAllowlistEffect::MonitorAll
                | RuntimeAllowlistEffect::AllowAll
        )
    );

    if allowlist_effect == Some(RuntimeAllowlistEffect::AllowAll) {
        let mut decision = WafDecision::from_matches_with_blocking_paranoia(
            request_id,
            WafMode::Off,
            Vec::new(),
            state.config.rules.inbound_anomaly_threshold,
            state.config.rules.blocking_paranoia_level(),
        );
        if let Some(runtime_allowlist) = runtime_allowlist {
            decision = decision.with_runtime_allowlist(runtime_allowlist);
        }
        return decision;
    }

    let bot_outcome = if state.config.bot_protection.enabled && !skip_bot_and_behavior {
        match state.bot_protection_store.evaluate(
            &state.config.bot_protection,
            BotProtectionRequest {
                client_id: client_ip,
                path,
                headers,
                user_agent,
                forwarded_headers: &state.config.forwarded_headers,
                trusted_forwarded_headers,
                server_mode: state.config.server.mode,
            },
        ) {
            Ok(outcome) => Some(outcome),
            Err(error) => {
                warn!(request_id, %error, "bot protection failed");
                None
            }
        }
    } else {
        None
    };

    if let Some(outcome) = &bot_outcome {
        if let Some(rule_match) = bot::bot_rule_match(&state.config.bot_protection, outcome) {
            if outcome.action == WafAction::Monitor {
                non_blocking_match_indices.push(matches.len());
            }
            matches.push(rule_match);
        }
    }

    let behavior_outcome = if state.config.behavior.enabled && !skip_bot_and_behavior {
        match state.behavior_store.evaluate(
            &state.config.behavior,
            BehaviorRequest {
                client_id: client_ip,
                path,
                rule_matches: &deterministic_matches,
                server_mode: state.config.server.mode,
            },
        ) {
            Ok(outcome) => Some(outcome),
            Err(error) => {
                warn!(request_id, %error, "behavior scoring failed");
                None
            }
        }
    } else {
        None
    };

    if let Some(outcome) = &behavior_outcome {
        if let Some(rule_match) = behavior::behavior_rule_match(outcome) {
            if outcome.action == WafAction::Monitor {
                non_blocking_match_indices.push(matches.len());
            }
            matches.push(rule_match);
        }
    }

    let unknown_threat_outcome = if state.config.unknown_threats.enabled && !skip_bot_and_behavior {
        match state.unknown_threat_store.evaluate(
            &state.config.unknown_threats,
            UnknownThreatRequest {
                path,
                client_id: client_ip,
                method,
                content_type,
                query,
                body_size,
                eligible_for_learning: deterministic_matches.is_empty(),
                server_mode: state.config.server.mode,
            },
        ) {
            Ok(outcome) => Some(outcome),
            Err(error) => {
                warn!(request_id, %error, "unknown-threat analysis failed");
                None
            }
        }
    } else {
        None
    };

    let mut campaign_categories = deterministic_matches
        .iter()
        .map(|rule_match| rule_match.category.clone())
        .collect::<Vec<_>>();
    if bot_outcome
        .as_ref()
        .is_some_and(|outcome| !outcome.contributors.is_empty())
    {
        campaign_categories.push("bot_protection".to_string());
    }
    if behavior_outcome.as_ref().is_some_and(|outcome| {
        outcome
            .contributors
            .iter()
            .any(|contributor| contributor.reason == "scanner_path_probe")
    }) {
        campaign_categories.push("scanner_behavior".to_string());
    }
    if unknown_threat_outcome
        .as_ref()
        .is_some_and(|outcome| !outcome.signals.is_empty())
    {
        campaign_categories.push("unknown_threat".to_string());
    }
    campaign_categories.sort();
    campaign_categories.dedup();
    let campaign_outcome = if state.config.campaign_correlation.enabled && !skip_bot_and_behavior {
        match state
            .campaign_store
            .evaluate(
                &state.config.campaign_correlation,
                CampaignRequest {
                    request_id: &request_id,
                    client_id: client_ip,
                    session_id,
                    path,
                    categories: &campaign_categories,
                    server_mode: state.config.server.mode,
                },
            )
            .await
        {
            Ok(outcome) => Some(outcome),
            Err(error) => {
                warn!(request_id, %error, "campaign correlation failed");
                None
            }
        }
    } else {
        None
    };

    let decision_mode = if allowlist_effect == Some(RuntimeAllowlistEffect::MonitorAll) {
        WafMode::Monitor
    } else {
        state.config.server.mode
    };
    let decision = WafDecision::from_matches_with_blocking_policy(
        request_id,
        decision_mode,
        matches,
        state.config.rules.inbound_anomaly_threshold,
        state.config.rules.blocking_paranoia_level(),
        &non_blocking_match_indices,
    );

    let mut decision = if let Some(outcome) = behavior_outcome {
        if outcome.action == WafAction::Block && state.config.server.mode != WafMode::Off {
            let mut decision = decision.with_behavior(outcome);
            decision.action = WafAction::Block;
            decision
        } else {
            decision.with_behavior(outcome)
        }
    } else {
        decision
    };

    if let Some(outcome) = unknown_threat_outcome {
        if let Some(rule_match) = unknown_threats::unknown_threat_rule_match(&outcome) {
            decision.severity = rule_match.severity.to_string();
            decision.risk_score = rule_match.severity.risk_score();
            decision.explanation = rule_match.explanation.clone();
            if let Some(category) = &rule_match.owasp_category {
                decision.owasp_category = Some(category.clone());
                if !decision.owasp_categories.contains(category) {
                    decision.owasp_categories.push(category.clone());
                }
            }
            decision.matched_rules.push(rule_match);
        }
        match outcome.action {
            WafAction::Block => decision.action = WafAction::Block,
            WafAction::Monitor if decision.action == WafAction::Allow => {
                decision.action = WafAction::Monitor;
            }
            WafAction::Allow | WafAction::Monitor => {}
        }
        decision = decision.with_unknown_threats(outcome);
    }

    if let Some(outcome) = bot_outcome {
        if outcome.action == WafAction::Block
            && state.config.server.mode != WafMode::Off
            && runtime_allowlist.is_none()
        {
            decision.action = WafAction::Block;
        }
        decision = decision.with_bot_protection(outcome);
    }

    if let Some(outcome) = campaign_outcome {
        if outcome.action == WafAction::Monitor && decision.action == WafAction::Allow {
            decision.action = WafAction::Monitor;
        }
        decision = decision.with_campaign(outcome);
    }

    if let Some(runtime_allowlist) = runtime_allowlist {
        decision = decision.with_runtime_allowlist(runtime_allowlist);
    }

    decision
}
