use crate::{
    ai::{
        explain_event, sanitized_route_shape,
        types::{AnomalyShadowCandidate, AnomalyShadowReport},
    },
    config::AiConfig,
    event_store::SecurityEvent,
};

pub async fn anomaly_shadow_review(
    config: &AiConfig,
    events: &[SecurityEvent],
) -> anyhow::Result<AnomalyShadowReport> {
    let mut candidates = Vec::new();
    for event in events
        .iter()
        .filter(|event| event.decision.unknown_threats.is_some())
    {
        let outcome = event.decision.unknown_threats.as_ref().unwrap();
        let explanation = explain_event(config, event).await?;
        candidates.push(AnomalyShadowCandidate {
            request_id: event.decision.request_id.clone(),
            route_shape: sanitized_route_shape(&outcome.route_shape),
            deterministic_action: outcome.action,
            deterministic_signals: outcome
                .signals
                .iter()
                .map(|signal| signal.kind.clone())
                .collect(),
            provider: explanation.provider,
            model: explanation.model,
            explanation: explanation.explanation,
            fallback_used: explanation.fallback_used,
        });
    }
    Ok(AnomalyShadowReport {
        version: 1,
        authority: "deterministic_policy_only".to_string(),
        enforcement_changes: 0,
        reviewed_events: candidates.len(),
        candidates,
    })
}
