use std::collections::{BTreeMap, BTreeSet};

use crate::{
    config::{UnknownThreatConfig, UnknownThreatMode, WafMode},
    decision::WafAction,
    event_store::SecurityEvent,
};

use super::{
    helpers::{
        client_matches_any, matching_route, normalized_content_type, path_matches_any,
        query_parameter_names, route_shape,
    },
    state::{
        parse_duration_seconds, read_state, unix_seconds_now, write_state, RouteBaseline,
        StateFileLock, UnknownThreatState,
    },
    UnknownThreatCleanupReport, UnknownThreatOutcome, UnknownThreatRequest,
    UnknownThreatRouteReport, UnknownThreatShadowReport, UnknownThreatSignal,
};

pub fn shadow_report(events: &[SecurityEvent]) -> UnknownThreatShadowReport {
    let mut report = UnknownThreatShadowReport {
        total_events: events.len(),
        analyzed_events: 0,
        monitor_candidates: 0,
        would_block_candidates: 0,
        enforced_blocks: 0,
        gated_candidates: 0,
        single_signal_candidates: 0,
        new_baseline_candidates: 0,
        routes: Vec::new(),
        sample_request_ids: Vec::new(),
    };
    let mut routes = BTreeMap::<String, UnknownThreatRouteReport>::new();

    for event in events {
        let Some(outcome) = &event.decision.unknown_threats else {
            continue;
        };
        report.analyzed_events += 1;
        if outcome.score < outcome.threshold {
            continue;
        }

        report.monitor_candidates += 1;
        if outcome.would_block {
            report.would_block_candidates += 1;
        } else {
            report.gated_candidates += 1;
        }
        if outcome.action == WafAction::Block {
            report.enforced_blocks += 1;
        }
        if outcome.signals.len() == 1 {
            report.single_signal_candidates += 1;
        }
        if outcome
            .enforcement_gates
            .iter()
            .any(|gate| gate == "baseline_too_new")
        {
            report.new_baseline_candidates += 1;
        }
        if report.sample_request_ids.len() < 20 {
            report
                .sample_request_ids
                .push(event.decision.request_id.clone());
        }

        let route = routes
            .entry(outcome.route_shape.clone())
            .or_insert_with(|| UnknownThreatRouteReport {
                route_shape: outcome.route_shape.clone(),
                candidates: 0,
                would_block: 0,
                enforced_blocks: 0,
            });
        route.candidates += 1;
        route.would_block += usize::from(outcome.would_block);
        route.enforced_blocks += usize::from(outcome.action == WafAction::Block);
    }

    report.routes = routes.into_values().collect();
    report.routes.sort_by(|left, right| {
        right
            .candidates
            .cmp(&left.candidates)
            .then_with(|| left.route_shape.cmp(&right.route_shape))
    });
    report
}

pub fn cleanup_local_state_at(
    config: &UnknownThreatConfig,
    dry_run: bool,
    now: u64,
) -> anyhow::Result<UnknownThreatCleanupReport> {
    let path = config.state_path.clone();
    if !path.exists() {
        return Ok(UnknownThreatCleanupReport {
            path,
            dry_run,
            state_found: false,
            routes_before: 0,
            routes_removed: 0,
            routes_after: 0,
        });
    }

    let _file_lock = StateFileLock::acquire(&path)?;
    let mut state = read_state(&path)?;
    let routes_before = state.routes.len();
    let retention_seconds = parse_duration_seconds(&config.retention).unwrap_or(30 * 86_400);
    let routes_removed = prune_stale_routes(&mut state, now, retention_seconds);
    if !dry_run && routes_removed > 0 {
        write_state(&path, &state)?;
    }

    Ok(UnknownThreatCleanupReport {
        path,
        dry_run,
        state_found: true,
        routes_before,
        routes_removed,
        routes_after: state.routes.len(),
    })
}

pub fn evaluate_with_state(
    config: &UnknownThreatConfig,
    request: UnknownThreatRequest<'_>,
    state: &mut UnknownThreatState,
    storage_backend: &str,
) -> UnknownThreatOutcome {
    evaluate_with_state_at(config, request, state, storage_backend, unix_seconds_now())
}

pub fn evaluate_with_state_at(
    config: &UnknownThreatConfig,
    request: UnknownThreatRequest<'_>,
    state: &mut UnknownThreatState,
    storage_backend: &str,
    now: u64,
) -> UnknownThreatOutcome {
    let retention_seconds = parse_duration_seconds(&config.retention).unwrap_or(30 * 86_400);
    let pruned_routes = prune_stale_routes(state, now, retention_seconds);
    let route_shape = route_shape(request.path);
    let route_policy = matching_route(&config.routes, request.path);
    let minimum_observations = route_policy
        .and_then(|route| route.minimum_observations)
        .unwrap_or(config.minimum_observations);
    let monitor_threshold = route_policy
        .and_then(|route| route.monitor_threshold)
        .unwrap_or(config.monitor_threshold);
    let block_threshold = route_policy
        .and_then(|route| route.block_threshold)
        .unwrap_or(config.block_threshold);
    let minimum_independent_signals = route_policy
        .and_then(|route| route.minimum_independent_signals)
        .unwrap_or(config.minimum_independent_signals);
    let minimum_baseline_age_seconds = route_policy
        .and_then(|route| route.minimum_baseline_age.as_deref())
        .and_then(parse_duration_seconds)
        .unwrap_or_else(|| {
            parse_duration_seconds(&config.minimum_baseline_age).unwrap_or(7 * 86_400)
        });
    let minimum_block_observations = route_policy
        .and_then(|route| route.minimum_block_observations)
        .unwrap_or(config.minimum_block_observations);
    let high_risk_route = route_policy.map(|route| route.high_risk).unwrap_or(false);
    let learning_enabled = route_policy
        .map(|route| route.learning_enabled)
        .unwrap_or(true);
    let route_excluded = path_matches_any(request.path, &config.excluded_paths);
    let analysis_active = config.enabled && config.mode != UnknownThreatMode::Off;
    let learning_source_trusted =
        client_matches_any(request.client_id, &config.trusted_learning_clients);
    let learning_source_allowed = !config.trusted_learning_only || learning_source_trusted;
    let can_allocate = state.routes.len() < config.max_routes;

    if analysis_active
        && !route_excluded
        && learning_enabled
        && request.eligible_for_learning
        && learning_source_allowed
        && !state.routes.contains_key(&route_shape)
        && can_allocate
    {
        state
            .routes
            .insert(route_shape.clone(), RouteBaseline::default());
    }

    let capacity_reached = !state.routes.contains_key(&route_shape) && !can_allocate;
    let baseline = state.routes.get_mut(&route_shape);
    let baseline_observations = baseline
        .as_ref()
        .map(|baseline| baseline.observations)
        .unwrap_or(0);
    let baseline_ready = baseline_observations >= minimum_observations;
    let baseline_age_seconds = baseline
        .as_ref()
        .map(|baseline| now.saturating_sub(baseline.first_observed_at))
        .unwrap_or(0);
    let mut signals = Vec::new();

    if config.enabled && !route_excluded && baseline_ready {
        if let Some(baseline) = baseline.as_ref() {
            let method = request.method.to_ascii_uppercase();
            if !baseline.methods.contains(&method) {
                signals.push(UnknownThreatSignal {
                    kind: "unseen_method".to_string(),
                    score_delta: config.signals.unseen_method.score,
                    explanation: format!(
                        "Method {method} was not present in the learned baseline for {route_shape}."
                    ),
                });
            }

            let content_type = normalized_content_type(request.content_type);
            if !content_type.is_empty() && !baseline.content_types.contains(&content_type) {
                signals.push(UnknownThreatSignal {
                    kind: "unseen_content_type".to_string(),
                    score_delta: config.signals.unseen_content_type.score,
                    explanation: format!(
                        "Content type {content_type} was not present in the learned baseline for {route_shape}."
                    ),
                });
            }

            let unseen_parameters = query_parameter_names(request.query)
                .difference(&baseline.query_parameters)
                .cloned()
                .collect::<Vec<_>>();
            if !unseen_parameters.is_empty() {
                signals.push(UnknownThreatSignal {
                    kind: "unseen_query_parameter".to_string(),
                    score_delta: config.signals.unseen_query_parameter.score,
                    explanation: format!(
                        "Query parameter(s) {} were not present in the learned baseline for {route_shape}.",
                        unseen_parameters.join(", ")
                    ),
                });
            }

            let body_limit = baseline
                .maximum_body_size
                .saturating_mul(config.body_size_multiplier as usize);
            if baseline.maximum_body_size > 0 && request.body_size > body_limit {
                signals.push(UnknownThreatSignal {
                    kind: "body_size_deviation".to_string(),
                    score_delta: config.signals.body_size_deviation.score,
                    explanation: format!(
                        "Body size {} exceeded the learned maximum {} by more than the configured multiplier.",
                        request.body_size, baseline.maximum_body_size
                    ),
                });
            }
        }
    }

    let score = signals.iter().map(|signal| signal.score_delta).sum();
    let active = analysis_active && !route_excluded;
    let monitor_candidate = active && baseline_ready && score >= monitor_threshold;
    let mut enforcement_gates = Vec::new();
    if !high_risk_route {
        enforcement_gates.push("route_not_high_risk".to_string());
    }
    if baseline_observations < minimum_block_observations {
        enforcement_gates.push("insufficient_observations".to_string());
    }
    if baseline_age_seconds < minimum_baseline_age_seconds {
        enforcement_gates.push("baseline_too_new".to_string());
    }
    if signals.len() < minimum_independent_signals {
        enforcement_gates.push("insufficient_independent_signals".to_string());
    }
    if score < block_threshold {
        enforcement_gates.push("score_below_block_threshold".to_string());
    }
    let block_eligible =
        active && baseline_ready && high_risk_route && enforcement_gates.is_empty();
    let would_block = block_eligible;
    let action = if would_block
        && config.mode == UnknownThreatMode::Block
        && matches!(request.server_mode, WafMode::Block | WafMode::Strict)
    {
        WafAction::Block
    } else if monitor_candidate {
        WafAction::Monitor
    } else {
        WafAction::Allow
    };

    if active
        && !route_excluded
        && learning_enabled
        && request.eligible_for_learning
        && learning_source_allowed
        && signals.is_empty()
    {
        if let Some(baseline) = baseline {
            learn(baseline, &request, config, now);
        }
    }

    let baseline_tracked = state.routes.contains_key(&route_shape);

    UnknownThreatOutcome {
        enabled: config.enabled,
        action,
        score,
        threshold: monitor_threshold,
        block_threshold,
        route_shape,
        baseline_observations,
        baseline_ready,
        baseline_age_seconds,
        minimum_block_observations,
        minimum_baseline_age_seconds,
        minimum_independent_signals,
        high_risk_route,
        would_block,
        block_eligible,
        enforcement_gates,
        baseline_tracked,
        learning_enabled,
        learning_source_trusted,
        learning_source_allowed,
        route_excluded,
        capacity_reached,
        pruned_routes,
        storage_backend: storage_backend.to_string(),
        signals,
    }
}

fn learn(
    baseline: &mut RouteBaseline,
    request: &UnknownThreatRequest<'_>,
    config: &UnknownThreatConfig,
    now: u64,
) {
    if baseline.first_observed_at == 0 {
        baseline.first_observed_at = now;
    }
    baseline.last_observed_at = now;
    baseline.observations = baseline.observations.saturating_add(1);
    observe_feature(
        &mut baseline.methods,
        &mut baseline.pending_methods,
        request.method.to_ascii_uppercase(),
        config.promotion_observations,
        config.max_methods_per_route,
    );

    let content_type = normalized_content_type(request.content_type);
    if !content_type.is_empty() {
        observe_feature(
            &mut baseline.content_types,
            &mut baseline.pending_content_types,
            content_type,
            config.promotion_observations,
            config.max_content_types_per_route,
        );
    }
    for parameter in query_parameter_names(request.query) {
        observe_feature(
            &mut baseline.query_parameters,
            &mut baseline.pending_query_parameters,
            parameter,
            config.promotion_observations,
            config.max_query_parameters_per_route,
        );
    }
    let body_bucket = body_size_bucket(request.body_size);
    if body_bucket > 0 && baseline.maximum_body_size < body_bucket {
        if !baseline
            .pending_body_size_buckets
            .contains_key(&body_bucket)
            && baseline.pending_body_size_buckets.len() >= 32
        {
            return;
        }
        let count = baseline
            .pending_body_size_buckets
            .entry(body_bucket)
            .or_default();
        *count = count.saturating_add(1);
        if *count >= config.promotion_observations {
            baseline.maximum_body_size = body_bucket;
            baseline
                .pending_body_size_buckets
                .retain(|bucket, _| *bucket > body_bucket);
        }
    }
}

fn observe_feature(
    active: &mut BTreeSet<String>,
    pending: &mut BTreeMap<String, u64>,
    value: String,
    promotion_observations: u64,
    maximum_active: usize,
) {
    if active.contains(&value) || active.len() >= maximum_active {
        return;
    }
    if !pending.contains_key(&value) && pending.len() >= maximum_active.saturating_mul(2) {
        return;
    }

    let count = pending.entry(value.clone()).or_default();
    *count = count.saturating_add(1);
    if *count >= promotion_observations {
        pending.remove(&value);
        active.insert(value);
    }
}

fn body_size_bucket(body_size: usize) -> usize {
    if body_size == 0 {
        0
    } else {
        body_size.checked_next_power_of_two().unwrap_or(usize::MAX)
    }
}

pub(super) fn prune_stale_routes(
    state: &mut UnknownThreatState,
    now: u64,
    retention_seconds: u64,
) -> usize {
    for baseline in state.routes.values_mut() {
        if baseline.first_observed_at == 0 {
            baseline.first_observed_at = now;
        }
        if baseline.last_observed_at == 0 {
            baseline.last_observed_at = now;
        }
    }

    let before = state.routes.len();
    state
        .routes
        .retain(|_, baseline| now.saturating_sub(baseline.last_observed_at) <= retention_seconds);
    before.saturating_sub(state.routes.len())
}
