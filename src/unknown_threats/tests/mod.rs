use std::collections::BTreeSet;

use super::{
    state::{RouteBaseline, UnknownThreatState},
    UnknownThreatRequest,
};
use crate::config::{
    BehaviorBackend, UnknownThreatConfig, UnknownThreatMode, UnknownThreatRouteConfig, WafMode,
};

mod eval_tests;
mod store_tests;

pub(super) fn config() -> UnknownThreatConfig {
    UnknownThreatConfig {
        enabled: true,
        backend: BehaviorBackend::Memory,
        minimum_observations: 2,
        monitor_threshold: 10,
        promotion_observations: 1,
        signals: crate::config::UnknownThreatSignals {
            unseen_method: crate::config::UnknownThreatSignalPolicy { score: 10 },
            unseen_content_type: crate::config::UnknownThreatSignalPolicy { score: 15 },
            unseen_query_parameter: crate::config::UnknownThreatSignalPolicy { score: 10 },
            body_size_deviation: crate::config::UnknownThreatSignalPolicy { score: 15 },
        },
        ..UnknownThreatConfig::default()
    }
}

pub(super) fn request<'a>(method: &'a str, path: &'a str) -> UnknownThreatRequest<'a> {
    UnknownThreatRequest {
        path,
        client_id: "203.0.113.10",
        method,
        content_type: "application/json",
        query: "page=1",
        body_size: 20,
        eligible_for_learning: true,
        server_mode: WafMode::Monitor,
    }
}

pub(super) fn blocking_config(mode: UnknownThreatMode) -> UnknownThreatConfig {
    UnknownThreatConfig {
        enabled: true,
        mode,
        minimum_observations: 10,
        monitor_threshold: 10,
        block_threshold: 20,
        minimum_independent_signals: 2,
        minimum_baseline_age: "1d".to_string(),
        minimum_block_observations: 100,
        promotion_observations: 1,
        routes: vec![UnknownThreatRouteConfig {
            path: "/admin".to_string(),
            high_risk: true,
            ..UnknownThreatRouteConfig::default()
        }],
        ..config()
    }
}

pub(super) fn mature_state() -> UnknownThreatState {
    let mut state = UnknownThreatState::default();
    state.routes.insert(
        "/admin/:id".to_string(),
        RouteBaseline {
            observations: 1_000,
            first_observed_at: 1,
            last_observed_at: 999_999,
            methods: BTreeSet::from(["GET".to_string()]),
            content_types: BTreeSet::from(["application/json".to_string()]),
            query_parameters: BTreeSet::from(["page".to_string()]),
            maximum_body_size: 32,
            ..RouteBaseline::default()
        },
    );
    state
}

pub(super) fn anomalous_request(server_mode: WafMode) -> UnknownThreatRequest<'static> {
    UnknownThreatRequest {
        path: "/admin/42",
        client_id: "203.0.113.10",
        method: "DELETE",
        content_type: "text/plain",
        query: "page=1",
        body_size: 20,
        eligible_for_learning: true,
        server_mode,
    }
}
