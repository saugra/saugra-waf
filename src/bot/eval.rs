use std::{
    collections::BTreeMap,
    fs,
    net::Ipv4Addr,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::{
    behavior::BehaviorContributor,
    config::{BehaviorMode, BotProtectionConfig, ForwardedHeadersConfig, WafMode},
    decision::WafAction,
};

use super::{BotProtectionOutcome, BotProtectionRequest};

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct BotProtectionState {
    pub(super) clients: BTreeMap<String, ClientBotProtectionState>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub(super) struct ClientBotProtectionState {
    pub(super) entries: Vec<BotProtectionEntry>,
    pub(super) temporary_blocked_until: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct BotProtectionEntry {
    timestamp_seconds: u64,
    reason: String,
    score_delta: u16,
    #[serde(default)]
    path: String,
}

pub fn evaluate_with_state(
    config: &BotProtectionConfig,
    request: BotProtectionRequest<'_>,
    state: &mut BotProtectionState,
    storage_backend: &str,
) -> BotProtectionOutcome {
    let now = unix_seconds_now();
    let score_window_seconds = parse_duration_seconds(&config.score_window).unwrap_or(600);
    let temporary_block_duration_seconds =
        parse_duration_seconds(&config.temporary_block_duration).unwrap_or(900);
    let thresholds = select_thresholds(config, request.path);
    let allowlisted = is_allowlisted(config, &request);
    let blocklisted = is_blocklisted(config, &request);

    let client_state = state
        .clients
        .entry(request.client_id.to_string())
        .or_default();
    let active_temporary_block = client_state
        .temporary_blocked_until
        .filter(|blocked_until| *blocked_until > now);

    if allowlisted {
        return outcome(
            config,
            WafAction::Allow,
            thresholds,
            score_window_seconds,
            temporary_block_duration_seconds,
            None,
            storage_backend,
            true,
            false,
            Vec::new(),
        );
    }

    if let Some(blocked_until) = active_temporary_block {
        return outcome(
            config,
            WafAction::Block,
            thresholds,
            score_window_seconds,
            temporary_block_duration_seconds,
            Some(blocked_until),
            storage_backend,
            false,
            false,
            vec![BehaviorContributor {
                reason: "temporary_block_active".to_string(),
                score_delta: thresholds.block_threshold,
                path: request.path.to_string(),
            }],
        );
    }

    let mut new_contributors = contributors_for_request(config, &request);
    if blocklisted {
        new_contributors.push(BehaviorContributor {
            reason: "blocklist_match".to_string(),
            score_delta: thresholds.block_threshold,
            path: request.path.to_string(),
        });
    }

    client_state
        .entries
        .retain(|entry| now.saturating_sub(entry.timestamp_seconds) <= score_window_seconds);

    for contributor in &new_contributors {
        client_state.entries.push(BotProtectionEntry {
            timestamp_seconds: now,
            reason: contributor.reason.clone(),
            score_delta: contributor.score_delta,
            path: contributor.path.clone(),
        });
    }

    let window_start = now.saturating_sub(score_window_seconds);
    let contributors = client_state
        .entries
        .iter()
        .filter(|entry| entry.timestamp_seconds >= window_start)
        .map(|entry| BehaviorContributor {
            reason: entry.reason.clone(),
            score_delta: entry.score_delta,
            path: entry.path.clone(),
        })
        .collect::<Vec<_>>();
    let score = contributors
        .iter()
        .map(|contributor| contributor.score_delta)
        .sum();
    let action = bot_action(
        config,
        request.server_mode,
        score,
        thresholds.monitor_threshold,
        thresholds.block_threshold,
        blocklisted,
    );
    let temporary_blocked_until = if action == WafAction::Block {
        let blocked_until = now.saturating_add(temporary_block_duration_seconds);
        client_state.temporary_blocked_until = Some(blocked_until);
        Some(blocked_until)
    } else {
        client_state.temporary_blocked_until = None;
        None
    };

    outcome(
        config,
        action,
        thresholds,
        score_window_seconds,
        temporary_block_duration_seconds,
        temporary_blocked_until,
        storage_backend,
        false,
        blocklisted,
        contributors,
    )
}

#[allow(clippy::too_many_arguments)]
fn outcome(
    config: &BotProtectionConfig,
    action: WafAction,
    thresholds: BotThresholds,
    score_window_seconds: u64,
    temporary_block_duration_seconds: u64,
    temporary_blocked_until: Option<u64>,
    storage_backend: &str,
    allowlisted: bool,
    blocklisted: bool,
    contributors: Vec<BehaviorContributor>,
) -> BotProtectionOutcome {
    BotProtectionOutcome {
        enabled: config.enabled,
        action,
        score: contributors
            .iter()
            .map(|contributor| contributor.score_delta)
            .sum(),
        monitor_threshold: thresholds.monitor_threshold,
        block_threshold: thresholds.block_threshold,
        score_window_seconds,
        temporary_block_duration_seconds,
        temporary_blocked_until,
        storage_backend: storage_backend.to_string(),
        allowlisted,
        blocklisted,
        contributors,
    }
}

#[derive(Clone, Copy)]
struct BotThresholds {
    monitor_threshold: u16,
    block_threshold: u16,
}

fn bot_action(
    config: &BotProtectionConfig,
    server_mode: WafMode,
    score: u16,
    monitor_threshold: u16,
    block_threshold: u16,
    blocklisted: bool,
) -> WafAction {
    if !config.enabled || config.mode == BehaviorMode::Off || server_mode == WafMode::Off {
        return WafAction::Allow;
    }

    if blocklisted || (config.mode == BehaviorMode::Block && score >= block_threshold) {
        WafAction::Block
    } else if score >= monitor_threshold {
        WafAction::Monitor
    } else {
        WafAction::Allow
    }
}

fn select_thresholds(config: &BotProtectionConfig, path: &str) -> BotThresholds {
    let mut thresholds = BotThresholds {
        monitor_threshold: config.monitor_threshold,
        block_threshold: config.block_threshold,
    };

    if let Some(route) = config
        .routes
        .iter()
        .filter(|route| path_matches_route(path, &route.path))
        .max_by_key(|route| route.path.trim_end_matches('/').len())
    {
        thresholds.monitor_threshold = route
            .monitor_threshold
            .unwrap_or(thresholds.monitor_threshold);
        thresholds.block_threshold = route.block_threshold.unwrap_or(thresholds.block_threshold);
    }

    thresholds
}

fn contributors_for_request(
    config: &BotProtectionConfig,
    request: &BotProtectionRequest<'_>,
) -> Vec<BehaviorContributor> {
    let mut contributors = Vec::new();
    let user_agent = request.user_agent.trim().to_ascii_lowercase();

    if user_agent.is_empty() {
        contributors.push(contributor("missing_user_agent", 20, request.path));
    }

    if [
        "curl",
        "wget",
        "python-requests",
        "httpx",
        "aiohttp",
        "go-http-client",
        "headlesschrome",
        "selenium",
        "playwright",
    ]
    .iter()
    .any(|needle| user_agent.contains(needle))
    {
        contributors.push(contributor("automation_user_agent", 20, request.path));
    }

    if path_matches_any(request.path, &config.scanner_paths)
        && !path_matches_any(request.path, &config.scanner_path_exclusions)
    {
        contributors.push(contributor("scanner_path_probe", 25, request.path));
    }

    if request.forwarded_headers.enabled
        && request.trusted_forwarded_headers
        && forwarded_proto_is_insecure(request.headers, request.forwarded_headers)
    {
        contributors.push(contributor(
            "insecure_forwarded_proto",
            request.forwarded_headers.insecure_proto_score,
            request.path,
        ));
    }

    contributors
}

fn forwarded_proto_is_insecure(headers: &str, config: &ForwardedHeadersConfig) -> bool {
    let Some(value) = normalized_header_value(headers, &config.proto_header) else {
        return false;
    };
    value
        .trim()
        .split(',')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some_and(|value| !value.eq_ignore_ascii_case(config.expected_proto.trim()))
}

fn normalized_header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers.lines().find_map(|line| {
        let (header_name, value) = line.split_once(':')?;
        if header_name.trim().eq_ignore_ascii_case(name.trim()) {
            Some(value.trim())
        } else {
            None
        }
    })
}

fn contributor(reason: &str, score_delta: u16, path: &str) -> BehaviorContributor {
    BehaviorContributor {
        reason: reason.to_string(),
        score_delta,
        path: path.to_string(),
    }
}

fn is_allowlisted(config: &BotProtectionConfig, request: &BotProtectionRequest<'_>) -> bool {
    list_matches(&config.allowlists.ip_ranges, request.client_id)
        || user_agent_matches(&config.allowlists.user_agents, request.user_agent)
}

fn is_blocklisted(config: &BotProtectionConfig, request: &BotProtectionRequest<'_>) -> bool {
    list_matches(&config.blocklists.ip_ranges, request.client_id)
        || user_agent_matches(&config.blocklists.user_agents, request.user_agent)
}

fn list_matches(entries: &[String], client_id: &str) -> bool {
    entries.iter().any(|entry| {
        let entry = entry.trim();
        entry == client_id || ipv4_cidr_contains(entry, client_id)
    })
}

fn user_agent_matches(entries: &[String], user_agent: &str) -> bool {
    let user_agent = user_agent.to_ascii_lowercase();
    entries
        .iter()
        .any(|entry| user_agent.contains(&entry.trim().to_ascii_lowercase()))
}

fn ipv4_cidr_contains(cidr: &str, ip: &str) -> bool {
    let Some((network, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u32>() else {
        return false;
    };
    if prefix > 32 {
        return false;
    }

    let Ok(network) = network.parse::<Ipv4Addr>() else {
        return false;
    };
    let Ok(ip) = ip.parse::<Ipv4Addr>() else {
        return false;
    };
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };

    u32::from(network) & mask == u32::from(ip) & mask
}

fn path_matches_any(path: &str, configured_paths: &[String]) -> bool {
    let path = path.to_ascii_lowercase();
    configured_paths.iter().any(|probe| {
        let probe = probe.trim().trim_end_matches('/').to_ascii_lowercase();
        path == probe || path.starts_with(&format!("{probe}/"))
    })
}

fn path_matches_route(path: &str, route_path: &str) -> bool {
    let route_path = route_path.trim_end_matches('/');
    path == route_path
        || path
            .strip_prefix(route_path)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

pub(super) fn read_state(path: &Path) -> anyhow::Result<BotProtectionState> {
    if !path.exists() {
        return Ok(BotProtectionState::default());
    }

    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read bot protection state {}", path.display()))?;
    serde_json::from_str(&contents).with_context(|| {
        format!(
            "bot protection state is not valid JSON at {}",
            path.display()
        )
    })
}

pub(super) fn write_state(path: &Path, state: &BotProtectionState) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create bot protection state directory {}",
                parent.display()
            )
        })?;
    }
    fs::write(path, serde_json::to_vec_pretty(state)?)
        .with_context(|| format!("failed to write bot protection state {}", path.display()))?;
    Ok(())
}

pub(super) fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn parse_duration_seconds(value: &str) -> Option<u64> {
    let trimmed = value.trim().to_ascii_lowercase();
    let split_at = trimmed.find(|c: char| !c.is_ascii_digit())?;
    let (number, unit) = trimmed.split_at(split_at);
    let number = number.parse::<u64>().ok()?;
    if number == 0 {
        return None;
    }

    let multiplier = match unit.trim() {
        "s" | "sec" | "secs" | "second" | "seconds" => 1,
        "m" | "min" | "mins" | "minute" | "minutes" => 60,
        "h" | "hr" | "hrs" | "hour" | "hours" => 60 * 60,
        "d" | "day" | "days" => 24 * 60 * 60,
        _ => return None,
    };

    number.checked_mul(multiplier)
}
