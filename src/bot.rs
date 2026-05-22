use std::{
    collections::BTreeMap,
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{
    behavior::BehaviorContributor,
    config::{BehaviorBackend, BehaviorMode, BotProtectionConfig, ForwardedHeadersConfig, WafMode},
    decision::WafAction,
    rules::{RuleMatch, RuleTarget},
};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct BotProtectionOutcome {
    pub enabled: bool,
    pub action: WafAction,
    pub score: u16,
    pub monitor_threshold: u16,
    pub block_threshold: u16,
    pub score_window_seconds: u64,
    pub temporary_block_duration_seconds: u64,
    pub temporary_blocked_until: Option<u64>,
    pub storage_backend: String,
    pub allowlisted: bool,
    pub blocklisted: bool,
    pub contributors: Vec<BehaviorContributor>,
}

#[derive(Debug, Clone)]
pub struct BotProtectionRequest<'a> {
    pub client_id: &'a str,
    pub path: &'a str,
    pub headers: &'a str,
    pub user_agent: &'a str,
    pub forwarded_headers: &'a ForwardedHeadersConfig,
    pub trusted_forwarded_headers: bool,
    pub server_mode: WafMode,
}

pub trait BotProtectionStore: Send + Sync {
    fn evaluate(
        &self,
        config: &BotProtectionConfig,
        request: BotProtectionRequest<'_>,
    ) -> anyhow::Result<BotProtectionOutcome>;
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct BotProtectionState {
    clients: BTreeMap<String, ClientBotProtectionState>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct ClientBotProtectionState {
    entries: Vec<BotProtectionEntry>,
    temporary_blocked_until: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct BotProtectionEntry {
    timestamp_seconds: u64,
    reason: String,
    score_delta: u16,
}

#[derive(Debug)]
pub struct MemoryBotProtectionStore {
    state: Mutex<BotProtectionState>,
}

impl MemoryBotProtectionStore {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(BotProtectionState::default()),
        }
    }
}

impl Default for MemoryBotProtectionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BotProtectionStore for MemoryBotProtectionStore {
    fn evaluate(
        &self,
        config: &BotProtectionConfig,
        request: BotProtectionRequest<'_>,
    ) -> anyhow::Result<BotProtectionOutcome> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("bot protection store lock poisoned"))?;
        Ok(evaluate_with_state(config, request, &mut state, "memory"))
    }
}

#[derive(Debug)]
pub struct LocalBotProtectionStore {
    path: PathBuf,
    state: Mutex<BotProtectionState>,
}

impl LocalBotProtectionStore {
    pub fn open(path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let path = path.into();
        let state = read_state(&path)?;
        Ok(Self {
            path,
            state: Mutex::new(state),
        })
    }
}

impl BotProtectionStore for LocalBotProtectionStore {
    fn evaluate(
        &self,
        config: &BotProtectionConfig,
        request: BotProtectionRequest<'_>,
    ) -> anyhow::Result<BotProtectionOutcome> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("bot protection store lock poisoned"))?;
        let outcome = evaluate_with_state(config, request, &mut state, "local");
        write_state(&self.path, &state)?;
        Ok(outcome)
    }
}

pub fn build_store(config: &BotProtectionConfig) -> anyhow::Result<Box<dyn BotProtectionStore>> {
    match config.backend {
        BehaviorBackend::Memory => Ok(Box::new(MemoryBotProtectionStore::new())),
        BehaviorBackend::Local => Ok(Box::new(LocalBotProtectionStore::open(&config.state_path)?)),
    }
}

pub fn reset_client(path: &Path, client_id: &str) -> anyhow::Result<bool> {
    let mut state = read_state(path)?;
    let removed = state.clients.remove(client_id).is_some();
    if removed {
        write_state(path, &state)?;
    }
    Ok(removed)
}

pub fn bot_rule_match(
    config: &BotProtectionConfig,
    outcome: &BotProtectionOutcome,
) -> Option<RuleMatch> {
    if outcome.action == WafAction::Allow {
        return None;
    }

    Some(RuleMatch {
        rule_id: config.rule.id.clone(),
        rule_name: config.rule.name.clone(),
        category: config.rule.category.clone(),
        severity: if outcome.action == WafAction::Block {
            config.rule.block_severity
        } else {
            config.rule.monitor_severity
        },
        matched_target: RuleTarget::Headers,
        paranoia_level: config.rule.paranoia_level,
        explanation: format!(
            "{} Bot protection score {} reached the {:?} threshold with {} contributor(s).",
            config.rule.explanation,
            outcome.score,
            outcome.action,
            outcome.contributors.len()
        ),
        owasp_category: config.rule.owasp_category.clone(),
    })
}

fn evaluate_with_state(
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
            }],
        );
    }

    let mut new_contributors = contributors_for_request(config, &request);
    if blocklisted {
        new_contributors.push(BehaviorContributor {
            reason: "blocklist_match".to_string(),
            score_delta: thresholds.block_threshold,
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
        contributors.push(contributor("missing_user_agent", 20));
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
        contributors.push(contributor("automation_user_agent", 20));
    }

    if path_matches_any(request.path, &config.scanner_paths) {
        contributors.push(contributor("scanner_path_probe", 25));
    }

    if request.forwarded_headers.enabled
        && request.trusted_forwarded_headers
        && forwarded_proto_is_insecure(request.headers, request.forwarded_headers)
    {
        contributors.push(contributor(
            "insecure_forwarded_proto",
            request.forwarded_headers.insecure_proto_score,
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

fn contributor(reason: &str, score_delta: u16) -> BehaviorContributor {
    BehaviorContributor {
        reason: reason.to_string(),
        score_delta,
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

fn read_state(path: &Path) -> anyhow::Result<BotProtectionState> {
    if !path.exists() {
        return Ok(BotProtectionState::default());
    }

    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn write_state(path: &Path, state: &BotProtectionState) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(state)?)?;
    Ok(())
}

fn unix_seconds_now() -> u64 {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BotProtectionLists, BotProtectionRouteConfig};

    #[test]
    fn monitors_deterministic_bot_signals() {
        let store = MemoryBotProtectionStore::new();
        let config = BotProtectionConfig {
            enabled: true,
            backend: BehaviorBackend::Memory,
            monitor_threshold: 20,
            block_threshold: 80,
            ..BotProtectionConfig::default()
        };

        let outcome = store
            .evaluate(
                &config,
                test_request("203.0.113.10", "/.env", "", "curl/8.0", WafMode::Monitor),
            )
            .unwrap();

        assert_eq!(outcome.action, WafAction::Monitor);
        assert!(outcome.score >= 20);
    }

    #[test]
    fn blocklist_blocks_immediately() {
        let store = MemoryBotProtectionStore::new();
        let config = BotProtectionConfig {
            enabled: true,
            mode: BehaviorMode::Block,
            backend: BehaviorBackend::Memory,
            blocklists: BotProtectionLists {
                ip_ranges: vec!["203.0.113.10".to_string()],
                user_agents: Vec::new(),
            },
            ..BotProtectionConfig::default()
        };

        let outcome = store
            .evaluate(
                &config,
                test_request("203.0.113.10", "/", "", "Mozilla/5.0", WafMode::Block),
            )
            .unwrap();

        assert_eq!(outcome.action, WafAction::Block);
        assert!(outcome.blocklisted);
    }

    #[test]
    fn allowlist_bypasses_bot_signals() {
        let store = MemoryBotProtectionStore::new();
        let config = BotProtectionConfig {
            enabled: true,
            mode: BehaviorMode::Block,
            backend: BehaviorBackend::Memory,
            allowlists: BotProtectionLists {
                ip_ranges: vec!["203.0.113.0/24".to_string()],
                user_agents: Vec::new(),
            },
            ..BotProtectionConfig::default()
        };

        let outcome = store
            .evaluate(
                &config,
                test_request("203.0.113.10", "/.env", "", "curl/8.0", WafMode::Block),
            )
            .unwrap();

        assert_eq!(outcome.action, WafAction::Allow);
        assert!(outcome.allowlisted);
    }

    #[test]
    fn temporary_block_survives_local_restart() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("bot.json");
        let config = BotProtectionConfig {
            enabled: true,
            mode: BehaviorMode::Block,
            backend: BehaviorBackend::Local,
            state_path: path.clone(),
            monitor_threshold: 20,
            block_threshold: 40,
            temporary_block_duration: "15m".to_string(),
            ..BotProtectionConfig::default()
        };

        for _ in 0..2 {
            LocalBotProtectionStore::open(&path)
                .unwrap()
                .evaluate(
                    &config,
                    test_request("203.0.113.10", "/.env", "", "curl/8.0", WafMode::Block),
                )
                .unwrap();
        }

        let outcome = LocalBotProtectionStore::open(&path)
            .unwrap()
            .evaluate(
                &config,
                test_request("203.0.113.10", "/", "", "Mozilla/5.0", WafMode::Block),
            )
            .unwrap();

        assert_eq!(outcome.action, WafAction::Block);
        assert!(outcome
            .contributors
            .iter()
            .any(|contributor| contributor.reason == "temporary_block_active"));
    }

    #[test]
    fn reset_client_removes_only_matching_local_bot_state() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("bot.json");
        let config = BotProtectionConfig {
            enabled: true,
            backend: BehaviorBackend::Local,
            state_path: path.clone(),
            ..BotProtectionConfig::default()
        };

        for client_id in ["203.0.113.10", "203.0.113.11"] {
            LocalBotProtectionStore::open(&path)
                .unwrap()
                .evaluate(
                    &config,
                    test_request(client_id, "/.env", "", "curl/8.0", WafMode::Monitor),
                )
                .unwrap();
        }

        assert!(reset_client(&path, "203.0.113.10").unwrap());
        assert!(!reset_client(&path, "203.0.113.12").unwrap());
        let state = read_state(&path).unwrap();

        assert!(!state.clients.contains_key("203.0.113.10"));
        assert!(state.clients.contains_key("203.0.113.11"));
    }

    #[test]
    fn expired_temporary_block_allows_clean_request() {
        let mut state = BotProtectionState::default();
        state.clients.insert(
            "203.0.113.10".to_string(),
            ClientBotProtectionState {
                entries: Vec::new(),
                temporary_blocked_until: Some(unix_seconds_now().saturating_sub(1)),
            },
        );
        let config = BotProtectionConfig {
            enabled: true,
            mode: BehaviorMode::Block,
            ..BotProtectionConfig::default()
        };

        let outcome = evaluate_with_state(
            &config,
            test_request("203.0.113.10", "/", "", "Mozilla/5.0", WafMode::Block),
            &mut state,
            "memory",
        );

        assert_eq!(outcome.action, WafAction::Allow);
        assert!(outcome.temporary_blocked_until.is_none());
    }

    #[test]
    fn route_override_changes_thresholds() {
        let store = MemoryBotProtectionStore::new();
        let config = BotProtectionConfig {
            enabled: true,
            backend: BehaviorBackend::Memory,
            monitor_threshold: 80,
            block_threshold: 100,
            routes: vec![BotProtectionRouteConfig {
                path: "/login".to_string(),
                monitor_threshold: Some(20),
                block_threshold: Some(40),
            }],
            ..BotProtectionConfig::default()
        };

        let outcome = store
            .evaluate(
                &config,
                test_request("203.0.113.10", "/login", "", "", WafMode::Monitor),
            )
            .unwrap();

        assert_eq!(outcome.monitor_threshold, 20);
        assert_eq!(outcome.action, WafAction::Monitor);
    }

    #[test]
    fn custom_scanner_paths_drive_bot_scoring() {
        let store = MemoryBotProtectionStore::new();
        let config = BotProtectionConfig {
            enabled: true,
            backend: BehaviorBackend::Memory,
            monitor_threshold: 20,
            block_threshold: 80,
            scanner_paths: vec!["/custom-scanner".to_string()],
            ..BotProtectionConfig::default()
        };

        let outcome = store
            .evaluate(
                &config,
                test_request(
                    "203.0.113.10",
                    "/custom-scanner/run",
                    "",
                    "Mozilla/5.0",
                    WafMode::Monitor,
                ),
            )
            .unwrap();

        assert_eq!(outcome.action, WafAction::Monitor);
        assert!(outcome
            .contributors
            .iter()
            .any(|contributor| contributor.reason == "scanner_path_probe"));
    }

    #[test]
    fn trusted_forwarded_proto_policy_scores_unexpected_proto() {
        let store = MemoryBotProtectionStore::new();
        let config = BotProtectionConfig {
            enabled: true,
            backend: BehaviorBackend::Memory,
            monitor_threshold: 10,
            block_threshold: 80,
            ..BotProtectionConfig::default()
        };

        let outcome = store
            .evaluate(
                &config,
                test_request(
                    "203.0.113.10",
                    "/",
                    "x-forwarded-proto: http",
                    "Mozilla/5.0",
                    WafMode::Monitor,
                ),
            )
            .unwrap();

        assert_eq!(outcome.action, WafAction::Monitor);
        assert!(outcome
            .contributors
            .iter()
            .any(|contributor| contributor.reason == "insecure_forwarded_proto"));
    }

    #[test]
    fn untrusted_forwarded_proto_header_is_not_scored() {
        let store = MemoryBotProtectionStore::new();
        let config = BotProtectionConfig {
            enabled: true,
            backend: BehaviorBackend::Memory,
            monitor_threshold: 10,
            block_threshold: 80,
            ..BotProtectionConfig::default()
        };

        let mut request = test_request(
            "203.0.113.10",
            "/",
            "x-forwarded-proto: http",
            "Mozilla/5.0",
            WafMode::Monitor,
        );
        request.trusted_forwarded_headers = false;
        let outcome = store.evaluate(&config, request).unwrap();

        assert_eq!(outcome.action, WafAction::Allow);
        assert!(outcome.contributors.is_empty());
    }

    #[test]
    fn bot_rule_match_uses_configured_rule_metadata() {
        let config = BotProtectionConfig {
            rule: crate::config::BotProtectionRuleConfig {
                id: "CUSTOM-BOT-001".to_string(),
                name: "Custom Bot Threshold".to_string(),
                category: "custom_bot".to_string(),
                ..Default::default()
            },
            ..BotProtectionConfig::default()
        };
        let outcome = BotProtectionOutcome {
            enabled: true,
            action: WafAction::Monitor,
            score: 40,
            monitor_threshold: 40,
            block_threshold: 80,
            score_window_seconds: 600,
            temporary_block_duration_seconds: 900,
            temporary_blocked_until: None,
            storage_backend: "memory".to_string(),
            allowlisted: false,
            blocklisted: false,
            contributors: Vec::new(),
        };

        let rule_match = bot_rule_match(&config, &outcome).unwrap();

        assert_eq!(rule_match.rule_id, "CUSTOM-BOT-001");
        assert_eq!(rule_match.rule_name, "Custom Bot Threshold");
        assert_eq!(rule_match.category, "custom_bot");
    }

    fn test_request<'a>(
        client_id: &'a str,
        path: &'a str,
        headers: &'a str,
        user_agent: &'a str,
        server_mode: WafMode,
    ) -> BotProtectionRequest<'a> {
        BotProtectionRequest {
            client_id,
            path,
            headers,
            user_agent,
            forwarded_headers: &DEFAULT_FORWARDED_HEADERS,
            trusted_forwarded_headers: true,
            server_mode,
        }
    }

    static DEFAULT_FORWARDED_HEADERS: std::sync::LazyLock<ForwardedHeadersConfig> =
        std::sync::LazyLock::new(ForwardedHeadersConfig::default);
}
