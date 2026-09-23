use std::fs;

use super::{eval::CampaignState, *};
use crate::config::{CampaignBackend, CampaignPolicyConfig, CampaignStageConfig, WafMode};

#[tokio::test]
async fn redis_store_reports_invalid_url_with_campaign_context() {
    let error = RedisCampaignStore::connect("not a Redis URL", None, "saugra-waf:campaign")
        .await
        .err()
        .unwrap();

    assert!(error
        .to_string()
        .contains("campaign_correlation.redis_url is not a valid Redis URL"));
}

#[tokio::test]
async fn disabled_store_does_not_touch_local_state_path() {
    let temp_dir = tempfile::tempdir().unwrap();
    let blocked_parent = temp_dir.path().join("not-a-directory");
    fs::write(&blocked_parent, b"file").unwrap();

    let config = CampaignCorrelationConfig {
        enabled: false,
        backend: CampaignBackend::Local,
        state_path: blocked_parent.join("campaign.json"),
        ..CampaignCorrelationConfig::default()
    };

    let store = build_store(&config).await.unwrap();
    let categories = vec!["scanner_behavior".to_string()];
    let outcome = store
        .evaluate(
            &config,
            CampaignRequest {
                request_id: "req-1",
                client_id: "203.0.113.10",
                session_id: "session-1",
                path: "/login",
                categories: &categories,
                server_mode: WafMode::Monitor,
            },
        )
        .await
        .unwrap();

    assert!(!outcome.enabled);
    assert_eq!(outcome.storage_backend, "memory");
}

fn config(policy: CampaignPolicyConfig) -> CampaignCorrelationConfig {
    CampaignCorrelationConfig {
        enabled: true,
        backend: CampaignBackend::Memory,
        window: "15m".to_string(),
        retention: "24h".to_string(),
        max_events: 100,
        policies: vec![policy],
        ..CampaignCorrelationConfig::default()
    }
}

#[tokio::test]
async fn correlates_distributed_scanning_across_clients_and_routes() {
    let store = MemoryCampaignStore::default();
    let config = config(CampaignPolicyConfig {
        kind: "distributed_scanning".to_string(),
        scope: "global".to_string(),
        score: 60,
        minimum_events: 3,
        minimum_clients: 3,
        minimum_sessions: 3,
        minimum_routes: 3,
        categories: vec!["scanner_behavior".to_string()],
        path_prefixes: Vec::new(),
        stages: Vec::new(),
        minimum_stages: 0,
    });

    for index in 0..2 {
        let outcome = store
            .evaluate(
                &config,
                CampaignRequest {
                    request_id: &format!("request-{index}"),
                    client_id: &format!("client-{index}"),
                    session_id: &format!("session-{index}"),
                    path: &format!("/probe-{index}"),
                    categories: &["scanner_behavior".to_string()],
                    server_mode: WafMode::Monitor,
                },
            )
            .await
            .unwrap();
        assert_eq!(outcome.action, WafAction::Allow);
    }

    let outcome = store
        .evaluate(
            &config,
            CampaignRequest {
                request_id: "request-2",
                client_id: "client-2",
                session_id: "session-2",
                path: "/probe-2",
                categories: &["scanner_behavior".to_string()],
                server_mode: WafMode::Monitor,
            },
        )
        .await
        .unwrap();
    assert_eq!(outcome.action, WafAction::Monitor);
    assert_eq!(outcome.matches[0].client_count, 3);
    assert!(outcome.campaign_ids[0].starts_with("cmp-"));
}

#[tokio::test]
async fn detects_multi_step_progression_within_one_session() {
    let store = MemoryCampaignStore::default();
    let config = config(CampaignPolicyConfig {
        kind: "multi_step_progression".to_string(),
        scope: "session".to_string(),
        score: 80,
        minimum_events: 3,
        minimum_clients: 1,
        minimum_sessions: 1,
        minimum_routes: 2,
        categories: Vec::new(),
        path_prefixes: Vec::new(),
        stages: vec![
            CampaignStageConfig {
                name: "recon".to_string(),
                categories: vec!["scanner_behavior".to_string()],
            },
            CampaignStageConfig {
                name: "access".to_string(),
                categories: vec!["authentication_abuse".to_string()],
            },
            CampaignStageConfig {
                name: "exploit".to_string(),
                categories: vec!["sql_injection".to_string()],
            },
        ],
        minimum_stages: 3,
    });
    for (index, category) in ["scanner_behavior", "authentication_abuse", "sql_injection"]
        .iter()
        .enumerate()
    {
        let outcome = store
            .evaluate(
                &config,
                CampaignRequest {
                    request_id: &format!("request-{index}"),
                    client_id: "client",
                    session_id: "session",
                    path: if index == 0 { "/probe" } else { "/login" },
                    categories: &[category.to_string()],
                    server_mode: WafMode::Monitor,
                },
            )
            .await
            .unwrap();
        if index == 2 {
            assert_eq!(outcome.matches[0].stages.len(), 3);
        }
    }
}

#[tokio::test]
async fn local_store_persists_campaign_state_and_builders_select_backends() {
    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("campaign-state.json");
    let mut config = config(CampaignPolicyConfig {
        kind: "single-client-scan".to_string(),
        scope: "client".to_string(),
        score: 40,
        minimum_events: 1,
        minimum_clients: 1,
        minimum_sessions: 1,
        minimum_routes: 1,
        categories: vec!["scanner_behavior".to_string()],
        path_prefixes: Vec::new(),
        stages: Vec::new(),
        minimum_stages: 0,
    });
    config.backend = CampaignBackend::Local;
    config.state_path = state_path.clone();

    let store = build_store(&config).await.unwrap();
    let outcome = store
        .evaluate(
            &config,
            CampaignRequest {
                request_id: "request-local",
                client_id: "client-local",
                session_id: "session-local",
                path: "/probe/123",
                categories: &["scanner_behavior".to_string()],
                server_mode: WafMode::Monitor,
            },
        )
        .await
        .unwrap();

    assert_eq!(outcome.storage_backend, "local");
    assert_eq!(outcome.action, WafAction::Monitor);
    assert!(state_path.exists());

    let reopened = build_store_without_redis(&config).unwrap();
    let repeated = reopened
        .evaluate(
            &config,
            CampaignRequest {
                request_id: "request-local-2",
                client_id: "client-local",
                session_id: "session-local",
                path: "/probe/456",
                categories: &["scanner_behavior".to_string()],
                server_mode: WafMode::Monitor,
            },
        )
        .await
        .unwrap();
    assert_eq!(repeated.matches[0].event_count, 2);

    config.backend = CampaignBackend::Redis;
    let error = match build_store_without_redis(&config) {
        Ok(_) => panic!("Redis should require asynchronous store construction"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("asynchronous store construction"));
}

#[test]
fn campaign_state_errors_include_paths() {
    let temp_dir = tempfile::tempdir().unwrap();
    let invalid_state = temp_dir.path().join("invalid-campaign-state.json");
    fs::write(&invalid_state, b"not-json").unwrap();

    let read_error = read_state(&invalid_state).unwrap_err();
    assert!(read_error
        .to_string()
        .contains("campaign state is not valid JSON"));
    assert!(read_error
        .to_string()
        .contains("invalid-campaign-state.json"));

    let blocked_parent = temp_dir.path().join("not-a-directory");
    fs::write(&blocked_parent, b"file").unwrap();
    let blocked_state = blocked_parent.join("campaign-state.json");
    let write_error = write_state(&blocked_state, &CampaignState::default()).unwrap_err();
    assert!(write_error
        .to_string()
        .contains("failed to create campaign state directory"));
    assert!(write_error.to_string().contains("not-a-directory"));

    let lock_error = match StateFileLock::acquire(&blocked_state) {
        Ok(_) => panic!("lock creation should fail for a path under a file"),
        Err(error) => error,
    };
    assert!(lock_error
        .to_string()
        .contains("failed to create campaign lock directory"));
    assert!(lock_error.to_string().contains("not-a-directory"));
}

#[test]
fn campaign_state_replace_errors_include_path() {
    let temp_dir = tempfile::tempdir().unwrap();
    let directory_path = temp_dir.path().join("campaign-state.json");
    fs::create_dir(&directory_path).unwrap();

    let error = write_state(&directory_path, &CampaignState::default()).unwrap_err();

    assert!(error
        .to_string()
        .contains("failed to replace campaign state"));
    assert!(error.to_string().contains("campaign-state.json"));
}

#[test]
fn fingerprints_session_material_without_retaining_it() {
    let first = session_fingerprint("127.0.0.1", "browser", Some(b"session=secret"));
    let second = session_fingerprint("127.0.0.1", "browser", Some(b"session=other"));
    assert_ne!(first, second);
    assert!(!first.contains("secret"));
}
