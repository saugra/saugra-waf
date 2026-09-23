use super::*;
use tempfile::NamedTempFile;

#[test]
fn cidr_matches_ip_inside_range() {
    assert!(ip_matches_entry(
        "203.0.113.10".parse().unwrap(),
        "203.0.113.0/24"
    ));
    assert!(!ip_matches_entry(
        "203.0.114.10".parse().unwrap(),
        "203.0.113.0/24"
    ));
}

#[test]
fn add_and_remove_entry_updates_policy_file() {
    let file = NamedTempFile::new().unwrap();
    let entry = add_ip_entry(
        file.path(),
        "203.0.113.10",
        Some(60),
        "admin testing",
        "test",
    )
    .unwrap();

    let policy = list_policy(file.path()).unwrap();
    assert_eq!(policy.allowlisted_ips.len(), 1);
    assert_eq!(policy.allowlisted_ips[0].value, "203.0.113.10/32");

    assert!(remove_entry(file.path(), &entry.id).unwrap());
    let policy = list_policy(file.path()).unwrap();
    assert!(policy.allowlisted_ips.is_empty());
}

#[test]
fn expired_entries_do_not_match() {
    let handle = RuntimePolicyHandle {
        config: RuntimePolicyConfig::default(),
        state: Mutex::new(RuntimePolicyState {
            policy: RuntimePolicy {
                version: 1,
                allowlisted_ips: vec![RuntimeAllowlistEntry {
                    id: "expired".to_string(),
                    value: "203.0.113.10/32".to_string(),
                    reason: "expired".to_string(),
                    created_by: "test".to_string(),
                    created_at_unix_seconds: 1,
                    expires_at_unix_seconds: Some(1),
                }],
                blocklisted_ips: Vec::new(),
            },
            last_loaded_metadata: None,
            last_checked: Instant::now(),
        }),
    };

    assert!(handle.match_ip("203.0.113.10").is_none());
}

#[test]
fn malformed_reload_keeps_last_known_good_policy() {
    let file = NamedTempFile::new().unwrap();
    add_ip_entry(
        file.path(),
        "198.51.100.25",
        Some(60),
        "rollout safety",
        "test",
    )
    .unwrap();
    let handle = RuntimePolicyHandle::open(RuntimePolicyConfig {
        enabled: true,
        path: file.path().to_path_buf(),
        reload_interval: "1s".to_string(),
        ..RuntimePolicyConfig::default()
    });

    assert!(handle.match_ip("198.51.100.25").is_some());

    fs::write(file.path(), b"{not-valid-json").unwrap();
    {
        let mut state = handle.state.lock().unwrap();
        state.last_checked = Instant::now() - Duration::from_secs(2);
    }

    let runtime_match = handle.match_ip("198.51.100.25").unwrap();

    assert_eq!(runtime_match.value, "198.51.100.25/32");
    assert_eq!(runtime_match.reason, "rollout safety");
}
