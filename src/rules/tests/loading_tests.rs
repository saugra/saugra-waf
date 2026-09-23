use crate::{
    config::{RuleExclusionConfig, RuleSettings, WafMode},
    decision::WafDecision,
    event_store::SecurityEvent,
    rules::{
        load_rule_set, load_rule_set_with_report, replay_events, validate_rule_file, RequestParts,
        RuleError, RuleTarget,
    },
};

#[test]
fn rejects_invalid_regex_in_configured_rule_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let rule_path = temp_dir.path().join("bad-rules.yml");
    std::fs::write(
        &rule_path,
        r#"
rules:
  - id: LOCAL-BAD-001
    name: Bad Regex
    category: local_policy
    severity: low
    targets:
      - query
    pattern: "["
    explanation: Bad regex should fail startup.
"#,
    )
    .unwrap();

    let error = load_rule_set(&RuleSettings {
        files: vec![rule_path],
        ..RuleSettings::default()
    })
    .unwrap_err();

    assert!(matches!(error, RuleError::InvalidRegex { .. }));
}

#[test]
fn filters_rules_above_configured_paranoia_level() {
    let temp_dir = tempfile::tempdir().unwrap();
    let rule_path = temp_dir.path().join("paranoia-rules.yml");
    std::fs::write(
        &rule_path,
        r#"
rules:
  - id: LOCAL-PL1-001
    name: PL1 Rule
    category: local_policy
    severity: low
    paranoia_level: 1
    targets:
      - query
    pattern: "pl1"
    explanation: PL1 rule matched.
  - id: LOCAL-PL2-001
    name: PL2 Rule
    category: local_policy
    severity: low
    paranoia_level: 2
    targets:
      - query
    pattern: "pl2"
    explanation: PL2 rule matched.
"#,
    )
    .unwrap();

    let rule_set = load_rule_set(&RuleSettings {
        files: vec![rule_path],
        paranoia_level: 1,
        ..RuleSettings::default()
    })
    .unwrap();

    assert_eq!(rule_set.rules().len(), 1);
    assert_eq!(rule_set.rules()[0].id, "LOCAL-PL1-001");
}

#[test]
fn loads_rules_up_to_detection_paranoia_level() {
    let temp_dir = tempfile::tempdir().unwrap();
    let rule_path = temp_dir.path().join("detection-paranoia-rules.yml");
    std::fs::write(
        &rule_path,
        r#"
rules:
  - id: LOCAL-PL1-001
    name: PL1 Rule
    category: local_policy
    severity: low
    paranoia_level: 1
    targets:
      - query
    pattern: "pl1"
    explanation: PL1 rule matched.
  - id: LOCAL-PL2-001
    name: PL2 Rule
    category: local_policy
    severity: low
    paranoia_level: 2
    targets:
      - query
    pattern: "pl2"
    explanation: PL2 rule matched.
"#,
    )
    .unwrap();

    let rule_set = load_rule_set(&RuleSettings {
        files: vec![rule_path],
        paranoia_level: 1,
        detection_paranoia_level: Some(2),
        blocking_paranoia_level: Some(1),
        ..RuleSettings::default()
    })
    .unwrap();

    assert_eq!(rule_set.rules().len(), 2);
    assert_eq!(rule_set.rules()[1].id, "LOCAL-PL2-001");
}

#[test]
fn validates_regexes_even_when_filtered_by_paranoia_level() {
    let temp_dir = tempfile::tempdir().unwrap();
    let rule_path = temp_dir.path().join("bad-paranoia-rules.yml");
    std::fs::write(
        &rule_path,
        r#"
rules:
  - id: LOCAL-PL1-001
    name: PL1 Rule
    category: local_policy
    severity: low
    paranoia_level: 1
    targets:
      - query
    pattern: "pl1"
    explanation: PL1 rule matched.
  - id: LOCAL-PL2-BAD-001
    name: Bad PL2 Rule
    category: local_policy
    severity: low
    paranoia_level: 2
    targets:
      - query
    pattern: "["
    explanation: Bad regex should fail even when PL2 is inactive.
"#,
    )
    .unwrap();

    let error = load_rule_set_with_report(&RuleSettings {
        files: vec![rule_path],
        paranoia_level: 1,
        ..RuleSettings::default()
    })
    .unwrap_err();

    assert!(matches!(error, RuleError::InvalidRegex { .. }));
}

#[test]
fn reports_rule_pack_loading_counts() {
    let temp_dir = tempfile::tempdir().unwrap();
    let rule_path = temp_dir.path().join("reported-rules.yml");
    std::fs::write(
        &rule_path,
        r#"
rules:
  - id: LOCAL-PL1-001
    name: PL1 Rule
    category: local_policy
    severity: low
    paranoia_level: 1
    targets:
      - query
      - body
    pattern: "pl1"
    explanation: PL1 rule matched.
  - id: LOCAL-PL2-001
    name: PL2 Rule
    category: local_policy
    severity: low
    paranoia_level: 2
    targets:
      - query
    pattern: "pl2"
    explanation: PL2 rule matched.
  - id: LOCAL-DISABLED-001
    name: Disabled Rule
    category: local_policy
    severity: low
    enabled: false
    targets:
      - query
    pattern: "disabled"
    explanation: Disabled rule should not load.
"#,
    )
    .unwrap();

    let (_rule_set, report) = load_rule_set_with_report(&RuleSettings {
        files: vec![rule_path.clone()],
        paranoia_level: 1,
        ..RuleSettings::default()
    })
    .unwrap();

    assert_eq!(report.files.len(), 1);
    assert_eq!(report.total_entries, 3);
    assert_eq!(report.enabled_entries, 2);
    assert_eq!(report.disabled_entries, 1);
    assert_eq!(report.compiled_rules, 3);
    assert_eq!(report.active_rules, 2);
    assert_eq!(report.transform_pipelines, 0);
    assert_eq!(report.filtered_by_paranoia, 1);
    assert_eq!(report.files[0].path, rule_path.display().to_string());
}

#[test]
fn reports_rule_exclusion_scope() {
    let temp_dir = tempfile::tempdir().unwrap();
    let rule_path = temp_dir.path().join("one-rule.yml");
    std::fs::write(
        &rule_path,
        r#"
rules:
  - id: LOCAL-001
    name: Local Rule
    category: local_policy
    severity: low
    targets:
      - query
    pattern: "local"
    explanation: Local rule matched.
"#,
    )
    .unwrap();

    let (_rule_set, report) = load_rule_set_with_report(&RuleSettings {
        files: vec![rule_path],
        exclusions: vec![
            RuleExclusionConfig {
                rule_ids: vec!["LOCAL-001".to_string()],
                ..RuleExclusionConfig::default()
            },
            RuleExclusionConfig {
                categories: vec!["local_policy".to_string()],
                path_prefixes: vec!["/health".to_string()],
                ..RuleExclusionConfig::default()
            },
        ],
        ..RuleSettings::default()
    })
    .unwrap();

    assert_eq!(report.exclusions.configured, 2);
    assert_eq!(report.exclusions.global, 1);
    assert_eq!(report.exclusions.scoped, 1);
    assert_eq!(report.exclusions.disabled_rule_ids, vec!["LOCAL-001"]);
    assert_eq!(report.exclusions.disabled_categories, vec!["local_policy"]);
    assert!(report
        .warnings
        .iter()
        .any(|warning| warning.contains("is global")));
}

#[test]
fn warns_for_unknown_rules_and_non_overlapping_exclusion_targets() {
    let (_rule_set, report) = load_rule_set_with_report(&RuleSettings {
        exclusions: vec![
            RuleExclusionConfig {
                rule_ids: vec!["DOES-NOT-EXIST".to_string()],
                path_prefixes: vec!["/review".to_string()],
                ..RuleExclusionConfig::default()
            },
            RuleExclusionConfig {
                rule_ids: vec!["SAUGRA-XSS-001".to_string()],
                targets: vec![RuleTarget::Body],
                ..RuleExclusionConfig::default()
            },
        ],
        ..RuleSettings::default()
    })
    .unwrap();

    assert!(report
        .warnings
        .iter()
        .any(|warning| warning.contains("unknown or inactive rule ID")));
    assert!(report
        .warnings
        .iter()
        .any(|warning| warning.contains("targets do not overlap")));
}

#[test]
fn reports_unsupported_imports_as_warnings() {
    let temp_dir = tempfile::tempdir().unwrap();
    let rule_path = temp_dir.path().join("converted-rules.yml");
    std::fs::write(
        &rule_path,
        r#"
metadata:
  name: converted-owasp-crs-rules
  version: generated
  standards:
    - owasp-crs-converted
unsupported_imports:
  - id: CRS-942100
    reason: unsupported operator @detectSQLi; only @rx is currently converted
rules:
  - id: LOCAL-001
    name: Local Rule
    category: local_policy
    severity: low
    targets:
      - query
    pattern: "local"
    explanation: Local rule matched.
"#,
    )
    .unwrap();

    let (_rule_set, report) = load_rule_set_with_report(&RuleSettings {
        files: vec![rule_path],
        ..RuleSettings::default()
    })
    .unwrap();

    assert_eq!(report.files[0].unsupported_imports, 1);
    assert!(report.warnings[0].contains("CRS-942100"));
    assert!(report.warnings[0].contains("unsupported operator"));
}

#[test]
fn rejects_blank_rule_pack_metadata() {
    let temp_dir = tempfile::tempdir().unwrap();
    let rule_path = temp_dir.path().join("blank-metadata-rules.yml");
    std::fs::write(
        &rule_path,
        r#"
metadata:
  name: ""
  version: 0.1.0
rules:
  - id: LOCAL-001
    name: Local Rule
    category: local_policy
    severity: low
    targets:
      - query
    pattern: "local"
    explanation: Local rule matched.
"#,
    )
    .unwrap();

    let error = load_rule_set_with_report(&RuleSettings {
        files: vec![rule_path],
        ..RuleSettings::default()
    })
    .unwrap_err();

    assert!(matches!(error, RuleError::InvalidMetadata { .. }));
}

#[test]
fn validates_and_replays_a_draft_rule_pack_without_activating_it() {
    let temp_dir = tempfile::tempdir().unwrap();
    let rule_path = temp_dir.path().join("draft-rules.yml");
    std::fs::write(
        &rule_path,
        r#"
metadata:
  name: reviewed-draft
  version: draft-1
rules:
  - id: DRAFT-LOCAL-001
    name: Repeated Probe
    category: local_policy
    severity: medium
    targets:
      - query
      - body
    pattern: "(?i)needle"
    explanation: A reviewed repeated probe matched.
"#,
    )
    .unwrap();

    let (rule_set, report) = validate_rule_file(&rule_path, u8::MAX).unwrap();
    assert_eq!(report.entries, 1);
    assert_eq!(report.compiled_rules, 2);

    let prior_match = rule_set.inspect(&RequestParts {
        query: "probe=needle",
        ..RequestParts::default()
    });
    let events = vec![
        SecurityEvent::new(
            "GET",
            "/search",
            "probe=needle",
            WafDecision::from_matches("allowed".to_string(), WafMode::Monitor, Vec::new(), 5),
        ),
        SecurityEvent::new(
            "GET",
            "/search",
            "safe=1",
            WafDecision::from_matches(
                "monitored".to_string(),
                WafMode::Monitor,
                prior_match.clone(),
                5,
            ),
        ),
        SecurityEvent::new(
            "GET",
            "/search",
            "probe=needle",
            WafDecision::from_matches("blocked".to_string(), WafMode::Block, prior_match, 3),
        ),
    ];

    let replay = replay_events(&rule_set, &events);

    assert_eq!(replay.total_events, 3);
    assert_eq!(replay.matched_events, 2);
    assert_eq!(replay.previously_allowed_review_candidates, 1);
    assert_eq!(replay.previously_blocked_matches, 1);
    assert_eq!(replay.prior_rule_detection_events, 2);
    assert_eq!(replay.prior_rule_detection_overlap, 1);
    assert_eq!(replay.rule_match_counts["DRAFT-LOCAL-001"], 2);
    assert_eq!(replay.replayed_targets, vec!["query"]);
    assert_eq!(replay.unavailable_targets, vec!["body"]);
}
