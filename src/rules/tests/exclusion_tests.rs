use crate::{
    config::{RuleExclusionConfig, WafMode},
    decision::WafDecision,
    event_store::SecurityEvent,
};

use super::super::{
    attach_labeled_replay, builtin_rules, replay_events, replay_events_with_exclusions,
    RequestParts, RuleSet, RuleTarget,
};

#[test]
fn excludes_rule_by_id_path_and_query_param() {
    let rule_set = RuleSet::new(builtin_rules().unwrap());
    let matches = rule_set.inspect_with_exclusions(
        &RequestParts {
            path: "/api/articles/preview",
            query: "content=<script>alert(1)</script>",
            ..RequestParts::default()
        },
        &[RuleExclusionConfig {
            rule_ids: vec!["SAUGRA-XSS-001".to_string()],
            path_prefixes: vec!["/api/articles".to_string()],
            query_params: vec!["content".to_string()],
            ..RuleExclusionConfig::default()
        }],
    );

    assert!(matches.is_empty());
}

#[test]
fn does_not_exclude_rule_when_path_scope_does_not_match() {
    let rule_set = RuleSet::new(builtin_rules().unwrap());
    let matches = rule_set.inspect_with_exclusions(
        &RequestParts {
            path: "/comments",
            query: "content=<script>alert(1)</script>",
            ..RequestParts::default()
        },
        &[RuleExclusionConfig {
            rule_ids: vec!["SAUGRA-XSS-001".to_string()],
            path_prefixes: vec!["/api/articles".to_string()],
            query_params: vec!["content".to_string()],
            ..RuleExclusionConfig::default()
        }],
    );

    assert_eq!(matches[0].rule_id, "SAUGRA-XSS-001");
}

#[test]
fn excludes_rule_by_category_and_header_scope() {
    let rule_set = RuleSet::new(builtin_rules().unwrap());
    let matches = rule_set.inspect_with_exclusions(
        &RequestParts {
            query: "content=<script>alert(1)</script>",
            headers: "x-trusted-editor: true",
            ..RequestParts::default()
        },
        &[RuleExclusionConfig {
            categories: vec!["cross_site_scripting".to_string()],
            headers: vec!["X-Trusted-Editor".to_string()],
            ..RuleExclusionConfig::default()
        }],
    );

    assert!(matches.is_empty());
}

#[test]
fn context_aware_exclusion_requires_every_configured_scope() {
    let rule_set = RuleSet::new(builtin_rules().unwrap());
    let exclusion = RuleExclusionConfig {
        rule_ids: vec!["SAUGRA-XSS-001".to_string()],
        methods: vec!["POST".to_string()],
        targets: vec![RuleTarget::Query],
        content_types: vec!["application/json".to_string()],
        trusted_headers: vec![crate::config::RuleExclusionHeaderValueConfig {
            name: "X-Deployment".to_string(),
            values: vec!["internal".to_string()],
        }],
        identities: vec![crate::config::RuleExclusionHeaderValueConfig {
            name: "X-Authenticated-Role".to_string(),
            values: vec!["editor".to_string()],
        }],
        ..RuleExclusionConfig::default()
    };
    let request = RequestParts {
        method: "POST",
        path: "/preview",
        query: "content=%3Cscript%3Ealert(1)%3C/script%3E",
        headers:
            "content-type: application/json\nx-deployment: internal\nx-authenticated-role: editor",
        content_type: "application/json; charset=utf-8",
        trusted_proxy: true,
        ..RequestParts::default()
    };

    assert!(rule_set
        .inspect_with_exclusions(&request, std::slice::from_ref(&exclusion))
        .is_empty());

    let untrusted_request = RequestParts {
        trusted_proxy: false,
        ..request
    };
    assert_eq!(
        rule_set
            .inspect_with_exclusions(&untrusted_request, &[exclusion])
            .len(),
        1
    );
}

#[test]
fn replay_reports_exclusion_impact_from_retained_context() {
    let rule_set = RuleSet::new(builtin_rules().unwrap());
    let event = SecurityEvent::new(
        "POST",
        "/preview",
        "content=%3Cscript%3Ealert(1)%3C/script%3E",
        WafDecision::from_matches("replay-exclusion".to_string(), WafMode::Monitor, vec![], 5),
    )
    .with_evidence(crate::event_store::RequestEvidence {
        content_type: "application/json".to_string(),
        body_size: 0,
        query_parameter_names: vec!["content".to_string()],
        header_names: vec!["content-type".to_string()],
    });
    let exclusions = vec![RuleExclusionConfig {
        rule_ids: vec!["SAUGRA-XSS-001".to_string()],
        methods: vec!["POST".to_string()],
        targets: vec![RuleTarget::Query],
        content_types: vec!["application/json".to_string()],
        query_params: vec!["content".to_string()],
        ..RuleExclusionConfig::default()
    }];

    let report = replay_events_with_exclusions(&rule_set, &[event], &exclusions);

    assert_eq!(report.matches_before_exclusions, 1);
    assert_eq!(report.matches_after_exclusions, 0);
    assert_eq!(report.excluded_events, 1);
}

#[test]
fn labeled_replay_separates_legitimate_impact_and_attack_coverage() {
    let temp_dir = tempfile::tempdir().unwrap();
    let fixture = temp_dir.path().join("cases.jsonl");
    std::fs::write(
        &fixture,
        r#"{"id":"legitimate","label":"legitimate","path":"/search","query":"q=summer"}
{"id":"attack","label":"attack","path":"/search","query":"q=%27%20OR%201%3D1--"}
"#,
    )
    .unwrap();
    let rule_set = RuleSet::new(builtin_rules().unwrap());
    let mut report = replay_events(&rule_set, &[]);

    attach_labeled_replay(&mut report, &rule_set, &[], &fixture).unwrap();

    assert_eq!(report.labeled_total_cases, 2);
    assert_eq!(report.labeled_legitimate_cases, 1);
    assert_eq!(report.labeled_legitimate_matches, 0);
    assert_eq!(report.labeled_attack_cases, 1);
    assert_eq!(report.labeled_attack_matches, 1);
}
