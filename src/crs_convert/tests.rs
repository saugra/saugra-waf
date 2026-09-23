use super::*;

#[test]
fn converts_crs_regex_rule() {
    let contents = r#"
SecRule ARGS "@rx (?i)union.*?select" \
    "id:942270,\
    phase:2,\
    block,\
    t:none,t:urlDecodeUni,\
    msg:'Looking for basic sql injection',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    severity:'CRITICAL'"
"#;

    let (rules, skipped) = convert_crs_contents(contents);

    assert!(skipped.is_empty());
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].id, "CRS-942270");
    assert_eq!(rules[0].category, "sql_injection");
    assert_eq!(rules[0].severity, "critical");
    assert_eq!(rules[0].targets, vec!["query"]);
    assert_eq!(rules[0].transforms, vec!["url_decode"]);
}

#[test]
fn converts_supported_crs_transforms_in_order() {
    let contents = r#"
SecRule ARGS "@rx union" "id:942271,phase:2,block,t:none,t:urlDecode,t:lowercase,msg:'Transform order',severity:'WARNING'"
"#;

    let (rules, skipped) = convert_crs_contents(contents);

    assert!(skipped.is_empty());
    assert_eq!(rules[0].transforms, vec!["url_decode", "lowercase"]);
}

#[test]
fn skips_unsupported_crs_transform() {
    let contents = r#"
SecRule ARGS "@rx union" "id:942272,phase:2,block,t:none,t:cmdLine,msg:'Unsupported transform',severity:'WARNING'"
"#;

    let (rules, skipped) = convert_crs_contents(contents);

    assert!(rules.is_empty());
    assert_eq!(skipped.len(), 1);
    assert_eq!(skipped[0].id.as_deref(), Some("CRS-942272"));
    assert!(skipped[0]
        .reason
        .contains("unsupported transform t:cmdLine"));
}

#[test]
fn converts_pm_from_file_rule_with_data_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let data_dir = temp_dir.path().join("util").join("regexp-assemble");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(
        data_dir.join("sql-keywords.data"),
        r#"
# comments are ignored
union select
sleep(
"#,
    )
    .unwrap();
    let contents = r#"
SecRule ARGS "@pmFromFile util/regexp-assemble/sql-keywords.data" \
    "id:942400,\
    phase:2,\
    block,\
    t:none,t:lowercase,\
    msg:'SQL keywords from data file',\
    tag:'attack-sqli',\
    severity:'CRITICAL'"
"#;

    let (rules, skipped) = convert_crs_contents_with_base(contents, Some(temp_dir.path()));

    assert!(skipped.is_empty());
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].id, "CRS-942400");
    assert_eq!(rules[0].category, "sql_injection");
    assert_eq!(rules[0].transforms, vec!["lowercase"]);
    assert!(rules[0].pattern.contains("union select"));
    assert!(rules[0].pattern.contains("sleep\\("));
}

#[test]
fn reports_missing_pm_from_file_data_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let contents = r#"
SecRule ARGS "@pmFromFile missing.data" "id:942401,phase:2,block,msg:'missing data file',severity:'CRITICAL'"
"#;

    let (rules, skipped) = convert_crs_contents_with_base(contents, Some(temp_dir.path()));

    assert!(rules.is_empty());
    assert_eq!(skipped.len(), 1);
    assert_eq!(skipped[0].id.as_deref(), Some("CRS-942401"));
    assert!(skipped[0].reason.contains("unable to read @pmFromFile"));
}

#[test]
fn reports_chained_rules_as_unsupported() {
    let contents = r#"
SecRule ARGS "@rx first" "id:942402,phase:2,block,chain,msg:'chain starter',severity:'CRITICAL'"
SecRule ARGS "@rx second" "t:none"
"#;

    let (rules, skipped) = convert_crs_contents(contents);

    assert!(rules.is_empty());
    assert_eq!(skipped.len(), 2);
    assert_eq!(skipped[0].id.as_deref(), Some("CRS-942402"));
    assert!(skipped[0].reason.contains("chained CRS rules"));
}

#[test]
fn converts_representative_crs_categories() {
    let contents = r#"
SecRule ARGS "@rx <script" "id:941100,phase:2,block,msg:'xss',tag:'attack-xss',severity:'CRITICAL'"
SecRule REQUEST_FILENAME "@rx \.\./" "id:930100,phase:2,block,msg:'lfi',tag:'attack-lfi',severity:'CRITICAL'"
SecRule ARGS "@rx ;id" "id:932100,phase:2,block,msg:'rce',tag:'attack-rce',severity:'CRITICAL'"
SecRule REQUEST_HEADERS "@rx nikto" "id:913100,phase:1,block,msg:'scanner',tag:'attack-scanner',severity:'WARNING'"
SecRule REQUEST_HEADERS "@rx bad-protocol" "id:920100,phase:1,block,msg:'protocol',tag:'protocol-violation',severity:'WARNING'"
SecRule FILES_NAMES "@rx \.php$" "id:933100,phase:2,block,msg:'file upload',tag:'attack-file-upload',severity:'CRITICAL'"
"#;

    let (rules, skipped) = convert_crs_contents(contents);
    let categories = rules
        .iter()
        .map(|rule| {
            (
                rule.id.as_str(),
                rule.category.as_str(),
                rule.targets.clone(),
            )
        })
        .collect::<Vec<_>>();

    assert!(skipped.is_empty());
    assert_eq!(rules.len(), 6);
    assert!(categories.contains(&(
        "CRS-941100",
        "cross_site_scripting",
        vec!["query".to_string()]
    )));
    assert!(categories.contains(&("CRS-930100", "path_traversal", vec!["path".to_string()])));
    assert!(categories.contains(&("CRS-932100", "command_injection", vec!["query".to_string()])));
    assert!(categories.contains(&(
        "CRS-913100",
        "scanner_behavior",
        vec!["headers".to_string()]
    )));
    assert!(categories.contains(&(
        "CRS-920100",
        "protocol_enforcement",
        vec!["headers".to_string()]
    )));
    assert!(categories.contains(&("CRS-933100", "file_upload", vec!["body".to_string()])));
}

#[test]
fn skips_unsupported_crs_operator() {
    let contents = r#"
SecRule ARGS "@detectSQLi" "id:942100,phase:2,block,msg:'libinjection',severity:'CRITICAL'"
"#;

    let (rules, skipped) = convert_crs_contents(contents);

    assert!(rules.is_empty());
    assert_eq!(skipped.len(), 1);
    assert_eq!(skipped[0].id.as_deref(), Some("CRS-942100"));
    assert!(skipped[0].reason.contains("unsupported operator"));
}
