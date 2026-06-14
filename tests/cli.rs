use std::{fs, path::PathBuf, process::Command};

use saugra_waf::{
    decision::WafDecision,
    event_store::{self, EventLogRetention, SecurityEvent, UpstreamEvent},
};

#[test]
fn cli_version_prints_package_version() {
    let output = saugra_waf_cmd(["--version"]);

    assert_success(&output);
    assert_eq!(
        stdout(&output).trim(),
        format!("saugra-waf {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn cli_cleanup_dry_run_prints_report_json() {
    let output = saugra_waf_cmd([
        "cleanup",
        "run",
        "--dry-run",
        "--config",
        "configs/saugra-waf.example.yml",
    ]);

    assert_success(&output);

    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["dry_run"], true);
    assert!(report["scanned_targets"].as_u64().unwrap() >= 1);
    assert!(report["files"].is_array());
    assert_eq!(report["unknown_threats"]["dry_run"], true);
    assert!(report["unknown_threats"]["routes_removed"].is_number());
}

#[test]
fn cli_init_commands_print_starter_configs() {
    let init = saugra_waf_cmd(["init"]);
    assert_success(&init);
    assert!(stdout(&init).contains("forwarded_headers:"));

    let nginx = saugra_waf_cmd(["init", "nginx"]);
    assert_success(&nginx);
    assert!(stdout(&nginx).contains("proxy_pass http://127.0.0.1:8787;"));

    let apache = saugra_waf_cmd(["init", "apache"]);
    assert_success(&apache);
    assert!(stdout(&apache).contains("ProxyPass / http://127.0.0.1:8787/"));
}

#[test]
fn cli_read_only_inspection_commands_run() {
    let fixture = CliFixture::new();
    let config = fixture.config_arg();

    let cases = [
        (
            vec!["test-config", "--config", &config],
            "config OK: listen=127.0.0.1:8787",
        ),
        (
            vec!["rules", "list", "--config", &config],
            "SAUGRA-SQLI-001",
        ),
        (
            vec!["rules", "view", "SAUGRA-SQLI-001", "--config", &config],
            "Performance cost tier: low",
        ),
        (
            vec!["owasp", "coverage", "--config", &config],
            "OWASP coverage standard:",
        ),
        (
            vec!["posture", "check", "--config", &config],
            "posture checks enabled:",
        ),
        (
            vec!["reports", "summary", "--config", &config],
            "security reports:",
        ),
        (
            vec!["logs", "summary", "--config", &config],
            "security events:",
        ),
        (vec!["logs", "tail", "--config", &config], ""),
        (
            vec!["summary", "daily", "--config", &config],
            "\"total_security_events\"",
        ),
        (
            vec!["unknown-threats", "report", "--config", &config],
            "\"would_block_candidates\"",
        ),
    ];

    for (args, expected) in cases {
        let output = saugra_waf_cmd(args);
        assert_success(&output);
        assert!(
            stdout(&output).contains(expected),
            "stdout did not contain {expected:?}: {}",
            stdout(&output)
        );
    }
}

#[test]
fn cli_explain_reads_recorded_event() {
    let fixture = CliFixture::new();
    let decision = WafDecision::from_matches(
        "cli-request-1".to_string(),
        saugra_waf::config::WafMode::Monitor,
        Vec::new(),
        5,
    );
    let event = SecurityEvent::new_with_timezone(
        "GET",
        "/meetings/",
        "page=1",
        decision,
        "203.0.113.10",
        "UTC",
    )
    .with_upstream(UpstreamEvent {
        name: "app".to_string(),
        host: "example.com".to_string(),
        target: "http://127.0.0.1:8000".to_string(),
    });
    event_store::append(
        &fixture.event_log_path,
        EventLogRetention {
            max_size_bytes: 1024 * 1024,
            max_files: 3,
        },
        &event,
    )
    .unwrap();

    let config = fixture.config_arg();
    let output = saugra_waf_cmd(["explain", "cli-request-1", "--config", &config]);

    assert_success(&output);
    assert!(stdout(&output).contains("Request ID: cli-request-1"));
    assert!(stdout(&output).contains("Client IP: 203.0.113.10"));
    assert!(stdout(&output).contains("Request: GET /meetings/"));
    assert!(stdout(&output).contains("Query: page=1"));
    assert!(stdout(&output).contains("Upstream: app@example.com -> http://127.0.0.1:8000"));
    assert!(stdout(&output).contains("No security rules matched this request."));
    assert!(stdout(&output).contains("\"request_id\": \"cli-request-1\""));
}

#[test]
fn cli_validates_and_replays_inactive_rule_pack() {
    let fixture = CliFixture::new();
    let draft_path = fixture._dir.path().join("draft-rules.yml");
    fs::write(
        &draft_path,
        r#"
metadata:
  name: cli-draft
  version: draft-1
rules:
  - id: DRAFT-CLI-001
    name: CLI Probe
    category: local_policy
    severity: medium
    targets:
      - query
    pattern: "(?i)draft-probe"
    explanation: A reviewed draft probe matched.
"#,
    )
    .unwrap();
    event_store::append(
        &fixture.event_log_path,
        EventLogRetention {
            max_size_bytes: 1024 * 1024,
            max_files: 3,
        },
        &SecurityEvent::new(
            "GET",
            "/search",
            "q=draft-probe",
            WafDecision::from_matches(
                "cli-replay-1".to_string(),
                saugra_waf::config::WafMode::Monitor,
                Vec::new(),
                5,
            ),
        ),
    )
    .unwrap();

    let draft = draft_path.display().to_string();
    let validate = saugra_waf_cmd(["rules", "validate", "--input", &draft]);
    assert_success(&validate);
    assert!(stdout(&validate).contains("rule pack OK"));
    assert!(stdout(&validate).contains("compiled=1"));

    let replay = saugra_waf_cmd([
        "rules",
        "replay",
        "--input",
        &draft,
        "--config",
        &fixture.config_arg(),
    ]);
    assert_success(&replay);
    let report: serde_json::Value = serde_json::from_slice(&replay.stdout).unwrap();
    assert_eq!(report["total_events"], 1);
    assert_eq!(report["matched_events"], 1);
    assert_eq!(report["previously_allowed_review_candidates"], 1);
}

#[test]
fn cli_discovers_config_from_environment() {
    let fixture = CliFixture::new();
    let output =
        saugra_waf_cmd_with_env(["test-config"], "SAUGRA_WAF_CONFIG", fixture.config_arg());

    assert_success(&output);
    assert!(stdout(&output).contains("config OK: listen=127.0.0.1:8787"));
}

#[test]
fn cli_explicit_config_overrides_discovered_config() {
    let fixture = CliFixture::new();
    let config = fixture.config_arg();
    let output = Command::new(env!("CARGO_BIN_EXE_saugra-waf"))
        .env("SAUGRA_WAF_CONFIG", "/does/not/exist/saugra-waf.yml")
        .args(["test-config", "--config", &config])
        .output()
        .unwrap();

    assert_success(&output);
    assert!(stdout(&output).contains("config OK: listen=127.0.0.1:8787"));
}

#[test]
fn cli_runtime_policy_and_state_commands_run() {
    let fixture = CliFixture::new();
    let config = fixture.config_arg();

    let add = saugra_waf_cmd([
        "allowlist",
        "add",
        "ip",
        "203.0.113.10",
        "--reason",
        "cli test",
        "--config",
        &config,
    ]);
    assert_success(&add);
    let entry: serde_json::Value = serde_json::from_slice(&add.stdout).unwrap();
    let id = entry["id"].as_str().unwrap().to_string();

    let list = saugra_waf_cmd(["allowlist", "list", "--config", &config]);
    assert_success(&list);
    assert!(stdout(&list).contains("203.0.113.10"));

    let remove = saugra_waf_cmd(["allowlist", "remove", &id, "--config", &config]);
    assert_success(&remove);
    assert!(stdout(&remove).contains("removed allowlist entry"));

    let block = saugra_waf_cmd([
        "allowlist",
        "block",
        "add",
        "198.51.100.20",
        "--reason",
        "cli test",
        "--config",
        &config,
    ]);
    assert_success(&block);
    assert!(stdout(&block).contains("198.51.100.20"));

    let prune = saugra_waf_cmd(["allowlist", "prune", "--config", &config]);
    assert_success(&prune);
    assert!(stdout(&prune).contains("pruned"));

    let behavior_reset = saugra_waf_cmd([
        "state",
        "reset",
        "behavior",
        "203.0.113.10",
        "--config",
        &config,
    ]);
    assert_success(&behavior_reset);
    assert!(stdout(&behavior_reset).contains("no behavior state found"));

    let bot_reset = saugra_waf_cmd(["state", "reset", "bot", "203.0.113.10", "--config", &config]);
    assert_success(&bot_reset);
    assert!(stdout(&bot_reset).contains("no bot state found"));
}

struct CliFixture {
    _dir: tempfile::TempDir,
    config_path: PathBuf,
    event_log_path: PathBuf,
}

impl CliFixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("saugra-waf.yml");
        let event_log_path = dir.path().join("events.jsonl");
        let runtime_policy_path = dir.path().join("runtime-policy.json");
        let behavior_state_path = dir.path().join("behavior-state.json");
        let bot_state_path = dir.path().join("bot-state.json");
        let ai_audit_path = dir.path().join("ai-audit.jsonl");
        let summary_path = dir.path().join("summary.json");
        let cleanup_dir = dir.path().join("cleanup");
        fs::create_dir_all(&cleanup_dir).unwrap();

        fs::write(
            &config_path,
            format!(
                r#"
server:
  listen: 127.0.0.1:8787
  mode: monitor
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
security:
  enable_rate_limiting: true
forwarded_headers:
  trusted_proxies:
    - 127.0.0.1/32
rate_limit:
  backend: memory
  requests_per_minute: 120
  burst: 30
behavior:
  backend: local
  state_path: {}
bot_protection:
  backend: local
  state_path: {}
ai:
  provider: local
  audit_log_path: {}
runtime_policy:
  path: {}
rules:
  files:
    - configs/rules/REQUEST-913-SCANNER-DETECTION.yml
    - configs/rules/REQUEST-921-CRYPTO-TRANSPORT.yml
    - configs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.yml
logging:
  event_log_path: {}
  event_log_max_files: 3
security_summary:
  output_path: {}
  channels:
    - type: file
      path: {}
storage_cleanup:
  dry_run: true
  targets:
    - name: test reports
      directory: {}
      filename_prefix: saugra-waf-
      filename_suffix: .json
      older_than: 1d
"#,
                behavior_state_path.display(),
                bot_state_path.display(),
                ai_audit_path.display(),
                runtime_policy_path.display(),
                event_log_path.display(),
                summary_path.display(),
                summary_path.display(),
                cleanup_dir.display(),
            ),
        )
        .unwrap();

        Self {
            _dir: dir,
            config_path,
            event_log_path,
        }
    }

    fn config_arg(&self) -> String {
        self.config_path.display().to_string()
    }
}

fn saugra_waf_cmd<I, S>(args: I) -> std::process::Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Command::new(env!("CARGO_BIN_EXE_saugra-waf"))
        .args(args)
        .output()
        .unwrap()
}

fn saugra_waf_cmd_with_env<I, S>(args: I, name: &str, value: String) -> std::process::Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Command::new(env!("CARGO_BIN_EXE_saugra-waf"))
        .env(name, value)
        .args(args)
        .output()
        .unwrap()
}

fn assert_success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        stdout(output),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}
