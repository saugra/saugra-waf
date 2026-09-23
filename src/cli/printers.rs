use saugra_waf::{event_store, owasp, posture, reports, rules};

use super::commands::InitTarget;

pub fn print_rule_load_report(report: &rules::RuleLoadReport) {
    if !report.standards.is_empty() {
        println!("rule standards: {}", report.standards.join(","));
    }
    println!("rule files: {}", report.files.len());
    for file in &report.files {
        println!(
            "  {}: name={}, version={}, standards={}, entries={}, enabled={}, disabled={}, active_rules={}, transform_pipelines={}, filtered_by_detection_paranoia={}, unsupported_imports={}",
            file.path,
            file.name.as_deref().unwrap_or("unknown"),
            file.version.as_deref().unwrap_or("unknown"),
            if file.standards.is_empty() {
                "none".to_string()
            } else {
                file.standards.join(",")
            },
            file.entries,
            file.enabled_entries,
            file.disabled_entries,
            file.active_rules,
            file.transform_pipelines,
            file.filtered_by_paranoia,
            file.unsupported_imports
        );
        for warning in &file.warnings {
            println!("    warning: {warning}");
        }
    }
    println!(
        "rules: entries={}, enabled={}, disabled={}, compiled={}, active={}, transform_pipelines={}, filtered_by_detection_paranoia={}",
        report.total_entries,
        report.enabled_entries,
        report.disabled_entries,
        report.compiled_rules,
        report.active_rules,
        report.transform_pipelines,
        report.filtered_by_paranoia
    );
    println!(
        "rule exclusions: configured={}, scoped={}, global={}",
        report.exclusions.configured, report.exclusions.scoped, report.exclusions.global
    );

    if !report.exclusions.disabled_rule_ids.is_empty() {
        println!(
            "disabled rule IDs: {}",
            report.exclusions.disabled_rule_ids.join(",")
        );
    }

    if !report.exclusions.disabled_categories.is_empty() {
        println!(
            "disabled categories: {}",
            report.exclusions.disabled_categories.join(",")
        );
    }

    for warning in &report.warnings {
        println!("warning: {warning}");
    }
}

pub fn print_owasp_coverage(report: &owasp::OwaspCoverageReport) {
    println!("OWASP coverage standard: {}", report.standard);
    for category in &report.categories {
        println!(
            "{} {}: status={}, request_rules={}",
            category.id, category.name, category.status, category.rule_count
        );

        if category.controls.is_empty() {
            println!("  active controls: none");
        } else {
            println!("  active controls:");
            for control in &category.controls {
                println!("    - {control}");
            }
        }

        if !category.planned_controls.is_empty() {
            println!("  planned controls:");
            for control in &category.planned_controls {
                println!("    - {control}");
            }
        }
    }
}

pub fn print_posture_report(report: &posture::PostureReport) {
    println!("posture checks enabled: {}", report.enabled);
    for check in &report.checks {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            check.status, check.id, check.owasp_category, check.name, check.message
        );
    }
}

pub fn print_security_report_summary(summary: &reports::SecurityReportSummary) {
    println!("security reports: {}", summary.reports.len());
    println!("findings: {}", summary.finding_count());

    for missing_path in &summary.missing_paths {
        println!("missing\t{}", missing_path.display());
    }

    for report in &summary.reports {
        println!(
            "report\t{}\tformat={}\tfindings={}",
            report.path.display(),
            report.format,
            report.findings.len()
        );
        for finding in &report.findings {
            println!(
                "finding\t{}\t{}\t{}\t{}\t{}",
                finding.id,
                finding.severity.as_deref().unwrap_or("unknown"),
                finding.package.as_deref().unwrap_or("unknown"),
                finding.owasp_category,
                finding.summary
            );
        }
    }
}

pub fn print_security_event_summary(summary: &event_store::SecurityEventSummary) {
    println!("security events: {}", summary.total_events);

    println!("actions:");
    if summary.actions.is_empty() {
        println!("  none\t0");
    } else {
        for action in &summary.actions {
            println!("  {}\t{}", action.name, action.count);
        }
    }

    println!("owasp categories:");
    if summary.owasp_categories.is_empty() {
        println!("  none\t0");
    } else {
        for category in &summary.owasp_categories {
            println!("  {}\t{}", category.name, category.count);
        }
    }

    println!("behavior actions:");
    if summary.behavior_actions.is_empty() {
        println!("  none\t0");
    } else {
        for action in &summary.behavior_actions {
            println!("  {}\t{}", action.name, action.count);
        }
    }
}

pub fn print_init(target: Option<InitTarget>) -> anyhow::Result<()> {
    match target {
        None => {
            println!("{}", include_str!("../../configs/saugra-waf.example.yml"));
        }
        Some(InitTarget::Nginx) => {
            println!(
                r#"location / {{
    proxy_pass http://127.0.0.1:8787;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}}"#
            );
        }
        Some(InitTarget::Apache) => {
            println!(
                r#"ProxyPass / http://127.0.0.1:8787/
ProxyPassReverse / http://127.0.0.1:8787/
RequestHeader set X-Forwarded-Proto "https""#
            );
        }
    }

    Ok(())
}

pub fn print_reset_result(state_name: &str, client_id: &str, removed: bool) {
    if removed {
        println!("reset {state_name} state for client {client_id}");
    } else {
        println!("no {state_name} state found for client {client_id}");
    }
}
