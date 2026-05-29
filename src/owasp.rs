use std::collections::BTreeMap;

use crate::{
    config::{RateLimitBackend, SaugraConfig},
    reports::SecurityReportSummary,
    rules::RuleSet,
    standards::{render_template, StandardCatalog},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwaspCoverageReport {
    pub standard: String,
    pub categories: Vec<OwaspCategoryCoverage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwaspCategoryCoverage {
    pub id: String,
    pub name: String,
    pub status: CoverageStatus,
    pub rule_count: usize,
    pub controls: Vec<String>,
    pub planned_controls: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageStatus {
    Active,
    Partial,
    Planned,
}

impl std::fmt::Display for CoverageStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Active => "active",
            Self::Partial => "partial",
            Self::Planned => "planned",
        };
        formatter.write_str(value)
    }
}

pub fn coverage_report(
    config: &SaugraConfig,
    rule_set: &RuleSet,
    catalog: &StandardCatalog,
    security_reports: Option<&SecurityReportSummary>,
) -> OwaspCoverageReport {
    let mut rule_counts = BTreeMap::<String, usize>::new();

    for rule in rule_set.rules() {
        if let Some(category) = &rule.owasp_category {
            if let Some((id, _name)) = category.split_once('-') {
                *rule_counts.entry(id.to_string()).or_default() += 1;
            }
        }
    }

    let categories = catalog
        .categories
        .iter()
        .map(|category| {
            let rule_count = rule_counts.get(&category.id).copied().unwrap_or(0);
            let mut controls = Vec::new();

            if rule_count > 0 {
                controls.push(category.baseline_control.clone());
            }

            controls.extend(config_controls(
                config,
                &category.id,
                catalog,
                security_reports,
            ));

            let status = coverage_status(rule_count, &controls, &category.planned_controls);

            OwaspCategoryCoverage {
                id: category.id.clone(),
                name: category.name.clone(),
                status,
                rule_count,
                controls,
                planned_controls: category.planned_controls.clone(),
            }
        })
        .collect();

    OwaspCoverageReport {
        standard: catalog.standard.clone(),
        categories,
    }
}

fn config_controls(
    config: &SaugraConfig,
    category_id: &str,
    catalog: &StandardCatalog,
    security_reports: Option<&SecurityReportSummary>,
) -> Vec<String> {
    let mut controls = Vec::new();

    if let Some(mapping) = &catalog.runtime_controls.rate_limiting {
        if mapping
            .categories
            .iter()
            .any(|category| category == category_id)
            && config.security.enable_rate_limiting
        {
            let template = match config.rate_limit.backend {
                RateLimitBackend::Memory => &mapping.memory_template,
                RateLimitBackend::Redis => &mapping.redis_template,
            };
            controls.push(render_template(
                template,
                &[
                    (
                        "requests_per_minute",
                        config.rate_limit.requests_per_minute.to_string(),
                    ),
                    ("burst", config.rate_limit.burst.to_string()),
                ],
            ));

            if !config.rate_limit.routes.is_empty() {
                controls.push(render_template(
                    &mapping.route_template,
                    &[("route_count", config.rate_limit.routes.len().to_string())],
                ));
            }
        }
    }

    if let Some(mapping) = &catalog.runtime_controls.event_log {
        if mapping
            .categories
            .iter()
            .any(|category| category == category_id)
        {
            controls.push(render_template(
                &mapping.template,
                &[
                    ("event_log_path", config.logging.event_log_path.clone()),
                    (
                        "event_log_max_files",
                        config.logging.event_log_max_files.to_string(),
                    ),
                ],
            ));
        }
    }

    if let Some(mapping) = &catalog.runtime_controls.body_limit {
        if mapping
            .categories
            .iter()
            .any(|category| category == category_id)
        {
            controls.push(render_template(
                &mapping.template,
                &[("max_body_size", config.security.max_body_size.clone())],
            ));
        }
    }

    if config.posture.enabled {
        controls.extend(posture_controls(config, category_id, catalog));
    }

    if let Some(security_reports) = security_reports {
        let finding_count = security_reports.finding_count_for_category(category_id);
        if finding_count > 0 {
            controls.push(format!(
                "{finding_count} normalized local security report finding(s)"
            ));
        }
    }

    controls
}

fn posture_controls(
    config: &SaugraConfig,
    category_id: &str,
    catalog: &StandardCatalog,
) -> Vec<String> {
    let mut controls = Vec::new();
    let checks = &catalog.posture_checks;

    if let Some(mapping) = &checks.security_headers {
        if mapping.category_id() == category_id && config.posture.require_security_headers {
            controls.push(mapping.control_template.clone());
        }
    }

    if let Some(mapping) = &checks.dependency_report {
        if mapping.category_id() == category_id && config.posture.dependency_report_path.is_some() {
            controls.push(mapping.control_template.clone());
        }
    }

    if let Some(mapping) = &checks.expected_external_scheme {
        if mapping.category_id() == category_id {
            controls.push(render_template(
                &mapping.control_template,
                &[(
                    "expected_external_scheme",
                    config.posture.expected_external_scheme.clone(),
                )],
            ));
        }
    }

    if let Some(mapping) = &checks.secure_cookies {
        if mapping.category_id() == category_id && config.posture.require_secure_cookies {
            controls.push(mapping.control_template.clone());
        }
    }

    if let Some(mapping) = &checks.allowed_methods {
        if mapping.category_id() == category_id && !config.posture.allowed_methods.is_empty() {
            controls.push(render_template(
                &mapping.control_template,
                &[("allowed_methods", config.posture.allowed_methods.join(","))],
            ));
        }
    }

    controls
}

trait CategoryId {
    fn category_id(&self) -> &str;
}

impl CategoryId for crate::standards::BooleanPostureMapping {
    fn category_id(&self) -> &str {
        self.category
            .split_once('-')
            .map(|(id, _)| id)
            .unwrap_or(&self.category)
    }
}

impl CategoryId for crate::standards::DependencyReportMapping {
    fn category_id(&self) -> &str {
        self.category
            .split_once('-')
            .map(|(id, _)| id)
            .unwrap_or(&self.category)
    }
}

impl CategoryId for crate::standards::ExpectedSchemeMapping {
    fn category_id(&self) -> &str {
        self.category
            .split_once('-')
            .map(|(id, _)| id)
            .unwrap_or(&self.category)
    }
}

impl CategoryId for crate::standards::AllowedMethodsMapping {
    fn category_id(&self) -> &str {
        self.category
            .split_once('-')
            .map(|(id, _)| id)
            .unwrap_or(&self.category)
    }
}

fn coverage_status(
    rule_count: usize,
    controls: &[String],
    planned_controls: &[String],
) -> CoverageStatus {
    if rule_count > 0 && controls.len() > 1 {
        CoverageStatus::Active
    } else if rule_count > 0 || !controls.is_empty() {
        CoverageStatus::Partial
    } else if !planned_controls.is_empty() {
        CoverageStatus::Planned
    } else {
        CoverageStatus::Partial
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{
            AiConfig, LoggingConfig, RateLimitBackend, RateLimitConfig, RuleSettings, SaugraConfig,
            SecurityConfig, ServerConfig, UpstreamConfig, WafMode,
        },
        rules, standards,
    };
    use std::path::Path;

    #[test]
    fn reports_all_catalog_categories() {
        let config = test_config();
        let catalog = standards::load_catalog_or_builtin(Path::new(
            "configs/standards/owasp-top-10-2025.yml",
        ))
        .unwrap();
        let rule_set = rules::load_rule_set(&config.rules).unwrap();
        let report = coverage_report(&config, &rule_set, &catalog, None);

        assert_eq!(report.standard, "owasp-top-10:2025");
        assert_eq!(report.categories.len(), catalog.categories.len());
        assert!(report
            .categories
            .iter()
            .all(|category| category.rule_count > 0));
    }

    #[test]
    fn reports_runtime_controls_from_catalog_templates() {
        let config = test_config();
        let catalog = standards::load_catalog_or_builtin(Path::new(
            "configs/standards/owasp-top-10-2025.yml",
        ))
        .unwrap();
        let rule_set = rules::load_rule_set(&config.rules).unwrap();
        let report = coverage_report(&config, &rule_set, &catalog, None);

        let insecure_design = report
            .categories
            .iter()
            .find(|category| category.id == "A06:2025")
            .unwrap();
        assert!(insecure_design
            .controls
            .iter()
            .any(|control| control.contains("rate limiting enabled")));

        let logging = report
            .categories
            .iter()
            .find(|category| category.id == "A09:2025")
            .unwrap();
        assert!(logging
            .controls
            .iter()
            .any(|control| control.contains("durable local security event log")));

        let exceptional_conditions = report
            .categories
            .iter()
            .find(|category| category.id == "A10:2025")
            .unwrap();
        assert!(exceptional_conditions
            .controls
            .iter()
            .any(|control| control.contains("request body inspection limit")));
    }

    fn test_config() -> SaugraConfig {
        SaugraConfig {
            server: ServerConfig {
                listen: "127.0.0.1:0".to_string(),
                mode: WafMode::Monitor,
            },
            upstreams: vec![UpstreamConfig {
                name: "app".to_string(),
                host: "example.com".to_string(),
                target: "http://127.0.0.1:8000".to_string(),
            }],
            routes: Vec::new(),
            security: SecurityConfig::default(),
            forwarded_headers: Default::default(),
            rate_limit: RateLimitConfig {
                backend: RateLimitBackend::Redis,
                redis_url: Some("redis://127.0.0.1:6379".to_string()),
                redis_password: None,
                requests_per_minute: 120,
                burst: 30,
                routes: vec![],
            },
            rules: RuleSettings::default(),
            behavior: Default::default(),
            bot_protection: Default::default(),
            runtime_policy: Default::default(),
            ai: AiConfig::default(),
            logging: LoggingConfig {
                event_log_path: "/var/log/saugra-waf/saugra-waf-events.jsonl".to_string(),
                event_log_max_files: 30,
                ..LoggingConfig::default()
            },
            websocket: Default::default(),
            posture: Default::default(),
            reports: Default::default(),
            standards: Default::default(),
            security_summary: Default::default(),
            storage_cleanup: Default::default(),
        }
    }
}
