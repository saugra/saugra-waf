use crate::{
    config::SaugraConfig,
    reports::SecurityReportSummary,
    standards::{render_template, StandardCatalog},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostureReport {
    pub enabled: bool,
    pub checks: Vec<PostureCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostureCheck {
    pub id: String,
    pub name: String,
    pub status: PostureStatus,
    pub owasp_category: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostureStatus {
    Pass,
    Warn,
    Fail,
}

impl std::fmt::Display for PostureStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
        };
        formatter.write_str(value)
    }
}

pub fn check(config: &SaugraConfig, catalog: &StandardCatalog) -> PostureReport {
    check_with_reports(config, catalog, None)
}

pub fn check_with_reports(
    config: &SaugraConfig,
    catalog: &StandardCatalog,
    security_reports: Option<&SecurityReportSummary>,
) -> PostureReport {
    let mappings = &catalog.posture_checks;

    if !config.posture.enabled {
        let check = mappings
            .disabled
            .as_ref()
            .map(|mapping| PostureCheck {
                id: mapping.check_id.clone(),
                name: mapping.name.clone(),
                status: PostureStatus::Warn,
                owasp_category: mapping.category.clone(),
                message: mapping.disabled_message.clone(),
            })
            .unwrap_or_else(|| PostureCheck {
                id: "POSTURE-ENABLED-001".to_string(),
                name: "Posture Checks Enabled".to_string(),
                status: PostureStatus::Warn,
                owasp_category: "unknown".to_string(),
                message: "posture checks are disabled in configuration".to_string(),
            });

        return PostureReport {
            enabled: false,
            checks: vec![check],
        };
    }

    let mut checks = Vec::new();

    if let Some(mapping) = &mappings.expected_external_scheme {
        checks.push(expected_external_scheme_check(config, mapping));
    }
    if let Some(mapping) = &mappings.allowed_methods {
        checks.push(allowed_methods_check(config, mapping));
    }
    if let Some(mapping) = &mappings.security_headers {
        checks.push(boolean_posture_check(
            config.posture.require_security_headers,
            &mapping.check_id,
            &mapping.name,
            &mapping.category,
            &mapping.pass_message,
            &mapping.warn_message,
        ));
    }
    if let Some(mapping) = &mappings.secure_cookies {
        checks.push(boolean_posture_check(
            config.posture.require_secure_cookies,
            &mapping.check_id,
            &mapping.name,
            &mapping.category,
            &mapping.pass_message,
            &mapping.warn_message,
        ));
    }
    if let Some(mapping) = &mappings.body_limit {
        checks.push(PostureCheck {
            id: mapping.check_id.clone(),
            name: mapping.name.clone(),
            status: PostureStatus::Pass,
            owasp_category: mapping.category.clone(),
            message: render_template(
                &mapping.pass_message,
                &[("max_body_size", config.security.max_body_size.clone())],
            ),
        });
    }
    if let Some(mapping) = &mappings.dependency_report {
        checks.push(dependency_report_check(config, mapping, security_reports));
    }

    PostureReport {
        enabled: true,
        checks,
    }
}

fn expected_external_scheme_check(
    config: &SaugraConfig,
    mapping: &crate::standards::ExpectedSchemeMapping,
) -> PostureCheck {
    let scheme = config.posture.expected_external_scheme.trim().to_string();
    let status = if scheme == "https" {
        PostureStatus::Pass
    } else {
        PostureStatus::Warn
    };
    let template = if status == PostureStatus::Pass {
        &mapping.pass_message
    } else {
        &mapping.warn_message
    };

    PostureCheck {
        id: mapping.check_id.clone(),
        name: mapping.name.clone(),
        status,
        owasp_category: mapping.category.clone(),
        message: render_template(template, &[("expected_external_scheme", scheme)]),
    }
}

fn allowed_methods_check(
    config: &SaugraConfig,
    mapping: &crate::standards::AllowedMethodsMapping,
) -> PostureCheck {
    let risky_methods = config
        .posture
        .allowed_methods
        .iter()
        .filter(|method| {
            let method = method.trim().to_ascii_uppercase();
            mapping
                .risky_methods
                .iter()
                .any(|risky_method| risky_method.eq_ignore_ascii_case(&method))
        })
        .cloned()
        .collect::<Vec<_>>();

    let status = if risky_methods.is_empty() {
        PostureStatus::Pass
    } else {
        PostureStatus::Fail
    };
    let message = if risky_methods.is_empty() {
        render_template(
            &mapping.pass_message,
            &[("allowed_methods", config.posture.allowed_methods.join(","))],
        )
    } else {
        render_template(
            &mapping.fail_message,
            &[("risky_methods", risky_methods.join(","))],
        )
    };

    PostureCheck {
        id: mapping.check_id.clone(),
        name: mapping.name.clone(),
        status,
        owasp_category: mapping.category.clone(),
        message,
    }
}

fn boolean_posture_check(
    enabled: bool,
    check_id: &str,
    name: &str,
    category: &str,
    pass_message: &str,
    warn_message: &str,
) -> PostureCheck {
    PostureCheck {
        id: check_id.to_string(),
        name: name.to_string(),
        status: if enabled {
            PostureStatus::Pass
        } else {
            PostureStatus::Warn
        },
        owasp_category: category.to_string(),
        message: if enabled {
            pass_message.to_string()
        } else {
            warn_message.to_string()
        },
    }
}

fn dependency_report_check(
    config: &SaugraConfig,
    mapping: &crate::standards::DependencyReportMapping,
    security_reports: Option<&SecurityReportSummary>,
) -> PostureCheck {
    if let Some(security_reports) = security_reports {
        if security_reports.finding_count() > 0 {
            return PostureCheck {
                id: mapping.check_id.clone(),
                name: mapping.name.clone(),
                status: PostureStatus::Pass,
                owasp_category: mapping.category.clone(),
                message: format!(
                    "{} normalized finding(s) loaded from {} report(s)",
                    security_reports.finding_count(),
                    security_reports.reports.len()
                ),
            };
        }
    }

    match config.posture.dependency_report_path.as_deref() {
        Some(path) if path.exists() => PostureCheck {
            id: mapping.check_id.clone(),
            name: mapping.name.clone(),
            status: PostureStatus::Pass,
            owasp_category: mapping.category.clone(),
            message: render_template(
                &mapping.pass_message,
                &[("dependency_report_path", path.display().to_string())],
            ),
        },
        Some(path) => PostureCheck {
            id: mapping.check_id.clone(),
            name: mapping.name.clone(),
            status: PostureStatus::Warn,
            owasp_category: mapping.category.clone(),
            message: render_template(
                &mapping.missing_message,
                &[("dependency_report_path", path.display().to_string())],
            ),
        },
        None => PostureCheck {
            id: mapping.check_id.clone(),
            name: mapping.name.clone(),
            status: PostureStatus::Warn,
            owasp_category: mapping.category.clone(),
            message: mapping.not_configured_message.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{
            AiConfig, LoggingConfig, PostureConfig, RateLimitConfig, RuleSettings, SaugraConfig,
            SecurityConfig, ServerConfig, UpstreamConfig, WafMode,
        },
        standards,
    };
    use std::path::Path;

    #[test]
    fn reports_passes_for_safe_local_posture_defaults() {
        let catalog = test_catalog();
        let report = check(&test_config(PostureConfig::default()), &catalog);

        assert!(report.enabled);
        assert!(report
            .checks
            .iter()
            .any(|check| check.id == "POSTURE-CRYPTO-001" && check.status == PostureStatus::Pass));
        assert!(report
            .checks
            .iter()
            .any(|check| check.id == "POSTURE-DESIGN-001" && check.status == PostureStatus::Pass));
    }

    #[test]
    fn warns_when_posture_checks_are_disabled() {
        let catalog = test_catalog();
        let report = check(
            &test_config(PostureConfig {
                enabled: false,
                ..PostureConfig::default()
            }),
            &catalog,
        );

        assert!(!report.enabled);
        assert_eq!(report.checks[0].status, PostureStatus::Warn);
    }

    #[test]
    fn fails_when_risky_methods_are_allowed() {
        let catalog = test_catalog();
        let report = check(
            &test_config(PostureConfig {
                allowed_methods: vec!["GET".to_string(), "TRACE".to_string()],
                ..PostureConfig::default()
            }),
            &catalog,
        );

        let method_check = report
            .checks
            .iter()
            .find(|check| check.id == "POSTURE-DESIGN-001")
            .unwrap();
        assert_eq!(method_check.status, PostureStatus::Fail);
    }

    fn test_catalog() -> StandardCatalog {
        standards::load_catalog_or_builtin(Path::new("configs/standards/owasp-top-10-2025.yml"))
            .unwrap()
    }

    fn test_config(posture: PostureConfig) -> SaugraConfig {
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
            rate_limit: RateLimitConfig::default(),
            rules: RuleSettings::default(),
            ai: AiConfig::default(),
            logging: LoggingConfig::default(),
            websocket: Default::default(),
            posture,
            reports: Default::default(),
            standards: Default::default(),
        }
    }
}
