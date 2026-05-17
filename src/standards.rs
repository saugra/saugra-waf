use std::{fs, path::Path};

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StandardCatalogError {
    #[error("failed to read OWASP standard catalog {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("OWASP standard catalog {path} is not valid YAML: {source}")]
    Yaml {
        path: String,
        source: serde_yaml::Error,
    },
    #[error("OWASP standard catalog must include at least one category")]
    EmptyCategories,
    #[error("OWASP standard catalog category entries must include non-empty id and name")]
    InvalidCategory,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct StandardCatalog {
    pub standard: String,
    pub categories: Vec<StandardCategory>,
    #[serde(default)]
    pub runtime_controls: RuntimeControls,
    #[serde(default)]
    pub posture_checks: PostureCheckCatalog,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct StandardCategory {
    pub id: String,
    pub name: String,
    pub baseline_control: String,
    #[serde(default)]
    pub planned_controls: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct RuntimeControls {
    #[serde(default)]
    pub rate_limiting: Option<RateLimitControlMapping>,
    #[serde(default)]
    pub event_log: Option<ControlMapping>,
    #[serde(default)]
    pub body_limit: Option<ControlMapping>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RateLimitControlMapping {
    #[serde(default)]
    pub categories: Vec<String>,
    pub memory_template: String,
    pub redis_template: String,
    pub route_template: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ControlMapping {
    #[serde(default)]
    pub categories: Vec<String>,
    pub template: String,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct PostureCheckCatalog {
    #[serde(default)]
    pub disabled: Option<DisabledPostureMapping>,
    #[serde(default)]
    pub expected_external_scheme: Option<ExpectedSchemeMapping>,
    #[serde(default)]
    pub allowed_methods: Option<AllowedMethodsMapping>,
    #[serde(default)]
    pub security_headers: Option<BooleanPostureMapping>,
    #[serde(default)]
    pub secure_cookies: Option<BooleanPostureMapping>,
    #[serde(default)]
    pub body_limit: Option<BodyLimitMapping>,
    #[serde(default)]
    pub dependency_report: Option<DependencyReportMapping>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct DisabledPostureMapping {
    pub check_id: String,
    pub name: String,
    pub category: String,
    pub disabled_message: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ExpectedSchemeMapping {
    pub check_id: String,
    pub name: String,
    pub category: String,
    pub control_template: String,
    pub pass_message: String,
    pub warn_message: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AllowedMethodsMapping {
    pub check_id: String,
    pub name: String,
    pub category: String,
    pub control_template: String,
    pub pass_message: String,
    pub fail_message: String,
    #[serde(default)]
    pub risky_methods: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct BooleanPostureMapping {
    pub check_id: String,
    pub name: String,
    pub category: String,
    pub control_template: String,
    pub pass_message: String,
    pub warn_message: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct BodyLimitMapping {
    pub check_id: String,
    pub name: String,
    pub category: String,
    pub pass_message: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct DependencyReportMapping {
    pub check_id: String,
    pub name: String,
    pub category: String,
    pub control_template: String,
    pub pass_message: String,
    pub missing_message: String,
    pub not_configured_message: String,
}

pub fn load_catalog(path: &Path) -> Result<StandardCatalog, StandardCatalogError> {
    let path_display = path.display().to_string();
    let contents = fs::read_to_string(path).map_err(|source| StandardCatalogError::Io {
        path: path_display.clone(),
        source,
    })?;

    parse_catalog(&contents, &path_display)
}

pub fn load_catalog_or_builtin(path: &Path) -> Result<StandardCatalog, StandardCatalogError> {
    match load_catalog(path) {
        Ok(catalog) => Ok(catalog),
        Err(StandardCatalogError::Io { .. })
            if path == Path::new("configs/standards/owasp-top-10-2025.yml") =>
        {
            parse_catalog(
                include_str!("../configs/standards/owasp-top-10-2025.yml"),
                "<embedded owasp-top-10-2025 catalog>",
            )
        }
        Err(error) => Err(error),
    }
}

fn parse_catalog(
    contents: &str,
    source_name: &str,
) -> Result<StandardCatalog, StandardCatalogError> {
    let catalog: StandardCatalog =
        serde_yaml::from_str(contents).map_err(|source| StandardCatalogError::Yaml {
            path: source_name.to_string(),
            source,
        })?;
    validate_catalog(catalog)
}

fn validate_catalog(catalog: StandardCatalog) -> Result<StandardCatalog, StandardCatalogError> {
    if catalog.categories.is_empty() {
        return Err(StandardCatalogError::EmptyCategories);
    }

    if catalog
        .categories
        .iter()
        .any(|category| category.id.trim().is_empty() || category.name.trim().is_empty())
    {
        return Err(StandardCatalogError::InvalidCategory);
    }

    Ok(catalog)
}

pub fn render_template(template: &str, values: &[(&str, String)]) -> String {
    let mut rendered = template.to_string();
    for (name, value) in values {
        rendered = rendered.replace(&format!("{{{name}}}"), value);
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_builtin_owasp_2025_catalog() {
        let catalog =
            load_catalog_or_builtin(Path::new("configs/standards/owasp-top-10-2025.yml")).unwrap();

        assert_eq!(catalog.standard, "owasp-top-10:2025");
        assert_eq!(catalog.categories.len(), 10);
        assert!(catalog.posture_checks.allowed_methods.is_some());
    }

    #[test]
    fn renders_templates_with_named_values() {
        let rendered = render_template(
            "rate limit {requests_per_minute}/{burst}",
            &[
                ("requests_per_minute", "120".to_string()),
                ("burst", "30".to_string()),
            ],
        );

        assert_eq!(rendered, "rate limit 120/30");
    }
}
