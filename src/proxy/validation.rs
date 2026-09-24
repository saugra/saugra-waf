use axum::http::{HeaderMap, Uri};
use serde::{Deserialize, Serialize};

use crate::{
    config::WafMode,
    decision::WafDecision,
    rules::{RuleMatch, RuleSeverity, RuleTarget},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputValidationConfig {
    pub max_path_length: usize,
    pub max_header_name_length: usize,
    pub max_header_value_length: usize,
    pub max_headers_count: usize,
    pub max_total_header_bytes: usize,
}

impl Default for InputValidationConfig {
    fn default() -> Self {
        Self {
            max_path_length: 8192,
            max_header_name_length: 1024,
            max_header_value_length: 8192,
            max_headers_count: 100,
            max_total_header_bytes: 65536,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    OversizedPath {
        length: usize,
        max: usize,
    },
    OversizedHeader {
        header: String,
        length: usize,
        max: usize,
    },
    TooManyHeaders {
        count: usize,
        max: usize,
    },
    OversizedTotalHeaders {
        length: usize,
        max: usize,
    },
    MalformedContentType {
        reason: String,
    },
}

impl ValidationError {
    pub fn to_rule_match(&self) -> RuleMatch {
        match self {
            ValidationError::OversizedPath { length, max } => RuleMatch {
                rule_id: "SAUGRA-VAL-001".to_string(),
                rule_name: "Oversized Request Path".to_string(),
                category: "input_validation".to_string(),
                severity: RuleSeverity::High,
                matched_target: RuleTarget::Path,
                paranoia_level: 1,
                explanation: format!(
                    "Request URI path length ({length}) exceeds maximum limit ({max})"
                ),
                owasp_category: Some("A03:2025-Injection".to_string()),
            },
            ValidationError::OversizedHeader {
                header,
                length,
                max,
            } => RuleMatch {
                rule_id: "SAUGRA-VAL-002".to_string(),
                rule_name: "Oversized Header Field".to_string(),
                category: "input_validation".to_string(),
                severity: RuleSeverity::High,
                matched_target: RuleTarget::Headers,
                paranoia_level: 1,
                explanation: format!(
                    "Header '{header}' size ({length}) exceeds maximum limit ({max})"
                ),
                owasp_category: Some("A03:2025-Injection".to_string()),
            },
            ValidationError::TooManyHeaders { count, max } => RuleMatch {
                rule_id: "SAUGRA-VAL-003".to_string(),
                rule_name: "Excessive Request Headers Count".to_string(),
                category: "input_validation".to_string(),
                severity: RuleSeverity::High,
                matched_target: RuleTarget::Headers,
                paranoia_level: 1,
                explanation: format!(
                    "Request header count ({count}) exceeds maximum limit ({max})"
                ),
                owasp_category: Some("A05:2025-Security-Misconfiguration".to_string()),
            },
            ValidationError::OversizedTotalHeaders { length, max } => RuleMatch {
                rule_id: "SAUGRA-VAL-004".to_string(),
                rule_name: "Oversized Total Headers Size".to_string(),
                category: "input_validation".to_string(),
                severity: RuleSeverity::High,
                matched_target: RuleTarget::Headers,
                paranoia_level: 1,
                explanation: format!("Total header bytes ({length}) exceeds maximum limit ({max})"),
                owasp_category: Some("A05:2025-Security-Misconfiguration".to_string()),
            },
            ValidationError::MalformedContentType { reason } => RuleMatch {
                rule_id: "SAUGRA-VAL-005".to_string(),
                rule_name: "Malformed Content-Type Header".to_string(),
                category: "input_validation".to_string(),
                severity: RuleSeverity::High,
                matched_target: RuleTarget::Headers,
                paranoia_level: 1,
                explanation: format!("Content-Type header is malformed: {reason}"),
                owasp_category: Some("A03:2025-Injection".to_string()),
            },
        }
    }
}

pub fn validate_request_bounds(
    uri: &Uri,
    headers: &HeaderMap,
    config: &InputValidationConfig,
) -> Result<(), ValidationError> {
    let path = uri.path();
    if path.len() > config.max_path_length {
        return Err(ValidationError::OversizedPath {
            length: path.len(),
            max: config.max_path_length,
        });
    }

    if headers.len() > config.max_headers_count {
        return Err(ValidationError::TooManyHeaders {
            count: headers.len(),
            max: config.max_headers_count,
        });
    }

    let mut total_bytes = 0usize;
    for (name, value) in headers.iter() {
        let name_str = name.as_str();
        if name_str.len() > config.max_header_name_length {
            return Err(ValidationError::OversizedHeader {
                header: name_str.to_string(),
                length: name_str.len(),
                max: config.max_header_name_length,
            });
        }

        let val_bytes = value.as_bytes();
        if val_bytes.len() > config.max_header_value_length {
            return Err(ValidationError::OversizedHeader {
                header: name_str.to_string(),
                length: val_bytes.len(),
                max: config.max_header_value_length,
            });
        }

        total_bytes += name_str.len() + val_bytes.len();
        if total_bytes > config.max_total_header_bytes {
            return Err(ValidationError::OversizedTotalHeaders {
                length: total_bytes,
                max: config.max_total_header_bytes,
            });
        }
    }

    if let Some(content_type) = headers.get(axum::http::header::CONTENT_TYPE) {
        if let Ok(val_str) = content_type.to_str() {
            if val_str.contains('\0') || val_str.contains('\r') || val_str.contains('\n') {
                return Err(ValidationError::MalformedContentType {
                    reason: "content-type contains control characters".to_string(),
                });
            }
        } else {
            return Err(ValidationError::MalformedContentType {
                reason: "content-type header contains non-ASCII bytes".to_string(),
            });
        }
    }

    Ok(())
}

pub fn create_validation_decision(
    request_id: String,
    mode: WafMode,
    err: ValidationError,
    inbound_anomaly_threshold: u16,
) -> WafDecision {
    let rule_match = err.to_rule_match();
    WafDecision::from_matches(
        request_id,
        mode,
        vec![rule_match],
        inbound_anomaly_threshold,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::WafAction;
    use axum::http::HeaderValue;

    #[test]
    fn validates_valid_request() {
        let uri: Uri = "/api/v1/resource".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", HeaderValue::from_static("application/json"));
        headers.insert("User-Agent", HeaderValue::from_static("TestClient/1.0"));

        let config = InputValidationConfig::default();
        assert!(validate_request_bounds(&uri, &headers, &config).is_ok());
    }

    #[test]
    fn rejects_oversized_path() {
        let long_path = format!("/{}", "a".repeat(100));
        let uri: Uri = long_path.parse().unwrap();
        let headers = HeaderMap::new();

        let config = InputValidationConfig {
            max_path_length: 50,
            ..Default::default()
        };

        let err = validate_request_bounds(&uri, &headers, &config).unwrap_err();
        assert_eq!(
            err,
            ValidationError::OversizedPath {
                length: 101,
                max: 50
            }
        );
        let rule_match = err.to_rule_match();
        assert_eq!(rule_match.rule_id, "SAUGRA-VAL-001");
    }

    #[test]
    fn rejects_too_many_headers() {
        let uri: Uri = "/".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("h1", HeaderValue::from_static("v1"));
        headers.insert("h2", HeaderValue::from_static("v2"));
        headers.insert("h3", HeaderValue::from_static("v3"));

        let config = InputValidationConfig {
            max_headers_count: 2,
            ..Default::default()
        };

        let err = validate_request_bounds(&uri, &headers, &config).unwrap_err();
        assert_eq!(err, ValidationError::TooManyHeaders { count: 3, max: 2 });
        let rule_match = err.to_rule_match();
        assert_eq!(rule_match.rule_id, "SAUGRA-VAL-003");
    }

    #[test]
    fn rejects_oversized_header_value() {
        let uri: Uri = "/".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-large", HeaderValue::from_str(&"x".repeat(100)).unwrap());

        let config = InputValidationConfig {
            max_header_value_length: 50,
            ..Default::default()
        };

        let err = validate_request_bounds(&uri, &headers, &config).unwrap_err();
        assert_eq!(
            err,
            ValidationError::OversizedHeader {
                header: "x-large".to_string(),
                length: 100,
                max: 50
            }
        );
        let rule_match = err.to_rule_match();
        assert_eq!(rule_match.rule_id, "SAUGRA-VAL-002");
    }

    #[test]
    fn rejects_malformed_content_type() {
        let uri: Uri = "/".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "Content-Type",
            HeaderValue::from_bytes(b"application/json; charset=\x80").unwrap(),
        );

        let config = InputValidationConfig::default();
        let err = validate_request_bounds(&uri, &headers, &config).unwrap_err();
        assert_eq!(
            err,
            ValidationError::MalformedContentType {
                reason: "content-type header contains non-ASCII bytes".to_string()
            }
        );
        let rule_match = err.to_rule_match();
        assert_eq!(rule_match.rule_id, "SAUGRA-VAL-005");
    }

    #[test]
    fn validation_decision_creation() {
        let err = ValidationError::OversizedPath {
            length: 9000,
            max: 8192,
        };
        let decision = create_validation_decision("req-123".to_string(), WafMode::Strict, err, 5);
        assert_eq!(decision.action, WafAction::Block);
        assert_eq!(decision.matched_rules.len(), 1);
        assert_eq!(decision.matched_rules[0].rule_id, "SAUGRA-VAL-001");
    }

    #[test]
    fn rejects_oversized_header_name() {
        let uri: Uri = "/".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::HeaderName::from_bytes(b"x-very-long-custom-header-name").unwrap(),
            HeaderValue::from_static("val"),
        );

        let config = InputValidationConfig {
            max_header_name_length: 10,
            ..Default::default()
        };

        let err = validate_request_bounds(&uri, &headers, &config).unwrap_err();
        assert_eq!(
            err,
            ValidationError::OversizedHeader {
                header: "x-very-long-custom-header-name".to_string(),
                length: 30,
                max: 10
            }
        );
    }

    #[test]
    fn rejects_oversized_total_headers() {
        let uri: Uri = "/".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-hdr-1", HeaderValue::from_static("value-1"));
        headers.insert("x-hdr-2", HeaderValue::from_static("value-2"));

        let config = InputValidationConfig {
            max_total_header_bytes: 15,
            ..Default::default()
        };

        let err = validate_request_bounds(&uri, &headers, &config).unwrap_err();
        assert_eq!(
            err,
            ValidationError::OversizedTotalHeaders {
                length: 28,
                max: 15
            }
        );
        let rule_match = err.to_rule_match();
        assert_eq!(rule_match.rule_id, "SAUGRA-VAL-004");
    }
}
