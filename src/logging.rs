use anyhow::Context;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::config::LoggingConfig;

pub use crate::error_tracking::ERROR_TRACKING_DSN_ENV;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorTrackingSink {
    pub dsn: Option<String>,
    pub enabled: bool,
}

impl ErrorTrackingSink {
    pub fn from_env() -> Self {
        let tracker = crate::error_tracking::ErrorTracker::from_env();
        Self {
            enabled: tracker.is_enabled(),
            dsn: tracker.dsn,
        }
    }

    pub fn record_error(&self, message: &str) {
        let tracker = crate::error_tracking::ErrorTracker::new(self.dsn.clone());
        tracker.record_error(message);
    }
}

pub fn format_panic_payload(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unspecified panic payload".to_string()
    }
}

pub fn setup_panic_hook(sink: Option<ErrorTrackingSink>) {
    let sink = sink.unwrap_or_else(ErrorTrackingSink::from_env);
    std::panic::set_hook(Box::new(move |info| {
        let location = info
            .location()
            .map(|loc| format!("{}:{}:{}", loc.file(), loc.line(), loc.column()))
            .unwrap_or_else(|| "unknown location".to_string());
        let payload = format_panic_payload(info.payload());

        error!(%location, %payload, "uncaught process panic recorded in Saugra WAF");
        sink.record_error(&format!("panic at {location}: {payload}"));
    }));
}

pub fn init(config: &LoggingConfig) -> anyhow::Result<()> {
    let filter = EnvFilter::try_new(&config.level)
        .or_else(|_| EnvFilter::try_new("info"))
        .context("failed to configure log filter")?;

    let subscriber = tracing_subscriber::fmt().with_env_filter(filter);

    if config.format == "json" {
        let _ = subscriber.json().try_init();
    } else {
        let _ = subscriber.try_init();
    }

    let sink = ErrorTrackingSink::from_env();
    if sink.enabled {
        info!(dsn = ?sink.dsn, "error tracking DSN sink enabled for production robustness");
    }
    setup_panic_hook(Some(sink));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_logging_config_level_parsing() {
        let config = LoggingConfig {
            level: "debug".to_string(),
            format: "json".to_string(),
            ..Default::default()
        };
        assert_eq!(config.level, "debug");
        assert_eq!(config.format, "json");
    }

    #[test]
    fn error_tracking_sink_is_noop_when_dsn_absent() {
        let _guard = crate::error_tracking::ENV_LOCK.lock().unwrap();
        std::env::remove_var(ERROR_TRACKING_DSN_ENV);
        let sink = ErrorTrackingSink::from_env();
        assert!(!sink.enabled);
        assert_eq!(sink.dsn, None);
        sink.record_error("test error event");
    }

    #[test]
    fn error_tracking_sink_captures_dsn_from_env() {
        let _guard = crate::error_tracking::ENV_LOCK.lock().unwrap();
        std::env::set_var(ERROR_TRACKING_DSN_ENV, "https://key@sentry.example.com/1");
        let sink = ErrorTrackingSink::from_env();
        assert!(sink.enabled);
        assert_eq!(
            sink.dsn.as_deref(),
            Some("https://key@sentry.example.com/1")
        );
        sink.record_error("test error event");
        std::env::remove_var(ERROR_TRACKING_DSN_ENV);
    }

    #[test]
    fn format_panic_payload_handles_str_string_and_unknown() {
        let str_payload: &(dyn std::any::Any + Send) = &"slice error";
        assert_eq!(format_panic_payload(str_payload), "slice error");

        let string_payload: &(dyn std::any::Any + Send) = &"owned string error".to_string();
        assert_eq!(format_panic_payload(string_payload), "owned string error");

        let int_payload: &(dyn std::any::Any + Send) = &42i32;
        assert_eq!(
            format_panic_payload(int_payload),
            "unspecified panic payload"
        );
    }

    #[test]
    fn setup_panic_hook_registers_without_panic() {
        setup_panic_hook(None);
        let sink = ErrorTrackingSink {
            dsn: Some("https://example.com/dsn".to_string()),
            enabled: true,
        };
        setup_panic_hook(Some(sink));
    }

    #[test]
    fn init_configures_logging_and_sink() {
        let _guard = crate::error_tracking::ENV_LOCK.lock().unwrap();
        std::env::set_var(ERROR_TRACKING_DSN_ENV, "https://key@sentry.example.com/1");
        let json_config = LoggingConfig {
            level: "info".to_string(),
            format: "json".to_string(),
            ..Default::default()
        };
        assert!(init(&json_config).is_ok());

        let text_config = LoggingConfig {
            level: "invalid_level_falls_back".to_string(),
            format: "text".to_string(),
            ..Default::default()
        };
        assert!(init(&text_config).is_ok());
        std::env::remove_var(ERROR_TRACKING_DSN_ENV);
    }
}
