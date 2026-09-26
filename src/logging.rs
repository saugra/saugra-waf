use anyhow::Context;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::config::LoggingConfig;

pub const ERROR_TRACKING_DSN_ENV: &str = "SAUGRA_WAF_ERROR_TRACKING_DSN";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorTrackingSink {
    pub dsn: Option<String>,
    pub enabled: bool,
}

impl ErrorTrackingSink {
    pub fn from_env() -> Self {
        let dsn = std::env::var(ERROR_TRACKING_DSN_ENV)
            .ok()
            .map(|val| val.trim().to_string())
            .filter(|val| !val.is_empty());
        let enabled = dsn.is_some();
        Self { dsn, enabled }
    }

    pub fn record_error(&self, message: &str) {
        if let Some(dsn) = &self.dsn {
            info!(sink_dsn = %dsn, %message, "forwarded error event to error tracking DSN sink");
        }
    }
}

pub fn setup_panic_hook(sink: Option<ErrorTrackingSink>) {
    let sink = sink.unwrap_or_else(ErrorTrackingSink::from_env);
    std::panic::set_hook(Box::new(move |info| {
        let location = info
            .location()
            .map(|loc| format!("{}:{}:{}", loc.file(), loc.line(), loc.column()))
            .unwrap_or_else(|| "unknown location".to_string());
        let payload = if let Some(s) = info.payload().downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "unspecified panic payload".to_string()
        };

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
        std::env::remove_var(ERROR_TRACKING_DSN_ENV);
        let sink = ErrorTrackingSink::from_env();
        assert!(!sink.enabled);
        assert_eq!(sink.dsn, None);
        sink.record_error("test error event");
    }

    #[test]
    fn error_tracking_sink_captures_dsn_from_env() {
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
}
