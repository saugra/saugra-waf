use serde::{Deserialize, Serialize};
use tracing::{error, info};

pub const ERROR_TRACKING_DSN_ENV: &str = "SAUGRA_WAF_ERROR_TRACKING_DSN";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorEventPayload {
    pub event_id: String,
    pub timestamp: String,
    pub level: String,
    pub message: String,
    pub service: String,
}

#[derive(Debug, Clone)]
pub struct ErrorTracker {
    pub dsn: Option<String>,
    client: reqwest::Client,
}

impl Default for ErrorTracker {
    fn default() -> Self {
        Self::from_env()
    }
}

impl ErrorTracker {
    pub fn new(dsn: Option<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        Self { dsn, client }
    }

    pub fn from_env() -> Self {
        let dsn = std::env::var(ERROR_TRACKING_DSN_ENV)
            .ok()
            .map(|val| val.trim().to_string())
            .filter(|val| !val.is_empty());
        Self::new(dsn)
    }

    pub fn is_enabled(&self) -> bool {
        self.dsn.is_some()
    }

    pub async fn dispatch_event(&self, message: &str, level: &str) -> anyhow::Result<bool> {
        let Some(dsn) = &self.dsn else {
            return Ok(false);
        };

        let payload = ErrorEventPayload {
            event_id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            level: level.to_string(),
            message: message.to_string(),
            service: "saugra-waf".to_string(),
        };

        let response = self.client.post(dsn).json(&payload).send().await?;

        if !response.status().is_success() {
            anyhow::bail!("error tracking DSN sink returned HTTP {}", response.status());
        }

        info!(sink_dsn = %dsn, %message, "forwarded error event to DSN sink");
        Ok(true)
    }

    pub fn record_error(&self, message: &str) {
        if let Some(dsn) = &self.dsn {
            info!(sink_dsn = %dsn, %message, "forwarded error event to error tracking DSN sink");
            let tracker = self.clone();
            let msg = message.to_string();
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    if let Err(err) = tracker.dispatch_event(&msg, "error").await {
                        error!(%err, "failed to send error event to DSN sink");
                    }
                });
            }
        }
    }

    pub fn capture_error(&self, err: &anyhow::Error) {
        self.record_error(&format!("{err:#}"));
    }
}

pub fn capture_error(err: &anyhow::Error) {
    let tracker = ErrorTracker::from_env();
    tracker.capture_error(err);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unconfigured_tracker_returns_false() {
        std::env::remove_var(ERROR_TRACKING_DSN_ENV);
        let tracker = ErrorTracker::from_env();
        assert!(!tracker.is_enabled());
        let dispatched = tracker.dispatch_event("test message", "error").await.unwrap();
        assert!(!dispatched);
    }

    #[test]
    fn capture_error_helper_runs_without_panic() {
        std::env::remove_var(ERROR_TRACKING_DSN_ENV);
        let err = anyhow::anyhow!("test error event");
        capture_error(&err);
    }
}
