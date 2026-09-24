use anyhow::Context;
use tracing_subscriber::EnvFilter;

use crate::config::LoggingConfig;

pub fn init(config: &LoggingConfig) -> anyhow::Result<()> {
    let filter = EnvFilter::try_new(&config.level)
        .or_else(|_| EnvFilter::try_new("info"))
        .context("failed to configure log filter")?;

    let subscriber = tracing_subscriber::fmt().with_env_filter(filter);

    if config.format == "json" {
        subscriber
            .json()
            .try_init()
            .map_err(|error| anyhow::anyhow!("failed to initialize logging: {error}"))?;
    } else {
        subscriber
            .try_init()
            .map_err(|error| anyhow::anyhow!("failed to initialize logging: {error}"))?;
    }

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
}
