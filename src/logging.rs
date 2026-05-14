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
