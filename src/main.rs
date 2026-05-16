use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use saugra::{
    ai, config::SaugraConfig, event_store, event_store::EventLogRetention, logging, proxy, rules,
};

#[derive(Debug, Parser)]
#[command(name = "saugra")]
#[command(about = "A lightweight Rust-based Web Application Firewall.")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Create starter configuration or proxy integration snippets.
    Init {
        #[command(subcommand)]
        target: Option<InitTarget>,
    },
    /// Validate a Saugra YAML configuration file.
    TestConfig {
        #[arg(short, long, default_value = "configs/saugra.example.yml")]
        config: PathBuf,
    },
    /// Start the Saugra service.
    Run {
        #[arg(short, long, default_value = "configs/saugra.example.yml")]
        config: PathBuf,
    },
    /// Inspect built-in rules.
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
    /// Read local Saugra security events.
    Logs {
        #[command(subcommand)]
        command: LogsCommand,
    },
    /// Explain a recorded request decision.
    Explain {
        request_id: String,
        #[arg(short, long, default_value = "configs/saugra.example.yml")]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum InitTarget {
    /// Print an Nginx reverse proxy snippet.
    Nginx,
    /// Print an Apache reverse proxy snippet.
    Apache,
}

#[derive(Debug, Subcommand)]
enum RulesCommand {
    /// List built-in WAF rules.
    List,
}

#[derive(Debug, Subcommand)]
enum LogsCommand {
    /// Print recent local security events.
    Tail {
        #[arg(short, long, default_value = "configs/saugra.example.yml")]
        config: PathBuf,
        #[arg(short, long, default_value_t = 20)]
        limit: usize,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { target } => print_init(target),
        Commands::TestConfig { config } => {
            let config = SaugraConfig::from_file(&config)
                .with_context(|| format!("failed to load config {}", config.display()))?;
            config.validate()?;
            println!("config OK: {}", config.summary());
            Ok(())
        }
        Commands::Run { config } => {
            let config = SaugraConfig::from_file(&config)
                .with_context(|| format!("failed to load config {}", config.display()))?;
            config.validate()?;
            logging::init(&config.logging)?;
            proxy::run(config).await
        }
        Commands::Rules { command } => match command {
            RulesCommand::List => {
                for rule in rules::builtin_rules()? {
                    println!(
                        "{}\t{}\t{}\t{}\t{}",
                        rule.id, rule.severity, rule.category, rule.target, rule.name
                    );
                }
                Ok(())
            }
        },
        Commands::Logs { command } => match command {
            LogsCommand::Tail { config, limit } => {
                let config = load_valid_config(&config)?;
                let retention = event_log_retention(&config)?;
                let events = event_store::tail(
                    PathBuf::from(config.logging.event_log_path).as_path(),
                    retention,
                    limit,
                )?;
                for event in events {
                    println!("{}", serde_json::to_string(&event)?);
                }
                Ok(())
            }
        },
        Commands::Explain { request_id, config } => {
            let config = load_valid_config(&config)?;
            let retention = event_log_retention(&config)?;
            let event = event_store::find_by_request_id(
                PathBuf::from(config.logging.event_log_path).as_path(),
                retention,
                &request_id,
            )?
            .with_context(|| format!("request ID not found: {request_id}"))?;

            println!("{}", ai::explain(&event.decision));
            println!("{}", serde_json::to_string_pretty(&event.decision)?);
            Ok(())
        }
    }
}

fn load_valid_config(path: &PathBuf) -> anyhow::Result<SaugraConfig> {
    let config = SaugraConfig::from_file(path)
        .with_context(|| format!("failed to load config {}", path.display()))?;
    config.validate()?;
    Ok(config)
}

fn event_log_retention(config: &SaugraConfig) -> anyhow::Result<EventLogRetention> {
    Ok(EventLogRetention {
        max_size_bytes: config.event_log_max_size_bytes()?,
        max_files: config.logging.event_log_max_files,
    })
}

fn print_init(target: Option<InitTarget>) -> anyhow::Result<()> {
    match target {
        None => {
            println!("{}", include_str!("../configs/saugra.example.yml"));
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
