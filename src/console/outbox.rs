use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::{bail, Context, Result};
use saugra_console_contracts::{EnrollmentResponse, SaugraProduct};
use serde::{Deserialize, Serialize};

use crate::{config::SaugraConfig, event_store::SecurityEvent};

use super::{now_unix_secs, protect_file, CONSOLE_PROTOCOL_VERSION};

#[derive(Clone)]
pub struct ConsoleOutbox {
    path: PathBuf,
    lock: Arc<Mutex<()>>,
}

impl ConsoleOutbox {
    pub fn from_config(config: &SaugraConfig) -> Self {
        Self::new(config.console.outbox_path(&config.logging.event_log_path))
    }

    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn append(&self, event: &SecurityEvent) -> Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| anyhow::anyhow!("Console outbox lock poisoned"))?;
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("failed to open Console outbox {}", self.path.display()))?;
        protect_file(&self.path)?;
        serde_json::to_writer(&mut file, event)?;
        file.write_all(b"\n")?;
        file.sync_data()?;
        Ok(())
    }

    pub fn batch(&self, limit: usize) -> Result<Vec<SecurityEvent>> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| anyhow::anyhow!("Console outbox lock poisoned"))?;
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let file = fs::File::open(&self.path)?;
        BufReader::new(file)
            .lines()
            .take(limit)
            .map(|line| serde_json::from_str(&line?).context("invalid event in Console outbox"))
            .collect()
    }

    pub fn remove_terminal(&self, keys: &HashSet<String>) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }
        let _guard = self
            .lock
            .lock()
            .map_err(|_| anyhow::anyhow!("Console outbox lock poisoned"))?;
        if !self.path.exists() {
            return Ok(());
        }
        let temporary = self
            .path
            .with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
        let source = fs::File::open(&self.path)?;
        let mut target = fs::File::create(&temporary)?;
        protect_file(&temporary)?;
        for line in BufReader::new(source).lines() {
            let line = line?;
            let event: SecurityEvent =
                serde_json::from_str(&line).context("invalid event in Console outbox")?;
            if !keys.contains(&event.decision.request_id) {
                target.write_all(line.as_bytes())?;
                target.write_all(b"\n")?;
            }
        }
        target.sync_all()?;
        fs::rename(&temporary, &self.path)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleCredential {
    pub protocol_version: u16,
    pub node_id: String,
    pub tenant_id: String,
    pub product: SaugraProduct,
    pub credential: String,
    pub credential_fingerprint: String,
    pub credential_expires_at: String,
    pub stored_at_unix_secs: u64,
}

impl ConsoleCredential {
    pub fn from_enrollment_response(response: EnrollmentResponse) -> Result<Self> {
        if response.protocol_version != CONSOLE_PROTOCOL_VERSION {
            bail!(
                "unsupported Console enrollment protocol version {}",
                response.protocol_version
            );
        }
        if response.product != SaugraProduct::Waf {
            bail!("Console enrollment response is not for a WAF node");
        }
        if response.node_id.trim().is_empty()
            || response.tenant_id.trim().is_empty()
            || response.credential.trim().is_empty()
            || response.credential_fingerprint.trim().is_empty()
            || response.credential_expires_at.trim().is_empty()
        {
            bail!("Console enrollment response contains empty credential fields");
        }
        Ok(Self {
            protocol_version: response.protocol_version,
            node_id: response.node_id,
            tenant_id: response.tenant_id,
            product: response.product,
            credential: response.credential,
            credential_fingerprint: response.credential_fingerprint,
            credential_expires_at: response.credential_expires_at,
            stored_at_unix_secs: now_unix_secs(),
        })
    }
}

pub struct ConsoleCredentialStore {
    path: PathBuf,
}

impl ConsoleCredentialStore {
    pub fn from_config(config: &SaugraConfig) -> Self {
        Self {
            path: config
                .console
                .credential_path(&config.logging.event_log_path),
        }
    }

    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn save(&self, credential: &ConsoleCredential) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary = self
            .path
            .with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
        fs::write(&temporary, serde_json::to_vec_pretty(credential)?)?;
        protect_file(&temporary)?;
        fs::rename(&temporary, &self.path).with_context(|| {
            format!("failed to store Console credential {}", self.path.display())
        })?;
        Ok(())
    }

    pub fn load(&self) -> Result<ConsoleCredential> {
        serde_json::from_slice(&fs::read(&self.path)?)
            .with_context(|| format!("failed to read Console credential {}", self.path.display()))
    }
}
