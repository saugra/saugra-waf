use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Instant,
};

use anyhow::Context;
use async_trait::async_trait;

use crate::{
    config::{RateLimitBackend, RateLimitConfig},
    redis_connection,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitPolicy {
    pub requests_per_minute: u32,
    pub burst: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitExceeded {
    pub client_id: String,
    pub limit: u32,
    pub burst: u32,
    pub retry_after_seconds: u64,
}

#[async_trait]
pub trait RateLimitStore: Send + Sync {
    async fn check(
        &self,
        key: &str,
        client_id: &str,
        policy: RateLimitPolicy,
    ) -> anyhow::Result<Option<RateLimitExceeded>>;
}

#[derive(Debug)]
struct ClientWindow {
    last_refill_at: Instant,
    tokens: f64,
}

#[derive(Debug)]
pub struct MemoryRateLimitStore {
    clients: Mutex<HashMap<String, ClientWindow>>,
}

impl MemoryRateLimitStore {
    pub fn new() -> Self {
        Self {
            clients: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for MemoryRateLimitStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RateLimitStore for MemoryRateLimitStore {
    async fn check(
        &self,
        key: &str,
        client_id: &str,
        policy: RateLimitPolicy,
    ) -> anyhow::Result<Option<RateLimitExceeded>> {
        let now = Instant::now();
        let capacity = token_capacity(policy);
        let refill_per_second = policy.requests_per_minute as f64 / 60.0;
        let mut clients = self
            .clients
            .lock()
            .map_err(|_| anyhow::anyhow!("rate limiter lock poisoned"))?;
        let window = clients
            .entry(key.to_string())
            .or_insert_with(|| ClientWindow {
                last_refill_at: now,
                tokens: capacity,
            });

        let elapsed_seconds = now.duration_since(window.last_refill_at).as_secs_f64();
        window.tokens = (window.tokens + elapsed_seconds * refill_per_second).min(capacity);
        window.last_refill_at = now;

        if window.tokens >= 1.0 {
            window.tokens -= 1.0;
            return Ok(None);
        }

        Ok(Some(RateLimitExceeded {
            client_id: client_id.to_string(),
            limit: policy.requests_per_minute,
            burst: policy.burst,
            retry_after_seconds: retry_after_seconds(window.tokens, refill_per_second),
        }))
    }
}

#[derive(Clone)]
pub struct RedisRateLimitStore {
    manager: redis::aio::ConnectionManager,
}

impl RedisRateLimitStore {
    pub async fn connect(redis_url: &str, redis_password: Option<&str>) -> anyhow::Result<Self> {
        let connection_info = redis_connection::connection_info(
            redis_url,
            redis_password,
            "rate_limit.redis_url is not a valid Redis URL",
        )?;
        let client =
            redis::Client::open(connection_info).context("failed to create Redis client")?;
        let manager = client
            .get_connection_manager()
            .await
            .context("failed to connect to Redis for rate limiting")?;

        Ok(Self { manager })
    }
}

#[async_trait]
impl RateLimitStore for RedisRateLimitStore {
    async fn check(
        &self,
        key: &str,
        client_id: &str,
        policy: RateLimitPolicy,
    ) -> anyhow::Result<Option<RateLimitExceeded>> {
        let mut connection = self.manager.clone();
        let redis_key = format!("saugra-waf:rate_limit:{key}");
        let capacity = token_capacity(policy);
        let refill_per_millisecond = policy.requests_per_minute as f64 / 60_000.0;
        let ttl_milliseconds = (capacity / refill_per_millisecond).ceil() as u64;
        let result: Vec<String> = redis::Script::new(REDIS_TOKEN_BUCKET_SCRIPT)
            .key(&redis_key)
            .arg(capacity)
            .arg(refill_per_millisecond)
            .arg(ttl_milliseconds)
            .invoke_async(&mut connection)
            .await
            .context("failed to evaluate Redis rate-limit token bucket")?;

        if result.first().map(String::as_str) == Some("1") {
            return Ok(None);
        }

        let retry_after_seconds = result
            .get(1)
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(1);

        Ok(Some(RateLimitExceeded {
            client_id: client_id.to_string(),
            limit: policy.requests_per_minute,
            burst: policy.burst,
            retry_after_seconds,
        }))
    }
}

fn token_capacity(policy: RateLimitPolicy) -> f64 {
    policy.requests_per_minute.saturating_add(policy.burst) as f64
}

fn retry_after_seconds(tokens: f64, refill_per_second: f64) -> u64 {
    if refill_per_second <= 0.0 {
        return 60;
    }

    ((1.0 - tokens).max(0.0) / refill_per_second).ceil() as u64
}

const REDIS_TOKEN_BUCKET_SCRIPT: &str = r#"
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_per_millisecond = tonumber(ARGV[2])
local ttl_milliseconds = tonumber(ARGV[3])
local now_parts = redis.call('TIME')
local now = (tonumber(now_parts[1]) * 1000) + math.floor(tonumber(now_parts[2]) / 1000)
local bucket = redis.call('HMGET', key, 'tokens', 'last_refill_at')
local tokens = tonumber(bucket[1])
local last_refill_at = tonumber(bucket[2])

if tokens == nil then
  tokens = capacity
  last_refill_at = now
end

local elapsed = math.max(0, now - last_refill_at)
tokens = math.min(capacity, tokens + (elapsed * refill_per_millisecond))
last_refill_at = now

if tokens >= 1 then
  tokens = tokens - 1
  redis.call('HMSET', key, 'tokens', tokens, 'last_refill_at', last_refill_at)
  redis.call('PEXPIRE', key, ttl_milliseconds)
  return {'1', '0'}
end

local retry_after = math.ceil((1 - tokens) / refill_per_millisecond / 1000)
redis.call('HMSET', key, 'tokens', tokens, 'last_refill_at', last_refill_at)
redis.call('PEXPIRE', key, ttl_milliseconds)
return {'0', tostring(retry_after)}
"#;

pub async fn build_store(config: &RateLimitConfig) -> anyhow::Result<Arc<dyn RateLimitStore>> {
    match config.backend {
        RateLimitBackend::Memory => Ok(Arc::new(MemoryRateLimitStore::new())),
        RateLimitBackend::Redis => {
            let redis_url = config
                .redis_url
                .as_deref()
                .context("rate_limit.redis_url is required when backend is redis")?;
            Ok(Arc::new(
                RedisRateLimitStore::connect(redis_url, config.redis_password.as_deref()).await?,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn redis_store_reports_invalid_url_with_rate_limit_context() {
        let error = RedisRateLimitStore::connect("not a Redis URL", None)
            .await
            .err()
            .unwrap();

        assert!(error
            .to_string()
            .contains("rate_limit.redis_url is not a valid Redis URL"));
    }

    #[tokio::test]
    async fn memory_store_allows_requests_inside_limit() {
        let store = MemoryRateLimitStore::new();
        let policy = RateLimitPolicy {
            requests_per_minute: 2,
            burst: 1,
        };

        assert!(store
            .check("global:127.0.0.1", "127.0.0.1", policy)
            .await
            .unwrap()
            .is_none());
        assert!(store
            .check("global:127.0.0.1", "127.0.0.1", policy)
            .await
            .unwrap()
            .is_none());
        assert!(store
            .check("global:127.0.0.1", "127.0.0.1", policy)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn memory_store_rejects_requests_after_limit() {
        let store = MemoryRateLimitStore::new();
        let policy = RateLimitPolicy {
            requests_per_minute: 1,
            burst: 1,
        };

        assert!(store
            .check("global:127.0.0.1", "127.0.0.1", policy)
            .await
            .unwrap()
            .is_none());
        assert!(store
            .check("global:127.0.0.1", "127.0.0.1", policy)
            .await
            .unwrap()
            .is_none());
        let exceeded = store
            .check("global:127.0.0.1", "127.0.0.1", policy)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(exceeded.client_id, "127.0.0.1");
        assert_eq!(exceeded.limit, 1);
        assert_eq!(exceeded.burst, 1);
        assert!(exceeded.retry_after_seconds <= 60);
    }

    #[tokio::test]
    async fn memory_store_tracks_clients_separately() {
        let store = MemoryRateLimitStore::new();
        let policy = RateLimitPolicy {
            requests_per_minute: 1,
            burst: 1,
        };

        assert!(store
            .check("global:client-a", "client-a", policy)
            .await
            .unwrap()
            .is_none());
        assert!(store
            .check("global:client-b", "client-b", policy)
            .await
            .unwrap()
            .is_none());
        assert!(store
            .check("global:client-a", "client-a", policy)
            .await
            .unwrap()
            .is_none());
        assert!(store
            .check("global:client-a", "client-a", policy)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn memory_store_tracks_route_keys_separately() {
        let store = MemoryRateLimitStore::new();
        let policy = RateLimitPolicy {
            requests_per_minute: 1,
            burst: 0,
        };

        assert!(store
            .check("global:client-a", "client-a", policy)
            .await
            .unwrap()
            .is_none());
        assert!(store
            .check("route:/sensitive-action:client-a", "client-a", policy)
            .await
            .unwrap()
            .is_none());
    }
}
