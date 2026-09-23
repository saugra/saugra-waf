use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default)]
    pub backend: RateLimitBackend,
    #[serde(default)]
    pub redis_url: Option<String>,
    #[serde(default)]
    pub redis_password: Option<String>,
    #[serde(default = "default_requests_per_minute")]
    pub requests_per_minute: u32,
    #[serde(default = "default_rate_limit_burst")]
    pub burst: u32,
    #[serde(default)]
    pub routes: Vec<RouteRateLimitConfig>,
}

fn default_requests_per_minute() -> u32 {
    120
}
fn default_rate_limit_burst() -> u32 {
    30
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            backend: RateLimitBackend::Memory,
            redis_url: None,
            redis_password: None,
            requests_per_minute: default_requests_per_minute(),
            burst: default_rate_limit_burst(),
            routes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RouteRateLimitConfig {
    pub path: String,
    #[serde(default = "default_requests_per_minute")]
    pub requests_per_minute: u32,
    #[serde(default = "default_rate_limit_burst")]
    pub burst: u32,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitBackend {
    #[default]
    Memory,
    Redis,
}
