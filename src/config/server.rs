use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub listen: String,
    #[serde(default)]
    pub mode: WafMode,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WafMode {
    Off,
    #[default]
    Monitor,
    Block,
    Strict,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
    pub name: String,
    pub host: String,
    pub target: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyRouteConfig {
    pub path_prefix: String,
    pub upstream: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    #[serde(default = "default_max_body_size")]
    pub max_body_size: String,
    #[serde(default = "default_true")]
    pub enable_rate_limiting: bool,
    #[serde(default = "default_true")]
    pub block_suspicious_user_agents: bool,
    #[serde(default = "default_true")]
    pub inspect_json_body: bool,
}

fn default_true() -> bool {
    true
}
fn default_max_body_size() -> String {
    "2mb".to_string()
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_body_size: default_max_body_size(),
            enable_rate_limiting: true,
            block_suspicious_user_agents: true,
            inspect_json_body: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ForwardedHeadersConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_trusted_proxies")]
    pub trusted_proxies: Vec<String>,
    #[serde(default = "default_real_ip_header")]
    pub real_ip_header: String,
    #[serde(default = "default_proto_header")]
    pub proto_header: String,
    #[serde(default = "default_expected_proto")]
    pub expected_proto: String,
    #[serde(default = "default_insecure_proto_score")]
    pub insecure_proto_score: u16,
    #[serde(default)]
    pub identity_assertions: Vec<String>,
}

fn default_trusted_proxies() -> Vec<String> {
    vec!["127.0.0.1/32".to_string(), "::1".to_string()]
}
fn default_real_ip_header() -> String {
    "X-Forwarded-For".to_string()
}
fn default_proto_header() -> String {
    "X-Forwarded-Proto".to_string()
}
fn default_expected_proto() -> String {
    "https".to_string()
}
fn default_insecure_proto_score() -> u16 {
    10
}

impl Default for ForwardedHeadersConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            trusted_proxies: default_trusted_proxies(),
            real_ip_header: default_real_ip_header(),
            proto_header: default_proto_header(),
            expected_proto: default_expected_proto(),
            insecure_proto_score: default_insecure_proto_score(),
            identity_assertions: Vec::new(),
        }
    }
}
