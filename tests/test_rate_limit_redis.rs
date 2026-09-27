use std::env;

use saugra_waf::{
    config::{RateLimitBackend, RateLimitConfig},
    rate_limit::{build_store, RateLimitPolicy},
};

#[tokio::test]
#[ignore = "Requires live Redis instance on 127.0.0.1:6379"]
async fn test_live_redis_rate_limiting() {
    let redis_url = match env::var("REDIS_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => {
            println!("Skipping live Redis test: REDIS_URL environment variable is unset.");
            return;
        }
    };

    let config = RateLimitConfig {
        backend: RateLimitBackend::Redis,
        redis_url: Some(redis_url.clone()),
        redis_password: None,
        requests_per_minute: 2,
        burst: 1,
        routes: Vec::new(),
    };

    let store = match build_store(&config).await {
        Ok(store) => store,
        Err(err) => {
            println!("Skipping live Redis test (Redis unreachable at {redis_url}): {err}");
            return;
        }
    };

    let policy = RateLimitPolicy {
        requests_per_minute: 2,
        burst: 1,
    };

    let test_key = format!("test_redis_{}", uuid::Uuid::new_v4());

    // 1st request - allowed
    let result1 = store.check(&test_key, "127.0.0.1", policy).await.unwrap();
    assert!(result1.is_none(), "1st request should be allowed");

    // 2nd request - allowed
    let result2 = store.check(&test_key, "127.0.0.1", policy).await.unwrap();
    assert!(result2.is_none(), "2nd request should be allowed");

    // 3rd request - rate limited
    let result3 = store.check(&test_key, "127.0.0.1", policy).await.unwrap();
    assert!(result3.is_some(), "3rd request should be rate-limited");
}
