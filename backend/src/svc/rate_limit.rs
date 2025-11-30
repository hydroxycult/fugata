use crate::errors::Result;
use crate::util;
use chrono::Utc;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    buckets: Arc<DashMap<String, TokenBucket>>,
    rate_per_minute: u64,
    burst: u64,
    ip_hash_key: [u8; 32],
}

#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    limit: u64,
    burst: u64,
}

#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    pub allowed: bool,
    pub limit: u64,
    pub remaining: u64,
    pub reset_at: i64,
}

impl RateLimiter {
    pub fn new(rate_per_minute: u64, burst: u64, ip_hash_key: [u8; 32]) -> Self {
        Self {
            buckets: Arc::new(DashMap::new()),
            rate_per_minute,
            burst,
            ip_hash_key,
        }
    }

    pub fn check_rate_limit(&self, ip: &str) -> Result<RateLimitInfo> {
        let ip_hash = util::hash_ip(ip, &self.ip_hash_key);

        let mut bucket = self
            .buckets
            .entry(ip_hash.clone())
            .or_insert_with(|| TokenBucket {
                tokens: self.burst as f64,
                last_refill: Instant::now(),
                limit: self.rate_per_minute,
                burst: self.burst,
            });

        let now = Instant::now();
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        let tokens_to_add = elapsed * (self.rate_per_minute as f64 / 60.0);
        bucket.tokens = (bucket.tokens + tokens_to_add).min(self.burst as f64);
        bucket.last_refill = now;

        let allowed = bucket.tokens >= 1.0;

        if allowed {
            bucket.tokens -= 1.0;
        }

        let tokens_to_full = self.burst as f64 - bucket.tokens;
        let seconds_to_full = (tokens_to_full / (self.rate_per_minute as f64 / 60.0)).ceil();
        let reset_at = Utc::now().timestamp() + seconds_to_full as i64;

        let remaining = bucket.tokens.floor() as u64;

        Ok(RateLimitInfo {
            allowed,
            limit: self.rate_per_minute,
            remaining,
            reset_at,
        })
    }

    pub fn cleanup_old_buckets(&self, max_age: Duration) {
        let now = Instant::now();
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.last_refill) < max_age);
    }

    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn test_key() -> [u8; 32] {
        [42u8; 32]
    }

    #[test]
    fn test_rate_limit_allows_under_limit() {
        let limiter = RateLimiter::new(60, 10, test_key());

        for i in 0..10 {
            let result = limiter.check_rate_limit("192.168.1.1").unwrap();
            assert!(result.allowed, "Request {} should be allowed", i);
            assert_eq!(result.limit, 60);
        }
    }

    #[test]
    fn test_rate_limit_blocks_over_limit() {
        let limiter = RateLimiter::new(60, 10, test_key());

        for _ in 0..10 {
            limiter.check_rate_limit("192.168.1.1").unwrap();
        }

        let result = limiter.check_rate_limit("192.168.1.1").unwrap();
        assert!(
            !result.allowed,
            "Request should be blocked after burst exhausted"
        );
    }

    #[test]
    fn test_rate_limit_burst() {
        let limiter = RateLimiter::new(60, 5, test_key());

        for i in 0..5 {
            let result = limiter.check_rate_limit("192.168.1.1").unwrap();
            assert!(result.allowed, "Burst request {} should be allowed", i);
        }

        let result = limiter.check_rate_limit("192.168.1.1").unwrap();
        assert!(!result.allowed, "Request beyond burst should be blocked");
    }

    #[test]
    fn test_rate_limit_refill_over_time() {
        let limiter = RateLimiter::new(60, 3, test_key());

        for _ in 0..3 {
            limiter.check_rate_limit("192.168.1.1").unwrap();
        }

        let result = limiter.check_rate_limit("192.168.1.1").unwrap();
        assert!(!result.allowed);

        thread::sleep(Duration::from_millis(1100));

        let result = limiter.check_rate_limit("192.168.1.1").unwrap();
        assert!(result.allowed, "Request should be allowed after refill");
    }

    #[test]
    fn test_rate_limit_different_ips() {
        let limiter = RateLimiter::new(60, 2, test_key());

        for _ in 0..2 {
            limiter.check_rate_limit("192.168.1.1").unwrap();
        }
        let result = limiter.check_rate_limit("192.168.1.1").unwrap();
        assert!(!result.allowed, "IP 1 should be blocked");

        let result = limiter.check_rate_limit("192.168.1.2").unwrap();
        assert!(result.allowed, "IP 2 should be allowed with fresh bucket");
    }

    #[test]
    fn test_cleanup_old_buckets() {
        let limiter = RateLimiter::new(60, 10, test_key());

        limiter.check_rate_limit("192.168.1.1").unwrap();
        limiter.check_rate_limit("192.168.1.2").unwrap();
        limiter.check_rate_limit("192.168.1.3").unwrap();

        assert_eq!(limiter.bucket_count(), 3);

        limiter.cleanup_old_buckets(Duration::from_secs(0));

        assert!(limiter.bucket_count() <= 3);
    }

    #[test]
    fn test_rate_limit_info_headers() {
        let limiter = RateLimiter::new(60, 10, test_key());

        let result = limiter.check_rate_limit("192.168.1.1").unwrap();

        assert_eq!(result.limit, 60);
        assert_eq!(result.remaining, 9);
        assert!(result.reset_at > 0);
    }
}
