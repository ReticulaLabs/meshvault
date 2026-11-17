//! Per-peer service rate limiting.
//!
//! Each peer gets a byte token bucket. Requests are charged an estimated
//! response cost (with a fixed minimum per request), so a peer cannot turn
//! tiny requests into unbounded inventory scans, manifest reads, or chunk
//! serving. Exhausted budgets produce a `429` control error.

use std::sync::Mutex;
use std::time::Instant;

/// Minimum token cost for one service request.
pub const MIN_REQUEST_COST: u64 = 64 * 1024;

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

pub struct ServiceLimiter {
    bucket: Mutex<Bucket>,
    rate_per_sec: f64,
    burst: f64,
}

impl ServiceLimiter {
    pub fn new(rate_bytes_per_sec: u64, burst_bytes: u64) -> Self {
        let burst = burst_bytes.max(1) as f64;
        Self {
            bucket: Mutex::new(Bucket {
                tokens: burst,
                last_refill: Instant::now(),
            }),
            rate_per_sec: rate_bytes_per_sec as f64,
            burst,
        }
    }

    /// Try to charge `bytes` (at least [`MIN_REQUEST_COST`]). Returns false when
    /// the peer must be rate-limited.
    pub fn try_consume(&self, bytes: u64) -> bool {
        let cost = bytes.max(MIN_REQUEST_COST) as f64;
        if cost > self.burst {
            return false;
        }
        let now = Instant::now();
        let mut bucket = self.bucket.lock().unwrap();
        let elapsed = now
            .saturating_duration_since(bucket.last_refill)
            .as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate_per_sec).min(self.burst);
        bucket.last_refill = now;
        if bucket.tokens >= cost {
            bucket.tokens -= cost;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_burst_and_minimum_cost() {
        let limiter = ServiceLimiter::new(0, 2 * MIN_REQUEST_COST);
        assert!(limiter.try_consume(0));
        assert!(limiter.try_consume(0));
        assert!(!limiter.try_consume(0));

        let too_small = ServiceLimiter::new(1_000_000, MIN_REQUEST_COST - 1);
        assert!(!too_small.try_consume(0));
    }

    #[test]
    fn large_request_costs_more() {
        let limiter = ServiceLimiter::new(1_000_000, 4 * MIN_REQUEST_COST);
        assert!(limiter.try_consume(MIN_REQUEST_COST));
        assert!(limiter.try_consume(2 * MIN_REQUEST_COST));
        assert!(!limiter.try_consume(2 * MIN_REQUEST_COST));
    }
}
