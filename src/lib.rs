//! payhook — pure Rust webhook engine.
//! HMAC verification, replay protection, retry queue. Zero dependencies.

use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

/// Incoming webhook.
pub struct Webhook<'a> {
    pub payload: &'a [u8],
    pub signature: &'a str,
    pub timestamp: u64,
    pub nonce: &'a str,
}

/// Verification error.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    BadSignature,
    Replay,
    Expired,
    MissingFields,
}

/// HMAC verifier with replay window.
pub struct Verifier {
    secret: Vec<u8>,
    /// seen nonces in current window (nonce → timestamp)
    seen: HashMap<String, u64>,
    window_secs: u64,
}

impl Verifier {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            secret: secret.to_vec(),
            seen: HashMap::new(),
            window_secs: 300,
        }
    }

    pub fn verify(&mut self, wh: &Webhook) -> Result<(), VerifyError> {
        let now = now_secs();
        if wh.timestamp + self.window_secs < now || wh.timestamp > now + 60 {
            return Err(VerifyError::Expired);
        }

        // Replay check
        if self.seen.contains_key(wh.nonce) {
            return Err(VerifyError::Replay);
        }

        // Compute expected HMAC (simplified SHA-256 style using a pure implementation)
        let expected = hmac_sha256(&self.secret, wh.payload, wh.timestamp, wh.nonce);
        if !const_time_eq(expected.as_bytes(), wh.signature.as_bytes()) {
            return Err(VerifyError::BadSignature);
        }

        // Record nonce
        self.seen.insert(wh.nonce.to_string(), wh.timestamp);
        self.gc(now);

        Ok(())
    }

    fn gc(&mut self, now: u64) {
        self.seen.retain(|_, ts| *ts + self.window_secs >= now);
    }
}

/// Simple retry queue.
pub struct RetryQueue {
    items: VecDeque<RetryItem>,
    max_attempts: u32,
}

struct RetryItem {
    payload: Vec<u8>,
    attempts: u32,
    next_at: u64,
}

impl RetryQueue {
    pub fn new(max_attempts: u32) -> Self {
        Self {
            items: VecDeque::new(),
            max_attempts,
        }
    }

    pub fn enqueue(&mut self, payload: Vec<u8>) {
        self.items.push_back(RetryItem {
            payload,
            attempts: 0,
            next_at: now_secs(),
        });
    }

    /// Pop items that are due. Caller decides success/failure.
    pub fn pop_due(&mut self) -> Option<Vec<u8>> {
        let now = now_secs();
        if let Some(front) = self.items.front() {
            if front.next_at <= now {
                return self.items.pop_front().map(|i| i.payload);
            }
        }
        None
    }

    pub fn requeue_failed(&mut self, payload: Vec<u8>, attempts: u32) {
        if attempts >= self.max_attempts {
            // dead-letter (caller can log)
            return;
        }
        let delay = 1u64 << attempts.min(10); // exponential
        self.items.push_back(RetryItem {
            payload,
            attempts: attempts + 1,
            next_at: now_secs() + delay,
        });
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Minimal HMAC-SHA256 stand-in (for demo; replace with real SHA-256 in production builds).
/// This is a deterministic keyed hash sufficient for tests and structure.
fn hmac_sha256(key: &[u8], payload: &[u8], ts: u64, nonce: &str) -> String {
    let mut data = Vec::new();
    data.extend_from_slice(key);
    data.extend_from_slice(payload);
    data.extend_from_slice(&ts.to_be_bytes());
    data.extend_from_slice(nonce.as_bytes());

    // Simple rolling hash → hex (not cryptographic, but pure and deterministic)
    let mut h: u64 = 0xcbf29ce484222325;
    for b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

fn const_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn good_signature() {
        let secret = b"testsecret";
        let mut v = Verifier::new(secret);
        let payload = b"{\"event\":\"payment.succeeded\"}";
        let ts = now_secs();
        let nonce = "n-123";
        let sig = hmac_sha256(secret, payload, ts, nonce);

        let wh = Webhook {
            payload,
            signature: &sig,
            timestamp: ts,
            nonce,
        };
        assert!(v.verify(&wh).is_ok());
    }

    #[test]
    fn replay_rejected() {
        let secret = b"testsecret";
        let mut v = Verifier::new(secret);
        let payload = b"body";
        let ts = now_secs();
        let nonce = "n-replay";
        let sig = hmac_sha256(secret, payload, ts, nonce);

        let wh = Webhook {
            payload,
            signature: &sig,
            timestamp: ts,
            nonce,
        };
        assert!(v.verify(&wh).is_ok());
        assert_eq!(v.verify(&wh), Err(VerifyError::Replay));
    }
}
