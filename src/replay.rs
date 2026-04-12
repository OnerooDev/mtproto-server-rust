//! Replay-attack protection.
//! Caches the first 8 bytes of each client's pre_key to detect duplicate
//! handshakes within a sliding window of `capacity` entries.

use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;

pub struct ReplayCache {
    inner: Mutex<LruCache<[u8; 8], ()>>,
}

impl ReplayCache {
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            inner: Mutex::new(LruCache::new(cap)),
        }
    }

    /// Returns `true` if this token was already seen (replay), `false` if fresh.
    pub fn check_and_insert(&self, token: [u8; 8]) -> bool {
        let mut cache = self.inner.lock().unwrap();
        if cache.contains(&token) {
            return true;
        }
        cache.put(token, ());
        false
    }
}
