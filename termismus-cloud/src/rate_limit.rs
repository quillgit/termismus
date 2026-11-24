use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_ENTRIES: usize = 100_000;
const PRUNE_AGE: Duration = Duration::from_secs(3600);

/// Simple in-memory fixed-window counter keyed by string.
pub struct RateLimiter {
    store: Mutex<HashMap<String, (u32, Instant)>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self { store: Mutex::new(HashMap::new()) }
    }

    /// Returns false if the limit is reached within the window. Does not increment.
    pub fn check(&self, key: &str, max: u32, window: Duration) -> bool {
        let store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        match store.get(key) {
            Some((count, start)) if start.elapsed() < window => *count < max,
            _ => true,
        }
    }

    /// Increment the counter, resetting it when the window has expired.
    pub fn hit(&self, key: &str, window: Duration) {
        let mut store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        if store.len() >= MAX_ENTRIES && !store.contains_key(key) {
            store.clear();
        }
        let now = Instant::now();
        let e = store.entry(key.to_string()).or_insert((0, now));
        if e.1.elapsed() >= window {
            *e = (0, now);
        }
        e.0 += 1;
    }

    pub fn reset(&self, key: &str) {
        let mut store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        store.remove(key);
    }

    pub fn prune(&self) {
        let mut store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        store.retain(|_, (_, start)| start.elapsed() < PRUNE_AGE);
        if store.len() > MAX_ENTRIES {
            store.clear();
        }
    }
}
