use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

// --- 1. TEMPORAL CACHE (Jitter & Interval Tracking) ---

#[derive(Clone, Copy)]
struct ConversationState {
    last_ts: f64,
    n: u64,
    mean: f64,
    m2: f64,
    last_seen: Instant,
}

#[derive(Clone)]
pub struct TemporalCache {
    state: Arc<DashMap<String, ConversationState>>,
}

impl Default for TemporalCache {
    fn default() -> Self { Self::new() }
}

impl TemporalCache {
    pub fn new() -> Self {
        Self { state: Arc::new(DashMap::new()) }
    }

    pub fn observe(&self, key: &str, current_ts: f64) -> (f64, f64) {
        let now = Instant::now();

        if let Some(mut e) = self.state.get_mut(key) {
            let delta = current_ts - e.last_ts;
            if current_ts > e.last_ts {
                e.last_ts = current_ts;
            }
            e.last_seen = now;

            let interval = if delta > 0.0 { delta } else { 0.0 };

            e.n += 1;
            let d1 = interval - e.mean;
            e.mean += d1 / e.n as f64;
            let d2 = interval - e.mean;
            e.m2 += d1 * d2;

            let cv = if e.n >= 2 && e.mean > 0.0 {
                let variance = e.m2 / (e.n as f64 - 1.0);
                variance.sqrt() / e.mean
            } else {
                0.0
            };

            (interval, cv)
        } else {
            self.state.insert(
                key.to_string(),
                ConversationState {
                    last_ts: current_ts,
                    n: 0,
                    mean: 0.0,
                    m2: 0.0,
                    last_seen: now,
                },
            );
            (0.0, 0.0)
        }
    }

    pub fn calculate_interval(&self, key: &str, current_ts: f64) -> f64 {
        self.observe(key, current_ts).0
    }

    pub fn remove_stale(&self, max_age_secs: u64) {
        self.state.retain(|_, v| v.last_seen.elapsed().as_secs() < max_age_secs);
    }
}

// --- 2. METADATA CACHE (Database Offloading) ---

#[derive(Clone)]
pub struct MetadataCache {
    store: Arc<DashMap<String, (HashMap<String, String>, Instant)>>,
}

impl Default for MetadataCache {
    fn default() -> Self { Self::new() }
}

impl MetadataCache {
    pub fn new() -> Self {
        Self { store: Arc::new(DashMap::new()) }
    }

    pub fn get(&self, key: &str) -> Option<HashMap<String, String>> {
        self.store.get(key).map(|entry| entry.0.clone())
    }

    pub fn insert(&self, key: String, metadata: HashMap<String, String>) {
        self.store.insert(key, (metadata, Instant::now()));
    }

    pub fn remove_stale(&self, max_age_secs: u64) {
        self.store.retain(|_, val| val.1.elapsed().as_secs() < max_age_secs);
    }
}