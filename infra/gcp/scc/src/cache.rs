use dashmap::DashMap;
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone)]
pub struct FindingCache {
    state: Arc<DashMap<String, Instant>>,
}

impl Default for FindingCache {
    fn default() -> Self {
        Self::new()
    }
}

impl FindingCache {
    pub fn new() -> Self {
        Self {
            state: Arc::new(DashMap::new()),
        }
    }

    /// Non-mutating membership check. Does NOT record the id.
    pub fn contains(&self, finding_id: &str) -> bool {
        self.state.contains_key(finding_id)
    }

    /// Record an id as seen. Call ONLY after a successful transmit so that a
    /// failed batch can be reprocessed on redelivery.
    pub fn commit(&self, finding_id: &str) {
        self.state.insert(finding_id.to_string(), Instant::now());
    }

    /// Back-compat check-and-insert (mutating). Prefer contains()+commit().
    pub fn is_duplicate(&self, finding_id: &str) -> bool {
        if self.state.contains_key(finding_id) {
            true
        } else {
            self.state.insert(finding_id.to_string(), Instant::now());
            false
        }
    }

    pub fn remove_stale(&self, max_age_secs: u64) {
        self.state.retain(|_, val| val.elapsed().as_secs() < max_age_secs);
    }
}