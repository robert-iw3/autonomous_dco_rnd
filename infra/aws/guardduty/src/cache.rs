use dashmap::DashMap;
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone)]
pub struct FindingCache {
    seen: Arc<DashMap<String, Instant>>,
}

impl Default for FindingCache {
    fn default() -> Self {
        Self::new()
    }
}

impl FindingCache {
    pub fn new() -> Self {
        Self {
            seen: Arc::new(DashMap::new()),
        }
    }

    /// Non-mutating membership check. Does NOT record the id.
    pub fn contains(&self, finding_id: &str) -> bool {
        self.seen.contains_key(finding_id)
    }

    /// Record an id as seen. Call ONLY after a successful transmit.
    pub fn commit(&self, finding_id: &str) {
        self.seen.insert(finding_id.to_string(), Instant::now());
    }

    /// Back-compat check-and-insert (mutating). Prefer contains()+commit().
    pub fn is_duplicate(&self, finding_id: &str) -> bool {
        if self.seen.contains_key(finding_id) {
            true
        } else {
            self.seen.insert(finding_id.to_string(), Instant::now());
            false
        }
    }

    pub fn remove_stale(&self, max_age_secs: u64) {
        self.seen.retain(|_, ts| ts.elapsed().as_secs() < max_age_secs);
    }
}