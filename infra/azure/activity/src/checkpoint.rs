// Minimal per-partition offset checkpoint, persisted to local disk.

use std::fs;
use std::path::{Path, PathBuf};

pub struct PartitionCheckpoint {
    dir: PathBuf,
}

impl PartitionCheckpoint {
    pub fn new(spool_dir: &Path) -> Self {
        let dir = spool_dir.join("checkpoints");
        if let Err(e) = fs::create_dir_all(&dir) {
            tracing::warn!("Failed to create checkpoint directory {}: {}", dir.display(), e);
        }
        Self { dir }
    }

    fn path(&self, partition_id: &str) -> PathBuf {
        self.dir.join(format!("{partition_id}.offset"))
    }

    /// Returns the last confirmed-transmitted offset for this partition, if any.
    pub fn load(&self, partition_id: &str) -> Option<String> {
        fs::read_to_string(self.path(partition_id))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    /// Persists `offset` as the new last-confirmed point for this partition.
    /// Call only after the batch containing that event has been successfully
    /// spooled+transmitted.
    pub fn save(&self, partition_id: &str, offset: &str) {
        if let Err(e) = fs::write(self.path(partition_id), offset) {
            tracing::warn!("Failed to persist checkpoint for partition {}: {}", partition_id, e);
        }
    }
}
