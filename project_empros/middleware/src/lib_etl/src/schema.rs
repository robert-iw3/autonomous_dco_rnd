use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SchemaMapping {
    pub name: String,
    #[serde(default)]
    pub match_field: String,
    #[serde(default)]
    pub match_value: String,
    pub fields: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SchemasConfig {
    pub schemas: Vec<SchemaMapping>,
}

#[derive(Clone)]
pub struct SchemaRegistry {
    schemas: Arc<RwLock<Vec<SchemaMapping>>>,
    file_path: String,
}

impl SchemaRegistry {
    pub fn load(file_path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(file_path)
            .map_err(|e| format!("Failed to read {}: {}", file_path, e))?;
        let config: SchemasConfig = serde_yaml::from_str(&content)
            .map_err(|e| format!("Failed to parse {}: {}", file_path, e))?;
        info!("Loaded {} schema mappings from {}", config.schemas.len(), file_path);
        Ok(Self {
            schemas: Arc::new(RwLock::new(config.schemas)),
            file_path: file_path.to_string(),
        })
    }

    /// Find matching schema for an event. Checks match_field/match_value pairs,
    /// falls back to first catch-all (empty match_field).
    pub async fn find_schema(&self, event: &serde_json::Map<String, serde_json::Value>) -> Option<SchemaMapping> {
        let schemas = self.schemas.read().await;

        // Exact match pass
        for schema in schemas.iter() {
            if schema.match_field.is_empty() || schema.match_value.is_empty() {
                continue; // Skip catch-alls in first pass
            }
            if let Some(val) = event.get(&schema.match_field) {
                if val.as_str() == Some(&schema.match_value) {
                    return Some(schema.clone());
                }
            }
        }

        // Catch-all pass (both match_field and match_value empty)
        schemas.iter()
            .find(|s| s.match_field.is_empty() && s.match_value.is_empty())
            .cloned()
    }

    /// Event-driven reload: watches file for changes using notify (#10).
    /// Only reloads when the file actually changes, not on a poll timer.
    pub async fn watch_loop(&self) {
        use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher, Event, EventKind};
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(4);

        let mut watcher = match RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                        let _ = tx.blocking_send(());
                    }
                }
            },
            Config::default(),
        ) {
            Ok(w) => w,
            Err(e) => { error!("Schema watcher init failed: {}. Hot-reload disabled.", e); return; }
        };

        if let Err(e) = watcher.watch(
            std::path::Path::new(&self.file_path), RecursiveMode::NonRecursive
        ) {
            error!("Schema watch failed: {}. Hot-reload disabled.", e);
            return;
        }

        info!("Schema watcher active on {}", self.file_path);

        // Keep watcher alive and process change events
        loop {
            match rx.recv().await {
                Some(()) => {
                    // Debounce: wait 500ms for writes to settle
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    // Drain any additional events queued during debounce
                    while rx.try_recv().is_ok() {}

                    match std::fs::read_to_string(&self.file_path) {
                        Ok(content) => match serde_yaml::from_str::<SchemasConfig>(&content) {
                            Ok(config) => {
                                let mut schemas = self.schemas.write().await;
                                *schemas = config.schemas;
                                info!("Reloaded {} schemas from {}", schemas.len(), self.file_path);
                            }
                            Err(e) => warn!("Schema parse failed on reload (keeping previous): {}", e),
                        },
                        Err(e) => warn!("Schema read failed on reload: {}", e),
                    }
                }
                None => break,
            }
        }
    }
}
