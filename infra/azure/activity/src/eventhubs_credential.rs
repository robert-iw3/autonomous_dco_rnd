use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use azure_core_eventhubs::credentials::{AccessToken, TokenCredential, TokenRequestOptions};
use azure_identity_eventhubs::{DeveloperToolsCredential, ManagedIdentityCredential};

pub struct EventHubsCredentialChain {
    sources: Vec<Arc<dyn TokenCredential>>,
    cached_source_index: AtomicUsize,
}

impl EventHubsCredentialChain {
    pub fn new() -> azure_core_eventhubs::Result<Arc<dyn TokenCredential>> {
        let sources: Vec<Arc<dyn TokenCredential>> = vec![
            ManagedIdentityCredential::new(None)?,
            DeveloperToolsCredential::new(None)?,
        ];
        Ok(Arc::new(Self {
            sources,
            cached_source_index: AtomicUsize::new(usize::MAX),
        }))
    }
}

impl fmt::Debug for EventHubsCredentialChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventHubsCredentialChain").finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl TokenCredential for EventHubsCredentialChain {
    async fn get_token(
        &self,
        scopes: &[&str],
        options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core_eventhubs::Result<AccessToken> {
        let cached = self.cached_source_index.load(Ordering::Relaxed);
        if cached != usize::MAX {
            return self.sources[cached].get_token(scopes, options).await;
        }

        let mut last_err = None;
        for (index, source) in self.sources.iter().enumerate() {
            match source.get_token(scopes, options.clone()).await {
                Ok(token) => {
                    self.cached_source_index.store(index, Ordering::Relaxed);
                    return Ok(token);
                }
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.expect("EventHubsCredentialChain::sources is non-empty"))
    }
}