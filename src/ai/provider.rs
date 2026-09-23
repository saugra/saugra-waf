use crate::ai::types::{ExplanationInput, ProviderOutput};
use async_trait::async_trait;

#[async_trait]
pub trait ExplanationProvider: Send + Sync {
    fn name(&self) -> &str;
    fn model(&self) -> &str;
    async fn explain(&self, input: &ExplanationInput) -> anyhow::Result<ProviderOutput>;
}
