use crate::errors::Result;
use async_trait::async_trait;
use std::collections::HashMap;

pub mod local;
pub mod vault;

#[cfg(feature = "aws-kms")]
pub mod aws;

#[async_trait]
pub trait Kms: Send + Sync {
    async fn encrypt_dek(&self, dek: &[u8], context: &HashMap<String, String>) -> Result<Vec<u8>>;

    async fn decrypt_dek(
        &self,
        encrypted_dek: &[u8],
        context: &HashMap<String, String>,
    ) -> Result<Vec<u8>>;

    async fn health_check(&self) -> Result<()>;
}

pub fn build_context(secret_id: &str, purpose: &str) -> HashMap<String, String> {
    let mut context = HashMap::new();
    context.insert("secret_id".to_string(), secret_id.to_string());
    context.insert("purpose".to_string(), purpose.to_string());
    context
}
