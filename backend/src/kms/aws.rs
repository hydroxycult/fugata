use crate::errors::{FugataError, Result};
use crate::kms::Kms;
use async_trait::async_trait;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::Client;
use std::collections::HashMap;

pub struct AwsKms {
    client: Client,
    key_id: String,
}

impl AwsKms {
    pub async fn new(region: String, key_id: String) -> Result<Self> {
        let config = aws_config::from_env()
            .region(aws_config::Region::new(region))
            .load()
            .await;

        let client = Client::new(&config);

        Ok(Self { client, key_id })
    }

    fn build_encryption_context(context: &HashMap<String, String>) -> HashMap<String, String> {
        context.clone()
    }
}

#[async_trait]
impl Kms for AwsKms {
    async fn encrypt_dek(&self, dek: &[u8], context: &HashMap<String, String>) -> Result<Vec<u8>> {
        if dek.len() != 32 {
            return Err(FugataError::Crypto(format!(
                "DEK must be 32 bytes, got {}",
                dek.len()
            )));
        }

        let encryption_context = Self::build_encryption_context(context);

        let response = self
            .client
            .encrypt()
            .key_id(&self.key_id)
            .plaintext(Blob::new(dek))
            .set_encryption_context(Some(encryption_context))
            .send()
            .await
            .map_err(|e| FugataError::Kms(format!("AWS KMS encrypt failed: {}", e)))?;

        let ciphertext = response
            .ciphertext_blob()
            .ok_or_else(|| FugataError::Kms("AWS KMS returned no ciphertext".into()))?;

        Ok(ciphertext.as_ref().to_vec())
    }

    async fn decrypt_dek(
        &self,
        encrypted_dek: &[u8],
        context: &HashMap<String, String>,
    ) -> Result<Vec<u8>> {
        let encryption_context = Self::build_encryption_context(context);

        let response = self
            .client
            .decrypt()
            .key_id(&self.key_id)
            .ciphertext_blob(Blob::new(encrypted_dek))
            .set_encryption_context(Some(encryption_context))
            .send()
            .await
            .map_err(|e| FugataError::Kms(format!("AWS KMS decrypt failed: {}", e)))?;

        let plaintext = response
            .plaintext()
            .ok_or_else(|| FugataError::Kms("AWS KMS returned no plaintext".into()))?;

        let dek = plaintext.as_ref().to_vec();

        if dek.len() != 32 {
            return Err(FugataError::Kms(format!(
                "Decrypted DEK has wrong length: {}",
                dek.len()
            )));
        }

        Ok(dek)
    }

    async fn health_check(&self) -> Result<()> {
        self.client
            .describe_key()
            .key_id(&self.key_id)
            .send()
            .await
            .map_err(|e| FugataError::Kms(format!("AWS KMS health check failed: {}", e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_encryption_context() {
        let mut context = HashMap::new();
        context.insert("secret_id".to_string(), "fug_test123".to_string());
        context.insert("purpose".to_string(), "secret".to_string());

        let aws_context = AwsKms::build_encryption_context(&context);

        assert_eq!(aws_context.len(), 2);
        assert_eq!(aws_context.get("secret_id").unwrap(), "fug_test123");
        assert_eq!(aws_context.get("purpose").unwrap(), "secret");
    }
}
