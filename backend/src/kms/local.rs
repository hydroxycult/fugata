use crate::errors::{FugataError, Result};
use crate::kms::Kms;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use async_trait::async_trait;
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::HashMap;
use zeroize::Zeroizing;

pub struct LocalKms {
    kek: Zeroizing<Vec<u8>>,
}

impl LocalKms {
    pub fn new(kek: Vec<u8>) -> Result<Self> {
        if kek.len() != 32 {
            return Err(FugataError::Config(format!(
                "KEK must be 32 bytes, got {}",
                kek.len()
            )));
        }

        Ok(Self {
            kek: Zeroizing::new(kek),
        })
    }

    fn generate_nonce() -> Result<[u8; 12]> {
        let mut nonce = [0u8; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|e| FugataError::Crypto(format!("Failed to generate nonce: {:?}", e)))?;
        Ok(nonce)
    }

    fn context_to_aad(context: &HashMap<String, String>) -> String {
        let mut keys: Vec<_> = context.keys().collect();
        keys.sort();
        keys.iter()
            .map(|k| format!("{}:{}", k, context.get(*k).unwrap()))
            .collect::<Vec<_>>()
            .join("|")
    }
}

#[async_trait]
impl Kms for LocalKms {
    async fn encrypt_dek(&self, dek: &[u8], context: &HashMap<String, String>) -> Result<Vec<u8>> {
        if dek.len() != 32 {
            return Err(FugataError::Crypto(format!(
                "DEK must be 32 bytes, got {}",
                dek.len()
            )));
        }

        let cipher = Aes256Gcm::new_from_slice(&self.kek)
            .map_err(|e| FugataError::Kms(format!("Failed to create cipher: {}", e)))?;

        let nonce_bytes = Self::generate_nonce()?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let aad = Self::context_to_aad(context);
        let payload = Payload {
            msg: dek,
            aad: aad.as_bytes(),
        };

        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|e| FugataError::Kms(format!("DEK encryption failed: {}", e)))?;

        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    async fn decrypt_dek(
        &self,
        encrypted_dek: &[u8],
        context: &HashMap<String, String>,
    ) -> Result<Vec<u8>> {
        if encrypted_dek.len() < 12 {
            return Err(FugataError::Kms("Encrypted DEK too short".into()));
        }

        let cipher = Aes256Gcm::new_from_slice(&self.kek)
            .map_err(|e| FugataError::Kms(format!("Failed to create cipher: {}", e)))?;

        let nonce = Nonce::from_slice(&encrypted_dek[..12]);
        let ciphertext = &encrypted_dek[12..];

        let aad = Self::context_to_aad(context);
        let payload = Payload {
            msg: ciphertext,
            aad: aad.as_bytes(),
        };

        let dek = cipher
            .decrypt(nonce, payload)
            .map_err(|e| FugataError::Kms(format!("DEK decryption failed: {}", e)))?;

        if dek.len() != 32 {
            return Err(FugataError::Kms(format!(
                "Decrypted DEK has wrong length: {}",
                dek.len()
            )));
        }

        Ok(dek)
    }

    async fn health_check(&self) -> Result<()> {
        let test_dek = vec![0u8; 32];
        let mut test_context = HashMap::new();
        test_context.insert("test".to_string(), "health_check".to_string());

        let encrypted = self.encrypt_dek(&test_dek, &test_context).await?;
        let decrypted = self.decrypt_dek(&encrypted, &test_context).await?;

        if decrypted != test_dek {
            return Err(FugataError::Kms(
                "Health check failed: roundtrip mismatch".into(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_local_kms_roundtrip() {
        let kek = vec![0u8; 32];
        let kms = LocalKms::new(kek).unwrap();

        let dek = vec![1u8; 32];
        let mut context = HashMap::new();
        context.insert("secret_id".to_string(), "fug_test123".to_string());
        context.insert("purpose".to_string(), "secret".to_string());

        let encrypted = kms.encrypt_dek(&dek, &context).await.unwrap();
        assert!(encrypted.len() > 32);

        let decrypted = kms.decrypt_dek(&encrypted, &context).await.unwrap();
        assert_eq!(decrypted, dek);
    }

    #[tokio::test]
    async fn test_local_kms_wrong_context_fails() {
        let kek = vec![0u8; 32];
        let kms = LocalKms::new(kek).unwrap();

        let dek = vec![1u8; 32];
        let mut context1 = HashMap::new();
        context1.insert("secret_id".to_string(), "fug_test123".to_string());

        let mut context2 = HashMap::new();
        context2.insert("secret_id".to_string(), "fug_test456".to_string());

        let encrypted = kms.encrypt_dek(&dek, &context1).await.unwrap();
        let result = kms.decrypt_dek(&encrypted, &context2).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_local_kms_health_check() {
        let kek = vec![0u8; 32];
        let kms = LocalKms::new(kek).unwrap();

        assert!(kms.health_check().await.is_ok());
    }

    #[tokio::test]
    async fn test_local_kms_invalid_kek_size() {
        let result = LocalKms::new(vec![0u8; 16]);
        assert!(result.is_err());
    }
}
