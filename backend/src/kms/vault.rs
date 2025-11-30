use crate::errors::{FugataError, Result};
use crate::kms::Kms;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

pub struct VaultKms {
    client: reqwest::Client,
    addr: String,
    token: String,
    mount: String,
    key_name: String,
}

#[derive(Serialize, Clone)]
struct EncryptRequest {
    plaintext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<String>,
}

#[derive(Deserialize)]
struct EncryptResponse {
    data: EncryptResponseData,
}

#[derive(Deserialize)]
struct EncryptResponseData {
    ciphertext: String,
}

#[derive(Serialize, Clone)]
struct DecryptRequest {
    ciphertext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<String>,
}

#[derive(Deserialize)]
struct DecryptResponse {
    data: DecryptResponseData,
}

#[derive(Deserialize)]
struct DecryptResponseData {
    plaintext: String,
}

impl VaultKms {
    pub fn new(addr: String, token: String, mount: String, key_name: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        Self {
            client,
            addr,
            token,
            mount,
            key_name,
        }
    }

    fn context_to_base64(context: &HashMap<String, String>) -> Result<String> {
        use base64::Engine;
        let json = serde_json::to_string(context)
            .map_err(|e| FugataError::Kms(format!("Failed to serialize context: {}", e)))?;
        Ok(base64::engine::general_purpose::STANDARD.encode(json.as_bytes()))
    }

    async fn retry<F, T>(&self, mut operation: F) -> Result<T>
    where
        F: FnMut() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T>> + Send>>,
    {
        let mut retries = 0;
        let max_retries = 3;
        let mut delay = Duration::from_millis(100);

        loop {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    retries += 1;
                    if retries >= max_retries {
                        return Err(e);
                    }

                    tracing::warn!(
                        error = %e,
                        retry = retries,
                        delay_ms = delay.as_millis(),
                        "KMS operation failed, retrying"
                    );

                    tokio::time::sleep(delay).await;
                    delay *= 2;
                }
            }
        }
    }
}

#[async_trait]
impl Kms for VaultKms {
    async fn encrypt_dek(&self, dek: &[u8], context: &HashMap<String, String>) -> Result<Vec<u8>> {
        if dek.len() != 32 {
            return Err(FugataError::Crypto(format!(
                "DEK must be 32 bytes, got {}",
                dek.len()
            )));
        }

        use base64::Engine;
        let plaintext_b64 = base64::engine::general_purpose::STANDARD.encode(dek);
        let context_b64 = Self::context_to_base64(context)?;

        let url = format!("{}/v1/{}/encrypt/{}", self.addr, self.mount, self.key_name);

        let request_body = EncryptRequest {
            plaintext: plaintext_b64,
            context: Some(context_b64),
        };

        let encrypted_dek = self
            .retry(|| {
                let url = url.clone();
                let token = self.token.clone();
                let request_body = request_body.clone();
                let client = self.client.clone();

                Box::pin(async move {
                    let response = client
                        .post(&url)
                        .header("X-Vault-Token", token)
                        .json(&request_body)
                        .send()
                        .await
                        .map_err(|e| FugataError::Kms(format!("Vault request failed: {}", e)))?;

                    if !response.status().is_success() {
                        let status = response.status();
                        let body = response.text().await.unwrap_or_default();
                        return Err(FugataError::Kms(format!(
                            "Vault encrypt failed: {} - {}",
                            status, body
                        )));
                    }

                    let resp: EncryptResponse = response.json().await.map_err(|e| {
                        FugataError::Kms(format!("Failed to parse Vault response: {}", e))
                    })?;

                    Ok(resp.data.ciphertext.into_bytes())
                })
            })
            .await?;

        Ok(encrypted_dek)
    }

    async fn decrypt_dek(
        &self,
        encrypted_dek: &[u8],
        context: &HashMap<String, String>,
    ) -> Result<Vec<u8>> {
        let ciphertext = String::from_utf8(encrypted_dek.to_vec())
            .map_err(|e| FugataError::Kms(format!("Invalid ciphertext encoding: {}", e)))?;

        let context_b64 = Self::context_to_base64(context)?;

        let url = format!("{}/v1/{}/decrypt/{}", self.addr, self.mount, self.key_name);

        let request_body = DecryptRequest {
            ciphertext,
            context: Some(context_b64),
        };

        let plaintext_b64 = self
            .retry(|| {
                let url = url.clone();
                let token = self.token.clone();
                let request_body = request_body.clone();
                let client = self.client.clone();

                Box::pin(async move {
                    let response = client
                        .post(&url)
                        .header("X-Vault-Token", token)
                        .json(&request_body)
                        .send()
                        .await
                        .map_err(|e| FugataError::Kms(format!("Vault request failed: {}", e)))?;

                    if !response.status().is_success() {
                        let status = response.status();
                        let body = response.text().await.unwrap_or_default();
                        return Err(FugataError::Kms(format!(
                            "Vault decrypt failed: {} - {}",
                            status, body
                        )));
                    }

                    let resp: DecryptResponse = response.json().await.map_err(|e| {
                        FugataError::Kms(format!("Failed to parse Vault response: {}", e))
                    })?;

                    Ok(resp.data.plaintext)
                })
            })
            .await?;

        use base64::Engine;
        let dek = base64::engine::general_purpose::STANDARD
            .decode(&plaintext_b64)
            .map_err(|e| FugataError::Kms(format!("Failed to decode DEK: {}", e)))?;

        if dek.len() != 32 {
            return Err(FugataError::Kms(format!(
                "Decrypted DEK has wrong length: {}",
                dek.len()
            )));
        }

        Ok(dek)
    }

    async fn health_check(&self) -> Result<()> {
        let url = format!("{}/v1/sys/health", self.addr);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| FugataError::Kms(format!("Vault health check failed: {}", e)))?;

        if !response.status().is_success() && response.status().as_u16() != 429 {
            return Err(FugataError::Kms(format!(
                "Vault unhealthy: {}",
                response.status()
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_kms_creation() {
        let kms = VaultKms::new(
            "https://vault.example.com:8200".to_string(),
            "test-token".to_string(),
            "transit".to_string(),
            "fugata-kek".to_string(),
        );

        assert_eq!(kms.addr, "https://vault.example.com:8200");
        assert_eq!(kms.mount, "transit");
    }

    #[test]
    fn test_context_to_base64() {
        let mut context = HashMap::new();
        context.insert("secret_id".to_string(), "fug_test123".to_string());
        context.insert("purpose".to_string(), "secret".to_string());

        let result = VaultKms::context_to_base64(&context).unwrap();
        assert!(!result.is_empty());

        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&result)
            .unwrap();
        let json: HashMap<String, String> = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(json.get("secret_id").unwrap(), "fug_test123");
    }
}
