use crate::config::Config;
use crate::crypto::{self, EncryptedData};
use crate::errors::{FugataError, Result};
use crate::kms::{self, Kms};
use crate::svc::audit::AuditLogger;
use crate::svc::cache::{ReplayCache, SecretCache};
use crate::svc::db::{Database, Secret};
use crate::svc::hasher::HasherPool;
use crate::util;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct SecretService {
    db: Database,
    kms: Arc<dyn Kms>,
    hasher: Arc<HasherPool>,
    secret_cache: SecretCache,
    replay_cache: ReplayCache,
    audit: AuditLogger,
    config: Arc<Config>,
}

#[derive(Debug, Deserialize)]
pub struct CreateSecretRequest {
    pub content: String,
    #[serde(default)]
    pub duration: Option<String>,
    #[serde(default)]
    pub one_time: bool,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct CreateSecretResponse {
    pub id: String,
    pub deletion_token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct GetSecretResponse {
    pub id: String,
    pub content: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct DeleteSecretResponse {
    pub message: String,
}

impl SecretService {
    pub fn new(
        db: Database,
        kms: Arc<dyn Kms>,
        hasher: Arc<HasherPool>,
        secret_cache: SecretCache,
        replay_cache: ReplayCache,
        audit: AuditLogger,
        config: Arc<Config>,
    ) -> Self {
        Self {
            db,
            kms,
            hasher,
            secret_cache,
            replay_cache,
            audit,
            config,
        }
    }

    pub async fn create_secret(
        &self,
        req: CreateSecretRequest,
        ip: &str,
        request_id: &str,
    ) -> Result<CreateSecretResponse> {
        if req.content.len() > self.config.max_secret_size {
            return Err(FugataError::BadRequest(format!(
                "Content too large: {} bytes (max: {})",
                req.content.len(),
                self.config.max_secret_size
            )));
        }

        let duration = req.duration.as_deref().unwrap_or("1h");
        if !self.config.ttl_presets.contains(&duration.to_string()) {
            return Err(FugataError::BadRequest(format!(
                "Invalid duration '{}'. Allowed: {}",
                duration,
                self.config.ttl_presets.join(", ")
            )));
        }

        let duration_parsed = Config::parse_duration(duration)?;

        let id = util::generate_secret_id()?;
        let deletion_token = util::generate_deletion_token()?;

        let token_hash = self.hasher.hash(&deletion_token).await?;

        let dek = crypto::generate_dek()?;
        let aad = util::build_aad(&id, "secret");
        let encrypted_content = crypto::encrypt(req.content.as_bytes(), &dek, &aad)?;

        let encrypted_metadata = if let Some(meta) = &req.metadata {
            let meta_bytes = serde_json::to_vec(meta)
                .map_err(|e| FugataError::BadRequest(format!("Invalid metadata: {}", e)))?;
            let meta_aad = util::build_aad(&id, "metadata");
            let encrypted_meta = crypto::encrypt(&meta_bytes, &dek, &meta_aad)?;
            Some(serde_json::to_vec(&encrypted_meta).unwrap())
        } else {
            None
        };

        let context = kms::build_context(&id, "dek");
        let encrypted_dek = self.kms.encrypt_dek(&dek, &context).await?;

        drop(dek);

        let created_at = Utc::now();
        let expires_at = created_at + duration_parsed;

        let secret = Secret {
            id: id.clone(),
            encrypted_dek: encrypted_dek.clone(),
            encrypted: encrypted_content.clone(),
            metadata: encrypted_metadata.clone(),
            one_time: req.one_time,
            created_at,
            expires_at,
            used: false,
            deletion_token_hash: token_hash.clone(),
        };

        let ip_hash = util::hash_ip(ip, &self.config.ip_hash_key);
        self.audit.log_create(&id, request_id, &ip_hash).await?;

        self.db.create_secret(&secret).await?;

        self.secret_cache.put(
            id.clone(),
            encrypted_content,
            encrypted_dek.clone(),
            token_hash.clone(),
            created_at,
            expires_at,
            req.one_time,
            false,
            encrypted_metadata.clone(),
        );

        tracing::info!(
            secret_id = %id,
            request_id = %request_id,
            one_time = req.one_time,
            "Secret created"
        );

        Ok(CreateSecretResponse {
            id,
            deletion_token,
            expires_at,
        })
    }

    pub async fn get_secret(
        &self,
        secret_id: &str,
        ip: &str,
        request_id: &str,
    ) -> Result<GetSecretResponse> {
        util::validate_secret_id(secret_id)?;

        let secret = if let Some(cached) = self.secret_cache.get(secret_id) {
            let (
                encrypted,
                encrypted_dek,
                token_hash,
                created_at,
                expires_at,
                one_time,
                used,
                metadata,
            ) = cached;

            if one_time && used {
                return Err(FugataError::NotFound(
                    "Secret has been accessed and is no longer available".into(),
                ));
            }

            Secret {
                id: secret_id.to_string(),
                encrypted_dek,
                encrypted,
                metadata,
                one_time,
                created_at,
                expires_at,
                used,
                deletion_token_hash: token_hash,
            }
        } else {
            let secret = self
                .db
                .get_secret(secret_id)
                .await?
                .ok_or_else(|| FugataError::NotFound("Secret not found or expired".into()))?;

            if secret.one_time && secret.used {
                return Err(FugataError::NotFound(
                    "Secret has been accessed and is no longer available".into(),
                ));
            }

            secret
        };

        let context = kms::build_context(secret_id, "dek");
        let dek = self
            .kms
            .decrypt_dek(&secret.encrypted_dek, &context)
            .await?;
        let dek = Zeroizing::new(dek);

        let aad = util::build_aad(secret_id, "secret");
        let plaintext = crypto::decrypt(&secret.encrypted, &dek, &aad)?;

        let metadata = if let Some(encrypted_meta_bytes) = &secret.metadata {
            let encrypted_meta: EncryptedData = serde_json::from_slice(encrypted_meta_bytes)
                .map_err(|e| {
                    FugataError::Internal(format!("Failed to parse encrypted metadata: {}", e))
                })?;

            let meta_aad = util::build_aad(secret_id, "metadata");
            let meta_bytes = crypto::decrypt(&encrypted_meta, &dek, &meta_aad)?;
            let meta: serde_json::Value = serde_json::from_slice(&meta_bytes)
                .map_err(|e| FugataError::Internal(format!("Failed to parse metadata: {}", e)))?;
            Some(meta)
        } else {
            None
        };

        drop(dek);

        if secret.one_time {
            self.db.mark_used(secret_id).await?;
            self.secret_cache.invalidate(secret_id);
        }

        let ip_hash = util::hash_ip(ip, &self.config.ip_hash_key);
        self.audit
            .log_get(secret_id, request_id, &ip_hash, secret.one_time)
            .await?;

        let content = String::from_utf8(plaintext)
            .map_err(|_| FugataError::Internal("Secret content is not valid UTF-8".into()))?;

        tracing::info!(
            secret_id = %secret_id,
            request_id = %request_id,
            one_time = secret.one_time,
            "Secret retrieved"
        );

        Ok(GetSecretResponse {
            id: secret.id,
            content,
            created_at: secret.created_at,
            expires_at: secret.expires_at,
            metadata,
        })
    }

    pub async fn delete_secret(
        &self,
        secret_id: &str,
        deletion_token: &str,
        ip: &str,
        request_id: &str,
    ) -> Result<DeleteSecretResponse> {
        util::validate_secret_id(secret_id)?;
        util::validate_deletion_token(deletion_token)?;

        let token_hash = self.hasher.hash(deletion_token).await?;

        if self.replay_cache.is_used(&token_hash) {
            return Err(FugataError::Unauthorized(
                "Token has already been used".into(),
            ));
        }

        let secret = self
            .db
            .get_secret(secret_id)
            .await?
            .ok_or_else(|| FugataError::NotFound("Secret not found or expired".into()))?;

        let valid = self
            .hasher
            .verify(deletion_token, &secret.deletion_token_hash)
            .await?;

        if !valid {
            return Err(FugataError::Unauthorized("Invalid deletion token".into()));
        }

        let deleted = self.db.delete_secret(secret_id).await?;

        if !deleted {
            return Err(FugataError::NotFound("Secret not found".into()));
        }

        self.secret_cache.invalidate(secret_id);

        let replay_expiry =
            Utc::now() + chrono::Duration::hours(self.config.token_replay_ttl_hours as i64);
        self.replay_cache.mark_used(token_hash, replay_expiry);

        let ip_hash = util::hash_ip(ip, &self.config.ip_hash_key);
        self.audit
            .log_delete(secret_id, request_id, &ip_hash)
            .await?;

        tracing::info!(
            secret_id = %secret_id,
            request_id = %request_id,
            "Secret deleted"
        );

        Ok(DeleteSecretResponse {
            message: "Secret deleted successfully".to_string(),
        })
    }

    pub async fn health_check(&self) -> Result<()> {
        self.db.health_check().await?;
        self.kms.health_check().await?;
        Ok(())
    }

    pub async fn cleanup_expired_secrets(&self) -> Result<u64> {
        let count = self.db.cleanup_expired().await?;

        if count > 0 {
            tracing::info!(count = %count, "Cleaned up expired secrets");
        }

        Ok(count)
    }

    pub fn cleanup_replay_cache(&self) {
        let before = self.replay_cache.len();
        self.replay_cache.cleanup();
        let after = self.replay_cache.len();

        if before != after {
            tracing::debug!(removed = before - after, "Cleaned up replay cache entries");
        }
    }
}
