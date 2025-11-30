use crate::crypto::EncryptedData;
use crate::errors::{FugataError, Result};
use chrono::{DateTime, Utc};
use sqlx::{Any, AnyPool, Pool, Row};

#[derive(Clone)]
pub struct Database {
    pub pool: Pool<Any>,
}

#[derive(Debug, Clone)]
pub struct Secret {
    pub id: String,
    pub encrypted_dek: Vec<u8>,
    pub encrypted: EncryptedData,
    pub metadata: Option<Vec<u8>>,
    pub one_time: bool,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
    pub deletion_token_hash: String,
}

impl Database {
    pub async fn new(database_url: &str, _max_connections: u32) -> Result<Self> {
        use sqlx::any::install_default_drivers;
        install_default_drivers();

        let pool = AnyPool::connect_with(
            database_url
                .parse()
                .map_err(|e| FugataError::Config(format!("Invalid database URL: {}", e)))?,
        )
        .await
        .map_err(FugataError::Database)?;

        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|e| FugataError::Internal(format!("Migration failed: {}", e)))?;

        Ok(())
    }

    pub async fn create_secret(&self, secret: &Secret) -> Result<()> {
        let query = r#"
            INSERT INTO secrets (
                id, encrypted_dek, ciphertext, nonce, tag, metadata,
                one_time, created_at, expires_at, used, deletion_token_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#;

        sqlx::query(query)
            .bind(&secret.id)
            .bind(&secret.encrypted_dek)
            .bind(&secret.encrypted.ciphertext)
            .bind(&secret.encrypted.nonce)
            .bind(&secret.encrypted.tag)
            .bind(&secret.metadata)
            .bind(secret.one_time)
            .bind(secret.created_at.timestamp())
            .bind(secret.expires_at.timestamp())
            .bind(secret.used)
            .bind(&secret.deletion_token_hash)
            .execute(&self.pool)
            .await
            .map_err(FugataError::Database)?;

        Ok(())
    }

    pub async fn get_secret(&self, secret_id: &str) -> Result<Option<Secret>> {
        let query = r#"
            SELECT id, encrypted_dek, ciphertext, nonce, tag, metadata,
                   one_time, created_at, expires_at, used, deletion_token_hash
            FROM secrets
            WHERE id = ? AND expires_at > ?
        "#;

        let now_ts = Utc::now().timestamp();
        let row = sqlx::query(query)
            .bind(secret_id)
            .bind(now_ts)
            .fetch_optional(&self.pool)
            .await
            .map_err(FugataError::Database)?;

        if let Some(row) = row {
            let created_ts: i64 = row.try_get("created_at")?;
            let expires_ts: i64 = row.try_get("expires_at")?;

            let metadata: Option<Vec<u8>> = match row.try_get("metadata") {
                Ok(data) => data,
                Err(_) => None,
            };

            let one_time: bool = match row.try_get::<i64, _>("one_time") {
                Ok(val) => val != 0,
                Err(_) => row.try_get("one_time")?,
            };

            let used: bool = match row.try_get::<i64, _>("used") {
                Ok(val) => val != 0,
                Err(_) => row.try_get("used")?,
            };

            let secret = Secret {
                id: row.try_get("id")?,
                encrypted_dek: row.try_get("encrypted_dek")?,
                encrypted: EncryptedData {
                    ciphertext: row.try_get("ciphertext")?,
                    nonce: row.try_get("nonce")?,
                    tag: row.try_get("tag")?,
                },
                metadata,
                one_time,
                created_at: DateTime::from_timestamp(created_ts, 0).unwrap(),
                expires_at: DateTime::from_timestamp(expires_ts, 0).unwrap(),
                used,
                deletion_token_hash: row.try_get("deletion_token_hash")?,
            };

            Ok(Some(secret))
        } else {
            Ok(None)
        }
    }

    pub async fn mark_used(&self, secret_id: &str) -> Result<()> {
        let query = "UPDATE secrets SET used = TRUE WHERE id = ?";

        sqlx::query(query)
            .bind(secret_id)
            .execute(&self.pool)
            .await
            .map_err(FugataError::Database)?;

        Ok(())
    }

    pub async fn delete_secret(&self, secret_id: &str) -> Result<bool> {
        let query = "DELETE FROM secrets WHERE id = ?";

        let result = sqlx::query(query)
            .bind(secret_id)
            .execute(&self.pool)
            .await
            .map_err(FugataError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn cleanup_expired(&self) -> Result<u64> {
        let query = "DELETE FROM secrets WHERE expires_at < ?";

        let now_ts = Utc::now().timestamp();
        let result = sqlx::query(query)
            .bind(now_ts)
            .execute(&self.pool)
            .await
            .map_err(FugataError::Database)?;

        Ok(result.rows_affected())
    }

    pub async fn health_check(&self) -> Result<()> {
        sqlx::query("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .map_err(FugataError::Database)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_test_db() -> Database {
        use sqlx::any::install_default_drivers;
        install_default_drivers();

        let pool = AnyPool::connect("sqlite:file::memory:?cache=shared")
            .await
            .expect("Failed to connect to in-memory database");

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS secrets (
                id TEXT PRIMARY KEY,
                encrypted_dek BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                nonce BLOB NOT NULL,
                tag BLOB NOT NULL,
                metadata BLOB,
                one_time INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                deletion_token_hash TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .expect("Failed to create secrets table");

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_secrets_expires_at ON secrets(expires_at)")
            .execute(&pool)
            .await
            .expect("Failed to create index");

        Database { pool }
    }

    #[tokio::test]
    async fn test_create_and_get_secret() {
        let db = setup_test_db().await;

        let secret = Secret {
            id: "fug_test123".to_string(),
            encrypted_dek: vec![1, 2, 3],
            encrypted: EncryptedData {
                ciphertext: vec![4, 5, 6],
                nonce: vec![7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
                tag: vec![
                    19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
                ],
            },
            metadata: None,
            one_time: false,
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            used: false,
            deletion_token_hash: "hash123".to_string(),
        };

        db.create_secret(&secret).await.unwrap();

        let retrieved = db.get_secret("fug_test123").await.unwrap().unwrap();
        assert_eq!(retrieved.id, "fug_test123");
        assert_eq!(retrieved.encrypted.ciphertext, vec![4, 5, 6]);
    }

    #[tokio::test]
    async fn test_get_nonexistent_secret() {
        let db = setup_test_db().await;

        let result = db.get_secret("fug_nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_secret() {
        let db = setup_test_db().await;

        let secret = Secret {
            id: "fug_test456".to_string(),
            encrypted_dek: vec![1],
            encrypted: EncryptedData {
                ciphertext: vec![2],
                nonce: vec![0; 12],
                tag: vec![0; 16],
            },
            metadata: None,
            one_time: false,
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            used: false,
            deletion_token_hash: "hash".to_string(),
        };

        db.create_secret(&secret).await.unwrap();

        let deleted = db.delete_secret("fug_test456").await.unwrap();
        assert!(deleted);

        let result = db.get_secret("fug_test456").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_mark_used() {
        let db = setup_test_db().await;

        let secret = Secret {
            id: "fug_onetime".to_string(),
            encrypted_dek: vec![1],
            encrypted: EncryptedData {
                ciphertext: vec![2],
                nonce: vec![0; 12],
                tag: vec![0; 16],
            },
            metadata: None,
            one_time: true,
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            used: false,
            deletion_token_hash: "hash".to_string(),
        };

        db.create_secret(&secret).await.unwrap();

        db.mark_used("fug_onetime").await.unwrap();

        let retrieved = db.get_secret("fug_onetime").await.unwrap().unwrap();
        assert!(retrieved.used);
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let db = setup_test_db().await;

        let expired = Secret {
            id: "fug_expired".to_string(),
            encrypted_dek: vec![1],
            encrypted: EncryptedData {
                ciphertext: vec![2],
                nonce: vec![0; 12],
                tag: vec![0; 16],
            },
            metadata: None,
            one_time: false,
            created_at: Utc::now() - chrono::Duration::hours(2),
            expires_at: Utc::now() - chrono::Duration::hours(1),
            used: false,
            deletion_token_hash: "hash".to_string(),
        };

        db.create_secret(&expired).await.unwrap();

        let cleaned = db.cleanup_expired().await.unwrap();
        assert_eq!(cleaned, 1);

        let result = db.get_secret("fug_expired").await.unwrap();
        assert!(result.is_none());
    }
}
