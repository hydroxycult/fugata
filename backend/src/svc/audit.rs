use crate::errors::Result;
use chrono::Utc;
use serde_json::Value;
use sqlx::Pool;

#[derive(Clone)]
pub struct AuditLogger {
    pool: Pool<sqlx::Any>,
}

#[derive(Debug, Clone, Copy)]
pub enum EventType {
    Create,
    Get,
    Delete,
    Expire,
}

impl EventType {
    fn as_str(&self) -> &'static str {
        match self {
            EventType::Create => "CREATE",
            EventType::Get => "GET",
            EventType::Delete => "DELETE",
            EventType::Expire => "EXPIRE",
        }
    }
}

impl AuditLogger {
    pub fn new(pool: Pool<sqlx::Any>) -> Self {
        Self { pool }
    }

    pub async fn log(
        &self,
        event_type: EventType,
        secret_id: Option<&str>,
        request_id: Option<&str>,
        metadata: Option<Value>,
    ) -> Result<()> {
        let meta_json = metadata.map(|m| m.to_string());

        let query = r#"
            INSERT INTO audit (timestamp, event_type, secret_id, request_id, meta_json)
            VALUES (?, ?, ?, ?, ?)
        "#;

        let now_ts = Utc::now().timestamp();
        sqlx::query(query)
            .bind(now_ts)
            .bind(event_type.as_str())
            .bind(secret_id)
            .bind(request_id)
            .bind(meta_json)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn log_create(&self, secret_id: &str, request_id: &str, ip_hash: &str) -> Result<()> {
        let metadata = serde_json::json!({
            "ip_hash": ip_hash,
        });

        self.log(
            EventType::Create,
            Some(secret_id),
            Some(request_id),
            Some(metadata),
        )
        .await
    }

    pub async fn log_get(
        &self,
        secret_id: &str,
        request_id: &str,
        ip_hash: &str,
        one_time: bool,
    ) -> Result<()> {
        let metadata = serde_json::json!({
            "ip_hash": ip_hash,
            "one_time": one_time,
        });

        self.log(
            EventType::Get,
            Some(secret_id),
            Some(request_id),
            Some(metadata),
        )
        .await
    }

    pub async fn log_delete(&self, secret_id: &str, request_id: &str, ip_hash: &str) -> Result<()> {
        let metadata = serde_json::json!({
            "ip_hash": ip_hash,
        });

        self.log(
            EventType::Delete,
            Some(secret_id),
            Some(request_id),
            Some(metadata),
        )
        .await
    }

    pub async fn log_expire(&self, secret_id: &str) {
        if let Err(e) = self
            .log(EventType::Expire, Some(secret_id), None, None)
            .await
        {
            tracing::error!(
                error = %e,
                secret_id = %secret_id,
                "Failed to log expire event"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::AnyPool;

    async fn setup_test_audit() -> AuditLogger {
        use sqlx::any::install_default_drivers;
        install_default_drivers();

        let pool = AnyPool::connect("sqlite:file::memory:?cache=shared")
            .await
            .unwrap();

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                secret_id TEXT,
                request_id TEXT,
                meta_json TEXT
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        AuditLogger::new(pool)
    }

    #[tokio::test]
    async fn test_log_create() {
        use sqlx::Row;
        let logger = setup_test_audit().await;

        logger
            .log_create("fug_test123", "req_123", "ip_hash_abc")
            .await;

        let row = sqlx::query("SELECT event_type, secret_id FROM audit WHERE secret_id = ?")
            .bind("fug_test123")
            .fetch_one(&logger.pool)
            .await
            .unwrap();

        let event_type: String = row.try_get("event_type").unwrap();
        assert_eq!(event_type, "CREATE");
    }

    #[tokio::test]
    async fn test_log_get() {
        use sqlx::Row;
        let logger = setup_test_audit().await;

        logger
            .log_get("fug_test456", "req_456", "ip_hash_def", true)
            .await;

        let row = sqlx::query("SELECT event_type, meta_json FROM audit WHERE secret_id = ?")
            .bind("fug_test456")
            .fetch_one(&logger.pool)
            .await
            .unwrap();

        let event_type: String = row.try_get("event_type").unwrap();
        let meta_json: String = row.try_get("meta_json").unwrap();

        assert_eq!(event_type, "GET");
        assert!(meta_json.contains("one_time"));
    }
}
