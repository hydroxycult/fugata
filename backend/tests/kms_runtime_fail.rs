use fugata::{
    config::Config,
    kms::{local::LocalKms, Kms},
    svc::{
        audit::AuditLogger,
        cache::{ReplayCache, SecretCache},
        db::Database,
        hasher::HasherPool,
        service::{CreateSecretRequest, SecretService},
    },
};
use std::sync::Arc;

struct FailingKms;

#[async_trait::async_trait]
impl Kms for FailingKms {
    async fn encrypt_dek(
        &self,
        _dek: &[u8],
        _context: &std::collections::HashMap<String, String>,
    ) -> fugata::errors::Result<Vec<u8>> {
        Err(fugata::errors::FugataError::Kms(
            "KMS unavailable".to_string(),
        ))
    }

    async fn decrypt_dek(
        &self,
        _encrypted_dek: &[u8],
        _context: &std::collections::HashMap<String, String>,
    ) -> fugata::errors::Result<Vec<u8>> {
        Err(fugata::errors::FugataError::Kms(
            "KMS unavailable".to_string(),
        ))
    }

    async fn health_check(&self) -> fugata::errors::Result<()> {
        Err(fugata::errors::FugataError::Kms(
            "KMS unavailable".to_string(),
        ))
    }
}

async fn setup_test_db(db_name: &str) -> Database {
    use sqlx::any::install_default_drivers;
    install_default_drivers();

    let connection_string = format!("sqlite:file:{}?mode=memory&cache=shared", db_name);
    let pool = sqlx::AnyPool::connect(&connection_string)
        .await
        .expect("Failed to connect");

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

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            secret_id TEXT,
            request_id TEXT,
            meta_json TEXT
        )",
    )
    .execute(&pool)
    .await
    .expect("Failed to create audit table");

    Database { pool }
}

async fn setup_failing_kms_service(db_name: &str) -> (Arc<SecretService>, Database) {
    let db = setup_test_db(db_name).await;
    let db_clone = Database {
        pool: db.pool.clone(),
    };
    let kms: Arc<dyn Kms> = Arc::new(FailingKms);

    let hasher = Arc::new(HasherPool::new(2, 10, [0u8; 32], 1, 8192, 1).unwrap());

    let secret_cache = SecretCache::new(100);
    let replay_cache = ReplayCache::new();
    let audit = AuditLogger::new(db.pool.clone());

    let config = Arc::new(Config {
        port: 8080,
        environment: "test".to_string(),
        log_level: "debug".to_string(),
        database_url: "sqlite:file:kms_test_db?mode=memory&cache=shared".to_string(),
        db_max_connections: 5,
        db_query_timeout_secs: 10,
        pepper: [0u8; 32],
        ip_hash_key: [1u8; 32],
        argon2_time: 1,
        argon2_memory: 8192,
        argon2_parallelism: 1,
        argon2_keylen: 32,
        hasher_worker_count: 2,
        hasher_queue_size: 10,
        rate_limit_rpm: 60,
        rate_limit_burst: 10,
        lru_cache_size: 100,
        max_secret_size: 10 * 1024 * 1024,
        ttl_presets: vec!["5m".into(), "1h".into(), "24h".into()],
        deletion_token_expiry_hours: 24,
        token_replay_ttl_hours: 1,
        kms_provider: fugata::config::KmsProvider::Local { key: vec![0u8; 32] },
        kms_fail_closed: true,
        trusted_proxies: vec![],
        proxy_mode: fugata::config::ProxyMode::Direct,
        allowed_origins: vec![],
    });

    let service = Arc::new(SecretService::new(
        db,
        kms,
        hasher,
        secret_cache,
        replay_cache,
        audit,
        config,
    ));

    (service, db_clone)
}

async fn setup_working_kms_service(db_name: &str) -> (Arc<SecretService>, Database) {
    let db = setup_test_db(db_name).await;
    let db_clone = Database {
        pool: db.pool.clone(),
    };
    let kek = vec![0u8; 32];
    let kms: Arc<dyn Kms> = Arc::new(LocalKms::new(kek).unwrap());

    let hasher = Arc::new(HasherPool::new(2, 10, [0u8; 32], 1, 8192, 1).unwrap());

    let secret_cache = SecretCache::new(100);
    let replay_cache = ReplayCache::new();
    let audit = AuditLogger::new(db.pool.clone());

    let config = Arc::new(Config {
        port: 8080,
        environment: "test".to_string(),
        log_level: "debug".to_string(),
        database_url: "sqlite:file:kms_test_db?mode=memory&cache=shared".to_string(),
        db_max_connections: 5,
        db_query_timeout_secs: 10,
        pepper: [0u8; 32],
        ip_hash_key: [1u8; 32],
        argon2_time: 1,
        argon2_memory: 8192,
        argon2_parallelism: 1,
        argon2_keylen: 32,
        hasher_worker_count: 2,
        hasher_queue_size: 10,
        rate_limit_rpm: 60,
        rate_limit_burst: 10,
        lru_cache_size: 100,
        max_secret_size: 10 * 1024 * 1024,
        ttl_presets: vec!["5m".into(), "1h".into(), "24h".into()],
        deletion_token_expiry_hours: 24,
        token_replay_ttl_hours: 1,
        kms_provider: fugata::config::KmsProvider::Local { key: vec![0u8; 32] },
        kms_fail_closed: true,
        trusted_proxies: vec![],
        proxy_mode: fugata::config::ProxyMode::Direct,
        allowed_origins: vec![],
    });

    let service = Arc::new(SecretService::new(
        db,
        kms,
        hasher,
        secret_cache,
        replay_cache,
        audit,
        config,
    ));

    (service, db_clone)
}

#[tokio::test]
async fn encrypt_fails_with_kms_error_no_side_effects() {
    let (service, db) = setup_failing_kms_service("encrypt_fail_test").await;

    let create_req = CreateSecretRequest {
        content: "test secret".to_string(),
        duration: Some("1h".to_string()),
        one_time: false,
        metadata: None,
    };

    let result = service
        .create_secret(create_req, "127.0.0.1", "req_kms_fail_1")
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, fugata::errors::FugataError::Kms(_)));

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM secrets")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(count, 0, "No secrets should exist in DB after KMS failure");

    let audit_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit WHERE event_type = 'create'")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(
        audit_count, 0,
        "No create audit events should exist after KMS failure"
    );
}

#[tokio::test]
async fn decrypt_fails_with_kms_error_no_mutation() {
    let (working_service, working_db) = setup_working_kms_service("decrypt_fail_test").await;

    let create_req = CreateSecretRequest {
        content: "test secret".to_string(),
        duration: Some("1h".to_string()),
        one_time: true,
        metadata: None,
    };

    let create_resp = working_service
        .create_secret(create_req, "127.0.0.1", "req_kms_setup")
        .await
        .unwrap();

    let secret_id = create_resp.id.clone();

    let used_before: i64 = sqlx::query_scalar("SELECT used FROM secrets WHERE id = ?")
        .bind(&secret_id)
        .fetch_one(&working_db.pool)
        .await
        .unwrap();
    assert_eq!(
        used_before, 0,
        "Secret should not be marked as used initially"
    );

    let (failing_service, failing_db) = setup_failing_kms_service("decrypt_fail_test").await;

    let result = failing_service
        .get_secret(&secret_id, "127.0.0.1", "req_kms_fail_get")
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, fugata::errors::FugataError::Kms(_)));

    let used_after: i64 = sqlx::query_scalar("SELECT used FROM secrets WHERE id = ?")
        .bind(&secret_id)
        .fetch_one(&failing_db.pool)
        .await
        .unwrap();
    assert_eq!(
        used_after, 0,
        "Secret must not be marked as used after KMS failure"
    );

    let get_audit_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit WHERE event_type = 'get' AND secret_id = ?")
            .bind(&secret_id)
            .fetch_one(&failing_db.pool)
            .await
            .unwrap();
    assert_eq!(
        get_audit_count, 0,
        "No get audit events should exist after KMS failure"
    );
}

#[tokio::test]
async fn delete_does_not_use_kms() {
    let (working_service, _working_db) = setup_working_kms_service("delete_test").await;

    let create_req = CreateSecretRequest {
        content: "test secret".to_string(),
        duration: Some("1h".to_string()),
        one_time: false,
        metadata: None,
    };

    let create_resp = working_service
        .create_secret(create_req, "127.0.0.1", "req_delete_setup")
        .await
        .unwrap();

    let (failing_service, failing_db) = setup_failing_kms_service("delete_test").await;

    let result = failing_service
        .delete_secret(
            &create_resp.id,
            &create_resp.deletion_token,
            "127.0.0.1",
            "req_delete_kms_fail",
        )
        .await;

    assert!(result.is_ok());

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM secrets WHERE id = ?")
        .bind(&create_resp.id)
        .fetch_one(&failing_db.pool)
        .await
        .unwrap();
    assert_eq!(count, 0, "Secret should be deleted");
}

#[tokio::test]
async fn kms_error_returns_503() {
    let (service, _db) = setup_failing_kms_service("503_test").await;

    let create_req = CreateSecretRequest {
        content: "test".to_string(),
        duration: Some("1h".to_string()),
        one_time: false,
        metadata: None,
    };

    let result = service
        .create_secret(create_req, "127.0.0.1", "req_503_test")
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();

    assert!(matches!(err, fugata::errors::FugataError::Kms(_)));

    assert_eq!(
        err.status_code(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "KMS errors must return 503 SERVICE_UNAVAILABLE"
    );
}
