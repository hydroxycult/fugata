use fugata::{
    config::Config,
    crypto,
    kms::local::LocalKms,
    svc::{
        audit::AuditLogger,
        cache::{ReplayCache, SecretCache},
        db::Database,
        hasher::HasherPool,
        service::{CreateSecretRequest, SecretService},
    },
};
use std::sync::Arc;

async fn setup_test_db() -> Database {
    use sqlx::any::install_default_drivers;
    install_default_drivers();

    let pool = sqlx::AnyPool::connect("sqlite:file::memory:?cache=shared")
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

async fn setup_service() -> Arc<SecretService> {
    let db = setup_test_db().await;
    let kek = vec![0u8; 32];
    let kms = Arc::new(LocalKms::new(kek).unwrap());

    let hasher = Arc::new(HasherPool::new(2, 10, [0u8; 32], 1, 8192, 1).unwrap());

    let secret_cache = SecretCache::new(100);
    let replay_cache = ReplayCache::new();
    let audit = AuditLogger::new(db.pool.clone());

    let config = Arc::new(Config {
        port: 8080,
        environment: "test".to_string(),
        log_level: "debug".to_string(),
        database_url: "sqlite::memory:".to_string(),
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

    Arc::new(SecretService::new(
        db,
        kms,
        hasher,
        secret_cache,
        replay_cache,
        audit,
        config,
    ))
}

#[tokio::test]
async fn test_large_secret_at_limit() {
    let service = setup_service().await;

    let content = "A".repeat(1024 * 1024);

    let create_req = CreateSecretRequest {
        content,
        duration: Some("1h".to_string()),
        one_time: false,
        metadata: None,
    };

    let result = service
        .create_secret(create_req, "127.0.0.1", "req_large_1")
        .await;

    assert!(result.is_ok(), "1MB secret should succeed");
    let response = result.unwrap();

    let get_result = service
        .get_secret(&response.id, "127.0.0.1", "req_large_2")
        .await;

    assert!(
        get_result.is_ok(),
        "Should be able to retrieve large secret"
    );
}

#[tokio::test]
async fn test_secret_over_config_limit() {
    let service = setup_service().await;

    let content = "B".repeat(11 * 1024 * 1024);

    let create_req = CreateSecretRequest {
        content,
        duration: Some("1h".to_string()),
        one_time: false,
        metadata: None,
    };

    let result = service
        .create_secret(create_req, "127.0.0.1", "req_over_limit")
        .await;

    assert!(result.is_err(), "Oversized secret should be rejected");
}

#[tokio::test]
async fn test_concurrent_large_secrets() {
    let service = setup_service().await;

    let mut success_count = 0;

    for i in 0..5 {
        let content = format!("Secret_{}_", i).repeat(50_000);

        let create_req = CreateSecretRequest {
            content,
            duration: Some("1h".to_string()),
            one_time: false,
            metadata: None,
        };

        let result = service
            .create_secret(create_req, "127.0.0.1", &format!("req_sequential_{}", i))
            .await;

        if result.is_ok() {
            success_count += 1;
        }
    }

    assert_eq!(
        success_count, 5,
        "All sequential large requests should succeed"
    );
}

#[tokio::test]
async fn test_encrypted_size_larger_than_plaintext() {
    let dek = crypto::generate_dek().unwrap();
    let aad = "test_aad";

    let plaintext = vec![0u8; 1024 * 1024];
    let encrypted = crypto::encrypt(&plaintext, &dek, aad).unwrap();

    let expected_overhead = 12 + 16;
    let actual_overhead = encrypted.nonce.len() + encrypted.tag.len();

    assert_eq!(actual_overhead, expected_overhead);
    assert_eq!(encrypted.ciphertext.len(), plaintext.len());

    let total_encrypted = encrypted.nonce.len() + encrypted.ciphertext.len() + encrypted.tag.len();
    assert!(
        total_encrypted < plaintext.len() + 100,
        "Encryption overhead should be minimal"
    );
}

#[tokio::test]
async fn test_metadata_encryption_overhead() {
    let service = setup_service().await;

    let metadata = serde_json::json!({
        "key1": "value1",
        "key2": "value2",
        "nested": {
            "data": "test"
        }
    });

    let create_req = CreateSecretRequest {
        content: "test content".to_string(),
        duration: Some("1h".to_string()),
        one_time: false,
        metadata: Some(metadata),
    };

    let result = service
        .create_secret(create_req, "127.0.0.1", "req_metadata")
        .await;

    assert!(result.is_ok(), "Secret with metadata should succeed");

    let response = result.unwrap();
    let get_result = service
        .get_secret(&response.id, "127.0.0.1", "req_metadata_get")
        .await
        .unwrap();

    assert!(get_result.metadata.is_some(), "Metadata should be present");
}

#[tokio::test]
async fn test_memory_cleanup_on_error() {
    let service = setup_service().await;

    let create_req = CreateSecretRequest {
        content: "test".to_string(),
        duration: Some("invalid_duration".to_string()),
        one_time: false,
        metadata: None,
    };

    let result = service
        .create_secret(create_req, "127.0.0.1", "req_error")
        .await;

    assert!(result.is_err(), "Invalid request should fail");

    let valid_req = CreateSecretRequest {
        content: "valid secret".to_string(),
        duration: Some("1h".to_string()),
        one_time: false,
        metadata: None,
    };

    let valid_result = service
        .create_secret(valid_req, "127.0.0.1", "req_after_error")
        .await;

    assert!(valid_result.is_ok(), "Should work after error");
}
