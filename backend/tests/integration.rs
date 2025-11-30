use fugata::{
    config::Config,
    crypto,
    kms::{local::LocalKms, Kms},
    svc::{
        audit::AuditLogger,
        cache::{ReplayCache, SecretCache},
        db::Database,
        hasher::HasherPool,
        service::{CreateSecretRequest, SecretService},
    },
    util,
};
use std::sync::Arc;

async fn setup_test_db() -> Database {
    use sqlx::any::install_default_drivers;
    install_default_drivers();

    let pool = sqlx::AnyPool::connect("sqlite:file:test_db?mode=memory&cache=shared")
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

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_secrets_expires_at ON secrets(expires_at)")
        .execute(&pool)
        .await
        .expect("Failed to create index");

    Database { pool }
}

async fn setup_test_service() -> Arc<SecretService> {
    let db = setup_test_db().await;

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
        database_url: "sqlite::memory:?cache=shared".to_string(),
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
async fn test_create_get_delete_flow() {
    let service = setup_test_service().await;

    let create_req = CreateSecretRequest {
        content: "Hello, Fugata!".to_string(),
        duration: Some("1h".to_string()),
        one_time: false,
        metadata: None,
    };

    let create_resp = service
        .create_secret(create_req, "127.0.0.1", "req_test_1")
        .await
        .unwrap();

    assert!(create_resp.id.starts_with("fug_"));
    assert!(create_resp.deletion_token.starts_with("dt_"));

    let get_resp = service
        .get_secret(&create_resp.id, "127.0.0.1", "req_test_2")
        .await
        .unwrap();

    assert_eq!(get_resp.content, "Hello, Fugata!");
    assert_eq!(get_resp.id, create_resp.id);

    let delete_resp = service
        .delete_secret(
            &create_resp.id,
            &create_resp.deletion_token,
            "127.0.0.1",
            "req_test_3",
        )
        .await
        .unwrap();

    assert_eq!(delete_resp.message, "Secret deleted successfully");

    let result = service
        .get_secret(&create_resp.id, "127.0.0.1", "req_test_4")
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_one_time_secret() {
    let service = setup_test_service().await;

    let create_req = CreateSecretRequest {
        content: "One-time secret".to_string(),
        duration: Some("1h".to_string()),
        one_time: true,
        metadata: None,
    };

    let create_resp = service
        .create_secret(create_req, "127.0.0.1", "req_test_onetime_1")
        .await
        .unwrap();

    let get_resp = service
        .get_secret(&create_resp.id, "127.0.0.1", "req_test_onetime_2")
        .await
        .unwrap();

    assert_eq!(get_resp.content, "One-time secret");

    let result = service
        .get_secret(&create_resp.id, "127.0.0.1", "req_test_onetime_3")
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_token_replay_protection() {
    let service = setup_test_service().await;

    let create_req = CreateSecretRequest {
        content: "Test replay".to_string(),
        duration: Some("1h".to_string()),
        one_time: false,
        metadata: None,
    };

    let create_resp = service
        .create_secret(create_req, "127.0.0.1", "req_test_replay_1")
        .await
        .unwrap();

    service
        .delete_secret(
            &create_resp.id,
            &create_resp.deletion_token,
            "127.0.0.1",
            "req_test_replay_2",
        )
        .await
        .unwrap();

    let result = service
        .delete_secret(
            &create_resp.id,
            &create_resp.deletion_token,
            "127.0.0.1",
            "req_test_replay_3",
        )
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_invalid_deletion_token() {
    let service = setup_test_service().await;

    let create_req = CreateSecretRequest {
        content: "Test auth".to_string(),
        duration: Some("1h".to_string()),
        one_time: false,
        metadata: None,
    };

    let create_resp = service
        .create_secret(create_req, "127.0.0.1", "req_test_auth_1")
        .await
        .unwrap();

    let wrong_token = util::generate_deletion_token().unwrap();

    let result = service
        .delete_secret(
            &create_resp.id,
            &wrong_token,
            "127.0.0.1",
            "req_test_auth_2",
        )
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_invalid_duration() {
    let service = setup_test_service().await;

    let create_req = CreateSecretRequest {
        content: "Test".to_string(),
        duration: Some("999h".to_string()),
        one_time: false,
        metadata: None,
    };

    let result = service
        .create_secret(create_req, "127.0.0.1", "req_test_duration")
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_secret_with_metadata() {
    let service = setup_test_service().await;

    let metadata = serde_json::json!({
        "author": "test",
        "tags": ["important", "confidential"]
    });

    let create_req = CreateSecretRequest {
        content: "Secret with metadata".to_string(),
        duration: Some("1h".to_string()),
        one_time: false,
        metadata: Some(metadata.clone()),
    };

    let create_resp = service
        .create_secret(create_req, "127.0.0.1", "req_test_meta_1")
        .await
        .unwrap();

    let get_resp = service
        .get_secret(&create_resp.id, "127.0.0.1", "req_test_meta_2")
        .await
        .unwrap();

    assert_eq!(get_resp.content, "Secret with metadata");
    assert_eq!(get_resp.metadata, Some(metadata));
}

#[tokio::test]
async fn test_cache_hit_miss() {
    let service = setup_test_service().await;

    let create_req = CreateSecretRequest {
        content: "Cached secret".to_string(),
        duration: Some("1h".to_string()),
        one_time: false,
        metadata: None,
    };

    let create_resp = service
        .create_secret(create_req, "127.0.0.1", "req_test_cache_1")
        .await
        .unwrap();

    service
        .get_secret(&create_resp.id, "127.0.0.1", "req_test_cache_2")
        .await
        .unwrap();

    service
        .get_secret(&create_resp.id, "127.0.0.1", "req_test_cache_3")
        .await
        .unwrap();
}

#[tokio::test]
async fn test_cleanup_expired_secrets() {
    let service = setup_test_service().await;

    let count = service.cleanup_expired_secrets().await.unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn test_health_check() {
    let service = setup_test_service().await;

    let result = service.health_check().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_crypto_roundtrip() {
    let dek = crypto::generate_dek().unwrap();
    assert_eq!(dek.len(), 32);

    let plaintext = b"Test message";
    let aad = "fugata:test_id:secret";

    let encrypted = crypto::encrypt(plaintext, &dek, aad).unwrap();
    assert_eq!(encrypted.nonce.len(), 12);
    assert!(!encrypted.ciphertext.is_empty());
    assert_eq!(encrypted.tag.len(), 16);

    let decrypted = crypto::decrypt(&encrypted, &dek, aad).unwrap();
    assert_eq!(decrypted.as_slice(), plaintext);
}

#[tokio::test]
async fn test_kms_roundtrip() {
    let kek = vec![0u8; 32];
    let kms = LocalKms::new(kek).unwrap();

    let dek = vec![1u8; 32];
    let mut context = std::collections::HashMap::new();
    context.insert("secret_id".to_string(), "fug_test".to_string());
    context.insert("purpose".to_string(), "dek".to_string());

    let encrypted = kms.encrypt_dek(&dek, &context).await.unwrap();
    assert!(!encrypted.is_empty());

    let decrypted = kms.decrypt_dek(&encrypted, &context).await.unwrap();
    assert_eq!(decrypted, dek);

    assert!(kms.health_check().await.is_ok());
}
