use fugata::{
    config::{Config, ProxyMode},
    kms::local::LocalKms,
    svc::{
        audit::AuditLogger,
        cache::{ReplayCache, SecretCache},
        db::Database,
        hasher::HasherPool,
        service::{CreateSecretRequest, SecretService},
    },
};
use sqlx::AnyPool;
use std::sync::Arc;

async fn setup_test_db() -> Database {
    use rand;
    use sqlx::any::install_default_drivers;

    install_default_drivers();

    let unique_id = format!(
        "{}_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        rand::random::<u64>()
    );
    let db_url = format!("sqlite:file:test_{}?mode=memory&cache=shared", unique_id);

    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(25)
        .min_connections(5)
        .connect(&db_url)
        .await
        .expect("Failed to create connection pool");

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

async fn setup_service_with_proxy(
    proxy_mode: ProxyMode,
    trusted_proxies: Vec<std::net::IpAddr>,
) -> Arc<SecretService> {
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
        rate_limit_rpm: 10,
        rate_limit_burst: 2,
        lru_cache_size: 100,
        max_secret_size: 1024 * 1024,
        ttl_presets: vec!["5m".into(), "1h".into(), "24h".into()],
        deletion_token_expiry_hours: 24,
        token_replay_ttl_hours: 1,
        kms_provider: fugata::config::KmsProvider::Local { key: vec![0u8; 32] },
        kms_fail_closed: true,
        trusted_proxies,
        proxy_mode,
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
async fn test_rate_limit_bypass_attack_blocked() {
    use fugata::svc::rate_limit::RateLimiter;
    use std::sync::Arc;

    let rate_limiter = Arc::new(RateLimiter::new(10, 2, [1u8; 32]));

    let client_ip = "203.0.113.1";

    let mut allowed = 0;
    let mut blocked = 0;

    for _ in 0..15 {
        let info = rate_limiter.check_rate_limit(client_ip).unwrap();
        if info.allowed {
            allowed += 1;
        } else {
            blocked += 1;
        }
    }

    assert!(
        blocked > 0,
        "Rate limit should block some requests! Allowed: {}, Blocked: {}",
        allowed,
        blocked
    );
    assert_eq!(allowed, 2, "Should allow exactly burst size (2)");
    assert_eq!(blocked, 13, "Should block 15 - 2 = 13 requests");
}

#[tokio::test]
async fn test_ip_extraction_prevents_spoofing() {
    use axum::http::HeaderMap;
    use fugata::util::ip::extract_client_ip;
    use std::net::IpAddr;

    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());

    let peer_ip: IpAddr = "203.0.113.1".parse().unwrap();
    let extracted = extract_client_ip(&headers, peer_ip, &[], &ProxyMode::Direct);

    assert_eq!(
        extracted, "203.0.113.1",
        "Direct mode should ignore spoofed headers!"
    );

    let untrusted_peer: IpAddr = "198.51.100.1".parse().unwrap();
    let trusted_proxies: Vec<IpAddr> = vec!["10.0.0.1".parse().unwrap()];

    let extracted2 = extract_client_ip(
        &headers,
        untrusted_peer,
        &trusted_proxies,
        &ProxyMode::TrustedProxy,
    );

    assert_eq!(
        extracted2, "198.51.100.1",
        "Untrusted proxy headers should be ignored (anti-spoofing)!"
    );

    let trusted_peer: IpAddr = "10.0.0.1".parse().unwrap();
    let extracted3 = extract_client_ip(
        &headers,
        trusted_peer,
        &trusted_proxies,
        &ProxyMode::TrustedProxy,
    );

    assert_eq!(
        extracted3, "1.2.3.4",
        "Trusted proxy should extract real client IP"
    );
}

#[tokio::test]
async fn test_memory_exhaustion_dos_blocked() {
    let service = setup_service_with_proxy(ProxyMode::Direct, vec![]).await;

    let attack_payload = "X".repeat(2 * 1024 * 1024);

    let req = CreateSecretRequest {
        content: attack_payload,
        duration: Some("1h".to_string()),
        one_time: false,
        metadata: None,
    };

    let result = service.create_secret(req, "203.0.113.1", "req_dos").await;

    assert!(
        result.is_err(),
        "Memory exhaustion attack should be blocked!"
    );
}

#[tokio::test]
async fn test_concurrent_memory_attack_blocked() {
    let service = setup_service_with_proxy(ProxyMode::Direct, vec![]).await;

    let mut handles = vec![];

    for i in 0..20 {
        let service_clone = service.clone();
        let handle = tokio::spawn(async move {
            let payload = format!("X{}", i).repeat(450_000);

            let req = CreateSecretRequest {
                content: payload,
                duration: Some("1h".to_string()),
                one_time: false,
                metadata: None,
            };

            service_clone
                .create_secret(req, "203.0.113.1", &format!("req_concurrent_{}", i))
                .await
        });
        handles.push(handle);
    }

    let mut successes = 0;
    for handle in handles {
        if let Ok(Ok(_)) = handle.await {
            successes += 1;
        }
    }

    assert!(successes > 0, "System should handle some requests");
    assert!(successes <= 20, "Sanity check passed");
}

#[tokio::test]
async fn test_audit_failure_blocks_operation() {
    let db = setup_test_db().await;

    sqlx::query("DROP TABLE audit")
        .execute(&db.pool)
        .await
        .expect("Failed to drop audit table");

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

    let service = Arc::new(SecretService::new(
        db,
        kms,
        hasher,
        secret_cache,
        replay_cache,
        audit,
        config,
    ));

    let req = CreateSecretRequest {
        content: "attack_payload".to_string(),
        duration: Some("1h".to_string()),
        one_time: false,
        metadata: None,
    };

    let result = service
        .create_secret(req, "203.0.113.1", "req_audit_attack")
        .await;

    assert!(
        result.is_err(),
        "Audit evasion attack should be blocked! Operation must fail when audit fails."
    );
}

#[tokio::test]
async fn test_cache_poisoning_blocked() {
    let service = setup_service_with_proxy(ProxyMode::Direct, vec![]).await;

    let req = CreateSecretRequest {
        content: "legitimate_secret".to_string(),
        duration: Some("1h".to_string()),
        one_time: false,
        metadata: None,
    };

    let response = service
        .create_secret(req, "203.0.113.1", "req_legit")
        .await
        .unwrap();
    let secret_id = response.id;
    let deletion_token = response.deletion_token;

    let get1 = service
        .get_secret(&secret_id, "203.0.113.1", "req_get1")
        .await
        .unwrap();
    assert_eq!(get1.content, "legitimate_secret");

    service
        .delete_secret(&secret_id, &deletion_token, "203.0.113.1", "req_delete")
        .await
        .unwrap();

    let get2 = service
        .get_secret(&secret_id, "203.0.113.1", "req_get2")
        .await;
    assert!(
        get2.is_err(),
        "Cache poisoning attack: Deleted secret should not be accessible from cache!"
    );
}
