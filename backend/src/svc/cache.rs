use crate::crypto::EncryptedData;
use chrono::{DateTime, Utc};
use lru::LruCache;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct SecretCache {
    cache: Arc<Mutex<LruCache<String, CachedSecret>>>,
    hits: Arc<Mutex<u64>>,
    misses: Arc<Mutex<u64>>,
}

#[derive(Clone)]
struct CachedSecret {
    encrypted: EncryptedData,
    encrypted_dek: Vec<u8>,
    deletion_token_hash: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    one_time: bool,
    used: bool,
    metadata: Option<Vec<u8>>,
}

impl SecretCache {
    pub fn new(capacity: usize) -> Self {
        let cache = LruCache::new(NonZeroUsize::new(capacity).unwrap());

        Self {
            cache: Arc::new(Mutex::new(cache)),
            hits: Arc::new(Mutex::new(0)),
            misses: Arc::new(Mutex::new(0)),
        }
    }

    pub fn get(
        &self,
        secret_id: &str,
    ) -> Option<(
        EncryptedData,
        Vec<u8>,
        String,
        DateTime<Utc>,
        DateTime<Utc>,
        bool,
        bool,
        Option<Vec<u8>>,
    )> {
        let mut cache = self.cache.lock().unwrap();

        if let Some(cached) = cache.get(secret_id) {
            *self.hits.lock().unwrap() += 1;
            Some((
                cached.encrypted.clone(),
                cached.encrypted_dek.clone(),
                cached.deletion_token_hash.clone(),
                cached.created_at,
                cached.expires_at,
                cached.one_time,
                cached.used,
                cached.metadata.clone(),
            ))
        } else {
            *self.misses.lock().unwrap() += 1;
            None
        }
    }

    pub fn put(
        &self,
        secret_id: String,
        encrypted: EncryptedData,
        encrypted_dek: Vec<u8>,
        deletion_token_hash: String,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        one_time: bool,
        used: bool,
        metadata: Option<Vec<u8>>,
    ) {
        let mut cache = self.cache.lock().unwrap();

        cache.put(
            secret_id,
            CachedSecret {
                encrypted,
                encrypted_dek,
                deletion_token_hash,
                created_at,
                expires_at,
                one_time,
                used,
                metadata,
            },
        );
    }

    pub fn invalidate(&self, secret_id: &str) {
        let mut cache = self.cache.lock().unwrap();
        cache.pop(secret_id);
    }

    pub fn stats(&self) -> (u64, u64) {
        let hits = *self.hits.lock().unwrap();
        let misses = *self.misses.lock().unwrap();
        (hits, misses)
    }

    pub fn hit_rate(&self) -> f64 {
        let (hits, misses) = self.stats();
        let total = hits + misses;
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }
}

#[derive(Clone)]
pub struct ReplayCache {
    cache: Arc<Mutex<HashMap<String, DateTime<Utc>>>>,
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayCache {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn is_used(&self, token_hash: &str) -> bool {
        let cache = self.cache.lock().unwrap();
        cache.contains_key(token_hash)
    }

    pub fn mark_used(&self, token_hash: String, expires_at: DateTime<Utc>) {
        let mut cache = self.cache.lock().unwrap();
        cache.insert(token_hash, expires_at);
    }

    pub fn cleanup(&self) {
        let mut cache = self.cache.lock().unwrap();
        let now = Utc::now();

        cache.retain(|_, expires_at| *expires_at > now);
    }

    pub fn len(&self) -> usize {
        let cache = self.cache.lock().unwrap();
        cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_cache_put_and_get() {
        let cache = SecretCache::new(10);

        let encrypted = EncryptedData {
            nonce: vec![0u8; 12],
            ciphertext: vec![1, 2, 3],
            tag: vec![4, 5, 6],
        };

        let created_at = Utc::now();
        let expires_at = created_at + chrono::Duration::hours(1);

        cache.put(
            "fug_test123".to_string(),
            encrypted.clone(),
            vec![7, 8, 9],
            "hash123".to_string(),
            created_at,
            expires_at,
            false,
            false,
            None,
        );

        let result = cache.get("fug_test123");
        assert!(result.is_some());

        let (cached_enc, cached_dek, cached_hash, _, _, one_time, used, metadata) = result.unwrap();
        assert_eq!(cached_enc.ciphertext, encrypted.ciphertext);
        assert_eq!(cached_dek, vec![7, 8, 9]);
        assert_eq!(cached_hash, "hash123");
        assert!(!one_time);
        assert!(!used);
        assert!(metadata.is_none());
    }

    #[test]
    fn test_secret_cache_miss() {
        let cache = SecretCache::new(10);

        let result = cache.get("fug_nonexistent");
        assert!(result.is_none());

        let (hits, misses) = cache.stats();
        assert_eq!(hits, 0);
        assert_eq!(misses, 1);
    }

    #[test]
    fn test_secret_cache_invalidate() {
        let cache = SecretCache::new(10);

        let encrypted = EncryptedData {
            nonce: vec![0u8; 12],
            ciphertext: vec![1, 2, 3],
            tag: vec![4, 5, 6],
        };

        let created_at = Utc::now();
        let expires_at = created_at + chrono::Duration::hours(1);

        cache.put(
            "fug_test123".to_string(),
            encrypted,
            vec![],
            "hash".to_string(),
            created_at,
            expires_at,
            false,
            false,
            None,
        );

        assert!(cache.get("fug_test123").is_some());

        cache.invalidate("fug_test123");

        assert!(cache.get("fug_test123").is_none());
    }

    #[test]
    fn test_secret_cache_lru_eviction() {
        let cache = SecretCache::new(2);

        let encrypted = EncryptedData {
            nonce: vec![0u8; 12],
            ciphertext: vec![1],
            tag: vec![2],
        };

        let created_at = Utc::now();
        let expires_at = created_at + chrono::Duration::hours(1);

        cache.put(
            "fug_1".to_string(),
            encrypted.clone(),
            vec![],
            "h1".to_string(),
            created_at,
            expires_at,
            false,
            false,
            None,
        );
        cache.put(
            "fug_2".to_string(),
            encrypted.clone(),
            vec![],
            "h2".to_string(),
            created_at,
            expires_at,
            false,
            false,
            None,
        );
        cache.put(
            "fug_3".to_string(),
            encrypted,
            vec![],
            "h3".to_string(),
            created_at,
            expires_at,
            false,
            false,
            None,
        );

        assert!(cache.get("fug_1").is_none());
        assert!(cache.get("fug_2").is_some());
        assert!(cache.get("fug_3").is_some());
    }

    #[test]
    fn test_replay_cache() {
        let cache = ReplayCache::new();

        assert!(!cache.is_used("hash1"));

        let expires_at = Utc::now() + chrono::Duration::hours(1);
        cache.mark_used("hash1".to_string(), expires_at);

        assert!(cache.is_used("hash1"));
        assert!(!cache.is_used("hash2"));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_replay_cache_cleanup() {
        let cache = ReplayCache::new();

        let past = Utc::now() - chrono::Duration::hours(1);
        let future = Utc::now() + chrono::Duration::hours(1);

        cache.mark_used("expired".to_string(), past);
        cache.mark_used("valid".to_string(), future);

        assert_eq!(cache.len(), 2);

        cache.cleanup();

        assert_eq!(cache.len(), 1);
        assert!(!cache.is_used("expired"));
        assert!(cache.is_used("valid"));
    }
}
