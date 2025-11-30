use crate::errors::{FugataError, Result};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, ParamsBuilder,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

pub struct HasherPool {
    sender: mpsc::Sender<HashJob>,
    pepper: Arc<[u8; 32]>,
}

enum HashOp {
    Hash { input: Vec<u8> },
    Verify { input: Vec<u8>, hash: String },
}

struct HashJob {
    operation: HashOp,
    response: oneshot::Sender<Result<HashResult>>,
}

enum HashResult {
    Hash(String),
    Verify(bool),
}

impl HasherPool {
    pub fn new(
        worker_count: usize,
        queue_size: usize,
        pepper: [u8; 32],
        argon2_time: u32,
        argon2_memory: u32,
        argon2_parallelism: u32,
    ) -> Result<Self> {
        let (sender, receiver) = mpsc::channel(queue_size);
        let pepper = Arc::new(pepper);

        let receiver = Arc::new(tokio::sync::Mutex::new(receiver));

        for worker_id in 0..worker_count {
            let receiver = Arc::clone(&receiver);
            let pepper = Arc::clone(&pepper);

            tokio::spawn(async move {
                Self::worker(
                    worker_id,
                    receiver,
                    pepper,
                    argon2_time,
                    argon2_memory,
                    argon2_parallelism,
                )
                .await;
            });
        }

        Ok(Self { sender, pepper })
    }

    async fn worker(
        worker_id: usize,
        receiver: Arc<tokio::sync::Mutex<mpsc::Receiver<HashJob>>>,
        pepper: Arc<[u8; 32]>,
        argon2_time: u32,
        argon2_memory: u32,
        argon2_parallelism: u32,
    ) {
        tracing::debug!(worker_id, "Hasher worker started");

        let params = ParamsBuilder::new()
            .t_cost(argon2_time)
            .m_cost(argon2_memory)
            .p_cost(argon2_parallelism)
            .output_len(32)
            .build()
            .unwrap();

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        loop {
            let job = {
                let mut rx = receiver.lock().await;
                rx.recv().await
            };

            let Some(job) = job else {
                break;
            };
            let result = match job.operation {
                HashOp::Hash { input } => {
                    let mut peppered = input.clone();
                    peppered.extend_from_slice(&*pepper);

                    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);

                    match argon2.hash_password(&peppered, &salt) {
                        Ok(hash) => Ok(HashResult::Hash(hash.to_string())),
                        Err(e) => Err(FugataError::Internal(format!("Argon2 hash failed: {}", e))),
                    }
                }
                HashOp::Verify { input, hash } => {
                    let mut peppered = input.clone();
                    peppered.extend_from_slice(&*pepper);

                    let parsed_hash = match PasswordHash::new(&hash) {
                        Ok(h) => h,
                        Err(e) => {
                            let _ = job.response.send(Err(FugataError::Internal(format!(
                                "Invalid hash format: {}",
                                e
                            ))));
                            continue;
                        }
                    };

                    let valid = argon2.verify_password(&peppered, &parsed_hash).is_ok();
                    Ok(HashResult::Verify(valid))
                }
            };

            let _ = job.response.send(result);
        }

        tracing::debug!(worker_id, "Hasher worker stopped");
    }

    pub async fn hash(&self, token: &str) -> Result<String> {
        let (response_tx, response_rx) = oneshot::channel();

        let job = HashJob {
            operation: HashOp::Hash {
                input: token.as_bytes().to_vec(),
            },
            response: response_tx,
        };

        self.sender
            .send(job)
            .await
            .map_err(|_| FugataError::WorkerPoolOverload)?;

        let result = timeout(Duration::from_secs(10), response_rx)
            .await
            .map_err(|_| FugataError::Internal("Hash operation timed out".into()))?
            .map_err(|_| FugataError::Internal("Worker dropped response channel".into()))??;

        match result {
            HashResult::Hash(hash) => Ok(hash),
            _ => Err(FugataError::Internal("Unexpected result type".into())),
        }
    }

    pub async fn verify(&self, token: &str, hash: &str) -> Result<bool> {
        let (response_tx, response_rx) = oneshot::channel();

        let job = HashJob {
            operation: HashOp::Verify {
                input: token.as_bytes().to_vec(),
                hash: hash.to_string(),
            },
            response: response_tx,
        };

        self.sender
            .send(job)
            .await
            .map_err(|_| FugataError::WorkerPoolOverload)?;

        let result = timeout(Duration::from_secs(10), response_rx)
            .await
            .map_err(|_| FugataError::Internal("Verify operation timed out".into()))?
            .map_err(|_| FugataError::Internal("Worker dropped response channel".into()))??;

        match result {
            HashResult::Verify(valid) => Ok(valid),
            _ => Err(FugataError::Internal("Unexpected result type".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_hasher_pool_hash_and_verify() {
        let pepper = [0u8; 32];
        let pool = HasherPool::new(2, 10, pepper, 1, 8192, 1).unwrap();

        let token = "dt_test_token_12345";
        let hash = pool.hash(token).await.unwrap();

        assert!(!hash.is_empty());
        assert!(hash.starts_with("$argon2id$"));

        let valid = pool.verify(token, &hash).await.unwrap();
        assert!(valid);

        let invalid = pool.verify("dt_wrong_token", &hash).await.unwrap();
        assert!(!invalid);
    }

    #[tokio::test]
    async fn test_hasher_pool_different_hashes() {
        let pepper = [0u8; 32];
        let pool = HasherPool::new(2, 10, pepper, 1, 8192, 1).unwrap();

        let token = "dt_test_token";
        let hash1 = pool.hash(token).await.unwrap();
        let hash2 = pool.hash(token).await.unwrap();

        assert_ne!(hash1, hash2);

        assert!(pool.verify(token, &hash1).await.unwrap());
        assert!(pool.verify(token, &hash2).await.unwrap());
    }

    #[tokio::test]
    async fn test_hasher_pool_pepper_affects_hash() {
        let pepper1 = [0u8; 32];
        let pepper2 = [1u8; 32];

        let pool1 = HasherPool::new(2, 10, pepper1, 1, 8192, 1).unwrap();
        let pool2 = HasherPool::new(2, 10, pepper2, 1, 8192, 1).unwrap();

        let token = "dt_test_token";
        let hash1 = pool1.hash(token).await.unwrap();

        let valid = pool2.verify(token, &hash1).await.unwrap();
        assert!(!valid);
    }
}
