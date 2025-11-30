use crate::errors::{FugataError, Result};
use std::env;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Default)]
pub enum ProxyMode {
    #[default]
    Direct,
    TrustedProxy,
    Auto,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub environment: String,
    pub log_level: String,

    pub database_url: String,
    pub db_max_connections: u32,
    pub db_query_timeout_secs: u64,

    pub pepper: [u8; 32],
    pub ip_hash_key: [u8; 32],

    pub argon2_time: u32,
    pub argon2_memory: u32,
    pub argon2_parallelism: u32,
    pub argon2_keylen: usize,

    pub hasher_worker_count: usize,
    pub hasher_queue_size: usize,

    pub rate_limit_rpm: u64,
    pub rate_limit_burst: u64,

    pub trusted_proxies: Vec<IpAddr>,
    pub proxy_mode: ProxyMode,

    pub allowed_origins: Vec<String>,

    pub lru_cache_size: usize,

    pub max_secret_size: usize,
    pub ttl_presets: Vec<String>,
    pub deletion_token_expiry_hours: u64,
    pub token_replay_ttl_hours: u64,

    pub kms_provider: KmsProvider,
    pub kms_fail_closed: bool,
}

#[derive(Debug, Clone)]
pub enum KmsProvider {
    Local {
        key: Vec<u8>,
    },
    Vault {
        addr: String,
        token: String,
        mount: String,
        key_name: String,
    },
    #[cfg(feature = "aws-kms")]
    Aws {
        region: String,
        key_id: String,
    },
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();

        let pepper = Self::parse_hex_32("PEPPER")?;
        let ip_hash_key = Self::parse_hex_32("IP_HASH_KEY").or_else(|_| -> Result<[u8; 32]> {
            tracing::warn!("IP_HASH_KEY not set, generating random key (NOT for production)");
            Ok(Self::generate_random_32())
        })?;

        let ttl_presets_str =
            env::var("TTL_PRESETS").unwrap_or_else(|_| "5m,1h,24h,168h".to_string());
        let ttl_presets: Vec<String> = ttl_presets_str
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        for preset in &ttl_presets {
            Self::parse_duration(preset)?;
        }

        let kms_provider = if let Ok(key_b64) = env::var("KMS_LOCAL_KEY") {
            use base64::Engine;
            let key = base64::engine::general_purpose::STANDARD
                .decode(&key_b64)
                .map_err(|e| FugataError::Config(format!("Invalid KMS_LOCAL_KEY base64: {}", e)))?;
            if key.len() != 32 {
                return Err(FugataError::Config(format!(
                    "KMS_LOCAL_KEY must be 32 bytes, got {}",
                    key.len()
                )));
            }
            KmsProvider::Local { key }
        } else if let Ok(addr) = env::var("VAULT_ADDR") {
            KmsProvider::Vault {
                addr,
                token: env::var("VAULT_TOKEN").map_err(|_| {
                    FugataError::Config("VAULT_TOKEN required for Vault KMS".into())
                })?,
                mount: env::var("VAULT_MOUNT").unwrap_or_else(|_| "transit".to_string()),
                key_name: env::var("VAULT_KEY_NAME").unwrap_or_else(|_| "fugata-kek".to_string()),
            }
        } else {
            #[cfg(feature = "aws-kms")]
            {
                if let Ok(key_id) = env::var("AWS_KMS_KEY_ID") {
                    KmsProvider::Aws {
                        region: env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string()),
                        key_id,
                    }
                } else {
                    return Err(FugataError::Config(
                        "No KMS provider configured. Set KMS_LOCAL_KEY, VAULT_ADDR, or AWS_KMS_KEY_ID".into()
                    ));
                }
            }
            #[cfg(not(feature = "aws-kms"))]
            {
                return Err(FugataError::Config(
                    "No KMS provider configured. Set KMS_LOCAL_KEY or VAULT_ADDR".into(),
                ));
            }
        };

        let config = Config {
            port: env::var("PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()
                .map_err(|e| FugataError::Config(format!("Invalid PORT: {}", e)))?,

            environment: env::var("ENVIRONMENT").unwrap_or_else(|_| "production".to_string()),
            log_level: env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),

            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite:./fugata.db".to_string()),

            db_max_connections: env::var("DB_MAX_CONNECTIONS")
                .unwrap_or_else(|_| "25".to_string())
                .parse()
                .map_err(|e| FugataError::Config(format!("Invalid DB_MAX_CONNECTIONS: {}", e)))?,

            db_query_timeout_secs: env::var("DB_QUERY_TIMEOUT_SECS")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .map_err(|e| {
                    FugataError::Config(format!("Invalid DB_QUERY_TIMEOUT_SECS: {}", e))
                })?,

            pepper,
            ip_hash_key,

            argon2_time: env::var("ARGON2_TIME")
                .unwrap_or_else(|_| "4".to_string())
                .parse()
                .map_err(|e| FugataError::Config(format!("Invalid ARGON2_TIME: {}", e)))?,

            argon2_memory: env::var("ARGON2_MEMORY")
                .unwrap_or_else(|_| "65536".to_string())
                .parse()
                .map_err(|e| FugataError::Config(format!("Invalid ARGON2_MEMORY: {}", e)))?,

            argon2_parallelism: env::var("ARGON2_PARALLELISM")
                .unwrap_or_else(|_| "1".to_string())
                .parse()
                .map_err(|e| FugataError::Config(format!("Invalid ARGON2_PARALLELISM: {}", e)))?,

            argon2_keylen: env::var("ARGON2_KEYLEN")
                .unwrap_or_else(|_| "32".to_string())
                .parse()
                .map_err(|e| FugataError::Config(format!("Invalid ARGON2_KEYLEN: {}", e)))?,

            hasher_worker_count: env::var("HASHER_WORKER_COUNT")
                .unwrap_or_else(|_| num_cpus::get().to_string())
                .parse()
                .map_err(|e| FugataError::Config(format!("Invalid HASHER_WORKER_COUNT: {}", e)))?,

            hasher_queue_size: env::var("HASHER_QUEUE_SIZE")
                .unwrap_or_else(|_| "1000".to_string())
                .parse()
                .map_err(|e| FugataError::Config(format!("Invalid HASHER_QUEUE_SIZE: {}", e)))?,

            rate_limit_rpm: env::var("RATE_LIMIT_RPM")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .map_err(|e| FugataError::Config(format!("Invalid RATE_LIMIT_RPM: {}", e)))?,

            rate_limit_burst: env::var("RATE_LIMIT_BURST")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .map_err(|e| FugataError::Config(format!("Invalid RATE_LIMIT_BURST: {}", e)))?,

            lru_cache_size: env::var("LRU_CACHE_SIZE")
                .unwrap_or_else(|_| "1000".to_string())
                .parse()
                .map_err(|e| FugataError::Config(format!("Invalid LRU_CACHE_SIZE: {}", e)))?,

            max_secret_size: env::var("MAX_SECRET_SIZE")
                .unwrap_or_else(|_| "10485760".to_string())
                .parse()
                .map_err(|e| FugataError::Config(format!("Invalid MAX_SECRET_SIZE: {}", e)))?,

            ttl_presets,

            deletion_token_expiry_hours: env::var("DELETION_TOKEN_EXPIRY_HOURS")
                .unwrap_or_else(|_| "24".to_string())
                .parse()
                .map_err(|e| {
                    FugataError::Config(format!("Invalid DELETION_TOKEN_EXPIRY_HOURS: {}", e))
                })?,

            token_replay_ttl_hours: env::var("TOKEN_REPLAY_TTL_HOURS")
                .unwrap_or_else(|_| "1".to_string())
                .parse()
                .map_err(|e| {
                    FugataError::Config(format!("Invalid TOKEN_REPLAY_TTL_HOURS: {}", e))
                })?,

            kms_provider,

            kms_fail_closed: env::var("KMS_FAIL_CLOSED")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .map_err(|e| FugataError::Config(format!("Invalid KMS_FAIL_CLOSED: {}", e)))?,

            trusted_proxies: Self::parse_trusted_proxies()?,
            proxy_mode: Self::parse_proxy_mode()?,

            allowed_origins: Self::parse_allowed_origins().unwrap_or_else(|_| {
                tracing::warn!("ALLOWED_ORIGINS not set - CORS will reject all origins");
                vec![]
            }),
        };

        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.argon2_time < 1 {
            return Err(FugataError::Config("ARGON2_TIME must be >= 1".into()));
        }

        if self.argon2_memory < 8192 {
            return Err(FugataError::Config(
                "ARGON2_MEMORY must be >= 8192 KiB".into(),
            ));
        }

        if self.argon2_parallelism < 1 {
            return Err(FugataError::Config(
                "ARGON2_PARALLELISM must be >= 1".into(),
            ));
        }

        if self.argon2_keylen != 32 {
            return Err(FugataError::Config("ARGON2_KEYLEN must be 32 bytes".into()));
        }

        if self.ttl_presets.is_empty() {
            return Err(FugataError::Config("TTL_PRESETS cannot be empty".into()));
        }

        Ok(())
    }

    fn parse_hex_32(var_name: &str) -> Result<[u8; 32]> {
        let hex_str = env::var(var_name)
            .map_err(|_| FugataError::Config(format!("{} is required", var_name)))?;

        let bytes = hex::decode(&hex_str)
            .map_err(|e| FugataError::Config(format!("Invalid hex in {}: {}", var_name, e)))?;

        if bytes.len() != 32 {
            return Err(FugataError::Config(format!(
                "{} must be 32 bytes, got {}",
                var_name,
                bytes.len()
            )));
        }

        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(array)
    }

    fn generate_random_32() -> [u8; 32] {
        use ring::rand::{SecureRandom, SystemRandom};
        let mut bytes = [0u8; 32];
        SystemRandom::new().fill(&mut bytes).unwrap();
        bytes
    }

    fn parse_trusted_proxies() -> Result<Vec<IpAddr>> {
        let proxies_str = match env::var("TRUSTED_PROXIES") {
            Ok(s) if !s.is_empty() => s,
            _ => return Ok(Vec::new()),
        };

        let mut proxies = Vec::new();
        for ip_str in proxies_str.split(',') {
            let ip_str = ip_str.trim();
            if ip_str.is_empty() {
                continue;
            }
            let ip: IpAddr = ip_str.parse().map_err(|e| {
                FugataError::Config(format!("Invalid IP in TRUSTED_PROXIES '{}': {}", ip_str, e))
            })?;
            proxies.push(ip);
        }

        Ok(proxies)
    }

    fn parse_proxy_mode() -> Result<ProxyMode> {
        let mode_str = env::var("PROXY_MODE").unwrap_or_else(|_| "Direct".to_string());
        match mode_str.to_lowercase().as_str() {
            "direct" => Ok(ProxyMode::Direct),
            "trustedproxy" | "trusted_proxy" | "trusted" => Ok(ProxyMode::TrustedProxy),
            "auto" => Ok(ProxyMode::Auto),
            _ => Err(FugataError::Config(format!(
                "Invalid PROXY_MODE '{}'. Must be 'Direct', 'TrustedProxy', or 'Auto'",
                mode_str
            ))),
        }
    }

    fn parse_allowed_origins() -> Result<Vec<String>> {
        let origins_str = env::var("ALLOWED_ORIGINS")
            .map_err(|e| FugataError::Config(format!("ALLOWED_ORIGINS not set: {}", e)))?;
        Ok(origins_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect())
    }

    pub fn parse_duration(s: &str) -> Result<chrono::Duration> {
        let s = s.trim();
        if s.is_empty() {
            return Err(FugataError::BadRequest("Empty duration".into()));
        }

        let (num_str, unit) = s.split_at(s.len() - 1);
        let num: i64 = num_str.parse().map_err(|_| {
            FugataError::BadRequest(format!("Invalid duration number: {}", num_str))
        })?;

        match unit {
            "m" => Ok(chrono::Duration::minutes(num)),
            "h" => Ok(chrono::Duration::hours(num)),
            _ => Err(FugataError::BadRequest(format!(
                "Invalid duration unit: {}",
                unit
            ))),
        }
    }
}
