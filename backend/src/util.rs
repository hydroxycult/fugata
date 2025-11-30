use crate::errors::{FugataError, Result};
use ring::rand::{SecureRandom, SystemRandom};
use subtle::ConstantTimeEq;

pub mod ip;

pub fn generate_secret_id() -> Result<String> {
    use base64::Engine;
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|e| FugataError::Crypto(format!("Failed to generate random ID: {:?}", e)))?;

    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    Ok(format!("fug_{}", encoded))
}

pub fn generate_deletion_token() -> Result<String> {
    use base64::Engine;
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|e| FugataError::Crypto(format!("Failed to generate random token: {:?}", e)))?;

    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    Ok(format!("dt_{}", encoded))
}

pub fn build_aad(secret_id: &str, purpose: &str) -> String {
    format!("fugata:{}:{}", secret_id, purpose)
}

pub fn hash_ip(ip: &str, key: &[u8; 32]) -> String {
    use ring::hmac;
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&key, ip.as_bytes());
    hex::encode(tag.as_ref())
}

pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

pub fn validate_secret_id(id: &str) -> Result<()> {
    if !id.starts_with("fug_") {
        return Err(FugataError::BadRequest("Invalid secret ID format".into()));
    }

    let encoded = &id[4..];
    if encoded.is_empty() || encoded.len() > 100 {
        return Err(FugataError::BadRequest("Invalid secret ID length".into()));
    }

    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| FugataError::BadRequest("Invalid secret ID encoding".into()))?;

    Ok(())
}

pub fn validate_deletion_token(token: &str) -> Result<()> {
    if !token.starts_with("dt_") {
        return Err(FugataError::BadRequest(
            "Invalid deletion token format".into(),
        ));
    }

    let encoded = &token[3..];
    if encoded.is_empty() {
        return Err(FugataError::BadRequest("Empty deletion token".into()));
    }

    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| FugataError::BadRequest("Invalid deletion token encoding".into()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_secret_id() {
        let id = generate_secret_id().unwrap();
        assert!(id.starts_with("fug_"));
        assert!(id.len() > 4);
        validate_secret_id(&id).unwrap();
    }

    #[test]
    fn test_generate_deletion_token() {
        let token = generate_deletion_token().unwrap();
        assert!(token.starts_with("dt_"));
        assert!(token.len() > 3);
        validate_deletion_token(&token).unwrap();
    }

    #[test]
    fn test_build_aad() {
        let aad = build_aad("fug_test123", "secret");
        assert_eq!(aad, "fugata:fug_test123:secret");
    }

    #[test]
    fn test_hash_ip() {
        let key = [0u8; 32];
        let hash1 = hash_ip("192.168.1.1", &key);
        let hash2 = hash_ip("192.168.1.1", &key);
        let hash3 = hash_ip("192.168.1.2", &key);

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn test_constant_time_compare() {
        let a = b"hello";
        let b = b"hello";
        let c = b"world";

        assert!(constant_time_compare(a, b));
        assert!(!constant_time_compare(a, c));
        assert!(!constant_time_compare(a, b"hi"));
    }

    #[test]
    fn test_validate_secret_id() {
        assert!(validate_secret_id("fug_YWJjZGVmZ2hpamtsbW5vcA").is_ok());
        assert!(validate_secret_id("invalid").is_err());
        assert!(validate_secret_id("fug_").is_err());
        assert!(validate_secret_id("dt_abc").is_err());
    }

    #[test]
    fn test_validate_deletion_token() {
        assert!(
            validate_deletion_token("dt_YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3OA==").is_ok()
        );
        assert!(validate_deletion_token("invalid").is_err());
        assert!(validate_deletion_token("dt_").is_err());
        assert!(validate_deletion_token("fug_abc").is_err());
    }
}
