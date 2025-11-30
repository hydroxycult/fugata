use crate::errors::{FugataError, Result};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedData {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

pub fn generate_dek() -> Result<Zeroizing<Vec<u8>>> {
    let mut dek = Zeroizing::new(vec![0u8; 32]);
    SystemRandom::new()
        .fill(&mut dek)
        .map_err(|e| FugataError::Crypto(format!("Failed to generate DEK: {:?}", e)))?;
    Ok(dek)
}

fn generate_nonce() -> Result<[u8; 12]> {
    let mut nonce = [0u8; 12];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|e| FugataError::Crypto(format!("Failed to generate nonce: {:?}", e)))?;
    Ok(nonce)
}

pub fn encrypt(plaintext: &[u8], dek: &[u8], aad: &str) -> Result<EncryptedData> {
    if dek.len() != 32 {
        return Err(FugataError::Crypto(format!(
            "DEK must be 32 bytes, got {}",
            dek.len()
        )));
    }

    let cipher = Aes256Gcm::new_from_slice(dek)
        .map_err(|e| FugataError::Crypto(format!("Failed to create cipher: {}", e)))?;

    let nonce_bytes = generate_nonce()?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: plaintext,
        aad: aad.as_bytes(),
    };

    let ciphertext_with_tag = cipher
        .encrypt(nonce, payload)
        .map_err(|e| FugataError::Crypto(format!("Encryption failed: {}", e)))?;

    let tag_start = ciphertext_with_tag.len().saturating_sub(16);
    let ciphertext = ciphertext_with_tag[..tag_start].to_vec();
    let tag = ciphertext_with_tag[tag_start..].to_vec();

    Ok(EncryptedData {
        nonce: nonce_bytes.to_vec(),
        ciphertext,
        tag,
    })
}

pub fn decrypt(encrypted: &EncryptedData, dek: &[u8], aad: &str) -> Result<Vec<u8>> {
    if dek.len() != 32 {
        return Err(FugataError::Crypto(format!(
            "DEK must be 32 bytes, got {}",
            dek.len()
        )));
    }

    if encrypted.nonce.len() != 12 {
        return Err(FugataError::Crypto(format!(
            "Nonce must be 12 bytes, got {}",
            encrypted.nonce.len()
        )));
    }

    let cipher = Aes256Gcm::new_from_slice(dek)
        .map_err(|e| FugataError::Crypto(format!("Failed to create cipher: {}", e)))?;

    let nonce = Nonce::from_slice(&encrypted.nonce);

    let mut ciphertext_with_tag = encrypted.ciphertext.clone();
    ciphertext_with_tag.extend_from_slice(&encrypted.tag);

    let payload = Payload {
        msg: &ciphertext_with_tag,
        aad: aad.as_bytes(),
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|e| FugataError::Crypto(format!("Decryption failed: {}", e)))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_dek() {
        let dek1 = generate_dek().unwrap();
        let dek2 = generate_dek().unwrap();

        assert_eq!(dek1.len(), 32);
        assert_eq!(dek2.len(), 32);
        assert_ne!(dek1.as_slice(), dek2.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"Hello, Fugata!";
        let dek = generate_dek().unwrap();
        let aad = "fugata:fug_test123:secret";

        let encrypted = encrypt(plaintext, &dek, aad).unwrap();
        assert_eq!(encrypted.nonce.len(), 12);
        assert!(!encrypted.ciphertext.is_empty());
        assert_eq!(encrypted.tag.len(), 16);
        assert_ne!(encrypted.ciphertext.as_slice(), plaintext);

        let decrypted = decrypt(&encrypted, &dek, aad).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_decrypt_wrong_aad_fails() {
        let plaintext = b"Secret data";
        let dek = generate_dek().unwrap();
        let aad = "fugata:fug_test123:secret";

        let encrypted = encrypt(plaintext, &dek, aad).unwrap();

        let wrong_aad = "fugata:fug_test456:secret";
        let result = decrypt(&encrypted, &dek, wrong_aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_dek_fails() {
        let plaintext = b"Secret data";
        let dek1 = generate_dek().unwrap();
        let dek2 = generate_dek().unwrap();
        let aad = "fugata:fug_test123:secret";

        let encrypted = encrypt(plaintext, &dek1, aad).unwrap();

        let result = decrypt(&encrypted, &dek2, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_modified_ciphertext_fails() {
        let plaintext = b"Secret data";
        let dek = generate_dek().unwrap();
        let aad = "fugata:fug_test123:secret";

        let mut encrypted = encrypt(plaintext, &dek, aad).unwrap();

        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 1;
        }

        let result = decrypt(&encrypted, &dek, aad);
        assert!(result.is_err());
    }
}
