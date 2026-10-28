//! # hsm-mock
//!
//! In-memory HSM backend used for unit/integration tests and local
//! development. **Not for production** — private keys live in process
//! memory. The implementation is still carefully written:
//!
//! * [`p256::ecdsa::SigningKey`] already implements `ZeroizeOnDrop`
//!   internally, so wrapping in `Zeroizing` would be redundant and
//!   actually requires an extra trait bound we don't need.
//! * AES-256 key material is held in a `Zeroizing<[u8; 32]>` so it is
//!   scrubbed on drop.
//! * No key material is ever serialized, cloned into unmanaged buffers,
//!   or logged.

#![deny(unsafe_code, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng as AesOsRng, Payload},
    Aes256Gcm,
};
use async_trait::async_trait;
use hsm_core::{
    AeadCiphertext, HsmBackend, HsmError, HsmResult, KeyAlgorithm, KeyId, PublicKey,
    SignatureAlgorithm, SignedPayload,
};
use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use std::collections::HashMap;
use tokio::sync::RwLock;
use zeroize::Zeroizing;

/// Concrete nonce type for AES-256-GCM (96-bit / 12-byte).
type AesNonce = aes_gcm::Nonce<<Aes256Gcm as AeadCore>::NonceSize>;

enum StoredKey {
    EcdsaP256(SigningKey),
    Aes256(Zeroizing<[u8; 32]>),
}

/// In-memory HSM backend.
#[derive(Default)]
pub struct MockHsm {
    keys: RwLock<HashMap<KeyId, StoredKey>>,
}

impl MockHsm {
    /// Create an empty mock HSM.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate and store a fresh ECDSA P-256 key under `key_id`.
    pub async fn generate_ecdsa_p256(&self, key_id: KeyId) -> HsmResult<PublicKey> {
        let sk = SigningKey::random(&mut OsRng);
        let pk = VerifyingKey::from(&sk);
        let bytes = pk.to_encoded_point(false).as_bytes().to_vec();
        self.keys
            .write()
            .await
            .insert(key_id, StoredKey::EcdsaP256(sk));
        Ok(PublicKey {
            algorithm: KeyAlgorithm::EcdsaP256,
            bytes,
        })
    }

    /// Generate and store a fresh AES-256 key under `key_id`.
    pub async fn generate_aes256(&self, key_id: KeyId) -> HsmResult<()> {
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(key.as_mut());
        self.keys
            .write()
            .await
            .insert(key_id, StoredKey::Aes256(key));
        Ok(())
    }
}

/// Build an AES-GCM cipher from a 32-byte key.
fn make_cipher(key: &[u8; 32]) -> HsmResult<Aes256Gcm> {
    Aes256Gcm::new_from_slice(key)
        .map_err(|e| HsmError::Backend(Box::new(std::io::Error::other(e.to_string()))))
}

/// Convert a byte slice to a 12-byte AES-GCM nonce.
fn make_nonce(iv: &[u8]) -> HsmResult<AesNonce> {
    let arr: [u8; 12] = iv
        .try_into()
        .map_err(|_| HsmError::InvalidInput("IV must be exactly 12 bytes".into()))?;
    Ok(AesNonce::from(arr))
}

#[async_trait]
impl HsmBackend for MockHsm {
    async fn get_public_key(&self, key_id: &KeyId) -> HsmResult<PublicKey> {
        let keys = self.keys.read().await;
        let k = keys
            .get(key_id)
            .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))?;
        match k {
            StoredKey::EcdsaP256(sk) => {
                let pk = VerifyingKey::from(sk);
                Ok(PublicKey {
                    algorithm: KeyAlgorithm::EcdsaP256,
                    bytes: pk.to_encoded_point(false).as_bytes().to_vec(),
                })
            }
            StoredKey::Aes256(_) => Err(HsmError::AlgorithmMismatch {
                requested: "public-key export".into(),
                actual: "AES-256".into(),
            }),
        }
    }

    async fn sign(
        &self,
        key_id: &KeyId,
        algorithm: SignatureAlgorithm,
        payload: &[u8],
    ) -> HsmResult<SignedPayload> {
        if payload.is_empty() {
            return Err(HsmError::InvalidInput("empty payload".into()));
        }
        let keys = self.keys.read().await;
        let k = keys
            .get(key_id)
            .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))?;
        match (k, algorithm) {
            (StoredKey::EcdsaP256(sk), SignatureAlgorithm::EcdsaP256Sha256) => {
                let sig: Signature = sk.sign(payload);
                Ok(SignedPayload {
                    signature: sig.to_bytes().to_vec(),
                    algorithm,
                })
            }
            (StoredKey::Aes256(_), _) => Err(HsmError::AlgorithmMismatch {
                requested: algorithm.to_string(),
                actual: "AES-256".into(),
            }),
        }
    }

    async fn aead_encrypt(
        &self,
        key_id: &KeyId,
        plaintext: &[u8],
        aad: &[u8],
    ) -> HsmResult<AeadCiphertext> {
        let keys = self.keys.read().await;
        let k = keys
            .get(key_id)
            .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))?;
        let StoredKey::Aes256(key) = k else {
            return Err(HsmError::AlgorithmMismatch {
                requested: "AES-256-GCM".into(),
                actual: "ECDSA".into(),
            });
        };
        // Zeroizing<[u8;32]> → &[u8;32] via Deref coercion through &**
        let cipher = make_cipher(key)?;
        let nonce = Aes256Gcm::generate_nonce(&mut AesOsRng);
        let ct = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|e| HsmError::Backend(Box::new(std::io::Error::other(e.to_string()))))?;
        Ok(AeadCiphertext {
            iv: nonce.to_vec(),
            ciphertext_and_tag: ct,
        })
    }

    async fn aead_decrypt(
        &self,
        key_id: &KeyId,
        ct: &AeadCiphertext,
        aad: &[u8],
    ) -> HsmResult<Vec<u8>> {
        let keys = self.keys.read().await;
        let k = keys
            .get(key_id)
            .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))?;
        let StoredKey::Aes256(key) = k else {
            return Err(HsmError::AlgorithmMismatch {
                requested: "AES-256-GCM".into(),
                actual: "ECDSA".into(),
            });
        };
        let cipher = make_cipher(key)?;
        let nonce = make_nonce(&ct.iv)?;
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &ct.ciphertext_and_tag,
                    aad,
                },
            )
            .map_err(|_| HsmError::AuthenticationFailed)
    }

    async fn health_check(&self) -> HsmResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Verifier, Signature as EcdsaSignature, VerifyingKey};

    #[tokio::test]
    async fn ecdsa_sign_and_verify_roundtrip() {
        let hsm = MockHsm::new();
        let kid = KeyId::new("test-key").unwrap();
        let pk = hsm.generate_ecdsa_p256(kid.clone()).await.unwrap();
        let msg = b"hello world";
        let sig = hsm
            .sign(&kid, SignatureAlgorithm::EcdsaP256Sha256, msg)
            .await
            .unwrap();
        let vk = VerifyingKey::from_sec1_bytes(&pk.bytes).unwrap();
        let s = EcdsaSignature::from_slice(&sig.signature).unwrap();
        vk.verify(msg, &s).unwrap();
    }

    #[tokio::test]
    async fn aes_gcm_roundtrip_and_tamper_detection() {
        let hsm = MockHsm::new();
        let kid = KeyId::new("sym-key").unwrap();
        hsm.generate_aes256(kid.clone()).await.unwrap();
        let msg = b"confidential";
        let aad = b"context";
        let mut ct = hsm.aead_encrypt(&kid, msg, aad).await.unwrap();
        assert_eq!(hsm.aead_decrypt(&kid, &ct, aad).await.unwrap(), msg);
        ct.ciphertext_and_tag[0] ^= 0xff;
        assert!(matches!(
            hsm.aead_decrypt(&kid, &ct, aad).await,
            Err(HsmError::AuthenticationFailed)
        ));
    }

    #[tokio::test]
    async fn aad_mismatch_fails_decryption() {
        let hsm = MockHsm::new();
        let kid = KeyId::new("sym-key").unwrap();
        hsm.generate_aes256(kid.clone()).await.unwrap();
        let ct = hsm.aead_encrypt(&kid, b"msg", b"aad-A").await.unwrap();
        assert!(matches!(
            hsm.aead_decrypt(&kid, &ct, b"aad-B").await,
            Err(HsmError::AuthenticationFailed)
        ));
    }

    #[tokio::test]
    async fn unknown_key_returns_not_found() {
        let hsm = MockHsm::new();
        let kid = KeyId::new("missing").unwrap();
        assert!(matches!(
            hsm.sign(&kid, SignatureAlgorithm::EcdsaP256Sha256, b"x")
                .await,
            Err(HsmError::KeyNotFound(_))
        ));
    }

    #[tokio::test]
    async fn empty_payload_rejected() {
        let hsm = MockHsm::new();
        let kid = KeyId::new("k").unwrap();
        hsm.generate_ecdsa_p256(kid.clone()).await.unwrap();
        assert!(matches!(
            hsm.sign(&kid, SignatureAlgorithm::EcdsaP256Sha256, b"")
                .await,
            Err(HsmError::InvalidInput(_))
        ));
    }

    #[tokio::test]
    async fn algorithm_key_type_mismatch_detected() {
        let hsm = MockHsm::new();
        let kid = KeyId::new("sym").unwrap();
        hsm.generate_aes256(kid.clone()).await.unwrap();
        assert!(matches!(
            hsm.sign(&kid, SignatureAlgorithm::EcdsaP256Sha256, b"x")
                .await,
            Err(HsmError::AlgorithmMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn bad_iv_length_rejected() {
        let hsm = MockHsm::new();
        let kid = KeyId::new("sym").unwrap();
        hsm.generate_aes256(kid.clone()).await.unwrap();
        let ct = AeadCiphertext {
            iv: vec![0u8; 8],
            ciphertext_and_tag: vec![0u8; 16],
        };
        assert!(matches!(
            hsm.aead_decrypt(&kid, &ct, b"").await,
            Err(HsmError::InvalidInput(_))
        ));
    }
}
