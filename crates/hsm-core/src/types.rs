//! Core value types shared across HSM backends.

use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

/// Stable logical identifier for a key stored in the HSM.
///
/// We deliberately use a `String` wrapper rather than a numeric handle so
/// callers can address keys by human-friendly names (e.g.
/// `arkion-intermediate-prod`) that remain stable across HSM reboots and
/// re-generations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct KeyId(String);

impl KeyId {
    /// Create a new [`KeyId`] after validating its contents.
    ///
    /// # Errors
    /// Returns an error if the id is empty, exceeds 128 bytes, or contains
    /// characters that are unsafe to use as a PKCS#11 `CKA_LABEL` or in
    /// log output.
    pub fn new(s: impl Into<String>) -> Result<Self, InvalidKeyId> {
        let s = s.into();
        if s.is_empty() {
            return Err(InvalidKeyId("empty".to_owned()));
        }
        if s.len() > 128 {
            return Err(InvalidKeyId("too long (max 128 bytes)".to_owned()));
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
        {
            return Err(InvalidKeyId("illegal character".to_owned()));
        }
        Ok(Self(s))
    }

    /// Returns the id as a `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Deserializing runs the same validation as [`KeyId::new`], so a
/// `KeyId` obtained from any source (HTTP, config, IPC) always satisfies
/// the invariant — serde cannot be used to bypass validation.
impl<'de> serde::Deserialize<'de> for KeyId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::new(s).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Error produced by [`KeyId::new`] on invalid input.
#[derive(Debug, thiserror::Error)]
#[error("invalid key id: {0}")]
pub struct InvalidKeyId(pub String);

/// Opaque, backend-specific handle. Not serialized across the API boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyHandle(
    /// Backend-defined handle value.
    pub u64,
);

/// Asymmetric key algorithm families supported by the service.
///
/// Additional algorithms (RSA-PSS, Ed25519, ML-DSA) can be added here
/// without breaking the HTTP wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyAlgorithm {
    /// NIST P-256 ECDSA key.
    EcdsaP256,
}

impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EcdsaP256 => f.write_str("ECDSA_P256"),
        }
    }
}

/// Signature algorithm selected per-request.
///
/// This is the *message* algorithm (hash + signature); PKCS#11 maps these
/// to concrete mechanisms such as `CKM_ECDSA_SHA256`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SignatureAlgorithm {
    /// ECDSA over P-256 with SHA-256 digest, raw `r||s` (64 bytes).
    EcdsaP256Sha256,
}

impl SignatureAlgorithm {
    /// Returns the compatible key algorithm.
    #[must_use]
    pub const fn key_algorithm(self) -> KeyAlgorithm {
        match self {
            Self::EcdsaP256Sha256 => KeyAlgorithm::EcdsaP256,
        }
    }
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EcdsaP256Sha256 => f.write_str("ECDSA_P256_SHA256"),
        }
    }
}

/// Exported public key material. Safe to serialize/log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// Which algorithm this public key is bound to.
    pub algorithm: KeyAlgorithm,
    /// Uncompressed SEC1 point for ECDSA keys (0x04 || X || Y).
    pub bytes: Vec<u8>,
}

/// A completed signature returned by the HSM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPayload {
    /// Signature bytes, encoding depends on the algorithm.
    pub signature: Vec<u8>,
    /// Algorithm used to produce the signature.
    pub algorithm: SignatureAlgorithm,
}

/// AEAD ciphertext envelope. The underlying symmetric key never leaves the HSM.
///
/// `Zeroize` is derived defensively: although these bytes are not secret
/// (ciphertext + IV), code paths that construct them may touch intermediate
/// buffers that should be scrubbed on drop.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
pub struct AeadCiphertext {
    /// 96-bit IV for AES-GCM (random per message).
    pub iv: Vec<u8>,
    /// Ciphertext concatenated with the 128-bit authentication tag.
    pub ciphertext_and_tag: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_id_validates_charset() {
        assert!(KeyId::new("ok-key_1.v2:prod").is_ok());
        assert!(KeyId::new("").is_err());
        assert!(KeyId::new("bad key").is_err());
        assert!(KeyId::new("bad/key").is_err());
        assert!(KeyId::new("a".repeat(129)).is_err());
    }

    #[test]
    fn signature_algo_maps_to_key_algo() {
        assert_eq!(
            SignatureAlgorithm::EcdsaP256Sha256.key_algorithm(),
            KeyAlgorithm::EcdsaP256
        );
    }

    #[test]
    fn display_formats_match_wire_format() {
        assert_eq!(
            SignatureAlgorithm::EcdsaP256Sha256.to_string(),
            "ECDSA_P256_SHA256"
        );
    }

    #[test]
    fn signature_algorithm_serde_matches_wire_format() {
        let json = serde_json::to_string(&SignatureAlgorithm::EcdsaP256Sha256).unwrap();
        assert_eq!(json, "\"ECDSA_P256_SHA256\"");
        let back: SignatureAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(back, SignatureAlgorithm::EcdsaP256Sha256);
    }

    #[test]
    fn aead_ciphertext_is_zeroizable() {
        let mut ct = AeadCiphertext {
            iv: vec![1, 2, 3],
            ciphertext_and_tag: vec![4, 5, 6],
        };
        ct.zeroize();
        assert!(ct.iv.is_empty());
        assert!(ct.ciphertext_and_tag.is_empty());
    }
}
