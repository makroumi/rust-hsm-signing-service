//! # hsm-pkcs11
//!
//! Production backend speaking PKCS#11 (Cryptoki) via the [`cryptoki`]
//! crate. Validated against **`SoftHSM2`** but should work with any
//! compliant token (`YubiHSM2`, nShield, AWS `CloudHSM`, Entrust nShield, ...).
//!
//! ## Key design decisions
//!
//! * **Session pool**: PKCS#11 sessions are a scarce, serial resource. We
//!   maintain a bounded [`SessionPool`] of pre-authenticated R/W sessions.
//!   Requests acquire a session via [`tokio::sync::Semaphore`] with a
//!   timeout, providing natural backpressure.
//! * **Blocking FFI isolation**: every C call is wrapped in
//!   `tokio::task::spawn_blocking` so the async runtime never stalls.
//! * **Non-exportable keys**: `CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false`,
//!   `CKA_TOKEN=true` enforced at generation time.
//! * **No secret in logs**: PIN is held in [`zeroize::Zeroizing`] and never
//!   logged, even on error.

#![deny(unsafe_code, rust_2018_idioms)]
#![warn(clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    // False positive for RAII guard patterns: the guard MUST outlive the
    // session reference it hands out. Merging into one line (as clippy
    // suggests) would drop the guard while the borrow is still live.
    clippy::significant_drop_tightening
)]

mod config;
mod pool;
mod provision;

pub use config::Pkcs11Config;
pub use pool::SessionPool;
pub use provision::Provisioner;

use async_trait::async_trait;
use cryptoki::{
    mechanism::Mechanism,
    object::{Attribute, AttributeType, ObjectClass, ObjectHandle},
    session::Session,
};
use hsm_core::{
    AeadCiphertext, HsmBackend, HsmError, HsmResult, KeyAlgorithm, KeyId, PublicKey,
    SignatureAlgorithm, SignedPayload,
};
use std::sync::Arc;
use tracing::{debug, instrument, warn};

/// PKCS#11-backed HSM.
pub struct Pkcs11Hsm {
    pool: Arc<SessionPool>,
}

impl Pkcs11Hsm {
    /// Initialize the backend from configuration.
    pub async fn new(cfg: Pkcs11Config) -> HsmResult<Self> {
        let pool = SessionPool::new(cfg).await?;
        Ok(Self {
            pool: Arc::new(pool),
        })
    }

    /// Expose a provisioner for generating/importing keys.
    pub fn provisioner(&self) -> Provisioner {
        Provisioner::new(self.pool.clone())
    }

    /// Access to the underlying pool (for metrics).
    pub fn pool(&self) -> &SessionPool {
        &self.pool
    }

    /// Lookup an object handle by `CKA_LABEL` and class.
    fn find_object(session: &Session, label: &str, class: ObjectClass) -> HsmResult<ObjectHandle> {
        let template = vec![
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Class(class),
        ];
        let objs = session
            .find_objects(&template)
            .map_err(|e| HsmError::Backend(Box::new(e)))?;
        objs.into_iter()
            .next()
            .ok_or_else(|| HsmError::KeyNotFound(label.to_owned()))
    }
}

#[async_trait]
impl HsmBackend for Pkcs11Hsm {
    #[instrument(skip(self), fields(key_id = %key_id))]
    async fn get_public_key(&self, key_id: &KeyId) -> HsmResult<PublicKey> {
        let label = key_id.as_str().to_owned();
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let guard = pool.blocking_acquire()?;
            let session = guard.session();
            let handle = Self::find_object(session, &label, ObjectClass::PUBLIC_KEY)?;
            let attrs = session
                .get_attributes(handle, &[AttributeType::EcPoint])
                .map_err(|e| HsmError::Backend(Box::new(e)))?;
            let point = attrs
                .into_iter()
                .find_map(|a| {
                    if let Attribute::EcPoint(p) = a {
                        Some(p)
                    } else {
                        None
                    }
                })
                .ok_or_else(|| {
                    HsmError::Backend(Box::new(std::io::Error::other("missing EC_POINT")))
                })?;
            let decoded = decode_ec_point(&point)?;
            Ok(PublicKey {
                algorithm: KeyAlgorithm::EcdsaP256,
                bytes: decoded,
            })
        })
        .await
        .map_err(|e| HsmError::Backend(Box::new(e)))?
    }

    #[instrument(skip(self, payload), fields(key_id = %key_id, algo = %algorithm, len = payload.len()))]
    async fn sign(
        &self,
        key_id: &KeyId,
        algorithm: SignatureAlgorithm,
        payload: &[u8],
    ) -> HsmResult<SignedPayload> {
        if payload.is_empty() {
            return Err(HsmError::InvalidInput("empty payload".into()));
        }
        let label = key_id.as_str().to_owned();
        let payload = payload.to_vec();
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let guard = pool.blocking_acquire()?;
            let session = guard.session();
            let handle = Self::find_object(session, &label, ObjectClass::PRIVATE_KEY)?;
            let mech = match algorithm {
                SignatureAlgorithm::EcdsaP256Sha256 => Mechanism::EcdsaSha256,
            };
            let sig = session.sign(&mech, handle, &payload).map_err(|e| {
                warn!(error.kind = "pkcs11_sign", "sign failed");
                HsmError::Backend(Box::new(e))
            })?;
            debug!(sig_len = sig.len(), "signed");
            Ok(SignedPayload {
                signature: sig,
                algorithm,
            })
        })
        .await
        .map_err(|e| HsmError::Backend(Box::new(e)))?
    }

    #[instrument(skip(self, plaintext, aad), fields(key_id = %key_id, len = plaintext.len()))]
    async fn aead_encrypt(
        &self,
        key_id: &KeyId,
        plaintext: &[u8],
        aad: &[u8],
    ) -> HsmResult<AeadCiphertext> {
        let label = key_id.as_str().to_owned();
        let plaintext = plaintext.to_vec();
        let aad = aad.to_vec();
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            use cryptoki::mechanism::aead::GcmParams;
            let guard = pool.blocking_acquire()?;
            let session = guard.session();
            let handle = Self::find_object(session, &label, ObjectClass::SECRET_KEY)?;
            let mut iv = [0u8; 12];
            getrandom_bytes(&mut iv)?;
            let params = GcmParams::new(&iv, &aad, 128u64.into());
            let mech = Mechanism::AesGcm(params);
            let ct = session
                .encrypt(&mech, handle, &plaintext)
                .map_err(|e| HsmError::Backend(Box::new(e)))?;
            Ok(AeadCiphertext {
                iv: iv.to_vec(),
                ciphertext_and_tag: ct,
            })
        })
        .await
        .map_err(|e| HsmError::Backend(Box::new(e)))?
    }

    #[instrument(skip(self, ct, aad), fields(key_id = %key_id))]
    async fn aead_decrypt(
        &self,
        key_id: &KeyId,
        ct: &AeadCiphertext,
        aad: &[u8],
    ) -> HsmResult<Vec<u8>> {
        if ct.iv.len() != 12 {
            return Err(HsmError::InvalidInput("IV must be 12 bytes".into()));
        }
        let label = key_id.as_str().to_owned();
        let iv = ct.iv.clone();
        let data = ct.ciphertext_and_tag.clone();
        let aad = aad.to_vec();
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            use cryptoki::mechanism::aead::GcmParams;
            let guard = pool.blocking_acquire()?;
            let session = guard.session();
            let handle = Self::find_object(session, &label, ObjectClass::SECRET_KEY)?;
            let params = GcmParams::new(&iv, &aad, 128u64.into());
            let mech = Mechanism::AesGcm(params);
            session
                .decrypt(&mech, handle, &data)
                .map_err(|_| HsmError::AuthenticationFailed)
        })
        .await
        .map_err(|e| HsmError::Backend(Box::new(e)))?
    }

    async fn health_check(&self) -> HsmResult<()> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let _g = pool.blocking_acquire()?;
            Ok(())
        })
        .await
        .map_err(|e| HsmError::Backend(Box::new(e)))?
    }
}

/// Decode PKCS#11 `CKA_EC_POINT`.
///
/// Per PKCS#11 v2.40 §A.3.4, `CKA_EC_POINT` is the DER encoding of an
/// `OCTET STRING` wrapping the raw SEC1 point. Some tokens (older `SoftHSM`
/// included) have historically returned the raw point instead; we handle
/// both for interoperability.
fn decode_ec_point(der: &[u8]) -> HsmResult<Vec<u8>> {
    if der.len() == 65 && der[0] == 0x04 {
        return Ok(der.to_vec());
    }
    if der.len() < 2 || der[0] != 0x04 {
        return Err(HsmError::Backend(Box::new(std::io::Error::other(
            "unexpected EC_POINT encoding",
        ))));
    }
    let (len, header) = if der[1] & 0x80 == 0 {
        (der[1] as usize, 2usize)
    } else {
        let n = (der[1] & 0x7f) as usize;
        if n == 0 || der.len() < 2 + n {
            return Err(HsmError::Backend(Box::new(std::io::Error::other(
                "truncated EC_POINT length",
            ))));
        }
        let mut l = 0usize;
        for b in &der[2..2 + n] {
            l = (l << 8) | *b as usize;
        }
        (l, 2 + n)
    };
    if der.len() < header + len {
        return Err(HsmError::Backend(Box::new(std::io::Error::other(
            "truncated EC_POINT body",
        ))));
    }
    Ok(der[header..header + len].to_vec())
}

fn getrandom_bytes(buf: &mut [u8]) -> HsmResult<()> {
    use rand::RngCore;
    rand::rngs::OsRng
        .try_fill_bytes(buf)
        .map_err(|e| HsmError::Backend(Box::new(e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_ec_point_accepts_raw_sec1() {
        let mut raw = vec![0x04u8];
        raw.extend_from_slice(&[0xAA; 64]);
        assert_eq!(decode_ec_point(&raw).unwrap(), raw);
    }

    #[test]
    fn decode_ec_point_accepts_der_short_form() {
        let der = vec![0x04, 0x03, 0x01, 0x02, 0x03];
        assert_eq!(decode_ec_point(&der).unwrap(), vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn decode_ec_point_accepts_der_long_form() {
        let mut der = vec![0x04, 0x81, 0x41, 0x04];
        der.extend_from_slice(&[0xBB; 64]);
        let decoded = decode_ec_point(&der).unwrap();
        assert_eq!(decoded.len(), 65);
        assert_eq!(decoded[0], 0x04);
    }

    #[test]
    fn decode_ec_point_rejects_garbage() {
        assert!(decode_ec_point(&[0xff, 0x00]).is_err());
        assert!(decode_ec_point(&[]).is_err());
    }
}
