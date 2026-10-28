//! Key provisioning: generate non-exportable key material inside the HSM.

use crate::pool::SessionPool;
use cryptoki::{
    mechanism::Mechanism,
    object::{Attribute, KeyType, ObjectClass},
};
use hsm_core::{HsmError, HsmResult, KeyId};
use std::sync::Arc;
use tracing::{info, instrument};

/// Thin facade used by operators / tests to provision keys.
pub struct Provisioner {
    pool: Arc<SessionPool>,
}

impl Provisioner {
    pub(crate) const fn new(pool: Arc<SessionPool>) -> Self {
        Self { pool }
    }

    /// Create a non-exportable ECDSA P-256 key pair.
    ///
    /// Attribute policy:
    /// * Private key: `CKA_TOKEN=true`, `CKA_PRIVATE=true`,
    ///   `CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false`, `CKA_SIGN=true`.
    /// * Public key: `CKA_TOKEN=true`, `CKA_VERIFY=true`.
    #[instrument(skip(self), fields(key_id = %key_id))]
    pub async fn generate_ecdsa_p256(&self, key_id: &KeyId) -> HsmResult<()> {
        let label = key_id.as_str().as_bytes().to_vec();
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || -> HsmResult<()> {
            let guard = pool.blocking_acquire()?;
            let session = guard.session();

            // OID for prime256v1 / NIST P-256 (1.2.840.10045.3.1.7) DER-encoded.
            let ec_params: Vec<u8> =
                vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

            let pub_template = vec![
                Attribute::Token(true),
                Attribute::Private(false),
                Attribute::Verify(true),
                Attribute::KeyType(KeyType::EC),
                Attribute::Class(ObjectClass::PUBLIC_KEY),
                Attribute::EcParams(ec_params),
                Attribute::Label(label.clone()),
            ];
            let priv_template = vec![
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Sign(true),
                Attribute::KeyType(KeyType::EC),
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::Label(label),
            ];

            session
                .generate_key_pair(&Mechanism::EccKeyPairGen, &pub_template, &priv_template)
                .map_err(|e| HsmError::Backend(Box::new(e)))?;
            info!("ECDSA P-256 key pair generated (non-exportable)");
            Ok(())
        })
        .await
        .map_err(|e| HsmError::Backend(Box::new(e)))??;
        Ok(())
    }

    /// Create a non-exportable AES-256 secret key.
    #[instrument(skip(self), fields(key_id = %key_id))]
    pub async fn generate_aes256(&self, key_id: &KeyId) -> HsmResult<()> {
        let label = key_id.as_str().as_bytes().to_vec();
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || -> HsmResult<()> {
            let guard = pool.blocking_acquire()?;
            let session = guard.session();
            let template = vec![
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Encrypt(true),
                Attribute::Decrypt(true),
                Attribute::KeyType(KeyType::AES),
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::ValueLen(32u64.into()),
                Attribute::Label(label),
            ];
            session
                .generate_key(&Mechanism::AesKeyGen, &template)
                .map_err(|e| HsmError::Backend(Box::new(e)))?;
            info!("AES-256 secret key generated (non-exportable)");
            Ok(())
        })
        .await
        .map_err(|e| HsmError::Backend(Box::new(e)))??;
        Ok(())
    }
}
