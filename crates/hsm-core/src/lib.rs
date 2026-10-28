//! # hsm-core
//!
//! Backend-agnostic abstraction over Hardware Security Modules (HSMs) and
//! PKCS#11 tokens. This crate defines the [`HsmBackend`] trait that every
//! concrete implementation (PKCS#11, mock, cloud KMS, ...) must satisfy.
//!
//! ## Design principles
//!
//! * **Zero sensitive material in Rust memory**: all private/symmetric keys
//!   live inside the HSM. The API only ever accepts/returns public material,
//!   handles, or opaque ciphertexts.
//! * **Backend neutrality**: callers depend on the trait, not on PKCS#11
//!   specifics. This enables unit testing with [`hsm-mock`] and allows
//!   future migration to cloud HSMs.
//! * **Explicit, typed errors**: [`HsmError`] distinguishes between retryable
//!   infrastructure failures, authentication problems, and client misuse.

#![deny(missing_docs, unsafe_code, rust_2018_idioms)]
#![warn(clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

pub mod error;
pub mod types;

use async_trait::async_trait;

pub use error::{HsmError, HsmResult};
pub use types::{
    AeadCiphertext, KeyAlgorithm, KeyHandle, KeyId, PublicKey, SignatureAlgorithm, SignedPayload,
};

/// The core trait implemented by every HSM backend.
///
/// Implementations **must** be `Send + Sync` because the signing service
/// invokes the backend from arbitrary Tokio worker threads.
///
/// All methods are async even when the underlying PKCS#11 FFI is blocking:
/// implementations are expected to dispatch blocking work via
/// `tokio::task::spawn_blocking` or an internal worker pool so that the
/// Tokio reactor is never stalled.
#[async_trait]
pub trait HsmBackend: Send + Sync + 'static {
    /// Return the public key corresponding to a key stored in the HSM.
    ///
    /// # Errors
    /// Returns [`HsmError::KeyNotFound`] if `key_id` is unknown.
    async fn get_public_key(&self, key_id: &KeyId) -> HsmResult<PublicKey>;

    /// Produce an asymmetric signature over `payload`.
    ///
    /// The `payload` is the **raw message to be signed**; the backend is
    /// responsible for hashing according to `algorithm`. This matches the
    /// semantics of PKCS#11 mechanisms such as `CKM_ECDSA_SHA256`.
    ///
    /// # Errors
    /// * [`HsmError::KeyNotFound`] – unknown key id.
    /// * [`HsmError::AlgorithmMismatch`] – key type incompatible with
    ///   requested algorithm.
    /// * [`HsmError::Backend`] – underlying HSM/token failure.
    async fn sign(
        &self,
        key_id: &KeyId,
        algorithm: SignatureAlgorithm,
        payload: &[u8],
    ) -> HsmResult<SignedPayload>;

    /// Encrypt `plaintext` using an HSM-resident AEAD key.
    ///
    /// Returns an [`AeadCiphertext`] containing a fresh IV and the
    /// ciphertext||tag. The caller never sees the raw key material.
    ///
    /// # Errors
    /// See [`HsmError`].
    async fn aead_encrypt(
        &self,
        key_id: &KeyId,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> HsmResult<AeadCiphertext>;

    /// Decrypt an [`AeadCiphertext`] previously produced by [`Self::aead_encrypt`].
    ///
    /// # Errors
    /// Returns [`HsmError::AuthenticationFailed`] on tag mismatch or
    /// tampered data.
    async fn aead_decrypt(
        &self,
        key_id: &KeyId,
        ciphertext: &AeadCiphertext,
        associated_data: &[u8],
    ) -> HsmResult<Vec<u8>>;

    /// Perform a lightweight liveness probe (e.g. session acquire + release).
    ///
    /// # Errors
    /// Returns an error if the HSM is unreachable or unauthenticated.
    async fn health_check(&self) -> HsmResult<()>;
}
