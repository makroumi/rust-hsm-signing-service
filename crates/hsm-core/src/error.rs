//! Error types for HSM backends.

use thiserror::Error;

/// Specialized `Result` for HSM operations.
pub type HsmResult<T> = Result<T, HsmError>;

/// Errors returned by any [`crate::HsmBackend`] implementation.
///
/// These errors are deliberately **coarse-grained**: implementations should
/// map low-level PKCS#11 return codes into the most appropriate variant so
/// that higher layers can make uniform decisions (retry? bubble 4xx? 5xx?).
#[derive(Debug, Error)]
pub enum HsmError {
    /// The requested key identifier does not exist in the HSM.
    #[error("key not found: {0}")]
    KeyNotFound(String),

    /// The key exists but cannot be used for the requested algorithm.
    #[error("algorithm {requested} is incompatible with key of type {actual}")]
    AlgorithmMismatch {
        /// Algorithm requested by the caller.
        requested: String,
        /// Actual key algorithm/type in the HSM.
        actual: String,
    },

    /// Authentication to the token/partition failed (bad PIN, locked, ...).
    #[error("HSM authentication failed")]
    AuthenticationFailed,

    /// No session could be acquired from the pool within the configured
    /// timeout. This indicates saturation and callers should apply
    /// backpressure.
    #[error("HSM session pool exhausted")]
    PoolExhausted,

    /// The HSM is reachable but in a degraded/unusable state.
    #[error("HSM unavailable: {0}")]
    Unavailable(String),

    /// Caller-supplied input is invalid (empty payload, oversized, ...).
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// Opaque backend failure. Low-level details are preserved via `source`
    /// but are **not** included in the user-facing `Display` to avoid
    /// leaking internals.
    #[error("HSM backend error")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl HsmError {
    /// Returns `true` if the operation is safe to retry (transient failure).
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::PoolExhausted | Self::Unavailable(_))
    }

    /// Returns `true` if this is a client (4xx) error vs server (5xx).
    #[must_use]
    pub const fn is_client_error(&self) -> bool {
        matches!(
            self,
            Self::KeyNotFound(_) | Self::AlgorithmMismatch { .. } | Self::InvalidInput(_)
        )
    }
}
