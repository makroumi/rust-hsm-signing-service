//! PKCS#11 configuration.

use std::path::PathBuf;
use std::time::Duration;
use zeroize::Zeroizing;

/// Configuration for connecting to a PKCS#11 token.
#[derive(Clone)]
pub struct Pkcs11Config {
    /// Filesystem path to the PKCS#11 shared library (`.so`/`.dll`/`.dylib`).
    pub module_path: PathBuf,
    /// Token slot id to open (`SoftHSM` uses dynamic slot ids).
    pub slot_id: u64,
    /// User PIN. Held in zeroizing storage; never logged or serialized.
    pub user_pin: Zeroizing<String>,
    /// Max number of concurrent R/W sessions kept in the pool.
    pub pool_size: usize,
    /// Max time to wait for a session before returning
    /// [`hsm_core::HsmError::PoolExhausted`].
    pub acquire_timeout: Duration,
}

impl std::fmt::Debug for Pkcs11Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs11Config")
            .field("module_path", &self.module_path)
            .field("slot_id", &self.slot_id)
            .field("user_pin", &"<redacted>")
            .field("pool_size", &self.pool_size)
            .field("acquire_timeout", &self.acquire_timeout)
            .finish()
    }
}
