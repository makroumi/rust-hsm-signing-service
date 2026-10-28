//! Build the configured HSM backend.

use crate::config::BackendConfig;
use hsm_core::HsmBackend;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

/// Construct an [`HsmBackend`] from configuration.
///
/// # Errors
/// Returns a wrapped error if the backend cannot be initialized.
pub async fn build_backend(cfg: &BackendConfig) -> anyhow::Result<Arc<dyn HsmBackend>> {
    match cfg {
        BackendConfig::Mock => {
            tracing::warn!("using in-memory MOCK HSM backend - not for production");
            let hsm = hsm_mock::MockHsm::new();
            // Pre-provision canonical demo keys so a dev run is usable.
            // Static demo id, valid by construction; kept fallible to avoid a panic path.
            let kid = hsm_core::KeyId::new("demo-ecdsa")?;
            hsm.generate_ecdsa_p256(kid).await?;
            let kid = hsm_core::KeyId::new("demo-aes")?;
            hsm.generate_aes256(kid).await?;
            Ok(Arc::new(hsm))
        }
        BackendConfig::Pkcs11 {
            module_path,
            slot_id,
            pool_size,
            acquire_timeout_ms,
        } => {
            let pin =
                std::env::var("HSM_PIN").map_err(|_| anyhow::anyhow!("HSM_PIN env var not set"))?;
            let cfg = hsm_pkcs11::Pkcs11Config {
                module_path: module_path.clone(),
                slot_id: *slot_id,
                user_pin: Zeroizing::new(pin),
                pool_size: *pool_size,
                acquire_timeout: Duration::from_millis(*acquire_timeout_ms),
            };
            let hsm = hsm_pkcs11::Pkcs11Hsm::new(cfg).await?;
            Ok(Arc::new(hsm))
        }
    }
}
