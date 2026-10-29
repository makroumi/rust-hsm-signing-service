//! Logging bootstrap.
//!
//! Metrics are installed directly in `main.rs` via
//! `PrometheusBuilder::install()` so that a single HTTP listener is
//! created and lifetime-bound to the process.

use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Install a JSON tracing subscriber honoring `RUST_LOG`.
///
/// Idempotent - safe to call multiple times from tests.
pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,signing_service=debug,hsm_pkcs11=debug"));
    let fmt_layer = fmt::layer()
        .json()
        .with_target(true)
        .with_current_span(true);
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .try_init();
}
