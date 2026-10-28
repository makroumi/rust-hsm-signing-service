//! Runtime configuration loaded from env/file.

use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf, time::Duration};

/// Which HSM backend to use.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase", tag = "kind")]
pub enum BackendConfig {
    /// In-memory mock backend – **development/tests only**.
    Mock,
    /// Real PKCS#11 backend.
    Pkcs11 {
        /// Path to the PKCS#11 .so/.dll/.dylib module.
        module_path: PathBuf,
        /// Slot id (numeric).
        slot_id: u64,
        /// Pool size (concurrent sessions).
        #[serde(default = "default_pool_size")]
        pool_size: usize,
        /// Session acquire timeout in milliseconds.
        #[serde(default = "default_acquire_timeout_ms")]
        acquire_timeout_ms: u64,
    },
}

const fn default_pool_size() -> usize {
    8
}
const fn default_acquire_timeout_ms() -> u64 {
    2_000
}

/// Top-level configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    /// Address to bind the HTTP server to.
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
    /// Max request body (bytes).
    #[serde(default = "default_body_limit")]
    pub max_body_bytes: usize,
    /// Request timeout.
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    /// Prometheus metrics bind address (optional).
    pub metrics_bind: Option<SocketAddr>,
    /// Backend selection.
    pub backend: BackendConfig,
}

fn default_bind() -> SocketAddr {
    "0.0.0.0:8080".parse().unwrap()
}
const fn default_body_limit() -> usize {
    1024 * 1024 // 1 MiB
}
const fn default_request_timeout_ms() -> u64 {
    10_000
}

impl AppConfig {
    /// Load configuration using the following precedence:
    /// 1. `CONFIG_FILE` env var pointing at TOML/YAML/JSON.
    /// 2. Env vars prefixed `APP__` (double underscore nesting).
    ///
    /// # Errors
    /// Returns a human-readable error on malformed config.
    pub fn load() -> Result<Self, config::ConfigError> {
        let mut builder = config::Config::builder();
        if let Ok(path) = std::env::var("CONFIG_FILE") {
            builder = builder.add_source(config::File::with_name(&path));
        }
        builder = builder.add_source(
            config::Environment::with_prefix("APP")
                .separator("__")
                .try_parsing(true),
        );
        builder.build()?.try_deserialize()
    }

    /// Request timeout as [`Duration`].
    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_ms)
    }
}
