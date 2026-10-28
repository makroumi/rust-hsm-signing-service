//! Shared application state wired into Axum.

use hsm_core::HsmBackend;
use std::sync::Arc;

/// Axum state – cheap to clone (`Arc` under the hood).
#[derive(Clone)]
pub struct AppState {
    /// Active HSM backend (trait object for testability).
    pub hsm: Arc<dyn HsmBackend>,
}

impl AppState {
    /// Wrap any backend behind the trait object.
    pub fn new(hsm: Arc<dyn HsmBackend>) -> Self {
        Self { hsm }
    }
}
