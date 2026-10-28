//! HTTP API layer.
mod error;
mod routes;

pub use error::ApiError;
pub use routes::router;
