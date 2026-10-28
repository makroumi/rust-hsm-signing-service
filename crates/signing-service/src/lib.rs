//! HSM-backed signing service.
//!
//! See the binary [`main`] for wiring; the library exposes the
//! building blocks so integration tests can spin up the full stack
//! in-process.

#![deny(rust_2018_idioms, unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

pub mod api;
pub mod config;
pub mod domain;
pub mod infra;
pub mod observability;

pub use api::router;
pub use domain::state::AppState;
