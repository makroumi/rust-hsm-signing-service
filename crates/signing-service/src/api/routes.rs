//! HTTP route definitions.

use crate::{api::error::ApiError, domain::state::AppState};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hsm_core::{KeyId, SignatureAlgorithm};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tower_http::{
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing::{info, instrument};

/// Build the Axum router with all middleware.
pub fn router(state: AppState, max_body_bytes: usize, request_timeout: Duration) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/v1/sign", post(sign))
        .with_state(state)
        .layer(DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(max_body_bytes))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            request_timeout,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
}

#[derive(Debug, Deserialize)]
pub struct SignRequest {
    pub key_id: String,
    pub algorithm: SignatureAlgorithm,
    /// Base64-encoded (standard, with padding) payload bytes.
    pub payload: String,
}

#[derive(Debug, Serialize)]
pub struct SignResponse {
    pub key_id: String,
    pub algorithm: SignatureAlgorithm,
    pub signature: String,
    pub duration_ms: u64,
}

#[instrument(skip(state, req), fields(key_id = %req.key_id, algo = %req.algorithm))]
async fn sign(
    State(state): State<AppState>,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResponse>, ApiError> {
    let key_id = KeyId::new(&req.key_id).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let payload = B64
        .decode(req.payload.as_bytes())
        .map_err(|e| ApiError::InvalidEncoding(e.to_string()))?;
    if payload.is_empty() {
        return Err(ApiError::BadRequest("payload must not be empty".into()));
    }

    let start = Instant::now();
    let signed = state.hsm.sign(&key_id, req.algorithm, &payload).await?;
    let duration = start.elapsed();

    metrics::histogram!("signing_duration_ms", "algorithm" => req.algorithm.to_string())
        .record(duration.as_secs_f64() * 1000.0);
    metrics::counter!("signing_success_total", "algorithm" => req.algorithm.to_string())
        .increment(1);

    info!(
        duration_ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
        "signing complete"
    );

    Ok(Json(SignResponse {
        key_id: key_id.to_string(),
        algorithm: signed.algorithm,
        signature: B64.encode(&signed.signature),
        duration_ms: u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
    }))
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    match state.hsm.health_check().await {
        Ok(()) => (StatusCode::OK, "ready").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "readiness check failed");
            (StatusCode::SERVICE_UNAVAILABLE, "not ready").into_response()
        }
    }
}
