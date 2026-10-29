//! HTTP contract edge cases that pin the exact behavior at every
//! boundary a real client (or attacker) might probe.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hsm_core::{HsmBackend, KeyId};
use hsm_mock::MockHsm;
use serde_json::json;
use signing_service::AppState;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

async fn make_app() -> axum::Router {
    let hsm = Arc::new(MockHsm::new());
    hsm.generate_ecdsa_p256(KeyId::new("k1").unwrap())
        .await
        .unwrap();
    let state = AppState::new(hsm as Arc<dyn HsmBackend>);
    signing_service::router(state, 1024 * 1024, Duration::from_secs(5))
}

fn post_sign(body: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/sign")
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

// ── Body limit ───────────────────────────────────────────────────────

/// A body clearly over the 1 MiB limit must be rejected with 413.
#[tokio::test]
async fn oversized_body_returns_413() {
    let app = make_app().await;
    // 2 MiB of base64 chars inside the JSON envelope.
    let big_payload = "A".repeat(2 * 1024 * 1024);
    let body = json!({
        "key_id": "k1",
        "algorithm": "ECDSA_P256_SHA256",
        "payload": big_payload,
    })
    .to_string();
    let res = app.oneshot(post_sign(&body)).await.unwrap();
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

/// A large but under-limit body must succeed end-to-end.
#[tokio::test]
async fn large_valid_payload_succeeds() {
    let app = make_app().await;
    // ~500 KiB raw payload → ~670 KiB base64 → ~670 KiB JSON body.
    let payload = vec![0xAB_u8; 500 * 1024];
    let body = json!({
        "key_id": "k1",
        "algorithm": "ECDSA_P256_SHA256",
        "payload": B64.encode(&payload),
    })
    .to_string();
    let res = app.oneshot(post_sign(&body)).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

// ── Method / route ───────────────────────────────────────────────────

/// GET on a POST-only route must return 405, not 404 or 200.
#[tokio::test]
async fn get_on_sign_returns_405() {
    let app = make_app().await;
    let req = Request::get("/v1/sign").body(Body::empty()).unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
}

/// A route that doesn't exist must return 404.
#[tokio::test]
async fn unknown_route_returns_404() {
    let app = make_app().await;
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v2/sign")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

// ── Base64 zoo ───────────────────────────────────────────────────────

/// Missing padding must be rejected (standard engine requires canonical).
#[tokio::test]
async fn base64_missing_padding_rejected() {
    let app = make_app().await;
    // "hello" = "aGVsbG8=" — drop the trailing '='.
    let body = json!({
        "key_id": "k1",
        "algorithm": "ECDSA_P256_SHA256",
        "payload": "aGVsbG8",
    })
    .to_string();
    let res = app.oneshot(post_sign(&body)).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

/// Embedded whitespace is not valid standard base64.
#[tokio::test]
async fn base64_whitespace_rejected() {
    let app = make_app().await;
    let body = json!({
        "key_id": "k1",
        "algorithm": "ECDSA_P256_SHA256",
        "payload": "aGVs bG8=",
    })
    .to_string();
    let res = app.oneshot(post_sign(&body)).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

/// URL-safe alphabet chars (- and _) are invalid in standard base64.
#[tokio::test]
async fn base64_url_safe_alphabet_rejected() {
    let app = make_app().await;
    let body = json!({
        "key_id": "k1",
        "algorithm": "ECDSA_P256_SHA256",
        "payload": "aGVsbG8_",
    })
    .to_string();
    let res = app.oneshot(post_sign(&body)).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

/// Non-canonical trailing bits must be rejected by the strict decoder.
/// "a" = "YQ==" (canonical). "YR==" has non-zero trailing bits.
#[tokio::test]
async fn base64_non_canonical_trailing_bits_rejected() {
    let app = make_app().await;
    let body = json!({
        "key_id": "k1",
        "algorithm": "ECDSA_P256_SHA256",
        "payload": "YR==",
    })
    .to_string();
    let res = app.oneshot(post_sign(&body)).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}
