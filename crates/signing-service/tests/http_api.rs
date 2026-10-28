//! HTTP-level integration tests using the mock HSM.
//! No external services required.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hsm_core::{HsmBackend, KeyId};
use hsm_mock::MockHsm;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde_json::{json, Value};
use signing_service::AppState;
use std::{sync::Arc, time::Duration};
use tower::ServiceExt;

async fn make_app() -> (axum::Router, Arc<MockHsm>) {
    let hsm = Arc::new(MockHsm::new());
    hsm.generate_ecdsa_p256(KeyId::new("k1").unwrap())
        .await
        .unwrap();
    hsm.generate_aes256(KeyId::new("sym1").unwrap())
        .await
        .unwrap();
    let state = AppState::new(hsm.clone() as Arc<dyn HsmBackend>);
    let app = signing_service::router(state, 1024 * 1024, Duration::from_secs(5));
    (app, hsm)
}

#[tokio::test]
async fn sign_happy_path_and_verify() {
    let (app, hsm) = make_app().await;
    let payload = B64.encode(b"message-to-sign");
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/sign")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "key_id": "k1",
                "algorithm": "ECDSA_P256_SHA256",
                "payload": payload,
            })
            .to_string(),
        ))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["key_id"], "k1");
    assert_eq!(body["algorithm"], "ECDSA_P256_SHA256");
    let sig = B64.decode(body["signature"].as_str().unwrap()).unwrap();
    assert_eq!(sig.len(), 64);

    // Verify against the public key.
    let pk = hsm
        .get_public_key(&KeyId::new("k1").unwrap())
        .await
        .unwrap();
    let vk = VerifyingKey::from_sec1_bytes(&pk.bytes).unwrap();
    let s = Signature::from_slice(&sig).unwrap();
    vk.verify(b"message-to-sign", &s).expect("valid signature");
}

#[tokio::test]
async fn unknown_key_returns_404() {
    let (app, _) = make_app().await;
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/sign")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "key_id": "nope",
                "algorithm": "ECDSA_P256_SHA256",
                "payload": B64.encode(b"x"),
            })
            .to_string(),
        ))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn invalid_base64_returns_400() {
    let (app, _) = make_app().await;
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/sign")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "key_id": "k1",
                "algorithm": "ECDSA_P256_SHA256",
                "payload": "@@@not-base64@@@",
            })
            .to_string(),
        ))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn invalid_key_id_charset_returns_400() {
    let (app, _) = make_app().await;
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/sign")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "key_id": "bad id!",
                "algorithm": "ECDSA_P256_SHA256",
                "payload": B64.encode(b"x"),
            })
            .to_string(),
        ))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn empty_payload_returns_400() {
    let (app, _) = make_app().await;
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/sign")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "key_id": "k1",
                "algorithm": "ECDSA_P256_SHA256",
                "payload": "",
            })
            .to_string(),
        ))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn malformed_json_returns_400() {
    let (app, _) = make_app().await;
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/sign")
        .header("content-type", "application/json")
        .body(Body::from("{not json"))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn healthz_and_readyz() {
    let (app, _) = make_app().await;
    let res = app
        .clone()
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let res = app
        .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}
