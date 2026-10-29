use axum::body::Body;
use axum::http::Method;
use axum::http::Request;
use axum::http::StatusCode;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hsm_core::HsmBackend;
use hsm_core::KeyId;
use hsm_mock::MockHsm;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::Signature;
use p256::ecdsa::VerifyingKey;
use proptest::collection::vec;
use proptest::prelude::*;
use serde_json::json;
use serde_json::Value;
use signing_service::AppState;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

fn test_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio rt")
}

fn sign_req(payload_b64: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/sign")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "key_id": "k1",
                "algorithm": "ECDSA_P256_SHA256",
                "payload": payload_b64,
            })
            .to_string(),
        ))
        .unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn http_sign_verifies_for_arbitrary_payloads(payload in vec(any::<u8>(), 1..=8192)) {
        test_rt().block_on(async move {
            let hsm = Arc::new(MockHsm::new());
            hsm.generate_ecdsa_p256(KeyId::new("k1").unwrap()).await.unwrap();
            let state = AppState::new(hsm.clone() as Arc<dyn HsmBackend>);
            let app = signing_service::router(state, 1024 * 1024, Duration::from_secs(5));
            let res = app.oneshot(sign_req(&B64.encode(&payload))).await.unwrap();
            prop_assert_eq!(res.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            let body: Value = serde_json::from_slice(&bytes).unwrap();
            prop_assert_eq!(&body["key_id"], "k1");
            prop_assert_eq!(&body["algorithm"], "ECDSA_P256_SHA256");
            prop_assert!(body["duration_ms"].as_u64().is_some());
            let sig_bytes = B64.decode(body["signature"].as_str().unwrap()).unwrap();
            prop_assert_eq!(sig_bytes.len(), 64);
            let pk = hsm.get_public_key(&KeyId::new("k1").unwrap()).await.unwrap();
            let vk = VerifyingKey::from_sec1_bytes(&pk.bytes).unwrap();
            let sig = Signature::from_slice(&sig_bytes).unwrap();
            prop_assert!(vk.verify(&payload, &sig).is_ok());
            Ok(())
        }).unwrap();
    }

    #[test]
    fn http_rejects_invalid_key_ids(
        (prefix_len, bad_char) in (0usize..32, any::<char>())
    ) {
        let bad = if bad_char.is_ascii_alphanumeric()
            || matches!(bad_char, '-' | '_' | '.' | ':')
        {
            ' '
        } else {
            bad_char
        };
        test_rt().block_on(async move {
            let hsm = Arc::new(MockHsm::new());
            let state = AppState::new(hsm.clone() as Arc<dyn HsmBackend>);
            let app = signing_service::router(state, 1024 * 1024, Duration::from_secs(5));
            let key_id = format!("{}{bad}tail", "k".repeat(prefix_len));
            let req = Request::builder()
                .method(Method::POST)
                .uri("/v1/sign")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "key_id": key_id,
                        "algorithm": "ECDSA_P256_SHA256",
                        "payload": B64.encode(b"x"),
                    })
                    .to_string(),
                ))
                .unwrap();
            let res = app.oneshot(req).await.unwrap();
            prop_assert_eq!(res.status(), StatusCode::BAD_REQUEST);
            Ok(())
        }).unwrap();
    }
}

#[tokio::test]
async fn wire_contract_is_strict() {
    let hsm = Arc::new(MockHsm::new());
    hsm.generate_ecdsa_p256(KeyId::new("k1").unwrap())
        .await
        .unwrap();
    let state = AppState::new(hsm.clone() as Arc<dyn HsmBackend>);
    let app = signing_service::router(state, 1024 * 1024, Duration::from_secs(5));

    let extra = Request::builder()
        .method(Method::POST)
        .uri("/v1/sign")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "key_id": "k1",
                "algorithm": "ECDSA_P256_SHA256",
                "payload": B64.encode(b"x"),
                "extra": "field",
            })
            .to_string(),
        ))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(extra).await.unwrap().status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

    let wrong_type = Request::builder()
        .method(Method::POST)
        .uri("/v1/sign")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "key_id": "k1",
                "algorithm": "ECDSA_P256_SHA256",
                "payload": 12345,
            })
            .to_string(),
        ))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(wrong_type).await.unwrap().status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

    let no_ct = Request::builder()
        .method(Method::POST)
        .uri("/v1/sign")
        .body(Body::from(
            json!({
                "key_id": "k1",
                "algorithm": "ECDSA_P256_SHA256",
                "payload": B64.encode(b"x"),
            })
            .to_string(),
        ))
        .unwrap();
    assert_eq!(
        app.oneshot(no_ct).await.unwrap().status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
}
