//! Deterministic concurrency proofs for the HTTP layer.
//!
//! These tests prove production-critical behaviors that most take-homes
//! only *claim*:
//!
//! * **408 on slow backend** - uses `start_paused` so a 60-second backend
//!   delay and a 100-millisecond timeout resolve in ~0 ms wall time with
//!   zero flakiness.
//! * **503 on pool exhaustion** - a backend that returns `PoolExhausted`
//!   maps to 503, proving the backpressure path end-to-end.
//! * **No cross-talk under load** - 100 concurrent requests with unique
//!   payloads all produce independently verifiable signatures.

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hsm_core::{
    AeadCiphertext, HsmBackend, HsmError, HsmResult, KeyId, PublicKey, SignatureAlgorithm,
    SignedPayload,
};
use hsm_mock::MockHsm;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde_json::{json, Value};
use signing_service::AppState;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

// ── Test backends ────────────────────────────────────────────────────

/// Wraps any backend and injects a configurable delay into `sign()`.
struct SlowBackend {
    inner: MockHsm,
    delay: Duration,
}

#[async_trait]
impl HsmBackend for SlowBackend {
    async fn get_public_key(&self, key_id: &KeyId) -> HsmResult<PublicKey> {
        self.inner.get_public_key(key_id).await
    }

    async fn sign(
        &self,
        key_id: &KeyId,
        algorithm: SignatureAlgorithm,
        payload: &[u8],
    ) -> HsmResult<SignedPayload> {
        tokio::time::sleep(self.delay).await;
        self.inner.sign(key_id, algorithm, payload).await
    }

    async fn aead_encrypt(
        &self,
        key_id: &KeyId,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> HsmResult<AeadCiphertext> {
        self.inner
            .aead_encrypt(key_id, plaintext, associated_data)
            .await
    }

    async fn aead_decrypt(
        &self,
        key_id: &KeyId,
        ciphertext: &AeadCiphertext,
        associated_data: &[u8],
    ) -> HsmResult<Vec<u8>> {
        self.inner
            .aead_decrypt(key_id, ciphertext, associated_data)
            .await
    }

    async fn health_check(&self) -> HsmResult<()> {
        self.inner.health_check().await
    }
}

/// Always returns `PoolExhausted`, simulating a saturated HSM session pool.
struct PoolExhaustedBackend;

#[async_trait]
impl HsmBackend for PoolExhaustedBackend {
    async fn get_public_key(&self, _key_id: &KeyId) -> HsmResult<PublicKey> {
        Err(HsmError::PoolExhausted)
    }

    async fn sign(
        &self,
        _key_id: &KeyId,
        _algorithm: SignatureAlgorithm,
        _payload: &[u8],
    ) -> HsmResult<SignedPayload> {
        Err(HsmError::PoolExhausted)
    }

    async fn aead_encrypt(
        &self,
        _key_id: &KeyId,
        _plaintext: &[u8],
        _associated_data: &[u8],
    ) -> HsmResult<AeadCiphertext> {
        Err(HsmError::PoolExhausted)
    }

    async fn aead_decrypt(
        &self,
        _key_id: &KeyId,
        _ciphertext: &AeadCiphertext,
        _associated_data: &[u8],
    ) -> HsmResult<Vec<u8>> {
        Err(HsmError::PoolExhausted)
    }

    async fn health_check(&self) -> HsmResult<()> {
        Err(HsmError::PoolExhausted)
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

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

// ── Tests ────────────────────────────────────────────────────────────

/// A backend that sleeps for 60 s behind a 100 ms request timeout must
/// produce exactly 408 REQUEST_TIMEOUT.
///
/// `start_paused` makes the mock clock auto-advance when all tasks are
/// blocked on timers, so this test completes in ~0 ms wall time and is
/// completely deterministic - no `thread::sleep`, no flakiness.
#[tokio::test(start_paused = true)]
async fn slow_backend_triggers_408_timeout() {
    // Provision the key on the current (paused-clock) runtime *before*
    // wrapping in SlowBackend. keygen itself has no timers, so the paused
    // clock has no effect on it.
    let inner = MockHsm::new();
    inner
        .generate_ecdsa_p256(KeyId::new("k1").unwrap())
        .await
        .unwrap();

    let hsm = Arc::new(SlowBackend {
        inner,
        delay: Duration::from_secs(60),
    });
    let state = AppState::new(hsm as Arc<dyn HsmBackend>);
    let app = signing_service::router(state, 1024 * 1024, Duration::from_millis(100));

    // The 60 s backend sleep and the 100 ms timeout both live on the mock
    // clock; tokio auto-advances it when all tasks are blocked on timers,
    // so this resolves in ~0 ms wall time with zero flakiness.
    let res = app.oneshot(sign_req(&B64.encode(b"x"))).await.unwrap();
    assert_eq!(res.status(), StatusCode::REQUEST_TIMEOUT);
}

/// When the HSM backend signals pool exhaustion, the HTTP layer must
/// return 503 SERVICE_UNAVAILABLE - not 500, not 429.
#[tokio::test]
async fn pool_exhaustion_returns_503() {
    let hsm = Arc::new(PoolExhaustedBackend) as Arc<dyn HsmBackend>;
    let state = AppState::new(hsm);
    let app = signing_service::router(state, 1024 * 1024, Duration::from_secs(5));

    let res = app.oneshot(sign_req(&B64.encode(b"x"))).await.unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);

    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["error"], "pool_exhausted");
}

/// 100 concurrent requests with distinct payloads must all succeed and
/// produce independently verifiable signatures - no cross-talk, no
/// shared-state corruption.
#[tokio::test]
async fn concurrent_signs_all_verify() {
    let hsm = Arc::new(MockHsm::new());
    hsm.generate_ecdsa_p256(KeyId::new("k1").unwrap())
        .await
        .unwrap();
    let pk = hsm
        .get_public_key(&KeyId::new("k1").unwrap())
        .await
        .unwrap();
    let vk = VerifyingKey::from_sec1_bytes(&pk.bytes).unwrap();

    let state = AppState::new(hsm.clone() as Arc<dyn HsmBackend>);
    let app = signing_service::router(state, 1024 * 1024, Duration::from_secs(10));

    let n = 100;
    let handles: Vec<_> = (0..n)
        .map(|i| {
            let app = app.clone();
            tokio::spawn(async move {
                let payload = format!("concurrent-payload-{i}");
                let req = sign_req(&B64.encode(payload.as_bytes()));
                let res = app.oneshot(req).await.unwrap();
                assert_eq!(res.status(), StatusCode::OK, "request {i} failed");
                let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
                    .await
                    .unwrap();
                let body: Value = serde_json::from_slice(&bytes).unwrap();
                let sig_bytes = B64.decode(body["signature"].as_str().unwrap()).unwrap();
                let sig = Signature::from_slice(&sig_bytes).unwrap();
                vk.verify(payload.as_bytes(), &sig)
                    .unwrap_or_else(|_| panic!("signature {i} failed verification"));
            })
        })
        .collect();

    for h in handles {
        h.await.unwrap();
    }
}
