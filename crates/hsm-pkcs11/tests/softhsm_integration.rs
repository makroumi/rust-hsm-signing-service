//! Integration tests that run against a real SoftHSM2 token.
//!
//! Skipped unless the following env vars are set:
//! * `PKCS11_MODULE` - path to libsofthsm2.so
//! * `PKCS11_SLOT`   - numeric slot id
//! * `PKCS11_PIN`    - user PIN
//!
//! A helper script `scripts/init-softhsm.sh` provisions a disposable token.

use hsm_core::{HsmBackend, KeyId, SignatureAlgorithm};
use hsm_pkcs11::{Pkcs11Config, Pkcs11Hsm};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use std::{path::PathBuf, time::Duration};
use zeroize::Zeroizing;

fn env_config() -> Option<Pkcs11Config> {
    let module = PathBuf::from(std::env::var("PKCS11_MODULE").ok()?);
    if !module.exists() {
        eprintln!("SKIP: PKCS11_MODULE {} not found", module.display());
        return None;
    }
    Some(Pkcs11Config {
        module_path: module,
        slot_id: std::env::var("PKCS11_SLOT").ok()?.parse().ok()?,
        user_pin: Zeroizing::new(std::env::var("PKCS11_PIN").ok()?),
        pool_size: 4,
        acquire_timeout: Duration::from_secs(5),
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ecdsa_end_to_end_against_softhsm() {
    let Some(cfg) = env_config() else {
        eprintln!("skipping: PKCS11 env not set");
        return;
    };
    let hsm = Pkcs11Hsm::new(cfg).await.expect("init pkcs11");
    let kid = KeyId::new(format!("it-ecdsa-{}", uuid::Uuid::new_v4().simple())).unwrap();
    hsm.provisioner().generate_ecdsa_p256(&kid).await.unwrap();

    let pk = hsm.get_public_key(&kid).await.unwrap();
    assert_eq!(pk.bytes.len(), 65, "uncompressed SEC1 point");
    assert_eq!(pk.bytes[0], 0x04);

    let msg = b"integration-test-message";
    let sig = hsm
        .sign(&kid, SignatureAlgorithm::EcdsaP256Sha256, msg)
        .await
        .unwrap();
    assert_eq!(sig.signature.len(), 64, "raw r||s");

    let vk = VerifyingKey::from_sec1_bytes(&pk.bytes).unwrap();
    let s = Signature::from_slice(&sig.signature).unwrap();
    vk.verify(msg, &s).expect("verify should succeed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aes_gcm_against_softhsm() {
    let Some(cfg) = env_config() else {
        eprintln!("skipping: PKCS11 env not set");
        return;
    };
    let hsm = Pkcs11Hsm::new(cfg).await.unwrap();
    let kid = KeyId::new(format!("it-aes-{}", uuid::Uuid::new_v4().simple())).unwrap();
    hsm.provisioner().generate_aes256(&kid).await.unwrap();

    let pt = b"top secret";
    let aad = b"ctx";
    let ct = hsm.aead_encrypt(&kid, pt, aad).await.unwrap();
    assert_eq!(ct.iv.len(), 12);
    assert_ne!(ct.ciphertext_and_tag.as_slice(), pt);
    let roundtrip = hsm.aead_decrypt(&kid, &ct, aad).await.unwrap();
    assert_eq!(roundtrip, pt);
}
