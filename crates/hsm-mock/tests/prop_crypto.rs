//! Property-based tests for the in-memory HSM backend.

use hsm_core::{AeadCiphertext, HsmBackend, KeyId, SignatureAlgorithm};
use hsm_mock::MockHsm;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use proptest::collection::vec;
use proptest::prelude::*;

fn test_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio rt")
}

async fn fresh_ecdsa() -> (MockHsm, KeyId, VerifyingKey) {
    let hsm = MockHsm::new();
    let kid = KeyId::new("prop-ecdsa").unwrap();
    let pk = hsm.generate_ecdsa_p256(kid.clone()).await.unwrap();
    let vk = VerifyingKey::from_sec1_bytes(&pk.bytes).unwrap();
    (hsm, kid, vk)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn ecdsa_signs_verify_for_all_payloads(payload in vec(any::<u8>(), 1..=4096)) {
        test_rt().block_on(async move {
            let (hsm, kid, vk) = fresh_ecdsa().await;
            let sig = hsm.sign(&kid, SignatureAlgorithm::EcdsaP256Sha256, &payload).await.unwrap();
            prop_assert_eq!(sig.signature.len(), 64);
            let s = Signature::from_slice(&sig.signature).unwrap();
            prop_assert!(vk.verify(&payload, &s).is_ok());
            Ok(())
        }).unwrap();
    }

    #[test]
    fn ecdsa_signing_is_deterministic(payload in vec(any::<u8>(), 1..=1024)) {
        test_rt().block_on(async move {
            let (hsm, kid, _) = fresh_ecdsa().await;
            let a = hsm.sign(&kid, SignatureAlgorithm::EcdsaP256Sha256, &payload).await.unwrap();
            let b = hsm.sign(&kid, SignatureAlgorithm::EcdsaP256Sha256, &payload).await.unwrap();
            prop_assert_eq!(a.signature, b.signature);
            Ok(())
        }).unwrap();
    }

    #[test]
    fn distinct_payloads_distinct_signatures(
        (p1, p2) in (vec(any::<u8>(), 1..=256), vec(any::<u8>(), 1..=256))
    ) {
        test_rt().block_on(async move {
            if p1 == p2 { return Ok(()); }
            let (hsm, kid, _) = fresh_ecdsa().await;
            let s1 = hsm.sign(&kid, SignatureAlgorithm::EcdsaP256Sha256, &p1).await.unwrap();
            let s2 = hsm.sign(&kid, SignatureAlgorithm::EcdsaP256Sha256, &p2).await.unwrap();
            prop_assert_ne!(s1.signature, s2.signature);
            Ok(())
        }).unwrap();
    }

    #[test]
    fn signature_bit_flips_fail(
        (payload, byte_idx, bit_idx) in (vec(any::<u8>(), 1..=1024), 0usize..64, 0u8..8)
    ) {
        test_rt().block_on(async move {
            let (hsm, kid, vk) = fresh_ecdsa().await;
            let sig = hsm.sign(&kid, SignatureAlgorithm::EcdsaP256Sha256, &payload).await.unwrap();
            let mut c = sig.signature.clone();
            c[byte_idx] ^= 1u8 << bit_idx;
            if let Ok(s) = Signature::from_slice(&c) {
                prop_assert!(vk.verify(&payload, &s).is_err());
            }
            Ok(())
        }).unwrap();
    }

    #[test]
    fn aes_gcm_roundtrips_all_sizes(
        (pt, aad) in (vec(any::<u8>(), 0..=4096), vec(any::<u8>(), 0..=64))
    ) {
        test_rt().block_on(async move {
            let hsm = MockHsm::new();
            let kid = KeyId::new("prop-aes").unwrap();
            hsm.generate_aes256(kid.clone()).await.unwrap();
            let ct = hsm.aead_encrypt(&kid, &pt, &aad).await.unwrap();
            prop_assert_eq!(ct.iv.len(), 12);
            prop_assert_eq!(ct.ciphertext_and_tag.len(), pt.len() + 16);
            let back = hsm.aead_decrypt(&kid, &ct, &aad).await.unwrap();
            prop_assert_eq!(back, pt);
            Ok(())
        }).unwrap();
    }

    #[test]
    fn aes_gcm_rejects_bit_tampering(
        (pt, aad, target, idx, bit_idx) in (
            vec(any::<u8>(), 1..=512),
            vec(any::<u8>(), 0..=64),
            0u8..3,
            any::<usize>(),
            0u8..8,
        )
    ) {
        test_rt().block_on(async move {
            let hsm = MockHsm::new();
            let kid = KeyId::new("prop-aes").unwrap();
            hsm.generate_aes256(kid.clone()).await.unwrap();
            let ct = hsm.aead_encrypt(&kid, &pt, &aad).await.unwrap();
            match target % 3 {
                0 => {
                    let mut c = ct.ciphertext_and_tag.clone();
                    let i = idx % c.len(); c[i] ^= 1u8 << bit_idx;
                    let t = AeadCiphertext { iv: ct.iv.clone(), ciphertext_and_tag: c };
                    prop_assert!(hsm.aead_decrypt(&kid, &t, &aad).await.is_err());
                }
                1 => {
                    let mut iv = ct.iv.clone();
                    let i = idx % iv.len(); iv[i] ^= 1u8 << bit_idx;
                    let t = AeadCiphertext { iv, ciphertext_and_tag: ct.ciphertext_and_tag.clone() };
                    prop_assert!(hsm.aead_decrypt(&kid, &t, &aad).await.is_err());
                }
                _ => {
                    let bad = if aad.is_empty() { vec![0u8] } else {
                        let mut a = aad.clone(); let i = idx % a.len(); a[i] ^= 1u8 << bit_idx; a
                    };
                    prop_assert!(hsm.aead_decrypt(&kid, &ct, &bad).await.is_err());
                }
            }
            Ok(())
        }).unwrap();
    }

    #[test]
    fn aes_gcm_rejects_truncation_extension(
        (pt, mode) in (vec(any::<u8>(), 1..=256), 0u8..4)
    ) {
        test_rt().block_on(async move {
            let hsm = MockHsm::new();
            let kid = KeyId::new("prop-aes").unwrap();
            hsm.generate_aes256(kid.clone()).await.unwrap();
            let ct = hsm.aead_encrypt(&kid, &pt, b"aad").await.unwrap();
            let t = match mode % 4 {
                0 => { let mut c = ct.ciphertext_and_tag.clone(); c.pop();
                       AeadCiphertext { iv: ct.iv.clone(), ciphertext_and_tag: c } }
                1 => { let mut c = ct.ciphertext_and_tag.clone(); c.push(0);
                       AeadCiphertext { iv: ct.iv.clone(), ciphertext_and_tag: c } }
                2 => { let mut iv = ct.iv.clone(); iv.pop();
                       AeadCiphertext { iv, ciphertext_and_tag: ct.ciphertext_and_tag.clone() } }
                _ => { let mut iv = ct.iv.clone(); iv.push(0);
                       AeadCiphertext { iv, ciphertext_and_tag: ct.ciphertext_and_tag.clone() } }
            };
            let err = hsm.aead_decrypt(&kid, &t, b"aad").await.expect_err("must reject");
            prop_assert!(matches!(err,
                hsm_core::HsmError::AuthenticationFailed | hsm_core::HsmError::InvalidInput(_)));
            Ok(())
        }).unwrap();
    }
}
