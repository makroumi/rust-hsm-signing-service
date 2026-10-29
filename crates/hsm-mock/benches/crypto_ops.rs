//! Micro-benchmarks for the HSM backend operations.
//!
//! Run: `cargo bench -p hsm-mock`
//!
//! These numbers feed the README performance table and the 100k certs/sec
//! scaling essay. They measure the *service-side* cost (sign, verify,
//! encrypt, decrypt, base64, JSON) exclusive of network and HSM latency.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hsm_core::{HsmBackend, KeyId, SignatureAlgorithm};
use hsm_mock::MockHsm;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn bench_ecdsa(c: &mut Criterion) {
    let rt = rt();
    let hsm = MockHsm::new();
    let kid = KeyId::new("bench-ec").unwrap();
    rt.block_on(hsm.generate_ecdsa_p256(kid.clone())).unwrap();
    let pk = rt.block_on(hsm.get_public_key(&kid)).unwrap();

    let mut group = c.benchmark_group("ecdsa-p256");
    for size in [64, 1024, 8192] {
        let payload = vec![0xAB_u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("sign", size), &payload, |b, p| {
            b.iter(|| {
                rt.block_on(hsm.sign(&kid, SignatureAlgorithm::EcdsaP256Sha256, p))
                    .unwrap()
            });
        });
        let sig = rt
            .block_on(hsm.sign(&kid, SignatureAlgorithm::EcdsaP256Sha256, &payload))
            .unwrap();
        group.bench_with_input(BenchmarkId::new("verify", size), &payload, |b, p| {
            use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
            let vk = VerifyingKey::from_sec1_bytes(&pk.bytes).unwrap();
            let s = Signature::from_slice(&sig.signature).unwrap();
            b.iter(|| vk.verify(p, &s).unwrap());
        });
    }
    group.finish();
}

fn bench_aes_gcm(c: &mut Criterion) {
    let rt = rt();
    let hsm = MockHsm::new();
    let kid = KeyId::new("bench-aes").unwrap();
    rt.block_on(hsm.generate_aes256(kid.clone())).unwrap();

    let mut group = c.benchmark_group("aes-256-gcm");
    for size in [64, 1024, 8192, 65536] {
        let pt = vec![0xCD_u8; size];
        let aad = b"bench-aad";
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("encrypt", size), &pt, |b, p| {
            b.iter(|| rt.block_on(hsm.aead_encrypt(&kid, p, aad)).unwrap());
        });
        let ct = rt.block_on(hsm.aead_encrypt(&kid, &pt, aad)).unwrap();
        group.bench_with_input(BenchmarkId::new("decrypt", size), &pt, |b, _| {
            b.iter(|| rt.block_on(hsm.aead_decrypt(&kid, &ct, aad)).unwrap());
        });
    }
    group.finish();
}

fn bench_base64(c: &mut Criterion) {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let mut group = c.benchmark_group("base64");
    for size in [64, 1024, 8192] {
        let data = vec![0xEF_u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("encode", size), &data, |b, d| {
            b.iter(|| B64.encode(d));
        });
        let encoded = B64.encode(&data);
        group.bench_with_input(BenchmarkId::new("decode", size), &encoded, |b, e| {
            b.iter(|| B64.decode(e).unwrap());
        });
    }
    group.finish();
}

criterion_group!(benches, bench_ecdsa, bench_aes_gcm, bench_base64);
criterion_main!(benches);
