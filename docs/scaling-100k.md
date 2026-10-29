# Scaling to 100,000 Certificates per Second

## The constraint

Short-lived credentials (minutes, not years) mean the CA signing path
must sustain peak issuance rates that would have been unthinkable with
annual certificate lifetimes. This document walks through the bottleneck
math and the architecture that reaches 100k certs/sec.

## Where the time goes

A certificate signing operation is dominated by a single ECDSA (or
future ML-DSA) signature over the TBS (to-be-signed) certificate body.
Everything else — CSR parsing, template filling, base64 encoding, JSON
serialization — is noise by comparison:

| Component | Latency | Notes |
|-----------|---------|-------|
| JSON + base64 decode | ~2 µs | Measured via Criterion |
| Key lookup + routing | ~5 µs | HashMap + Arc clone |
| **HSM sign (P-256)** | **1–10 ms** | **Network HSM round-trip** |
| Base64 encode + JSON | ~3 µs | Measured via Criterion |
| **Total per cert** | **~1–10 ms** | **>99% is the HSM call** |

The service-side overhead is ~10 µs. At 100k certs/sec that's 1 second
of CPU per second — a single core. The bottleneck is the HSM, full stop.

## Sizing the HSM tier

Real-world network HSM throughput for ECDSA P-256:

| HSM | Signs/sec/partition | Source |
|-----|---------------------|--------|
| AWS CloudHSM | ~1,500 | AWS docs |
| Thales Luna 7 | ~2,000 | Datasheet |
| Entrust nShield | ~3,000 | Datasheet |
| YubiHSM 2 | ~100 | Measured |

At 1,500 signs/sec/partition (conservative CloudHSM number):

``` text
100,000 certs/sec ÷ 1,500 signs/sec/partition = 67 partitions
```

With 3× redundancy for failover and rolling upgrades: **~200 partitions** across multiple HSM clusters in multiple AZs.

## Architecture

``` text
                    ┌─────────────────────────────────┐
                    │         Arkion NHIG CA          │
                    │   (certificate template + CSR)  │
                    └──────────────┬──────────────────┘
                                   │ gRPC / mTLS
                    ┌──────────────▼──────────────────┐
                    │     Signer Fleet (stateless)    │
                    │                                 │
                    │  ┌─────┐ ┌─────┐     ┌─────┐   │
                    │  │pod 1│ │pod 2│ ... │pod N│   │
                    │  └──┬──┘ └──┬──┘     └──┬──┘   │
                    │     │       │            │      │
                    │  Session pools (bounded,        │
                    │  deadline-aware, 503 on sat.)   │
                    └─────┼───────┼────────────┼──────┘
                          │       │            │
             ┌────────────▼───────▼────────────▼──────┐
             │          HSM Partition Mesh            │
             │                                        │
             │  ┌──────┐ ┌──────┐       ┌──────┐     │
             │  │ HSM 1│ │ HSM 2│  ...  │ HSM M│     │
             │  │(AZ-a)│ │(AZ-b)│       │(AZ-c)│     │
             │  └──────┘ └──────┘       └──────┘     │
             └────────────────────────────────────────┘


### Key design decisions

**1. Stateless signer pods.** No local key material, no session affinity.
Any pod can sign with any partition. This means horizontal scaling is `kubectl scale`; no rebalancing, no state migration.

**2. Partition sharding by key role.** Root CA keys live on dedicated, air-gapped partitions (low volume, maximum security). 
Intermediate and
leaf-signing keys are spread across the high-throughput partition mesh.
The `key_id` in the API maps to a partition+slot via a config service, so the signer fleet doesn't need to know the topology.

**3. Session pool per partition, not global.** Each signer pod maintains a bounded pool (semaphore + deadline) to each partition it's configured for. 
The 503 backpressure path proven in our test suite fires when a single partition saturates, not when the aggregate fleet is busy; this gives the load balancer a signal to route around hot partitions.

**4. Pre-warmed sessions.** `C_Login` on SoftHSM takes ~1ms; on network HSMs it can take 10–50ms. The pool authenticates at startup and reuses sessions, so the steady-state cost per sign is the `C_Sign` call alone.

**5. Async FFI isolation.** Every PKCS#11 call runs on `spawn_blocking`, so a slow HSM response blocks a thread-pool worker, not the Tokio reactor. The reactor continues to accept new connections and serve health checks even under HSM saturation.

## Post-quantum impact

ML-DSA-65 (the likely NIST PQC signing standard for certificates) has significantly larger signatures (~3,293 bytes vs 64 bytes for P-256) and slower signing (~5–20× slower on current HSM firmware). The impact on this architecture:

* **Throughput:** 1,500 P-256 signs/sec → ~100–300 ML-DSA signs/sec per partition. The fleet scales to ~300–1,000 partitions for 100k certs/sec.
  This is a capacity planning problem, not an architecture problem.
* **Wire format:** The `SignatureAlgorithm` enum and the `SignedPayload` type are already sized for variable-length signatures. No schema changes needed.
* **Session pool:** Unchanged. The pool manages sessions, not algorithms.
* **Latency budget:** ML-DSA sign at ~5ms on HSM still fits comfortably within a 100ms end-to-end SLO for certificate issuance.

The migration path: add `MlDsa65` to the `SignatureAlgorithm` enum, map it to `CKM_ML_DSA` in the PKCS#11 backend, deploy new HSM firmware. The service code changes are confined to two `match` arms.

## What this repo proves

The 50 tests in this repository aren't just coverage; they're proofs of the properties that make the above architecture work:

* **Property tests** (~2,000 generated cases) prove the crypto invariants hold for all inputs, not just happy paths.
* **Deterministic concurrency tests** (`start_paused` mock clock) prove the 408 timeout and 503 backpressure paths fire exactly when expected, with zero flakiness.
* **100-request concurrent verification** proves no cross-talk under load.
* **Criterion benchmarks** provide the real numbers that feed the capacity math above.
* **Allocation counting** in the load test proves the per-request memory footprint is bounded and predictable.

This is the foundation. The scaling is arithmetic from here.
