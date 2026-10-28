# Rust HSM-Backed Signing Service

[![CI](https://github.com/makroumi/rust-hsm-signing-service/actions/workflows/ci.yml/badge.svg)](https://github.com/makroumi/rust-hsm-signing-service/actions)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)

A production-grade Rust service that performs cryptographic signing and
authenticated encryption through a **PKCS#11-compatible HSM** (SoftHSM2 by
default; any Cryptoki module works). Private keys are generated **inside**
the HSM, flagged non-exportable, and are **never** materialised in the
application process.

---

## Highlights

* **Clean hexagonal architecture**: `hsm-core` defines the backend trait;
  `hsm-pkcs11` and `hsm-mock` are swappable implementations.
* **PKCS#11 best practices**: non-exportable key generation
  (`CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false`), label-based lookups,
  bounded authenticated session pool with blocking-FFI isolation.
* **Async-safe FFI**: every Cryptoki call is dispatched via
  `tokio::task::spawn_blocking`; the reactor is never stalled.
* **Backpressure built-in**: session acquisition uses
  `tokio::sync::Semaphore` with a deadline, returning HTTP 503 on
  saturation.
* **Zero secret leakage**: PINs held in `Zeroizing<String>`, custom
  `Debug` impls redact credentials, 5xx errors return opaque bodies.
* **End-to-end testing**: unit, HTTP integration, and PKCS#11
  integration tests. Load generator with HDR histograms for p50/p95/p99.
* **Observability**: structured JSON tracing, Prometheus metrics
  (`signing_duration_ms`, `signing_success_total`), request-id propagation.
* **Container-first**: multi-stage Dockerfile, SoftHSM auto-bootstrap
  entrypoint, non-root user, `tini` PID 1.

---

## Repository layout

├── crates/
│ ├── hsm-core/ # Trait + error/type definitions
│ ├── hsm-mock/ # In-memory backend (dev/test only)
│ ├── hsm-pkcs11/ # SoftHSM2/PKCS#11 production backend
│ ├── signing-service/ # Axum HTTP service (binary)
│ └── load-test/ # Benchmark harness (binary)
├── docker/ # Dockerfile, compose, entrypoint
├── scripts/ # SoftHSM init / key provisioning
└── .github/workflows/ci.yml


---

## Quick start

### 1. Local development with SoftHSM2

Prereqs: `rustc >= 1.75`, `softhsm2-util`, `pkcs11-tool` (from `opensc`).

```zsh
# One-shot: init token, provision keys, run service.
./scripts/dev-run.sh
```

Then in another terminal:
```zsh
curl -s http://localhost:8080/v1/sign \
  -H 'content-type: application/json' \
  -d "$(jq -nc --arg p "$(printf 'hello' | base64)" '
       {key_id:"arkion-intermediate-prod",
        algorithm:"ECDSA_P256_SHA256",
        payload:$p}')" | jq
```
### 2. Mock Backend (no HSM required)
```zsh
cat > /tmp/mock.toml <<'TOML'
bind = "0.0.0.0:8080"
max_body_bytes = 1048576
request_timeout_ms = 5000
[backend]
kind = "mock"
TOML
CONFIG_FILE=/tmp/mock.toml cargo run --release --bin signing-service
```
Preseeded keys: `demo-ecdsa`, `demo-aes`.

### 3. Container
Build + run the whole stack (service + embedded SoftHSM auto-bootstrapped):
```zsh
docker build -f docker/Dockerfile -t makroumi/rust-hsm-signing-service:latest .
docker run --rm -p 8080:8080 -p 9100:9100 \
    makroumi/rust-hsm-signing-service:latest
```

Or with compose:
```zsh
cd docker && docker compose up --build
```

---
## HTTPS API
'POST/v1//sign'
Request
```JSON
{
  "key_id": "arkion-intermediate-prod",
  "algorithm": "ECDSA_P256_SHA256",
  "payload": "<base64>"
}
```

Response:
``` JSON
{
  "key_id": "arkion-intermediate-prod",
  "algorithm": "ECDSA_P256_SHA256",
  "signature": "<base64>",
  "duration_ms": 8
}
````

Status codes:
| Status	| Condition |
|------|-----|
| 200	| success|
| 400	| malformed JSON / bad base64 / bad key_id charset / empty body |
|404	| key_id not present in HSM |
| 401	| HSM authentication failure |
| 503	| session pool exhausted or HSM unavailable (retry with backoff) | 
| 500	| unexpected backend failure (opaque body) |

`GET /healthz, GET /readyz`
Liveness and readiness. `/readyz` performs a lightweight session acquire-and-release angainst the HSM.

`GET /metrics` (optional)
Exposed on `metrics_bind` (default disabled). Prometheus text format:
- `signing_duration_ms{algorithm} - histogram`
- `signing_success_total{algorithm} - counter

---

## Configuration
Loaded via `CONFIG_FILE` (TOML/TAML/JSON) with `APP__*` env override.
Example TOML:
``` toml
bind              = "0.0.0.0:8080"
max_body_bytes    = 1048576
request_timeout_ms = 10000
metrics_bind      = "0.0.0.0:9100"

[backend]
kind              = "pkcs11"
module_path       = "/usr/lib/softhsm/libsofthsm2.so"
slot_id           = 707482493
pool_size         = 16
acquire_timeout_ms = 2000
```
The HSN PIN is **never** read from confih; set `HSM_PIN` as an env var or mount it as a secrect. The service holds its in `Zeroizing<String>` and redacts it from debug output.

---

## HSM & key-management approach
- **ECDSA P-256 key pair:** generated via `C_GenerateKeyPair` with `CKM_ECDSA_KEY_PAIR_GEN`. Private key attributes: `CKA_TOKEN=true`, `CKA_PRIVATE=true`, `CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false`, `CKA_SIGN=true`. Public key marked`CKA_VERIFY=true.`
- **AES-256 secret key:** generated via `CKM_AES_KEY_GEN` `CKA_VALUE_LEN=32`, `CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false`, `CKA_ENCRYPT=true`,x`CKA_DECRYPT=true`. Demonstrated by AES-GCM encrypt/decrypt with per-message random 96-bit IVs.
- **Signing path:** `CKM_ECDSA_SHA256` performs hash + sign in a singlevHSM round trip. Signatures are `raw r||s` (64 bytes), the format required by most CA tooling (e.g. CFSSL, step-ca).
- Verification: pure-Rust `p256` crate verifies against the SEC1-encoded public key fetched from the HSM which ensures end-to-end integrity in integration tests.
- Lookup: `CKA_LABEL`-based (stable, operator-friendly). `KeyId` validation prevents injection into labels / logs.
- Credentials: `HSM_PIN` env var only; captured once at startup into zeroizing storage.

---
## Archittecture
``` text
          ┌──────────────────┐
HTTP ───▶ │  Axum router     │─── middleware: trace, request-id,
          │  (signing-svc)   │               body-limit, timeout
          └────────┬─────────┘
                   │ Arc<dyn HsmBackend>
          ┌────────▼─────────┐          ┌─────────────────┐
          │  HsmBackend trait │◀────────│  hsm-mock (test)│
          │   (hsm-core)      │         └─────────────────┘
          └────────┬─────────┘
                   │
          ┌────────▼─────────────────────┐
          │  Pkcs11Hsm (hsm-pkcs11)      │
          │  ┌─────────────────────────┐ │
          │  │  SessionPool (Semaphore)│ │
          │  │  N× authenticated R/W   │─┼──▶ libsofthsm2 / vendor .so
          │  │  sessions, reused.      │ │     (blocking FFI inside
          │  └─────────────────────────┘ │      spawn_blocking)
          └──────────────────────────────┘
```
Design decisions:
- **Why a trait?** PCKS#11 is slow in test loops and painful on CI macOS. `MockHsm lets us run thousands of HTTP tests in milliseconds without compromising on real integration coverage.
- **Why pool sessions instead of poolong the HSM module?** PKCS#11 `c_login` is per-session and expensive (~ms on SoftHSM, ~tens of ms on real HSMs). Login once at startup, reuse. Sessions are single threaded by spec, so one session per in-flight op.
- **Why `spawn_blocking`?** Cryptoki is sync C FFI. Running it on the reactor would stall every other task; isolating it keeps p99 for non_sign routes (health, metrics) tight.
- **Why label-based lookup?** `CKA_ID` is also  fine but labels are human-readable, operator-friendly, and align with industry CA tooling.

---
## Conccurency & session management

The `SessionPool` enforces:

| **Mechanism** |	**Effect** |
| --------- | --------- |
| `Semaphore(N)` |	Hard cap on in-flight HSM ops |
| `acquire_timeout` |	Deadline → `PoolExhausted` → HTTP 503 (backpressure) |
| `Session reuse` | Avoids `C_Login` per request |
| `spawn_blocking`	| Keeps reactor responsive |
| `tower-http Timeout` |	Request-level deadline, cancels pending acquires |

### Benchmark harness

Build & run:
```zsh
cargo run --release -p load-test -- \
    --url http://localhost:8080/v1/sign \
    --key-id arkion-intermediate-prod \
    --concurrencies 1,10,100,500 \
    --duration-secs 20
```

---

## Architecture question: 100k signatures/sec

**Problem:** 100 kops/s of leaf cert signing exceeds any single HSM (nShield Connect XC: ~10k ECDSA/s; CloudHSM: ~1–3k/s per cluster member).

Design:

    **1. Multi-tier CA hierarchy**
        - **Offline root CA** (air-gapped HSM, quorum-controlled): signs intermediates only. Zero online exposure.
        - **Online intermediate CAs** (HSM-resident): sign short-lived signing certificates for stateless leaf-signers. Low rate.
        - **Leaf signers** (per region, horizontally scalable): hold short-lived (minutes–hours) delegated certs + corresponding private keys in memory (never persisted),sign leaf certs in software using well-audited crypto (e.g. ring/rustls). This is the pattern used by Let's Encrypt (Boulder), Cloudflare, and Fulcio.

    ** 2. Why not sign every leaf in the HSM?**
        - HSM throughput is 1–3 orders of magnitude below target.
        - HSM ops cost real money (CloudHSM ≈ $1.60/hr/instance; sustained 100k/s would be absurd).
        - Horizontal scaling of HSMs is bounded by vendor cluster limits (CloudHSM: 28 HSMs; nShield: tens with care).

    ** 3.Key wrapping alternative **
    For workflows that must remain fully HSM-contained (e.g. qualified signatures), use the HSM's AES wrapping key to wrap/unwrap ephemeral signing keys. Signers unwrap once per epoch, hold the plaintext key in a locked memory region, sign at line rate, then discard. Compromise window = epoch length. This is still slower than pure software signing but much faster than per-op HSM calls.

    ** 4. Regional capacity & failover**
        - Deploy ≥3 regions, each with its own intermediate CA + HSM cluster.
        - Leaf signers are stateless; auto-scale on CPU.
        - Health-check surfaces HSM saturation (PoolExhausted → 503) so Envoy/ALB can drain + reroute.
        - CT (Certificate Transparency) logs provide global audit; losing a region never loses the audit trail.

    ** 5. Security implications**
        - The attacker surface moves from "steal HSM" to "steal an in-memory
        epoch key". Mitigated by:
            - Short epochs (minutes).
            - Signing cert name constraints (Boulder-style) so a compromised signer cannot mint for arbitrary domains.
            - Memory hardening (MADV_DONTDUMP, mlock, Zeroize on epoch rotation).
            - Hardware attestation (TPM / SEV-SNP) of the signer image.
       -  CT logs + per-signer rate limits catch misuse within minutes.

    ** 6. Cost model
        - HSM ops: ~100 intermediate signings/day (one per signer per epoch).
        That's ~$4k/mo for a 3-region CloudHSM footprint — fixed, not per-leaf.
        - Software signers: commodity compute, auto-scale on QPS.

    Trade-offs summary

| **Approach | Throughput |	Compromise blast radius	| Cost | Compliance |
| Every leaf in HSM |	~10k/s cap |	HSM only | $$$$$ |	 highest |
| Wrapped epoch keys |	~100k/s |	1 epoch of leaves |	$$	| with attestation |
| Delegated short-lived |	1M/s+ |	1 epoch of leaves	| $ |	 (LE/Fulcio proven) |

**Recommendation:** tiered CA + delegated short-lived signers with HSM-rooted intermediates; the only option that meets throughput while keeping blast radius bounded.

---
## Security considerations
- Private + symmetric keys never leave the HSM (enforced at generation).
- `HSM_PIN` loaded once, held in `Zeroizing`, redacted from `Debug`.
- No sensitive payloads logged. Request body size capped (`max_body_bytes`).
- 5xx responses return opaque `"internal error"` bodies.
- Request IDs propagated for cross-service correlation without exposing internal state.
- Container: non-root user, read-only root FS compatible, `tini` PID 1 for correct signal handling.
- `cargo deny` enforces licence + advisory policy in CI.

## Known limitations
- The mock backend is clearly labelled as dev/test; a warning is logged on startup.
- Only `ECDSA_P256_SHA256` is wired through the API; adding RSA-PSS or Ed25519 is ~20 line extension (`SignatureAlgorithm` + mechanism map).
- `cryptoki` surfaces `CKR_FUNCTION_CANCELED` as backend error; a future enhancement would map common Cryptoki return codes 1:1.

---
## Testing
```zsh
# Full suite (mock-backed tests, no HSM needed)
cargo test --workspace

# PKCS#11 integration tests (requires SoftHSM env)
eval "$(./scripts/init-softhsm.sh)"
./scripts/provision-keys.sh
cargo test --workspace --all-targets

# Lint
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Supply chain
cargo deny check
```
Coverage includes:

    - Unit tests for key id validation, algorithm mapping, mock backend round-trips, AEAD tamper detection.
    - HTTP integration tests for happy path, unknown key, bad base64,invalid charset, empty payload, malformed JSON, health routes.
    - PKCS#11 integration tests (sign+verify, AES-GCM) gated on `PKCS11_MODULE` env.
---
## Production considerations
- **Secrets**: inject `HSM_PIN` via a secrets manager (Vault,
AWS Secrets Manager, Kubernetes `Secret` with `envFrom`). Never bake into the image.
- **Pool sizing**: start at `min(hsm_concurrent_ops, cpu_cores * 2)`.
Monitor `signing_duration_ms p99` and `pool_exhausted_total (503s) to tune.
- **HPA signal:** scale on 503 rate rather than CPU; HSM is the bottleneck.
- **TLS:** terminate at an ingress proxy (Envoy/nginx) or add
`axum-server` with rustls; intentionally omitted here to keep the code focused on the HSM path.
- **AuthN/Z:** this service exposes a privileged operation. In production, require a mutual-TLS client cert or signed JWT in a `tower` middleware before `/v1/sign`.
- **Audit:** forward structured logs to an append-only log store; include `key_id`, request id, duration. Never log payloads.