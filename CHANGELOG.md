# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-10

### Added
- `hsm-core` trait + typed errors (`HsmBackend`, `HsmError`).
- `hsm-pkcs11` SoftHSM2-tested PKCS#11 backend with authenticated
  bounded session pool and non-exportable key provisioning.
- `hsm-mock` in-memory backend for tests/dev.
- `signing-service` Axum HTTP server exposing `POST /v1/sign`,
  `/healthz`, `/readyz`, and Prometheus metrics.
- `load-test` harness with HDR histograms.
- Multi-stage Dockerfile with embedded SoftHSM auto-bootstrap.
- CI (fmt, clippy, test with SoftHSM, cargo-deny).
