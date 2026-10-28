#!/usr/bin/env bash
# Convenience: initialize SoftHSM, provision keys, then run the service.
set -euo pipefail
eval "$(./scripts/init-softhsm.sh)"
./scripts/provision-keys.sh

cat > /tmp/signing-service.toml <<CFG
bind = "0.0.0.0:8080"
max_body_bytes = 1048576
request_timeout_ms = 10000
metrics_bind = "0.0.0.0:9100"

[backend]
kind = "pkcs11"
module_path = "$PKCS11_MODULE"
slot_id = $PKCS11_SLOT
pool_size = 8
acquire_timeout_ms = 2000
CFG

CONFIG_FILE=/tmp/signing-service.toml HSM_PIN="$HSM_PIN" \
    cargo run --release --bin signing-service
