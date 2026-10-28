#!/usr/bin/env bash
set -euo pipefail

if [[ "${INIT_SOFTHSM:-1}" == "1" ]]; then
    eval "$(/usr/local/bin/init-softhsm.sh)"
    /usr/local/bin/provision-keys.sh || true
fi

: "${PKCS11_MODULE:?missing}"
: "${PKCS11_SLOT:?missing}"
: "${HSM_PIN:?missing}"

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

export CONFIG_FILE=/tmp/signing-service.toml
exec /usr/local/bin/signing-service
