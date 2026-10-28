#!/usr/bin/env bash
# Provision canonical demo keys inside the configured SoftHSM token
# using pkcs11-tool. Requires: opensc.
set -euo pipefail
: "${PKCS11_MODULE:?run scripts/init-softhsm.sh first}"
: "${PKCS11_SLOT:?run scripts/init-softhsm.sh first}"
: "${PKCS11_PIN:?run scripts/init-softhsm.sh first}"

KEY_LABEL="${KEY_LABEL:-arkion-intermediate-prod}"
AES_LABEL="${AES_LABEL:-arkion-wrap-prod}"

echo ">> generating ECDSA P-256 key pair labelled $KEY_LABEL"
pkcs11-tool --module "$PKCS11_MODULE" --slot "$PKCS11_SLOT" --login --pin "$PKCS11_PIN" \
    --keypairgen --key-type EC:prime256v1 --label "$KEY_LABEL" \
    --usage-sign --sensitive --private >/dev/null

echo ">> generating AES-256 key labelled $AES_LABEL"
pkcs11-tool --module "$PKCS11_MODULE" --slot "$PKCS11_SLOT" --login --pin "$PKCS11_PIN" \
    --keygen --key-type AES:32 --label "$AES_LABEL" \
    --usage-wrap --sensitive --private >/dev/null

echo "done."
