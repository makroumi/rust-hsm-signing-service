#!/usr/bin/env bash
# Initialize a disposable SoftHSM2 token for local/dev/CI use.
# Prints the env vars to export to your shell.
set -euo pipefail

TOKEN_DIR="${TOKEN_DIR:-$(pwd)/.softhsm/tokens}"
CONF="${TOKEN_DIR%/tokens}/softhsm2.conf"
SO_PIN="${SO_PIN:-12345678}"
USER_PIN="${USER_PIN:-1234}"
LABEL="${LABEL:-arkion-dev}"

mkdir -p "$TOKEN_DIR"
cat > "$CONF" <<CONF
directories.tokendir = $TOKEN_DIR
objectstore.backend = file
log.level = ERROR
CONF
export SOFTHSM2_CONF="$CONF"

# Reinitialize if already present.
softhsm2-util --delete-token --token "$LABEL" >/dev/null 2>&1 || true
softhsm2-util --init-token --free --label "$LABEL" \
    --so-pin "$SO_PIN" --pin "$USER_PIN" >/dev/null

# Resolve slot (SoftHSM assigns a dynamic one).
SLOT=$(softhsm2-util --show-slots | awk -v L="$LABEL" '
    /^Slot [0-9]+/ { slot=$2 }
    $1=="Label:" && $2==L { print slot; exit }
')

MODULE_CANDIDATES=(
    /usr/lib/softhsm/libsofthsm2.so
    /usr/lib64/softhsm/libsofthsm2.so
    /usr/local/lib/softhsm/libsofthsm2.so
    /opt/homebrew/lib/softhsm/libsofthsm2.so
    /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
)
for p in "${MODULE_CANDIDATES[@]}"; do
    if [[ -f "$p" ]]; then MODULE="$p"; break; fi
done
: "${MODULE:?libsofthsm2.so not found - set MODULE manually}"

cat <<EOT
# SoftHSM2 token initialized.
export SOFTHSM2_CONF="$CONF"
export PKCS11_MODULE="$MODULE"
export PKCS11_SLOT="$SLOT"
export PKCS11_PIN="$USER_PIN"
export HSM_PIN="$USER_PIN"
EOT
