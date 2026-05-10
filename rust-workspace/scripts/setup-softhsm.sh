#!/usr/bin/env bash
# setup-softhsm.sh — configure SoftHSM2 environment for idv2 development
#
# Run once (or source in your shell profile):
#   source scripts/setup-softhsm.sh
#
# Then run the key ceremony to generate K_wrap, attestation key, and Ed25519
# signing key inside the token:
#   cargo run -p enclave --bin key_ceremony

set -euo pipefail

# ── Library and config ────────────────────────────────────────────────────────
export SOFTHSM2_LIB="/opt/homebrew/Cellar/softhsm/2.7.0/lib/softhsm/libsofthsm2.so"
export SOFTHSM2_CONF="/opt/homebrew/etc/softhsm/softhsm2.conf"

if [[ ! -f "$SOFTHSM2_LIB" ]]; then
    echo "ERROR: SoftHSM2 library not found at $SOFTHSM2_LIB"
    echo "       Install via: brew install softhsm"
    exit 1
fi

echo "SOFTHSM2_LIB=$SOFTHSM2_LIB"
echo "SOFTHSM2_CONF=$SOFTHSM2_CONF"

# ── Token initialisation ──────────────────────────────────────────────────────
# We use a single token (idv2-dev) for all demo operations.
# The three-slot production layout (root/booth/voter) is documented in HSM.md.
IDV2_TOKEN_LABEL="idv2-dev"
IDV2_TOKEN_PIN="${IDV2_TOKEN_PIN:-1234}"
IDV2_SO_PIN="${IDV2_SO_PIN:-0000}"

EXISTING=$(softhsm2-util --show-slots 2>&1 | grep "Label:" | grep -c "$IDV2_TOKEN_LABEL" || true)

if [[ "$EXISTING" -eq 0 ]]; then
    echo "Initialising token '$IDV2_TOKEN_LABEL'..."
    softhsm2-util --init-token \
        --free \
        --label "$IDV2_TOKEN_LABEL" \
        --pin "$IDV2_TOKEN_PIN" \
        --so-pin "$IDV2_SO_PIN"
    echo "Token initialised."
else
    echo "Token '$IDV2_TOKEN_LABEL' already exists — skipping init."
fi

echo ""
echo "SoftHSM2 ready.  Next step:"
echo "  cargo run -p enclave --bin key_ceremony"
echo ""
echo "To make these env vars permanent add to ~/.zshrc or ~/.bashrc:"
echo "  export SOFTHSM2_LIB=\"$SOFTHSM2_LIB\""
echo "  export SOFTHSM2_CONF=\"$SOFTHSM2_CONF\""
echo "  export IDV2_TOKEN_PIN=\"$IDV2_TOKEN_PIN\""
