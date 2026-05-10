#!/usr/bin/env bash
# idv2 — build all four Pinocchio programs for SBF and deploy to devnet.
#
# Assumes keygen.sh has run (program keypairs in .keys/programs/) and the
# authority keypair is funded (airdrop.sh). Uses `cargo build-sbf` and
# `solana program deploy --program-id <keypair>` so the program ID is
# stable across redeploys.

set -euo pipefail

log() { printf "\033[1;34m[idv2-deploy]\033[0m %s\n" "$*"; }
err() { printf "\033[1;31m[idv2-deploy]\033[0m %s\n" "$*" >&2; }

KEYS_DIR="${KEYS_DIR:-.keys}"
PROGRAM_KEYS_DIR="$KEYS_DIR/programs"
RPC_URL="${RPC_URL:-https://api.devnet.solana.com}"
#WORKSPACE_DIR="${WORKSPACE_DIR:-rust-workspace}"
WORKSPACE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_DIR="$WORKSPACE_DIR/target/deploy"

if ! command -v cargo-build-sbf >/dev/null 2>&1; then
  err "cargo-build-sbf missing. Run ./scripts/install.sh first."
  exit 1
fi

log "building all programs for SBF (release)"
(cd "$WORKSPACE_DIR" && cargo build-sbf -- \
  -p election_registry \
  -p voter_registry \
  -p ballot \
  -p tally)

for prog in election_registry voter_registry ballot tally; do
  so="$TARGET_DIR/${prog}.so"
  kp="$PROGRAM_KEYS_DIR/${prog}.json"
  if [ ! -f "$so" ]; then
    err "build output missing: $so"; exit 1
  fi
  if [ ! -f "$kp" ]; then
    err "program keypair missing: $kp (run ./scripts/keygen.sh)"; exit 1
  fi

  log "deploying $prog → $(solana-keygen pubkey "$kp")"
  solana program deploy \
    --url "$RPC_URL" \
    --keypair "$KEYS_DIR/authority.json" \
    --program-id "$kp" \
    "$so"
done

log "all four programs deployed. Program IDs:"
for prog in election_registry voter_registry ballot tally; do
  printf "  %-20s %s\n" "$prog" "$(solana-keygen pubkey "$PROGRAM_KEYS_DIR/$prog.json")"
done
