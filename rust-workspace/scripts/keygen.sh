#!/usr/bin/env bash
# idv2 — generate the devnet keypair set.
#
# Produces (idempotent; skip if file exists):
#   .keys/authority.json                     — authority signer for idv2-admin
#   .keys/relayer.json                       — fee payer for voter/ballot txs
#   .keys/aggregation.json                   — Ed25519 aggregation signer (dev only; prod in HSM)
#   .keys/programs/election_registry.json    — program IDs (stable across deploys)
#   .keys/programs/voter_registry.json
#   .keys/programs/ballot.json
#   .keys/programs/tally.json
#
# .keys/ is gitignored. DO NOT commit private keys. Pubkeys are written to
# .keys/PUBKEYS.txt for reference and can safely be committed if you want.

set -euo pipefail

log() { printf "\033[1;34m[idv2-keygen]\033[0m %s\n" "$*"; }

KEYS_DIR="${KEYS_DIR:-.keys}"
PROGRAM_KEYS_DIR="$KEYS_DIR/programs"
mkdir -p "$PROGRAM_KEYS_DIR"

gen_keypair() {
  local path="$1"
  if [ -f "$path" ]; then
    log "keeping $path (exists)"
  else
    solana-keygen new --no-bip39-passphrase --silent --outfile "$path"
    log "created $path"
  fi
}

# Principal signers
gen_keypair "$KEYS_DIR/authority.json"
gen_keypair "$KEYS_DIR/relayer.json"
gen_keypair "$KEYS_DIR/aggregation.json"

# Program keypairs (one per Pinocchio program; the file is the canonical program ID)
for prog in election_registry voter_registry ballot tally; do
  gen_keypair "$PROGRAM_KEYS_DIR/$prog.json"
done

# Emit a pubkey manifest for reference
{
  echo "# idv2 pubkey manifest — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# Safe to commit. Private keys live alongside these files and must NOT be committed."
  echo
  echo "authority   = $(solana-keygen pubkey $KEYS_DIR/authority.json)"
  echo "relayer     = $(solana-keygen pubkey $KEYS_DIR/relayer.json)"
  echo "aggregation = $(solana-keygen pubkey $KEYS_DIR/aggregation.json)"
  echo
  for prog in election_registry voter_registry ballot tally; do
    echo "$prog = $(solana-keygen pubkey $PROGRAM_KEYS_DIR/$prog.json)"
  done
} > "$KEYS_DIR/PUBKEYS.txt"

log "wrote $KEYS_DIR/PUBKEYS.txt"
cat "$KEYS_DIR/PUBKEYS.txt"
