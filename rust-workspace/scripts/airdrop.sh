#!/usr/bin/env bash
# idv2 — airdrop SOL to every keypair that pays fees.
#
# Devnet faucet caps single-shot airdrops at 2 SOL and applies per-IP cooldowns.
# We loop with a short pause; if you hit the cap, wait ~1 hour or use the
# web faucet (https://faucet.solana.com) as a fallback.

set -euo pipefail

log() { printf "\033[1;34m[idv2-airdrop]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[idv2-airdrop]\033[0m %s\n" "$*"; }

KEYS_DIR="${KEYS_DIR:-.keys}"
RPC_URL="${RPC_URL:-https://api.devnet.solana.com}"
AMOUNT="${AMOUNT:-2}"

solana config set --url "$RPC_URL" >/dev/null

for path in \
  "$KEYS_DIR/authority.json" \
  "$KEYS_DIR/relayer.json"; do
    pubkey=$(solana-keygen pubkey "$path")
    log "airdropping $AMOUNT SOL to $pubkey ($(basename "$path" .json))"
    if solana airdrop "$AMOUNT" "$pubkey" --url "$RPC_URL"; then
      log "  ok"
    else
      warn "  faucet refused — try again in a few minutes, or use https://faucet.solana.com"
    fi
    sleep 2
done

log "balances:"
for path in "$KEYS_DIR/authority.json" "$KEYS_DIR/relayer.json"; do
  pubkey=$(solana-keygen pubkey "$path")
  bal=$(solana balance "$pubkey" --url "$RPC_URL" 2>/dev/null || echo "?")
  printf "  %-12s %s  %s\n" "$(basename "$path" .json)" "$pubkey" "$bal"
done
