#!/usr/bin/env bash
# idv2 — full end-to-end test: 100 voters, 3 candidates.
#
# Defaults to localnet (no devnet rate limits, unlimited airdrop).
#
# Usage:
#   cd rust-workspace
#   bash scripts/devnet-e2e.sh                                           # localnet
#   RPC_URL=https://api.devnet.solana.com bash scripts/devnet-e2e.sh    # devnet
#   VOTER_COUNT=10 bash scripts/devnet-e2e.sh                            # quick smoke
#
# Phase transition rules (enforced on-chain):
#   set-candidates          → DRAFT(0) → REG_OPEN(1)   [auto, no slot gate]
#   advance-phase --target 2 → REG_OPEN→REG_CLOSED      [needs slot >= reg_close]
#   advance-phase --target 3 → REG_CLOSED→VOTING_OPEN   [needs slot >= vote_open]
#   advance-phase --target 4 → VOTING_OPEN→VOTING_CLOSED[needs slot >= vote_close]
#   voter_registry::insert_commitment checks current_slot < reg_close
#   ballot::cast              checks current_slot < vote_close

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────

ELECTION_ID="${ELECTION_ID:-1}"
VOTER_COUNT="${VOTER_COUNT:-100}"
RPC_URL="${RPC_URL:-http://localhost:8899}"
SMT_PORT="${SMT_PORT:-8765}"
KEYS_DIR="${KEYS_DIR:-.keys}"
WORKSPACE_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Slot windows (relative to current slot at create-election time).
# At localnet ~2 slots/s; at devnet ~2.5 slots/s.
# reg_close must be AFTER the last registration.
# vote_close must be AFTER the last vote.
# For 100 voters at ~1s/voter: registration = ~100s = ~200 slots + headroom.
# vote_close must allow ~100 votes: ~100s = ~200 slots + headroom.
REG_OPEN_OFFSET="${REG_OPEN_OFFSET:-5}"
REG_CLOSE_OFFSET="${REG_CLOSE_OFFSET:-600}"    # 300s of headroom after set-candidates
VOTE_OPEN_OFFSET="${VOTE_OPEN_OFFSET:-610}"
VOTE_CLOSE_OFFSET="${VOTE_CLOSE_OFFSET:-1400}" # another 400s after voting opens

VALIDATOR_PID=""
SMT_PID=""

log()  { printf "\033[1;34m[e2e]\033[0m %s\n" "$*"; }
ok()   { printf "\033[1;32m[e2e]\033[0m ✓ %s\n" "$*"; }
warn() { printf "\033[1;33m[e2e]\033[0m ⚠  %s\n" "$*"; }
err()  { printf "\033[1;31m[e2e]\033[0m ✗ %s\n" "$*" >&2; }
step() { printf "\n\033[1;37m══ Step %s ══\033[0m\n" "$*"; }

cleanup() {
    if [ -n "$SMT_PID" ] && kill -0 "$SMT_PID" 2>/dev/null; then
        log "stopping SMT server (pid $SMT_PID)"
        kill "$SMT_PID" 2>/dev/null || true
    fi
    if [ -n "$VALIDATOR_PID" ] && kill -0 "$VALIDATOR_PID" 2>/dev/null; then
        log "stopping solana-test-validator (pid $VALIDATOR_PID)"
        kill "$VALIDATOR_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

is_localnet() { [[ "$RPC_URL" == *"localhost"* || "$RPC_URL" == *"127.0.0.1"* ]]; }

wait_slot() {
    local target="$1"
    local label="${2:-target}"
    while true; do
        local cur
        cur=$(solana slot --url "$RPC_URL")
        [ "$cur" -ge "$target" ] && break
        local rem=$(( target - cur ))
        log "  waiting for slot $target ($label) — current $cur, ~$(( rem / 2 ))s"
        sleep 3
    done
}

wait_for_rpc() {
    for i in $(seq 1 40); do
        if curl -sf "$RPC_URL" -X POST -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' \
            | grep -q '"ok"'; then
            return 0
        fi
        sleep 1
    done
    err "RPC at $RPC_URL did not become ready in 40s"; return 1
}

# ── Step 1: build CLI binaries ────────────────────────────────────────────────
step "1: build CLI binaries"
(cd "$WORKSPACE_DIR" && cargo build -q -p clients)
ok "binaries compiled"

# Use the compiled binary directly — avoids 2-3s cargo overhead per invocation
ADMIN="$WORKSPACE_DIR/target/debug/idv2-admin"
VOTER_BIN="$WORKSPACE_DIR/target/debug/idv2-voter"
VERIFY_BIN="$WORKSPACE_DIR/target/debug/idv2-verify"

admin() {
    "$ADMIN" \
        --rpc              "$RPC_URL" \
        --keypair          "$KEYS_DIR/authority.json" \
        --election-program "$ELECTION_PROG" \
        --voter-program    "$VOTER_PROG" \
        --tally-program    "$TALLY_PROG" \
        "$@"
}

voter_cast() {
    "$VOTER_BIN" \
        --rpc              "$RPC_URL" \
        --keypair          "$KEYS_DIR/relayer.json" \
        --ballot-program   "$BALLOT_PROG" \
        --election-program "$ELECTION_PROG" \
        --voter-program    "$VOTER_PROG" \
        --tally-program    "$TALLY_PROG" \
        "$@"
}

verify() {
    "$VERIFY_BIN" \
        --rpc              "$RPC_URL" \
        --election-program "$ELECTION_PROG" \
        --voter-program    "$VOTER_PROG" \
        --ballot-program   "$BALLOT_PROG" \
        --tally-program    "$TALLY_PROG" \
        "$@"
}

# ── Step 2: keypairs ──────────────────────────────────────────────────────────
step "2: keypairs"
(cd "$WORKSPACE_DIR" && bash scripts/keygen.sh)

ELECTION_PROG=$(grep "^election_registry" "$KEYS_DIR/PUBKEYS.txt" | awk '{print $3}')
VOTER_PROG=$(grep    "^voter_registry"    "$KEYS_DIR/PUBKEYS.txt" | awk '{print $3}')
BALLOT_PROG=$(grep   "^ballot "           "$KEYS_DIR/PUBKEYS.txt" | awk '{print $3}')
TALLY_PROG=$(grep    "^tally "            "$KEYS_DIR/PUBKEYS.txt" | awk '{print $3}')
AGG_PK=$(grep        "^aggregation"       "$KEYS_DIR/PUBKEYS.txt" | awk '{print $3}')

log "election_registry : $ELECTION_PROG"
log "voter_registry    : $VOTER_PROG"
log "ballot            : $BALLOT_PROG"
log "tally             : $TALLY_PROG"
log "aggregation_pk    : $AGG_PK"

# ── Step 3: start solana-test-validator (localnet only) ───────────────────────
step "3: validator"
if is_localnet; then
    pkill -f solana-test-validator 2>/dev/null || true
    sleep 1
    log "starting solana-test-validator..."
    solana-test-validator \
        --ledger /tmp/idv2-test-ledger \
        --reset \
        --quiet \
        &>/tmp/idv2-validator.log &
    VALIDATOR_PID=$!
    log "validator pid $VALIDATOR_PID (log: /tmp/idv2-validator.log)"
    wait_for_rpc
    ok "solana-test-validator ready"
else
    ok "devnet — skipping local validator"
fi

# ── Step 4: airdrop ───────────────────────────────────────────────────────────
step "4: airdrop"
if is_localnet; then
    for path in "$KEYS_DIR/authority.json" "$KEYS_DIR/relayer.json"; do
        PK=$(solana-keygen pubkey "$path")
        solana airdrop 100 "$PK" --url "$RPC_URL" >/dev/null
        log "  $(basename "$path" .json)  $PK  +100 SOL"
    done
else
    (cd "$WORKSPACE_DIR" && RPC_URL="$RPC_URL" bash scripts/airdrop.sh)
fi
ok "airdrops done"

# ── Step 5: build + deploy programs ──────────────────────────────────────────
step "5: build + deploy SBF programs"
(cd "$WORKSPACE_DIR" && RPC_URL="$RPC_URL" bash scripts/deploy.sh)
ok "all four programs deployed"

# ── Step 6: start SMT server ──────────────────────────────────────────────────
step "6: start SMT server"
PORT="$SMT_PORT" cargo run -q --manifest-path "$WORKSPACE_DIR/Cargo.toml" \
    -p smt-server &>/tmp/idv2-smt.log &
SMT_PID=$!
for i in $(seq 1 20); do
    curl -sf "http://localhost:$SMT_PORT/root" >/dev/null 2>&1 && break
    [ "$i" -eq 20 ] && { err "SMT server failed to start"; exit 1; }
    sleep 1
done
ok "SMT server ready (pid $SMT_PID  port $SMT_PORT)"

# ── Step 7: create election ───────────────────────────────────────────────────
step "7: create election $ELECTION_ID"
BASE_SLOT=$(solana slot --url "$RPC_URL")
log "base slot: $BASE_SLOT"

REG_OPEN=$((  BASE_SLOT + REG_OPEN_OFFSET  ))
REG_CLOSE=$(( BASE_SLOT + REG_CLOSE_OFFSET ))
VOTE_OPEN=$(( BASE_SLOT + VOTE_OPEN_OFFSET ))
VOTE_CLOSE=$(( BASE_SLOT + VOTE_CLOSE_OFFSET ))

log "  reg_open=$REG_OPEN  reg_close=$REG_CLOSE"
log "  vote_open=$VOTE_OPEN  vote_close=$VOTE_CLOSE"

admin create-election \
    --id          "$ELECTION_ID" \
    --reg-open    "$REG_OPEN"    \
    --reg-close   "$REG_CLOSE"   \
    --vote-open   "$VOTE_OPEN"   \
    --vote-close  "$VOTE_CLOSE"  \
    --agg-pubkey  "$AGG_PK"
ok "ElectionAccount created"

# ── Step 8: init registry + tally ─────────────────────────────────────────────
step "8: init-registry and init-tally"
admin init-registry --election-id "$ELECTION_ID"
ok "VoterRegistryAccount created"
admin init-tally --election-id "$ELECTION_ID"
ok "TallyAccount created"

# ── Step 9: set candidates ────────────────────────────────────────────────────
# set-candidates automatically advances DRAFT(0) → REG_OPEN(1) on-chain.
# Do NOT call advance-phase --target 1; the match arm does not exist in the program.
step "9: set candidates  [auto-advances phase: DRAFT → REG_OPEN]"
admin set-candidates \
    --election-id "$ELECTION_ID" \
    --candidates  "0:Candidate Alpha:PARTY-A,1:Candidate Beta:PARTY-B,2:Candidate Gamma:PARTY-C"
ok "3 candidates written — phase is now REG_OPEN (1)"

# ── Step 10: register VOTER_COUNT voters (phase must stay REG_OPEN) ───────────
step "10: register $VOTER_COUNT voters"
log "  slot deadline: $REG_CLOSE  (registration rejected at or after this slot)"
for i in $(seq 0 $((VOTER_COUNT - 1))); do
    eval "$("$ADMIN" \
        --rpc "$RPC_URL" --keypair "$KEYS_DIR/authority.json" \
        --election-program "$ELECTION_PROG" \
        --voter-program    "$VOTER_PROG" \
        --tally-program    "$TALLY_PROG" \
        gen-test-voter \
            --election-id     "$ELECTION_ID" \
            --voter-index     "$i" \
            --signing-keypair "$KEYS_DIR/aggregation.json")"

    admin register-voter \
        --election-id "$ELECTION_ID" \
        --commitment  "$COMMITMENT"  \
        --smt-url     "http://localhost:$SMT_PORT"

    if (( (i + 1) % 10 == 0 )); then
        CSLOT=$(solana slot --url "$RPC_URL")
        ok "registered $((i + 1)) / $VOTER_COUNT  (slot $CSLOT / $REG_CLOSE)"
    fi
done
ok "all $VOTER_COUNT voters registered"

# ── Step 11: REG_OPEN → REG_CLOSED → VOTING_OPEN ─────────────────────────────
# advance-phase requires two separate hops; the program rejects 1→3 directly.
step "11: advance phase  REG_OPEN → REG_CLOSED → VOTING_OPEN"

wait_slot "$REG_CLOSE" "reg_close"
admin advance-phase --election-id "$ELECTION_ID" --target 2
ok "phase → REG_CLOSED (2)"

wait_slot "$VOTE_OPEN" "vote_open"
admin advance-phase --election-id "$ELECTION_ID" --target 3
ok "phase → VOTING_OPEN (3)"

# ── Step 12: cast VOTER_COUNT votes ───────────────────────────────────────────
step "12: cast $VOTER_COUNT votes  (50→cand-0 / 30→cand-1 / 20→cand-2)"
log "  slot deadline: $VOTE_CLOSE  (votes rejected at or after this slot)"
for i in $(seq 0 $((VOTER_COUNT - 1))); do
    if   [ "$i" -lt 50 ]; then CAND=0
    elif [ "$i" -lt 80 ]; then CAND=1
    else                        CAND=2
    fi

    STATE_ID=$(( (i % 36) + 1 ))
    LGA_ID=$(( 100 + (i % 36) ))

    eval "$("$ADMIN" \
        --rpc "$RPC_URL" --keypair "$KEYS_DIR/authority.json" \
        --election-program "$ELECTION_PROG" \
        --voter-program    "$VOTER_PROG" \
        --tally-program    "$TALLY_PROG" \
        gen-test-voter \
            --election-id     "$ELECTION_ID" \
            --voter-index     "$i" \
            --signing-keypair "$KEYS_DIR/aggregation.json")"

    voter_cast cast-vote \
        --election-id  "$ELECTION_ID" \
        --candidate-id "$CAND"        \
        --state-id     "$STATE_ID"    \
        --lga-id       "$LGA_ID"      \
        --nullifier    "$NULLIFIER"   \
        --hsm-sig      "$HSM_SIG"     \
        --authority-pk "$AUTHORITY_PK" \
        --leaf-index   "$LEAF_INDEX"

    if (( (i + 1) % 10 == 0 )); then
        CSLOT=$(solana slot --url "$RPC_URL")
        ok "cast $((i + 1)) / $VOTER_COUNT  (slot $CSLOT / $VOTE_CLOSE)"
    fi
done
ok "all $VOTER_COUNT votes cast"

# ── Step 13: VOTING_OPEN → VOTING_CLOSED ──────────────────────────────────────
step "13: advance phase  VOTING_OPEN → VOTING_CLOSED"
wait_slot "$VOTE_CLOSE" "vote_close"
admin advance-phase --election-id "$ELECTION_ID" --target 4
ok "phase → VOTING_CLOSED (4)"

# ── Step 14: finalise tally ───────────────────────────────────────────────────
step "14: finalise tally"
admin finalise-tally --election-id "$ELECTION_ID"
ok "tally finalised"

# ── Step 15: audit ────────────────────────────────────────────────────────────
step "15: audit"
echo ""
verify show-election    --id "$ELECTION_ID"
echo ""
verify audit-tally      --id "$ELECTION_ID"
echo ""
verify check-nullifiers --id "$ELECTION_ID"
echo ""
verify rebuild-tally    --id "$ELECTION_ID"
echo ""
verify rebuild-merkle   --id "$ELECTION_ID"

echo ""
log "══════════════════════════════════════════════════"
ok  "End-to-end test complete."
log "  election_id  : $ELECTION_ID"
log "  voters       : $VOTER_COUNT"
log "  distribution : 50 cand-0 / 30 cand-1 / 20 cand-2"
log "  network      : $RPC_URL"
log "══════════════════════════════════════════════════"
