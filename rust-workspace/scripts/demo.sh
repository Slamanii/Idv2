#!/usr/bin/env bash
# idv2 — full-stack local demo.
#
# Starts every component on localhost in the correct order and opens the
# observer screen in the default browser when everything is ready.
#
# Usage (from repo root or rust-workspace/):
#   bash scripts/demo.sh
#
# Environment overrides:
#   SKIP_BUILD=1      skip `cargo build` (binaries must already exist)
#   SKIP_DEPLOY=1     skip `cargo build-sbf` + `solana program deploy`
#   ELECTION_ID=2     use a different election ID (default 1)
#   HSM_PIN=1234      PKCS#11 operator PIN (default 1234)
#   RPC_URL=...       Solana RPC endpoint (default http://localhost:8899)
#   DASH_PORT=3000    dashboard-server listen port (default 3000)
#   SMT_PORT=8765     SMT server listen port (default 8765)
#
# Prerequisites (install once):
#   brew install softhsm solana
#   cargo install cargo-build-sbf   # or: sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"

set -euo pipefail

# ── helpers ───────────────────────────────────────────────────────────────────

BOLD=$'\033[1m'
BLUE=$'\033[1;34m'
GREEN=$'\033[1;32m'
YELLOW=$'\033[1;33m'
RED=$'\033[1;31m'
RESET=$'\033[0m'

log()  { printf "${BLUE}[demo]${RESET} %s\n" "$*"; }
ok()   { printf "${GREEN}[demo]${RESET} ✓ %s\n" "$*"; }
warn() { printf "${YELLOW}[demo]${RESET} ⚠  %s\n" "$*"; }
err()  { printf "${RED}[demo]${RESET} ✗ %s\n" "$*" >&2; }
step() { printf "\n${BOLD}══ %s ══${RESET}\n" "$*"; }

die() { err "$*"; exit 1; }

# ── config ────────────────────────────────────────────────────────────────────

WORKSPACE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
KEYS_DIR="$WORKSPACE_DIR/.keys"
CREDS_DIR="$WORKSPACE_DIR/.creds"

ELECTION_ID="${ELECTION_ID:-1}"
HSM_PIN="${HSM_PIN:-1234}"
HSM_SO_PIN="${HSM_SO_PIN:-0000}"
RPC_URL="${RPC_URL:-http://127.0.0.1:8899}"
DASH_PORT="${DASH_PORT:-3000}"
SMT_PORT="${SMT_PORT:-8765}"

SKIP_BUILD="${SKIP_BUILD:-0}"
SKIP_DEPLOY="${SKIP_DEPLOY:-0}"
# Set RESET_HSM=1 to delete and reinitialise the 'idv2-dev' token.
# Required when the token exists but was initialised with a different PIN.
RESET_HSM="${RESET_HSM:-0}"

# Slot windows relative to create-election time.
# At localnet ~2 slots/s (default demo values):
#   REG_OPEN  :    5 slots  (~2s)    — registration opens almost immediately
#   REG_CLOSE :  600 slots  (~5min)  — 5 minutes to register all demo voters
#   VOTE_OPEN :  605 slots  (~5min)  — voting opens ~2s after registration closes
#   VOTE_CLOSE: 1200 slots  (~10min) — 5-minute voting window
#
# For a production-like run (30-min registration window):
#   REG_CLOSE_OFFSET=3600 VOTE_OPEN_OFFSET=3605 VOTE_CLOSE_OFFSET=7200 bash scripts/demo.sh
REG_OPEN_OFFSET="${REG_OPEN_OFFSET:-5}"
REG_CLOSE_OFFSET="${REG_CLOSE_OFFSET:-600}"
VOTE_OPEN_OFFSET="${VOTE_OPEN_OFFSET:-605}"
VOTE_CLOSE_OFFSET="${VOTE_CLOSE_OFFSET:-1200}"

# Candidate roster for the demo election.
CANDIDATES="0:Bola Ahmed Tinubu:APC,1:Atiku Abubakar:PDP,2:Peter Gregory Obi:LP"
CANDIDATE_NAMES="Bola Ahmed Tinubu,Atiku Abubakar,Peter Gregory Obi"

# 4 polling units: id|display_name|state_id|lga_id|port|hmac_suffix
POLLING_UNIT_SPECS=(
    "FCT|Federal Capital Territory — Abuja Municipal|37|3701|8443|fct"
    "Lagos|Lagos State — Lagos Island|24|2401|8444|lagos"
    "Kano|Kano State — Nassarawa|19|1901|8445|kano"
    "Anambra|Anambra State — Awka South|4|401|8446|anambra"
)

# Mario-universe party names (parallel to CANDIDATES array by candidate_id)
CANDIDATE_PARTIES="Mushroom Kingdom Congress,Green Pipe Alliance,Fire Dragon Labour"

VALIDATOR_PID=""
SMT_PID=""
ENCLAVE_PIDS=()
DASH_PID=""

# ── cleanup ───────────────────────────────────────────────────────────────────

cleanup() {
    echo ""
    log "shutting down…"
    for pid in "${ENCLAVE_PIDS[@]:-}"; do
        [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && kill "$pid" 2>/dev/null && log "  stopped enclave pid $pid"
    done
    for var in DASH_PID SMT_PID VALIDATOR_PID; do
        pid="${!var:-}"
        [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && kill "$pid" 2>/dev/null && log "  stopped $var pid $pid"
    done
}
trap cleanup EXIT INT TERM

# ── prereq checks ─────────────────────────────────────────────────────────────

step "0: prerequisite checks"

command -v cargo              >/dev/null 2>&1 || die "cargo not found — install Rust"
command -v solana             >/dev/null 2>&1 || die "solana CLI not found"
command -v solana-test-validator >/dev/null 2>&1 || die "solana-test-validator not found"
command -v softhsm2-util      >/dev/null 2>&1 || die "softhsm2-util not found — brew install softhsm"
command -v python3            >/dev/null 2>&1 || die "python3 not found"

# Locate SoftHSM2 shared library.
if [ -z "${SOFTHSM2_LIB:-}" ]; then
    for candidate in \
        /opt/homebrew/Cellar/softhsm/2.7.0/lib/softhsm/libsofthsm2.so \
        /usr/local/lib/softhsm/libsofthsm2.so \
        /usr/lib/softhsm/libsofthsm2.so; do
        if [ -f "$candidate" ]; then
            export SOFTHSM2_LIB="$candidate"
            break
        fi
    done
fi
[ -n "${SOFTHSM2_LIB:-}" ] || die "SOFTHSM2_LIB not set and library not found at default paths"
[ -f "$SOFTHSM2_LIB" ] || die "SOFTHSM2_LIB=$SOFTHSM2_LIB does not exist"

if [ -z "${SOFTHSM2_CONF:-}" ]; then
    for candidate in \
        /opt/homebrew/etc/softhsm/softhsm2.conf \
        /etc/softhsm2.conf \
        /usr/local/etc/softhsm/softhsm2.conf; do
        if [ -f "$candidate" ]; then
            export SOFTHSM2_CONF="$candidate"
            break
        fi
    done
fi
[ -n "${SOFTHSM2_CONF:-}" ] || die "SOFTHSM2_CONF not set and config not found at default paths"

ok "prerequisites satisfied"
log "SOFTHSM2_LIB  = $SOFTHSM2_LIB"
log "SOFTHSM2_CONF = $SOFTHSM2_CONF"

# ── SoftHSM2 token ────────────────────────────────────────────────────────────

step "1: SoftHSM2 token"
TOKEN_LABEL="idv2-dev"
EXISTING=$(softhsm2-util --show-slots 2>&1 | grep -c "Label.*$TOKEN_LABEL" || true)

if [ "$EXISTING" -gt 0 ] && [ "$RESET_HSM" = "1" ]; then
    log "RESET_HSM=1 — deleting existing token '$TOKEN_LABEL'…"
    softhsm2-util --delete-token --token "$TOKEN_LABEL" 2>/dev/null || true
    EXISTING=0
    ok "old token deleted"
fi

if [ "$EXISTING" -eq 0 ]; then
    log "initialising token '$TOKEN_LABEL' with PIN '$HSM_PIN'…"
    softhsm2-util --init-token --free \
        --label  "$TOKEN_LABEL" \
        --pin    "$HSM_PIN" \
        --so-pin "$HSM_SO_PIN"
    ok "token '$TOKEN_LABEL' created"
else
    ok "token '$TOKEN_LABEL' already exists  (PIN must match HSM_PIN=$HSM_PIN)"
    log "  if PIN mismatch: re-run with RESET_HSM=1 to wipe and reinitialise"
fi

# ── keypairs ──────────────────────────────────────────────────────────────────

step "2: keypairs"
(cd "$WORKSPACE_DIR" && bash scripts/keygen.sh)

ELECTION_PROG=$(grep "^election_registry" "$KEYS_DIR/PUBKEYS.txt" | awk '{print $3}')
VOTER_PROG=$(grep    "^voter_registry"    "$KEYS_DIR/PUBKEYS.txt" | awk '{print $3}')
BALLOT_PROG=$(grep   "^ballot "          "$KEYS_DIR/PUBKEYS.txt" | awk '{print $3}')
TALLY_PROG=$(grep    "^tally "           "$KEYS_DIR/PUBKEYS.txt" | awk '{print $3}')

log "election_registry : $ELECTION_PROG"
log "voter_registry    : $VOTER_PROG"
log "ballot            : $BALLOT_PROG"
log "tally             : $TALLY_PROG"

mkdir -p "$CREDS_DIR"

# ── build native binaries ─────────────────────────────────────────────────────

step "3: build native binaries"
if [ "$SKIP_BUILD" = "1" ]; then
    warn "SKIP_BUILD=1 — using existing binaries"
else
    (cd "$WORKSPACE_DIR" && cargo build -q -p clients -p enclave -p dashboard -p smt-server)
    ok "binaries compiled"
fi

ADMIN="$WORKSPACE_DIR/target/debug/idv2-admin"
ENCLAVE_BIN="$WORKSPACE_DIR/target/debug/enclave-server"
DASH_BIN="$WORKSPACE_DIR/target/debug/dashboard-server"
SMT_BIN="$WORKSPACE_DIR/target/debug/smt-server"

[ -x "$ADMIN" ]       || die "idv2-admin binary missing — run without SKIP_BUILD"
[ -x "$ENCLAVE_BIN" ] || die "enclave-server binary missing"
[ -x "$DASH_BIN" ]    || die "dashboard-server binary missing"
[ -x "$SMT_BIN" ]     || die "smt-server binary missing"

# ── solana-test-validator ────────────────────────────────────────────────────

step "4: solana-test-validator"
pkill -f enclave-server 2>/dev/null || true
pkill -f dashboard-server 2>/dev/null || true
pkill -f solana-test-validator 2>/dev/null || true
sleep 1

# Clear stale credential files so old leaf-indices from a previous ledger
# cannot poison a fresh run.
if [ -d "$CREDS_DIR" ]; then
    find "$CREDS_DIR" -name "*.json" -delete 2>/dev/null || true
    log "cleared stale credentials in $CREDS_DIR"
fi
log "starting solana-test-validator…"
solana-test-validator \
    --ledger /tmp/idv2-demo-ledger \
    --reset \
    --quiet \
    >/tmp/idv2-validator.log 2>&1 &
VALIDATOR_PID=$!
log "validator pid $VALIDATOR_PID  (log: /tmp/idv2-validator.log)"

for i in $(seq 1 40); do
    if curl -sf "$RPC_URL" -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' 2>/dev/null \
        | grep -q '"ok"'; then
        break
    fi
    [ "$i" -eq 40 ] && die "validator did not start within 40s"
    sleep 1
done
ok "validator ready"

# ── airdrop ───────────────────────────────────────────────────────────────────

step "5: airdrop"
for kp in "$KEYS_DIR/authority.json" "$KEYS_DIR/relayer.json"; do
    PK=$(solana-keygen pubkey "$kp")
    solana airdrop 100 "$PK" --url "$RPC_URL" >/dev/null
    ok "  $(basename "$kp" .json)  $PK  +100 SOL"
done

# ── SBF build + deploy ────────────────────────────────────────────────────────

step "6: build + deploy SBF programs"
if [ "$SKIP_DEPLOY" = "1" ]; then
    warn "SKIP_DEPLOY=1 — assuming programs already deployed at these IDs"
else
    if ! command -v cargo-build-sbf >/dev/null 2>&1; then
        die "cargo-build-sbf not found — install Solana tools or set SKIP_DEPLOY=1 if already deployed"
    fi
    (cd "$WORKSPACE_DIR" && RPC_URL="$RPC_URL" bash scripts/deploy.sh)
    ok "all four programs deployed"
fi

# ── key ceremony ──────────────────────────────────────────────────────────────

step "7: HSM key ceremony"
CEREMONY_BIN="$WORKSPACE_DIR/target/debug/key_ceremony"
log "running key_ceremony (idempotent)…"

# Try the pre-compiled binary first; fall back to `cargo run`.
ceremony_cmd() {
    if [ -x "$CEREMONY_BIN" ]; then
        SOFTHSM2_LIB="$SOFTHSM2_LIB" SOFTHSM2_CONF="$SOFTHSM2_CONF" \
            "$CEREMONY_BIN" --slot 0 --pin "$HSM_PIN"
    else
        cd "$WORKSPACE_DIR" && \
        SOFTHSM2_LIB="$SOFTHSM2_LIB" SOFTHSM2_CONF="$SOFTHSM2_CONF" \
            cargo run -q -p enclave --bin key_ceremony -- --slot 0 --pin "$HSM_PIN"
    fi
}

if ! CEREMONY_OUT=$(ceremony_cmd 2>&1); then
    err "key_ceremony failed.  Output:"
    printf '%s\n' "$CEREMONY_OUT" | sed 's/^/    /' >&2
    echo "" >&2
    printf "${RED}Fix:${RESET} the token exists but was initialised with a different PIN.\n" >&2
    printf "  Re-run with RESET_HSM=1 to wipe and reinitialise the token:\n" >&2
    printf "    ${BOLD}RESET_HSM=1 bash scripts/demo.sh${RESET}\n" >&2
    printf "  Or supply the correct PIN:\n" >&2
    printf "    ${BOLD}HSM_PIN=<your-pin> bash scripts/demo.sh${RESET}\n" >&2
    exit 1
fi

# The ceremony binary outputs the pubkey as hex after "=== Ed25519 public key ===".
ED_HEX=$(printf '%s\n' "$CEREMONY_OUT" | grep -A1 "Ed25519 public key" | tail -1 | tr -d '[:space:]')

[ ${#ED_HEX} -eq 64 ] || die "could not parse Ed25519 pubkey from key ceremony output (got: '$ED_HEX')"
log "Ed25519 hex  : $ED_HEX"

# Convert 32-byte hex → base58 (pure Python, no third-party libraries).
AGG_PK_B58=$(python3 - "$ED_HEX" <<'PYEOF'
import sys
data = bytes.fromhex(sys.argv[1])
alpha = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
n = int.from_bytes(data, 'big')
result = b''
while n:
    n, r = divmod(n, 58)
    result = bytes([alpha[r]]) + result
for b in data:
    if b == 0: result = bytes([alpha[0]]) + result
    else: break
print(result.decode())
PYEOF
)
ok "ballot-sign pubkey (base58): $AGG_PK_B58"

# ── Nigeria GeoJSON (serves the observer choropleth map) ─────────────────────

step "7b: Nigeria ADM1 GeoJSON"
GEOJSON_PATH="$WORKSPACE_DIR/dashboard/data/nigeria-adm1.geojson"
if [ -f "$GEOJSON_PATH" ]; then
    ok "nigeria-adm1.geojson already present"
else
    log "downloading Nigeria state boundaries…"
    DOWNLOADED=0

    # Source 1: geoBoundaries REST API → resolves the current download URL.
    GB_META=$(curl -fsSL --max-time 15 \
        "https://www.geoboundaries.org/api/current/gbOpen/NGA/ADM1/" 2>/dev/null || true)
    if [ -n "$GB_META" ]; then
        GB_URL=$(python3 -c "
import json, sys
try:
    d = json.loads(sys.argv[1])
    print(d.get('gjDownloadURL') or d.get('downloadURL') or '')
except: print('')
" "$GB_META" 2>/dev/null || true)
        if [ -n "$GB_URL" ] && \
           curl -fsSL --max-time 60 "$GB_URL" -o "$GEOJSON_PATH" 2>/dev/null && \
           grep -q "FeatureCollection" "$GEOJSON_PATH" 2>/dev/null; then
            ok "downloaded via geoBoundaries API"
            DOWNLOADED=1
        else
            rm -f "$GEOJSON_PATH" 2>/dev/null || true
        fi
    fi

    # Source 2: Natural Earth 50m admin1 — filter to Nigeria + normalize property.
    if [ "$DOWNLOADED" -eq 0 ]; then
        log "trying Natural Earth 50m admin1…"
        NE_URL="https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_50m_admin_1_states_provinces.geojson"
        if curl -fsSL --max-time 120 "$NE_URL" 2>/dev/null \
            | python3 - "$GEOJSON_PATH" <<'PYEOF'
import json, sys
out_path = sys.argv[1]
d = json.load(sys.stdin)
nga = [f for f in d['features'] if f['properties'].get('adm0_a3') == 'NGA']
for f in nga:
    # Add shapeName so the JS lookup works (NE uses 'name').
    f['properties']['shapeName'] = f['properties'].get('name', '')
result = {'type': 'FeatureCollection', 'features': nga}
with open(out_path, 'w') as fp:
    json.dump(result, fp)
PYEOF
           [ -f "$GEOJSON_PATH" ] && grep -q "FeatureCollection" "$GEOJSON_PATH" 2>/dev/null; then
            ok "downloaded from Natural Earth (${#nga[@]} features)"
            DOWNLOADED=1
        else
            rm -f "$GEOJSON_PATH" 2>/dev/null || true
        fi
    fi

    if [ "$DOWNLOADED" -eq 0 ]; then
        warn "could not download Nigeria GeoJSON — observer map will be empty"
        warn "Place a valid ADM1 GeoJSON at: $GEOJSON_PATH"
    fi
fi

# ── SMT server ────────────────────────────────────────────────────────────────

step "8: SMT server"
"$SMT_BIN" --port "$SMT_PORT" >/tmp/idv2-smt.log 2>&1 &
SMT_PID=$!
for i in $(seq 1 20); do
    curl -sf "http://localhost:$SMT_PORT/root" >/dev/null 2>&1 && break
    [ "$i" -eq 20 ] && { err "SMT server failed to start (log: /tmp/idv2-smt.log)"; exit 1; }
    sleep 1
done
ok "SMT server ready  pid=$SMT_PID  port=$SMT_PORT"

# ── create election ───────────────────────────────────────────────────────────

step "9: create election $ELECTION_ID"
BASE_SLOT=$(solana slot --url "$RPC_URL")
log "base slot: $BASE_SLOT"

REG_OPEN=$(( BASE_SLOT + REG_OPEN_OFFSET  ))
REG_CLOSE=$(( BASE_SLOT + REG_CLOSE_OFFSET ))
VOTE_OPEN=$(( BASE_SLOT + VOTE_OPEN_OFFSET ))
VOTE_CLOSE=$(( BASE_SLOT + VOTE_CLOSE_OFFSET ))

log "  reg_open=$REG_OPEN  reg_close=$REG_CLOSE"
log "  vote_open=$VOTE_OPEN  vote_close=$VOTE_CLOSE"

admin() {
    "$ADMIN" \
        --rpc              "$RPC_URL" \
        --keypair          "$KEYS_DIR/authority.json" \
        --election-program "$ELECTION_PROG" \
        --voter-program    "$VOTER_PROG" \
        --tally-program    "$TALLY_PROG" \
        "$@"
}

admin create-election \
    --id         "$ELECTION_ID" \
    --reg-open   "$REG_OPEN"  \
    --reg-close  "$REG_CLOSE" \
    --vote-open  "$VOTE_OPEN" \
    --vote-close "$VOTE_CLOSE" \
    --agg-pubkey "$AGG_PK_B58"
ok "ElectionAccount created"

admin init-registry --election-id "$ELECTION_ID"
ok "VoterRegistryAccount created"

admin init-tally --election-id "$ELECTION_ID"
ok "TallyAccount created"

# set-candidates auto-advances Draft → RegOpen.
admin set-candidates \
    --election-id "$ELECTION_ID" \
    --candidates  "$CANDIDATES"
ok "3 candidates set — phase is now REG_OPEN"

# ── enclave-servers (4 polling units) ────────────────────────────────────────

step "10: enclave-servers (4 polling units)"
ENCLAVE_PIDS=()

for spec in "${POLLING_UNIT_SPECS[@]}"; do
    IFS='|' read -r uid uname state_id lga_id port hmac_suffix <<< "$spec"
    log "starting booth $uid (state=$state_id lga=$lga_id port=$port)..."
    SOFTHSM2_LIB="$SOFTHSM2_LIB" \
    SOFTHSM2_CONF="$SOFTHSM2_CONF" \
    "$ENCLAVE_BIN" \
        --nimc-data                  "$WORKSPACE_DIR/dashboard/data/nimc.json" \
        --relayer-keypair            "$KEYS_DIR/relayer.json" \
        --root-pin                   "$HSM_PIN" \
        --voter-pin                  "$HSM_PIN" \
        --root-slot                  0 \
        --voter-slot                 0 \
        --polling-state-id           "$state_id" \
        --polling-lga-id             "$lga_id" \
        --cred-dir                   "$CREDS_DIR/$uid" \
        --hmac-key-path              "$KEYS_DIR/enclave-hmac-$hmac_suffix.key" \
        --rpc-url                    "$RPC_URL" \
        --election-registry-program  "$ELECTION_PROG" \
        --voter-registry-program     "$VOTER_PROG" \
        --ballot-program             "$BALLOT_PROG" \
        --tally-program              "$TALLY_PROG" \
        --election-id                "$ELECTION_ID" \
        --bind                       "0.0.0.0:$port" \
        >"/tmp/idv2-enclave-$uid.log" 2>&1 &
    ENCLAVE_PIDS+=($!)
    mkdir -p "$CREDS_DIR/$uid"
done
log "started ${#ENCLAVE_PIDS[@]} enclave processes: ${ENCLAVE_PIDS[*]}"

# Wait for all HMAC keys to be written (each enclave writes its key at startup)
for spec in "${POLLING_UNIT_SPECS[@]}"; do
    IFS='|' read -r uid uname state_id lga_id port hmac_suffix <<< "$spec"
    for i in $(seq 1 30); do
        [ -f "$KEYS_DIR/enclave-hmac-$hmac_suffix.key" ] && break
        [ "$i" -eq 30 ] && die "enclave $uid did not write HMAC key within 30s (check /tmp/idv2-enclave-$uid.log)"
        sleep 1
    done
    # Wait for HTTP health
    for i in $(seq 1 30); do
        curl -sf "http://localhost:$port/health" >/dev/null 2>&1 && break
        [ "$i" -eq 30 ] && die "enclave $uid not healthy after 30s"
        sleep 1
    done
    ok "enclave $uid ready  port=$port"
done

# ── dashboard-server ──────────────────────────────────────────────────────────

step "11: dashboard-server"
UNIT_ARGS=()
for spec in "${POLLING_UNIT_SPECS[@]}"; do
    IFS='|' read -r uid uname state_id lga_id port hmac_suffix <<< "$spec"
    UNIT_ARGS+=(--polling-unit "$uid|$uname|http://127.0.0.1:$port|$KEYS_DIR/enclave-hmac-$hmac_suffix.key")
done

"$DASH_BIN" \
    --rpc-url                  "$RPC_URL" \
    "${UNIT_ARGS[@]}" \
    --ballot-program           "$BALLOT_PROG" \
    --voter-registry-program   "$VOTER_PROG" \
    --election-id              "$ELECTION_ID" \
    --candidate-names          "$CANDIDATE_NAMES" \
    --candidate-parties        "$CANDIDATE_PARTIES" \
    --bind                     "0.0.0.0:$DASH_PORT" \
    >/tmp/idv2-dashboard.log 2>&1 &
DASH_PID=$!
log "dashboard-server pid=$DASH_PID  port=$DASH_PORT  (log: /tmp/idv2-dashboard.log)"

for i in $(seq 1 20); do
    curl -sf "http://localhost:$DASH_PORT/" >/dev/null 2>&1 && break
    [ "$i" -eq 20 ] && die "dashboard-server did not start (check /tmp/idv2-dashboard.log)"
    sleep 1
done
ok "dashboard-server ready"

# ── open browser ──────────────────────────────────────────────────────────────

step "12: open browser"
OBSERVER_URL="http://localhost:$DASH_PORT/"

# macOS: open; Linux: xdg-open or sensible-browser.
if command -v open >/dev/null 2>&1; then
    open "$OBSERVER_URL"
elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$OBSERVER_URL"
fi

# ── ready banner ──────────────────────────────────────────────────────────────

echo ""
printf "${GREEN}${BOLD}╔══════════════════════════════════════════════════════╗${RESET}\n"
printf "${GREEN}${BOLD}║           idv2 DEMO — ALL SYSTEMS READY              ║${RESET}\n"
printf "${GREEN}${BOLD}╚══════════════════════════════════════════════════════╝${RESET}\n"
echo ""
printf "  ${BOLD}Observer map${RESET}   ${BLUE}%s${RESET}\n" "$OBSERVER_URL"
echo ""
printf "  ${BOLD}Voting booths${RESET}\n"
for spec in "${POLLING_UNIT_SPECS[@]}"; do
    IFS='|' read -r uid uname state_id lga_id port hmac_suffix <<< "$spec"
    printf "    %-10s  ${BLUE}http://localhost:%s/booth/%s${RESET}\n" "$uid" "$DASH_PORT" "$uid"
done
echo ""
printf "  ${BOLD}election_id${RESET}    %s\n" "$ELECTION_ID"
printf "  ${BOLD}candidates${RESET}     %s\n" "$CANDIDATE_NAMES"
printf "  ${BOLD}parties${RESET}        %s\n" "$CANDIDATE_PARTIES"
echo ""
# Phase guide — show absolute slots and wall-clock estimates.
SLOTS_PER_SEC=2
REG_OPEN_ETA=$(( (REG_OPEN_OFFSET)  / SLOTS_PER_SEC ))
REG_CLOSE_ETA=$(( (REG_CLOSE_OFFSET) / SLOTS_PER_SEC ))
VOTE_OPEN_ETA=$(( (VOTE_OPEN_OFFSET) / SLOTS_PER_SEC ))
VOTE_CLOSE_ETA=$(( (VOTE_CLOSE_OFFSET) / SLOTS_PER_SEC ))
printf "  ${BOLD}Phase timeline${RESET} (base slot: %s)\n" "$BASE_SLOT"
printf "    REGISTRATION OPEN   slot %-7s  (~%ds from launch)\n" "$REG_OPEN"  "$REG_OPEN_ETA"
printf "    REGISTRATION CLOSE  slot %-7s  (~%ds from launch)\n" "$REG_CLOSE" "$REG_CLOSE_ETA"
printf "    VOTING OPEN         slot %-7s  (~%ds from launch)\n" "$VOTE_OPEN"  "$VOTE_OPEN_ETA"
printf "    VOTING CLOSE        slot %-7s  (~%ds from launch)\n" "$VOTE_CLOSE" "$VOTE_CLOSE_ETA"
printf "    Check current slot: ${BOLD}solana slot --url %s${RESET}\n" "$RPC_URL"
echo ""
printf "  ${BOLD}Demo steps${RESET}\n"
printf "    1. Register voters now (registration is open for ~%ds)\n" "$(( REG_CLOSE_ETA - REG_OPEN_ETA ))"
printf "    2. Wait for slot %s (~%ds) — then voting unlocks\n" "$VOTE_OPEN" "$VOTE_OPEN_ETA"
printf "    3. Cast votes at each booth, watch the map update live\n"
echo ""
printf "  ${BOLD}Demo voters (fingerprint_secret → name → assigned booth):${RESET}\n"
printf "    fp-MS-146  Malam Shehu Abuja          → FCT booth\n"
printf "    fp-BA-091  Bola Adeyemi Lagos-Island  → Lagos booth\n"
printf "    fp-AS-070  Abubakar Sule Kano         → Kano booth\n"
printf "    fp-ON-011  Obiora Nwosu Anambra       → Anambra booth\n"
printf "    fp-CO-001  Chukwuemeka Okonkwo (Abia) → Anambra booth  ★ vote counts for Anambra!\n"
echo ""
printf "  ${BOLD}Logs${RESET}\n"
for spec in "${POLLING_UNIT_SPECS[@]}"; do
    IFS='|' read -r uid _ _ _ _ _ <<< "$spec"
    printf "    enclave-%-8s  /tmp/idv2-enclave-%s.log\n" "$uid" "$uid"
done
printf "    dashboard          /tmp/idv2-dashboard.log\n"
printf "    validator          /tmp/idv2-validator.log\n"
printf "    smt                /tmp/idv2-smt.log\n"
echo ""
printf "  Press ${BOLD}Ctrl+C${RESET} to stop all processes.\n"
echo ""

# ── live phase monitor + auto-advance (runs in foreground until Ctrl+C) ──────
#
# Every 5 seconds:
#   1. Checks the current slot.
#   2. Auto-advances the on-chain election phase when slot gates open:
#        REG_OPEN → REG_CLOSED  (slot >= REG_CLOSE)
#        REG_CLOSED → VOTING_OPEN (slot >= VOTE_OPEN)
#   3. Prints the current phase on a single overwritten line.
#
# Both transitions can fire in the same iteration if the 5-slot gap between
# REG_CLOSE and VOTE_OPEN has already passed (common at 5-second poll interval).

REG_CLOSED_ADVANCED=0
VOTE_OPEN_ADVANCED=0

while true; do
    CURRENT_SLOT=$(solana slot --url "$RPC_URL" 2>/dev/null || echo "0")

    # ── auto-advance REG_OPEN → REG_CLOSED ────────────────────────────────────
    if [ "$REG_CLOSED_ADVANCED" -eq 0 ] && [ "$CURRENT_SLOT" -ge "$REG_CLOSE" ]; then
        REG_CLOSED_ADVANCED=1
        printf "\n"
        if admin advance-phase --election-id "$ELECTION_ID" --target 2 >/dev/null 2>&1; then
            ok "on-chain phase → REG_CLOSED  (slot $CURRENT_SLOT)"
        else
            warn "advance-phase REG_CLOSED failed (may already be advanced)"
        fi
    fi

    # ── auto-advance REG_CLOSED → VOTING_OPEN ────────────────────────────────
    if [ "$REG_CLOSED_ADVANCED" -eq 1 ] && [ "$VOTE_OPEN_ADVANCED" -eq 0 ] && [ "$CURRENT_SLOT" -ge "$VOTE_OPEN" ]; then
        VOTE_OPEN_ADVANCED=1
        printf "\n"
        if admin advance-phase --election-id "$ELECTION_ID" --target 3 >/dev/null 2>&1; then
            ok "on-chain phase → VOTING_OPEN  (slot $CURRENT_SLOT) — booths unlocked!"
        else
            warn "advance-phase VOTING_OPEN failed (may already be advanced)"
        fi
    fi

    # ── phase display ─────────────────────────────────────────────────────────
    if   [ "$CURRENT_SLOT" -lt "$REG_OPEN" ]; then
        PHASE="PENDING   — registration opens at slot $REG_OPEN  (now: $CURRENT_SLOT)"
    elif [ "$CURRENT_SLOT" -lt "$REG_CLOSE" ]; then
        LEFT=$(( REG_CLOSE - CURRENT_SLOT ))
        PHASE="${GREEN}REG OPEN  — register voters now  ($LEFT slots left)${RESET}"
    elif [ "$CURRENT_SLOT" -lt "$VOTE_OPEN" ]; then
        LEFT=$(( VOTE_OPEN - CURRENT_SLOT ))
        PHASE="${YELLOW}TRANSITIONING — voting opens in $LEFT slots${RESET}"
    elif [ "$CURRENT_SLOT" -lt "$VOTE_CLOSE" ]; then
        LEFT=$(( VOTE_CLOSE - CURRENT_SLOT ))
        PHASE="${GREEN}VOTE OPEN — cast votes now  ($LEFT slots left)${RESET}"
    else
        PHASE="${RED}CLOSED    — election over (slot $CURRENT_SLOT)${RESET}"
    fi
    printf "\r[demo] Phase: %b%*s" "$PHASE" 20 "" 2>/dev/null || true
    sleep 5
done
