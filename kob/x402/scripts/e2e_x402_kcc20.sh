#!/usr/bin/env bash
# x402 KCC20 (scheme B) facilitator E2E on testnet-10.
#
# Proves the facilitator settles a REAL on-chain KCC20 token_unit payment
# (spec-form token_unit-P2SH transfer) and refuses underpayment / wrong
# recipient / replay.
#
# Precondition: a fresh token_unit UTXO owned by the wallet. Mint one with:
#   kob-cli token mint --txid <auth_txid> --index 0 --token <asset> --amount <N>
# and pass UNIT=<mint_txid>:1  (value == N).  ASSET defaults to the fixture.
#
# Only ONE token_unit is needed: all artifacts are built while it is still
# unspent, the two rejection cases (which never broadcast) run first, then the
# happy path consumes it, then the replay partner is refused.
#
# No jq. Usage: UNIT=<txid>:1 [TOKEN_AMOUNT=10000000] kob/x402/scripts/e2e_x402_kcc20.sh
set -uo pipefail

BIN="${BIN:-/root/kob-rust-target4/release}"
NODE="${NODE:-ws://65.108.107.30:18210}"
WALLET="${WALLET:-/tmp/kob_e2e/wallet.json}"
NETWORK="${NETWORK:-kaspa:testnet-10}"
FAC_BIND="${FAC_BIND:-127.0.0.1:8403}"
FAC_URL="http://${FAC_BIND}"
WORK="${WORK:-/tmp/kob_e2e/x402_kcc20}"
FIXTURE="${FIXTURE:-$(cd "$(dirname "$0")/../.." && pwd)/e2e_fixture.json}"
REPLAY_LOG="${WORK}/replay.jsonl"
RESULTS="${WORK}/E2E_X402_KCC20_TXIDS.txt"
ASSET="${ASSET:-$(grep -oE '"token_covenant_id": "[0-9a-f]+"' "$FIXTURE" | grep -oE '[0-9a-f]{64}')}"
TOKEN_AMOUNT="${TOKEN_AMOUNT:-10000000}"

[ -z "${UNIT:-}" ] && { echo "UNIT=<token_unit txid:index> is required"; exit 1; }
mkdir -p "$WORK"; rm -f "$REPLAY_LOG"; : > "$RESULTS"

log()  { echo "[kcc20-e2e] $*"; }
field() { grep -oE "\"$1\":(\"[^\"]*\"|[a-z0-9]+)" | head -1 | sed -E "s/\"$1\"://; s/^\"//; s/\"$//"; }

WADDR=$("$BIN/kob-cli" --node "$NODE" --wallet "$WALLET" wallet 2>/dev/null | grep -oE 'kaspatest:[0-9a-z]+' | head -1)
[ -z "$WADDR" ] && { echo "no wallet address"; exit 1; }
INTENDED=$("$BIN/x402-client" derive-address 0303030303030303030303030303030303030303030303030303030303030303 testnet 2>/dev/null)
log "wallet=$WADDR  asset=$ASSET  unit=$UNIT  amount=$TOKEN_AMOUNT"
log "intended(wrong-recipient)=$INTENDED"

CLI() { "$BIN/x402-client" kcc20 --node "$NODE" --wallet "$WALLET" --network "$NETWORK" \
          --asset "$ASSET" --token-utxo "$UNIT" "$@"; }

# ---- Build all artifacts up front (token_unit still unspent) ----
log "building artifacts (happy + replay partner) ..."
CLI --pay-to "$WADDR" --amount "$TOKEN_AMOUNT" \
    --out "$WORK/req_happy.json" --replay-out "$WORK/req_replay.json" \
    --replay-recipient "$INTENDED" || { echo "build happy failed"; exit 1; }
log "building underpayment artifact ..."
CLI --pay-to "$WADDR" --amount "$TOKEN_AMOUNT" --require $((TOKEN_AMOUNT*2)) \
    --out "$WORK/req_under.json" || { echo "build under failed"; exit 1; }
log "building wrong-recipient artifact ..."
CLI --pay-to "$INTENDED" --tx-recipient "$WADDR" --amount "$TOKEN_AMOUNT" \
    --out "$WORK/req_wrong.json" || { echo "build wrong failed"; exit 1; }

# ---- Start facilitator ----
log "starting facilitator on $FAC_BIND ..."
"$BIN/kob-x402" --node "$NODE" --bind "$FAC_BIND" --network "$NETWORK" --replay-log "$REPLAY_LOG" \
  > "$WORK/facilitator.log" 2>&1 &
FAC_PID=$!
trap 'kill $FAC_PID 2>/dev/null' EXIT
for i in $(seq 1 30); do curl -sf "$FAC_URL/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -sf "$FAC_URL/health" >/dev/null 2>&1 || { echo "facilitator did not start"; tail -20 "$WORK/facilitator.log"; exit 1; }

post() { curl -s -X POST "$FAC_URL/$1" -H 'content-type: application/json' --data-binary @"$2"; }
PASS=0; FAIL=0
check() { if [ "$2" = "$3" ]; then echo "  PASS: $1"; PASS=$((PASS+1)); else echo "  FAIL: $1 (expected success=$2 got=$3)"; FAIL=$((FAIL+1)); fi; }

# ---- CASE 2: UNDERPAYMENT (no broadcast) ----
log "CASE 2: underpayment (must be refused)"
V=$(post verify "$WORK/req_under.json"); log "verify -> $V"
check "kcc20 underpayment verify refused" "false" "$(echo "$V" | field isValid)"
S=$(post settle "$WORK/req_under.json"); log "settle -> $S"
check "kcc20 underpayment settle refused" "false" "$(echo "$S" | field success)"

# ---- CASE 3: WRONG RECIPIENT (no broadcast) ----
log "CASE 3: wrong recipient (must be refused)"
V=$(post verify "$WORK/req_wrong.json"); log "verify -> $V"
check "kcc20 wrong-recipient verify refused" "false" "$(echo "$V" | field isValid)"

# ---- CASE 1: HAPPY (real on-chain token payment) ----
log "CASE 1: happy path (verify + settle + confirm)"
V=$(post verify "$WORK/req_happy.json"); log "verify -> $V"
check "kcc20 happy verify isValid" "true" "$(echo "$V" | field isValid)"
S=$(post settle "$WORK/req_happy.json"); log "settle -> $S"
check "kcc20 happy settle success" "true" "$(echo "$S" | field success)"
TXID=$(echo "$S" | field transaction)
echo "KCC20_HAPPY_TXID=$TXID" | tee -a "$RESULTS"

# ---- CASE 4: REPLAY (same token input, different artifact) ----
log "CASE 4: replay of consumed token input (must be refused)"
V=$(post verify "$WORK/req_replay.json"); log "replay verify -> $V"
check "kcc20 replay verify refused" "false" "$(echo "$V" | field isValid)"
S=$(post settle "$WORK/req_replay.json"); log "replay settle -> $S"
check "kcc20 replay settle refused" "false" "$(echo "$S" | field success)"

# ---- Independent on-chain confirmation of the happy token payment ----
if [ -n "${TXID:-}" ] && [ "$TXID" != "null" ]; then
  log "independently confirming token payment $TXID on-chain ..."
  # The token_unit output (:0) is at the recipient token P2SH; the fee-change
  # output (:1) is at the wallet P2PK — so the txid shows up in the wallet's
  # per-UTXO listing (`wallet`, which prints outpoints; `balance` shows only a
  # total).
  for i in $(seq 1 25); do
    if "$BIN/kob-cli" --node "$NODE" --wallet "$WALLET" wallet 2>/dev/null | grep -q "$TXID"; then
      echo "KCC20_ONCHAIN_CONFIRMED=$TXID (fee-change output in wallet UTXO set)" | tee -a "$RESULTS"; break
    fi
    sleep 1
  done
fi

echo
echo "=== KCC20 RESULT: $PASS passed, $FAIL failed ==="
cat "$RESULTS"
[ "$FAIL" -eq 0 ]
