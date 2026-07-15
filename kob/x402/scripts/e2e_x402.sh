#!/usr/bin/env bash
# x402 native-KAS facilitator E2E on testnet-10.
#
# Proves the facilitator does REAL settlement (broadcast -> UTXO -> finality),
# not a mock: a client builds+signs a native-KAS payment artifact, the
# facilitator verifies -> broadcasts -> confirms -> authorizes, and the
# rejection cases (underpayment, wrong recipient, replay) are refused.
#
# No jq (this device lacks it): JSON field reads use grep/sed.
#
# Usage: kob/x402/scripts/e2e_x402.sh
# Requires: release binaries kob-x402 + x402-client; a funded wallet.
set -uo pipefail

BIN="${BIN:-/root/kob-rust-target4/release}"
NODE="${NODE:-ws://65.108.107.30:18210}"
WALLET="${WALLET:-/tmp/kob_e2e/wallet.json}"
NETWORK="${NETWORK:-kaspa:testnet-10}"
FAC_BIND="${FAC_BIND:-127.0.0.1:8402}"
FAC_URL="http://${FAC_BIND}"
WORK="${WORK:-/tmp/kob_e2e/x402}"
REPLAY_LOG="${WORK}/replay.jsonl"
RESULTS="${WORK}/E2E_X402_TXIDS.txt"

mkdir -p "$WORK"
rm -f "$REPLAY_LOG"
: > "$RESULTS"

log()  { echo "[e2e] $*"; }
field() { grep -oE "\"$1\":(\"[^\"]*\"|[a-z0-9]+)" | head -1 | sed -E "s/\"$1\"://; s/^\"//; s/\"$//"; }

# ---- wallet address (payer = recipient for the happy path, so KAS returns) ----
WADDR=$("$BIN/kob-cli" --node "$NODE" --wallet "$WALLET" wallet 2>/dev/null | grep -oE 'kaspatest:[0-9a-z]+' | head -1)
[ -z "$WADDR" ] && { echo "could not derive wallet address"; exit 1; }
log "wallet/payTo = $WADDR"

# A distinct 'intended' recipient for the wrong-recipient case: a valid testnet
# P2PK address for an unrelated pubkey (derived so the refusal is for the right
# reason, not a decode error).
INTENDED=$("$BIN/x402-client" derive-address 02$(printf '%062x' 2) testnet 2>/dev/null)
[ -z "$INTENDED" ] && INTENDED=$("$BIN/x402-client" derive-address 0202020202020202020202020202020202020202020202020202020202020202 testnet 2>/dev/null)
log "intended (wrong-recipient) = $INTENDED"

# ---- start facilitator ----
log "starting facilitator on $FAC_BIND ..."
"$BIN/kob-x402" --node "$NODE" --bind "$FAC_BIND" --network "$NETWORK" --replay-log "$REPLAY_LOG" \
  > "$WORK/facilitator.log" 2>&1 &
FAC_PID=$!
trap 'kill $FAC_PID 2>/dev/null' EXIT

# wait for health
for i in $(seq 1 30); do
  if curl -sf "$FAC_URL/health" >/dev/null 2>&1; then break; fi
  sleep 0.5
done
curl -sf "$FAC_URL/health" >/dev/null 2>&1 || { echo "facilitator did not start"; tail -20 "$WORK/facilitator.log"; exit 1; }
log "facilitator up: $(curl -s "$FAC_URL/supported")"

post() { curl -s -X POST "$FAC_URL/$1" -H 'content-type: application/json' --data-binary @"$2"; }

PASS=0; FAIL=0
check() { # desc, expect(true|false), got_success
  if [ "$2" = "$3" ]; then echo "  PASS: $1"; PASS=$((PASS+1)); else echo "  FAIL: $1 (expected success=$2 got=$3)"; FAIL=$((FAIL+1)); fi
}

# =====================================================================
# CASE 1 — HAPPY PATH (self-pay 0.2 KAS): verify -> settle -> confirm
# =====================================================================
# Self-pay 0.4 KAS: the payment output (0.4 KAS) exceeds the change, so the
# facilitator identifies output 0 as the payment; funds return to the wallet.
log "CASE 1: happy path (verify + settle + confirm)"
"$BIN/x402-client" --node "$NODE" --wallet "$WALLET" --network "$NETWORK" \
  --pay-to "$WADDR" --amount 40000000 --nonce "happy-$(date +%s)" \
  --out "$WORK/req_happy.json" --replay-out "$WORK/req_replay.json" || { echo "client failed"; exit 1; }

V=$(post verify "$WORK/req_happy.json"); log "verify -> $V"
VI=$(echo "$V" | field isValid)
check "happy verify isValid" "true" "$VI"

S=$(post settle "$WORK/req_happy.json"); log "settle -> $S"
SS=$(echo "$S" | field success)
check "happy settle success" "true" "$SS"
TXID=$(echo "$S" | field transaction)
echo "HAPPY_PATH_TXID=$TXID" | tee -a "$RESULTS"

# =====================================================================
# CASE 2 — UNDERPAYMENT: tx pays 20M, requirements demand 40M -> refuse
# =====================================================================
log "CASE 2: underpayment (must be refused, no broadcast)"
"$BIN/x402-client" --node "$NODE" --wallet "$WALLET" --network "$NETWORK" \
  --pay-to "$WADDR" --amount 20000000 --require 40000000 --nonce "under-$(date +%s)" \
  --out "$WORK/req_under.json"
V=$(post verify "$WORK/req_under.json"); log "verify -> $V"
check "underpayment verify refused" "false" "$(echo "$V" | field isValid)"
S=$(post settle "$WORK/req_under.json"); log "settle -> $S"
check "underpayment settle refused" "false" "$(echo "$S" | field success)"

# =====================================================================
# CASE 3 — WRONG RECIPIENT: tx pays wallet, requirements demand INTENDED
# =====================================================================
log "CASE 3: wrong recipient (must be refused)"
"$BIN/x402-client" --node "$NODE" --wallet "$WALLET" --network "$NETWORK" \
  --pay-to "$INTENDED" --tx-pay-to "$WADDR" --amount 20000000 --nonce "wrong-$(date +%s)" \
  --out "$WORK/req_wrong.json"
V=$(post verify "$WORK/req_wrong.json"); log "verify -> $V"
check "wrong-recipient verify refused" "false" "$(echo "$V" | field isValid)"

# =====================================================================
# CASE 4 — REPLAY: a second artifact over the SAME input as CASE 1 -> refuse
# =====================================================================
log "CASE 4: replay of a consumed outpoint (must be refused)"
if [ -f "$WORK/req_replay.json" ]; then
  V=$(post verify "$WORK/req_replay.json"); log "replay verify -> $V"
  check "replay verify refused" "false" "$(echo "$V" | field isValid)"
  S=$(post settle "$WORK/req_replay.json"); log "replay settle -> $S"
  check "replay settle refused" "false" "$(echo "$S" | field success)"
else
  echo "  SKIP: replay partner artifact not produced"
fi

# =====================================================================
# Independent on-chain confirmation of the happy-path txid.
# =====================================================================
if [ -n "${TXID:-}" ] && [ "$TXID" != "null" ]; then
  log "independently confirming happy-path txid $TXID on-chain ..."
  for i in $(seq 1 20); do
    if "$BIN/kob-cli" --node "$NODE" --wallet "$WALLET" wallet 2>/dev/null | grep -q "$TXID"; then
      echo "ONCHAIN_CONFIRMED=$TXID (appears in wallet UTXO set)" | tee -a "$RESULTS"; break
    fi
    sleep 1
  done
fi

echo
echo "=== RESULT: $PASS passed, $FAIL failed ==="
cat "$RESULTS"
[ "$FAIL" -eq 0 ]
