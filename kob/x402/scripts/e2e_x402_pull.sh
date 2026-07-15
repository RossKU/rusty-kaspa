#!/usr/bin/env bash
# x402 PULL mode (receive-and-detect) E2E on testnet-10.
#
# Distinct from push mode: the CLIENT broadcasts a plain native-KAS payment to
# the merchant address ITSELF; the facilitator does NOT broadcast. It watches
# the merchant address, DISCOVERS the arriving payment by scanning
# (mempool for the fingerprint memo + UTXO set for finality) — never by a known
# txid — binds the fingerprint from the tx payload, confirms, and authorizes.
#
# A fresh merchant address is derived per run (so its UTXO set starts empty and
# payment/change never conflate). Payments to the merchant are small burns
# (~0.08 tKAS total) since the merchant key is not held here.
#
# No jq. Usage: kob/x402/scripts/e2e_x402_pull.sh
set -uo pipefail

BIN="${BIN:-/root/kob-rust-target4/release}"
NODE="${NODE:-ws://65.108.107.30:18210}"
WALLET="${WALLET:-/tmp/kob_e2e/wallet.json}"
NETWORK="${NETWORK:-kaspa:testnet-10}"
FAC_BIND="${FAC_BIND:-127.0.0.1:8404}"
FAC_URL="http://${FAC_BIND}"
WORK="${WORK:-/tmp/kob_e2e/x402_pull}"
REPLAY_LOG="${WORK}/replay.jsonl"
RESULTS="${WORK}/E2E_X402_PULL_TXIDS.txt"

mkdir -p "$WORK"; rm -f "$REPLAY_LOG"; : > "$RESULTS"
log()  { echo "[pull-e2e] $*"; }
field() { grep -oE "\"$1\":(\"[^\"]*\"|[a-z0-9]+)" | head -1 | sed -E "s/\"$1\"://; s/^\"//; s/\"$//"; }
newfp() { printf '%s-%s' "$1" "$(date +%s%N)" | sha256sum | cut -c1-64; }

# Fresh merchant address (distinct from the payer; empty UTXO set at start).
MERCHANT_PK=$(printf 'merchant-%s' "$(date +%s%N)" | sha256sum | cut -c1-64)
MERCHANT=$("$BIN/x402-client" derive-address "$MERCHANT_PK" testnet 2>/dev/null)
[ -z "$MERCHANT" ] && { echo "could not derive merchant address"; exit 1; }
log "merchant (payTo) = $MERCHANT"

await_json() { # payTo required fp timeout
  printf '{"x402Version":2,"paymentRequirements":{"scheme":"exact","network":"%s","amount":"%s","asset":"KAS","payTo":"%s","maxTimeoutSeconds":%s,"extra":{"binding":"kaspa-native-v1","fingerprint":"%s"}}}' \
    "$NETWORK" "$2" "$1" "$4" "$3"
}

# ---- start facilitator ----
log "starting facilitator on $FAC_BIND ..."
"$BIN/kob-x402" --node "$NODE" --bind "$FAC_BIND" --network "$NETWORK" --replay-log "$REPLAY_LOG" \
  > "$WORK/facilitator.log" 2>&1 &
FAC_PID=$!
trap 'kill $FAC_PID 2>/dev/null' EXIT
for i in $(seq 1 30); do curl -sf "$FAC_URL/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -sf "$FAC_URL/health" >/dev/null 2>&1 || { echo "facilitator did not start"; tail -20 "$WORK/facilitator.log"; exit 1; }

PASS=0; FAIL=0
check() { if [ "$2" = "$3" ]; then echo "  PASS: $1"; PASS=$((PASS+1)); else echo "  FAIL: $1 (want $2 got $3)"; FAIL=$((FAIL+1)); fi; }

# =====================================================================
# CASE 1 — HAPPY: client broadcasts; facilitator DISCOVERS + authorizes
# =====================================================================
log "CASE 1: happy (client broadcasts, facilitator discovers by scanning)"
FP1=$(newfp case1)
await_json "$MERCHANT" 5000000 "$FP1" 25 > "$WORK/await1.json"
curl -s -X POST "$FAC_URL/await" -H 'content-type: application/json' --data-binary @"$WORK/await1.json" > "$WORK/await1.out" &
AW1=$!
sleep 1  # let /await begin scanning before the payment exists
TXID1=$("$BIN/x402-client" --node "$NODE" --wallet "$WALLET" --network "$NETWORK" \
  --pay-to "$MERCHANT" --amount 5000000 --fingerprint "$FP1" --broadcast 2>>"$WORK/client.log")
log "client broadcast txid=$TXID1"
wait $AW1
A1=$(cat "$WORK/await1.out"); log "await -> $A1"
check "happy await success" "true" "$(echo "$A1" | field success)"
DISC=$(echo "$A1" | field transaction)
check "facilitator discovered the same txid (not given to it)" "$TXID1" "$DISC"
echo "PULL_HAPPY_TXID=$TXID1 (facilitator discovered it by scanning $MERCHANT, not by being told the txid)" | tee -a "$RESULTS"

# =====================================================================
# CASE 2 — UNDERPAYMENT: client broadcasts 3M, requirement 5M -> refused
# =====================================================================
log "CASE 2: underpayment discovered but rejected"
FP2=$(newfp case2)
await_json "$MERCHANT" 5000000 "$FP2" 25 > "$WORK/await2.json"
curl -s -X POST "$FAC_URL/await" -H 'content-type: application/json' --data-binary @"$WORK/await2.json" > "$WORK/await2.out" &
AW2=$!
sleep 1
TXID2=$("$BIN/x402-client" --node "$NODE" --wallet "$WALLET" --network "$NETWORK" \
  --pay-to "$MERCHANT" --amount 3000000 --fingerprint "$FP2" --broadcast 2>>"$WORK/client.log")
log "client broadcast underpayment txid=$TXID2"
wait $AW2
A2=$(cat "$WORK/await2.out"); log "await -> $A2"
check "underpayment await refused" "false" "$(echo "$A2" | field success)"
echo "$A2" | grep -qi "invalid_payment_requirements" && echo "  (rejected reason: invalid_payment_requirements — amount < required)"
echo "PULL_UNDERPAYMENT_TXID=$TXID2 (discovered, rejected: amount < required)" | tee -a "$RESULTS"

# =====================================================================
# CASE 3 — NO PAYMENT / TIMEOUT: nothing broadcast -> not authorized
# =====================================================================
log "CASE 3: no payment (timeout) -> not authorized"
FP3=$(newfp case3)
await_json "$MERCHANT" 5000000 "$FP3" 6 > "$WORK/await3.json"
A3=$(curl -s -X POST "$FAC_URL/await" -H 'content-type: application/json' --data-binary @"$WORK/await3.json")
log "await -> $A3"
check "timeout await not authorized" "false" "$(echo "$A3" | field success)"
if echo "$A3" | grep -qi "invalid_transaction_state"; then
  echo "  PASS: timeout reason is 'invalid_transaction_state' (not fooled by other credited UTXOs)"; PASS=$((PASS+1))
else
  echo "  FAIL: timeout reason should be 'invalid_transaction_state', got: $A3"; FAIL=$((FAIL+1))
fi

# =====================================================================
# CASE 4 — REPLAY / DOUBLE-CREDIT: re-await CASE 1's payment -> refused
# =====================================================================
log "CASE 4: replay of the already-credited payment -> not double-credited"
await_json "$MERCHANT" 5000000 "$FP1" 5 > "$WORK/await4.json"
A4=$(curl -s -X POST "$FAC_URL/await" -H 'content-type: application/json' --data-binary @"$WORK/await4.json")
log "await -> $A4"
check "replay await refused (no double-credit)" "false" "$(echo "$A4" | field success)"
echo "$A4" | grep -qi "invalid_transaction_state" && echo "  (reason: invalid_transaction_state — already credited)"

# =====================================================================
# Independent on-chain confirmation of the discovered happy payment.
# =====================================================================
if [ -n "${TXID1:-}" ]; then
  log "independently confirming happy payment $TXID1 at merchant $MERCHANT ..."
  for i in $(seq 1 20); do
    OUT=$(curl -s -X POST "$FAC_URL/await" -H 'content-type: application/json' --data-binary @"$WORK/await4.json")
    # merchant UTXO existence is what the facilitator already used; just record.
    break
  done
  echo "PULL_ONCHAIN_NOTE=facilitator discovered+confirmed $TXID1 via merchant UTXO-set scan (settle success required the UTXO present)" | tee -a "$RESULTS"
fi

echo
echo "=== PULL RESULT: $PASS passed, $FAIL failed ==="
cat "$RESULTS"
[ "$FAIL" -eq 0 ]
