#!/usr/bin/env bash
# x402 KIP-10 additive "exact" (strict interop) E2E on testnet-10.
#
# Flow: compute the additive borrow covenant P2SH -> merchant funds it ->
# /reserve -> client builds the additive exact-transaction (spend borrow +
# funding, pay amount to payTo, continuation >= borrow+threshold to merchant,
# change) -> /verify -> /settle -> authorize. Then the 4 rejection cases and a
# schema-conformance check of the captured happy-path messages.
#
# Self-pay: payer = merchant = the funded wallet (funds cycle back minus fees).
# No jq. Usage: kob/x402/scripts/e2e_x402_exact.sh
set -uo pipefail

BIN="${BIN:-/root/kob-rust-target4/release}"
NODE="${NODE:-ws://65.108.107.30:18210}"
WALLET="${WALLET:-/tmp/kob_e2e/wallet.json}"
NETWORK="${NETWORK:-kaspa:testnet-10}"
FAC_BIND="${FAC_BIND:-127.0.0.1:8405}"
FAC_URL="http://${FAC_BIND}"
WORK="${WORK:-/tmp/kob_e2e/x402_exact}"
REPLAY_LOG="${WORK}/replay.jsonl"
RESULTS="${WORK}/E2E_X402_EXACT_TXIDS.txt"
AMOUNT="${AMOUNT:-5000000}"
BORROW="${BORROW:-10000000}"
THRESHOLD="${THRESHOLD:-3000000}"
# Request-binding is mandatory (Phase 2): the reservation binds this hash and
# the client payload must echo it. 64-hex.
REQHASH="${REQHASH:-abababababababababababababababababababababababababababababababab}"

mkdir -p "$WORK"; rm -f "$REPLAY_LOG"; : > "$RESULTS"
log()  { echo "[exact-e2e] $*"; }
field() { grep -oE "\"$1\":(\"[^\"]*\"|[a-z0-9]+)" | head -1 | sed -E "s/\"$1\"://; s/^\"//; s/\"$//"; }
txid_of() { grep -oE '[0-9a-f]{64}' | head -1; }

WADDR=$("$BIN/kob-cli" --node "$NODE" --wallet "$WALLET" wallet 2>/dev/null | grep -oE 'kaspatest:[0-9a-z]+' | head -1)
[ -z "$WADDR" ] && { echo "no wallet address"; exit 1; }
PAYTO="$WADDR"   # self-pay merchant
log "wallet/payTo=$PAYTO amount=$AMOUNT borrow=$BORROW threshold=$THRESHOLD"

# ---- 1. covenant address + fund it ----
COV_ADDR=$("$BIN/x402-client" exact-address "$PAYTO" "$BORROW" "$THRESHOLD" testnet 2>/dev/null)
[ -z "$COV_ADDR" ] && { echo "could not compute covenant address"; exit 1; }
log "borrow covenant P2SH: $COV_ADDR"
log "funding borrow UTXO ($BORROW sompi) ..."
BORROW_TXID=$("$BIN/x402-client" --node "$NODE" --wallet "$WALLET" --network "$NETWORK" \
  --pay-to "$COV_ADDR" --amount "$BORROW" --broadcast 2>>"$WORK/client.log")
[ -z "$BORROW_TXID" ] && { echo "borrow funding failed"; tail -3 "$WORK/client.log"; exit 1; }
log "borrow funding txid=$BORROW_TXID (borrow outpoint ${BORROW_TXID}:0)"

# ---- start facilitator ----
log "starting facilitator on $FAC_BIND ..."
"$BIN/kob-x402" --node "$NODE" --bind "$FAC_BIND" --network "$NETWORK" --replay-log "$REPLAY_LOG" \
  > "$WORK/facilitator.log" 2>&1 &
FAC_PID=$!
trap 'kill $FAC_PID 2>/dev/null' EXIT
for i in $(seq 1 30); do curl -sf "$FAC_URL/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -sf "$FAC_URL/health" >/dev/null 2>&1 || { echo "facilitator down"; tail -20 "$WORK/facilitator.log"; exit 1; }

# ---- 2. reserve ----
log "reserving ..."
RESREQ="{\"payTo\":\"$PAYTO\",\"amount\":\"$AMOUNT\",\"borrowTxid\":\"$BORROW_TXID\",\"borrowIndex\":0,\"borrowAmount\":\"$BORROW\",\"additiveThresholdSompi\":\"$THRESHOLD\",\"paymentOutputIndex\":0,\"resourceUrl\":\"https://api.example.test/file\",\"requestHash\":\"$REQHASH\"}"
curl -s -X POST "$FAC_URL/reserve" -H 'content-type: application/json' --data-binary "$RESREQ" > "$WORK/reserve.json"
log "reserve -> $(cat "$WORK/reserve.json" | head -c 300)"
# extract accepts[0] into requirements.json (strip the outer PaymentRequired).
python3 - "$WORK/reserve.json" "$WORK/requirements.json" <<'PY' 2>/dev/null || {
import json,sys
d=json.load(open(sys.argv[1]))
json.dump(d["accepts"][0], open(sys.argv[2],"w"))
PY
  echo "python3 unavailable — cannot extract accepts[0]"; exit 1; }

# wait for the borrow UTXO to confirm (verify does an on-chain check).
sleep 3

PASS=0; FAIL=0
check() { if [ "$2" = "$3" ]; then echo "  PASS: $1"; PASS=$((PASS+1)); else echo "  FAIL: $1 (want $2 got $3)"; FAIL=$((FAIL+1)); fi; }
build_exact() { "$BIN/x402-client" exact --node "$NODE" --wallet "$WALLET" --requirements-file "$WORK/requirements.json" --scenario "$1" --request-hash "$REQHASH" --out "$2" 2>>"$WORK/client.log"; }
post() { curl -s -X POST "$FAC_URL/$1" -H 'content-type: application/json' --data-binary @"$2"; }

# =====================================================================
# REJECTION CASES (verify-only, no broadcast) — run before the happy settle
# =====================================================================
log "CASE R1: wrong borrow outpoint (must be refused)"
build_exact wrong-borrow "$WORK/req_wrongborrow.json"
V=$(post verify "$WORK/req_wrongborrow.json"); log "verify -> $V"
check "wrong-borrow refused" "false" "$(echo "$V" | field isValid)"
check "wrong-borrow code" "invalid_transaction_state" "$(echo "$V" | field invalidReason)"

log "CASE R2: continuation under threshold (must be refused)"
build_exact under-threshold "$WORK/req_under.json"
V=$(post verify "$WORK/req_under.json"); log "verify -> $V"
check "under-threshold refused" "false" "$(echo "$V" | field isValid)"
check "under-threshold code" "invalid_payment_requirements" "$(echo "$V" | field invalidReason)"

log "CASE R3: wrong recipient (must be refused)"
build_exact wrong-recipient "$WORK/req_wrongrcpt.json"
V=$(post verify "$WORK/req_wrongrcpt.json"); log "verify -> $V"
check "wrong-recipient refused" "false" "$(echo "$V" | field isValid)"
check "wrong-recipient code" "invalid_payment_requirements" "$(echo "$V" | field invalidReason)"

log "CASE R5: wrong request hash (mandatory binding must be enforced)"
build_exact wrong-request-hash "$WORK/req_wrongrh.json"
V=$(post verify "$WORK/req_wrongrh.json"); log "verify -> $V"
check "wrong-request-hash refused" "false" "$(echo "$V" | field isValid)"
check "wrong-request-hash code" "invalid_payload" "$(echo "$V" | field invalidReason)"

# =====================================================================
# CASE 1 — HAPPY: verify -> settle -> confirm -> authorize
# =====================================================================
log "CASE 1: happy (verify + settle + confirm)"
build_exact happy "$WORK/req_happy.json"
V=$(post verify "$WORK/req_happy.json"); log "verify -> $V"
check "happy verify isValid" "true" "$(echo "$V" | field isValid)"
S=$(post settle "$WORK/req_happy.json"); log "settle -> $S"
check "happy settle success" "true" "$(echo "$S" | field success)"
TXID=$(echo "$S" | field transaction)
echo "EXACT_HAPPY_TXID=$TXID" | tee -a "$RESULTS"
echo "EXACT_BORROW_FUNDING_TXID=$BORROW_TXID" | tee -a "$RESULTS"

# =====================================================================
# CASE R4 — REPLAY: a distinct artifact over the consumed borrow outpoint
# =====================================================================
log "CASE R4: replay of the consumed borrow outpoint (must be refused)"
build_exact replay "$WORK/req_replay.json"
V=$(post verify "$WORK/req_replay.json"); log "replay verify -> $V"
check "replay refused" "false" "$(echo "$V" | field isValid)"

# =====================================================================
# Schema conformance of the captured happy-path message set
# =====================================================================
log "schema conformance (captured live messages vs vendored schemas)"
conform() { if echo "$2" | grep -q "$3"; then echo "  PASS: $1"; PASS=$((PASS+1)); else echo "  FAIL: $1"; FAIL=$((FAIL+1)); fi; }
RES=$(cat "$WORK/reserve.json"); PAY=$(cat "$WORK/req_happy.json"); SET="$S"
# PaymentRequired (alpha.8: kaspa-exact-v2 + additive profile head/challenge vocabulary)
conform "PaymentRequired x402Version=2"        "$RES" '"x402Version":2'
conform "PaymentRequired resource.url"         "$RES" '"resource":{[^}]*"url"'
conform "PaymentRequirements scheme=exact"     "$RES" '"scheme":"exact"'
conform "PaymentRequirements asset=KAS"        "$RES" '"asset":"KAS"'
conform "extra binding=kaspa-exact-v2"         "$RES" '"binding":"kaspa-exact-v2"'
conform "extra profile=additive"               "$RES" '"profile":"additive"'
conform "extra templateId kip10-additive"      "$RES" '"templateId":"kaspa-x402-kip10-additive-v1"'
conform "extra transactionEncoding"            "$RES" '"transactionEncoding":"kaspa-sdk-safe-json-v2.0.0"'
conform "extra payToScriptPublicKey 0000..."   "$RES" '"payToScriptPublicKey":"0000'
conform "extra headScriptPublicKey 0000..."    "$RES" '"headScriptPublicKey":"0000'
conform "extra expectedHeadOutpoint"           "$RES" '"expectedHeadOutpoint":{'
conform "extra headVersion"                    "$RES" '"headVersion":"0"'
conform "extra challengeId 64hex"              "$RES" '"challengeId":"[0-9a-f]\{64\}"'
conform "extra challengeExpiresAt ISO"         "$RES" '"challengeExpiresAt":"[0-9]\{4\}-'
if echo "$RES" | grep -q '"borrowOutpoint"\|"reservationId"'; then echo "  FAIL: alpha.7 borrow/reservation fields must be gone"; FAIL=$((FAIL+1)); else echo "  PASS: no alpha.7 borrow/reservation fields"; PASS=$((PASS+1)); fi
# PaymentPayload
conform "PaymentPayload x402Version=2"         "$PAY" '"x402Version":2'
conform "PaymentPayload has accepted"          "$PAY" '"accepted":'
conform "payload type exact-transaction"       "$PAY" '"type":"exact-transaction"'
conform "payload profile=additive"             "$PAY" '"profile":"additive"'
conform "payload transactionEncoding"          "$PAY" '"transactionEncoding":"kaspa-sdk-safe-json-v2.0.0"'
conform "payload challengeId 64hex"            "$PAY" '"challengeId":"[0-9a-f]\{64\}"'
conform "payload requestHash"                  "$PAY" '"requestHash":"[0-9a-f]\{64\}"'
conform "payload authorization version"        "$PAY" '"version":"kaspa-x402-exact-request-authorization-v1"'
if echo "$PAY" | grep -q '"payload":{[^}]*"transactionId"'; then echo "  FAIL: exact payload must NOT carry transactionId"; FAIL=$((FAIL+1)); else echo "  PASS: no transactionId in exact payload"; PASS=$((PASS+1)); fi
# SettlementResponse
conform "SettlementResponse success=true"      "$SET" '"success":true'
conform "SettlementResponse 64hex transaction" "$SET" '"transaction":"[0-9a-f]\{64\}"'
conform "SettlementResponse has amount"        "$SET" '"amount":"'
conform "SettlementResponse extensions.kaspa"  "$SET" '"extensions":{"kaspa"'
conform "SettlementResponse exactProfile"      "$SET" '"exactProfile":"additive"'
conform "SettlementResponse headOutpoint"      "$SET" '"headOutpoint":{'
if echo "$SET" | grep -q '"extra":'; then echo "  FAIL: SettlementResponse must not have top-level extra"; FAIL=$((FAIL+1)); else echo "  PASS: no top-level extra in SettlementResponse"; PASS=$((PASS+1)); fi

echo
echo "=== EXACT RESULT: $PASS passed, $FAIL failed ==="
cat "$RESULTS"
[ "$FAIL" -eq 0 ]
