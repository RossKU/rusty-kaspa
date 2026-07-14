#!/usr/bin/env bash
# v16 buy-contract E2E harness for testnet-10.
#
# Reuses a persisted token (kob/e2e_fixture.json) so reruns of the honest-match
# and adversarial legs are cheap: the token GENESIS is deployed once and reused;
# only fresh token_units are minted per run (a cancelled sell unlocks tokens to
# KAS in the KOB model, so token_units are not long-lived). If the fixture is
# missing or its mint authority UTXO is spent, a new genesis is deployed and the
# fixture rewritten.
#
# Usage: kob/scripts/e2e_v16.sh
# Requires: kob-cli + kob-engine release binaries; a funded wallet.
# No jq dependency (this device lacks jq): fixture reads use grep/sed.
set -uo pipefail

FIXTURE="${FIXTURE:-$(cd "$(dirname "$0")/.." && pwd)/e2e_fixture.json}"
BIN="${BIN:-/root/kob-rust-target4/release}"
NODE="${NODE:-ws://65.108.107.30:18210}"
WALLET="${WALLET:-/tmp/kob_e2e/wallet.json}"
FEE_RATE="${FEE_RATE:-400000}"
KOB="$BIN/kob-cli --node $NODE --wallet $WALLET --fee-rate $FEE_RATE"

json_str() { grep -oE "\"$1\": \"[^\"]*\"" "$FIXTURE" | sed -E 's/.*: "(.*)"/\1/'; }
set_authority() { sed -i -E "s#(\"mint_authority_outpoint\": )\"[^\"]*\"#\\1\"$1\"#" "$FIXTURE"; }
txid_of() { grep -oE 'TXID:[[:space:]]+[0-9a-f]{64}' | grep -oE '[0-9a-f]{64}' | head -1; }

# ---- 1. Load or create the reusable token ----
if [ -f "$FIXTURE" ]; then
  TOKEN=$(json_str token_covenant_id)
  AUTH=$(json_str mint_authority_outpoint)
  echo "[fixture] token=$TOKEN authority=$AUTH"
  if ! $BIN/kob-cli --node "$NODE" --wallet "$WALLET" order-status --outpoint "$AUTH" 2>&1 \
       | grep -qiE "OPEN|found|entry|utxo"; then
    echo "[fixture] mint authority spent — redeploying token genesis"; rm -f "$FIXTURE"
  fi
fi

if [ ! -f "$FIXTURE" ]; then
  echo "[genesis] deploying fresh token..."
  OUT=$($KOB token create --ticker V16E2E --supply 1000000000 --decimals 8 --amount 100000000 2>&1)
  TOKEN=$(echo "$OUT" | grep -oE 'Token ID: [0-9a-f]{64}' | grep -oE '[0-9a-f]{64}')
  GEN_TX=$(echo "$OUT" | txid_of)
  AUTH="$GEN_TX:0"
  printf '{\n  "network": "testnet-10",\n  "node": "%s",\n  "ticker": "V16E2E",\n  "token_covenant_id": "%s",\n  "token_genesis_txid": "%s",\n  "mint_authority_outpoint": "%s"\n}\n' \
    "$NODE" "$TOKEN" "$GEN_TX" "$AUTH" > "$FIXTURE"
  echo "[genesis] token=$TOKEN genesis=$GEN_TX"
fi

# ---- 2. Mint fresh token_units from the reused authority ----
echo "[mint] minting 30M token_units from $AUTH ..."
MOUT=$($KOB token mint --txid "${AUTH%%:*}" --index "${AUTH##*:}" --token "$TOKEN" --amount 30000000 2>&1)
MINT_TX=$(echo "$MOUT" | txid_of)
[ -z "$MINT_TX" ] && { echo "[mint] FAILED:"; echo "$MOUT" | tail -3; exit 1; }
UNIT="$MINT_TX:1"; set_authority "$MINT_TX:0"
echo "[mint] token_unit=$UNIT  new_authority=$MINT_TX:0 (fixture updated)"

echo
echo "TOKEN=$TOKEN"
echo "UNIT=$UNIT"
echo "Next: start kob-engine (wait for 'listening for new blocks'), then deploy"
echo "  sell FIRST (teaches the covenant): deploy sell --token \$TOKEN --price-num 499 --price-den 500 --min-fill 8000000 --amount 30000000 --token-utxo \$UNIT"
echo "  then buy: deploy buy --token \$TOKEN --version 16 --mmfee-bps 2000 --price-num 1 --price-den 1 --min-fill 8000000 --amount 30000000"
echo "See kob/V16_STATUS.md Phase 9 for the remaining covenant-fill blocker + diagnostic."
