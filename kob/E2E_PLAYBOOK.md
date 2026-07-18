# KOB E2E Playbook (TN12)

> **SUPERSEDED — frozen at pre-v18 (v14/v15) generation.** These copy-paste
> patterns predate the v18 unification (`V18_DESIGN.md`, deleted
> v14/v16/v17 — commits `23eb1edc`/`e5bfcd6c`) and the TIME contracts /
> LIMITS re-freeze that followed it. See `kob/RELEASE_STATUS.md` for the
> current canary scope and live-proof status; do not copy-paste these
> commands against current binaries without checking they still apply.
> Kept as historical record, not regenerated.

Copy-paste test patterns. Assumes wallet exists and is funded.

> **2026-07-14 (post-Toccata / KCC20)**: token_unit RS changed 35B → 38B
> (KCC20 Standard State Header) — token_unit P2SH addresses moved, so any
> token UTXOs from older binaries are invisible to the new CLI. Always run
> the Shared Setup (fresh `token create` + `token mint`) on a new binary.
> Verify the node endpoint runs a post-Toccata (v2.x) build. On-device build
> notes (exec-capable `CARGO_TARGET_DIR`, Termux clang linker) are in
> kob/README.md.

## Critical Notes

- **ENGINE FIRST**: Start engine BEFORE deploying orders. Engine does NOT rescan old UTXOs — it only discovers orders from new blocks after startup.
- `--allow-self-trade` required when same wallet does both sides
- Fresh `--orderbook /tmp/ob_<NAME>.json` per test (stale UTXO prevention)
- 1 KAS = 100,000,000 sompi
- Price: sell at 1/20 (0.05), buy at 1/10 (0.1) -- these cross
- Wait **6s** after last deploy for CSV(50 DAA ~ 5s) to pass before engine can match
- Engine needs `config.json`: `{"node":"ws://65.108.107.30:18210"}`
- Parse: deploy commands output `Order deployed at output <txid>:<idx>`; token create/mint still use `TXID: <hex>`
- Engine startup order: start engine → wait for "Deploy orders AFTER this message" → deploy
- Engine startup log: `[ENGINE] allow_self_trade=true cross_pair=false` confirms settings
- **KILL STALE ENGINES**: Always `pkill -9 -f kob-engine` before starting a new engine. Stale engines steal orders and cause double-spend failures.
- ZK false positive fixed: CLI no longer falsely warns about OpZkPrecompile when state bytes contain 0xa6
- SD card filesystem: if `cargo build` does not detect `.rs` changes, run `touch` on the modified files first

## Aliases

```bash
NODE="ws://65.108.107.30:18210"
BIN="/data/data/com.termux/files/home/cargo-target/debug"
KOB="$BIN/kob-cli --node $NODE"
ENGINE="$BIN/kob-engine --node $NODE --wallet wallet.json --config e2e_config.json --allow-self-trade"
```

## Shared Setup: Token Create + Mint

Run once. Reuse TOKEN/TOKEN_UTXO across patterns.

```bash
CREATE_OUT=$($KOB token create --ticker E2E --supply 1000000 --decimals 8 --amount 1000000000 2>&1)
CREATE_TXID=$(echo "$CREATE_OUT" | grep "^TXID:" | awk '{print $2}')
TOKEN=$(echo "$CREATE_OUT" | grep "^Token ID:" | awk '{print $3}')
sleep 3

# Mint 1: token unit at output :1, mint continuation at :0
MINT_OUT=$($KOB token mint --txid "$CREATE_TXID" --token "$TOKEN" --amount 5000000000 2>&1)
MINT_TXID=$(echo "$MINT_OUT" | grep "^TXID:" | awk '{print $2}')
TOKEN_UTXO="${MINT_TXID}:1"
sleep 3

# Mint 2
MINT2_OUT=$($KOB token mint --txid "$MINT_TXID" --token "$TOKEN" --amount 5000000000 2>&1)
MINT2_TXID=$(echo "$MINT2_OUT" | grep "^TXID:" | awk '{print $2}')
TOKEN_UTXO2="${MINT2_TXID}:1"
MINT_CONT="${MINT2_TXID}:0"
sleep 3
```

---

## Pattern 1: Buy Sweep (1:N)

1 big buy consumes 2 small sells.

```bash
OB="/tmp/ob_buysweep.json"

# 1. Start engine FIRST (background)
$ENGINE --orderbook "$OB" --mode continuous --interval 3000 2>&1 | tee /tmp/buysweep.log &
ENGINE_PID=$!
sleep 5  # wait for "Deploy orders AFTER this message"

# 2. Deploy orders (engine discovers them from new blocks)
S1_OUT=$($KOB deploy sell --token "$TOKEN" --price-num 1 --price-den 20 \
  --min-fill 1000000 --amount 200000000 --token-utxo "$TOKEN_UTXO" 2>&1)
S1_OP=$(echo "$S1_OUT" | grep "^Order deployed" | awk '{print $5}')
sleep 3

S2_OUT=$($KOB deploy sell --token "$TOKEN" --price-num 1 --price-den 20 \
  --min-fill 1000000 --amount 200000000 --token-utxo "$TOKEN_UTXO2" 2>&1)
S2_OP=$(echo "$S2_OUT" | grep "^Order deployed" | awk '{print $5}')
sleep 3

B1_OUT=$($KOB deploy buy --token "$TOKEN" --price-num 1 --price-den 10 \
  --min-fill 1000000 --amount 1000000000 2>&1)
B1_OP=$(echo "$B1_OUT" | grep "^Order deployed" | awk '{print $5}')

# 3. Wait for CSV(50 DAA ~5s) + match cycle
sleep 15
kill $ENGINE_PID 2>/dev/null

grep "BATCH.*SUCCESS" /tmp/buysweep.log
# Expected: [BATCH] SUCCESS! TXID: <hex>
```

---

## Pattern 2: Sell Sweep (N:1)

1 big sell, 2 small buys.

```bash
OB="/tmp/ob_sellsweep.json"

# Mint tokens for sell
MINT3_OUT=$($KOB token mint --txid "$MINT_CONT" --token "$TOKEN" --amount 5000000000 2>&1)
MINT3_TXID=$(echo "$MINT3_OUT" | grep "^TXID:" | awk '{print $2}')
TOKEN_UTXO3="${MINT3_TXID}:1"; MINT_CONT="${MINT3_TXID}:0"
sleep 3

# 1. Start engine FIRST
$ENGINE --orderbook "$OB" --mode continuous --interval 3000 2>&1 | tee /tmp/sellsweep.log &
ENGINE_PID=$!
sleep 5

# 2. Deploy orders
B1_OUT=$($KOB deploy buy --token "$TOKEN" --price-num 1 --price-den 10 \
  --min-fill 1000000 --amount 300000000 2>&1)
sleep 3

B2_OUT=$($KOB deploy buy --token "$TOKEN" --price-num 1 --price-den 10 \
  --min-fill 1000000 --amount 300000000 2>&1)
sleep 3

S1_OUT=$($KOB deploy sell --token "$TOKEN" --price-num 1 --price-den 20 \
  --min-fill 1000000 --amount 1000000000 --token-utxo "$TOKEN_UTXO3" 2>&1)

# 3. Wait + kill
sleep 15
kill $ENGINE_PID 2>/dev/null

grep "BATCH.*SUCCESS" /tmp/sellsweep.log
# Expected: [BATCH] SUCCESS! TXID: <hex>
```

---

## Pattern 3: Partial Fill

Buy partially consumes a sell via CLI `partial-fill`.

```bash
MINT4_OUT=$($KOB token mint --txid "$MINT_CONT" --token "$TOKEN" --amount 5000000000 2>&1)
MINT4_TXID=$(echo "$MINT4_OUT" | grep "^TXID:" | awk '{print $2}')
TOKEN_UTXO4="${MINT4_TXID}:1"; MINT_CONT="${MINT4_TXID}:0"
sleep 3

# Sell: 5 KAS tokens at 1/20, min_fill allows partial
# NOTE: min_fill is in KAS (sompi). fill_amount is tokens.
# fill_kas = fill_amount * price = 200M * 1/20 = 10M sompi.
# min_fill must be <= fill_kas, so use 1M (not 50M).
# Also: residual tokens must satisfy min_fill when converted to KAS.
S_OUT=$($KOB deploy sell --token "$TOKEN" --price-num 1 --price-den 20 \
  --min-fill 1000000 --amount 500000000 --token-utxo "$TOKEN_UTXO4" 2>&1)
S_OP=$(echo "$S_OUT" | grep "^Order deployed" | awk '{print $5}')

sleep 6

# Fill 2 KAS of the 5 KAS sell
# --fee-rate is required; default 0 causes rejection
PF_OUT=$($KOB partial-fill \
  --outpoint "$S_OP" --side sell --token "$TOKEN" \
  --price-num 1 --price-den 20 --min-fill 1000000 \
  --fill-amount 200000000 --fee-rate 5000 2>&1)
PF_TXID=$(echo "$PF_OUT" | grep "^TXID:" | awk '{print $2}')

# Residual sell at PF_TXID:0 with 3 KAS remaining
# Expected: SUCCESS! Partial fill submitted.
```

---

## Pattern 4: OCO Sell

Deploy OCO sell (TP + SL), fill the TP path via engine.

```bash
OB="/tmp/ob_oco.json"

MINT5_OUT=$($KOB token mint --txid "$MINT_CONT" --token "$TOKEN" --amount 5000000000 2>&1)
MINT5_TXID=$(echo "$MINT5_OUT" | grep "^TXID:" | awk '{print $2}')
TOKEN_UTXO5="${MINT5_TXID}:1"; MINT_CONT="${MINT5_TXID}:0"
sleep 3

# 1. Start engine FIRST
$ENGINE --orderbook "$OB" --mode continuous --interval 3000 2>&1 | tee /tmp/oco.log &
ENGINE_PID=$!
sleep 5

# 2. Deploy OCO sell + crossing buy
OCO_OUT=$($KOB deploy oco-sell --token "$TOKEN" \
  --tp-price-num 1 --tp-price-den 10 --tp-min-fill 1000000 \
  --sl-price-num 1 --sl-price-den 40 --sl-min-fill 1000000 \
  --amount 300000000 --token-utxo "$TOKEN_UTXO5" 2>&1)
sleep 3

BUY_OUT=$($KOB deploy buy --token "$TOKEN" --price-num 1 --price-den 5 \
  --min-fill 1000000 --amount 500000000 2>&1)

# 3. Wait + kill
sleep 15
kill $ENGINE_PID 2>/dev/null

grep "BATCH.*SUCCESS" /tmp/oco.log
# Expected: [BATCH] SUCCESS! TXID: <hex>
# Filling TP spends the UTXO, naturally canceling SL (OCO behavior)
# NOTE: Engine may match either the TP or SL path depending on traversal order.
# Both are valid matches -- whichever is consumed first cancels the other.
```

---

## Pattern 5: DCA Fill

Deploy DCA schedule, fill one period manually.

```bash
# Mint tokens for filler to provide
# NOTE: `token mint` creates P2SH UTXOs. `dca fill` handles P2SH directly
# (fixed in commit d09840c1) — no need to `token transfer` to P2PK first.
# NOTE: Continuation fill (periods>1, D&R path) has a known bytecode issue.
# Only final fill (periods=1) is currently validated on TN12.
MINT6_OUT=$($KOB token mint --txid "$MINT_CONT" --token "$TOKEN" --amount 3000000000 2>&1)
MINT6_TXID=$(echo "$MINT6_OUT" | grep "^TXID:" | awk '{print $2}')
FILLER_TOKEN="${MINT6_TXID}:1"; FILLER_TOKEN_VALUE=3000000000
MINT_CONT="${MINT6_TXID}:0"
sleep 3

# Get buyer pubkey
BUYER_PK=$($KOB wallet info 2>&1 | grep "^Public Key:" | awk '{print $3}')

# Deploy DCA: 3 periods, 1 KAS/period, interval 10 DAA, price 1/20
DCA_OUT=$($KOB dca deploy --target-cov-id "$TOKEN" \
  --price-num 1 --price-den 20 --amount-per-period 100000000 \
  --interval-daa 10 --periods 3 2>&1)
DCA_TXID=$(echo "$DCA_OUT" | grep "^TXID:" | awk '{print $2}')
DCA_RS=$(echo "$DCA_OUT" | grep "^RS:" | awk '{print $2}')
DCA_OP="${DCA_TXID}:0"

sleep 6

# Fill one period (permissionless -- anyone can call)
FILL_OUT=$($KOB dca fill --outpoint "$DCA_OP" --rs "$DCA_RS" \
  --token-outpoint "$FILLER_TOKEN" --token-value "$FILLER_TOKEN_VALUE" \
  --buyer-pubkey "$BUYER_PK" 2>&1)
FILL_TXID=$(echo "$FILL_OUT" | grep "^TXID:" | awk '{print $2}')
# Expected: SUCCESS! DCA period filled (continuation).
# Next fill RS+outpoint printed in "Next fill command:" line
```

---

## Pattern 6: Swap

Deploy cross-token swap. Requires two tokens + cross-pair engine.

```bash
OB="/tmp/ob_swap.json"

# Create Token B + mint
CREATE2_OUT=$($KOB token create --ticker SWPB --supply 1000000 --decimals 8 --amount 1000000000 2>&1)
CREATE2_TXID=$(echo "$CREATE2_OUT" | grep "^TXID:" | awk '{print $2}')
TOKEN_B=$(echo "$CREATE2_OUT" | grep "^Token ID:" | awk '{print $3}')
sleep 3

MINT_B_OUT=$($KOB token mint --txid "$CREATE2_TXID" --token "$TOKEN_B" --amount 3000000000 2>&1)
MINT_B_TXID=$(echo "$MINT_B_OUT" | grep "^TXID:" | awk '{print $2}')
TOKEN_B_UTXO="${MINT_B_TXID}:1"
sleep 3

# Mint Token A for swap source
MINT7_OUT=$($KOB token mint --txid "$MINT_CONT" --token "$TOKEN" --amount 3000000000 2>&1)
MINT7_TXID=$(echo "$MINT7_OUT" | grep "^TXID:" | awk '{print $2}')
TOKEN_A_UTXO="${MINT7_TXID}:1"; MINT_CONT="${MINT7_TXID}:0"
sleep 3

RECEIPT_COV="0000000000000000000000000000000000000000000000000000000000000000"

# 1. Start engine FIRST (with --cross-pair)
$ENGINE --orderbook "$OB" --cross-pair --mode continuous --interval 3000 2>&1 | tee /tmp/swap.log &
ENGINE_PID=$!
sleep 5

# 2. Deploy swap + liquidity (engine discovers from blocks)
SWAP_OUT=$($KOB swap deploy --source-token "$TOKEN" --target-token "$TOKEN_B" \
  --amount 300000000 --min-receive 100000000 \
  --receipt-cov-id "$RECEIPT_COV" --token-utxo "$TOKEN_A_UTXO" 2>&1)
sleep 3

$KOB deploy sell --token "$TOKEN" --price-num 1 --price-den 20 \
  --min-fill 1000000 --amount 500000000 --token-utxo "${MINT7_TXID}:0" 2>&1
sleep 3
$KOB deploy buy --token "$TOKEN_B" --price-num 1 --price-den 10 \
  --min-fill 1000000 --amount 500000000 2>&1

# 3. Wait + kill
sleep 20
kill $ENGINE_PID 2>/dev/null

grep "SUCCESS" /tmp/swap.log
```

---

## Quick Reference: Output Parsing

| Command | Key output line | Parse |
|---------|----------------|-------|
| `token create` | `TXID: <hex>` / `Token ID: <hex>` | `grep "^TXID:" \| awk '{print $2}'` |
| `token mint` | `TXID: <hex>` / `Token unit: <txid>:1` | Token UTXO is always `<TXID>:1` |
| `deploy buy` | `Order deployed at output <txid>:<idx>` | `grep "^Order deployed" \| awk '{print $5}'` |
| `deploy sell` | `Order deployed at output <txid>:<idx>` | `grep "^Order deployed" \| awk '{print $5}'` |
| `deploy oco-sell` | `Order deployed at output <txid>:<idx>` | `grep "^Order deployed" \| awk '{print $5}'` |
| `dca deploy` | `TXID: <hex>` / `RS: <hex>` | Both needed for fill/cancel |
| `dca fill` | `TXID: <hex>` | Continuation outpoint in "Next fill" line |
| `swap deploy` | `TXID: <hex>` / `RS: <hex>` | Both needed for cancel |
| Engine match | `[BATCH] SUCCESS! TXID: <hex>` | `grep "BATCH.*SUCCESS"` |
| Engine startup | `[ENGINE] allow_self_trade=true cross_pair=false` | Confirms settings |
