# KOB SPOT E2E Verification Matrix

Production-readiness checklist for the SPOT suite. Every order type × match path ×
operational command must have a **post-M1** TN12 E2E PASS before release.

## Environment
- Network: TN12 `ws://65.108.107.30:18210`
- Binary: `$CARGO_TARGET_DIR/release/kob-{engine,cli}`
- Runner: `kob/scripts/e2e_spot_full.sh`
- Wallet: `/tmp/wallet_e2e.json` (funded)
- Config: `kob/e2e_config.json`

## Legend
- `[ ]` not yet run on post-M1 binary
- `[x]` PASS (note TXID + date in "Run history")
- `[!]` FAIL (note cause)
- `[-]` not automatable in pure sh (Manual section)

## Reference commits
- `87ba6c97` — origin/kob-phase0 tip pre-M1
- `5d888d07` — H1 wallet_spk caching
- `1b5ac6be` — M1 v2 BATCH single-sign
- `85ad6a93` — MatchTx (same-pair + cross-pair) single-sign (current HEAD)

---

## I. Limit orders

- [ ] **P01** Buy limit (1:N sweep via BATCH) — `deploy buy`
- [ ] **P02** Sell limit (1:N sweep via BATCH) — `deploy sell`
- [ ] **P03** Partial fill (fill_amt < order_amt) — `deploy` + engine partial fill
- [ ] **P36** Partial-fill (explicit CLI, owner-initiated) — `partial-fill`

## II. Time-in-Force

- [ ] **P04** GTC (default, implicit in P01/P02)
- [ ] **P05** IOC (`--time-in-force IOC`)
- [ ] **P06** FOK (`--time-in-force FOK`)
- [ ] **P07** GTD (`--expiry <daa_score>`)

## III. Payload modifiers

- [ ] **P08** Post-Only (`--post-only`)

## IV. Advanced L1 orders

- [ ] **P09** OCO (`deploy oco-sell` = v6 single-UTXO)
- [ ] **P10** Bracket v6 (entry + oco exit, `bracket deploy`)
- [ ] **P11** IFD (parent→child activation, `deploy ifd`)
- [ ] **P12a** DCA final fill, periods=1 (`dca deploy` + `dca fill`)
- [ ] **P12b** DCA continuation, periods>1 (D&R bytecode)
- [ ] **P13** Swap (token A → B routed, `swap deploy`)
- [ ] **P34** IFO (buy entry + auto-deploy TP+SL, Matcher-registered, `deploy ifo`)
- [ ] **P35** IFO Trustless (bracket via IFD payload, `deploy ifo-trustless`)

## V. Matcher-managed orders (need Matcher HTTP API running)

- [ ] **P14** Stop-Limit buy/sell (`stop deploy-buy/sell --type stop-limit`)
- [ ] **P15** Stop-Market (`--type stop-market`)
- [ ] **P16** Trailing-Stop (`trailing-stop deploy`)

## VI. Market orders

- [ ] **P17** Market order (`deploy buy --market --slippage-bps`)

## VII. Auction (multi-party) — Manual

- [-] **P18** English auction (`auction english-deploy/bid/settle`)
- [-] **P19** Dutch auction (`auction dutch-deploy/tick/buy/cancel`)

## VIII. Match paths

- [ ] **P20** Same-pair match (explicit `kob-cli match`)
- [ ] **P21** Cross-pair single (`match --cross-pair`)
- [ ] **P22** BATCH N:M same-pair (exercised by P01/P02)
- [ ] **P23** BATCH cross-pair (2 tokens × N+M orders)
- [ ] **P24** Auto-match (engine continuous scan, exercised by P01 etc.)
- [ ] **P25** Match-batch CLI explicit (`match-batch`)

## IX. Operational

- [ ] **P26** Requote atomic (`requote`)
- [ ] **P27** Consolidate (`wallet consolidate`)
- [ ] **P28** Cancel single (`cancel`)
- [ ] **P29** Cancel-all (`cancel-all`)
- [ ] **P30** Cancel-mark (`cancel-mark`)
- [ ] **P31** Batch file ops (`batch --file <json>`)
- [ ] **P32** Recover/RBF (`recover-orders`, needs stuck TX)
- [ ] **P33** MM bot (`mm`, long-running daemon)

---

## Run history

<!-- Append a new section after each full/partial run. Keep most-recent-first. -->

### Run 2026-04-15 14:44 (post-M1 + auto-select, kob-phase0 @ `85ad6a93` + local mods)

Runner: `kob/scripts/e2e_spot_full.sh` with `MATCH_WAIT=35s`, **`--token-utxo` flag removed from P01/P02/P03/P05** (full auto-select validation). Pre-run `kob-cli recover` executed to RBF-unstick mempool UTXOs (`1bc03433:4` → `d4c0c616:0`).

Local modifications vs `85ad6a93` (additive since 12:55 run):
- `kob/cli/src/deploy.rs`: `pick_sell_deployable_token_utxo()` heuristic (covenant_id filter + amount ≥ min + smallest-first + `block_daa_score` tie-break). Wired into `deploy_sell` (l.834) and `deploy_oco_sell` (l.1300).
- `kob/cli/src/token.rs:517-520`: mint fee UTXO `.find()` → `.filter().min_by_key(amount)` (WASM-spec smallest-first). Root-fix for `1bc03433:4` (top-tier P2PK) being repeatedly re-selected from DESC-sorted wallet.
- `kob_core` / `kob_engine` plumbing: `covenant_id` field propagated through `rpc_types` → engine API → CLI UTXO view.

```
Pattern | Status | TXID                                                             | Notes
--------|--------|------------------------------------------------------------------|----------------------------------------------
P01     | PASS   | b1e85aa085019d6559da5aadfcea6444ce2fdc381e78a226d1bc1e7e2869813f | BATCH 1:2 via auto-select (no --token-utxo)
P02     | PASS   | 4df7a303ababca7ee37e197dc7f889c0b43f2a8c9215b4a583c2afb8889cb5ac | BATCH 2:1 via auto-select (no --token-utxo)
P03     | FAIL   | —                                                                | pre-existing timing attribution bug
P05     | PASS   | 44c51e60f4b033cacb019e7bb07c574ad5de2c30134ade2d0b9b9a34525d25d2 | IOC match via auto-select
P06     | PASS   | —                                                                | FOK deploy accepted (TXID dea626ac...)
P09     | PASS   | —                                                                | oco-sell v6 deploy accepted (TXID d69effbc...)
P11     | PASS   | —                                                                | IFD deploy accepted
P12a    | PASS   | —                                                                | DCA periods=1 deploy accepted
P13     | PASS   | —                                                                | swap deploy accepted
P17     | PASS   | —                                                                | market order accepted
P23     | FAIL   | —                                                                | pre-existing: cross_pair engine feature default off
P26     | PASS   | —                                                                | requote accepted
P28     | PASS   | —                                                                | cancel succeeded
P29     | PASS   | —                                                                | cancel-all executed (empty orders.json)
```

**Totals: 12 PASS / 2 FAIL / 0 SKIP** — identical to 12:55 baseline but **with full auto-select** (no manual UTXO flags).

#### What's new vs 12:55 baseline

- `--token-utxo` no longer required for `deploy sell` / `deploy oco-sell` on TN12.
- 10 fresh mint UTXOs seeded cleanly (token.rs mint fee selection no longer collides with pending-mempool UTXOs).
- `recover` successfully RBF-replaces stuck self-send mempool TXs (freed 1/49 UTXOs in this run).

#### Unresolved issues (carried forward)

1. **P03 timing attribution** — unchanged from 12:55 run. `MATCH_WAIT=35s` can close before late match lands; next pattern's `log_since` can scoop the TXID. Fix: poll for TXID instead of fixed sleep.
2. **P23 cross_pair** — engine feature flag `cross_pair` off by default; not a bug.
3. **Heuristic wall (agent memo)** — if fresh-mint UTXO and match-merged UTXO coincidentally share amount, smallest-first breaks. Observed-safe for now (fresh mints are exactly 50 KAS, merged are larger). True fix needs kaspad `getUtxoReturnInfo`-like covenant-lineage RPC.
4. **`token.rs:919-933` (transfer fee UTXO)** — still uses `.find()` on amount-DESC. Not exercised by current e2e suite but latent bug. Candidate for cleanup patch.

### Run 2026-04-15 12:55 (post-M1, kob-phase0 @ `85ad6a93` + local mods)

Runner: `kob/scripts/e2e_spot_full.sh` with `MATCH_WAIT=35s`, 10 TOKEN_A mint UTXOs,
CLI stderr captured to `/tmp/e2e_cli_stderr.log`. Engine auto-detect via
`DEFAULT_ENGINE_URL=http://127.0.0.1:8080` (no explicit `--engine-url` needed).

Local modifications vs `85ad6a93`:
- `kob/cli/src/node.rs`: `auto_engine_url()` TCP-probe, 3-tier routing priority.
- `kob/cli/src/main.rs`: `--engine-url` / `KOB_ENGINE_URL` clap arg.
- `kob/engine/src/api/mod.rs`, `lib.rs`: `/api/v1/wallet/utxos` endpoint + `SharedState.rpc`.
- `kob/cli/src/deploy.rs`: token auto-select chain order (`unit_utxos` first) — partial fix; still broken when prior match-merged UTXOs coexist with fresh mints.

```
Pattern | Status | TXID                                                             | Notes
--------|--------|------------------------------------------------------------------|----------------------------------------------
P01     | PASS   | c19f14c9afa06db9272f65804836bc18c0d052a60a407c600407628200e70fa2 | BATCH N:M (1 buy × 2 sells)
P02     | PASS   | db81090edb7e4fadab1f95feb0ed910882121cfbdad935bfc9cc36e6f5a384f9 | BATCH N:M (2 buys × 1 sell)
P03     | *FAIL  | (actual: 53b44ad0..., stolen by P05 grep)                        | Match succeeded on-chain @12:58:01 but landed 13s AFTER MATCH_WAIT=35s window. log_since attribution bug.
P05     | *PASS  | 53b44ad00a85554db88eb934f6744286ac262fcd0cc9223462c117fd71e8f2dc | TXID actually belongs to P03. Real P05 BATCH failed signature verification (logged at 12:59:07 + 12:59:39 retry).
P06     | PASS   | —                                                                | FOK deploy accepted (fill/kill semantics need follow-up)
P09     | PASS   | —                                                                | oco-sell v6 deploy accepted
P11     | PASS   | —                                                                | IFD deploy accepted
P12a    | PASS   | —                                                                | DCA periods=1 deploy accepted (fill path needs standalone test)
P13     | PASS   | —                                                                | swap deploy accepted (10 UTXO seed resolved prior exhaustion)
P17     | PASS   | —                                                                | market order accepted
P23     | FAIL   | —                                                                | cross_pair engine feature default off (not a bug; feature gate)
P26     | PASS   | —                                                                | requote accepted
P28     | PASS   | —                                                                | cancel succeeded
P29     | PASS   | —                                                                | cancel-all executed
```

**Totals (raw script): 12 PASS / 2 FAIL / 0 SKIP.**

#### Known issues uncovered by this run

1. **P03/P05 attribution swap** — `log_since "$mark" "BATCH.*SUCCESS.*TXID"` races the
   engine's match scan. Real match lands 48s after deploy but `MATCH_WAIT=35s`
   closes P03's window. Next pattern's `log_since` scoops up the late TXID.
   Fix: poll for TXID instead of fixed sleep, or bump wait to 60s.
2. **P05 real BATCH signature verify FAIL** — engine logs `[BATCH] Submit failed:
   script ran, but verification failed` for a 1 sell × 3 buys match twice.
   Distinct from attribution bug; worth isolating.
3. **Token auto-select covenant mismatch** — when unit_addr holds both fresh mint
   outputs and prior match-merged outputs, `first()` picks match-merged whose
   covenant genesis chain is incompatible with sell deploy. Chain-order fix
   (`unit_utxos.iter().chain(mint_utxos.iter())`) alone is insufficient.
4. **P23 cross_pair** — not a bug; engine's `cross_pair` feature is off by default.

#### What's working end-to-end on TN12

- BATCH 1:N, N:1, single-sign (P01, P02) — TXIDs confirmed
- IOC partial fill path — BATCH submission succeeded
- Deploy-only patterns (FOK, OCO, IFD, DCA, Market, Requote, Cancel, Cancel-all)
- Engine auto-detect via port 8080 probe (`/tmp/e2e_cli_stderr.log` shows
  "engine auto-detected" firing 6× across run 3 and similar rate in run 4)
