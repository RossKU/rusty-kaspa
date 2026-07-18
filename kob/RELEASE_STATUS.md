# KOB Release Status — mainnet canary scope and current state

**This is the canonical status doc.** The audit that produced this file
found the release truth scattered across `README.md`, `BATCH_LIMITS.md`,
`TIME_CONTRACTS_DESIGN.md`, `V18_DESIGN.md`, `E2E_MATRIX.md`,
`E2E_PLAYBOOK.md`, `E2E_LIVE_RESULTS.md`, and `ENGINE_API_DESIGN.md`, some
of it contradicting itself or the shipping code. Those docs still hold the
detailed evidence (measurements, TXIDs, adversarial matrices); this file is
the single place that says what's true *right now* and what the canary
scope actually is. Every claim below is grounded in one of those docs or in
code — cited inline.

**As of 2026-07-18** (the date of the latest Stage-G entries in
`E2E_LIVE_RESULTS.md`), **HEAD `73d3e330`** (`git rev-parse --short HEAD`).

---

## 1. Canary scope decision: SPOT-FIRST, staged

The owner's decision: a minimal spot canary first, then add products
incrementally, each gated on its own live-fire before inclusion.

**Stage 1 canary = spot (v18).** Strongest live evidence of any product in
the tree: the full 15-form matrix is live-proven on testnet-10 (Stage F,
`E2E_LIVE_RESULTS.md`), and the current `MAX_N=32` sweep ceiling is
live-proven at full width (TXID `536047f3…`, `BATCH_LIMITS.md`). See §2 for
exactly what's proven vs. still owed against the *current* bytecode — a
same-day re-freeze (`317f163c`) voided 7 of the 15 forms' proofs, tracked
in §4.

**Near-term follow-ons** (each gated on its own live-fire before
inclusion into the canary):
- **TIME_CONTRACTS** (`decay_sell` / `decay_buy` / `twap_sell` /
  `ratchet_oco`) — already heavily live-tested (Stage-G, 2026-07-17/18):
  every new contract form, all four composition proofs (CP-1..4), the
  owner-cap enforcement, and the full RT-2 adversarial set (21/21 malformed
  advances rejected live) have TXIDs. See §2c.
- **x402** — native/KCC20/exact payment schemes are live-confirmed,
  including a live-verified regression fix (CASE R2, TXID `9d61a47c…`,
  `e2e_x402_exact.sh` 30/30) (`E2E_LIVE_RESULTS.md:741,757,894-960`).

**Explicitly OUT of initial scope / staged later**, each with the reason:
- **Options (call/put)** — zero live TXIDs and zero engine wiring: no
  `option_executor`, no auto-fill path of any kind; exercise/expire/cancel
  are manual-CLI-only (`E2E_LIVE_RESULTS.md:1312-1313,1321`).
- **Dutch auction + English bidding** — untested. `listing` (the
  English/Dutch auction contract) got deploy + PATH-6 (permissionless
  settle-after-expiry) live-proven in the release-backlog pass (TXIDs
  `cf0db1ff…` deploy, `0aff3da5…` settle), but **bidding (PATH 5) and
  buy-fill (PATH 1/3, external position transfer) were explicitly out of
  scope for that smoke** and remain untested (`E2E_LIVE_RESULTS.md:737`,
  `SECURITY_FIXES.md:80-107`).
- **DCA multi-period** — known bytecode bug. Continuation fill
  (periods>1, the D&R/splice path) "has a known bytecode issue"; only the
  `periods=1` final-fill path is validated on testnet-10
  (`E2E_PLAYBOOK.md`, "Pattern 5: DCA Fill" note).
- **Stop / trailing-stop auto-broadcast-on-trigger** — never live-fired
  (deploy-only PASS exists in the superseded `E2E_MATRIX.md` P14-P16 rows;
  no trigger→broadcast TXID appears anywhere in `E2E_LIVE_RESULTS.md`) and
  two silent-death engine bugs are open, tracked in §4.

---

## 2. What ships / what's proven

Truncated TXIDs below; full IDs are in the cited source file. Statuses are
pulled verbatim from `E2E_LIVE_RESULTS.md` / `BATCH_LIMITS.md` — nothing
here is invented.

### 2a. Spot v18 core (15-form matrix — Stage F, 2026-07-17)

**Caveat (see §4 and `V18_DESIGN.md`'s updated banner): the LIMITS
re-freeze (`317f163c`, same day) changed the plain buy/sell bytecode
(RS 1720B→5655B / 515B→542B). This VOIDED the Stage-F proofs below for the
7 forms marked OWED RE-PROOF; the other 8 are unaffected (bytecode
unchanged) or independently re-proven in Stage-G / `BATCH_LIMITS.md`.**

| # | Form | Status vs. current bytecode | Evidence (TXID / note) |
|---|---|---|---|
| 1 | mint fresh A/B/C tokens | re-proven (unaffected) | various, `E2E_LIVE_RESULTS.md:331` |
| 2 | deploy every contract | re-proven for buy/sell (RS 5655B/542B confirmed live in the Stage-G re-proof, `E2E_LIVE_RESULTS.md:60`); Stage-F's own deploy proof (`:332`) used the now-stale RS 1720B/515B | `0e755001…` (Stage-G), `E2E_LIVE_RESULTS.md:332` (Stage-F, stale) |
| 3 | GTC N:M sweep | **re-proven** (Stage-G 1:1 re-proof + CP-1/CP-2 multi-sell + live N=8/N=32 sweeps) | `0e755001…` (`E2E_LIVE_RESULTS.md:60`), `405dbe39…`/`536047f3…` (`BATCH_LIMITS.md`) |
| 4 | IOC N:M sweep | **OWED RE-PROOF** (not exercised by any Stage-G form) | Stage-F only: `86f1363b…` (voided) |
| 5 | buy partial Op2 chain | **OWED RE-PROOF** (Stage-G tested `decay_buy`'s partial, not plain v18 buy's) | Stage-F only: `f1e52ddb…` et al. (voided) |
| 6 | sell partial (Fix-3) | **OWED RE-PROOF** | Stage-F only: `9eabee26…`, `d8bc05b1…` (voided) |
| 7a/7b | OCO swept, TP + SL branches | re-proven (OCO bytecode byte-identical, unaffected by `317f163c`) | `9cb0686e…` / `af85a538…` |
| 8 | cancel-mark → fill-reject → cancel | **OWED RE-PROOF** | Stage-F only: mark `87f7991e…`, cancel `a71e2265…` (voided) |
| 9 | expire seats (manual, buy+sell) | **OWED RE-PROOF** | Stage-F only: `41cb9d69…` / `f56e41f7…` (voided) |
| 10 | 2-cycle ring | re-proven (swap bytecode unchanged) | `2b2cdb55…` |
| 11 | 3-cycle triangle | re-proven (swap bytecode unchanged) | `8e51b36c…` |
| 12 | IFD soft path | **OWED RE-PROOF** (entry leg uses the changed plain-buy FILL bytecode; IFD-specific composition not retested) | Stage-F only: `72436538…` (voided) |
| 13 | bracket fill | re-proven (bracket bytecode unchanged) | `b112129d…` |
| 14 | delivery re-wrap (token_unit transfer) | re-proven (unaffected) | `c95e5707…` |
| 15 | engine auto-expire | **OWED RE-PROOF** (same EXPIRE branch as #9, automated path) | Stage-F only: `b8389a19…` (voided) |

The OWED RE-PROOF column (7 forms: #4, #5, #6, #8, #9, #12, #15) is this
doc's own derivation, cross-referencing `317f163c`'s stated scope ("plain
buy, plain sell, decay_buy, decay_sell, twap_sell, ratchet_oco" changed;
"swap/bracket/OCO/DCA remain byte-identical") against which Stage-G forms
actually exercised the changed bytecode — not copied verbatim from either
source doc. See `V18_DESIGN.md`'s updated banner for the same breakdown.

### 2b. Batch limits (current shipping `MAX_N=32`)

| Form | Status | Evidence |
|---|---|---|
| N=8 GTC sweep, current (post-`317f163c`) bytecode | LIVE | `405dbe39…`, node mass 12,225 (`BATCH_LIMITS.md`) |
| N=32 GTC sweep (full width) | LIVE | `536047f3…`, node mass 53,337 = exact lab prediction (`BATCH_LIMITS.md`) |
| N up to 60 (distinct)/81 (merged) under the 100k-gram cap; N=227 at the VM stack limit | offline-test-only (real `TxScriptEngine`, not live) | `BATCH_LIMITS.md` binary-searched ceilings |

### 2c. TIME_CONTRACTS (Stage-G, 2026-07-17/18)

| Form | Status | Evidence |
|---|---|---|
| decay_sell (DK-1, DK-3i/ii/iii honest fills) | LIVE | `1433dd79…`, `3a42f148…`, `377f3ee9…`, `8ed2fe16…` |
| decay_sell adversarial (DK-2 stale-price, DK-4 unix-ms) | LIVE-REJECTED (correct) | submit errors, `E2E_LIVE_RESULTS.md:35,39` |
| twap_sell (TW-1 window pair, TW-2 caps) | LIVE (accept + correct rejects) | `fd1c5ce3…`, `84688e42…`, `9ab1b48e…`, `e61843f3…` |
| Re-frozen six-contract re-proof: plain buy+sell 1:1 | LIVE | `0e755001…` |
| CP-1 (buy sweeps decay_sell + plain sell) | LIVE | `1a439c5d…` |
| CP-2 (buy sweeps twap_sell + plain sell) | LIVE | `5349126d…` |
| CP-4 / DB-1 (decay_buy settles plain sell) | LIVE | `42373b6a…` |
| DB-2 (decay_buy partial + residual) | LIVE | `bbd6825d…` |
| Owner caps (n_max reject / batch_max reject / in-bounds accept) | LIVE (2 correct rejects + 1 accept) | `E2E_LIVE_RESULTS.md:97-99`, accept `ac9eeaf0…` |
| ratchet_oco RT-1 (happy-path settle+advance) | LIVE | `5759da5e…` |
| ratchet_oco RT-2 (21-case adversarial set) | LIVE — 21/21 rejected, honest advance accepted ×2 | `4c017ea7…`, `9c413867…`; attribution caveat in §4 |
| ratchet_oco RT-3 (owner cancel of continuation) | LIVE | `956af539…` |
| CP-3 (buy sweeps ratchet TP branch) | LIVE | `10ff4610…` |
| Competing-matcher live race | LIVE — winner accepted, loser cleanly rejected as orphan double-spend | winner `d6cd4cff…` |

### 2d. Engine resilience (mainnet canary prep, 2026-07-18)

| Item | Status | Evidence |
|---|---|---|
| RPC reconnect: consecutive-timeout dead-marking + giveup-after-N (`exit(10)`) | code + unit-proven | `retry_config_default_has_reconnect_giveup_cap`; live-exercised against a real dead TCP endpoint in `cae349d9` |
| `--rescan-seed` startup order recovery | LIVE smoke | fresh engine recovered a real resting `ratchet_oco` (`ad0c2027…`) with 0 incorrect pruning, `E2E_LIVE_RESULTS.md:1369-1404` |
| KIP-10/Toccata activation status | confirmed via consensus gate, not blocking | mainnet active since DAA 474,165,565 (~2.5 weeks before this doc), `E2E_LIVE_RESULTS.md:1406-1430` |

### 2e. x402 (follow-on candidate, not in Stage-1 scope)

Native/KCC20/exact schemes live-confirmed; CASE R2 regression fixed and
live-verified (TXID `9d61a47c…`, `e2e_x402_exact.sh` 30/30)
(`E2E_LIVE_RESULTS.md:741,757,894-960`).

---

## 3. Owner judgment required (not an engineering task)

A mainnet canary deploy should get an external security audit or
bug-bounty pass before real funds are at stake — a product/business
decision for the owner, not something resolved in-repo
(`E2E_LIVE_RESULTS.md:1546-1549`).

---

## 4. Known open items tracked for the canary

- **Engine stop/trailing-stop silent-death bugs (two, deferred with
  scope, not fixed)** — independently verified against code (not
  previously written up in any `kob/*.md`): (a) stop orders: after
  `MAX_BROADCAST_RETRIES` is exhausted or a non-recoverable broadcast
  rejection occurs, `mark_triggered(id, None)` is still called
  (`kob/engine/src/chain/executor.rs:6526-6541`), which permanently
  excludes the order from `list_by_owner` and makes it uncancellable
  (`kob/domain/src/spot/stop_book.rs` tests `list_by_owner_excludes_triggered`
  and `cancel_triggered_order_fails`, both at lines 720-735) **even though
  no broadcast ever succeeded and no funds moved** — only a `warn!` log
  marks the failure. (b) trailing stops: `on_price_update`
  (`kob/domain/src/spot/trailing_stop.rs:503`) sets `order.triggered = true`
  in the domain layer *before* the executor attempts to broadcast, but the
  executor's trailing-stop broadcast branch
  (`kob/engine/src/chain/executor.rs:6558-6577`) has **no retry and no
  un-trigger on any failure path** (unlike the stop-order path's explicit
  retry-with-cap) — a single transient broadcast failure permanently drops
  the order from `list_for_pair` (filtered by `!o.triggered`,
  `trailing_stop.rs:603`) with zero funds moved and zero retry. Both match
  the "silent-death" characterization: an order the owner believes is live
  vanishes from the visible book without ever executing. Deferred along
  with the rest of stop/trailing-stop (§1); not fixed this pass.
- **Fee-reconciliation fixes owed a live re-smoke** — three same-shape
  Phase-2 fee bugs fixed this session (`6bae05c3` deploy leftover-into-
  covenant-output; `83d8293a` + `8ce15f89` Phase-1/Phase-2 fee gate in
  `match`/`match-batch`/engine settle; a 4th copy in kob-cli auto-match
  fixed in `73d3e330`) — all pass their unit/regression suites but have
  **not yet been re-run live on testnet-10** to confirm the fix against a
  real node (`E2E_LIVE_RESULTS.md`'s "New anomalies found during the race"
  items 1 and 3, annotated).
- **RT-2 per-case isolation re-fire** — the live 21/21 reject result is
  real, but for cases that corrupt the sibling's own shape (`l1`,
  `l2-*`, `l3`, `l4-*`), the shared genuine sibling's own covenant check
  also fails alongside the ratchet branch, so those rejects are not always
  cleanly isolated to "the ratchet branch specifically." A per-case-bespoke
  re-fire (dedicated sibling per case) would close this; not done this pass
  (`E2E_LIVE_RESULTS.md`, "Attribution caveat" section under "RT-2 — LANDED
  LIVE (2026-07-18)").
- **7 Stage-F forms owed re-proof against post-`317f163c` bytecode** —
  IOC N:M sweep, buy partial Op2 chain, sell partial (Fix-3), cancel-mark→
  fill-reject→cancel, expire seats (manual), IFD soft path, engine
  auto-expire. See §2a table and `V18_DESIGN.md`'s updated banner.

---

## 5. Recently fixed (this session)

- **Deploy sell mint-authority auto-pick** (commit `a5ecf8bc`) —
  `pick_sell_deployable_token_utxo_auto` previously could select a KCC20
  mint-authority UTXO over a fungible unit, silently consuming/locking
  minting into a sell covenant; now restricted to fungible candidates,
  errors with a `--token-utxo` hint instead. Found during the RT-2 live-fire
  session (`E2E_LIVE_RESULTS.md`, "Known issue found (NOT fixed, out of
  scope...)" section under "RT-2 — LANDED LIVE (2026-07-18)").
- **kob-cli auto-match revival = real sell version + Phase-2 fee**
  (commit `73d3e330`) — `submit_match` had hardcoded the sell
  `BatchOrder` to `version:14`; since the v18 consolidation (`23eb1edc`)
  domain gates `sell.version==18`, every non-dry-run auto-match failed
  with `UnsupportedVersion` before building a tx — **live matching via
  kob-cli auto-match was 100% dead** until this fix. The same function
  also carried the 4th copy of the Phase-2 fee-gate bug (see §4); both
  fixes were needed for auto-match to settle. `kob-cli` regression green;
  not yet live-re-smoked (see §4).

---

## 6. Pointers

- Detailed spot measurements: `kob/BATCH_LIMITS.md`
- TIME contracts design + verdicts: `kob/TIME_CONTRACTS_DESIGN.md`
- v18 generation freeze: `kob/V18_DESIGN.md`
- All live TXIDs, chronological: `kob/E2E_LIVE_RESULTS.md`
- Superseded (pre-v18) matrices, historical only: `kob/E2E_MATRIX.md`,
  `kob/E2E_PLAYBOOK.md`
