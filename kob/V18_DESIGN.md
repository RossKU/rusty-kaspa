# V18 DESIGN FREEZE — single-generation spot, delete v14/v16/v17

Status: frozen 2026-07-16. Stages A–E DONE (2026-07-17). Unreleased chain
state → no migration.

Stage E (deletion + rename) landed in three commits:
- **E1** expire-seat covenant fix: buy state 145B→178B (owner KAS seat
  `okspkh`, EXPIRE refunds there); sell 112B→145B and OCO 139B→172B (owner
  token seat `otspkh`, EXPIRE refunds a covenant-bound token_unit via the
  Fix-3 per-input binding). RS lengths buy 1720 / sell 515 / OCO 397.
- **E2** delete all pre-v18 generations (v14/v16/v17 spot, v1 OCO/swap/
  bracket, the KAS-bridged swap route, the 7B ownerless TOKEN_RS).
- **E3** rename v18 → plain: the `_v18`/`_V18` suffixes are gone; a single
  `pub const SPOT_GENERATION: u32 = 18` (in `contract/spot/mod.rs`) is the
  only place the number 18 lives. The `version` u8 fields still REPORT 18
  (engine/API consumers) via that const; on-chain dispatch is by RS length.

Only Stage F (fresh live smoke on the renamed binary) remains.

## Goals
1. One spot contract generation (v18) covering everything the matrix needs: N:M GTC/IOC sweep, buy partial-fill (old item C), OCO sweep-eligible (old OCO-SL blocker), token↔token ring settle incl. triangle (old item F, closes Fix-7 locally).
2. After live E2E green on testnet-10: delete all v14/v16/v17 spot code, planners, CLI gates, tests. v18 becomes the only generation; drop `_v18` suffixes at the end (plain names + one `SPOT_GENERATION = 18` const).
3. Item D (multi-buy) stays fail-closed **by proof**: delivery outputs must carry the token's CovenantBinding whose `authorizing_input` is a tcid input (engine model, covenants.rs), so they can never be bound to a buy input → cross-buy disjointness is unprovable on-chain. Pin with `test_v18_multi_buy_rejected` + doc note.

## Canonical price attestation (all sweep-eligible sell-side fill sigscripts)
Byte layout, fixed for plain sell fill, sell IOC, OCO TP, OCO SL:

```
[0x01, koi]  [0x08, pnum(8LE)]  [0x08, pden(8LE)]  [selector push]  [RS pushdata]  [branch extras (fta etc.) AFTER RS]
 offsets 0-1   2, 3..11           11? no: 12..20 — see below
```

Precisely: pnum bytes at sigscript **[3..11)**, pden at **[12..20)**. `koi` always a forced 2-byte push. Branch-specific extras (e.g. `fta`) go after the RS push so the prefix offsets never move.

**Covenant obligation**: every fill-family branch verifies the attested `(pnum, pden)` equals the *executing branch's* state fields — plain sell: `pnum/pden`; OCO TP: `pnum_tp/pden_tp`; OCO SL: `pnum_sl/pden_sl`. Buys read counterparty price ONLY at [3..11)/[12..20) via `OpTxInputScriptSigSubstr` on the covenant-authenticated `tii` (sii-safe: index authenticated by `OpInputCovenantId(tii)==tcid` first). This kills the OCO-SL fixed-offset mismatch and unifies all reads.

Delete the non-fixed-offset sigscript builders; the canonical layout is the only layout.

## Buy v18 — state 145B unchanged, selector dispatch (depth 9, v17 style)
Selectors: 0=CANCEL, 1=FILL(GTC full), 2=PARTIAL-FILL (new), 3=CANCEL-MARK, 4=EXPIRE, 5=IOC.

FILL/IOC: carry v17 `emit_fill_body` semantics unchanged (MAX_N=8, strict-increasing tii chain, per-sell delivery `OpAuthOutputIdx(tii_i,0)`, `OpInputCovenantId(tii_i)==tcid`, `blake2b(outSpk)==bspkh`, PASS1 token_sum, PASS2 fair_sum, GTC floor `token_sum >= kas_in/pden*pnum`, IOC floor `token_sum >= mfill`, cap `(kas_in - fair_sum) <= kas_in/10000*mmfee_bps`) — except price reads move to the canonical offsets above. Note sweep is structurally full-fill-only: a partial/IOC sell's auth slot 0 is its residual (self-SPK) and fails the buyer-SPK check, so no extra selector byte check is needed.

NEW Op2 PARTIAL-FILL (item C):
- Sigscript adds residual output index `ri` (before selector? — keep buy sigscript layout free; buys are never read by others at fixed offsets).
- Residual: `OpTxOutputSpk(ri) == OpTxInputSpk(self)` **byte-exact** (same RS ⇒ same 145B state carried; remaining size lives in the UTXO amount), `residual = OpTxOutputAmount(ri) >= 1`. Residual output carries NO covenant binding (plain KAS P2SH).
- Accounting on the spent portion only: `spent = kas_in - residual`; floor `token_sum >= spent/pden*pnum` AND `token_sum >= mfill` (per-event, blocks dust-grind); cap `(spent - fair_sum) <= spent/10000*mmfee_bps` (proportional ⇒ splitting one fill into k partials cannot increase total extraction).
- **Self-instance uniqueness guard**: require exactly one tx input whose SPK == own SPK. Unrolled loop i=0..15 gated by `i < OpTxInputCount`, count `OpTxInputSpk(i)==mySpk`, require count==1, and require `OpTxInputCount <= 16`. (Blocks two identical-RS buy UTXOs sharing one residual output — the non-covenant continuation hazard; buys carry no covenant id so Fix-3 auth binding is unavailable.)
- F5 `cpend==0` enforced (no partial on cancel-pending). Op2 requires residual>=1; residual==0 must use selector 1/5 (branch mutual exclusion).

## Sell v18 — state 112B unchanged
- Fill-family branches add the attestation check (`attested == state pnum/pden`).
- PARTIAL F4 upgraded from count-only (`OpCovOutCount>=2`) to Fix-3: `OpTxInputIndex Op0 OpAuthOutputIdx` → residual token output, `spk == OpTxInputSpk(self)`, `value >= token_in - fta`. (IOC already Fix-3; this closes the last shared-count wart.)
- KAS leg unchanged: sigscript `koi` + `blake2b(spk)==sspkh` + amount floor. mmfee is BPS uniformly (v14 absolute-sompi semantics dies with v14).

## OCO v18 — state 139B unchanged
- TP/SL branches use canonical attestation; body verifies attested == active branch's pair. This removes the sweep blocker: delete `OcoMultiSellSweepUnsupported` and the stale "pre-Fix-3 F4" comments (`batch.rs:293`, `matching.rs:468`); OCO sells become sweep-eligible on both branches. `OcoRemainderUnsupported` (no OCO partial) stays, documented.

## Swap v18 — ring legs (cross-pair + triangle), closes Fix-7 locally
State: current 174B + `mmfee_bps` 8B. All-or-nothing legs only (no ring partial — documented limitation + pin test).
- F2 target floor `output[toi].value >= min_target`, F3 `blake2b(spk[toi]) == owner_spk_hash` — kept.
- F5 replaced: `toi == OpAuthOutputIdx(giver_idx, 0)` where `giver_idx` is sigscript-supplied and authenticated by `OpInputCovenantId(giver_idx) == target_tcid` (sii-safe; replaces the colliding global `OpCovOutputIdx(target,0)` read).
- F4 replaced (conservation cap): own source delivery = `OpTxInputIndex Op0 OpAuthOutputIdx` (slot 0), `value >= source_in - source_in/10000*mmfee_bps`. Receiver pins slot 0 by SPK/floor (its F5/F3/F2); giver pins slot-0 value; matcher skim is capped and can only sit at slots >= 1. Both ends of every edge are pinned ⇒ ring is safe with purely local checks; the ring spread beyond per-leg mmfee is unreachable.
- Old KAS-bridged `execute_swap_fill` (swap+sell+v14 buy) dies with v14. Token↔KAS = normal spot; token↔token = 2-cycle; triangle = 3-cycle. `RING_MAX = 3` for now.
- Planner `plan_ring_match` (2..=3 legs, all-or-nothing, per-leg floor + cap feasibility), executor `execute_ring_fill`, CLI wiring.

## Version model
`parse_redeem_script` dispatches on v18 RS lengths (+ bracket 365 + token/perp untouched); `version` u8 reports 18. Deploy paths bail on anything non-v18. After deletion stage, drop `_v18` suffixes → plain names, single `SPOT_GENERATION` const.

## IFD / IFO — MANDATORY (added 2026-07-16, MK directive)
IFD (if-done) and IFO (IFD-OCO) are release-required, not optional. Port to v18: entry leg = v18 buy/sell; on-fill the done-leg order (plain sell for IFD, OCO sell for IFO) must be emitted with v18 RS. If the existing ifd.rs/bracket mechanism needs a core-side v18 bracket contract, build it (same canonical attestation rules). Done-leg orders are ordinary v18 sells/OCOs ⇒ automatically sweep/batch-eligible.

Note (supersedes any trigger language): KOB has no market-price concept — consistency comes from arbitrage only. OCO SL is simply the alternative limit price; the covenant guarantees execution price, branch selection belongs to matchers/arbitrage. No trigger semantics exist or are needed on-chain.

## Stages (each ends: build green → commit, RossKU style, no AI mentions)
- **A core**: order.rs buy/sell v18, oco.rs v18, swap.rs v18, parse.rs v18 arm, adversarial tests (port NM_BUY_DESIGN Sec 6 + new: residual-SPK forgery incl. same-RS dual-buy, attestation mismatch TP/SL/plain, decoy giver_idx, ring slot-0 theft, partial grind arithmetic, mfill boundaries, Op2/Op5 confusion, cpend-partial reject, uniqueness-guard bounds at 16 inputs).
- **B domain**: planners v18 (batch GTC/IOC, sell-IOC parity, partial planning, plan_ring_match), D pin test, build_tx sigscript emission on canonical layout.
- **C engine+cli**: executor/scanner/deploy/api on v18, execute_ring_fill, CLI subcommands, remove version branching (bail non-v18).
- **D live E2E** (testnet-10, node ws://65.108.107.30:18210, REST api-tn10.kaspa.org): fund via kob-miner if needed; mint 3 tokens (SPA/SPB/SPC pattern); matrix = GTC N:M, IOC N:M, buy partial multi-event, sell partial Fix-3, OCO swept on TP and on SL, cancel-mark→fill-reject→cancel, expire, 2-cycle ring, 3-cycle triangle; record TXIDs (is_accepted) in E2E_LIVE_RESULTS.md.
- **E deletion**: remove v14/v16/v17 bodies/builders/consts/planners/gates/tests per the recon inventory (core ~283 / domain ~238 / engine ~60 / cli ~176 sites), rename v18→plain, docs updated (legacy *.md kept as history, marked superseded), full regression.
- **F final**: fresh live smoke on the renamed binary + final matrix report (implemented vs documented-limitation per form).

## Build env (this machine)
Termux cargo 1.94.1; `CARGO_TARGET_DIR=/root/kob-rust-target4` (exec-capable rootfs; /storage is noexec). Per-crate commands only (`cargo test -p kob-core -p kob-domain -p kob-engine -p kob-cli`), never bare `cargo build`. Release binaries for E2E from the same target dir.
