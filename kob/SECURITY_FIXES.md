# KOB Covenant Security Fixes — Phase 1 (release hardening)

Phase 1 of the 5-phase release-hardening sequence: fix the covenant
fund-theft holes found in the adversarial audit of the spot ORDER/TOKEN
covenants. Read-only audit findings are in the audit report; this file tracks
what was actually changed.

Verification: off-chain against the real post-Toccata `kaspa-txscript`
`TxScriptEngine` (`covenants_enabled = true`) via
`kob/core/tests/toccata_fill_repro.rs` (spot) and
`kob/core/tests/x402_borrow_covenant.rs` (x402). Every applied fix has an
adversarial test proving the specific theft tx now FAILS and the honest tx
still PASSES. `cargo test -p kob-core --lib` = 655 passed; the spot harness =
11 passed; the x402 harness = 6 passed; `kob-domain --lib` = 629;
`kob-x402 --lib` = 50 (wire_v2 schema conformance intact).

Phase 1a applied fixes 2/3/4/5/7; Phase 1b applied fixes 1/8 and refined the
analysis of fix 6 (see below).

Key primitive used throughout: **per-input output binding**. `OpCovOutputIdx`
(0xd3) returns the k-th covenant output for a token id across the WHOLE
transaction (a shared index — the root of the multi-party drains).
`OpAuthOutputIdx` (0xcc) / `OpOutputAuthorizingInput` (0xd6) bind an output to
the specific input that authorized it (`CovenantBinding.authorizing_input`);
each output has exactly one authorizing input, so two covenant inputs can
never share one output.

---

## APPLIED + VERIFIED

### Fix 2 — v14 buy has no on-chain surplus cap; was the CLI deploy default
- **Files**: `kob/cli/src/deploy.rs` (deploy_buy version gate),
  `kob/cli/src/lib.rs` (deploy-buy `--version` default 14 → 16).
- **What**: v14 buy removed F6 entirely ("Buy is protected by price check and
  covenant binding instead"), so nothing bounds a buyer's KAS outflow relative
  to tokens received — a matcher keeps the whole spread. v14 was the deploy
  default. New buy deploys are now rejected unless v16 (which has the working
  F6 cap). v14 build/parse retained for managing existing on-chain orders.
- **Impact**: no bytecode change; no RS-length/dispatch impact.

### Fix 3 — sell full-fill F4 used a transaction-wide shared covenant output
- **File**: `kob/core/src/contract/spot/order.rs` (`SELL_ORDER_BODY` fill F4).
- **What**: full-fill token conservation used `OpCovOutputIdx(T,0)` (shared
  output-0 for token T). Two sellers of the same token both checked that one
  output, so a matcher could deliver a single token output to satisfy both and
  drain the second seller's tokens out as KAS. Now uses
  `OpTxInputIndex Op0 OpAuthOutputIdx` (the 0th output THIS input authorized) +
  `OpOutputCovenantId == this token` + `OpTxOutputAmount >= token_in`.
- **Impact**: **length-neutral** (14B == old 14B, no NOP needed), so
  `SELL_ORDER_BODY` stays 304B, `SELL_RS_SIZE` stays 416B — no ripple to the
  hardcoded 416 constants or dispatch. Needs NO sigscript change, so the v16
  buy F6 fixed-offset reads of the sell sigscript are untouched. Updated the
  `SELL_ORDER` `bytecode_stable` pin.
- **Test**: `sell_f4_shared_output_drain_rejected_honest_passes` — 2 sellers,
  one shared token output; drained seller FAILS, honestly-delivered seller
  PASSES.

### Fix 4 — v16 buy F6 was blind to IOC partial delivery
- **File**: `kob/core/src/contract/spot/order.rs` (`BUY_ORDER_V16_BODY` fill F6).
- **What**: the IOC sub-dispatch (Op5) relaxes the buyer's token-output floor
  from `expected_tokens` to `mfill`, but F6 computed the surplus cap against
  the FULL hypothetical quantity (`kas_in * buy_price`). A matcher could
  consume the whole `kas_in` while delivering only `mfill` tokens, and F6 saw
  ~zero surplus. F6 now reads the ACTUAL delivered amount at `output[toi]`.
- **Impact**: **length-neutral** — 8-byte recompute replaced by
  `Op13 OpPick(toi) OpTxOutputAmount` (3B) + 5 `OpNop`, so RS length (476B)
  and the T0/T1/T2 dispatch thresholds are unchanged. No ripple.
- **Tests**: `v16_ioc_partial_delivery_theft_rejected_by_f6` (deliver only
  mfill, pocket 22M → aborts) and `v16_ioc_partial_delivery_within_cap_passes_f6`
  (same delivery within a widened cap → passes).

### Fix 5 — listing PATH 6 (settle) skimmed the accrued bid + 2 dead bugs
- **File**: `kob/core/src/listing.rs`.
- **What (security)**: PATH 6 (permissionless english-auction settle /
  collateral claim) checked only that `output[1]` went to the seller's address,
  not its value, so a settler could pay the seller dust and pocket the accrued
  bid (which accumulates in the listing UTXO's own value via PATH 5
  self-continuation). Added `output[1].value >= this UTXO's accrued value`.
- **Also fixed (pre-existing, contract was never engine-executed)**:
  1. expiry checks used opcode `0xba` (OpOutpointTxId) where they meant `0xb5`
     (OpTxLockTime) in PATH 1/3/5/6 — popped the expiry value as an input index
     and errored. Corrected all four.
  2. the `seller_spk_hash` comparison in PATH 1/3/6 picked `Op5` (raw
     seller_spk) instead of `Op6` (the hash, at depth 6 after the blake2b
     push); PATH 2 already had the correct `Op6`. Corrected all three.
- **Impact**: selector-dispatched (no length threshold); no external length
  hardcodes; `LISTING_BODY` not in the `bytecode_stable` pin set.
- **Tests**: `listing_settle_dust_skim_rejected` (pay dust → FAILS),
  `listing_settle_full_payment_passes` (pay accrued bid → PASSES).
- **Residual**: only PATH 6 (the security path) is engine-verified here.
  PATH 1/3 fills are corrected-by-construction but still need their own
  engine harness; the listing covenant as a whole warrants a full
  correctness+verification pass (it had never been executed on-chain).

### Fix 7 — cross-pair swap surplus was uncapped
- **File**: `kob/domain/src/spot/matching.rs` (`match_swap_routes`).
- **What**: computed `surplus = kas_available - kas_needed` with no cap, unlike
  the sibling KAS-book match fns. Added
  `.min(buy_source.max_matcher_fee).min(sell_target.max_matcher_fee)`.
- **Residual (noted in-code, honest)**: the cross-pair buy leg is v14-only
  (v16 is excluded from cross-pair swaps in `executor.rs` because F6's
  fixed-offset read needs buy and sell to share a token), and v14 has no
  on-chain surplus cap — so this planner cap is the ONLY bound on matcher take
  for this path. A matcher hand-building the tx is not additionally constrained
  on-chain. Fully closing it requires a cross-pair-capable capped buy contract
  (see Fix 1/6 coupling notes).

---

### Fix 1 — sell IOC (Op5) fill: free `fta`, no residual conservation  [Phase 1b]
- **File**: `kob/core/src/contract/spot/order.rs` (`SELL_ORDER_BODY` IOC path).
- **What**: IOC priced the fill from a free sigscript `fta` and its F4 was
  existence-only (`OpCovOutCount >= 1`), so the seller's whole `token_in` was
  consumed while only `fta` was priced and the `token_in - fta` residual could
  be drained out as KAS. F4 now forces the residual to return to THIS seller via
  a self-continuation output that is the input's 0th authorized covenant output:
  `OpTxInputIndex Op0 OpAuthOutputIdx` → r, `OpTxOutputSpk(r) == OpTxInputSpk`,
  `OpTxOutputAmount(r) >= token_in - fta`. Per-input (like Fix 3), so sellers
  can't share and the matcher can't skip the return.
- **Impact**: NO sigscript change → v16 F6's fixed-offset sell-price reads are
  untouched (RS start stays at the same prefix offset; PUSHDATA2 for both 416
  and 427). `SELL_ORDER_BODY` 304 → 315B, `SELL_RS_SIZE` 416 → 427B: updated
  parse/estimate constants, the RS-length asserts across
  recover/requote/matching/scanner/batch, and the `SELL_ORDER`
  `bytecode_stable` pin.
- **Tests**: `sell_ioc_residual_drain_rejected` (short residual, and residual
  not bound to this input, both FAIL) + `sell_ioc_honest_residual_passes`.
- **Residual (honest)**: the covenant is now safe-closed on-chain, but the
  batch/CLI match builders do not yet EMIT the residual self-continuation output
  for IOC-sell, so honest partial IOC-sell fills fail closed (no drain) until
  that builder wiring lands. Follow-on: make the match builders create the
  residual as the sell's 0th authorized output.

### Fix 8 — x402 additive borrow: aggregate-inputs drain  [Phase 1b]
- **File**: `kob/x402/src/reservation.rs` (+ harness
  `kob/core/tests/x402_borrow_covenant.rs`).
- **What (non-breaking mitigation, as directed)**: the covenant is unchanged;
  the drain needed two concurrent borrow UTXOs sharing one `merchant_spk_hash`
  so a single continuation output could satisfy both. `ReservationProvider` now
  tracks active `merchant_spk_hash`es and rejects any reservation that reuses
  one; `mark_consumed` frees the target (its UTXO is spent). Two live borrow
  UTXOs therefore always have distinct continuation targets, so one shared
  continuation output can satisfy at most one covenant.
- **Impact**: client/wire untouched (the client keys the continuation off
  `req.payTo`, so a fresh per-reservation merchant address flows through with no
  wire change); single-reservation E2E and the wire_v2 schema conformance are
  unaffected (kob-x402 lib 50/50).
- **Tests**: `rejects_duplicate_merchant_continuation_target` (reservation
  provider) + covenant harness `same_merchant_aggregate_shares_one_continuation`
  (documents the drain) and `distinct_merchant_aggregate_cannot_share_continuation`
  (distinct targets → the second covenant FAILS).
- **Residual (spec proposal)**: a merchant that insists on a single fixed
  continuation address for concurrent reservations is not covered by this
  provider-side guard. The complete fix is the covenant-output option: make the
  merchant continuation a covenant output (carrying `authorizing_input`), then
  require `OpOutputAuthorizingInput(cont_idx) == OpTxInputIndex` in
  `X402_BORROW_BODY`, and update `x402_client.rs` + facilitator. That changes
  the KIP-10 "additive exact" interop and must be agreed with the counterparty
  (elldeeone), so it is proposed here rather than applied unilaterally.

## NOT APPLIED — refined analysis

### Fix 6 — bracket buy entry surplus cap: does not fit the current bracket model
- **File**: `kob/core/src/contract/spot/bracket.rs` (`BRACKET_ORDER_BODY` buy
  entry).
- **Refined analysis (deeper than the original "medium" finding)**: the scoped
  fix — a v16-F6-style surplus cap plus an `mmfee_bps` state field — does not
  cleanly fit bracket, for two structural reasons found while implementing it:
  1. **No counterparty price to cap against.** The bracket entry fill layout
     (`cli/src/bracket.rs` doc: `input[0]=bracket, input[1]=P2PK funding,
     input[2]=receipt`) has NO resting counterparty sell-order input. The entry
     fills at the buyer's own `entry_price` against matcher inventory, so there
     is no fair/counterparty price for an F6-style cap to reference. The buyer
     is already protected at their limit by the existing `output[1].value >= et`
     (`et = kas * entry_price`) + SPK check — getting filled AT the limit is
     correct limit-order semantics, and the matcher's arbitrage-within-limit is
     not principal theft.
  2. **`output[1]` is value-based, not a token covenant.** The buy entry has no
     covenant-id check on `output[1]`, AND the honest builder
     (`cli/src/bracket.rs:645`) emits `output[1]` as a PLAIN output (`None`
     covenant) to a wallet SPK. Bracket's "tokens" are represented as sompi
     value, not a KCC20 covenant continuation. Adding either a token-covenant
     binding or a covenant-output surplus cap would break the honest flow and
     requires redefining bracket's entry token/matching model.
- **Why not applied**: both would require a redesign of bracket's (currently
  UNWIRED — see audit finding #9) entry-fill counterparty/token model, not a
  covenant patch. Forcing an `mmfee_bps` field + cap onto a value-based,
  counterparty-less, dead-code path would be unverifiable (no honest flow to
  test against) and could mask the deeper `output[1]` binding gap. Immediate
  exploit risk is gated: bracket batch-matching is unwired and fails closed.
- **Recommended slice (dedicated)**: define the bracket entry matching layout
  (which input is the priced counterparty; whether `output[1]` becomes a token
  covenant output); then bind `output[1]` to the token covenant (per-input,
  `OpAuthOutputIdx` like Fix 3) and add a surplus cap against the now-defined
  counterparty price, with the state-layout bump (224→232, RS 365→373, sigLen
  dispatch, parse, pin) and an engine harness. Treat as a bracket-hardening
  project, not a covenant one-liner.
