# KOB Covenant Security Fixes — Phase 1 (release hardening)

Phase 1 of the 5-phase release-hardening sequence: fix the covenant
fund-theft holes found in the adversarial audit of the spot ORDER/TOKEN
covenants. Read-only audit findings are in the audit report; this file tracks
what was actually changed.

Verification: off-chain against the real post-Toccata `kaspa-txscript`
`TxScriptEngine` (`covenants_enabled = true`) via
`kob/core/tests/toccata_fill_repro.rs`. Every applied fix has an adversarial
test proving the specific theft tx now FAILS and the honest tx still PASSES.
`cargo test -p kob-core --lib` = 655 passed; the harness = 9 passed.

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

## NOT YET APPLIED — require coordinated multi-file changes (documented for a
## dedicated slice; not rushed because an unverified covenant edit can ship a
## worse bug than the known one)

### Fix 1 — sell IOC (Op5) fill: free `fta`, no residual conservation
- **File**: `kob/core/src/contract/spot/order.rs` (`SELL_ORDER_BODY` IOC path,
  ~L370), driven by `kob/domain/src/spot/batch.rs` (`has_remainder` → IOC).
- **The hole**: IOC prices the fill from a free sigscript `fta` never bounded
  by the real `OpTxInputAmount`, and its F4 is existence-only
  (`OpCovOutCount >= 1`, no amount). The seller's whole `token_in` is consumed,
  only `fta` is priced/delivered, and the residual `token_in - fta` is
  unconstrained — it can go out as KAS to the matcher.
- **Why deferred**: the correct fix (bind `fta`, force the residual back to the
  seller as a covenant output, like the PARTIAL path) is genuinely coupled:
  (a) adding a residual index to the IOC sigscript shifts the fixed-offset
  bytes that v16 buy F6 reads for IOC (`build_sell_ioc_fill_sigscript_fixed_offset`,
  pnum at [16..24), pden at [25..33)), so v16 F6 offsets must move in lockstep;
  (b) full residual conservation needs two per-input authorized outputs
  ([buyer fta, seller residual]) with a builder ordering convention; (c) the
  PARTIAL path (Op2) already conserves correctly, so the cleanest fix is to
  **route sell remainders to PARTIAL instead of IOC** in `batch.rs` and make
  IOC-sell full-delivery-only — a batch-builder + body change.
- **Recommended slice**: (1) `batch.rs`: route `has_remainder` sells to the
  Op2 PARTIAL path (which already forces `residual = token_in - fta` back via a
  self-continuation output and checks it); (2) tighten IOC-sell F4 to the
  per-input `OpAuthOutputIdx` binding used in Fix 3 so it can't share outputs
  either; (3) add an engine test: IOC/partial sell that pockets the residual
  FAILS, honest partial with residual returned PASSES.

### Fix 6 — bracket buy entry has no surplus cap (and no mmfee field)
- **File**: `kob/core/src/contract/spot/bracket.rs` (`BRACKET_ORDER_BODY` buy
  entry, ~L102).
- **The hole**: buy entry checks only `output[1] >= et` (token floor) + SPK;
  nothing bounds the buyer's KAS outflow, and the bracket state has NO `mmfee`
  field, so there is no v16-style cap available. Every bracket buy entry is
  exposed to unbounded matcher surplus capture.
- **Why deferred**: fixing it needs a new state field (`mmfee_bps`) →
  `BRACKET_STATE_SIZE` 224 → 232, `BRACKET_RS_SIZE` 365 → 373, the sigLen<400
  dispatch threshold, `parse_bracket_state`, every hardcoded bracket size, and
  the `BRACKET_ORDER` `bytecode_stable` pin — plus an F6-equivalent cap body
  reading the counterparty price. A state-layout + dispatch change that must be
  done and verified as its own slice.
- **Recommended slice**: add `mmfee_bps` to state; add a buy-entry surplus cap
  mirroring v16 F6 (surplus of `kas_in` over the fair token value ≤ cap); bump
  all size constants + dispatch + pin; add an engine test bracketing the cap.

### Fix 8 — x402 additive borrow: aggregate-inputs drain of concurrent reservations
- **File**: `kob/core/src/contract/x402_borrow.rs` (`X402_BORROW_BODY`).
- **The hole**: the borrow UTXO is spendable by anyone who produces a
  continuation output ≥ `min_continuation` to the merchant, at a free sigscript
  index `cont_idx`. Multiple concurrent borrow reservations (same merchant) can
  be spent in one tx all pointing `cont_idx` at ONE continuation output — each
  covenant passes, and the attacker pockets `(N-1) * min_continuation` of the
  merchant's locked funds.
- **Why deferred**: the per-input binding here is blocked by the wire scheme.
  The continuation is a PLAIN merchant payment (no `CovenantBinding`), so
  `OpOutputAuthorizingInput`/`OpAuthOutputIdx` can't bind it, and hardcoding
  `cont_idx == OpTxInputIndex(+k)` over-constrains the layout and would break
  the KIP-10 "additive exact" strict-interop scheme (elldeeone interop) which
  places the continuation at an arbitrary non-payment index
  (`kob/x402/src/scheme_exact.rs`). The safe fix requires a coordinated
  protocol decision: either make the continuation a covenant output (so it
  carries an authorizing input, then require
  `OpOutputAuthorizingInput(cont_idx) == OpTxInputIndex`) and update the client
  (`kob/x402/src/bin/x402_client.rs`) + facilitator, or mandate a
  covenant-computable continuation index. This must be agreed against the
  interop spec, not patched unilaterally.
- **Recommended slice**: decide with the interop counterparty whether the
  continuation becomes a covenant output; then add the per-input binding +
  update the client/facilitator + add the drain/honest engine tests in
  `kob/core/tests/x402_borrow_covenant.rs`.
