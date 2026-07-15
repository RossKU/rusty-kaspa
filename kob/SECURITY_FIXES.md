# KOB Security Fixes — release hardening (Phases 1-3)

5-phase release-hardening sequence. Phase 1: covenant fund-theft holes found
in the adversarial audit of the spot ORDER/TOKEN covenants. Phase 2: x402
facilitator hardening. Phase 3: a DoS byte-slice panic class in RPC/JSON
parsing. Read-only audit findings are in the audit report; this file tracks
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

---

# Phase 2 — x402 facilitator hardening

`kob/x402/src/facilitator.rs` (+ `scheme_exact.rs`). Fixes 1 and 3 (exact
verifies against the stored reservation; requestHash threaded) landed first
(commits `66e0ef0`, `7e81003`). This section covers Fix 2 and Fix 4.

Verification: off-chain, `cargo test -p kob-x402 --lib` = 59 passed (0
failed) — up from 54 (Fix 3) + the Fix-4 alignment test. `wire_v2` schema
conformance (6 tests) untouched and still green. `cargo test -p kob-settle
--lib` = 216 passed, unaffected by this phase's edits.

### Fix 2 — cross-resource replay: a settled artifact was replayable against a different request
- **File**: `kob/x402/src/facilitator.rs` (+ `scheme_exact.rs` call site).
- **What**: the facilitator's internal `Validated` carried no per-request
  binding. On a `DuplicateTxid` replay-store hit (the SAME signed artifact
  presented again), `/settle` returned the cached success unconditionally —
  it never checked that this SECOND presentation was still authorizing the
  SAME request/resource the artifact was originally settled for. Two
  compounding gaps made this reachable:
  1. Request-binding (`extra.fingerprint` for native/KCC20, `requestHash` for
     exact/KIP-10) was OPTIONAL. A merchant/reservation that never set one
     produced artifacts with no per-request scope at all.
  2. For exact/KIP-10, `requestHash` lives in the wire payload, not in the
     hashed transaction bytes (`artifact_id = blake2b256(compact_json(tx))`),
     so it was never pinned to a specific artifact in the first place —
     unlike native/KCC20, where the fingerprint is embedded IN the tx payload
     and therefore baked into `artifact_id` once mandatory (see below).
- **Fix**:
  - Added `Validated.binding_fingerprint: String` (mandatory, non-`Option`),
    set per scheme: `extra.fingerprint` for native/KCC20, the reservation's
    bound `request_hash` for exact/KIP-10.
  - Request-binding is now MANDATORY for all three schemes: `validate()`
    rejects (`invalid_payload`) a native/KCC20 request with no
    `extra.fingerprint`, and an exact/KIP-10 reservation with no bound
    `request_hash`, before ever reaching scheme verification.
  - New helper `duplicate_binding_matches(store, artifact_id,
    binding_fingerprint)`: on a `DuplicateTxid` hit, the stored
    `PaymentRecord.fingerprint` must equal THIS request's
    `binding_fingerprint`, or the call is refused
    (`invalid_transaction_state`) — applied in both `/verify` and `/settle`
    (including the not-yet-broadcast retry sub-case, so a mismatch can't
    silently overwrite the original record's binding either).
  - `settle()`'s replay-store record now always stores
    `binding_fingerprint` (previously `req.payment_requirements.fingerprint()`,
    which is always `None` for exact — so exact-scheme settlements
    previously recorded NO binding at all).
- **Tests**: `rejects_missing_fingerprint_binding` /
  `kcc20_rejects_missing_fingerprint_binding` /
  `exact_kip10_rejects_reservation_with_no_bound_request_hash` (mandatory
  binding enforced per scheme); `settle_refuses_duplicate_artifact_bound_to_a_different_request`
  — settles an artifact, then tampers the stored replay record's fingerprint
  to simulate it having been bound to a different request, and proves a
  re-presentation of the SAME artifact (still bound to the original request)
  is now refused at both `/verify` and `/settle`, with no re-broadcast.
- **Residual (honest)**: for native/KCC20, once the fingerprint is mandatory
  and scheme-checked against the embedded tx payload, the `DuplicateTxid`
  binding mismatch can no longer occur through the ordinary validate() path
  (the embedded value is fixed once signed, so any request that re-validates
  the identical artifact must supply the same fingerprint) — the check is
  defense-in-depth there. For exact/KIP-10 it is load-bearing, since
  `requestHash` is NOT part of the hashed artifact. `kob-x402`'s live E2E
  client (`x402_client.rs`) currently omits `requestHash`/`fingerprint` for
  its KCC20 mode and for some exact-scheme reservations — a live re-run of
  `e2e_x402_kcc20.sh` / `e2e_x402_exact.sh` would now fail at the mandatory
  check until the client is updated to always supply one. Not done here
  (off-chain unit tests only, per scope); flagged for the live-E2E follow-up.
  Separately (found, not in scope to fix): `ReservationProvider::mark_consumed`
  is never called from `facilitator.rs`, so `BorrowTerms.consumed` never
  flips — reservations rely entirely on the on-chain spent-outpoint check and
  the replay store for reuse protection, not the `consumed` flag.

### Fix 4 — reject-code mapping was inconsistent across schemes (and used wildcard arms)
- **File**: `kob/x402/src/facilitator.rs` (`native_reject_code`,
  `kcc20_reject_code`, `exact_reject_code`).
- **What**: the three `*_reject_code` functions mapped the same logical
  failure (a missing/mismatched request binding) to different wire codes —
  exact used `invalid_transaction_state`, native/KCC20 fell through a
  wildcard `_ =>` arm to `invalid_payload`. The wildcard arms also meant a
  new reject variant would silently get miscategorized instead of failing to
  compile.
- **Fix**: aligned all three to ONE mapping table (documented in-code):
  payment doesn't satisfy the offer -> `invalid_payment_requirements`;
  request binding missing/mismatched -> `invalid_payload`; spent/stale
  on-chain outpoint -> `invalid_transaction_state`; otherwise malformed ->
  `invalid_payload`. All wildcard `_ =>` arms replaced with exhaustive
  explicit arms (compiler-enforced: a new reject variant now fails to build
  until it's classified).
- **Test**: `reject_codes_align_request_binding_across_schemes` — the same
  logical failure (`FingerprintMismatch`/`FingerprintMissing` per scheme)
  maps to the identical wire code across all three `*_reject_code` functions.

---

# Phase 3 — DoS: byte-slice panic on malformed scriptPublicKey (4+1 sites)

One panic class, reachable from untrusted client JSON and node RPC data:
`flat.len() >= 4` measures BYTE length, but `&flat[..4]` / `&flat[4..]` slice
Rust `str`s at a BYTE index. Rust panics if that index doesn't land on a
UTF-8 char boundary — which a multibyte character straddling offset 4 can
trigger even when the byte-length guard passes. A single malformed
`scriptPublicKey` string (e.g. from a hostile/buggy node response, or
attacker-controlled JSON reaching these parsers) crashes the process.

- **Files fixed** (the 4 flagged sites, plus a 5th identical-pattern
  occurrence found in the same sweep):
  1. `kob/settle/src/observe/mod.rs` (`ObservedOutput::from_rpc_json`)
  2. `kob/settle/src/rpc_types.rs` (`RpcSpk`'s `visit_str` deserializer)
  3. `kob/settle/src/rpc_types.rs` (`parse_rest_spk`, same pattern, not
     originally flagged — fixed in the same pass since the shared helper
     lives in this file)
  4. `kob/settle/src/rpc/rest_client.rs` (`translate_wrpc_tx_to_rest`)
  5. `kob/engine/src/chain/scanner.rs` (`TransactionData::from_rpc_json`)
- **Fix**: added a shared helper, `kob_settle::rpc_types::split_flat_spk_hex(s:
  &str) -> Option<(&str, &str)>` — `Some((s.get(..4)?, s.get(4..)?))`.
  `str::get` is the checked, non-panicking equivalent of indexing: it returns
  `None` on an out-of-bounds OR non-boundary index, so it can never panic
  regardless of input. All 5 sites now go through it; `None` falls back to
  the SAME degrade path each site already had for an under-length string
  (version 0, whole string treated as script hex) instead of panicking.
  `kob/engine/src/chain/scanner.rs` (a different crate) calls it via the
  existing `kob_core::rpc_types` re-export, no new dependency.
- **Tests**: one regression test per site (`split_flat_spk_hex` itself, the
  `RpcSpk` deserializer, `parse_rest_spk`, `translate_wrpc_tx_to_rest`,
  `ObservedOutput::from_rpc_json`, and `TransactionData::from_rpc_json`),
  each feeding a string with a multibyte UTF-8 character (`'\u{20AC}'`, 3
  bytes) straddling byte offset 4 — the exact shape that previously panicked
  — and asserting a clean `None`/`Err`/graceful-degrade result instead.
- **Verified**: `cargo test -p kob-settle --lib` = 216 passed (0 failed),
  covers sites 1-4. `cargo check -p kob-engine` (non-test) is clean for site
  5's actual fix. `cargo test -p kob-engine --lib`/`--tests` currently fails
  to even COMPILE for reasons unrelated to this fix or to `scanner.rs`: the
  legacy inline test module in `kob/engine/src/chain/executor.rs` calls a
  `SpentTracker::prune_spent_by_age` method that no longer exists post-Phase-1
  extraction (the real method is `prune_spent`) and a `prune_spent_with_probe`
  that is `pub(crate)` in `kob-settle` (not visible from `kob-engine`).
  Confirmed pre-existing via `git stash` on a clean checkout — present before
  any Phase 2/3 edit in this pass, unrelated to `scanner.rs`. Out of scope
  here; flagged as a residual (kob-engine's lib test suite cannot currently
  run at all until that's fixed).
