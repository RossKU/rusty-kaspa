# KOB v16 Buy Contract — Status

Tracks the v16 buy-contract implementation (fixes the v15 F6 cross-input
surplus-cap flaw). Updated as work proceeds; phases are checkpointed with
separate commits so the work is resumable after a crash.

---

## Phase 0 — Fix-shape determination

### The v15 flaw (as diagnosed before this work started)

v15's F6 (surplus cap) reads the counterparty sell order's price
(`sell_pnum`/`sell_pden`) via `OpTxInputScriptSigSubstr` at a tx-input index
`sii` that is a bare sigscript parameter — a number the party building the
spending transaction (the matcher) supplies directly, with **no on-chain
check that `sii` is the same input that was already covenant-verified as the
token input `tii`** (verified via `OpTxInputCovId(tii) == tcid`). A malicious
matcher can set `sii` to point at a self-controlled decoy input, whose
sigscript is crafted so the bytes at the expected offsets `[7..15)`/`[16..24)`
decode as a favorable (low) price, defeating the surplus cap while the real
trade still settles against the genuine, higher-price counterparty.

### Does the price data live on the input already covenant-verified as `tii`?

**Yes, for the FILL path — and it's even simpler for the PARTIAL path.**
Evidence gathered from the actual code (not just the diagnosis):

1. `kob/domain/src/spot/batch.rs` — every call site that builds a v15 buy
   sigscript passes `sii = *tii` (see `build_tx()`, the v15 fill / IOC-fill /
   partial-fill branches, ~L494-540): *"sii = sell input index (= tii, the
   sell carrying this buy's token covenant)"*. The honest matcher path never
   sets `sii` to anything other than `tii`. `sii` is a redundant, unauthenticated
   copy of a value the contract can already read straight from `tii` — because
   `tii` is exactly the tx-input index of the sell order UTXO whose sigscript
   contains that sell order's `pnum`/`pden` at the fixed offsets (the sell side
   already uses a fixed 2-byte `koi` push, `build_sell_fill_sigscript_v15`, so
   those offsets are stable). `OpTxInputCovId(tii) == tcid` already proves
   `tii` is a genuine covenant input for the traded token; there is nothing
   left to authenticate once `sii` is forced to equal `tii`.
2. `token_input_map` (`batch.rs` `build_token_input_map`, "First occurrence of
   each token wins") assigns exactly one `tii` per token for the whole batch —
   confirming `tii` is *the* authenticated carrier of that token's price data
   the buy contract is meant to read from.
3. **Fill path**: the F6 fix is "force `sii == tii`" — i.e. delete the `sii`
   sigscript parameter and have F6's `OpTxInputScriptSigSubstr` calls read the
   input index from the *already on-stack, already-verified* `tii` value
   (the same `Op10 OpPick(tii)` pattern the covenant check already uses)
   instead of a second, free `OpPick(sii)`.
4. **Partial path**: the existing v14/v15 partial-fill body does not even
   have a parameterized `tii` — its token-input covenant check is **hardcoded**
   to `Op1 OpTxInputCovId` (tx input index literal `1`; see the CLI's
   `partial_fill.rs` TX-layout doc comment: `input[0]=buy, input[1]=token,
   input[2]=fee`). So the correct fix there is even more direct: hardcode
   F6's substr-source index to the literal `1` too (matching what the
   covenant check already trusts), and drop `sii` entirely — no `OpPick`
   needed at all, since there is no stack value to authenticate against;
   the index itself is the constant the covenant check hardcodes.

Both cases reduce to the same principle: **the fix is "force `sii == tii`"**
(literal `tii` for fill/IOC-fill, literal constant `1` for partial, matching
each path's own pre-existing covenant-authenticated input). No new
authentication opcode sequence is needed (the "NO" branch in the task brief
does not apply) — this is the smallest, cheapest fix: it *removes* bytes
(no `sii` push, no second free `OpPick`) rather than adding a redeem-script
hash check.

### Unplanned discovery: version number 16 is already taken

`kob_core::contract::spot::bracket` ("bracket entry", trustless-bracket
orders) already reports `BatchOrder.version == 16` throughout the engine and
domain layers (`kob/engine/src/chain/executor.rs` — `buy_version`/`version`
assignment keyed off `rs.len() == BRACKET_RS_SIZE (365B)`; and
`kob/domain/src/spot/batch.rs:484` — `let is_bracket = buy.version == 16;`).
Bracket is a structurally unrelated contract (entry + auto-OCO-exit, receipt
consumption, hardcoded output indices) — nothing to do with the F6 fix.

This is a real collision risk: if the new fixed buy contract also reports
`.version == 16`, `batch.rs`'s `is_bracket` check (keyed off the bare version
number, not RS length) would misidentify it as a bracket entry and build the
wrong sigscript, corrupting the transaction.

**Resolution** (chosen so the contract can still be named/branded "v16" as
instructed, without colliding with bracket): make bracket detection in
`batch.rs` keyed off **RS length** (`BRACKET_RS_SIZE`, 365B) instead of the
bare version number — mirroring how `is_v15` is already computed
(`buy.redeem_script.len() == BUY_ORDER_V15_RS_EXPECTED_LEN`). Since the new
v16 buy RS (478B) is a different length from both bracket (365B) and v15
(479B), the collision is fully resolved: `BatchOrder.version == 16` can mean
either "bracket" or "buy v16 (F6 fix)" and the two are disambiguated by RS
length everywhere it matters for tx construction. `extract_bracket_meta()`
already internally guards on `rs.len() != BRACKET_RS_SIZE => None`, so it was
already safe to call (just wasteful) with a v16 buy RS.

### Fix-shape summary

| Path | v15 (flawed) | v16 (fixed) |
|------|--------------|-------------|
| Fill / IOC-fill | `sii` free sigscript param; `OpPick(sii)` reads substr source | `sii` removed; substr source read via `OpPick(tii)` (same value already used by the covenant check) |
| Partial-fill | `sii` free sigscript param; `OpPick(sii)` reads substr source | `sii` removed; substr source is hardcoded literal `1` (matches the pre-existing hardcoded `Op1 OpTxInputCovId` covenant check) |

---

## Phase 1 — v16 buy contract implementation

Status: **DONE**.

Files changed:
- `kob/core/src/contract/spot/order.rs` — added `BUY_ORDER_V16_BODY` (333B),
  `BUY_ORDER_V16_BODY_EXPECTED_LEN`, `BUY_ORDER_V16_RS_EXPECTED_LEN` (478B),
  `build_buy_v16_redeem_script`, `build_buy_v16_fill_sigscript`,
  `build_buy_v16_ioc_fill_sigscript`, `build_buy_v16_partial_fill_sigscript`.
  v14 (`BUY_ORDER_BODY`) and v15 (`BUY_ORDER_V15_BODY`) are untouched.
- `kob/core/src/contract/spot/parse.rs` — `parse_redeem_script` now also
  matches `BUY_ORDER_V16_RS_EXPECTED_LEN` and dispatches to `parse_buy_state`
  (state layout is byte-identical to v14/v15, 145B).
- `kob/domain/src/spot/batch.rs` — `is_bracket` now keyed off RS length
  (`BRACKET_RS_SIZE`) instead of `buy.version == 16` (see collision fix
  above); added `is_v16` (mirrors `is_v16`/`is_v15` pattern) so `build_tx()`
  picks the v16 fill / IOC-fill / partial-fill sigscript builders (no `sii`
  argument); `validate()` already accepted version 16 (now correctly shared
  between bracket and v16-buy, disambiguated by RS length at construction
  time).
- `kob/engine/src/chain/executor.rs` — the two `buy_version`/`version`
  RS-length dispatch sites now add a v16-buy-RS-length branch alongside the
  existing v15/bracket branches.

Dispatch thresholds (RS=478B): T0=484, T1=490, T2=497 (see Phase 3 for the
derivation and verification of these).

v14 stays canonical and fully intact. v15 stays exactly as it was (gated,
not deleted, not used by CLI) per instructions.

---

## Phase 2 — CLI wiring

Status: **DONE**.

| File | Change |
|------|--------|
| `cli/src/deploy.rs` | `deploy_buy` version gate accepts 14/16; branch to `build_buy_v16_redeem_script` (bps semantics, same as v15) when `version==16` |
| `cli/src/cancel.rs` | gate accepts 14/16; buy-side branch to `build_buy_v16_redeem_script` |
| `cli/src/cancel_mark.rs` | gate accepts 14/16; both `current_rs`/`target_rs` buy branches |
| `cli/src/requote.rs` | both gates (`new_params.version`, `old_version`) accept 14/16; both `old_redeem_script`/`new_redeem_script` buy branches |
| `cli/src/cancel_all.rs` | `build_redeem_script_for_order` gate accepts 14/16; buy branch |
| `cli/src/watch.rs` | `detect_fill_from_sigscript` recognizes `BUY_ORDER_V16_RS_EXPECTED_LEN` against `BUY_ORDER_V16_BODY` (mirrors the existing v14 check; v15 never had this) |
| `cli/src/recover.rs` | **no change needed** — RBF self-send is version-agnostic (doesn't reconstruct order redeem scripts at all) |

`max_matcher_fee`/`mmfee_bps` plumbing for v16 reuses the exact same fields
v15 already introduced (cache stores one `max_matcher_fee` u64 field
regardless of absolute-sompi-vs-bps semantics; `version==16` picks the bps
interpretation exactly like `version==15` does).

---

## Phase 3 — Bytecode trace

Status: see below (filled in as this phase completes).

---

## Phase 4 — Tests

Status: see below.

---

## Phase 5 — E2E (testnet-10)

Status: see below.
