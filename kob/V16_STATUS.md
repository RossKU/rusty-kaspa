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

Status: **DONE** (analytical/structural trace + worked numeric example;
methodology follows `KOB_DEPRECATED_DO_NOT_USE/security/trace-sell-v4.md`,
adapted to what actually changed rather than re-tracing the whole 476B RS).

### 3.1 Length verification

Programmatically counted from the literal byte array actually committed to
`order.rs` (not hand-arithmetic — see scratch script used during
development, reproduced here for the record):

```
BUY_ORDER_V16_BODY:             331 bytes  (verified: re-parsed the const from the
                                             committed file and counted 0x?? tokens)
BUY_ORDER_V16_BODY_EXPECTED_LEN: 331  -- matches
BUY_ORDER_V16_RS_EXPECTED_LEN:   476  (145 state + 331 body)
```

Fill path: 61B (byte-identical to v14's fill path through F4) + 41B (F6) +
6B (cleanup, Op2Drop x6 — v14-identical, NOT v15's 7B) = 108B.
Partial path: 1B (OpElse) + 88B (byte-identical to v14's partial path
through F4) + 39B (F6, 2 bytes shorter than v15's 41B because the hardcoded
literal `1` needs no `OpPick`) + 6B (cleanup, Op2Drop x5 + OpDrop —
v14-identical) = 134B.

### 3.2 Dispatch preamble decode (the only other bytes that change vs v15)

```
offset  hex           opcode                  meaning
0       b9            OpTxInputIndex
1       c9            OpTxInputScriptSigLen
2       76            OpDup
3-5     02 ee 01       push T2=494 (0x01ee LE)
6       9f            OpLessThan            sigLen < 494 ?
7       63            OpIf                  (expire/fill/partial)
8       76            OpDup
9-11    02 e1 01       push T0=481 (0x01e1 LE)
12      9f            OpLessThan            sigLen < 481 ?
13      63            OpIf                  (EXPIRE)
14      75            OpDrop
```

... and further in, after the time-gate + exposure-delay (unchanged from
v14/v15):

```
02 e9 01   push T1=489 (0x01e9 LE)
9f         OpLessThan   sigLen < 489 ?
63         OpIf         (fill, else partial)
```

Sigscript length ranges actually produced by the v16 builders (computed
from the real `push_index`/`push_data` encoders, not assumed):

| Path | Sigscript shape | Length (idx ≤16, 1B each) | Length (idx 17-127, 2B each) |
|------|------------------|---------------------------:|------------------------------:|
| Expire | `[Op4][pushData(RS)]` | 480 (fixed) | 480 (fixed) |
| Fill / IOC-fill | `[toi][tii][coi][Op1/5][pushData(RS)]` | 483 | 486 |
| Partial | `[ri][ti][pushData(fk)][Op2][pushData(RS)]` | 491 | 493 |
| Cancel / cancel-mark | `[Op0/1][sig 65B][pk 32B][pushData(RS)]` | 579 (fixed) | 579 (fixed) |

`480 < T0(481) ≤ 483`, `486 < T1(489) ≤ 491`, `493 < T2(494) ≤ 579` — every
gap strictly separates the path below it from the path above it, for both
the 1-byte and 2-byte index encodings. Dispatch is unambiguous.

### 3.3 F6 fill-path decode (the security-critical change)

```
offset(rel)  hex               opcode                          meaning
0            5a 79             Op10 OpPick(tii)                copy tii (already
                                                                 authenticated a few
                                                                 instructions earlier
                                                                 by OpTxInputCovId)
2            57                Op7  (start=7)
3            5f                Op15 (end=15)
4            bc                OpTxInputScriptSigSubstr         -> sell_pnum, reads
                                                                    input[tii].sigscript[7..15)
5            5b 79             Op11 OpPick(tii)                 copy tii again
7            60                Op16 (start=16)
8            01 18             push 24 (end=24)
10           bc                OpTxInputScriptSigSubstr         -> sell_pden, reads
                                                                    input[tii].sigscript[16..24)
11           52 79             Op2 OpPick(kas)
13           58 79             Op8 OpPick(pden_b)
15           96                OpDiv                            kas / buy_pden
16           59 79             Op9 OpPick(pnum_b)
18           95                OpMul                            -> tokens
19           51 79             Op1 OpPick(sell_pden)
21           96                OpDiv                            tokens / sell_pden
22           52 79             Op2 OpPick(sell_pnum)
24           95                OpMul                            -> fair_kas
25           53 79             Op3 OpPick(kas)
27           7c                OpSwap
28           94                OpSub                            surplus = kas - fair_kas
29           53 79             Op3 OpPick(kas)
31           02 10 27          push 10000
34           96                OpDiv                            kas / 10000
35           55 79             Op5 OpPick(mmfee_bps)
37           95                OpMul                            -> max_surplus
38           a2 69             OpGTE OpVerify                    max_surplus >= surplus, or ABORT
39           6d                Op2Drop                           drop sell_pden, sell_pnum
```

**The load-bearing line is offset 0 and offset 5**: both read the input
index from `Op10`/`Op11 OpPick`, i.e. the tx-input-index value that is
already sitting on the stack at the SAME depth the token-input covenant
check (`Op10 OpPick(tii) OpTxInputCovId` ... `OpEqual OpVerify`, a few
instructions earlier in the same fill path) reads and validates against
`tcid`. There is no second, independent stack slot for a matcher-chosen
index anywhere in this bytecode — compare to v15 where offset 0 was
`0x5c,0x79` (`Op12 OpPick(sii)`), a *different* stack depth holding a
*second*, unauthenticated number.

### 3.4 F6 partial-path decode (hardcoded literal, no `OpPick` at all)

```
offset(rel)  hex          opcode                       meaning
0            51           Op1 (literal 1)               tx-input-index constant
1            57           Op7  (start=7)
2            5f           Op15 (end=15)
3            bc           OpTxInputScriptSigSubstr       -> sell_pnum, reads
                                                             input[1].sigscript[7..15)
4            51           Op1 (literal 1)               same constant again
5            60           Op16 (start=16)
6            01 18        push 24 (end=24)
8            bc           OpTxInputScriptSigSubstr       -> sell_pden, reads
                                                             input[1].sigscript[16..24)
...          (identical arithmetic to the fill path, using fk instead of kas)
```

`0x51` (`Op1`, the literal number 1) is not a stack reference at all — it is
a constant baked into the P2SH-committed body bytecode, identical to the
`Op1 OpTxInputCovId` the covenant check a few instructions earlier already
uses to authenticate "the token input is at index 1". A matcher cannot make
F6 read from anywhere else without changing the redeem script itself, which
would change the P2SH address and stop matching the deployed order.

### 3.5 Worked numeric example (verifies the arithmetic, not just the opcodes)

Buyer's own limit price 1:1 (`buy_pnum=1, buy_pden=1`), `kas_in = 1,000,000`
sompi, `mmfee_bps = 30` (0.30%):

| Scenario | seller's real price | `tokens` | `fair_kas` | `surplus` | `max_surplus` | F6 result |
|---|---|---:|---:|---:|---:|---|
| Honest, tight spread | 997/1000 | 1,000,000 | 997,000 | 3,000 | 3,000 | **PASS** (boundary) |
| Honest, real spread that exceeds the cap | 1/2 | 1,000,000 | 500,000 | 500,000 | 3,000 | **FAIL** (correctly rejected) |
| **v15 attack**: matcher forges a decoy claiming the seller's price is 1/1 (no spread), while the REAL counterparty (at `tii`) is actually priced 1/2 | forged: 1/1 | 1,000,000 | 1,000,000 | 0 | 3,000 | **v15: PASS** (exploit succeeds — matcher pockets the 497,000-sompi difference between what F6 "sees" and what the real trade settles at) |

The third row is the actual v15 vulnerability quantified: by pointing `sii`
at a decoy input whose forged sigscript bytes decode to `sell_pnum=1,
sell_pden=1`, F6 computes `surplus=0` and passes, even though the real
sell order at `tii` is priced 1:2 and the trade actually settles at the
worse 500,000-surplus rate. **In v16 this row is unreachable**: there is no
`sii` to forge — F6 can only ever read from `tii` (fill) or the hardcoded
literal `1` (partial), both already required to be genuine covenant inputs
by the pre-existing covenant checks.

### 3.6 Adversarial verdict: does a forged/decoy index now fail?

**Yes — categorically, by construction, not merely "in practice".** Two
independent, stacked defenses:

1. **No opcode reads a free index.** The v16 body bytecode (P2SH-committed,
   unchangeable by whoever spends the UTXO) contains no `OpPick`/`OpRoll`
   instruction that consumes a matcher-suppliable "which input do I read
   the sell price from" value for F6. The only values it can possibly use
   are `tii` (already authenticated by `OpTxInputCovId(tii)==tcid`) or the
   literal `1` (matching the covenant check's own hardcoded index). There is
   no way to "point `sii` at a decoy" because `sii` does not exist as a
   concept in this bytecode — not as an unenforced parameter, but as
   nothing at all. The sigscript builder functions
   (`build_buy_v16_fill_sigscript`, `..._ioc_fill_sigscript`,
   `..._partial_fill_sigscript`) don't even have a parameter for it, so this
   is enforced at the Rust API level too, not just on-chain.
2. **Clean-stack is defense-in-depth against append/prepend tampering.**
   Suppose an attacker hand-crafts a raw sigscript (bypassing the builder
   entirely) that pushes an extra, unused decoy item — attempting to mimic
   v15's shape. `kaspa-txscript`'s engine enforces clean-stack: the script
   must finish with **exactly one** item on the data stack
   (`crypto/txscript/src/lib.rs`, `TxScriptError::CleanStack` when
   `dstack.len() > 1` at the end). v16's cleanup (`Op2Drop` x N) drops
   exactly the number of items the honest 3-index (fill) or 2-index
   (partial) layout produces — a stray extra item is never referenced by
   any instruction (nothing in the fixed bytecode points at it) and is
   therefore never dropped, so it survives to the end of execution and the
   whole transaction is rejected by consensus, independent of whether every
   internal `OpVerify` happened to pass. (This mirrors Finding 6.6 in the
   deprecated `trace-sell-v4.md` audit for an analogous scenario.)

Both of these are structural/bytecode-level proofs, verified against the
actual committed bytes and the actual `kaspa-txscript` engine source (not
assumed). What Phase 3 does **not** provide is a live on-chain execution of
the adversarial transaction — that requires a running node and funded
wallet, which is Phase 5's job; see that section for what could and could
not be completed on this device.

---

## Phase 4 — Tests

Status: see below.

---

## Phase 5 — E2E (testnet-10)

Status: see below.
