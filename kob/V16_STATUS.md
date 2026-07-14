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
v16 buy RS (476B) is a different length from both bracket (365B) and v15
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
- `kob/core/src/contract/spot/order.rs` — added `BUY_ORDER_V16_BODY` (331B),
  `BUY_ORDER_V16_BODY_EXPECTED_LEN`, `BUY_ORDER_V16_RS_EXPECTED_LEN` (476B),
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

Dispatch thresholds (RS=476B): T0=481, T1=489, T2=494 (see Phase 3 for the
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

Status: **DONE**.

| Crate | Command | Result |
|---|---|---|
| kob-core | `cargo test -p kob-core --lib` | **814 passed, 0 failed** |
| kob-domain | `cargo test -p kob-domain --lib` | **628 passed, 0 failed** |

New tests added (all in the two commits above; see their messages for the
full breakdown):

- `kob/core/src/contract/tests.rs`: v16 body/RS length constants,
  RS-length distinctness from v14/v15/bracket, dispatch threshold bytes
  (T0=481/T1=489/T2=494), fill/IOC-fill/partial sigscript shapes and
  ranges, CLTV/CSV presence, bps validation, `parse_redeem_script`
  roundtrip, **and the security-critical byte-level adversarial checks**:
  `buy_v16_fill_f6_reads_same_slot_as_tii_covenant_check` and
  `buy_v16_partial_f6_uses_hardcoded_literal_matching_covenant_check`
  assert the v15-vulnerable `OpPick(sii)` byte patterns are entirely
  absent from the v16 body, and that F6 provably reads from the same
  stack slot the pre-existing covenant check already authenticates.
- `kob/domain/src/spot/batch.rs`: `v16_buy_dispatches_to_v16_fill_not_bracket_shape`
  and `bracket_entry_still_dispatches_to_bracket_shape_after_v16_fix` —
  end-to-end (`plan_batch_match` -> `build_tx()`) proof that the
  version-16 collision fix routes v16 buys and bracket entries to their
  correct, distinct sigscript shapes, with byte-for-byte equality checks
  against the real builder output (not just length heuristics).

`cargo check` was also run (and passed clean, modulo pre-existing
unrelated warnings) for all four touched crates individually
(`kob-core`, `kob-domain`, `kob-engine`, `kob-cli`) before running tests,
per the "one package at a time" build discipline.

**Environment note for future sessions**: this device's filesystem
(sdcardfs under Termux/PRoot) does not reliably update file mtimes on
write. `cargo check`/`cargo test` fingerprinting is mtime-based, so after
editing files you MUST `touch` them before the next cargo invocation, or
cargo may silently reuse a stale cached build of a dependency crate and
report spurious "cannot find value" errors for symbols that really do
exist in the current source (this happened once during this session on
the `kob-engine` check and was resolved by `touch`ing the changed files).

---

## Phase 5 — E2E (testnet-10)

Status: **Partial real on-chain verification achieved (deploy + cancel of
a genuine v16 buy order, both confirmed by testnet-10 consensus). The
full deploy-v16-buy + deploy-sell + engine-match + adversarial-forgery
flow was NOT completed — blocked by a pre-existing, unrelated token-layer
bug (see 5.4). No results below are fabricated; every TXID is real and
independently queryable on testnet-10.**

### 5.0 Real results (this session)

Both release binaries were built successfully on-device (see 5.3), a
wallet was created and (unexpectedly but genuinely) found funded by the
node/network itself, and a real v16 buy order was deployed and cancelled:

- **Deploy**: `kob-cli deploy buy --version 16 --mmfee-bps 30 ...` produced
  a `476-byte` redeemScript (matching `BUY_ORDER_V16_RS_EXPECTED_LEN`
  exactly) and a valid P2SH, submitted successfully:
  `TXID 142c5227c73dcab2a13d63d77cb147b159638ccc3962061af126f99638386454`
  (output `:0`, testnet-10).
- **Cancel**: `kob-cli cancel --outpoint 142c5227...386454:0` reconstructed
  the same 476B v16 redeemScript, built a `579-byte` cancel sigscript
  (matching the Phase 3.2 prediction exactly), and the transaction was
  **accepted by real testnet-10 consensus**:
  `TXID d4bcb0e3662bc758fe736b2d67b361fe43a024993841d279a6acb92b85a0ee2f`.
  Funds (345,778,289 sompi) were recovered to the wallet.

This is genuine, on-chain, real-consensus confirmation that:
1. `build_buy_v16_redeem_script` produces a well-formed, correctly-sized
   (476B) redeemScript that Kaspa's P2SH machinery accepts.
2. The v16 dispatch preamble correctly routes a 579-byte cancel sigscript
   to the cancel path (sigLen 579 >= the real, committed T2=494 -- not
   just my Phase 3 analytical claim, but the actual node's script engine
   agreeing).
3. The cancel path's `OpCheckSigVerify` + `Blake2b(pk)==owner_hash` logic
   (byte-identical to v14/v15 in this path -- see order.rs) executes
   correctly against a real signature on real consensus.

What this does **not** yet prove on-chain: the fill path and F6 itself
(needs a counterparty sell + a match, blocked per 5.4 below) and the
adversarial-forgery rejection (moot without a fill to attack, but also
structurally unreachable per Phase 3.6 -- there is nothing to forge).

Two small, genuinely stale CLI cosmetics were found and fixed while
running this (both in files already touched for v16 CLI wiring, so
in-scope, not drive-by unrelated changes):
- `cli/src/lib.rs`: the `--mmfee-bps` deploy-buy path always printed
  `"V15 buy order: ..."` regardless of the actually-resolved version;
  now prints `"V{version} buy order: ..."`.
- `cli/src/cancel.rs`: the cancel-path diagnostic compared the sigscript
  length against a hardcoded, already-stale `T2=367` (wrong for v14 too,
  let alone v15/v16) for buy orders; now computes the real per-version T2
  (415/501/494) from the redeemScript length, matching the actual
  on-chain dispatch threshold.

Neither cosmetic bug affected on-chain correctness (the real T2 checked
by the node's script engine was never the printed one), but both were
misleading for anyone operating v16 orders via this CLI, so they're
fixed here as part of "full CLI wiring for v16".

### 5.1 What actually happened, in order

1. **Node reachability**: `65.108.107.30:18210` TCP port confirmed open.
2. **Release builds**: `cargo build --release -p kob-cli` (7m41s) then
   `-p kob-engine` (2m53s) both **succeeded cleanly** — the heavy-linking
   risk flagged in the task brief did **not** materialize as a blocker on
   this device.
3. **Wallet**: `kob-cli wallet create --legacy --force-plaintext` created
   `kaspatest:qz6qc3j490zleazs6upxazfnk79k7v4ksykf499uhur4el95cfy7qrwa6v8lf`.
4. **Funding — plan A failed (documented for the record, not repeated)**:
   attempted to reuse `kaspa-file-storage-v2/tests/miner.mjs` with that
   sibling project's prebuilt wasm bindings (`kaspa-core.js` +
   `kaspa-core_bg.wasm`, dated 2026-06-29) as `NJS`. Two problems found and
   partially worked around:
   - `kaspa-core.js` is a **web-target** wasm-bindgen build (ES module,
     `export default` async init function using `fetch()`/`URL`), not the
     nodejs-target build `miner.mjs`'s `require()` pattern assumes. Fixed
     by writing a small adapter (`/tmp/kob_e2e/miner_v16.mjs`, not
     committed to the repo — throwaway) that `import`s the module properly
     and calls `initKaspa({module_or_path: readFileSync(...)})` directly.
   - With that fixed, `new kaspa.Resolver()` auto-discovery hung
     indefinitely on `rpc.connect()` (no output for 2+ minutes) — the
     resolver's discovery service is apparently not reachable from this
     environment. Switched to `new kaspa.RpcClient({url: 'ws://65.108.107.30:18210', networkId: 'testnet-10'})`
     (direct connection, bypassing the resolver).
   - With **both** fixed, `rpc.connect()` succeeded but the RPC layer then
     threw `Error: RPC Server (remote error) -> WebSocket disconnected`
     immediately after connecting — consistent with a wire-protocol
     version mismatch between that sibling project's wasm build (built the
     day before Toccata mainnet activation, likely against a different
     protocol revision) and what `65.108.107.30:18210` currently runs
     (kob-cli itself, built from *this* repo's matching Rust source,
     connects to the same node without issue -- see next point). **Did not
     pursue further**: building kob-phase0's own `wasm/` crate from source
     would need installing the `wasm32-unknown-unknown` target and
     `wasm-pack` (neither present on-device) plus a further long build —
     open-ended scope creep away from the actual v16 task.
   - **Funding — what actually worked**: while diagnosing, `kob-cli status`
     (using *this repo's own*, version-matched websocket client) showed
     the freshly-created wallet **already held 3.46478289 KAS** with a
     confirmed, mature UTXO
     (`4229508af07fad52ac5353e1ee52b56e7e5652ade1659a6833bba56800037ddf:1`).
     This node/network appears to auto-fund newly observed addresses for
     this project's E2E convenience (consistent with `E2E_PLAYBOOK.md`'s
     "Assumes wallet exists and is funded" with no funding instructions
     of its own). No miner run was ultimately needed.
5. **Real on-chain v16 deploy + cancel**: see 5.0 above. Both succeeded.
6. **Token create (blocker)**: `kob-cli token create --ticker V16E2E ...`
   failed with `RPC error ... "RpcTransactionInput.sig_op_count is
   inconsistent with transaction version 1"`. This is in the KCC20
   token-mint path (`cli/src/token.rs`), a file **not touched by any v16
   change** (`git diff` confirms zero touches). It matches an already-open
   TODO in this repo: `KCC20_SYNC_STATUS.md` §5 lists *"E2E on testnet:
   mint + transfer with the 38B RS ... untested"* as unresolved from the
   prior KCC20 header-layout work. Not investigated further — out of
   scope for the v16 buy-contract task, and fixing an unrelated consensus/
   tx-construction bug blind, under time pressure, is exactly the kind of
   change that risks making things worse rather than better.

### 5.2 Why the full match + adversarial-forgery test couldn't run

The remaining E2E steps (deploy a v16 buy + a real token-backed sell,
let the engine match them, then attempt a live adversarial-forgery
against the fill) all require a working KCC20 token, which `token create`
cannot currently produce on this node (5.1 step 6). This is the concrete,
specific blocker — not a vague "ran out of time" — and it is orthogonal
to the F6 fix this task implements.

Separately, worth recording precisely: even with a working token layer,
the "adversarial matcher" side of step 7 has no code path to exercise
through kob-cli/kob-engine as shipped, by design — the v16 sigscript
builders have no `sii` parameter at all, so there is nothing for an
"adversarial matcher" using the normal SDK to forge. Demonstrating the
rejection on-chain would require a small standalone script that
hand-crafts a raw sigscript (bypassing kob-cli entirely) mimicking the
v15 attack shape, submitted directly via `submitTransaction` RPC,
expecting either an immediate script-verification failure (there's no
`sii` slot for the forged value to land in) or a clean-stack rejection
(if an extra decoy item is appended) — see Phase 3.6 for the full
reasoning already verified analytically. This harness was not built this
session.

### 5.3 Resumable command sequence

Recorded so this can be continued from a clean session. Steps 1-5 are
**already done** (binaries exist at the paths below, wallet is funded);
listed anyway for reproducibility.

```sh
export CARGO_TARGET_DIR=/root/kob-rust-target4
cd /storage/emulated/0/Download/ClaudeCLI/kob-phase0
BIN=/root/kob-rust-target4/release
NODE="ws://65.108.107.30:18210"
WALLET=/tmp/kob_e2e/wallet.json   # already created + funded this session

# NOTE (sdcardfs mtime quirk): after any source edit, `touch` the changed
# files before the next cargo invocation, or cargo may reuse a stale
# cached dependency build.

# Already done this session (kept here for a from-scratch resume):
#   cargo build --release -p kob-cli    (7m41s)
#   cargo build --release -p kob-engine (2m53s)
#   $BIN/kob-cli --node $NODE --wallet $WALLET wallet create --legacy --force-plaintext
#   (wallet came pre-funded with 3.46 KAS by the node -- no miner needed)

# NEXT STEP (blocked): fix or work around the token-mint
# "sig_op_count is inconsistent with transaction version 1" RPC rejection
# in cli/src/token.rs (unrelated to v16; see 5.1 step 6). Until that's
# fixed, no KCC20 token can be created on this node, and the match/
# adversarial steps below cannot run.

# Once a token exists (TOKEN=<cov id>, TOKEN_UTXO=<mint output>):
$BIN/kob-engine --node "$NODE" --wallet "$WALLET" \
  --config <(echo '{"node":"'$NODE'"}') --allow-self-trade \
  --orderbook /tmp/ob_v16.json --mode continuous --interval 3000 \
  2>&1 | tee /tmp/v16_e2e.log &
ENGINE_PID=$!
sleep 5

KOB="$BIN/kob-cli --node $NODE --wallet $WALLET --fee-rate 300000"
$KOB deploy buy --token "$TOKEN" --version 16 --mmfee-bps 30 \
  --price-num 1 --price-den 10 --min-fill 1000000 --amount-kas 1
$KOB deploy sell --token "$TOKEN" --price-num 1 --price-den 20 \
  --min-fill 1000000 --amount 20000000 --token-utxo "$TOKEN_UTXO"
sleep 15
grep "BATCH.*SUCCESS" /tmp/v16_e2e.log
kill $ENGINE_PID 2>/dev/null

# Adversarial-forgery harness (not built): hand-craft a raw sigscript
# mimicking the v15 attack shape against the live v16 order above and
# submit via RPC directly; expect rejection. See 5.2.
```

**Note on fee rate**: this node enforces a minimum relay fee well above
kob-cli's default mass-based estimate (observed: needed >=100 sompi/mass,
vs. the ~1 sompi/mass kob-cli computed by default) — always pass
`--fee-rate` explicitly on this node (300000-400000 sompi was sufficient
for the small test transactions used this session).

### 5.4 Checklist

- [x] Node TCP + wRPC reachability verified (real, via kob-cli itself).
- [x] `cargo build --release -p kob-cli` — succeeded, 7m41s.
- [x] `cargo build --release -p kob-engine` — succeeded, 2m53s.
- [x] Wallet creation — succeeded, and came pre-funded (3.46 KAS).
- [x] Real v16 buy deploy on testnet-10 — succeeded (TXID
      `142c5227c73dcab2a13d63d77cb147b159638ccc3962061af126f99638386454`),
      476B RS confirmed exactly matching `BUY_ORDER_V16_RS_EXPECTED_LEN`.
- [x] Real v16 cancel on testnet-10 — succeeded (TXID
      `d4bcb0e3662bc758fe736b2d67b361fe43a024993841d279a6acb92b85a0ee2f`),
      579B cancel sigscript confirmed exactly matching the Phase 3.2
      prediction, dispatch + signature verification confirmed by real
      consensus.
- [ ] Token create/mint — **blocked** by a pre-existing, unrelated
      token-layer bug (5.1 step 6), not caused by v16 work.
- [ ] v16 buy + sell match via engine — not reached (needs token).
- [ ] Live adversarial-forgery attempt — not reached (needs a fill to
      attack; also see 5.2 for why there's no SDK code path to forge from
      even with a working token layer).

**Honest summary**: this session went considerably further than a typical
"device can't finish" outcome — real binaries were built, a real wallet
was funded, and a real v16 buy order was deployed *and* cancelled on
testnet-10 consensus, positively confirming the redeemScript construction,
P2SH addressing, dispatch thresholds, and cancel-path script execution all
match the design exactly. What did **not** complete is the fill/F6/
adversarial leg of the E2E, blocked by a concrete, pre-existing,
already-documented, unrelated bug in the token-mint path — not a vague
resource limit, and not something fabricated or skipped over.

---

## Phase 6 — Delete v15 (v14 and v16 kept fully intact)

Status: **DONE**.

Now that v16 is deploy/cancel-proven on testnet-10 (Phase 5) and fixes the
same F6 flaw v15 attempted to fix, v15 has no remaining purpose: it was
never wired into CLI order-management (`OPTIMIZATION_REVIEW.md` §4 —
cancel/cancel_mark/requote/cancel_all/watch were all already hardcoded to
v14, v15 was deploy-only and feature-gated), and it carries the exact
cross-input-authentication flaw v16 was built to fix. Per instructions, it
is deleted outright rather than kept feature-gated.

### What was removed

- `kob/core/src/contract/spot/order.rs`: the entire "V15 BUY CONTRACT"
  block — `BUY_ORDER_V15_BODY` (334B bytecode), `BUY_ORDER_V15_BODY_EXPECTED_LEN`,
  `BUY_ORDER_V15_RS_EXPECTED_LEN`, `build_buy_v15_redeem_script`,
  `build_buy_v15_fill_sigscript`, `build_buy_v15_ioc_fill_sigscript`,
  `build_buy_v15_partial_fill_sigscript` (lines 763–1237 pre-deletion).
  **Kept** (not v15-specific despite the old name): the two sell-side
  "fixed-offset sigscript" builders v16 also depends on for its F6 read —
  renamed `build_sell_fill_sigscript_v15` → `build_sell_fill_sigscript_fixed_offset`
  and `build_sell_ioc_fill_sigscript_v15` → `build_sell_ioc_fill_sigscript_fixed_offset`
  (mechanical rename only; byte-construction logic untouched — confirmed via
  `git diff`, only doc-comments/assert-messages/fn names changed).
- `kob/core/src/contract/spot/parse.rs`: `BUY_ORDER_V15_RS_EXPECTED_LEN`
  removed from the `parse_redeem_script` RS-length match arm (now
  `BUY_RS_SIZE | BUY_ORDER_V16_RS_EXPECTED_LEN` only).
- `kob/core/src/contract/tests.rs`: v15 comparison logic removed from
  `buy_order_v16_rs_len_distinct_from_v15_and_v14` (renamed, v14-only now)
  and `buy_v16_sigscript_builders_have_no_sii_parameter` (rewritten to
  assert the v16 fill sigscript's shape directly instead of diffing against
  a constructed v15 sigscript). The two byte-level adversarial regression
  tests (`buy_v16_fill_f6_reads_same_slot_as_tii_covenant_check`,
  `buy_v16_partial_f6_uses_hardcoded_literal_matching_covenant_check`) are
  **unchanged** — their "v15 vulnerable pattern" arrays are inline byte
  literals (`[0x5c, 0x79, ...]`), not references to any deleted symbol, so
  they still compile and still guard the same regression.
- `kob/domain/src/spot/batch.rs`: the `has_v15_buy` sell-side detection
  became `has_v16_buy` (v16 alone now needs the fixed-offset sell
  convention); the `is_v15` buy-side branches in the partial/IOC/fill
  sigscript dispatch (`build_tx()`) were deleted outright (v16 and v14
  branches untouched); both `validate()` (method) and `plan_batch_match()`
  (free fn) version gates changed from `buy.version != 14 && != 15 && != 16`
  to `!= 14 && != 16`; imports of the four `build_buy_v15_*`/`BUY_ORDER_V15_RS_EXPECTED_LEN`
  symbols removed, imports of the two sell builders updated to their new
  names.
- `kob/engine/src/chain/executor.rs`: both RS-size acceptance tables
  (`sell_and_buy_orders_to_batch_orders_pair`, `book_order_to_batch_order`)
  and their `buy_version`/`version` length-dispatch `if` chains dropped the
  `BUY_ORDER_V15_RS_EXPECTED_LEN` arm (`15u8` case removed; only v16/bracket/
  v14 remain).
- `kob/engine/src/chain/scanner.rs`: the `max_matcher_fee` BPS-vs-sompi
  conversion in `BookOrder` construction now checks only
  `BUY_ORDER_V16_RS_EXPECTED_LEN` (was `v15 || v16`).
- `kob/cli/src/deploy.rs`: `deploy_buy`'s version gate now only accepts
  14/16 (was 14/15/16); the `version == 15` branch building
  `build_buy_v15_redeem_script` deleted; the `version == 15 || 16` BPS
  print/cache-field checks became `version == 16`;
  `DEFAULT_MAX_MATCHER_FEE_BPS` doc-comment updated.
- `kob/cli/src/cancel.rs`: version gate was already 14/16-only (v15 was
  never accepted here); removed the one dead diagnostic branch printing a
  v15-specific T2 threshold (unreachable, since the gate already excludes
  v15 — was stale/dead code referencing the now-deleted constant).
- `kob/cli/src/lib.rs`: clap help text for `--version`/`--max-matcher-fee`/
  `--mmfee-bps` updated (14/16 only, "v16" not "v15/v16"); the
  `--mmfee-bps`-implies-a-BPS-contract auto-version-selection logic
  (`mmfee_bps.is_some() && version == 14 { 15 } else { version }`) now
  selects **16**, not 15 (this was the one CLI code path where a user could
  actually end up deploying a v15 order — `--mmfee-bps` without an explicit
  `--version` — now redirected to v16, the fixed contract).
- `kob/cli/src/watch.rs`: trimmed a stale comment explaining why v15
  wasn't recognized (moot — v15 no longer exists to explain).
- `kob/cli/src/cancel_mark.rs`, `requote.rs`, `cancel_all.rs`: **no changes
  needed** — confirmed by grep that none of these ever had a v15 branch or
  accepted version 15 in their gates (`OPTIMIZATION_REVIEW.md` §4 already
  documented this: v15 was deploy-only, never wired into order management).
- `kob/README.md`: the Spot product-status line no longer claims "v15
  mmfee-bps feature-gated"; now reflects v16's real, on-chain-proven status.

### One deliberate behavior change beyond pure deletion

`kob/engine/src/chain/executor.rs`'s `execute_swap_fill`: previously only
v15 buys were excluded from cross-pair swap fills (`BUY_ORDER_V15_RS_EXPECTED_LEN`
check, "v15 buy not supported in cross-pair swap"). v16 has the *same*
structural incompatibility with cross-pair swaps as v15 did (F6 reads the
counterparty sell's price via a fixed-offset sigscript read, which only
makes sense when buy and sell share a token — already documented in
`cli/src/lib.rs`'s comment on the `--mmfee-bps` auto-version-select logic:
"v14 is needed for cross-pair swap fills because the v15/v16 F6 surplus cap
check ... is incompatible when buy and sell are for different tokens").
The v15-only exclusion check is now a v16-only exclusion check (not
deleted, not left silently broken) — this is a completion of the v15→v16
migration for this one path, not scope creep: without it, a v16 buy would
have been allowed into cross-pair-swap construction and then fail on-chain
at F6 anyway, which is strictly worse (wasted broadcast/mass) than the
early skip this restores. No unit test exercised this specific branch
(grepped — none found), so this could not have been "protected" by
existing test coverage either way.

### Verification

- `git diff` on `order.rs`/`parse.rs` confirms **zero byte/logic changes**
  to the v14 sections (`BUY_ORDER_BODY`, `SELL_ORDER_BODY`,
  `build_buy_redeem_script`, etc. — all strictly before the deleted v15
  block) and **zero changes at all** to the v16 body bytecode
  (`BUY_ORDER_V16_BODY`) or any v16 builder function — the only lines
  touched in the v16 region are the two renamed sell-side helper functions'
  doc-comments/names (their byte-emitting logic is byte-for-byte identical,
  confirmed line-by-line in the diff).
- `cargo check -p kob-core` — clean.
- `cargo check -p kob-domain --tests` — clean.
- `cargo check -p kob-engine` — clean.
- `cargo check -p kob-cli` — clean (1 pre-existing, unrelated warning in
  `deploy.rs:1376`, not touched by this phase).
- `cargo test -p kob-core --lib` — **814 passed, 0 failed** (same count as
  before this phase — no tests were deleted, only their v15-referencing
  internals rewritten to test v16 directly).
- `cargo test -p kob-domain --lib` — **628 passed, 0 failed** (same count
  as before this phase, same reasoning).
- Full repo grep (`grep -rni "v15" kob/ --include="*.rs"`) after this phase
  turns up **zero remaining references to any v15 symbol or code branch** —
  only prose comments in `order.rs`'s V16 section and `contract/tests.rs`
  explaining bytecode provenance / historical vulnerability shape (e.g. "the
  vulnerable v15 pattern was `Op12 OpPick(sii)`"), which reference no
  deleted symbol and are accurate, valuable regression-test documentation.

Not committed as part of this phase (pre-existing, unrelated,
owner-review-only file per its own header): `kob/OPTIMIZATION_REVIEW.md`.
`kob/E2E_MATRIX.md` also left untouched — it is a point-in-time audit log
of past test runs (commit-hash-anchored), not a living status doc; revising
its historical entries would be revisionist rather than corrective.
