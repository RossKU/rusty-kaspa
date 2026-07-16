# N:M-capable buy covenant — design (Phase 1) + implementation status (Phase 2)

Status: **IMPLEMENTED (Phase 2 complete); v17 is now the SOLE creatable buy
contract (version-cleanup pass).** The v17 contract, its full adversarial
matrix, all the recognition wiring, and the `plan_batch_match` N-per-sell emission
are landed and green against the real post-Toccata `kaspa-txscript` `TxScriptEngine`.
A later pass closed the gap where `deploy_buy` and `requote` still accepted
`--version 16` for brand-new buy deploys (see "Wiring" below) -- v16 (like
v14) is now deploy-rejected and retained purely for servicing orders already
on-chain. Phase 1 (design + feasibility spike, `kob/core/tests/nm_buy_spike.rs`)
is preserved below unchanged; the Phase-2 outcome is summarized here.

## Phase 2 outcome (implemented)

- **Contract**: `BUY_ORDER_V17` in `kob/core/src/contract/spot/order.rs`
  (`build_buy_v17_body`/`build_buy_v17_redeem_script` + fill/IOC/expire/cancel
  sigscript builders). **MAX_N = 8** (justified from the tx compute-mass budget:
  an 8-sell sweep ≈ 12k grams ≈ 12% of the pre-Toccata 100k standard cap). Body
  693B, RS 838B, pinned in `bytecode_stable`. Selector dispatch (Op9 OpRoll), not
  length-based. Both buyer protections carried: aggregate limit-price floor AND
  aggregate surplus cap. Every summation term per-input bound via
  `OpAuthOutputIdx(tii,0)` + covenant-id + buyer-SPK; strict-increasing `tii`.
- **Adversarial matrix**: `kob/core/tests/v17_nm_buy.rs`, 26 engine tests, all the
  §6 items green (double-count, non-covenant/ wrong-token/ wrong-SPK/ mis-authorized
  terms, over-cap, mixed-price dilution, limit-price-floor violation, IOC theft,
  forged sell price, decoy-uncounted, over-delivery-no-exposure, N=1 parity,
  N=MAX_N boundary, N>MAX_N unrepresentable, RS length/collision) + expire/cancel.
- **Wiring**: v17 is now the SOLE creatable buy contract -- `deploy_buy`'s
  version gate (`kob/cli/src/deploy.rs`) rejects both v14 and v16 for new
  deploys (previously it allowed v16 through as an alternative to v17); v14
  and v16 stay fully parseable/cancellable for orders already resting
  on-chain. `kob-cli requote`'s independent new-deploy gate got the same
  treatment (buy: v17-only; sell: unaffected, single version). Landed in
  `parse.rs`, `scanner.rs`, `executor.rs` (version + cross-pair exclusion), CLI
  `deploy.rs`/`lib.rs`/`cancel.rs`/`cancel_all.rs`/`requote.rs`/`watch.rs`, and
  the `bytecode_stable` pin. Fixed along the way: `cancel.rs`/`cancel_all.rs`
  imported `build_buy_v17_cancel_sigscript` and length-gated on
  `BUY_ORDER_V17_RS_EXPECTED_LEN` but their version gates still hard-rejected
  `version == 17` before ever reaching that dispatch, and their RS
  reconstruction (from cached order params) had no v17 branch at all -- so a
  v17 order could never actually be cancelled through either command despite
  the sigscript plumbing already being present. Both gates + reconstruction
  now handle v17; `requote.rs`'s old-order-side (the leg being cancelled) got
  the equivalent fix so a v17 order can be requoted, not just deployed.
  `cancel_mark.rs`'s buy cancel-mark path (hand-inlined Op1-selector
  sigscript) is NOT yet v17-aware -- v17 dispatches by a different selector
  scheme and the mark(cpend 0->1) path has no engine-proven test yet, so it
  was left v14/v16-only rather than hand-derived unverified; flagged here
  as a residual, not silently patched. `kob-cli batch deploy-buy`, `ifd`/`ifo`
  conditional deploys, the `kob mm` bot, and `kob-engine --mode deploy-test`
  all construct buy orders through their own independent, pre-existing
  hardcoded-v14 (or, for `mm`, v14-only-gated) paths, entirely bypassing
  `deploy_buy`'s gate; that inconsistency predates this change and is out of
  its scope.
- **Matcher emission (`plan_batch_match`)**: a v17 buy routes to a dedicated,
  isolated `plan_batch_match_v17` that emits ONE BuyerTokens output per sell, each
  bound to its own sell input (new `BatchPlan.output_auth_input` +
  `buy_sweep_sells`); `build_tx` emits the v17 fill sigscript; the engine executor
  binds each output per its authorizing sell input. The v14/v16 merge path is
  untouched (zero regression: kob-domain 634, kob-engine 369, kob-cli 517 green).
- **Live N:M** remains blocked by the node's bulk-`getBlocks` catch-up hang (noted
  in `E2E_LIVE_RESULTS.md`); the harness is the authoritative verification, as
  agreed. The exact planner output shape+values equal the engine-proven
  `honest(2)` case, so the pipeline (planner → tx → contract) is established.

---

Status (Phase 1, historical): design + feasibility spike only. Nothing in
`kob/core/src/contract/spot/order.rs` was changed by the Phase-1 document; the
mechanism was proven in `kob/core/tests/nm_buy_spike.rs`. See "Feasibility spike
result" below for the original go/no-go.

## 1. The problem (recap)

`kob/SECURITY_FIXES.md` (Fix 3) bound the sell contract's token-conservation check
(F4) to the *specific input* that authorized it (`OpTxInputIndex Op0 OpAuthOutputIdx`),
closing a shared-output drain across multiple sellers. That per-input binding means
each sell's tokens must land in an output that ONLY that sell authorizes — so an
N-sell match needs N separate token outputs, one per sell.

The v16 buy contract's F6 (`BUY_ORDER_V16_BODY`, `order.rs:~999-1032`) reads exactly
ONE output (`output[toi]`) as "the tokens the buyer received" and caps the buyer's
surplus against that single value. `kob/E2E_LIVE_RESULTS.md` ("Auto-matcher
comprehensive run") reproduces the resulting deadlock live: splitting sell-side
tokens per seller (needed for F4) breaks buy-side F6 (which sees only one seller's
worth and computes a bogus giant "surplus"); merging them into one output (what F6
wants) breaks the seller-side per-input F4 (`0 is not a valid covenant output index
for input 1 with 0 authorized outputs`). The two fixes are mutually exclusive as
long as F6 reads a single output. **N sells : 1 buy in one tx is currently
unsettleable on-chain** (`BuySweep`/`GtcBuyMultiFill` in the engine's own capability
matrix).

## 2. Core idea

Keep the sell side exactly as Fix 3 left it (per-input F4, unchanged). Change the
buy side's delivery check from reading one `output[toi]` to **summing N per-sell
outputs**, each independently re-derived and bound to its own sell input, each
priced at *that sell's own* committed price, then capping the buyer's aggregate
surplus against the sum.

## 3. (a) Opcode approach

### OP_SUBTRACTOUTPUTS (0xc7) does not exist as such — correction to the brief

The audit's "`OP_SUBTRACTOUTPUTS` 0xc7, defined but unused" comes from
`kob/core/src/contract/opcodes.rs:106`, a disassembler name table used only for
human-readable script dumps. It mislabels the byte: the real post-Toccata engine
(`crypto/txscript/src/opcodes/mod.rs:1386`) implements `0xc7` as **`OpTxOutputSpkLen`**
— pop an output index, push the byte-length of that output's `scriptPublicKey`. It
has nothing to do with output amounts or subtraction, and it isn't dormant either:
`kob/core/src/contract/prediction/market.rs` and `ballot_box.rs` already use it
(correctly named `OP_TXOUTPUTSPKLEN`) for SPK-length checks. There is no "sum/subtract
a set of outputs" primitive anywhere in `crypto/txscript`. Grepping the whole engine
confirms it: the only per-item numeric ops are `OpAdd`/`OpSub`/`OpMul`/`OpDiv`, each
consuming exactly two stack items — no vector/aggregate arithmetic exists.

**This settles the evaluation: Option B (`OP_SUBTRACTOUTPUTS`) isn't on the table
because it doesn't exist as a real opcode.** The only implementable approach is
Option A: `OpCovOutCount`-style introspection plus a per-output `OpTxOutputAmount`
read, accumulated with `OpAdd`.

### No native loop — "summation" means compile-time unrolling to a fixed MAX_N

Kaspa/kob script (like Bitcoin Script) has `OpIf`/`OpElse`/`OpEndIf` but no backward
jump and no subroutine call — a script cannot loop over "however many sells the
sigscript happens to supply." Any N-term sum has to be **unrolled at
contract-authoring time up to a fixed compile-time bound `MAX_N`**, with the actual
per-tx arity `N <= MAX_N` selected at runtime. Two ways to unroll, evaluated:

- **Naive: one full branch per exact arity value** (an `OpIf` cascade with `MAX_N`
  branches, branch `k` containing `k` copies of the term-processing block). Bytecode
  grows `O(MAX_N^2)` (sum of 1+2+...+MAX_N term-blocks). Simple to reason about, but
  wasteful — not recommended past `MAX_N` of 3-4.
- **Recommended: MAX_N fixed *slots*, each conditionally active.** Unroll exactly
  `MAX_N` term-processing slots once; each slot `i` is guarded by `i <= N` (a runtime
  sigscript value), and an inactive slot contributes `fair_kas_i = 0` and skips all
  binding/price checks. Bytecode grows `O(MAX_N)` — linear, one term-block per slot
  regardless of how many are unused in a given tx. **This is the shape Phase 2 should
  implement.** The distinctness check (below) generalizes the same way: guard each
  adjacent-pair check by `i+1 <= N` instead of requiring `MAX_N-1` pairwise checks
  unconditionally.

  The Phase 1 spike (below) implements the simpler *fixed* N=2 case (both slots always
  active, no `i<=N` guard) — sufficient to prove the summation/binding mechanism
  itself, not the full slot-count-selection machinery. That machinery is straightforward
  `OpIf` plumbing reusing the same verified term block; it's deferred to Phase 2 to keep
  the spike's diff small and its correctness easy to hand-verify end to end.

  Script-size headroom is generous here and not the binding constraint:
  post-Toccata `max_scripts_size = 1_000_000` bytes and `max_ops_per_script =
  1_000_000` (`crypto/txscript/src/lib.rs:78,82`), so even `MAX_N` in the dozens is
  nowhere near a hard limit. The real cost is **transaction mass / fees** (a bigger
  redeemScript means a bigger sigscript push, which is what should bound `MAX_N` in
  practice — see §7).

### The chosen per-term mechanism

For term `i`, given `tii_i` (a sigscript-supplied index into `tx.inputs`, claimed to
be the i-th sell):

1. **`toi_i = OpAuthOutputIdx(tii_i, 0)`** — the output is *derived*, not taken as a
   free sigscript parameter. `OpAuthOutputIdx` is not a "self" opcode — it takes an
   arbitrary `input_idx` off the stack (`crypto/txscript/src/opcodes/mod.rs:1457`),
   so the buy input can look up *another* input's authorized output directly. Because
   `CovenantsContext::from_tx` (`crypto/txscript/src/covenants.rs:107-145`) only adds
   an output to `input_ctxs[k].auth_outputs` when that output's declared
   `covenant_id` equals input `k`'s own `covenant_id`, `toi_i` is *structurally*
   guaranteed (before any script even runs) to carry the same covenant id as
   `tii_i` — there is no sigscript field an attacker can set to point a term at an
   arbitrary/decoy output. This is strictly tighter than v16, where `toi`/`coi` are
   independent free sigscript parameters whose relationship is only implicit-by-topology
   in the 1:1 case.
2. **`OpInputCovenantId(tii_i) == tcid`** — `tii_i` must really be a sell of the
   token being bought. Without this, an attacker could splice in a *different*
   token's sell as a summation term (its `OpAuthOutputIdx` would resolve fine, since
   the invariant above only guarantees internal consistency between an input and its
   own auth outputs — it says nothing about which token that is).
3. **buyer SPK check on `toi_i`** (`blake2b(OpTxOutputSpk(toi_i)) == bspkh`) — without
   this, `toi_i`'s tokens could be routed to anyone while the buyer's `kas_in` is
   still fully spent and still counted toward the sum.
4. **`fair_kas_i = OpTxOutputAmount(toi_i) / sell_pden_i * sell_pnum_i`** — sell price
   read off `tii_i`'s own sigscript via the *existing* v16 fixed-offset convention
   (`OpTxInputScriptSigSubstr` at `[7..15)`/`[16..24)`, unchanged,
   `build_sell_fill_sigscript_fixed_offset` unmodified). This price is
   cryptographically pinned: the sell's sigscript must supply the exact redeemScript
   bytes that hash to that sell's on-chain P2SH address (checked inside the *sell's
   own* script execution), so a matcher cannot forge a term's price without also
   invalidating that sell input's own spend.

Plus one check across all active terms:

5. **Distinctness: `tii_1 < tii_2 < ... < tii_N` (strict)**. This is the anti-double-count
   guard: without it, a matcher could supply the same `tii` in two term slots and have
   the (single) real sell's one authorized output counted twice toward the sum,
   inflating apparent `fair_kas` without a second sell ever existing. Strict
   monotonicity gets distinctness in `O(N)` comparisons (`N-1` adjacent `OpLessThan`
   checks) instead of `O(N^2)` pairwise checks — cheap, and it costs the matcher
   nothing since it just has to list sells in ascending input-index order, which it
   controls anyway when building the tx.

Then, once per tx (not per term):

6. **`surplus = kas_in - sum(fair_kas_i)`; `max_surplus = kas_in / 10000 * mmfee_bps`;
   verify `surplus <= max_surplus`.** Identical shape to v16 F6, just fed a sum
   instead of a single term. Because each term's `fair_kas_i` is computed from the
   *actual delivered* `OpTxOutputAmount(toi_i)` (not a hypothetical), this is
   automatically immune to the exact bug Fix 4 patched for the 1:1 case (IOC partial
   delivery pocketing the difference) — see §5.

### Concrete bytecode sketch (verified against the real engine)

This is not a paper sketch — it's the actual sequence proven in
`kob/core/tests/nm_buy_spike.rs::build_nm2_buy_redeem_script` (fixed N=2). State
layout: `[tcid 32B][bspkh 32B][mmfee_bps 8B]` (72B, no `pnum`/`pden`/`mfill`/`ohash`
in this trimmed spike — Phase 2 keeps the full v16 state, see §4). Stack after state
push (depth0 = top): `mmfee_bps(0), bspkh(1), tcid(2), tii_2(3), tii_1(4)`.

```
; DISTINCTNESS: tii_1 < tii_2
pick(4); pick(4); OpLessThan; OpVerify

; TERM i (tii at depth `d`, tcid at depth `c`, bspkh at depth `b`, entering):
pick(d); Op0; OpAuthOutputIdx                    ; toi = auth_outputs[tii][0]
pick(d+1); OpInputCovenantId; pick(c+2); OpEqual; OpVerify
pick(0); OpTxOutputSpk; OpBlake2b; pick(b+2); OpEqual; OpVerify
OpTxOutputAmount                                 ; tokens = amount(toi)
pick(d+1); num(7); num(15); OpTxInputScriptSigSubstr   ; sell_pnum
pick(d+2); num(16); num(24); OpTxInputScriptSigSubstr  ; sell_pden
pick(2); pick(1); OpDiv; pick(2); OpMul          ; fair_kas = tokens/pden*pnum

; term(4,2,1) for tii_1, then term(7,6,5) for tii_2 (depths shift by the first
; term's 4 leftover temporaries -- see the file for the fully worked depth trace)

; SUM + CAP
roll(4); OpAdd                                   ; sum = fair_kas_1 + fair_kas_2
OpTxInputIndex; OpTxInputAmount; OpDup            ; kas_in (x2)
roll(2); OpSub                                   ; surplus = kas_in - sum
pick(1); num(10000); OpDiv; pick(9); OpMul        ; max_surplus = kas_in/10000*mmfee_bps
OpLessThanOrEqual; OpVerify                       ; surplus <= max_surplus
Op2Drop x6; Op1                                   ; cleanup, TRUE
```

Measured size: **114 bytes of body for a fixed N=2** (186B total redeemScript
including the 72B trimmed state) — about 45-55 bytes per additional term at this
arity. `crypto/txscript`'s size ceiling (§ above) is nowhere close to binding at
this rate even for `MAX_N` well into the double digits.

## 4. (b) Supersede v16, or new version alongside?

**Decision: new version (v17), not a patch to v16.** Every prior buy-contract
security fix in `SECURITY_FIXES.md` (Fix 2's F6 add, Fix 4's F6 read-site change)
was **length-neutral** specifically so the fixed-offset dispatch (T0/T1/T2 sigLen
thresholds) and the sell-side fixed-offset price convention didn't need to move.
N:M breaks that constraint structurally: a variable-arity fill sigscript
(`[N][tii_1]...[tii_N][Op1/Op5][pushData(RS)]`) has a **variable length** that grows
with `N`, so the existing single T1 threshold (currently separating "fill" from
"partial") has to become a *range* covering every arity up to `MAX_N`, and the body
itself is `MAX_N`x-or-so larger than v16's 331 bytes. This cannot be shimmed in
place; it needs its own `BUY_ORDER_V17_BODY`, its own state-independent RS-size
constant, and its own dispatch thresholds.

**Functionally, v17 is a strict superset.** `N=1` degenerates to exactly v16's
1:1 case, with one *improvement carried through unconditionally*: `toi` is derived
via `OpAuthOutputIdx(tii, 0)` instead of taken as an independent free `coi`/`toi`
pair, closing the implicit (topology-only, not contract-enforced) binding gap noted
in §3 point 1. So v17 should become the **new deploy default**, exactly the
precedent Fix 2 already set for v14 -> v16 (`kob/cli/src/deploy.rs`'s
`deploy_buy` version gate): reject new v17-capable deploys below v17,
while retaining full v16 parse/build/match support for orders already resting
on-chain. v16 is not deleted, just no longer offered for new deploys.

**RS-length / dispatch / pin impact** (concrete, from grepping every consumer of
`BUY_ORDER_V16_RS_EXPECTED_LEN` today — v17 needs the equivalent set for its own
constant):
- `kob/core/src/contract/spot/order.rs` — new `BUY_ORDER_V17_BODY`,
  `BUY_ORDER_V17_BODY_EXPECTED_LEN`, `BUY_ORDER_V17_RS_EXPECTED_LEN`,
  `build_buy_v17_redeem_script`, new sigscript builders taking a variable `tii` list.
- `kob/core/src/contract/spot/parse.rs:93` — RS-length dispatch (`BUY_RS_SIZE |
  BUY_ORDER_V16_RS_EXPECTED_LEN => ...`) needs a v17 arm; since v17's own length is
  no longer a single constant (arity-dependent), parsing needs either a length
  *range* check or a leading length-prefixed arity field read before the rest is
  parsed.
- `kob/domain/src/spot/batch.rs:45,396,497,3459-3462` — the planner's v16-detection
  by exact RS length; needs a v17 detection (range) and the actual N:M-aware planning
  logic (currently `plan_batch_match`/`plan_ioc_match` explicitly avoid this shape —
  see the "Deeper finding" in `E2E_LIVE_RESULTS.md`).
- `kob/engine/src/chain/executor.rs:428-476,541-563,1289` — version detection and the
  cross-pair v16-exclusion note (`buy_rs.len() != ...V16_RS_EXPECTED_LEN`) both need a
  v17 arm.
- `kob/engine/src/chain/scanner.rs:361` — order-book ingestion's mmfee-field
  interpretation switch by RS length.
- `kob/cli/src/cancel.rs:338`, `kob/cli/src/watch.rs:158` — CLI-side version display
  by RS length.
- `kob/core/src/contract/tests.rs` (`bytecode_stable`, ~line 2001) — new pinned
  `blake2b256(BUY_ORDER_V17_BODY)` hash entry, and the length-collision assertions
  (`assert_ne!(BUY_ORDER_V16_RS_EXPECTED_LEN, ...)`) need a v17 counterpart against
  every other RS-size constant in the crate (bracket, v14 buy, sell, etc.) to prove no
  accidental sigLen collision across contract types.
- `kob/cli/src/deploy.rs` — version gate, as above.

None of this is optional busywork: the RS-length-as-implicit-version-tag pattern is
load-bearing throughout matching/scanning/parsing, so a variable-length contract
needs every one of these call sites to move from "is it exactly this many bytes" to
"is it in this arity-parameterized family," which is a bigger, more error-prone
change than any prior length bump in `SECURITY_FIXES.md` and should get its own
dedicated review pass in Phase 2, not be folded silently into the covenant patch.

## 5. (c) Interaction with partial-fill, IOC, and cross-pair

**IOC (Op5) — generalizes cleanly, already immune to the Fix 4 bug by construction.**
IOC relaxes the buyer's floor from the full expected amount to `mfill`; for N:M that
becomes `sum(tokens_i) >= mfill` instead of a per-term floor. Because every term's
`fair_kas_i` is computed from `OpTxOutputAmount(toi_i)` — the *actual* delivered
amount, never a hypothetical `kas_in`-derived quantity — the exact hole Fix 4 closed
(surplus computed against a hypothetical full fill while only `mfill` was delivered)
cannot recur here: there is no hypothetical anywhere in the N:M sum, every term is
priced off what really landed. No new IOC-specific risk from going to N:M.

**Partial-fill (Op2) — out of scope for v17's N:M capability, kept v16-identical.**
Partial-fill is a different axis: it's about the *buy order itself* being
incrementally consumed across possibly many separate transactions over time (each
partial-fill sigscript hardcodes a single token input at literal index 1), not
about how many sells fund one fill. Conflating "N sells funding one fill" with "this
fill only covers a fraction of the order" compounds the dispatch/state design
significantly for a case the live E2E run never actually needed (`BuySweep`/
`GtcBuyMultiFill` — the reported gap — are both *full*-fill multi-sell shapes).
Recommendation: v17's partial-fill path is a byte-for-byte carryover of v16's
(single hardcoded counterparty input), revisited only if N:M-partial is later a
real product need.

**Cross-pair — unaffected, still excluded, still a separate project.**
`kob/domain/src/spot/matching.rs`'s cross-pair swap routing already excludes v16 buys
(`executor.rs`, noted in Fix 7's residual) because F6's fixed-offset read needs buy
and sell to share a token — cross-pair inherently doesn't. v17's summation doesn't
change that constraint (it's still reading `tii_i`'s sigscript assuming it's a
same-token sell); cross-pair-capable N:M is a distinct follow-on, not a byproduct of
this change.

**Gap found while designing this (must close before shipping, not covered by the
Phase 1 spike): the buyer's own limit-price floor.** v16's fill path has *two*
separate protections: F6 (bounds the matcher's *spread* against the sells' own
prices) and a floor, `output[toi] >= kas_in/pden*pnum` computed from the **buyer's
own** limit price (protects against being filled at a worse-than-limit rate at all,
independent of matcher-skim). The design in §3 only carries F6's shape forward — it
does not yet enforce `sum(tokens_i) >= kas_in/buy_pden*buy_pnum`. Without it, a
matcher could match a buyer's `kas_in` against sells priced worse than the buyer's
stated limit, and the surplus check (which compares `kas_in` to the *sells'* fair
value, not the buyer's limit) would not catch it — a legitimately-priced-per-sell
but limit-violating fill would pass F6 while silently breaking the buy order's basic
semantics. **Phase 2 must add this as a sixth, tx-level check**, alongside the
summed surplus cap. Recommend enforcing it in aggregate
(`sum(tokens_i) >= kas_in/buy_pden*buy_pnum`) rather than per-term, matching the
"batch executes at a blended rate at least as good as the limit" spirit of a sweep —
but this is a policy call that should be made explicitly in Phase 2, not defaulted
silently; the alternative (strict per-term floor) is more conservative and trades off
against matchable liquidity in mixed-price batches.

## 6. (d) Full adversarial test matrix (Phase 2 must implement before shipping)

Legend: **[spike]** = already proven in `nm_buy_spike.rs` (Phase 1); everything else
is a Phase 2 TODO, listed here so it isn't invented ad hoc later.

**Core theft / gaming vectors (the "summing outputs gets gamed" surface):**
1. **[spike]** Duplicate `tii` across two term slots (double-count one sell's
   output) -> rejected by the strict-increasing distinctness check.
2. Duplicate `tii` in a *non-adjacent* pair once `MAX_N > 2` (e.g. slot 1 and slot 3
   collide while slot 2 sits between them) -> the strict-monotonic chain (`tii_1 <
   tii_2 < tii_3`) transitively forbids this too, but needs its own test once the
   real `MAX_N`-slot contract exists (the spike only has 2 slots, so this case
   doesn't structurally exist there yet).
3. `tii_i` points at an input with no `covenant_id` at all (e.g. the fee/change
   input) -> `OpAuthOutputIdx` finds zero `auth_outputs` for it ->
   `InvalidAuthCovOutIndex` -> script errors. Needs a dedicated test (not exercised
   by the spike, which only used real token-sell inputs).
4. `tii_i` points at a genuine covenant input, but of a **different token** ->
   `OpAuthOutputIdx` still resolves (its own auth-output invariant doesn't check
   token identity, only that input-vs-output covenant ids match each other), so this
   is caught only by the explicit `OpInputCovenantId(tii_i) == tcid` check — needs a
   dedicated adversarial test substituting a second token's sell as a term.
5. Attacker attempts to supply a free `toi_i` disconnected from `tii_i` (the v16-style
   attack) -> structurally impossible in this design (there is no `toi` sigscript
   field at all, only `tii`; `toi` is always derived) — worth a test that confirms
   the *sigscript shape itself* has no such field, i.e. a negative parse-level test,
   not just a script-execution test.
6. **[spike]** Attacker's `tii` is honest and distinct, but the buyer's `kas_in` is
   pushed far above the sum of per-sell fair value within a tight `mmfee_bps` ->
   over-cap sweep rejected.
7. Attacker under-delivers to the buyer: one term's `toi_i` is a legitimate,
   correctly-priced, correctly-authorized output, but its SPK is NOT the buyer's ->
   rejected by the per-term buyer-SPK check. Needs a dedicated test (not covered by
   the spike, which always used the honest buyer SPK).
8. Attacker inflates one term's *value* beyond what that sell's own token_in
   justifies (relies on the sell's own F4 being `>=` not `==`) -> bounded by the
   sell's own script, pre-existing v16 behavior, not new to N:M; still worth a
   regression test showing the buy side doesn't add any NEW exposure here.
9. Per-sell F4 still rejects aggregate-drain in the N:M context specifically: extend
   `sell_f4_shared_output_drain_rejected_honest_passes` (already proven for the
   *sell* side alone) to the full N:M tx shape — N sells, one authorized output
   missing/redirected -> that sell's own script fails AND (if the buy script
   references it as a term) the buy script also fails via the SPK/amount checks.
10. Wrong price via a forged sell sigscript -> structurally impossible (P2SH commits
    the sell's redeemScript bytes, including the price fields the substr reads;
    forging them invalidates that sell input's own spend) — a test should still
    demonstrate the sell input itself fails when its sigscript's committed
    redeemScript doesn't match its UTXO's P2SH hash, to document the invariant is
    actually exercised, not merely assumed.
11. **The limit-price floor gap from §5**: sells honestly priced worse than the
    buyer's own limit, still within the `mmfee_bps` spread cap relative to the
    sells' own prices -> must be rejected once the floor check (§5) is added; this
    is the one case where the *design* itself (not just the test) is incomplete
    today, flagged prominently rather than silently deferred.
12. Over-cap N:M sweep via a decoy LOW-priced sell diluting the average (matcher
    picks one genuinely cheap sell and one at-cap-violating expensive sell, banking
    on the average looking fine) -> already covered by the aggregate surplus math in
    §3 (surplus is summed in absolute KAS, not price-averaged), but deserves an
    explicit mixed-price test distinct from the spike's already-mixed-price honest
    case, specifically probing the boundary.

**Structural / integration:**
13. `N=1` (single sell) through the new v17 dispatch reproduces v16's fill semantics
    bit-for-bit in outcome (not necessarily in bytecode) — a parity test against
    `v16_full_fill_match_scripts_pass`'s scenario.
14. `N=MAX_N` (arity at the compile-time ceiling) succeeds; `N=MAX_N+1` cannot even be
    expressed (sigscript shape has no slot for it) — confirm this fails closed (wrong
    dispatch bucket / parse rejection), not open.
15. IOC + N:M together (§5): honest partial delivery within cap passes; IOC
    partial delivery that pockets kas (mirroring `v16_ioc_partial_delivery_theft_rejected_by_f6`,
    generalized to the sum) is rejected.
16. `bytecode_stable` pin + RS-length collision assertions (§4) — confirm v17's RS
    size (or size range) never collides with any other contract's fixed dispatch
    length in the crate.
17. Cross-pair still correctly excludes v17 buys, same as v16 today (a regression
    test on the existing exclusion, not a new capability).

## 7. Feasibility spike result

`kob/core/tests/nm_buy_spike.rs` implements the fixed-N=2 mechanism from §3 as a
standalone `ScriptBuilder`-built covenant (not touching `order.rs`), reusing the
*real, unmodified* `build_sell_redeem_script` / `build_sell_fill_sigscript_fixed_offset`
for two sells at **different prices** (1/1 and 1/2), and runs all three covenant
inputs (sell1, sell2, buy) through the real post-Toccata `TxScriptEngine`
(`covenants_enabled = true`).

- `nm2_honest_sweep_passes` — 2 distinct sells (30M tokens @1/1, 20M tokens @1/2),
  buyer pays 41M KAS (1M surplus) against a 2000bps cap (8.2M) -> **all three
  covenant scripts PASS.**
- `nm2_duplicate_sell_input_double_count_rejected` — same honest tx shape, but
  `tii_1 = tii_2 = 0` (both terms point at the same sell) -> **buy script FAILS**
  (distinctness check).
- `nm2_over_cap_spread_rejected` — same two honest, distinct sells, but `kas_in` =
  100M against a tight 30bps cap -> **buy script FAILS** (surplus cap).

`cargo test -p kob-core --test nm_buy_spike` = 3 passed, 0 failed. Full regression
(`cargo test -p kob-core --lib --tests`) = 655 (lib) + 3 (this spike) + 2
(prediction_vote_repro) + 12 (toccata_fill_repro) + 6 (x402_borrow_covenant), all
green — nothing in production code was touched, so this is confirmation of no
collateral breakage rather than a meaningful regression signal by itself.

**Go/no-go: go.** The summation-based delivery check verifies correctly in the real
engine, the per-term `OpAuthOutputIdx` binding is provably tighter than v16's
free-parameter `toi`/`coi`, and the double-count and over-cap attacks the task
flagged as the highest-risk gaming surface are both closed by mechanisms that were
hand-derived, then *proven*, not merely asserted. §5 and §6 record the two things
the spike deliberately did **not** cover (the limit-price floor gap, and the full
`MAX_N`-slot conditional-arity machinery) so Phase 2 starts from an accurate map of
what's proven versus what's still open, rather than rediscovering them mid-implementation.
