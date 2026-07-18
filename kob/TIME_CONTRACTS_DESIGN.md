# TIME CONTRACTS DESIGN FREEZE — decay limit, TWAP, trailing ratchet
# (ADDITIVE contracts alongside the frozen v18 generation — NO generation bump)

Status: design frozen 2026-07-17. Stage A landed (`45ff9cc`); LIMITS
re-freeze landed (`317f163` — MAX_N=32 / owner n_max+batch_max / ring 8;
voids the prior live proofs of the six changed contracts, re-proof owed in
Stage D); Stage B planners landed (`8d1c83e`); Stage C (engine+cli, incl.
the addenda C-a/C-b/C-c) landed (`9ba03e8`). **Stage D (live E2E,
recorded as "Stage-G" in `E2E_LIVE_RESULTS.md`) substantially landed
2026-07-18: RT-1/CP-3/RT-3 all SETTLED LIVE on testnet-10** (script-units
budget bug found + fixed + permanently regression-tested, see
`kob/domain/tests/budget_limited_repro.rs`); **RT-2 (adversarial set) and
the competing-matcher stretch goal remain DEFERRED** (unit-proven against
the real engine already; live demonstration needs bespoke tooling not yet
built — see `E2E_LIVE_RESULTS.md`'s "Canary readiness status" handoff
section, updated 2026-07-18, for the full current picture and next-session
resume point). Stage E (doc/final: E2E_MATRIX.md rows, README touch-ups,
this stamp) is still open beyond what this update covers.
Base: v18 single-generation spot (see `V18_DESIGN.md`), HEAD `bc07c18f`
(2026-07-18; was `b37c590` at design-freeze time).
History: this file was briefly `V19_TIME_DESIGN.md` (a generation-bump
packaging); superseded same day by MK directive — **v18 stays frozen and
shipping, `SPOT_GENERATION` stays 18**, and the three features ship as four
ADDITIVE sibling contracts with their own RS-length parse arms:

- `decay_sell` — Dutch sell (ask decays with tx lock_time)
- `decay_buy` — rising bid (the buy-side variant SURVIVES the soundness
  argument, §2.1, so it ships)
- `twap_sell` — rate-limited sell (consensus CSV clock)
- `ratchet_oco` — OCO sell with a permissionless trailing-SL ratchet branch

All adversarial content of the original round stands unchanged: the verdicts,
the CSV-clock redesign of TWAP, the ratchet guards G1–G4, the R9 positivity
guards, and the canonical-shape sibling checks. Only the packaging layer
(state layouts, sizes, collision table, proof plan, stages) is reworked.

Verdicts (summary, unchanged):

| Contract | Verdict | Crux resolution |
|---|---|---|
| decay_sell / decay_buy | **SOUND** | consensus `acceptance-DAA > L` makes understating L self-defeating and overstating L unminable; L=0 and unix-ms-type L both collapse to the worst-for-taker end of the schedule by construction |
| twap_sell | **SOUND after redesign** — the originally specified `last_fill_daa := L` splice is **UNSOUND** (clock-lag burst, §3.2); frozen design replaces the stored clock with the consensus UTXO-age clock (`CSV`), which is strictly stronger and deletes the field | the residual UTXO's creation DAA *is* the true last-fill time; `check_sequence_lock` makes it unforgeable |
| ratchet_oco | **CONDITIONAL — ship only with the four mandatory guards** (§4.5); grief tree has no pecuniary leaf, the binding leaf is execution-probability grief equivalent to honest gap-risk | fake prints cannot be distinguished from genuine ones in a no-oracle system; the guards force fake cost up to genuine-self-trade cost and bound the blast radius |

---

## 0. Packaging decision (MK directive, rationale recorded)

**Additive sibling contracts, not embedded fields.** The v18 attestation ABI
is a genuine cross-contract interface, and it is what makes this packaging
free:

1. A v18 buy authenticates a swept counterparty ONLY by
   `OpInputCovenantId(tii) == tcid`, takes delivery ONLY from that input's
   auth slot 0 (`OpAuthOutputIdx(tii,0)` → SPK/amount checks), and reads its
   price ONLY at the canonical sigscript offsets [3..11)/[12..20). It never
   parses the counterparty RS and never depends on its length. Therefore an
   **unchanged v18 buy sweeps every new sell variant** — decay_sell,
   twap_sell, and both ratchet_oco fill branches — in the same tx shapes it
   sweeps plain sells today.
2. Symmetrically, an **unchanged v18 sell settles against a decay_buy**: a
   sell never reads the buy at all (the buy enforces its own floor/cap); the
   only coupling is the sell's own attestation, which the decay_buy consumes
   through the same offsets.
3. Embedding the features in the plain contracts (the superseded plan) would
   have taxed EVERY plain order ≈ +50% sell RS / +13% buy RS, changed every
   RS length, and voided the proven 15-form live matrix (RS-length dispatch
   ⇒ full re-freeze + full re-proof). Additive packaging keeps v18 frozen
   and shipping, prices the features only on the orders that use them, and
   shrinks the live-proof burden to the new forms plus one composition proof
   per variant (§6).

Consequences of standalone packaging:
- The `dslope=0 / twin=0 / rstep=0` "feature off" conventions are DELETED.
  Each new contract's builder REQUIRES its feature live (`dslope ≥ 1`,
  `twin ≥ 50`, `rstep ≥ 1`); "plain behavior" = deploy the v18 contract.
  This also deletes the in-body feature-off guard opcodes.
- `SPOT_GENERATION` stays 18 and is untouched; the new contracts are
  contract KINDS (own builders, own parse arms, own RS lengths); `version`
  u8 continues to report 18 wherever surfaced.
- Stage A carries a **v18 zero-diff pin**: a test asserting the four v18
  spot bodies and their `*_EXPECTED_LEN`/`*_RS_SIZE` constants are
  byte-identical before/after this work lands.

---

## 1. Consensus time toolbox (facts, with receipts)

Everything below was re-verified against this tree, not quoted from memory.

**T1 — tx.lock_time semantics** (`consensus/src/processes/transaction_validator/tx_validation_in_header_context.rs:56-93`):
- `lock_time == 0` → type *Finalized*: no time constraint at all.
- `0 < lock_time < LOCK_TIME_THRESHOLD (= 500_000_000_000)` → DAA type: the tx
  is acceptable only in a block whose DAA score satisfies
  `lock_time < ctx_daa_score`, i.e. **acceptance-DAA ≥ L+1 > L**. This is the
  one-sided floor every design below leans on.
- `lock_time ≥ threshold` → unix-ms type (median-time compared instead).
- Escape hatch: all inputs with `sequence == u64::MAX` — but CLTV (T2) and CSV
  (T3) both reject that state, so covenant branches that use them are safe.

**T2 — OpCheckLockTimeVerify 0xb0** (`crypto/txscript/src/opcodes/mod.rs:1014`):
pops S (≤8B, zero-padded, NOT scriptnum-minimal), requires *type match*
(S and `tx.lock_time` on the same side of the threshold), `S ≤ tx.lock_time`,
and `input.sequence != MAX`. Kaspa CLTV **consumes** its operand (unlike BTC).

**T3 — OpCheckSequenceVerify 0xb1 + consensus relative lock**
(`opcodes/mod.rs:1066`, `tx_validation_in_utxo_context.rs:136`): the opcode
requires `stack_seq & MASK ≤ input.sequence & MASK` (MASK = low 32 bits,
disabled bit 63 rejected); consensus *independently* requires for every input
without the disabled bit: `utxo.block_daa_score + (sequence & MASK) - 1 <
pov_daa_score`. Together: **`Δ CSV` proves the spent UTXO is ≥ Δ DAA old in
real, consensus-verified time.** This is exactly the mechanism behind the
already-live-proven `50 CSV` exposure delay on every v18 fill branch. The
spender cannot weaken it: a smaller sequence fails the opcode, a larger one
only waits longer.

**T4 — OpTxInputDaaScore 0xc0** (`opcodes/mod.rs:1282`): pushes the *creation*
DAA score of any input's UTXO. A second consensus-truthful clock (absolute
form of T3). Post-Toccata (`covenants_enabled`) only — fine, all of KOB is.

**T5 — OpTxLockTime 0xb5** (`opcodes/mod.rs:1137`): pushes `tx.lock_time` as
i64. NOTE: values ≥ 2^63 arrive negative; §2 shows why that is harmless here.

**T6 — numeric encoding** (`data_stack.rs:351-363`, 190-213): post-Toccata,
numeric pops use `enforce_minimal = !covenants_enabled` = **false**, up to 8
bytes. So 8-byte LE state/sigscript pushes with high zero padding feed
arithmetic ops directly (this is why all existing KOB math works). Corollary:
a *computed* value (minimal encoding) compared against an 8-byte *pushed*
value must use `OpNumEqual`, never `OpEqual` (byte comparison) — this bites
the decay attestation check (§2.5) and the ratchet splice (§4.4).

**T7 — arithmetic is checked** (`opcodes/mod.rs:755-800`): OpAdd/OpSub/OpMul
error on i64 overflow, OpDiv/OpMod on zero divisor. Overflow = script failure
= fail-closed. OpMin 0xa3 / OpMax 0xa4 / OpWithin 0xa5 exist.

**T8 — splice machinery** (post-Toccata): OpCat 0x7e, OpSubstr 0x7f, OpSize
0x82 all gated on `covenants_enabled` and available; element limit 1MB,
sigscript limit 250KB — a ~700B RS reconstructed on-stack is nowhere near any
limit. The proven in-repo template is the **DCA D&R block**
(`kob/core/src/contract/spot/dca.rs`, `DCA_ORDER_BODY`): old_rs authenticity
via `blake2b(old_rs)` wrapped into a P2SH SPK (`[0x00,0x00,0xaa,0x20] || hash
|| [0x87]`, OpCat) compared to `OpTxInputSpk(self)`; prefix/suffix byte
equality around a mutable window; field arithmetic on `OpSubstr`-extracted 8B
values via numeric ops; continuation output SPK == P2SH(new_rs).

**T9 — provenance correction**: v18 CANCEL-MARK does **not** splice. It is an
owner-signature branch (`emit_sell_cancel(mark=true)` checks `cpend==0`, ohash
and the signature, and verifies *no* outputs); the cpend 0→1 continuation is
built by the owner's own tx and trusted because only the owner can execute the
branch — a mis-built continuation only hurts its owner. The ratchet (§4) is
*permissionless*, so it cannot use that trust model and must use the DCA-style
covenant-enforced splice (T8). TWAP, after the §3.2 redesign, needs no splice
at all.

---

## 2. `decay_sell` / `decay_buy` — Dutch orders — **SOUND**

### 2.1 Semantics

The price numerator is a function of `tx.lock_time` L:

```
eff       = min( max(L, t0), t_end )          // clamp, handles L=0 and L<t0
pnum_eff  = pnum − dslope × (eff − t0)        // dslope ≥ 1, integer, exact
```

with build-time invariants `t0 < t_end < LOCK_TIME_THRESHOLD` and
`dslope × (t_end − t0) ≤ pnum − 1` (so `pnum_eff ≥ p_floor ≥ 1`; the floor is
derived, not stored).

Direction is HARDWIRED per side, because only one direction is enforceable:

- **decay_sell (Dutch)**: `pnum/pden` = KAS per token; `pnum_eff` falls with
  time ⇒ ask price decays. A *rising* sell schedule is unenforceable: the
  taker would understate L to buy at the old cheap price, and understating is
  always minable (T1 is a one-sided floor). Rejected as a feature, documented.
- **decay_buy (rising bid)**: in the buy, `pnum/pden` = tokens per KAS (floor
  is `token_sum ≥ kas_in/pden×pnum`), so a rising bid = *fewer* tokens
  demanded per KAS = `pnum_eff` falls — the SAME formula. A falling bid is
  unenforceable for the mirrored reason. One formula, both sides — this is
  the soundness argument the buy-side variant survives on, hence it ships.

**Soundness argument (to be reproduced in code comments verbatim):** the
schedule f(L) is monotone in the taker-favorable direction as L grows.
Consensus (T1) guarantees `actual acceptance DAA > L`. Therefore:
(a) a taker understating L executes at f(L) which is *worse for the taker*
than f(actual) — self-defeating, allowed, harmless; (b) a taker overstating L
makes the tx unminable until DAA > L, at which point f(L) is exactly the
maker's declared price for that time; (c) hence the executed price always lies
inside the maker's declared envelope [f(actual), f(t0)] — the maker's schedule
can never be violated, only under-used by lazy takers. `L=0` (Finalized type)
carries no consensus time information, and the clamp maps it to `eff = t0` =
the worst-for-taker end — the required default, obtained for free.
A unix-ms-type L (≥ 5e11) would fast-forward the schedule to the floor while
being minable immediately — killed by an explicit in-branch type guard
`L < 500_000_000_000` (§2.5 line D1). An L ≥ 2^63 arrives negative from
OpTxLockTime (T5): it passes the `<` guard but clamps to t0 (worst-for-taker)
and is unminable for ~292M years anyway — fail-safe both ways.

**Rounding, decided adversarially:** f itself is division-free (additive in
integer DAA steps) — exact, no rounding point exists. The only rounding in the
fill path stays the v18 fill math (`token_in × pnum_eff / pden` floor-rounded
etc.), deliberately unchanged: the CLTV floor already forces the taker onto
`f(L) with L ≤ actual`, i.e. the *older = taker-unfavorable* point of the
schedule, which is the taker-unfavorable rounding of "price at execution time"
at DAA granularity. Changing the intra-fill division direction would break
buy/sell fair_sum parity and re-open v18 proofs for zero adversarial gain.

### 2.2 State layout delta (standalone contracts)

New fields are PREPENDED to the v18 state (pushed first = deepest on stack),
so every v18 body depth reference [0..N) survives inside the new bodies; only
dispatch roll depth, cleanup counts and the new checks change.

```
decay_sell state (172B = 27 + v18 sell 145):
  [0x08][dslope 8B] [0x08][t0 8B] [0x08][t_end 8B]
  ‖ v18 sell 145B layout unchanged ([0x20 otspkh] … [0x08 expiry])
stack at body start (12): expiry(0) cpend(1) mmfee(2) sspkh(3) ohash(4)
  mfill(5) pden(6) pnum(7) otspkh(8) t_end(9) t0(10) dslope(11)
  selector at 12 (v18 sell: 9)

decay_buy state (205B = 27 + v18 buy 178): same three fields prepended.
stack at body start (13): expiry(0) … tcid(8) okspkh(9) t_end(10) t0(11)
  dslope(12); selector at 13 (v18 buy: 10)
```
Builder validation: `dslope ≥ 1 ∧ t0 < t_end < LOCK_TIME_THRESHOLD ∧
dslope×(t_end−t0) ≤ pnum−1`.

### 2.3 Branch/selector allocation

Selector maps identical to the v18 parents (sell: 0=CANCEL 1=FILL 2=PARTIAL
3=CANCEL-MARK 4=EXPIRE 5=IOC; buy: 0/1/2/3/4/5). Decay lives inside the
fill-family branches (sell: 1/5/2; buy: 1/5/2), each computing `pnum_eff`
once at branch entry and using it wherever v18 used `pnum`.
CANCEL/CANCEL-MARK/EXPIRE are semantics-identical to v18 (owner paths never
price).

### 2.4 (reserved — the embedded-fields packaging that previously lived here
was superseded by §0)

### 2.5 Verification logic (opcode-level, decay_sell FILL shown; IOC/PARTIAL
and the decay_buy floors are the same block at shifted depths, pinned Stage A)

decay_sell FILL entry after time-gate + `50 CSV` + F5, base(13):
`mmfee(0) sspkh(1) ohash(2) mfill(3) pden(4) pnum(5) otspkh(6) t_end(7)
t0(8) dslope(9) pden_att(10) pnum_att(11) koi(12)`

```
D1  TXLOCKTIME DUP                    // L
    <push 5B: 500_000_000_000> LT VERIFY  // type guard: DAA-domain only
D2  e_pick(9)  MAX                    // max(L, t0)        (t0 @8, +1 for L)
    e_pick(8)  MIN                    // eff = min(…,t_end)(t_end @7, +1)
    e_pick(9)  SUB                    // eff − t0
    e_pick(10) MUL                    // dec = (eff−t0)×dslope  (no overflow:
                                      //  ≤ pnum−1 by build invariant, T7)
    e_pick(6)  SWAP SUB               // pnum_eff = pnum − dec  (pnum @5, +1)
                                      // pnum_eff on top, base(13) below
D3  DUP e_pick(13) NUMEQUAL VERIFY    // ATTESTATION: pnum_att == pnum_eff
                                      // (NUMEQUAL, not EQUAL — T6: computed
                                      //  vs 8B-padded push)
D4  e_pick(11) e_pick(6) EQUAL VERIFY // pden_att == pden (both 8B pushes)
D5  … v18 price math with pnum_eff in place of the pnum pick …
    expected_kas = token_in × pnum_eff / pden ; ≥ mfill ; KAS out ≥ expected ;
    F2 sspkh ; F4 Fix-3 — all byte-identical to v18 except the operand source.
```
Estimated cost: ≈ 40B per fill branch (×3 sell, ×2 buy; the feature-off
IF/ELSE of the superseded packaging is gone — the builder guarantees
dslope ≥ 1).

### 2.6 Sigscript layout + attestation (offsets MUST NOT move — they don't)

```
decay_sell fill:  [0x01,koi][0x08 pnum_eff(L) 8LE][0x08 pden 8LE][Op1][RS]
```
Identical SHAPE to the v18 sell fill; only the VALUE at [3..11) changes: the
builder writes `pnum_eff(L)` for the L the matcher will set on the tx. pnum
stays at [3..11), pden at [12..20) — canonical offsets stable for every
sweep-eligible sell-side branch, which is precisely what lets an unchanged
v18 buy sweep this contract (§0). **Builder pitfall (freeze rule):** the
effective pair must NOT be gcd-normalized (`push_attested_prefix` normalizes
today — decayed attestations need the raw `(pnum_eff, pden)` or D3/D4 fail).
New builder `build_decay_sell_fill_sigscript(koi, pnum_eff, pden, rs)`; same
for IOC/partial.

**Which price is attested when a decay_sell is swept by an unchanged v18
buy: f(L) at settle time, enforced twice.** The decay_sell body forces
`pnum_att == pnum_eff(L)` (D3). The v18 buy's PASS 2 fair_sum reads ONLY
sigscript [3..11)/[12..20) of the covenant-authenticated tii (v18 mechanism,
untouched) — so `fair_kas_i = tokens_i / pden_att_i × pnum_att_i`
automatically consumes `f_i(L)` for each decay_sell in the sweep. One tx has
one lock_time, so every schedule in the sweep is evaluated at the same L —
internally consistent by construction. A decay_buy's own GTC floor uses its
own `pnum_eff` at the same L while its fair-cap consumes the (plain or
decayed) sells' attested prices — no new cross-contract reads anywhere.

### 2.7 Planner / engine / CLI implications

- Planner (`batch.rs`/`matching.rs`): decay variants enter the existing sweep
  planner as ordinary members (ABI, §0); the only new logic is price
  feasibility at the L the tx will carry. Policy: L := current tip DAA score
  (maximizes decay in the taker's favor; minable next block since
  acceptance > L). Batching constraint solver: a tx's single lock_time must
  satisfy every member (fill time-gates want `L < expiry_i` for expiry≠0
  members; an auto-expire branch wants `L ≥ expiry_j`) — if the intersection
  is empty, split into separate txs (auto-expire already runs separately).
- Engine executor: pass L into the sigscript builders; recompute `pnum_eff`
  with the exact integer formula (ONE shared helper must generate builder
  values, covenant emitter constants and test vectors).
- Scanner/API: new parse arms (§5); expose `effective_price(now)` next to the
  static price; order-book sorting uses f(tip), refreshed per block.
- CLI: `order create-decay --side sell|buy --slope --t0 --until`; display
  shows `price now / floor / t_end`.

### 2.8 Adversarial matrix (NM_BUY_DESIGN §6 style)

1. **Understated L** (taker wants yesterday's schedule point): executes at
   f(L) ≤ taker-favorability of f(actual) — self-defeating by monotonicity;
   allowed. Test: fill with L = t0 at actual ≫ t0 pays the start price.
2. **Overstated L** (taker wants tomorrow's price): consensus `NotFinalized`
   until DAA > L (T1); at that time f(L) is the declared price. Live-proof
   form DK-3 submits early and observes rejection.
3. **L = 0**: Finalized type, no consensus floor — but clamp ⇒ eff = t0 ⇒
   start price = worst-for-taker. Explicit convention, unit + live test.
4. **Unix-ms-type L** (≥ 5e11, minable now, huge in DAA units — the schedule
   fast-forward attack): killed by D1 type guard; script errors. This is the
   one genuinely dangerous vector; it gets a dedicated adversarial unit test
   and a live rejection form.
5. **L ≥ 2^63** (negative i64 from T5): passes D1's `<`, clamps to t0 (worst
   for taker), and the tx is unminable for centuries — doubly harmless.
6. **Stale-price attestation** (matcher attests pnum instead of pnum_eff, or
   yesterday's pnum_eff): D3 NUMEQUAL fails — reject. Mirror of the v18
   attestation-mismatch tests, per branch (fill/IOC/partial).
7. **Overflow grind** (adversarial L to blow up MUL): clamp (D2) runs BEFORE
   MUL, so the multiplicand is ≤ t_end−t0 and the product ≤ pnum−1 by the
   build invariant — overflow unreachable on a well-formed RS; hand-rolled
   RS with violating fields only mispays its own deployer (fail-closed T7).
8. **Mixed sweep, one L**: matcher picks L to minimize total payment across
   plain v18 + decay sells — each f_i is independently ≤-capped by its own
   schedule at actual time; the v18 buy's absolute-KAS surplus cap is
   computed from the same attested values the sells enforce — no averaging
   hole. (This is also composition proof CP-1.)
9. **Expiry dodge via understated L** (fill with L < expiry ≤ actual): v18
   time-gate semantics unchanged (expiry hard-stops only the EXPIRE race);
   for decay sells an understated L additionally *costs* the taker (worse
   price) — strictly less attractive than in v18. Documented, not new.
10. **Residual re-pricing** (partial then later fills): each event
    re-evaluates f at ITS tx's L — a taker cannot lock an old price into the
    residual; the residual is byte-identical state, the schedule is absolute
    (t0/t_end in DAA), so continuation pricing is automatic.

---

## 3. `twap_sell` — rate-limited execution — **SOUND after redesign**
(the specified stored-clock design is UNSOUND; both are given, one is frozen)

### 3.1 The specified design (for the record) and its splice

As originally tasked: state `{window_daa Δ, max_fill_per_window,
last_fill_daa}`; the partial-fill branch additionally requires
`tx.lock_time ≥ last_fill_daa + Δ` (push last, push Δ, ADD, CLTV — T2 makes
this a valid computed-operand use) and `fill ≤ max_per_window`; continuation
output = RS with `last_fill_daa := L` spliced in DCA style (T8):
prefix/suffix byte-equality around the 8B window at the field's RS offset,
`new_field == L` via OpSubstr + NUMEQUAL against TXLOCKTIME, old_rs
authenticity via blake2b→P2SH == OpTxInputSpk(self), continuation SPK ==
P2SH(new_rs), value ≥ token_in − fta.

### 3.2 The clock-lag crux: 3.1 is UNSOUND

CLTV is a one-sided floor (T1/T2): L may LAG real time arbitrarily. Lagging L
does not merely "widen the wait" — it breaks the limiter:

> Deploy at real DAA R0 with `last = R0`, Δ = 1000, order unfilled for 10
> windows. At real R0+10000 a matcher submits fill#1 with L = R0+1000
> (≤ actual ⇒ minable NOW), splicing `last := R0+1000`; fill#2 with
> L = R0+2000 in the next block; … ten maximal fills land within ~10 real DAA.
> `last := L` records the *claimed* clock, so the whole idle allowance is
> bankable and dumpable in one burst — exactly what a TWAP exists to prevent.

Fix candidates, adversarially evaluated:
- **Staleness bound** (`require L ≥ now − B`): needs a trustworthy "now" ABOVE
  L, which no opcode gives directly (CLTV floors it from below only); any
  matcher-supplied reference input can be pre-aged. Within-bound bursts of
  B/Δ windows survive anyway. Dead end.
- **`last := max(L, …)`**: max with what? With the previous `last`, the burst
  is unchanged (the recorded clock still advances Δ per event regardless of
  real time). With the input's real creation DAA (`OpTxInputDaaScore`, T4) it
  works — but then the stored field is provably redundant: the UTXO's own
  creation score IS the true last-fill time.
- **FROZEN FIX — delete the clock; gate on real UTXO age.** Every fill-family
  event on a twap_sell consumes the order UTXO and (for partials) creates the
  residual continuation; that residual's `block_daa_score` is the REAL
  acceptance time of the previous event, recorded by consensus itself. Gate:
  `twin CSV` (T3). Then consecutive events on one order lineage are ≥ twin
  REAL DAA apart — unforgeable, burst-free (age resets to 0 at every fill),
  no splice, no stored field, two opcodes per branch. The absolute-form
  equivalent (`TXINPUTINDEX OpTxInputDaaScore twin ADD CLTV`, T4) is kept in
  reserve in case a branch ever needs lock_time-decoupling — but CSV uses the
  per-input sequence field, so it composes with decay's lock_time use and
  with multi-order batching with no interaction at all, and it is the exact
  pattern already live-proven as the v18 `50 CSV` exposure delay. CSV chosen.

Consequence: **`last_fill_daa` is REJECTED from the state, not deferred** —
`{twin, mpw}` only (18B), and twap_sell needs no splice machinery at all.

### 3.3 Frozen TWAP semantics

`twin` = DAA window, `mpw` = max tokens per event; applied to ALL fill-family
branches (full FILL and IOC included — otherwise a matcher bypasses the
limiter by full-filling; the "last chunk" must also obey `token_in ≤ mpw`):

```
twin CSV                      // real age of this order UTXO ≥ twin (T3)
vol ≤ mpw                     // vol: FILL = token_in ; IOC/PARTIAL = fta
```
Owner branches (CANCEL/CANCEL-MARK/EXPIRE) are NOT gated — the owner's escape
is never rate-limited.

Rate guarantee: fills on one lineage are ≥ twin apart in real acceptance DAA
and each moves ≤ mpw ⇒ long-run rate ≤ mpw/twin, worst-case burst = mpw. The
first fill also waits twin from DEPLOY (the deploy UTXO's age gates it) —
accepted and documented; a "grace first window" variant was rejected (it
would need a stored flag = the splice we just deleted).

(A `twap_buy` sibling is NOT in this freeze — non-goal §8; the ABI makes it
additive later if wanted.)

### 3.4 State delta, builder validation, opcode sketch

```
twap_sell state (163B = 18 + v18 sell 145):
  [0x08][twin 8B] [0x08][mpw 8B]  ‖  v18 sell 145B layout unchanged
stack at body start (11): expiry(0) … otspkh(8) mpw(9) twin(10)
  selector at 11 (v18 sell: 9)
```
Builder: `50 ≤ twin ≤ 0xFFFF_FFFF` (CSV 32-bit mask, T3) `∧ mpw ≥ 1 ∧
mpw×pnum/pden ≥ mfill` (else no event can satisfy both floors).

Sketch (FILL, base(12) after time-gate/CSV50/F5: `mmfee(0) sspkh(1) ohash(2)
mfill(3) pden(4) pnum(5) otspkh(6) mpw(7) twin(8) pden_att(9) pnum_att(10)
koi(11)`; stack-neutral):
```
W1  e_pick(8) CSV                    // twin; consensus real-age gate (T3)
W2  TXINPUTINDEX TXINPUTAMOUNT       // vol = token_in   (FILL form)
    e_pick(8) SWAP                   // mpw (7 + 1 for vol) ; [mpw, vol]
    GTE VERIFY                       // mpw ≥ vol
```
(IOC/PARTIAL replace W2's amount with the fta value already on stack;
≈ 10–14B per branch.) Engine must set `input.sequence = max(50, twin)` on
twap_sell fill inputs (it already sets ≥ 50 for the exposure delay).

### 3.5 Planner / engine / CLI

- Planner: a twap_sell is fill-eligible iff `tip_daa ≥ utxo.block_daa_score
  + twin` (scanner already has creation scores); planned vol capped at mpw.
  Sweep membership: a twap_sell inside a v18 buy's N:M batch is legal (its
  own CSV gates only itself; the batch tx satisfies it by setting that
  input's sequence) — composition proof CP-2.
- Engine: sequence wiring (above); scheduler may queue the next event at
  `creation + twin` — a natural fit for the existing auto-expire loop.
- CLI: `order create-twap --window --max-per-window`; book display shows
  next-eligible DAA.

### 3.6 Adversarial matrix

1. **Clock-lag burst** (the crux, §3.2): dead by design — there is no stored
   clock to lag. Regression test reproduces the 10-window burst against a
   simulated 3.1 contract (documentation test) and proves the CSV design
   rejects fill#2 (`SequenceLockConditionsAreNotMet`).
2. **Sequence games**: seq < twin → CSV opcode fails; seq ≥ twin → consensus
   demands ≥ seq real age (longer wait); disabled bit 63 → CSV rejects;
   seq = MAX → disabled bit set → CSV rejects. No degree of freedom (T3).
3. **Dust-grind**: per-event `vol ≥` the existing `mfill` floor (v18,
   unchanged) blocks dust; per-event `vol ≤ mpw` + real spacing blocks
   splitting one window's allowance into many events — k events need k×twin
   real DAA, so grinding cannot exceed the declared rate. Boundary tests at
   vol = mfill = mpw.
4. **Dual same-RS UTXO residual sharing**: the per-input Fix-3 auth binding
   (v18 sell partial/IOC F4, carried unchanged into this body) isolates each
   input's residual. Regression pin re-run on the new RS.
5. **Full-fill bypass**: FILL/IOC are gated identically (§3.3) — pinned by an
   adversarial test (full fill with token_in > mpw rejected).
6. **Owner lock-out grief**: not possible — owner branches skip the gate.
7. **Mass cost**: +18B state, ≈ +12B per fill branch; a rejected early-CSV tx
   dies in consensus validation before script execution (cheap for the
   network). Mass measurements themselves belong to the concurrent
   batch-mass workstream and are out of scope here.

---

## 4. `ratchet_oco` — trailing ratchet OCO — **CONDITIONAL: ship only with
the four mandatory guards of §4.5** (no pecuniary grief leaf remains;
residual = execution-probability grief equal to honest gap-risk)

### 4.1 Semantics

Permissionless RATCHET branch on an otherwise-v18 OCO sell: anyone who can
point at a genuine same-token settle *in the same tx* at attested price P may
tighten the SL one step:

```
trigger:   P ≥ (pnum_sl + rstep + rgap) / pden_sl        (cross-multiplied)
mutation:  pnum_sl := pnum_sl + rstep                     (additive, exact)
```
`rstep` (pnum_sl units per ratchet) and `rgap` (required print premium over
the POST-ratchet stop = the trailing distance) are state constants; steps are
additive on the SAME pden_sl, so iterated ratchets have zero rounding drift
(a multiplicative bps step was rejected: iterated ÷10000 rounding drifts and
needs a rounding-direction proof per step). TP is NOT moved (trailing-stop
semantics; also §4.5 guard G3 needs a fixed ceiling). One step per spend by
construction (the splice enforces `new == old + rstep` exactly). Direction is
one-way by construction (rstep ≥ 1 enforced in-branch; there is no branch
that decreases pnum_sl). Everything else byte-preserved.

### 4.2 State layout delta

```
ratchet_oco state (208B = 36 + v18 OCO 172), new fields PREPENDED:
  [0x08][rstep 8B] [0x08][rgap 8B] [0x08][rwin 8B] [0x08][mrv 8B]
  ‖ v18 OCO 172B layout unchanged
stack at body start (16): expiry(0) … otspkh(11) mrv(12) rwin(13) rgap(14)
  rstep(15); selector at 16 (v18 OCO: 12)
RS byte offsets (all v18 OCO offsets +36): pnum_sl VALUE = [97..105) (its
  0x08 prefix at 96 is inside the fixed prefix), pden_sl = [106..114),
  pnum_tp = [70..78), cpend at 198, expiry value [200..208).
```
Builder: `rstep ≥ 1 ∧ 50 ≤ rwin ≤ 0xFFFF_FFFF ∧ mrv ≥ 1 ∧
(pnum_sl + rstep)×pden_tp < pnum_tp×pden_sl` (initial headroom sanity).

### 4.3 Branch/selector allocation + sigscript

Selector **3** (free in the v18 OCO map: 0=CANCEL, 1=TP, 2=SL, 4=EXPIRE; OCO
has no cancel-mark). sigOpCount = 0 (permissionless).

```
ratchet sigscript: [pushData(new_rs)][pushData(old_rs)][sii][Op3][pushData(RS)]
```
new_rs FIRST is deliberate: its pushData opcode for a ~700B RS is 0x4d, so a
ratchet sigscript can never begin with 0x01 and can never impersonate a
canonical settle when *itself* named as a sibling (see matrix L3 — this
closes the nested-ratchet fake for every sii encoding, including the
`push_index` 17..127 form `[0x01, sii]` which would otherwise collide with
the canonical prefix's first byte).

TP/SL/cancel/expire sigscripts are byte-identical in shape to v18's ⇒ the
canonical attestation offsets of the sweep-eligible branches do not move,
and an unchanged v18 buy sweeps this contract's TP and SL branches
(composition proof CP-3).

### 4.4 Verification logic (opcode-level)

Entry (selector consumed): `expiry(0) cpend(1) mmfee(2) sspkh(3) ohash(4)
mfill_sl(5) pden_sl(6) pnum_sl(7) mfill_tp(8) pden_tp(9) pnum_tp(10)
otspkh(11) mrv(12) rwin(13) rgap(14) rstep(15) sii(16) old_rs(17) new_rs(18)`
(depths shown at entry; the Stage-A implementation pins every intermediate
depth exactly as order.rs does).

```
R1  hand-roll guard: rstep ≥ 1              (builder enforces it; in-branch
                                             check kept as defense vs
                                             hand-rolled RS — 3B)
R2  F5:          cpend == 0                 (a deploy-marked OCO can't
                                             ratchet)
R3  time-gate:   v18 expiry gate, stack-neutral (parity with fill family;
                 ratchet never EXTENDS life: expiry bytes are in the fixed
                 suffix, preserved)
R4  rate:        rwin CSV                   (T3; rwin ≥ 50 at build ⇒ also
                                             covers the exposure delay)
R5  sii != self: sii TXINPUTINDEX NUMEQUAL OpNot VERIFY
R6  same token:  OpInputCovenantId(sii) == OpInputCovenantId(self)
                 (the OCO carries no tcid field; self-reference IS the tcid —
                  same sii-safe discipline as fills: authenticate the index
                  by covenant id BEFORE trusting anything read from it; a
                  non-covenant input yields ZERO_HASH (`opcodes/mod.rs:1507`)
                  ≠ own id ⇒ fail-closed)
R7  canonical-shape guard on the sibling's sigscript (OpTxInputScriptSigSubstr):
      substr(sii,0,1)  == 0x01     substr(sii,2,3)  == 0x08
      substr(sii,11,12) == 0x08
    ⇒ the sibling's sigscript is canonical-attestation-shaped; combined with
      R6, the ONLY tx-valid spends with this shape are fill-family branches
      whose OWN covenant enforces `attested == executing price` (v18 sell
      fill/IOC/partial, v18 OCO TP/SL, and the new decay_sell/twap_sell fill
      families — all valid print sources by construction; token_unit
      transfer (0x41), cancels (0x41/0x20), expire (0x54), ratchet (0x4d)
      are all killed by byte 0)
R8  print read (canonical offsets, fixed): pnum_att = substr(sii,3,11),
      pden_att = substr(sii,12,20)
R9  positivity guards: pnum_att ≥ 1, pden_att ≥ 1
      (WITHOUT these, a hand-rolled sibling sell whose 8th price byte has the
       high bit set makes pden_att negative as i64 ⇒ the R11 cross-mul RHS
       goes negative ⇒ trigger passes vacuously — found during this design
       round, mandatory)
R10 volume:  vol = token_in(sii);  if substr(sii,20,21) == 0x08 then
      vol = min(vol, num(substr(sii,21,29)))          // IOC/partial: fta
      require vol ≥ mrv
R11 trigger: pnum_att × pden_sl ≥ (pnum_sl + rstep + rgap) × pden_att
      (cross-multiplied; overflow ⇒ checked error ⇒ fail-closed, T7)
R12 settle-magnitude re-check: koi = num(substr(sii,1,2));
      OpTxOutputAmount(koi) × pden_att ≥ vol × pnum_att
      (defense-in-depth: for full fills the sibling's own branch enforces
       this; for IOC/partial it re-anchors the KAS leg to the fta volume;
       koi bytes ≥ 0x80 read negative ⇒ OOB ⇒ fail-closed — such siblings
       simply cannot serve as prints, documented)
R13 splice (DCA template, T8; window = pnum_sl value bytes [97..105)):
  a. authenticity: blake2b(old_rs) → [0x00,0x00,0xaa,0x20]‖hash‖[0x87]
       == OpTxInputSpk(self)
  b. prefix:  substr(old,0,97)   == substr(new,0,97)     (byte EQUAL)
  c. suffix:  substr(old,105,size(old)) == substr(new,105,size(new))
       (EQUAL on unequal lengths fails ⇒ new_rs length is pinned = old's;
        no interior push-prefix check needed — the 8B window has none)
  d. field:   num(substr(new,97,105)) == num(substr(old,97,105)) + rstep
       (NUMEQUAL — T6)
  e. travel cap (guard G3): (pnum_sl_old + rstep) × pden_tp < pnum_tp × pden_sl
  f. continuation: ci = OpAuthOutputIdx(self,0)  (Fix-3);
       OpTxOutputSpk(ci) == [0x00,0x00,0xaa,0x20]‖blake2b(new_rs)‖[0x87];
       OpOutputCovenantId(ci) == OpInputCovenantId(self)   (binding kept);
       OpTxOutputAmount(ci) ≥ OpTxInputAmount(self)        (full escrow)
R14 cleanup
```
Estimated branch cost ≈ 250–290B (DCA D&R ≈ 137B + trigger/structure ≈ 90B +
housekeeping); OCO body 225 → ≈ 505B.

### 4.5 Mandatory guards (the CONDITIONAL in the verdict)

- **G1 rate limit**: `rwin CSV` — ≤ 1 ratchet per rwin real DAA per order
  (reuses the TWAP clock mechanism, not a stored one). Bounds grief spam and
  gives the owner ≥ rwin DAA of reaction time per step.
- **G2 volume floor**: `vol ≥ mrv` (R10) + settle-magnitude re-check (R12) —
  a print costs real KAS liquidity proportional to the claimed price × a
  real volume floor.
- **G3 travel cap**: SL may never reach TP (R13e) — total attacker-forced
  displacement is bounded by the owner's own declared TP; the degenerate
  terminal state is "OCO ≈ plain sell at just under TP", never worse.
- **G4 sibling authentication**: R5–R9 exactly as specified (covenant id via
  self-reference, canonical-shape bytes, positivity). Weakening any of these
  reopens a cheap-fake lane (see L2–L4).

Plus a disclosure rule (doc + CLI help): the ratchet schedule is declared
over PRINTS (on-chain settles of this token), not over a "true market price"
— KOB has no market-price concept (V18 note); anyone can be both sides of a
print at the cost of fees.

### 4.6 Adversarial economics — the full grief tree

Notation: owner O holds ratchet_oco(TP, SL, rstep, rgap, rwin, mrv);
attacker A; "schedule" = O's declared mapping prints→stop. Every leaf states
who pays whom. A *pecuniary* loss = O receiving less than the declared floor
for what is taken, or losing custody; opportunity cost is tracked separately.

- **L1. Fake print below trigger** (P < threshold): R11 rejects. A pays a tx
  fee for nothing. No state change.
- **L2. Garbage print** (cancel/expire/token-transfer sibling, signature
  bytes at [3..20)): R7 shape guard rejects (byte 0 is 0x41/0x54/…, never
  0x01). A pays fees. — Without R7 this would have been the cheapest fake:
  cancel-your-own-sell, sig bytes ≈ random ≥ threshold.
- **L3. Nested-ratchet print** (A's second ratchet_oco spent on RATCHET named
  as sibling): its sigscript begins 0x4d (new_rs pushData, §4.3) — R7
  rejects; the `[0x01,sii]` encoding of sii is irrelevant because sii is
  pushed third. For completeness: even if shaped through, R12+R9 force a real
  KAS output ≥ mrv × claimed price — self-trade economics anyway.
- **L4. Negative-encoding print** (hand-rolled sibling RS with high-bit price
  bytes; the sibling's own fill passes vacuously): R9 positivity guards
  reject. Found during this design round; without R9 the trigger passes for
  ANY claimed P.
- **L5. Genuine self-trade print** (A deploys sell + buy of the token, fills
  them, ≥ 3 txs + 50-CSV exposure waits + mrv×P KAS liquidity in flight, all
  funds returning to A minus fees): trigger legitimately passes; SL := SL +
  rstep. Sub-leaves:
  - **L5a. A (or anyone) then fills the ratcheted SL**: pays O
    `tokens × (SL+rstep)/pden` — MORE than O's previous floor. O strictly
    gains vs schedule; the filler eats (new SL − market) if above market.
    Self-defeating for A. ("Ratchet then fill" in the same tx is impossible:
    the continuation UTXO cannot be spent in the tx that creates it.)
  - **L5b. Market ≥ new SL**: arbitrage fills O at a strictly better price
    than the pre-ratchet floor whenever the market next touches it. O ≥
    schedule. This is the feature working as declared (A subsidized it).
  - **L5c. PARKING (the binding leaf)**: A repeats k×L5 (cost ≥ 3k fees,
    duration ≥ k×rwin, capped by G3 at the TP ceiling) until SL > market.
    O's SL branch becomes a standing ask above market: it can only execute
    if someone overpays (O gains) or the market rises to it (O exits at the
    declared trailing distance). On a crash, nobody fills — O rides down
    UNLESS O acts. O's remedy: CANCEL (owner-signed, immediate, never
    rate-limited, works on the continuation with the same key); cost ≈ 1–2
    txs + redeploy. Pecuniary transfer to A: **zero** — A cannot buy below
    the original SL at any node, cannot touch escrow, cannot extend expiry
    (R3/suffix), cannot exceed TP (G3). O's loss: remediation fees + the
    option value of a crossing stop during the reaction window (≥ rwin per
    step, G1). Decisive comparison: this exact end-state (stop parked above
    a fallen market) is reachable WITHOUT any attacker — a genuine rise
    (prints real), ratchet, then a fast retracement through the stop before
    any arb fills. Trailing stops without guaranteed execution carry
    gap-risk inherently; A can only *force* the gap-risk state at fee cost,
    not create a new class of loss. → grief, bounded, non-pecuniary;
    accepted with G1–G4 + disclosure. If MK rejects this residual, the
    honest alternative is NOT a tweak — it is killing the feature (no-oracle
    print-authenticity is unattainable; every "stronger" print test reduces
    to volume/fee economics already priced here).
  - **L5d. Race with an in-flight SL/TP fill**: both spend the same UTXO —
    one confirms, the other is rejected by the UTXO model; a losing fill
    retries against the continuation at a strictly-better-for-O price.
  - **L5e. Forcing O's cancel to race**: a ratchet landing before O's cancel
    consumes the UTXO; O re-signs against the continuation (deterministic
    derivation, §4.7). ≤ 1 retry per rwin (G1). Fee grief ≈ symmetric.
- **L6. Genuine third-party print** (organic trade at ≥ threshold): the
  intended path; O's stop trails as declared. Prints from the new sell
  variants count too (R7 note) — a decay_sell settle is a genuine settle.
- **L7. One print, many OCOs**: several ratchet_ocos may ratchet off one
  sibling print in one tx — each runs its own R1–R13; prints are
  non-exclusive by design (a real market move should tighten every trailing
  stop).
- **L8. Self-reference** (sii = own input): R5 rejects (else [3..20) of the
  ratchet's own sigscript — attacker bytes — would price the trigger).
- **L9. Ratchet spam DoS**: G1 caps at 1/rwin per order; each attempt ≥ 1 tx
  fee; rejected attempts don't consume the UTXO.
- **L10. Wrong-step / wrong-window splice** (new ≠ old+rstep, or any other
  byte moved, incl. cpend/expiry/prices/seats): R13b/c/d reject byte-exactly.
- **L11. Escrow skim via continuation** (value < escrow, missing binding,
  foreign SPK): R13f rejects (Fix-3 + covenant id + full-value floor).

**Leaf audit result: no leaf transfers O's funds below the declared schedule;
no leaf reduces O's execution price; the only standing harm is L5c's
execution-probability grief, bounded by G1–G4 and identical in kind to honest
gap-risk.** Hence CONDITIONAL (guards mandatory), not KILLED.

### 4.7 Planner / engine / CLI implications

- Engine executor: `execute_oco_ratchet(oco, sibling_settle_plan)` — builds
  the tx containing the print (usually a normal batch settle) plus the
  ratchet input; splices new_rs = old_rs with `[97..105) += rstep`; sets the
  ratchet input's sequence ≥ rwin; registers the continuation.
- Scanner: ratchet_oco tracking must follow continuations: derive
  `new_rs(k) = old_rs with pnum_sl += k×rstep`, watch the corresponding P2SH
  addresses (bounded: k ≤ (TP−SL)/rstep by G3). API exposes `current SL`,
  `ratchets applied`, `next eligible DAA`.
- Matcher incentive note: ratcheting earns no fee by itself; it composes with
  fills the matcher already profits from, and arbitrageurs profit from L5b
  fills after genuine rises. No protocol fee is added (non-goal).
- CLI: `oco create-ratchet --step --gap --window --min-vol`; `oco show`
  prints the ratchet ladder and history.

### 4.8 Interaction with cancel-mark / expire (explicit)

- cpend==1 freezes ratcheting (R2) — but note the v18 OCO family has NO
  cancel-mark branch (selectors 0/1/2/4); the owner's actual remedy is plain
  CANCEL, which is immediate and never rate-limited. cpend can only be 1 if
  deployed that way. Adding OCO cancel-mark stays out of scope (unchanged
  from v18).
- EXPIRE: expiry bytes sit in the R13-fixed suffix — a ratchet can never
  extend (or shorten) the order's life; the EXPIRE branch works identically
  on any continuation.
- CANCEL: ohash/sspkh/otspkh are byte-preserved — the owner's key and seats
  survive every ratchet.

---

## 5. Version model, RS lengths, collision plan

`SPOT_GENERATION = 18`, untouched. The four new contracts are additional
KINDS: own builders, own `*_RS_SIZE` consts, own `parse_redeem_script` arms
(RS-length dispatch, v18 house model); `version` u8 reports 18 wherever
surfaced. v18 bytecode is byte-frozen (Stage-A zero-diff pin).

| Contract | state | body (est) | RS (est) | vs parent |
|---|---|---|---|---|
| twap_sell | 163 (145+18) | ≈ 412 | **≈ 575 ±10** | sell 515 |
| decay_sell | 172 (145+27) | ≈ 495 | **≈ 667 ±15** | sell 515 |
| ratchet_oco | 208 (172+36) | ≈ 505 | **≈ 713 ±20** | OCO 397 |
| decay_buy | 205 (178+27) | ≈ 1637 | **≈ 1842 ±25** | buy 1720 |

Frozen v18 / legacy lengths for reference: borrow_request 202, perp 212,
loan_offer 214, swap 260, bracket 372, DCA 374, OCO 397, sell 515, buy 1720,
x402_borrow (42 + body). Estimates are design-stage; the freeze numbers are
pinned at Stage A exactly as v18 did (`*_BODY_EXPECTED_LEN` consts +
`debug_assert_eq!` in the builders + `bytecode_stable` pin tests).

**Collision check plan** (extends NM_BUY_DESIGN §6 item 16):
1. Stage-A pin test collects EVERY `pub const *_RS_SIZE / *_RS_EXPECTED_LEN`
   in kob-core (the four new + spot v18 + lending/perp/x402/prediction/
   auction/options/insurance/token bodies) and asserts pairwise distinctness.
2. `parse_redeem_script` arms must be disjoint by construction (match on the
   new lengths); a round-trip test feeds each builder's output through the
   parser and asserts field identity.
3. Policy if two lengths land equal at freeze: append one `OpNop` to the
   YOUNGER body (deterministic, documented in the body comment) — never
   reshuffle state.
4. Danger zone watch: **decay_sell (667+15=682) vs ratchet_oco (713−20=693)
   have a worst-case gap of 11B** — the closest new pair, resolved by the
   OpNop policy at freeze if the estimates converge; twap_sell 575 vs sell
   515 (gap 60) and decay_buy 1842 vs buy 1720 (gap ~120) are safe; bracket
   372 vs DCA 374 remains the closest legacy pair — all asserted.

---

## 6. Live proof plan (testnet-10; node ws://65.108.107.30:18210, REST
api-tn10.kaspa.org; record TXIDs + `is_accepted` in E2E_LIVE_RESULTS.md,
Stage-G section; rejections recorded via the submit error, v18 style)

**v18 proofs REMAIN VALID** — the v18 bytecode is untouched (zero-diff pin,
§0); the Stage-F 15-form matrix TXIDs stand. No re-proof of v18 forms.
Live proof is needed only for the new forms plus one composition proof per
variant (unchanged v18 counterparty in the same tx):

decay_sell:
- **DK-1** GTC fill mid-schedule: L = tip, seller KAS ==
  `token_in × pnum_eff(L) / pden` exactly (output-level REST verification).
- **DK-2** adversarial: attest the START price after decay has run → covenant
  reject (D3).
- **DK-3** boundaries: (i) L=0 fill executes at start price; (ii) fill with
  L > tip rejected `NotFinalized`, re-accepted once DAA > L; (iii) L past
  t_end executes at the floor.
- **DK-4** adversarial: unix-ms-type L (schedule fast-forward) → reject (D1).

decay_buy:
- **DB-1** fill at a risen bid: token floor demanded == kas_in/pden×pnum_eff
  at L = tip (fewer tokens than at deploy).
- **DB-2** partial fill + residual re-priced at the next event's L.

twap_sell:
- **TW-1** window pair: fill#1 accepted; immediate fill#2 rejected
  (`SequenceLockConditionsAreNotMet`); same fill accepted after twin DAA.
- **TW-2** caps: fta > mpw rejected; fta = mpw accepted; full-fill with
  token_in > mpw rejected (bypass pin).

ratchet_oco:
- **RT-1** happy path: genuine settle sibling in-tx, ratchet accepted;
  continuation address == P2SH(derived new_rs) verified via REST; then SL
  fill at the ratcheted price.
- **RT-2** adversarial set (each a recorded rejection): second ratchet inside
  rwin; wrong-step splice (new ≠ old+rstep); mutated non-window byte; print
  below threshold; cancel-sibling fake print (R7); sub-mrv volume;
  travel-cap breach at the TP ceiling; sii = self.
- **RT-3** owner remedy: ratchet lands, owner CANCELs the continuation with
  the original key.

Composition (one per variant — the point of the additive packaging):
- **CP-1** unchanged v18 buy sweeps decay_sell + plain v18 sell in ONE tx
  (fair_sum consumes f(L) at the canonical offsets next to a static price).
- **CP-2** unchanged v18 buy sweeps twap_sell (+ plain sell) in one tx, the
  twap_sell input carrying sequence = twin.
- **CP-3** unchanged v18 buy sweeps ratchet_oco on the TP branch (SL-branch
  sweep is covered by RT-1's ratcheted-SL fill).
- **CP-4** unchanged v18 sell settled by a decay_buy (full fill; DB-2 covers
  the partial shape).

---

## 7. Stages (each ends: build green → commit, RossKU style)

- **A core**: new bodies + builders (`decay_sell`/`twap_sell`/`decay_buy`
  beside the v18 emitters in order.rs or a sibling `time.rs`; `ratchet_oco`
  in oco.rs), parse arms + field structs, builder validations (§2.2/§3.4/
  §4.2), EXPECTED_LEN pins, collision pin test (§5), **v18 zero-diff pin**
  (§0), and the adversarial unit matrix: all of §2.8, §3.6, §4.6 L1–L4/L8/
  L10/L11 as script-level tests, plus NUMEQUAL-vs-EQUAL encoding tests (T6),
  the R9 negative-encoding pin, and the §3.2 burst documentation test.
- **B domain**: planner support — new sells enter the existing sweep planner
  as ordinary members (ABI §0); new logic only for decay pricing at L=tip +
  the lock_time feasibility solver (§2.7), TWAP eligibility by UTXO age +
  sequence wiring (§3.5), ratchet splice plan builder (§4.7); sigscript
  emission incl. the no-gcd decayed attestation builders; D pin regression.
- **C engine+cli**: deploy paths for the four kinds, scanner arms +
  ratchet-continuation tracking, `execute_oco_ratchet`, effective-price
  surfacing in API/book, CLI subcommands (§2.7/§3.5/§4.7).
  **Stage-C addenda (agreed 2026-07-17, recorded here so they don't ride
  only in conversation):**
  - **C-a executor wiring of planner authority**: the executor must consume
    `BatchPlan.lock_time` and the per-input `BatchTxInput.sequence` produced
    by the Stage-B planners; today the executor sets its own values, so the
    Stage-B authoritative time gates are not yet reflected in submitted txs.
  - **C-b competing-matcher friendliness**: miner-style weighted-random
    match selection plus collision backoff (on a lost race, back off and
    re-plan instead of resubmitting the same sweep).
  - **C-c TxSubmitter three-lane abstraction**: `Urgent` / `Free` / `Auto`
    with per-tx lane selection; `Auto` falls back Urgent→Free. This is the
    receiving port for the future miner-engine mode (fee-0 settle in
    self-mined blocks) — that mode itself stays OUT of Stage C (separate
    track, touches node/mining code).
- **D live E2E**: testnet-10 forms of §6 (fund via kob-miner if needed; mint
  fresh SPA/SPB pattern tokens); TXIDs recorded in E2E_LIVE_RESULTS.md
  Stage-G.
- **E doc/final**: E2E_MATRIX.md rows for the new forms, README/
  ENGINE_API_DESIGN touch-ups, this file gets a status update stamp (like
  V18_DESIGN's header), final regression sweep (which re-asserts the v18
  zero-diff pin).

**Stage-B residuals (carry-forward, recorded 2026-07-17).** Small holes
left by Stage B; picked up in Stage C unless marked otherwise:

1. **Sell-anchored planners do not admit time variants** — time sells enter
   only the buy-anchored sweep planners; the sell-anchored IOC path builds
   the legacy Finalized shape (`domain/src/spot/batch.rs` Stage-B scope
   note, `lock_time: 0`). Stage C either admits time variants there or
   promotes this to an explicit non-goal at Stage E.
2. **Ratchet sell-anchor path missing** — RT TP/SL branch fills ride only
   buy-anchored plans, and `compose_settle_and_ratchet` assumes a buy-side
   settle sibling; no sell-initiated composition exists. Same disposition
   as (1).
3. **`decay_buy` partial planner absent** — only `plan_decay_buy_match`
   (GTC) and `plan_decay_buy_ioc_match` exist; the v18 partial-fill planner
   shape is not mirrored for decay_buy (§6 DB-2 proves partial via the
   residual re-price path, but planner support is owed).
4. **R12 print selection is fail-closed and narrow** — only divisible
   prints with `koi <= 127` qualify (`domain/src/spot/time_planner.rs`
   skips `koi > 127`: the covenant's R12 reads koi as a single signed byte,
   so >= 0x80 would read negative). Documented limitation, NOT Stage-C
   work: settle shapes at MAX_N=32 stay far below 128 outputs; revisit only
   if output counts ever approach the boundary.

Build env: unchanged from V18_DESIGN §Build env (Termux cargo 1.94.1,
`CARGO_TARGET_DIR=/root/kob-rust-target4`, per-crate commands only).

---

## 8. NON-GOALS (explicit)

- **No oracle, no off-chain price import** — all four contracts consume only
  consensus-observable quantities (tx.lock_time, UTXO age via sequence locks,
  sibling-input sigscript bytes authenticated by covenant id). The ratchet's
  "price" is an on-chain print, declared as such (§4.5).
- **No generation bump; no change of any kind to v18 bytecode, state layouts,
  RS lengths, planners or proofs** — enforced by the Stage-A zero-diff pin.
- **MAX_N = 8 unchanged** (`BUY_ORDER_MAX_N`); no new sweep slots; the mass
  budget argument is not revisited (concurrent batch-mass measurement
  workstream owns that topic).
- **No combined decay+TWAP order initially** — a combined variant is added
  later ONLY on product demand; the attestation ABI makes it additive too
  (one more RS length, zero change to v18 or these four).
- **No `last_fill_daa` field** — rejected as unsound, not deferred (§3.2).
- **No `twap_buy`**; no decay or TWAP on OCO/bracket/DCA/swap; no buy-side
  trailing ratchet; no OCO cancel-mark; no rising-sell / falling-bid
  schedules (unenforceable, §2.1); no multiplicative ratchet steps (§4.1);
  no ring/swap changes; no trigger semantics of any kind (V18 note stands:
  consistency via arbitrage only).
- **No change to v18 fill-math rounding or fair_sum/mmfee semantics** — the
  new bodies substitute the pnum operand (decay) and add gates; the v18
  proofs of those mechanisms are reused, not reopened.
- **No protocol fee for ratcheting**; no mempool-level anti-spam beyond G1.
