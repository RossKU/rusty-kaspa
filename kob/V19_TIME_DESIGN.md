# V19 DESIGN FREEZE — on-chain TIME features: decay limit, TWAP, trailing ratchet

Status: design frozen 2026-07-17. Implementation NOT started (Stage A pending).
Base: v18 single-generation spot (see `V18_DESIGN.md`), HEAD `b37c590`.
Generation bump: `SPOT_GENERATION` 18 → 19 (state fields added to sell/buy/OCO
⇒ RS lengths change ⇒ full re-freeze + full live re-proof; swap/bracket/DCA
bytecode untouched, they only REPORT 19 through the const).

Verdicts (summary):

| Feature | Verdict | Crux resolution |
|---|---|---|
| 1. Decay limit (Dutch) | **SOUND** | consensus `acceptance-DAA > L` makes understating L self-defeating and overstating L unminable; L=0 and unix-ms-type L both collapse to the worst-for-taker end of the schedule by construction |
| 2. TWAP / rate limit | **SOUND after redesign** — the specified `last_fill_daa := L` splice is **UNSOUND** (clock-lag burst, §3.2); frozen design replaces the stored clock with the consensus UTXO-age clock (`CSV`), which is strictly stronger and deletes the field | the residual UTXO's creation DAA *is* the true last-fill time; `check_sequence_lock` makes it unforgeable |
| 3. Trailing ratchet (OCO) | **CONDITIONAL — ship only with the four mandatory guards** (§4.5); grief tree has no pecuniary leaf, the binding leaf is execution-probability grief equivalent to honest gap-risk | fake prints cannot be distinguished from genuine ones in a no-oracle system; the guards force fake cost up to genuine-self-trade cost and bound the blast radius |

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
arithmetic ops directly (this is why all existing KOB math works). Corollary
for v19: a *computed* value (minimal encoding) compared against an 8-byte
*pushed* value must use `OpNumEqual`, never `OpEqual` (byte comparison) —
this bites the decay attestation check (§2.5) and the ratchet splice (§4.4).

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

## 2. Feature 1 — Decay limit ("Dutch") orders — **SOUND**

### 2.1 Semantics

One extra degree of freedom on the standard v19 sell and buy: the price
numerator becomes a function of `tx.lock_time` L,

```
eff       = min( max(L, t0), t_end )          // clamp, handles L=0 and L<t0
pnum_eff  = pnum − dslope × (eff − t0)        // dslope ≥ 0, integer, exact
```

with build-time invariants `t0 < t_end < LOCK_TIME_THRESHOLD` and
`dslope × (t_end − t0) ≤ pnum − 1` (so `pnum_eff ≥ p_floor ≥ 1`; the floor is
derived, not stored). `dslope == 0` means "no decay" (t0/t_end must be 0) and
the branch skips all clock logic — a v19 plain order.

Direction is HARDWIRED per side, because only one direction is enforceable:

- **Sell (Dutch)**: `pnum/pden` = KAS per token; `pnum_eff` falls with time ⇒
  ask price decays. A *rising* sell schedule is unenforceable: the taker would
  understate L to buy at the old cheap price, and understating is always
  minable (T1 is a one-sided floor). Rejected as a feature, documented.
- **Buy (rising bid)**: in the buy, `pnum/pden` = tokens per KAS (floor is
  `token_sum ≥ kas_in/pden×pnum`), so a rising bid = *fewer* tokens demanded
  per KAS = `pnum_eff` falls — the SAME formula. A falling bid is
  unenforceable for the mirrored reason. One formula, both sides.

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
`L < 500_000_000_000` (§2.5 line D2). An L ≥ 2^63 arrives negative from
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

### 2.2 Separate contract vs fields on the standard order — DECIDED: fields

Fields on the standard sell/buy with `dslope=0` = "no decay". Argument:
- RS cost: +45B state (§2.3) and ≈ +215B body on the sell (≈ +185B on the
  buy) — per swept sell input that is ≈ +260B of sigscript mass against a
  250KB post-Toccata sigscript budget and the block-fit bounds that already
  accommodate 8×~550B sweeps; MAX_N=8 stays (non-goal §8). Acceptable.
- A separate contract would double the planner/scanner/CLI dispatch surface,
  add two more RS lengths to the collision space, and make "decaying TWAP
  sell" impossible to compose. It also violates the v18 charter ("ONE spot
  generation covering everything the matrix needs").
- Sweep-eligibility: a decayed sell keeps the canonical attestation prefix at
  the same offsets (§2.5), so it batches with plain sells transparently.

### 2.3 State layout delta

New fields are PREPENDED to the RS (pushed first = deepest on stack), so every
existing body depth reference [0..N) survives; only dispatch roll depth,
cleanup counts and the new checks change.

```
SELL v19 state (190B = 45 + v18 145):
  [0x08][dslope 8B] [0x08][t0 8B] [0x08][t_end 8B]     (decay, §2)
  [0x08][twin 8B]   [0x08][mpw 8B]                     (TWAP, §3)
  ‖ v18 145B layout unchanged ([0x20 otspkh] … [0x08 expiry])
stack at body start: expiry(0) cpend(1) mmfee(2) sspkh(3) ohash(4) mfill(5)
  pden(6) pnum(7) otspkh(8) | mpw(9) twin(10) t_end(11) t0(12) dslope(13)
  selector at 14 (was 9)

BUY v19 state (223B = 45 + v18 178): same five fields prepended
  (buy mpw is in KAS sompi, sell mpw in token units).
stack: expiry(0) … okspkh(9) | mpw(10) twin(11) t_end(12) t0(13) dslope(14)
  selector at 15 (was 10)
```

Builder validation added: `dslope==0 ⇒ t0==t_end==0`; `dslope>0 ⇒ t0 < t_end <
LOCK_TIME_THRESHOLD ∧ dslope×(t_end−t0) ≤ pnum−1`. (twin/mpw rules in §3.4.)

### 2.4 Branch/selector allocation

No new selectors. Decay lives inside the existing fill-family branches
(sell: FILL 1 / IOC 5 / PARTIAL 2; buy: FILL 1 / IOC 5 / PARTIAL 2), each of
which computes `pnum_eff` once at branch entry and uses it wherever v18 used
`pnum`. CANCEL/CANCEL-MARK/EXPIRE are untouched (owner paths never price).

### 2.5 Verification logic (opcode-level, sell FILL shown; IOC/PARTIAL and the
buy floors are the same block at shifted depths, pinned at Stage A)

Sell FILL entry after time-gate + `50 CSV` + F5, base(15):
`mmfee(0) sspkh(1) ohash(2) mfill(3) pden(4) pnum(5) otspkh(6) mpw(7) twin(8)
t_end(9) t0(10) dslope(11) pden_att(12) pnum_att(13) koi(14)`

```
D1  e_pick(11) OP0 NUMEQUAL          // dslope == 0 ?
    IF   e_pick(5)                   //   pnum_eff := pnum
    ELSE
D2    TXLOCKTIME DUP                 //   L
      <push 5B: 500_000_000_000> LT VERIFY   // type guard: DAA-domain only
D3    e_pick(11) MAX                 //   max(L, t0)        (t0 @10, +1)
      e_pick(10) MIN                 //   eff = min(…,t_end)(t_end @9, +1)
      e_pick(11) SUB                 //   eff − t0
      e_pick(12) MUL                 //   dec = (eff−t0)×dslope  (no overflow:
                                     //   ≤ pnum−1 by build invariant, T7)
      e_pick(6) SWAP SUB             //   pnum_eff = pnum − dec  (pnum @5, +1)
    ENDIF                            // pnum_eff on top, base(15) below
D4  DUP e_pick(15) NUMEQUAL VERIFY   // ATTESTATION: pnum_att == pnum_eff
                                     // (NUMEQUAL, not EQUAL — T6: computed vs
                                     //  8B-padded push)
D5  e_pick(13) e_pick(6) EQUAL VERIFY// pden_att == pden (both 8B pushes)
D6  …v18 price math with pnum_eff in place of the pnum pick…
    expected_kas = token_in × pnum_eff / pden ; ≥ mfill ; KAS out ≥ expected ;
    F2 sspkh ; F4 Fix-3 — all byte-identical to v18 except the operand source.
```

Estimated cost: ≈ 45B per fill branch (×3 sell, ×2 buy).

### 2.6 Sigscript layout + attestation (offsets MUST NOT move — they don't)

```
decayed sell fill:  [0x01,koi][0x08 pnum_eff(L) 8LE][0x08 pden 8LE][Op1][RS]
```
Identical SHAPE to v18; only the VALUE at [3..11) changes: the builder writes
`pnum_eff(L)` for the L the matcher will set on the tx. pnum stays at [3..11),
pden at [12..20) — canonical offsets stable for every sweep-eligible sell-side
branch. **Builder pitfall (freeze rule):** the effective pair must NOT be
gcd-normalized (`push_attested_prefix` normalizes today — decayed sells need
the raw `(pnum_eff, pden)` or D4/D5 fail). New builder
`build_sell_fill_sigscript_decayed(koi, pnum_eff, pden, rs)` or a
no-normalize flag.

**Which price is attested when a decaying sell is swept by a buy: f(L) at
settle time, enforced twice.** The sell body forces `pnum_att == pnum_eff(L)`
(D4). The buy's PASS 2 fair_sum reads ONLY sigscript [3..11)/[12..20) of the
covenant-authenticated tii (v18 mechanism, unchanged) — so
`fair_kas_i = tokens_i / pden_att_i × pnum_att_i` automatically consumes
`f_i(L)` for each decaying sell in the sweep. One tx has one lock_time, so
every schedule in the sweep is evaluated at the same L — internally
consistent by construction. The buy's own GTC floor uses its own `pnum_eff`
(buy-decay) at the same L. No new cross-contract offsets, no new trust.

### 2.7 Planner / engine / CLI implications

- Planner (`batch.rs`/`matching.rs`): price feasibility must be evaluated at
  the L the tx will carry. Policy: L := current tip DAA score (maximizes decay
  in the taker's favor; minable in the next block since acceptance > L).
  Batching constraint solver: a tx's single lock_time must satisfy every
  member (fill time-gates want `L < expiry_i` for expiry≠0 members; an
  auto-expire branch wants `L ≥ expiry_j`) — if the intersection is empty,
  split into separate txs (auto-expire already runs separately today).
- Engine executor: pass L into sigscript builders; recompute `pnum_eff` with
  the exact integer formula (share one helper with the covenant emitter — the
  same function must generate the builder value and the test vectors).
- Scanner/API: parse the three fields, expose `effective_price(now)` next to
  the static price; order book sorting must use f(tip), refreshed per block.
- CLI: `order create --decay-slope --decay-t0 --decay-until`; display shows
  `price now / floor / t_end`.

### 2.8 Adversarial matrix (NM_BUY_DESIGN §6 style)

1. **Understated L** (taker wants yesterday's schedule point): executes at
   f(L) ≤ taker-favorability of f(actual) — self-defeating by monotonicity;
   allowed. Test: fill with L = t0 at actual ≫ t0 pays the start price.
2. **Overstated L** (taker wants tomorrow's price): consensus `NotFinalized`
   until DAA > L (T1); at that time f(L) is the declared price. Live-proof
   form DK-4 submits early and observes rejection.
3. **L = 0**: Finalized type, no consensus floor — but clamp ⇒ eff = t0 ⇒
   start price = worst-for-taker. Explicit convention, unit + live test.
4. **Unix-ms-type L** (≥ 5e11, minable now, huge in DAA units — the schedule
   fast-forward attack): killed by D2 type guard; script errors. This is the
   one genuinely dangerous vector; it gets a dedicated adversarial unit test
   and a live rejection form.
5. **L ≥ 2^63** (negative i64 from T5): passes D2's `<`, clamps to t0 (worst
   for taker), and the tx is unminable for centuries — doubly harmless.
6. **Stale-price attestation** (matcher attests pnum instead of pnum_eff, or
   yesterday's pnum_eff): D4 NUMEQUAL fails — reject. Mirror of the v18
   attestation-mismatch tests, per branch (fill/IOC/partial).
7. **Overflow grind** (adversarial L to blow up MUL): clamp (D3) runs BEFORE
   MUL, so the multiplicand is ≤ t_end−t0 and the product ≤ pnum−1 by the
   build invariant — overflow unreachable on a well-formed RS; hand-rolled
   RS with violating fields only mispays its own deployer (fail-closed T7).
8. **Mixed sweep, one L**: matcher picks L to minimize total payment across
   plain+decayed sells — each f_i is independently ≤-capped by its own
   schedule at actual time; absolute-KAS surplus cap (v18 PASS 2) is computed
   from the same attested values the sells enforce — no averaging hole.
9. **Expiry dodge via understated L** (fill with L < expiry ≤ actual): v18
   time-gate semantics unchanged (expiry hard-stops only the EXPIRE race);
   for decayed sells an understated L additionally *costs* the taker (worse
   price) — strictly less attractive than in v18. Documented, not new.
10. **Residual re-pricing** (sell partial then later fills): each event
    re-evaluates f at ITS tx's L — a taker cannot lock an old price into the
    residual; the residual is byte-identical state, the schedule is absolute
    (t0/t_end in DAA), so continuation pricing is automatic.

---

## 3. Feature 2 — TWAP / rate-limited execution — **SOUND after redesign**
(the specified stored-clock design is UNSOUND; both are given, one is frozen)

### 3.1 The specified design (for the record) and its splice

As tasked: state `{window_daa Δ, max_fill_per_window, last_fill_daa}`; the
partial-fill branch additionally requires `tx.lock_time ≥ last_fill_daa + Δ`
(push last, push Δ, ADD, CLTV — T2 makes this a valid computed-operand use)
and `fill ≤ max_per_window`; continuation output = RS with
`last_fill_daa := L` spliced in DCA style (T8): prefix/suffix byte-equality
around the 8B window at the field's RS offset, `new_field == L` via
OpSubstr + NUMEQUAL against TXLOCKTIME, old_rs authenticity via
blake2b→P2SH == OpTxInputSpk(self), continuation SPK == P2SH(new_rs),
value ≥ token_in − fta.

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
  event on a TWAP order consumes the order UTXO and (for partials) creates the
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
`{twin, mpw}` only (18B, not 27B), and TWAP needs no splice machinery at all.

### 3.3 Frozen TWAP semantics

For sell (`twin` DAA window, `mpw` max tokens per event) and buy (`mpw` in
KAS sompi), applied to ALL fill-family branches (full FILL and IOC included —
otherwise a matcher bypasses the limiter by full-filling; the "last chunk"
must also obey `token_in ≤ mpw`):

```
if twin != 0:
    twin CSV                      // real age of this order UTXO ≥ twin
    vol ≤ mpw                     // vol: FILL = token_in (sell) / kas_in (buy)
                                  //      IOC/PARTIAL = fta / spent
```
`twin == 0` ⇒ both checks skipped (plain v19 order). Owner branches
(CANCEL/CANCEL-MARK/EXPIRE) are NOT gated — the owner's escape is never
rate-limited.

Rate guarantee: fills on one lineage are ≥ twin apart in real acceptance DAA
and each moves ≤ mpw ⇒ long-run rate ≤ mpw/twin, worst-case burst = mpw. The
first fill also waits twin from DEPLOY (the deploy UTXO's age gates it) —
accepted and documented; a "grace first window" variant was rejected (it
would need a stored flag = the splice we just deleted).

### 3.4 State delta, builder validation, opcode sketch

State: sell +`[0x08 twin][0x08 mpw]`, buy same (§2.3 shows position/depths;
the five v19 fields land together). Builder: `twin==0 ⇒ mpw==0`;
`twin>0 ⇒ 50 ≤ twin ≤ 0xFFFF_FFFF` (CSV 32-bit mask, T3) `∧ mpw ≥ 1 ∧`
sell: `mpw×pnum_floor/pden ≥ mfill` (else no event can satisfy both floors;
pnum_floor = decay floor or pnum), buy: `mpw ≥ mfill-consistent` mirror.

Sketch (sell FILL, base(15) of §2.5; stack-neutral):
```
W1  e_pick(8) DUP OP0 NUMEQUAL       // twin; twin == 0 ?
    NOTIF
W2    DUP CSV                        // consensus real-age gate (T3)
W3    TXINPUTINDEX TXINPUTAMOUNT     // vol = token_in   (FILL form)
      e_pick(9) SWAP                 // mpw (7 + 2 picks) ; [mpw, vol]
      GTE VERIFY                     // mpw ≥ vol
    ENDIF
    DROP                             // twin copy
```
(IOC/PARTIAL replace W3's amount with the fta/spent value already on stack;
≈ 16–22B per branch.) Engine must set `input.sequence = max(50, twin)` on
TWAP fill inputs (it already sets ≥ 50 for the exposure delay).

### 3.5 Planner / engine / CLI

- Planner: a TWAP order is fill-eligible iff `tip_daa ≥ utxo.block_daa_score
  + twin` (scanner already has creation scores); planned vol capped at mpw.
  Sweep membership: a TWAP sell inside an N:M batch is legal (its own CSV
  gates only itself; the batch tx satisfies it by setting that input's
  sequence).
- Engine: sequence wiring (above); scheduler may queue the next event at
  `creation + twin` — a nice fit for the existing auto-expire loop.
- CLI: `order create --twap-window --twap-max`; book display shows
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
4. **Dual same-RS UTXO residual sharing**: sell — per-input Fix-3 auth
   binding (v18) already isolates residuals; buy — the P5 self-instance
   uniqueness guard (v18) already blocks it. Regression pins re-run on v19.
5. **Full-fill bypass**: FILL/IOC are gated identically (§3.3) — pinned by an
   adversarial test (full fill with token_in > mpw rejected).
6. **Owner lock-out grief**: not possible — owner branches skip the gate.
7. **Mass cost**: +18B state, ≈ +20B per fill branch; a rejected early-CSV tx
   dies in consensus validation before script execution (cheap for the
   network). Mass measurements themselves belong to the concurrent
   batch-mass workstream and are out of scope here.

---

## 4. Feature 3 — Trailing ratchet (OCO extension) — **CONDITIONAL: ship only
with the four mandatory guards of §4.5** (no pecuniary grief leaf remains;
residual = execution-probability grief equal to honest gap-risk)

### 4.1 Semantics

Permissionless RATCHET branch on the v19 OCO sell: anyone who can point at a
genuine same-token settle *in the same tx* at attested price P may tighten the
SL one step:

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
OCO v19 state (208B = 36 + v18 172), new fields PREPENDED:
  [0x08][rstep 8B] [0x08][rgap 8B] [0x08][rwin 8B] [0x08][mrv 8B]
  ‖ v18 172B layout unchanged
stack: expiry(0) … otspkh(11) | mrv(12) rwin(13) rgap(14) rstep(15)
  selector at 16 (was 12)
RS byte offsets (all v18 offsets +36): pnum_sl VALUE = [97..105) (its 0x08
  prefix at 96 is inside the fixed prefix), pden_sl = [106..114),
  pnum_tp = [70..78), cpend at 198, expiry value [200..208).
```
Builder: `rstep==0 ⇒ rgap==rwin==mrv==0` (feature off — the branch is dead
because R1 fails); `rstep≥1 ⇒ 50 ≤ rwin ≤ 0xFFFF_FFFF ∧ mrv ≥ 1 ∧
(pnum_sl + rstep)×pden_tp < pnum_tp×pden_sl` (initial headroom sanity).

### 4.3 Branch/selector allocation + sigscript

Selector **3** on the OCO (free today: 0=CANCEL, 1=TP, 2=SL, 4=EXPIRE; OCO
has no cancel-mark). sigOpCount = 0 (permissionless).

```
ratchet sigscript: [pushData(new_rs)][pushData(old_rs)][sii][Op3][pushData(RS)]
```
new_rs FIRST is deliberate: its pushData opcode for a ~700B RS is 0x4d, so a
ratchet sigscript can never begin with 0x01 and can never impersonate a
canonical settle when *itself* named as a sibling (see matrix A6 — this
closes the nested-ratchet fake for every sii encoding, including the
`push_index` 17..127 form `[0x01, sii]` which would otherwise collide with
the canonical prefix's first byte).

TP/SL/cancel/expire sigscripts are unchanged ⇒ the canonical attestation
offsets of sweep-eligible OCO branches do not move.

### 4.4 Verification logic (opcode-level)

Entry (selector consumed): `expiry(0) cpend(1) mmfee(2) sspkh(3) ohash(4)
mfill_sl(5) pden_sl(6) pnum_sl(7) mfill_tp(8) pden_tp(9) pnum_tp(10)
otspkh(11) mrv(12) rwin(13) rgap(14) rstep(15) sii(16) old_rs(17) new_rs(18)`
(depths shown at entry; the Stage-A implementation pins every intermediate
depth exactly as order.rs does).

```
R1  feature-on:  rstep ≥ 1                    (pick, OP0 GT VERIFY)
R2  F5:          cpend == 0                   (ratchet respects cancel-mark:
                                               marking instantly freezes
                                               ratcheting — owner's remedy)
R3  time-gate:   v18 expiry gate, stack-neutral (parity with fill family;
                 ratchet never EXTENDS life: expiry bytes are in the fixed
                 suffix, preserved)
R4  rate:        rwin CSV                     (T3; rwin ≥ 50 at build ⇒ also
                                               covers the exposure delay)
R5  sii != self: sii TXINPUTINDEX NUMEQUAL OpNot VERIFY
R6  same token:  OpInputCovenantId(sii) == OpInputCovenantId(self)
                 (OCO carries no tcid field; self-reference IS the tcid —
                  same sii-safe discipline as fills: authenticate the index
                  by covenant id BEFORE trusting anything read from it)
R7  canonical-shape guard on the sibling's sigscript (OpTxInputScriptSigSubstr):
      substr(sii,0,1)  == 0x01     substr(sii,2,3)  == 0x08
      substr(sii,11,12) == 0x08
    ⇒ the sibling's sigscript is canonical-attestation-shaped; combined with
      R6, the ONLY tx-valid spends with this shape are fill-family branches
      whose OWN covenant enforces `attested == executing state price`
      (fill/IOC/partial/TP/SL; token_unit, cancel, expire, ratchet all start
      with 0x41/0x54/0x4d/OpN — killed; see matrix A5/A6)
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
  reopens a cheap-fake lane (see A5–A7).

Plus a disclosure rule (doc + CLI help): the ratchet schedule is declared
over PRINTS (on-chain settles of this token), not over a "true market price"
— KOB has no market-price concept (V18 note); anyone can be both sides of a
print at the cost of fees.

### 4.6 Adversarial economics — the full grief tree

Notation: owner O holds OCO(TP, SL, rstep, rgap, rwin, mrv); attacker A;
"schedule" = O's declared mapping prints→stop. Every leaf states who pays
whom. A *pecuniary* loss = O receiving less than the declared floor for what
is taken, or losing custody; opportunity cost is tracked separately.

- **L1. Fake print below trigger** (P < threshold): R11 rejects. A pays a tx
  fee for nothing. No state change.
- **L2. Garbage print** (cancel/expire/token-transfer sibling, signature
  bytes at [3..20)): R7 shape guard rejects (byte 0 is 0x41/0x54/…, never
  0x01). A pays fees. — Without R7 this would have been the cheapest fake:
  cancel-your-own-sell, sig bytes ≈ random ≥ threshold.
- **L3. Nested-ratchet print** (A's second OCO spent on RATCHET named as
  sibling): its sigscript begins 0x4d (new_rs pushData, §4.3) — R7 rejects;
  the `[0x01,sii]` encoding of sii is irrelevant because sii is pushed third.
  For completeness: even if shaped through, R12+R9 force a real KAS output ≥
  mrv × claimed price — self-trade economics anyway.
- **L4. Negative-encoding print** (hand-rolled sibling RS with high-bit price
  bytes; sibling's own fill passes vacuously): R9 positivity guards reject.
  Found during this round; without R9 the trigger passes for ANY claimed P.
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
    rate-limited, works on the continuation with the same key) or
    cancel-mark→cancel; cost ≈ 1–2 txs + redeploy. Pecuniary transfer to A:
    **zero** — A cannot buy below the original SL at any node, cannot touch
    escrow, cannot extend expiry (R3/suffix), cannot exceed TP (G3). O's
    loss: remediation fees + the option value of a crossing stop during the
    reaction window (≥ rwin per step, G1). Decisive comparison: this exact
    end-state (stop parked above a fallen market) is reachable WITHOUT any
    attacker — a genuine rise (prints real), ratchet, then a fast retracement
    through the stop before any arb fills. Trailing stops without guaranteed
    execution carry gap-risk inherently; A can only *force* the gap-risk
    state at fee cost, not create a new class of loss. → grief, bounded,
    non-pecuniary; accepted with G1–G4 + disclosure. If MK rejects this
    residual, the honest alternative is NOT a tweak — it is killing the
    feature (no-oracle print-authenticity is unattainable; every "stronger"
    print test reduces to volume/fee economics already priced here).
  - **L5d. Race with an in-flight SL/TP fill**: both spend the same UTXO —
    one confirms, the other is rejected by the UTXO model; a losing fill
    retries against the continuation at a strictly-better-for-O price.
  - **L5e. Forcing O's cancel to race**: a ratchet landing before O's cancel
    consumes the UTXO; O re-signs against the continuation (deterministic
    derivation, §4.7). ≤ 1 retry per rwin (G1). Fee grief ≈ symmetric.
- **L6. Genuine third-party print** (organic trade at ≥ threshold): the
  intended path; O's stop trails as declared.
- **L7. One print, many OCOs**: several OCOs may ratchet off one sibling
  print in one tx — each runs its own R1–R13; prints are non-exclusive by
  design (a real market move should tighten every trailing stop).
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
- Scanner: OCO tracking must follow ratchet continuations: derive
  `new_rs(k) = old_rs with pnum_sl += k×rstep`, watch the corresponding P2SH
  addresses (bounded: k ≤ (TP−SL)/rstep by G3). API exposes `current SL`,
  `ratchets applied`, `next eligible DAA`.
- Matcher incentive note: ratcheting earns no fee by itself; it composes with
  fills the matcher already profits from, and arbitrageurs profit from L5b
  fills after genuine rises. No protocol fee is added (non-goal).
- CLI: `oco create --ratchet-step --ratchet-gap --ratchet-window
  --ratchet-min-vol`; `oco show` prints the ratchet ladder and history.

### 4.8 Interaction with cancel-mark / expire (explicit)

- cpend==1 freezes ratcheting (R2) — but note the v18 OCO has NO cancel-mark
  branch (selectors 0/1/2/4); the owner's actual remedy is plain CANCEL,
  which is immediate and never rate-limited. cpend can only be 1 if deployed
  that way. Adding OCO cancel-mark remains out of scope (unchanged from v18).
- EXPIRE: expiry bytes sit in the R13-fixed suffix — a ratchet can never
  extend (or shorten) the order's life; the EXPIRE branch works identically
  on any continuation.
- CANCEL: ohash/sspkh/otspkh are byte-preserved — the owner's key and seats
  survive every ratchet.

---

## 5. Generation 19 — re-freeze, RS lengths, collision plan

`SPOT_GENERATION = 19` (`contract/spot/mod.rs`), the only place the number
lives (v18 house model: `version` u8 REPORTS it; on-chain dispatch is by RS
length). Chain state: v18 was proven on testnet-10 but never released —
no migration, v19 supersedes in place (same policy V18_DESIGN used).

| Contract | v18 RS | v19 state | v19 body (est) | v19 RS (est) |
|---|---|---|---|---|
| buy | 1720 (178+1542) | 223 (+45) | ≈ 1727 (+~185) | **≈ 1950 ±25** |
| sell | 515 (145+370) | 190 (+45) | ≈ 585 (+~215) | **≈ 775 ±15** |
| OCO sell | 397 (172+225) | 208 (+36) | ≈ 505 (+~280) | **≈ 713 ±20** |
| swap | 260 | unchanged | unchanged | 260 |
| bracket | 372 | unchanged | unchanged | 372 |
| DCA | 374 | unchanged | unchanged | 374 |

Estimates are design-stage; the freeze numbers are pinned at Stage A exactly
as v18 did (`*_BODY_EXPECTED_LEN` consts + `debug_assert_eq!` in the builders
+ `bytecode_stable` pin tests).

**Collision check plan** (extends NM_BUY_DESIGN §6 item 16):
1. Stage-A pin test collects EVERY `pub const *_RS_SIZE / *_RS_EXPECTED_LEN`
   in kob-core (spot: buy/sell/OCO/swap/bracket/DCA; plus lending 214/202,
   perp 212, x402_borrow, prediction/auction/options/insurance/token bodies)
   and asserts pairwise distinctness.
2. `parse_redeem_script` v19 arms must be disjoint by construction (match on
   the new lengths); a second test feeds each builder's output through the
   parser and asserts round-trip identity of every field.
3. Policy if two lengths land equal at freeze: append one `OpNop` to the
   YOUNGER body (deterministic, documented in the body comment) — never
   reshuffle state.
4. Danger zone watch: sell(≈775) vs OCO(≈713) are the closest new pair (gap
   ≈ 62B); bracket 372 vs DCA 374 remains the closest legacy pair — both
   asserted.

Re-proof obligation: RS lengths changing means every v18 live proof is void
for v19 bytecode. Stage D therefore re-runs the FULL v18 15-form matrix on
v19 binaries in addition to the new forms (§6) — same standard Stage F of
v18 set ("beyond a smoke").

---

## 6. Live E2E forms (testnet-10; node ws://65.108.107.30:18210, REST
api-tn10.kaspa.org; record TXIDs + `is_accepted` in E2E_LIVE_RESULTS.md,
Stage-G section; rejections recorded via the submit error, v18 style)

Decay:
- **DK-1** decay sell GTC fill mid-schedule: L = tip, seller KAS ==
  `token_in × pnum_eff(L) / pden` exactly (output-level REST verification).
- **DK-2** adversarial: attest the START price after decay has run → covenant
  reject (D4).
- **DK-3** N:M sweep mixing one decaying + plain sells through a plain buy:
  fair_sum consumes f(L) at the canonical offsets.
- **DK-4** boundaries: (i) L=0 fill executes at start price; (ii) fill with
  L > tip rejected `NotFinalized`, re-accepted once DAA > L; (iii) L past
  t_end executes at the floor.
- **DK-5** adversarial: unix-ms-type L (schedule fast-forward) → reject (D2).
- **DK-6** buy-decay partial: bid improved vs deploy-time bid, residual
  re-priced at the next event's L.

TWAP:
- **TW-1** sell TWAP: fill#1 accepted; immediate fill#2 rejected
  (`SequenceLockConditionsAreNotMet`); same fill accepted after twin DAA.
- **TW-2** per-event cap: fta > mpw rejected; fta = mpw accepted; full-fill
  with token_in > mpw rejected (bypass pin).
- **TW-3** buy TWAP partial: two-event window pair, kas spent ≤ mpw each.

Ratchet:
- **RT-1** happy path: genuine settle sibling in-tx, ratchet accepted;
  continuation address == P2SH(derived new_rs) verified via REST; then SL
  fill at the ratcheted price.
- **RT-2** adversarial set (each a recorded rejection): second ratchet inside
  rwin; wrong-step splice (new ≠ old+rstep); mutated non-window byte; print
  below threshold; cancel-sibling fake print (R7); sub-mrv volume;
  travel-cap breach at the TP ceiling; sii = self.
- **RT-3** owner remedy: ratchet lands, owner CANCELs the continuation with
  the original key.

Regression:
- **REG-19** the full v18 15-form matrix re-settled on v19 bytecode
  (GTC N:M, IOC N:M, buy partial multi-event, sell partial Fix-3, OCO TP/SL
  sweeps, cancel-mark→fill-reject→cancel, expire seats, 2-cycle, triangle,
  bracket IFD/IFO forms) — all with dslope=twin=rstep=0 (plain v19 orders).

---

## 7. Stages (each ends: build green → commit, RossKU style)

- **A core**: order.rs sell/buy v19 (state prepend, decay block, TWAP gate,
  dispatch/cleanup depth updates), oco.rs RATCHET branch (R1–R14), parse.rs
  v19 arms + field exposure, builder validations (§2.3/§3.4/§4.2),
  `SPOT_GENERATION = 19`, EXPECTED_LEN pins, collision pin test (§5), and the
  adversarial unit matrix: all of §2.8, §3.6, §4.6 L1–L4/L8/L10/L11 as
  script-level tests (the engine harness used for v18's Sec-6 ports), plus
  NUMEQUAL-vs-EQUAL encoding tests (T6) and the R9 negative-encoding pin.
- **B domain**: planner decay pricing at L=tip + lock_time feasibility solver
  (§2.7), TWAP eligibility/vol planning (§3.5), ratchet plan builder
  (sibling selection + splice derivation), sigscript emission (incl. the
  no-gcd decayed attestation builder), D pin regression.
- **C engine+cli**: executor wiring (sequence = max(50, twin/rwin), lock_time
  plumbing, execute_oco_ratchet), scanner continuation tracking + effective
  price surfacing, API/CLI flags and displays (§2.7/§3.5/§4.7).
- **D live E2E**: testnet-10 forms of §6 (fund via kob-miner if needed; mint
  fresh SPA/SPB pattern tokens); TXIDs recorded.
- **E doc/final**: E2E_LIVE_RESULTS.md Stage-G, E2E_MATRIX.md rows for the
  new forms, README/ENGINE_API_DESIGN touch-ups, this file gets a status
  update stamp (like V18_DESIGN's header), final regression sweep.

Build env: unchanged from V18_DESIGN §Build env (Termux cargo 1.94.1,
`CARGO_TARGET_DIR=/root/kob-rust-target4`, per-crate commands only).

---

## 8. NON-GOALS (explicit)

- **No oracle, no off-chain price import** — all three features consume only
  consensus-observable quantities (tx.lock_time, UTXO age via sequence locks,
  sibling-input sigscript bytes authenticated by covenant id). The ratchet's
  "price" is an on-chain print, declared as such (§4.5).
- **MAX_N = 8 unchanged** (`BUY_ORDER_MAX_N`); v19 adds no sweep slots and
  does not revisit the mass budget argument (concurrent batch-mass
  measurement workstream owns that topic).
- **No `last_fill_daa` field** — rejected as unsound, not deferred (§3.2).
- **No decay or TWAP on OCO/bracket/DCA/swap**; no buy-side trailing ratchet;
  no OCO cancel-mark; no rising-sell / falling-bid schedules (unenforceable,
  §2.1); no multiplicative ratchet steps (§4.1); no ring/swap changes; no
  trigger semantics of any kind (V18 note stands: consistency via arbitrage
  only).
- **No change to v18 fill-math rounding or fair_sum/mmfee semantics** — v19
  only substitutes the pnum operand (decay) and adds gates; the v18 proofs of
  those mechanisms are reused, not reopened.
- **No protocol fee for ratcheting**; no mempool-level anti-spam beyond G1.
