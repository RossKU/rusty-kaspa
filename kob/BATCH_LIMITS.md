# BATCH LIMITS — measured mass ceilings across settle patterns

Status: measurement campaign, 2026-07-17, on the shipping single-generation
spot bytecode (HEAD b37c590). **(Update 2026-07-17, same day: this
campaign's own N=32 measurement became the SHIPPING covenant.) Landed by
commit `317f163c` — `BUY_ORDER_MAX_N = 32` is now shipping
(`kob/core/src/contract/spot/order.rs:16`), not experimental; the
"decision deferred, MAX_N=8 stays" conclusion at the bottom of this file is
STALE, superseded the same day it was written — see the Conclusion section
for the update note.** At measurement time all campaign code was clearly
experimental: `core/src/contract/spot/lab.rs` (parameterized buy-body
variants; **the `max_n = 32` variant is now pinned byte-identical to
shipping**, `lab_max_n_32_matches_shipping_bytes`), `core/tests/batch_limits_lab.rs`
(the offline lab), and `cli/src/bin/kob-batch-lab` (live deploy/settle
driver for the large-N variants, testnet only — the product CLI itself now
natively supports N up to 32).

## Method

1. **Offline lab** — full settle transactions are built with the real
   builders and executed input-by-input through the post-Toccata
   `kaspa-txscript` `TxScriptEngine` (`covenants_enabled = true`,
   `used_script_units()` metered). Masses come from the vendored consensus
   model, reproduced exactly:
   - `size` = `transaction_estimated_serialized_size` (v1: +2B per input
     `compute_budget`, +34B per covenant output)
   - `compute` = `size*1 + spk_bytes*10 + 100 * Σ compute_budget_units`
   - `transient` = `size*4`
   - `storage` = KIP-9 with plurality (35B-P2SH + covenant outputs/entries
     count as 2)
   - min relay fee = `max(compute, ceil(transient*0.5)) * 100` sompi
   - per input: `compute_budget*10,000 + 9,999` free script units;
     stack cap 244; post-Toccata script size cap 1MB.
   Reproduce: `cargo test -p kob-core --test batch_limits_lab -- --nocapture`.
   **Budget-limited regression** (2026-07-18): the mass model above was
   validated offline, but `kob-domain`'s planner-engine-repro harness ran
   every composed tx under an UNLIMITED script-units budget, which missed a
   live under-commit in `plan_ratchet_advance` (`sig_op_count: 0` — only the
   9,999-unit free allowance for a shape that measured 10,311). Permanent
   detector: `kob/domain/tests/budget_limited_repro.rs` runs each planner
   shape's covenant inputs under `input.compute_commit.allowed_script_units()`
   — the SAME per-input limit `check_scripts` commits at consensus — instead
   of `ScriptUnits(u64::MAX)`.
2. **Model validation** — the lab rebuilds the Stage-F live GTC 3:1 shape
   (5-in/4-out, merged seller KAS, D2 token_unit deliveries) and reproduces
   the live compute mass **exactly: 6,563 grams** (test
   `live_form3_compute_mass_reproduced`). Both live transactions below also
   matched prediction (12,137 predicted vs 12,225 node-reported on a
   slightly different CLI shape; 53,337 predicted vs 53,337 node-reported).
3. **Live validation** — testnet-10, node `ws://65.108.107.30:18210`, REST
   `api-tn10.kaspa.org`, wallet `kaspatest:qz6qc3j…a6v8lf`, funded by
   `kob-miner` (8+6+3+12 blocks this run).

**Budgets.** Two reference lines appear throughout: the conservative
pre-Toccata standard cap of **100,000 grams per dimension** (the number the
Stage-F results quote), and the limits actually enforced on tn10 today
(Toccata active since DAA 467,579,632): **compute ≤ 500,000, transient
≤ 1,000,000, storage ≤ 500,000** per transaction (block-fit). The mempool
fee floor prices `max(compute, transient/2)`; storage has no fee but is a
hard per-tx cap — and it turns out to be the *binding* constraint for real
batch sizes (see the storage section).

## Shipping covenant — GTC sweep N ∈ {1,2,4,8} (HISTORICAL: pre-317f163c shape)

**(Update 2026-07-17): this table measures the then-shipping 8-slot-max buy
body (RS 1720B). `317f163c` replaced it with the 32-slot body (RS 5655B)
the same day — the bytes below no longer match current shipping RS
lengths/masses, though the linear compute-mass fit still holds as a model.
Kept as measurement history; see "Live validation" below and
`kob/RELEASE_STATUS.md` for current shipping numbers.**

Distinct-seller shape (`N` seller-KAS + `N` delivery outputs + change),
100M-sompi sells at 99/100, buy 1/1:

| N | tx bytes | compute | transient | storage | min fee (sompi) | buy script units |
|---|---|---|---|---|---|---|
| 1 | 2,784 | 4,864 | 11,136 | 38,769 | 556,800 | 3,870 |
| 2 | 3,515 | 6,315 | 14,060 | 76,492 | 703,000 | 4,160 |
| 4 | 4,977 | 9,217 | 19,908 | 146,854 | 995,400 | 4,743 |
| 8 | 7,901 | 15,021 | 31,604 | 278,194 | 1,580,200 | 5,907 |
| 8 (merged seller — engine shape) | 7,537 | 12,137 | 30,148 | 198,648 | 1,507,400 | 5,907 |

Linear fit (distinct sellers): **compute ≈ 3,413 + 1,451 per sell**. The
live Stage-F point (6,563 @ N=3, merged shape) sits on the merged variant
of the same model and is reproduced exactly by the lab. ~~Every shipping
sweep runs on budget-0 covenant inputs (≤ 9,999 free script units — N=8
uses 5,907).~~ **(Update 2026-07-17, FALSE against current shipping):**
`317f163c` made the shipping buy body a fixed 32-slot unrolled covenant
(RS 5655B) — buy fill inputs now declare `sig_op_count = 1` (10 budget
units, 100,000 extra script units) **at every N**, because the covenant's
static instruction count is dictated by the 32-slot body regardless of how
many sells actually fill; budget-0 no longer holds for the shipping
covenant at any N. See "Live validation" below (the live N=32 run declared
`sig_op_count = 1`) and `kob/RELEASE_STATUS.md`.

## MAX_N ∈ {16,32,64}: 32 is SHIPPING, 16/64 remain experimental

**(Update 2026-07-17): the `max_n=32` variant below is BYTE-IDENTICAL to
the shipping buy body since `317f163c` — `lab_max_n_32_matches_shipping_bytes`
pins it. Only 16 and 64 remain purely experimental (`kob-batch-lab` only,
product CLI refuses those RS lengths by design).**
`lab::build_buy_body_lab(max_n)` — same emitters, more unrolled slots.
RS grows ~**149–155 B per slot** (1,720 → 2,912 @16 → 5,392 @32 → 10,352
@64). At N = MAX_N, 400M-sompi sells, distinct sellers:

| MAX_N | RS bytes | tx bytes | compute | transient | storage | buy units | budget units |
|---|---|---|---|---|---|---|---|
| 16 | 2,912 | 14,949 | 27,929 | 59,796 | 118,658 | 10,672 | 1 |
| 32 | 5,392 | 29,157 | 53,757 | 116,628 | 239,054 | 20,369 | 2 |
| 64 | 10,352 | 57,573 | 105,313 | 230,292 | 479,900 | 39,761 | 3 |

All pass the real TxScriptEngine. Binary-searched ceilings:

| ceiling | N_max | binding constraint |
|---|---|---|
| compute ≤ 100,000, distinct sellers | **60** (98,881 grams; N=61 → 100,488) | compute mass |
| compute ≤ 100,000, merged seller | **81** (99,888 grams) | compute mass |
| TxScriptEngine hard limit (mass ignored) | **227** | stack: N=228 fails `StackSizeExceeded(245, 244)` |
| distinct-seller sigscript convention | 255 | koi is a forced 1-byte push in the canonical attestation |
| actual tn10 block-fit (500k compute) | > 227 | the VM stack dies first |

Buy-input execution cost is ~600 script units per sell: **budget-0 (the
shipping `sig_op_count → computeBudget` mapping) holds only to N≈15**;
N=16 already needs `computeBudget = 1` (10,672 units), N=32 needs 2, N=64
needs 3 — each unit costs 100 grams of compute mass and must be declared
per input (the live N=32 run declared 10 via `sig_op_count = 1`).

## Other patterns at their maxima

| pattern | N | tx bytes | compute | transient | storage | min fee | notes |
|---|---|---|---|---|---|---|---|
| IOC sweep (ship) | 8 | 7,901 | 15,021 | 31,604 | 278,194 | 1,580,200 | identical shape to GTC |
| buy Op2 partial + residual (ship) | 8 | 7,955 | 15,445 | 31,820 | 300,552 | 1,591,000 | |
| buy Op2 partial (experimental) | **14** | 13,242 | 25,152 | 52,968 | 489,654 | 2,648,400 | **hard ceiling N=14**: the P5 uniqueness guard scans 16 inputs; N=15 (17 inputs) engine-rejected |
| sell-side IOC batch (one payer) | 8 | 6,882 | 16,962 | 27,528 | 293,601 | 1,696,200 | 400M sells, fta 200M; 2 covenant outputs/sell (residual+delivery) doubles the storage bill |
| OCO-heavy sweep (8 OCO sells × 1 buy) | 8 | 6,957 | 14,077 | 27,828 | 266,708 | 1,407,700 | OCO RS 397B < sell 515B → cheaper than plain-sell sweep |
| ring (shipping swap bytecode) | 2 | 1,078 | 3,158 | 4,312 | 61,170 | 315,800 | |
| ring | 3 | 1,484 | 3,924 | 5,936 | 84,312 | 392,400 | |
| ring | 4 | 1,890 | 4,690 | 7,560 | 104,148 | 469,000 | passes the engine; ~~`RING_MAX = 3` is planner policy, not covenant~~ **(Update: `317f163c` raised `RING_MAX` to 8, `kob/domain/src/spot/batch.rs:2769`)** |
| ring | 5 | 2,296 | 5,456 | 9,184 | 121,337 | 545,600 | |
| ring | 6 | 2,702 | 6,222 | 10,808 | 136,375 | 622,200 | |
| ring @ legs_max | **128** | 52,456 | 99,896 | 209,824 | 16,789 | 10,491,200 | ~766 grams/leg; storage nearly cancels (full-value in = out) |
| bracket fill (rigid 4-in/4-out) | 1 | 1,161 | 5,611 | 4,644 | 175,384 | 561,100 | fixed shape, no N axis |

Answer to "can a ring exceed 3 legs?": yes — the swap covenant's checks are
purely local (giver/receiver pin both ends of each edge), so 4-, 5-, 6-…
up to ~128-leg chains fit under even the 100k compute cap and pass the
engine on the SHIPPING bytecode. ~~Only `plan_ring_match` caps at 3.~~
**(Update 2026-07-17): `plan_ring_match` now caps at `RING_MAX = 8`**
(`317f163c`, `kob/domain/src/spot/batch.rs:2769`) — still a planner-policy
cap, not a covenant limit (the covenant itself is VM-proven to 128 legs).

## Storage-mass edge (KIP-9): the real batch limiter

Deliveries are covenant P2SH outputs → plurality 2 → each costs
`4×10¹²/value` grams. Shipping GTC N=8, distinct sellers, 10-KAS fee input,
sweeping per-sell value `v`:

| v (sompi-units per sell) | compute | storage | binding dim | fits 500k block? |
|---|---|---|---|---|
| 20,000,000 | 15,021 | 1,760,592 | storage | NO |
| 40,000,000 | 15,021 | 806,466 | storage | NO |
| 60,000,000 | 15,021 | 504,714 | storage | NO |
| 65,000,000 | 15,021 | 459,810 | storage | yes |
| 100,000,000 | 15,021 | 278,194 | storage | yes |
| 400,000,000 | 15,021 | 58,424 | storage | yes |
| 2,000,000,000 | 15,021 | 12,230 | compute | yes |

- **Exact N=8 floor: v ≈ 60,485,626 sompi-units per sell** (bisected) —
  below ~0.6 KAS per delivery an 8-sweep cannot land at all, regardless of
  fee. Compute only becomes the max dimension above v ≈ 2 KAS.
- The floor scales with N (merged shape, single 10-KAS fee input): N=16 →
  ~84.2M, N=24 → ~115.9M, N=32 → ~148.4M, N=60 → ~267.3M per sell.
- **In/out cancellation**: matched trades get the escrow inputs' plurality
  credit — the same 8×100M delivery set costs 278,194 storage in the sweep
  but 402,408 if conjured from one wallet UTXO. The credit is
  `C·|I|²/Σin`, so it grows with input COUNT and shrinks with input VALUE:
  padding the settle with small wallet inputs buys storage headroom
  (the live N=32 run below used 10×50M pads + a 50M fee input to hold
  100M-unit sells at storage 449,449), while adding large inputs makes it
  worse. This is also why note 2 of the Stage-F ops notes ("KOB_FEE_FLOOR
  on covenant-heavy shapes") coexists with storage never having been the
  reported blocker: at Stage-F values (30M) N was 3, not 8.

## Live validation (testnet-10, 2026-07-17)

**(a) Shipping N=8 GTC sweep — the product ceiling.** 8 sells (100M units
of `690fa2aa…` @ 99/100; deploys `803d57ce…`, `527ae253…`, `e1df9aab…`,
`a744ee96…`, `adba86db…`, `f6c844c1…`, `3f0315b6…`, `1e55e186…`) + 1 buy
(8 KAS @ 1/1, mmfee 200 bps, `fe6cbda0…`) settled by `kob-cli match-batch`
(`KOB_FEE_FLOOR=1700000`) in one 10-in/10-out tx — merged 792M seller KAS
+ 8 covenant deliveries + change:

> TXID **`405dbe39ecdf8f02721aef81ea4f6a78ff104bd3f9202e88b0d91ad55ad8fb11`**
> — `is_accepted: true`, blue score 508,255,642, node mass **12,225**
> (lab merged-shape prediction 12,137; the +88 is the CLI's koi/change
> details). 12.2% of the conservative 100k cap, 2.4% of the tn10 block
> compute limit.

**(b) MAX_N=32 sweep — one transaction, 32 fills.** At measurement time
this was EXPERIMENTAL: covenant built by `lab::build_buy_redeem_script_lab(32,…)`
(RS **5,392B**), deployed and settled by `kob-batch-lab` (the product CLI
of the time refused this RS length by design). **(Update, same day):**
this measurement is what `317f163c` promoted to shipping — RS 5,392B here
vs. shipping 5,655B (the extra bytes are the `n_max`/`batch_max` owner-cap
fields added in the same commit); the product CLI now natively builds this
shape. 32 sells (100M units of V18A
`eab5c99a…` @ 99/100) + one 32-KAS experimental buy
(`ca232d1325e078921e80db7e9d54349b3d5b6a2004b923e25f0d83ef26be603f:0`),
settled in ONE 44-in/34-out tx (32 sells + buy + fee + 10 storage-credit
pads; merged 3.168-KAS…×10⁹ seller output + 32 bound token_unit
deliveries + change; buy input declared `computeBudget 10` for its ~20.4k
script units; fee 5,765,400 sompi):

> TXID **`536047f38c5440ffd6f0f6ab0f3d4eb712b6cd2cc9cad454dffb491b1ca7564b`**
> — `is_accepted: true`, blue score 508,265,603, node mass **53,337 —
> exactly the lab prediction**. REST shows all 32 delivery outputs with
> `covenant_id = eab5c99a…` and `covenant_authorizing_input` 0…31.

Bookkeeping: V18A mint authority advanced twice this run (fixture updated
to `c5feddf6…:0`); wallet end state 83.65 KAS free + token units; both
books left empty. One pre-existing quirk hit en route: a legacy V18A unit
UTXO from an older campaign fails its owner-path spend ("script ran, but
verification failed"), which stalls `deploy sell`'s default unit selection
— worked around with `--token-utxo` (fresh mint); not a covenant issue.

## Conclusion

~~Shipping MAX_N=8 uses ~12–15% of even the conservative 100,000-gram
standard budget (live: 12,225 grams at N=8, 2.4% of the actual 500k tn10
compute limit); the measured compute ceiling for one sweep is N≈60
(distinct sellers) / N≈81 (merged) under the 100k cap, N=227 at the VM's
stack limit, and a live 44-input N=32 settle is proven on-chain — but the
*practical* limiter is KIP-9 storage, which demands ≥ ~0.6 KAS per
delivery already at N=8 and ~1.5 KAS at N=32, plus a computeBudget
declaration (engine/executor change) beyond N≈15. Raising MAX_N would cost
a covenant re-freeze (~155B of RS per slot), fee-model and budget plumbing,
and buys little while order values sit near the storage floor — decision
deferred; MAX_N=8 stays.~~

**(Update 2026-07-17, same day — the decision above was NOT deferred, it
was made within hours of this campaign):** `317f163c` landed MAX_N=32 as
the shipping covenant the same day this campaign ran (live-proven N=32
settle `536047f3…`, node mass 53,337 = exactly the lab prediction, ~53% of
the conservative 100k-gram budget). The measured ceilings above (N≈60/81
compute-bound, N=227 VM-stack-bound) remain accurate as upper bounds beyond
32 — they were simply not the number chosen; N=32 was picked as the
live-proven, comfortably-under-budget point, not the maximum theoretically
reachable one. The `computeBudget` declaration this file flagged as an
"engine/executor change... beyond N≈15" is now unconditional at every N
(`sig_op_count = 1` on every buy fill input, `317f163c`) since the 32-slot
body's static size exceeds the 9,999-unit free allowance regardless of how
many sells actually fill. `RING_MAX` was raised 3 → 8 in the same commit
(`kob/domain/src/spot/batch.rs:2769`). Current shipping status:
`kob/RELEASE_STATUS.md`.
