# KOB Live testnet-10 E2E — post-hardening full run

## TIME CONTRACTS combined live E2E — Stage-G (Stage D of TIME_CONTRACTS_DESIGN) — 2026-07-17

Combined live re-proof on testnet-10 of the four additive TIME contracts
(decay_sell, decay_buy, twap_sell, ratchet_oco), the four §6 compositions,
the six LIMITS-re-frozen contracts (`317f163` voided their prior proofs), and
the on-chain caps + competing-matcher tests. HEAD `9ba03e8` (Stage C) + this
run's CLI-glue fixes. Node `ws://65.108.107.30:18210`, REST verification via
`api-tn10.kaspa.org` (every accept re-checked `is_accepted:true` + output
level). Wallet `kaspatest:qz6qc3j…cfy7qrwa6v8lf`. Token **V18A**
`eab5c99a…a4b4` (12 fresh chained mints off authority `c5feddf6…:0`).

Current tn10 note: virtualDaaScore (~519.37M) runs ~10.9M ABOVE blueScore
(~508.44M) — DAA counts red blocks. `tx.lock_time` is compared against the
accepting block's DAA score, so schedules and NotFinalized tests are designed
against virtualDaaScore, not blue score.

**Glue (this run, non-covenant; separate `fix:` commit):**
- `match-batch --sell-rs/--buy-rs <hex>`: RS override so the CLI batch driver
  can settle a decay_sell/twap_sell (swept by a plain v18 buy) or a decay_buy
  anchor — the order cache stores no schedule fields, so the cache-rebuilt
  plain RS would hash to the wrong P2SH. The planner re-classifies the kind
  from the RS bytes (`classify_sell`), so the covenant path is 100% the tested
  product plumbing.
- `kob-e2e-util decay-fill` / `twap-fill`: direct single-order fills with a
  CHOSEN attested (pnum,pden) + lock_time (decay) or sequence + fta (twap),
  for the adversarial matrix the engine/planner never build.

### decay_sell (DK-1..4)

| Form | Path | Result | TXID / evidence |
|---|---|---|---|
| DK-1 | `decay-fill` L=508,440,502 att=f(L)=2,559,498/1M on decayB (t0 507M/t_end 510M/slope 1) | **ACCEPT** — REST out[0]=**76,784,940** = 30M×2,559,498/1M EXACT, out[1]=30M token_unit delivery | **`1433dd7989cbb88cc7db98b5e9c55bc3498e9f6dfaf8f9de65862a8beee0a97d`** (blue 508440136) |
| DK-2 | `decay-fill` attest START 4M/1M at a mid L (f(L)<4M) | **REJECT (D3)** — NUMEQUAL(att, f(L)) fails | submit err `…31efc52d…: script ran, but verification failed` |
| DK-3i | `decay-fill` **L=0** att=start 4M/1M on decayE | **ACCEPT** — L=0 clamps eff→t0→start; REST out[0]=**120,000,000**=30M×4 | **`3a42f14806d52daa24d3ff8476dae40745c7773c463e01c8e524f104b3ecb496`** (blue 508441422) |
| DK-3ii | `decay-fill` L=DAA+150 (>tip) att=floor on decayA | **REJECT then ACCEPT** — submit#1 `…: transaction input #0 is not finalized`; after DAA passed L, submit#2 ACCEPT, REST out[0]=**30,000,000** (floor) | **`377f3ee9adf22d3fe1b71682199364f3438c70b48490c91ad52eced66464b5c5`** (blue 508441205) |
| DK-3iii | `decay-fill` L=tip (>t_end) att=floor 1M/1M on decayC (t0 506M/t_end 507M, already floored) | **ACCEPT** — REST out[0]=**30,000,000**=30M×1 (floor) | **`8ed2fe16feac5a8b133efac8b15c69ebf21f05c8807afc8b5f07e8cdc64c4e43`** (blue 508441445) |
| DK-4 | `decay-fill` L=1.752e12 (unix-ms, <median so minable) att=floor | **REJECT (D1)** — type guard `L<5e11` fails in-script | submit err `…9eb17d12…: script ran, but verification failed` |

### twap_sell (TW-1..2)

| Form | Path | Result | TXID / evidence |
|---|---|---|---|
| TW-2a | `twap-fill` FULL 30M > mpw 20M, seq=60 on twap_A | **REJECT (W2 bypass pin)** | submit err `…90802ce7…: script ran, but verification failed` |
| TW-2b | `twap-fill` partial fta=25M > mpw 20M, seq=60 | **REJECT (W2)** | submit err `…7d1f8ba2…: script ran, but verification failed` |
| TW-2c (=TW-1 fill#1) | `twap-fill` fta=60M = mpw, seq=60 on twap_B (100M, mpw 60M) | **ACCEPT** — residual 40M at `:1` | **`fd1c5ce345170114aacbe7be36f77589c9d6411f8e572dd9e6dd0a2ff6120c98`** |
| TW-1 fill#2 (residual) | `twap-fill` full 40M on the residual, seq=60 | **ACCEPT** (residual had aged past twin=60 in the RPC latency — twin=60≈4s at tn10 rate) | **`84688e420820900c4c963f9e284be805366ca98383fa95a3cbb7a6ea6175f77f`** |
| TW-1 sequence gate | twap_C (twin=1000): fill#1 fta=60M → residual; fill#2 immediate ×7 attempts | **ACCEPT / REJECT / ACCEPT** — fill#1 `9ab1b48e…` ACCEPT; fill#2 immediate + 6 retries REJECTED `…: one of the transaction sequence locks conditions was not met` (twin CSV, residual not aged); retry#7 (~72s later, DAA +1000) **ACCEPT** `e61843f3…` | fill#1 **`9ab1b48e3a5dd17fe0b8f42560262e544b7ef6ce475af5839331e28d2bd8fe57`**, fill#2 **`e61843f3165616a88614dc91c78d87ee41d2aa219c8f28a85f57e074963d69e5`** |

Storage note: multi-covenant-output settles at 30M/delivery breach the KIP-9
500k storage cap (each 30M covenant output ≈ 4e12/30e6 ≈ 133k grams);
compositions/caps below use ≥100M deliveries (fresh mints) so storage clears,
exactly as BATCH_LIMITS.md documents.

### Re-frozen six-contract re-proof (item 3) + compositions

| Form | Path | Result | TXID |
|---|---|---|---|
| Re-proof plain buy(5655B)+sell(542B) 1:1 | `match-batch` plain, sell 30M @99/100, buy 30M @1/1 | **SETTLED** — RS lengths confirmed **542 / 5655**; REST out[0]=29,700,000 seller KAS, out[1]=30M delivery | **`0e755001ea413a13e747958937d09de1c6d19a74d1fd67fdbf528d139292d4e6`** (blue 508726893) |
| **CP-1** buy sweeps decay_sell + plain sell | `match-batch --sell-rs <decay649B>,` (decay floored f=1, plain @4) | **SETTLED** — REST out[0]=**500,000,000** merged (decay 100M×1 + plain 100M×4), out[1/2]=100M covenant deliveries, out[3]=10M matcher fee at cap | **`1a439c5d5b6b4f371c5b62fd1fd3303ad7e478fc749a5deeb15bd6294ed965a3`** (blue 508727861) |
| **CP-2** buy sweeps twap_sell + plain sell | `match-batch --sell-rs <twap596B>,` (twap seq=twin auto) | **SETTLED** — out[0]=800M merged (twap 100M×4 + plain 100M×4), out[1/2]=100M deliveries, **out[3]=344,878,289 wallet change** (fee-fix), fee 1.6M | **`5349126dc876b50a46ea6fab43cd50dd5af7f861a2807829b0901ed5156cfa8e`** |
| **CP-4 / DB-1** decay_buy settles plain v18 sell (full) | `match-batch --buy-rs <decaybuy5895B>` (rising bid) | **SETTLED** — decay_buy RS **5895B**; risen-bid floor at L=519,653,657 = 25.2M/1M×pnum_eff(3,346,343)=84.3M < 100M avail (fewer tokens than the 100.8M it demands at deploy pnum=4M); REST out[0]=25,690,525 seller KAS, out[1]=102,762,100 delivery | **`42373b6a42e09f6ed9504fbddd5582d6ab5979e5cc9eb9e32601dd15c996da7a`** (blue 508728937) |

### CLI/planner fix surfaced by this run (separate `fix:` commit)

**`plan_gtc_sweep_core` wallet-fee-input overpay** (`domain/src/spot/batch.rs`):
the GTC sweep folded the wallet fee input's VALUE into the matcher "surplus"
and left everything past the bps cap to the miner fee — with NO WalletChange
output. With a large fee UTXO this dumped multi-KAS to the miner (observed:
CP-1 fee ~371M sompi, DB-1 fee ~499M sompi before the fix). The covenant
ACCEPTED these txs (not a covenant defect — a matcher-side overpay). Fix:
bound the matcher take to the buy's actual over-escrow (`buy.utxo_value −
fair_sum`), and emit a `WalletChange` output returning the fee-input remainder
to the matcher wallet; `apply_exact_fee` recovers the Phase-2 delta there.
Regression test `test_wallet_fee_input_returned_as_change_not_dumped`.
**Live confirmation: CP-2 fee dropped 371M→1.6M and out[3]=344.9M change
returned.** 4-crate regression green (test_wallet_fee… + all others).

| **DB-2** decay_buy partial + residual | `match-batch --partial --buy-rs` (decay_buy 200M escrow fills 100M sell @1/4) | **SETTLED** — REST out[0]=25M seller KAS, out[1]=100M delivery, out[2]=**174,500,000 decay_buy KAS residual** (self-P2SH continuation; re-prices at the next event's L via its byte-identical state — unit `decay_buy_partial_repriced`) | **`bbd6825d5b3c4845692e94462aa9d1a76c26801d1abd8dd90309278745c4b024`** |

Fix note extended: DB-2 (partial path) initially overpaid the fee (800.5M
sompi) — the `plan_partial_sweep_core` and the IOC/sell-IOC cores share the
same wallet-dump pattern as the GTC core. Fixed `plan_partial_sweep_core`
identically (matcher take bounded to `buy_kas − seller_kas − residual`, wallet
remainder → WalletChange). The IOC (`plan_ioc_sweep_core`) and sell-IOC
(`plan_sell_ioc_match_at`) cores have an entangled buyer-refund/kas-remaining
model (Stage-F-proven) and are NOT restructured this run; instead
`match-batch` now selects the SMALLEST sufficient fee UTXO, bounding any
residual overpay there. None of the remaining Stage-G forms use the IOC/
sell-IOC match-batch paths.

### Caps on-chain (item 4) — n_max / batch_max

| Form | Path | Result | Evidence |
|---|---|---|---|
| CAP n_max reject | `match-batch` buyN1(n_max=1) sweeps 2 sells (RS override) | **REJECTED (planner cap)** | `Error: v18 sweep has 2 sells, exceeds BUY_ORDER_MAX_N=1` |
| CAP batch_max reject | `match-batch` buyN2 sweeps sellA + sellC(batch_max=1) | **REJECTED (planner cap)** | `Error: sell 3ac23889…:0 carries batch_max=1 but the planned batch has 2 same-token inputs` |
| CAP in-bounds accept | `match-batch` buyN2(n_max=2) sweeps 2 sells (batch_max=2) | **SETTLED** — REST out[0]=200M merged seller KAS, out[1/2]=100M deliveries, out[3]=23,799,021 wallet change | **`ac9eeaf0a253297e56c194beb2340267341c28854f940150318a68c938b0d1d4`** |

The n_max/batch_max are enforced by the planner pre-flight (BatchCapExceeded /
TooManySells) — a conforming matcher cannot build an over-cap tx. The COVENANT
backstop (a hand-built over-cap spend rejected by script) is proven by the
`317f163` Stage-A adversarial unit suite (N=33 covenant reject, N > n_max,
per-sell batch_max in a batch, 34/35-input guard boundary) against the real
`kaspa-txscript` engine. A live hand-built over-cap submission was NOT run this
pass (the product planner refuses to build one; would need a bespoke
planner-bypass driver) — noted as the one covenant-level caps deferral.

### ratchet_oco (RT-1..3) + CP-3 + competing matcher (item 5)

| Form | Status | Evidence |
|---|---|---|
| ratchet_oco deploy | **DEPLOYED LIVE** — RS **760B** | historical first deploy (pre-fix, superseded): `5d05efae518faaa9d8f354adc5076b904ef00cbd23c5189d1292633859529e10:0`, `d889a65c8be367da81aad2ae77499b2cafd759f599e2f7642dd62a491f748e00:0`. Final live-proof redeploy (this run): **`dfa23cc165096495a0014a71f583f07cc225e7e5d9af667faba71b20d6842397:0`** (TP 101/100, SL 25/100, rstep 1, rgap 0, rwin 60, mrv 8M, 100M escrow) |
| **RT-1** ratchet advance (engine) | **SETTLED LIVE** — settle + SL advance composed and accepted in ONE tx | **`5759da5e5b09abacd9c862f5a871be47277dade07d851263434bfa74f6d5e0fd`** (blue score 508862900); continuation `…5e0fd:3` = 100,000,000 sompi at `kaspatest:pzaz097ufhkjmcsnrzw9gs25czejcxhx5cjek7a30cp2crgeg0nnj4jxjxlaa` (SL stepped 25/100 → 26/100, k=1) |
| RT-2 adversarial set | DEFERRED (covenant unit-proven) — scope note below | Stage-A `time_contracts.rs` L1–L11 |
| RT-3 owner cancel of continuation | **SETTLED LIVE** — owner recovers full escrow with the original key | **`956af539b2a428cd3f18477008b901c5aee0446e1eb5309a59ed489a5a499bdd`** (blue score 508892097) |
| **CP-3** buy sweeps ratchet TP | **SETTLED LIVE** — v18 buy fully sweeps the TP branch | **`10ff461089cfa59ad08fa67999e20e9ac69d8d50a678144a45b5d972b00539c8`** (blue score 508874731) |
| Competing matcher (item 5) | DEFERRED live (unit-proven) | Stage-C weighted-selection/race/backoff tests |

**RT-1 — RESOLVED this run (2026-07-18), two sequential engine-glue bugs fixed.**

*Bug 1 (fixed in `ec4881d`, prior run): transient-mass fee floor.* The engine's
settle fee was the compute-mass `min_relay_fee` and did not bump to the node's
byte-proportional transient floor for covenant-heavy shapes (`has 886100 fees
which is under the required amount of 1354200`). Fixed by absorbing the
deficit from WalletChange-then-MatcherFee in `execute_oco_ratchet`
(`KOB_FEE_FLOOR` env knob).

*Bug 2 (fixed this run, retry of the same live scenario): per-input script-units
budget.* With bug 1 fixed, the engine advanced past the fee floor to an actual
submit attempt, but the node rejected it: `script units exceeded the amount
committed in the input: used=10311, limit=9999`. Root cause: the ratchet
advance's covenant input (`plan_ratchet_advance` in
`kob/domain/src/spot/time_planner.rs`) committed `sig_op_count=0`, i.e.
`computeBudget=0`, relying entirely on the node's flat 9,999-script-unit free
per-input allowance (`compute_budget_for_sig_ops`,
`kob/settle/src/tx.rs`) — sized for a standalone ratchet fill, not the heavier
splice+introspection work of a *composed* settle+advance (measured 10,311
units live). Fix: `sig_op_count: 1` on that input (same headroom trick already
used for the lab buy input in `kob_batch_lab.rs`), buying 10 budget units
(100,000 extra script units, total allowance 109,999). This is a pure
consensus wire-field change (no covenant bytecode touched) — confirmed no
covenant script introspects computeBudget. Domain regression green (639
tests, incl. updated `ratchet_advance_happy_path_and_compose`).

**Live proof (fresh redeploy after the fix, this run):** continuous engine
(fresh cursor, `--allow-self-trade --api-port 0`, `KOB_FEE_FLOOR=2500000`),
deployed ratchet_oco `dfa23cc1…:0` + sibling print sell (97/100, 100M) + v18
buy (1/1, 100M) after the banner. Engine discovered the ratchet_oco, formed
the sibling-settle group (`Group kind=Batch sells=1 buys=1 surplus=300000`),
composed settle+advance (`Storage mass pre-check: 68542/500000`,
`compute=13663`), and submitted successfully:
`[RATCHET] SUCCESS! TXID: 5759da5e… (settle + SL advance in one tx)`.
REST-confirmed accepted; out[0]=97,000,000 (seller KAS), out[1]=100,000,000
(buyer token delivery), out[3]=100,000,000 at the predicted k=1 continuation
address (full escrow rides through, SL only advances 25/100→26/100 — TP
unchanged at 101/100).

The **ratchet ADVANCE covenant composition** (compose_settle_and_ratchet →
R1–R13 acceptance, continuation P2SH = P2SH(pnum_sl+rstep), R13f binding) is
proven against the real `kaspa-txscript` TxScriptEngine by the Stage-A/C
engine-repro tests (`time_contracts.rs::ratchet_happy_one_step_with_genuine_settle`,
`planner_engine_repro` sell-initiated settle+ratchet) — the authoritative
method, as used for harness-authoritative forms in prior stages. Note: these
engine-repro tests execute via `TxScriptEngine::from_transaction_input`
(unlimited/default script-units accounting), not the
`_with_script_units_limit` variant `batch_limits_lab.rs` uses to observe real
usage — this is *why* the RT-1 script-units gap above was invisible to the
existing test suite and only surfaced live. Worth a follow-up: add a
budget-limited regression for the composed settle+advance shape so this class
of gap is caught pre-live next time.

**CP-3 — SETTLED LIVE (2026-07-18, this run).** Buy sweeps the TP branch of
the ratchet_oco continuation (`…5e0fd:3`, TP 101/100, unaffected by RT-1's SL
advance). Driven via `kob-cli match-batch --sell-rs <k1 RS>` (the order cache
has no entry for an engine-produced continuation output, so one was added by
hand with `price_num/price_den = 101/100` to select the TP branch — the
intended use of the cache per its own error message, `"...Deploy it first or
add manually."`). The OCO-branch-selection glue (the previously-uncommitted
`match_batch.rs` change) correctly parsed the RS and selected `OCO TP branch
101/100` on the first try and every try after.

Two planning errors were hit and resolved before the accept — **both were
operator/CLI-usage mistakes, not code bugs, on investigation:**
- First attempt (buy 20,000,000 @ 102/100, a genuine partial of the 100M
  escrow): `Error: Insufficient fee UTXO: need 201524200 have 126616223`.
- Retry sized to fully sweep the escrow, still with a KAS-per-token-style
  price (buy 102,000,000 @ 102/100): `Error: Sell[1] partial fill 100000000
  KAS below min_fill 104040000`. This looked like a unit-confusion bug
  (104,040,000 = 100,000,000 × 1.02², the buy's own price ratio applied
  twice) — but tracing `plan_gtc_sweep_core`'s `floor_tokens = utxo_value *
  price_num/price_den` (`kob/domain/src/spot/batch.rs`) back to the **actual
  on-chain covenant bytecode** (`kob/core/src/contract/spot/order.rs:568`,
  comment `floor_value = spent/pden*pnum`) confirms the formula is correct
  and the planner faithfully mirrors the deployed contract. The real issue:
  **buy `--price-num`/`--price-den` is documented as tokens-per-KAS** (`kob/
  cli/src/lib.rs:922-929`, "Price numerator (tokens per KAS)"), the *inverse*
  of a sell's KAS-per-token convention — both CP-3 deploys used the sell-side
  convention by mistake, which for a buy states "I demand ≥1.02 tokens per
  KAS", i.e. a price *below* what the 101/100 KAS/token TP ask offers, making
  the fill mathematically impossible. No code was changed for this: the buy
  was redeployed with the correct direction, `--price-num 98 --price-den
  100` (0.98 tokens/KAS ⇒ buyer accepts paying up to ~1.0204 KAS/token,
  comfortably above the 1.01 KAS/token TP ask) — `3291c6b5a7d095394885dbe65e1
  f34cc3ecc8733fe77b33843d346e9a09525da:0`.

**Live proof:** `KOB_FEE_FLOOR=2500000 kob-cli match-batch --sell-outpoints
…5e0fd:3 --buy-outpoints 3291c6b5…:0 --sell-rs <k1 RS> --fee-bps 500`.
Phase-1/Phase-2 fee convergence landed at 2,500,000 sompi (floor override),
storage mass 172,216/500,000 OK. Submitted and **REST-confirmed accepted**:
`10ff461089cfa59ad08fa67999e20e9ac69d8d50a678144a45b5d972b00539c8` (blue
score 508874731). out[0]=101,000,000 sompi to the seller (=100M tokens ×
101/100 TP price, exact), out[1]=100,000,000 token delivery to the buyer,
out[2]=5,116,223 wallet change. No covenant defect, no planner defect — the
OCO-branch-selection glue and `plan_gtc_sweep_core`'s GTC floor check both
worked correctly against the real ratchet_oco TP branch on the first
correctly-priced attempt.

**RT-3 — SETTLED LIVE (2026-07-18).** A fresh ratchet_oco/sibling-sell/buy
cycle (identical params to the RT-1 proof) was deployed and the continuous
engine composed the same settle+SL-advance
(`e50ee3424b6f60ed91fb1a72ba8f1472b26f22ebdbb4f51b1bedc4b24a6fcf60`, accepted;
continuation `…fcf60:3` = 100,000,000 sompi at the same deterministic k=1
address as the RT-1 proof, confirming the splice is byte-for-byte
reproducible). The owner then cancelled that continuation with the original
key — **new CLI capability added for this**: `kob-cli cancel` could
previously only reconstruct a plain v18 sell/buy redeemScript from
`--price-num`/`--price-den`/`--min-fill`; it had no way to cancel an
OCO/ratchet_oco shape (extra TP/SL/rstep/rgap/rwin/mrv fields, per the same
gap `match-batch` closed earlier with `--sell-rs`). Added a `--rs` hex
override (`kob/cli/src/cancel.rs`, `kob/cli/src/lib.rs`) that uses the exact
on-chain redeemScript verbatim instead of reconstructing one; confirmed the
cancel sigscript envelope (`build_sell_cancel_sigscript`) is already
content-agnostic (just embeds whatever RS it's given), so this is the only
change needed — proves §4.8's "OCO cancel byte-preserved through ratchets"
end-to-end for the first time outside a unit test. `kob-cli cancel-mark` and
the batch/TIF auto-cancel paths (`kob/cli/src/batch.rs`, `kob/cli/src/tif.rs`)
were updated to pass the new parameter through unchanged (`None`, no behavior
change) since they only ever cancel plain v18 orders.

First attempt with the auto-selected (small, ~3.1M sompi) fee UTXO was
rejected by the node: `transaction storage mass of 603305 is larger than max
allowed size of 500000`. Root cause (operator/UTXO-selection, not a code
bug): the cancel's own recovered-KAS change output ended up tiny (~1.5M
sompi after the miner fee), and KIP-9 storage mass is inversely related to
output value — a small-value output costs disproportionately more storage
mass than a large one. Fixed by pointing `--fee-utxo` at one of the wallet's
large (~346M sompi) UTXOs instead of relying on auto-selection, which made
the KAS change output large too; storage mass dropped from 603,305 to 13.
Resubmitted and **REST-confirmed accepted**:
`956af539b2a428cd3f18477008b901c5aee0446e1eb5309a59ed489a5a499bdd` (blue
score 508892097). out[0]=100,000,000 token refund to the owner's token_unit
P2SH, out[1]=344,878,289 KAS change. Full escrow recovered.

**RT-2 — remains DEFERRED (scope decision, 2026-07-18).** The adversarial set
(8 sub-cases: second ratchet inside rwin, wrong-step splice, mutated
non-window byte, print below threshold, cancel-sibling fake print, sub-mrv
volume, travel-cap breach, self-reference) is already proven against the real
`kaspa-txscript` TxScriptEngine by `time_contracts.rs`'s L1/L2/L3/L4/L8/L10/
L11 + rwin-rate-limit + travel-cap unit tests (`ratchet_print_below_threshold_
rejected`, `ratchet_garbage_prints_rejected`, `ratchet_nested_ratchet_print_
rejected`, `ratchet_negative_encoding_print_rejected`, `ratchet_self_
reference_rejected`, `ratchet_splice_pins`, `ratchet_continuation_escrow_
pins`, `ratchet_rwin_rate_limit`, `ratchet_travel_cap`, `ratchet_handrolled_
rstep_zero_rejected`) — the same script-verification engine the live node
runs. Constructing genuinely malformed advance transactions to submit live
(rather than just declining to compose, which the honest engine/planner
already does) requires porting those tests' hand-rolled sigscript
construction from their synthetic-UTXO harness into new live-network-capable
CLI tooling (there is no existing flag or command that emits a deliberately
invalid ratchet-advance tx, unlike the plain-fill `--tamper` mode
`match-batch` already has for F6). That is materially more engineering than
RT-1/CP-3/RT-3 needed (each of which reused or minimally extended existing
plumbing) and was judged out of proportion to attempt in this pass — applying
the same "don't deep-dive if it turns heavy" call the stretch goal was
explicitly given. Marginal live value is also low: the real risk surface
(consensus-level script verification) is identical to what the unit tests
already exercise against the real engine; live-only differences would have to
come from node/mempool policy, not covenant logic. Left DEFERRED, same as
before, with this scope note. Competing-matcher (the stretch goal, gated on
RT-2/RT-3 landing cleanly) was not attempted since RT-2 didn't land.

<!-- STAGE-G IN PROGRESS: remaining forms appended below as they land -->

## single-generation spot — Stage F final live E2E (2026-07-17)

Full re-proof of the 15-form spot matrix on the RENAMED single-generation
binaries (HEAD e5bfcd6 + this run's glue fixes). Stage E1 changed the
buy/sell/OCO covenant BYTECODE (expire seats: buy state 145B→178B / RS
1720B, sell 112B→145B / 515B, OCO 139B→172B / 397B; swap 260B and bracket
372B unchanged), E2 deleted every pre-v18 generation and rewrote engine
auto-expire, E3 dropped the `_v18` names — so the Stage-D TXIDs prove
retired bytecode, and every form below was re-settled on the shipping
bytecode. Node `ws://65.108.107.30:18210`, REST verification via
`api-tn10.kaspa.org` (every settle/claim TXID re-checked
`is_accepted:true`; the REST API exposes `covenant_id` /
`covenant_authorizing_input` per output, which this run used for every
binding assertion). Wallet `kaspatest:qz6qc3j…cfy7qrwa6v8lf`.

Funding: start 5.01 KAS free → reclaimed ~32.9 KAS by `cancel-all` of the
legacy v14/v16/v17 resting orders using a preserved pre-E2 binary (the
shipping binary correctly refuses non-v18 generations); mid-run mined 4
blocks with `kob-miner` (31s; tn10 coinbase maturity = 1000 DAA);
recovered 2.47 KAS of binding-less unit-P2SH change with the new
`sweep-unit-kas` helper (`ab5fd46b…`). All three fixture mint authorities
were unspent and reused; 26 fresh mints; end state 14.47 KAS free + token
holdings, orderbook left empty (all Stage-F orders settled, cancelled,
expired, or reclaimed).

| # | Form | Path | Result | TXID |
|---|---|---|---|---|
| 1 | mint fresh A/B/C token_units | chained `token mint` off the fixture authorities | **PASS** — 22×A (incl. 90M and 300M units), 2×B, 2×C | first A `2affa93c…`, last A `955f601c…`, B `b0168cf6…`/`7f8b255f…`, C `6859d4a0…`/`c34388258…` |
| 2 | deploy every contract on the renamed bytecode | CLI deploys | **PASS** — buy RS 1720B, sell 515B, OCO 397B, swap 260B, bracket 372B, receipt genesis; all `is_accepted` | buys `99ca1541…`/`1967e5e4…` et al., sells `3d0535fa…` et al., OCOs `a31c1f1e…`/`9d1b34e0…`, swaps `fe7a1396…`/`13f4c880…`/`1b77c885…`/`3c71df78…`/`c7cfe05e…`, bracket `7fb44bfe…`, receipt `6bb2860d…` |
| 3 | GTC N:M sweep (3 sells × 1 buy) | engine `GtcBuyMultiFill` (fresh-cursor LISTEN) | **SETTLED** (blue 508055941) — 5-in/4-out, 3 per-sell token_unit deliveries COV(A) + merged 89.1M SellerKas | **`1a0cfed2f67c0c21da15d129ef1098db9dde09990ad8b7c6f052f6b3ffebbcf3`** |
| 4 | IOC N:M sweep (3 sells × 1 buy, min_fill 30M tokens) | `match-batch --ioc` (`KOB_FEE_FLOOR=900000`) | **SETTLED** (blue 508058030) — deliveries COV(A); buyer-change seat = bspkh = token_unit P2SH (D2 model; binding-less KAS, later swept) | **`86f1363b31b0d3376a36e4a074e5b92645ab3323156f648b2433510b4cee7c22`** |
| 5 | buy partial Op2 ×2 chained + final fill | `match-batch --partial` ×2 → `--ioc` | **SETTLED ×3** — 90M buy: ev1 residual 60M @`f1e52ddb…:2`, ev2 residual 30M @`c4eaf42a…:2` (byte-exact self-SPK, no covenant), final IOC consumes it (blues 508058808 / 508059505 / 508059789) | **`f1e52ddb…`**, **`c4eaf42a…`**, **`93934899…`** |
| 6 | sell partial (Fix-3), direct Stage-D shape | `kob-e2e-util sell-partial` (E1 state offsets) | **SETTLED ×2 chained** — 300M sell: fta 100M (residual 200M @`9eabee26…:1`, COV at auth slot 0), then fta 50M on the residual (150M @`d8bc05b1…:1`); residual then cancelled (`8b3a5001…`) proving it rests live | **`9eabee26…`** (blue 508066998), **`d8bc05b1…`** (blue 508067289) |
| 7a | OCO swept in a 2-sell batch, TP branch | engine `GtcBuyMultiFill sells=2` (OCO TP 99/100 + plain, buy 59.4M @1/1) | **SETTLED** (blue 508068352) on the new 397B OCO | **`9cb0686ef51a0e1071dfcd67213c6dec43c2bd83c6c242870ad6be8b00bdca80`** |
| 7b | OCO swept in a 2-sell batch, SL branch | engine (OCO TP 2/1 no-cross / SL 1/2 + plain @1/2, buy 30M @3/4 min_fill 22.5M — the TOKEN floor) | **SETTLED** (blue 508069141) — out[0] 30M = 2×15M @1/2 proves the SL pair executed on-chain | **`af85a538bb363c2aa2713c423fbe1b213a979f30fe2443e2113952a858121d5d`** |
| 8 | cancel-mark → fill rejected on-chain → cancel | `cancel-mark` → `kob-e2e-util sell-partial` ×2 → `cancel --cpend 1` | **PASS** — mark `87f7991e…` (cpend=1, binding carried per D2); fill attempts REFUSED by the node ("script ran, but verification failed", F5 cpend) both with covenant (`ed131e92…`) and plain (`aedfebbe…`), REST confirms neither landed; cancel recovered the escrow as a bound token_unit | mark **`87f7991e…`**, cancel **`a71e2265…`** |
| 9 | expire seats (E1 — the changed bytecode) | `kob-e2e-util expire` (2-input full-refund, lockTime = expiry) | **CLAIMED ×2, NEW SEATS REST-VERIFIED**: buy expire → out[0] 30M FULL refund on the owner's RAW P2PK (`20b40c…ac`, `covenant_id:null`) = **okspkh seat live**; sell expire → out[0] 30M token_unit P2SH with `covenant_id` = V18A and `authorizing_input:0` = **otspkh + Fix-3 binding live**. (On-chain early-claim probe not exercised this run — optional; the client-side DAA guard is in place.) | buy **`41cb9d6958cad13cd6050e18f6c5dd0f15bbe5977469ac26ad9b18e5a4412113`** (blue 508077585), sell **`f56e41f78b033251691ebeb5aa3b9731c5590a5caa9365918a1486c6b259aedf`** (blue 508077607) |
| 10 | 2-cycle ring A↔B | `match-ring` (2 legs) | **SETTLED** (blue 508074921) — token↔token direct, all-or-nothing, deliveries COV(A)/COV(B) | **`2b2cdb551a96989ebeaa68074038caf1fdf03b45125b0dc025773efaedb4ee60`** |
| 11 | 3-cycle triangle A→B→C→A | `match-ring` (3 legs) | **SETTLED** (blue 508075669) — 3×30M deliveries COV(A)/COV(B)/COV(C), no KAS in any order leg | **`8e51b36c02ad36772485a172477fe2ce3dec021e5ba0aee3f432c148306821cc`** |
| 12 | IFD soft path | `deploy ifd` → engine fills the entry | **SETTLED** (blue 508078516) — delivery out[1] landed ON the done-leg sell P2SH (`aa201018b690…`) with COV(A); the engine immediately rediscovered it as a live sell @2/1 (`72436538…:1`, later cancelled `5e8c233a…`) | **`724365386c2cb80ac74cf1c42567b192dda2e063d053e4ddad55a41c6f017687`** |
| 13 | bracket fill (receipt in[2], CSV 50, OCO spawn on the 397B layout) | `receipt create` → `bracket deploy`/`fill --token-utxo` → `kob-e2e-util oco-cancel` | **SETTLED** (blue 508089255) after the D2 trade-seat fill fix (below) — in[2] = receipt `6bb2860d…:0`, in[3] = matcher token; out[1] 30M delivery token_unit COV(A) ai=3, out[2] 30M OCO spawn at the exact pinned `oco_spk` COV(A) ai=3, out[3] token change; the spawned 397B OCO then cancelled (owner path) | deploy **`7fb44bfe…`**, fill **`b112129d2db1f46d212b5facd2ac73854e0d6e7d80607a8527c7e3674e084099`**, OCO cancel **`6f48b46e…`** |
| 14 | delivery re-wrap spend | `token transfer` of the form-3 delivery `1a0cfed2…:1` (38B token_unit P2SH + binding) | **SETTLED** (blue 508081300) — out[0] is again a covenant-bound token_unit (COV(A) ai=0): recipient re-wrap live on the renamed code | **`c95e5707e852dd74714379670ad4297c54f86dbfee63a69b94b1d6534986d94c`** |
| 15 | engine auto-expire (E2 rewrite, 2-input full-refund) | continuous engine `expire_orders` after the fee fix (below) | **CLAIMED autonomously** (blue 508093935) — in[0] expired GTD sell `cb85d850…:0` + in[1] engine wallet fee; out[0] 30M FULL refund token_unit COV(A) ai=0 (otspkh + Fix-3 binding); log `[EXPIRE] Reclaimed expired SELL … (full refund to the owner seat)` | **`b8389a199081e5ee8b670586847e031e557fe7064a8f90fa9d88eb84659c5a12`** |

**Verdict: the full single-generation spot matrix is LIVE-CONFIRMED on the
shipping (post-E1/E2/E3) bytecode — all 15 forms have `is_accepted:true`
TXIDs, and both E1 expire-seat changes are REST-verified at the output
level (okspkh raw-P2PK KAS refund; otspkh token_unit refund WITH
CovenantBinding). No covenant defect found.** The two on-chain rejections
hit during the run were both CLI-glue defects (fixed below), not contract
defects — in both cases the covenant correctly refused a malformed spend.

**Product-code defects found + fixed during the run** (glue, non-covenant;
both re-run live to green; 2427-suite regression `cargo test -p kob-cli -p
kob-engine` green):
1. **Bracket fill vs D2 trade seat** (`bracket.rs fill_bracket_inner`): the
   buy-entry fill still delivered out[1] to the wallet's RAW P2PK while
   post-D2 `bracket deploy` commits `trade_spk_hash` = token_unit P2SH
   hash — the covenant's N5 check rejected every fill of a post-D2 bracket
   ("script ran, but verification failed"; attempts `70b4a8ca…`,
   `ed557da2…`, `87360914…` never landed). Stage D's successful fill
   `9a993dc1…` had used a PRE-D2 bracket, masking the mismatch. Fix: the
   fill resolves the committed trade seat from `rs[159..191)` (raw P2PK or
   token_unit P2SH) and fails loudly if neither preimage matches.
2. **Engine auto-expire fee** (`executor.rs expire_orders`, the E2
   rewrite): used `estimate_compute_mass()` (grams) AS the fee (sompi) —
   the node rejected with "4259 fees … under required 265600". Fix:
   `min_relay_fee(mass + 500)`. (A failed expire also drops the order from
   the engine book until redeploy/restart-rescan — the owner can always
   self-expire via the CLI; noted, not changed.)
3. **`cancel-mark` default mmfee** was the legacy sompi constant
   (10000000), which can never reconstruct a v18 RS (BPS ≤ 10000) — the
   command was unusable without an explicit flag. Fix: `--max-matcher-fee`
   is now optional and resolves from the orders cache, with a clear error
   when neither is available.
4. **New `kob-e2e-util sweep-unit-kas`**: recovers binding-less KAS parked
   at the wallet's token_unit P2SH via the unit-RS owner-sig path (single
   P2PK output; tx version 0, so a covenant-carrying UTXO fails the whole
   sweep closed). Live: `ab5fd46b…` swept 246,887,072 sompi.

**Operational notes (Stage F)**:
- Binding-less KAS accumulates at the token_unit P2SH by design post-D2:
  the v18 buy's change/refund seat (bspkh) IS the token_unit hash, so IOC
  buyer change and cancel refunds of de-tokenized escrows land there as
  plain KAS (`token balance` flags them; `sweep-unit-kas` recovers them).
- `cancel-mark` + `cancel` preserve the token covenant end-to-end (mark
  carries the binding onto the cpend=1 UTXO; cancel refunds a bound
  token_unit — REST-verified). There is no de-tokenize path anymore.
- `cancel` with explicit params (uncached outpoint) requires `--version 18`
  (the no-cache default is an intentional invalid sentinel).
- Op2 residuals are not auto-cached: add the residual outpoint to
  orders.json (same params, new outpoint/value) before chaining
  `match-batch --partial` onto it.
- min_fill semantics at the deploy gate: sell-side = KAS proceeds floor
  (30M tokens @99/100 needs `--min-fill ≤ 29700000`); buy-side = TOKEN
  floor (the Stage-D pin holds on the renamed code).
- `KOB_FEE_FLOOR` remains necessary on covenant-heavy shapes (batch ~9e5,
  1720B-RS buy deploys/expires ~4.5e5; the IFD two-RS payload needed
  6e5) — the node's byte-proportional transient floor exceeds compute-mass
  fees there.
- tn10 coinbase maturity is 1000 DAA; `kob-miner` remains the funding path
  (4/4 blocks accepted in 31s this run).
- Build env: sdcardfs does not reliably bump mtimes on /storage — ALWAYS
  `touch` changed sources before `cargo build`, and verify the fix string
  is present in the binary (`strings | grep`) before re-running live.

**Final matrix statement**: implemented + live-proven on the shipping
bytecode — N:M GTC and IOC sweeps, buy Op2 partial chains, sell Fix-3
partial chains, OCO sweeps on BOTH branches, two-phase cancel with on-chain
fill rejection, permissionless expiry with the E1 owner seats (buy → owner
P2PK KAS, sell/OCO → owner token_unit with binding), token↔token 2-cycle
and 3-cycle rings, IFD done-leg spawn, receipt-gated bracket with live OCO
spawn, KCC20 token_unit delivery re-wrap, and engine-autonomous expiry.
Documented limitations (unchanged, by design): multi-buy (item D) stays
fail-closed by proof, ring legs are all-or-nothing (no ring partial), and
trailing stops remain off-chain matcher constructs.

---

## v18 delivery re-wrap (KCC20 token_units) — Stage D2 live run (2026-07-16)

Fix: v18 fills previously delivered tokens to the buyer's **raw P2PK SPK**
(bspkh = blake2b(P2PK)) — carrying the CovenantBinding but no KCC20 Standard
State Header, unreadable by KCC20 tooling and unspendable by KOB's own
`token transfer`. D2 re-wraps every v18 token-delivery endpoint at the
**deploy-parameter level** (no covenant change): buy `bspkh`, swap `ospkh`,
and buy-entry bracket `trade_spk_hash` now commit the owner's **token_unit
P2SH SPK hash** (`compute_token_unit_spk_hash`), so fills land spendable
KCC20 token_units. KAS-proceeds commitments (sell/OCO `sspkh`, sell-entry
bracket) stay raw P2PK. Refund endpoints re-wrapped too: sell/swap/bracket
cancels return the token escrow as a token_unit (binding preserved) instead
of burning it to plain KAS; cancel-mark carries the binding onto the cpend=1
continuation. Receive side: `token balance` now queries the token_unit P2SH
address (holdings keyed by covenant binding) and `token transfer` wraps the
recipient into THEIR token_unit P2SH. Reconstruction paths (cancel /
cancel-all / cancel-mark / requote / match-batch / auto-match / mm requote)
resolve the committed spkh cache-first, so pre-D2 orders stay cancellable;
the engine scanner's `extract_owner_spk` additionally derives the token_unit
P2SH of any P2PK deploy-output pubkey to recover the delivery-SPK preimage.

Live proof (node `ws://65.108.107.30:18210`, REST `api-tn10.kaspa.org`, all
`is_accepted:true`): sell `5a53089e…:0` + buy `ef41ccdd…:0` (bspkh
`fe271675…` = token_unit hash) matched via `match-batch` —
**fill `7ee7edceeb1616383ee1bf35cd34c5ecf0a033dca9a45f7f66e78b498eafe15a`**
(blue 507915963), out[1] = 30M at the token_unit P2SH
(`aa2052faa4c1…87`, blake2b == committed bspkh) with COV(ai=0, V18A
`eab5c99a…a4b4`). Spendability proven:
**`token transfer` `064b389334825e5e6b6a4ee93f0330561f4777978cf604b418a5c33a640b92f8`**
(blue 507916661) spends `7ee7edce…:1`; its out[0] is again a bound
token_unit (recipient re-wrap live too). Refund path also live-verified:
sell `55401be9…:0` cancelled → `b9dea2209dbdbe1543aeb041cf2bbab29e93caf1850ad3cdcea6935f395d2013`
(blue 507917355), out[0] = 30M token_unit refund with binding.

Known residual endpoints (documented, not regressions): the v18 buy EXPIRE
branch forces the KAS refund onto bspkh — post-D2 that parks plain KAS at
the token_unit address (binding-less; `token balance` flags it, owner-sig
spendable); the v18 sell/OCO EXPIRE branch still refunds tokens to the raw
P2PK sspkh (sspkh doubles as the KAS-proceeds seat — covenant-level, out of
D2's no-covenant-change scope; use cancel instead of expire for sells). The
DCA covenant generation keeps its own raw-P2PK delivery (separate contract,
out of D2 scope). Regression: 2427 tests / 21 suites green across
kob-core/domain/engine/cli, incl. a new planner+engine repro
(`v18_gtc_planner_token_unit_delivery_passes_real_engine`) asserting every
BuyerTokens output lands on the token_unit P2SH and hashes to bspkh.

---

## v18 full spot unification — Stage D live run (2026-07-16)

Full 13-form matrix on fresh v18 binaries (HEAD cc18931 + this run's CLI-glue
fixes). Node `ws://65.108.107.30:18210`, REST verification via
`api-tn10.kaspa.org` (every TXID below re-checked `is_accepted:true`,
independent of the wRPC node). Wallet `kaspatest:qz6qc3j…cfy7qrwa6v8lf`
(start 216.59 KAS free / 89 UTXOs; end ~5.3 KAS free — the rest sits in
self-trade token round-trips/resting orders, net spend = miner fees only).
Three fresh tokens: **V18A** `eab5c99a…a4b4` (genesis `f4e01942…`),
**V18B** `d5fb0009…2c45` (genesis `3cbe6e7e…`), **V18C** `31679217…c07e`
(genesis `37b16f78…`), 23 chained mints. Engine-driven forms ran LISTEN-mode
daemons fresh from the tip (scan cursor deleted, `[H1] No cursor`); the rest
were CLI-driven (`match-batch --ioc/--partial`, `match-ring`) plus a new E2E
glue bin `kob-e2e-util` (oco-spk / sell-partial / expire / oco-cancel /
*-rs helpers) for the paths the CLI has no subcommand for yet.

| # | Form | Path | Result | TXID |
|---|---|---|---|---|
| 1 | mint 3 fresh tokens A/B/C | `token create` + chained `token mint` | **PASS** | `f4e01942…`, `3cbe6e7e…`, `37b16f78…` + 23 mints |
| 2 | deploy v18 buy/sell/OCO/swap/bracket + receipt genesis | CLI deploys (all v18 RS) | **PASS** | buys `04495ad2…`/`c0a519b2…`, sells `38975397…` et al., OCO `3b87a680…`/`631409e4…`, swaps `852a5504…`/`0c10f03b…`/`ed9c88c6…`/`6bbab79f…`/`ac2e1b1d…`, bracket `fc50b663…`, receipt `986d73f4…` |
| 3 | GTC N:M sweep (1 v18 buy × 3 v18 sells) | engine `GtcBuyMultiFill` → `plan_batch_match_v18` | **SETTLED** (blue 507744211) — 5-in/4-out, 3 per-sell BuyerTokens COV(ai=0/1/2) + merged 89.1M SellerKas | **`a951f2abd71354ad6e941cc9068c3c7adad1f3fd582f10ba83310a575dce3a75`** |
| 4 | IOC N:M sweep (1 v18 buy × 3 v18 sells) | `kob-cli match-batch --ioc` → `plan_ioc_match_v18` | **SETTLED** (blue 507748168) — matcher fee at the 2000bps cap, buyer change returned | **`793e84ff6fad4ba44e0b417b443c371786ce01deff38ef5b6ef1668401a4d7c3`** |
| 5 | buy partial Op2, two chained events + final fill | `match-batch --partial` ×2 → `plan_partial_match_v18`, final `--ioc` | **SETTLED ×3** — 90M buy: ev1 spends 30M (residual 60M @ `4b7767d7…:2`), ev2 spends 30M (residual 30M @ `81a6d1b1…:2`), final IOC consumes the residual fully; residual SPK byte-exact, no covenant | **`4b7767d7…`**, **`81a6d1b1…`**, **`a264d66f…`** |
| 6 | sell partial (v18 Fix-3 F4, direct spend) | `kob-e2e-util sell-partial` — wallet is the KAS payer (no planner composes v18 sell partial with a v18 buy, by design) | **SETTLED ×2 chained** — 300M sell: fta 100M (residual 200M @ `99dbe088…:1`), then fta 50M on the residual (150M @ `02a1592a…:1`); shape: in[0] sell (seq 50) + in[1] wallet; out[0] seller KAS (koi=0, sspkh), out[1] residual self-SPK COV(ai=0) at auth slot 0, out[2] delivery COV(ai=0), out[3] change; residual later cancelled (`9b70b1ae…`) proving it rests as a live v18 sell | **`99dbe088…`**, **`02a1592a…`** |
| 7a | OCO swept in a 2-sell batch, TP branch | engine `GtcBuyMultiFill sells=2` (OCO TP 99/100 + plain 99/100, buy 59.4M @1/1) | **SETTLED** (blue 507757077) — OCO input attests the TP pair (canonical [3..11)/[12..20) layout) | **`95f241de65edbeddbe4b4e02eea3fd45e05aeadf7d09423aa39a7548e0c5a7db`** |
| 7b | OCO swept in a 2-sell batch, SL branch | engine `GtcBuyMultiFill sells=2` (OCO SL 1/2 + plain 1/2, buy 30M @3/4) | **SETTLED** (blue 507764333) — OCO input attests the SL pair; the pre-v18 OCO-SL sweep blocker is gone live | **`c512fcdbbfc4352fde7fa41d7550253c5bee2dc7ecf54536c27cc474d26f9625`** |
| 8 | cancel-mark → fill rejected → cancel (v18 two-phase) | `cancel-mark` (sell, v18) → direct fill attempt → `cancel --cpend 1` | **PASS** — mark `795366c8…` (cpend=1 UTXO); fill attempt `f9a360ca…` refused by the node with `script ran, but verification failed` (F5 cpend); covenant-bound variant separately refused at the covenants layer (mark de-tokenizes, see notes); cancel `516d15a1…` recovered the funds | mark **`795366c8…`**, cancel **`516d15a1…`** |
| 9 | expire path (near expiry_daa → wait → claim) | v18 buy Op4 via `kob-e2e-util expire` (permissionless, CLTV, FULL refund + wallet fee input) | **CLAIMED ×2** — `54470692…` (first probe) and `650eafd6…` (order live ~80s; early claim correctly refused pre-expiry, claimed after DAA passed) | **`54470692…`**, **`650eafd6…`** |
| 10 | 2-cycle ring A↔B | `kob-cli match-ring` → `plan_ring_match` (2 legs) | **SETTLED** (blue 507793686) — token↔token direct, all-or-nothing, per-leg slot-0 delivery COV | **`fcffaaaf58f067f4a09a8643ba2b0ee8dcde23bb550cee9d0b8101c74abd3799`** |
| 11 | 3-cycle triangle A→B→C→A | `kob-cli match-ring` (3 legs) | **SETTLED** (blue 507794242) — 3 swap legs + fee input, 3×30M deliveries, **no KAS in any order leg** | **`ac5fab548ca1cf2c6a2a517657680e8668b2febe7cb914d32537cd221f415598`** |
| 12 | IFD soft path (register → entry fill → done-leg live) | `deploy ifd` (v18 buy entry, done-leg RS in payload) → engine fill | **SETTLED** (blue 507798479) — entry `0847a1ed…` filled autonomously; delivery out[1] landed ON the done-leg sell P2SH (`aa204a9fb8…`) and the engine immediately discovered it as a live v18 sell @2/1 (`252e953b…:1`) | **`252e953b997d60cb0d0946f3a8bc4099314e5b947636a78d9749515f43176252`** |
| 13 | bracket v18 fill (receipt input[2], CSV(50), OCO spawn) | `receipt create` → `kob-e2e-util oco-spk` → `bracket deploy`/`fill --token-utxo` → `kob-e2e-util oco-cancel` | **SETTLED** (blue 507802941) — in[2] = receipt `986d73f4…:0` (cov `924ab6c5…`), in[3] matcher token unit; out[1] 30M delivery COV, out[2] 30M OCO spawn at the exact `oco_spk`, out[3] token change; spawned OCO then cancelled (`76891f4c…`, owner path) | deploy **`fc50b663…`**, fill **`9a993dc11548406fce5698c901f7751267360eccf8b37582f8ecc0ff9e0ad9da`**, OCO cancel **`76891f4c…`** |

**Verdict: the full v18 spot matrix is LIVE-CONFIRMED on testnet-10 — all 13
forms have `is_accepted:true` TXIDs (32 verified via REST). No contract
defect found**; the OCO-SL sweep, buy Op2 partial chain, sell Fix-3 partial,
token↔token rings (incl. the 3-cycle triangle), IFD done-leg spawn, and the
receipt-gated bracket→OCO spawn — all previously impossible or unproven —
settled on-chain.

**One near-miss that was NOT a defect**: the first SL-sweep buy used
`--min-fill 30000000` (its full KAS) at price 3/4 and the node kept rejecting
the settle. Offline repro against the real `kaspa-txscript` engine isolated
it to Section E of `emit_fill_body_v18`: `expected = kas_in/pden*pnum >= mfill`
— **the v18 buy `min_fill` is a floor on TOKENS, not KAS** (22.5M expected
tokens < 30M mfill can never fill; at 1/1 prices KAS==tokens masked this).
Pinned in `kob/core/tests/v18_mfill_pin.rs` (reject + 4 passing price/floor
combos).

**Glue fixes landed during the run** (product code, non-covenant):
1. `deploy.rs`: v18 **sell** deploys cached the raw sompi `max_matcher_fee`
   (10000000) instead of the BPS baked into the RS → `match-batch` rebuilt a
   different RS ("max_matcher_fee_bps must be <= 10000"). Cache now stores
   BPS for v18, mirroring the buy path.
2. `match_batch.rs`: `KOB_FEE_FLOOR` env override — the node's
   byte-proportional transient-mass floor can exceed the compute-mass fee on
   covenant-heavy shapes; the bump is absorbed by matcher-side outputs
   (WalletChange→MatcherFee), never seller/buyer.
3. `bracket.rs` v18 fill: receipt UTXO now resolved via
   `get_utxos_by_addresses` on the P2SH of `--receipt-rs` — this node does
   not serve `getTransaction` (30s timeout), and the new path doubles as an
   unspent check.
4. New `kob/cli/src/bin/kob_e2e_util.rs` (E2E glue bin): `oco-spk` (compute
   v18 OCO RS/SPK for `bracket deploy --oco-spk`), `sell-partial` (direct
   v18 sell Op2 settle), `expire` (v18 Op4 with the full-refund + fee-input
   shape), `oco-cancel`, and `buy-rs`/`sell-rs`/`receipt-rs` helpers.

**Operational notes for Stage E / future runs**:
- v18 buy deploys carry a ~1.7KB RS payload → the CLI's mass fee is below the
  node's transient floor; `--fee-rate 450000` (or better: fee model unification)
  is required. BUT a forced fee can produce an exact-spend deploy with **no
  P2PK change output**, and the scanner then cannot extract `counterparty_spk`
  → `[INDEXER] skipped unmatchable order`. Consolidate first, then deploy.
- The engine's auto-expire builder (1-in/1-out, fee subtracted from the
  refund) predates v18: the v18 expire branch demands a FULL refund
  (`out[0] >= input`), so engine-side auto-expiry of v18 orders would be
  rejected on-chain. Needs the 2-input shape (order + fee) at Stage E.
- Fresh-cursor LISTEN engines defer buy orders on tokens whose covenant has
  not yet been seen in scanned blocks (`Marking covenant … invalid (not seen
  on-chain, TTL=300s)`). Deploy a covenant-carrying tx (e.g. the sell) BEFORE
  the buy, or wait out the TTL (hit once on the first IFD entry `0ec3c3cd…`,
  which now rests unfilled; the redeploy settled cleanly).
- `cancel-mark` intentionally strips the token covenant from the marked sell
  UTXO (tokens unlock-to-KAS at mark): a fill attempt with covenant-bound
  outputs dies at the covenants layer, a plain attempt dies at F5 — both
  captured live.
- OCO deploys print `Order at output …` (not `Order deployed at output …`) —
  parse accordingly.

---


## v17 full spot coverage — composition-hardening live run (2026-07-16)

LISTEN-mode daemon, FRESH FROM THE CURRENT TIP (persisted scan cursor absent
→ `[H1] No cursor; initial last_seen_hash = 87a5b989…` → zero historical
catch-up, no bulk `getBlocks`). Daemon-first + orders deployed AFTER the
scanning banner, so each deploy landed in a block the daemon scanned forward
(small near-tip scans only). Fresh binaries built from the composition-hardening
commits. Node `ws://65.108.107.30:18210`, wallet `kaspatest:qz6qc3j…cfy7qrwa6v8lf`,
token `cfe91413dfbf9250e2bcc6940b3c26c2dbe231e29188f6f7538b2ad21f67f6cd` (V17HARD).

| # | Case | Path exercised | Result | TXID |
|---|---|---|---|---|
| a | honest v17 N:M GTC sweep (3 sells : 1 v17 buy, `min_fill = full`) | `GtcBuyMultiFill` → **`plan_batch_match_v17`** | **SETTLED** (`is_accepted:true`, blue_score 507428908) — regression of `6794639c…` | **`1c25c0dd8bd18ffdce05f7e5d7a8d7796a39bbf759ccd28776e161a2165a902b`** |
| b | honest v17 N:M IOC sweep (3 sells : 1 v17 buy, `min_fill < full` ⇒ IOC-eligible) | `BuySweep` → **`plan_ioc_match_v17`** (newly-wired) | **SETTLED** (`is_accepted:true`, blue_score 507421873) | **`40f87a828f72489d504a4bd9a59c99f418395745f3144890384a397a12c6938e`** |
| c | OCO-sell NOT swept into a multi-sell composition | `find_sweep_groups` OCO exclusion | **HOLDS** — see below | (matching-layer; deploy TXIDs below) |
| d | N>8 rejects gracefully (no panic) | `find_sweep_groups` MAX_N cap + `plan_batch_match_v17` `V17TooManySells` | **harness-authoritative** — see below | (unit-proven; daemon structurally capped) |

Both N:M settles verified on-chain via the tn10 REST API (independent of the
wRPC node): each is **5 inputs (3 sells + 1 v17 buy + 1 fee UTXO)** with
**one per-sell BuyerTokens output covenant-bound to its OWN sell input**
(daemon TX debug: `COV(ai=0)`, `COV(ai=1)`, `COV(ai=2)`), plus the merged
SellerKas output (89,100,000 = 3 × 29.7M) — the exact v17 per-sell shape that
v14/v16 cannot express. (a) and (b) produce the SAME on-chain shape; they
differ only in the matcher-internal routing (`plan_batch_match_v17` vs
`plan_ioc_match_v17`), so the run exercises BOTH newly-relevant v17 planners.

**(c) OCO exclusion — LIVE-PROVEN at the matching layer.** Deployed a plain
sell (`b1a058c7…`, 30M @ 99/100), an OCO sell (`e00973988b…`, 30M, TP 99/100 /
SL 9/10), and a v17 buy (`37557c0a…`, 60M KAS @ 1/1) that could afford BOTH
sells. The daemon discovered all three (the OCO recognized as `Discovered OCO
sell … TP=99/100 SL=9/10`, tagged `oco_path`); the book showed **1 bid / 3
asks** (plain + OCO-TP + OCO-SL virtual orders). Yet every matching cycle
formed **`Group kind=Batch sells=1 buys=1`** — only the PLAIN sell, never a
2-sell sweep including the OCO — proving the `find_sweep_groups` OCO exclusion
holds live: an OCO sell is never composed into a multi-sell sweep even when a
buy could afford it. (The plain-sell settle itself was intermittently blocked
by transient node `getUtxos`/`getDaaScore` RPC timeouts — the same node
flakiness that delayed the (a)/(b) settles by several retry cycles — but the
exclusion is established by the group shape, independent of that settle.)

**(d) N>8 graceful reject — harness-authoritative + structural.** The panic
path (`build_buy_v17_fill_sigscript`'s `assert!(len <= MAX_N)`) is unreachable
in the daemon: `find_sweep_groups` caps a v17-anchor sweep at `BUY_ORDER_V17_MAX_N`
(8) before any planner is called (`test_v17_buy_sweep_capped_at_max_n` /
`test_v17_ioc_sweep_capped_at_max_n`), and `plan_batch_match_v17` independently
returns `BatchError::V17TooManySells` for `N>8`
(`test_v17_too_many_sells_rejects_not_panics`) — never a panic. A 9th crossing
sell is simply left for a follow-on group. Not separately driven live this pass
(would require 9 minted token UTXOs + 9 deploys under the flaky node); the
covenant/planner guards are the authoritative verification, as agreed.

**Verdict: v17 full spot coverage is LIVE-CONFIRMED** for both N:M sweep paths
(GTC + IOC) and the OCO-exclusion safety boundary; the two documented
limitations (N>8, and C/D/F below) are guarded and unit-proven.

---

## v17 N:M live verification

**RESULT: the v17 N-sells:1-buy sweep settled autonomously on-chain in ONE
tx — the live proof the harness could not give. testnet-10 accepted it.**

- **Settle TXID: `6794639c6cff0e6967bb0ca3dceb6d0cee7885aa72a48d43f6e5f667d7c2f8a5`**
  (`is_accepted: true`, accepting-block blue_score 507333120, confirmed via
  `api-tn10.kaspa.org/transactions/<txid>`, independent of the wRPC node).
- **Genuine multi-sell sweep, verified on-chain** (5 inputs, 4 outputs):
  - IN[0] `add68feb…:0`, IN[1] `9a0e1c1f…:0`, IN[2] `2be82d7e…:0` — **3 distinct
    v14 sells** (30M token_units each @ 99/100), all consumed in one tx.
  - IN[3] `1ec3ab83…:0` — the **v17 buy** (90M KAS @ 1/1, mmfee 2000bps, GTC
    full-fill min_fill=90M). IN[4] `e459a8d5…:2` — wallet fee UTXO.
  - OUT[0] 89,100,000 sompi = SellerKas (3 × 29.7M merged to the one seller SPK).
  - OUT[1..3] 30,000,000 each = **one BuyerTokens output per sell, each covenant-
    bound to its OWN sell input** (`COV(ai=0)`, `COV(ai=1)`, `COV(ai=2)` in the
    daemon's TX debug dump). This is the exact shape the merged v14/v16 path
    cannot express: the sell-side per-input F4 needs N separate token outputs,
    and the v17 buy's F6 SUMS them. Node acceptance proves all 3 per-input sell
    F4 checks passed simultaneously with the v17 buy's aggregate check.
  - **F6 aggregate surplus cap held**: buyer paid 90M KAS, aggregate fair value
    89.1M, matcher surplus 900,000 ≤ cap 18,000,000 (=90M/10000×2000bps). The
    surplus was dropped to the miner fee (no matcher-fee output emitted).
  - **Aggregate limit-price floor held**: Σtokens 90,000,000 ≥ kas_in/buy_price
    = 90M/(1/1) = 90,000,000 (satisfied exactly at the floor).

- **Autonomous, LISTEN-mode discovery (bulk-getBlocks avoided)**: the daemon was
  started FRESH FROM THE CURRENT TIP — the persisted scan cursor
  (`orderbook.json.scan.json`) was deleted before launch, so `[H1] No cursor;
  initial last_seen_hash = <sink>` then `startup catchup: tip … (spot+0, perp+0)`
  = zero historical catch-up, no bulk `getBlocks`. The crossing book (1 v17 buy
  + 3 sells, all resting on-chain) was in the persisted order book; the daemon
  loaded it, found the crossing on its first scan cycle, and settled — no manual
  `match` call. Group classified `GtcBuyMultiFill sells=3 buys=1`, routed to the
  isolated `plan_batch_match_v17`, `[BATCH] SUCCESS!`, then it pruned all 4
  orders (book → 0 bids/0 asks) after seeing its own tx consume them.

- **Two product-code bugs found + fixed to get here** (both in the v17 wiring,
  surfaced only by this live run; the harness could not because it hand-builds
  the sell sigscripts):
  1. `BatchPlan::validate()` (`kob/domain/src/spot/batch.rs`) still hard-rejected
     `buy.version == 17` ("is v17, unsupported (v14/v16 only)") as a post-hoc
     sanity check, even though `plan_batch_match` itself already routed v17
     correctly — so a correctly-planned sweep was killed at the last gate.
     Added v17 to the allowed set (mirrors the planner's own check).
  2. **The load-bearing one**: `build_tx`'s `has_v16_buy` gate
     (`kob/domain/src/spot/batch.rs`) decided whether the swept sells use the
     fixed-offset sell fill sigscript (`build_sell_fill_sigscript_fixed_offset`,
     2-byte koi push) vs the regular 1-byte-OpN koi push. v17 — exactly like v16
     — reads each sell's pnum/pden via `OpTxInputScriptSigSubstr` at fixed
     offsets `[7..15)`/`[16..24)`, which only line up when the sell RS push
     starts at a fixed byte (the 2-byte koi). The gate only recognized v16, so a
     v17 sweep left the sells on the 1-byte push, shifting the RS one byte and
     making v17's price read decode garbage → the node rejected the tx with
     `script ran, but verification failed` (the identical txid `6794639c…`, since
     Kaspa txids exclude sigscripts — only the sigscripts differed between the
     rejected and accepted submits). Renamed the gate `has_fixed_offset_buy` and
     included the v17 RS length. This matches the proven harness, which uses
     `build_sell_fill_sigscript_fixed_offset` for its v17 sells
     (`kob/core/tests/v17_nm_buy.rs`).

  Both binaries rebuilt after each fix; the final settle above ran on the
  offset-fix binary. Sell sigscript length went 432B → 433B (the extra byte is
  the fixed-offset koi push), the on-chain confirmation that the fix took.

- **v17's core spot capability is now LIVE-PROVEN on testnet-10.** The
  N-sells→1-buy sweep — unsettleable under v14/v16 (mutually-exclusive sell-F4
  vs buy-F6 output requirements, per `NM_BUY_DESIGN.md §1`) — settles in a
  single real on-chain tx under v17, discovered and built autonomously by the
  continuous daemon.

- **Token/orders for the record** (testnet-10, wallet
  `kaspatest:qz6qc3j…cfy7qrwa6v8lf`): token
  `e503795c370e0aa9acac0ceedd589cb8db52e8e12692504316a8492643939d79` (V17E2E,
  genesis `b6ca7b5d…`). v17 cancel path also live-exercised en route (the
  wrong-priced first buy, cancel TXID `d09972357e09e1cd…`, and a min_fill-too-low
  buy, cancel TXID `62d1c4db33104a6e…`) — confirms v17 orders stay cancellable
  after the version-gate change (Task A).

## Final summary

Every flow/command actually attempted live against testnet-10 in this pass,
with result and TXID (or reason if not landed/not applicable). "Fixed"
means the underlying bug was patched and the SAME command was re-run live
to confirm it now lands, unless noted otherwise.

| Flow / command | Result | TXID or reason |
|---|---|---|
| `token create` + chained `mint` (fixture refresh) | PASS | genesis `e2697bc5...`, 8x chained mints, all confirmed |
| `deploy sell` (v16, default fee path) | PASS | `58525c1a250f494c...` (fee = mass*100, Phase-4 floor confirmed live) |
| `deploy buy` (v16 default, no flag) | PASS | `e8ad85394930608447...` |
| `list` / `orderbook` / `spread` / `order-status` | PASS | read-only, correct crossed-book display |
| Batch matcher AUTO mode (`kob-engine --mode continuous`) | PASS | settle TXID `750e226376ca5af35f...` (surplus 60000 sompi, retried past a transient immature-coinbase pick) |
| F6 cap adversarial (lying `--fee-bps` over-cap attempt) | PASS (correctly rejected) | attempted `4a16f18d5e549a3cc...` never landed; node: "script ran, but verification failed" |
| `cancel` / `requote` version-resolution bug | FIXED, live-verified | cancel `ccfd4514d07de4738...` |
| `cancel-mark` (2-step) | PASS | mark `8df6b85caa40cc80f...`, cancel `88769f30d98acd7b6...` |
| `partial-fill` (no fee floor) | FIXED, live-verified | `86ef6b4238478ccc6...` |
| `requote` (atomic cancel+deploy) | PASS | cancel `7ba0fe8e0072a13d6...`, deploy `61a0855bc3de08e48...` |
| `cancel-all` | PASS | 2 cancelled (`ebf0024b...`, `ec8e8db9...`), 6 correctly skipped (already spent) |
| `wallet send` | PASS | `535da5818dd4857fd...` |
| `wallet consolidate` (50 UTXOs -> 1) | PASS | `b56e3bd50ebc4ecde...` |
| `token transfer` | PASS | `109f1f843a1e9c43d...` |
| `oco-sell` deploy | PASS (deploy only) | `2561b00388ab46f28...`; **no cancel path exists anywhere** (CLI or kob-core) -- real gap, not fixed |
| `dca deploy` + `cancel` | PASS | `eaef9ac32ef2c4be5...` / `0ec83a8e1220d5ff0...` |
| `lending offer` + `cancel` | PASS | `f08c38f3dc531286f...` / `6b40f0ab80bca1b6d...` |
| `perp deploy-long` + `cancel` | PASS | `2973101a165182c10...` / `f5f380c3270bfd290...` |
| `insurance deploy-offer` + `cancel-offer` | PASS | `cee7d902512c68df7...` / `85086b92f5698207c...` |
| `swap deploy` + `cancel` | PASS | `0f6d0631daff2d8bb...` / `e33da5cc78c702eb4...` |
| `bracket deploy` + `cancel` | PASS | `2186357bf3b92b87f...` / `2187ef817c172df52...` |
| `prediction create` (2-step) | PASS | step1 `afb239e36705e54cd...`, step2 `31276e4d2ed14681f...` |
| `prediction expire` -- malformed 36B owner SPK | FIXED (necessary, not sufficient) | code fix; still failed until the two bugs below were also fixed |
| `prediction expire` -- OP_CLTV consumption bug (stack underflow) | FIXED, live-verified | see required-step TXID below |
| `prediction expire` -- fee estimate too low for actual sigscript size | FIXED, live-verified | see required-step TXID below |
| **`prediction expire` (required step, after all 3 fixes)** | **PASS** | **`93da68e841c7036981b7c9143ae301df58242b2607f23892f34ce3a2985c161a`** |
| `prediction create` (2-step, covenant-binding + fee fix) | PASS (re-verified, release-backlog pass) | step1 `92bbd39d885a69df4c57a310004d19b194248139d90f72f72f6307faf6244f85`, step2 `eee6297b0c013f767ba5d39cf4d7de9d9c8efbaa776e08b2b156eaff515326b6` |
| `prediction vote` | BUILDER FIXED (3-in/4-out); mempool-blocked BY DESIGN | domain builder rewritten to the deployed 3-in/4-out VoteReceipt contract + a deeper covenant-binding deploy gap fixed (both proven vs the real engine in `prediction_vote_repro.rs`). Live submit reached the node and was refused with `transaction has 0 fees which is under the required amount` -- a standardness/fee rejection, NOT a script failure. The contract's V6 mandates `total_in == total_out` (fee EXACTLY 0), so vote is a fee==0 miner-INCLUSION-only tx by design; it cannot enter the standard RPC mempool. Not a builder bug. |
| `redemption.rs` / `split_merge.rs` refund paths (CLTV fix) | FIXED, live-verified (release-backlog pass) | OP_CLTV fix confirmed on-chain: SplitMerge refund `87ebbc9fe556fdda96c054613330dfa8d0554f7f04316fa25d2724266874d8c6`, Redemption refund `efd681470db89ff429af3fff7c6dfabcba5bd518737d184459d9029655795d18`. Two follow-on bugs found + fixed en route: refund fee underpayment (Phase-2 exact recompute added, like `expire`) and a tx-finality race (`lockTime = current_daa` -> `expiry_daa`). |
| `listing` (English/Dutch auction) | CLI ADDED + live deploy+settle (release-backlog pass) | new `kob-cli listing` subcommand (deploy + settle). Live english-auction deploy `cf0db1ff3a23c8144d9fca5b229520284b2bfb23ea01ff70db2b1e3c44630c74`, then PATH-6 settle after expiry `0aff3da54032a4b4bc40c14e458f450b02a8b60b065988697e3f774b539d1fa8` (accrued value paid to seller). Bidding (PATH 5) / buy-fill (PATH 1/3, external position transfer) out of scope for this smoke. |
| sell IOC honest residual builder (SECURITY_FIXES Fix 1 residual) | WIRED + covenant-engine verified (release-backlog pass) | `plan_sell_ioc_match` now emits the residual self-continuation to the sell order's own P2SH at the sell input's auth[0]; proven against the real `kaspa-txscript` engine (harness `sell_ioc_builder_layout_residual_at_auth0_passes`). Not separately live-smoked (engine harness is the authoritative method); multi-sell batch residual deferred (fail-closed). |
| bracket single-order fill surplus cap (SECURITY_FIXES Fix 6) | RE-DECIDED: safe-by-limit, no cap (release-backlog pass) | `fill_bracket_v4` is reachable but has no free fill parameter; `output[1] >= et` (et = full deposit * entry_price) to the buyer's own SPK fully bounds it. No F6-style drain; closed, no state change. |
| dead lending/perp fee builders | FIXED (release-backlog pass) | all 14 un-wired blueprint-builder fees wrapped in `min_relay_fee` so they're correct if wired; dead code today (no caller). |
| x402 KIP-10 exact CASE R2 (under-threshold continuation) | FIXED, live-verified | root cause + fix in `kob/x402/src/scheme_exact.rs` (see below); re-run of `e2e_x402_exact.sh` after rebuild: 30/30, R2 now correctly refused (`invalid_payment_requirements`); happy-path settle TXID `9d61a47c4180785b8b8e85af9b72c26979471a5c006876e4a1e7279b2c62f78c` |

## FINAL release verdict (release-backlog pass complete)

All six backlog items resolved. Complete TXID table for the release-backlog
pass (testnet-10, node `ws://65.108.107.30:18210`, wallet
`kaspatest:qz6qc3j...cfy7qrwa6v8lf`):

| Item | Flow | Result | TXID(s) |
|---|---|---|---|
| 1 | prediction create (2-step) | PASS | step1 `92bbd39d885a69df4c57a310004d19b194248139d90f72f72f6307faf6244f85`, step2 `eee6297b0c013f767ba5d39cf4d7de9d9c8efbaa776e08b2b156eaff515326b6` |
| 1 | prediction vote | BUILDER FIXED; mempool-blocked BY DESIGN (fee==0 miner-inclusion) | rejected `dbde746457bcf678b50a36611fe87e56074ca0a062026519bdebb38fcf427b1c` ("has 0 fees" — standardness, not script failure) |
| 1 | SplitMerge refund (OP_CLTV) | PASS | `87ebbc9fe556fdda96c054613330dfa8d0554f7f04316fa25d2724266874d8c6` |
| 1 | Redemption refund (OP_CLTV) | PASS | `efd681470db89ff429af3fff7c6dfabcba5bd518737d184459d9029655795d18` |
| 2 | sell IOC honest residual | WIRED, covenant-engine verified | (off-chain engine harness; no separate live smoke) |
| 3 | bracket single-order cap | RE-DECIDED safe-by-limit, no cap | (analysis; no code/tx) |
| 4 | x402 KIP-10 exact R2 regression | FIXED, live-verified | happy settle `9d61a47c4180785b8b8e85af9b72c26979471a5c006876e4a1e7279b2c62f78c` (30/30 e2e) |
| 5 | dead lending/perp fee builders | FIXED (min_relay_fee) | (dead code; no live tx) |
| 6 | listing deploy (english) | PASS | `cf0db1ff3a23c8144d9fca5b229520284b2bfb23ea01ff70db2b1e3c44630c74` |
| 6 | listing settle (PATH 6) | PASS | `0aff3da54032a4b4bc40c14e458f450b02a8b60b065988697e3f774b539d1fa8` |

**Is prediction vote now green?** The vote *builder* is fixed and correct
(rewritten to the deployed 3-in/4-out VoteReceipt layout, proven against the
real engine, and confirmed on-chain up to the fee gate). Vote is NOT
mempool-submittable and never will be: the deployed contract's V6 mandates
`total_in == total_out` (fee exactly 0), making it a miner-INCLUSION-only tx
by design. This is a design property of the deployed contract, not a bug — so
"prediction vote via kob-cli + RPC mempool" is closed as won't-fix (needs a
block producer), while every other prediction path (deploy, expire, both
refunds) is live-green.

**Anything still blocking?** No release blocker remains from this backlog.
Residuals (tracked, non-blocking): the prediction settle path shares the
vote/create covenant-binding requirement (fixed at the builder; settle wiring
not separately live-re-verified here); the multi-sell batch IOC residual is
fail-closed (dedicated `--ioc` single-sell path is the supported route); the
x402 `discover_landed_payment` stale-UTXO false-success gap (surfaced by, not
caused by, R2); and `oco-sell` has no cancel path. Spot lifecycle,
auto-matching, F6 defense, x402 native/KCC20/exact, listing, and the other
instruments are live-confirmed.

---

**Release verdict** (updated, release-backlog pass): The prediction module,
previously the main blocker, is now materially closed. `create` deploys
clean on-chain (covenant-binding + fee fix), and BOTH CLTV creator-reclaim
families -- `expire` and the `refund` (SplitMerge + Redemption) paths -- are
live-verified on testnet-10. `vote`'s builder is now correct (rewritten to
the deployed 3-in/4-out VoteReceipt layout, proven against the real
`kaspa-txscript` engine), and the live test established definitively that
`vote` is a fee==0 miner-INCLUSION-only tx by contract design (V6 forces
`total_in == total_out`), so it cannot be admitted to the standard RPC
mempool -- a design constraint of the deployed contract, not a builder bug.
The x402 CASE R2 `has_continuation` regression is FIXED + live-verified.

Remaining known gaps (tracked, not blocking spot/x402): the prediction
settle path shares the same covenant-binding requirement as vote (same root
cause, fixed at the builder for create/vote; settle wiring not re-verified
live here); the x402 `discover_landed_payment` stale-UTXO false-success gap
(surfaced by, not caused by, R2); and `oco-sell` has no cancel path. Spot
lifecycle, auto-matching, F6 adversarial defense, x402 native/KCC20/exact,
and the other instruments remain solid and live-confirmed.

## Post-hardening full run — running log

Node: `ws://65.108.107.30:18210`. Wallet: `/tmp/kob_e2e/wallet.json`
(`kaspatest:qz6qc3j490zleazs6upxazfnk79k7v4ksykf499uhur4el95cfy7qrwa6v8lf`).
Binaries: `/root/kob-rust-target4/release/{kob-cli,kob-engine,kob-x402,x402-client}`,
built from HEAD `a7f87e4` (SECURITY_FIXES Phases 1-5 applied: v16-default buy,
min_relay_fee=mass*100, sell RS 427B, x402 mandatory fingerprint/requestHash).

Funding: the external kaspa-wasm SDK miner (`tests/miner.mjs` derivative,
`/tmp/kob_e2e/miner_v16.mjs`) hit an immediate "WebSocket disconnected" on
every real RPC call against this node (getInfo/getUtxosByAddresses/
getBlockTemplate all failed identically, both borsh and json encodings) —
a protocol/version mismatch between that external wasm build and this node.
Built a native replacement, `kob-miner` (new `[[bin]]` in `kob/cli`,
`kob/cli/src/bin/kob_miner.rs`), reusing kob-cli's own proven-working
hand-rolled JSON-RPC websocket client plus `kaspa-pow`/`kaspa-rpc-core` for
the mining loop. Confirmed working (2/2 then N/N blocks accepted). Mined in
background to fund the wallet.

The final compact pass/fail table and release verdict are at the very top
of this file. Everything below is the terse running log it was derived
from.

## Log

- Funding: native `kob-miner` built + verified (see above). Background mine
  running (target ~40 blocks / ~300 KAS).
- Fixture token refreshed (old mint authority spent): token_covenant_id
  `690fa2aacde2ad6344114a2622bd402fdb493d564cfc025c38564cd0d18d5a10`, genesis
  `e2697bc5153bb4fe06bf4fce97770f20ee751f64be52984c169cf1e0e3d350b5`. 8
  fresh 30M token_units minted (chained mints, all confirmed).
- Spot: `deploy sell` (499/500) TXID `58525c1a250f494c6795191fdacd71361fc4fd5c5cfad31c4332472086bc8b5f`,
  fee=326400 sompi for compute mass 3264 -> exactly mass*100, confirms
  Phase-4 min-relay floor is live (no --fee-rate override used anywhere in
  this run -- default fee path exercised throughout).
  `deploy buy` (v16 default, no --version flag needed) TXID
  `e8ad85394930608447e985d42cdd170d448fd8591481081b2003154b3d9ff4da`.
  `list`, `orderbook`, `spread`, `order-status` all exercised against this
  pair (orderbook/spread showed correct crossed book: bid 1.0 / ask 0.998,
  spread -0.20%). `list` itself doesn't enumerate by token (documented
  legacy behavior -- "future version will cache"; ran clean, no error).
- **Batch matcher AUTO mode**: started `kob-engine --mode continuous
  --allow-self-trade --interval 3000`. Deployed a FRESH sell (499/500) +
  buy v16 mmfee-bps=2000 pair AFTER the engine's "ready" banner (orders
  deployed before are documented as not discovered -- confirmed by
  design, not a bug). Engine scanner discovered both within ~10s
  (`[SCANNER-ALL] Discovered SELL ...` / `Discovered BUY ...`), computed
  the crossing (surplus=60000, 0.2%, within the 2000bps/20% cap), and
  attempted settlement. First attempt hit a transient immature-coinbase
  fee-UTXO pick (artifact of the fresh mining, not a hardening bug); the
  engine's own retry loop picked a mature UTXO on the next 3s scan and
  settled successfully:
  **AUTO-MATCH TXID: `750e226376ca5af35f8b6e9d2446500fb2fbefc48da4e6e06dfdbc12d5459345`**
  (surplus captured=60000 sompi, matches the F6 cap-respecting plan).
  Confirmed both order UTXOs now `UNKNOWN`/spent via `order-status`
  (i.e. consumed by the settling tx). Engine killed after this to avoid
  interfering with the manual adversarial/instrument tests below.
- **F6 cap adversarial test**: deployed sell (1/2, 50% spread) + buy v16
  mmfee-bps=30 (0.3% real cap). Used `kob-cli match` with the TRUE
  mmfee-bps=30 for RS reconstruction (must match on-chain) but a lying
  `--fee-bps 5000` (50%) to force the planner to build an over-cap
  matcher take (7,500,000 sompi surplus vs the real 90,000 sompi cap).
  Node rejected: `"script ran, but verification failed"` (attempted TXID
  `4a16f18d5e549a3cc31cd556e4a012bda79f5664badecb166cf595f0f1aedd58`,
  never landed). F6 confirmed holding under current hardened binaries.
  Both orders left open (swept later by cancel-all).

### Bugs found + fixed live (product code, not just scripts)

1. **`kob-cli cancel` / `requote`: version-resolution bug** (`kob/cli/src/cancel.rs`,
   `kob/cli/src/requote.rs`). Cache lookup was gated on "some other field is
   missing"; supplying `--side/--price-num/--price-den/--min-fill` explicitly
   (a documented, sanctioned pattern) skipped the cache entirely, and
   `version` has NO CLI flag on `cancel` at all -- it silently fell back to
   sentinel `12` ("Unsupported contract version 12") or, on `requote`,
   silently assumed v14 for a v16 order (wrong RS, would fail closed at
   broadcast). Fixed: cache lookup now always runs (cheap local read);
   `needs_cache` kept only for the "loaded from cache" print. Rebuilt,
   verified live: `cancel` on a v14 sell succeeded
   (TXID `ccfd4514d07de4738488c226c6e5c5accce6954b190bd174e870e1a334557330`).
2. **`kob-cli partial-fill`: no fee floor at all** (`kob/cli/src/partial_fill.rs`).
   Not in Phase 4's fixed-17-files list; unlike those it never priced a fee
   from mass in the first place -- it just used the raw `--fee-rate`
   override (0 if omitted). Live tx was rejected: `"has 0 fees which is
   under the required amount of 344800 for compute mass 3448"`. Fixed: added
   the same Phase-1-estimate / Phase-2-exact-recompute-and-resign pattern
   used elsewhere (`kob_core::mass::{estimate_compute_mass,
   calc_mass_with_sigscripts, min_relay_fee}`), for both the sell and buy
   partial-fill builders.

### x402 finding: CASE R2 regression -- FIXED, live-verified (backlog item 4)

Live KIP-10 "exact" E2E (`e2e_x402_exact.sh`) CASE R2 (under-threshold
additive continuation) **regressed**: historically 28/28 (commit `56cbdce`);
now `/verify` returns `isValid:true` for a genuinely under-threshold
continuation instead of refusing it. Root-caused to
`scheme_exact.rs::verify_exact_kip10`'s off-chain "double-check" heuristic
(`has_continuation`: any output OTHER than the payment output, at the
merchant's SPK, with value >= min_continuation) -- in this E2E's **self-pay**
setup (payer == merchant, documented as intentional for practicality), the
payer's own change output also lands at the merchant's SPK and can
coincidentally satisfy the value check, even though it isn't the real
covenant continuation.

**Confirmed via a live repro that funds are NOT at risk**: calling `/settle`
on the SAME under-threshold artifact, the node's real on-chain covenant
correctly rejected the broadcast (`"script ran, but verification failed"`).
BUT this repro surfaced a SECOND, more concerning bug in the Phase-5
"recover from submit errors" path (`Facilitator::discover_landed_payment`,
`kob/x402/src/facilitator.rs:848`): on the submit error it scans the
merchant address's CURRENT UTXO set for ANY output at
`(pay_output_index, amount)` with no check that it resulted from THIS
broadcast -- it matched a stale, unrelated UTXO left over from an EARLIER,
unrelated happy-path settlement (same self-pay address, same fixed
`amount`/`index`), and `/settle` incorrectly returned
`"success":true"` with that OLD txid. Repro: reservation on a fresh borrow
(`db81d2ba...`), under-threshold artifact, `/settle` returned
`success:true, transaction:5d20cc25...` (a completely different, older,
already-settled TXID) while the facilitator log shows the real submit was
rejected on-chain (`0c45b407...` rejected, `5d20cc25` reused). This is a
real gap: a merchant with a fixed resource price (the common case) is
exposed to a false "paid" verdict when a payer's tx is rejected on-chain but
an older UTXO happens to share `(index, amount)`.
**Not patched here**: a correct fix requires either (a) snapshotting the
confirm-address UTXO set before every broadcast and only accepting a
post-broadcast-new outpoint, or (b) verifying the discovered output's
containing transaction actually spends this payment's `input_outpoints` --
both need updates to `ChainBackend`/the test `MockChain` (which currently
models "landed" as a statically-seeded UTXO with no before/after timing) to
verify without regressing `submit_error_but_payment_landed_recovers_to_success`
et al., which is beyond what could be safely verified live in this pass
(no local access to re-run `cargo test -p kob-x402 --lib` fast enough to be
sure). Flagged here as a follow-up, not silently patched.
**Severity**: merchant-side false-positive risk (release a resource for an
unpaid/rejected request) when the merchant reuses a fixed `(payTo, amount,
index)` tuple across requests; NOT a payer-fund-theft vector -- the on-chain
covenant still correctly protects the actual value transfer.
**Residual, still NOT patched (separate from the R2 fix below, out of this
pass's scope)**: the `discover_landed_payment` stale-UTXO issue just above is
a DIFFERENT bug from the R2 `has_continuation` heuristic (it was only
surfaced by the R2 repro, not caused by it). It still needs the
snapshot-before-broadcast or spends-these-outpoints fix described above.

**FIXED**: root cause was `scheme_exact.rs::verify_exact_kip10`'s
`has_continuation` check scanning ALL outputs for "any output at the
merchant's SPK with value >= min_continuation", instead of checking the ONE
output the borrow input's own signature script designates as the
continuation index -- the exact same index `X402_BORROW_BODY` reads on-chain
via `Op2 OpPick` (`kob/core/src/contract/x402_borrow.rs`). Fixed by decoding
that designated index from the borrow input's `signatureScript` (new
`decode_continuation_index`, mirroring `push_index`'s encoding) and checking
only that output -- bit-for-bit consistent with on-chain enforcement, so an
incidental same-address output (the payer's own change in this self-pay
harness) can no longer coincidentally satisfy it. New regression test
`scheme_exact::tests::rejects_under_threshold_continuation_despite_incidental_matching_change`.
`cargo test -p kob-x402 --lib` = 67 passed (was 66), 0 failed. Live re-run of
`e2e_x402_exact.sh` against testnet-10 after rebuild: **30/30 passed**,
CASE R2 now correctly refused (`invalid_payment_requirements`); happy-path
settle TXID `9d61a47c4180785b8b8e85af9b72c26979471a5c006876e4a1e7279b2c62f78c`,
borrow-funding TXID
`6875548ce8e302511c06c1f6f1f9e9d665c02c88588d8290ddd4b0b8909be2f0`. No
further live re-run needed for this specific bug.

### Spot lifecycle -- remaining commands (all live, all PASS)

- `cancel-mark` (2-step): mark TXID `8df6b85caa40cc80f303074e847bf2f03dbb5359350f4327f418a4cf81bffcfc`,
  step-2 cancel TXID `88769f30d98acd7b6bb252ee6d182ec9168dc86ad2dd4243cb3887f0fb21d6a6`.
- `partial-fill` (owner CLI, sell, after the fee-floor fix): TXID
  `86ef6b4238478ccc605c0ebf21cc572bb97593db9d1b7eb7571ebaac5303bf98`.
- `requote` (atomic cancel+deploy): cancel TXID
  `7ba0fe8e0072a13d5c0965d996b742c9e5315821fe073fc67f5f4c114941208e`, deploy
  TXID `61a0855bc3de08e48517f8bbd38eb0d20a8fbc28f3beeeeeba3159a5bbe24e4a`.
- `cancel-all --token ... --orders-file ... --yes`: correctly cancelled the
  2 genuinely-open orders (TXIDs `ebf0024b08535acff7f545b4b951ab715a50ef974c368938daf02e7191c3a82d`,
  `ec8e8db9f5001bb70d3fe6b981e08ad4f1c2a037f3dd97ae065a995dbddbbb9d`) and
  correctly SKIPPED the 6 already-spent ones ("not found on-chain"). Note:
  `--orders-file` defaults to a CWD-relative `orders.json`, NOT the
  wallet-directory cache other commands auto-use -- must pass it explicitly
  (documented behavior, not a bug; noted for the record).
- `wallet send`: TXID `535da5818dd4857fd2f59b7bf0eb34c072ff6ea570446c3406bf1919d9d15f05`
  (0.5 KAS to a throwaway derived address).
- `wallet consolidate`: 50 P2PK UTXOs -> 1, TXID
  `b56e3bd50ebc4ecdee446c14979c19a1b42f3c01d42f65699a99ba4b3953233b`.

### Other instruments (live deploy+cancel smoke, all against the same wallet)

- `token transfer`: TXID `109f1f843a1e9c43d98fd648d7af711ddc3bd47908068748570212a8ad0a7cd2`.
- `oco-sell` deploy: TXID `2561b00388ab46f28e87518ac9ae4f40038d7e0906701b699c16f0b371eaf822`.
  **No cancel path exists anywhere** (CLI or kob-core) for oco_sell -- only
  `deploy oco-sell` is wired; confirmed no `build_oco_sell_cancel`-shaped
  function anywhere in the tree. Left open (real gap, not a quick-fix; noted
  honestly rather than faked).
- `dca deploy` + `dca cancel`: TXID `eaef9ac32ef2c4be56567dc32bf9b62cd1ceaa61e791955807cda80a4cc8f311`
  / `0ec83a8e1220d5ff03f2cc3b679bb0348af8a46e00207f3ddbeceea4e8208526`.
- `lending offer` + `lending cancel`: TXID `f08c38f3dc531286fa2e48d9892d9a9a2c44f942fc1d6527ab96b0289e07c6c4`
  / `6b40f0ab80bca1b6d7aa0fe32346bca97beb05c6e8a40b98ea253f4746ecc936`.
- `perp deploy-long` + `perp cancel`: TXID `2973101a165182c1018de0419295c4a681b74771f01d2251199cf1d0ede20e17`
  / `f5f380c3270bfd290f1d34b219414c0f555a34a3c1aab75e923ab4de4d24aa19`.
- `insurance deploy-offer` + `insurance cancel-offer`: TXID `cee7d902512c68df753a27a0b7493fab16cb53ea475538c32bb30fb3d9df1003`
  / `85086b92f5698207c2991e6de70387ce5227688f90a36402cb997b700cdf33ac`.
- `swap deploy` + `swap cancel`: TXID `0f6d0631daff2d8bb8eef7046007f86d1b7c7c70c27e06890ca090eadd30236c`
  / `e33da5cc78c702eb415722f894f2aca406cce42e9059400f0c8aaebf41e6dea4`.
  (`receipt-cov-id` is only checked at FILL time (N4), not deploy, so a
  placeholder token-id is structurally valid for a deploy+cancel smoke.)
- `bracket deploy` + `bracket cancel`: TXID `2186357bf3b92b87f4e7d4aedff2e72b0eaca2e6198608a4153648f171211f41`
  / `2187ef817c172df528181953b921cd558a77c6686d1d59079a7e417dff64e905`.
  (`--oco-spk` fed a real, previously-deployed oco-sell P2SH SPK;
  `--receipt-cov-id` a placeholder -- same N4-at-fill-only reasoning. Fill
  not exercised.)
- `prediction create` (2-step: BallotBoxes+SplitMerge, then Redemption):
  step1 TXID `afb239e36705e54cd277a200f0b00d1fc177ff59526cfb66d2409fc3fb94de1f`,
  step2 TXID `31276e4d2ed14681f3c7ebea19a143b988f742da1c904066d765b7986bac54e2`.
- `listing`: **no CLI subcommand exists at all** (confirmed via `--help` and
  a `Listing`/`Auction` grep of `cli/src/lib.rs`) -- `kob/core/src/listing.rs`
  is a contract-only English/Dutch auction with off-chain-only test coverage
  (Fix 5 in SECURITY_FIXES.md notes it "had never been executed on-chain").
  Genuinely not exercisable via kob-cli; not a script-fixable gap.

### Third bug found + fixed live: prediction reclaim paths built a malformed scriptPublicKey

`kob-cli prediction expire` (BallotBox reclaim after the vote deadline
passed) was rejected on-chain: `"non-standard script form"`. Root cause:
`build_owner_spk()` (`kob/cli/src/prediction.rs:870`) returned a 36-byte
buffer with a redundant, hand-rolled 2-byte zero "version" prefix baked
INTO the script bytes, on top of the output's own separately-tracked
`script_version: 0` field (`PredictionTxOutput` in
`kob/domain/src/prediction/prediction_executor.rs:1046-1049`) --
double-counting the version and producing a 36-byte scriptPublicKey instead
of the correct 34-byte P2PK script. This helper is shared by ALL 8 of
prediction's owner-reclaim paths (vote/split/merge/settle/redeem/expire/
refund change + miner-change outputs), so this almost certainly meant NONE
of prediction's fund-reclaim paths had ever landed on-chain successfully.
Fixed: `build_owner_spk` now returns the plain 34-byte P2PK script (no
prefix). This fix was NECESSARY but not SUFFICIENT -- two more independent
bugs (below) were still blocking `expire` after this fix + rebuild, found
by actually re-running the live command rather than assuming the first fix
was the whole story.

### Fourth bug found + fixed: OP_CLTV consumption misunderstood across all 3 prediction covenants with a CLTV path

After the SPK fix + rebuild, a fresh live `prediction expire` attempt was
rejected on-chain with a NEW error: `"failed to verify the signature
script: opcode requires at least 2 but stack has only 1"` -- a script VM
stack-underflow, not a malformed-output problem. Root cause, confirmed
against the real kaspad `kaspa-txscript` engine source
(`OpCheckLockTimeVerify<0xb0, 1>`, which does `vm.dstack.pop_raw()`):
**`OP_CLTV` (CheckLockTimeVerify) POPS the stack value it checks**, unlike
Bitcoin's non-consuming `CHECKLOCKTIMEVERIFY`. Every CLTV use in this
codebase's prediction contracts (`kob/core/src/contract/prediction/`) was
written assuming the opposite (a value left on the stack that must be
explicitly dropped afterward), so each one over-drops by one stack item:

- `ballot_box.rs` EXPIRE PATH: dropped 5 items after CLTV (assuming
  `expiry_daa` was still there to drop) when only 4 remained (CLTV had
  already consumed it) -- starving the trailing `OP_CHECKSIGVERIFY` down to
  1 stack item (pubkey only, no signature). **This is the exact bug that
  blocked the required live step.**
- `ballot_box.rs` VOTE PATH (V1, `start_daa` CLTV check): the `PICK`+CLTV+
  `DROP` idiom assumed CLTV leaves the picked copy for the trailing
  `OP_DROP` to remove; in reality CLTV consumes the copy itself, so the
  trailing `OP_DROP` wrongly ate `expiry_daa` (the next real state item),
  corrupting every later PICK-by-index in the vote path. Found by
  re-deriving the stack by hand from the (verified, on-chain-confirmed)
  popping semantics -- **not live-tested** (see the vote-path gap below,
  which blocks testing this independently of the CLTV fix).
- `redemption.rs` refund path (RF1): `OP_CLTV, OP_DROP` -- same
  over-drop. Fix is a straight removal of the stray `OP_DROP`; the
  resulting stack exactly matches what the very next line's own comment
  already assumed (`pk (idx 7)`), confirming the rest of the path's
  indexing was already written for the correct (consuming) CLTV semantics
  and only this one extra drop was wrong.
- `split_merge.rs` refund path: same over-drop PLUS two knock-on bugs in
  the same block (a `PICK` depth off by one for `pk`, another off by one
  for `creator_pkh`, and a spurious trailing `OP_SWAP` before
  `OP_CHECKSIGVERIFY` that would have fed the signature check `(sig, pk)`
  instead of the required `(pk, sig)` order). Rewritten from a clean,
  from-scratch stack derivation rather than patched incrementally.

**Fixed** in all four spots (`kob/core/src/contract/prediction/ballot_box.rs`,
`redemption.rs`, `split_merge.rs`). The ballot_box EXPIRE fix is
**live-verified** (see the required-step TXID below). The other three
(`ballot_box` vote path, `redemption` refund, `split_merge` refund) are
fixed by the same rigorously-derived logic and covered by the existing
`cargo test -p kob-core` suite (63/63 prediction tests still pass -- these
are blueprint-construction/structure tests, not script-VM execution tests,
so they could not have caught this class of bug, but they confirm no
regression), **but were NOT live-verified** -- redemption's refund needs a
full settle-then-expire flow and split_merge's needs a split-then-wait-
then-refund flow, both considerably more live setup than this pass's scope
covered. Flagged here rather than silently assumed fixed.

**This is a systemic, previously-undiscovered bug family**: since prediction
contracts have no local script-VM test harness (unlike spot/x402, which
have `kob/core/tests/toccata_fill_repro.rs` and `x402_borrow_covenant.rs`
exercising the real `kaspa-txscript` engine), NOTHING in the test suite
could have caught a stack-shape bug like this -- only a live broadcast
against a real node surfaces it. This means every one of prediction's
CLTV-gated creator-reclaim paths was very likely non-functional on-chain
before this pass, on top of (layered under) the SPK bug above.

### Fifth bug found + fixed live: prediction expire's fee estimate was far too low for its actual sigscript size

After the CLTV fix + rebuild, the live `expire` attempt got past script
verification but was rejected as non-standard: `"has 166900 fees which is
under the required amount of 186500 for compute mass 1865"`. Root cause:
`build_expire_ballot_tx`'s fee (`kob/domain/src/prediction/prediction_executor.rs`)
uses the generic `estimate_compute_mass(1, 1, 0)`, which assumes a
generic ~100-byte P2PK-style sigscript per input. `expire`'s real
sigscript embeds the FULL BallotBox redeemScript (~190 bytes) alongside the
signature and pubkey pushes -- several times larger than the estimate
accounts for. Fixed in `kob-cli`'s `expire_ballot()`
(`kob/cli/src/prediction.rs`), mirroring the existing Phase-1-estimate /
Phase-2-exact-recompute-and-resign pattern already used elsewhere
(`kob/SECURITY_FIXES.md` Phase 4, and this same pass's partial-fill fix
below): after building the fully-signed tx, recompute the EXACT mass from
the real sigscript via `kob_core::mass::calc_mass_with_sigscripts`, and if
the exact fee exceeds the domain layer's rough estimate, shrink the payout
output and re-sign once more before broadcasting. **Live-verified**: see
the TXID below.

### Required live step: `prediction expire` landed on-chain

After all three fixes above (SPK, CLTV, fee estimate) + rebuild, a fresh
prediction market was deployed with a short vote deadline
(`--bet-deadline-daa 2 --vote-deadline-daa 6`), and `prediction expire` was
polled (~0.5-1s interval) on the YES BallotBox until the deadline passed:

- Market: question "E2E expire-flow test market v2 (post CLTV fix)",
  market ID `0cdaf340b236f31590d17f48e3da2ab180bf12fe6de19239f1bf51c8f37ec2e7`.
- YES BallotBox: `e39f40b08afeff4bb80ec251284a55f54ab8d0d86a979001410afa02de809d33:0`.
- **EXPIRE TXID: `93da68e841c7036981b7c9143ae301df58242b2607f23892f34ce3a2985c161a`**
  (reclaimed 999813500 sompi / 9.998135 KAS to the creator, per the CLI's
  own printed `Reclaimed:` line). `submit_transaction` returned the TXID
  with no RPC rejection (all prior attempts in this pass returned an
  explicit rejection message instead), and a follow-up `wallet balance`
  showed a new spendable UTXO (2 UTXOs total) consistent with the payout
  having landed.

### Gap found (NOT fixed, out of scope for this pass): `prediction vote` is structurally stale vs. the deployed BallotBox contract

While investigating the CLTV bug in the vote path, a separate, larger,
pre-existing gap surfaced: `kob-cli prediction vote` builds its
transaction via `kob_domain::prediction::build_vote_tx` (a 2-input
[BallotBox + miner] / 2-output ["v4"] blueprint, per its own doc comment
and the `build_vote_tx_basic` test asserting `bp.inputs.len() == 2`). The
CURRENTLY DEPLOYED `BALLOT_BOX_BODY` bytecode is a newer "vote-receipt
enabled" version whose vote path requires **3 inputs** (the voted
BallotBox, the OTHER side's BallotBox as a read-only co-input, and the
miner UTXO) and **4 outputs** (both BallotBox continuations, miner change,
and a minted VoteReceipt) -- `V0`/`V5`/`V6`/`V7` in the redeem script all
enforce this. `build_vote_tx` was never updated when the contract grew
VoteReceipt support, so `kob-cli prediction vote` would fail on-chain
immediately (wrong input/co-input count) regardless of the CLTV fix.
**Not fixed here**: a correct fix needs a new domain builder (3-in/4-out,
including on-stack-matching VoteReceipt P2SH construction) -- a real
feature, not a bugfix, and beyond this pass's scope. This ALSO means the
`ballot_box.rs` VOTE PATH CLTV fix above could not be live-tested through
the current CLI (there is no working path to a live vote transaction to
test it with). Noted honestly rather than silently left broken.

## Auto-matcher comprehensive run (continuous daemon, autonomous discovery + settle)

Node `ws://65.108.107.30:18210` (testnet-10). Wallet
`kaspatest:qz6qc3j...cfy7qrwa6v8lf` (`/tmp/kob_e2e/wallet.json`). Binaries
`/root/kob-rust-target4/release/{kob-cli,kob-engine}`. Daemon launched
DAEMON-FIRST and detached (`setsid nohup kob-engine --mode continuous
--interval 800 --allow-self-trade --cross-pair --fee-bps 30 --api-port 8080
... &`), confirmed scanning (ready banner + block cursor advancing), THEN
orders deployed so their deploy TXs land in blocks it scans forward. Funding
via `kob-miner` (PoW.checkWork native miner; 60/60 blocks accepted this run).

### Autonomous auto-match settle TXIDs (daemon-produced, confirmed on-chain)

All confirmed via the tn10 REST API (`api-tn10.kaspa.org/transactions/<txid>`),
independent of the wRPC node:

| # | TXID | Form | Book | Surplus (F6) | Binary |
|---|---|---|---|---|---|
| 1 | `6cf08c27dbdd8dcdd3760f239891ef08e6c77d62a9a7212cf8f3d853d75909f7` | 1:1 `Batch` | sell 800M@499/500 + v16 buy 800M@1/1 | 0 (mmfee floor) | pre-fix |
| 2 | `a801a585b01c9d5eb8acc3e38dcba2d2e7bdd954ab6d7b72c03b68a0cee76a1f` | 1:1 `Batch` | sell 200M@495/500 + v16 buy 200M@1/1 | 2,000,000 ≤ 40M cap ✓ | per-pair fix |
| 3 | `e459a8d5edcb8f0914ef444ab955284ac499fe970c3402f1295c124c25269d7b` | 1:1 `Batch` | sell 200M@497/500 + v16 buy 200M@1/1 | 1,200,000 ≤ cap ✓ | per-pair fix |

TXID 2 verified 3-in/3-out on-chain: out0 198,000,000 (seller KAS = 200M @
495/500), out1 200,000,000 (buyer tokens, covenant-bound), out2 change; F6
surplus 2M well under the 2000bps (40M) cap. TXIDs 2+3 came from a single
2-sell:2-buy crossing book that the daemon discovered across separate scan
cycles and autonomously settled as two sequential 1:1 `Batch` matches —
i.e. autonomous multi-order settlement, several orders matched + settled by
the daemon with no manual `match` call.

### Bug found + root-caused (real product-code bug; fix DESIGNED, not committed — see below)

**Multi-sell same-token single-TX batch: covenant-authorization reject.**
When the daemon discovered a crossing book with **2+ sells of the same
token** and swept them against a buy, it planned + built the settlement TX
and the node rejected it:
`covenants error: 0 is not a valid covenant output index for input 1 with 0
authorized outputs` (rejected, never landed: `97964d89c29cd64d...`,
`7090e23b3f31f611...`).

Root cause: `plan_batch_match` / `plan_ioc_match`
(`kob/domain/src/spot/batch.rs`) **merged** all buyer-token outputs of a
token into ONE output whose covenant `authorizing_input` was, via
`token_input_map`, always the **first** sell. But the deployed v14 sell
contract's F4 token-conservation check is **per-input** —
`OpTxInputIndex Op0 OpAuthOutputIdx` (see `SELL_ORDER_BODY` in
`kob/core/src/contract/spot/order.rs` and `auth_output_index` in
`crypto/txscript/src/covenants.rs`). Every covenant output can declare only
one `authorizing_input`, so the 2nd+ sells had **zero** authorized outputs
and the node rejected. This is why the pre-existing auto-matcher had only
ever settled **1:1** groups (a single sell authorizes the single buyer
output).

**Fix DESIGN** (prototyped in `kob/domain/src/spot/batch.rs` `plan_batch_match`
+ `kob/engine/src/chain/executor.rs` `execute_batch_match`, then **reverted —
NOT committed**, see "Why the fix is not committed" below): when a token has
>=2 fully-filled sells, emit **one buyer-token output per buy** (no cross-buy
merge) and bind each output to a **distinct** sell (new
`BatchPlan.buyer_token_auth_input`, distributed least-used). The executor
reads `buyer_token_auth_input` for the per-output authorizing input in BOTH
the initial and the Phase-2 fee-convergence covenant-binding builds; an empty
vec preserves the legacy single-authorizer binding for 1:1 / cross-token /
single-sell groups.

**Deeper finding (documented contract limitation, not fixable in the
builder): `BuySweep` / `GtcBuyMultiFill` — N sells : 1 buy, same token — is
fundamentally unsettleable.** Splitting per sell (needed for the sell F4)
was tried first and moved the reject from the covenant error to
`script ran, but verification failed`: the **v16 buy's F6 surplus cap**
(`BUY_ORDER_V16_BODY`, `order.rs`) reads `output[toi]` as the **total**
tokens delivered to the buyer to compute `fair_kas`; with tokens split into
one output per sell, F6 sees only one sell's worth (e.g. 200M of 600M),
computes a bogus 500M "surplus" and rejects. The sell side wants N separate
covenant outputs; the buy side wants ONE aggregated output — and token
conservation (total token output == total token input) forbids satisfying
both at once. The per-sell fix therefore keeps the **merged single output
for `plan_ioc_match`/BuySweep** (correct for exactly 1 sell) and confines
the multi-sell per-pair binding to `plan_batch_match`. The only settleable
same-token N:M-in-one-TX form is **N sells : N buys paired 1:1**.

**Why the fix is NOT committed (honest):** the prototype compiled clean and
the shared `plan_batch_match` 1:1 path kept settling live (TXIDs 2+3 were
produced by the prototype binary, using that unchanged 1:1 path), BUT:
(1) `cargo test -p kob-domain spot::batch` went **41 passed / 5 failed** —
the prototype breaks `test_simple_same_pair_batch`, `test_large_batch`,
`test_20x20_large_batch`, `test_large_coi_succeeds`,
`test_bps_cap_prorata_multi_buyer`. Those failures are two kinds mixed
together: some are *partial-sell* multi-sell scenarios (buyer wants fewer
tokens than a sell holds) where the legacy merge is actually **correct**
on-chain (each partial sell authorizes its OWN residual/`SellRemainder`
output via the Op5 F4 path, so the per-input auth is satisfied without
per-buy binding) and the per-sell branch wrongly rejects them; others are
genuine *full-fill* multi-sell tests whose assertions encode the very merge
that fails on-chain and would need rewriting to the corrected structure.
A correct fix must therefore scope the per-sell binding to **full-fill only**
and **fall back to the legacy merge for partial-sell**, then update the
full-fill test assertions. (2) The full-fill N:N success path could not be
**live-verified** on this node (see below), and committing an unverifiable,
test-breaking change to covenant-critical code is the wrong call. The bug +
root cause + fix design are captured here for a proper implementation.

**Why the N:N-in-one-TX success path is not live-settled here (honest):**
the daemon matches greedily every 0.8s, so a balanced book deployed
order-by-order settles as **sequential 1:1s** (exactly what TXIDs 2+3 show
from a 2:2 book). Forming a single >=2-sell group requires **batched
discovery** — all orders discovered in ONE scan cycle — which in kob-engine
only happens during a forward-scan **catch-up**. This testnet node
deterministically **hangs at 0% CPU** on the daemon's bulk `getBlocks` for
large gaps (observed 4x: 1057 / 1358 / 1320 / 1357-block catch-ups all
stalled with no progress), so the batched-discovery trick (kill daemon ->
deploy the full book while down -> restart -> catch-up discovers all at
once) never completed. Small near-tip catch-ups DO work (that is how the
daemon discovered + settled TXIDs 2+3). The blocker is node catch-up
throughput, not the fix. Six such orders remain OPEN on-chain for a future
run where the node serves the catch-up:
`3815bd03...`, `6ae839da...`, `02d33920...` (sells) +
`baee5fa3...`, `dc256ba9...`, `0c4f607a...` (buys), plus a 2-sell:2-buy set
`b03a9fc5...`,`038ac10a...`,`d013a0cc...`,`a44208f4...`.

### Matcher-internal-form coverage (from batch.rs / matching.rs / executor.rs)

| Internal form (`GroupKind` / path) | Planner | Status this run |
|---|---|---|
| 1:1 full `Batch` | `plan_batch_match` | **LIVE-SETTLED** (`6cf08c27`, `a801a585`, `e459a8d5`) |
| N:N same-token in ONE TX (`Batch`, >=2 sells) | `plan_batch_match` (per-pair fix) | **BUG root-caused; fix DESIGNED, not committed** (breaks 5 partial-sell/merge unit tests; unverifiable on this node — see Bug section) |
| `PartialBuy` / `PartialSell` (1:1 partial) | `compute_partial_fill_match` -> `plan_ioc_match` | not driven live this pass; CLI partial-fill separately live-proven earlier (`86ef6b42...`). Seed: 1 small sell + 1 larger buy (or vice-versa) crossing, in one cycle |
| `BuySweep` (N sells : 1 buy, IOC) | `plan_ioc_match` (v14/v16) / `plan_ioc_match_v17` (v17) | **CONTRACT-LIMITED for v14/v16 IOC** (sell-F4 needs per-sell outputs vs buy-F6 needs one aggregated output; token conservation forbids both). **v17 IOC BuySweep is now genuinely wired** via the dedicated `plan_ioc_match_v17` (per-sell BuyerTokens outputs, each bound to its own sell input; IOC floor relaxed to the buy's own `min_fill`); routed at the executor's `BuySweep`/`PartialBuy` dispatch and the CLI `--ioc` path, both gated on `buy.version == 17`. Engine-proven end-to-end in `domain/tests/v17_ioc_planner_engine_repro.rs` (the ACTUAL `build_tx()` output through the real `kaspa-txscript` engine). Correction: an earlier note here claimed "the v17 IOC BuySweep path (`plan_ioc_match` for v17) is wired" — that was FALSE (`plan_ioc_match`'s single merged output does not match the v17 per-term `OpAuthOutputIdx` binding, so it could never settle); the real fix is the new `plan_ioc_match_v17`. |
| `SellSweep` (1 sell : N buys) | `plan_sell_ioc_match` | not driven live; needs an IOC sell + >=2 buys discovered in one cycle |
| `GtcBuyMultiFill` (N sells : 1 v17 buy, same token) | `plan_batch_match` -> `plan_batch_match_v17` | **LIVE-SETTLED under v17** (`6794639c…`, 3 sells → 1 v17 buy in one tx; see "v17 N:M live verification" at the top). The old contract limitation was a v14/v16 property; v17's per-sell BuyerTokens + summed F6 lifts it. `GtcSellMultiFill` (1 sell : N buys) is the still-open mirror. |
| `CrossSwap` / cross-pair 2-hop / triangular ("triangle") | `match_swap_routes` -> `execute_swap_fill` (submit at executor.rs:1538) | cross-pair routing was ENABLED (`--cross-pair`) but no `swap` covenant + bridge counterparties were deployed to route; needs 2 tokens + a `swap deploy` + a buy-source in pair A + a sell-target in pair B |

### Non-spot instrument auto-fill capability matrix (engine wiring audit)

Does the continuous daemon autonomously BUILD + SUBMIT a settlement/fill TX
(vs deploy-only / manual CLI)? Evidence from `kob/engine/src/chain/executor.rs`
unless noted.

| Instrument | Auto-fill wired into daemon? | Trigger | Evidence |
|---|---|---|---|
| **Spot** (buy/sell; batch/sweep/partial/IOC) | **YES (auto)** | crossing orders in a token book | Phase 1 `execute_batch_match` -> `[BATCH] SUCCESS!` (1163); LIVE this run |
| **Swap** (cross-token) | **YES (auto)** | swap covenant + buy-source (pair A) + sell-target (pair B), KAS-bridged | Phase 3 `execute_swap_fill` submit (1538) -> `[SWAP-FILL] SUCCESS!` |
| **Perp** (long/short) | **YES (auto)** | a crossing long + short perp deploy pair | Phase 4 `perp_executor::build_open_position_tx` + submit (3839) -> `[PERP] SUCCESS! Open-position TXID` |
| **Lending** (offer/request) | **YES (auto)** | a loan offer matched to a borrow request | Phase 5 `lending_executor::build_lending_match_tx` + submit (4102) -> `[LENDING] SUCCESS! Match TXID` |
| **DCA** | **YES (auto)** | period window reached (`next_execution_daa`) AND limit price crosses; permissionless | DCA block submit (4747) -> `[DCA] FILL SUCCESS` |
| **Stop / Stop-limit / Stop-market** | **YES (auto-broadcast)** | trigger price hit; Matcher broadcasts the pre-signed TX it holds | `submit_transaction` + `mark_triggered(id, Some(tx_id))` (~5400). Requires `stop deploy-sell --matcher-url` (Matcher-held, off-chain, not an on-chain covenant) |
| **Trailing stop** | **YES (auto-broadcast)** | price reverses by the trail distance | same broadcast loop as stop (~5400); Matcher-held |
| **IFD (If-Done)** | **YES (auto)** | entry order fills -> exit auto-deployed via the fill TX's IFD payload | `ifd.trigger(rule_id, tx_id)` after a batch fill (3462); trustless IFD via embedded payload |
| **Prediction market** | **NO (track-only)** | Phase 6 only LOGS "SETTLEABLE" / "creator can reclaim after expiry" | Phase 6 (~4214-4282) has **no** `submit_transaction`; `settle`/`expire`/`vote`/`redeem` are manual CLI (and `vote` is a fee==0 miner-inclusion-only TX by contract design, see above) |
| **Options** (call/put) | **NO (deploy-only)** | — | **zero** engine references; no `option_executor`; exercise/expire/cancel are manual CLI only |
| **Insurance (CDS)** | **NO (deploy-only)** | — | **zero** engine references; claim/release/timeout/mutual-cancel are manual CLI only |
| **Bracket / OCO-sell** | partial (folds into spot) | bracket entry / OCO-sell fill folds into a spot batch group (RS-size / `oco_path` detection) | executor.rs 422-503; fill not driven live this pass |

Summary: `lending_executor` / `perp_executor` / `prediction_executor` are the
three `kob_domain` executor modules re-exported by the engine
(`kob/engine/src/matcher/mod.rs` 22/25/28). Perp, lending, DCA, spot, swap
all have a real auto-fill submit path in the continuous daemon; stop /
trailing-stop / IFD auto-broadcast on trigger; **prediction is settlement
track-only (no auto-submit); options and insurance are deploy-only with no
engine-side execution at all.**
