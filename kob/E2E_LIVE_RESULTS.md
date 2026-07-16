# KOB Live testnet-10 E2E — post-hardening full run

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
| `BuySweep` (N sells : 1 buy) | `plan_ioc_match` | **CONTRACT-LIMITED** (sell-F4 needs per-sell outputs vs buy-F6 needs one aggregated output; token conservation forbids both) — currently rejects on-chain |
| `SellSweep` (1 sell : N buys) | `plan_sell_ioc_match` | not driven live; needs an IOC sell + >=2 buys discovered in one cycle |
| `GtcBuyMultiFill` / `GtcSellMultiFill` (N:1 same token) | `plan_batch_match` | same contract limitation as BuySweep (one aggregated buyer/seller output cannot be authorized by N inputs) |
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
