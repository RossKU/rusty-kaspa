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
| `prediction vote` | NOT FIXED (found broken, out of scope) | domain builder is a stale 2-in/2-out "v4" blueprint; deployed contract requires 3-in/4-out with VoteReceipt minting -- real feature gap, not a bugfix |
| `redemption.rs` / `split_merge.rs` refund paths (same CLTV bug family) | FIXED in code, NOT live-verified | fix derived by rigorous stack-trace + confirmed against 63/63 passing `cargo test -p kob-core` (construction-level only, cannot catch VM-level bugs) |
| `listing` (English/Dutch auction) | NOT EXERCISABLE | no CLI subcommand exists at all; contract-only, off-chain-tested per SECURITY_FIXES.md Fix 5 |
| x402 KIP-10 exact CASE R2 (under-threshold continuation) | FIXED, live-verified | root cause + fix in `kob/x402/src/scheme_exact.rs` (see below); re-run of `e2e_x402_exact.sh` after rebuild: 30/30, R2 now correctly refused (`invalid_payment_requirements`); happy-path settle TXID `9d61a47c4180785b8b8e85af9b72c26979471a5c006876e4a1e7279b2c62f78c` |

**Release verdict**: NOT ready to ship as-is. Spot lifecycle, auto-matching,
F6 adversarial defense, and most secondary instruments are solid and
live-confirmed. But this pass found **5 live bugs in the prediction
market module alone** (malformed SPK, two independent CLTV-consumption
stack bugs, an undersized fee estimate, and a structurally stale vote
path) -- the prediction contract family in particular was very likely
non-functional end-to-end before this pass, and `vote` still is. Ship
spot/x402/other instruments; block on a real audit + fix pass for
prediction's vote path before treating that module as production-ready.
(Update, release-backlog pass: the x402 CASE R2 `has_continuation` regression
is now FIXED + live-verified -- see below. The unrelated
`discover_landed_payment` stale-UTXO false-success gap it surfaced is still
open, tracked separately.)

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
