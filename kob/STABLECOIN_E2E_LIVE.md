# KCC-0020 Robust Stablecoin — testnet-10 Live E2E Results

**Date:** 2026-07-20
**Network:** testnet-10  **Node:** `ws://65.108.107.30:18210` (synced, v2.0.1)
**Harness:** `cli/src/bin/kob_stablecoin_e2e.rs` (bin `kob-stablecoin-e2e`)
**Design:** `STABLECOIN_ROBUST_DESIGN.md` (Liquid-AMP model, option B baked keys)

The full robust stablecoin lifecycle — the 5-branch covenant plus the separate
mint-authority contract — was exercised end-to-end on testnet-10 in a single
clean run. Every transaction was accepted and every covenant output's
shape/covenant_id/value was verified on-chain.

## Op sequence (clean run, all accepted)

| # | Op | TXID | On-chain result |
|---|---|---|---|
| 1 | DEPLOY TX1 (anchor, fixes G) | `1e8e11ae4e71c7e0e315118ca06a536f23c28249e839a2311f9dd6e6b17e6580` | anchor tagged CovenantBinding(G) |
| 2 | DEPLOY TX2 (mint-authority genesis) | `e83c3621428af3113753998b5b03fabf6e6231421cbc965978f6bb19ae9cb714` | authority live @ `:0`, G=`0c1612d8a0623d4cc492a18b28bb44dcf95b9d0a34ece51384e354b0ab6566f5` |
| 3 | MINT | `806f49732bb6e6f8f3c4a8b70822b3223b608a67f26b32f4376ee826f51ae40a` | authority value preserved (`:0`); coin @ `:1` value=50000000, covenant_id=`a3aa08d2…`, frozen=0 |
| 4 | TRANSFER (owner→owner2, OPS-attested) | `e084241bb11d8dc35a2086a1a8b36457fe61307768caccf3133bb731d9b35123` | successor value/root/epoch preserved, frozen==0 gated |
| 5 | FREEZE (FREEZE key) | `7feda6f60a7705d8230b4c4ae6e5b6fff9ec79e71ae14a0d083fb4339698ed28` | frozen_flag 0→1, value continuity |
| 6 | SEIZE (2-of-3 cold quorum) | `06ae2006493ab3e302353d0acea3a6922c8e436c80c31f84eac20654435c806b` | owner→recovery (no owner sig), frozen preserved, value continuity |
| 7 | UNFREEZE (FREEZE key, new_flag=0) | `ccd41e6e5f27846551b8478381c6f3835068faedf4786c9634c5d276c5826030` | frozen_flag 1→0 (required before BURN) |
| 8 | BURN (owner+MINT) | `88c837c100f4cbf51d535c07db48293c992eca1a02df5901cfab3fe887048c43` | 50000000 sompi destroyed → P2SH(OP_RETURN) unspendable sink `:0` |
| 9 | RAISE_CAP (2-of-3 cap_authority) | `ec15b0d8acc4c05aa83b372570a990b4ebafcbe5ab7a0cf8fcc5b79064def802` | current_cap 100G→200G, running_supply preserved, value continuity |

Verify any TXID at `https://api-tn10.kaspa.org/transactions/<txid>`.

## Behaviors validated on-chain
- 2-TX genesis bootstrap; mint-authority genesis covenant_id `G` baked and
  enforced (`OpInputCovenantId == G`) so a fake parallel authority cannot mint.
- Per-coin covenant_id prediction matched consensus exactly.
- Anti-backdoor emitted-coin reconstruction + recipient binding (MINT).
- Value continuity on non-owner-signed branches (FREEZE/SEIZE/RAISE_CAP) and
  the mint-authority self-continuation.
- `frozen_flag==0` gate on owner-side ops (TRANSFER/BURN/MIGRATE); SEIZE acts on
  frozen coins; UNFREEZE restores mobility.
- 2-of-3 cold multisig for SEIZE and cap_authority (RAISE_CAP).
- Elastic (raisable) cap as a real safety bound.

## Bugs discovered during the live run (all fixed)
1. **compute-budget under-committed** — covenant inputs declared `sig_op_count=1`
   → v1 computeBudget=10 → 109999-unit cap < MINT's 127801 actual. Fixed:
   covenant inputs use `sig_op_count=8` (budget 809999). (harness)
2. **burn sink non-standard** — bare `OP_RETURN [0x6a]` is not a standard Kaspa
   output (only P2PK / P2PK-ECDSA / P2SH classes exist). Fixed: sink is now
   `P2SH(OP_RETURN)` — standard and provably unspendable. (core `body.rs`)
3. **burn sink check** — realigned from a raw-bytes compare to the proven
   `dr_output_spk_check` hash mechanism. (core `body.rs`)
4. **op_burn input SPK** — the covenant input used the raw redeem script for
   `script_bytes` instead of the P2SH locking script, so the owner's SIGHASH_ALL
   was signed over the wrong sighash → `OpCheckSigVerify` failed. Fixed to use
   `build_p2sh(&coin.rs).script()`. Only affected owner-signed ops (TRANSFER did
   it right; BURN was the only other one). (harness)
5. **op_raise_cap orphan** — re-queried the node for a fee UTXO and reused BURN's
   just-spent (unconfirmed) outpoint → orphan. Fixed to thread BURN's change
   output forward as the fee input. (harness)

## Operational notes
- Funding: self-mined with `kob-miner` (RELEASE build — the debug build is far
  too slow to find testnet blocks). Node is a low-difficulty dev node.
- Coinbase maturity on testnet-10 is **1000 DAA** (a few minutes).
- The wallet/keys files must live on a real filesystem (e.g. `/root`), NOT under
  `/storage` (sdcardfs ignores `chmod`, so the required `600` never sticks there
  and the wallet loader refuses to open it).
- Invocation:
  `NODE=ws://65.108.107.30:18210 WALLET=/root/kob_wallet.json KEYS_MANIFEST=/root/kob_sc_keys.json CAP=100000000000 MINT_AMOUNT=50000000 MINT_AUTHORITY_VALUE=100000000 kob-stablecoin-e2e`

---

# Live run 2 — 2026-07-20, post-hardening (MIGRATE's first live execution)

Run against testnet-10 with the binary built from `9a705335`, i.e. AFTER the
covenant hardening and the CRITICAL template-authentication fix. Every branch
whose bytecode changed is exercised here, so this run is the live proof of that
work — the first run predates all of it and its P2SH addresses no longer exist,
since changing the body changes the redeem script and therefore the address.

Command (`MIGRATE_DEMO=1` swaps MIGRATE in for BURN; both consume the single
minted coin, so they are alternatives):

```
NODE=ws://65.108.107.30:18210 WALLET=/root/kob_wallet.json \
KEYS_MANIFEST=/root/kob_sc_keys_v2.json CAP=100000000000 \
MINT_AMOUNT=50000000 MINT_AUTHORITY_VALUE=100000000 MIGRATE_DEMO=1 \
kob-stablecoin-e2e
```

| # | Op | TXID | storage mass |
|---|----|------|--------------|
| 1 | DEPLOY TX1 (anchor) | `86fc330c12bc0d3f4d60ffd75a3a9ddc252b93515ebc0a2ac1bb145b70d39fbd` | — |
| 2 | DEPLOY TX2 (mint authority) | `320bfbcfc7e66ae179c67860f5ba5f04777a80bd67644f80351571781c3b554c` | 30,066 |
| 3 | MINT | `2a0728ac3725fdc05efd5113ae43336db979056c7094f3cf9265af0255fb6a3c` | 122,741 |
| 4 | TRANSFER | `74984aa82c28cbe4f5ca9fbe9c4ef11defd5ce261dcb150c49d1f52d27c67e09` | 90,326 |
| 5 | FREEZE (flag=1) | `5d501905f5d14d37ea1bbb948ad10a333f9ac1c85bfa49514f1c8a69947b117d` | 96,665 |
| 6 | SEIZE (2-of-3) | `60fbba95ab8bd0e13f885c79ab54400898524e18d8328fd66dae33e53ac9a64f` | 104,905 |
| 7 | UNFREEZE (flag=0) | `40d4bce01167a021d732c46a99c9aaaa33b8b86d948f6d3f0e7bc82e8095d9d7` | 115,544 |
| 8 | **MIGRATE** (owner + cold 2-of-3) | `8cb054a6a07a66636421244d58413109543e0e77dc1a2f04ea5666119dca5260` | 13,196 |
| 9 | RAISE_CAP (2-of-3) | `c5cb1d028d313dc50e48d54d2d4b40e7398ed2f76dd090ce17206f8070704524` | 141,197 |

Genesis covenant id `60471fea…7611`; coin covenant id `30a2e430…1cd9`; final
`current_cap` 200,000,000,000. Every output was verified on-chain for value,
covenant id and shape before the next op was built.

## What this run establishes

- **Template authentication works on a real node.** TRANSFER, FREEZE and SEIZE
  each now supply their own redeem script as an extra deepest sigscript item,
  prove it against the input's own SPK, and suffix-compare the successor. All
  three were accepted, so the added `dr_input_spk_check` + `dr_suffix_check`
  bytecode executes correctly under the real engine, at the real script size,
  with the real P2SH wrapper — not just in the test harness.
- **MIGRATE ran live for the first time**, under its new authorization: owner
  SIGHASH_ALL plus a cold 2-of-3 SEIZE quorum. The coin moved to a plain wallet
  P2PK output (`covenant_id=None` on the destination, confirmed by the on-chain
  check), which is the branch behaving as designed: it authenticates the target
  only by the hash the quorum attested and never inspects it, so the coin does
  genuinely leave covenant governance — by cold-quorum decision.
- **The frozen_flag domain gate and the sig_op_count change are live-clean.**
  Both FREEZE ops (set and clear) were accepted, and MIGRATE's 4 sig ops passed
  the compute budget.
- **Storage-mass preflight matched reality.** Every op printed a mass well under
  the 500,000 limit and none was rejected by the node for mass — the local
  KIP-9 calculation agrees with what the network enforced.

## Live run 3 — the BURN path, same binary plus a fee-selection fix

Run 2's BURN-path attempt stopped at UNFREEZE with `fee UTXO 3183989 too small
after fee 1347300`. The cause was not a shortage of funds but
`pick_wallet_utxo`, which returns the SMALLEST UTXO clearing `min_value` — and
the covenant ops asked for `300_000` when the real requirement is the fee
(1.1–1.6M sompi on testnet-10) plus a change output clearing `MIN_UTXO_VALUE`
(3,000,000). Asking for too little does not merely under-specify: it actively
selects a UTXO that is doomed to fail the change check later, while passing over
larger ones that would have worked. Fixed by introducing `FEE_INPUT_MIN`
(`MIN_UTXO_VALUE + 2_000_000`) and using it at every fee-only call site.

With that fix the full BURN sequence completed on the first attempt:

| # | Op | TXID |
|---|----|------|
| 1 | DEPLOY TX1 | `ff9583bec021d186dd819faee13b2457560d12719139b46e26d6dd674bfcd07b` |
| 2 | DEPLOY TX2 | `9b96a50587d9a7b0e00666a7599ba3d4ca7fc0d27ea47cdf1a7b08787b4cf7cc` |
| 3 | MINT | `db575ea1ffb4ed89f34d45987bdc3c2d2a754edd2d33f94bb934787cf68055a1` |
| 4 | TRANSFER | `eb8dd8b8b95ab6e3a563ef3d263b3cfd4e2f1456c48adf03ffc99d21fdf41665` |
| 5 | FREEZE (flag=1) | `08c3dff10e9cc4eca99d577eea365f5c689a0e48918f70762d4c5721a1002cac` |
| 6 | SEIZE (2-of-3) | `81faebca5ca6abdc354c9f4468317f7b8f00d5da782c7887cd0bb957c12b0d19` |
| 7 | UNFREEZE (flag=0) | `d412abd69ab93890b201acb8395d2f87bdc88bcaec361ebf0e930cc81707437a` |
| 8 | **BURN** | `583b511ac18a4aceb16cead3a8fa633e697ba63f2d10db5ffa9e518ef6aaca9d` |
| 9 | RAISE_CAP | `bc878cc0abff607d08b65fa975591cd8bb7d9ece28f48c488a24c73581bbde50` |

Both terminal branches are therefore live-proven against the hardened covenant:
MIGRATE in run 2, BURN here. TRANSFER, FREEZE and SEIZE — the three branches
that gained template authentication — have now each been accepted on-chain three
times across the three runs.
