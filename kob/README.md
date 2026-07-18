# KOB — Kaspa Order Book

Pure order book DEX on Kaspa L1 covenants. No AMM, no liquidity pools, no oracles.

## Architecture

```
kob/
  settle/  — Settlement core: crypto, mass/fee, tx building, wallet, RPC
             client (submit/UTXO/finality), payment-watch seam, replay log.
             Zero DEX-domain coupling; reused by the DEX and the x402 crate.
  core/    — Contract scripts, sighash, mass calculation, signing, wallet
             (re-exports the settlement pieces from kob-settle)
  domain/  — Order books, batch planner, match domain logic (spot/perp/lending/prediction)
  cli/     — Command-line interface for deploy, cancel, match, MM bot
  engine/  — Matching engine, chain scanner/executor, cross-pair routing, API
  x402/    — Kaspa x402 payment facilitator (verify/settle HTTP server) over
             kob-settle: native-KAS + KCC20 "exact" payment schemes
  lab/     — Script-level experiments and prototypes
```

Built as workspace members of [rusty-kaspa](https://github.com/kaspanet/rusty-kaspa), directly referencing `kaspa-consensus-core`, `kaspa-hashes`, and `kaspa-addresses`. Synced with upstream master post-Toccata (mainnet activation 2026-06-30); crates.io kaspa crates (frozen at 0.15.0, pre-covenants) are NOT usable — the in-tree path deps are required.

## Release status

**See `kob/RELEASE_STATUS.md` for the current canary scope, what's live-proven
vs. untested, and known open items.** That file is the single source of
truth; this README's Products table below is refreshed alongside it but
`RELEASE_STATUS.md` is authoritative on anything time-sensitive.

## Products

_As of 2026-07-18 (HEAD `73d3e330`; see `kob/E2E_LIVE_RESULTS.md`'s latest
Stage-G entries for the reference date)._

| Product | Status |
|---------|--------|
| Spot (Buy/Sell/Partial/OCO) | **v18 is the sole spot generation** (`pub const SPOT_GENERATION: u32 = 18`, `kob/core/src/contract/spot/mod.rs:8`); v14/v16/v17 were deleted (commits `23eb1edc`, `e5bfcd6c`) — pre-existing v14/v16 order UTXOs are now **unparseable and uncancellable** by current binaries: the parser (`kob/core/src/contract/spot/parse.rs:105-168`) dispatches purely by v18 RS-length constants, with no v14/v16 arm. `BUY_ORDER_MAX_N = 32` (`kob/core/src/contract/spot/order.rs:16`, landed by commit `317f163c`) is the shipping sweep ceiling, live-proven at N=32 (TXID `536047f3...`, see `kob/BATCH_LIMITS.md`). |
| TIME contracts (`decay_sell` / `decay_buy` / `twap_sell` / `ratchet_oco`) | Additive sibling contracts alongside v18 (no generation bump, own RS-length parse arms) — design + verdicts in `kob/TIME_CONTRACTS_DESIGN.md`, live-proof status in `kob/RELEASE_STATUS.md` |
| Token layer | KCC20 Standard State Header (draft spec conformant, see below) |
| Perpetuals | Oracle-free bilateral P2P |
| Lending | Offer/Borrow/Repay/Default/Liquidate |
| Prediction Market | BallotBox v9 + Redemption v7 |
| Insurance | Pool/Claim/Payout |
| Auction (English/Dutch) | Deploy/Bid/Settle |
| DCA | Scheduled execution (V2 contract) |
| Options (Put) | Deploy/Exercise/Expire |

## Token layer (KCC20)

`token_unit` conforms to the draft KCC20 fungible-token covenant spec
(kas-smiths.org): redeemScript leads with the Standard State Header —
`owner_identifier` (32B) + `identifier_type` (1B, PUBKEY=0x00) script-encoded,
`amount` mapped to the UTXO's native sompi value. RS is 38 bytes (was 35
pre-KCC20; old-layout UTXOs live at different P2SH addresses and must be
re-minted). Single-entrypoint covenant: no selector byte in the sigscript.
Descriptor, state layout, and a reserved `kcc20_nonce_v1` extension slot are in
`kob/core/src/contract/token.rs`; decisions in `kob/KCC20_SYNC_STATUS.md`.

## Requirements

- Rust 1.91+ (workspace `rust-version`)
- Kaspa Toccata hard fork (covenants) — active on mainnet since 2026-06-30

## Build & Test

```sh
cargo test -p kob-core -p kob-cli -p kob-engine -p kob-domain
```

Prefer per-crate `cargo check -p <crate>` during development — the kob crates
only pull the light kaspa leaf crates, never kaspad/consensus/rocksdb.

On Android/Termux (PRoot guest): set `CARGO_TARGET_DIR` to an exec-capable
path (e.g. under `$HOME`; `/storage/emulated` is mounted noexec and build
scripts will fail with os error 13). The workspace `.cargo/config.toml` pins
the `aarch64-linux-android` linker to Termux clang — required because a glibc
guest's `cc`/`ld` cannot link bionic-ABI libraries.

## License

Same as rusty-kaspa (ISC).
