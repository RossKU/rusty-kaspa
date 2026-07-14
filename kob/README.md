# KOB — Kaspa Order Book

Pure order book DEX on Kaspa L1 covenants. No AMM, no liquidity pools, no oracles.

## Architecture

```
kob/
  core/    — Contract scripts, sighash, mass calculation, signing, wallet
  domain/  — Order books, batch planner, match domain logic (spot/perp/lending/prediction)
  cli/     — Command-line interface for deploy, cancel, match, MM bot
  engine/  — Matching engine, chain scanner/executor, cross-pair routing, API
  lab/     — Script-level experiments and prototypes
```

Built as workspace members of [rusty-kaspa](https://github.com/kaspanet/rusty-kaspa), directly referencing `kaspa-consensus-core`, `kaspa-hashes`, and `kaspa-addresses`. Synced with upstream master post-Toccata (mainnet activation 2026-06-30); crates.io kaspa crates (frozen at 0.15.0, pre-covenants) are NOT usable — the in-tree path deps are required.

## Products

| Product | Status |
|---------|--------|
| Spot (Buy/Sell/Partial/OCO) | v14 contract live (v15 mmfee-bps feature-gated), TN12 verified |
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
