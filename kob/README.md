# KOB — Kaspa Order Book

Pure order book DEX on Kaspa L1 covenants. No AMM, no liquidity pools, no oracles.

## Architecture

```
kob/
  core/    — Contract scripts, sighash, mass calculation, signing, wallet
  cli/     — Command-line interface for deploy, cancel, match, MM bot
  engine/  — Matching engine, batch planner, cross-pair routing, scanner
```

Built as workspace members of [rusty-kaspa](https://github.com/kaspanet/rusty-kaspa), directly referencing `kaspa-consensus-core`, `kaspa-hashes`, and `kaspa-addresses`.

## Products

| Product | Status |
|---------|--------|
| Spot (Buy/Sell/Partial/OCO) | v13 contract, TN12 verified |
| Perpetuals | Oracle-free bilateral P2P |
| Lending | Offer/Borrow/Repay/Default/Liquidate |
| Prediction Market | BallotBox v9 + Redemption v7 |
| Insurance | Pool/Claim/Payout |
| Auction (English/Dutch) | Deploy/Bid/Settle |
| DCA | Scheduled execution |
| Options (Put) | Deploy/Exercise/Expire |

## Requirements

- Rust 1.80+
- Kaspa Covenants++ hard fork (pending, ~June 2026)

## Build & Test

```sh
cargo test -p kob-core -p kob-cli -p kob-engine
```

## License

Same as rusty-kaspa (ISC).
