# Kaspa x402 Payment Facilitator — PLAN

Status: PHASE 0 (this doc). See `X402_STATUS.md` for crash-recovery / progress
tracking as phases land.

## 0. Why

`elldeeone/kaspa-x402` implements the x402 wire format (HTTP 402 flow,
`PaymentRequirements`, `X-PAYMENT` header) but its `ChainProvider` is an
abstract stub — no real broadcast, no real UTXO lookup, no finality check. It
cannot settle a real payment. KOB already has a production settlement core
(RPC client, mass/fee calc, wallet, covenant scripts, finality polling) built
and proven on testnet-10. This project extracts that core into a reusable
crate and builds a real facilitator on top of it, supporting both a plain
native-KAS transfer ("exact" scheme, mainnet-ready, no covenant) and a KCC20
covenant token transfer ("exact" scheme, token payments).

Goal: a facilitator that is wire-conformant with the upstream x402 protocol
(https://github.com/coinbase/x402 conventions — `PaymentRequirements`,
`X-PAYMENT`, `/verify`, `/settle`, `x402Version`) so any generic x402 client
library can pay a Kaspa-priced resource, not just a KOB-specific client.

## 1. Architecture — 3 layers

```
kob/settle/   (crate: kob-settle)   — settlement core, zero kob_domain refs.
              Crypto primitives, mass/fee math, tx building, wallet, RPC
              client (submit/UTXO/finality), generic covenant-existence +
              spent-outpoint tracking, RPC payload builders. Reused verbatim
              by the DEX engine (via re-export from kob-core/kob-engine) AND
              by the facilitator. This is the only crate that talks to a
              Kaspa node.

kob/settle/{payment_observer, replay_store}  (Phase 2, still inside kob-settle)
              — generic "watch address(es) -> payment observed -> confirm
              finality" seam, decoupled from KOB covenant-order parsing.
              Durable submitted-payment / replay log (sqlite or append-only
              file — see Phase 2 decision below).

kob/x402/     (crate: kob-x402)      — HTTP facilitator + wire types.
              Owns nothing chain-specific beyond calling into kob-settle.
              Exposes /verify, /settle, /supported per the x402 facilitator
              contract. Scheme-specific verifiers:
                - scheme (A) native-KAS exact  — no covenant.
                - scheme (B) KCC20 exact       — covenant token_unit.
              A thin TS client shim (kob/x402/client-ts/) mirrors the
              upstream `x402-fetch` wrapper so any web client can pay with a
              Kaspa wallet the same way it pays with an EVM wallet today.
```

Dependency direction is strictly one-directional: `kob-x402 -> kob-settle`,
and (unchanged) `kob-engine -> kob-settle` (re-exported through `kob-core`
for path compatibility). `kob-settle` never depends on `kob-domain`,
`kob-engine`, or `kob-x402`. This mirrors the existing DEX dependency
direction (DEX -> settlement) called out in the extraction analysis.

### Deviation from the extraction analysis (recorded, not re-litigated)

`kob/core/src/types.rs` was not in the original "clean" file list, but
`tx.rs`, `wallet.rs`, and `compat.rs` all hard-depend on
`crate::types::{Network, Outpoint, UtxoEntry}`. `types.rs` itself has zero
`kob_domain` references and zero references to anything outside itself, so
it moves into `kob-settle` too (as `kob_settle::types`), re-exported from
`kob_core::types` unchanged. Two crate-root constants used by the moved
`tx.rs` (`MIN_UTXO_VALUE`, `SUBNETWORK_ID`) become canonical in
`kob-settle` and are re-exported from `kob-core` for the same reason.
Recorded in `X402_STATUS.md` Phase 1 notes.

## 2. The two payment schemes

Both schemes use x402's `scheme: "exact"` (the payer pays exactly the
required amount — no change-is-a-tip semantics, no streaming/subscription
scheme). Network identifiers follow x402's CAIP-2-flavored convention:

- `kaspa:mainnet`
- `kaspa:testnet-10`

### (A) Native-KAS exact — no covenant, mainnet-ready

The payment artifact is a **standard, fully-signed, self-contained Kaspa
transaction** the client builds and signs locally with its own wallet (via
`kob-settle`'s `tx`/`wallet`/`crypto` modules or an equivalent client-side
lib): one or more of the client's own UTXOs as input(s), one output paying
`payTo` exactly `maxAmountRequired` sompi, one change output back to the
client, miner fee computed from `kob_settle::mass`. No covenant, no
facilitator co-signature — this is a plain P2PK spend, so it is valid on
mainnet today (no Toccata-only opcodes involved).

`X-PAYMENT` payload (`payload` field, scheme "exact", network `kaspa:*`):

```json
{
  "x402Version": 1,
  "scheme": "exact",
  "network": "kaspa:testnet-10",
  "payload": {
    "transaction": { /* kob_settle rpc_types-shaped RPC tx JSON, fully signed */ },
    "payTo": "kaspatest:qz...",
    "amount": "100000000"
  }
}
```

Facilitator `/verify`:
1. Decode + structurally validate the transaction (well-formed inputs/
   outputs, no covenant fields, version/mass sane).
2. Confirm exactly one output pays `payTo` with value >= `maxAmountRequired`
   (>= not == at the UTXO level, since a KAS transfer's "exact" is about the
   *paid* amount, not about zero change).
3. Confirm the request-fingerprint embedded in the tx `payload` bytes
   (`X402:<fingerprint_hex>`, see 2.3) matches the resource being requested.
4. Confirm the consumed input outpoint(s) are real, unspent, on-chain
   (`RpcClient::get_utxos` / spendable check) — this catches a stale/already-
   spent artifact before broadcast, without spending an RPC submit on it.
5. Confirm the artifact has not already been used (replay store lookup by
   txid AND by consumed outpoints — see 2.3).
6. Return `{ isValid: true, payer: <address derived from input SPK> }` or
   `{ isValid: false, invalidReason: "..." }`.

Facilitator `/settle`:
1. Re-run `/verify` (never trust a verify-then-settle gap).
2. Broadcast via `RpcClient::submit_transaction`.
3. Observe finality: poll the `payTo` address via the generic
   `PaymentObserver` (Phase 2) until the paying output is visible, then
   `RpcClient::confirm_tx_output` for the deeper accepted-into-virtual-chain
   check.
4. Record the txid + consumed outpoints in the durable replay store
   (idempotency: a `/settle` retry on the same artifact after a crash must
   not double-broadcast — check "already settled" before submit).
5. Return `{ success: true, transaction: txid, network, payer }`.

### (B) KCC20 exact — covenant token_unit transfer

Reuses the existing KCC20 Standard State Header covenant
(`kob/core/src/contract/token.rs`: `build_token_unit_redeem_script`,
`build_token_unit_sigscript`, `parse_token_unit_state`,
`Kcc20StateHeader`). The payment artifact spends the client's `token_unit`
covenant UTXO and creates a new `token_unit` output whose state header's
`owner_identifier` is `payTo`'s pubkey/identifier and whose native-sompi
value equals the token `amount` (KCC20 maps amount to UTXO value). Any KAS
change/fee UTXO is handled the same way as scheme (A).

`X-PAYMENT` payload adds the token identity:

```json
{
  "x402Version": 1,
  "scheme": "exact",
  "network": "kaspa:testnet-10",
  "payload": {
    "transaction": { /* signed RPC tx JSON incl. covenant sigscript+output */ },
    "payTo": "kaspatest:qz...",
    "asset": "<token_covenant_id hex>",
    "amount": "50000000"
  }
}
```

`PaymentRequirements.asset` carries the token covenant ID (analogous to an
ERC-20 contract address in the upstream EVM schemes).

Facilitator verification adds, on top of scheme (A)'s checks:
1. The spent input is a genuine `token_unit` covenant UTXO for the declared
   `asset` covenant ID (on-chain existence check — reuses the generalized
   `CovenantCache` extracted in Phase 1, generic existence cache, not
   KOB-order-specific).
2. The new `token_unit` output's redeem script / state header parses
   (`parse_token_unit_state`) and its `owner_identifier` matches `payTo`,
   `identifier_type == PUBKEY`.
3. The output's native-sompi value (== token amount per KCC20 spec) >=
   `maxAmountRequired`.
4. Covenant binding (`authorizingInput` / `covenantId`) is well-formed and
   matches the input being spent (no "pay one token, bind a different
   covenant" substitution).

Settle path is identical to scheme (A) (broadcast, observe, confirm,
replay-record).

### 2.3 Wire conformance details

- **HTTP 402 response** (resource server surface — the facilitator itself
  doesn't emit this; it's what a resource-server integration built on
  `kob-x402`'s verify/settle would emit, and what the E2E harness plays both
  roles of in Phase 5): `402 Payment Required` with JSON body
  `{ x402Version: 1, accepts: [PaymentRequirements, ...], error?: string }`.
- **PaymentRequirements** fields: `scheme`, `network`, `maxAmountRequired`
  (sompi, string-encoded u64), `resource` (URL), `description`, `mimeType`,
  `payTo`, `maxTimeoutSeconds`, `asset` (native: `"kas"` / KCC20: covenant-id
  hex), `extra` (scheme-specific: for (A)/(B) carries the resource
  fingerprint the client must embed in the tx payload, see below).
- **X-PAYMENT header**: base64(JSON) of the payload shown in 2.1/2.2,
  matching upstream's header-encoding convention.
- **Request-fingerprint <-> payment binding**: the facilitator issues (in
  `PaymentRequirements.extra.fingerprint`) a value derived from
  `sha256(method | path | payTo | maxAmountRequired | nonce)`. The client
  embeds `X402:<fingerprint_hex>` in the Kaspa transaction's `payload` bytes
  (reusing the existing `KOB:1:`-style payload-tagging convention already in
  `kob-settle::tx`). `/verify` recomputes the expected fingerprint for the
  current request and rejects a mismatch — this is what stops a client from
  replaying one paid artifact against a *different* resource/request.
- **Replay store**: keyed by txid and by each consumed input outpoint.
  `/settle` is idempotent (repeat call with the same artifact after a crash
  returns the previously-recorded result instead of re-broadcasting); a
  *different* artifact that reuses an already-consumed outpoint is rejected
  outright (UTXO double-spend would fail on-chain anyway, but rejecting at
  `/verify` avoids a wasted broadcast + gives a clean 402 retry to the
  client).

## 3. Milestones (maps to the phases in the task)

| Phase | Deliverable |
|---|---|
| 0 | This plan. |
| 1 | `kob-settle` crate exists; `kob-core`/`kob-engine`/`kob-cli`/`kob-domain` still compile via re-export shims; `cargo check` green. |
| 2 | `PaymentObserver` (generic watch-address -> ScanEvent -> confirm-finality) + durable replay/submitted-payment log in `kob-settle`, unit-tested with the `TxScriptEngine` mock pattern. |
| 3 | `kob-x402` HTTP server: `/verify`, `/settle`, `/supported`; scheme (A) end to end against a mock/local RPC; replay + fingerprint binding enforced. |
| 4 | Scheme (B) KCC20 verify/settle wired in; reuses Phase 1's `CovenantCache`. |
| 5 | Testnet-10 E2E for both schemes via `kob/e2e_fixture.json`-style fixture, funded by `tests/miner.mjs`; rejection cases proven (underpayment, replay, wrong recipient); TXIDs recorded in `X402_STATUS.md`. |

## 4. E2E plan (Phase 5 detail)

Fixture pattern follows `kob/scripts/e2e_v16.sh` / `kob/e2e_fixture.json`
(reuse funded testnet-10 keys where possible instead of re-funding via
`miner.mjs` every run — miner throughput is the scarce resource).

Happy paths (both schemes):
1. Resource server (harness role) issues 402 with `PaymentRequirements`.
2. Client builds + signs the payment artifact (scheme A: plain transfer;
   scheme B: token_unit transfer), embeds the fingerprint, sets `X-PAYMENT`.
3. Facilitator `/verify` — expect `isValid: true`.
4. Facilitator `/settle` — expect broadcast, `confirm_tx_output` true,
   `success: true`, txid recorded.
5. Poll node directly (independent of the facilitator) to confirm the txid
   is in a block / accepted into the virtual chain — belt-and-suspenders
   check that `/settle`'s claim is real, not just "RPC accepted it".
6. Record txid in `X402_STATUS.md` under an E2E log section.

Rejection paths (must be refused, both schemes where applicable):
- **Underpayment**: artifact pays less than `maxAmountRequired` -> `/verify`
  returns `isValid: false`, `/settle` never broadcasts.
- **Replay**: re-submit the exact artifact from a prior successful `/settle`
  against a *new* request (new fingerprint) -> rejected by replay store
  (txid/outpoint already consumed), independent of fingerprint mismatch.
- **Wrong recipient**: artifact pays a valid amount to an address that is
  not `payTo` -> rejected.
- (Bonus, if time allows in Phase 5) **stale outpoint**: artifact spends a
  UTXO that's already been spent by an unrelated transaction -> rejected at
  `/verify`'s on-chain existence check, not left to fail at broadcast.

Polling cadence: 0.5-1s between polls (Kaspa runs ~10 BPS on testnet-10),
matching `ConfirmConfig`'s existing default (`initial_delay: 500ms,
poll_interval: 500ms` from the extracted `RpcClient::confirm_tx_output`).

## 5. Non-goals / explicitly out of scope for this project

- No AMM/pooled liquidity, no oracle pricing — x402 prices are set by the
  resource server, not discovered on-chain.
- No mainnet KCC20 tokens are assumed to exist yet at project start; scheme
  (B) E2E runs on testnet-10 using KOB's existing test-token deploy tooling.
- Not implementing every upstream x402 scheme (e.g. no streaming/subscription
  scheme) — "exact" only, matching what elldeeone/kaspa-x402 itself targets.
- Not forking/patching elldeeone/kaspa-x402's TS code; `kob-x402` is a
  from-scratch Rust facilitator plus a minimal TS client shim for
  interoperability, not a drop-in replacement package.
