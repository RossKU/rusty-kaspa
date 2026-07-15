# X402 Status — crash-recovery record

Read this first after any interruption. Update after every phase / every
build handoff.

## Where things live

- Plan: `kob/x402/PLAN.md`
- New crate (Phase 1): `kob/settle` (`kob-settle`)
- Facilitator crate (Phase 3+): `kob/x402` (`kob-x402`) — not created yet.
- Build dir: `CARGO_TARGET_DIR=/root/kob-rust-target4` (never the in-repo
  `target/`, it's noexec).

## Phase log

### PHASE 0 — DONE
`kob/x402/PLAN.md` written: 3-layer architecture (kob-settle / payment-watch
seam / kob-x402 facilitator + TS shim), scheme (A) native-KAS exact and
scheme (B) KCC20 exact wire formats, x402 conformance details (402 response,
X-PAYMENT, PaymentRequirements, fingerprint binding, replay store,
`kaspa:mainnet`/`kaspa:testnet-10` identifiers), phase milestones, E2E plan
incl. failure cases.

### PHASE 1 — IN PROGRESS
Creating `kob-settle` crate; moving the clean settlement-core files out of
`kob-core`/`kob-engine`, re-exporting from both so the rest of the workspace
doesn't need edits.

**Deviation from the extraction analysis** (see PLAN.md section 1): the
analysis's clean-file list omitted `kob/core/src/types.rs`, but `tx.rs`,
`wallet.rs`, and `compat.rs` (all on the clean list) hard-depend on
`crate::types::{Network, Outpoint, UtxoEntry}`. Verified `types.rs` itself
has zero `kob_domain` refs and zero refs outside itself (grep-verified), so
it moves into `kob-settle` too, re-exported from `kob_core::types`
unchanged. Two crate-root consts used by `tx.rs` (`MIN_UTXO_VALUE`,
`SUBNETWORK_ID`) become canonical in `kob-settle`, re-exported from
`kob-core`.

Files moved into `kob/settle/src/` (verbatim or near-verbatim, internal
`crate::` paths unchanged since everything they reference moved together):
- `error.rs`, `primitives.rs`, `types.rs`, `mass.rs`, `tx.rs`, `wallet.rs`,
  `compat.rs`, `rpc_types.rs` (from `kob/core/src/`)
- `crypto/{mod,bech32,p2sh,sighash,signing}.rs` (from `kob/core/src/crypto/`)
- `rpc/{mod,rest_client}.rs` → `kob_settle::rpc` (from `kob/engine/src/rpc/`;
  this is the `RpcClient` — connect/submit_transaction/get_utxos*/
  subscribe_utxos_changed/confirm_tx_output+ConfirmConfig+ConfirmResult/
  get_daa_score/get_block/get_sink_hash — plus `RestClient` REST fallback)
- `utils.rs` → `kob_settle::utils` (from `kob/engine/src/utils.rs`)
- `config.rs` → `kob_settle::config::NodeConfig` only (NOT the full
  `AppConfig` — that stays in `kob-engine::config` because it references
  engine-internal `DEFAULT_FEE_BPS`; moving it would create a
  kob-settle -> kob-engine back-reference, which is exactly the circular
  coupling the extraction is supposed to avoid)
- `chain/cache.rs` → `kob_settle::chain::{CovenantCache, SpentTracker,
  SpentEntry, MempoolProbe, RpcMempoolProbe, fetch_wallet_utxos,
  check_mass_presubmit}` (extracted from `kob/engine/src/chain/executor.rs`
  lines ~27-564, 799-821, 845-871 — the generic on-chain-existence cache and
  local-spend tracker, zero order-book domain logic mixed in)
- `chain/deploy.rs` → `kob_settle::chain::deploy::{build_submit_payload*,
  build_rpc_input*, build_rpc_output*}` (extracted from
  `kob/engine/src/chain/deploy.rs` lines 37-166)

Re-export shims left behind (so no downstream crate needed edits beyond the
9-line module-declaration swap in `kob-core`/`kob-engine`'s own `lib.rs`):
- `kob-core/src/lib.rs`: `pub mod X;` → `pub use kob_settle::X;` for each of
  {crypto, error, primitives, types, mass, tx, wallet, compat, rpc_types}.
  All subsequent `pub use X::{...}` flat re-export lines in `kob-core`
  untouched — they resolve through the aliased module name.
- `kob-engine/src/lib.rs`: `pub mod rpc;` / `pub mod utils;` →
  `pub use kob_settle::{rpc, utils};`.
- `kob-engine/src/config.rs`: local `NodeConfig` struct replaced with
  `pub use kob_settle::config::NodeConfig;`.
- `kob-engine/src/chain/executor.rs` / `deploy.rs`: extracted
  structs/fns/consts replaced with `pub use kob_settle::chain::{...}` /
  `pub use kob_settle::chain::deploy::{...}`; the giant inline `#[cfg(test)]
  mod tests` block at the bottom of `executor.rs` (~1600 lines, covers
  `SpentTracker`/`CovenantCache`/`MempoolProbe` among other things) was left
  completely untouched — it resolves the re-exported names via `super::*`
  exactly as it resolved the old local definitions, so it needed zero edits.

Build: `cargo check` kicked off in background after this batch of edits —
see "Build handoff" below for the pid and what to check when it exits.

**When the build comes back, check first**: `kob-settle` itself (new code,
highest risk of typos — the hand-written `chain/cache.rs`, `chain/deploy.rs`,
`config.rs`, `lib.rs`), then `kob-core`/`kob-engine` re-export shims (missing
`pub use`, name collisions), then downstream (`kob-domain`/`kob-cli`/`kob-lab`
should be untouched and should just work if the re-exports are right).
Known loose end not yet verified by a build: whether `kob-core`'s
now-possibly-unused direct deps (k256, zeroize, chacha20poly1305, argon2,
rand, base64, sha2, hmac, pbkdf2, blake2b_simd — still declared in
`kob/core/Cargo.toml`, left untouched deliberately) still get used by
`contract/*.rs`/`listing.rs`; if not, they'll just be unused-dep warnings,
not errors — no action needed unless doing a dependency-cleanup pass later.

### PHASE 2 — IN PROGRESS (build handed off)

Generic payment-watch seam + durable replay log, both inside `kob-settle`
(no covenant-parsing dependency), new module `kob/settle/src/observe/`:

- `observe/mod.rs` — `PaymentObserver`: watch address(es) (decoded to their
  script-public-key via `crate::bech32::address_to_spk`), then match paying
  outputs against the watched set purely on SPK bytes (native P2PK/P2SH are
  both spk-version 0). Emits a generic `ScanEvent { txid, output_index,
  address, value, covenant_id (opaque hex, NOT parsed), spk_version,
  spk_script }`. Three feed paths: `scan_utxos(&[RpcUtxo])` (polling
  `get_utxos`), `scan_tx_outputs(txid, &[ObservedOutput])`
  (block-notification / self-broadcast), and `observe_tx_json(&Value)`
  (parses raw RPC tx JSON — both TN12 flat-hex SPK and `{version,script}`
  object forms, `value`/`amount` keys, optional covenant binding).
  `ObservedOutput::from_rpc_json` mirrors the engine scanner's output
  parsing so real node responses work unchanged. Finality confirmation is a
  separate async step behind a `FinalityChecker` trait (impl'd for
  `RpcClient` -> `confirm_tx_output`; tests mock it) — same seam pattern as
  `MempoolProbe` in `chain::cache`.
- `observe/replay.rs` — `ReplayStore`: durable append-only JSON-lines file
  (NO sqlite/rocksdb — keeps `kob-settle` leaf-light; `PaymentRecord` per
  line, last-write-wins per txid on reload, each write flushed + `sync_all`).
  Keyed by txid AND by consumed outpoint. `check_replay(txid, outpoints) ->
  ReplayCheck::{Fresh, DuplicateTxid(status), OutpointReused{..}}` is the
  guard both `/verify` and `/settle` will use in Phase 3: same-txid retry =
  idempotent `DuplicateTxid`; a *different* artifact re-spending a consumed
  outpoint = rejected `OutpointReused`. `mark_confirmed`/`mark_failed` do
  in-place status updates (append a new line). Tolerates a corrupt/truncated
  trailing line on open (crash mid-write).

Design decisions:
- Observer matching is pure (no RPC) so it unit-tests without a node; the
  only async surface (finality) is behind a mockable trait. Tests build a
  *real* testnet P2PK address<->SPK pair (`pubkey_to_address` +
  `address_to_spk`) and feed it through as a node would — the
  "construct-real-bytecode, run-off-chain" harness style from
  `toccata_fill_repro.rs`, applied to the address/SPK layer.
- `covenant_id` is carried through opaquely (raw hex) rather than dropped, so
  the Phase 4 KCC20 scheme can consume it, but the observer neither parses
  nor links against any covenant logic — satisfies "does NOT depend on
  covenant parsing".
- Replay store deliberately a flat file, not SQLite: the gap the extraction
  analysis named was "durable state (submitted-tx log) is absent"; a
  synced append-only log is the minimal durable answer and adds zero deps.

Wired into `kob/settle/src/lib.rs` (`pub mod observe;` + flat re-exports of
`PaymentObserver`/`ScanEvent`/`ObservedOutput`/`FinalityChecker`/`ReplayStore`
/`PaymentRecord`/`PaymentStatus`/`ReplayCheck`).

Build: `cargo test -p kob-settle --lib` (PID 13685) came back **GREEN** —
`test result: ok. 211 passed; 0 failed` (198 Phase-1 + 13 new: 7
`observe::tests` + 6 `observe::replay::tests`, all confirmed executed).

**PHASE 2 STATUS: DONE.** Committed. Next: Phase 3 (kob-x402 facilitator
crate). The Phase-3 verify/settle flow will use `PaymentObserver`
(observe the broadcast tx's paying output) + `FinalityChecker` on
`RpcClient` (confirm) + `ReplayStore::check_replay` (idempotent settle +
outpoint-reuse rejection).
### PHASE 3 — IN PROGRESS (build handed off)

New crate `kob-x402` (`kob/x402/`, workspace member added), HTTP facilitator
+ scheme (A) native-KAS "exact" end to end:

- `src/wire.rs` — x402 wire types kept aligned with upstream
  (coinbase/x402): `PaymentRequirements` (scheme/network/maxAmountRequired
  string-sompi/resource/payTo/asset/extra), `PaymentPayload` +
  `NativeExactPayload` (`transaction` signed RPC tx, `from`, `payTo`,
  `amount`), `X-PAYMENT` base64(JSON) encode/decode, 402
  `PaymentRequiredResponse`, `FacilitatorRequest` (paymentPayload +
  paymentRequirements), `VerifyResponse` (isValid/invalidReason/payer),
  `SettleResponse` (success/errorReason/transaction/network/payer),
  `/supported` types. Networks `kaspa:mainnet` / `kaspa:testnet-10`, asset
  `kas`.
- `src/fingerprint.rs` — request-fingerprint binding. `compute_fingerprint`
  = sha256(method\0path\0payTo\0maxAmountRequired\0nonce) hex;
  `embed_fingerprint` -> `X402:<hex>` tx-payload bytes; `extract_fingerprint`
  reads it back (hex-validated so a covenant payload can't smuggle bytes).
- `src/scheme_native.rs` — PURE native-KAS verification
  (`verify_native_exact`): normalizes envelope/bare tx, parses outputs
  generically, matches payTo via `kob_settle`'s `PaymentObserver`
  (SPK-based, covenant-blind), rejects covenant outputs / wrong recipient /
  underpayment / missing-or-mismatched fingerprint / no-inputs, computes a
  deterministic `artifact_id = blake2b256(compact_json(tx))` as the
  pre-broadcast replay key. 9 unit tests.
- `src/facilitator.rs` — `Facilitator<B: ChainBackend>` (chain access behind
  a mockable trait; impl'd for `RpcClient` via get_utxos/submit_transaction/
  confirm_tx_output). `verify()` = envelope/scheme/network + pure verify +
  ON-CHAIN input-existence check (every spent input must be an unspent UTXO
  of the declared `from` — proves real+unspent+owned) + replay check.
  `settle()` = re-verify, record Submitted BEFORE broadcast, broadcast,
  persist chain txid, confirm finality, mark Confirmed, authorize.
  Idempotent (same artifact retried returns the recorded on-chain txid, no
  double broadcast; a broadcast-accepted-but-unconfirmed payment recovers on
  retry from the durable log). Different artifact reusing a consumed outpoint
  is rejected at verify AND settle. 7 async unit tests with a `MockChain`.
- `src/server.rs` — axum router: POST /verify, POST /settle, GET /supported,
  GET /health, permissive CORS. Generic over the backend.
- `src/main.rs` — binary: `--node --bind --network --replay-log`, connects
  RpcClient, opens ReplayStore, serves.
- Added `chain_txid: Option<String>` (serde default) to `PaymentRecord` in
  `kob-settle` (replay.rs) so an idempotent `/settle` retry returns the same
  on-chain txid; Phase 2 tests unaffected (default field).

Design notes:
- artifact_id (hash of signed tx), NOT the canonical Kaspa txid, is the
  replay key — the canonical txid depends on covenant/compute-budget
  serialization subtleties and isn't known pre-broadcast; the artifact hash
  is deterministic, node-independent, and gives the exact same replay
  guarantees (same artifact = idempotent; shared outpoint = reuse). The real
  on-chain txid is learned at submit and returned in SettleResponse.
- payer is verified by requiring the spent inputs to be in `from`'s unspent
  set (no per-outpoint RPC lookup exists in the wRPC surface we have; this
  also validates the `from` claim).
- KCC20 asset (Phase 4) currently returns invalid "asset not supported yet".

Build: `cargo test -p kob-x402 --lib` (PID 19263) came back **GREEN** —
`test result: ok. 22 passed; 0 failed` (3 wire + 3 fingerprint + 9
scheme_native + 7 facilitator, all confirmed). Compiled clean on axum 0.7,
no warnings surfaced.

**PHASE 3 STATUS: DONE.** Committed. Next: Phase 4 (KCC20 covenant
token_unit transfer as an x402 payment).
### PHASE 4 — NOT STARTED
### PHASE 5 — NOT STARTED

## Build handoff log

(Most recent first. Always check exit status + `cargo check` output before
trusting a phase is actually green.)

### Phase 1 handoff (2026-07-15)

```
CARGO_TARGET_DIR=/root/kob-rust-target4 cargo check \
  -p kob-settle -p kob-core -p kob-domain -p kob-engine -p kob-cli -p kob-lab
```
- Attempt 1: PID 3715, log `.../scratchpad/phase1_cargo_check.log`. Failed:
  `CovenantCache.valid`/`.invalid` are private fields, but
  `kob/engine/src/chain/executor.rs` (now in a different crate from
  `CovenantCache`) read them directly at two call sites (pre-seed log count,
  verification-cycle log line). **Fixed**: added
  `CovenantCache::valid_len()`/`invalid_len()` accessors in
  `kob/settle/src/chain/cache.rs`, updated the two call sites in
  `executor.rs` to use them.
- Attempt 2: PID 5577, log `.../scratchpad/phase1_cargo_check_r2.log`.
  **GREEN** — `Finished \`dev\` profile [unoptimized + debuginfo] target(s)
  in 1m 00s`, all 6 packages (`kob-settle`, `kob-core`, `kob-domain`,
  `kob-lab`, `kob-engine`, `kob-cli`) compiled clean. Two pre-existing
  warnings, neither introduced by this phase and neither worth chasing now:
  `unused import std::time::Instant` in `kob/engine/src/chain/executor.rs`
  (used only by that file's `#[cfg(test)] mod tests` via `use super::*`, so
  it's "unused" under plain `cargo check` but not under `cargo test`), and
  an `unused_assignments` warning in `kob/cli/src/deploy.rs:1376`
  (`token_input_value`) that predates this phase entirely — not a file this
  phase touched.

**PHASE 1 STATUS: DONE.** `cargo check -p kob-settle -p kob-core -p
kob-domain -p kob-engine -p kob-cli -p kob-lab` is green under
`CARGO_TARGET_DIR=/root/kob-rust-target4`. Not yet run: `cargo test` (unit
tests for the new `chain::cache`/`chain::deploy` modules added during this
phase haven't been executed yet, only type-checked) — worth doing early in
Phase 2 before building on top, since Phase 2's `PaymentObserver` will sit
right next to `chain::cache`.

### Files touched this phase (for a quick `git diff` orientation)

- new: `kob/settle/**` (whole new crate)
- edited: root `Cargo.toml` (workspace members), `kob/core/Cargo.toml`,
  `kob/core/src/lib.rs`, `kob/engine/Cargo.toml`, `kob/engine/src/lib.rs`,
  `kob/engine/src/config.rs`, `kob/engine/src/chain/executor.rs`,
  `kob/engine/src/chain/deploy.rs`
- deleted: `kob/core/src/{crypto/,primitives.rs,mass.rs,tx.rs,wallet.rs,
  compat.rs,rpc_types.rs,error.rs,types.rs,bip39_english.txt}`,
  `kob/engine/src/{rpc/,utils.rs}`
- backups of the two surgically-edited big files (pre-sed) left at
  `/tmp/executor.rs.bak`, `/tmp/deploy.rs.bak` (scratch, not committed) in
  case a diff-against-original is ever needed to double check the surgery.

## E2E TXID log (Phase 5)

(none yet)
