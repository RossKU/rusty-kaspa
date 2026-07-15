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

### PHASE 2 — NOT STARTED
### PHASE 3 — NOT STARTED
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
