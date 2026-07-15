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
### PHASE 4 — IN PROGRESS (build handed off)

Scheme (B): KCC20 covenant `token_unit` transfer as an x402 payment. Reuses
the KCC20 Standard State Header builders in `kob-core` (added `kob-core` as a
dep of `kob-x402`; kob-core -> kob-settle so no cycle).

- `src/scheme_kcc20.rs` — pure `verify_kcc20_exact`. A KCC20 payment output
  is the one whose SPK == `P2SH(build_token_unit_redeem_script(recipient_pk))`
  (recipient pubkey extracted from the `payTo` P2PK address) AND carrying a
  covenant binding to the token `asset` (covenant id); its native sompi value
  is the token amount (per KCC20: amount == UTXO value). Checks:
  asset is 32-byte hex covenant id; recipient/payer are P2PK identities;
  finds the recipient token_unit output; rejects wrong-recipient / missing-
  or-wrong covenant binding / underpayment / bad-asset / fingerprint
  missing-or-mismatch. Computes the payer's own token_unit P2SH address (for
  the on-chain input check) and the deterministic artifact_id. 8 unit tests.
- `src/facilitator.rs` — `validate()` now routes by `asset`: empty/`kas` ->
  native (scheme A), else -> KCC20 (scheme B). Generalized the on-chain
  input-existence check to union UTXOs across multiple owner addresses (for
  KCC20: payer token_unit P2SH address for the token input + payer P2PK
  address for any KAS fee input) and to additionally require that at least
  one spent input is an on-chain UTXO carrying the required token covenant id
  (generic existence — the CovenantCache idea from Phase 1, applied
  directly). Flattened the internal `Validated` struct so both schemes feed
  the same settle path (broadcast/confirm/replay/idempotency unchanged and
  scheme-agnostic). 3 new KCC20 facilitator tests (happy path, token-input-
  covenant-absent rejection, underpayment) using a covenant-aware MockChain.
- `src/lib.rs` — registered `scheme_kcc20`.

Design notes:
- Recipient/payer are identified by their P2PK identity address in `payTo` /
  `from`; the facilitator derives the token_unit P2SH addresses itself. This
  keeps the x402 `payTo` a normal address (interoperable) rather than
  exposing raw covenant P2SH.
- `asset` in `PaymentRequirements` carries the token covenant id (the KCC20
  analog of an ERC-20 contract address), matching the PLAN.
- Full covenant *script* validation still happens on-chain at broadcast (the
  node enforces the covenant); the facilitator verifies the covenant
  *binding* (covenantId == asset) + on-chain existence of the spent token
  UTXO, which is what's needed to refuse a bogus payment before broadcast.

Build: `cargo test -p kob-x402 --lib` (PID 24313) came back **GREEN** —
`test result: ok. 32 passed; 0 failed` (22 Phase-3 + 7 scheme_kcc20 + 3
KCC20 facilitator). Clean compile with kob-core added as a dep.

**PHASE 4 STATUS: DONE.** Committed. Next: Phase 5 (testnet-10 E2E for both
schemes via a fixture, funded by miner.mjs; record TXIDs; rejection cases).
### PHASE 5 — IN PROGRESS (release build handed off)

Live testnet-10 E2E harness for the native-KAS scheme. Environment verified
ready: node `ws://65.108.107.30:18210` reachable; wallet
`/tmp/kob_e2e/wallet.json` FUNDED (~1.97 KAS, 3 P2PK UTXOs — no mining needed
for native); Node.js v20 present; `kaspatest:qz6qc3j...rwa6v8lf` is the payer.

- `src/bin/x402_client.rs` (new binary `x402-client`): builds + signs a REAL
  native-KAS transfer as an x402 artifact WITHOUT broadcasting, emits a
  ready-to-POST `FacilitatorRequest`. Reuses the proven wallet_send tx
  sequence (select UTXO, 2-phase converge_fee, compute_sighash, schnorr_sign,
  build_p2pk_sigscript, to_rpc_payload) from kob-settle; sets the tx payload
  to the `X402:<fingerprint>` tag. Scenario flags: `--require` (underpayment),
  `--tx-pay-to` (wrong recipient), `--replay-out` (a 2nd artifact over the
  SAME input for the replay case). Also a `derive-address <pubkey_hex>`
  helper so the harness gets a valid, distinct 'intended' recipient.
  Collapses client + resource-server roles (computes the fingerprint itself,
  binds it into both the tx payload and requirements.extra.fingerprint).
- `scripts/e2e_x402.sh`: starts the facilitator (release), waits for /health,
  then drives 4 cases against it: (1) HAPPY self-pay 0.2 KAS -> verify +
  settle + on-chain-confirm, records TXID; (2) UNDERPAYMENT (tx 20M, require
  40M) -> refused, no broadcast; (3) WRONG RECIPIENT (tx pays wallet,
  requirements demand a different valid addr) -> refused; (4) REPLAY (2nd
  artifact over the consumed outpoint) -> refused. Independently re-confirms
  the happy txid via kob-cli. No jq (grep/sed field parsing). Records TXIDs
  to `/tmp/kob_e2e/x402/E2E_X402_TXIDS.txt`.
- `src/main.rs`: bumped facilitator ConfirmConfig to ~10s window (15 polls x
  700ms) for real-network latency; idempotent retry re-confirms from the
  durable log so it's a soft cap.

Self-pay (payTo == payer wallet) for the happy path so the 0.2 KAS returns to
the wallet — the full verify->broadcast->confirm->authorize loop still runs
on a real on-chain tx.

KCC20 (scheme B) live E2E: deferred within this phase — needs a token_unit
transfer artifact builder. Scheme B verification is already proven at unit
level (7 scheme_kcc20 + 3 facilitator tests incl. covenant-aware mock end to
end).

IMPORTANT finding for a live scheme-B run (recorded during Phase 5 study of
`kob/cli/src/token.rs::token_transfer`): kob-cli's `token transfer` builds
the recipient output as a **P2PK SPK + covenant binding** (line ~1033, an
explicitly-documented "simpler approach"), NOT the spec-conformant
**token_unit P2SH** output that `scheme_kcc20` expects (SPK ==
P2SH(build_token_unit_redeem_script(recipient_pk)), the form `token mint`
creates and `parse_token_unit_state` reads). So a live KCC20 E2E driven by
`kob-cli token transfer` would NOT match the facilitator's verifier as
written. Two clean options for the follow-up live run:
  (a) write a spec-form KCC20 client that outputs a token_unit-P2SH covenant
      output (correct KCC20; matches scheme_kcc20 as-is), or
  (b) additionally accept the P2PK+covenant form in scheme_kcc20 (matches
      kob-cli's current on-chain tokens, but is the non-spec shortcut).
Recommend (a) to stay spec-conformant. This is the only remaining gap to a
live scheme-B run; the verifier logic itself is done and unit-proven. The
native (scheme A) live E2E — the primary proof that this facilitator does
real broadcast/UTXO/finality, unlike the elldeeone mock — is what this phase
runs live.

Release build: green (both bins). First live run surfaced one client bug:
the fee was set to raw compute-mass, but post-Toccata the node requires
`min_relay_fee = mass * 100 sompi/gram` — node rejected with "2105 fees ...
under the required 210500". Fixed the client to compute `fee =
min_relay_fee(calc_mass_with_sigscripts(...))` (measure mass with real
sigscript sizes, then *100), rebuilt.

**PHASE 5 STATUS: DONE (native scheme, live on testnet-10).**
`bash kob/x402/scripts/e2e_x402.sh` -> **7/7 checks passed**. The facilitator
did REAL settlement end to end: verify -> broadcast -> finality-confirm ->
authorize, and refused all three rejection cases. This is the concrete proof
that this facilitator is NOT the elldeeone mock. See the E2E TXID log below.

Durable replay log (`/tmp/kob_e2e/x402/replay.jsonl`) captured the exact
designed lifecycle across three appended lines for the happy payment:
`Submitted (chain_txid=null)` -> `Submitted (chain_txid=<real>)` ->
`Confirmed`.

KCC20 (scheme B) live E2E: **DONE (2026-07-15, 7/7 on testnet-10)** — see the
"KCC20 token scheme" entry in the E2E TXID log below. The spec-form gap was
closed by adding an `x402-client kcc20` mode (builds a token_unit-P2SH
transfer) plus a facilitator finality-address fix (confirm the recipient
token P2SH, not the P2PK identity). Real on-chain token payment TXID
`0577d3616b4c4a38d625f34fc4e916b0de360982495138e3cf2f1d094755d97c`.

Known conservative behavior (documented, not a bug): a *failed* broadcast
leaves the outpoint reserved in the replay store (record marked Failed but
the outpoint stays indexed), so a later *different* artifact over that same
outpoint is refused even though the funds may still be spendable. This is
deliberate replay-safety (reject > risk double-spend). The proper future
refinement is to key the reservation on the canonical Kaspa txid computed
pre-broadcast (deferred — depends on covenant/compute-budget tx-hash
serialization).

## PULL mode (receive-and-detect) — Phase 5c

Distinct from the push mode (client hands the facilitator a signed artifact,
facilitator broadcasts). In PULL mode the client broadcasts a plain native-KAS
payment to the merchant's `payTo` ITSELF; the facilitator does NOT broadcast —
it DISCOVERS the arriving payment by scanning, binds the fingerprint from the
tx payload memo, confirms finality, and authorizes. Exercises the Phase-2
`PaymentObserver` block/UTXO-scan discovery path live.

How detection is wired:
- New facilitator endpoint `POST /await` (body = `{x402Version,
  paymentRequirements}`, no paymentPayload). Handler `Facilitator::await_payment`.
- New `ChainBackend::discover_incoming(address)` — impl'd for `RpcClient` via
  `getMempoolEntriesByAddresses` (`entries[].receiving[].transaction`), which
  carries each incoming tx's full **payload** (the `X402:<fp>` memo) even
  before confirmation. Default impl returns none (so the trait stays
  cheap for other backends).
- Discovery loop (poll 700ms until `maxTimeoutSeconds`): (1) cache incoming-tx
  payloads from the mempool (for the fingerprint memo); (2) scan `payTo`'s
  UTXO set via `PaymentObserver::scan_utxos` — a UTXO present in the set is
  confirmed/final. For each discovered event: dedupe against the replay store
  (by the payTo-output outpoint), bind the fingerprint from the cached
  payload, then amount-check. `value >= required` -> record + authorize
  (returns the discovered txid); `value < required` (fingerprint-matched) ->
  reject underpayment; already-credited -> refuse (no double-credit);
  timeout with nothing matching -> not authorized. The facilitator never
  calls `submit` in pull mode.
- Client: `x402-client --broadcast --fingerprint <hex> ...` builds the signed
  native payment (fingerprint memo in the tx payload) and broadcasts it
  itself, printing the txid. The merchant issues the fingerprint (passed via
  `--fingerprint`); pull mode does not go through the facilitator to send.

Unit tests: 4 new `await_*` facilitator tests (discover+authorize,
underpayment reject, timeout, no-double-credit) with a mock chain that seeds
mempool `receiving` + confirmed UTXOs.

One fix during the live run: the already-credited dedupe must be
fingerprint-scoped — a fresh request for a NEW payment was wrongly told
"already credited" because some OTHER credited UTXO sat at the merchant
address. Now dedupe only counts a credited payment as "this request's" when
its stored fingerprint matches the request's (so CASE 3 correctly reports "no
matching payment" instead).

Live E2E: `kob/x402/scripts/e2e_x402_pull.sh` — 6/6 checks passed
(2026-07-15). See the E2E TXID log below.

## Phase B — x402 v2 wire + KIP-10 interop (elldeeone/kaspa-x402 drop-in)

Goal: make kob-x402 wire-conformant with elldeeone/kaspa-x402 (v2) and add
their KIP-10 additive-covenant "exact" scheme as THE interoperable exact
scheme. Keep native push/pull + KCC20 working (KOB-native path). Downloaded
spec/schemas/vectors to `kob/x402/interop/` (schemas from repo main;
exact-transfer vector from snapshot v0.1.0-alpha.3).

CANONICAL v2 SHAPES (from elldeeone main schemas — authoritative):
- **x402Version = 2** everywhere; validate it (else `invalid_x402_version`).
- **PaymentRequired** (402 body / `PAYMENT-REQUIRED` header):
  `{x402Version:2, resource:{url, description?, mimeType?}, accepts:[PaymentRequirements], error?, extensions?}`.
- **PaymentRequirements**: `{scheme:"exact"|"batch-settlement", network:"kaspa:mainnet"|"kaspa:testnet-10", amount:"<sompi string>", asset:"KAS", payTo, maxTimeoutSeconds:int, extra}`.
  Note: `amount` (NOT maxAmountRequired); `asset` const `"KAS"`; nested
  `resource` at the PaymentRequired top level (not per-requirement).
- **extra for exact** (kaspa-requirements-extra): `{binding:"kaspa-exact-v1", finality:"mempool"|"accepted"|"confirmed", templateId:"kaspa-x402-kip10-additive-v1", transactionEncoding:"kaspa-sdk-safe-json-v2.0.0", borrowOutpoint:{txid(64hex),index}, borrowAmount:"<sompi>", borrowScriptPublicKey:"0000"+hex, borrowRedeemScript:hex, additiveThresholdSompi:"<sompi>", paymentOutputIndex:int, reservationId:64hex, reservationExpiresAt?, assetKind:"native", assetDecimals:8}`.
  `dependentRequired`: presence of templateId requires ALL the borrow fields.
- **PaymentPayload** (`PAYMENT-SIGNATURE` header): `{x402Version:2, accepted:<the chosen PaymentRequirements verbatim>, payload, extensions?}`.
- **payload for exact** (kaspa-payment-payload, main): `{type:"exact-transaction", transaction:"<encoded string>", transactionEncoding:"kaspa-sdk-safe-json-v2.0.0", paymentOutputIndex:int, payerAddress?, requestHash?(64hex)}`. Main schema REQUIRES type+transaction+transactionEncoding+paymentOutputIndex and FORBIDS transactionId for exact-transaction. (The alpha.3 vector used older `type:"exact-transfer"`+transactionId; follow MAIN = "exact-transaction".)
- **SettlementResponse** (`PAYMENT-RESPONSE` header / /settle body): `{success, transaction:"<64hex on success, ''/absent on fail>", network, payer?, amount?, errorReason?, extensions:{kaspa:{paymentOutputIndex?, finality?, requestHash?, templateId?, reservationId?, borrowOutpoint?}}}`. On success: network + amount required, transaction must be 64hex. On failure: errorReason required. `extra` field is FORBIDDEN at top level.
- **/verify** req `{x402Version:2, paymentPayload, paymentRequirements}` -> `{isValid, payer?}` | `{isValid:false, invalidReason:<error code>}`.
- **/settle** req same -> SettlementResponse.
- **/supported** -> `{kinds:[{x402Version:2, scheme:"exact", network, extra:{asset:"KAS", binding:"kaspa-exact-v1", modes:["verify","settle"]}}], extensions:[], signers:{}}`.
- **Headers** (base64 of JSON): `PAYMENT-REQUIRED` (server->client), `PAYMENT-SIGNATURE` (client->server), `PAYMENT-RESPONSE` (server->client). Legacy `X-PAYMENT` NOT supported.
- **Errors** closed enum (public wire): `invalid_x402_version, invalid_scheme, invalid_network, invalid_payment_requirements, invalid_payload, invalid_transaction_state, unsupported_scheme, unexpected_settle_error`. Local diagnostics (not on wire): `invalid_kaspa_x402_amount, invalid_kaspa_x402_binding, invalid_kaspa_x402_payload, invalid_kaspa_payment_identifier, missing_kaspa_payment_identifier, kaspa_payment_identifier_conflict, invalid_kaspa_exact_replay, invalid_kaspa_settlement_response`.

KIP-10 additive "exact" mechanics: merchant reserves `borrowOutpoint` locked
by a KIP-10 additive-covenant redeem script (spendable by anyone who returns
>= borrowAmount + additiveThresholdSompi to the merchant continuation output).
Client builds an exact-transaction that spends exactly borrowOutpoint, pays
exactly `amount` to `payTo` at `paymentOutputIndex`, and satisfies the
additive rule + requestHash binding. Facilitator verifies -> broadcasts ->
confirms -> authorizes via the real settlement engine.

Phase status: B0 DONE (committed c9b095c — PLAN.md v2 delta + vendored
schemas). B1 IN PROGRESS.

### B1 — v2 wire types (first slice, non-breaking)
`kob/x402/src/wire_v2.rs`: the full v2 canonical types + header codecs +
closed error enum, as a NEW module so the working+live-proven native/pull +
KCC20 (v1 `wire` module) keep compiling and running unchanged. Types:
`PaymentRequired{x402Version,resource,accepts[],error?,extensions?}`,
`PaymentRequirements{scheme,network,amount,asset,payTo,maxTimeoutSeconds,extra}`
(+ KIP-10 accessors: binding/templateId/borrowOutpoint/borrowAmount/
additiveThreshold/paymentOutputIndex/reservationId/borrowRedeemScript),
`Resource`, `Outpoint`, `ExactPayload{type:exact-transaction,transaction,
transactionEncoding,paymentOutputIndex,payerAddress?,requestHash?}`,
`PaymentPayload{x402Version,accepted,payload,extensions?}`,
`FacilitatorRequest`, `AwaitRequest`(TODO), `VerifyResponse`,
`SettlementResponse{success,transaction,network?,payer?,amount?,errorReason?,
extensions.kaspa}`, `SupportedResponse{kinds[],extensions[],signers{}}`,
`encode_header`/`decode_header` (base64 JSON) + PAYMENT-REQUIRED/SIGNATURE/
RESPONSE names + `errors::*` closed enum.
Schema-conformance tests (6) assert sample v2 messages satisfy the invariants
extracted from the vendored `interop/schemas/*.json` (x402Version==2, asset
const KAS, exact scheme extra dependentRequired borrow fields, payload.type
== exact-transaction with transactionEncoding + no transactionId, settlement
success requires network+amount+64hex-txid and forbids top-level extra,
/supported extra+extensions+signers, header base64 round-trip, closed error
enum).

REMAINING B1 (next): migrate facilitator.rs verify/settle/await + server.rs +
existing unit tests + E2E clients/harnesses onto `wire_v2` (route native/KCC20
by a KOB binding under the v2 envelope; only KIP-10 exact claims strict
interop). This is the mechanical "rewrite" step; kept separate from the type
landing so the build stays green at each step.

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

### Native-KAS "exact" scheme — testnet-10, 2026-07-15 (7/7 checks passed)

Node `ws://65.108.107.30:18210`; payer wallet
`kaspatest:qz6qc3j490zleazs6upxazfnk79k7v4ksykf499uhur4el95cfy7qrwa6v8lf`.
Harness: `kob/x402/scripts/e2e_x402.sh`; results file
`/tmp/kob_e2e/x402/E2E_X402_TXIDS.txt`.

- CASE 1 HAPPY (verify -> settle -> broadcast -> finality-confirm ->
  authorize): **on-chain TXID**
  `19155ed285fa57b29e7ab094f151dfca4ea4b5f4444e8854a57a1563d4ee43c7`
  (self-pay 0.4 KAS; spent input
  `afd8cb439d98518f813574371ff9a2d49323946008a51b35ec49fa6a2ebd7708:0`).
  Independently re-confirmed present in the wallet UTXO set via kob-cli
  (belt-and-suspenders, not just "RPC accepted it"). Facilitator
  `/verify` -> `{isValid:true}`, `/settle` -> `{success:true, transaction:
  19155ed2..., payer: kaspatest:qz6qc3j...}`.
- CASE 2 UNDERPAYMENT (tx pays 20M, requirements demand 40M): refused at
  `/verify` and `/settle` (`underpayment: required 40000000 paid 20000000`);
  NO broadcast.
- CASE 3 WRONG RECIPIENT (tx pays the wallet, requirements demand a distinct
  valid address): refused (`no output pays the required recipient`); NO
  broadcast.
- CASE 4 REPLAY (a 2nd distinct artifact over the input CASE 1 already
  spent): refused (`input afd8cb43...:0 is not an unspent UTXO of the
  payer` — CASE 1 genuinely spent it on-chain, so the on-chain check fired;
  the replay-store OutpointReused guard is the backstop when the input is
  still in the UTXO set pre-confirmation); NO broadcast.

### PULL mode (receive-and-detect), native-KAS — testnet-10, 2026-07-15 (6/6) — DONE

Client broadcasts the payment ITSELF; facilitator discovers it by scanning
the merchant address (never given the txid). Harness
`kob/x402/scripts/e2e_x402_pull.sh`; results
`/tmp/kob_e2e/x402_pull/E2E_X402_PULL_TXIDS.txt`. Fresh merchant address per
run: `kaspatest:qrt7yzygwyjfs4gwfnn6tvfxpe5uedhxcpul2hp8fewsjq0elgxx7v9dpsy6z`.

- CASE 1 HAPPY (client broadcasts 5M KAS to merchant with an X402 fingerprint
  memo; facilitator `/await` DISCOVERS it by scanning): discovery evidence —
  `/await` returned `transaction:
  fbcb0d130777259c4045e7943658c80d67d37e5a1a9171a616d3ccfb4d08cabf`, the exact
  txid the client printed from its OWN broadcast, which the facilitator was
  never handed (it only got `{payTo, maxAmountRequired, fingerprint}`).
  Independently re-confirmed on-chain: `fbcb0d13...:0` (5,000,000 sompi) is in
  the merchant's UTXO set (raw `getUtxosByAddresses`). Durable log:
  Submitted -> Confirmed, fingerprint-bound.
- CASE 2 UNDERPAYMENT (client broadcasts 3M, requirement 5M): discovered
  (txid `40f84df24f0a9d40792d6c72a63e5d9ce661dd09a3b26bce3c4a118785dbd68c`)
  and rejected — `underpayment discovered ... paid 3000000 < required
  5000000`.
- CASE 3 NO-PAYMENT/TIMEOUT (nothing broadcast, fresh fingerprint): not
  authorized — `no matching payment discovered at <merchant> within 6s` (and
  NOT fooled into "already credited" by the CASE 1/2 UTXOs sitting at the
  merchant — the fingerprint-scoped dedupe fix).
- CASE 4 REPLAY/DOUBLE-CREDIT (re-`/await` the already-credited CASE 1
  payment): refused — `matching payment already credited (not
  double-crediting)`. No second credit recorded.

The facilitator never called `submit` in any pull case — it only observed.

### KCC20 token scheme — testnet-10, 2026-07-15 (7/7 checks passed) — DONE

Token fixture `kob/e2e_fixture.json` (covenant
`0c113120cb56668a5aa984752496f8cc4ac65e9044f2fa85d64e7bbcb5fc6039`); minted a
fresh 10M-sompi token_unit `aca2d5dd6299ce02c05d3d6b64773f4693be27cd31b2843660330a6c1fac970e:1`
from the fixture mint authority (fixture authority advanced to
`aca2d5dd...970e:0`). Harness `kob/x402/scripts/e2e_x402_kcc20.sh`; results
`/tmp/kob_e2e/x402_kcc20/E2E_X402_KCC20_TXIDS.txt`.

- CASE 1 HAPPY (spec-form token_unit-P2SH transfer; verify -> settle ->
  broadcast -> finality-confirm -> authorize): **on-chain TXID**
  `0577d3616b4c4a38d625f34fc4e916b0de360982495138e3cf2f1d094755d97c`.
  Spends token_unit `aca2d5dd...970e:1` + fee `aca2d5dd...970e:2`; creates the
  recipient token_unit at its token P2SH (output :0, covenant-bound to the
  asset) + fee change (output :1). The node ACCEPTED the spec-form
  token_unit-P2SH covenant transfer (settle success requires both broadcast
  and the facilitator's confirm_tx_output on the recipient token P2SH).
  Independently re-confirmed on-chain: the fee-change output `0577d3...:1`
  (8,238,067 sompi P2PK) is in the wallet UTXO set.
- CASE 2 UNDERPAYMENT (pays 10M token units, requirements demand 20M):
  refused at verify + settle (`underpayment: required 20000000 paid
  10000000`); NO broadcast.
- CASE 3 WRONG RECIPIENT (tx pays the wallet's token P2SH, requirements demand
  a distinct recipient's token P2SH): refused (`no token_unit output pays the
  required recipient for this asset`); NO broadcast.
- CASE 4 REPLAY (a 2nd artifact over the token_unit input CASE 1 spent):
  refused (`input aca2d5dd...970e:1 is not an unspent UTXO of the payer`); NO
  broadcast.

Durable log captured Submitted(null) -> Submitted(chain_txid=0577d3...) ->
Confirmed, spending both the token_unit and fee inputs.

Note: single token_unit reuse — the harness builds all artifacts while the
token_unit is unspent, runs the two non-broadcasting rejection cases first,
then the happy path (consumes it), then the replay partner (refused). The
finality-address fix (confirm against the recipient token_unit P2SH, not the
P2PK identity) was essential for the happy settle to report success.

(superseded IN-PROGRESS notes below retained for the record.)

**Spec-form reconciliation (the fix):** confirmed `kob-cli token mint`
(token.rs:606) creates the canonical token_unit as
`P2SH(build_token_unit_redeem_script(recipient_pk))` + covenant binding —
exactly what `scheme_kcc20` expects. `kob-cli token transfer` (token.rs:1033)
instead emits a documented non-spec P2PK+covenant shortcut. So the verifier
was right; the fix is to BUILD a spec-form token_unit-P2SH transfer, NOT to
loosen the verifier. The node already accepts token_unit-P2SH covenant
outputs (mint proves it), so a token_unit-P2SH -> token_unit-P2SH transfer
is valid (covenant continuity = spent input carries C -> output carries C;
the covenant does not constrain output scripts).

**What was added:**
- `x402-client kcc20` mode (in `src/bin/x402_client.rs`): builds a signed
  spec-form token_unit transfer — input0 = payer token_unit P2SH (spent via
  `build_token_unit_sigscript`), input1 = fee P2PK; output0 = recipient
  token_unit P2SH + covenant(asset); output1 = remainder token_unit P2SH +
  covenant (if partial); output N = fee change; `fee = min_relay_fee(mass)`.
  Emits a KCC20 FacilitatorRequest (payTo = recipient P2PK identity; the
  client derives the token P2SH). Scenario flags: `--require` (underpayment),
  `--tx-recipient` (wrong recipient), `--replay-out`/`--replay-recipient`
  (2nd artifact over the same token+fee inputs to a distinct recipient).
  Fingerprint omitted for KCC20 (keeps the covenant tx payload standard; the
  binding is scheme-agnostic + unit-proven).
- **Facilitator finality-address fix (real bug found):** the confirm step
  polled `pay_to` (the recipient's P2PK identity), but the KCC20 payment
  output lives at the recipient's token_unit *P2SH* address. Added
  `recipient_token_address` to `Kcc20Verified` and a `confirm_address` field
  on the facilitator's internal `Validated`; `finalize()` now confirms
  against `confirm_address` (native: pay_to; KCC20: recipient token P2SH).
