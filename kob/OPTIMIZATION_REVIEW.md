# KOB Structural Optimization Review — 2026-07-14

Analysis only; no code was changed for this review. Scope: kob/core, kob/domain,
kob/cli, kob/engine, kob/lab (~124k LOC incl. tests). Dependency graph:
`core` (no kob deps) ← `domain` ← `engine` ← `cli`; `lab` depends only on
`core`; nothing depends on `lab`.

This file is intentionally left uncommitted (owner review input).

**(Note, added later): §4 below and ranked-refactor items #2–#3 describe the
v14/v15 spot-buy dual-layout that existed at review time (2026-07-14). v14,
v15, v16, and v17 have since all been deleted; v18 is now the sole spot
generation (`SPOT_GENERATION=18`, commits `317f163c`/`23eb1edc`) — see
`kob/RELEASE_STATUS.md` for current status. The rest of this review (dead
code, module boundaries, error handling, test architecture, build hotspots)
is independent of contract-version generation and unaffected by this note.**

## 1. Dead / duplicated code

- **kob-lab is a fully dead crate (2487 LOC).** `lab/src/lib.rs:1-9`
  self-describes as "NOT used in the live trading flow"; zero references to
  `kob-lab`/`kob_lab` outside `lab/`. It archives 9 experimental bytecodes
  (crowdfund_pool v2, amm_pool v1, cdp v1, streaming_payment, bridge_vault,
  bridge_receipt, nft_royalty, index_basket, futures_dated) and 88 unwraps,
  and compiles on every workspace build.
- **Stalled matcher migration, now load-bearing.** `engine/src/matcher/mod.rs:1-43`
  is an explicit "Legacy compat façade" re-exporting `kob_domain::*` and
  `crate::{chain,storage,api,reporting}` under old `crate::matcher::` paths
  with a "new code should import from canonical locations" note — ignored by
  **267 call sites**, including `engine/src/lib.rs:26-38` and CLI
  (`cli/src/match_batch.rs:22`, `cli/src/prediction.rs:27-30`).
- **Two matching implementations, drifted.** `cli/src/auto_match.rs` (2243 LOC)
  reimplements matching business logic — `find_crossing_pairs` (:105),
  `compute_match_outputs` (:143), `compute_cross_pair_outputs` (:841),
  `needs_partial_fill` (:1149), `submit_partial_{buy,sell}_fill` (:448/:647) —
  overlapping `domain/src/spot/matching.rs` (2895 LOC) and
  `domain/src/spot/batch.rs`. Version drift: CLI production paths emit only
  v14 non-IOC sigscripts; engine/domain use v14 + IOC + v15.
- **Blanket `#[allow(dead_code)]` hides real dead API.** Domain carries 35;
  module-level suppressions at `domain/src/spot/mod.rs:4-20`,
  `lending/mod.rs:3-7`, `perp/mod.rs:3-7`, `prediction/mod.rs:3-7`. Spot
  checks confirm genuinely-unused exports, e.g. `perp/perp_book.rs:411
  pub fn clear()`, `lending/lending_book.rs:680 pub fn clear()`.
- **Legacy paths retained alongside replacements**: legacy bracket deploy
  (`cli/src/bracket.rs:956`, `:1237/:1250`; `cli/src/deploy.rs:1669` prints
  "deprecated"); legacy `KOB:1:` payload still parsed
  (`engine/src/chain/scanner.rs:851,1278,2146`; deprecated builder
  `engine/src/chain/deploy.rs:142`); legacy wallet format
  (`core/src/wallet.rs:37,138-157`). ~130 `#[allow(dead_code)]`/
  `#[allow(deprecated)]` total — this, not TODO comments (only ~4 in the
  whole subtree), is where the deferred work hides.

## 2. Module boundaries

Largest files: `engine/src/chain/executor.rs` **7893**, `engine/src/api/mod.rs`
3480, `cli/src/lib.rs` 3301 (~65 clap variants), `domain/src/spot/batch.rs`
3259, `engine/src/mm/mod.rs` 3062, `core/src/contract/lending/tests.rs` 2926,
`domain/src/spot/matching.rs` 2895, `engine/src/chain/scanner.rs` 2703,
`lab/src/lib.rs` 2487 (dead), `cli/src/auto_match.rs` 2243 (duplicate logic).

- **executor.rs is the god-module**: `CovenantCache` (:97), `SpentTracker`
  (:282), `ReorgTracker`/`BlockProvenance` (:584/:592), batch settlement
  (:1192-1760), swap settlement (:1760-2133), block parsing (:2133, :3181),
  trade recording (:3210), order expiry (:3300); single functions
  `run_scan_cycle` ≈ lines 3439–5318 (~1879 lines) and
  `run_continuous_with_ws` ≈ 5318–6179; inline tests 6272–7893.
- **Dependency inversion**: `cli/Cargo.toml` does not depend on `kob-domain`;
  CLI reaches domain types through `kob_engine::matcher::` re-exports,
  coupling CLI to engine internals for a domain-layer need.
- Positive: engine reuses domain's `OrderBook` and core's parsers
  (`scanner.rs:85,94` delegate to `kob_core::contract::spot::parse`);
  `core/src/compat.rs` is genuinely shared. Parsing is NOT duplicated.

## 3. Error handling

Three incompatible conventions; no typed error crosses the domain boundary.

- core: `KobError` (thiserror, 184 uses) — clean, but highest production
  unwrap count (~119, e.g. `core/src/wallet.rs`).
- domain: **no error type at all** — 14 stringly `Result<_, String>`
  signatures (`stop_book.rs:145,309,314,357,369`;
  `ifd.rs:166,337,343,382,425,464,476`; `trailing_stop.rs:565`).
- engine: mixed `anyhow` (×49) + stringly `Result<_, String>` (×41 across
  `persistence.rs`, `rpc/mod.rs`, `config.rs`, `lib.rs:43`) + `Box<dyn>` (×3).
- cli: `anyhow` ×954 (fine for a binary) but ~35 production unwraps on
  user-controlled input, e.g. `compat::parse_hash(...).unwrap()` at
  `cli/src/matching.rs:152,1078`, `cli/src/match_batch.rs:322`,
  `cli/src/deploy.rs:1087,1105,1515,1526`.

## 4. Contract-version sprawl

- **v14 and v15 spot-buy layouts are simultaneously live.** v14
  (`BUY_RS_SIZE` 396, `core/src/contract/spot/parse.rs:50-64`) and v15
  (`BUY_ORDER_V15_RS_EXPECTED_LEN` 479, `spot/order.rs:1101-1104`); parser
  accepts both (`parse.rs:93`). Deploy switches on flag
  (`cli/src/deploy.rs:401`, default 14).
- **v15 wiring is half-done**: v15 sigscript builders
  (`order.rs:1175/1197/1220/1247/1267`) are used only by
  `domain/src/spot/batch.rs:441-534`; all CLI order-management surfaces
  (cancel.rs:149, cancel_mark.rs:84, matching.rs:194,811, ifd.rs:229,526,826,
  recover.rs:888+, requote.rs:178,409, auto_match.rs:1340,
  match_batch.rs:191, watch.rs:716, cancel_all.rs:503) are hardcoded v14.
- Residue: `DCA_V2_*` naming with no v1 remaining; `PERP_DEPLOY_V1_*`
  (`contract/perp/parse.rs:27-31`) and v13 markers in `perp/position.rs`;
  `KOB:1:` payloads parsed-but-deprecated next to `KOB:2:` plus per-product
  `KOB:P:/L:/M:/A:`; v12 helpers survive in tests
  (`scanner.rs:805,820`, `cli/src/matching.rs:1189,1257,1280`).

## 5. Test architecture

- Mixed conventions: dedicated `tests.rs` only in core (4 files, 6077 lines:
  lending 2926, contract 1831, prediction 868, auction 452); domain/cli/engine
  are inline-only; core uses BOTH, making it the inconsistent crate.
- Duplication: `core/src/contract/tests.rs` (118 `#[test]`s incl.
  `adversarial_tests` :1440) overlaps the 19 inline tests in
  `core/src/contract/spot/parse.rs` (same parse/roundtrip surface,
  e.g. `BUY_RS_SIZE` roundtrips :463,482,676,702).
- Tests are pure unit/in-memory (no `#[ignore]`, no network); "e2e" tests
  are simulated blocks (`scanner.rs:1470+`). The 7893-line executor.rs
  embeds ~1620 lines of inline tests.
- 2026-07-14 experience: struct-field additions (`bracket_meta`,
  `deploy_delay_secs`) silently rotted dozens of test initializers because
  tests construct structs literally. A `fn test_default()` constructor per
  config/order struct would have prevented both breakages.

## 6. Build-time hotspots (on-device observations)

- Cold `cargo check -p kob-core`: 1m53s; `-p kob-core -p kob-cli --tests`:
  2m15s; warm incremental engine+cli check: ~33s. The expensive first-time
  items observed in compile logs: `secp256k1-sys`/`k256` (C build + heavy
  generics), `malachite-nz/base` (via kaspa-math), `wasm-bindgen`/`web-sys`
  (pulled on NATIVE builds via kaspa-consensus-core → workflow-* — pure
  waste for kob), `tokio`+`reqwest`+`tokio-tungstenite` (cli).
- kob-cli carries TWO TLS stacks: `tokio-tungstenite` with `native-tls` and
  `reqwest` with `rustls-tls` (`cli/Cargo.toml`) — unify on rustls to drop
  openssl-sys/native-tls from the graph.
- The kob crates correctly avoid kaspad/consensus/rocksdb; keeping checks
  per-crate (`-p`) is the single biggest lever and is already documented in
  README/KCC20_SYNC_STATUS.
- Test-profile LINK is the dominant cost on this device (not codegen):
  prefer `cargo check --tests` for iteration; run test binaries only at
  milestones.

## Ranked top-10 refactors (effort S/M/L, risk L/M/H)

1. **Split `engine/src/chain/executor.rs`** into cache/tracker, settlement,
   scan-cycle, and test modules; break up the 1879-line `run_scan_cycle`.
   Effort L, risk M (pure moves first, then function extraction; inline
   tests move with their subjects). Highest payoff for navigability and
   incremental compile.
2. **Collapse CLI's duplicate matcher** — make `cli/src/auto_match.rs` and
   `cli/src/matching.rs` call `kob-domain` matching/batch. Effort M-L,
   risk M-H (behavioral drift already exists — v14-only vs v14+IOC+v15 —
   needs golden-output tests first). Eliminates the class of "fixed in one
   matcher, not the other" bugs.
3. **Decide the v15 migration** — either wire v15 through all CLI
   order-management surfaces or explicitly park it behind a feature flag
   with v14 as the sole live layout. Effort M, risk M. Today's half-state
   (engine emits v15, CLI can't cancel/requote/recover it) is a live
   operational trap.
4. **Delete or workspace-exclude `kob-lab`.** Effort S, risk L. 2487 LOC and
   88 unwraps out of every build; archive value preserved by git history.
5. **Introduce `DomainError` (thiserror) in kob-domain** and convert the 14
   `Result<_, String>` signatures; then unify engine's 41 stringly
   signatures on typed errors at the boundary. Effort M, risk L
   (mechanical; call sites mostly `?`/log).
6. **Make kob-cli depend on kob-domain directly** and start burning down the
   267 `matcher::` façade call sites (mechanical sed per module, one commit
   per namespace); delete `engine/src/matcher/mod.rs` last. Effort M, risk L.
7. **Remove module-level `#[allow(dead_code)]` in domain** and delete what
   falls out (unused `clear()` etc.). Effort S, risk L. Restores the
   compiler's dead-code signal for future work.
8. **Add `test_default()` constructors** (or `Default` impls) for
   `BatchOrder`, `MmConfig`, `BookOrder` and other literally-constructed
   test structs. Effort S, risk L. Directly prevents the
   `bracket_meta`/`deploy_delay_secs` rot class (31 initializers fixed
   2026-07-14).
9. **Unify CLI TLS stacks on rustls** (drop `native-tls` from
   tokio-tungstenite). Effort S, risk L-M (verify wss:// against the node
   endpoints). Removes a C dependency and a chunk of cold build time.
10. **Retire parsed-but-deprecated legacy paths** — `KOB:1:` payload parsing,
    legacy bracket deploy, legacy wallet format — after confirming no
    on-chain UTXOs from those eras remain relevant. Effort S-M, risk M
    (requires an explicit compatibility cutoff decision by the owner).

Not recommended now: crates.io/git-dep standalone workspace (evaluated in
KCC20_SYNC_STATUS.md §3 — crates.io kaspa is frozen pre-covenants at 0.15.0);
error-handling rewrite of kob-cli away from anyhow (appropriate as-is for a
binary crate).
