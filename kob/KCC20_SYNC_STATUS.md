# KCC20 Sync Status — kob-phase0

Last updated: 2026-07-14

## 1. Upstream merge

- Branch: `kob-phase0` (RossKU/rusty-kaspa), merged `upstream/master`
  (kaspanet/rusty-kaspa, post-Toccata, workspace v2.0.1) as a MERGE commit
  (no rebase): `5a3ce69 merge: sync with upstream kaspanet/master (post-Toccata)`.
- Merge base `8c8d036`; 86 upstream commits merged over 138 local commits.
- kob-phase0's non-/kob delta was tiny (workspace members list + one dep line),
  so only 2 conflicts:

| File | Conflict | Resolution |
|---|---|---|
| `Cargo.lock` | both sides regenerated | took upstream's (`--theirs`), then let cargo re-resolve to re-add the kob crates' deps (axum etc.). Committed post-resolve. |
| `consensus/core/Cargo.toml` | local had removed `kaspa-core` dep ("Termux build fix"); upstream kept it and added `mem_size` feature to `kaspa-hashes` | upstream wins: `kaspa-core` restored, `kaspa-hashes = { workspace = true, features = ["mem_size"] }`. The old local removal is superseded by the linker fix below (the original Termux issue was link-stage, now solved properly). |

- `/kob` untouched by the merge (upstream never touches it); kob workspace
  members entry in root `Cargo.toml` auto-merged cleanly.
- No /kob API adaptation was needed: kob-core builds against in-tree
  `kaspa-consensus-core`/`kaspa-addresses`/`kaspa-hashes` v2.0.1 and
  `cargo check` passes unmodified (see §2).

## 2. Build / check status (Android PRoot + Termux toolchain)

Environment: PRoot-Distro glibc guest, Termux rustc/cargo 1.94.1
(host = `aarch64-linux-android`).

Two environment obstacles found and fixed/worked around:

1. **Linker mismatch** — the guest's glibc `cc`/`ld` cannot link
   bionic-ABI artifacts (`cannot find -llog -lunwind`, then bionic
   `__sF`/`__errno` symbol errors). Fixed persistently in
   `.cargo/config.toml`:
   `[target.aarch64-linux-android] linker = "/data/data/com.termux/files/usr/bin/clang"`.
2. **`/storage/emulated` is mounted noexec** — build scripts placed in a
   target dir under `/storage/...` fail with `Permission denied (os error 13)`
   when cargo executes them. The old shared target dir
   `/storage/emulated/0/Download/ClaudeCLI/kob-rust-target4` is therefore
   unusable for any crate with build scripts (i.e. all of them) — and it was
   also stale (rustc 1.92 fingerprint vs current 1.94). Workaround: target
   dir on the rootfs, `CARGO_TARGET_DIR=/root/kob-rust-target4`.

Check/test results (2026-07-14, commands exactly as run, all with
`CARGO_TARGET_DIR=/root/kob-rust-target4` and Termux bin on PATH):

| Command | Result |
|---|---|
| `cargo check -p kob-core` | PASS (1m53s cold) |
| `cargo test -p kob-core --lib` | **PASS — 802 passed / 0 failed** (2.5s run after link) |
| `cargo check -p kob-domain --tests` | PASS (after `bracket_meta` fix, see below) |
| `cargo test -p kob-domain --lib` | **PASS — 625 passed / 0 failed** (0.9s run) |
| `cargo check -p kob-cli -p kob-engine --tests` | PASS (after `MmConfig` fix, see below) |
| `cargo test -p kob-cli / -p kob-engine` (execution) | NOT run — link stage too heavy for this session; run `cargo test -p kob-cli --lib` and `cargo test -p kob-engine --lib` when budget allows |

First on-device test execution surfaced and fixed three issues:

1. **KCC20 header length bug (real bug, caught by the new tests)**: the
   script-encoded header is `[0x20]+32 + [0x01]+1` = **35** bytes, not 34 as
   first coded. `SCRIPT_ENCODED_LEN` corrected 34 → 35; token_unit RS is
   **38B** (not 37B) and transfer sigscript **105B** (not 104B). The 34
   value also made `Kcc20StateHeader::decode` read one byte past its own
   bounds check. All sizes/docs/tests re-synced to 38/105.
2. **`bytecode_stable` pin**: the adversarial test pins blake2b-256 of every
   contract body; TOKEN_UNIT pin updated `44a029fd…` → `2ae2756e…` for the
   new 3-byte body `75ad51`.
3. **Pre-existing WIP test-rot (unrelated to KCC20), fixed**:
   - `kob/domain/src/spot/matching.rs` — 5 test `BatchOrder` initializers
     predated the v16 `bracket_meta` field; added `bracket_meta: None`.
   - `kob/engine/src/mm/mod.rs` — 26 test `MmConfig` initializers predated
     the H12 `deploy_delay_secs` field; added `deploy_delay_secs: 0`
     (`validate()` does not constrain it; prod path in engine lib.rs uses 2).

## 3. Lightweight sustainable build structure (evaluated, documented)

Options considered:

- **(a) Standalone /kob workspace on crates.io kaspa crates** — REJECTED.
  crates.io kaspa crates are frozen at **0.15.0 (2024-09-27)**: pre-Crescendo,
  pre-Toccata, no covenant/CovenantBinding APIs at all. Not viable.
- **(b) Standalone /kob workspace with git deps on kaspanet/rusty-kaspa** —
  viable but NOT chosen: cargo would clone/compile the same upstream sources
  anyway (no compile savings), while losing the ability to patch upstream
  in-tree and adding version-skew risk between the DEX and the node.
- **(c) Stay in-workspace, scoped checks (CHOSEN, pragmatic)** — the kob
  crates only pull the small leaf crates (`kaspa-consensus-core`,
  `kaspa-addresses`, `kaspa-hashes` + ~200 light deps); a cold
  `cargo check -p kob-core` is under 2 minutes even on this phone. The heavy
  crates (kaspad, consensus, rocksdb, wasm, grpc) are never built unless
  explicitly requested. Rules that keep it light:
  - always `cargo check -p <kob crate>` — never bare `cargo check`/`build`
    (workspace default members include kaspad et al.);
  - keep `CARGO_TARGET_DIR=/root/kob-rust-target4` (exec-capable, warm cache);
  - `--tests` on check catches test-code rot without linking;
  - full `cargo test` (link stage) reserved for milestone verification.
- Feature-trimming upstream defaults was inspected but has little to give:
  kob-core's three kaspa deps already compile without the expensive optional
  machinery; the cost driver is the *test-profile link*, not features.

## 4. KCC20 conformance changes

Spec source: "Fungible Token Covenant Specification (KCC20)" — Manyfest,
kas-smiths.org thread 8 (opening post + SilverScript Interface / Token
Descriptor follow-ups). Only `token_unit` is in scope: `token_mint` is the
admin mint/burn authority covenant, never a transferable token state, so it
keeps its existing 47B layout.

### Changed files

- `kob/core/src/contract/token.rs` — rewritten around the KCC20 shapes:
  - `Kcc20StateHeader { owner_identifier: [u8;32], identifier_type: u8, amount: u64 }`
    — the Standard State Header as canonical leading fields; `encode_script()`
    (Writer) and `decode()` (Reader).
  - `identifier_type` consts: `PUBKEY=0x00`, `SCRIPT_HASH=0x01`,
    `COVENANT_ID=0x02` (only PUBKEY implemented by the body).
  - `TokenDescriptor { prefix, suffix, state_layout, leader_entrypoint_selector,
    delegator_entrypoint_selector, optional_extensions }` +
    `StateField { name, len, in_script }` and the concrete
    `KCC20_TOKEN_UNIT_DESCRIPTOR` / `TOKEN_UNIT_STATE_LAYOUT` instances.
  - token_unit redeemScript: **35B → 38B**:
    old `[0x20][owner_pk 32] [ad 51]`,
    new `[0x20][owner_identifier 32][0x01][identifier_type 1] [75 ad 51]`
    (body gained one `OpDrop` for identifier_type; sigscript 102B → 105B).
  - `parse_token_unit_state(script, utxo_value)` — Reader-side decode with
    body verification.
- `kob/core/src/lib.rs` — re-exports for the new KCC20 items.
- `kob/core/src/contract/tests.rs` — updated body/RS/sigscript size + layout
  tests to the new 38B layout; added `kcc20_state_header_decode_roundtrip`,
  `kcc20_parse_token_unit_state_rejects_wrong_length`,
  `kcc20_token_unit_descriptor_shape`.
- `kob/cli/src/token.rs` — updated the two size-asserting unit tests + a
  stale size comment. **No functional call-site changes were needed
  anywhere** (cli/deploy.rs, cli/swap.rs, cli/dca.rs, engine/chain/deploy.rs,
  engine executor): builder signatures are unchanged and every consumer
  derives RS/P2SH/sigscript through the builders; mass/fee uses
  `calc_mass_with_sigscripts` on the actual bytes, so the 2-byte growth is
  picked up automatically.

### Decisions (recorded per spec ambiguity)

- **Entrypoint selector for single-entrypoint covenants** (open thread
  question, Shawn/KRON's `without_selector: true` case): `token_unit` has
  exactly one method (transfer), so the simplest option was chosen —
  `leader_entrypoint_selector = None` = *no selector byte pushed at all*
  (not an empty push, not a null sentinel). `prefix = []`. This matches the
  existing sigscript `[sig][pushData(RS)]` byte-for-byte in shape.
  `delegator_entrypoint_selector = None` (delegator dispatch not implemented).
- **`amount` maps to the UTXO's native sompi value, not script bytes.**
  KOB's entire UTXO-discovery model derives the token_unit P2SH address from
  the owner pubkey alone; embedding a balance in the RS would give every
  balance a distinct address and break discovery across cli/engine. KOB
  already used `1 token unit == 1 sompi of UTXO value` semantics, so the
  header's `amount` is sourced from the output value (marked
  `in_script: false` in the state_layout descriptor). This preserves the
  spec's header semantics (owner, type, amount all on-chain and
  Reader-decodable) without inventing a new indexing subsystem.
- **`optional_extensions = []`** — no extensions declared; specifically
  `kcc20_borrowed_receive_v1` is NOT declared/implemented.
- **`token_mint` out of scope** — see above.

### Nonce reservation (extension candidate, documentation-only)

`kob/core/src/contract/token.rs` reserves — as comments plus three inert
constants (`NONCE_EXT_ID = "kcc20_nonce_v1"`, `NONCE_EXT_OFFSET` (= end of
script-encoded header), `NONCE_EXT_LEN = 8`) — a trailing per-UTXO nonce
slot `[0x08][nonce LE 8B]` appended after `identifier_type`. The
`TOKEN_UNIT_STATE_LAYOUT` carries the slot as a commented-out entry. No
nonce is encoded, parsed, checked, or incremented anywhere; building the
actual mechanism (and declaring the extension id in `optional_extensions`)
is future work.

### Compatibility note

The 35B→38B RS change moves the token_unit P2SH address for a given owner
pubkey. Any token_unit UTXOs minted with the old layout (testnet only) are
not discoverable/spendable through the new builders — re-mint test tokens
after deploying this change.

## 5. TODOs

- [x] Execute kob-core unit tests — done 2026-07-14: 802/802 PASS (see §2).
- [x] Fix pre-existing `bracket_meta` test-compile error — done 2026-07-14;
      kob-domain now 625/625 PASS. Same-class `MmConfig.deploy_delay_secs`
      test rot in kob-engine also fixed (check --tests PASS).
- [ ] Execute kob-cli / kob-engine test binaries (`cargo test -p kob-cli --lib`,
      `cargo test -p kob-engine --lib`) — compile-checked only so far.
- [ ] E2E on testnet: mint + transfer with the 38B RS (script executes
      `OpDrop OpCheckSigVerify Op1` — logic unchanged, but on-chain
      verification of the new layout is untested).
- [ ] Track the KCC20 thread: virtual/extension state field proposal
      (michaelsutton's Open ICC post) may change the recommended layout for
      extension data (digest-behind-virtual-field instead of trailing plain
      fields) — the nonce reservation should follow whatever the spec adopts.
- [ ] Consider a Reader implementation over engine/chain/scanner.rs that
      projects KCC20 state (`parse_token_unit_state`) for indexer-style
      history, per the spec's Reader role.
