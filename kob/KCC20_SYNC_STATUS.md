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

Check results (commands exactly as run):

```
export CARGO_TARGET_DIR=/root/kob-rust-target4
export PATH=/data/data/com.termux/files/usr/bin:$PATH
cargo check -p kob-core                      # PASS (1m53s cold)
cargo check -p kob-core -p kob-cli --tests   # PASS, warnings only (2m15s;
                                             #   also checks kob-engine as a dep)
cargo check -p kob-domain --tests            # FAIL — PRE-EXISTING, unrelated:
    # error[E0063]: missing field `bracket_meta` in initializer of `batch::BatchOrder`
    #   kob/domain/src/spot/matching.rs:2862  (test-only; from the earlier
    #   "checkpoint WIP across cli/core/domain/engine" commit)
```

`cargo test -p kob-core --lib contract::token` was NOT run to completion:
the test profile recompiles + links the full dep graph, which is heavy on
this device and was cut short per the light-build budget. The KCC20 unit
tests compile (covered by `--tests` check above) but their assertions have
not been executed on this machine. Run when budget allows:

```
export CARGO_TARGET_DIR=/root/kob-rust-target4
export PATH=/data/data/com.termux/files/usr/bin:$PATH
cargo test -p kob-core --lib   # token tests are in kob/core/src/contract/tests.rs
cargo test -p kob-cli --lib token
```

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
  - token_unit redeemScript: **35B → 37B**:
    old `[0x20][owner_pk 32] [ad 51]`,
    new `[0x20][owner_identifier 32][0x01][identifier_type 1] [75 ad 51]`
    (body gained one `OpDrop` for identifier_type; sigscript 102B → 104B).
  - `parse_token_unit_state(script, utxo_value)` — Reader-side decode with
    body verification.
- `kob/core/src/lib.rs` — re-exports for the new KCC20 items.
- `kob/core/src/contract/tests.rs` — updated body/RS/sigscript size + layout
  tests to the new 37B layout; added `kcc20_state_header_decode_roundtrip`,
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

The 35B→37B RS change moves the token_unit P2SH address for a given owner
pubkey. Any token_unit UTXOs minted with the old layout (testnet only) are
not discoverable/spendable through the new builders — re-mint test tokens
after deploying this change.

## 5. TODOs

- [ ] Execute the kob-core/kob-cli token unit tests (`cargo test` commands in §2)
      when a heavier compile window is acceptable.
- [ ] Fix pre-existing `bracket_meta` test-compile error in
      `kob/domain/src/spot/matching.rs:2862` (unrelated to KCC20).
- [ ] E2E on testnet: mint + transfer with the 37B RS (script executes
      `OpDrop OpCheckSigVerify Op1` — logic unchanged, but on-chain
      verification of the new layout is untested).
- [ ] Track the KCC20 thread: virtual/extension state field proposal
      (michaelsutton's Open ICC post) may change the recommended layout for
      extension data (digest-behind-virtual-field instead of trailing plain
      fields) — the nonce reservation should follow whatever the spec adopts.
- [ ] Consider a Reader implementation over engine/chain/scanner.rs that
      projects KCC20 state (`parse_token_unit_state`) for indexer-style
      history, per the spec's Reader role.
