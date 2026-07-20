# Stablecoin — post-Live audit findings & pending work (2026-07-20)

Recorded after the testnet-10 7-op live run (see `STABLECOIN_E2E_LIVE.md`, HEAD `25a2429c`).
Two review passes were run: (A) external spec-consistency (KCC-0020/KCC-0001/x402
vs our impl) and (B) a new unevaluated-edge-case adversarial audit.

**Status 2026-07-20 (updated):** every finding below is now APPLIED. `e7c40414`
made a partial first pass; a multi-agent re-verification of that commit found
two of its three claims overstated (§D), and `fdabc98c` + the x402 commit that
follows it complete the work. Each fix is backed by a test that fails when the
guard is removed.

## A. External spec consistency (web-verified 2026-07-20)

- **KCC-0020** (`kaspanet/kccs#2`): unchanged since 2026-07-15. Still zero
  freeze/blacklist/seize/issuer/authority — our issuer-authority stablecoin is
  correctly OUTSIDE KCC-0020 scope. `identifier_type` discussion ongoing
  (Manyfestation leaning toward a single 32-byte hash + runtime hint — larger
  reshape than our ISSUE-4 anticipated).
- **KCC-0001** (`#3`): evolving (07-17: blake2b→blake3 default; ABI value-location
  annotation). ISSUE-1/11 `State[]` int-leaf encoding conflict STILL OPEN. New §9
  "Leader and delegator roles" now normatively mandates cardinality/coverage
  validation → moves ISSUE-19 toward resolution (our `max_participants` descriptor
  field still absent upstream).
- **x402** (`elldeeone/kaspa-x402`): **alpha.9 cut 2026-07-20**; PR#3 (07-19,
  merged, head `379ed675e181`) published the byte-exact canonical-JSON
  **Authorization-digest preimage** — and, less obviously, the **`TransactionID`
  keyed-blake2b preimage** as well. Both arrive as one language-independent
  vector, `vectors/exact/interop-v1.json`, now vendored under
  `kob/x402/interop/vectors/exact/`.
- **"#1729" / July-24 identifier-registration deadline** (from memory
  `kaspa-x402-status`): **NOT VERIFIED** — no such forum post found; kaspa-x402 has
  only 5 PRs. Treat that memory claim as unconfirmed.

Implementation alignment confirmed OK: State encoding (PushExplicit; P2SH=BLAKE2b /
dispatch=BLAKE3) matches kcc-0001 verbatim; descriptor in-memory-only is the right
conservative call (no upstream wire format); identifier_type=PUBKEY-only correct
while the spec is contested; the stablecoin covenant is self-consistent (BLAKE3).

### Spec risks (ranked)
1. ~~**HIGH** — `x402/src/facilitator.rs::validate()` only checks digest/sig
   LENGTH+hex-shape; never recomputes the digest nor Schnorr-verifies.~~
   **FIXED.** New `kob/x402/src/exact_authorization.rs` implements canonical
   JSON, `paymentRequirementsHash`, the authorization digest and its Schnorr
   verification, tested byte-for-byte against the PR#3 vector (both preimages,
   both SHA-256 results, the published signature under the published key).
   `validate()` now recomputes the digest from what the FACILITATOR holds and
   verifies the signature under the key the payer's P2PK address commits.
   Ordering matters and is deliberate: the offer is validated against the terms
   we issued FIRST, so a tampered offer still reports
   `invalid_payment_requirements` rather than being masked by the signature
   failure it also causes.
2. **HIGH** — descriptor wire-format void (ISSUE-6) blocks accepting externally
   issued KCC20 tokens via x402 (upstream-blocked).
3. MEDIUM — identifier_type reshape risk; ISSUE-1/11 State[] deviation (upstream).
4. LOW — MAX_N=4 cardinality now quasi-mandated by §9 but not externally declared.

## B. New unevaluated edge cases — all APPLIED

1. ~~**MEDIUM-HIGH — role-key degeneracy.**~~ **FIXED** (`e7c40414`, corrected in
   `fdabc98c`). SEIZE/RAISE_CAP "2-of-3" are fixed-positional-slot checks summed
   `>=2`, so a duplicated baked key collapses the threshold. The pairwise-distinct
   assertion now lives in `build_stablecoin_body` / `build_mint_authority_body` —
   the `pub fn`s that actually emit the threshold bytecode — not only in the outer
   redeem-script wrappers a caller could route around. The wrapper additionally
   asserts `owner_pubkey` differs from every role key, which item 2 made
   load-bearing.
2. ~~**MEDIUM — MIGRATE governance-exit.**~~ **FIXED** (`fdabc98c`). MIGRATE now
   requires owner + a cold **2-of-3 SEIZE quorum**, sharing SEIZE's exact
   threshold segment (`emit_2of3_threshold`, with a test that the two cannot
   drift). The `frozen_flag == 0` gate is retained on top. Escaping governance
   now costs the owner key plus two of three cold keys — i.e. what seizing the
   coin costs. Note for anyone touching these tests: Kaspa's sighash commits
   `sig_op_count`, so the skeleton and final inputs must declare the same value.
3. ~~**MEDIUM — no MINT dust floor.**~~ **FIXED** (`fdabc98c`), and the original
   reasoning corrected — see §D2.
4. ~~**LOW — frozen_flag not domain-checked to {0,1}.**~~ **FIXED** (`fdabc98c`).
   FREEZE now gates `new_frozen_flag` to exactly the two canonical literals,
   **bytewise** — a numeric compare would also admit non-minimal encodings, which
   the explicit-push convention forbids. Out-of-domain bytes created an undefined
   third state: not "clear" (every owner branch compares bytewise against `[0x00]`
   and aborts) and not the `[0x01]` tooling reads as frozen.
5. ~~**LOW — mandatory-fee-input trap.**~~ **FIXED** (`fdabc98c`). A new
   `preflight()` in the harness asserts a separate fee input exists for the four
   ops with exact value-continuity (FREEZE/SEIZE/MINT/RAISE_CAP) and runs a
   kaspad-backed whole-transaction storage-mass check before every submission.

### Confirmed safe
Script/sigscript sizes (~1.2–1.3KB / ~2.7–2.9KB) far under the 1MB / 244-stack
limits (design doc's "500–700B" is stale). cap==supply boundary `<=` correct.
Epoch(u32) rollover unreachable (ROTATE deferred). mint_amount=0 blocked by
consensus zero-output rule. Concurrency = ordinary UTXO double-spends; mint-authority
is a single linear UTXO so MINT vs RAISE_CAP serialize (operational note, not a vuln).

## C. Verification of `e7c40414` (4 parallel adversarial agents)

Worth recording because two of that commit's three claims did not survive:

- **Dead constant.** `MIN_MINT_AMOUNT` had ZERO call sites; its doc claimed
  "Enforced off-chain at build time". That was simply false.
- **Assertion placement.** The distinctness assert guarded only the two wrapper
  functions; the lower-level `pub` builders that emit the vulnerable bytecode
  were unguarded, and `kob/core/tests/mint_authority_contracts.rs` already calls
  one of them directly.
- **Owner not covered.** Harmless at the time, but the MIGRATE quorum decision
  would have made `owner == seize[i]` degrade the quorum silently.
- Angles that CLOSED cleanly: the on-chain 2-of-3 uses fixed positional slots
  with baked keys (spenders supply signatures only, never pubkeys), so distinct
  baked keys genuinely prevent one signature satisfying two slots; and
  byte-equality is the right distinctness test for x-only keys, since one secret
  yields exactly one x-only encoding.
- Still open by design: MIGRATE's destination template is authenticated only by
  its attested hash, so a hand-crafted degenerate template can be migrated to by
  a cooperating owner + quorum. That is now a 2-of-3 cold decision rather than a
  hot-key one; on-chain template introspection remains out of scope.

## D. Corrections to earlier analysis

1. **The relay-gating mass limit.** An intermediate review argued the binding cap
   was the pre-Toccata per-dimension standardness cap of 100_000
   (`check_transaction_standard.rs`). It is not: Toccata activated on testnet-10
   at DAA 467_579_632 (~2026-05-18) and mainnet 474_165_565 (~2026-06-30), both
   before today, so that cap is lifted and `block_mass_limits.storage` (500_000,
   `check_transaction_limits.rs`) is what actually gates. `kob/settle/src/mass.rs`'s
   `MAX_TX_MASS = 500_000` is therefore correct.
2. **The dust-floor arithmetic.** The `e7c40414` doc described an isolated
   `C / amount` term. Real KIP-9 storage mass is a whole-transaction quantity —
   `max(0, Σ C·p(o)²/amount(o) − input credit)` — and a covenant-bound P2SH output
   has `utxo_plurality` **2** (63 + 35 + 32 = 130 bytes → two 100-byte units), so
   the minted coin costs `4e12 / amount`, four times the naive figure. Consequence:
   **no constant can guarantee relay.** In the reference MINT shape the true floor
   is ~8.1e6 sompi, but it rises past 1e7 once the authority's own balance falls to
   0.2 KAS. `MIN_MINT_AMOUNT` is documented as necessary-not-sufficient and
   enforced by `check_mint_amount_floor`; the authoritative check is whole-tx
   storage mass in `preflight()`.
3. **"Harms only the minter."** Qualified: `running_supply` is strictly monotonic
   (no path decrements it — BURN acts on the coin's own covenant and never
   respends the authority UTXO), so a dust mint that does get mined permanently
   consumes that much cap headroom. That is why the floor is a hard error.

## Pending work queue

- [x] **x402 transaction-id recomputation — DONE.** `kob/x402/src/transaction_id.rs`
      implements the canonical consensus serialization and both identifier
      constructions (version 0: keyed BLAKE2b-256 `TransactionID`; version 1: the
      `PayloadDigest`/`TransactionRest`/`TransactionV1Id` BLAKE3 stages), verified
      byte-for-byte against the PR#3 pre-images for both profiles. The facilitator
      now derives the id instead of reading the artifact's own, and refuses an
      artifact whose self-declared `id` disagrees with its contents. `x402_client.rs`
      was moved off its KOB-local blake2b digest onto the spec object as part of
      the same change, so client and facilitator compute the same digest.
- [ ] Descriptor wire format (ISSUE-6) — upstream-blocked.
- [x] **MIGRATE offline verification — DONE.** The real-engine suite
      (`kob/core/tests/stablecoin_contracts.rs`, `TxScriptEngine` with covenants
      enabled) covers the new authorization shape: honest owner + 2-of-3 accepts,
      exactly-2-of-3 accepts, 1-of-3 rejects, and the old hot OPS key signing all
      three slots rejects, alongside the pre-existing template-mismatch, replay
      and frozen-gate cases.
- [x] **MIGRATE is now runnable live.** `op_migrate` added to the e2e harness,
      opt-in via `MIGRATE_DEMO=1`, running in place of BURN (both consume the one
      coin the harness mints; both leave a wallet change output at index 1, so
      RAISE_CAP chains off either). Not yet executed on testnet-10.
- [ ] Phase 2: CLI migration (all ops as kob-cli subcommands = Liquid-equivalent
      UTXO control), then re-verify offline → testnet-10.
- Env note: subagents keep hitting the 600s stream watchdog whenever the device's
  network drops mid-stream (this session: 8 stalls). They resume with context
  intact via a follow-up message, so prefer small tasks and ask for findings to be
  emitted early rather than after further reads.
