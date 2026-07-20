# Stablecoin — post-Live audit findings & pending work (2026-07-20)

Recorded after the testnet-10 7-op live run (see `STABLECOIN_E2E_LIVE.md`, HEAD `25a2429c`).
Two review passes were run: (A) external spec-consistency (KCC-0020/KCC-0001/x402
vs our impl) and (B) a new unevaluated-edge-case adversarial audit. Findings below
are NOT YET APPLIED (the fix agents repeatedly hit the environment's 600s
stream-watchdog and wrote nothing to disk; working tree is clean at `25a2429c`).

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
- **x402** (`elldeeone/kaspa-x402`): **alpha.9 cut 2026-07-20**; PR#3 (07-19)
  published the byte-exact canonical-JSON **Authorization-digest preimage**. This
  makes full verification implementable and makes our facilitator's under-checking
  a now-fixable gap.
- **"#1729" / July-24 identifier-registration deadline** (from memory
  `kaspa-x402-status`): **NOT VERIFIED** — no such forum post found; kaspa-x402 has
  only 5 PRs. Treat that memory claim as unconfirmed.

Implementation alignment confirmed OK: State encoding (PushExplicit; P2SH=BLAKE2b /
dispatch=BLAKE3) matches kcc-0001 verbatim; descriptor in-memory-only is the right
conservative call (no upstream wire format); identifier_type=PUBKEY-only correct
while the spec is contested; the stablecoin covenant is self-consistent (BLAKE3).

### Spec risks (ranked)
1. **HIGH** — `x402/src/facilitator.rs::validate()` (~L449-466) only checks
   digest/sig LENGTH+hex-shape; never recomputes the digest nor Schnorr-verifies.
   PR#3 now specifies the exact preimage → **implement full verification**.
2. **HIGH** — descriptor wire-format void (ISSUE-6) blocks accepting externally
   issued KCC20 tokens via x402 (upstream-blocked).
3. MEDIUM — identifier_type reshape risk; ISSUE-1/11 State[] deviation (upstream).
4. LOW — MAX_N=4 cardinality now quasi-mandated by §9 but not externally declared.

## B. New unevaluated edge cases (NOT covered by the 5-dim audit or the live run)

1. **MEDIUM-HIGH — role-key degeneracy.** SEIZE / RAISE_CAP "2-of-3" are
   fixed-positional-slot checks summed `>=2`; nothing asserts the baked pubkeys are
   pairwise distinct. Duplicate a key ⇒ one key satisfies two slots ⇒ 2-of-3
   collapses to unilateral control. Also `mint_pubkey == cap_authority[i]` lets a
   hot key contribute a RAISE_CAP vote. **Fix:** pairwise-distinct assertion in
   `build_stablecoin_redeem_script` + `build_mint_authority_redeem_script`.
2. **MEDIUM — MIGRATE governance-exit.** MIGRATE (owner + hot OPS) can move an
   UNFROZEN coin to any attested template, escaping FREEZE/SEIZE/BURN — contradicts
   §11 ("stolen OPS cannot redirect"). Mitigated today by the frozen==0 gate + OPS
   co-sign, but a compromised-OPS+owner can still escape. **DECISION 2026-07-20:
   gate MIGRATE behind a cold 2-of-3 quorum (owner + SEIZE-quorum reuse).** — to apply.
3. **MEDIUM — no MINT dust floor (KIP-9 storage mass).** `build_mint_branch`
   accepts any `mint_amount>=1`; a coin below ~2e6 sompi alone exceeds a typical
   500k block-mass budget (storage-mass term = 1e12/amount) and won't relay.
   **Fix:** on-chain `MIN_MINT_AMOUNT` floor (~10_000_000 sompi / 0.1 KAS) + off-chain.
4. **LOW — frozen_flag not domain-checked to {0,1}.** FREEZE key can write any byte.
   **Fix:** on-chain `new_frozen_flag ∈ {0,1}` check.
5. **LOW — mandatory-fee-input trap.** Exact value-continuity means FREEZE/SEIZE/
   RAISE_CAP/MINT can't source fee from the covenant coin; a single-input build is
   zero-fee (relay-rejected). **Fix:** harness assertion + regression test.

### Confirmed safe
Script/sigscript sizes (~1.2–1.3KB / ~2.7–2.9KB) far under the 1MB / 244-stack
limits (design doc's "500–700B" is stale). cap==supply boundary `<=` correct.
Epoch(u32) rollover unreachable (ROTATE deferred). mint_amount=0 blocked by
consensus zero-output rule. Concurrency = ordinary UTXO double-spends; mint-authority
is a single linear UTXO so MINT vs RAISE_CAP serialize (operational note, not a vuln).

## Pending work queue (not yet applied)
- [ ] x402 facilitator full digest + Schnorr verification (spec risk #1) — needs the
      PR#3 canonical preimage (fetch was flaky; do the fetch on the main loop, hand
      the concrete spec to the implementer).
- [ ] Covenant hardening pass: MIGRATE→cold 2-of-3 (decided), role-key distinctness,
      MINT dust floor, frozen_flag {0,1}, fee-input regression test.
- [ ] Phase 2: CLI migration (all ops as kob-cli subcommands = Liquid-equivalent
      UTXO control), then re-verify offline → testnet-10 (incl. MIGRATE, not yet run live).
- Env note: subagents doing large-file reads or web fetches keep hitting the 600s
  watchdog; prefer tight line-range reads, main-loop web fetches, and small tasks.
</content>
