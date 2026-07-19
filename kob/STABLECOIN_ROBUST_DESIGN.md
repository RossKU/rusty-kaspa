# KCC-0020 Robust Issuer-Grade Stablecoin Covenant — Design Spec

**Status**: locked architecture ("B-backbone + A-hardening + C-descriptor"); implementation in
progress under **Decision 2026-07-19: option B — baked keys for initial Live** (Resolved Decisions,
(d)) — role keys baked as bytecode literals, not verified against `role_registry_root`. Phase I
TRANSFER + Phase II FREEZE done & green; SEIZE in progress.
**Supersedes**: case-A (`core/src/contract/stablecoin/*` as of this writing). Case-A becomes the
`TRANSFER` + `FREEZE` subset of this design.
**Stranding**: none — no on-chain mint has occurred under case-A, so this is a pre-Live redesign,
not a migration.

Code anchors verified against repo state (branch `kob-phase0`):
- `core/src/contract/stablecoin/body.rs:115` — `STABLECOIN_BODY_LEN = 68`.
- `core/src/contract/stablecoin/body.rs:118` — `STABLECOIN_REDEEM_SCRIPT_LEN = Kcc20StateHeader::SCRIPT_ENCODED_LEN (35) + STABLECOIN_BODY_LEN (68) = 103`.
- `core/src/contract/stablecoin/body.rs:123` — `ISSUER_PUBKEY_RS_OFFSET = 68` (state 35B + 33B stage-1 prefix).
- `core/src/contract/stablecoin/body.rs:154-159` — successor reconstruction: `OpTxInputIndex OpTxOutputSpk OpBlake3 OpCat` (input index reused as output index, 1:1 binding).
- `core/src/contract/stablecoin/attestation.rs:18-27,61-70` — preimage = `DOMAIN_TAG(8) || covenant_id(32) || outpoint_txid(32) || outpoint_index(4,LE) || successor_spk_hash(32) || amount(8,LE)`, 116B total.
- `core/src/contract/kcc20/dispatch.rs:156-186` — `build_dispatch_skeleton`: roll tag to top, `DUP DATA4 <tag> EQUAL IF ... ELSE ... ENDIF` shape, generalized here to 6 branches (this covenant's dispatch; `op_type` 0x04 is reserved for the separate mint-authority contract, §9).
- `core/src/contract/kcc20/transfer.rs:356,462-463` (helpers defined `core/src/contract/dr.rs:41,70,125`) — `dr_input_spk_check` / `dr_output_spk_check` / `dr_suffix_check`: successor-template (redeem-script) authentication via Blake2b/suffix matching.
- `core/tests/stablecoin_contracts.rs:229-371` — real-engine (`covenants_enabled = true`) test harness style: `Cfg` struct with per-field overrides, `build()`/`run()`/`assert_rejected_with()`, one happy path + N adversarial single-lever mutations.

---

## §1 Overview

Regulated-stablecoin-grade covenant. Ordinary transfer requires **2-of-2 co-signature**:

- coin **OWNER** — `OpCheckSigVerify`, `SIGHASH_ALL`, standard transaction signature.
- issuer **OPS** role — `OpCheckSigFromStack` over a spend-bound attestation message (extends the
  case-A pattern in `body.rs`/`attestation.rs`).

Privileged actions (freeze, seize, rotate, migrate, burn — mint lives outside this covenant, see
below) are **issuer-side only** — no owner signature required for those (except `MIGRATE`, which needs
owner consent to move the coin to a new template). Issuer authority is single-key for hot/low-risk
roles (OPS, FREEZE, MINT) and **cold multisig** for fund-moving/master-key roles: **SEIZE = 2-of-3**,
**ROTATE = 3-of-5** `OpCheckMultiSig` (ROTATE strictly stronger, since it is the ultimate re-key
master and can rewrite SEIZE's own key material).

**MINT is not part of this covenant.** Minting lives in a separate, self-continuing mint-authority
contract (§9); this covenant's `op_type` dispatch only ever spends existing per-coin UTXOs
(TRANSFER/FREEZE/SEIZE/BURN/ROTATE/MIGRATE) — it never mints.

Role keys are committed as a **Blake3 `role_registry_root`** carried in mutable per-coin state, into
every successor. Rotating any role — including the hot OPS key — is a `ROTATE` spend that writes a
new root; it does not require re-minting or touching holders' coins individually (aside from the
per-coin epoch-lag caveat in §6/§11).

**Decision 2026-07-19: option B — baked keys for initial Live.** For the initial testnet Live, role
keys (OPS, FREEZE, SEIZE, MINT) are **baked as bytecode literals** directly in the covenant body —
they are NOT verified against `role_registry_root`. The `role_registry_root`/`epoch` fields described
above remain in the 75B state (§3) and are carried-forward-and-continuity-enforced into every
successor (TRANSFER/FREEZE already implement/enforce this), but for the initial Live they are **not
verified** against the baked keys. They are reserved for a post-Live root-verification robustness
upgrade (see "Deferred to post-Live robustness upgrade", below) that will enable
rotate-without-remint. Under this decision, key rotation for the initial Live means **redeploying a
fresh covenant with the new baked keys and MIGRATE-ing coins to it** — not an in-covenant `ROTATE`
spend; see §4/§11 for the (deferred) `ROTATE` branch.

## §2 Role Model

| Role | Key type | Purpose | Can move/redirect funds? |
|---|---|---|---|
| OWNER | per-coin key | holds/authorizes ordinary transfer | yes (co-sign only) |
| OPS | single key (hot) | per-transfer attestation (co-signs TRANSFER) | no — policy gate only |
| FREEZE | single key | set/clear per-coin `frozen_flag` | no |
| SEIZE | **2-of-3** multisig (cold) | force-move a coin to issuer-chosen owner | **yes** |
| MINT | single key (mint-authority's supply key) | authorizes MINT in the separate mint-authority contract (§9) + authorizes BURN (issuer side) in this covenant | no (burn is destructive, not redirective; mint issues new coins in its own contract) |
| ROTATE | **3-of-5** multisig (cold) | rewrite `role_registry_root` (rotate any/all keys) | **yes** (re-keys everything) |

`role_registry_root = Blake3(OPS_pk(32) || FREEZE_pk(32) || SEIZE_multisig_commit(32) || MINT_pk(32) || ROTATE_multisig_commit(32) || epoch(4))`

**Initial-Live status (Decision 2026-07-19, option B):** the role keys above (OPS, FREEZE, SEIZE,
MINT) are baked as bytecode literals in the covenant body for the initial Live —
`role_registry_root` is carried in state but NOT verified against these keys (see §1, §3, §6, and
"Deferred to post-Live robustness upgrade", below). **ROTATE (3-of-5) is deferred to post-Live**;
only **SEIZE (2-of-3) is implemented now** for the initial Live.

Rationale for multisig on SEIZE + ROTATE only: they are the *only* paths that move/redirect funds or
re-key the whole system. A single compromised OPS, FREEZE, or MINT key is **policy-only** damage
(can block/allow transfers, freeze accounts, or halt burns) — it cannot redirect value. This keeps
the hot-key attack surface (OPS, needed on every transfer) cheap to operate while keeping the two
fund-moving/master-key paths behind cold multisig (2-of-3 for SEIZE, 3-of-5 for ROTATE).

## §3 State Layout (byte map)

Extends case-A's 35B `Kcc20StateHeader` framing (`body.rs:118`, `Kcc20StateHeader::SCRIPT_ENCODED_LEN
= 35`: `OpData32(0x20) || owner_pubkey(32) || OpData1(0x01) || identifier_type(1)`).

New mutable-state fields are appended after the existing 35B header, each framed with its own
push-opcode (matching the existing `OpDataN` convention — a literal push opcode sized to the field,
no length-prefix byte beyond the opcode itself):

| Offset | Push opcode | Field | Width | Notes |
|---|---|---|---|---|
| 0 | `0x20` (OpData32) | `owner_pubkey` | 32B | case-A, unchanged |
| 33 | `0x01` (OpData1) | `identifier_type` | 1B | case-A, unchanged |
| 35 | `0x20` (OpData32) | `role_registry_root` | 32B | **new** — Blake3 commitment, §2 |
| 68 | `0x01` (OpData1) | `frozen_flag` | 1B | **new** — 0x00/0x01 |
| 70 | `0x04` (OpData4) | `epoch` | 4B, LE | **new** — monotonic, bumped by ROTATE |

**Initial-Live note (Decision 2026-07-19, option B):** `role_registry_root` and `epoch` remain in
this 75B layout and are carried-forward-and-continuity-enforced into every successor
(TRANSFER/FREEZE already implement/enforce this), but for the initial Live they are **not
verified** — role keys are baked as bytecode literals in the covenant body instead (§1, §2). These
fields are reserved for a post-Live root-verification robustness upgrade (see "Deferred to post-Live
robustness upgrade", below); no state-layout migration will be needed to add that verification.

Total header: 35 + 33 + 2 + 5 = **75B** (each new field includes its 1-byte push opcode: role_registry_root `0x20`+32, frozen_flag `0x01`+1, epoch `0x04`+4; `STATE_HEADER_LEN` proposed; supersedes
`Kcc20StateHeader::SCRIPT_ENCODED_LEN = 35`). Framing convention (push-opcode immediately preceding
raw payload, no extra length byte) matches `Kcc20StateHeader::encode_script` (`token.rs:76-86`) and
`ISSUER_PUBKEY_RS_OFFSET`'s `0x20`-then-payload pattern (`body.rs:123`,`235`) — new fields follow the
same rule so existing offset-arithmetic idioms (`rs[OFFSET - 1] == push_opcode`) generalize directly.

Body follows immediately at offset 74 (vs. offset 35 in case-A).

## §4 Body = op_type Dispatch

Reuse `build_dispatch_skeleton`'s shape (`dispatch.rs:156-186`: roll tag to top, `DUP`/compare/`IF`/
`ELSE`/`ENDIF`), generalized from the current 2-branch (`transfer` / `transfer_delegator`) tag compare
to a **6-way `op_type` discriminant byte** dispatch — TRANSFER/FREEZE/SEIZE/BURN/ROTATE/MIGRATE
(single-byte compare via `OpData1`+`OpEqual` chains, or a nested nested-`IF` nested-`IF` nested-`IF`
cascade — same mechanical shape, wider). `op_type` `0x04` is reserved and unused in this dispatch —
MINT lives in a separate mint-authority contract (§9).

**Initial-Live dispatch arity (Decision 2026-07-19, option B):** of the 6 designed branches, the
initial-Live dispatch wires only **5 in-covenant ops** — TRANSFER `0x00` / FREEZE `0x01` / SEIZE
`0x02` / BURN `0x03` / MIGRATE `0x06`. **ROTATE `0x05` is DEFERRED (post-Live); rotation is
redeploy+MIGRATE for now** (it needs root-verification to be meaningful under baked keys — see
"Deferred to post-Live robustness upgrade", below), and MINT `0x04` remains reserved and is not an
in-covenant op for the initial Live either (§9). Both are absent from the initial-Live dispatch
skeleton.

**Cross-branch invariant — successor native-value continuity (security fix, 2026-07-19).** Branches
without an owner `SIGHASH_ALL` signature (FREEZE `0x01`, SEIZE `0x02`, ROTATE `0x05`) MUST enforce
**successor-covenant-output native-value == input native-value** on-chain (exact equality — a 1:1
covenant; the tx fee must come from a separate funding input, never by shaving the covenant coin).
Owner-signed branches (TRANSFER `0x00`, BURN `0x03` (canonical-sink successor, not a value-carrying
one), MIGRATE `0x06`) inherit this "for free": `SIGHASH_ALL` commits the whole transaction, including
every output's amount, so the owner's signature alone already pins it. A branch authorized only by
some OTHER role's `OpCheckSigFromStack` attestation signs a fixed-format message, not the whole
transaction, so without an explicit on-chain check a holder of only that (lower-privileged) role's key
could alter the coin's native value while exercising the branch — exactly the value-continuity hole
found and fixed in FREEZE (`core/src/contract/stablecoin/body.rs`'s `build_freeze_branch`): FREEZE's
attestation preimage includes the CURRENT input amount as a replay-binding field, but nothing compared
it against the successor OUTPUT's actual value. The fix is the reusable helper
`dr_value_continuity_check` (`core/src/contract/dr.rs`) — `OpTxInputIndex OpTxInputAmount` vs.
`OpTxInputIndex OpTxOutputAmount` (index reused per the existing 1:1 successor-binding convention),
`OpEqual OpVerify`; zero net stack effect, no depth argument, so it can be spliced into SEIZE and
ROTATE's bodies (when implemented) exactly as it was into FREEZE's.

Common attestation preimage (extends case-A's `attestation.rs:18-27` 116B layout with an op-type tag
and epoch, both bound into the signed message so a rotated/revoked key or wrong-branch attestation is
rejected — see §6):

```text
DOMAIN_TAG(8) || covenant_id(32) || op_type(1) || epoch(4,LE) || outpoint_txid(32)
  || outpoint_index(4,LE) || successor_spk_hash(32) || amount(8,LE) || <op-specific fields>
```

Base preimage (before op-specific fields): 8+32+1+4+32+4+32+8 = **121B** (vs. case-A's 116B — adds
`op_type(1)` + `epoch(4)`).

### Branch table

| op_type | Name | Authorization | Op-specific preimage fields | Effect |
|---|---|---|---|---|
| `0x00` | TRANSFER | OWNER `OpCheckSigVerify` + OPS `OpCheckSigFromStack` | none | 1:1 native-value move; successor carries identical `role_registry_root`+`epoch` |
| `0x01` | FREEZE | FREEZE `OpCheckSigFromStack` only (no owner sig) | `new_frozen_flag(1)` | successor `frozen_flag` set 0/1 |
| `0x02` | SEIZE | SEIZE `OpCheckMultiSig` (**2-of-3**), no owner sig | `new_owner_pubkey(32)` | forced move to issuer-chosen owner |
| `0x03` | BURN | OWNER `OpCheckSigVerify` + MINT-role (mint-authority's supply key) `OpCheckSigFromStack` | none (successor pinned to sink) | successor = canonical unspendable sink; sompi destroyed |
| `0x04` | *(reserved — not used by this covenant)* | — | — | MINT lives in a separate, self-continuing mint-authority contract (§9); it emits UTXOs paying to this covenant's P2SH, it does not spend a holder's coin |
| `0x05` | ROTATE — **DEFERRED (post-Live); rotation is redeploy+MIGRATE for now** | ROTATE `OpCheckMultiSig` (**3-of-5**) only | `new_role_registry_root(32)` | successor root = new value, `epoch += 1`; `owner_pubkey`/`amount` reconstructed from own immutable state (not attacker-suppliable) — **not wired in the initial-Live dispatch** |
| `0x06` | MIGRATE | OWNER `OpCheckSigVerify` + (ROTATE or OPS) attestation | `new_template_hash(32)` | coin moves to new redeem-script template |

### Per-branch opcode-sequence sketches

Pseudo-asm, following `body.rs`'s naming convention (`OpTxInputIndex` prefixing every introspection
op — the replay-binding discipline pinned by `body.rs:314-330`'s
`body_uses_input_index_for_every_introspection` test — carried into every branch below).

**0x00 TRANSFER**
```text
OpDrop                                    ; drop identifier_type
OpCheckSigVerify                          ; owner_pubkey x owner_sig (SIGHASH_ALL)
<state-carry check>
  OpTxInputIndex OpTxOutputSpk            ; successor SPK
  <slice role_registry_root+epoch bytes>  ; offset 35..74 of successor state
  OpTxInputIndex <own state role_registry_root+epoch>
  OpEqual OpVerify                        ; successor must carry same root+epoch
<frozen check>
  <own state frozen_flag> Op0 OpEqual OpVerify   ; frozen_flag == 0
<attestation build>                       ; DOMAIN_TAG||covenant_id||op_type||epoch||
                                           ; outpoint_txid||outpoint_index||successor_spk_hash||amount
  OpBlake3                                ; msg_hash
  <OPS pubkey>
  OpCheckSigFromStack OpVerify
Op1
```

**0x01 FREEZE**
```text
OpDrop                                    ; drop identifier_type (no owner sig at all)
<attestation build incl. new_frozen_flag>
  OpBlake3
  <FREEZE pubkey>
  OpCheckSigFromStack OpVerify
<successor check> new_frozen_flag == successor.frozen_flag  OpEqual OpVerify
Op1
```

**0x02 SEIZE**
```text
OpDrop
<attestation build incl. new_owner_pubkey>
  OpBlake3
  <SEIZE 2-of-3 pubkeys/threshold>
  OpCheckMultiSig OpVerify
<successor check> successor.owner_pubkey == new_owner_pubkey  OpEqual OpVerify
Op1
```

**0x03 BURN**
```text
OpDrop
OpCheckSigVerify                          ; owner consents to burn
<attestation build>
  OpBlake3
  <MINT pubkey>
  OpCheckSigFromStack OpVerify
<sink pin> OpTxInputIndex OpTxOutputSpk <canonical sink SPK bytes> OpEqual OpVerify
Op1
```

**0x04 MINT** (in the separate mint-authority cell, not this covenant's dispatch — see §9)
```text
<self-continuation authorization: MINT pubkey>
  OpCheckSigFromStack OpVerify
<supply check>
  <own state running_supply> <mint_amount from attestation> OpAdd
  <compare to successor running_supply>  OpEqual OpVerify
  <compare to SUPPLY_CAP>  OpLessThanOrEqual OpVerify
Op1
```

**0x05 ROTATE**
```text
OpDrop
<attestation build incl. new_role_registry_root>
  OpBlake3
  <ROTATE 3-of-5 pubkeys/threshold>
  OpCheckMultiSig OpVerify
<successor checks>
  successor.role_registry_root == new_role_registry_root   OpEqual OpVerify
  successor.epoch == own.epoch + 1                         OpEqual OpVerify
  successor.owner_pubkey == own.owner_pubkey                OpEqual OpVerify   ; not attacker-suppliable
  successor.amount == own.amount (native value carried)     OpEqual OpVerify
Op1
```

**0x06 MIGRATE**
```text
OpDrop
OpCheckSigVerify                          ; owner consents to template migration
<attestation build incl. new_template_hash>
  OpBlake3
  <ROTATE-or-OPS pubkey>
  OpCheckSigFromStack OpVerify
<successor-template authentication — reuses dr.rs>
  dr_input_spk_check(self_rs_depth)       ; this input's own committed P2SH hash, dr.rs:41
  dr_suffix_check(old_rs_depth, new_rs_depth, begin)   ; new template shares required suffix, dr.rs:125
  dr_output_spk_check(new_rs_depth, output_idx_depth)  ; claimed output slot is really locked to it, dr.rs:70
Op1
```

### Per-branch detail

**0x00 TRANSFER** — mirrors case-A (`body.rs` stage 1 + stage 2) exactly, plus:
- Invariant (new): `frozen_flag == 0`, enforced with `OpVerify` before the attestation check —
  fail-closed if frozen.
- Invariant (new): successor state's `role_registry_root` and `epoch` bytes, reconstructed on-chain
  via `OpTxOutputSpk` + offset-slice + `OpBlake3`-compare (reusing the successor-reconstruction
  pattern at `body.rs:154-159`), must equal this coin's own current values — i.e. an ordinary
  transfer cannot smuggle a role-registry or epoch change.

**0x01 FREEZE** — no owner signature at all; FREEZE key alone gates it. `new_frozen_flag` is an
op-specific preimage field so the issuer's signature commits to *which* value (0 or 1) is being set,
preventing a captured freeze-attestation from being replayed to toggle the opposite state. Because
there is no owner `SIGHASH_ALL` signature to pin output amounts, this branch also enforces the §4
cross-branch value-continuity invariant via `dr_value_continuity_check` — see §11 (v).

**0x02 SEIZE** — no owner signature, no registry read beyond this coin's own state (per-coin,
concurrency-free — no cross-coin lag, unlike a hypothetical registry-based ban-list). `new_owner_pubkey`
is signed by the SEIZE 2-of-3 quorum, so a forced move always requires fresh multisig consent per
seizure.

**0x03 BURN** — owner must consent (`OpCheckSigVerify`) in addition to the mint-authority's supply key
attestation (MINT role, `OpCheckSigFromStack`; burn is the supply-down counterpart of mint, gated by
the same authority that governs issuance in the separate mint-authority contract, §9). Successor SPK
is pinned to a canonical unspendable sink script (not attacker-suppliable) — `OpVerify`'d equal, so a
burn cannot be redirected to a spendable output.

**0x04 — reserved, not used by this covenant.** MINT is authorized entirely inside a *separate*,
low-frequency, self-continuing mint-authority contract (see §9; reuses the existing `token_mint`
self-continuation/admin pattern, `core/src/contract/token.rs:164-238`), not by a per-coin attestation
against this covenant. It issues new coins by emitting UTXOs paying to *this* covenant's P2SH — it
never spends an existing holder's coin, so this covenant's dispatch never branches on `0x04`.

**0x05 ROTATE** — no owner signature; ROTATE 3-of-5 quorum alone. Critically, `owner_pubkey` and `amount` in
the successor are reconstructed from *this coin's own current immutable/mutable state* (via
introspection), not read from attacker-suppliable sigscript data or output fields — so a ROTATE spend
cannot be used to also silently change ownership or value; it is scoped to exactly
`role_registry_root` + `epoch`.

**0x06 MIGRATE** — reuses `dr_input_spk_check`/`dr_suffix_check`/`dr_output_spk_check`
(`dr.rs:41,70,125`, invoked in `transfer.rs:356,462-463`) to authenticate that the successor really is
locked to the *new* template (self-hash check against the claimed new redeem script, then
suffix/output-slot checks) — the same successor-template-authentication discipline
`kcc20::transfer` uses for its dynamic-redeem-script (DR) successor construction. Effect: forward
upgrade path (new body/state layout) without forcing holders to abandon the token.

## §5 Attestation Message Formats

All messages are `Blake3(preimage)`; preimage is the common 121B prefix (§4) plus the op-specific
tail below.

| op_type | Preimage tail (appended after amount(8)) | Total preimage len |
|---|---|---|
| 0x00 TRANSFER | *(none)* | 121B |
| 0x01 FREEZE | `new_frozen_flag(1)` | 122B |
| 0x02 SEIZE | `new_owner_pubkey(32)` | 153B |
| 0x03 BURN | *(none — sink pinned structurally, not via preimage)* | 121B |
| 0x04 MINT *(separate mint-authority contract, §9 — not part of this covenant)* | `mint_amount(8,LE) \|\| new_running_supply(8,LE)` | 137B |
| 0x05 ROTATE | `new_role_registry_root(32)` | 153B |
| 0x06 MIGRATE | `new_template_hash(32)` | 153B |

All multi-byte numeric fields: little-endian, matching the engine's `OpNum2Bin` output convention
(`attestation.rs:39-43`) and the existing domain caps (`outpoint_index < 2^31`, amounts `< 2^63`,
`attestation.rs:75-81`).

## §6 Rotation & Epoch / Replay Protection

**Initial-Live status (Decision 2026-07-19, option B):** the mechanism described below is the
post-Live root-verification design, once `ROTATE` is implemented and role keys are verified against
`role_registry_root`. For the initial Live, `ROTATE` is deferred (§4, §11) and role keys are baked,
not verified against `role_registry_root`/`epoch` — so key rotation for the initial Live is
**redeploy + MIGRATE** (a fresh covenant with the new baked keys, existing coins MIGRATE-d across),
not an in-covenant spend. `role_registry_root`/`epoch` continue to be
carried-forward-and-continuity-enforced (§1, §3) so this upgrade path remains open without a
state-layout change.

- `ROTATE` increments `epoch` and writes a new `role_registry_root` into the successor.
- `op_type` + `epoch` are both inside every signed message (§4/§5) ⇒ a revoked key's old-epoch
  attestations are rejected on any coin that has since been rotated (the on-chain reconstruction
  reads the coin's *current* `epoch`/root from its own state, so a stale attestation signed under the
  old epoch fails the `OpCheckSigFromStack`/`OpBlake3` comparison).
- Outpoint binding (`covenant_id`+`outpoint_txid`+`outpoint_index`, unchanged from case-A) ⇒ one-shot
  per spend, same as today.
- `op_type` inside the message ⇒ no cross-branch replay (a FREEZE attestation cannot be replayed as a
  TRANSFER attestation, etc.) — mirrors the adversarial-test intent of
  `cross_token_attestation_rejected` (`stablecoin_contracts.rs:353`) generalized across branches.

**Honest limitation**: there is no reference-input/registry mechanism (would require e.g. a
consensus-level indexed lookup akin to `consensus/core/src/tx.rs`'s input model extended with
external state reads) ⇒ **no instant GLOBAL key revocation**. A revoked key remains valid on any coin
that has not yet been individually touched/rotated — this is a **per-coin lag**, not a global
switch.

**Mitigation**:
- *Global* pause: withhold OPS attestations entirely. Since every TRANSFER requires a fresh OPS
  signature, this is instant and total (doubles as a free global kill-switch for transfers — see
  §11(i),(iv)). **This is the resolved position — no on-chain global-pause flag is added** (§11(iv),
  Resolved Decisions).
- *Targeted* per-account pause: `FREEZE` branch, instant for that one coin.

## §7 Seize / Rescue

`SEIZE` (§4, 0x02) doubles as both punitive seizure and user-rescue (e.g. lost-key recovery):
`new_owner_pubkey` is simply set to the recovery address. No structural distinction between
"seizure" and "rescue" on-chain — the distinction is policy, decided off-chain by whoever controls
the SEIZE 2-of-3 quorum before it signs.

## §8 Burn / Redemption

On-chain burn is the `BURN` branch (§4, 0x03): native sompi is destroyed by pinning the successor to
an unspendable sink. The fiat-redemption leg (issuer wiring fiat out to the redeemer) is **off-chain**
and out of this covenant's scope — see GAP §4.2-C (referenced tracking doc) for the redemption
workflow this on-chain burn is one half of.

## §9 Mint + Supply Cap

**RESOLVED 2026-07-19: MINT is a fully separate, self-continuing mint-authority contract — a
per-token-series singleton — not a branch of this transfer covenant's `op_type` dispatch.** Supply
model: **raisable cap (elastic, issuer-first)** — see Resolved Decisions (e). Exactly one
mint-authority contract instance exists per deployed stablecoin token series, and exactly one
newly-minted stablecoin coin is emitted per MINT spend (no batch/multi-recipient mints).

**Mutable state.** The mint-authority contract carries exactly two mutable state fields:

| Field | Width | Notes |
|---|---|---|
| `running_supply` | 8B, LE | monotonic, issued-only counter; `+= mint_amount` on every MINT (see Deferred (d) for the net-vs-gross-supply limitation this implies) |
| `current_cap` | 8B, LE | **mutable, raisable only** — `RAISE_CAP` may increase it (`new_cap > current_cap`); nothing ever decreases it |

**Baked constants (option B, per Resolved Decisions (d)).** Consistent with this covenant's own
option-B decision, the mint-authority body bakes its authority keys as bytecode literals rather than
a verified registry root:
- `mint_pubkey` — the hot MINT-role key. This is the SAME key referenced throughout as the "MINT
  role" in §2's role table and as the BURN-branch attestor in §4/§8 — one key, two authorized uses
  spanning the two contracts.
- `cap_authority` — a cold **2-of-3** multisig commit (3 pubkeys + threshold), structurally identical
  in strength to this covenant's SEIZE quorum (§2, §11-iii's "cold multisig for fund-moving/master-key
  roles" principle, applied here to the cap ceiling instead of fund redirection).
- The full set of **covenant role constants** needed to reconstruct a freshly-minted coin's redeem
  script byte-for-byte: this covenant's `OPS_pk`, `FREEZE_pk`, `SEIZE_multisig_commit`, `MINT_pk`,
  `ROTATE_multisig_commit` (or, equivalently, the precomputed `role_registry_root = Blake3(...)`
  digest over them with `epoch = 0`, since both are static for a given deployment), plus this
  covenant's full body-template bytes (§4, ~500–700B dispatch) — see "Anti-backdoor reconstruction,"
  below.

**Two operations (mini op_type dispatch).** Structurally a 2-way selector — the same shape as
`TOKEN_MINT_BODY`'s `Op1 OpRoll ... OpIf/OpElse` (`core/src/contract/token.rs:164-186`), but with real
state-mutating logic in each branch instead of TOKEN_MINT's flat admin-only branches:

- **MINT** (authorized by hot `mint_pubkey`): self-continue with
  `new_running_supply = old_running_supply + mint_amount`; `OpVerify(new_running_supply <=
  current_cap)`; successor `current_cap` unchanged; emit exactly one shape-verified stablecoin coin to
  the attested recipient (`output[1]`), whose native value == `mint_amount`.
- **RAISE_CAP** (authorized by cold **2-of-3** `cap_authority`): self-continue with
  `current_cap' = new_cap` where `OpVerify(new_cap > current_cap)`; `running_supply` unchanged in the
  successor; no coin emitted (self-continuation output only).

**The cap is a genuine safety bound, not a policy suggestion.** Because MINT enforces
`running_supply <= current_cap` against the coin's own CURRENT state and cannot itself write a new
`current_cap`, a compromised hot `mint_pubkey` — the highest-frequency, lowest-assurance key in the
whole system — can mint up to the existing ceiling and no further. Only the cold 2-of-3
`cap_authority` quorum can move that ceiling. This mirrors this covenant's SEIZE/ROTATE-vs-hot-key
trust model (§11, "Why an issuer should still be comfortable...") one level down: a stolen hot key
here is bounded damage, never unbounded issuance.

**Recipient-binding security fix (closes a gap in the earlier §9 draft).** The earlier draft of this
section (and §5's `0x04 MINT` preimage-tail row, cross-referenced there as belonging to this
contract's own attestation set, not the covenant's) specified a MINT attestation preimage tail of only
`mint_amount(8,LE) || new_running_supply(8,LE)` — nothing in the signed message bound *who receives*
the newly-minted coin. A validly-signed MINT attestation could therefore have been replayed into a
transaction paying the new coin to an attacker-chosen recipient instead of the intended one (a
redirection attack, structurally the same kind of hole as the FREEZE value-continuity gap found and
fixed in §11(v), just on the mint side rather than the value side). **Fixed**: the mint-authority's
own attestation preimage now explicitly binds the recipient:

```text
DOMAIN_TAG_MINT(8) || covenant_id(32) || outpoint_txid(32) || outpoint_index(4,LE)
  || mint_amount(8,LE) || new_running_supply(8,LE) || recipient_spk_hash(32)
```

124B total. `DOMAIN_TAG_MINT` is a **distinct domain tag** from this covenant's own `DOMAIN_TAG`
(§4/§5) — the two contracts must never accept each other's attestations, even incidentally, so the
tags are chosen to differ. `covenant_id` here is the mint-authority contract's own id (self-replay
domain separation, the same discipline as this covenant's own `covenant_id` field). `RAISE_CAP`'s
attestation preimage follows the same prefix with a `new_cap(8,LE)` tail in place of the MINT-specific
fields (`DOMAIN_TAG_MINT || covenant_id || outpoint_txid || outpoint_index || new_cap(8,LE)`, 84B
total) — no recipient field is needed since `RAISE_CAP` never emits a coin. Cross-op replay is
structurally impossible regardless, since MINT and RAISE_CAP are authorized by entirely different keys
(`mint_pubkey` vs. the `cap_authority` quorum) and neither attestation shape can satisfy the other op's
signature check.

**Anti-backdoor reconstruction.** The mint-authority contract does not trust the sigscript for
anything about the emitted coin's *shape* — only its recipient and amount. On every MINT spend, the
body reconstructs the entire emitted coin's redeem script on-chain: `state_header || body`, where
`state_header` = the baked push-opcode framing (§3) + `owner_pubkey = recipient_pubkey` (the one
sigscript-supplied field) + baked `identifier_type` + baked `role_registry_root` (from the baked role
constants, above) + baked `frozen_flag = 0x00` + baked `epoch = 0x00000000`, and `body` = the baked
covenant body-template bytes (§4) — byte-identical for every coin ever minted in this series. It
Blake3-hashes the assembled redeem script, wraps it in the P2SH template, and `OpEqualVerify`s the
result against `output[1].spk`. **The signer's only discretion is `recipient_pubkey` (via sigscript)
and `mint_amount` (the coin's native UTXO value, per the existing KCC20 amount-as-native-value
convention, `token.rs`'s `Kcc20StateHeader` decision note) — every other byte of the minted coin is
either a baked constant or independently on-chain-derived.** A compromised `mint_pubkey` cannot mint a
coin with a forged `frozen_flag`, a non-zero starting `epoch`, a different role registry, or a
different body — only a legitimate coin to an address of the attacker's choosing, up to the cap.

**Genesis-binding fix (closes a CRITICAL audit finding — unbounded parallel-authority minting,
2026-07-19).** Baked keys (option B, above) are, definitionally, *public* bytecode literals — anyone
can read `mint_pubkey`/`cap_authority` out of the deployed script and bake the identical keys into a
brand-new, self-funded mint-authority instance of their own. Without a further check, that fake
instance would pass every rule described above (shape reconstruction, recipient-binding, cap
enforcement) using the SAME keys, producing coins indistinguishable on their face from the legitimate
authority's output — an unbounded parallel-authority minting hole. **Fixed**: the mint-authority body
additionally bakes the deployment's own genesis `covenant_id` — call it `G`, the consensus-tracked id
fixed once, at genesis, and unique per deployed instance (distinct from any individual stablecoin
coin's own `covenant_id`, §4/§9's attestation fields) — as a literal, and both MINT and RAISE_CAP now
enforce `OpTxInputIndex OpInputCovenantId <baked G> OpEqualVerify` before doing anything else. A fake
parallel authority baking the same public `mint_pubkey`/`cap_authority` still gets its OWN distinct,
consensus-assigned `covenant_id` at its own genesis (an outpoint it does not and cannot share with the
real deployment) — it cannot forge `G` to match — so its spends fail this check and it can never mint
a coin traceable to the real authority. `covenant_id` propagates unchanged through every
self-continuation spend (verified in consensus code, not merely this contract's own logic), so `G`
stays pinned to the one legitimate instance for its entire lifetime.

**Deploy consequence: two-transaction bootstrap.** `G` cannot be derived from the same script it is
baked into — a literal that is a hash of the script containing that literal is a hash fixed-point, not
directly constructible. Deployment is therefore two transactions: **TX1** fixes `G` by creating a
covenant-tagged anchor output (establishing the genesis `covenant_id` on-chain, without yet baking any
`G`-literal into it); **TX2** creates the real mint-authority body with `G` baked in, declared as a
continuation of TX1's anchor so consensus assigns it the same `covenant_id` `G` rather than minting a
fresh, unrelated one. Only once TX2 confirms is the mint-authority contract live and mintable under
its bound genesis.

**Self-continuation lineage.** The mint-authority's self-continuation is deliberately NOT
`token.rs`'s `TOKEN_MINT_BODY` (`core/src/contract/token.rs:164-238`) pattern: TOKEN_MINT carries no
mutable per-spend state at all (only a baked `admin_pk`), so its self-continuation is a single flat
`output[0].spk == input.spk` check with nothing to reconstruct — too weak for a contract with mutable
supply/cap fields. This contract has two mutable fields that change on every spend (`running_supply`,
`current_cap`), so it needs the same **D&R (Destroy & Recreate)** discipline
`core/src/contract/spot/dca.rs` uses for its own mutable fields (`next_execution_daa`,
`periods_remaining`) — reusing the composable helpers in `core/src/contract/dr.rs`:
`dr_input_spk_check` (`dr.rs:43`, this input's own SPK really is `P2SH(old_rs)`), prefix/suffix checks
over the baked-constant region (`dr_prefix_check`/`dr_suffix_check`, `dr.rs:100,127`, mirroring
`dca.rs`'s 136B-locked-prefix / 153B-suffix split, generalized to this contract's own boundary), and
`dr_output_spk_check` (`dr.rs:72`, the successor really is locked to `new_rs`) — before independently
re-deriving `new_running_supply`/`new_current_cap` from old state + attested deltas, exactly as this
covenant's own ROTATE branch (§4, 0x05) re-derives its successor fields rather than trusting
attacker-suppliable output data.

**BURN stays in this covenant.** Unchanged from the earlier draft: BURN (0x03, §4/§8) is authorized by
OWNER + the same `mint_pubkey`/MINT-role key via `OpCheckSigFromStack`, executed entirely inside *this*
covenant, not the mint-authority contract — only issuance (MINT) and the cap ceiling (RAISE_CAP) are
fully external. See Deferred (d) for why BURN does not, and structurally cannot, decrement the
mint-authority's `running_supply`.

## §10 DEX-Escrow Safety — KNOWN LIMITATION, NOT YET IMPLEMENTED (audit finding, 2026-07-19)

**Status: proposed design, zero integration today.** A grep of `engine/`, `domain/`, `settle/`, and
`core/src/contract/spot/` finds no reference to any issuer-authority/seize descriptor from any spot
order type — KOB's spot covenant does not read, reject, or hedge on stablecoin issuer-authority state
in any form. An earlier draft of this section stated in the present tense that the spot covenant
"consumes this descriptor to statically reject or hedge seize-capable collateral"; that was an
overclaim and is corrected here: **no such consumption exists in the codebase.**

The proposed (still-unimplemented) design is to standardize a **coin descriptor** (metadata, not new
opcodes) that declares:
- issuer-authority present (yes/no, and which roles),
- seize-capability present (yes/no).

The intent would be for KOB's spot covenant to consume this descriptor to **statically reject or
hedge** seize-capable collateral at order-placement/escrow time, so that settlement **fails closed**
rather than suffering "silent death on seize."

**Consequence of the current state — risk is UNMITIGATED today.** Composing today's stablecoin
covenant (this design) with today's spot covenants leaves the "silent death on seize" risk fully live:
an escrowed stablecoin leg can be frozen or seized (§4 FREEZE/SEIZE, issuer-side only, no owner
co-sign required) mid-order, with **zero on-chain awareness** on the spot side — the order proceeds as
if the collateral were still good until settlement itself fails. There is no static rejection, no
hedge, and no fail-closed behavior at escrow time. This is a **known limitation**, not a mitigated
risk, for as long as the stablecoin and spot covenants are deployed independently as they are today.
Deferred work: design and wire the descriptor-consumption path described above into the spot covenant
before composing seize-capable stablecoins with DEX escrow in Live. Ties to `KCC20_ISSUES.md`
**ISSUE-15** (successor-binding/descriptor deferral already flagged in case-A, `body.rs:51-59`).

## §11 Kaspa L1 Trust Costs (honest) + Residual Risks

**(i) Issuer-online SPOF.** Every TRANSFER needs a fresh OPS attestation (§1, §4 0x00) — if the
issuer's OPS signer is down, all transfers halt. This is a real availability cost, but it doubles as
a free, instant global pause (§6) — the same mechanism that makes the issuer a SPOF also makes
"withhold signing" a complete kill-switch with no extra code. Mitigate operationally with an
HA/redundant signer setup (multiple online replicas of the same OPS key material, standard HSM/HA
practice) — out of scope for the covenant itself.

**(ii) No instant global revocation.** Per-coin epoch lag (§6): a compromised-but-not-yet-rotated
key stays valid on untouched coins until each is individually rotated or the global OPS-withhold
pause is invoked.

**(iii) ROTATE multisig quorum is the ultimate master key.** It can rewrite every role including
itself. It MUST be cold storage with the strongest quorum in the system — **RESOLVED: 3-of-5**,
strictly stronger than SEIZE's 2-of-3 (Resolved Decisions, below), since ROTATE can also change
SEIZE's own key material.

**(iv) Global kill-switch scope — RESOLVED 2026-07-19.** No formal on-chain global-pause flag is
added. The only global stop is OPS withholding attestations ((i) above, §6) — instant and free, since
every TRANSFER already requires a fresh OPS attestation. A formal on-chain "paused" flag, checked by
every branch, was considered and rejected: with no reference-input mechanism (ii), such a flag would
need either a global state read (reintroducing exactly the per-coin serialization/lag this design
otherwise avoids) or independently-updated per-coin flag state no faster than FREEZE already provides.
Per-account control remains the FREEZE branch (0x01, §4).

**(v) Value continuity in non-owner-signed branches — FOUND + FIXED 2026-07-19.** FREEZE (`0x01`) was
implemented with no on-chain check binding the successor covenant output's native value to the input's:
the FREEZE attestation preimage carries the CURRENT input amount only as a replay-binding field, never
compared against the successor OUTPUT's actual value, and (unlike TRANSFER) there is no owner
`SIGHASH_ALL` signature to pin it "for free". A holder of only the FREEZE key could therefore have
altered the coin's native value while freezing/unfreezing it — value theft/destruction by the
policy-only role the "Why an issuer should still be comfortable" paragraph below assumes is harmless.
Fixed via the reusable `dr_value_continuity_check` helper (§4's cross-branch invariant,
`core/src/contract/dr.rs`), wired into FREEZE's body and regression-tested
(`freeze_successor_reduces_value_rejected` / `freeze_successor_inflates_value_rejected`,
`core/tests/stablecoin_contracts.rs`). **SEIZE (`0x02`) and ROTATE (`0x05`) are not yet implemented and
MUST call the same helper when they are** — the branch table's SEIZE/ROTATE effect column ("forced move
to issuer-chosen owner" / successor root+epoch change) does not by itself pin value either, so this is
not automatically covered by those branches' other planned checks.

**Why an issuer should still be comfortable with this design**: the only paths that can move or
redirect *value* (SEIZE) or re-key *everything* (ROTATE) require cold multisig — 2-of-3 for SEIZE,
3-of-5 for ROTATE — there is no single-key path to fund movement. Compromise of any single
hot/single-key role (OPS, FREEZE, MINT) is **policy-only** damage: an attacker with a stolen OPS key
can approve or block transfers but cannot redirect them (owner must still co-sign, to their own chosen
destination); a stolen FREEZE key can only toggle freeze flags; a stolen MINT key can approve burn (in
this covenant) or mint (in the separate mint-authority contract, §9) but cannot exceed the cap or
divert existing holders' coins. Holders always co-sign their own ordinary transfers (§1) — the issuer
side of TRANSFER is a gate, not a redirect.

## §12 Test Matrix + Delta-from-Case-A

Mirror `core/tests/stablecoin_contracts.rs`'s harness style (`Cfg` struct with per-field overrides →
`build()` → `run()` against the real `TxScriptEngine` with `covenants_enabled = true` →
`assert_rejected_with()` for adversarial cases, `stablecoin_contracts.rs:83-227`). One `Cfg`-like
struct per branch (or one shared struct with an `op_type` field + branch-specific optional overrides),
one happy-path test per branch, then adversarial single-lever mutations.

### Per-branch happy path (6, this covenant)
- `happy_transfer_accepts` (case-A baseline, `frozen_flag == 0`, registry/epoch carried forward).
- `happy_freeze_set_accepts` / `happy_freeze_clear_accepts`.
- `happy_seize_accepts` (2-of-3 quorum signs, `new_owner_pubkey` lands in successor).
- `happy_burn_accepts` (successor == canonical sink).
- `happy_rotate_accepts` (3-of-5 quorum; new root + `epoch+1` land in successor; owner/amount unchanged).
- `happy_migrate_accepts` (successor matches new template, authenticated via `dr_*_check`).

*(`happy_mint_accepts` — running supply increments, stays under cap — belongs to the separate
mint-authority contract's own test suite, §9; it is not part of this covenant's dispatch.)*

### Adversarial matrix (mirrors case-A's existing style: `replay_attestation_for_other_outpoint_rejected`,
`recipient_substitution_rejected`, `amount_tamper_rejected`, `owner_wrong_key_rejected`,
`cross_token_attestation_rejected`, `stablecoin_contracts.rs:297-371`)

| Test | Branch(es) | What it mutates |
|---|---|---|
| `replay_attestation_for_other_outpoint_rejected` | all | reused outpoint across coins (per-branch, generalized) |
| `wrong_key_*_rejected` | all | attestation signed by a non-role key (OPS/FREEZE/SEIZE/MINT/ROTATE impostor) |
| `cross_branch_replay_rejected` | all pairs | valid attestation for op_type X replayed as op_type Y |
| `revoked_epoch_attestation_rejected` | all | attestation signed under a pre-ROTATE epoch, replayed post-rotation |
| `frozen_transfer_rejected` | TRANSFER | `frozen_flag == 1`, otherwise-honest transfer attempt |
| `unfreeze_by_non_freeze_key_rejected` | FREEZE | valid-shaped attestation, wrong signer |
| `seize_without_quorum_rejected` | SEIZE | fewer than 2-of-3 SEIZE signatures |
| `mint_over_cap_rejected`* | mint-authority contract | `new_running_supply > SUPPLY_CAP` |
| `mint_running_supply_tamper_rejected`* | mint-authority contract | signed `new_running_supply` disagrees with `old + mint_amount` |
| `rotate_by_non_rotate_quorum_rejected` | ROTATE | fewer than 3-of-5, or wrong keys entirely |
| `rotate_smuggled_owner_change_rejected` | ROTATE | successor owner/amount diverge from coin's own state |
| `migrate_to_unauthorized_template_rejected` | MIGRATE | `new_template_hash`/successor SPK fails `dr_input_spk_check`/`dr_suffix_check` |
| `burn_to_spendable_successor_rejected` | BURN | successor SPK != canonical sink |
| `transfer_registry_root_tamper_rejected` | TRANSFER | successor `role_registry_root`/`epoch` diverge from current state |

*`mint_over_cap_rejected` / `mint_running_supply_tamper_rejected` exercise the separate
mint-authority contract (§9), tracked in its own test suite — not this covenant's dispatch.*

### Delta from case-A

| Dimension | Case-A | This design |
|---|---|---|
| State size | 35B | 75B (§3) |
| Body size | 68B | ~500–700B (6-way dispatch, `dispatch.rs`-style skeleton generalized) |
| Branches | 1 (transfer/freeze folded into one gate) | 6 in this covenant (`op_type` 0x00–0x03, 0x05–0x06; `0x04` reserved for the separate mint-authority contract, §9) |
| Preimage len | 116B | 121B base + op-specific tail (§5) |
| Files touched | — | `core/src/contract/stablecoin/{body,attestation,mod}.rs` (rewrite), `core/src/contract/stablecoin/dispatch.rs` (new, mirrors `kcc20/dispatch.rs`), CLI subcommands: `freeze`, `seize`, `burn`, `mint` (targets the separate mint-authority contract), `rotate`, `migrate`, `core/tests/stablecoin_contracts.rs` (expand) |
| Est. LOC | — | ~1500–2500 |

---

## Resolved Decisions

**Resolved 2026-07-19.**

**(a) SEIZE / ROTATE quorums.** **SEIZE = 2-of-3**, **ROTATE = 3-of-5** `OpCheckMultiSig` (both cold)
(§2, §4, §11-iii). Rationale: ROTATE is the ultimate re-key master — it can rewrite every role's key
material, including SEIZE's own — so it sits behind a strictly stronger quorum than the fund-moving
role it can also re-key.

**(b) MINT placement.** MINT is a **separate, self-continuing mint-authority contract** (reusing the
existing `token_mint` self-continuation/admin pattern, `core/src/contract/token.rs:164-238`), not a
branch of this covenant's `op_type` dispatch — `0x04` is reserved and unused here (§4, §9). Rationale:
isolates the running-supply counter and cap check from the high-frequency TRANSFER/FREEZE/SEIZE path;
the mint-authority contract emits newly-minted UTXOs paying to this covenant's P2SH. BURN (0x03) stays
in this covenant, authorized by OWNER + the mint-authority's supply key (MINT role) via
`OpCheckSigFromStack`.

**(c) Global kill-switch.** **OPS-withhold only** — no formal on-chain global-pause flag is added
(§6, §11-iv). Rationale: every TRANSFER already requires a fresh OPS attestation, so withholding it is
an instant, free, total pause with no extra code; a formal on-chain flag would need a reference-input
mechanism to be checked by every branch, which reintroduces exactly the per-coin serialization/lag
(§6, §11-ii) this design otherwise avoids. Per-account control remains the FREEZE branch (0x01).

**(d) Key management for initial Live.** **Decision 2026-07-19: option B — baked keys for initial
Live.** Role keys (OPS, FREEZE, SEIZE, MINT) are baked as bytecode literals in the covenant body —
NOT verified against `role_registry_root` — for the initial testnet Live (§1, §2, §3, §6).
`role_registry_root`/`epoch` remain in the 75B state and are carried-forward-and-continuity-enforced
(TRANSFER/FREEZE already implement/enforce this), but reserved, unverified, for a post-Live
root-verification upgrade (see "Deferred to post-Live robustness upgrade", below). Consequence: key
rotation for the initial Live is **redeploy + MIGRATE** (fresh covenant with new baked keys, coins
MIGRATE-d across) — an explicit, intentional, documented limitation, not an in-covenant op. `ROTATE`
(`0x05`, 3-of-5) is therefore **deferred to post-Live** (§4, §11); `SEIZE` (`0x02`, 2-of-3) is
implemented now.

**(e) Supply model + mint-authority security.** **Resolved 2026-07-19.** Supply model is a
**raisable cap — elastic, issuer-first**: `current_cap` (§9) is mutable and may only be *raised*
(`new_cap > current_cap`), never lowered, and only by the cold **2-of-3 `cap_authority`** multisig via
the `RAISE_CAP` op (§9) — the hot `mint_pubkey` can mint under the cap but can never move the cap
itself. Also resolved: the mint-authority's attestation preimage now explicitly binds
`recipient_spk_hash` (§9), closing a redirection gap in the earlier §9 draft, where the signed message
covered only `mint_amount || new_running_supply` and a valid attestation could have been replayed
against a different recipient.

## Deferred to post-Live robustness upgrade

The following are explicitly out of scope for the initial testnet Live (Decision 2026-07-19, option
B, above) and deferred to a later robustness upgrade:

- **(a) `role_registry_root` verification.** Reveal the role keys per spend and Blake3-check them
  against the state's committed `role_registry_root`, in place of today's baked-literal keys. This is
  what enables **rotate-without-remint**: a `ROTATE` spend could then rewrite the root and have every
  subsequent spend verify against the new keys, instead of requiring a fresh covenant deployment.
- **(b) The `ROTATE` branch (`op_type 0x05`).** Deferred along with (a), since `ROTATE` only becomes
  meaningful once role keys are verified against `role_registry_root` rather than baked — rotating a
  baked key requires redeploying the covenant, not writing a new root (§4, §11).
- **(c) Cost rationale.** Root-verification was costed at roughly **160B of extra sigscript per
  transfer** (reveal + compare of role pubkeys against the committed root on every spend); deferring
  it keeps the initial-Live hot path (TRANSFER) light. This was the deciding factor for option B over
  verifying the root from the start.

No state-layout migration is required to add this upgrade later: the state already carries
`role_registry_root` and `epoch` (§3), carried-forward-and-continuity-enforced end-to-end since the
initial Live — the upgrade only changes what the covenant body *checks* against those already-present
bytes, not their layout or presence.

Also deferred, orthogonal to the above (mint-authority side, §9):

- **(d) Net/circulating supply accounting.** `running_supply` (§9) is monotonic and issued-only — it
  counts total minted, never decremented. BURN (`0x03`, §4/§8) executes entirely inside *this*
  covenant and destroys sompi there; it does NOT, and structurally CANNOT, decrement the
  mint-authority contract's `running_supply`, because the two contracts share no on-chain state —
  Kaspa has no reference-input mechanism (§6), so the mint-authority contract has no way to observe an
  unrelated transaction's BURN spend happening elsewhere. Consequence: `running_supply`/`current_cap`
  bound *gross issuance*, not net/circulating supply; true net supply (`running_supply` minus
  cumulative burns) is not tracked on-chain anywhere today and must be reconstructed off-chain (e.g. by
  indexing all BURN outputs to the canonical sink). A future robustness upgrade could add a
  burn-receipt mechanism (e.g. BURN emits a canonical receipt the mint-authority side periodically
  consumes to reconcile `running_supply` downward, or a shared/committed net-supply oracle) — deferred;
  **known limitation for the initial Live**.

- **(e) Coin-level provenance ("is this specific coin authority-issued?").** Under the amount =
  native-sompi model (§9, following `token.rs`'s `Kcc20StateHeader` convention), a coin an attacker
  self-funds directly at the stablecoin covenant's P2SH — the role keys are baked, public bytecode
  literals (§1, §2, option B), so anyone can compute the same P2SH and pay their own real KAS into it —
  is **ON-CHAIN INDISTINGUISHABLE** from a coin legitimately emitted by a MINT spend. Stablecoin coins
  carry no shared, coin-level on-chain class identifier: each MINT output gets its own fresh genesis
  `covenant_id`, exactly as a self-funded lookalike coin would get its own fresh genesis `covenant_id`
  simply by existing as a new UTXO — there is no bit pattern that says "issued by the authority" versus
  "self-funded," because the covenant script itself is, by design, byte-identical either way (§9's
  anti-backdoor reconstruction). Consequences:
  - `running_supply` (§9, mint-authority) counts only supply that actually passed through a MINT spend
    of the mint-authority contract — it says nothing about, and cannot observe, coins funded directly at
    the covenant's P2SH outside the mint-authority contract entirely. It is **not** a total-coins-in-
    existence counter.
  - Coin provenance — "was this specific coin actually MINT-issued?" — is inherently an **OFF-CHAIN /
    INDEXER responsibility**, not something decidable by the covenant at spend time: an indexer must
    trace the pinned-genesis mint-authority contract's own lineage (from its bound `G`, above) and
    record each of *its* MINT tx's emitted output as known-good; any coin at the P2SH not reachable from
    that lineage is not authority-issued, however identical its script and state layout.
  - Within the amount = native-sompi model this is **not a peg attack**: a self-funded coin is backed
    1:1 by its own locked KAS (the funder's own real sompi, not fabricated value) and remains fully
    issuer-governable exactly like any other coin at this P2SH — FREEZE/SEIZE apply to it identically,
    since those branches authorize on role keys and per-coin state, not on provenance. It is a
    bookkeeping/classification gap (which coins count as "the stablecoin, as issued by us"), not a
    value-forgery or inflation gap.
  - **Considered and REJECTED**: baking the mint-authority's genesis `covenant_id` `G` (above) into
    every minted coin's own state, so a coin could self-report its issuing authority on-chain. Rejected
    because `G`, like the role keys, would be a public baked value readable out of any real coin's
    script — a self-funder could simply copy the same `G` bytes into their own self-funded lookalike,
    reproducing an identical coin. This has **zero security value**: it does not change who *can*
    produce the byte pattern, it only makes the fake coin look more convincing.

