//! KCC-0020 stablecoin — Plan A ("native-value") covenant, WU-A.
//!
//! # What this module is
//!
//! This is the implementation seed for the KCC-0020 stablecoin, **Plan A**
//! (the "reduced / ease-of-adoption" design recorded in the integrated
//! evaluation memo). Its single covenant "kind" is an **issuer-attestation-
//! gated native-value transfer**: a token-holding UTXO whose spend requires
//! BOTH the owner's authorization AND a fresh, per-spend cryptographic
//! attestation from the token issuer. That attestation gate is the on-chain
//! realization of a stablecoin *freeze* control (Liquid AMP-style: the issuer
//! is a mandatory co-signer of every move), without any seize path.
//!
//! # KCC-0020 `amount` mapping — the native-value deviation (stated plainly)
//!
//! This covenant reuses `token_unit`'s KCC20 Standard State Header
//! ([`crate::contract::token::Kcc20StateHeader`], 35 script bytes: a 32-byte
//! `owner_identifier` pubkey + a 1-byte `identifier_type`). As in `token_unit`,
//! KCC20 `amount` is **not** embedded in the redeem script; it is mapped onto
//! the UTXO's native sompi value. This is a deliberate **deviation from
//! KCC-0020's in-script `amount`** (kcc-0020 / kcc-0001 §8.1 place `amount`
//! inside the encoded state). The trade recorded in the evaluation memo:
//! native-value keeps the P2SH address a pure function of `owner_pubkey`
//! (so KOB's existing address-based UTXO discovery keeps working and no
//! covenant-id scanner subsystem is required), at the cost of literal
//! KCC-0020 conformance on the `amount` field. See `token.rs`'s module-level
//! decision note for the full rationale this module inherits.
//!
//! # The issuer attestation gate (freeze)
//!
//! Every spend of a stablecoin UTXO must satisfy, in order:
//!
//! 1. **Owner authorization** — an `OpCheckSigVerify` of a SIGHASH_ALL
//!    signature against the state's `owner_identifier` pubkey. SIGHASH_ALL
//!    binds the whole transaction (the raw `OpCheckSigFromStack` attestation,
//!    by contrast, is not tx-bound on its own — hence the replay fields
//!    below).
//! 2. **Issuer attestation** — an `OpCheckSigFromStack` of the issuer's
//!    signature over a message hash the script *recomputes on-chain* from
//!    transaction introspection. The message binds the covenant id, the
//!    exact outpoint being spent (replay protection), the successor output's
//!    scriptPublicKey, and the amount. Without a valid issuer signature the
//!    script hard-aborts (`OpVerify`), so the gate is **fail-close**: a
//!    frozen token is one for which the issuer simply declines to attest.
//!
//! The attestation message composition (domain tag, field order, and field
//! widths) is defined once, canonically, in [`attestation`]; [`body`] emits
//! the on-chain opcode sequence that reconstructs *exactly* those bytes. The
//! two are kept in lock-step by conformance tests in both files — this is the
//! foundation WU-F's real-engine round-trip verification builds on.
//!
//! # ISSUE-15: 1:1 operating assumption (explicit)
//!
//! This body attests a **single** successor per gated input (the output at
//! the same index as the spent input — see [`body`]) and binds the *input's
//! full native amount*. It therefore assumes **1:1 transfers** (one gated
//! input funds one attested successor, no split / change output on the token
//! side). This is the deliberate ISSUE-15 avoidance for Plan A: N:M transfer
//! shapes, change outputs, and per-instance shape enforcement
//! (`OpCovInputCount == 1`) are explicitly out of WU-A scope and deferred to
//! a later phase. Callers (WU-B/C/D/F) MUST honor the 1:1 shape.
//!
//! # Public surface for downstream work units
//!
//! - [`DOMAIN_TAG`] — the 8-byte domain-separation constant baked into the
//!   body and prepended by the encoder (below).
//! - [`attestation::build_attestation_message`] / [`attestation::build_attestation_preimage`]
//!   — the canonical issuer pre-image the off-chain attest tool signs.
//! - [`attestation::validate_x_only_pubkey`] — 32-byte x-only key validation.
//! - [`body::build_stablecoin_redeem_script`] — the complete redeem script.

pub mod attestation;
pub mod body;
pub mod dispatch;
pub mod mint_authority;
pub mod sigscript;
pub mod state;

pub use attestation::*;
pub use body::*;
pub use sigscript::*;
pub use state::{StablecoinStateHeader, STATE_HEADER_LEN};

/// 8-byte domain-separation tag for the KCC-0020 native-value stablecoin
/// attestation message.
///
/// Layout (human-auditable ASCII):
/// - bytes `[0..4]` = `"K20S"` — scheme discriminant (KCC-0020 Stablecoin,
///   Plan A native-value). Distinguishes these attestations from any other
///   `OpCheckSigFromStack` message this codebase might sign.
/// - bytes `[4..8]` = `"MNET"` — network discriminant. This is the
///   evaluation memo's "DOMAIN_TAG must include network magic" requirement:
///   it prevents an issuer attestation minted for one network from being
///   replayed against an identically-shaped covenant on another network. A
///   non-mainnet build MUST use a distinct trailing tag (e.g. `b"K20STN10"`
///   for testnet-10); whatever value is chosen, the body bytecode and the
///   [`attestation`] encoder MUST reference this same constant so the
///   on-chain and off-chain pre-images agree byte-for-byte.
pub const DOMAIN_TAG: [u8; 8] = *b"K20SMNET";
