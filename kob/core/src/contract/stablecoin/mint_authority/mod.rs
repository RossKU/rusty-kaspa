//! Mint-authority contract (`STABLECOIN_ROBUST_DESIGN.md` §9 "Mint + Supply
//! Cap"; §1/§2/Resolved Decisions (b): "MINT is a fully separate authority
//! contract, not a branch of this transfer covenant").
//!
//! A SEPARATE, low-frequency, self-continuing covenant (reusing the
//! `token_mint` self-continuation/admin pattern already in the codebase,
//! `core/src/contract/token.rs:164-238`, generalized on top of the
//! `spot::dca`/`dr.rs` D&R self-continuation template — see [`body`]'s module
//! doc for exactly which pieces are mirrored from where). It carries its own
//! **running-supply counter** and **raisable supply cap** as mutable state
//! ([`state`]), and — on every honest MINT spend — emits a newly-minted
//! stablecoin UTXO paying to the (separate) stablecoin covenant's P2SH,
//! alongside its own self-continuation successor.
//!
//! Both mini-dispatch operations are wired: **MINT** (`op_type 0x00`) and
//! **RAISE_CAP** (`op_type 0x01`, `STABLECOIN_ROBUST_DESIGN.md` §9: cold
//! 2-of-3 `cap_authority_pubkeys` authorization, self-continuing with
//! `current_cap` strictly increased and `running_supply` unchanged, no coin
//! emitted).
//!
//! This covenant is intentionally NOT the stablecoin covenant
//! (`super::body`/`super::state`/`super::attestation`) — see this crate's
//! `STABLECOIN_ROBUST_DESIGN.md` §9's "RESOLVED: MINT is a fully separate
//! authority contract" for the rationale (isolating the running-supply
//! counter/cap check from the high-frequency TRANSFER/FREEZE/SEIZE path). The
//! stablecoin covenant's own `op_type` dispatch never branches on `0x04`
//! (reserved) and never reads/writes supply state.

pub mod attestation;
pub mod body;
pub mod sigscript;
pub mod state;

pub use attestation::*;
pub use body::*;
pub use sigscript::*;
pub use state::{MintAuthorityStateHeader, STATE_HEADER_LEN};

/// 8-byte domain-separation tag for the mint-authority contract's MINT
/// attestation message. Deliberately DISTINCT from the stablecoin covenant's
/// own [`super::DOMAIN_TAG`] — a signature minted for one contract must never
/// verify against the other (cross-contract replay protection).
///
/// Layout (human-auditable ASCII), mirroring [`super::DOMAIN_TAG`]'s
/// convention:
/// - bytes `[0..4]` = `"K20A"` — scheme discriminant (KCC-0020 mint-Authority
///   contract). Distinguishes these attestations from the stablecoin
///   covenant's own `"K20S"`-prefixed messages.
/// - bytes `[4..8]` = `"MNET"` — network discriminant, same convention and
///   caveat as [`super::DOMAIN_TAG`]: a non-mainnet build MUST use a distinct
///   trailing tag, and the on-chain body/off-chain [`attestation`] encoder
///   MUST reference this same constant so the two pre-images agree
///   byte-for-byte.
pub const DOMAIN_TAG_MINT: [u8; 8] = *b"K20AMNET";
