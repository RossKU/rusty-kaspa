//! Kaspa x402 payment facilitator.
//!
//! A production facilitator for the x402 payment protocol
//! (coinbase/x402-compatible wire format) settling on Kaspa. It verifies a
//! client-signed payment artifact, broadcasts it, observes finality, and
//! authorizes — backed by KOB's real settlement core (`kob-settle`), not a
//! mock chain provider.
//!
//! Layers:
//! - [`wire_v2`] — x402 v2 wire types (`PaymentRequirements`, PAYMENT-* headers,
//!   verify/settle request+response, `/supported`), synced to upstream
//!   v0.1.0-alpha.8 (profile split: `standard-native` default + `additive`).
//! - [`exact_authorization`] — canonical JSON, the exact request-authorization
//!   digest, and its Schnorr verification (upstream PR#3 / alpha.9).
//! - [`transaction_id`] — independent recomputation of the canonical Kaspa
//!   transaction id from a safe-JSON artifact (upstream PR#3 / alpha.9).
//! - [`fingerprint`] — request-fingerprint <-> payment binding.
//! - [`scheme_native`] — KOB-native binding "exact" verification (pure).
//! - [`scheme_exact`] — strict-interop `kaspa-exact-v2` verification for both
//!   alpha.8 profiles (pure).
//! - [`scheme_stablecoin`] — robust KCC-0020 stablecoin covenant TRANSFER
//!   binding (`kaspa-stablecoin-v1`) verification (pure), plus the client
//!   tx builder and OPS-attestation co-sign seam (§7.4(B) of
//!   `STABLECOIN_FOUR_AXIS_AUDIT_2026-07-20.md`, audit finding G-x1).
//! - [`facilitator`] — verify/settle orchestration with replay protection and
//!   idempotent settlement, over a mockable [`facilitator::ChainBackend`].
//! - [`server`] — axum HTTP server.

pub mod exact_authorization;
pub mod facilitator;
pub mod fingerprint;
#[cfg(test)]
mod interop_tests;
pub mod reservation;
pub mod scheme_exact;
pub mod scheme_kcc20;
pub mod scheme_native;
pub mod scheme_stablecoin;
pub mod server;
pub mod transaction_id;
pub mod wire_v2;

pub use facilitator::{ChainBackend, DiscoveredTx, Facilitator, FacilitatorConfig};
pub use reservation::{BorrowTerms, ReservationProvider};
pub use wire_v2::{
    AwaitRequest, FacilitatorRequest, PaymentPayload, PaymentRequired, PaymentRequirements,
    SettlementResponse, SupportedResponse, VerifyResponse,
    ASSET_KAS, BINDING_EXACT, BINDING_KCC20, BINDING_NATIVE, BINDING_STABLECOIN, NETWORK_MAINNET, NETWORK_TESTNET10,
    PROFILE_ADDITIVE, PROFILE_STANDARD_NATIVE, SCHEME_EXACT, X402_VERSION,
};
