//! Kaspa x402 payment facilitator.
//!
//! A production facilitator for the x402 payment protocol
//! (coinbase/x402-compatible wire format) settling on Kaspa. It verifies a
//! client-signed payment artifact, broadcasts it, observes finality, and
//! authorizes — backed by KOB's real settlement core (`kob-settle`), not a
//! mock chain provider.
//!
//! Layers:
//! - [`wire`] — x402 wire types (`PaymentRequirements`, `X-PAYMENT`,
//!   verify/settle request+response, `/supported`).
//! - [`fingerprint`] — request-fingerprint <-> payment binding.
//! - [`scheme_native`] — scheme (A) native-KAS "exact" verification (pure).
//! - [`facilitator`] — verify/settle orchestration with replay protection and
//!   idempotent settlement, over a mockable [`facilitator::ChainBackend`].
//! - [`server`] — axum HTTP server.

pub mod facilitator;
pub mod fingerprint;
pub mod scheme_native;
pub mod server;
pub mod wire;

pub use facilitator::{ChainBackend, Facilitator, FacilitatorConfig};
pub use wire::{
    FacilitatorRequest, PaymentPayload, PaymentRequirements, PaymentRequiredResponse,
    SettleResponse, SupportedResponse, VerifyResponse,
    ASSET_NATIVE_KAS, NETWORK_MAINNET, NETWORK_TESTNET10, SCHEME_EXACT, X402_VERSION,
};
