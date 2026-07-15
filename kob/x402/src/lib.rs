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
//!   verify/settle request+response, `/supported`).
//! - [`fingerprint`] — request-fingerprint <-> payment binding.
//! - [`scheme_native`] — scheme (A) native-KAS "exact" verification (pure).
//! - [`facilitator`] — verify/settle orchestration with replay protection and
//!   idempotent settlement, over a mockable [`facilitator::ChainBackend`].
//! - [`server`] — axum HTTP server.

pub mod facilitator;
pub mod fingerprint;
pub mod reservation;
pub mod scheme_exact;
pub mod scheme_kcc20;
pub mod scheme_native;
pub mod server;
pub mod wire_v2;

pub use facilitator::{ChainBackend, DiscoveredTx, Facilitator, FacilitatorConfig};
pub use reservation::{BorrowTerms, ReservationProvider};
pub use wire_v2::{
    AwaitRequest, FacilitatorRequest, PaymentPayload, PaymentRequired, PaymentRequirements,
    SettlementResponse, SupportedResponse, VerifyResponse,
    ASSET_KAS, BINDING_EXACT, BINDING_KCC20, BINDING_NATIVE, NETWORK_MAINNET, NETWORK_TESTNET10,
    SCHEME_EXACT, X402_VERSION,
};
