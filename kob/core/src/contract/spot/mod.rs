//! Spot order covenants: buy/sell orders, receipts, OCO, brackets, DCA,
//! and token pairs.

/// The single spot contract generation. Parsers/scanners tag every spot
/// order (buy, sell, OCO, swap, bracket) with this as its `version` u8 so
/// engine/API consumers keep a stable numeric identifier; the on-chain
/// dispatch itself is by RS length, not this field.
pub const SPOT_GENERATION: u32 = 18;

pub mod order;
pub mod parse;
pub mod receipt;
pub mod oco;
pub mod bracket;
pub mod dca;
pub mod swap;
pub mod token_pair;

// Time-contracts family (kob/TIME_CONTRACTS_DESIGN.md): ADDITIVE sibling
// contracts beside the frozen v18 generation — own builders, own RS-length
// parse arms, no generation bump, v18 bytecode untouched (zero-diff pin).
pub mod decay;
pub mod ratchet;
pub mod twap;

/// RT-2 adversarial tooling: construct malformed `ratchet_oco` RATCHET-branch
/// advance transactions for offline (and, later, live) covenant-rejection
/// proof. Not shipping bytecode -- deliberately NOT re-exported via `pub use`
/// below so its `RatchetTamperCase`/`SiblingPrint` names stay out of the flat
/// namespace; consumers `use kob_core::contract::spot::ratchet_tamper::*`.
pub mod ratchet_tamper;

/// EXPERIMENTAL — batch-limit measurement variants (kob/BATCH_LIMITS.md).
/// Not shipping bytecode: nothing in the deploy/parse/settle paths uses this
/// module. Deliberately NOT re-exported via `pub use` below.
pub mod lab;

pub use order::*;
pub use parse::*;
pub use receipt::*;
pub use oco::*;
pub use bracket::*;
pub use dca::*;
pub use swap::*;
pub use token_pair::*;
pub use decay::*;
pub use ratchet::*;
pub use twap::*;
