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
