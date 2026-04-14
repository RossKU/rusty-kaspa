//! Chain-layer modules: block scanning, spot order matching and TX
//! construction/submission, deploy commands. Everything here touches
//! kaspad RPC or constructs real transactions.

#[allow(dead_code)]
pub mod executor;
#[allow(dead_code)]
pub mod scanner;
pub mod deploy;
