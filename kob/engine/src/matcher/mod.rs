//! Legacy compat façade for the pre-refactor `crate::matcher::X` paths.
//!
//! Engine modules were regrouped by concern in Phase 5:
//!
//! - chain-layer       → `crate::chain`  (executor, scanner, deploy)
//! - storage-layer     → `crate::storage` (persistence, history)
//! - api-layer         → `crate::api`    (REST/WS)
//! - reporting-layer   → `crate::reporting` (trades, candle)
//! - domain-layer      → `kob_domain`    (books, trackers, matching, …)
//!
//! This file re-exports every module at its original `crate::matcher::X`
//! path so existing call sites keep resolving. New code should import
//! from the canonical locations above instead of from `matcher::`.

// Domain re-exports (from Phase 3)
pub use kob_domain::order_book;
pub use kob_domain::stop_book;
pub use kob_domain::dca_book;
pub use kob_domain::swap_book;
pub use kob_domain::perp_book;
pub use kob_domain::perp_tracker;
pub use kob_domain::perp_executor;
pub use kob_domain::lending_book;
pub use kob_domain::lending_tracker;
pub use kob_domain::lending_executor;
pub use kob_domain::prediction_book;
pub use kob_domain::prediction_tracker;
pub use kob_domain::prediction_executor;
pub use kob_domain::matching;
pub use kob_domain::routing;
pub use kob_domain::batch;
pub use kob_domain::ifd;
pub use kob_domain::trailing_stop;

// Engine re-exports (from Phase 5)
pub use crate::chain::executor;
pub use crate::chain::scanner;
pub use crate::chain::deploy;
pub use crate::storage::persistence;
pub use crate::storage::history;
pub use crate::api;
pub use crate::reporting::trades;
pub use crate::reporting::candle;
