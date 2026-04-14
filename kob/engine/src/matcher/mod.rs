// Chain-layer matcher modules (engine-only).
//
// Per-contract books, trackers, executors, matching orchestration, routing,
// batch, ifd, and trailing_stop live in `kob-domain` and are re-exported
// below for backward-compat with existing `crate::matcher::X` paths.

// Chain-layer (stays in engine)
#[allow(dead_code)]
pub mod executor;
#[allow(dead_code)]
pub mod scanner;
pub mod persistence;
#[allow(dead_code)]
pub mod api;
#[allow(dead_code)]
pub mod trades;
pub mod candle;
#[allow(dead_code)]
pub mod history;
pub mod deploy;

// Domain-layer (re-exported from kob-domain)
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
