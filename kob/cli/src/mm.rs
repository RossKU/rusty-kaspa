//! `kob-cli mm` -- Market Maker bot for continuous two-sided quoting.
//!
//! This module re-exports the canonical MM implementation from `kob-engine`.
//! All MM logic (deploy, cancel, monitor, state persistence) lives in
//! `kob_engine::mm`. The CLI command dispatch calls through here.

// Re-export everything from kob-engine's MM module.
pub use kob_engine::mm::*;
