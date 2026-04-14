//! kob-domain — pure in-memory matching logic for KOB contracts.
//!
//! This crate holds the domain-pure logic for every KOB contract type
//! (spot, perp, lending, prediction, etc.): order books, matching,
//! executors, trackers. It has zero chain I/O — no kaspad RPC, no block
//! scanner, no REST server, no persistence.
//!
//! Depends only on:
//! - `kob-core` — bytecode, sighash, tx builders, primitives
//! - `kaspa-consensus-core` — read-only types (Transaction, TransactionOutpoint)
//!
//! Consumers:
//! - `kob-engine` adds chain I/O, orchestration, and REST API on top.
//! - Standalone tools (MM bots, simulators) can depend on this crate
//!   directly to reuse matching logic without pulling in chain dependencies.

/// Default maximum matcher fee (in sompi) embedded in deploy redeemScripts.
/// Must match `kob-cli`'s `DEFAULT_MAX_MATCHER_FEE` to avoid P2SH mismatch.
pub const DEFAULT_MAX_MATCHER_FEE: u64 = 10_000_000;

// Spot books
#[allow(dead_code)]
pub mod order_book;
#[allow(dead_code)]
pub mod stop_book;
#[allow(dead_code)]
pub mod dca_book;
#[allow(dead_code)]
pub mod swap_book;

// Perp
#[allow(dead_code)]
pub mod perp_book;
#[allow(dead_code)]
pub mod perp_tracker;
#[allow(dead_code)]
pub mod perp_executor;

// Lending
#[allow(dead_code)]
pub mod lending_book;
#[allow(dead_code)]
pub mod lending_tracker;
#[allow(dead_code)]
pub mod lending_executor;

// Prediction
#[allow(dead_code)]
pub mod prediction_book;
#[allow(dead_code)]
pub mod prediction_tracker;
#[allow(dead_code)]
pub mod prediction_executor;

// Matching / orchestration
#[allow(dead_code)]
pub mod matching;
#[allow(dead_code)]
pub mod routing;
#[allow(dead_code)]
pub mod batch;
#[allow(dead_code)]
pub mod ifd;
#[allow(dead_code)]
pub mod trailing_stop;

use std::collections::HashMap;
use std::hash::Hash;

use kaspa_consensus_core::tx::TransactionOutpoint;

/// Reverse-index mapping spent outpoints back to the domain key (order id,
/// position id, etc.) they belong to. Enables O(1) removal of an order
/// when its backing UTXO is spent on-chain.
///
/// Every book implementation in this crate is expected to maintain one of
/// these alongside its primary id→order map.
#[derive(Debug, Default)]
pub struct OutpointIndex<K: Eq + Hash + Clone> {
    map: HashMap<TransactionOutpoint, K>,
}

impl<K: Eq + Hash + Clone> OutpointIndex<K> {
    pub fn new() -> Self {
        Self { map: HashMap::new() }
    }

    pub fn insert(&mut self, op: TransactionOutpoint, key: K) -> Option<K> {
        self.map.insert(op, key)
    }

    pub fn get(&self, op: &TransactionOutpoint) -> Option<&K> {
        self.map.get(op)
    }

    pub fn remove(&mut self, op: &TransactionOutpoint) -> Option<K> {
        self.map.remove(op)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn clear(&mut self) {
        self.map.clear();
    }
}

/// Common shape of every order book in kob-domain.
///
/// Phase 3 will migrate the existing books to implement this trait.
/// The trait intentionally stays minimal — book-specific queries
/// (best bid/ask, depth, expiry sweeps) remain on the concrete type.
pub trait ContractBook {
    /// Order envelope the book stores.
    type Order;
    /// Stable id used to address orders within the book.
    type OrderId: Eq + Hash + Clone;

    /// Insert an order and return its assigned id.
    fn insert(&mut self, order: Self::Order) -> Self::OrderId;

    /// Remove an order by id.
    fn remove(&mut self, id: &Self::OrderId) -> Option<Self::Order>;

    /// Remove an order whose backing outpoint was spent on-chain.
    /// Returns the removed order on success.
    fn remove_by_outpoint(&mut self, op: &TransactionOutpoint) -> Option<Self::Order>;

    /// Snapshot every current order (for persistence or REST).
    fn snapshot(&self) -> Vec<Self::Order>;
}

/// Common shape of every executor in kob-domain. An executor consumes
/// a confirmed transaction and mutates the paired book accordingly.
pub trait ContractExecutor<B: ContractBook> {
    /// Observable side-effect the executor emits (fills, settlements, etc.).
    type Event;

    /// Process one confirmed transaction at the given DAA score.
    fn process_tx(
        &mut self,
        book: &mut B,
        tx: &kaspa_consensus_core::tx::Transaction,
        daa: u64,
    ) -> Vec<Self::Event>;
}
