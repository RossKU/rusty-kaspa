//! Multi-pair order book with price-priority BTreeMap ordering.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::time::Instant;

/// Order key for BTreeMap sorting.
///
/// For bids: sort by price DESC, then by DAA ASC (FIFO), then by value DESC.
/// For asks: sort by price ASC, then by DAA ASC (FIFO), then by value ASC.
/// The outpoint key is included for uniqueness.
#[derive(Debug, Clone)]
pub struct OrderKey {
    /// Price as rational number (num/den), stored for comparison
    pub price_num: u64,
    pub price_den: u64,
    /// DAA score when the order was discovered (FIFO tiebreaker).
    /// Lower value = older order = higher priority at equal price.
    pub discovered_daa: u64,
    /// Order value in sompi (secondary tiebreaker)
    pub value: u64,
    /// Outpoint key for uniqueness (txId:index)
    pub outpoint_key: String,
}

impl OrderKey {
    fn price_cmp(&self, other: &Self) -> Ordering {
        // Cross-multiply to compare: self.num/self.den vs other.num/other.den
        // self.num * other.den vs other.num * self.den
        let lhs = (self.price_num as u128) * (other.price_den as u128);
        let rhs = (other.price_num as u128) * (self.price_den as u128);
        lhs.cmp(&rhs)
    }
}

/// Ordering for bid keys: highest price first (DESC)
#[derive(Debug, Clone)]
pub struct BidKey(pub OrderKey);

impl PartialEq for BidKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.outpoint_key == other.0.outpoint_key
    }
}

impl Eq for BidKey {}

impl PartialOrd for BidKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BidKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse price order (DESC): higher price comes first
        let price_ord = other.0.price_cmp(&self.0);
        if price_ord != Ordering::Equal {
            return price_ord;
        }
        // FIFO tiebreak: older order first (lower DAA = earlier discovery)
        let daa_ord = self.0.discovered_daa.cmp(&other.0.discovered_daa);
        if daa_ord != Ordering::Equal {
            return daa_ord;
        }
        // Secondary tiebreak: higher value first
        let val_ord = other.0.value.cmp(&self.0.value);
        if val_ord != Ordering::Equal {
            return val_ord;
        }
        // Final tiebreak: lexicographic outpoint
        self.0.outpoint_key.cmp(&other.0.outpoint_key)
    }
}

/// Ordering for ask keys: lowest price first (ASC)
#[derive(Debug, Clone)]
pub struct AskKey(pub OrderKey);

impl PartialEq for AskKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.outpoint_key == other.0.outpoint_key
    }
}

impl Eq for AskKey {}

impl PartialOrd for AskKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AskKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // Normal price order (ASC): lower price comes first
        let price_ord = self.0.price_cmp(&other.0);
        if price_ord != Ordering::Equal {
            return price_ord;
        }
        // FIFO tiebreak: older order first (lower DAA = earlier discovery)
        let daa_ord = self.0.discovered_daa.cmp(&other.0.discovered_daa);
        if daa_ord != Ordering::Equal {
            return daa_ord;
        }
        // Secondary tiebreak: lower value first
        let val_ord = self.0.value.cmp(&other.0.value);
        if val_ord != Ordering::Equal {
            return val_ord;
        }
        // Final tiebreak: lexicographic outpoint
        self.0.outpoint_key.cmp(&other.0.outpoint_key)
    }
}

/// An order in the book (buy or sell).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookOrder {
    pub tx_id: String,
    pub index: u32,
    pub value: u64,
    pub token_cov_id: String,
    pub price_num: u64,
    pub price_den: u64,
    pub min_fill: u64,
    pub owner_hash: String,
    /// Blake2b-256(counterparty scriptPublicKey) embedded in the RS state.
    ///
    /// For buy orders: `bspkh` = Blake2b(buyer's SPK). The matcher must route
    /// the token output to the buyer's SPK; the contract verifies this.
    /// For sell orders: `sspkh` = Blake2b(seller's SPK). The matcher must route
    /// the KAS output to the seller's SPK; the contract verifies this.
    pub spk_hash: String,
    /// Actual counterparty scriptPublicKey bytes (hex-encoded), needed to build
    /// match TX outputs.
    ///
    /// The contract checks `Blake2b(output.spk) == spk_hash`, which means the
    /// matcher must know the *actual* SPK bytes — not just their hash. Since
    /// Blake2b is one-way, the only way to recover the SPK is to include it in
    /// the deploy TX payload (payload v2 format: "KOB:2:" + spk_len_u16LE +
    /// spk_bytes + rs_bytes). When populated, this holds the hex-encoded SPK
    /// that produced `spk_hash`. When `None`, the matcher cannot execute the
    /// match and will log an error and skip the order.
    pub counterparty_spk: Option<String>,
    /// Cached redeemScript (hex-encoded for persistence)
    pub redeem_script_hex: String,
    /// Cached P2SH scriptPublicKey (hex-encoded)
    pub p2sh_script_hex: String,
    /// P2SH script version
    pub p2sh_version: u16,
    /// Order side
    pub side: OrderSide,
    /// Post-only flag: if true, the order must only rest on the book as a
    /// maker. The matching engine will skip this order when it would cross
    /// the spread immediately (i.e., act as a taker). This is a Matcher-level
    /// policy — the L1 covenant is unaware of this flag.
    #[serde(default)]
    pub post_only: bool,
    /// GTD (Good-Till-Date) expiry DAA score. None = GTC (no expiry).
    /// When `Some(daa)`, the order should be skipped by the matching engine
    /// and eventually pruned once the current DAA score exceeds `daa`.
    #[serde(default)]
    pub expiry_daa: Option<u64>,
    /// True if the order's redeemScript contains OpZkPrecompile (0xa6),
    /// indicating a freezable token covenant (e.g. USDC) that requires a
    /// ZK proof to spend. When true, the Matcher must have a ZK prover
    /// configured or the order will be skipped during matching.
    #[serde(default)]
    pub is_freezable: bool,
    /// Maximum fee the matcher may extract from this order's value.
    /// The buy contract's F6 check enforces `kas_in - out[0].value <= mmfee`.
    /// When mmfee=0, the seller must receive ALL the buyer's KAS (matcher profit = 0).
    /// Defaults to u64::MAX (unlimited) for backward compatibility.
    #[serde(default = "default_max_matcher_fee")]
    pub max_matcher_fee: u64,
    /// IFD: order B's redeemScript hex. When set, the fill TX must include
    /// order B as payload so the scanner discovers it on-chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ifd_order_b_rs_hex: Option<String>,
    /// OCO path: which path this virtual order represents (TP or SL).
    /// None for regular (non-OCO) orders.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oco_path: Option<kob_core::OcoPath>,
    /// OCO partner: outpoint_key of the partner virtual order.
    /// When this order is filled or removed, the partner must also be removed
    /// (the UTXO is shared, spending it cancels both paths).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oco_partner_key: Option<String>,
    /// DAA score at which the scanner discovered this order on-chain.
    /// Used for FIFO tiebreaking: at equal price, older orders (lower DAA)
    /// are matched first, ensuring first-come-first-served fairness.
    /// Defaults to 0 for backward compatibility with pre-FIFO persisted orders.
    #[serde(default)]
    pub discovered_daa: u64,
    /// Time-contract classification (kob/TIME_CONTRACTS_DESIGN.md). None for
    /// the plain v18 spot kinds; Some(..) for the four additive time kinds.
    /// The scanner populates this from the RS parse arms; the book price
    /// fields carry the START price (decay) / state price (twap) / branch
    /// pair (ratchet) — effective-price surfacing reads this metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_meta: Option<TimeMeta>,
}

/// Time-contract metadata carried on a book entry (design §2.7/§3.5/§4.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeMeta {
    /// twap_sell: rate limiter fields. Fill inputs must carry
    /// `sequence = max(50, twin)`; per-event volume <= mpw.
    TwapSell { twin: u64, mpw: u64 },
    /// decay_sell: falling-ask schedule; the book pair is the START price,
    /// the executing price is `pnum_eff(L) = pnum - dslope*(clamp(L)-t0)`.
    DecaySell { dslope: u64, t0: u64, t_end: u64 },
    /// decay_buy: rising bid; same schedule formula on the buy pair.
    DecayBuy { dslope: u64, t0: u64, t_end: u64 },
    /// ratchet_oco: trailing-SL ratchet fields. `ratchets_applied` counts the
    /// continuation generation (0 = deploy UTXO; the scanner increments it
    /// when it follows a landed RATCHET spend to the successor P2SH).
    RatchetOco { rstep: u64, rgap: u64, rwin: u64, mrv: u64, ratchets_applied: u64 },
}

impl BookOrder {
    /// The consensus real-age (CSV) maturity this order's fill input needs:
    /// `max(50, twin)` for a twap_sell (its `twin CSV` gate), the plain
    /// 50-DAA exposure delay otherwise. `discovered_daa` approximates the
    /// UTXO creation score for the planner-side gate; consensus is the
    /// authority either way (a premature tx is rejected, not mis-priced).
    pub fn csv_maturity(&self) -> u64 {
        match &self.time_meta {
            Some(TimeMeta::TwapSell { twin, .. }) => (*twin).max(50),
            Some(TimeMeta::RatchetOco { .. }) => 50,
            _ => 50,
        }
    }

    /// The price pair this order would EXECUTE at in a tx carrying
    /// `lock_time = now_daa` (design §2.7 effective-price surfacing): decay
    /// kinds evaluate their schedule at `now_daa`; every other kind returns
    /// the book pair unchanged (twap state price / ratchet branch pair).
    pub fn effective_price(&self, now_daa: u64) -> (u64, u64) {
        match &self.time_meta {
            Some(TimeMeta::DecaySell { dslope, t0, t_end })
            | Some(TimeMeta::DecayBuy { dslope, t0, t_end }) => (
                kob_core::contract::spot::decay::decay_effective_pnum(
                    self.price_num, *dslope, *t0, *t_end, now_daa,
                ),
                self.price_den,
            ),
            _ => (self.price_num, self.price_den),
        }
    }
}

fn default_max_matcher_fee() -> u64 {
    u64::MAX
}

impl BookOrder {
    pub fn outpoint_key(&self) -> String {
        let base = format!("{}:{}", self.tx_id, self.index);
        match self.oco_path {
            Some(kob_core::OcoPath::TakeProfit) => format!("{}:tp", base),
            Some(kob_core::OcoPath::StopLoss) => format!("{}:sl", base),
            None => base,
        }
    }

    /// Returns the raw UTXO outpoint key (without OCO suffix).
    /// Use this for UTXO lookups and TX building.
    pub fn utxo_outpoint_key(&self) -> String {
        format!("{}:{}", self.tx_id, self.index)
    }

    /// Returns true if this is a GTD order whose expiry DAA score has been
    /// exceeded by `current_daa`. GTC orders (expiry_daa = None) never expire.
    pub fn is_expired(&self, current_daa: u64) -> bool {
        match self.expiry_daa {
            Some(expiry) => expiry > 0 && current_daa >= expiry,
            None => false,
        }
    }

    pub fn redeem_script(&self) -> Vec<u8> {
        hex::decode(&self.redeem_script_hex).unwrap_or_else(|e| {
            tracing::warn!("[ORDER] Bad hex in redeem_script_hex for {}: {}", self.outpoint_key(), e);
            Vec::new()
        })
    }

    pub fn p2sh_script(&self) -> Vec<u8> {
        hex::decode(&self.p2sh_script_hex).unwrap_or_else(|e| {
            tracing::warn!("[ORDER] Bad hex in p2sh_script_hex for {}: {}", self.outpoint_key(), e);
            Vec::new()
        })
    }


    /// Expected output amount for a full fill.
    ///
    /// - Buy side: `expected_tokens = value * price_num / price_den`
    ///   (how many tokens the buyer expects for their KAS).
    /// - Sell side: `expected_kas = value * price_num / price_den`
    ///   (how much KAS the seller expects for their tokens).
    ///
    /// Returns 0 if `price_den == 0` (corrupt order).
    pub fn expected_output(&self) -> u64 {
        if self.price_den == 0 {
            return 0;
        }
        self.value.checked_mul(self.price_num)
            .map(|v| v / self.price_den)
            .unwrap_or(0)
    }

    /// Returns true if this order can accept partial fills via the IOC
    /// (selector=Op5) path.  IOC-eligible orders have `min_fill` strictly
    /// less than their full expected output, so the L1 contracts relaxed
    /// check (`output >= mfill`) allows partial fills.
    ///
    /// GTC orders where `min_fill >= expected_output` must use the normal
    /// fill path (selector=Op1), which enforces `output >= exp_tok`.
    pub fn is_ioc_eligible(&self) -> bool {
        let exp = self.expected_output();
        exp > 0 && self.min_fill < exp
    }

    /// Return the counterparty SPK bytes for building a match TX output.
    ///
    /// Returns `Some((version, script_bytes))` when `counterparty_spk` is
    /// populated (payload v2 deploy), or `None` when it is absent (payload v1
    /// deploy, or the scanner could not extract it). When `None` the match
    /// must be skipped — the matcher cannot satisfy the L1 contract check
    /// `Blake2b(output.spk) == spk_hash` without the actual SPK bytes.
    pub fn resolve_counterparty_spk(&self) -> Option<(u16, Vec<u8>)> {
        let hex_spk = self.counterparty_spk.as_deref()?;
        let raw = hex::decode(hex_spk).ok()?;
        // counterparty_spk is stored as version (2B LE) + script bytes
        if raw.len() < 3 {
            return None;
        }
        let version = u16::from_le_bytes([raw[0], raw[1]]);
        let script = raw[2..].to_vec();
        Some((version, script))
    }
}

pub use kob_core::types::OrderSide;

/// Number of price levels retained in the denormalized top-of-book cache,
/// per side, per pair.
///
/// Hub cross-rate routing (Forex-USD-hub style: every pair quotes through
/// KAS) only ever needs the best few resting prices per pair to find or
/// quote a route -- not the full resting book, which can hold up to
/// `MAX_ORDERS_PER_PAIR` orders. Reading `top_bids()`/`top_asks()` turns an
/// O(orders-in-pair) walk into an O(1) read of at most this many entries.
pub const TOP_OF_BOOK_DEPTH: usize = 8;

/// A single denormalized top-of-book price level.
///
/// Carries just enough to route/quote without a second BTreeMap lookup;
/// callers that need the full `BookOrder` (e.g. to build a settlement TX)
/// resolve `outpoint_key` via `PairBook::get_bid`/`get_ask`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopQuote {
    pub price_num: u64,
    pub price_den: u64,
    pub value: u64,
    pub outpoint_key: String,
}

impl From<&BookOrder> for TopQuote {
    fn from(order: &BookOrder) -> Self {
        TopQuote {
            price_num: order.price_num,
            price_den: order.price_den,
            value: order.value,
            outpoint_key: order.outpoint_key(),
        }
    }
}

/// Per-pair order book (one token_covenant_id)
#[derive(Default)]
pub struct PairBook {
    pub bids: BTreeMap<BidKey, BookOrder>,
    pub asks: BTreeMap<AskKey, BookOrder>,
    /// Reverse lookup: outpoint_key -> BidKey or AskKey identifier
    bid_outpoints: HashMap<String, BidKey>,
    ask_outpoints: HashMap<String, AskKey>,
    /// Denormalized top-of-book cache: the best (up to `TOP_OF_BOOK_DEPTH`)
    /// bid/ask levels, refreshed on every insert/remove (`refresh_top_bids`/
    /// `refresh_top_asks`). `bids`/`asks` are already price-ordered
    /// BTreeMaps, so the refresh is a cheap `O(log n + TOP_OF_BOOK_DEPTH)`
    /// prefix read -- the cache exists so callers that need "N hub quotes"
    /// (routing.rs, match_swap_routes) don't re-walk every resting order in
    /// every pair on every routing pass.
    top_bids: Vec<TopQuote>,
    top_asks: Vec<TopQuote>,
}

impl PairBook {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_bid(&mut self, order: BookOrder) {
        let key = BidKey(OrderKey {
            price_num: order.price_num,
            price_den: order.price_den,
            discovered_daa: order.discovered_daa,
            value: order.value,
            outpoint_key: order.outpoint_key(),
        });
        self.bid_outpoints
            .insert(order.outpoint_key(), key.clone());
        self.bids.insert(key, order);
        self.refresh_top_bids();
    }

    pub fn add_ask(&mut self, order: BookOrder) {
        let key = AskKey(OrderKey {
            price_num: order.price_num,
            price_den: order.price_den,
            discovered_daa: order.discovered_daa,
            value: order.value,
            outpoint_key: order.outpoint_key(),
        });
        self.ask_outpoints
            .insert(order.outpoint_key(), key.clone());
        self.asks.insert(key, order);
        self.refresh_top_asks();
    }

    pub fn remove_bid(&mut self, outpoint_key: &str) -> Option<BookOrder> {
        if let Some(key) = self.bid_outpoints.remove(outpoint_key) {
            let removed = self.bids.remove(&key);
            self.refresh_top_bids();
            removed
        } else {
            None
        }
    }

    pub fn remove_ask(&mut self, outpoint_key: &str) -> Option<BookOrder> {
        if let Some(key) = self.ask_outpoints.remove(outpoint_key) {
            let removed = self.asks.remove(&key);
            self.refresh_top_asks();
            removed
        } else {
            None
        }
    }

    fn refresh_top_bids(&mut self) {
        self.top_bids = self.bids.values().take(TOP_OF_BOOK_DEPTH).map(TopQuote::from).collect();
    }

    fn refresh_top_asks(&mut self) {
        self.top_asks = self.asks.values().take(TOP_OF_BOOK_DEPTH).map(TopQuote::from).collect();
    }

    /// Denormalized top-of-book bid levels, best price first, up to
    /// `TOP_OF_BOOK_DEPTH` entries.
    pub fn top_bids(&self) -> &[TopQuote] {
        &self.top_bids
    }

    /// Denormalized top-of-book ask levels, best price first, up to
    /// `TOP_OF_BOOK_DEPTH` entries.
    pub fn top_asks(&self) -> &[TopQuote] {
        &self.top_asks
    }

    /// Best (highest) resting bid, if any.
    pub fn best_bid(&self) -> Option<&TopQuote> {
        self.top_bids.first()
    }

    /// Best (lowest) resting ask, if any.
    pub fn best_ask(&self) -> Option<&TopQuote> {
        self.top_asks.first()
    }

    /// Resolve a bid's full `BookOrder` by outpoint key (O(1)).
    pub fn get_bid(&self, outpoint_key: &str) -> Option<&BookOrder> {
        let key = self.bid_outpoints.get(outpoint_key)?;
        self.bids.get(key)
    }

    /// Resolve an ask's full `BookOrder` by outpoint key (O(1)).
    pub fn get_ask(&self, outpoint_key: &str) -> Option<&BookOrder> {
        let key = self.ask_outpoints.get(outpoint_key)?;
        self.asks.get(key)
    }

    /// Check if a buy order at the given price would cross the best ask.
    ///
    /// A buy crosses if its price >= the best ask price, meaning it would
    /// be immediately matchable (taker). Used for post-only rejection.
    pub fn would_buy_cross(&self, price_num: u64, price_den: u64) -> bool {
        if let Some((_, best_ask)) = self.asks.iter().next() {
            // buy crosses ask when: buy_price >= ask_price
            // i.e., price_num/price_den >= ask.price_num/ask.price_den
            // i.e., price_num * ask.price_den >= ask.price_num * price_den
            let lhs = (price_num as u128) * (best_ask.price_den as u128);
            let rhs = (best_ask.price_num as u128) * (price_den as u128);
            lhs >= rhs
        } else {
            false // No asks to cross
        }
    }

    /// Check if a sell order at the given price would cross the best bid.
    ///
    /// A sell crosses if its price <= the best bid price, meaning it would
    /// be immediately matchable (taker). Used for post-only rejection.
    pub fn would_sell_cross(&self, price_num: u64, price_den: u64) -> bool {
        if let Some((_, best_bid)) = self.bids.iter().next() {
            // sell crosses bid when: sell_price <= bid_price
            // i.e., price_num/price_den <= bid.price_num/bid.price_den
            // i.e., price_num * bid.price_den <= bid.price_num * price_den
            let lhs = (price_num as u128) * (best_bid.price_den as u128);
            let rhs = (best_bid.price_num as u128) * (price_den as u128);
            lhs <= rhs
        } else {
            false // No bids to cross
        }
    }

    /// Check if an outpoint exists in this pair book (bid or ask).
    pub fn contains_outpoint(&self, outpoint_key: &str) -> bool {
        self.bid_outpoints.contains_key(outpoint_key)
            || self.ask_outpoints.contains_key(outpoint_key)
    }
}

/// Maximum number of orders per trading pair before insertion is rejected.
pub const MAX_ORDERS_PER_PAIR: usize = 10_000;

/// Maximum number of distinct trading pairs before new pairs are rejected.
pub const MAX_TOTAL_PAIRS: usize = 500;

/// Maximum number of entries in `matched_outpoints` before automatic pruning.
/// At ~100 bytes per entry, 10,000 entries consume ~1MB.
const MAX_MATCHED_OUTPOINTS: usize = 10_000;

/// Maximum age of a matched outpoint entry before it is pruned (10 minutes).
/// Entries older than this are safe to remove because confirmed transactions
/// will not reappear as UTXOs. This is more precise than the previous
/// arbitrary-eviction approach which could remove recent entries.
const MATCHED_OUTPOINT_MAX_AGE_SECS: u64 = 600;

/// The complete multi-pair order book.
#[derive(Default)]
pub struct OrderBook {
    pub pair_books: HashMap<String, PairBook>,
    /// Outpoints that have been matched (spent). Maps outpoint_key -> insertion
    /// time. Time-based pruning removes entries older than MATCHED_OUTPOINT_MAX_AGE_SECS
    /// to prevent unbounded growth while preserving recent entries.
    pub matched_outpoints: HashMap<String, Instant>,
    /// Global outpoint index: outpoint_key -> (token_cov_id, side).
    /// Enables O(1) lookup of which pair book an order belongs to,
    /// replacing O(P) linear scans across all pair books.
    outpoint_index: HashMap<String, (String, OrderSide)>,
    /// Reverse index: txid -> list of outpoint_keys.
    /// Enables O(1) lookup by txid (used by the /api/v1/order endpoint)
    /// instead of scanning all orders across all pair books.
    txid_index: HashMap<String, Vec<String>>,
}

impl OrderBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ensure a pair book exists for the given token_covenant_id.
    pub fn ensure_pair_book(&mut self, token_cov_id: &str) -> &mut PairBook {
        self.pair_books
            .entry(token_cov_id.to_string())
            .or_default()
    }

    /// Add a buy order to the book.
    ///
    /// Returns `false` if the order was rejected due to capacity limits or
    /// post-only crossing rejection.
    pub fn add_buy_order(&mut self, order: BookOrder) -> bool {
        let token_cov_id = order.token_cov_id.clone();

        // Check pair cap: if this token is new, enforce MAX_TOTAL_PAIRS
        if !self.pair_books.contains_key(&token_cov_id)
            && self.pair_books.len() >= MAX_TOTAL_PAIRS
        {
            tracing::warn!(
                "[ORDER BOOK] Rejecting BUY: MAX_TOTAL_PAIRS ({}) reached, cannot add new pair [{}...]",
                MAX_TOTAL_PAIRS,
                &token_cov_id[..token_cov_id.len().min(12)],
            );
            return false;
        }

        // Check per-pair order cap
        if let Some(book) = self.pair_books.get(&token_cov_id) {
            let count = book.bids.len() + book.asks.len();
            if count >= MAX_ORDERS_PER_PAIR {
                tracing::warn!(
                    "[ORDER BOOK] Rejecting BUY: MAX_ORDERS_PER_PAIR ({}) reached for [{}...]",
                    MAX_ORDERS_PER_PAIR,
                    &token_cov_id[..token_cov_id.len().min(12)],
                );
                return false;
            }
        }

        // Post-only check: reject if the buy order would cross the best ask.
        // A post-only order must only rest on the book as a maker; it must not
        // immediately match as a taker.
        if order.post_only {
            if let Some(book) = self.pair_books.get(&token_cov_id) {
                if book.would_buy_cross(order.price_num, order.price_den) {
                    tracing::info!(
                        "[ORDER BOOK] Rejecting POST-ONLY BUY (would cross spread): {}:{} price={}/{}",
                        &order.tx_id[..order.tx_id.len().min(16)],
                        order.index,
                        order.price_num,
                        order.price_den,
                    );
                    return false;
                }
            }
        }

        let key = order.outpoint_key();
        let txid = order.tx_id.clone();
        tracing::info!(
            "[ORDER BOOK] Added BUY{}{} [{}...]: {} value={} price={}/{}",
            if order.post_only { " (POST-ONLY)" } else { "" },
            if order.is_freezable { " (FREEZABLE/ZK)" } else { "" },
            &token_cov_id[..token_cov_id.len().min(12)],
            &key[..key.len().min(16)],
            order.value,
            order.price_num,
            order.price_den,
        );
        self.outpoint_index.insert(key.clone(), (token_cov_id.clone(), OrderSide::Buy));
        self.txid_index.entry(txid).or_default().push(key);
        self.ensure_pair_book(&token_cov_id).add_bid(order);
        true
    }

    /// Add a sell order to the book.
    ///
    /// H-3: Sell orders with all-zero token_cov_id (scanner couldn't resolve
    /// the covenant ID) are ghost orders. Log a warning and skip them.
    ///
    /// Returns `false` if the order was rejected due to capacity limits or
    /// ghost order filtering.
    pub fn add_sell_order(&mut self, order: BookOrder) -> bool {
        let token_cov_id = order.token_cov_id.clone();
        // All-zero token_cov_id means the scanner failed to resolve the covenant.
        if token_cov_id.chars().all(|c| c == '0') {
            tracing::warn!(
                "[ORDER BOOK] Skipping SELL with zero token_cov_id: {}",
                order.outpoint_key(),
            );
            return false;
        }

        // Check pair cap: if this token is new, enforce MAX_TOTAL_PAIRS
        if !self.pair_books.contains_key(&token_cov_id)
            && self.pair_books.len() >= MAX_TOTAL_PAIRS
        {
            tracing::warn!(
                "[ORDER BOOK] Rejecting SELL: MAX_TOTAL_PAIRS ({}) reached, cannot add new pair [{}...]",
                MAX_TOTAL_PAIRS,
                &token_cov_id[..token_cov_id.len().min(12)],
            );
            return false;
        }

        // Check per-pair order cap
        if let Some(book) = self.pair_books.get(&token_cov_id) {
            let count = book.bids.len() + book.asks.len();
            if count >= MAX_ORDERS_PER_PAIR {
                tracing::warn!(
                    "[ORDER BOOK] Rejecting SELL: MAX_ORDERS_PER_PAIR ({}) reached for [{}...]",
                    MAX_ORDERS_PER_PAIR,
                    &token_cov_id[..token_cov_id.len().min(12)],
                );
                return false;
            }
        }

        // Post-only check: reject if the sell order would cross the best bid.
        if order.post_only {
            if let Some(book) = self.pair_books.get(&token_cov_id) {
                if book.would_sell_cross(order.price_num, order.price_den) {
                    tracing::info!(
                        "[ORDER BOOK] Rejecting POST-ONLY SELL (would cross spread): {}:{} price={}/{}",
                        &order.tx_id[..order.tx_id.len().min(16)],
                        order.index,
                        order.price_num,
                        order.price_den,
                    );
                    return false;
                }
            }
        }

        let key = order.outpoint_key();
        let txid = order.tx_id.clone();
        tracing::info!(
            "[ORDER BOOK] Added SELL{}{} [{}...]: {} value={} price={}/{}",
            if order.post_only { " (POST-ONLY)" } else { "" },
            if order.is_freezable { " (FREEZABLE/ZK)" } else { "" },
            &token_cov_id[..token_cov_id.len().min(12)],
            &key[..key.len().min(16)],
            order.value,
            order.price_num,
            order.price_den,
        );
        self.outpoint_index.insert(key.clone(), (token_cov_id.clone(), OrderSide::Sell));
        self.txid_index.entry(txid).or_default().push(key);
        self.ensure_pair_book(&token_cov_id).add_ask(order);
        true
    }

    /// Remove an order by outpoint key (after match).
    ///
    /// The outpoint is added to `matched_outpoints` to prevent re-processing.
    /// When the set exceeds MAX_MATCHED_OUTPOINTS, it is automatically pruned
    /// to avoid unbounded growth (F20). Empty pair books are cleaned up
    /// afterwards to reclaim memory.
    pub fn remove_order(&mut self, outpoint_key: &str) {
        self.matched_outpoints.insert(outpoint_key.to_string(), Instant::now());

        // F20: Automatic size-based pruning
        if self.matched_outpoints.len() > MAX_MATCHED_OUTPOINTS {
            self.prune_matched_outpoints();
        }

        // Clean up txid_index: extract txid from "txid:index" format
        if let Some(colon_pos) = outpoint_key.find(':') {
            let txid = &outpoint_key[..colon_pos];
            if let Some(keys) = self.txid_index.get_mut(txid) {
                keys.retain(|k| k != outpoint_key);
                if keys.is_empty() {
                    self.txid_index.remove(txid);
                }
            }
        }

        // Use the outpoint index for O(1) lookup instead of scanning all pairs
        if let Some((token_cov_id, side)) = self.outpoint_index.remove(outpoint_key) {
            if let Some(book) = self.pair_books.get_mut(&token_cov_id) {
                match side {
                    OrderSide::Buy => { book.remove_bid(outpoint_key); }
                    OrderSide::Sell => { book.remove_ask(outpoint_key); }
                }
            }
        } else {
            // Fallback: outpoint not in index (e.g. orders loaded from old persistence).
            // Scan all pair books to be safe.
            for book in self.pair_books.values_mut() {
                book.remove_bid(outpoint_key);
                book.remove_ask(outpoint_key);
            }
        }

        self.cleanup_empty_pairs();
    }

    /// Remove pair books that have zero orders (both bids and asks empty).
    ///
    /// Called automatically after `remove_order` to reclaim memory from
    /// fully-drained trading pairs.
    pub fn cleanup_empty_pairs(&mut self) {
        let before = self.pair_books.len();
        self.pair_books.retain(|_, book| {
            !book.bids.is_empty() || !book.asks.is_empty()
        });
        let removed = before - self.pair_books.len();
        if removed > 0 {
            tracing::info!(
                "[ORDER BOOK] Cleaned up {} empty pair(s), {} remaining",
                removed,
                self.pair_books.len(),
            );
        }
    }

    /// Prune the matched_outpoints map to prevent unbounded growth (F20).
    ///
    /// Uses time-based eviction: entries older than MATCHED_OUTPOINT_MAX_AGE_SECS
    /// (10 minutes) are removed. This is safe because matched outpoints are
    /// spent UTXOs that will not reappear in future UTXO queries.
    ///
    /// If the map still exceeds MAX_MATCHED_OUTPOINTS after time-based pruning,
    /// a secondary size-based pass removes the oldest entries until the map
    /// is at half capacity.
    pub fn prune_matched_outpoints(&mut self) {
        let before = self.matched_outpoints.len();
        let cutoff = Instant::now() - std::time::Duration::from_secs(MATCHED_OUTPOINT_MAX_AGE_SECS);

        // Primary: time-based eviction
        self.matched_outpoints.retain(|_, ts| *ts > cutoff);

        // Secondary: if still over limit, remove oldest entries by timestamp
        if self.matched_outpoints.len() > MAX_MATCHED_OUTPOINTS {
            let target = MAX_MATCHED_OUTPOINTS / 2;
            let mut entries: Vec<(String, Instant)> = self.matched_outpoints.drain().collect();
            entries.sort_by_key(|(_, ts)| *ts);
            // Keep only the newest `target` entries
            let keep_start = entries.len().saturating_sub(target);
            self.matched_outpoints = entries.into_iter().skip(keep_start).collect();
        }

        let after = self.matched_outpoints.len();
        if before != after {
            tracing::info!(
                "[ORDER BOOK] Pruned matched_outpoints: {} -> {} entries (F20, time-based)",
                before,
                after,
            );
        }
    }

    /// Clear all matched outpoints. Used during periodic resets.
    pub fn clear_matched_outpoints(&mut self) {
        let cleared = self.matched_outpoints.len();
        if cleared > 0 {
            tracing::info!(
                "[ORDER BOOK] Cleared {} matched_outpoints entries",
                cleared
            );
        }
        self.matched_outpoints.clear();
    }

    /// Check if an outpoint exists in any pair book (M-7).
    ///
    /// Used by the scanner to prevent duplicate order insertion when the
    /// same block notification is received more than once.
    pub fn contains_outpoint(&self, outpoint_key: &str) -> bool {
        self.outpoint_index.contains_key(outpoint_key)
    }

    /// Look up an order by outpoint key in O(1).
    ///
    /// Uses the global outpoint index to locate the pair book and side,
    /// then retrieves the order from the PairBook's internal HashMap.
    pub fn get_order(&self, outpoint_key: &str) -> Option<&BookOrder> {
        let (token_cov_id, side) = self.outpoint_index.get(outpoint_key)?;
        let book = self.pair_books.get(token_cov_id)?;
        match side {
            OrderSide::Buy => {
                let key = book.bid_outpoints.get(outpoint_key)?;
                book.bids.get(key)
            }
            OrderSide::Sell => {
                let key = book.ask_outpoints.get(outpoint_key)?;
                book.asks.get(key)
            }
        }
    }

    /// Back-fill `counterparty_spk` on an existing order when a rescan
    /// produces a non-None value that was not available on the first scan.
    ///
    /// Root-cause fix for executor dedup path: when the scanner sees a deploy
    /// TX early (e.g., from a mempool/partial block payload where outputs
    /// aren't fully resolved), `extract_owner_spk` returns None and the order
    /// is inserted with `counterparty_spk = None`. Later when the block is
    /// fully indexed, a rescan produces the same outpoint with `Some(spk)`,
    /// but the dedup check discards it — leaving the order un-matchable in
    /// `process_batch_unified` (which skips orders missing counterparty_spk).
    ///
    /// This method performs an in-place update that covers exactly the
    /// None → Some transition; other fields are not touched so existing
    /// matchers and reorg snapshots remain stable.
    ///
    /// Returns `true` when an update was performed.
    pub fn update_counterparty_spk_if_missing(
        &mut self,
        outpoint_key: &str,
        new_spk: &Option<String>,
    ) -> bool {
        let new_spk = match new_spk {
            Some(s) if !s.is_empty() => s.clone(),
            _ => return false,
        };
        let (token_cov_id, side) = match self.outpoint_index.get(outpoint_key) {
            Some(v) => (v.0.clone(), v.1),
            None => return false,
        };
        let book = match self.pair_books.get_mut(&token_cov_id) {
            Some(b) => b,
            None => return false,
        };
        match side {
            OrderSide::Buy => {
                let key = match book.bid_outpoints.get(outpoint_key) {
                    Some(k) => k.clone(),
                    None => return false,
                };
                if let Some(order) = book.bids.get_mut(&key) {
                    if order.counterparty_spk.is_none() {
                        order.counterparty_spk = Some(new_spk);
                        return true;
                    }
                }
            }
            OrderSide::Sell => {
                let key = match book.ask_outpoints.get(outpoint_key) {
                    Some(k) => k.clone(),
                    None => return false,
                };
                if let Some(order) = book.asks.get_mut(&key) {
                    if order.counterparty_spk.is_none() {
                        order.counterparty_spk = Some(new_spk);
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Look up the first order matching a txid in O(1).
    ///
    /// Uses the `txid_index` to find outpoint keys for this txid, then
    /// delegates to `get_order` for each. Returns the first match along
    /// with its pair (token_cov_id) and side.
    pub fn get_order_by_txid(&self, txid: &str) -> Option<(&str, &BookOrder)> {
        let keys = self.txid_index.get(txid)?;
        for outpoint_key in keys {
            if let Some((token_cov_id, _)) = self.outpoint_index.get(outpoint_key.as_str()) {
                if let Some(order) = self.get_order(outpoint_key) {
                    return Some((token_cov_id.as_str(), order));
                }
            }
        }
        None
    }

    /// Remove all orders whose GTD expiry DAA score has been exceeded.
    ///
    /// Returns the removed orders so the caller can build expire TXs to
    /// reclaim their funds on-chain.
    pub fn remove_expired(&mut self, current_daa: u64) -> Vec<BookOrder> {
        // Collect outpoint keys of expired orders first (avoid borrow conflict).
        let expired_keys: Vec<String> = self
            .outpoint_index
            .keys()
            .filter_map(|key| {
                let order = self.get_order(key)?;
                if order.expiry_daa.is_some_and(|e| e > 0 && e <= current_daa) {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect();

        let mut removed = Vec::with_capacity(expired_keys.len());
        for key in &expired_keys {
            // Retrieve the order before removing it.
            if let Some(order) = self.get_order(key).cloned() {
                tracing::info!(
                    "[ORDER BOOK] Removing expired {} order: {} (expiry_daa={:?}, current={})",
                    if order.side == OrderSide::Buy { "BUY" } else { "SELL" },
                    &key[..key.len().min(20)],
                    order.expiry_daa,
                    current_daa,
                );
                removed.push(order);
            }
            self.remove_order(key);
        }
        removed
    }

    /// Get aggregate statistics.
    pub fn stats(&self) -> OrderBookStats {
        let mut stats = OrderBookStats::default();
        for (token_cov_id, book) in &self.pair_books {
            let bids = book.bids.len();
            let asks = book.asks.len();
            if bids + asks > 0 {
                stats.pairs += 1;
                stats.total_bids += bids;
                stats.total_asks += asks;
                stats.by_pair.push(PairStats {
                    token_cov_id: token_cov_id[..token_cov_id.len().min(16)].to_string(),
                    bids,
                    asks,
                });
            }
        }
        stats
    }
}

/// Order book statistics for reporting.
#[derive(Debug, Default)]
pub struct OrderBookStats {
    pub pairs: usize,
    pub total_bids: usize,
    pub total_asks: usize,
    pub by_pair: Vec<PairStats>,
}

#[derive(Debug)]
pub struct PairStats {
    pub token_cov_id: String,
    pub bids: usize,
    pub asks: usize,
}

#[cfg(test)]
impl OrderBook {
    /// Look up which pair and side an outpoint belongs to.
    ///
    /// Returns `Some((token_cov_id, side))` in O(1) via the global index,
    /// or `None` if the outpoint is not in the book.
    pub fn lookup_outpoint(&self, outpoint_key: &str) -> Option<(&str, OrderSide)> {
        self.outpoint_index
            .get(outpoint_key)
            .map(|(tcid, side)| (tcid.as_str(), *side))
    }

    /// Rebuild the global outpoint index and txid index from pair_books.
    ///
    /// Useful after deserialization or manual pair_books manipulation.
    pub fn rebuild_outpoint_index(&mut self) {
        self.outpoint_index.clear();
        self.txid_index.clear();
        for (token_cov_id, book) in &self.pair_books {
            for order in book.bids.values() {
                let key = order.outpoint_key();
                self.outpoint_index.insert(
                    key.clone(),
                    (token_cov_id.clone(), OrderSide::Buy),
                );
                self.txid_index.entry(order.tx_id.clone()).or_default().push(key);
            }
            for order in book.asks.values() {
                let key = order.outpoint_key();
                self.outpoint_index.insert(
                    key.clone(),
                    (token_cov_id.clone(), OrderSide::Sell),
                );
                self.txid_index.entry(order.tx_id.clone()).or_default().push(key);
            }
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sell(tx_id: &str, token_cov_id: &str) -> BookOrder {
        BookOrder {
            tx_id: tx_id.to_string(),
            index: 0,
            value: 10_000_000,
            token_cov_id: token_cov_id.to_string(),
            price_num: 1,
            price_den: 2,
            min_fill: 1_000_000,
            owner_hash: "aa".repeat(32),
            spk_hash: "bb".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Sell,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0, time_meta: None,
        }
    }

    // H-3: sell order with all-zero token_cov_id must be silently dropped.
    #[test]
    fn test_add_sell_zero_token_cov_id_is_skipped() {
        let mut ob = OrderBook::new();
        let zero_tcid = "0".repeat(64);
        let ghost = make_sell("a".repeat(64).as_str(), &zero_tcid);
        ob.add_sell_order(ghost);
        // No pair book entry should be created for the zero id
        assert!(ob.pair_books.is_empty(), "ghost sell must not enter the book");
    }

    // H-3: sell order with a real token_cov_id must be accepted normally.
    #[test]
    fn test_add_sell_valid_token_cov_id_is_accepted() {
        let mut ob = OrderBook::new();
        let real_tcid = "ab".repeat(32);
        let order = make_sell("c".repeat(64).as_str(), &real_tcid);
        ob.add_sell_order(order);
        assert_eq!(ob.pair_books.len(), 1, "valid sell must enter the book");
        assert_eq!(
            ob.pair_books[&real_tcid].asks.len(),
            1,
            "book should contain 1 ask"
        );
    }

    // resolve_counterparty_spk: None when counterparty_spk field is absent.
    #[test]
    fn resolve_counterparty_spk_none_when_absent() {
        let order = make_sell("a".repeat(64).as_str(), &"ab".repeat(32));
        // counterparty_spk is None in make_sell
        assert!(
            order.resolve_counterparty_spk().is_none(),
            "must return None when counterparty_spk is not set"
        );
    }

    // resolve_counterparty_spk: Some when counterparty_spk is set with valid hex.
    #[test]
    fn resolve_counterparty_spk_some_when_set() {
        // Simulate stored counterparty_spk: version (2B LE) + P2PK SPK [0x20][pubkey32][0xac]
        let spk_script: Vec<u8> = std::iter::once(0x20u8)
            .chain([0xABu8; 32].iter().copied())
            .chain(std::iter::once(0xACu8))
            .collect();
        // Stored format: version 0 (0x00, 0x00) + script bytes
        let mut stored: Vec<u8> = vec![0x00, 0x00];
        stored.extend_from_slice(&spk_script);
        let spk_hex = hex::encode(&stored);
        let mut order = make_sell("b".repeat(64).as_str(), &"cd".repeat(32));
        order.counterparty_spk = Some(spk_hex.clone());

        let result = order.resolve_counterparty_spk();
        assert!(result.is_some(), "must return Some when counterparty_spk is set");
        let (version, script) = result.unwrap();
        assert_eq!(version, 0, "version must be 0 (P2PK)");
        assert_eq!(script, spk_script, "script must match the original SPK bytes (without version prefix)");
    }

    // resolve_counterparty_spk: None when counterparty_spk is an empty string.
    #[test]
    fn resolve_counterparty_spk_none_for_empty_hex() {
        let mut order = make_sell("c".repeat(64).as_str(), &"ef".repeat(32));
        order.counterparty_spk = Some(String::new());
        assert!(
            order.resolve_counterparty_spk().is_none(),
            "empty hex string must return None"
        );
    }

    // M-7: OrderBook::contains_outpoint
    #[test]
    fn test_order_book_contains_outpoint() {
        let mut ob = OrderBook::new();
        let tcid = "ab".repeat(32);
        let outpoint = format!("{}:0", "a".repeat(64));

        assert!(!ob.contains_outpoint(&outpoint), "empty book should not contain anything");

        let order = make_sell("a".repeat(64).as_str(), &tcid);
        ob.add_sell_order(order);

        assert!(ob.contains_outpoint(&outpoint), "should find outpoint in asks");
        assert!(!ob.contains_outpoint("nonexistent:0"), "should not find nonexistent outpoint");
    }

    // Memory cap: per-pair order limit
    #[test]
    fn test_max_orders_per_pair_rejects_excess() {
        let mut ob = OrderBook::new();
        let tcid = "ab".repeat(32);
        // Fill to MAX_ORDERS_PER_PAIR
        for i in 0..MAX_ORDERS_PER_PAIR {
            let tx_id = format!("{:064x}", i);
            let order = make_sell(&tx_id, &tcid);
            assert!(ob.add_sell_order(order), "order {} should be accepted", i);
        }
        // Next order should be rejected
        let overflow = make_sell(&format!("{:064x}", MAX_ORDERS_PER_PAIR), &tcid);
        assert!(!ob.add_sell_order(overflow), "should reject when at capacity");
    }

    // Memory cap: total pairs limit
    #[test]
    fn test_max_total_pairs_rejects_new_pair() {
        let mut ob = OrderBook::new();
        for i in 0..MAX_TOTAL_PAIRS {
            let tcid = format!("{:064x}", i + 1); // +1 to avoid all-zero
            let tx_id = format!("{:064x}", i + 0x10000);
            let order = make_sell(&tx_id, &tcid);
            assert!(ob.add_sell_order(order), "pair {} should be accepted", i);
        }
        assert_eq!(ob.pair_books.len(), MAX_TOTAL_PAIRS);
        // New pair should be rejected
        let new_tcid = format!("{:064x}", MAX_TOTAL_PAIRS + 1);
        let overflow = make_sell(&format!("{:064x}", 0xFFFFF), &new_tcid);
        assert!(!ob.add_sell_order(overflow), "should reject new pair beyond cap");
    }

    // Cleanup: empty pairs removed after order removal
    #[test]
    fn test_cleanup_empty_pairs() {
        let mut ob = OrderBook::new();
        let tcid = "ab".repeat(32);
        let tx_id = "a".repeat(64);
        let order = make_sell(&tx_id, &tcid);
        ob.add_sell_order(order);
        assert_eq!(ob.pair_books.len(), 1);

        let outpoint = format!("{}:0", tx_id);
        ob.remove_order(&outpoint);
        // After removing the only order, the pair should be cleaned up
        assert_eq!(ob.pair_books.len(), 0, "empty pair should be removed");
    }

    #[test]
    fn test_order_book_contains_outpoint_across_pairs() {
        let mut ob = OrderBook::new();
        let tcid_a = "ab".repeat(32);
        let tcid_b = "cd".repeat(32);

        let order_a = make_sell("a".repeat(64).as_str(), &tcid_a);
        let order_b = make_sell("b".repeat(64).as_str(), &tcid_b);
        ob.add_sell_order(order_a);
        ob.add_sell_order(order_b);

        let key_a = format!("{}:0", "a".repeat(64));
        let key_b = format!("{}:0", "b".repeat(64));
        assert!(ob.contains_outpoint(&key_a), "should find in pair A");
        assert!(ob.contains_outpoint(&key_b), "should find in pair B");
    }

    // Outpoint index: O(1) lookup, get_order, and index maintenance
    #[test]
    fn test_outpoint_index_lookup_and_get_order() {
        let mut ob = OrderBook::new();
        let tcid = "ab".repeat(32);

        // Add a sell order
        let sell = make_sell("a".repeat(64).as_str(), &tcid);
        ob.add_sell_order(sell);
        let sell_key = format!("{}:0", "a".repeat(64));

        // Add a buy order
        let buy = BookOrder {
            tx_id: "b".repeat(64),
            index: 1,
            value: 10_000_000,
            token_cov_id: tcid.clone(),
            price_num: 1,
            price_den: 2,
            min_fill: 1_000_000,
            owner_hash: "cc".repeat(32),
            spk_hash: "dd".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Buy,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0, time_meta: None,
        };
        ob.add_buy_order(buy);
        let buy_key = format!("{}:1", "b".repeat(64));

        // Verify lookup_outpoint returns correct pair and side
        let (lookup_tcid, lookup_side) = ob.lookup_outpoint(&sell_key).expect("sell must be in index");
        assert_eq!(lookup_tcid, tcid);
        assert_eq!(lookup_side, OrderSide::Sell);

        let (lookup_tcid, lookup_side) = ob.lookup_outpoint(&buy_key).expect("buy must be in index");
        assert_eq!(lookup_tcid, tcid);
        assert_eq!(lookup_side, OrderSide::Buy);

        // Verify get_order returns the correct order
        let sell_order = ob.get_order(&sell_key).expect("sell must be retrievable");
        assert_eq!(sell_order.tx_id, "a".repeat(64));
        assert_eq!(sell_order.side, OrderSide::Sell);

        let buy_order = ob.get_order(&buy_key).expect("buy must be retrievable");
        assert_eq!(buy_order.tx_id, "b".repeat(64));
        assert_eq!(buy_order.side, OrderSide::Buy);

        // Nonexistent outpoint
        assert!(ob.lookup_outpoint("nonexistent:0").is_none());
        assert!(ob.get_order("nonexistent:0").is_none());

        // Remove sell, verify index is updated
        ob.remove_order(&sell_key);
        assert!(ob.lookup_outpoint(&sell_key).is_none(), "removed sell must not be in index");
        assert!(ob.get_order(&sell_key).is_none(), "removed sell must not be retrievable");

        // Buy should still be there
        assert!(ob.lookup_outpoint(&buy_key).is_some(), "buy must still be in index");
        assert!(ob.get_order(&buy_key).is_some(), "buy must still be retrievable");
    }

    // Outpoint index: rebuild from pair_books
    #[test]
    fn test_rebuild_outpoint_index() {
        let mut ob = OrderBook::new();
        let tcid = "ab".repeat(32);

        let sell = make_sell("a".repeat(64).as_str(), &tcid);
        ob.add_sell_order(sell);

        // Manually clear the index to simulate stale state
        ob.outpoint_index.clear();
        assert!(!ob.contains_outpoint(&format!("{}:0", "a".repeat(64))));

        // Rebuild
        ob.rebuild_outpoint_index();
        assert!(ob.contains_outpoint(&format!("{}:0", "a".repeat(64))));

        let (lookup_tcid, lookup_side) = ob.lookup_outpoint(&format!("{}:0", "a".repeat(64))).unwrap();
        assert_eq!(lookup_tcid, tcid);
        assert_eq!(lookup_side, OrderSide::Sell);
    }

    // Outpoint index consistency across multiple pairs
    #[test]
    fn test_outpoint_index_multi_pair() {
        let mut ob = OrderBook::new();
        let tcid_a = "ab".repeat(32);
        let tcid_b = "cd".repeat(32);

        let sell_a = make_sell("a".repeat(64).as_str(), &tcid_a);
        let sell_b = make_sell("b".repeat(64).as_str(), &tcid_b);
        ob.add_sell_order(sell_a);
        ob.add_sell_order(sell_b);

        let key_a = format!("{}:0", "a".repeat(64));
        let key_b = format!("{}:0", "b".repeat(64));

        // Each outpoint maps to its own pair
        let (tcid, _) = ob.lookup_outpoint(&key_a).unwrap();
        assert_eq!(tcid, tcid_a);
        let (tcid, _) = ob.lookup_outpoint(&key_b).unwrap();
        assert_eq!(tcid, tcid_b);

        // Remove from pair A does not affect pair B
        ob.remove_order(&key_a);
        assert!(ob.lookup_outpoint(&key_a).is_none());
        assert!(ob.lookup_outpoint(&key_b).is_some());
    }

    // E2E Integration: Order caps, pruning, and capacity tests

    fn make_buy(tx_id: &str, token_cov_id: &str) -> BookOrder {
        BookOrder {
            tx_id: tx_id.to_string(),
            index: 0,
            value: 10_000_000,
            token_cov_id: token_cov_id.to_string(),
            price_num: 1,
            price_den: 2,
            min_fill: 1_000_000,
            owner_hash: "cc".repeat(32),
            spk_hash: "dd".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Buy,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0, time_meta: None,
        }
    }

    /// Order cap: MAX_TOTAL_PAIRS rejects new pairs when limit is reached.
    #[test]
    fn e2e_max_total_pairs_cap() {
        let mut ob = OrderBook::new();

        // Fill up to MAX_TOTAL_PAIRS
        for i in 0..MAX_TOTAL_PAIRS {
            let tcid = format!("{:064x}", i);
            let tx_id = format!("{:064x}", i + 10000);
            let order = make_buy(&tx_id, &tcid);
            let added = ob.add_buy_order(order);
            assert!(added, "pair {} should be accepted", i);
        }
        assert_eq!(ob.pair_books.len(), MAX_TOTAL_PAIRS);

        // Next new pair should be rejected
        let new_tcid = format!("{:064x}", MAX_TOTAL_PAIRS + 1);
        let new_tx = format!("{:064x}", MAX_TOTAL_PAIRS + 10001);
        let rejected = ob.add_buy_order(make_buy(&new_tx, &new_tcid));
        assert!(!rejected, "new pair beyond MAX_TOTAL_PAIRS should be rejected");

        // But adding to an existing pair should still work
        let existing_tcid = format!("{:064x}", 0);
        let extra_tx = format!("{:064x}", MAX_TOTAL_PAIRS + 20000);
        let accepted = ob.add_buy_order(make_buy(&extra_tx, &existing_tcid));
        assert!(accepted, "adding to existing pair should still work");
    }

    /// Order cap: MAX_TOTAL_PAIRS for sell orders too.
    #[test]
    fn e2e_max_total_pairs_sell_rejection() {
        let mut ob = OrderBook::new();
        // Start from 1 to avoid all-zero tcid (ghost filter)
        for i in 1..=MAX_TOTAL_PAIRS {
            let tcid = format!("{:064x}", i);
            let tx_id = format!("{:064x}", i + 10000);
            ob.add_sell_order(make_sell(&tx_id, &tcid));
        }
        assert_eq!(ob.pair_books.len(), MAX_TOTAL_PAIRS);
        let new_tcid = format!("{:064x}", MAX_TOTAL_PAIRS + 1);
        let new_tx = format!("{:064x}", MAX_TOTAL_PAIRS + 10001);
        let rejected = ob.add_sell_order(make_sell(&new_tx, &new_tcid));
        assert!(!rejected, "sell for new pair beyond MAX_TOTAL_PAIRS should be rejected");
    }

    /// Per-pair order cap: MAX_ORDERS_PER_PAIR rejects when limit is reached.
    #[test]
    fn e2e_max_orders_per_pair_cap() {
        let mut ob = OrderBook::new();
        let tcid = "ab".repeat(32);

        // Fill a single pair to MAX_ORDERS_PER_PAIR
        for i in 0..MAX_ORDERS_PER_PAIR {
            let tx_id = format!("{:064x}", i);
            let mut order = make_buy(&tx_id, &tcid);
            order.value = 10_000_000 + i as u64; // unique values for BTreeMap
            let added = ob.add_buy_order(order);
            assert!(added, "order {} should be accepted", i);
        }

        let book = ob.pair_books.get(&tcid).unwrap();
        assert_eq!(book.bids.len(), MAX_ORDERS_PER_PAIR);

        // Next order in this pair should be rejected
        let overflow_tx = format!("{:064x}", MAX_ORDERS_PER_PAIR + 1);
        let rejected = ob.add_buy_order(make_buy(&overflow_tx, &tcid));
        assert!(!rejected, "order beyond MAX_ORDERS_PER_PAIR should be rejected");
    }

    /// Matched outpoints pruning: when set exceeds MAX_MATCHED_OUTPOINTS,
    /// it auto-prunes to half.
    #[test]
    fn e2e_matched_outpoints_auto_pruning() {
        let mut ob = OrderBook::new();

        // Manually fill matched_outpoints beyond the threshold
        for i in 0..10_001 {
            ob.matched_outpoints.insert(format!("fake:{}:{}", "a".repeat(60), i), Instant::now());
        }
        assert!(ob.matched_outpoints.len() > 10_000);

        // Trigger pruning via remove_order (which checks the threshold)
        let tcid = "ab".repeat(32);
        let order = make_sell("x".repeat(64).as_str(), &tcid);
        let key = order.outpoint_key();
        ob.add_sell_order(order);
        ob.remove_order(&key);

        // After remove_order, matched_outpoints should have been pruned
        assert!(
            ob.matched_outpoints.len() <= 10_001,
            "matched_outpoints should be pruned after exceeding threshold"
        );
    }

    /// Cleanup empty pairs: removing all orders from a pair removes the pair book.
    #[test]
    fn e2e_cleanup_empty_pairs() {
        let mut ob = OrderBook::new();
        let tcid = "ab".repeat(32);

        let order = make_sell("a".repeat(64).as_str(), &tcid);
        let key = order.outpoint_key();
        ob.add_sell_order(order);
        assert_eq!(ob.pair_books.len(), 1);

        ob.remove_order(&key);
        assert_eq!(ob.pair_books.len(), 0, "empty pair book should be cleaned up");
    }

    /// Ghost sell order (all-zero token_cov_id) rejected by add_sell_order.
    #[test]
    fn e2e_ghost_sell_zero_tcid_rejected() {
        let mut ob = OrderBook::new();
        let zero_tcid = "00".repeat(32);
        let ghost = make_sell("a".repeat(64).as_str(), &zero_tcid);
        let added = ob.add_sell_order(ghost);
        assert!(!added, "ghost sell with zero tcid should return false");
        assert!(ob.pair_books.is_empty());
    }

    /// OrderBook::get_order retrieves order in O(1).
    #[test]
    fn e2e_get_order_by_outpoint() {
        let mut ob = OrderBook::new();
        let tcid = "ab".repeat(32);
        let order = make_buy("a".repeat(64).as_str(), &tcid);
        let key = order.outpoint_key();
        ob.add_buy_order(order);

        let found = ob.get_order(&key);
        assert!(found.is_some(), "get_order should find the order");
        assert_eq!(found.unwrap().tx_id, "a".repeat(64));

        // Non-existent key
        assert!(ob.get_order("nonexistent:0").is_none());
    }

    /// Rebuild outpoint index from pair_books.
    #[test]
    fn e2e_rebuild_outpoint_index() {
        let mut ob = OrderBook::new();
        let tcid = "ab".repeat(32);
        let order = make_buy("a".repeat(64).as_str(), &tcid);
        let key = order.outpoint_key();
        ob.add_buy_order(order);

        // Clear index manually, then rebuild
        ob.outpoint_index.clear();
        assert!(ob.lookup_outpoint(&key).is_none());

        ob.rebuild_outpoint_index();
        assert!(ob.lookup_outpoint(&key).is_some());
    }

    /// Stats correctly counts across multiple pairs.
    #[test]
    fn e2e_stats_multi_pair() {
        let mut ob = OrderBook::new();
        let tcid_a = "0a".repeat(32);
        let tcid_b = "0b".repeat(32);

        ob.add_buy_order(make_buy("a".repeat(64).as_str(), &tcid_a));
        ob.add_buy_order(make_buy("b".repeat(64).as_str(), &tcid_a));
        ob.add_sell_order(make_sell("c".repeat(64).as_str(), &tcid_b));

        let stats = ob.stats();
        assert_eq!(stats.pairs, 2);
        assert_eq!(stats.total_bids, 2);
        assert_eq!(stats.total_asks, 1);
        assert_eq!(stats.by_pair.len(), 2);
    }

    // Post-Only tests

    fn make_buy_at(tx_id: &str, token_cov_id: &str, price_num: u64, price_den: u64, post_only: bool) -> BookOrder {
        BookOrder {
            tx_id: tx_id.to_string(),
            index: 0,
            value: 10_000_000,
            token_cov_id: token_cov_id.to_string(),
            price_num,
            price_den,
            min_fill: 1_000_000,
            owner_hash: "aa".repeat(32),
            spk_hash: "bb".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Buy,
            post_only,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0, time_meta: None,
        }
    }

    fn make_sell_at(tx_id: &str, token_cov_id: &str, price_num: u64, price_den: u64, post_only: bool) -> BookOrder {
        BookOrder {
            tx_id: tx_id.to_string(),
            index: 0,
            value: 10_000_000,
            token_cov_id: token_cov_id.to_string(),
            price_num,
            price_den,
            min_fill: 1_000_000,
            owner_hash: "cc".repeat(32),
            spk_hash: "dd".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Sell,
            post_only,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0, time_meta: None,
        }
    }

    /// Post-only buy that does NOT cross the spread should be accepted.
    #[test]
    fn post_only_buy_accepted_when_no_asks() {
        let mut ob = OrderBook::new();
        let tcid = "ab".repeat(32);
        let buy = make_buy_at("a".repeat(64).as_str(), &tcid, 1, 2, true);
        assert!(ob.add_buy_order(buy), "post-only buy with no asks must be accepted");
        assert_eq!(ob.pair_books[&tcid].bids.len(), 1);
    }

    /// Post-only buy that does NOT cross (price below best ask) is accepted.
    #[test]
    fn post_only_buy_accepted_when_below_best_ask() {
        let mut ob = OrderBook::new();
        let tcid = "ab".repeat(32);
        // Ask at price 3/1 (price = 3.0)
        ob.add_sell_order(make_sell_at("s".repeat(64).as_str(), &tcid, 3, 1, false));
        // Post-only buy at price 2/1 (price = 2.0) -- below best ask, should be accepted
        let buy = make_buy_at("b".repeat(64).as_str(), &tcid, 2, 1, true);
        assert!(ob.add_buy_order(buy), "post-only buy below best ask must be accepted");
        assert_eq!(ob.pair_books[&tcid].bids.len(), 1);
    }

    /// Post-only buy that WOULD cross the spread is rejected.
    #[test]
    fn post_only_buy_rejected_when_crosses_ask() {
        let mut ob = OrderBook::new();
        let tcid = "ab".repeat(32);
        // Ask at price 2/1 (price = 2.0)
        ob.add_sell_order(make_sell_at("s".repeat(64).as_str(), &tcid, 2, 1, false));
        // Post-only buy at price 3/1 (price = 3.0) -- above best ask, would cross
        let buy = make_buy_at("b".repeat(64).as_str(), &tcid, 3, 1, true);
        assert!(!ob.add_buy_order(buy), "post-only buy crossing spread must be rejected");
        assert!(ob.pair_books[&tcid].bids.is_empty());
    }

    /// Post-only buy at exactly the best ask price is rejected (would cross).
    #[test]
    fn post_only_buy_rejected_at_exact_ask_price() {
        let mut ob = OrderBook::new();
        let tcid = "ab".repeat(32);
        // Ask at price 5/2 (price = 2.5)
        ob.add_sell_order(make_sell_at("s".repeat(64).as_str(), &tcid, 5, 2, false));
        // Post-only buy at price 5/2 -- equals best ask, would cross
        let buy = make_buy_at("b".repeat(64).as_str(), &tcid, 5, 2, true);
        assert!(!ob.add_buy_order(buy), "post-only buy at exact ask price must be rejected");
    }

    /// Non-post-only buy that crosses is still accepted (normal behavior).
    #[test]
    fn non_post_only_buy_accepted_when_crosses() {
        let mut ob = OrderBook::new();
        let tcid = "ab".repeat(32);
        ob.add_sell_order(make_sell_at("s".repeat(64).as_str(), &tcid, 2, 1, false));
        let buy = make_buy_at("b".repeat(64).as_str(), &tcid, 3, 1, false);
        assert!(ob.add_buy_order(buy), "non-post-only buy must be accepted even if crossing");
        assert_eq!(ob.pair_books[&tcid].bids.len(), 1);
    }

    /// Post-only sell that does NOT cross the spread should be accepted.
    #[test]
    fn post_only_sell_accepted_when_no_bids() {
        let mut ob = OrderBook::new();
        let tcid = "ab".repeat(32);
        let sell = make_sell_at("s".repeat(64).as_str(), &tcid, 5, 1, true);
        assert!(ob.add_sell_order(sell), "post-only sell with no bids must be accepted");
        assert_eq!(ob.pair_books[&tcid].asks.len(), 1);
    }

    /// Post-only sell that does NOT cross (price above best bid) is accepted.
    #[test]
    fn post_only_sell_accepted_when_above_best_bid() {
        let mut ob = OrderBook::new();
        let tcid = "ab".repeat(32);
        // Bid at price 2/1 (price = 2.0)
        ob.add_buy_order(make_buy_at("b".repeat(64).as_str(), &tcid, 2, 1, false));
        // Post-only sell at price 3/1 (price = 3.0) -- above best bid, should be accepted
        let sell = make_sell_at("s".repeat(64).as_str(), &tcid, 3, 1, true);
        assert!(ob.add_sell_order(sell), "post-only sell above best bid must be accepted");
        assert_eq!(ob.pair_books[&tcid].asks.len(), 1);
    }

    /// Post-only sell that WOULD cross the spread is rejected.
    #[test]
    fn post_only_sell_rejected_when_crosses_bid() {
        let mut ob = OrderBook::new();
        let tcid = "ab".repeat(32);
        // Bid at price 3/1 (price = 3.0)
        ob.add_buy_order(make_buy_at("b".repeat(64).as_str(), &tcid, 3, 1, false));
        // Post-only sell at price 2/1 (price = 2.0) -- below best bid, would cross
        let sell = make_sell_at("s".repeat(64).as_str(), &tcid, 2, 1, true);
        assert!(!ob.add_sell_order(sell), "post-only sell crossing spread must be rejected");
        // The bid pair book should exist but have no asks
        assert!(ob.pair_books[&tcid].asks.is_empty());
    }

    /// Post-only sell at exactly the best bid price is rejected (would cross).
    #[test]
    fn post_only_sell_rejected_at_exact_bid_price() {
        let mut ob = OrderBook::new();
        let tcid = "ab".repeat(32);
        ob.add_buy_order(make_buy_at("b".repeat(64).as_str(), &tcid, 5, 2, false));
        let sell = make_sell_at("s".repeat(64).as_str(), &tcid, 5, 2, true);
        assert!(!ob.add_sell_order(sell), "post-only sell at exact bid price must be rejected");
    }

    /// Non-post-only sell that crosses is still accepted (normal behavior).
    #[test]
    fn non_post_only_sell_accepted_when_crosses() {
        let mut ob = OrderBook::new();
        let tcid = "ab".repeat(32);
        ob.add_buy_order(make_buy_at("b".repeat(64).as_str(), &tcid, 3, 1, false));
        let sell = make_sell_at("s".repeat(64).as_str(), &tcid, 2, 1, false);
        assert!(ob.add_sell_order(sell), "non-post-only sell must be accepted even if crossing");
        assert_eq!(ob.pair_books[&tcid].asks.len(), 1);
    }

    /// Post-only buy on empty book (no pair book yet) is accepted.
    #[test]
    fn post_only_buy_on_new_pair_accepted() {
        let mut ob = OrderBook::new();
        let tcid = "ff".repeat(32);
        let buy = make_buy_at("x".repeat(64).as_str(), &tcid, 100, 1, true);
        assert!(ob.add_buy_order(buy), "post-only buy on brand new pair must be accepted");
        assert_eq!(ob.pair_books.len(), 1);
    }

    /// PairBook::would_buy_cross returns false on empty book.
    #[test]
    fn would_buy_cross_empty_book() {
        let book = PairBook::new();
        assert!(!book.would_buy_cross(100, 1), "empty asks => no crossing possible");
    }

    /// PairBook::would_sell_cross returns false on empty book.
    #[test]
    fn would_sell_cross_empty_book() {
        let book = PairBook::new();
        assert!(!book.would_sell_cross(1, 100), "empty bids => no crossing possible");
    }

    /// PairBook::would_buy_cross with rational price comparison.
    #[test]
    fn would_buy_cross_rational_prices() {
        let mut book = PairBook::new();
        // Ask at 3/4 = 0.75
        book.add_ask(make_sell_at("s".repeat(64).as_str(), &"ab".repeat(32), 3, 4, false));
        // Buy at 2/3 = 0.667 < 0.75 -> no cross
        assert!(!book.would_buy_cross(2, 3));
        // Buy at 3/4 = 0.75 == 0.75 -> cross (equal counts)
        assert!(book.would_buy_cross(3, 4));
        // Buy at 4/5 = 0.80 > 0.75 -> cross
        assert!(book.would_buy_cross(4, 5));
    }

    /// PairBook::would_sell_cross with rational price comparison.
    #[test]
    fn would_sell_cross_rational_prices() {
        let mut book = PairBook::new();
        // Bid at 3/4 = 0.75
        book.add_bid(make_buy_at("b".repeat(64).as_str(), &"ab".repeat(32), 3, 4, false));
        // Sell at 4/5 = 0.80 > 0.75 -> no cross
        assert!(!book.would_sell_cross(4, 5));
        // Sell at 3/4 = 0.75 == 0.75 -> cross (equal counts)
        assert!(book.would_sell_cross(3, 4));
        // Sell at 2/3 = 0.667 < 0.75 -> cross
        assert!(book.would_sell_cross(2, 3));
    }

    /// BookOrder defaults post_only to false via serde deserialization.
    #[test]
    fn post_only_defaults_false_via_serde() {
        let json = r#"{
            "tx_id": "aaaa",
            "index": 0,
            "value": 1000,
            "token_cov_id": "bbbb",
            "price_num": 1,
            "price_den": 1,
            "min_fill": 100,
            "owner_hash": "cccc",
            "spk_hash": "dddd",
            "counterparty_spk": null,
            "redeem_script_hex": "",
            "p2sh_script_hex": "",
            "p2sh_version": 0,
            "side": "Buy"
        }"#;
        let order: BookOrder = serde_json::from_str(json).expect("deserialization must succeed");
        assert!(!order.post_only, "post_only must default to false when absent from JSON");
    }

    // remove_expired tests

    fn make_buy_with_expiry(tx_id: &str, token_cov_id: &str, expiry: Option<u64>) -> BookOrder {
        BookOrder {
            tx_id: tx_id.to_string(),
            index: 0,
            value: 10_000_000,
            token_cov_id: token_cov_id.to_string(),
            price_num: 1,
            price_den: 2,
            min_fill: 1_000_000,
            owner_hash: "aa".repeat(32),
            spk_hash: "bb".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Buy,
            post_only: false,
            expiry_daa: expiry,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0, time_meta: None,
        }
    }

    #[test]
    fn test_remove_expired_removes_expired_orders() {
        let mut ob = OrderBook::new();
        let tcid = "ab".repeat(32);
        ob.add_buy_order(make_buy_with_expiry(&"a".repeat(64), &tcid, Some(100)));
        ob.add_buy_order(make_buy_with_expiry(&"b".repeat(64), &tcid, Some(200)));
        ob.add_buy_order(make_buy_with_expiry(&"c".repeat(64), &tcid, None)); // GTC
        assert_eq!(ob.pair_books[&tcid].bids.len(), 3);

        let removed = ob.remove_expired(150);
        assert_eq!(removed.len(), 1, "Only the order with expiry=100 should be removed");
        assert_eq!(removed[0].tx_id, "a".repeat(64));
        assert_eq!(ob.pair_books[&tcid].bids.len(), 2);
    }

    #[test]
    fn test_remove_expired_skips_gtc_orders() {
        let mut ob = OrderBook::new();
        let tcid = "cd".repeat(32);
        ob.add_buy_order(make_buy_with_expiry(&"a".repeat(64), &tcid, None));
        ob.add_buy_order(make_buy_with_expiry(&"b".repeat(64), &tcid, Some(0))); // expiry=0 means GTC

        let removed = ob.remove_expired(999_999);
        assert_eq!(removed.len(), 0, "GTC orders (None or 0) must not be removed");
    }

    #[test]
    fn test_remove_expired_boundary() {
        let mut ob = OrderBook::new();
        let tcid = "ef".repeat(32);
        ob.add_buy_order(make_buy_with_expiry(&"a".repeat(64), &tcid, Some(100)));

        // At exact expiry (current_daa == expiry), order should be removed
        let removed = ob.remove_expired(100);
        assert_eq!(removed.len(), 1, "Order at exact expiry boundary should be removed");
    }

    #[test]
    fn test_remove_expired_not_yet_expired() {
        let mut ob = OrderBook::new();
        let tcid = "12".repeat(32);
        ob.add_buy_order(make_buy_with_expiry(&"a".repeat(64), &tcid, Some(200)));

        let removed = ob.remove_expired(100);
        assert_eq!(removed.len(), 0, "Order not yet expired should not be removed");
    }

    // Top-of-book cache tests (denormalized best-bid/best-ask + top-K)

    /// Best bid/ask reflect price priority immediately after insert, with no
    /// separate refresh call needed (maintained incrementally on add).
    #[test]
    fn top_of_book_best_bid_ask_track_price_priority() {
        let mut book = PairBook::new();
        assert!(book.best_bid().is_none());
        assert!(book.best_ask().is_none());

        book.add_bid(make_buy_at("a".repeat(64).as_str(), &"ab".repeat(32), 1, 2, false)); // 0.5
        book.add_bid(make_buy_at("b".repeat(64).as_str(), &"ab".repeat(32), 3, 4, false)); // 0.75 (better bid)
        assert_eq!(book.best_bid().unwrap().price_num, 3, "higher bid price should be best");
        assert_eq!(book.best_bid().unwrap().price_den, 4);

        book.add_ask(make_sell_at("c".repeat(64).as_str(), &"ab".repeat(32), 9, 10, false)); // 0.9
        book.add_ask(make_sell_at("d".repeat(64).as_str(), &"ab".repeat(32), 4, 5, false)); // 0.8 (better ask)
        assert_eq!(book.best_ask().unwrap().price_num, 4, "lower ask price should be best");
        assert_eq!(book.best_ask().unwrap().price_den, 5);
    }

    /// Removing the current best bid/ask promotes the next-best level.
    #[test]
    fn top_of_book_removal_promotes_next_level() {
        let mut book = PairBook::new();
        let best_key = "a".repeat(64);
        let second_key = "b".repeat(64);
        book.add_bid(make_buy_at(&best_key, &"ab".repeat(32), 3, 4, false)); // 0.75 best
        book.add_bid(make_buy_at(&second_key, &"ab".repeat(32), 1, 2, false)); // 0.5

        assert_eq!(book.best_bid().unwrap().outpoint_key, format!("{}:0", best_key));

        book.remove_bid(&format!("{}:0", best_key));
        assert_eq!(
            book.best_bid().unwrap().outpoint_key,
            format!("{}:0", second_key),
            "removing the best bid must promote the next-best level"
        );

        book.remove_bid(&format!("{}:0", second_key));
        assert!(book.best_bid().is_none(), "removing the last bid must clear best_bid");
    }

    /// The cache retains at most TOP_OF_BOOK_DEPTH levels even when more
    /// orders exist in the pair.
    #[test]
    fn top_of_book_depth_is_capped() {
        let mut book = PairBook::new();
        let tcid = "ab".repeat(32);
        let total = TOP_OF_BOOK_DEPTH + 5;
        for i in 0..total {
            // Distinct, monotonically improving-for-bids prices: higher i => higher price.
            book.add_bid(make_buy_at(&format!("{:064x}", i), &tcid, (i + 1) as u64, 1, false));
        }
        assert_eq!(book.bids.len(), total, "all orders should be in the full book");
        assert_eq!(book.top_bids().len(), TOP_OF_BOOK_DEPTH, "cache must be capped at TOP_OF_BOOK_DEPTH");
        // Best bid must be the highest price (i = total - 1 => price total).
        assert_eq!(book.best_bid().unwrap().price_num, total as u64);
        // Cache must be sorted best-first.
        for w in book.top_bids().windows(2) {
            assert!(w[0].price_num >= w[1].price_num, "top_bids must be sorted best (highest) first");
        }
    }

    /// get_bid/get_ask resolve the full BookOrder for a cached outpoint key.
    #[test]
    fn top_of_book_get_bid_ask_resolve_full_order() {
        let mut book = PairBook::new();
        let tcid = "ab".repeat(32);
        book.add_ask(make_sell_at("c".repeat(64).as_str(), &tcid, 1, 2, false));

        let tq = book.best_ask().expect("ask must be present").clone();
        let full = book.get_ask(&tq.outpoint_key).expect("must resolve full order from cache key");
        assert_eq!(full.tx_id, "c".repeat(64));
        assert_eq!(full.price_num, 1);
        assert_eq!(full.price_den, 2);

        assert!(book.get_bid(&tq.outpoint_key).is_none(), "ask key must not resolve as a bid");
    }

    /// OrderBook-level insertion (add_buy_order/add_sell_order) maintains the
    /// per-pair top-of-book cache the same way direct PairBook calls do.
    #[test]
    fn top_of_book_maintained_through_order_book_api() {
        let mut ob = OrderBook::new();
        let tcid = "ab".repeat(32);
        ob.add_buy_order(make_buy_at("a".repeat(64).as_str(), &tcid, 1, 2, false));
        ob.add_buy_order(make_buy_at("b".repeat(64).as_str(), &tcid, 3, 4, false));

        let book = ob.pair_books.get(&tcid).unwrap();
        assert_eq!(book.best_bid().unwrap().price_num, 3, "best bid via OrderBook::add_buy_order");

        let key = format!("{}:0", "b".repeat(64));
        ob.remove_order(&key);
        let book = ob.pair_books.get(&tcid).unwrap();
        assert_eq!(book.best_bid().unwrap().price_num, 1, "removal via OrderBook::remove_order must refresh cache");
    }
}
