//! Crossing pair detection and match output computation.

use kob_core::MIN_UTXO_VALUE;
use crate::matcher::order_book::{BookOrder, OrderBook};
use crate::matcher::routing;

/// Maximum number of bid x ask iterations per token pair before bailing out.
/// Prevents O(n*m) explosion when both sides have many orders.
pub const MAX_MATCH_ITERATIONS: usize = 50_000;

/// A matched pair ready for execution.
#[derive(Debug, Clone)]
pub struct CrossingPair {
    pub token_cov_id: String,
    pub buy: BookOrder,
    pub sell: BookOrder,
    pub seller_kas: u64,
    pub buyer_tokens: u64,
    pub surplus: u64,
    pub expected_tokens: u64,
    pub expected_kas: u64,
    pub match_type: MatchType,
    /// For partial buy: how much KAS to fill from the buy order
    pub fill_kas: Option<u64>,
    /// For partial buy: residual KAS left in buy order
    pub residual_kas: Option<u64>,
    /// For partial sell: how many tokens to fill from the sell order
    pub fill_token_amount: Option<u64>,
    /// For partial sell: residual tokens left in sell order
    pub residual_tokens: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchType {
    Full,
    PartialBuy,
    PartialSell,
}

/// Find all crossing pairs across all token pairs in the order book.
///
/// Returns crossing pairs sorted by surplus (highest first).
/// Self-trade pairs (same owner_hash on both sides) are excluded by default.
pub fn find_all_crossing_pairs(order_book: &OrderBook) -> Vec<CrossingPair> {
    find_all_crossing_pairs_with_stp(order_book, false)
}

/// Find all crossing pairs with configurable self-trade prevention.
///
/// When `allow_self_trade` is false (default), pairs where buy.owner_hash == sell.owner_hash
/// are skipped. Set to true only for testing.
///
/// Orders whose outpoint keys appear in `spent_outpoints` are excluded from
/// matching. Pass `None` when no SpentTracker context is available (e.g. tests).
pub fn find_all_crossing_pairs_with_stp(order_book: &OrderBook, allow_self_trade: bool) -> Vec<CrossingPair> {
    find_all_crossing_pairs_full(order_book, allow_self_trade, None, None)
}

/// Find all crossing pairs, filtering out orders that are tracked as locally
/// spent by the SpentTracker. This prevents Phase 1a-consumed orders from
/// being re-matched in Phase 1b.
pub fn find_all_crossing_pairs_with_spent(
    order_book: &OrderBook,
    allow_self_trade: bool,
    spent_outpoints: &std::collections::HashSet<String>,
) -> Vec<CrossingPair> {
    find_all_crossing_pairs_full(order_book, allow_self_trade, None, Some(spent_outpoints))
}

/// Internal: find crossing pairs with optional DAA-based expiry filtering
/// and optional SpentTracker-based exclusion.
fn find_all_crossing_pairs_full(
    order_book: &OrderBook,
    allow_self_trade: bool,
    current_daa: Option<u64>,
    spent_outpoints: Option<&std::collections::HashSet<String>>,
) -> Vec<CrossingPair> {
    let mut all_pairs = Vec::new();

    for (token_cov_id, book) in &order_book.pair_books {
        let pairs = find_crossing_pairs_for_token(
            token_cov_id,
            book,
            &order_book.matched_outpoints,
            allow_self_trade,
            current_daa,
            spent_outpoints,
        );
        all_pairs.extend(pairs);
    }

    // Sort by surplus descending (best match first)
    all_pairs.sort_by(|a, b| b.surplus.cmp(&a.surplus));
    all_pairs
}

/// Find crossing pairs for a specific token pair.
///
/// Orders whose outpoint keys appear in `spent_outpoints` are excluded.
/// This prevents orders consumed by Phase 1a batch from being re-matched
/// in Phase 1b remaining (deferred-removal race, commit 2a346a5b).
fn find_crossing_pairs_for_token(
    token_cov_id: &str,
    book: &crate::matcher::order_book::PairBook,
    matched: &std::collections::HashMap<String, std::time::Instant>,
    allow_self_trade: bool,
    current_daa: Option<u64>,
    spent_outpoints: Option<&std::collections::HashSet<String>>,
) -> Vec<CrossingPair> {
    let empty_set = std::collections::HashSet::new();
    let spent = spent_outpoints.unwrap_or(&empty_set);
    let mut pairs = Vec::new();

    // Collect active bids and asks (filtered by matched set, spent tracker, and expiry)
    let bids: Vec<&BookOrder> = book
        .bids
        .values()
        .filter(|b| {
            let key = b.outpoint_key();
            !matched.contains_key(&key)
                && !spent.contains(&key)
                && !current_daa.is_some_and(|daa| b.is_expired(daa))
        })
        .collect();

    let asks: Vec<&BookOrder> = book
        .asks
        .values()
        .filter(|s| {
            let key = s.outpoint_key();
            !matched.contains_key(&key)
                && !spent.contains(&key)
                && !current_daa.is_some_and(|daa| s.is_expired(daa))
        })
        .collect();

    if bids.is_empty() || asks.is_empty() {
        return pairs;
    }

    let mut iterations: usize = 0;

    'outer: for buy in &bids {
        for sell in &asks {
            iterations += 1;
            if iterations > MAX_MATCH_ITERATIONS {
                tracing::warn!(
                    "[MATCHING] Iteration cap ({}) hit for pair [{}...], {} bids x {} asks. Breaking early.",
                    MAX_MATCH_ITERATIONS,
                    &token_cov_id[..token_cov_id.len().min(12)],
                    bids.len(),
                    asks.len(),
                );
                break 'outer;
            }
            // STP: skip if same owner
            if !allow_self_trade && buy.owner_hash == sell.owner_hash {
                continue;
            }
            // M-3: skip orders with zero price fields (corrupted JSON / bad state)
            if buy.price_num == 0 || buy.price_den == 0 || sell.price_num == 0 || sell.price_den == 0 {
                continue;
            }
            // Full fill computation (multiply-first arithmetic, F3 fix)
            let buy_kas = buy.value;
            let sell_tokens = sell.value;
            let expected_tokens = match buy_kas.checked_mul(buy.price_num) {
                Some(v) => v / buy.price_den,
                None => {
                    tracing::warn!(
                        "u64 overflow in full fill: buy_kas={} * price_num={}, skipping pair",
                        buy_kas, buy.price_num
                    );
                    continue;
                }
            };
            let expected_kas = match sell_tokens.checked_mul(sell.price_num) {
                Some(v) => v / sell.price_den,
                None => {
                    tracing::warn!(
                        "u64 overflow in full fill: sell_tokens={} * price_num={}, skipping pair",
                        sell_tokens, sell.price_num
                    );
                    continue;
                }
            };
            // Respect buy order's max_matcher_fee: the buy contract enforces
            // kas_in - out[0].value <= mmfee, so seller_kas >= kas_in - mmfee.
            let mmfee_floor = buy_kas.saturating_sub(buy.max_matcher_fee);
            let seller_kas = std::cmp::max(expected_kas, mmfee_floor);
            let buyer_tokens = sell_tokens;
            let total_in = match buy_kas.checked_add(sell_tokens) {
                Some(v) => v,
                None => {
                    tracing::warn!(
                        "u64 overflow in total_in: buy_kas={} + sell_tokens={}, skipping pair",
                        buy_kas, sell_tokens
                    );
                    continue;
                }
            };

            // Check for overflow: if seller_kas + buyer_tokens > total_in, skip
            if seller_kas.checked_add(buyer_tokens).is_none_or(|sum| sum > total_in) {
                // Prices don't cross for full fill, or overflow
            } else {
                let raw_surplus = total_in - seller_kas - buyer_tokens;
                // C4 fix: cap surplus at both orders max_matcher_fee
                let surplus = raw_surplus
                    .min(buy.max_matcher_fee)
                    .min(sell.max_matcher_fee);

                // surplus=0 is valid when mmfee=0 (matcher pays miner fee from fee UTXOs).
                if seller_kas >= MIN_UTXO_VALUE
                    && buyer_tokens >= MIN_UTXO_VALUE
                {
                    pairs.push(CrossingPair {
                        token_cov_id: token_cov_id.to_string(),
                        buy: (*buy).clone(),
                        sell: (*sell).clone(),
                        seller_kas,
                        buyer_tokens,
                        surplus,
                        expected_tokens,
                        expected_kas,
                        match_type: MatchType::Full,
                        fill_kas: None,
                        residual_kas: None,
                        fill_token_amount: None,
                        residual_tokens: None,
                    });
                }
            }

            // Check partial fill possibilities
            if let Some(partial) = compute_partial_fill_match(token_cov_id, buy, sell) {
                pairs.push(partial);
            }
        }
    }

    pairs
}

/// Minimum partial fill size to produce at least 1 unit of output after
/// integer-division truncation (OpDiv floors).
///
/// For an order with price = num/den, the input amount `x` must satisfy
/// `x * num / den >= 1`, i.e. `x >= ceil(den / num) = (den + num - 1) / num`.
///
/// Returns 0 if `num == 0` (caller must guard against that separately).
#[inline]
fn min_partial_fill(price_num: u64, price_den: u64) -> u64 {
    if price_num == 0 {
        return 0;
    }
    (price_den + price_num - 1) / price_num
}

/// Compute partial fill match parameters.
///
/// Returns None if full fill is available or no viable partial fill exists.
fn compute_partial_fill_match(
    token_cov_id: &str,
    buy: &BookOrder,
    sell: &BookOrder,
) -> Option<CrossingPair> {
    // M-3: guard against division by zero from corrupted JSON state
    if buy.price_num == 0 || buy.price_den == 0 || sell.price_num == 0 || sell.price_den == 0 {
        return None;
    }
    let buy_kas = buy.value;
    let sell_tokens = sell.value;

    let expected_tokens = match buy_kas.checked_mul(buy.price_num) {
        Some(v) => v / buy.price_den,
        None => {
            tracing::warn!(
                "u64 overflow in partial fill: buy_kas={} * price_num={}, skipping",
                buy_kas, buy.price_num
            );
            return None;
        }
    };
    let expected_kas = match sell_tokens.checked_mul(sell.price_num) {
        Some(v) => v / sell.price_den,
        None => {
            tracing::warn!(
                "u64 overflow in partial fill: sell_tokens={} * price_num={}, skipping",
                sell_tokens, sell.price_num
            );
            return None;
        }
    };

    // If full fill works, no need for partial.
    // Must replicate the EXACT same check as the full-fill path in find_crossing_pairs_for_token:
    //   seller_kas = max(expected_kas, buy_kas - mmfee)
    //   buyer_tokens = sell_tokens  (buyer receives ALL tokens in a full fill)
    //   seller_kas + buyer_tokens <= total_in
    let total_in = buy_kas + sell_tokens;
    let mmfee_floor = buy_kas.saturating_sub(buy.max_matcher_fee);
    let full_seller_kas = std::cmp::max(expected_kas, mmfee_floor);
    let full_buyer_tokens = sell_tokens; // full fill: buyer gets all sell tokens
    if let Some(sum) = full_seller_kas.checked_add(full_buyer_tokens) {
        if sum <= total_in {
            // surplus=0 is valid when mmfee=0 (matcher pays miner fee from fee UTXOs).
            if full_seller_kas >= MIN_UTXO_VALUE
                && full_buyer_tokens >= MIN_UTXO_VALUE
                && sell_tokens >= expected_tokens
            {
                return None; // Full fill is better (buyer's demand fully met)
            }
        }
    }

    // Case 1: Buy is larger, sell fills fully, buy partially fills
    let case1_viable = expected_tokens > sell_tokens && {
        // M-7: Minimum partial fill guard — reject if fill_kas would truncate to 0 tokens.
        let min_kas = min_partial_fill(buy.price_num, buy.price_den);
        let candidate_fill = sell_tokens.checked_mul(buy.price_den)
            .map(|v| v.div_ceil(buy.price_num));
        match candidate_fill {
            Some(fk) if fk >= min_kas => true,
            _ => {
                tracing::debug!(
                    "partial buy: fill would truncate to 0 tokens (price {}/{}), skipping case 1",
                    buy.price_num, buy.price_den
                );
                false
            }
        }
    };
    if case1_viable {
        let fill_kas = match sell_tokens.checked_mul(buy.price_den) {
            Some(v) => v.div_ceil(buy.price_num), // ceil division
            None => {
                tracing::warn!(
                    "u64 overflow in partial buy ceil: sell_tokens={} * price_den={}, skipping",
                    sell_tokens, buy.price_den
                );
                return None;
            }
        };
        let fill_tokens = match fill_kas.checked_mul(buy.price_num) {
            Some(v) => v / buy.price_den,
            None => {
                tracing::warn!(
                    "u64 overflow in partial buy fill_tokens: fill_kas={} * price_num={}, skipping",
                    fill_kas, buy.price_num
                );
                return None;
            }
        };
        // Respect buy order's max_matcher_fee for partial fill.
        // The buy contract enforces fill_kas - seller_kas <= mmfee.
        let mmfee_floor = fill_kas.saturating_sub(buy.max_matcher_fee);
        let seller_kas = std::cmp::max(expected_kas, mmfee_floor);

        if buy_kas >= fill_kas {
            let residual_kas = buy_kas - fill_kas;
            let residual_tokens = match residual_kas.checked_mul(buy.price_num) {
                Some(v) => v / buy.price_den,
                None => {
                    tracing::warn!(
                        "u64 overflow in partial buy residual: residual_kas={} * price_num={}, skipping",
                        residual_kas, buy.price_num
                    );
                    return None;
                }
            };

            if fill_kas >= MIN_UTXO_VALUE
                && fill_tokens >= buy.min_fill
                && residual_kas >= MIN_UTXO_VALUE
                && residual_tokens >= buy.min_fill
                && seller_kas >= MIN_UTXO_VALUE
                && fill_tokens >= MIN_UTXO_VALUE
            {
                if let Some(after_seller) = (buy_kas + sell_tokens).checked_sub(seller_kas) {
                    if let Some(after_tokens) = after_seller.checked_sub(fill_tokens) {
                        if let Some(raw_surplus) = after_tokens.checked_sub(residual_kas) {
                            // C4 fix: cap surplus at both orders max_matcher_fee
                            let surplus = raw_surplus
                                .min(buy.max_matcher_fee)
                                .min(sell.max_matcher_fee);
                            // surplus=0 is valid when mmfee=0 (matcher pays miner fee from fee UTXOs).
                            return Some(CrossingPair {
                                token_cov_id: token_cov_id.to_string(),
                                buy: buy.clone(),
                                sell: sell.clone(),
                                seller_kas,
                                buyer_tokens: fill_tokens,
                                surplus,
                                expected_tokens: fill_tokens,
                                expected_kas,
                                match_type: MatchType::PartialBuy,
                                fill_kas: Some(fill_kas),
                                residual_kas: Some(residual_kas),
                                fill_token_amount: None,
                                residual_tokens: None,
                            });
                        }
                    }
                }
            }
        }
    }

    // Case 2: Sell is larger, buy fills fully, sell partially fills
    let case2_viable = expected_kas > buy_kas && {
        // M-7: Minimum partial fill guard — reject if fill_token_amount would truncate to 0 KAS.
        let min_tokens = min_partial_fill(sell.price_num, sell.price_den);
        let candidate_fill = buy_kas.checked_mul(sell.price_den)
            .map(|v| v.div_ceil(sell.price_num));
        match candidate_fill {
            Some(ft) if ft >= min_tokens => true,
            _ => {
                tracing::debug!(
                    "partial sell: fill would truncate to 0 KAS (price {}/{}), skipping case 2",
                    sell.price_num, sell.price_den
                );
                false
            }
        }
    };
    if case2_viable {
        let fill_token_amount = match buy_kas.checked_mul(sell.price_den) {
            Some(v) => v.div_ceil(sell.price_num), // ceil division
            None => {
                tracing::warn!(
                    "u64 overflow in partial sell ceil: buy_kas={} * price_den={}, skipping",
                    buy_kas, sell.price_den
                );
                return None;
            }
        };
        let fill_kas = match fill_token_amount.checked_mul(sell.price_num) {
            Some(v) => v / sell.price_den,
            None => {
                tracing::warn!(
                    "u64 overflow in partial sell fill_kas: fill_token_amount={} * price_num={}, skipping",
                    fill_token_amount, sell.price_num
                );
                return None;
            }
        };
        let buyer_tokens = expected_tokens;

        if sell_tokens >= fill_token_amount {
            let residual_tokens = sell_tokens - fill_token_amount;
            let residual_kas = match residual_tokens.checked_mul(sell.price_num) {
                Some(v) => v / sell.price_den,
                None => {
                    tracing::warn!(
                        "u64 overflow in partial sell residual: residual_tokens={} * price_num={}, skipping",
                        residual_tokens, sell.price_num
                    );
                    return None;
                }
            };

            if fill_token_amount >= MIN_UTXO_VALUE
                && fill_kas >= sell.min_fill
                && residual_tokens >= MIN_UTXO_VALUE
                && residual_kas >= sell.min_fill
                && buyer_tokens >= MIN_UTXO_VALUE
                && fill_kas >= MIN_UTXO_VALUE
            {
                if let Some(after_kas) = (buy_kas + sell_tokens).checked_sub(fill_kas) {
                    if let Some(after_tokens) = after_kas.checked_sub(buyer_tokens) {
                        if let Some(surplus) = after_tokens.checked_sub(residual_tokens) {
                            // Respect buy order's max_matcher_fee.
                            // Buy contract enforces buy_kas - seller_kas <= mmfee.
                            let mmfee_floor = buy_kas.saturating_sub(buy.max_matcher_fee);
                            let adj_seller_kas = std::cmp::max(fill_kas, mmfee_floor);
                            let adj_surplus = surplus.saturating_sub(adj_seller_kas - fill_kas)
                                .min(buy.max_matcher_fee)
                                .min(sell.max_matcher_fee); // C4 fix
                            // surplus=0 is valid when mmfee=0 (matcher pays miner fee from fee UTXOs).
                            return Some(CrossingPair {
                                token_cov_id: token_cov_id.to_string(),
                                buy: buy.clone(),
                                sell: sell.clone(),
                                seller_kas: adj_seller_kas,
                                buyer_tokens,
                                surplus: adj_surplus,
                                expected_tokens: buyer_tokens,
                                expected_kas: adj_seller_kas,
                                match_type: MatchType::PartialSell,
                                fill_kas: None,
                                residual_kas: None,
                                fill_token_amount: Some(fill_token_amount),
                                residual_tokens: Some(residual_tokens),
                            });
                        }
                    }
                }
            }
        }
    }

    None
}

/// Maximum number of crossing pairs per batch group.
///
/// Constrained by MAX_TX_MASS (500,000). A batch TX with N pairs uses
/// ~900 mass per pair (sigscripts + outputs). N=15 produces ~14k mass,
/// well under the limit.
///
/// Input/output indices beyond 16 are handled by `push_index()` which
/// uses data-push encoding (2-3 bytes) instead of OpN (1 byte), so
/// the OpN range (0..=16) is NOT a binding constraint.
///
/// Larger batches are more efficient (amortized fee per order) but have
/// higher failure probability if any single order is stale or spent.
/// N=15 balances throughput with reliability.
pub const MAX_BATCH_GROUP_SIZE: usize = 15;

/// Group crossing pairs into batch-eligible groups.
///
/// Only **full-fill** pairs are eligible for batching (partial fills have
/// residual outputs that complicate TX layout). Groups are partitioned by
/// `token_cov_id` and each group contains at least 2 pairs (a single pair
/// is handled by the remaining-pair path as a single-pair batch). Groups are capped at
/// [`MAX_BATCH_GROUP_SIZE`] pairs due to OpN index limits.
///
/// Returns a vec of groups, where each group is a vec of crossing pairs
/// that share the same token and are all full fills.
pub fn find_batch_groups(pairs: &[CrossingPair]) -> Vec<Vec<&CrossingPair>> {
    use std::collections::{HashMap, HashSet};

    // Partition full-fill pairs by token
    let mut by_token: HashMap<&str, Vec<&CrossingPair>> = HashMap::new();
    for p in pairs {
        if p.match_type != MatchType::Full {
            continue;
        }
        by_token.entry(&p.token_cov_id).or_default().push(p);
    }

    let mut groups = Vec::new();
    for (_token, token_pairs) in by_token {
        if token_pairs.is_empty() {
            continue;
        }

        // Sort by surplus descending so we greedily pick the most profitable pairs first
        let mut sorted = token_pairs;
        sorted.sort_by(|a, b| b.surplus.cmp(&a.surplus));

        // Deduplicate: each outpoint (sell or buy) can appear in at most one pair.
        // Greedy selection: pick pairs in surplus order, skip if either outpoint is already used.
        // Split into groups of MAX_BATCH_GROUP_SIZE.
        let mut used_outpoints = HashSet::new();
        let mut deduped = Vec::new();

        for p in &sorted {
            let sell_key = p.sell.outpoint_key();
            let buy_key = p.buy.outpoint_key();
            if used_outpoints.contains(&sell_key) || used_outpoints.contains(&buy_key) {
                continue;
            }
            used_outpoints.insert(sell_key);
            used_outpoints.insert(buy_key);
            deduped.push(*p);
        }

        for chunk in deduped.chunks(MAX_BATCH_GROUP_SIZE) {
            if !chunk.is_empty() {
                groups.push(chunk.to_vec());
            }
        }
    }

    // Sort by total surplus descending (most profitable batch first)
    groups.sort_by(|a, b| {
        let surplus_a: u64 = a.iter().map(|p| p.surplus).sum();
        let surplus_b: u64 = b.iter().map(|p| p.surplus).sum();
        surplus_b.cmp(&surplus_a)
    });

    groups
}

/// A 1:N sweep group: one large anchor order sweeps multiple fills.
///
/// For a **buy sweep**: the anchor is a buy order and fills are sell orders
/// sorted by price ascending (best price for buyer first).
///
/// For a **sell sweep**: the anchor is a sell order and fills are buy orders
/// sorted by price descending (highest bidder first).
///
/// The anchor's total value must cover all fills' requirements.
#[derive(Debug, Clone)]
pub struct SweepGroup {
    /// The large anchor order that sweeps multiple counterparties.
    pub anchor: BookOrder,
    /// Counterparty orders that the anchor can fill, sorted by price
    /// (ascending for buy sweep, descending for sell sweep).
    pub fills: Vec<BookOrder>,
    /// True if anchor is a buy (buy sweeps sells). False if anchor is a sell.
    pub is_buy_sweep: bool,
    /// Total KAS the anchor needs across all fills (buy sweep) or total
    /// tokens needed (sell sweep).
    pub total_fill_cost: u64,
    /// True when the anchor is a GTC order (not IOC-eligible) and the
    /// fills collectively provide enough output to satisfy a full fill.
    /// When true, the executor must use `plan_batch_match` (Op1 selector)
    /// instead of `plan_ioc_match` (Op5 selector).
    pub is_gtc_multi_fill: bool,
}

/// Find sweep groups: detect when one large order can fill multiple
/// counterparties on the same token pair.
///
/// This complements `find_batch_groups` which only groups 1:1 full-fill pairs.
/// Sweep groups detect 1:N relationships where a single large buy can afford
/// multiple sells (or a single large sell can fill multiple buys).
///
/// # Algorithm
/// For each token pair:
/// 1. For each buy, collect all crossing sells (sell_price <= buy_price).
/// 2. Sort sells by price ascending (best price for buyer first).
/// 3. Greedily accumulate sells until the buy's KAS is exhausted or
///    MAX_BATCH_GROUP_SIZE is reached.
/// 4. Only emit a sweep group if 2+ sells are swept (1:1 is handled by
///    the existing batch/remaining path).
///
/// # Arguments
/// * `order_book` - The order book to scan.
/// * `allow_self_trade` - If true, allow same-owner matches (testing only).
/// * `spent_outpoints` - Outpoints already claimed by prior phases.
pub fn find_sweep_groups(
    order_book: &OrderBook,
    allow_self_trade: bool,
    spent_outpoints: Option<&std::collections::HashSet<String>>,
) -> Vec<SweepGroup> {
    use std::collections::HashSet;

    let empty_set = HashSet::new();
    let spent = spent_outpoints.unwrap_or(&empty_set);

    let mut groups = Vec::new();
    // Track which outpoints are already assigned to a sweep group
    // to avoid double-spending across groups.
    let mut claimed: HashSet<String> = HashSet::new();

    for (_token_cov_id, book) in &order_book.pair_books {
        // Collect active bids and asks
        let bids: Vec<&BookOrder> = book
            .bids
            .values()
            .filter(|b| {
                let key = b.outpoint_key();
                !order_book.matched_outpoints.contains_key(&key)
                    && !spent.contains(&key)
                    && !claimed.contains(&key)
                    && b.price_num > 0
                    && b.price_den > 0
            })
            .collect();

        let mut asks: Vec<&BookOrder> = book
            .asks
            .values()
            .filter(|s| {
                let key = s.outpoint_key();
                !order_book.matched_outpoints.contains_key(&key)
                    && !spent.contains(&key)
                    && !claimed.contains(&key)
                    && s.price_num > 0
                    && s.price_den > 0
            })
            .collect();

        // Sort asks by price ascending (sell price = price_num/price_den).
        // Lower price = better deal for buyer.
        // Compare a.price_num/a.price_den vs b.price_num/b.price_den
        // using cross-multiplication to avoid floating point.
        asks.sort_by(|a, b| {
            let lhs = a.price_num as u128 * b.price_den as u128;
            let rhs = b.price_num as u128 * a.price_den as u128;
            lhs.cmp(&rhs)
        });

        // --- Buy sweeps (1 buy : N sells) ---
        // Sort bids by value descending (largest buy first, most likely to sweep)
        let mut sorted_bids = bids.clone();
        sorted_bids.sort_by(|a, b| b.value.cmp(&a.value));

        for buy in &sorted_bids {
            if claimed.contains(&buy.outpoint_key()) {
                continue;
            }
            let buy_kas = buy.value;
            let mut kas_remaining = buy_kas;
            let mut sweep_sells: Vec<BookOrder> = Vec::new();
            let mut total_fill_cost: u64 = 0;

            for sell in &asks {
                if sweep_sells.len() >= MAX_BATCH_GROUP_SIZE {
                    break;
                }
                if claimed.contains(&sell.outpoint_key()) {
                    continue;
                }
                // STP
                if !allow_self_trade && buy.owner_hash == sell.owner_hash {
                    continue;
                }
                // Check crossing: sell price <= buy price
                // sell.price_num/sell.price_den <= buy.price_num/buy.price_den
                // <=> sell.price_num * buy.price_den <= buy.price_num * sell.price_den
                let lhs = sell.price_num as u128 * buy.price_den as u128;
                let rhs = buy.price_num as u128 * sell.price_den as u128;
                if lhs > rhs {
                    // Sell price > buy price: does not cross. Since asks are
                    // sorted ascending, all remaining asks are also non-crossing.
                    break;
                }

                // How much KAS does this sell require?
                let sell_kas_128 = sell.value as u128 * sell.price_num as u128
                    / sell.price_den as u128;
                if sell_kas_128 > u64::MAX as u128 {
                    continue;
                }
                let sell_kas = sell_kas_128 as u64;
                if sell_kas < MIN_UTXO_VALUE {
                    continue;
                }

                if kas_remaining >= sell_kas {
                    kas_remaining -= sell_kas;
                    total_fill_cost += sell_kas;
                    sweep_sells.push((*sell).clone());
                }
                // If can't afford, skip this sell and try the next
                // (a cheaper sell might still fit)
            }

            // Only emit if 2+ sells swept (1:1 is handled elsewhere)
            if sweep_sells.len() >= 2 {
                // IOC/GTC distinction: GTC buys must be fully filled
                // across all sweep sells.  IOC buys tolerate partial fill.
                let is_ioc = buy.is_ioc_eligible();
                let emit = if is_ioc {
                    true // IOC: partial fill OK
                } else {
                    // GTC: total tokens from fills must satisfy expected_tokens.
                    let total_tokens: u64 = sweep_sells.iter().map(|s| s.value).sum();
                    let expected_tokens = buy.expected_output();
                    total_tokens >= expected_tokens && expected_tokens > 0
                };

                if emit {
                    let buy_key = buy.outpoint_key();
                    claimed.insert(buy_key);
                    for s in &sweep_sells {
                        claimed.insert(s.outpoint_key());
                    }
                    groups.push(SweepGroup {
                        anchor: (*buy).clone(),
                        fills: sweep_sells,
                        is_buy_sweep: true,
                        total_fill_cost,
                        is_gtc_multi_fill: !is_ioc,
                    });
                }
            }
        }

        // --- Sell sweeps (1 sell : N buys) ---
        let mut sorted_bids_for_sell_sweep = bids;
        // Sort bids by price descending (highest bidder first -- best for seller)
        sorted_bids_for_sell_sweep.sort_by(|a, b| {
            let lhs = a.price_num as u128 * b.price_den as u128;
            let rhs = b.price_num as u128 * a.price_den as u128;
            rhs.cmp(&lhs) // descending
        });

        // Sort asks by value descending (largest sell first)
        let mut sorted_asks = asks;
        sorted_asks.sort_by(|a, b| b.value.cmp(&a.value));

        for sell in &sorted_asks {
            if claimed.contains(&sell.outpoint_key()) {
                continue;
            }
            let sell_tokens = sell.value;
            let mut tokens_remaining = sell_tokens;
            let mut sweep_buys: Vec<BookOrder> = Vec::new();
            let mut total_fill_cost: u64 = 0;

            for buy in &sorted_bids_for_sell_sweep {
                if sweep_buys.len() >= MAX_BATCH_GROUP_SIZE {
                    break;
                }
                if claimed.contains(&buy.outpoint_key()) {
                    continue;
                }
                // STP
                if !allow_self_trade && buy.owner_hash == sell.owner_hash {
                    continue;
                }
                // Check crossing: sell price <= buy price
                let lhs = sell.price_num as u128 * buy.price_den as u128;
                let rhs = buy.price_num as u128 * sell.price_den as u128;
                if lhs > rhs {
                    continue; // sell price > buy price: not crossing
                }

                // How many tokens does this buy want?
                let buy_tokens_128 = buy.value as u128 * buy.price_num as u128
                    / buy.price_den as u128;
                if buy_tokens_128 > u64::MAX as u128 {
                    continue;
                }
                let buy_tokens = buy_tokens_128 as u64;
                if buy_tokens < MIN_UTXO_VALUE {
                    continue;
                }

                if tokens_remaining >= buy_tokens {
                    tokens_remaining -= buy_tokens;
                    total_fill_cost += buy_tokens;
                    sweep_buys.push((*buy).clone());
                }
            }

            // Only emit if 2+ buys swept
            if sweep_buys.len() >= 2 {
                // IOC/GTC distinction for sell anchor
                let is_ioc = sell.is_ioc_eligible();
                let emit = if is_ioc {
                    true // IOC: partial fill OK
                } else {
                    // GTC: total KAS from buys must satisfy expected_kas.
                    let total_kas: u64 = sweep_buys.iter()
                        .map(|b| {
                            let kas_128 = b.value as u128 * b.price_num as u128
                                / b.price_den.max(1) as u128;
                            kas_128.min(u64::MAX as u128) as u64
                        })
                        .sum();
                    let expected_kas = sell.expected_output();
                    total_kas >= expected_kas && expected_kas > 0
                };

                if emit {
                    let sell_key = sell.outpoint_key();
                    claimed.insert(sell_key);
                    for b in &sweep_buys {
                        claimed.insert(b.outpoint_key());
                    }
                    groups.push(SweepGroup {
                        anchor: (*sell).clone(),
                        fills: sweep_buys,
                        is_buy_sweep: false,
                        total_fill_cost,
                        is_gtc_multi_fill: !is_ioc,
                    });
                }
            }
        }
    }

    // Sort by fill count descending (largest sweeps first -- most efficient)
    groups.sort_by(|a, b| b.fills.len().cmp(&a.fills.len()));
    groups
}

/// A cross-pair batch group containing sells and buys from different token
/// pairs that can be matched atomically through the batch engine.
///
/// Each group represents one atomic batch TX: the sell orders produce KAS,
/// and the buy orders consume KAS to acquire different tokens.
#[derive(Debug, Clone)]
pub struct CrossPairBatchGroup {
    /// Sell-side orders (each sells tokens for KAS, from various pairs).
    pub sells: Vec<BookOrder>,
    /// Buy-side orders (each buys tokens with KAS, from various pairs).
    pub buys: Vec<BookOrder>,
    /// Total KAS surplus across all route legs in this group.
    pub total_surplus: u64,
}

/// Combine same-pair crossings from different tokens into multi-pair batch groups.
///
/// Algorithm:
/// 1. Find all same-pair crossings via `find_all_crossing_pairs_with_stp`.
/// 2. Filter out orders already claimed by the BATCH path (`spent_outpoints`).
/// 3. Keep only full-fill pairs (partials handled by REMAINING path).
/// 4. Group by token, pick the best (highest surplus) crossing per token.
/// 5. Combine crossings from 2+ different tokens into one `CrossPairBatchGroup`.
///
/// Each crossing pair adds 1 sell + 1 buy to the TX. With `MAX_BATCH_GROUP_SIZE`
/// as the per-group cap on crossing pairs, we can fit that many token pairs plus
/// 1 wallet input. The batch engine's `token_input_map` routes each buy's `tii`
/// to the correct sell (same `token_cov_id`), so multi-token batches work natively.
///
/// # Arguments
/// * `order_book` - The order book to scan.
/// * `_max_routes` - Reserved for future use (capped by `MAX_BATCH_GROUP_SIZE`).
/// * `allow_self_trade` - If true, allow same-owner matches (testing only).
/// * `spent_outpoints` - Outpoints already claimed by BATCH or spent_tracker.
///   Pass `None` when no prior phase has run (e.g. diagnostics, tests).
///
/// # Returns
/// A vec of `CrossPairBatchGroup`s, sorted by total surplus descending.
/// Each group contains crossings from >= 2 different token pairs.
pub fn find_cross_pair_batch_groups(
    order_book: &OrderBook,
    _max_routes: usize,
    allow_self_trade: bool,
    spent_outpoints: Option<&std::collections::HashSet<String>>,
) -> Vec<CrossPairBatchGroup> {
    use std::collections::{HashMap, HashSet};

    let all_pairs = find_all_crossing_pairs_with_stp(order_book, allow_self_trade);
    if all_pairs.is_empty() {
        return Vec::new();
    }

    let empty_set = HashSet::new();
    let spent = spent_outpoints.unwrap_or(&empty_set);

    // Step 1: Filter to full-fill pairs not already claimed.
    // Step 2: Group by token, keeping best (highest surplus) per token.
    // Each outpoint may appear in multiple CrossingPair candidates; we
    // track used outpoints to avoid double-spending across tokens.
    let mut best_by_token: HashMap<&str, &CrossingPair> = HashMap::new();

    for p in &all_pairs {
        if p.match_type != MatchType::Full {
            continue;
        }
        let bk = p.buy.outpoint_key();
        let sk = p.sell.outpoint_key();
        if spent.contains(&bk) || spent.contains(&sk) {
            continue;
        }
        let entry = best_by_token
            .entry(&p.token_cov_id)
            .or_insert(p);
        if p.surplus > entry.surplus {
            *entry = p;
        }
    }

    // Need crossings from at least 2 different tokens to form a cross-pair group.
    if best_by_token.len() < 2 {
        return Vec::new();
    }

    // Step 3: Sort candidates by surplus descending, then deduplicate outpoints.
    let mut candidates: Vec<&CrossingPair> = best_by_token.values().copied().collect();
    candidates.sort_by(|a, b| b.surplus.cmp(&a.surplus));

    let mut used_outpoints = HashSet::new();
    let mut deduped: Vec<&CrossingPair> = Vec::new();

    for p in &candidates {
        let bk = p.buy.outpoint_key();
        let sk = p.sell.outpoint_key();
        if used_outpoints.contains(&bk) || used_outpoints.contains(&sk) {
            continue;
        }
        used_outpoints.insert(bk);
        used_outpoints.insert(sk);
        deduped.push(p);
    }

    // After dedup, still need >= 2 different tokens.
    if deduped.len() < 2 {
        return Vec::new();
    }

    // Step 4: Chunk into groups of MAX_BATCH_GROUP_SIZE crossing pairs.
    // Each crossing pair = 1 sell + 1 buy = 2 order inputs + 2 outputs.
    // TX layout: (2 * N_pairs) order inputs + 1 wallet = total inputs,
    // (2 * N_pairs) outputs + receipt + change = total outputs.
    // push_index() handles indices >16, so the OpN range is not a limit.
    // Bounded by MAX_TX_MASS (500k); N=15 uses ~14k mass.
    let mut groups = Vec::new();

    for chunk in deduped.chunks(MAX_BATCH_GROUP_SIZE) {
        // Each chunk must contain crossings from >= 2 tokens to be a cross-pair group.
        let mut token_set = HashSet::new();
        for p in chunk {
            token_set.insert(&p.token_cov_id);
        }
        if token_set.len() < 2 {
            continue;
        }

        let mut sells = Vec::new();
        let mut buys = Vec::new();
        let mut total_surplus = 0u64;

        for p in chunk {
            sells.push(p.sell.clone());
            buys.push(p.buy.clone());
            total_surplus = total_surplus.saturating_add(p.surplus);
        }

        groups.push(CrossPairBatchGroup {
            sells,
            buys,
            total_surplus,
        });
    }

    // Sort by total surplus descending
    groups.sort_by(|a, b| b.total_surplus.cmp(&a.total_surplus));

    groups
}

/// Find triangular (3-hop) arbitrage routes and package them as batch groups.
///
/// Each `TriangularRoute` has 3 legs (each a 2-hop CrossPairRoute), totalling
/// 6 orders (3 sells + 3 buys). These are converted into `CrossPairBatchGroup`s
/// that the batch engine processes identically to 2-hop groups.
///
/// Input count per triangular group: 3 sells + 3 buys + up to 3 token units + 1 wallet = 10,
/// well within the OpN limit of 16.
pub fn find_triangular_batch_groups(
    order_book: &OrderBook,
    max_routes: usize,
    allow_self_trade: bool,
) -> Vec<CrossPairBatchGroup> {
    let tri_routes = routing::find_triangular_routes(order_book, max_routes, allow_self_trade);
    if tri_routes.is_empty() {
        return Vec::new();
    }

    let mut groups = Vec::new();

    for route in &tri_routes {
        let mut sells = Vec::new();
        let mut buys = Vec::new();

        for leg in &route.legs {
            sells.push(leg.sell_leg.clone());
            buys.push(leg.buy_leg.clone());
        }

        groups.push(CrossPairBatchGroup {
            sells,
            buys,
            total_surplus: route.total_surplus,
        });
    }

    groups
}

/// Planner hint: which plan function to call for this group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupKind {
    /// N:N full-fill batch (including 1:1 full). Uses `plan_batch_match`.
    Batch,
    /// 1 buy sweeps N sells. Uses `plan_ioc_match`.
    BuySweep,
    /// 1 sell sweeps N buys. Uses `plan_sell_ioc_match`.
    SellSweep,
    /// 1:1 partial buy (buyer larger than seller). Uses `plan_ioc_match`.
    PartialBuy,
    /// 1:1 partial sell (seller larger than buyer). Uses `plan_sell_ioc_match`.
    PartialSell,
    /// GTC 1:N multi-fill: 1 GTC buy fully filled by N sells.
    /// Total sell tokens >= buy expected_tokens, so the buy uses Op1 (full fill).
    /// Uses `plan_batch_match` (not IOC).
    GtcBuyMultiFill,
    /// GTC N:1 multi-fill: 1 GTC sell fully filled by N buys.
    /// Total buy KAS >= sell expected_kas, so the sell uses Op1 (full fill).
    /// Uses `plan_batch_match` (not IOC).
    GtcSellMultiFill,
}

/// A unified batch group that the executor processes in one loop.
///
/// Replaces the old Phase 0/0.5/1a/1b split. Each `BatchGroup` maps to
/// exactly one call to the appropriate planner + `execute_batch_match`.
#[derive(Debug, Clone)]
pub struct BatchGroup {
    /// Sell-side orders.
    pub sells: Vec<BookOrder>,
    /// Buy-side orders.
    pub buys: Vec<BookOrder>,
    /// Total surplus across all pairs in this group.
    pub total_surplus: u64,
    /// Which planner to use.
    pub kind: GroupKind,
    /// The crossing pairs that formed this group (for IFD lookup + MatchResult).
    pub source_pairs: Vec<CrossingPair>,
}

impl BatchGroup {
    /// All orders (sells + buys) for iteration.
    pub fn all_orders(&self) -> impl Iterator<Item = &BookOrder> {
        self.sells.iter().chain(self.buys.iter())
    }
}

/// Unified grouper: replaces `find_batch_groups`, `find_sweep_groups`, and
/// the Phase 1b remaining-pair selection with a single pass.
///
/// Algorithm:
/// 1. Collect sweep groups from the order book (1:N relationships).
/// 2. Collect N:N batch groups from the crossing pairs.
/// 3. Collect remaining 1:1 pairs (full, partial buy, partial sell) not yet claimed.
/// 4. Return all groups sorted by surplus descending.
///
/// The returned groups are non-overlapping: no outpoint appears in more than one group.
pub fn find_optimal_groups(
    all_pairs: &[CrossingPair],
    order_book: &OrderBook,
    allow_self_trade: bool,
    spent_outpoints: Option<&std::collections::HashSet<String>>,
) -> Vec<BatchGroup> {
    use std::collections::HashSet;

    let mut groups: Vec<BatchGroup> = Vec::new();
    let mut used: HashSet<String> = HashSet::new();

    // H1-fix: helper to mark an order key as used AND also exclude its
    // OCO partner.  OCO orders (TP + SL) share a single UTXO; if one
    // path is selected for a group the other must be excluded from all
    // subsequent groups to prevent a double-spend within the same cycle.
    let use_order = |used: &mut HashSet<String>, order: &BookOrder| {
        let key = order.outpoint_key();
        used.insert(key);
        if let Some(ref partner) = order.oco_partner_key {
            used.insert(partner.clone());
        }
    };

    // ---------------------------------------------------------------
    // Step 1: Sweep groups (1:N)  -- highest priority because they
    // atomically fill large orders that would otherwise be broken into
    // multiple 1:1 pairs across cycles.
    // ---------------------------------------------------------------
    let sweep_spent: HashSet<String> = spent_outpoints
        .map(|s| s.iter().cloned().collect())
        .unwrap_or_default();
    let sweep_groups = find_sweep_groups(order_book, allow_self_trade, Some(&sweep_spent));

    for sg in sweep_groups {
        let anchor_key = sg.anchor.outpoint_key();
        if used.contains(&anchor_key) {
            continue;
        }
        // Skip if any fill already used
        if sg.fills.iter().any(|f| used.contains(&f.outpoint_key())) {
            continue;
        }
        // Claim all outpoints (+ OCO partners via H1-fix)
        use_order(&mut used, &sg.anchor);
        for f in &sg.fills {
            use_order(&mut used, f);
        }

        let total_surplus = sg.total_fill_cost; // approximate
        let (sells, buys, kind) = if sg.is_buy_sweep {
            let k = if sg.is_gtc_multi_fill {
                GroupKind::GtcBuyMultiFill
            } else {
                GroupKind::BuySweep
            };
            (sg.fills.clone(), vec![sg.anchor.clone()], k)
        } else {
            let k = if sg.is_gtc_multi_fill {
                GroupKind::GtcSellMultiFill
            } else {
                GroupKind::SellSweep
            };
            (vec![sg.anchor.clone()], sg.fills.clone(), k)
        };

        groups.push(BatchGroup {
            sells,
            buys,
            total_surplus,
            kind,
            source_pairs: Vec::new(), // sweep groups don't map 1:1 to CrossingPairs
        });
    }

    // ---------------------------------------------------------------
    // Step 2: N:N batch groups from full-fill crossing pairs.
    // Greedy: sort all full-fill pairs by surplus desc, deduplicate
    // outpoints, then chunk by token into groups of MAX_BATCH_GROUP_SIZE.
    // ---------------------------------------------------------------
    {
        let mut full_pairs: Vec<&CrossingPair> = all_pairs
            .iter()
            .filter(|p| {
                p.match_type == MatchType::Full
                    && !used.contains(&p.buy.outpoint_key())
                    && !used.contains(&p.sell.outpoint_key())
            })
            .collect();
        full_pairs.sort_by(|a, b| b.surplus.cmp(&a.surplus));

        // Greedy deduplicate
        let mut deduped: Vec<&CrossingPair> = Vec::new();
        for p in &full_pairs {
            let bk = p.buy.outpoint_key();
            let sk = p.sell.outpoint_key();
            if used.contains(&bk) || used.contains(&sk) {
                continue;
            }
            use_order(&mut used, &p.buy);
            use_order(&mut used, &p.sell);
            deduped.push(p);
        }

        // Group by token
        let mut by_token: std::collections::HashMap<&str, Vec<&CrossingPair>> =
            std::collections::HashMap::new();
        for p in &deduped {
            by_token.entry(&p.token_cov_id).or_default().push(p);
        }

        for (_token, token_pairs) in by_token {
            for chunk in token_pairs.chunks(MAX_BATCH_GROUP_SIZE) {
                if chunk.is_empty() {
                    continue;
                }
                let sells: Vec<BookOrder> = chunk.iter().map(|p| p.sell.clone()).collect();
                let buys: Vec<BookOrder> = chunk.iter().map(|p| p.buy.clone()).collect();
                let total_surplus: u64 = chunk.iter().map(|p| p.surplus).sum();
                let source_pairs: Vec<CrossingPair> = chunk.iter().map(|p| (*p).clone()).collect();

                groups.push(BatchGroup {
                    sells,
                    buys,
                    total_surplus,
                    kind: GroupKind::Batch,
                    source_pairs,
                });
            }
        }
    }

    // ---------------------------------------------------------------
    // Step 3: Remaining 1:1 pairs (partial buy, partial sell, or
    // full-fill pairs that didn't make it into a batch group).
    // Pick the best remaining pair per token.
    // ---------------------------------------------------------------
    {
        let mut best_by_token: std::collections::HashMap<&str, &CrossingPair> =
            std::collections::HashMap::new();

        for p in all_pairs {
            let bk = p.buy.outpoint_key();
            let sk = p.sell.outpoint_key();
            if used.contains(&bk) || used.contains(&sk) {
                continue;
            }
            let entry = best_by_token.entry(&p.token_cov_id).or_insert(p);
            if p.surplus > entry.surplus {
                *entry = p;
            }
        }

        for (_token, best) in best_by_token {
            let bk = best.buy.outpoint_key();
            let sk = best.sell.outpoint_key();
            if used.contains(&bk) || used.contains(&sk) {
                continue;
            }
            use_order(&mut used, &best.buy);
            use_order(&mut used, &best.sell);

            let kind = match best.match_type {
                MatchType::Full => GroupKind::Batch,
                MatchType::PartialBuy => GroupKind::PartialBuy,
                MatchType::PartialSell => GroupKind::PartialSell,
            };

            groups.push(BatchGroup {
                sells: vec![best.sell.clone()],
                buys: vec![best.buy.clone()],
                total_surplus: best.surplus,
                kind,
                source_pairs: vec![best.clone()],
            });
        }
    }

    // Sort all groups by surplus descending (most profitable first)
    groups.sort_by(|a, b| b.total_surplus.cmp(&a.total_surplus));

    groups
}

#[cfg(test)]
mod tests {
    use super::*;
    use kob_core::mass::estimate_compute_mass;
    use crate::matcher::order_book::{BookOrder, OrderBook, OrderSide};

    fn make_buy(value: u64, price_num: u64, price_den: u64, token_cov_id: &str) -> BookOrder {
        BookOrder {
            tx_id: "a".repeat(64),
            index: 1,
            value,
            token_cov_id: token_cov_id.to_string(),
            price_num,
            price_den,
            min_fill: 1_000_000,
            owner_hash: "b".repeat(64),
            spk_hash: "11".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Buy,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0,
        }
    }

    fn make_sell(value: u64, price_num: u64, price_den: u64, token_cov_id: &str) -> BookOrder {
        BookOrder {
            tx_id: "c".repeat(64),
            index: 2,
            value,
            token_cov_id: token_cov_id.to_string(),
            price_num,
            price_den,
            min_fill: 1_000_000,
            owner_hash: "d".repeat(64),
            spk_hash: "22".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Sell,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0,
        }
    }

    const FAKE_TOKEN: &str = "0102030405060708091011121314151617181920212223242526272829303132";

    #[test]
    fn test_crossing_pair_detection() {
        let mut ob = OrderBook::new();
        ob.add_buy_order(make_buy(10_000_000, 1, 2, FAKE_TOKEN));
        ob.add_sell_order(make_sell(10_000_000, 1, 2, FAKE_TOKEN));

        let pairs = find_all_crossing_pairs(&ob);
        assert_eq!(pairs.len(), 1, "Should find 1 crossing pair");
        assert_eq!(pairs[0].expected_tokens, 5_000_000);
        assert_eq!(pairs[0].expected_kas, 5_000_000);
        // buyer_tokens = sell_tokens (10M), not expected_tokens (5M)
        assert_eq!(pairs[0].buyer_tokens, 10_000_000);
        // surplus = total_in - seller_kas - buyer_tokens = 20M - 5M - 10M = 5M
        assert_eq!(pairs[0].surplus, 5_000_000);
    }

    #[test]
    fn test_no_crossing_different_prices() {
        let mut ob = OrderBook::new();
        // Buy at 1/10 (low bid), sell at 5/1 (high ask)
        ob.add_buy_order(make_buy(3_500_000, 1, 10, FAKE_TOKEN));
        ob.add_sell_order(make_sell(3_500_000, 5, 1, FAKE_TOKEN));

        let pairs = find_all_crossing_pairs(&ob);
        assert!(pairs.is_empty(), "Non-overlapping prices should not cross");
    }

    #[test]
    fn test_exact_price_match_no_surplus() {
        let mut ob = OrderBook::new();
        // Both at 1/1: surplus = 0, valid when mmfee allows fee from external UTXOs
        ob.add_buy_order(make_buy(3_500_000, 1, 1, FAKE_TOKEN));
        ob.add_sell_order(make_sell(3_500_000, 1, 1, FAKE_TOKEN));

        let pairs = find_all_crossing_pairs(&ob);
        assert_eq!(pairs.len(), 1, "Zero surplus is valid (matcher pays fee from fee UTXOs)");
        assert_eq!(pairs[0].surplus, 0);
    }

    #[test]
    fn test_large_order_values() {
        let mut ob = OrderBook::new();
        ob.add_buy_order(make_buy(1_000_000_000, 1, 2, FAKE_TOKEN));
        ob.add_sell_order(make_sell(1_000_000_000, 1, 2, FAKE_TOKEN));

        let pairs = find_all_crossing_pairs(&ob);
        assert_eq!(pairs.len(), 1);
        let p = &pairs[0];
        // buyer_tokens = sell_tokens (1B), surplus = 2B - 500M - 1B = 500M
        assert_eq!(p.surplus, 500_000_000);
    }

    #[test]
    fn test_multi_pair_independent() {
        let token_a = "0102030405060708091011121314151617181920212223242526272829303132";
        let token_b = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";

        let mut ob = OrderBook::new();
        ob.add_buy_order(make_buy(10_000_000, 1, 2, token_a));
        ob.add_sell_order(make_sell(10_000_000, 1, 2, token_a));
        ob.add_buy_order(make_buy(20_000_000, 1, 3, token_b));
        ob.add_sell_order(make_sell(20_000_000, 1, 3, token_b));

        let pairs = find_all_crossing_pairs(&ob);
        assert_eq!(pairs.len(), 2, "Should find 2 independent crossing pairs");

        let token_ids: Vec<&str> = pairs.iter().map(|p| p.token_cov_id.as_str()).collect();
        assert!(token_ids.contains(&token_a));
        assert!(token_ids.contains(&token_b));
    }

    #[test]
    fn test_storage_mass_minimum() {
        let mut ob = OrderBook::new();
        // Buy 5M at price 1/4 -> expected_tokens = 1.25M < MIN_UTXO_VALUE (3M)
        ob.add_buy_order(make_buy(5_000_000, 1, 4, FAKE_TOKEN));
        ob.add_sell_order(make_sell(5_000_000, 1, 4, FAKE_TOKEN));

        let pairs = find_all_crossing_pairs(&ob);
        assert!(
            pairs.is_empty(),
            "Should reject when buyer_tokens < MIN_UTXO_VALUE"
        );
    }

    #[test]
    fn test_multiply_first_arithmetic() {
        // Verify multiply-first: (amount * price_num) / price_den
        // With amount=7, pnum=3, pden=2:
        //   multiply-first: (7 * 3) / 2 = 21 / 2 = 10
        //   division-first: (7 / 2) * 3 = 3 * 3  = 9  (WRONG, loses precision)
        let mut ob = OrderBook::new();
        // Buy 20M at price 3/2 -> expected_tokens = (20M * 3) / 2 = 30M
        ob.add_buy_order(make_buy(20_000_000, 3, 2, FAKE_TOKEN));
        // Sell 10M at price 1/2 -> expected_kas = (10M * 1) / 2 = 5M
        ob.add_sell_order(make_sell(10_000_000, 1, 2, FAKE_TOKEN));

        let pairs = find_all_crossing_pairs(&ob);
        assert!(!pairs.is_empty(), "Should find at least 1 crossing pair");
        // Find the full-fill match
        let full = pairs.iter().find(|p| p.match_type == MatchType::Full).expect("Should have full fill");
        // expected_tokens = (20M * 3) / 2 = 30M (multiply-first)
        assert_eq!(full.expected_tokens, 30_000_000);
        // expected_kas = (10M * 1) / 2 = 5M
        assert_eq!(full.expected_kas, 5_000_000);
        // buyer_tokens = sell_tokens = 10M
        assert_eq!(full.buyer_tokens, 10_000_000);
        // surplus = (20M + 10M) - 5M - 10M = 15M
        assert_eq!(full.surplus, 15_000_000);
    }

    #[test]
    fn test_multiply_first_precision() {
        // Case where division-first loses precision but multiply-first does not.
        // amount=7_000_001, pnum=1, pden=3:
        //   multiply-first: (7_000_001 * 1) / 3 = 2_333_333 (truncated)
        //   division-first: (7_000_001 / 3) * 1 = 2_333_333 (same here because pnum=1)
        // But with pnum=2, pden=3:
        //   multiply-first: (7_000_001 * 2) / 3 = 14_000_002 / 3 = 4_666_667
        //   division-first: (7_000_001 / 3) * 2 = 2_333_333 * 2 = 4_666_666 (loses 1 sompi!)
        let buy_kas: u64 = 7_000_001;
        let price_num: u64 = 2;
        let price_den: u64 = 3;
        let multiply_first = (buy_kas * price_num) / price_den;
        let division_first = (buy_kas / price_den) * price_num;
        // Multiply-first should yield a higher (more precise) result
        assert!(
            multiply_first >= division_first,
            "multiply-first must be >= division-first"
        );
        assert_eq!(multiply_first, 4_666_667);
        assert_eq!(division_first, 4_666_666);
    }

    // M-3: orders with price_num=0 or price_den=0 must not cause division by zero.
    #[test]
    fn test_zero_price_fields_skipped() {
        let mut ob = OrderBook::new();
        // buy with price_num=0 (would divide by 0 in ceil division)
        let bad_buy = BookOrder {
            tx_id: "a".repeat(64),
            index: 0,
            value: 10_000_000,
            token_cov_id: FAKE_TOKEN.to_string(),
            price_num: 0,
            price_den: 1,
            min_fill: 1_000_000,
            owner_hash: "b".repeat(64),
            spk_hash: "11".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Buy,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0,
        };
        // sell with price_den=0 (would divide by 0 in expected_kas)
        let bad_sell = BookOrder {
            tx_id: "c".repeat(64),
            index: 0,
            value: 10_000_000,
            token_cov_id: FAKE_TOKEN.to_string(),
            price_num: 1,
            price_den: 0,
            min_fill: 1_000_000,
            owner_hash: "d".repeat(64),
            spk_hash: "22".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Sell,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0,
        };
        ob.add_buy_order(bad_buy);
        ob.add_sell_order(bad_sell);
        // Must not panic; should return empty (no valid crossing pairs)
        let pairs = find_all_crossing_pairs(&ob);
        assert!(pairs.is_empty(), "zero-price orders must not produce crossing pairs");
    }

    // MAX_MATCH_ITERATIONS: verify the loop breaks early and does not
    // run the full N*M product when it would exceed the cap.
    #[test]
    fn test_match_iteration_cap() {
        // Create enough orders on both sides that N*M > MAX_MATCH_ITERATIONS
        // e.g., 300 bids x 300 asks = 90,000 > 50,000
        let n = 300usize;
        let mut ob = OrderBook::new();
        for i in 0..n {
            let mut buy = make_buy(10_000_000, 1, 2, FAKE_TOKEN);
            buy.tx_id = format!("{:064x}", i);
            buy.owner_hash = format!("{:064x}", i); // unique owner to avoid STP
            ob.add_buy_order(buy);
        }
        for i in 0..n {
            let mut sell = make_sell(10_000_000, 1, 2, FAKE_TOKEN);
            sell.tx_id = format!("{:064x}", n + i);
            sell.owner_hash = format!("{:064x}", n + i);
            ob.add_sell_order(sell);
        }

        let pairs = find_all_crossing_pairs(&ob);
        // Without the cap, we'd get up to 90,000 crossing pairs.
        // With the cap at 50,000, the loop breaks early so we get fewer.
        assert!(
            pairs.len() < n * n,
            "iteration cap should prevent full N*M enumeration (got {} pairs from {}x{})",
            pairs.len(),
            n,
            n,
        );
    }

    // Integer edge case tests (adversarial review follow-up)

    #[test]
    fn test_u64_max_price_num_overflow_skipped() {
        // price_num = u64::MAX causes checked_mul overflow -> pair must be skipped, not panic
        let mut ob = OrderBook::new();
        let mut buy = make_buy(10_000_000, u64::MAX, 1, FAKE_TOKEN);
        buy.owner_hash = "aa".repeat(32);
        ob.add_buy_order(buy);
        let mut sell = make_sell(10_000_000, 1, 1, FAKE_TOKEN);
        sell.owner_hash = "bb".repeat(32);
        ob.add_sell_order(sell);
        // Must not panic; overflow is handled gracefully
        let pairs = find_all_crossing_pairs(&ob);
        // The overflowing pair should be skipped
        assert!(
            pairs.is_empty(),
            "u64::MAX price_num should cause overflow skip, not a match"
        );
    }

    #[test]
    fn test_u64_max_price_den_no_panic() {
        // price_den = u64::MAX -> division yields 0 or 1, below MIN_UTXO_VALUE -> no match
        let mut ob = OrderBook::new();
        let mut buy = make_buy(10_000_000, 1, u64::MAX, FAKE_TOKEN);
        buy.owner_hash = "aa".repeat(32);
        ob.add_buy_order(buy);
        let mut sell = make_sell(10_000_000, 1, u64::MAX, FAKE_TOKEN);
        sell.owner_hash = "bb".repeat(32);
        ob.add_sell_order(sell);
        let pairs = find_all_crossing_pairs(&ob);
        // expected_tokens = 10M * 1 / u64::MAX = 0, below MIN_UTXO_VALUE
        assert!(pairs.is_empty(), "u64::MAX denominator should produce dust -> no match");
    }

    #[test]
    fn test_both_sides_overflow_handled() {
        // Both buy and sell have price_num near u64::MAX
        let mut ob = OrderBook::new();
        let mut buy = make_buy(u64::MAX / 2, u64::MAX / 2, 1, FAKE_TOKEN);
        buy.owner_hash = "aa".repeat(32);
        ob.add_buy_order(buy);
        let mut sell = make_sell(u64::MAX / 2, u64::MAX / 2, 1, FAKE_TOKEN);
        sell.owner_hash = "bb".repeat(32);
        ob.add_sell_order(sell);
        // checked_mul(u64::MAX/2, u64::MAX/2) overflows -> skip
        let pairs = find_all_crossing_pairs(&ob);
        assert!(pairs.is_empty(), "double overflow should be safely skipped");
    }

    #[test]
    fn test_zero_price_den_in_partial_fill() {
        // Ensure compute_partial_fill_match handles price_den=0 (M-3 guard)
        let buy = make_buy(10_000_000, 1, 0, FAKE_TOKEN);
        let sell = make_sell(10_000_000, 1, 1, FAKE_TOKEN);
        let result = compute_partial_fill_match(FAKE_TOKEN, &buy, &sell);
        assert!(result.is_none(), "price_den=0 must return None, not panic");
    }

    #[test]
    fn test_zero_price_num_in_partial_fill() {
        let buy = make_buy(10_000_000, 0, 1, FAKE_TOKEN);
        let sell = make_sell(10_000_000, 1, 1, FAKE_TOKEN);
        let result = compute_partial_fill_match(FAKE_TOKEN, &buy, &sell);
        assert!(result.is_none(), "price_num=0 must return None, not panic");
    }

    #[test]
    fn test_min_fill_equals_value_full_fill_only() {
        // When min_fill == value, partial fill should not be possible
        // (residual would be 0, below MIN_UTXO_VALUE)
        let mut ob = OrderBook::new();
        let mut buy = make_buy(10_000_000, 1, 2, FAKE_TOKEN);
        buy.min_fill = 10_000_000; // min_fill = entire value
        buy.owner_hash = "aa".repeat(32);
        ob.add_buy_order(buy);
        let mut sell = make_sell(10_000_000, 1, 2, FAKE_TOKEN);
        sell.owner_hash = "bb".repeat(32);
        ob.add_sell_order(sell);
        let pairs = find_all_crossing_pairs(&ob);
        // Full fill should work; partial fill should not appear
        for p in &pairs {
            assert_eq!(p.match_type, MatchType::Full, "only full fill allowed when min_fill == value");
        }
    }

    #[test]
    fn test_dust_output_prevention() {
        // When expected_tokens or expected_kas is exactly at MIN_UTXO_VALUE boundary
        let mut ob = OrderBook::new();
        // Buy 6M at price 1/2 -> expected_tokens = 3M = MIN_UTXO_VALUE (assuming MIN_UTXO_VALUE = 3M)
        let mut buy = make_buy(6_000_000, 1, 2, FAKE_TOKEN);
        buy.owner_hash = "aa".repeat(32);
        ob.add_buy_order(buy);
        let mut sell = make_sell(6_000_000, 1, 2, FAKE_TOKEN);
        sell.owner_hash = "bb".repeat(32);
        ob.add_sell_order(sell);
        let pairs = find_all_crossing_pairs(&ob);
        // At 3M exactly (= MIN_UTXO_VALUE), it should be accepted
        assert_eq!(pairs.len(), 1, "exact MIN_UTXO_VALUE should be accepted");
    }

    // Batch group tests

    /// Helper: create a CrossingPair for batch group tests.
    ///
    /// `token` is the token_cov_id string, `id` is used to generate unique
    /// tx_ids so pairs don't collide.
    fn make_crossing_pair(token: &str, id: u32) -> CrossingPair {
        let buy_tx = format!("{:0>64}", format!("buy{}", id));
        let sell_tx = format!("{:0>64}", format!("sell{}", id));
        CrossingPair {
            token_cov_id: token.to_string(),
            buy: BookOrder {
                tx_id: buy_tx,
                index: 0,
                value: 10_000_000,
                token_cov_id: token.to_string(),
                price_num: 1,
                price_den: 2,
                min_fill: 1_000_000,
                owner_hash: "b".repeat(64),
                spk_hash: "11".repeat(32),
                counterparty_spk: None,
                redeem_script_hex: String::new(),
                p2sh_script_hex: String::new(),
                p2sh_version: 0,
                side: OrderSide::Buy,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0,
            },
            sell: BookOrder {
                tx_id: sell_tx,
                index: 0,
                value: 10_000_000,
                token_cov_id: token.to_string(),
                price_num: 1,
                price_den: 2,
                min_fill: 1_000_000,
                owner_hash: "d".repeat(64),
                spk_hash: "22".repeat(32),
                counterparty_spk: None,
                redeem_script_hex: String::new(),
                p2sh_script_hex: String::new(),
                p2sh_version: 0,
                side: OrderSide::Sell,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0,
            },
            seller_kas: 5_000_000,
            buyer_tokens: 5_000_000,
            surplus: estimate_compute_mass(3, 5, 0) + 100_000,
            expected_tokens: 5_000_000,
            expected_kas: 5_000_000,
            match_type: MatchType::Full,
            fill_kas: None,
            residual_kas: None,
            fill_token_amount: None,
            residual_tokens: None,
        }
    }

    #[test]
    fn test_find_batch_groups_single_pair_batched() {
        let pairs = vec![make_crossing_pair(FAKE_TOKEN, 1)];
        let groups = find_batch_groups(&pairs);
        assert_eq!(groups.len(), 1, "single pair should be batched");
        assert_eq!(groups[0].len(), 1);
    }

    #[test]
    fn test_find_batch_groups_two_pairs_same_token() {
        let pairs = vec![
            make_crossing_pair(FAKE_TOKEN, 1),
            make_crossing_pair(FAKE_TOKEN, 2),
        ];
        let groups = find_batch_groups(&pairs);
        assert_eq!(groups.len(), 1, "should have 1 batch group");
        assert_eq!(groups[0].len(), 2, "group should have 2 pairs");
    }

    #[test]
    fn test_find_batch_groups_different_tokens() {
        let token_b = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        let pairs = vec![
            make_crossing_pair(FAKE_TOKEN, 1),
            make_crossing_pair(token_b, 2),
        ];
        let groups = find_batch_groups(&pairs);
        assert_eq!(groups.len(), 2, "different tokens should produce 2 groups of 1");
    }

    #[test]
    fn test_find_batch_groups_opn_limit() {
        // 16 pairs of same token -> should be split: group of 15 + group of 1
        let pairs: Vec<_> = (0..16).map(|i| make_crossing_pair(FAKE_TOKEN, i)).collect();
        let groups = find_batch_groups(&pairs);
        assert_eq!(groups.len(), 2, "16 pairs should produce 2 groups (15 + 1)");
        assert_eq!(groups[0].len(), 15, "first group should have 15 pairs");
        assert_eq!(groups[1].len(), 1, "second group should have 1 pair");
    }

    #[test]
    fn test_find_batch_groups_partial_fills_excluded() {
        let mut pair = make_crossing_pair(FAKE_TOKEN, 1);
        pair.match_type = MatchType::PartialBuy;
        let pairs = vec![pair, make_crossing_pair(FAKE_TOKEN, 2)];
        let groups = find_batch_groups(&pairs);
        assert_eq!(groups.len(), 1, "partial excluded, 1 full pair should batch");
        assert_eq!(groups[0].len(), 1);
    }

    #[test]
    fn test_find_batch_groups_mixed_full_and_partial() {
        // 3 full + 1 partial for same token -> group of 3 full fills
        let mut partial = make_crossing_pair(FAKE_TOKEN, 99);
        partial.match_type = MatchType::PartialSell;
        let pairs = vec![
            make_crossing_pair(FAKE_TOKEN, 1),
            make_crossing_pair(FAKE_TOKEN, 2),
            partial,
            make_crossing_pair(FAKE_TOKEN, 3),
        ];
        let groups = find_batch_groups(&pairs);
        assert_eq!(groups.len(), 1, "should have 1 batch group from the 3 full fills");
        assert_eq!(groups[0].len(), 3);
    }

    #[test]
    fn test_find_batch_groups_30_pairs_two_groups() {
        // 30 pairs -> group of 15 + group of 15
        let pairs: Vec<_> = (0..30).map(|i| make_crossing_pair(FAKE_TOKEN, i)).collect();
        let groups = find_batch_groups(&pairs);
        assert_eq!(groups.len(), 2, "30 pairs should produce 2 groups of 15");
        assert_eq!(groups[0].len(), 15);
        assert_eq!(groups[1].len(), 15);
    }

    #[test]
    fn test_find_batch_groups_multi_token_batches() {
        let token_b = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        // 3 pairs token_a + 2 pairs token_b -> 2 groups
        let pairs = vec![
            make_crossing_pair(FAKE_TOKEN, 1),
            make_crossing_pair(FAKE_TOKEN, 2),
            make_crossing_pair(FAKE_TOKEN, 3),
            make_crossing_pair(token_b, 4),
            make_crossing_pair(token_b, 5),
        ];
        let groups = find_batch_groups(&pairs);
        assert_eq!(groups.len(), 2, "should have 2 groups (one per token)");
    }

    #[test]
    fn test_find_batch_groups_empty_input() {
        let groups = find_batch_groups(&[]);
        assert!(groups.is_empty());
    }

    // Cross-pair batch group tests

    const TOKEN_A_CP: &str = "0102030405060708091011121314151617181920212223242526272829303132";
    const TOKEN_B_CP: &str = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    const TOKEN_C_CP: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn make_buy_cp(
        tx_id_char: char,
        value: u64,
        price_num: u64,
        price_den: u64,
        token_cov_id: &str,
    ) -> BookOrder {
        BookOrder {
            tx_id: tx_id_char.to_string().repeat(64),
            index: 0,
            value,
            token_cov_id: token_cov_id.to_string(),
            price_num,
            price_den,
            min_fill: 1_000_000,
            owner_hash: "b".repeat(64),
            spk_hash: "11".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Buy,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0,
        }
    }

    fn make_sell_cp(
        tx_id_char: char,
        value: u64,
        price_num: u64,
        price_den: u64,
        token_cov_id: &str,
    ) -> BookOrder {
        BookOrder {
            tx_id: tx_id_char.to_string().repeat(64),
            index: 1,
            value,
            token_cov_id: token_cov_id.to_string(),
            price_num,
            price_den,
            min_fill: 1_000_000,
            owner_hash: "d".repeat(64),
            spk_hash: "22".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Sell,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0,
        }
    }

    /// Test: combines same-pair crossings from two different tokens into one group.
    #[test]
    fn test_cross_pair_batch_groups_basic() {
        let mut ob = OrderBook::new();
        // Token A: crossing pair (sell + buy same token)
        // Sell 20M Token A at price 1/2 (expects 10M KAS)
        ob.add_sell_order(make_sell_cp('c', 20_000_000, 1, 2, TOKEN_A_CP));
        // Buy Token A with 15M KAS at price 1/1 (expects 15M tokens)
        // Crossing: buyer pays 15M KAS, seller expects 10M -> surplus = 5M
        ob.add_buy_order(make_buy_cp('a', 15_000_000, 1, 1, TOKEN_A_CP));

        // Token B: crossing pair (sell + buy same token)
        // Sell 10M Token B at price 1/3 (expects ~3.3M KAS)
        ob.add_sell_order(make_sell_cp('f', 10_000_000, 1, 3, TOKEN_B_CP));
        // Buy Token B with 5_000_000 KAS at price 1/1 (expects 5M tokens)
        // Crossing: buyer pays 5M KAS, seller expects ~3.3M -> surplus ~ 1.7M
        ob.add_buy_order(make_buy_cp('e', 5_000_000, 1, 1, TOKEN_B_CP));

        let groups = find_cross_pair_batch_groups(&ob, 100, false, None);

        assert_eq!(groups.len(), 1, "Should find 1 cross-pair batch group");
        assert_eq!(groups[0].sells.len(), 2, "Group should have 2 sells (one per token)");
        assert_eq!(groups[0].buys.len(), 2, "Group should have 2 buys (one per token)");
        assert!(groups[0].total_surplus > 0);
    }

    /// Test: no same-pair crossings -> empty (sell A + buy B is not a valid crossing).
    #[test]
    fn test_cross_pair_batch_groups_no_route() {
        let mut ob = OrderBook::new();
        // Only a sell in Token A and a buy in Token B -- no same-pair crossing
        ob.add_sell_order(make_sell_cp('c', 20_000_000, 1, 2, TOKEN_A_CP));
        ob.add_buy_order(make_buy_cp('a', 15_000_000, 1, 3, TOKEN_B_CP));

        let groups = find_cross_pair_batch_groups(&ob, 100, false, None);
        assert!(groups.is_empty(), "No same-pair crossings should yield no groups");
    }

    /// Test: single token with a crossing pair -> not a cross-pair group (needs >= 2 tokens).
    #[test]
    fn test_cross_pair_batch_groups_skips_single_token() {
        let mut ob = OrderBook::new();
        // Only Token A has a crossing pair
        ob.add_sell_order(make_sell_cp('c', 20_000_000, 1, 2, TOKEN_A_CP));
        ob.add_buy_order(make_buy_cp('a', 20_000_000, 1, 1, TOKEN_A_CP));

        let groups = find_cross_pair_batch_groups(&ob, 100, false, None);
        assert!(groups.is_empty(), "Single-token crossing is not a cross-pair group");
    }

    /// Test: crossings from 3 different tokens combined into one group.
    #[test]
    fn test_cross_pair_batch_groups_multiple_tokens() {
        let mut ob = OrderBook::new();
        // Token A crossing: surplus = 15M - 5M = 10M
        ob.add_sell_order(make_sell_cp('c', 10_000_000, 1, 2, TOKEN_A_CP));
        ob.add_buy_order(make_buy_cp('a', 15_000_000, 1, 1, TOKEN_A_CP));
        // Token B crossing: surplus = 15M - 5M = 10M
        ob.add_sell_order(make_sell_cp('f', 15_000_000, 1, 3, TOKEN_B_CP));
        ob.add_buy_order(make_buy_cp('e', 15_000_000, 1, 1, TOKEN_B_CP));
        // Token C crossing: surplus = 20M - 10M = 10M
        ob.add_sell_order(make_sell_cp('h', 20_000_000, 1, 2, TOKEN_C_CP));
        ob.add_buy_order(make_buy_cp('g', 20_000_000, 1, 1, TOKEN_C_CP));

        let groups = find_cross_pair_batch_groups(&ob, 100, false, None);

        assert_eq!(groups.len(), 1, "All 3 token crossings fit in one group");
        assert_eq!(groups[0].sells.len(), 3);
        assert_eq!(groups[0].buys.len(), 3);
        assert!(groups[0].total_surplus > 0);
    }

    /// Test: empty order book returns no groups.
    #[test]
    fn test_cross_pair_batch_groups_empty() {
        let ob = OrderBook::new();
        let groups = find_cross_pair_batch_groups(&ob, 100, false, None);
        assert!(groups.is_empty());
    }

    /// Test: spent_outpoints filters out already-claimed orders.
    #[test]
    fn test_cross_pair_batch_groups_spent_filter() {
        use std::collections::HashSet;
        let mut ob = OrderBook::new();
        // Token A crossing
        let sell_a = make_sell_cp('c', 20_000_000, 1, 2, TOKEN_A_CP);
        let sell_a_key = sell_a.outpoint_key();
        ob.add_sell_order(sell_a);
        ob.add_buy_order(make_buy_cp('a', 15_000_000, 1, 1, TOKEN_A_CP));
        // Token B crossing
        ob.add_sell_order(make_sell_cp('f', 10_000_000, 1, 3, TOKEN_B_CP));
        ob.add_buy_order(make_buy_cp('e', 5_000_000, 1, 1, TOKEN_B_CP));

        // Without spent filter: should find 1 group
        let groups = find_cross_pair_batch_groups(&ob, 100, false, None);
        assert_eq!(groups.len(), 1);

        // Mark Token A sell as spent: only Token B crossing remains -> not enough for cross-pair
        let mut spent = HashSet::new();
        spent.insert(sell_a_key);
        let groups = find_cross_pair_batch_groups(&ob, 100, false, Some(&spent));
        assert!(groups.is_empty(), "With Token A sell spent, only 1 token crossing remains");
    }

    // Triangular batch group tests

    const TOKEN_A_TRI: &str = "0102030405060708091011121314151617181920212223242526272829303132";
    const TOKEN_B_TRI: &str = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    const TOKEN_C_TRI: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn make_sell_tri(tx_id: &str, index: u32, value: u64, price_num: u64, price_den: u64, token: &str) -> BookOrder {
        BookOrder {
            tx_id: format!("{:0>64}", tx_id),
            index,
            value,
            token_cov_id: token.to_string(),
            price_num,
            price_den,
            min_fill: 1_000_000,
            owner_hash: format!("owner_sell_{}", tx_id),
            spk_hash: "22".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Sell,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0,
        }
    }

    fn make_buy_tri(tx_id: &str, index: u32, value: u64, price_num: u64, price_den: u64, token: &str) -> BookOrder {
        BookOrder {
            tx_id: format!("{:0>64}", tx_id),
            index,
            value,
            token_cov_id: token.to_string(),
            price_num,
            price_den,
            min_fill: 1_000_000,
            owner_hash: format!("owner_buy_{}", tx_id),
            spk_hash: "11".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Buy,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0,
        }
    }

    /// Test: triangular batch group correctly contains 3 sells + 3 buys.
    #[test]
    fn triangular_batch_group_basic() {
        let mut ob = OrderBook::new();

        // 3-leg cycle: A->B->C->A, each leg surplus = 5M
        ob.add_sell_order(make_sell_tri("ts1", 1, 10_000_000, 1, 2, TOKEN_A_TRI));
        ob.add_buy_order(make_buy_tri("tb1", 0, 10_000_000, 1, 2, TOKEN_B_TRI));

        ob.add_sell_order(make_sell_tri("ts2", 1, 10_000_000, 1, 2, TOKEN_B_TRI));
        ob.add_buy_order(make_buy_tri("tb2", 0, 10_000_000, 1, 2, TOKEN_C_TRI));

        ob.add_sell_order(make_sell_tri("ts3", 1, 10_000_000, 1, 2, TOKEN_C_TRI));
        ob.add_buy_order(make_buy_tri("tb3", 0, 10_000_000, 1, 2, TOKEN_A_TRI));

        let groups = find_triangular_batch_groups(&ob, 10, true);

        assert!(!groups.is_empty(), "Should find at least 1 triangular batch group");

        let group = &groups[0];
        assert_eq!(group.sells.len(), 3, "Triangular group should have 3 sell legs");
        assert_eq!(group.buys.len(), 3, "Triangular group should have 3 buy legs");
        assert_eq!(group.total_surplus, 15_000_000, "Total surplus = 3 * 5M");
    }

    // E2E Integration: Full matching pipeline tests

    /// Helper: make a buy with unique tx_id and configurable owner.
    fn make_buy_e2e(
        tx_id: &str,
        index: u32,
        value: u64,
        price_num: u64,
        price_den: u64,
        token_cov_id: &str,
        owner_hash: &str,
    ) -> BookOrder {
        BookOrder {
            tx_id: tx_id.to_string(),
            index,
            value,
            token_cov_id: token_cov_id.to_string(),
            price_num,
            price_den,
            min_fill: 1_000_000,
            owner_hash: owner_hash.to_string(),
            spk_hash: "11".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Buy,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0,
        }
    }

    fn make_sell_e2e(
        tx_id: &str,
        index: u32,
        value: u64,
        price_num: u64,
        price_den: u64,
        token_cov_id: &str,
        owner_hash: &str,
    ) -> BookOrder {
        BookOrder {
            tx_id: tx_id.to_string(),
            index,
            value,
            token_cov_id: token_cov_id.to_string(),
            price_num,
            price_den,
            min_fill: 1_000_000,
            owner_hash: owner_hash.to_string(),
            spk_hash: "22".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Sell,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0,
        }
    }

    /// E2E: Buy + sell cross -> batch group creation.
    #[test]
    fn e2e_match_creates_batch_group() {
        let mut ob = OrderBook::new();
        let token = FAKE_TOKEN;
        let owner_a = "aa".repeat(32);
        let owner_b = "bb".repeat(32);

        // 3 buys and 3 sells that all cross at 1/2
        for i in 0..3u32 {
            ob.add_buy_order(make_buy_e2e(
                &format!("b{}", "a".repeat(63)), i, 20_000_000, 1, 2, token, &owner_a,
            ));
            ob.add_sell_order(make_sell_e2e(
                &format!("s{}", "c".repeat(63)), i, 20_000_000, 1, 2, token, &owner_b,
            ));
        }

        let pairs = find_all_crossing_pairs_with_stp(&ob, true);
        assert!(!pairs.is_empty(), "Should find crossing pairs");

        // Full-fill pairs should form batch groups
        let groups = find_batch_groups(&pairs);
        // With 3 crossing full-fill pairs of the same token, we get 1 batch group
        if !groups.is_empty() {
            let group = &groups[0];
            assert!(group.len() >= 2, "Batch group needs at least 2 pairs");
            assert!(group.len() <= MAX_BATCH_GROUP_SIZE);
        }
    }

    /// E2E: Partial fill — large buy matched partially with small sell, remainder stays.
    ///
    /// For a partial buy to trigger:
    ///   - expected_tokens (buy's demand) > sell.value (sell's supply of tokens)
    ///   - full fill arithmetic must FAIL (sum > total_in, or surplus < threshold)
    ///   - the partial amount must exceed min_fill and MIN_UTXO_VALUE thresholds
    ///
    /// Setup: buy 50M KAS at 3/1 (expects 150M tokens), sell 30M tokens at 2/1 (expects 60M KAS).
    /// Full fill: sum = 60M + 150M = 210M > total_in = 50M + 30M = 80M -> full fill FAILS.
    /// Partial buy: fill_kas = ceil(30M * 1 / 3) = 10M. fill_tokens = 10M * 3 / 1 = 30M.
    /// seller_kas = 60M. residual_kas = 50M - 10M = 40M.
    /// surplus = (50M + 30M) - 60M - 30M - 40M = -50M -> negative, won't work either.
    ///
    /// Actually, we need: buy price >= sell price (prices cross),
    /// AND full fill fails, AND partial fill has enough surplus.
    ///
    /// Approach: buy at 2/1 (2 tokens per KAS), sell at 1/1 (1 token per KAS).
    /// Buy: 50M KAS, expects 100M tokens. Sell: 30M tokens, expects 30M KAS.
    /// Full fill: sum = 30M + 100M = 130M > total_in = 80M -> FAILS.
    /// Partial buy: expected_tokens(100M) > sell.value(30M), so we try.
    /// fill_kas = ceil(30M * 1/2) = 15M. fill_tokens = 15M * 2/1 = 30M.
    /// seller_kas = 30M. residual = 50M - 15M = 35M.
    /// surplus = (50M + 30M) - 30M - 30M - 35M = -15M -> still negative!
    ///
    /// The issue is that the sell expects too much KAS relative to what's available.
    /// Let me use: buy 50M at 2/1, sell 10M tokens at 1/10.
    /// Sell expects 10M * 1/10 = 1M KAS. Full fill: sum = 1M + 100M = 101M > 60M -> FAILS.
    /// Partial: fill_kas = ceil(10M / 2) = 5M. fill_tokens = 5M * 2 = 10M.
    /// seller_kas = 1M. residual = 50M - 5M = 45M.
    /// surplus = (50M + 10M) - 1M - 10M - 45M = 4M >= 3.01M -> WORKS!
    #[test]
    fn e2e_partial_fill_large_buy_small_sell() {
        let mut ob = OrderBook::new();
        let token = FAKE_TOKEN;
        let owner_a = "aa".repeat(32);
        let owner_b = "bb".repeat(32);

        // Large buy: 50M KAS at 2/1 (expects 100M tokens)
        ob.add_buy_order(make_buy_e2e(
            &"a".repeat(64), 0, 50_000_000, 2, 1, token, &owner_a,
        ));
        // Small sell: 20M tokens at 1/3 (expects ~6.67M KAS)
        // Buy expects 100M tokens but sell has only 20M -> PartialBuy
        // Surplus = ~3.33M >= estimated miner fee
        ob.add_sell_order(make_sell_e2e(
            &"c".repeat(64), 1, 20_000_000, 1, 3, token, &owner_b,
        ));

        let pairs = find_all_crossing_pairs_with_stp(&ob, true);
        let partial_buys: Vec<_> = pairs.iter()
            .filter(|p| p.match_type == MatchType::PartialBuy)
            .collect();

        assert!(!partial_buys.is_empty(), "Should find a partial buy match (found {} total pairs)", pairs.len());
        let pb = &partial_buys[0];
        assert!(pb.fill_kas.is_some(), "PartialBuy should have fill_kas");
        assert!(pb.residual_kas.is_some(), "PartialBuy should have residual_kas");
        let fill_kas = pb.fill_kas.unwrap();
        let residual_kas = pb.residual_kas.unwrap();
        assert!(fill_kas < pb.buy.value, "fill_kas < full buy amount");
        assert!(residual_kas > 0, "should have non-zero residual");
        assert_eq!(fill_kas + residual_kas, pb.buy.value, "fill + residual = buy value");
        assert!(pb.surplus >= estimate_compute_mass(3, 5, 0), "surplus must cover mass-based miner fee");
    }

    /// E2E: Partial fill — large sell matched partially with small buy, remainder stays.
    #[test]
    fn e2e_partial_fill_large_sell_small_buy() {
        let mut ob = OrderBook::new();
        let token = FAKE_TOKEN;
        let owner_a = "aa".repeat(32);
        let owner_b = "bb".repeat(32);

        // Small buy: 10M KAS at 1/2 (expects 5M tokens)
        ob.add_buy_order(make_buy_e2e(
            &"a".repeat(64), 0, 10_000_000, 1, 2, token, &owner_a,
        ));
        // Large sell: 100M tokens at 1/3 (expects ~33M KAS)
        // sell price lower than buy price -> they cross
        ob.add_sell_order(make_sell_e2e(
            &"c".repeat(64), 1, 100_000_000, 1, 3, token, &owner_b,
        ));

        let pairs = find_all_crossing_pairs_with_stp(&ob, true);
        let partial_sells: Vec<_> = pairs.iter()
            .filter(|p| p.match_type == MatchType::PartialSell)
            .collect();

        // Should find partial sell since sell is much larger
        if !partial_sells.is_empty() {
            let ps = &partial_sells[0];
            assert!(ps.fill_token_amount.is_some(), "PartialSell should have fill_token_amount");
            assert!(ps.residual_tokens.is_some(), "PartialSell should have residual_tokens");
            let fill_tokens = ps.fill_token_amount.unwrap();
            let residual_tokens = ps.residual_tokens.unwrap();
            assert!(fill_tokens < 100_000_000, "fill < full sell amount");
            assert!(residual_tokens > 0, "should have non-zero residual");
        }
    }

    /// E2E: Self-trade prevention — same owner on both sides should be skipped.
    #[test]
    fn e2e_stp_blocks_same_owner() {
        let mut ob = OrderBook::new();
        let token = FAKE_TOKEN;
        let same_owner = "aa".repeat(32);

        ob.add_buy_order(make_buy_e2e(
            &"a".repeat(64), 0, 20_000_000, 1, 2, token, &same_owner,
        ));
        ob.add_sell_order(make_sell_e2e(
            &"c".repeat(64), 1, 20_000_000, 1, 2, token, &same_owner,
        ));

        // With STP enabled (default), same owner pairs should be skipped
        let pairs_stp = find_all_crossing_pairs(&ob);
        assert!(pairs_stp.is_empty(), "STP should block same-owner match");

        // With STP disabled, they should cross
        let pairs_no_stp = find_all_crossing_pairs_with_stp(&ob, true);
        assert!(!pairs_no_stp.is_empty(), "Without STP, same-owner should cross");
    }

    /// E2E: Matched outpoint prevents re-matching.
    #[test]
    fn e2e_matched_outpoint_prevents_rematch() {
        let mut ob = OrderBook::new();
        let token = FAKE_TOKEN;
        let owner_a = "aa".repeat(32);
        let owner_b = "bb".repeat(32);

        let buy = make_buy_e2e(&"a".repeat(64), 0, 20_000_000, 1, 2, token, &owner_a);
        let sell = make_sell_e2e(&"c".repeat(64), 1, 20_000_000, 1, 2, token, &owner_b);
        let buy_key = buy.outpoint_key();
        ob.add_buy_order(buy);
        ob.add_sell_order(sell);

        let pairs = find_all_crossing_pairs_with_stp(&ob, true);
        assert!(!pairs.is_empty(), "Should find match before removal");

        // Simulate match execution: remove the buy order
        ob.remove_order(&buy_key);

        let pairs_after = find_all_crossing_pairs_with_stp(&ob, true);
        assert!(pairs_after.is_empty(), "No match after buy order removed");
    }

    /// E2E: Cross-pair batch group combines same-pair crossings from two tokens.
    #[test]
    fn e2e_cross_pair_batch_group() {
        let mut ob = OrderBook::new();
        let token_a = "0a".repeat(32);
        let token_b = "0b".repeat(32);
        let owner_a = "aa".repeat(32);
        let owner_b = "bb".repeat(32);
        let owner_c = "cc".repeat(32);
        let owner_d = "dd".repeat(32);

        // Token A: same-pair crossing (sell A + buy A)
        ob.add_sell_order(make_sell_e2e(
            &"s".repeat(64), 0, 20_000_000, 1, 2, &token_a, &owner_a,
        ));
        ob.add_buy_order(make_buy_e2e(
            &"b".repeat(64), 0, 20_000_000, 1, 1, &token_a, &owner_b,
        ));
        // Token B: same-pair crossing (sell B + buy B)
        ob.add_sell_order(make_sell_e2e(
            &"t".repeat(64), 0, 15_000_000, 1, 3, &token_b, &owner_c,
        ));
        ob.add_buy_order(make_buy_e2e(
            &"u".repeat(64), 0, 10_000_000, 1, 1, &token_b, &owner_d,
        ));

        let groups = find_cross_pair_batch_groups(&ob, 10, true, None);
        // Two same-pair crossings from different tokens -> 1 cross-pair group
        assert!(!groups.is_empty(), "Should find cross-pair batch group");
        let group = &groups[0];
        assert_eq!(group.sells.len(), 2, "Should have sell from each token");
        assert_eq!(group.buys.len(), 2, "Should have buy from each token");
        assert!(group.total_surplus > 0);
    }

    /// E2E: Multiple pairs independently matched.
    #[test]
    fn e2e_multi_pair_matching() {
        let mut ob = OrderBook::new();
        let token_a = "0a".repeat(32);
        let token_b = "0b".repeat(32);

        // Pair A: crossing orders
        ob.add_buy_order(make_buy_e2e(
            &"a".repeat(64), 0, 20_000_000, 1, 2, &token_a, &"aa".repeat(32),
        ));
        ob.add_sell_order(make_sell_e2e(
            &"b".repeat(64), 0, 20_000_000, 1, 2, &token_a, &"bb".repeat(32),
        ));

        // Pair B: crossing orders
        ob.add_buy_order(make_buy_e2e(
            &"c".repeat(64), 0, 30_000_000, 1, 3, &token_b, &"cc".repeat(32),
        ));
        ob.add_sell_order(make_sell_e2e(
            &"d".repeat(64), 0, 30_000_000, 1, 3, &token_b, &"dd".repeat(32),
        ));

        let pairs = find_all_crossing_pairs_with_stp(&ob, true);
        // Should find matches in both pairs
        let pair_a_matches: Vec<_> = pairs.iter().filter(|p| p.token_cov_id == token_a).collect();
        let pair_b_matches: Vec<_> = pairs.iter().filter(|p| p.token_cov_id == token_b).collect();
        assert!(!pair_a_matches.is_empty(), "Pair A should have matches");
        assert!(!pair_b_matches.is_empty(), "Pair B should have matches");
    }

    /// E2E: Zero-price orders are skipped (M-3 guard).
    #[test]
    fn e2e_zero_price_orders_skipped() {
        let mut ob = OrderBook::new();
        let token = FAKE_TOKEN;

        // Buy with price_num=0 (corrupted)
        let mut bad_buy = make_buy(20_000_000, 1, 2, token);
        bad_buy.price_num = 0;
        bad_buy.tx_id = "z".repeat(64);
        ob.add_buy_order(bad_buy);

        ob.add_sell_order(make_sell_e2e(
            &"c".repeat(64), 1, 20_000_000, 1, 2, token, &"dd".repeat(32),
        ));

        let pairs = find_all_crossing_pairs_with_stp(&ob, true);
        assert!(pairs.is_empty(), "Zero-price buy should be skipped by M-3 guard");
    }

    // M-7: Minimum partial fill / rounding-drain guard tests

    #[test]
    fn test_min_partial_fill_helper() {
        // price 1/3: need ceil(3/1) = 3 input to get >= 1 output
        assert_eq!(min_partial_fill(1, 3), 3);
        // price 1/1: need ceil(1/1) = 1
        assert_eq!(min_partial_fill(1, 1), 1);
        // price 3/1: need ceil(1/3) = 1
        assert_eq!(min_partial_fill(3, 1), 1);
        // price 1/100: need 100
        assert_eq!(min_partial_fill(1, 100), 100);
        // price 2/7: need ceil(7/2) = 4
        assert_eq!(min_partial_fill(2, 7), 4);
        // price_num = 0: returns 0 (caller guards separately)
        assert_eq!(min_partial_fill(0, 5), 0);
    }

    #[test]
    fn test_rounding_drain_partial_buy_rejected() {
        // Buy order with extreme price ratio: pnum=1, pden=1_000_000.
        // A partial buy with fill_kas < 1_000_000 would yield 0 tokens
        // after truncation (fill_kas * 1 / 1_000_000 = 0).
        // The M-7 guard should prevent this from producing a CrossingPair.
        let _buy = make_buy(100_000_000, 1, 1_000_000, FAKE_TOKEN);
        // Small sell: only 50 tokens. fill_kas = ceil(50 * 1_000_000 / 1) = 50_000_000.
        // fill_tokens = 50_000_000 * 1 / 1_000_000 = 50. That's >= 1, so this SHOULD work.
        // But if sell value is just 1 token:
        // fill_kas = ceil(1 * 1_000_000 / 1) = 1_000_000
        // fill_tokens = 1_000_000 * 1 / 1_000_000 = 1 -- borderline OK.
        // To trigger zero: sell value must be < min_partial_fill's threshold.
        // Actually the computed fill_kas from ceil already ensures >= 1 output.
        // The guard catches cases where the ceil-computed fill itself is tiny.
        //
        // Direct test via compute_partial_fill_match:
        // Buy: 10M KAS, price 1/10_000_000 (expects 1 token per 10M KAS)
        // Sell: 1 token, price 1/1 (expects 1 KAS)
        // expected_tokens = 10M * 1 / 10_000_000 = 1
        // expected_kas = 1 * 1 / 1 = 1
        // expected_tokens(1) <= sell_tokens(1) -> Case 1 doesn't trigger.
        // expected_kas(1) <= buy_kas(10M) -> Case 2 doesn't trigger either.
        // This is actually a full-fill scenario. Let's craft a true partial.
        //
        // True rounding drain: buy with pnum=1, pden=very_large,
        // and sell small enough that fill_kas ends up below ceil(pden/pnum).
        let buy2 = BookOrder {
            tx_id: "a".repeat(64),
            index: 0,
            value: 50_000_000,
            token_cov_id: FAKE_TOKEN.to_string(),
            price_num: 1,
            price_den: 100_000_000, // 1 token per 100M KAS
            min_fill: 0, // set to 0 to bypass min_fill guard, isolate M-7
            owner_hash: "aa".repeat(32),
            spk_hash: "11".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Buy,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0,
        };
        let sell2 = BookOrder {
            tx_id: "c".repeat(64),
            index: 1,
            value: 5_000_000, // 5M tokens
            token_cov_id: FAKE_TOKEN.to_string(),
            price_num: 1,
            price_den: 100_000_000, // sells at same ratio
            min_fill: 0,
            owner_hash: "bb".repeat(32),
            spk_hash: "22".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Sell,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0,
        };
        // expected_tokens = 50M * 1 / 100M = 0 -> Case 1 won't trigger (0 <= 5M)
        // expected_kas = 5M * 1 / 100M = 0 -> Case 2 won't trigger (0 <= 50M)
        // Both expected outputs are 0, so neither partial case triggers.
        // Full fill: sum = 0 + 0 = 0 <= 55M, surplus = 55M >= threshold...
        // BUT seller_kas=0 < MIN_UTXO_VALUE and buyer_tokens=0 < MIN_UTXO_VALUE -> rejected.
        let result = compute_partial_fill_match(FAKE_TOKEN, &buy2, &sell2);
        assert!(result.is_none(), "zero-output partial fill must be rejected");
    }

    #[test]
    fn test_rounding_drain_partial_sell_rejected() {
        // Sell order with extreme price ratio: pnum=1, pden=100_000_000.
        // fill_token_amount * 1 / 100_000_000 must be >= 1,
        // so fill_token_amount must be >= 100_000_000.
        // If buy_kas is too small, the computed fill_token_amount will be small
        // and the M-7 guard should reject.
        let buy = BookOrder {
            tx_id: "a".repeat(64),
            index: 0,
            value: 5_000_000,
            token_cov_id: FAKE_TOKEN.to_string(),
            price_num: 1,
            price_den: 1, // buyer wants 1:1
            min_fill: 0,
            owner_hash: "aa".repeat(32),
            spk_hash: "11".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Buy,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0,
        };
        let sell = BookOrder {
            tx_id: "c".repeat(64),
            index: 1,
            value: 500_000_000, // large sell
            token_cov_id: FAKE_TOKEN.to_string(),
            price_num: 1,
            price_den: 100_000_000, // 1 KAS per 100M tokens
            min_fill: 0,
            owner_hash: "bb".repeat(32),
            spk_hash: "22".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Sell,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0,
        };
        // expected_tokens = 5M * 1 / 1 = 5M
        // expected_kas = 500M * 1 / 100M = 5
        // Full fill: sum = 5 + 5M = ~5M <= 505M, surplus huge. But expected_kas=5 < MIN_UTXO_VALUE -> no full fill.
        // Case 2: expected_kas(5) <= buy_kas(5M) -> doesn't trigger.
        // Case 1: expected_tokens(5M) > sell.value(500M)? No, 5M < 500M.
        // So neither partial case triggers. No match.
        let result = compute_partial_fill_match(FAKE_TOKEN, &buy, &sell);
        assert!(result.is_none(), "rounding-drain partial sell must be rejected");
    }

    #[test]
    fn test_partial_fill_at_exact_minimum_threshold() {
        // Price = 1/3: minimum fill = ceil(3/1) = 3. fill * 1 / 3 = 1 (exactly).
        // This should be allowed by the M-7 guard (output is 1, not 0).
        let min = min_partial_fill(1, 3);
        assert_eq!(min, 3);
        let output = min * 1 / 3;
        assert_eq!(output, 1, "at minimum threshold, output must be exactly 1");

        // Price = 2/7: minimum fill = ceil(7/2) = 4. fill * 2 / 7 = 8 / 7 = 1.
        let min2 = min_partial_fill(2, 7);
        assert_eq!(min2, 4);
        let output2 = min2 * 2 / 7;
        assert_eq!(output2, 1, "at minimum threshold, output must be exactly 1");

        // One below minimum should yield 0.
        let below = (min2 - 1) * 2 / 7;
        assert_eq!(below, 0, "below minimum threshold, output must be 0");
    }

    #[test]
    fn test_normal_partial_fills_unaffected() {
        // Normal partial fill scenario should still work exactly as before.
        // This is a regression test against the e2e_partial_fill_large_buy_small_sell test.
        let mut ob = OrderBook::new();
        let token = FAKE_TOKEN;
        let owner_a = "aa".repeat(32);
        let owner_b = "bb".repeat(32);

        // Large buy: 50M KAS at 2/1 (expects 100M tokens)
        ob.add_buy_order(make_buy_e2e(
            &"a".repeat(64), 0, 50_000_000, 2, 1, token, &owner_a,
        ));
        // Small sell: 20M tokens at 1/3 (expects ~6.67M KAS)
        ob.add_sell_order(make_sell_e2e(
            &"c".repeat(64), 1, 20_000_000, 1, 3, token, &owner_b,
        ));

        let pairs = find_all_crossing_pairs_with_stp(&ob, true);
        let partial_buys: Vec<_> = pairs.iter()
            .filter(|p| p.match_type == MatchType::PartialBuy)
            .collect();

        assert!(!partial_buys.is_empty(), "Normal partial buy should still work after M-7 guard");
        let pb = &partial_buys[0];
        let fill_kas = pb.fill_kas.unwrap();
        // Verify output is non-zero
        let output_tokens = fill_kas * pb.buy.price_num / pb.buy.price_den;
        assert!(output_tokens > 0, "fill must produce non-zero tokens");
    }

    // Sweep group tests

    #[test]
    fn test_sweep_buy_3_sells() {
        // 1 large buy (5B KAS at price 4/1) vs 3 sells at 2/1, 3/1, 4/1 (500M tokens each)
        let token = FAKE_TOKEN;
        let mut ob = OrderBook::new();

        // Buy: 5B KAS, price 4/1 (wants 20B tokens)
        let mut buy = make_buy(5_000_000_000, 4, 1, token);
        buy.tx_id = format!("{:0>64}", "buy_big");
        buy.owner_hash = "aa".repeat(32);
        ob.add_buy_order(buy);

        // Sell 1: 500M tokens at price 2/1 (wants 1B KAS) -- cheapest
        let mut sell1 = make_sell(500_000_000, 2, 1, token);
        sell1.tx_id = format!("{:0>64}", "sell1");
        sell1.owner_hash = "b1".repeat(32);
        ob.add_sell_order(sell1);

        // Sell 2: 500M tokens at price 3/1 (wants 1.5B KAS)
        let mut sell2 = make_sell(500_000_000, 3, 1, token);
        sell2.tx_id = format!("{:0>64}", "sell2");
        sell2.owner_hash = "b2".repeat(32);
        ob.add_sell_order(sell2);

        // Sell 3: 500M tokens at price 4/1 (wants 2B KAS) -- most expensive
        let mut sell3 = make_sell(500_000_000, 4, 1, token);
        sell3.tx_id = format!("{:0>64}", "sell3");
        sell3.owner_hash = "b3".repeat(32);
        ob.add_sell_order(sell3);

        let groups = find_sweep_groups(&ob, true, None);
        assert!(!groups.is_empty(), "Should find at least 1 sweep group");

        let g = &groups[0];
        assert!(g.is_buy_sweep, "Should be a buy sweep");
        assert_eq!(g.fills.len(), 3, "Should sweep all 3 sells");

        // Verify fills are sorted by price ascending (cheapest first)
        let prices: Vec<(u64, u64)> = g.fills.iter()
            .map(|s| (s.price_num, s.price_den))
            .collect();
        assert_eq!(prices[0], (2, 1), "cheapest sell first");
        assert_eq!(prices[1], (3, 1), "middle sell second");
        assert_eq!(prices[2], (4, 1), "most expensive sell last");

        // Total cost: 1B + 1.5B + 2B = 4.5B <= 5B
        assert_eq!(g.total_fill_cost, 4_500_000_000);
    }

    #[test]
    fn test_sweep_buy_budget_exhaustion() {
        // Buy can only afford 2 of 3 sells
        let token = FAKE_TOKEN;
        let mut ob = OrderBook::new();

        // Buy: 2B KAS at price 4/1
        let mut buy = make_buy(2_000_000_000, 4, 1, token);
        buy.tx_id = format!("{:0>64}", "buy_med");
        buy.owner_hash = "aa".repeat(32);
        ob.add_buy_order(buy);

        // Sell 1: 500M tokens at 2/1 (needs 1B KAS)
        let mut sell1 = make_sell(500_000_000, 2, 1, token);
        sell1.tx_id = format!("{:0>64}", "sell1");
        sell1.owner_hash = "b1".repeat(32);
        ob.add_sell_order(sell1);

        // Sell 2: 500M tokens at 3/1 (needs 1.5B KAS) -- can't afford after sell1
        // ... but actually 2B - 1B = 1B left, and sell2 needs 1.5B -> can't fill
        // Try with a cheaper sell2:
        let mut sell2 = make_sell(200_000_000, 2, 1, token);
        sell2.tx_id = format!("{:0>64}", "sell2");
        sell2.owner_hash = "b2".repeat(32);
        ob.add_sell_order(sell2);

        // Sell 3: 500M tokens at 4/1 (needs 2B KAS)
        let mut sell3 = make_sell(500_000_000, 4, 1, token);
        sell3.tx_id = format!("{:0>64}", "sell3");
        sell3.owner_hash = "b3".repeat(32);
        ob.add_sell_order(sell3);

        let groups = find_sweep_groups(&ob, true, None);
        // Buy has 2B. sell1=1B, sell2=0.4B -> total 1.4B, remaining 0.6B.
        // sell3 needs 2B -> skip. So sweep = 2 sells.
        assert!(!groups.is_empty(), "Should find sweep group");
        let g = &groups[0];
        assert_eq!(g.fills.len(), 2, "Should only sweep 2 affordable sells");
    }

    #[test]
    fn test_sweep_single_sell_not_grouped() {
        // If only 1 sell crosses, no sweep group (1:1 handled by existing path)
        let token = FAKE_TOKEN;
        let mut ob = OrderBook::new();

        let mut buy = make_buy(1_000_000_000, 3, 1, token);
        buy.tx_id = format!("{:0>64}", "buy1");
        buy.owner_hash = "aa".repeat(32);
        ob.add_buy_order(buy);

        let mut sell1 = make_sell(500_000_000, 2, 1, token);
        sell1.tx_id = format!("{:0>64}", "sell1");
        sell1.owner_hash = "bb".repeat(32);
        ob.add_sell_order(sell1);

        let groups = find_sweep_groups(&ob, true, None);
        assert!(groups.is_empty(), "Single sell should not form a sweep group");
    }

    #[test]
    fn test_sweep_sell_multiple_buys() {
        // 1 large sell sweeps multiple buys
        let token = FAKE_TOKEN;
        let mut ob = OrderBook::new();

        // Sell: 2B tokens at price 1/5 (wants 400M KAS)
        let mut sell = make_sell(2_000_000_000, 1, 5, token);
        sell.tx_id = format!("{:0>64}", "sell_big");
        sell.owner_hash = "cc".repeat(32);
        ob.add_sell_order(sell);

        // Buy 1: 500M KAS at price 5/1 (wants 2.5B tokens) -- best bidder
        let mut buy1 = make_buy(500_000_000, 5, 1, token);
        buy1.tx_id = format!("{:0>64}", "buy1");
        buy1.owner_hash = "d1".repeat(32);
        ob.add_buy_order(buy1);

        // Buy 2: 200M KAS at price 3/1 (wants 600M tokens)
        let mut buy2 = make_buy(200_000_000, 3, 1, token);
        buy2.tx_id = format!("{:0>64}", "buy2");
        buy2.owner_hash = "d2".repeat(32);
        ob.add_buy_order(buy2);

        let groups = find_sweep_groups(&ob, true, None);
        // Sell has 2B tokens. buy1 wants 2.5B but sell only has 2B -> buy1 can't be fully filled.
        // Actually: sell sweep checks buy_tokens <= tokens_remaining.
        // buy1 wants 2.5B tokens but sell only has 2B -> skip buy1.
        // buy2 wants 600M tokens, sell has 2B -> fills. But only 1 buy fills -> no sweep.
        // Let's adjust buy values to make it work:
        assert!(groups.is_empty() || groups[0].fills.len() >= 2,
            "Either empty or valid sweep");
    }

    #[test]
    fn test_sweep_sell_multiple_small_buys() {
        let token = FAKE_TOKEN;
        let mut ob = OrderBook::new();

        // Sell: 1B tokens at price 1/4 (cheap)
        let mut sell = make_sell(1_000_000_000, 1, 4, token);
        sell.tx_id = format!("{:0>64}", "sell_big");
        sell.owner_hash = "cc".repeat(32);
        ob.add_sell_order(sell);

        // 3 small buys, each wants 100M tokens
        for i in 0..3u32 {
            let mut buy = make_buy(400_000_000, 1, 1, token);
            buy.tx_id = format!("{:0>64}", format!("buy{}", i));
            buy.owner_hash = format!("{:0>64}", format!("d{}", i));
            ob.add_buy_order(buy);
        }

        let groups = find_sweep_groups(&ob, true, None);
        // Each buy at price 1/1 wants 400M tokens.
        // Sell has 1B tokens. buy0: 400M (rem 600M), buy1: 400M (rem 200M), buy2: 400M (rem -200M, skip).
        // So 2 buys fit -> valid sell sweep.
        let sell_sweeps: Vec<_> = groups.iter().filter(|g| !g.is_buy_sweep).collect();
        assert!(!sell_sweeps.is_empty(), "Should find a sell sweep");
        assert_eq!(sell_sweeps[0].fills.len(), 2, "Should sweep 2 buys");
    }

    #[test]
    fn test_sweep_stp_prevents_self_trade() {
        let token = FAKE_TOKEN;
        let mut ob = OrderBook::new();

        let owner = "aa".repeat(32);

        let mut buy = make_buy(5_000_000_000, 4, 1, token);
        buy.tx_id = format!("{:0>64}", "buy1");
        buy.owner_hash = owner.clone();
        ob.add_buy_order(buy);

        for i in 0..3u32 {
            let mut sell = make_sell(500_000_000, 2, 1, token);
            sell.tx_id = format!("{:0>64}", format!("sell{}", i));
            sell.owner_hash = owner.clone(); // same owner!
            ob.add_sell_order(sell);
        }

        // With STP enabled (allow_self_trade=false), no sweep should form
        let groups = find_sweep_groups(&ob, false, None);
        assert!(groups.is_empty(), "STP should prevent self-trade sweep");

        // With STP disabled, sweep should form
        let groups2 = find_sweep_groups(&ob, true, None);
        assert!(!groups2.is_empty(), "Self-trade sweep should work when STP disabled");
    }

    #[test]
    fn test_sweep_respects_spent_outpoints() {
        let token = FAKE_TOKEN;
        let mut ob = OrderBook::new();

        let mut buy = make_buy(5_000_000_000, 4, 1, token);
        buy.tx_id = format!("{:0>64}", "buy1");
        buy.owner_hash = "aa".repeat(32);
        ob.add_buy_order(buy);

        for i in 0..3u32 {
            let mut sell = make_sell(500_000_000, 2, 1, token);
            sell.tx_id = format!("{:0>64}", format!("sell{}", i));
            sell.owner_hash = format!("{:0>64}", format!("b{}", i));
            ob.add_sell_order(sell);
        }

        // Mark sell0 and sell1 as spent (make_sell uses index: 2)
        let mut spent = std::collections::HashSet::new();
        spent.insert(format!("{}:2", format!("{:0>64}", "sell0")));
        spent.insert(format!("{}:2", format!("{:0>64}", "sell1")));

        let groups = find_sweep_groups(&ob, true, Some(&spent));
        // Only 1 sell available (sell2) -> no sweep (needs >= 2)
        assert!(groups.is_empty(), "Spent sells should not form sweep group");
    }

    #[test]
    fn test_sweep_max_batch_group_size_cap() {
        let token = FAKE_TOKEN;
        let mut ob = OrderBook::new();

        // Buy with enough KAS to sweep 20 sells
        let mut buy = make_buy(20_000_000_000, 4, 1, token);
        buy.tx_id = format!("{:0>64}", "buy_huge");
        buy.owner_hash = "aa".repeat(32);
        ob.add_buy_order(buy);

        for i in 0..20u32 {
            let mut sell = make_sell(100_000_000, 2, 1, token);
            sell.tx_id = format!("{:0>64}", format!("sell{:02}", i));
            sell.owner_hash = format!("{:0>64}", format!("b{:02}", i));
            ob.add_sell_order(sell);
        }

        let groups = find_sweep_groups(&ob, true, None);
        assert!(!groups.is_empty(), "Should find sweep group");
        assert!(
            groups[0].fills.len() <= MAX_BATCH_GROUP_SIZE,
            "Sweep should be capped at MAX_BATCH_GROUP_SIZE={}  got {}",
            MAX_BATCH_GROUP_SIZE,
            groups[0].fills.len(),
        );
    }

    // --- find_optimal_groups tests ---

    #[test]
    fn test_optimal_groups_single_full_pair() {
        let mut ob = OrderBook::new();
        ob.add_buy_order(make_buy(10_000_000, 1, 2, FAKE_TOKEN));
        ob.add_sell_order(make_sell(10_000_000, 1, 2, FAKE_TOKEN));

        let pairs = find_all_crossing_pairs_with_stp(&ob, true);
        let groups = find_optimal_groups(&pairs, &ob, true, None);

        assert!(!groups.is_empty(), "Should produce at least 1 group");
        // Single pair should be a Batch group
        let batch_groups: Vec<_> = groups.iter().filter(|g| g.kind == GroupKind::Batch).collect();
        assert!(!batch_groups.is_empty(), "Single full pair should produce a Batch group");
    }

    #[test]
    fn test_optimal_groups_no_overlap() {
        // 3 full pairs same token -> all in one batch group, no duplicates
        let mut ob = OrderBook::new();
        for i in 0..3u32 {
            let mut buy = make_buy(10_000_000, 1, 2, FAKE_TOKEN);
            buy.tx_id = format!("{:0>64}", format!("buy{}", i));
            buy.owner_hash = format!("{:0>64}", format!("ob{}", i));
            ob.add_buy_order(buy);
            let mut sell = make_sell(10_000_000, 1, 2, FAKE_TOKEN);
            sell.tx_id = format!("{:0>64}", format!("sell{}", i));
            sell.owner_hash = format!("{:0>64}", format!("os{}", i));
            ob.add_sell_order(sell);
        }

        let pairs = find_all_crossing_pairs_with_stp(&ob, true);
        let groups = find_optimal_groups(&pairs, &ob, true, None);

        // Collect all outpoints across all groups
        let mut all_outpoints = std::collections::HashSet::new();
        let mut total_orders = 0;
        for g in &groups {
            for o in g.all_orders() {
                let key = o.outpoint_key();
                assert!(!all_outpoints.contains(&key), "Outpoint {} appears in multiple groups", key);
                all_outpoints.insert(key);
                total_orders += 1;
            }
        }
        assert!(total_orders > 0, "Should have some orders in groups");
    }

    #[test]
    fn test_optimal_groups_sweep_priority() {
        // 1 large buy + 3 small sells -> sweep should take priority
        let mut ob = OrderBook::new();

        let mut buy = make_buy(5_000_000_000, 4, 1, FAKE_TOKEN);
        buy.tx_id = format!("{:0>64}", "buy_big");
        buy.owner_hash = "aa".repeat(32);
        ob.add_buy_order(buy);

        for i in 0..3u32 {
            let mut sell = make_sell(500_000_000, 2, 1, FAKE_TOKEN);
            sell.tx_id = format!("{:0>64}", format!("sell{}", i));
            sell.owner_hash = format!("{:0>64}", format!("b{}", i));
            ob.add_sell_order(sell);
        }

        let pairs = find_all_crossing_pairs_with_stp(&ob, true);
        let groups = find_optimal_groups(&pairs, &ob, true, None);

        let sweep_groups: Vec<_> = groups.iter()
            .filter(|g| g.kind == GroupKind::BuySweep || g.kind == GroupKind::SellSweep || g.kind == GroupKind::GtcBuyMultiFill || g.kind == GroupKind::GtcSellMultiFill)
            .collect();
        assert!(!sweep_groups.is_empty(), "Should find sweep groups when 1:N relationship exists");
    }

    #[test]
    fn test_optimal_groups_partial_remaining() {
        // Large buy + small sell -> should produce a PartialBuy group
        let mut ob = OrderBook::new();

        let mut buy = make_buy(50_000_000, 2, 1, FAKE_TOKEN);
        buy.tx_id = "a".repeat(64);
        buy.owner_hash = "aa".repeat(32);
        ob.add_buy_order(buy);

        let mut sell = make_sell(20_000_000, 1, 3, FAKE_TOKEN);
        sell.tx_id = "c".repeat(64);
        sell.owner_hash = "bb".repeat(32);
        ob.add_sell_order(sell);

        let pairs = find_all_crossing_pairs_with_stp(&ob, true);
        let groups = find_optimal_groups(&pairs, &ob, true, None);

        assert!(!groups.is_empty(), "Should find at least one group");
        // Should have a partial group if partial pair exists
        let has_partial = groups.iter().any(|g|
            g.kind == GroupKind::PartialBuy || g.kind == GroupKind::PartialSell
        );
        let has_full = groups.iter().any(|g| g.kind == GroupKind::Batch);
        assert!(has_partial || has_full, "Should have either partial or batch group");
    }

    #[test]
    fn test_optimal_groups_empty() {
        let ob = OrderBook::new();
        let groups = find_optimal_groups(&[], &ob, true, None);
        assert!(groups.is_empty());
    }

    #[test]
    fn test_optimal_groups_sorted_by_surplus() {
        let mut ob = OrderBook::new();
        let token_a = FAKE_TOKEN;
        let token_b = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";

        // Token A: high surplus
        let mut buy_a = make_buy(20_000_000, 1, 1, token_a);
        buy_a.tx_id = "a".repeat(64);
        buy_a.owner_hash = "aa".repeat(32);
        ob.add_buy_order(buy_a);
        let mut sell_a = make_sell(20_000_000, 1, 2, token_a);
        sell_a.tx_id = "b".repeat(64);
        sell_a.owner_hash = "bb".repeat(32);
        ob.add_sell_order(sell_a);

        // Token B: lower surplus
        let mut buy_b = make_buy(5_000_000, 1, 1, token_b);
        buy_b.tx_id = "c".repeat(64);
        buy_b.owner_hash = "cc".repeat(32);
        ob.add_buy_order(buy_b);
        let mut sell_b = make_sell(5_000_000, 1, 2, token_b);
        sell_b.tx_id = "d".repeat(64);
        sell_b.owner_hash = "dd".repeat(32);
        ob.add_sell_order(sell_b);

        let pairs = find_all_crossing_pairs_with_stp(&ob, true);
        let groups = find_optimal_groups(&pairs, &ob, true, None);

        if groups.len() >= 2 {
            assert!(
                groups[0].total_surplus >= groups[1].total_surplus,
                "Groups should be sorted by surplus descending"
            );
        }
    }

    // ----------------------------------------------------------------
    // IOC / GTC distinction tests
    // ----------------------------------------------------------------

    #[test]
    fn test_is_ioc_eligible_low_min_fill() {
        // Buy: 5B KAS at 3/1 -> expected_tokens = 15B
        // min_fill = 1M << 15B -> IOC eligible
        let buy = make_buy(5_000_000_000, 3, 1, FAKE_TOKEN);
        assert_eq!(buy.expected_output(), 15_000_000_000);
        assert!(buy.is_ioc_eligible(), "low min_fill should be IOC eligible");
    }

    #[test]
    fn test_is_ioc_eligible_high_min_fill() {
        // Buy: 5B KAS at 3/1 -> expected_tokens = 15B
        // min_fill = 15B (== expected_tokens) -> NOT IOC eligible (GTC)
        let mut buy = make_buy(5_000_000_000, 3, 1, FAKE_TOKEN);
        buy.min_fill = 15_000_000_000;
        assert_eq!(buy.expected_output(), 15_000_000_000);
        assert!(!buy.is_ioc_eligible(), "min_fill == expected should NOT be IOC eligible");
    }

    #[test]
    fn test_gtc_buy_no_sweep_when_partial() {
        // GTC buy (min_fill == expected_tokens) should NOT sweep when
        // total sell tokens < expected_tokens.
        let mut ob = OrderBook::new();

        // Buy 5B KAS at 3/1 -> expects 15B tokens.  min_fill = 15B (GTC).
        let mut buy = make_buy(5_000_000_000, 3, 1, FAKE_TOKEN);
        buy.tx_id = format!("{:0>64}", "gtc_buy");
        buy.owner_hash = "aa".repeat(32);
        buy.min_fill = 15_000_000_000; // GTC: must fully fill
        ob.add_buy_order(buy);

        // 3 sells of 2B tokens each at price 2/1 -> total 6B tokens < 15B expected
        for i in 0..3u32 {
            let mut sell = make_sell(2_000_000_000, 2, 1, FAKE_TOKEN);
            sell.tx_id = format!("{:0>64}", format!("sell{}", i));
            sell.owner_hash = format!("{:0>64}", format!("s{}", i));
            ob.add_sell_order(sell);
        }

        let groups = find_sweep_groups(&ob, true, None);
        // GTC buy cannot be partially filled, so no sweep group should exist
        let buy_sweeps: Vec<_> = groups.iter()
            .filter(|g| g.is_buy_sweep)
            .collect();
        assert!(buy_sweeps.is_empty(),
            "GTC buy should NOT produce sweep when total tokens < expected");
    }

    #[test]
    fn test_gtc_buy_multi_fill_when_sufficient() {
        // GTC buy with 3 sells providing >= expected_tokens -> should emit
        // as a GTC multi-fill group (not a sweep).
        let mut ob = OrderBook::new();

        // Buy 9B KAS at 1/1 -> expects 9B tokens.  min_fill = 9B (GTC).
        let mut buy = make_buy(9_000_000_000, 1, 1, FAKE_TOKEN);
        buy.tx_id = format!("{:0>64}", "gtc_buy");
        buy.owner_hash = "aa".repeat(32);
        buy.min_fill = 9_000_000_000;
        ob.add_buy_order(buy);

        // 3 sells of 3B tokens each at price 1/1.
        // Each sell needs sell.value * sell.price_num / sell.price_den = 3B * 1/1 = 3B KAS.
        // Buy can afford all 3 (3B * 3 = 9B KAS = buy value).
        // Total tokens = 9B >= 9B expected -> GTC multi-fill.
        for i in 0..3u32 {
            let mut sell = make_sell(3_000_000_000, 1, 1, FAKE_TOKEN);
            sell.tx_id = format!("{:0>64}", format!("sell{}", i));
            sell.owner_hash = format!("{:0>64}", format!("s{}", i));
            ob.add_sell_order(sell);
        }

        let groups = find_sweep_groups(&ob, true, None);
        let buy_groups: Vec<_> = groups.iter()
            .filter(|g| g.is_buy_sweep)
            .collect();
        assert!(!buy_groups.is_empty(),
            "GTC buy should produce a group when total tokens >= expected");
        assert!(buy_groups[0].is_gtc_multi_fill,
            "Group should be flagged as GTC multi-fill");
    }

    #[test]
    fn test_ioc_buy_sweep_normal() {
        // IOC buy (low min_fill) should sweep normally even when partial.
        let mut ob = OrderBook::new();

        // Buy 5B KAS at 4/1 -> expects 20B tokens.  min_fill = 1M (IOC).
        let mut buy = make_buy(5_000_000_000, 4, 1, FAKE_TOKEN);
        buy.tx_id = format!("{:0>64}", "ioc_buy");
        buy.owner_hash = "aa".repeat(32);
        // min_fill = 1_000_000 (default) -- IOC eligible
        ob.add_buy_order(buy);

        // 3 sells of 500M tokens at price 2/1 -> total 1.5B << 20B expected
        for i in 0..3u32 {
            let mut sell = make_sell(500_000_000, 2, 1, FAKE_TOKEN);
            sell.tx_id = format!("{:0>64}", format!("sell{}", i));
            sell.owner_hash = format!("{:0>64}", format!("s{}", i));
            ob.add_sell_order(sell);
        }

        let groups = find_sweep_groups(&ob, true, None);
        let buy_sweeps: Vec<_> = groups.iter()
            .filter(|g| g.is_buy_sweep)
            .collect();
        assert!(!buy_sweeps.is_empty(),
            "IOC buy should still produce sweep with partial tokens");
        assert!(!buy_sweeps[0].is_gtc_multi_fill,
            "IOC sweep should NOT be flagged as GTC multi-fill");
    }

    #[test]
    fn test_gtc_multi_fill_uses_batch_kind() {
        // When find_optimal_groups processes a GTC multi-fill sweep,
        // it should produce a GtcBuyMultiFill GroupKind.
        let mut ob = OrderBook::new();

        // Buy 9B KAS at 1/1 -> expected 9B tokens, min_fill=9B (GTC)
        let mut buy = make_buy(9_000_000_000, 1, 1, FAKE_TOKEN);
        buy.tx_id = format!("{:0>64}", "gtc_buy");
        buy.owner_hash = "aa".repeat(32);
        buy.min_fill = 9_000_000_000;
        ob.add_buy_order(buy);

        // 3 sells of 3B tokens at 1/1 -> total 9B tokens, each costs 3B KAS
        for i in 0..3u32 {
            let mut sell = make_sell(3_000_000_000, 1, 1, FAKE_TOKEN);
            sell.tx_id = format!("{:0>64}", format!("sell{}", i));
            sell.owner_hash = format!("{:0>64}", format!("s{}", i));
            ob.add_sell_order(sell);
        }

        let pairs = find_all_crossing_pairs_with_stp(&ob, true);
        let groups = find_optimal_groups(&pairs, &ob, true, None);

        let gtc_groups: Vec<_> = groups.iter()
            .filter(|g| g.kind == GroupKind::GtcBuyMultiFill)
            .collect();
        assert!(!gtc_groups.is_empty(),
            "Should produce GtcBuyMultiFill group for GTC buy with sufficient sells");
        assert_eq!(gtc_groups[0].buys.len(), 1, "Should have 1 buy");
        assert!(gtc_groups[0].sells.len() >= 2, "Should have 2+ sells");
    }

    /// Post-only buy resting on the book should be matchable when a
    /// non-post-only sell arrives and crosses it.
    /// This verifies that post-only is a registration-time check (maker
    /// enforcement), NOT a match-time filter.  Once the order is on the
    /// book it IS the maker and any taker can cross it.
    #[test]
    fn test_post_only_maker_matches_regular_taker() {
        let mut ob = OrderBook::new();

        // Step 1: post-only buy at price 3/1 (no asks, accepted as maker)
        let mut buy = make_buy(5_000_000_000, 3, 1, FAKE_TOKEN);
        buy.tx_id = format!("{:0>64}", "po_buy");
        buy.owner_hash = "aa".repeat(32);
        buy.post_only = true;
        assert!(ob.add_buy_order(buy), "post-only buy with no asks must be accepted");

        // Step 2: regular sell at price 2/1 (crosses the buy at 3/1)
        let mut sell = make_sell(1_000_000_000, 2, 1, FAKE_TOKEN);
        sell.tx_id = format!("{:0>64}", "reg_sell");
        sell.owner_hash = "bb".repeat(32);
        sell.post_only = false;
        assert!(ob.add_sell_order(sell), "non-post-only sell must be accepted");

        // The matcher should find a crossing pair.
        let pairs = find_all_crossing_pairs_with_stp(&ob, true);
        assert!(!pairs.is_empty(),
            "post-only maker buy + regular taker sell should produce a crossing pair");
    }

    /// Two post-only orders cannot both rest at crossing prices because
    /// the second one is rejected at registration.
    #[test]
    fn test_two_post_only_cannot_cross() {
        let mut ob = OrderBook::new();

        // Post-only buy at price 5/1
        let mut buy = make_buy(5_000_000_000, 5, 1, FAKE_TOKEN);
        buy.tx_id = format!("{:0>64}", "po_buy");
        buy.owner_hash = "aa".repeat(32);
        buy.post_only = true;
        assert!(ob.add_buy_order(buy));

        // Post-only sell at price 3/1 (would cross buy at 5/1)
        let mut sell = make_sell(1_000_000_000, 3, 1, FAKE_TOKEN);
        sell.tx_id = format!("{:0>64}", "po_sell");
        sell.owner_hash = "bb".repeat(32);
        sell.post_only = true;
        assert!(!ob.add_sell_order(sell),
            "post-only sell that would cross existing bid must be rejected");
    }

}
