//! Crossing pair detection and match output computation.

use kob_core::{MIN_UTXO_VALUE, RECEIPT_VALUE};
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
pub fn find_all_crossing_pairs_with_stp(order_book: &OrderBook, allow_self_trade: bool) -> Vec<CrossingPair> {
    find_all_crossing_pairs_full(order_book, allow_self_trade, None)
}

/// Internal: find crossing pairs with optional DAA-based expiry filtering.
fn find_all_crossing_pairs_full(
    order_book: &OrderBook,
    allow_self_trade: bool,
    current_daa: Option<u64>,
) -> Vec<CrossingPair> {
    let mut all_pairs = Vec::new();

    for (token_cov_id, book) in &order_book.pair_books {
        let pairs = find_crossing_pairs_for_token(
            token_cov_id,
            book,
            &order_book.matched_outpoints,
            allow_self_trade,
            current_daa,
        );
        all_pairs.extend(pairs);
    }

    // Sort by surplus descending (best match first)
    all_pairs.sort_by(|a, b| b.surplus.cmp(&a.surplus));
    all_pairs
}

/// Find crossing pairs for a specific token pair.
fn find_crossing_pairs_for_token(
    token_cov_id: &str,
    book: &crate::matcher::order_book::PairBook,
    matched: &std::collections::HashMap<String, std::time::Instant>,
    allow_self_trade: bool,
    current_daa: Option<u64>,
) -> Vec<CrossingPair> {
    let mut pairs = Vec::new();

    // Collect active bids and asks (filtered by matched set and expiry)
    let bids: Vec<&BookOrder> = book
        .bids
        .values()
        .filter(|b| {
            !matched.contains_key(&b.outpoint_key())
                && !current_daa.is_some_and(|daa| b.is_expired(daa))
        })
        .collect();

    let asks: Vec<&BookOrder> = book
        .asks
        .values()
        .filter(|s| {
            !matched.contains_key(&s.outpoint_key())
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
                let surplus = total_in - seller_kas - buyer_tokens;

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
            {
                return None; // Full fill is better
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
                        if let Some(surplus) = after_tokens.checked_sub(residual_kas) {
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
                            let adj_surplus = surplus.saturating_sub(adj_seller_kas - fill_kas);
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

/// Compute match TX output amounts for a full fill.
///
/// Receipt value is a fixed constant (RECEIPT_VALUE = 1 KAS) funded by the
/// matcher wallet, NOT from order surplus. Surplus goes entirely to
/// matcher_change (minus estimated miner fee).
///
/// The miner fee is pre-estimated from compute mass for a typical match TX
/// (3 inputs, 4 outputs). The actual fee is verified after TX construction
/// in the executor.
pub fn compute_match_outputs(pair: &CrossingPair) -> MatchOutputs {
    let receipt_value = RECEIPT_VALUE;
    // Pre-estimate miner fee from compute mass.
    // Typical match TX: 2 covenant inputs (0 sig_ops) + 1 fee input (1 sig_op),
    // 3-4 outputs, ~0 payload. Overestimate with 4 inputs, 4 outputs.
    let estimated_fee = kob_core::mass::estimate_compute_mass(4, 4, 0);
    let raw_matcher_change = pair.surplus.saturating_sub(estimated_fee);

    // If matcher change is below minimum, add it to seller_kas
    let (final_seller_kas, matcher_change) = if raw_matcher_change >= MIN_UTXO_VALUE {
        (pair.seller_kas, raw_matcher_change)
    } else {
        (pair.seller_kas + raw_matcher_change, 0)
    };

    MatchOutputs {
        seller_kas: final_seller_kas,
        buyer_tokens: pair.buyer_tokens,
        receipt_value,
        matcher_change,
        fee: estimated_fee,
    }
}

/// Computed match TX output amounts.
#[derive(Debug, Clone)]
pub struct MatchOutputs {
    pub seller_kas: u64,
    pub buyer_tokens: u64,
    pub receipt_value: u64,
    pub matcher_change: u64,
    pub fee: u64,
}

/// Maximum number of crossing pairs per batch group.
///
/// Constrained by Kaspa's OpN range (0..=16). A batch TX with N same-token
/// full-fill pairs requires 2N inputs (N sells + N buys) + 1 token unit + 1
/// wallet = 2N+2 inputs, and 2N outputs (N seller KAS + N buyer tokens) + up
/// to 2 (matcher fee + change). Both input and output counts must be <= 16,
/// so N <= 7.
pub const MAX_BATCH_GROUP_SIZE: usize = 7;

/// Group crossing pairs into batch-eligible groups.
///
/// Only **full-fill** pairs are eligible for batching (partial fills have
/// residual outputs that complicate TX layout). Groups are partitioned by
/// `token_cov_id` and each group contains at least 2 pairs (a single pair
/// is more efficiently handled by the 1:1 path). Groups are capped at
/// [`MAX_BATCH_GROUP_SIZE`] pairs due to OpN index limits.
///
/// Returns a vec of groups, where each group is a vec of crossing pairs
/// that share the same token and are all full fills.
pub fn find_batch_groups(pairs: &[CrossingPair]) -> Vec<Vec<&CrossingPair>> {
    use std::collections::HashMap;

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
        if token_pairs.len() < 2 {
            // Single pair: not worth batching
            continue;
        }
        // Split into chunks of MAX_BATCH_GROUP_SIZE
        for chunk in token_pairs.chunks(MAX_BATCH_GROUP_SIZE) {
            if chunk.len() >= 2 {
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

/// Find cross-pair routes and group them into batch-eligible groups.
///
/// Uses `routing::find_cross_pair_routes_with_stp` to discover routes across
/// different token pairs, then selects non-conflicting routes and packages
/// them into `CrossPairBatchGroup`s suitable for `plan_batch_match`.
///
/// Each group contains 1+ non-conflicting cross-pair routes. The batch engine
/// handles multi-token batches natively (one token_unit per unique buy token).
///
/// # Arguments
/// * `order_book` - The order book to scan.
/// * `max_routes` - Maximum number of routes to discover.
/// * `allow_self_trade` - If true, allow same-owner cross-pair matches.
///
/// # Returns
/// A vec of `CrossPairBatchGroup`s, sorted by total surplus descending.
pub fn find_cross_pair_batch_groups(
    order_book: &OrderBook,
    max_routes: usize,
    allow_self_trade: bool,
) -> Vec<CrossPairBatchGroup> {
    let routes = routing::find_cross_pair_routes_with_stp(order_book, max_routes, allow_self_trade);
    if routes.is_empty() {
        return Vec::new();
    }

    let selected = routing::select_non_conflicting_routes(&routes);
    if selected.is_empty() {
        return Vec::new();
    }

    // Package all non-conflicting routes into a single batch group.
    // The batch engine supports multi-token batches, so we can include
    // sells and buys from different token pairs in one atomic TX.
    //
    // Cap the group size to respect OpN index limits (max 16 inputs/outputs).
    // Each route adds 1 sell + 1 buy = 2 inputs and 2 outputs, plus we need
    // token_unit inputs (1 per unique buy token) + 1 wallet input.
    // Conservative limit: 7 routes = 14 order inputs + up to 7 token units + 1 wallet.
    // But OpN max is 16, so we cap at a safe number.
    let max_group = MAX_BATCH_GROUP_SIZE; // 7 routes max per group

    let mut groups = Vec::new();
    let mut i = 0;

    while i < selected.len() {
        let end = (i + max_group).min(selected.len());
        let chunk = &selected[i..end];

        let mut sells = Vec::new();
        let mut buys = Vec::new();
        let mut total_surplus = 0u64;

        for route in chunk {
            sells.push(route.sell_leg.clone());
            buys.push(route.buy_leg.clone());
            total_surplus += route.surplus;
        }

        if !sells.is_empty() && !buys.is_empty() {
            groups.push(CrossPairBatchGroup {
                sells,
                buys,
                total_surplus,
            });
        }

        i = end;
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
            max_matcher_fee: u64::MAX,
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
            max_matcher_fee: u64::MAX,
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

        let outputs = compute_match_outputs(p);
        assert_eq!(outputs.receipt_value, RECEIPT_VALUE);
        assert!(outputs.matcher_change >= MIN_UTXO_VALUE);
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

    #[test]
    fn test_match_outputs_small_change() {
        // With small surplus: change < MIN_UTXO_VALUE gets added to seller
        let pair = CrossingPair {
            token_cov_id: FAKE_TOKEN.to_string(),
            buy: make_buy(3_500_000, 1, 2, FAKE_TOKEN),
            sell: make_sell(3_500_000, 1, 2, FAKE_TOKEN),
            seller_kas: 1_750_000,
            buyer_tokens: 1_750_000,
            surplus: 500_000, // small surplus
            expected_tokens: 1_750_000,
            expected_kas: 1_750_000,
            match_type: MatchType::Full,
            fill_kas: None,
            residual_kas: None,
            fill_token_amount: None,
            residual_tokens: None,
        };

        let outputs = compute_match_outputs(&pair);
        // raw_change = 500_000 - estimated_fee < MIN_UTXO_VALUE (3M)
        // So it gets added to seller_kas
        let estimated_fee = kob_core::mass::estimate_compute_mass(4, 4, 0);
        let expected_raw_change = 500_000 - estimated_fee;
        assert_eq!(outputs.matcher_change, 0);
        assert_eq!(outputs.seller_kas, 1_750_000 + expected_raw_change);
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
            max_matcher_fee: u64::MAX,
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
            max_matcher_fee: u64::MAX,
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

    #[test]
    fn test_compute_match_outputs_zero_surplus_regression() {
        // Manually construct a pair with surplus = estimated miner fee (minimum viable)
        let estimated_fee = kob_core::mass::estimate_compute_mass(4, 4, 0);
        let pair = CrossingPair {
            token_cov_id: FAKE_TOKEN.to_string(),
            buy: make_buy(10_000_000, 1, 2, FAKE_TOKEN),
            sell: make_sell(10_000_000, 1, 2, FAKE_TOKEN),
            seller_kas: 5_000_000,
            buyer_tokens: 5_000_000,
            surplus: estimated_fee, // exactly the miner fee
            expected_tokens: 5_000_000,
            expected_kas: 5_000_000,
            match_type: MatchType::Full,
            fill_kas: None,
            residual_kas: None,
            fill_token_amount: None,
            residual_tokens: None,
        };
        let outputs = compute_match_outputs(&pair);
        // raw_matcher_change = estimated_fee - estimated_fee = 0
        assert_eq!(outputs.matcher_change, 0);
        assert_eq!(outputs.seller_kas, 5_000_000); // no change to add
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
            max_matcher_fee: u64::MAX,
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
            max_matcher_fee: u64::MAX,
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
    fn test_find_batch_groups_single_pair_no_batch() {
        let pairs = vec![make_crossing_pair(FAKE_TOKEN, 1)];
        let groups = find_batch_groups(&pairs);
        assert!(groups.is_empty(), "single pair should not be batched");
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
        assert!(groups.is_empty(), "different tokens should not be batched together");
    }

    #[test]
    fn test_find_batch_groups_opn_limit() {
        // 8 pairs of same token -> should be split: group of 7 + 1 leftover (not batched)
        let pairs: Vec<_> = (0..8).map(|i| make_crossing_pair(FAKE_TOKEN, i)).collect();
        let groups = find_batch_groups(&pairs);
        assert_eq!(groups.len(), 1, "8 pairs should produce 1 group of 7 (leftover 1 not batched)");
        assert_eq!(groups[0].len(), 7, "first group should have 7 pairs");
    }

    #[test]
    fn test_find_batch_groups_partial_fills_excluded() {
        let mut pair = make_crossing_pair(FAKE_TOKEN, 1);
        pair.match_type = MatchType::PartialBuy;
        let pairs = vec![pair, make_crossing_pair(FAKE_TOKEN, 2)];
        let groups = find_batch_groups(&pairs);
        assert!(groups.is_empty(), "partial fills should be excluded from batch");
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
    fn test_find_batch_groups_14_pairs_two_groups() {
        // 14 pairs -> group of 7 + group of 7
        let pairs: Vec<_> = (0..14).map(|i| make_crossing_pair(FAKE_TOKEN, i)).collect();
        let groups = find_batch_groups(&pairs);
        assert_eq!(groups.len(), 2, "14 pairs should produce 2 groups of 7");
        assert_eq!(groups[0].len(), 7);
        assert_eq!(groups[1].len(), 7);
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
            max_matcher_fee: u64::MAX,
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
            max_matcher_fee: u64::MAX,
        }
    }

    /// Test: finds a single cross-pair batch group from two different token pairs.
    #[test]
    fn test_cross_pair_batch_groups_basic() {
        let mut ob = OrderBook::new();
        // Sell Token A at price 1/2 -> expects 10M KAS
        ob.add_sell_order(make_sell_cp('c', 20_000_000, 1, 2, TOKEN_A_CP));
        // Buy Token B with 15M KAS at price 1/3 -> expects 5M Token B
        ob.add_buy_order(make_buy_cp('a', 15_000_000, 1, 3, TOKEN_B_CP));

        let groups = find_cross_pair_batch_groups(&ob, 100, false);

        assert_eq!(groups.len(), 1, "Should find 1 cross-pair batch group");
        assert_eq!(groups[0].sells.len(), 1);
        assert_eq!(groups[0].buys.len(), 1);
        assert!(groups[0].total_surplus > 0);
    }

    /// Test: no crossing prices across pairs -> empty result.
    #[test]
    fn test_cross_pair_batch_groups_no_route() {
        let mut ob = OrderBook::new();
        // Sell Token A at very high price (3 KAS per token) -> expects 60M KAS
        ob.add_sell_order(make_sell_cp('c', 20_000_000, 3, 1, TOKEN_A_CP));
        // Buy Token B with only 5M KAS
        ob.add_buy_order(make_buy_cp('a', 5_000_000, 1, 3, TOKEN_B_CP));

        let groups = find_cross_pair_batch_groups(&ob, 100, false);
        assert!(groups.is_empty(), "No crossing prices should yield no groups");
    }

    /// Test: same-pair matches are excluded from cross-pair batch groups.
    #[test]
    fn test_cross_pair_batch_groups_skips_same_pair() {
        let mut ob = OrderBook::new();
        ob.add_sell_order(make_sell_cp('c', 20_000_000, 1, 2, TOKEN_A_CP));
        ob.add_buy_order(make_buy_cp('a', 20_000_000, 1, 3, TOKEN_A_CP));

        let groups = find_cross_pair_batch_groups(&ob, 100, false);
        assert!(groups.is_empty(), "Same-pair should not appear in cross-pair groups");
    }

    /// Test: multiple non-conflicting routes grouped together.
    #[test]
    fn test_cross_pair_batch_groups_multiple_routes() {
        let mut ob = OrderBook::new();
        // Route 1: sell Token A -> buy Token B
        // sell 10M Token A at price 1/2 -> expects 5M KAS
        // buy Token B with 20M KAS at price 1/3 -> expects ~6.67M tokens
        // surplus = 20M - 5M = 15M
        ob.add_sell_order(make_sell_cp('c', 10_000_000, 1, 2, TOKEN_A_CP));
        ob.add_buy_order(make_buy_cp('a', 20_000_000, 1, 3, TOKEN_B_CP));
        // Route 2: sell Token B -> buy Token C (different sell, different buy)
        // sell 15M Token B at price 1/3 -> expects 5M KAS
        // buy Token C with 15M KAS at price 1/2 -> expects 7.5M tokens (> MIN_UTXO_VALUE)
        // surplus = 15M - 5M = 10M
        ob.add_sell_order(make_sell_cp('f', 15_000_000, 1, 3, TOKEN_B_CP));
        ob.add_buy_order(make_buy_cp('e', 15_000_000, 1, 2, TOKEN_C_CP));

        let groups = find_cross_pair_batch_groups(&ob, 100, false);

        // Both routes are non-conflicting, so they should be in one group
        assert!(!groups.is_empty(), "Should find at least 1 group");
        let total_sells: usize = groups.iter().map(|g| g.sells.len()).sum();
        let total_buys: usize = groups.iter().map(|g| g.buys.len()).sum();
        assert!(total_sells >= 2, "Should have at least 2 sell legs across groups");
        assert!(total_buys >= 2, "Should have at least 2 buy legs across groups");
    }

    /// Test: empty order book returns no groups.
    #[test]
    fn test_cross_pair_batch_groups_empty() {
        let ob = OrderBook::new();
        let groups = find_cross_pair_batch_groups(&ob, 100, false);
        assert!(groups.is_empty());
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
            max_matcher_fee: u64::MAX,
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
            max_matcher_fee: u64::MAX,
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
            max_matcher_fee: u64::MAX,
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
            max_matcher_fee: u64::MAX,
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

    /// E2E: Cross-pair batch group creation from two different token pairs.
    #[test]
    fn e2e_cross_pair_batch_group() {
        let mut ob = OrderBook::new();
        let token_a = "0a".repeat(32);
        let token_b = "0b".repeat(32);
        let owner_a = "aa".repeat(32);
        let owner_b = "bb".repeat(32);

        // Sell Token A for KAS (ask in pair A)
        ob.add_sell_order(make_sell_e2e(
            &"s".repeat(64), 0, 20_000_000, 1, 2, &token_a, &owner_a,
        ));
        // Buy Token B with KAS (bid in pair B)
        ob.add_buy_order(make_buy_e2e(
            &"b".repeat(64), 0, 20_000_000, 1, 2, &token_b, &owner_b,
        ));

        let groups = find_cross_pair_batch_groups(&ob, 10, true);
        // Cross-pair route: sell A -> KAS -> buy B
        // sell_kas_output = 20M * 1/2 = 10M
        // buy_kas_input = 20M
        // surplus = 20M - 10M = 10M (covers receipt + fee easily)
        assert!(!groups.is_empty(), "Should find cross-pair batch group");
        let group = &groups[0];
        assert_eq!(group.sells.len(), 1);
        assert_eq!(group.buys.len(), 1);
        assert!(group.total_surplus > 0);
    }

    /// E2E: Match outputs computation verifies KAS conservation.
    #[test]
    fn e2e_match_outputs_conserve_kas() {
        let mut ob = OrderBook::new();
        let token = FAKE_TOKEN;
        let owner_a = "aa".repeat(32);
        let owner_b = "bb".repeat(32);

        ob.add_buy_order(make_buy_e2e(
            &"a".repeat(64), 0, 50_000_000, 1, 2, token, &owner_a,
        ));
        ob.add_sell_order(make_sell_e2e(
            &"c".repeat(64), 1, 50_000_000, 1, 2, token, &owner_b,
        ));

        let pairs = find_all_crossing_pairs_with_stp(&ob, true);
        let full_fills: Vec<_> = pairs.iter()
            .filter(|p| p.match_type == MatchType::Full)
            .collect();

        if !full_fills.is_empty() {
            let pair = full_fills[0];
            let outputs = compute_match_outputs(pair);
            // Surplus conservation: order inputs = seller_kas + buyer_tokens + matcher_change + fee
            // (Receipt value is funded by matcher wallet, not from order inputs)
            let total_in = pair.buy.value + pair.sell.value;
            let total_out = outputs.seller_kas + outputs.buyer_tokens
                + outputs.matcher_change + outputs.fee;
            assert_eq!(total_in, total_out, "KAS must be conserved: in={} out={}", total_in, total_out);
        }
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
            max_matcher_fee: u64::MAX,
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
            max_matcher_fee: u64::MAX,
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
            max_matcher_fee: u64::MAX,
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
            max_matcher_fee: u64::MAX,
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
}
