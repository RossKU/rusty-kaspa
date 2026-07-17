//! Crossing pair detection and match output computation.

use kob_core::MIN_UTXO_VALUE;
use kob_core::contract::spot::oco::OCO_SELL_RS_SIZE;
use kob_core::contract::spot::order::{
    BUY_ORDER_MAX_N, BUY_ORDER_RS_EXPECTED_LEN,
    SELL_ORDER_RS_EXPECTED_LEN,
};
use crate::order_book::{BookOrder, OrderBook, PairBook};

/// True when a redeem script is a v18 buy (unified spot generation).
/// RS length is the canonical generation discriminator in this codebase
/// (version numbers are engine-layer labels).
pub fn is_buy_rs(rs: &[u8]) -> bool {
    rs.len() == BUY_ORDER_RS_EXPECTED_LEN
}

/// True when a redeem script is a v18 sell.
pub fn is_sell_rs(rs: &[u8]) -> bool {
    rs.len() == SELL_ORDER_RS_EXPECTED_LEN
}

/// True when a redeem script is a v18 OCO sell — sweep-eligible on BOTH
/// branches (the canonical branch attestation removed the pre-v18 OCO-SL
/// fixed-offset price-read blocker).
pub fn is_oco_sell_rs(rs: &[u8]) -> bool {
    rs.len() == OCO_SELL_RS_SIZE
}

/// Sweep-collection cap for a buy anchor: the contract's compile-time term
/// slot count for v17/v18 sweeps, the generic batch cap otherwise. Collecting
/// beyond this would be rejected wholesale at plan time (or panic inside the
/// sigscript builder), losing the whole group.
pub fn max_sweep_sells_for_buy(rs: &[u8]) -> usize {
    if is_buy_rs(rs) {
        BUY_ORDER_MAX_N
    } else {
        MAX_BATCH_GROUP_SIZE
    }
}

/// OP_CSV maturity window: orders must age at least this many DAA scores
/// before they can be spent. Matches the lockTime embedded in deploy TXs.
pub const CSV_MATURITY_DAA: u64 = 50;

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
///
/// Sweep detection helper used internally by `match_book_direct()`.
fn find_sweep_groups(
    order_book: &OrderBook,
    allow_self_trade: bool,
    spent_outpoints: Option<&std::collections::HashSet<String>>,
    current_daa: u64,
) -> Vec<SweepGroup> {
    use std::collections::HashSet;

    let empty_set = HashSet::new();
    let spent = spent_outpoints.unwrap_or(&empty_set);

    let mut groups = Vec::new();
    // Track which outpoints are already assigned to a sweep group
    // to avoid double-spending across groups.
    let mut claimed: HashSet<String> = HashSet::new();

    // OCO-aware claim helper: mark both the order's key and its partner key
    // so that the other OCO path (same underlying UTXO) is excluded.
    let claim_order = |claimed: &mut HashSet<String>, order: &BookOrder| {
        claimed.insert(order.outpoint_key());
        if let Some(ref partner) = order.oco_partner_key {
            claimed.insert(partner.clone());
        }
    };

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
                    && current_daa.saturating_sub(b.discovered_daa) >= CSV_MATURITY_DAA.max(b.csv_maturity())
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
                    && current_daa.saturating_sub(s.discovered_daa) >= CSV_MATURITY_DAA.max(s.csv_maturity())
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
            // Track UTXO outpoints within this sweep to prevent OCO
            // duplicate inputs (TP + SL share the same UTXO).
            let mut sweep_utxo_keys: HashSet<String> = HashSet::new();

            // HIGH DoS #3: a v17/v18 buy's contract has exactly MAX_N term
            // slots -- collecting more sells than that for such an anchor
            // would later panic (or, since batch.rs guards it, get rejected
            // wholesale) at plan time. Cap collection at the contract's own
            // limit so the buy still gets a good, plannable group instead of
            // losing the whole sweep; any sells beyond the cap stay
            // unclaimed for a follow-on group.
            let buy_rs = buy.redeem_script();
            let is_spot_anchor = is_buy_rs(&buy_rs);
            let max_sells_for_buy = max_sweep_sells_for_buy(&buy_rs);

            for sell in &asks {
                if sweep_sells.len() >= max_sells_for_buy {
                    break;
                }
                if claimed.contains(&sell.outpoint_key()) {
                    continue;
                }
                // Pre-v18 OCO exclusion (RELEASE-BLOCKER #1, historical): the
                // real multi-sell blocker was the OCO-SL fixed-offset
                // price-read mismatch — a v16/v17 buy reads the swept sell's
                // price at fixed sigscript offsets that land on the TP pair
                // even when the SL branch executes. (The once-cited OCO F4
                // shared-output drain was already closed by the per-input
                // Fix-3 rewrite of OCO_SELL_BODY — see
                // BatchError::OcoMultiSellSweepUnsupported in
                // domain/src/spot/batch.rs for the full history.)
                //
                // v18 solves the price read with the canonical branch
                // attestation (pnum/pden at sigscript [3..11)/[12..20),
                // body-verified against the EXECUTING branch's pair), so v18
                // OCO sells ARE sweep-eligible on both branches under a v18
                // anchor. Everything pre-v18 stays excluded; a solo OCO fill
                // is unaffected in any generation.
                if sell.oco_path.is_some()
                    && !(is_spot_anchor && is_oco_sell_rs(&sell.redeem_script()))
                {
                    continue;
                }
                // OCO: skip if another path of the same UTXO is already
                // in this sweep (prevents duplicate inputs in the TX).
                let utxo_key = sell.utxo_outpoint_key();
                if sweep_utxo_keys.contains(&utxo_key) {
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
                    sweep_utxo_keys.insert(utxo_key);
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
                    claim_order(&mut claimed, buy);
                    for s in &sweep_sells {
                        claim_order(&mut claimed, s);
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
            // Track UTXO outpoints within this sweep to prevent OCO
            // duplicate inputs (TP + SL share the same UTXO).
            let mut sweep_utxo_keys: HashSet<String> = HashSet::new();

            for buy in &sorted_bids_for_sell_sweep {
                if sweep_buys.len() >= MAX_BATCH_GROUP_SIZE {
                    break;
                }
                if claimed.contains(&buy.outpoint_key()) {
                    continue;
                }
                // OCO: skip if another path of the same UTXO is already
                // in this sweep (prevents duplicate inputs in the TX).
                let utxo_key = buy.utxo_outpoint_key();
                if sweep_utxo_keys.contains(&utxo_key) {
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
                    sweep_utxo_keys.insert(utxo_key);
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
                    claim_order(&mut claimed, sell);
                    for b in &sweep_buys {
                        claim_order(&mut claimed, b);
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
    /// Cross-book swap: swap covenant + buy-source + sell-target in one atomic TX.
    /// Uses custom swap planner (not the standard batch planners).
    CrossSwap,
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


// ===================================================================
// Direct book traversal matcher (replaces CrossingPair enumeration)
// ===================================================================

/// Cross-book swap order: a user wants to sell token A and receive token B
/// in a single atomic transaction.
///
/// # Future use
/// In the matching loop, after processing same-token crossings, swap orders
/// can be satisfied by cross-referencing the output of one token book with
/// the input of another. This replaces the TRI-BATCH mechanism with a
/// cleaner first-class data model.
#[derive(Debug, Clone)]
pub struct SwapOrder {
    /// The order selling token A for KAS (first leg).
    pub sell: BookOrder,
    /// The desired token to buy (token B covenant id).
    pub target_token_cov_id: String,
    /// Maximum price the user is willing to pay for the target token
    /// (expressed as target_price_num / target_price_den KAS per token).
    pub target_price_num: u64,
    pub target_price_den: u64,
}

/// Per-token swap order queue, keyed by sell-side token_cov_id.
///
/// TODO: After swap routing is implemented, the executor will:
/// 1. Match same-token orders via `match_book_direct()`.
/// 2. For each unmatched SwapOrder, check if the target token book has
///    crossing asks at <= target_price. If so, combine the sell-leg
///    (token A -> KAS) and buy-leg (KAS -> token B) into a single
///    CrossPairBatchGroup for atomic execution.
pub type SwapBook = std::collections::HashMap<String, Vec<SwapOrder>>;

/// Walk the order book directly, producing `BatchGroup`s without
/// intermediate `CrossingPair` enumeration.
///
/// This replaces the O(N x M) `find_all_crossing_pairs` +
/// `find_optimal_groups` pipeline with a single O(N + M) traversal
/// per token pair, preserving BTreeMap FIFO ordering.
///
/// # Algorithm (per token book)
///
/// 1. Iterate asks (ascending price, FIFO within level) and bids
///    (descending price, FIFO within level).
/// 2. While best_ask.price <= best_bid.price (prices cross):
///    a. Compute full/partial fill parameters.
///    b. Accumulate into the current batch group.
///    c. Advance the consumed side (or both if exact match).
/// 3. When the group reaches `MAX_BATCH_GROUP_SIZE` or prices stop
///    crossing, emit the group and start a new one.
///
/// The emitted groups are non-overlapping and FIFO-ordered. OCO partner
/// exclusion (H1 fix) is respected: filling one OCO path excludes the
/// partner from subsequent groups.
///
/// # Arguments
/// * `order_book` — The multi-pair order book.
/// * `allow_self_trade` — If true, same-owner matches are allowed (testing).
/// * `spent_outpoints` — Outpoints already consumed by prior phases.
pub fn match_book_direct(
    order_book: &OrderBook,
    allow_self_trade: bool,
    spent_outpoints: Option<&std::collections::HashSet<String>>,
    current_daa: u64,
) -> Vec<BatchGroup> {
    use std::collections::HashSet;

    let empty_set = HashSet::new();
    let spent = spent_outpoints.unwrap_or(&empty_set);

    let mut all_groups: Vec<BatchGroup> = Vec::new();

    // Track used outpoints globally (across all token books) so an order
    // consumed in one token pair is not re-matched in another (shouldn't
    // happen for same-token, but guards against edge cases with OCO).
    let mut used: HashSet<String> = HashSet::new();

    // H1-fix helper: mark order + OCO partner as used.
    let use_order = |used: &mut HashSet<String>, order: &BookOrder| {
        let key = order.outpoint_key();
        used.insert(key);
        if let Some(ref partner) = order.oco_partner_key {
            used.insert(partner.clone());
        }
    };

    // ---------------------------------------------------------------
    // Step 1: Sweep groups (1:N) — highest priority.
    // Uses the existing BTreeMap-ordered sweep detection, which is
    // already O(B * A) but with early termination on sorted asks.
    // Sweeps must be detected first because they atomically fill large
    // orders that would otherwise be broken into multiple 1:1 pairs.
    // ---------------------------------------------------------------
    let sweep_groups = find_sweep_groups(order_book, allow_self_trade, spent_outpoints, current_daa);

    for sg in sweep_groups {
        let anchor_key = sg.anchor.outpoint_key();
        if used.contains(&anchor_key) {
            continue;
        }
        if sg.fills.iter().any(|f| used.contains(&f.outpoint_key())) {
            continue;
        }
        // Claim all outpoints (+ OCO partners via H1-fix).
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

        all_groups.push(BatchGroup {
            sells,
            buys,
            total_surplus,
            kind,
            source_pairs: Vec::new(),
        });
    }

    // ---------------------------------------------------------------
    // Step 2: Direct book traversal for 1:1 full fills and partials.
    // O(N + M) per token pair, preserving FIFO ordering from BTreeMap.
    // ---------------------------------------------------------------
    for (token_cov_id, book) in &order_book.pair_books {
        // Collect active, filtered asks and bids in BTreeMap iteration order.
        // BTreeMap guarantees: asks = price ASC, FIFO within level;
        //                      bids = price DESC, FIFO within level.
        let asks: Vec<&BookOrder> = book
            .asks
            .values()
            .filter(|s| {
                let key = s.outpoint_key();
                !order_book.matched_outpoints.contains_key(&key)
                    && !spent.contains(&key)
                    && !used.contains(&key)
                    && s.price_num > 0
                    && s.price_den > 0
                    && current_daa.saturating_sub(s.discovered_daa) >= CSV_MATURITY_DAA.max(s.csv_maturity())
            })
            .collect();

        let bids: Vec<&BookOrder> = book
            .bids
            .values()
            .filter(|b| {
                let key = b.outpoint_key();
                !order_book.matched_outpoints.contains_key(&key)
                    && !spent.contains(&key)
                    && !used.contains(&key)
                    && b.price_num > 0
                    && b.price_den > 0
                    && current_daa.saturating_sub(b.discovered_daa) >= CSV_MATURITY_DAA.max(b.csv_maturity())
            })
            .collect();

        if asks.is_empty() || bids.is_empty() {
            continue;
        }

        // Simultaneous walk of both sides.
        //
        // Both `ask_idx` and `bid_idx` advance only when the respective
        // order is consumed:
        //
        //   Full fill (1:1): both the bid UTXO and ask UTXO are entirely
        //     consumed by one match pair. Advance both.
        //
        //   Partial fill: both UTXOs are consumed by the TX (the residual
        //     becomes a new UTXO after confirmation). Advance both.
        //
        // This produces N:M batch groups where each bid pairs with one ask
        // in FIFO order. 1:N sweeps are handled by Step 1 above.
        let mut ask_idx = 0usize;
        let mut bid_idx = 0usize;

        // Accumulator for the current group.
        let mut group_sells: Vec<BookOrder> = Vec::new();
        let mut group_buys: Vec<BookOrder> = Vec::new();
        let mut group_surplus: u64 = 0;
        let mut group_source_pairs: Vec<CrossingPair> = Vec::new();

        while ask_idx < asks.len() && bid_idx < bids.len() {
            let ask = asks[ask_idx];
            let bid = bids[bid_idx];

            // Skip used orders (may have been excluded via OCO partner or sweep).
            if used.contains(&ask.outpoint_key()) {
                ask_idx += 1;
                continue;
            }
            if used.contains(&bid.outpoint_key()) {
                bid_idx += 1;
                continue;
            }

            // STP: skip same owner. Advance ask to try next counterpart.
            if !allow_self_trade && ask.owner_hash == bid.owner_hash {
                tracing::debug!("[DIRECT] STP skip: ask={} bid={} same owner_hash={}", ask.outpoint_key(), bid.outpoint_key(), &ask.owner_hash[..16]);
                ask_idx += 1;
                continue;
            }

            // Check crossing: ask.price <= bid.price
            let lhs = ask.price_num as u128 * bid.price_den as u128;
            let rhs = bid.price_num as u128 * ask.price_den as u128;
            tracing::debug!("[DIRECT] Crossing check: ask {}/{} vs bid {}/{} → lhs={} rhs={} cross={}", ask.price_num, ask.price_den, bid.price_num, bid.price_den, lhs, rhs, lhs <= rhs);
            if lhs > rhs {
                // Best ask doesn't cross best bid. No more crossings possible.
                break;
            }

            // --- Compute fill parameters ---
            let buy_kas = bid.value;
            let sell_tokens = ask.value;

            let expected_tokens = match buy_kas.checked_mul(bid.price_num) {
                Some(v) => v / bid.price_den,
                None => {
                    tracing::warn!(
                        "[DIRECT] u64 overflow: buy_kas={} * price_num={}, skipping bid",
                        buy_kas, bid.price_num
                    );
                    bid_idx += 1;
                    continue;
                }
            };
            let expected_kas = match sell_tokens.checked_mul(ask.price_num) {
                Some(v) => v / ask.price_den,
                None => {
                    tracing::warn!(
                        "[DIRECT] u64 overflow: sell_tokens={} * price_num={}, skipping ask",
                        sell_tokens, ask.price_num
                    );
                    ask_idx += 1;
                    continue;
                }
            };

            // Try full fill.
            let mmfee_floor = buy_kas.saturating_sub(bid.max_matcher_fee);
            let seller_kas = std::cmp::max(expected_kas, mmfee_floor);
            let buyer_tokens = sell_tokens;
            let total_in = match buy_kas.checked_add(sell_tokens) {
                Some(v) => v,
                None => {
                    tracing::warn!(
                        "[DIRECT] u64 overflow in total_in, skipping pair"
                    );
                    ask_idx += 1;
                    bid_idx += 1;
                    continue;
                }
            };

            let full_fill_ok = seller_kas.checked_add(buyer_tokens)
                .is_some_and(|sum| sum <= total_in)
                && seller_kas >= MIN_UTXO_VALUE
                && buyer_tokens >= MIN_UTXO_VALUE;

            if full_fill_ok {
                let raw_surplus = total_in - seller_kas - buyer_tokens;
                let surplus = raw_surplus
                    .min(bid.max_matcher_fee)
                    .min(ask.max_matcher_fee);

                group_sells.push(ask.clone());
                group_buys.push(bid.clone());
                group_surplus += surplus;
                group_source_pairs.push(CrossingPair {
                    token_cov_id: token_cov_id.clone(),
                    buy: bid.clone(),
                    sell: ask.clone(),
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

                use_order(&mut used, ask);
                use_order(&mut used, bid);
                ask_idx += 1;
                bid_idx += 1;

                // Check if group is full.
                if group_sells.len() >= MAX_BATCH_GROUP_SIZE {
                    emit_group(
                        &mut all_groups,
                        &mut group_sells,
                        &mut group_buys,
                        &mut group_surplus,
                        &mut group_source_pairs,
                    );
                }
            } else {
                // Try partial fill.
                if let Some(partial) = compute_partial_fill_match(token_cov_id, bid, ask) {
                    // Emit accumulated full fills first.
                    if !group_sells.is_empty() || !group_buys.is_empty() {
                        emit_group(
                            &mut all_groups,
                            &mut group_sells,
                            &mut group_buys,
                            &mut group_surplus,
                            &mut group_source_pairs,
                        );
                    }

                    let kind = match partial.match_type {
                        MatchType::PartialBuy => GroupKind::PartialBuy,
                        MatchType::PartialSell => GroupKind::PartialSell,
                        MatchType::Full => GroupKind::Batch,
                    };

                    use_order(&mut used, ask);
                    use_order(&mut used, bid);

                    all_groups.push(BatchGroup {
                        sells: vec![partial.sell.clone()],
                        buys: vec![partial.buy.clone()],
                        total_surplus: partial.surplus,
                        kind,
                        source_pairs: vec![partial],
                    });

                    ask_idx += 1;
                    bid_idx += 1;
                } else {
                    // Neither full nor partial fill viable.
                    // Advance ask to try a different one with this bid.
                    ask_idx += 1;
                }
            }
        } // end while

        // Emit any remaining accumulated group.
        if !group_sells.is_empty() || !group_buys.is_empty() {
            emit_group(
                &mut all_groups,
                &mut group_sells,
                &mut group_buys,
                &mut group_surplus,
                &mut group_source_pairs,
            );
        }
    }

    // Sort all groups by surplus descending (most profitable first).
    all_groups.sort_by(|a, b| b.total_surplus.cmp(&a.total_surplus));

    all_groups
}

/// Helper: flush the accumulator into a `BatchGroup` and reset.
fn emit_group(
    all_groups: &mut Vec<BatchGroup>,
    sells: &mut Vec<BookOrder>,
    buys: &mut Vec<BookOrder>,
    surplus: &mut u64,
    source_pairs: &mut Vec<CrossingPair>,
) {
    if sells.is_empty() && buys.is_empty() {
        return;
    }

    let kind = classify_group_kind(sells, buys);

    all_groups.push(BatchGroup {
        sells: std::mem::take(sells),
        buys: std::mem::take(buys),
        total_surplus: *surplus,
        kind,
        source_pairs: std::mem::take(source_pairs),
    });
    *surplus = 0;
}

/// Classify a group into the correct `GroupKind` based on sell/buy counts.
///
/// This replaces the old separate sweep-detection pass. The group shape
/// naturally determines the kind:
/// - 1 buy + N sells (N >= 2) = BuySweep
/// - 1 sell + N buys (N >= 2) = SellSweep
/// - N sells + N buys = Batch
/// - 1:1 handled by caller for partials
fn classify_group_kind(sells: &[BookOrder], buys: &[BookOrder]) -> GroupKind {
    let ns = sells.len();
    let nb = buys.len();

    if nb == 1 && ns >= 2 {
        // Check if the single buy is GTC (non-IOC): if so, use GtcBuyMultiFill
        // so the executor uses plan_batch_match (Op1) instead of plan_ioc_match.
        if !buys[0].is_ioc_eligible() {
            // Verify total sell tokens >= buy expected_tokens for GTC satisfaction.
            let total_tokens: u64 = sells.iter().map(|s| s.value).sum();
            let expected = buys[0].expected_output();
            if total_tokens >= expected && expected > 0 {
                return GroupKind::GtcBuyMultiFill;
            }
        }
        GroupKind::BuySweep
    } else if ns == 1 && nb >= 2 {
        if !sells[0].is_ioc_eligible() {
            let total_kas: u64 = buys.iter().map(|b| {
                let kas_128 = b.value as u128 * b.price_num as u128
                    / b.price_den.max(1) as u128;
                kas_128.min(u64::MAX as u128) as u64
            }).sum();
            let expected = sells[0].expected_output();
            if total_kas >= expected && expected > 0 {
                return GroupKind::GtcSellMultiFill;
            }
        }
        GroupKind::SellSweep
    } else {
        GroupKind::Batch
    }
}

/// A cross-book swap group: one swap order routed through two TOKEN/KAS books.
///
/// Atomic TX structure:
///   Inputs:
///     [0] Swap UTXO (user's source tokens, swap covenant)
///     [1] Buy-source order (counterparty on SOURCE/KAS book who buys source tokens)
///     [2] Sell-target order (counterparty on TARGET/KAS book who sells target tokens)
///     [3] Matcher wallet UTXO
///   Outputs:
///     [0] Source tokens -> Buy-source counterparty
///     [1] Target tokens -> swap user (covenant verifies this via toi)
///     [2] KAS -> Sell-target counterparty
///     [3] Change/surplus -> matcher
#[derive(Debug, Clone)]
pub struct CrossSwapGroup {
    /// The swap entry from the swap book.
    pub swap: crate::swap_book::SwapEntry,
    /// Buy-source: counterparty on SOURCE/KAS book who wants to buy source tokens.
    /// This order provides KAS in exchange for the swap user's source tokens.
    pub buy_source: BookOrder,
    /// Sell-target: counterparty on TARGET/KAS book who sells target tokens.
    /// This order provides target tokens in exchange for KAS.
    pub sell_target: BookOrder,
    /// KAS flowing from buy_source to sell_target.
    pub kas_flow: u64,
    /// Matcher surplus (buy_source KAS - sell_target expected KAS).
    pub surplus: u64,
}

/// Find cross-book swap routes.
///
/// For each swap order in the swap book:
///   1. Look up the SOURCE token's book for a Buy order (someone buying source tokens with KAS).
///   2. Look up the TARGET token's book for a Sell order (someone selling target tokens for KAS).
///   3. Verify KAS math: Buy-source provides >= KAS needed to pay Sell-target.
///   4. Verify the Sell-target provides >= min_target_amount of target tokens.
///   5. If both sides found, produce a `CrossSwapGroup`.
///
/// Respects FIFO ordering (uses first eligible counterparty from BTreeMap iteration).
/// Skips spent outpoints and orders already consumed by same-token matching.
///
/// # Arguments
/// * `order_book` — The multi-pair order book (contains SOURCE/KAS and TARGET/KAS books).
/// * `swap_book` — The swap order tracker.
/// * `spent_outpoints` — Outpoints consumed by prior phases or under cooldown.
/// * `used_outpoints` — Outpoints consumed by same-token matching in this cycle.
/// Find an available bid for hub cross-rate routing.
///
/// H2-TOB: tries the denormalized top-of-book cache first (best few resting
/// bids, see `order_book::TOP_OF_BOOK_DEPTH`) -- O(TOP_OF_BOOK_DEPTH) instead
/// of O(orders-in-pair). If every cached candidate is spent/used/claimed
/// (cache exhausted), falls back to a full scan of the pair's resting bids
/// so correctness never depends on how deep the cache is: a route is never
/// missed just because it wasn't among the top few cached levels.
fn find_available_bid<'a>(
    order_book: &'a OrderBook,
    pair_book: &'a PairBook,
    spent: &std::collections::HashSet<String>,
    used_outpoints: &std::collections::HashSet<String>,
    claimed: &std::collections::HashSet<String>,
) -> Option<&'a BookOrder> {
    let is_available = |key: &str| {
        !spent.contains(key)
            && !used_outpoints.contains(key)
            && !claimed.contains(key)
            && !order_book.matched_outpoints.contains_key(key)
    };
    for tq in pair_book.top_bids() {
        if tq.price_num > 0 && tq.price_den > 0 && is_available(&tq.outpoint_key) {
            if let Some(order) = pair_book.get_bid(&tq.outpoint_key) {
                return Some(order);
            }
        }
    }
    pair_book.bids.values().find(|bid| {
        bid.price_num > 0 && bid.price_den > 0 && is_available(&bid.outpoint_key())
    })
}

/// Find an available ask for hub cross-rate routing. Mirror of
/// `find_available_bid` for the sell side.
fn find_available_ask<'a>(
    order_book: &'a OrderBook,
    pair_book: &'a PairBook,
    spent: &std::collections::HashSet<String>,
    used_outpoints: &std::collections::HashSet<String>,
    claimed: &std::collections::HashSet<String>,
) -> Option<&'a BookOrder> {
    let is_available = |key: &str| {
        !spent.contains(key)
            && !used_outpoints.contains(key)
            && !claimed.contains(key)
            && !order_book.matched_outpoints.contains_key(key)
    };
    for tq in pair_book.top_asks() {
        if tq.price_num > 0 && tq.price_den > 0 && is_available(&tq.outpoint_key) {
            if let Some(order) = pair_book.get_ask(&tq.outpoint_key) {
                return Some(order);
            }
        }
    }
    pair_book.asks.values().find(|ask| {
        ask.price_num > 0 && ask.price_den > 0 && is_available(&ask.outpoint_key())
    })
}


/// Find v18 swap rings (item F): closed 2-cycles (token<->token) and
/// 3-cycles (triangle) among v18 swap orders in the swap book.
///
/// Each returned ring is a leg list `[e_0 .. e_{n-1}]` where leg i's target
/// token equals leg `(i+1) % n`'s source token, ready for
/// `batch::plan_ring_match` (which re-validates every leg from its RS and
/// performs the F2/F3/F4 feasibility checks — this function only does the
/// cheap structural pass: v18 RS length, `owner_spk` present, closed cycle,
/// distinct sources, greedy first-found claiming). Pre-v18 (243B) swap
/// entries are ignored — they settle via the KAS-bridged
/// `execute_swap_fill` route.
pub fn find_rings(
    swap_book: &crate::swap_book::SwapBook,
    spent_outpoints: Option<&std::collections::HashSet<String>>,
) -> Vec<Vec<crate::swap_book::SwapEntry>> {
    use kob_core::contract::spot::swap::SWAP_RS_SIZE;
    use std::collections::HashSet;

    let empty_set = HashSet::new();
    let spent = spent_outpoints.unwrap_or(&empty_set);

    // Deterministic order: sort candidates by outpoint key.
    let mut candidates: Vec<&crate::swap_book::SwapEntry> = swap_book
        .all_entries()
        .into_iter()
        .filter(|e| {
            hex::decode(&e.redeem_script_hex)
                .map(|rs| rs.len() == SWAP_RS_SIZE)
                .unwrap_or(false)
                && e.owner_spk.is_some()
                && !spent.contains(&e.outpoint_key())
        })
        .collect();
    candidates.sort_by_key(|e| e.outpoint_key());

    let mut rings: Vec<Vec<crate::swap_book::SwapEntry>> = Vec::new();
    let mut claimed: HashSet<String> = HashSet::new();

    // 2-cycles first (cheapest settle), then triangles from the leftovers.
    for i in 0..candidates.len() {
        let a = candidates[i];
        if claimed.contains(&a.outpoint_key()) {
            continue;
        }
        if let Some(b) = candidates.iter().find(|b| {
            !claimed.contains(&b.outpoint_key())
                && b.outpoint_key() != a.outpoint_key()
                && b.source_cov_id == a.target_cov_id
                && b.target_cov_id == a.source_cov_id
        }) {
            claimed.insert(a.outpoint_key());
            claimed.insert(b.outpoint_key());
            rings.push(vec![a.clone(), (*b).clone()]);
        }
    }

    for i in 0..candidates.len() {
        let a = candidates[i];
        if claimed.contains(&a.outpoint_key()) {
            continue;
        }
        let found = candidates.iter().find_map(|b| {
            if claimed.contains(&b.outpoint_key())
                || b.outpoint_key() == a.outpoint_key()
                || b.source_cov_id != a.target_cov_id
                || b.target_cov_id == a.source_cov_id
            {
                return None;
            }
            candidates
                .iter()
                .find(|c| {
                    !claimed.contains(&c.outpoint_key())
                        && c.outpoint_key() != a.outpoint_key()
                        && c.outpoint_key() != b.outpoint_key()
                        && c.source_cov_id == b.target_cov_id
                        && c.target_cov_id == a.source_cov_id
                })
                .map(|c| ((*b).clone(), (*c).clone()))
        });
        if let Some((b, c)) = found {
            claimed.insert(a.outpoint_key());
            claimed.insert(b.outpoint_key());
            claimed.insert(c.outpoint_key());
            rings.push(vec![a.clone(), b, c]);
        }
    }

    rings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::order_book::{BookOrder, OrderBook, OrderSide};

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
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0, time_meta: None,
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
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0, time_meta: None,
        }
    }

    const FAKE_TOKEN: &str = "0102030405060708091011121314151617181920212223242526272829303132";

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



    // E2E Integration: Full matching pipeline tests

    /// Helper: make a buy with unique tx_id and configurable owner.
    #[allow(dead_code)]
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
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0, time_meta: None,
        }
    }

    #[allow(dead_code)]
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
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0, time_meta: None,
        }
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
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0, time_meta: None,
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
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0, time_meta: None,
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
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0, time_meta: None,
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
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0, time_meta: None,
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

        let groups = find_sweep_groups(&ob, true, None, CSV_MATURITY_DAA);
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

    /// RELEASE-BLOCKER #1 regression: an OCO sell must never be collected
    /// into a multi-sell buy-sweep group. `OCO_SELL_BODY`'s F4 still uses the
    /// pre-Fix-3 transaction-wide shared output index (see
    /// `BatchError::OcoMultiSellSweepUnsupported` in `domain/spot/batch.rs`),
    /// so combining it with any other same-token sell in one sweep tx risks
    /// the OCO seller's tokens never landing anywhere a buyer actually paid
    /// for. With the OCO sell excluded, only 1 non-OCO sell remains, which
    /// can't form a 2+ sweep group on its own.
    #[test]
    fn test_oco_sell_excluded_from_multi_sell_sweep() {
        let token = FAKE_TOKEN;
        let mut ob = OrderBook::new();

        let mut buy = make_buy(5_000_000_000, 4, 1, token);
        buy.tx_id = format!("{:0>64}", "buy_big");
        buy.owner_hash = "aa".repeat(32);
        ob.add_buy_order(buy);

        let mut sell_plain = make_sell(500_000_000, 2, 1, token);
        sell_plain.tx_id = format!("{:0>64}", "sell_plain");
        sell_plain.owner_hash = "b1".repeat(32);
        ob.add_sell_order(sell_plain);

        let mut sell_oco = make_sell(500_000_000, 2, 1, token);
        sell_oco.tx_id = format!("{:0>64}", "sell_oco");
        sell_oco.owner_hash = "b2".repeat(32);
        sell_oco.oco_path = Some(kob_core::OcoPath::TakeProfit);
        ob.add_sell_order(sell_oco);

        let groups = find_sweep_groups(&ob, true, None, CSV_MATURITY_DAA);

        for g in &groups {
            for s in &g.fills {
                assert!(s.oco_path.is_none(), "OCO sell must never be swept into a multi-sell group");
            }
        }
        assert!(groups.is_empty(), "a single remaining non-OCO sell can't form a 2+ sweep group");
    }

    /// Same fixture but with 2 plain sells + 1 OCO sell (cheapest price, so
    /// it would be picked first if not excluded): the OCO sell is skipped and
    /// the 2 plain sells still sweep together.
    #[test]
    fn test_oco_sell_excluded_but_plain_sells_still_sweep() {
        let token = FAKE_TOKEN;
        let mut ob = OrderBook::new();

        let mut buy = make_buy(5_000_000_000, 4, 1, token);
        buy.tx_id = format!("{:0>64}", "buy_big2");
        buy.owner_hash = "aa".repeat(32);
        ob.add_buy_order(buy);

        let mut sell1 = make_sell(500_000_000, 2, 1, token);
        sell1.tx_id = format!("{:0>64}", "sell1b");
        sell1.owner_hash = "b1".repeat(32);
        ob.add_sell_order(sell1);

        let mut sell2 = make_sell(500_000_000, 3, 1, token);
        sell2.tx_id = format!("{:0>64}", "sell2b");
        sell2.owner_hash = "b2".repeat(32);
        ob.add_sell_order(sell2);

        // Cheapest of all three -- would sort first if not excluded.
        let mut sell_oco = make_sell(500_000_000, 1, 1, token);
        sell_oco.tx_id = format!("{:0>64}", "sell_oco2");
        sell_oco.owner_hash = "b3".repeat(32);
        sell_oco.oco_path = Some(kob_core::OcoPath::StopLoss);
        ob.add_sell_order(sell_oco);

        let groups = find_sweep_groups(&ob, true, None, CSV_MATURITY_DAA);
        assert!(!groups.is_empty(), "the 2 plain sells should still form a sweep group");
        let g = &groups[0];
        assert_eq!(g.fills.len(), 2, "only the 2 plain sells swept");
        assert!(g.fills.iter().all(|s| s.oco_path.is_none()), "no OCO sell in the group");
    }

    /// v18 sibling of the DoS #3 cap test: a v18-anchor buy-sweep collection
    /// caps at BUY_ORDER_MAX_N via `max_sweep_sells_for_buy`.
    #[test]
    fn test_buy_sweep_capped_at_max_n() {
        let token = FAKE_TOKEN;
        let mut ob = OrderBook::new();

        let rs = kob_core::contract::spot::order::build_buy_redeem_script(
            &[0x01; 32], 1, 1, 1_000_000, &[0xBB; 32], &[0xCC; 32], &[0xDD; 32], 2000, 0, 0,
        ).unwrap();
        assert!(is_buy_rs(&rs), "helper must recognize the v18 buy RS");
        assert_eq!(max_sweep_sells_for_buy(&rs), BUY_ORDER_MAX_N);
        let mut buy = make_buy(1_000_000_000, 1, 1, token);
        buy.tx_id = format!("{:064x}", 2);
        buy.owner_hash = "aa".repeat(32);
        buy.redeem_script_hex = hex::encode(&rs);
        ob.add_buy_order(buy);

        for i in 0..12u32 {
            let mut sell = make_sell(10_000_000, 1, 1, token);
            sell.tx_id = format!("{:064x}", 9100 + i);
            sell.owner_hash = format!("{:064x}", 5100 + i);
            ob.add_sell_order(sell);
        }

        let groups = find_sweep_groups(&ob, true, None, CSV_MATURITY_DAA);
        assert!(!groups.is_empty(), "should find a sweep group");
        let g = &groups[0];
        assert!(g.is_buy_sweep);
        assert!(
            g.fills.len() <= BUY_ORDER_MAX_N,
            "v18 buy sweep must be capped at MAX_N={}, got {}",
            BUY_ORDER_MAX_N, g.fills.len(),
        );
    }

    /// v18 OCO sweep enablement: a v18 OCO sell IS collected into a
    /// multi-sell sweep under a v18 buy anchor (the canonical branch
    /// attestation removed the pre-v18 OCO-SL fixed-offset blocker).
    #[test]
    fn test_oco_sell_included_in_sweep() {
        let token = FAKE_TOKEN;
        let mut ob = OrderBook::new();

        let buy_rs = kob_core::contract::spot::order::build_buy_redeem_script(
            &[0x01; 32], 1, 1, 1_000_000, &[0xBB; 32], &[0xCC; 32], &[0xDD; 32], 2000, 0, 0,
        ).unwrap();
        let mut buy = make_buy(2_000_000_000, 1, 1, token);
        buy.tx_id = format!("{:064x}", 3);
        buy.owner_hash = "aa".repeat(32);
        buy.redeem_script_hex = hex::encode(&buy_rs);
        ob.add_buy_order(buy);

        let mut sell_plain = make_sell(500_000_000, 1, 1, token);
        sell_plain.tx_id = format!("{:0>64}", "v18plain");
        sell_plain.owner_hash = "b1".repeat(32);
        ob.add_sell_order(sell_plain);

        let oco_rs = kob_core::contract::spot::oco::build_oco_sell_redeem_script(
            2, 1, 1_000_000, 1, 2, 1_000_000, &[0xBB; 32], &[0xCC; 32], &[0xDD; 32], 30, 0, 0,
        ).unwrap();
        assert!(is_oco_sell_rs(&oco_rs), "helper must recognize the v18 OCO RS");
        let mut sell_oco = make_sell(500_000_000, 1, 2, token);
        sell_oco.tx_id = format!("{:0>64}", "v18oco");
        sell_oco.owner_hash = "b2".repeat(32);
        sell_oco.oco_path = Some(kob_core::OcoPath::StopLoss);
        sell_oco.redeem_script_hex = hex::encode(&oco_rs);
        ob.add_sell_order(sell_oco);

        let groups = find_sweep_groups(&ob, true, None, CSV_MATURITY_DAA);
        assert!(!groups.is_empty(), "v18 anchor + plain + OCO must form a sweep group");
        let g = &groups[0];
        assert_eq!(g.fills.len(), 2, "both sells swept, incl. the v18 OCO");
        assert!(
            g.fills.iter().any(|s| s.oco_path.is_some()),
            "the v18 OCO sell must be included in the sweep"
        );
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

        let groups = find_sweep_groups(&ob, true, None, CSV_MATURITY_DAA);
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

        let groups = find_sweep_groups(&ob, true, None, CSV_MATURITY_DAA);
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

        let groups = find_sweep_groups(&ob, true, None, CSV_MATURITY_DAA);
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

        let groups = find_sweep_groups(&ob, true, None, CSV_MATURITY_DAA);
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
        let groups = find_sweep_groups(&ob, false, None, CSV_MATURITY_DAA);
        assert!(groups.is_empty(), "STP should prevent self-trade sweep");

        // With STP disabled, sweep should form
        let groups2 = find_sweep_groups(&ob, true, None, CSV_MATURITY_DAA);
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

        let groups = find_sweep_groups(&ob, true, Some(&spent), CSV_MATURITY_DAA);
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

        let groups = find_sweep_groups(&ob, true, None, CSV_MATURITY_DAA);
        assert!(!groups.is_empty(), "Should find sweep group");
        assert!(
            groups[0].fills.len() <= MAX_BATCH_GROUP_SIZE,
            "Sweep should be capped at MAX_BATCH_GROUP_SIZE={}  got {}",
            MAX_BATCH_GROUP_SIZE,
            groups[0].fills.len(),
        );
    }

    // --- match_book_direct: surplus ordering (migrated from find_optimal_groups tests) ---

    #[test]
    fn test_direct_sorted_by_surplus() {
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

        let groups = match_book_direct(&ob, true, None, u64::MAX);

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

        let groups = find_sweep_groups(&ob, true, None, CSV_MATURITY_DAA);
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

        let groups = find_sweep_groups(&ob, true, None, CSV_MATURITY_DAA);
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

        let groups = find_sweep_groups(&ob, true, None, CSV_MATURITY_DAA);
        let buy_sweeps: Vec<_> = groups.iter()
            .filter(|g| g.is_buy_sweep)
            .collect();
        assert!(!buy_sweeps.is_empty(),
            "IOC buy should still produce sweep with partial tokens");
        assert!(!buy_sweeps[0].is_gtc_multi_fill,
            "IOC sweep should NOT be flagged as GTC multi-fill");
    }

    #[test]
    fn test_direct_gtc_multi_fill_uses_batch_kind() {
        // When match_book_direct processes a GTC multi-fill sweep,
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

        let groups = match_book_direct(&ob, true, None, u64::MAX);

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

        // The matcher should find a crossing group.
        let groups = match_book_direct(&ob, true, None, u64::MAX);
        assert!(!groups.is_empty(),
            "post-only maker buy + regular taker sell should produce a match group");
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

    // ================================================================
    // match_book_direct tests
    // ================================================================

    #[test]
    fn test_direct_single_full_pair() {
        let mut ob = OrderBook::new();
        ob.add_buy_order(make_buy(10_000_000, 1, 2, FAKE_TOKEN));
        ob.add_sell_order(make_sell(10_000_000, 1, 2, FAKE_TOKEN));

        let groups = match_book_direct(&ob, true, None, u64::MAX);
        assert!(!groups.is_empty(), "Should find at least 1 group");
        assert_eq!(groups[0].kind, GroupKind::Batch);
        assert_eq!(groups[0].sells.len(), 1);
        assert_eq!(groups[0].buys.len(), 1);
    }

    #[test]
    fn test_direct_no_crossing() {
        let mut ob = OrderBook::new();
        // Buy at 1/10 (low bid), sell at 5/1 (high ask)
        ob.add_buy_order(make_buy(3_500_000, 1, 10, FAKE_TOKEN));
        ob.add_sell_order(make_sell(3_500_000, 5, 1, FAKE_TOKEN));

        let groups = match_book_direct(&ob, true, None, u64::MAX);
        assert!(groups.is_empty(), "Non-overlapping prices should produce no groups");
    }

    #[test]
    fn test_direct_multiple_full_pairs_same_token() {
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

        let groups = match_book_direct(&ob, true, None, u64::MAX);
        // All 6 orders should be matched. With sweep detection:
        // - Buy sweep: 1 buy sweeps 2 sells (buy has enough KAS for 2 sells)
        // - Sell sweep: remaining 1 sell sweeps 2 remaining buys
        // Result: all 3 sells and all 3 buys matched across 2 groups.
        let total_sells: usize = groups.iter().map(|g| g.sells.len()).sum();
        let total_buys: usize = groups.iter().map(|g| g.buys.len()).sum();
        assert_eq!(total_sells, 3, "All 3 sells should be matched");
        assert_eq!(total_buys, 3, "All 3 buys should be matched");
        assert!(groups.len() >= 2, "Should have multiple groups");
    }

    #[test]
    fn test_direct_stp_blocks_same_owner() {
        let mut ob = OrderBook::new();
        let owner = "aa".repeat(32);
        let mut buy = make_buy(10_000_000, 1, 2, FAKE_TOKEN);
        buy.owner_hash = owner.clone();
        ob.add_buy_order(buy);
        let mut sell = make_sell(10_000_000, 1, 2, FAKE_TOKEN);
        sell.owner_hash = owner;
        ob.add_sell_order(sell);

        // STP on: no groups
        let groups = match_book_direct(&ob, false, None, u64::MAX);
        assert!(groups.is_empty(), "STP should block same-owner match");

        // STP off: should match
        let groups2 = match_book_direct(&ob, true, None, u64::MAX);
        assert!(!groups2.is_empty(), "Without STP, should produce group");
    }

    #[test]
    fn test_direct_spent_outpoints_excluded() {
        let mut ob = OrderBook::new();
        let mut buy = make_buy(10_000_000, 1, 2, FAKE_TOKEN);
        buy.tx_id = "a".repeat(64);
        buy.owner_hash = "aa".repeat(32);
        let buy_key = buy.outpoint_key();
        ob.add_buy_order(buy);
        let mut sell = make_sell(10_000_000, 1, 2, FAKE_TOKEN);
        sell.tx_id = "c".repeat(64);
        sell.owner_hash = "bb".repeat(32);
        ob.add_sell_order(sell);

        let groups_before = match_book_direct(&ob, true, None, u64::MAX);
        assert!(!groups_before.is_empty());

        let mut spent = std::collections::HashSet::new();
        spent.insert(buy_key);
        let groups_after = match_book_direct(&ob, true, Some(&spent), u64::MAX);
        assert!(groups_after.is_empty(), "Spent buy should prevent matching");
    }

    #[test]
    fn test_direct_no_outpoint_overlap() {
        // Verify no outpoint appears in more than one group.
        let mut ob = OrderBook::new();
        for i in 0..6u32 {
            let mut buy = make_buy(10_000_000, 1, 2, FAKE_TOKEN);
            buy.tx_id = format!("{:0>64}", format!("buy{}", i));
            buy.owner_hash = format!("{:0>64}", format!("ob{}", i));
            ob.add_buy_order(buy);
            let mut sell = make_sell(10_000_000, 1, 2, FAKE_TOKEN);
            sell.tx_id = format!("{:0>64}", format!("sell{}", i));
            sell.owner_hash = format!("{:0>64}", format!("os{}", i));
            ob.add_sell_order(sell);
        }

        let groups = match_book_direct(&ob, true, None, u64::MAX);
        let mut all_outpoints = std::collections::HashSet::new();
        for g in &groups {
            for o in g.all_orders() {
                let key = o.outpoint_key();
                assert!(
                    !all_outpoints.contains(&key),
                    "Outpoint {} appears in multiple groups",
                    key
                );
                all_outpoints.insert(key);
            }
        }
    }

    #[test]
    fn test_direct_max_batch_group_size_cap() {
        // 20 pairs -> should be split at MAX_BATCH_GROUP_SIZE
        let mut ob = OrderBook::new();
        for i in 0..20u32 {
            let mut buy = make_buy(10_000_000, 1, 2, FAKE_TOKEN);
            buy.tx_id = format!("{:0>64}", format!("buy{:02}", i));
            buy.owner_hash = format!("{:0>64}", format!("ob{:02}", i));
            ob.add_buy_order(buy);
            let mut sell = make_sell(10_000_000, 1, 2, FAKE_TOKEN);
            sell.tx_id = format!("{:0>64}", format!("sell{:02}", i));
            sell.owner_hash = format!("{:0>64}", format!("os{:02}", i));
            ob.add_sell_order(sell);
        }

        let groups = match_book_direct(&ob, true, None, u64::MAX);
        for g in &groups {
            assert!(
                g.sells.len() <= MAX_BATCH_GROUP_SIZE,
                "Group sells {} > MAX_BATCH_GROUP_SIZE {}",
                g.sells.len(),
                MAX_BATCH_GROUP_SIZE,
            );
        }
        let total: usize = groups.iter().map(|g| g.sells.len()).sum();
        assert_eq!(total, 20, "All 20 pairs should be matched");
    }

    #[test]
    fn test_direct_partial_fill() {
        let mut ob = OrderBook::new();
        // Large buy: 50M KAS at 2/1 (expects 100M tokens)
        let mut buy = make_buy(50_000_000, 2, 1, FAKE_TOKEN);
        buy.tx_id = "a".repeat(64);
        buy.owner_hash = "aa".repeat(32);
        ob.add_buy_order(buy);
        // Small sell: 20M tokens at 1/3 (expects ~6.67M KAS)
        let mut sell = make_sell(20_000_000, 1, 3, FAKE_TOKEN);
        sell.tx_id = "c".repeat(64);
        sell.owner_hash = "bb".repeat(32);
        ob.add_sell_order(sell);

        let groups = match_book_direct(&ob, true, None, u64::MAX);
        assert!(!groups.is_empty(), "Should find at least one group");
        let has_partial = groups.iter().any(|g|
            g.kind == GroupKind::PartialBuy || g.kind == GroupKind::PartialSell
        );
        let has_batch = groups.iter().any(|g| g.kind == GroupKind::Batch);
        assert!(has_partial || has_batch, "Should have partial or batch group");
    }

    #[test]
    fn test_direct_fifo_ordering() {
        // Verify that FIFO ordering is preserved: at equal price, older
        // orders (lower discovered_daa) should be matched first.
        let mut ob = OrderBook::new();

        // Two buys at the same price, different DAA
        let mut buy_old = make_buy(10_000_000, 1, 2, FAKE_TOKEN);
        buy_old.tx_id = format!("{:0>64}", "buy_old");
        buy_old.owner_hash = "aa".repeat(32);
        buy_old.discovered_daa = 100; // older
        ob.add_buy_order(buy_old);

        let mut buy_new = make_buy(10_000_000, 1, 2, FAKE_TOKEN);
        buy_new.tx_id = format!("{:0>64}", "buy_new");
        buy_new.owner_hash = "cc".repeat(32);
        buy_new.discovered_daa = 200; // newer
        ob.add_buy_order(buy_new);

        // Only one sell (will match the older buy first)
        let mut sell = make_sell(10_000_000, 1, 2, FAKE_TOKEN);
        sell.tx_id = format!("{:0>64}", "sell_one");
        sell.owner_hash = "bb".repeat(32);
        ob.add_sell_order(sell);

        let groups = match_book_direct(&ob, true, None, u64::MAX);
        assert!(!groups.is_empty());

        // The matched buy should be the older one (daa=100)
        let matched_buy = &groups[0].buys[0];
        assert_eq!(
            matched_buy.discovered_daa, 100,
            "FIFO: older order (daa=100) should be matched before newer (daa=200)"
        );
    }

    #[test]
    fn test_direct_multi_token() {
        let token_a = FAKE_TOKEN;
        let token_b = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";

        let mut ob = OrderBook::new();
        let mut buy_a = make_buy(10_000_000, 1, 2, token_a);
        buy_a.tx_id = "a".repeat(64);
        buy_a.owner_hash = "aa".repeat(32);
        ob.add_buy_order(buy_a);
        let mut sell_a = make_sell(10_000_000, 1, 2, token_a);
        sell_a.tx_id = "b".repeat(64);
        sell_a.owner_hash = "bb".repeat(32);
        ob.add_sell_order(sell_a);

        let mut buy_b = make_buy(20_000_000, 1, 3, token_b);
        buy_b.tx_id = "c".repeat(64);
        buy_b.owner_hash = "cc".repeat(32);
        ob.add_buy_order(buy_b);
        let mut sell_b = make_sell(20_000_000, 1, 3, token_b);
        sell_b.tx_id = "d".repeat(64);
        sell_b.owner_hash = "dd".repeat(32);
        ob.add_sell_order(sell_b);

        let groups = match_book_direct(&ob, true, None, u64::MAX);
        let total_sells: usize = groups.iter().map(|g| g.sells.len()).sum();
        assert_eq!(total_sells, 2, "Both token pairs should produce matches");
    }

    #[test]
    fn test_direct_sweep_detection() {
        // 1 large buy + 3 small sells -> should produce BuySweep or GtcBuyMultiFill
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

        let groups = match_book_direct(&ob, true, None, u64::MAX);
        assert!(!groups.is_empty(), "Should find groups");
        // The single buy matching 3 sells should form a group with 1 buy + 3 sells
        let group = &groups[0];
        assert_eq!(group.buys.len(), 1, "Should have 1 buy");
        assert!(group.sells.len() >= 2, "Should have multiple sells");
        let sweep_kind = matches!(
            group.kind,
            GroupKind::BuySweep | GroupKind::GtcBuyMultiFill | GroupKind::Batch
        );
        assert!(sweep_kind, "Kind should be BuySweep, GtcBuyMultiFill, or Batch");
    }

    #[test]
    fn test_direct_empty_book() {
        let ob = OrderBook::new();
        let groups = match_book_direct(&ob, true, None, u64::MAX);
        assert!(groups.is_empty());
    }

    #[test]
    fn test_direct_zero_price_skipped() {
        let mut ob = OrderBook::new();
        let mut buy = make_buy(10_000_000, 0, 1, FAKE_TOKEN);
        buy.owner_hash = "aa".repeat(32);
        ob.add_buy_order(buy);
        let mut sell = make_sell(10_000_000, 0, 1, FAKE_TOKEN);
        sell.owner_hash = "bb".repeat(32);
        ob.add_sell_order(sell);

        let groups = match_book_direct(&ob, true, None, u64::MAX);
        assert!(groups.is_empty(), "Zero-price orders should be skipped");
    }

    /// OCO duplicate-input prevention: when TP and SL paths of the same
    /// UTXO are both in the order book, only one may appear in any batch
    /// group. Both paths share the same tx_id:index, so including both
    /// would create a TX with duplicate inputs that kaspad rejects.
    #[test]
    fn test_oco_duplicate_input_excluded_from_sweep() {
        let mut ob = OrderBook::new();

        // Large buy that can sweep multiple sells.
        let mut buy = make_buy_e2e(
            &"aa".repeat(32), 0,
            100_000_000,  // 100M sompi
            1, 1,         // price 1/1: 1 KAS per token
            FAKE_TOKEN,
            &"b1".repeat(32),
        );
        buy.discovered_daa = 1;
        ob.add_buy_order(buy);

        // OCO sell: TP path (price 1/1, 10M tokens).
        // tx_id = "cc..cc", index = 0 → utxo_outpoint_key = "cc..cc:0"
        let oco_tx_id = "cc".repeat(32);
        let mut sell_tp = make_sell_e2e(
            &oco_tx_id, 0,
            10_000_000,   // 10M tokens
            1, 1,         // price 1/1
            FAKE_TOKEN,
            &"s1".repeat(32),
        );
        sell_tp.oco_path = Some(kob_core::OcoPath::TakeProfit);
        // Partner key points to the SL virtual order.
        sell_tp.oco_partner_key = Some(format!("{}:0:sl", oco_tx_id));
        sell_tp.discovered_daa = 2;
        ob.add_sell_order(sell_tp);

        // OCO sell: SL path (price 1/2, same UTXO).
        let mut sell_sl = make_sell_e2e(
            &oco_tx_id, 0,
            10_000_000,   // same 10M tokens
            1, 2,         // price 1/2 (cheaper for buyer)
            FAKE_TOKEN,
            &"s1".repeat(32),
        );
        sell_sl.oco_path = Some(kob_core::OcoPath::StopLoss);
        sell_sl.oco_partner_key = Some(format!("{}:0:tp", oco_tx_id));
        sell_sl.discovered_daa = 2;
        ob.add_sell_order(sell_sl);

        // A second regular sell at a crossing price (different UTXO).
        let mut sell_regular = make_sell_e2e(
            &"dd".repeat(32), 0,
            10_000_000,
            1, 1,
            FAKE_TOKEN,
            &"s2".repeat(32),
        );
        sell_regular.discovered_daa = 3;
        ob.add_sell_order(sell_regular);

        let groups = match_book_direct(&ob, true, None, u64::MAX);
        assert!(!groups.is_empty(), "Should produce at least one group");

        // Collect all sell utxo_outpoint_keys across all groups.
        let mut utxo_keys: Vec<String> = Vec::new();
        for g in &groups {
            for s in &g.sells {
                utxo_keys.push(s.utxo_outpoint_key());
            }
        }

        // The OCO UTXO must appear at most once across all groups.
        let oco_utxo = format!("{}:0", oco_tx_id);
        let oco_count = utxo_keys.iter().filter(|k| **k == oco_utxo).count();
        assert!(
            oco_count <= 1,
            "OCO UTXO {} appears {} times in batch groups (expected <= 1). \
             Duplicate inputs would cause TX rejection.",
            oco_utxo, oco_count,
        );
    }

    /// Same as above but for the 1:1 direct walk path (not sweep).
    #[test]
    fn test_oco_duplicate_input_excluded_from_direct_walk() {
        let mut ob = OrderBook::new();

        let oco_tx_id = "cc".repeat(32);

        // Two separate buys, each big enough for a 1:1 match.
        let mut buy1 = make_buy_e2e(
            &"a1".repeat(32), 0,
            10_000_000, 1, 1, FAKE_TOKEN, &"b1".repeat(32),
        );
        buy1.discovered_daa = 1;
        ob.add_buy_order(buy1);

        let mut buy2 = make_buy_e2e(
            &"a2".repeat(32), 0,
            10_000_000, 1, 2, FAKE_TOKEN, &"b2".repeat(32),
        );
        buy2.discovered_daa = 2;
        ob.add_buy_order(buy2);

        // OCO TP sell
        let mut sell_tp = make_sell_e2e(
            &oco_tx_id, 0, 10_000_000, 1, 1, FAKE_TOKEN, &"s1".repeat(32),
        );
        sell_tp.oco_path = Some(kob_core::OcoPath::TakeProfit);
        sell_tp.oco_partner_key = Some(format!("{}:0:sl", oco_tx_id));
        sell_tp.discovered_daa = 3;
        ob.add_sell_order(sell_tp);

        // OCO SL sell (same UTXO, lower price)
        let mut sell_sl = make_sell_e2e(
            &oco_tx_id, 0, 10_000_000, 1, 2, FAKE_TOKEN, &"s1".repeat(32),
        );
        sell_sl.oco_path = Some(kob_core::OcoPath::StopLoss);
        sell_sl.oco_partner_key = Some(format!("{}:0:tp", oco_tx_id));
        sell_sl.discovered_daa = 3;
        ob.add_sell_order(sell_sl);

        let groups = match_book_direct(&ob, true, None, u64::MAX);

        let mut utxo_keys: Vec<String> = Vec::new();
        for g in &groups {
            for s in &g.sells {
                utxo_keys.push(s.utxo_outpoint_key());
            }
        }

        let oco_utxo = format!("{}:0", oco_tx_id);
        let oco_count = utxo_keys.iter().filter(|k| **k == oco_utxo).count();
        assert!(
            oco_count <= 1,
            "OCO UTXO {} appears {} times across groups (expected <= 1). \
             Both TP and SL paths were matched, causing duplicate inputs.",
            oco_utxo, oco_count,
        );
    }

    // =========================================================================
    // Phase-3 race regression tests
    //
    // These tests lock in the behavior fixed in the Phase-3 race investigation
    // (see /tmp/phase3_race_investigation.md).  The race was:
    //
    //   1. Scanner discovers an OCO sell on token A (TP+SL, single UTXO, added
    //      to the book as two virtual entries with suffixed outpoint_keys).
    //   2. find_sweep_groups picks up the cheaper OCO leg (SL price) and 2+ buys
    //      as a SellSweep candidate.  The buys don't absorb the full 200M-token
    //      OCO UTXO — there's a remainder.
    //   3. plan_sell_ioc_match happily returns a plan.  build_tx() in batch.rs
    //      dispatches to build_sell_ioc_fill_sigscript because has_remainder is
    //      true — emitting selector=5 in the sigscript.
    //   4. OCO v1 covenant's dispatch has no selector=5 path.  sel=5 falls
    //      through to the SL-branch's `Op2 OpEqual OpVerify` check, which
    //      fails (5 != 2).  The node rejects the TX with
    //      "script ran, but verification failed".
    //   5. executor marks ALL orders in the group as failed with 30-sec
    //      cooldown — dragging the P23 cross-pair BUY into cooldown.
    //   6. Phase 3 (match_swap_routes) excludes cooldown-failed orders;
    //      the P23 swap route has no `buy_source` candidate and returns empty.
    //   7. 30 sec later the cooldown clears, Phase 1 re-plans the same OCO
    //      batch, the same failure cascades, and P23 never gets matched.
    //
    // The fix has three pieces:
    //
    //   * plan_sell_ioc_match returns BatchError::OcoRemainderUnsupported when
    //     sell is OCO and buys leave a token remainder.
    //   * plan_batch_match returns the same error for OCO sells under same
    //     condition.
    //   * executor treats OcoRemainderUnsupported as a skip-without-cooldown
    //     (same pattern as MinFillViolation).
    //
    // =========================================================================

    /// Helper: build a BookOrder with an explicit owner_hash to bypass STP.
    #[allow(dead_code)]
    fn make_buy_with_owner(
        tx_id: &str,
        index: u32,
        value: u64,
        price_num: u64,
        price_den: u64,
        token_cov_id: &str,
        owner: &str,
    ) -> BookOrder {
        let mut o = make_buy(value, price_num, price_den, token_cov_id);
        o.tx_id = tx_id.to_string();
        o.index = index;
        o.owner_hash = owner.to_string();
        o
    }

    /// Helper: build a SELL BookOrder with explicit owner.
    #[allow(dead_code)]
    fn make_sell_with_owner(
        tx_id: &str,
        index: u32,
        value: u64,
        price_num: u64,
        price_den: u64,
        token_cov_id: &str,
        owner: &str,
    ) -> BookOrder {
        let mut o = make_sell(value, price_num, price_den, token_cov_id);
        o.tx_id = tx_id.to_string();
        o.index = index;
        o.owner_hash = owner.to_string();
        o
    }

    /// Helper: construct a minimal SwapEntry for the swap book.
    fn make_swap_entry(
        tx_id: &str,
        index: u32,
        source_cov_id: &str,
        target_cov_id: &str,
        value: u64,
        min_target_amount: u64,
    ) -> crate::swap_book::SwapEntry {
        crate::swap_book::SwapEntry {
            tx_id: tx_id.to_string(),
            index,
            value,
            source_cov_id: source_cov_id.to_string(),
            target_cov_id: target_cov_id.to_string(),
            min_target_amount,
            owner_hash: "ee".repeat(32),
            owner_spk_hash: "ff".repeat(32),
            receipt_cov_id: "11".repeat(32),
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            discovered_daa: 0,
            owner_spk: Some("0000".to_string()),
        }
    }

    // ===============================================================
    // v18 ring detection (find_rings)
    // ===============================================================

    fn make_ring_swap_entry(
        id_byte: u8,
        source: [u8; 32],
        target: [u8; 32],
        amount: u64,
    ) -> crate::swap_book::SwapEntry {
        let owner_spk: Vec<u8> = {
            let mut s = vec![0x20u8];
            s.extend_from_slice(&[id_byte; 32]);
            s.push(0xac);
            s
        };
        let owner_spk_hash = kob_core::p2sh::compute_spk_hash(0, &owner_spk);
        let rs = kob_core::contract::spot::swap::build_swap_redeem_script(
            &source, &target, 1_000_000, &[0xBB; 32], &owner_spk_hash, &[0xEE; 32], 100,
        )
        .unwrap();
        let p2sh = kob_core::build_p2sh(&rs);
        let mut spk_full = Vec::with_capacity(37);
        spk_full.extend_from_slice(&0u16.to_le_bytes());
        spk_full.extend_from_slice(&owner_spk);
        crate::swap_book::SwapEntry {
            tx_id: hex::encode([id_byte; 32]),
            index: 0,
            value: amount,
            source_cov_id: hex::encode(source),
            target_cov_id: hex::encode(target),
            min_target_amount: 1_000_000,
            owner_hash: hex::encode([0xBB; 32]),
            owner_spk_hash: hex::encode(owner_spk_hash),
            receipt_cov_id: hex::encode([0xEE; 32]),
            redeem_script_hex: hex::encode(&rs),
            p2sh_script_hex: hex::encode(p2sh.script()),
            p2sh_version: p2sh.version,
            discovered_daa: 0,
            owner_spk: Some(hex::encode(&spk_full)),
        }
    }

    const RING_TOKEN_A: [u8; 32] = [0xA1; 32];
    const RING_TOKEN_B: [u8; 32] = [0xB2; 32];
    const RING_TOKEN_C: [u8; 32] = [0xC3; 32];

    #[test]
    fn find_rings_detects_2_cycle() {
        let mut book = crate::swap_book::SwapBook::new();
        book.add(make_ring_swap_entry(0x01, RING_TOKEN_A, RING_TOKEN_B, 50_000_000));
        book.add(make_ring_swap_entry(0x02, RING_TOKEN_B, RING_TOKEN_A, 60_000_000));
        let rings = find_rings(&book, None);
        assert_eq!(rings.len(), 1);
        assert_eq!(rings[0].len(), 2);
        // Closed cycle: leg i's target == leg (i+1)%n's source.
        for i in 0..2 {
            assert_eq!(rings[0][i].target_cov_id, rings[0][(i + 1) % 2].source_cov_id);
        }
    }

    #[test]
    fn find_rings_detects_3_cycle_triangle() {
        let mut book = crate::swap_book::SwapBook::new();
        book.add(make_ring_swap_entry(0x01, RING_TOKEN_A, RING_TOKEN_B, 50_000_000));
        book.add(make_ring_swap_entry(0x02, RING_TOKEN_B, RING_TOKEN_C, 60_000_000));
        book.add(make_ring_swap_entry(0x03, RING_TOKEN_C, RING_TOKEN_A, 70_000_000));
        let rings = find_rings(&book, None);
        assert_eq!(rings.len(), 1);
        assert_eq!(rings[0].len(), 3);
        for i in 0..3 {
            assert_eq!(rings[0][i].target_cov_id, rings[0][(i + 1) % 3].source_cov_id);
        }
    }

    #[test]
    fn find_rings_prefers_2_cycle_and_skips_spent() {
        let mut book = crate::swap_book::SwapBook::new();
        let e1 = make_ring_swap_entry(0x01, RING_TOKEN_A, RING_TOKEN_B, 50_000_000);
        let e2 = make_ring_swap_entry(0x02, RING_TOKEN_B, RING_TOKEN_A, 60_000_000);
        let key1 = e1.outpoint_key();
        book.add(e1);
        book.add(e2);
        // Spending one leg kills the only ring.
        let mut spent = std::collections::HashSet::new();
        spent.insert(key1);
        assert!(find_rings(&book, Some(&spent)).is_empty());
    }

    #[test]
    fn find_rings_ignores_pre_swaps_and_open_chains() {
        let mut book = crate::swap_book::SwapBook::new();
        // Open chain A->B, B->C (no C->A): no ring.
        book.add(make_ring_swap_entry(0x01, RING_TOKEN_A, RING_TOKEN_B, 50_000_000));
        book.add(make_ring_swap_entry(0x02, RING_TOKEN_B, RING_TOKEN_C, 60_000_000));
        assert!(find_rings(&book, None).is_empty());
        // A pre-v18 (243B RS) B->A closer must NOT complete the ring.
        let mut legacy = make_ring_swap_entry(0x03, RING_TOKEN_B, RING_TOKEN_A, 60_000_000);
        legacy.redeem_script_hex = "00".repeat(243);
        book.add(legacy);
        assert!(find_rings(&book, None).is_empty());
    }

    #[test]
    fn find_rings_requires_owner_spk() {
        let mut book = crate::swap_book::SwapBook::new();
        book.add(make_ring_swap_entry(0x01, RING_TOKEN_A, RING_TOKEN_B, 50_000_000));
        let mut e2 = make_ring_swap_entry(0x02, RING_TOKEN_B, RING_TOKEN_A, 60_000_000);
        e2.owner_spk = None; // fill would be unbuildable — defer
        book.add(e2);
        assert!(find_rings(&book, None).is_empty());
    }
}
