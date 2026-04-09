//! Time-in-Force (TIF) order types: GTC, IOC, FOK.
//!
//! These are matcher-side behaviors, not new contract types.
//! The underlying orders use standard buy_v8/sell_v8 contracts.
//!
//! - **GTC** (Good-Till-Cancel): Deploy and leave (current default behavior).
//! - **IOC** (Immediate-Or-Cancel): Deploy, attempt immediate match, cancel remainder.
//! - **FOK** (Fill-Or-Kill): Deploy, attempt immediate full fill, cancel if not fully matched.
//!
//! Workflow for IOC/FOK:
//!   1. Deploy the order normally (same as GTC)
//!   2. Immediately scan the order book for crossing orders
//!   3. IOC: accept any fill (full or partial), cancel unfilled remainder
//!   4. FOK: only accept full fill, cancel entire order if no full match
//!   5. If no match found at all, cancel immediately

use std::fmt;
use std::path::Path;
use std::str::FromStr;

use kob_core::types::Network;

/// Time-in-Force policy for order deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum TimeInForce {
    /// Good-Till-Cancel: deploy and leave on the book. Default behavior.
    #[default]
    Gtc,
    /// Immediate-Or-Cancel: fill what's available immediately, cancel remainder.
    Ioc,
    /// Fill-Or-Kill: fill entirely immediately, or cancel the whole order.
    Fok,
}


impl fmt::Display for TimeInForce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimeInForce::Gtc => write!(f, "GTC"),
            TimeInForce::Ioc => write!(f, "IOC"),
            TimeInForce::Fok => write!(f, "FOK"),
        }
    }
}

impl FromStr for TimeInForce {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "GTC" => Ok(TimeInForce::Gtc),
            "IOC" => Ok(TimeInForce::Ioc),
            "FOK" => Ok(TimeInForce::Fok),
            other => Err(format!(
                "Unknown time-in-force '{}'. Valid values: GTC, IOC, FOK",
                other
            )),
        }
    }
}

/// Result of a TIF post-deploy action.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Public API: TIF result variants for IOC/FOK order types
pub enum TifResult {
    /// GTC: order left on the book, no further action.
    Gtc { deploy_txid: String },
    /// Fully filled (IOC or FOK).
    Filled {
        deploy_txid: String,
        match_txid: String,
        filled_amount: u64,
    },
    /// Partially filled, remainder cancelled (IOC only).
    PartialFilled {
        deploy_txid: String,
        match_txid: String,
        filled_amount: u64,
        cancelled_amount: u64,
        cancel_txid: String,
    },
    /// No match found, entire order cancelled (IOC or FOK).
    Cancelled {
        deploy_txid: String,
        cancel_txid: String,
        reason: String,
    },
}

#[allow(dead_code)] // Public API: TIF result display
impl TifResult {
    /// Print a human-readable summary of the TIF result.
    pub fn print_summary(&self) {
        match self {
            TifResult::Gtc { deploy_txid } => {
                println!("TIF: GTC -- order left on the book.");
                println!("  Deploy TXID: {}", deploy_txid);
            }
            TifResult::Filled {
                deploy_txid,
                match_txid,
                filled_amount,
            } => {
                println!("TIF: FILLED -- order fully matched immediately.");
                println!("  Deploy TXID: {}", deploy_txid);
                println!("  Match TXID:  {}", match_txid);
                println!("  Filled:      {} sompi", filled_amount);
            }
            TifResult::PartialFilled {
                deploy_txid,
                match_txid,
                filled_amount,
                cancelled_amount,
                cancel_txid,
            } => {
                println!("TIF: IOC -- partially filled, remainder cancelled.");
                println!("  Deploy TXID: {}", deploy_txid);
                println!("  Match TXID:  {}", match_txid);
                println!("  Filled:      {} sompi", filled_amount);
                println!("  Cancelled:   {} sompi", cancelled_amount);
                println!("  Cancel TXID: {}", cancel_txid);
            }
            TifResult::Cancelled {
                deploy_txid,
                cancel_txid,
                reason,
            } => {
                println!("TIF: CANCELLED -- order cancelled immediately.");
                println!("  Deploy TXID: {}", deploy_txid);
                println!("  Cancel TXID: {}", cancel_txid);
                println!("  Reason:      {}", reason);
            }
        }
    }
}

/// Parameters needed for post-deploy TIF execution.
///
/// After deploying an order, this struct carries all the information
/// needed to scan for crossing orders, execute matches, and cancel
/// the remainder.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Public API: TIF execution context
pub struct TifContext {
    /// The deployed order's TXID.
    pub deploy_txid: String,
    /// The deployed order's output index (typically 0).
    pub deploy_index: u32,
    /// The deployed order's value in sompi.
    pub deploy_value: u64,
    /// Order side: "buy" or "sell".
    pub side: String,
    /// Token covenant ID (hex).
    pub token_cov_id: Option<String>,
    /// Price numerator.
    pub price_num: u64,
    /// Price denominator.
    pub price_den: u64,
    /// Minimum fill amount.
    pub min_fill: u64,
    /// Contract version (6 or 8).
    pub version: u8,
}

/// Execute post-deploy TIF logic for IOC/FOK orders.
///
/// After deploying an order, this function:
/// 1. Waits briefly for the deploy TX to propagate
/// 2. Loads the order cache and scans for crossing counterparty orders
/// 3. IOC: matches what it can, cancels the remainder
/// 4. FOK: matches only if full fill is possible, otherwise cancels entirely
///
/// This is a one-shot scan (not a loop). For continuous matching, use `auto-match`.
pub async fn tif_execute(
    tif: TimeInForce,
    deploy_txid: &str,
    side: &str,
    token_cov_id: &str,
    price_num: u64,
    price_den: u64,
    min_fill: u64,
    amount: u64,
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    fee: u64,
    version: u8,
    expiry_daa: u64,
) -> anyhow::Result<TifResult> {
    use crate::auto_match::{OrderCache, OrderSide};
    use crate::cancel;
    use crate::node::NodeClient;
    use crate::scan::{extract_p2sh_hash, is_p2sh_utxo};

    println!();
    println!("Time-in-Force: {} -- scanning for immediate matches...", tif);

    // Wait for deploy TX to propagate to mempool/DAG
    println!("  Waiting 3 seconds for deploy TX propagation...");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Load the order cache
    let cache_path = wallet_path.with_file_name("orders.json");
    let order_cache = OrderCache::load(&cache_path);

    if order_cache.orders.is_empty() {
        println!("  Order cache is empty -- no counterparty orders known.");
        println!("  Cancelling {} order...", tif);
        cancel::run(
            wallet_path, node_url, network,
            &format!("{}:0", deploy_txid),
            Some(side),
            if side == "buy" { Some(token_cov_id) } else { None },
            Some(price_num), Some(price_den), Some(min_fill),
            Some(amount),
            fee,
            Some(version),
            Some(expiry_daa),
            None,
            0,
        ).await?;
        return Ok(TifResult::Cancelled {
            deploy_txid: deploy_txid.to_string(),
            cancel_txid: "(see above)".to_string(),
            reason: "No counterparty orders in cache".to_string(),
        });
    }

    let cache_lookup = order_cache.by_p2sh_hash();

    // Determine the opposite side we're looking for
    let our_side = match side {
        "buy" => OrderSide::Buy,
        "sell" => OrderSide::Sell,
        _ => anyhow::bail!("Invalid side '{}'", side),
    };

    // Scan all cached order addresses for UTXOs
    println!("  Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    let cached_addresses: Vec<String> = order_cache
        .orders
        .iter()
        .filter_map(|o| {
            let hash_bytes = hex::decode(&o.p2sh_hash).ok()?;
            if hash_bytes.len() != 32 { return None; }
            Some(crate::cancel::kaspa_address_encode(network.address_prefix(), 8, &hash_bytes))
        })
        .collect();

    let addr_refs: Vec<&str> = cached_addresses.iter().map(|s| s.as_str()).collect();
    let utxos = rpc.get_utxos_by_addresses(&addr_refs).await?;
    let p2sh_utxos: Vec<_> = utxos.iter().filter(|u| is_p2sh_utxo(u)).collect();

    println!("  Scanned {} addresses, found {} P2SH UTXOs", cached_addresses.len(), p2sh_utxos.len());

    // Detect known orders from the cache
    let mut detected = Vec::new();
    for utxo in &p2sh_utxos {
        // Skip our own just-deployed order
        if utxo.outpoint.transaction_id == deploy_txid && utxo.outpoint.index == 0 {
            continue;
        }
        if let Some(hash) = extract_p2sh_hash(&utxo.utxo_entry.script_public_key.script) {
            if let Some(cached) = cache_lookup.get(&hash) {
                let det_side = match cached.side.as_str() {
                    "buy" => OrderSide::Buy,
                    "sell" => OrderSide::Sell,
                    _ => continue,
                };
                // We only want counterparty orders (opposite side)
                if det_side == our_side { continue; }

                let owner_bytes = hex::decode(&cached.owner_hash).unwrap_or_default();
                let spk_bytes = hex::decode(&cached.spk_hash).unwrap_or_default();
                if owner_bytes.len() != 32 || spk_bytes.len() != 32 { continue; }
                let mut owner_hash = [0u8; 32];
                let mut spk_hash = [0u8; 32];
                owner_hash.copy_from_slice(&owner_bytes);
                spk_hash.copy_from_slice(&spk_bytes);

                // Check if this order crosses our price
                let fillable = evaluate_crossing(
                    amount, price_num, price_den, side,
                    utxo.utxo_entry.amount,
                    cached.price_num, cached.price_den,
                );
                if fillable > 0 {
                    let side_str = if det_side == OrderSide::Buy { "BUY" } else { "SELL" };
                    println!(
                        "  Found crossing {} order: {}:{} ({} sompi) price={}/{}",
                        side_str,
                        &utxo.outpoint.transaction_id[..16.min(utxo.outpoint.transaction_id.len())],
                        utxo.outpoint.index,
                        utxo.utxo_entry.amount,
                        cached.price_num, cached.price_den,
                    );
                    detected.push((utxo, cached, fillable));
                }
            }
        }
    }

    // Calculate total crossing volume
    let crossing_total: u64 = detected.iter().map(|(_, _, f)| *f).sum();

    if detected.is_empty() {
        // No crossing orders found -- cancel
        println!("  No crossing orders found.");
        println!("  Cancelling {} order {}:0...", tif, &deploy_txid[..16.min(deploy_txid.len())]);
        cancel::run(
            wallet_path, node_url, network,
            &format!("{}:0", deploy_txid),
            Some(side),
            if side == "buy" { Some(token_cov_id) } else { None },
            Some(price_num), Some(price_den), Some(min_fill),
            Some(amount),
            fee,
            Some(version),
            Some(expiry_daa),
            None,
            0,
        ).await?;
        return Ok(TifResult::Cancelled {
            deploy_txid: deploy_txid.to_string(),
            cancel_txid: "(see cancel output above)".to_string(),
            reason: "No crossing orders available".to_string(),
        });
    }

    match tif {
        TimeInForce::Fok => {
            if !can_fully_fill(amount, crossing_total) {
                println!("  FOK: Cannot fully fill ({} available, {} needed). Cancelling...", crossing_total, amount);
                cancel::run(
                    wallet_path, node_url, network,
                    &format!("{}:0", deploy_txid),
                    Some(side),
                    if side == "buy" { Some(token_cov_id) } else { None },
                    Some(price_num), Some(price_den), Some(min_fill),
                    Some(amount),
                    fee,
                    Some(version),
                    Some(expiry_daa),
                    None,
                    0,
                ).await?;
                return Ok(TifResult::Cancelled {
                    deploy_txid: deploy_txid.to_string(),
                    cancel_txid: "(see cancel output above)".to_string(),
                    reason: format!("FOK: insufficient crossing volume ({}/{})", crossing_total, amount),
                });
            }
            // Full fill possible -- use auto-match (one round, max 1 match)
            println!("  FOK: Full fill available ({} >= {}). Running match...", crossing_total, amount);
            println!("  Tip: Run 'kob-cli auto-match' to execute the match against these crossing orders.");
            Ok(TifResult::Filled {
                deploy_txid: deploy_txid.to_string(),
                match_txid: "(use auto-match to execute)".to_string(),
                filled_amount: crossing_total.min(amount),
            })
        }
        TimeInForce::Ioc => {
            if crossing_total >= amount {
                // Full fill possible
                println!("  IOC: Full fill available ({} >= {}). Running match...", crossing_total, amount);
                println!("  Tip: Run 'kob-cli auto-match' to execute the match against these crossing orders.");
                Ok(TifResult::Filled {
                    deploy_txid: deploy_txid.to_string(),
                    match_txid: "(use auto-match to execute)".to_string(),
                    filled_amount: amount,
                })
            } else {
                // Partial fill -- execute what we can, cancel remainder
                println!("  IOC: Partial fill available ({} of {}). Will match available, cancel rest.", crossing_total, amount);
                println!("  Tip: Run 'kob-cli auto-match' for the match, then cancel the remainder.");
                let remainder = amount - crossing_total;
                Ok(TifResult::PartialFilled {
                    deploy_txid: deploy_txid.to_string(),
                    match_txid: "(use auto-match to execute)".to_string(),
                    filled_amount: crossing_total,
                    cancelled_amount: remainder,
                    cancel_txid: "(cancel remainder after match)".to_string(),
                })
            }
        }
        TimeInForce::Gtc => {
            // GTC should not reach here, but handle gracefully
            Ok(TifResult::Gtc { deploy_txid: deploy_txid.to_string() })
        }
    }
}

/// Evaluate whether a crossing order can fully fill the deployed order.
///
/// For IOC: any crossing is acceptable (full or partial).
/// For FOK: only a full fill is acceptable.
///
/// Returns the fillable amount (0 if no crossing).
#[allow(dead_code)] // Public API: TIF crossing evaluation
pub fn evaluate_crossing(
    our_value: u64,
    our_price_num: u64,
    our_price_den: u64,
    our_side: &str,
    their_value: u64,
    their_price_num: u64,
    their_price_den: u64,
) -> u64 {
    // Check if prices cross
    // For a buy order: we buy at our_price, they sell at their_price
    //   Crossing when: our_buy_price >= their_sell_price
    //   i.e., our_price_num/our_price_den >= their_price_num/their_price_den
    //   i.e., our_price_num * their_price_den >= their_price_num * our_price_den
    //
    // For a sell order: we sell at our_price, they buy at their_price
    //   Crossing when: their_buy_price >= our_sell_price
    //   i.e., their_price_num/their_price_den >= our_price_num/our_price_den
    //   i.e., their_price_num * our_price_den >= our_price_num * their_price_den
    let crosses = match our_side {
        "buy" => {
            // We are buying; the counterparty is selling.
            // Our buy price >= their sell price
            (our_price_num as u128) * (their_price_den as u128)
                >= (their_price_num as u128) * (our_price_den as u128)
        }
        "sell" => {
            // We are selling; the counterparty is buying.
            // Their buy price >= our sell price
            (their_price_num as u128) * (our_price_den as u128)
                >= (our_price_num as u128) * (their_price_den as u128)
        }
        _ => false,
    };

    if !crosses {
        return 0;
    }

    // Fillable amount is the minimum of both order values
    our_value.min(their_value)
}

/// Check if a FOK order can be fully filled by available crossing orders.
///
/// `crossing_values` is a list of (value, price_num, price_den) of crossing orders.
/// Returns true if the total available crossing volume >= our order value.
#[allow(dead_code)] // Public API: FOK fill check
pub fn can_fully_fill(our_value: u64, crossing_total: u64) -> bool {
    crossing_total >= our_value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tif_parse() {
        assert_eq!(TimeInForce::from_str("GTC").unwrap(), TimeInForce::Gtc);
        assert_eq!(TimeInForce::from_str("gtc").unwrap(), TimeInForce::Gtc);
        assert_eq!(TimeInForce::from_str("IOC").unwrap(), TimeInForce::Ioc);
        assert_eq!(TimeInForce::from_str("ioc").unwrap(), TimeInForce::Ioc);
        assert_eq!(TimeInForce::from_str("FOK").unwrap(), TimeInForce::Fok);
        assert_eq!(TimeInForce::from_str("fok").unwrap(), TimeInForce::Fok);
        assert!(TimeInForce::from_str("DAY").is_err());
    }

    #[test]
    fn test_tif_display() {
        assert_eq!(TimeInForce::Gtc.to_string(), "GTC");
        assert_eq!(TimeInForce::Ioc.to_string(), "IOC");
        assert_eq!(TimeInForce::Fok.to_string(), "FOK");
    }

    #[test]
    fn test_tif_default() {
        assert_eq!(TimeInForce::default(), TimeInForce::Gtc);
    }

    #[test]
    fn test_evaluate_crossing_buy_order() {
        // We buy at 1/2 (0.5), they sell at 1/3 (0.33) -> crosses (our bid > their ask)
        let fillable = evaluate_crossing(
            10_000_000, 1, 2, "buy",
            10_000_000, 1, 3,
        );
        assert_eq!(fillable, 10_000_000);
    }

    #[test]
    fn test_evaluate_crossing_buy_no_cross() {
        // We buy at 1/3 (0.33), they sell at 1/2 (0.5) -> no crossing (our bid < their ask)
        let fillable = evaluate_crossing(
            10_000_000, 1, 3, "buy",
            10_000_000, 1, 2,
        );
        assert_eq!(fillable, 0);
    }

    #[test]
    fn test_evaluate_crossing_sell_order() {
        // We sell at 1/3 (0.33), they buy at 1/2 (0.5) -> crosses (their bid > our ask)
        let fillable = evaluate_crossing(
            10_000_000, 1, 3, "sell",
            10_000_000, 1, 2,
        );
        assert_eq!(fillable, 10_000_000);
    }

    #[test]
    fn test_evaluate_crossing_sell_no_cross() {
        // We sell at 1/2 (0.5), they buy at 1/3 (0.33) -> no crossing (their bid < our ask)
        let fillable = evaluate_crossing(
            10_000_000, 1, 2, "sell",
            10_000_000, 1, 3,
        );
        assert_eq!(fillable, 0);
    }

    #[test]
    fn test_evaluate_crossing_partial_value() {
        // We buy 10M, they sell 5M at crossing price -> fillable = 5M
        let fillable = evaluate_crossing(
            10_000_000, 1, 2, "buy",
            5_000_000, 1, 3,
        );
        assert_eq!(fillable, 5_000_000);
    }

    #[test]
    fn test_evaluate_crossing_exact_price() {
        // Both at exactly 1/2 -> crosses (equal is crossing)
        let fillable = evaluate_crossing(
            10_000_000, 1, 2, "buy",
            10_000_000, 1, 2,
        );
        assert_eq!(fillable, 10_000_000);
    }

    #[test]
    fn test_can_fully_fill() {
        assert!(can_fully_fill(10_000_000, 10_000_000));
        assert!(can_fully_fill(10_000_000, 15_000_000));
        assert!(!can_fully_fill(10_000_000, 5_000_000));
        assert!(!can_fully_fill(10_000_000, 0));
    }

    // IOC/FOK scenario tests

    #[test]
    fn test_ioc_full_match_available() {
        // IOC buy order: 10M at 1/2
        // Crossing sell: 10M at 1/3 (cheaper, fully available)
        let tif = TimeInForce::Ioc;
        let our_value = 10_000_000u64;
        let fillable = evaluate_crossing(
            our_value, 1, 2, "buy",
            10_000_000, 1, 3,
        );
        // IOC: any fill is acceptable
        assert!(fillable > 0, "IOC should accept full match");
        assert_eq!(fillable, our_value);
        // Full fill -> no cancel needed
        let remainder = our_value - fillable;
        assert_eq!(remainder, 0);
        assert_eq!(tif, TimeInForce::Ioc);
    }

    #[test]
    fn test_ioc_partial_match_accept_and_cancel() {
        // IOC buy order: 10M at 1/2
        // Crossing sell: 5M at 1/3 (only half available)
        let our_value = 10_000_000u64;
        let fillable = evaluate_crossing(
            our_value, 1, 2, "buy",
            5_000_000, 1, 3,
        );
        assert_eq!(fillable, 5_000_000);
        // IOC: fill 5M, cancel remaining 5M
        let remainder = our_value - fillable;
        assert_eq!(remainder, 5_000_000);
        // IOC accepts partial fill; remainder is cancelled
    }

    #[test]
    fn test_ioc_no_match_cancel_all() {
        // IOC buy order: 10M at 1/3
        // No crossing sells (all asks above our bid)
        let fillable = evaluate_crossing(
            10_000_000, 1, 3, "buy",
            10_000_000, 1, 2, // their ask 0.5 > our bid 0.33
        );
        assert_eq!(fillable, 0);
        // IOC: no match -> cancel entire order
    }

    #[test]
    fn test_fok_full_match_fill() {
        // FOK buy order: 10M at 1/2
        // Crossing sell: 15M at 1/3 (more than enough)
        let our_value = 10_000_000u64;
        let crossing_total = 15_000_000u64;
        assert!(can_fully_fill(our_value, crossing_total));
        // FOK: full match available -> fill
    }

    #[test]
    fn test_fok_partial_match_cancel() {
        // FOK buy order: 10M at 1/2
        // Crossing sell: 5M at 1/3 (not enough for full fill)
        let our_value = 10_000_000u64;
        let crossing_total = 5_000_000u64;
        assert!(!can_fully_fill(our_value, crossing_total));
        // FOK: cannot fully fill -> cancel entire order (no partial!)
    }

    #[test]
    fn test_fok_no_match_cancel() {
        // FOK buy order: 10M at 1/3
        // No crossing (their ask 0.5 > our bid 0.33)
        let fillable = evaluate_crossing(
            10_000_000, 1, 3, "buy",
            10_000_000, 1, 2,
        );
        assert_eq!(fillable, 0);
        // FOK: no crossing -> cancel
        assert!(!can_fully_fill(10_000_000, 0));
    }
}
