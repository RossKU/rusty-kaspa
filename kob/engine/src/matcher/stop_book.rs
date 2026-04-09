//! Stop order book with pre-signed TX broadcast on price trigger.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Unique identifier for a stop order (monotonic counter).
pub type StopOrderId = u64;

/// Type of stop order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StopOrderType {
    StopLimit,
    StopMarket,
}

/// Side of the stop trigger.
///
/// - `Sell`: triggers when price drops to or below stop_price (protective stop-loss)
/// - `Buy`: triggers when price rises to or above stop_price (breakout buy)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StopSide {
    Buy,
    Sell,
}

/// A stop order held by the Matcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StopOrder {
    /// Unique identifier assigned by the Matcher.
    pub id: StopOrderId,
    /// Trading pair (token_covenant_id).
    pub pair: String,
    /// Trigger side: Buy (breakout) or Sell (protective).
    pub side: StopSide,
    /// Stop price as rational number (num/den).
    pub stop_price_num: u64,
    pub stop_price_den: u64,
    /// Stop-Limit or Stop-Market.
    pub order_type: StopOrderType,
    /// Pre-signed deploy TX as hex-encoded raw transaction JSON.
    /// This is the complete `submitTransaction` JSON payload that the Matcher
    /// will broadcast to L1 when the stop is triggered.
    pub signed_tx_json: String,
    /// Owner identifier (e.g., public key hash) for listing/cancellation auth.
    pub owner_id: String,
    /// Creation timestamp (unix seconds).
    pub created_at: u64,
    /// Optional expiry timestamp (unix seconds). `None` means GTC (good-till-cancel).
    pub expires_at: Option<u64>,
    /// Whether this stop order has been triggered (broadcast attempted).
    pub triggered: bool,
    /// TX ID returned by L1 after broadcast (populated after trigger).
    pub trigger_tx_id: Option<String>,
    /// Secret token required for cancellation (not exposed in list responses).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancel_secret: Option<String>,
}

impl StopOrder {
    /// Check if the stop condition is met given a trade price.
    ///
    /// - Buy stop: triggered when `trade_price >= stop_price`
    /// - Sell stop: triggered when `trade_price <= stop_price`
    ///
    /// Prices are compared as rationals using cross-multiplication to avoid
    /// floating-point imprecision.
    pub fn is_triggered(&self, trade_price_num: u64, trade_price_den: u64) -> bool {
        if self.triggered {
            return false; // Already triggered
        }
        // Cross-multiply: trade_num/trade_den vs stop_num/stop_den
        let trade_cross = (trade_price_num as u128) * (self.stop_price_den as u128);
        let stop_cross = (self.stop_price_num as u128) * (trade_price_den as u128);

        match self.side {
            StopSide::Buy => trade_cross >= stop_cross,  // price >= stop
            StopSide::Sell => trade_cross <= stop_cross,  // price <= stop
        }
    }

    /// Check if this stop order has expired.
    pub fn is_expired(&self, now_unix: u64) -> bool {
        if let Some(expiry) = self.expires_at {
            now_unix >= expiry
        } else {
            false
        }
    }

}

#[cfg(test)]
impl StopOrder {
    /// Stop price as f64 (for display/logging only).
    pub fn stop_price_f64(&self) -> f64 {
        self.stop_price_num as f64 / self.stop_price_den as f64
    }
}

// Stop Order Book

/// Maximum number of stop orders per trading pair.
pub const MAX_STOP_ORDERS_PER_PAIR: usize = 1_000;

/// Maximum total stop orders across all pairs.
pub const MAX_TOTAL_STOP_ORDERS: usize = 5_000;

/// The stop order book: stores pending conditional orders grouped by pair.
#[derive(Debug)]
pub struct StopOrderBook {
    /// pair -> Vec<StopOrder> (only non-triggered, non-expired orders)
    orders: HashMap<String, Vec<StopOrder>>,
    /// Next ID to assign.
    next_id: StopOrderId,
    /// Total count of active (non-triggered) orders across all pairs.
    total_count: usize,
}

impl Default for StopOrderBook {
    fn default() -> Self {
        StopOrderBook {
            orders: HashMap::new(),
            next_id: 1,
            total_count: 0,
        }
    }
}

impl StopOrderBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a new stop order. Returns the assigned ID, or an error string if
    /// capacity limits are exceeded.
    pub fn add(&mut self, mut order: StopOrder) -> Result<StopOrderId, String> {
        // Global cap
        if self.total_count >= MAX_TOTAL_STOP_ORDERS {
            return Err(format!(
                "stop order limit reached ({}/{})",
                self.total_count, MAX_TOTAL_STOP_ORDERS
            ));
        }

        // Per-pair cap
        let pair_count = self.orders.get(&order.pair).map_or(0, |v| v.len());
        if pair_count >= MAX_STOP_ORDERS_PER_PAIR {
            return Err(format!(
                "stop order limit for pair reached ({}/{})",
                pair_count, MAX_STOP_ORDERS_PER_PAIR
            ));
        }

        // Validate price
        if order.stop_price_den == 0 {
            return Err("stop_price_den cannot be zero".to_string());
        }

        let id = self.next_id;
        self.next_id += 1;
        order.id = id;
        order.triggered = false;
        order.trigger_tx_id = None;

        let pair = order.pair.clone();
        self.orders.entry(pair).or_default().push(order);
        self.total_count += 1;

        Ok(id)
    }

    /// Cancel a stop order by ID, verified by owner_id and cancel_secret.
    pub fn cancel_by_owner(&mut self, id: StopOrderId, owner_id: &str, cancel_secret: Option<&str>) -> Option<StopOrder> {
        for orders in self.orders.values_mut() {
            if let Some(pos) = orders.iter().position(|o| {
                o.id == id && !o.triggered && o.owner_id == owner_id
                    && match (&o.cancel_secret, cancel_secret) {
                        (Some(stored), Some(provided)) => stored == provided,
                        (None, _) => true, // legacy orders without secret: owner_id suffices
                        (Some(_), None) => false, // secret required but not provided
                    }
            }) {
                let removed = orders.remove(pos);
                self.total_count = self.total_count.saturating_sub(1);
                return Some(removed);
            }
        }
        None
    }

    /// Get a stop order by ID (read-only).
    pub fn get(&self, id: StopOrderId) -> Option<&StopOrder> {
        for orders in self.orders.values() {
            if let Some(order) = orders.iter().find(|o| o.id == id) {
                return Some(order);
            }
        }
        None
    }

    /// List all active (non-triggered, non-expired) stop orders for a given owner.
    pub fn list_by_owner(&self, owner_id: &str) -> Vec<&StopOrder> {
        let mut result = Vec::new();
        for orders in self.orders.values() {
            for order in orders {
                if order.owner_id == owner_id && !order.triggered {
                    result.push(order);
                }
            }
        }
        result.sort_by_key(|o| o.id);
        result
    }

    /// List all active stop orders for a given pair.
    pub fn list_by_pair(&self, pair: &str) -> &[StopOrder] {
        self.orders.get(pair).map_or(&[], |v| v.as_slice())
    }

    /// Check all stop orders for a given pair against a trade price.
    /// Returns the IDs of orders that should be triggered.
    ///
    /// Does NOT mutate the orders — the caller is responsible for marking
    /// them as triggered after successful broadcast.
    pub fn check_triggers(
        &self,
        pair: &str,
        trade_price_num: u64,
        trade_price_den: u64,
    ) -> Vec<StopOrderId> {
        let orders = match self.orders.get(pair) {
            Some(o) => o,
            None => return Vec::new(),
        };

        orders
            .iter()
            .filter(|o| !o.triggered && o.is_triggered(trade_price_num, trade_price_den))
            .map(|o| o.id)
            .collect()
    }

    /// Mark a stop order as triggered and record the resulting TX ID.
    pub fn mark_triggered(&mut self, id: StopOrderId, tx_id: Option<String>) {
        for orders in self.orders.values_mut() {
            if let Some(order) = orders.iter_mut().find(|o| o.id == id) {
                order.triggered = true;
                order.trigger_tx_id = tx_id;
                // Don't decrement total_count here; we purge triggered orders
                // during cleanup instead.
                return;
            }
        }
    }

    /// Remove expired and triggered orders. Returns count of removed orders.
    pub fn cleanup(&mut self, now_unix: u64) -> usize {
        let mut removed = 0usize;
        for orders in self.orders.values_mut() {
            let before = orders.len();
            orders.retain(|o| !o.triggered && !o.is_expired(now_unix));
            removed += before - orders.len();
        }
        // Remove empty pair entries
        self.orders.retain(|_, v| !v.is_empty());
        self.total_count = self.total_count.saturating_sub(removed);
        removed
    }

    /// Total number of active (non-triggered) stop orders.
    pub fn len(&self) -> usize {
        self.total_count
    }

    /// Check if there are no active stop orders.
    pub fn is_empty(&self) -> bool {
        self.total_count == 0
    }

    /// Number of distinct pairs with stop orders.
    pub fn pair_count(&self) -> usize {
        self.orders.len()
    }

    /// Serialize the stop order book to JSON for persistence.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(&self.orders).map_err(|e| e.to_string())
    }

    /// Deserialize the stop order book from JSON, restoring state.
    pub fn from_json(json: &str) -> Result<Self, String> {
        let orders: HashMap<String, Vec<StopOrder>> =
            serde_json::from_str(json).map_err(|e| e.to_string())?;

        let mut total_count = 0usize;
        let mut max_id: StopOrderId = 0;
        for pair_orders in orders.values() {
            for order in pair_orders {
                if !order.triggered {
                    total_count += 1;
                }
                if order.id > max_id {
                    max_id = order.id;
                }
            }
        }

        Ok(StopOrderBook {
            orders,
            next_id: max_id + 1,
            total_count,
        })
    }
}

#[cfg(test)]
impl StopOrderBook {
    /// Cancel a stop order by ID. Returns the removed order if found.
    pub fn cancel(&mut self, id: StopOrderId) -> Option<StopOrder> {
        for orders in self.orders.values_mut() {
            if let Some(pos) = orders.iter().position(|o| o.id == id && !o.triggered) {
                let removed = orders.remove(pos);
                self.total_count = self.total_count.saturating_sub(1);
                return Some(removed);
            }
        }
        None
    }
}

// Persistence

/// Save stop orders to a JSON file (atomic write).
pub fn save_stop_orders(path: &str, book: &StopOrderBook) -> Result<(), String> {
    let json = book.to_json()?;
    let tmp_path = format!("{}.tmp", path);
    std::fs::write(&tmp_path, &json)
        .map_err(|e| format!("Failed to write {}: {}", tmp_path, e))?;
    std::fs::rename(&tmp_path, path)
        .map_err(|e| format!("Failed to rename {} -> {}: {}", tmp_path, path, e))?;
    tracing::info!("[STOP BOOK] Saved {} stop orders to {}", book.len(), path);
    Ok(())
}

/// Load stop orders from a JSON file.
pub fn load_stop_orders(path: &str) -> Result<StopOrderBook, String> {
    let path_ref = std::path::Path::new(path);
    if !path_ref.exists() {
        tracing::info!("[STOP BOOK] No persisted file at {}, starting empty", path);
        return Ok(StopOrderBook::new());
    }
    let json = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path, e))?;
    let book = StopOrderBook::from_json(&json)?;
    tracing::info!(
        "[STOP BOOK] Loaded {} stop orders from {}",
        book.len(),
        path
    );
    Ok(book)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now_unix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn make_stop_order(pair: &str, side: StopSide, stop_num: u64, stop_den: u64) -> StopOrder {
        StopOrder {
            id: 0, // assigned by add()
            pair: pair.to_string(),
            side,
            stop_price_num: stop_num,
            stop_price_den: stop_den,
            order_type: StopOrderType::StopLimit,
            signed_tx_json: r#"{"transaction":{}}"#.to_string(),
            owner_id: "owner_abc".to_string(),
            created_at: now_unix(),
            expires_at: None,
            triggered: false,
            trigger_tx_id: None,
            cancel_secret: None,
        }
    }


    #[test]
    fn sell_stop_triggers_when_price_drops_to_stop() {
        let order = make_stop_order("pair_a", StopSide::Sell, 100, 1);
        // Trade at exactly stop price
        assert!(order.is_triggered(100, 1));
        // Trade below stop price
        assert!(order.is_triggered(90, 1));
        // Trade above stop price: should NOT trigger
        assert!(!order.is_triggered(110, 1));
    }

    #[test]
    fn buy_stop_triggers_when_price_rises_to_stop() {
        let order = make_stop_order("pair_a", StopSide::Buy, 100, 1);
        // Trade at exactly stop price
        assert!(order.is_triggered(100, 1));
        // Trade above stop price
        assert!(order.is_triggered(110, 1));
        // Trade below stop price: should NOT trigger
        assert!(!order.is_triggered(90, 1));
    }

    #[test]
    fn trigger_uses_rational_comparison() {
        // Stop at 1/3, trade at 2/6 (equal) -> should trigger
        let sell_stop = make_stop_order("p", StopSide::Sell, 1, 3);
        assert!(sell_stop.is_triggered(2, 6), "2/6 == 1/3, sell stop should trigger");

        // Stop at 1/3, trade at 1/4 (below) -> sell stop triggers
        assert!(sell_stop.is_triggered(1, 4), "1/4 < 1/3, sell stop should trigger");

        // Stop at 1/3, trade at 1/2 (above) -> sell stop should NOT trigger
        assert!(!sell_stop.is_triggered(1, 2), "1/2 > 1/3, sell stop should not trigger");
    }

    #[test]
    fn already_triggered_order_does_not_retrigger() {
        let mut order = make_stop_order("pair_a", StopSide::Sell, 100, 1);
        order.triggered = true;
        assert!(!order.is_triggered(50, 1), "already triggered order must not re-trigger");
    }

    #[test]
    fn expiry_check() {
        let now = now_unix();
        let mut order = make_stop_order("pair_a", StopSide::Sell, 100, 1);

        // No expiry -> never expires
        assert!(!order.is_expired(now));
        assert!(!order.is_expired(now + 999999));

        // Set expiry in the past
        order.expires_at = Some(now - 10);
        assert!(order.is_expired(now));

        // Set expiry in the future
        order.expires_at = Some(now + 3600);
        assert!(!order.is_expired(now));
        assert!(order.is_expired(now + 3601));
    }


    #[test]
    fn add_and_list() {
        let mut book = StopOrderBook::new();
        let order = make_stop_order("pair_a", StopSide::Sell, 100, 1);
        let id = book.add(order).unwrap();
        assert_eq!(id, 1);
        assert_eq!(book.len(), 1);

        let listed = book.list_by_owner("owner_abc");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, 1);
    }

    #[test]
    fn add_increments_id() {
        let mut book = StopOrderBook::new();
        let id1 = book.add(make_stop_order("p", StopSide::Sell, 100, 1)).unwrap();
        let id2 = book.add(make_stop_order("p", StopSide::Buy, 110, 1)).unwrap();
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
    }

    #[test]
    fn cancel_by_id() {
        let mut book = StopOrderBook::new();
        let id = book.add(make_stop_order("p", StopSide::Sell, 100, 1)).unwrap();
        assert_eq!(book.len(), 1);

        let removed = book.cancel(id);
        assert!(removed.is_some());
        assert_eq!(book.len(), 0);

        // Cancel again -> None
        assert!(book.cancel(id).is_none());
    }

    #[test]
    fn cancel_by_owner_rejects_wrong_owner() {
        let mut book = StopOrderBook::new();
        let id = book.add(make_stop_order("p", StopSide::Sell, 100, 1)).unwrap();

        // Wrong owner
        assert!(book.cancel_by_owner(id, "wrong_owner", None).is_none());
        assert_eq!(book.len(), 1);

        // Correct owner
        assert!(book.cancel_by_owner(id, "owner_abc", None).is_some());
        assert_eq!(book.len(), 0);
    }

    #[test]
    fn get_by_id() {
        let mut book = StopOrderBook::new();
        let id = book.add(make_stop_order("p", StopSide::Sell, 100, 1)).unwrap();

        let order = book.get(id);
        assert!(order.is_some());
        assert_eq!(order.unwrap().stop_price_num, 100);

        assert!(book.get(999).is_none());
    }

    #[test]
    fn list_by_pair() {
        let mut book = StopOrderBook::new();
        book.add(make_stop_order("pair_a", StopSide::Sell, 100, 1)).unwrap();
        book.add(make_stop_order("pair_b", StopSide::Buy, 200, 1)).unwrap();
        book.add(make_stop_order("pair_a", StopSide::Buy, 150, 1)).unwrap();

        assert_eq!(book.list_by_pair("pair_a").len(), 2);
        assert_eq!(book.list_by_pair("pair_b").len(), 1);
        assert_eq!(book.list_by_pair("pair_c").len(), 0);
    }


    #[test]
    fn check_triggers_finds_matching_orders() {
        let mut book = StopOrderBook::new();
        // Sell stop at 100: triggers when price <= 100
        let id1 = book.add(make_stop_order("pair_a", StopSide::Sell, 100, 1)).unwrap();
        // Buy stop at 200: triggers when price >= 200
        let id2 = book.add(make_stop_order("pair_a", StopSide::Buy, 200, 1)).unwrap();
        // Sell stop at 50: triggers when price <= 50
        let id3 = book.add(make_stop_order("pair_a", StopSide::Sell, 50, 1)).unwrap();

        // Trade at 90: sell stop at 100 triggers, buy stop at 200 does not, sell stop at 50 does not
        let triggered = book.check_triggers("pair_a", 90, 1);
        assert_eq!(triggered, vec![id1]);

        // Trade at 210: buy stop at 200 triggers
        let triggered = book.check_triggers("pair_a", 210, 1);
        assert_eq!(triggered, vec![id2]);

        // Trade at 40: both sell stops trigger
        let triggered = book.check_triggers("pair_a", 40, 1);
        assert!(triggered.contains(&id1));
        assert!(triggered.contains(&id3));
        assert_eq!(triggered.len(), 2);
    }

    #[test]
    fn check_triggers_returns_empty_for_unknown_pair() {
        let book = StopOrderBook::new();
        let triggered = book.check_triggers("nonexistent", 100, 1);
        assert!(triggered.is_empty());
    }

    #[test]
    fn mark_triggered_and_cleanup() {
        let mut book = StopOrderBook::new();
        let id = book.add(make_stop_order("pair_a", StopSide::Sell, 100, 1)).unwrap();
        assert_eq!(book.len(), 1);

        book.mark_triggered(id, Some("tx_abc".to_string()));

        // Should not appear in trigger checks anymore
        let triggered = book.check_triggers("pair_a", 50, 1);
        assert!(triggered.is_empty());

        // Cleanup removes triggered orders
        let removed = book.cleanup(now_unix());
        assert_eq!(removed, 1);
        assert_eq!(book.len(), 0);
    }


    #[test]
    fn cleanup_removes_expired() {
        let now = now_unix();
        let mut book = StopOrderBook::new();

        let mut expired_order = make_stop_order("pair_a", StopSide::Sell, 100, 1);
        expired_order.expires_at = Some(now - 10); // already expired
        book.add(expired_order).unwrap();

        let mut live_order = make_stop_order("pair_a", StopSide::Buy, 200, 1);
        live_order.expires_at = Some(now + 3600); // 1 hour from now
        book.add(live_order).unwrap();

        assert_eq!(book.len(), 2);
        let removed = book.cleanup(now);
        assert_eq!(removed, 1);
        assert_eq!(book.len(), 1);
    }

    #[test]
    fn cleanup_removes_empty_pair_entries() {
        let now = now_unix();
        let mut book = StopOrderBook::new();

        let mut order = make_stop_order("pair_a", StopSide::Sell, 100, 1);
        order.expires_at = Some(now - 10);
        book.add(order).unwrap();

        assert_eq!(book.pair_count(), 1);
        book.cleanup(now);
        assert_eq!(book.pair_count(), 0);
    }


    #[test]
    fn global_cap_rejects_excess() {
        let mut book = StopOrderBook::new();
        for i in 0..MAX_TOTAL_STOP_ORDERS {
            let pair = format!("pair_{}", i % 100); // spread across pairs
            let result = book.add(make_stop_order(&pair, StopSide::Sell, (i + 1) as u64, 1));
            assert!(result.is_ok(), "order {} should be accepted", i);
        }
        assert_eq!(book.len(), MAX_TOTAL_STOP_ORDERS);

        let result = book.add(make_stop_order("pair_0", StopSide::Sell, 999, 1));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("stop order limit reached"));
    }

    #[test]
    fn per_pair_cap_rejects_excess() {
        let mut book = StopOrderBook::new();
        for i in 0..MAX_STOP_ORDERS_PER_PAIR {
            let result = book.add(make_stop_order("pair_a", StopSide::Sell, (i + 1) as u64, 1));
            assert!(result.is_ok(), "order {} should be accepted", i);
        }

        let result = book.add(make_stop_order("pair_a", StopSide::Buy, 999, 1));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("stop order limit for pair"));

        // Different pair should still work
        let result = book.add(make_stop_order("pair_b", StopSide::Sell, 100, 1));
        assert!(result.is_ok());
    }

    #[test]
    fn zero_denominator_rejected() {
        let mut book = StopOrderBook::new();
        let result = book.add(make_stop_order("p", StopSide::Sell, 100, 0));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("zero"));
    }


    #[test]
    fn serialize_deserialize_roundtrip() {
        let mut book = StopOrderBook::new();
        book.add(make_stop_order("pair_a", StopSide::Sell, 100, 1)).unwrap();
        book.add(make_stop_order("pair_b", StopSide::Buy, 200, 1)).unwrap();

        let json = book.to_json().unwrap();
        let restored = StopOrderBook::from_json(&json).unwrap();

        assert_eq!(restored.len(), 2);
        assert_eq!(restored.pair_count(), 2);
        // next_id should be max(existing ids) + 1
        assert!(restored.next_id > 2);
    }

    #[test]
    fn save_and_load_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_stop_orders.json");
        let path_str = path.to_str().unwrap();

        let mut book = StopOrderBook::new();
        book.add(make_stop_order("pair_a", StopSide::Sell, 100, 1)).unwrap();

        save_stop_orders(path_str, &book).unwrap();
        let loaded = load_stop_orders(path_str).unwrap();
        assert_eq!(loaded.len(), 1);

        // Cleanup
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_nonexistent_returns_empty() {
        let loaded = load_stop_orders("/tmp/nonexistent_stop_orders_test.json").unwrap();
        assert_eq!(loaded.len(), 0);
    }


    #[test]
    fn list_by_owner_excludes_triggered() {
        let mut book = StopOrderBook::new();
        let id = book.add(make_stop_order("p", StopSide::Sell, 100, 1)).unwrap();
        book.mark_triggered(id, None);

        let listed = book.list_by_owner("owner_abc");
        assert!(listed.is_empty(), "triggered orders should not appear in owner list");
    }

    #[test]
    fn cancel_triggered_order_fails() {
        let mut book = StopOrderBook::new();
        let id = book.add(make_stop_order("p", StopSide::Sell, 100, 1)).unwrap();
        book.mark_triggered(id, None);

        // Cannot cancel a triggered order
        assert!(book.cancel(id).is_none());
    }

    #[test]
    fn multiple_triggers_same_trade() {
        let mut book = StopOrderBook::new();
        // Three sell stops at different prices
        let id1 = book.add(make_stop_order("p", StopSide::Sell, 100, 1)).unwrap();
        let id2 = book.add(make_stop_order("p", StopSide::Sell, 90, 1)).unwrap();
        let id3 = book.add(make_stop_order("p", StopSide::Sell, 80, 1)).unwrap();

        // Trade at 75: all three should trigger
        let triggered = book.check_triggers("p", 75, 1);
        assert_eq!(triggered.len(), 3);
        assert!(triggered.contains(&id1));
        assert!(triggered.contains(&id2));
        assert!(triggered.contains(&id3));
    }

    #[test]
    fn stop_price_f64_display() {
        let order = make_stop_order("p", StopSide::Sell, 3, 4);
        assert!((order.stop_price_f64() - 0.75).abs() < 1e-10);
    }
}
