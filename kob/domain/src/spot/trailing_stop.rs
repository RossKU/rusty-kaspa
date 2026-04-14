//! Trailing stop orders with dynamic stop price tracking.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write as IoWrite};
use tracing::{info, warn};

/// Unique identifier for a trailing stop order.
pub type TrailingStopId = u64;

/// Side of the trailing stop (which direction triggers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrailingStopSide {
    /// Trailing stop sell: triggers when price drops from peak
    Sell,
    /// Trailing stop buy: triggers when price rises from trough
    Buy,
}

/// How the trail distance is specified.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrailSpec {
    /// Absolute trail distance in price units (rational: num/den).
    /// The stop price is peak - amount (sell) or trough + amount (buy).
    Amount { num: u64, den: u64 },
    /// Percentage trail distance. The stop price is
    /// peak * (1 - pct/100) for sell, trough * (1 + pct/100) for buy.
    Percent(f64),
}

/// A trailing stop order managed by the matcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrailingStopOrder {
    /// Unique order ID (assigned by matcher).
    pub id: TrailingStopId,
    /// Trading pair identifier (token_covenant_id, 64-char hex).
    pub pair_id: String,
    /// Buy or sell trailing stop.
    pub side: TrailingStopSide,
    /// Trail specification (absolute or percentage).
    pub trail_spec: TrailSpec,
    /// Pre-signed deploy TX hex to broadcast when triggered.
    pub signed_tx_hex: String,
    /// Peak price observed since order creation (for sell: highest, for buy: lowest).
    /// Stored as rational num/den.
    pub peak_price_num: u64,
    pub peak_price_den: u64,
    /// Current computed stop price (rational num/den).
    pub current_stop_num: u64,
    pub current_stop_den: u64,
    /// Owner identifier (e.g. public key or address) for authentication.
    pub owner_id: String,
    /// DAA score when order was created.
    pub created_at_daa: u64,
    /// Whether this order has been triggered (and TX broadcast attempted).
    pub triggered: bool,
    /// Secret token required for cancellation (not exposed in list responses).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancel_secret: Option<String>,
}

impl TrailingStopOrder {
    /// Create a new trailing stop order.
    ///
    /// `initial_price_num/den` is the current market price at creation time.
    /// The peak_price is initialized to this value, and the stop price is
    /// computed from it.
    pub fn new(
        id: TrailingStopId,
        pair_id: String,
        side: TrailingStopSide,
        trail_spec: TrailSpec,
        signed_tx_hex: String,
        initial_price_num: u64,
        initial_price_den: u64,
        owner_id: String,
        created_at_daa: u64,
    ) -> Self {
        let mut order = TrailingStopOrder {
            id,
            pair_id,
            side,
            trail_spec,
            signed_tx_hex,
            peak_price_num: initial_price_num,
            peak_price_den: initial_price_den,
            current_stop_num: 0,
            current_stop_den: 1,
            owner_id,
            created_at_daa,
            triggered: false,
            cancel_secret: None,
        };
        order.recalculate_stop_price();
        order
    }

    /// Recalculate `current_stop_num/den` from `peak_price` and `trail_spec`.
    fn recalculate_stop_price(&mut self) {
        let (stop_num, stop_den) = compute_stop_price(
            self.side,
            self.peak_price_num,
            self.peak_price_den,
            &self.trail_spec,
        );
        self.current_stop_num = stop_num;
        self.current_stop_den = stop_den;
    }

    /// Update peak price with a new market price observation.
    /// Returns `true` if the peak price was updated (and stop price recalculated).
    pub fn update_peak(&mut self, price_num: u64, price_den: u64) -> bool {
        if self.triggered {
            return false;
        }

        let should_update = match self.side {
            TrailingStopSide::Sell => {
                // For sell: peak is the highest observed price
                // Compare: price_num/price_den > peak_num/peak_den
                // => price_num * peak_den > peak_num * price_den
                (price_num as u128) * (self.peak_price_den as u128)
                    > (self.peak_price_num as u128) * (price_den as u128)
            }
            TrailingStopSide::Buy => {
                // For buy: peak is the lowest observed price (trough)
                // Compare: price_num/price_den < peak_num/peak_den
                (price_num as u128) * (self.peak_price_den as u128)
                    < (self.peak_price_num as u128) * (price_den as u128)
            }
        };

        if should_update {
            self.peak_price_num = price_num;
            self.peak_price_den = price_den;
            self.recalculate_stop_price();
            true
        } else {
            false
        }
    }

    /// Check if the current market price triggers this trailing stop.
    /// Returns `true` if the order should be triggered.
    pub fn should_trigger(&self, price_num: u64, price_den: u64) -> bool {
        if self.triggered {
            return false;
        }

        match self.side {
            TrailingStopSide::Sell => {
                // Trigger when price <= stop price
                // price_num/price_den <= stop_num/stop_den
                // => price_num * stop_den <= stop_num * price_den
                (price_num as u128) * (self.current_stop_den as u128)
                    <= (self.current_stop_num as u128) * (price_den as u128)
            }
            TrailingStopSide::Buy => {
                // Trigger when price >= stop price
                // price_num/price_den >= stop_num/stop_den
                // => price_num * stop_den >= stop_num * price_den
                (price_num as u128) * (self.current_stop_den as u128)
                    >= (self.current_stop_num as u128) * (price_den as u128)
            }
        }
    }
}

/// Compute the stop price given a peak/trough price and trail specification.
///
/// Returns (stop_num, stop_den) as a rational number.
/// For sell: stop = peak - trail
/// For buy:  stop = peak + trail (where peak is the trough)
///
/// Stop price is clamped to a minimum of 0 (stop_num = 0) for sell trailing stops.
pub fn compute_stop_price(
    side: TrailingStopSide,
    peak_num: u64,
    peak_den: u64,
    trail_spec: &TrailSpec,
) -> (u64, u64) {
    match trail_spec {
        TrailSpec::Amount { num: trail_num, den: trail_den } => {
            // For sell: stop = peak - trail
            //   stop_num/stop_den = peak_num/peak_den - trail_num/trail_den
            //   = (peak_num * trail_den - trail_num * peak_den) / (peak_den * trail_den)
            // For buy: stop = peak + trail
            //   = (peak_num * trail_den + trail_num * peak_den) / (peak_den * trail_den)
            let common_den = (peak_den as u128) * (*trail_den as u128);
            let peak_scaled = (peak_num as u128) * (*trail_den as u128);
            let trail_scaled = (*trail_num as u128) * (peak_den as u128);

            let stop_num_128 = match side {
                TrailingStopSide::Sell => {
                    peak_scaled.saturating_sub(trail_scaled)
                }
                TrailingStopSide::Buy => {
                    peak_scaled + trail_scaled
                }
            };

            // Reduce the fraction by GCD to keep values manageable
            let g = gcd_u128(stop_num_128, common_den);
            let stop_num = match u64::try_from(stop_num_128 / g) {
                Ok(v) => v,
                Err(_) => return (u64::MAX, 1), // overflow: clamp to max price
            };
            let stop_den = match u64::try_from(common_den / g) {
                Ok(v) => v,
                Err(_) => return (u64::MAX, 1), // overflow: clamp to max price
            };

            (stop_num, stop_den)
        }
        TrailSpec::Percent(pct) => {
            // For sell: stop = peak * (1 - pct/100) = peak * (100 - pct) / 100
            // For buy:  stop = peak * (1 + pct/100) = peak * (100 + pct) / 100
            //
            // To stay in integer arithmetic, multiply peak_num by the factor
            // and peak_den by 10000 (for 2 decimal places of precision).
            let pct_basis = (pct * 100.0).round() as u128; // pct in basis points (0.01%)
            let peak_n = peak_num as u128;
            let peak_d = peak_den as u128;

            let (stop_n_128, stop_d_128) = match side {
                TrailingStopSide::Sell => {
                    if pct_basis >= 10000 {
                        // Trail >= 100%, stop is 0
                        (0u128, 1u128)
                    } else {
                        let factor = 10000u128 - pct_basis;
                        (peak_n * factor, peak_d * 10000u128)
                    }
                }
                TrailingStopSide::Buy => {
                    let factor = 10000u128 + pct_basis;
                    (peak_n * factor, peak_d * 10000u128)
                }
            };

            let g = gcd_u128(stop_n_128, stop_d_128);
            let stop_num = match u64::try_from(stop_n_128 / g) {
                Ok(v) => v,
                Err(_) => return (u64::MAX, 1), // overflow: clamp to max price
            };
            let stop_den = match u64::try_from(stop_d_128 / g) {
                Ok(v) => v,
                Err(_) => return (u64::MAX, 1), // overflow: clamp to max price
            };

            (stop_num, stop_den)
        }
    }
}

fn gcd_u128(a: u128, b: u128) -> u128 {
    if b == 0 { if a == 0 { 1 } else { a } } else { gcd_u128(b, a % b) }
}

// Trailing Stop Book — manages all trailing stop orders for all pairs

/// Maximum number of trailing stop orders allowed.
pub const MAX_TRAILING_STOPS: usize = 1_000;

/// Manages all trailing stop orders across all pairs.
pub struct TrailingStopBook {
    /// All orders indexed by ID.
    orders: HashMap<TrailingStopId, TrailingStopOrder>,
    /// Pair index: pair_id -> set of order IDs for that pair.
    by_pair: HashMap<String, Vec<TrailingStopId>>,
    /// Next ID to assign.
    next_id: TrailingStopId,
    /// Optional persistence file path.
    file_path: Option<String>,
}

impl Default for TrailingStopBook {
    fn default() -> Self {
        TrailingStopBook {
            orders: HashMap::new(),
            by_pair: HashMap::new(),
            next_id: 1,
            file_path: None,
        }
    }
}

impl TrailingStopBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a trailing stop book with file-backed persistence.
    /// Loads existing orders from the file on startup.
    pub fn new_with_file(path: &str) -> Self {
        let mut book = Self::new();
        book.file_path = Some(path.to_string());

        // Load existing orders
        if let Ok(file) = File::open(path) {
            let reader = BufReader::new(file);
            let mut max_id: TrailingStopId = 0;
            for text in reader.lines().map_while(Result::ok) {
                    let text = text.trim();
                    if text.is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<TrailingStopOrder>(text) {
                        Ok(order) => {
                            if order.id >= max_id {
                                max_id = order.id + 1;
                            }
                            if !order.triggered {
                                let pair_id = order.pair_id.clone();
                                let id = order.id;
                                book.orders.insert(id, order);
                                book.by_pair.entry(pair_id).or_default().push(id);
                            }
                        }
                        Err(e) => {
                            warn!("[TRAILING STOP] Corrupt line in {}: {}", path, e);
                        }
                    }
            }
            book.next_id = max_id;
            info!(
                "[TRAILING STOP] Loaded {} active orders from {}",
                book.orders.len(),
                path,
            );
        }

        book
    }

    /// Add a new trailing stop order. Returns the assigned ID, or None if at capacity.
    pub fn add(
        &mut self,
        pair_id: String,
        side: TrailingStopSide,
        trail_spec: TrailSpec,
        signed_tx_hex: String,
        initial_price_num: u64,
        initial_price_den: u64,
        owner_id: String,
        created_at_daa: u64,
    ) -> Option<TrailingStopId> {
        if self.orders.len() >= MAX_TRAILING_STOPS {
            warn!(
                "[TRAILING STOP] Capacity reached ({}/{}), rejecting order",
                self.orders.len(),
                MAX_TRAILING_STOPS,
            );
            return None;
        }

        // Validate trail spec
        match &trail_spec {
            TrailSpec::Amount { num, den } => {
                if *num == 0 || *den == 0 {
                    warn!("[TRAILING STOP] Invalid trail amount: {}/{}", num, den);
                    return None;
                }
            }
            TrailSpec::Percent(pct) => {
                if *pct <= 0.0 || *pct > 99.0 {
                    warn!("[TRAILING STOP] Invalid trail percent: {}%", pct);
                    return None;
                }
            }
        }

        if initial_price_den == 0 {
            warn!("[TRAILING STOP] Invalid initial price denominator (zero)");
            return None;
        }

        let id = self.next_id;
        self.next_id += 1;

        let order = TrailingStopOrder::new(
            id,
            pair_id.clone(),
            side,
            trail_spec,
            signed_tx_hex,
            initial_price_num,
            initial_price_den,
            owner_id,
            created_at_daa,
        );

        info!(
            "[TRAILING STOP] Added {} #{} for pair [{}...]: trail={:?}, stop={}/{}, peak={}/{}",
            match side {
                TrailingStopSide::Sell => "SELL",
                TrailingStopSide::Buy => "BUY",
            },
            id,
            &pair_id[..pair_id.len().min(12)],
            trail_spec,
            order.current_stop_num,
            order.current_stop_den,
            order.peak_price_num,
            order.peak_price_den,
        );

        self.persist_order(&order);
        self.orders.insert(id, order);
        self.by_pair.entry(pair_id).or_default().push(id);

        Some(id)
    }

    /// Remove a trailing stop order by ID. Returns the removed order if found.
    pub fn remove(&mut self, id: TrailingStopId) -> Option<TrailingStopOrder> {
        if let Some(order) = self.orders.remove(&id) {
            if let Some(ids) = self.by_pair.get_mut(&order.pair_id) {
                ids.retain(|&oid| oid != id);
                if ids.is_empty() {
                    self.by_pair.remove(&order.pair_id);
                }
            }
            info!("[TRAILING STOP] Removed #{}", id);
            Some(order)
        } else {
            None
        }
    }

    /// Remove a trailing stop order by ID, only if owner and cancel_secret match.
    /// Returns the removed order if found and auth passes, None otherwise.
    pub fn remove_by_owner(&mut self, id: TrailingStopId, owner_id: &str, cancel_secret: Option<&str>) -> Option<TrailingStopOrder> {
        // Check owner and cancel_secret before removing
        if let Some(order) = self.orders.get(&id) {
            if order.owner_id != owner_id {
                warn!("[TRAILING STOP] Cancel #{} rejected: owner mismatch", id);
                return None;
            }
            match (&order.cancel_secret, cancel_secret) {
                (Some(stored), Some(provided)) if stored != provided => {
                    warn!("[TRAILING STOP] Cancel #{} rejected: wrong cancel_secret", id);
                    return None;
                }
                (Some(_), None) => {
                    warn!("[TRAILING STOP] Cancel #{} rejected: cancel_secret required", id);
                    return None;
                }
                _ => {} // OK: either no secret stored (legacy) or secrets match
            }
        } else {
            return None;
        }
        self.remove(id)
    }

    /// List all active (non-triggered) orders.
    pub fn list_active(&self) -> Vec<&TrailingStopOrder> {
        self.orders.values().filter(|o| !o.triggered).collect()
    }

    /// Process a new trade price. Updates peak prices and checks triggers.
    ///
    /// Returns a list of (order_id, signed_tx_hex) for orders that should be
    /// triggered (TX broadcast to L1). These orders are marked as triggered
    /// and will be cleaned up on the next persistence save.
    pub fn on_price_update(
        &mut self,
        pair_id: &str,
        price_num: u64,
        price_den: u64,
    ) -> Vec<(TrailingStopId, String)> {
        let ids = match self.by_pair.get(pair_id) {
            Some(ids) => ids.clone(),
            None => return Vec::new(),
        };

        let mut triggered = Vec::new();

        for id in &ids {
            if let Some(order) = self.orders.get_mut(id) {
                if order.triggered {
                    continue;
                }

                // First, update the peak price (which may adjust stop price upward)
                let peak_updated = order.update_peak(price_num, price_den);

                // Then check if this price triggers the stop
                if order.should_trigger(price_num, price_den) {
                    info!(
                        "[TRAILING STOP] TRIGGERED #{} ({:?}) at price {}/{}, stop was {}/{}",
                        order.id,
                        order.side,
                        price_num,
                        price_den,
                        order.current_stop_num,
                        order.current_stop_den,
                    );
                    order.triggered = true;
                    triggered.push((*id, order.signed_tx_hex.clone()));
                } else if peak_updated {
                    info!(
                        "[TRAILING STOP] #{} peak updated to {}/{}, new stop {}/{}",
                        order.id,
                        order.peak_price_num,
                        order.peak_price_den,
                        order.current_stop_num,
                        order.current_stop_den,
                    );
                }
            }
        }

        // Clean up triggered orders from the pair index
        if !triggered.is_empty() {
            if let Some(ids) = self.by_pair.get_mut(pair_id) {
                let triggered_ids: std::collections::HashSet<_> =
                    triggered.iter().map(|(id, _)| *id).collect();
                ids.retain(|id| !triggered_ids.contains(id));
                if ids.is_empty() {
                    self.by_pair.remove(pair_id);
                }
            }
            // Remove triggered orders from the main map
            for (id, _) in &triggered {
                self.orders.remove(id);
            }
        }

        triggered
    }

    /// Total number of active (non-triggered) orders.
    pub fn len(&self) -> usize {
        self.orders.len()
    }

    pub fn is_empty(&self) -> bool {
        self.orders.is_empty()
    }

    /// Persist a single order to the file (append).
    fn persist_order(&self, order: &TrailingStopOrder) {
        if let Some(ref path) = self.file_path {
            match OpenOptions::new().create(true).append(true).open(path) {
                Ok(mut file) => {
                    if let Ok(json) = serde_json::to_string(order) {
                        if let Err(e) = writeln!(file, "{}", json) {
                            warn!("[TRAILING STOP] Failed to persist order: {}", e);
                        }
                    }
                }
                Err(e) => {
                    warn!("[TRAILING STOP] Failed to open persistence file: {}", e);
                }
            }
        }
    }

    /// Save full state (overwrite). Called on shutdown for crash recovery.
    pub fn save_full(&self, path: &str) -> Result<(), String> {
        let active: Vec<&TrailingStopOrder> = self.orders.values().filter(|o| !o.triggered).collect();

        let json_lines: Vec<String> = active
            .iter()
            .filter_map(|o| serde_json::to_string(o).ok())
            .collect();

        std::fs::write(path, json_lines.join("\n") + "\n")
            .map_err(|e| format!("Failed to save trailing stops: {}", e))?;

        info!(
            "[TRAILING STOP] Saved {} active orders to {}",
            active.len(),
            path,
        );

        Ok(())
    }
}

impl TrailingStopBook {
    /// Get an order by ID.
    pub fn get(&self, id: TrailingStopId) -> Option<&TrailingStopOrder> {
        self.orders.get(&id)
    }

    /// Get mutable reference to a trailing stop order by ID.
    pub fn get_mut(&mut self, id: TrailingStopId) -> Option<&mut TrailingStopOrder> {
        self.orders.get_mut(&id)
    }

    /// List active orders for a specific pair.
    pub fn list_for_pair(&self, pair_id: &str) -> Vec<&TrailingStopOrder> {
        match self.by_pair.get(pair_id) {
            Some(ids) => ids
                .iter()
                .filter_map(|id| self.orders.get(id))
                .filter(|o| !o.triggered)
                .collect(),
            None => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // compute_stop_price tests

    #[test]
    fn test_stop_price_sell_absolute() {
        // Peak = 100/1, trail = 10/1 => stop = 90/1
        let (num, den) = compute_stop_price(
            TrailingStopSide::Sell,
            100, 1,
            &TrailSpec::Amount { num: 10, den: 1 },
        );
        // 90/1 = stop_num/stop_den
        assert_eq!(num as f64 / den as f64, 90.0);
    }

    #[test]
    fn test_stop_price_buy_absolute() {
        // Trough = 100/1, trail = 10/1 => stop = 110/1
        let (num, den) = compute_stop_price(
            TrailingStopSide::Buy,
            100, 1,
            &TrailSpec::Amount { num: 10, den: 1 },
        );
        assert_eq!(num as f64 / den as f64, 110.0);
    }

    #[test]
    fn test_stop_price_sell_percent() {
        // Peak = 200/1, trail = 5% => stop = 200 * 0.95 = 190
        let (num, den) = compute_stop_price(
            TrailingStopSide::Sell,
            200, 1,
            &TrailSpec::Percent(5.0),
        );
        let stop = num as f64 / den as f64;
        assert!((stop - 190.0).abs() < 0.01, "Expected 190, got {}", stop);
    }

    #[test]
    fn test_stop_price_buy_percent() {
        // Trough = 200/1, trail = 5% => stop = 200 * 1.05 = 210
        let (num, den) = compute_stop_price(
            TrailingStopSide::Buy,
            200, 1,
            &TrailSpec::Percent(5.0),
        );
        let stop = num as f64 / den as f64;
        assert!((stop - 210.0).abs() < 0.01, "Expected 210, got {}", stop);
    }

    #[test]
    fn test_stop_price_sell_clamp_zero() {
        // Peak = 5/1, trail = 10/1 => stop would be -5, clamped to 0
        let (num, _den) = compute_stop_price(
            TrailingStopSide::Sell,
            5, 1,
            &TrailSpec::Amount { num: 10, den: 1 },
        );
        assert_eq!(num, 0);
    }

    #[test]
    fn test_stop_price_rational_fractions() {
        // Peak = 3/2 (1.5), trail = 1/4 (0.25) => stop = 1.25 = 5/4
        let (num, den) = compute_stop_price(
            TrailingStopSide::Sell,
            3, 2,
            &TrailSpec::Amount { num: 1, den: 4 },
        );
        let stop = num as f64 / den as f64;
        assert!((stop - 1.25).abs() < 0.0001, "Expected 1.25, got {}", stop);
    }

    #[test]
    fn test_stop_price_percent_100() {
        // 100% trail for sell => stop = 0
        let (num, _den) = compute_stop_price(
            TrailingStopSide::Sell,
            100, 1,
            &TrailSpec::Percent(100.0),
        );
        assert_eq!(num, 0);
    }

    // TrailingStopOrder peak update tests

    #[test]
    fn test_sell_peak_rises() {
        let mut order = TrailingStopOrder::new(
            1, "pair1".into(), TrailingStopSide::Sell,
            TrailSpec::Amount { num: 10, den: 1 },
            "tx_hex".into(), 100, 1, "test_owner".into(), 0,
        );
        // Initial stop = 90
        assert_eq!(order.current_stop_num as f64 / order.current_stop_den as f64, 90.0);

        // Price rises to 120 => peak=120, stop=110
        assert!(order.update_peak(120, 1));
        assert_eq!(order.peak_price_num, 120);
        let stop = order.current_stop_num as f64 / order.current_stop_den as f64;
        assert!((stop - 110.0).abs() < 0.01);
    }

    #[test]
    fn test_sell_peak_does_not_drop() {
        let mut order = TrailingStopOrder::new(
            1, "pair1".into(), TrailingStopSide::Sell,
            TrailSpec::Amount { num: 10, den: 1 },
            "tx_hex".into(), 100, 1, "test_owner".into(), 0,
        );
        // Price drops to 95 => peak stays 100, stop stays 90
        assert!(!order.update_peak(95, 1));
        assert_eq!(order.peak_price_num, 100);
    }

    #[test]
    fn test_buy_trough_falls() {
        let mut order = TrailingStopOrder::new(
            1, "pair1".into(), TrailingStopSide::Buy,
            TrailSpec::Amount { num: 10, den: 1 },
            "tx_hex".into(), 100, 1, "test_owner".into(), 0,
        );
        // Initial stop = 110
        let stop = order.current_stop_num as f64 / order.current_stop_den as f64;
        assert!((stop - 110.0).abs() < 0.01);

        // Price drops to 80 => trough=80, stop=90
        assert!(order.update_peak(80, 1));
        assert_eq!(order.peak_price_num, 80);
        let stop = order.current_stop_num as f64 / order.current_stop_den as f64;
        assert!((stop - 90.0).abs() < 0.01);
    }

    #[test]
    fn test_buy_trough_does_not_rise() {
        let mut order = TrailingStopOrder::new(
            1, "pair1".into(), TrailingStopSide::Buy,
            TrailSpec::Amount { num: 10, den: 1 },
            "tx_hex".into(), 100, 1, "test_owner".into(), 0,
        );
        // Price rises to 105 => trough stays 100
        assert!(!order.update_peak(105, 1));
        assert_eq!(order.peak_price_num, 100);
    }

    // Trigger condition tests

    #[test]
    fn test_sell_trigger_at_stop() {
        let order = TrailingStopOrder::new(
            1, "pair1".into(), TrailingStopSide::Sell,
            TrailSpec::Amount { num: 10, den: 1 },
            "tx_hex".into(), 100, 1, "test_owner".into(), 0,
        );
        // Stop = 90. Price at 90 should trigger
        assert!(order.should_trigger(90, 1));
    }

    #[test]
    fn test_sell_trigger_below_stop() {
        let order = TrailingStopOrder::new(
            1, "pair1".into(), TrailingStopSide::Sell,
            TrailSpec::Amount { num: 10, den: 1 },
            "tx_hex".into(), 100, 1, "test_owner".into(), 0,
        );
        // Stop = 90. Price at 85 should trigger
        assert!(order.should_trigger(85, 1));
    }

    #[test]
    fn test_sell_no_trigger_above_stop() {
        let order = TrailingStopOrder::new(
            1, "pair1".into(), TrailingStopSide::Sell,
            TrailSpec::Amount { num: 10, den: 1 },
            "tx_hex".into(), 100, 1, "test_owner".into(), 0,
        );
        // Stop = 90. Price at 95 should NOT trigger
        assert!(!order.should_trigger(95, 1));
    }

    #[test]
    fn test_buy_trigger_at_stop() {
        let order = TrailingStopOrder::new(
            1, "pair1".into(), TrailingStopSide::Buy,
            TrailSpec::Amount { num: 10, den: 1 },
            "tx_hex".into(), 100, 1, "test_owner".into(), 0,
        );
        // Stop = 110. Price at 110 should trigger
        assert!(order.should_trigger(110, 1));
    }

    #[test]
    fn test_buy_trigger_above_stop() {
        let order = TrailingStopOrder::new(
            1, "pair1".into(), TrailingStopSide::Buy,
            TrailSpec::Amount { num: 10, den: 1 },
            "tx_hex".into(), 100, 1, "test_owner".into(), 0,
        );
        // Stop = 110. Price at 115 should trigger
        assert!(order.should_trigger(115, 1));
    }

    #[test]
    fn test_buy_no_trigger_below_stop() {
        let order = TrailingStopOrder::new(
            1, "pair1".into(), TrailingStopSide::Buy,
            TrailSpec::Amount { num: 10, den: 1 },
            "tx_hex".into(), 100, 1, "test_owner".into(), 0,
        );
        // Stop = 110. Price at 105 should NOT trigger
        assert!(!order.should_trigger(105, 1));
    }

    #[test]
    fn test_triggered_order_ignores_updates() {
        let mut order = TrailingStopOrder::new(
            1, "pair1".into(), TrailingStopSide::Sell,
            TrailSpec::Amount { num: 10, den: 1 },
            "tx_hex".into(), 100, 1, "test_owner".into(), 0,
        );
        order.triggered = true;
        assert!(!order.update_peak(200, 1));
        assert!(!order.should_trigger(0, 1));
    }

    // TrailingStopBook tests

    #[test]
    fn test_book_add_and_list() {
        let mut book = TrailingStopBook::new();
        let id = book.add(
            "pair1".into(), TrailingStopSide::Sell,
            TrailSpec::Amount { num: 10, den: 1 },
            "tx1".into(), 100, 1, "test_owner".into(), 0,
        );
        assert!(id.is_some());
        assert_eq!(book.len(), 1);
        assert_eq!(book.list_active().len(), 1);
        assert_eq!(book.list_for_pair("pair1").len(), 1);
        assert_eq!(book.list_for_pair("pair2").len(), 0);
    }

    #[test]
    fn test_book_remove() {
        let mut book = TrailingStopBook::new();
        let id = book.add(
            "pair1".into(), TrailingStopSide::Sell,
            TrailSpec::Amount { num: 10, den: 1 },
            "tx1".into(), 100, 1, "test_owner".into(), 0,
        ).unwrap();

        let removed = book.remove(id);
        assert!(removed.is_some());
        assert_eq!(book.len(), 0);
        assert!(book.list_for_pair("pair1").is_empty());
    }

    #[test]
    fn test_book_remove_by_owner() {
        let mut book = TrailingStopBook::new();
        let id = book.add(
            "pair1".into(), TrailingStopSide::Sell,
            TrailSpec::Amount { num: 10, den: 1 },
            "tx1".into(), 100, 1, "owner_abc".into(), 0,
        ).unwrap();

        // Wrong owner => rejected
        assert!(book.remove_by_owner(id, "wrong_owner", None).is_none());
        assert_eq!(book.len(), 1); // still present

        // Correct owner => removed
        assert!(book.remove_by_owner(id, "owner_abc", None).is_some());
        assert_eq!(book.len(), 0);
    }

    #[test]
    fn test_book_remove_nonexistent() {
        let mut book = TrailingStopBook::new();
        assert!(book.remove(999).is_none());
    }

    #[test]
    fn test_book_capacity_limit() {
        let mut book = TrailingStopBook::new();
        for i in 0..MAX_TRAILING_STOPS {
            assert!(book.add(
                format!("pair{}", i), TrailingStopSide::Sell,
                TrailSpec::Amount { num: 1, den: 1 },
                format!("tx{}", i), 100, 1, "test_owner".into(), 0,
            ).is_some());
        }
        // Next add should fail
        assert!(book.add(
            "overflow".into(), TrailingStopSide::Sell,
            TrailSpec::Amount { num: 1, den: 1 },
            "tx_overflow".into(), 100, 1, "test_owner".into(), 0,
        ).is_none());
    }

    #[test]
    fn test_book_price_update_triggers() {
        let mut book = TrailingStopBook::new();
        book.add(
            "pair1".into(), TrailingStopSide::Sell,
            TrailSpec::Amount { num: 10, den: 1 },
            "signed_tx_hex_1".into(), 100, 1, "test_owner".into(), 0,
        );

        // Price stays above stop (90) => no trigger
        let t = book.on_price_update("pair1", 95, 1);
        assert!(t.is_empty());

        // Price drops to 90 => trigger
        let t = book.on_price_update("pair1", 90, 1);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].1, "signed_tx_hex_1");

        // Order should be removed after trigger
        assert_eq!(book.len(), 0);
    }

    #[test]
    fn test_book_price_update_moves_stop() {
        let mut book = TrailingStopBook::new();
        let id = book.add(
            "pair1".into(), TrailingStopSide::Sell,
            TrailSpec::Amount { num: 10, den: 1 },
            "tx1".into(), 100, 1, "test_owner".into(), 0,
        ).unwrap();

        // Price rises to 120 => peak=120, stop=110
        let t = book.on_price_update("pair1", 120, 1);
        assert!(t.is_empty());

        let order = book.get(id).unwrap();
        assert_eq!(order.peak_price_num, 120);
        let stop = order.current_stop_num as f64 / order.current_stop_den as f64;
        assert!((stop - 110.0).abs() < 0.01);

        // Price drops to 110 => trigger
        let t = book.on_price_update("pair1", 110, 1);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn test_book_multiple_orders_same_pair() {
        let mut book = TrailingStopBook::new();
        book.add(
            "pair1".into(), TrailingStopSide::Sell,
            TrailSpec::Amount { num: 10, den: 1 },
            "tx1".into(), 100, 1, "test_owner".into(), 0,
        );
        book.add(
            "pair1".into(), TrailingStopSide::Sell,
            TrailSpec::Amount { num: 20, den: 1 },
            "tx2".into(), 100, 1, "test_owner".into(), 0,
        );

        assert_eq!(book.len(), 2);

        // Price drops to 85 => both trigger (stop1=90, stop2=80 — only first triggers)
        let t = book.on_price_update("pair1", 85, 1);
        assert_eq!(t.len(), 1); // Only stop at 90 triggers

        // Price drops to 75 => second triggers
        let t = book.on_price_update("pair1", 75, 1);
        assert_eq!(t.len(), 1);

        assert_eq!(book.len(), 0);
    }

    #[test]
    fn test_book_different_pairs_independent() {
        let mut book = TrailingStopBook::new();
        book.add(
            "pair1".into(), TrailingStopSide::Sell,
            TrailSpec::Amount { num: 10, den: 1 },
            "tx1".into(), 100, 1, "test_owner".into(), 0,
        );
        book.add(
            "pair2".into(), TrailingStopSide::Sell,
            TrailSpec::Amount { num: 10, den: 1 },
            "tx2".into(), 100, 1, "test_owner".into(), 0,
        );

        // Price update for pair1 only affects pair1
        let t = book.on_price_update("pair1", 85, 1);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].1, "tx1");

        // pair2 unaffected
        assert_eq!(book.list_for_pair("pair2").len(), 1);
    }

    // Edge cases and stress tests

    #[test]
    fn test_price_gap_down_triggers_immediately() {
        // Simulates a flash crash: price jumps from 100 to 50
        let mut book = TrailingStopBook::new();
        book.add(
            "pair1".into(), TrailingStopSide::Sell,
            TrailSpec::Amount { num: 5, den: 1 },
            "tx1".into(), 100, 1, "test_owner".into(), 0,
        );
        // Stop = 95. Price gaps to 50 => triggers
        let t = book.on_price_update("pair1", 50, 1);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn test_price_gap_up_triggers_buy() {
        // Price jumps from 100 to 200
        let mut book = TrailingStopBook::new();
        book.add(
            "pair1".into(), TrailingStopSide::Buy,
            TrailSpec::Amount { num: 5, den: 1 },
            "tx1".into(), 100, 1, "test_owner".into(), 0,
        );
        // Stop = 105. Price gaps to 200 => triggers
        let t = book.on_price_update("pair1", 200, 1);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn test_rapid_reversals_sell() {
        // Price zigzags: 100 -> 105 -> 95 -> 110 -> 99
        let mut book = TrailingStopBook::new();
        book.add(
            "pair1".into(), TrailingStopSide::Sell,
            TrailSpec::Amount { num: 10, den: 1 },
            "tx1".into(), 100, 1, "test_owner".into(), 0,
        );

        // 105: peak moves to 105, stop=95
        let t = book.on_price_update("pair1", 105, 1);
        assert!(t.is_empty());

        // 95: exactly at stop=95, triggers
        let t = book.on_price_update("pair1", 95, 1);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn test_rapid_reversals_no_trigger() {
        // Price zigzags but never hits stop
        let mut book = TrailingStopBook::new();
        book.add(
            "pair1".into(), TrailingStopSide::Sell,
            TrailSpec::Amount { num: 10, den: 1 },
            "tx1".into(), 100, 1, "test_owner".into(), 0,
        );

        // 105: peak=105, stop=95
        let t = book.on_price_update("pair1", 105, 1);
        assert!(t.is_empty());

        // 96: above stop (95), no trigger
        let t = book.on_price_update("pair1", 96, 1);
        assert!(t.is_empty());

        // 110: peak=110, stop=100
        let t = book.on_price_update("pair1", 110, 1);
        assert!(t.is_empty());

        // 101: above stop (100), no trigger
        let t = book.on_price_update("pair1", 101, 1);
        assert!(t.is_empty());

        assert_eq!(book.len(), 1);
    }

    #[test]
    fn test_percent_trailing_stop_lifecycle() {
        let mut book = TrailingStopBook::new();
        book.add(
            "pair1".into(), TrailingStopSide::Sell,
            TrailSpec::Percent(10.0),
            "tx1".into(), 100, 1, "test_owner".into(), 0,
        );
        // Stop = 90 (100 * 0.90)
        let id = 1;
        let order = book.get(id).unwrap();
        let stop = order.current_stop_num as f64 / order.current_stop_den as f64;
        assert!((stop - 90.0).abs() < 0.01);

        // Price rises to 200 => stop = 180
        book.on_price_update("pair1", 200, 1);
        let order = book.get(id).unwrap();
        let stop = order.current_stop_num as f64 / order.current_stop_den as f64;
        assert!((stop - 180.0).abs() < 0.01);

        // Price drops to 180 => trigger
        let t = book.on_price_update("pair1", 180, 1);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn test_invalid_trail_amount_zero() {
        let mut book = TrailingStopBook::new();
        let id = book.add(
            "pair1".into(), TrailingStopSide::Sell,
            TrailSpec::Amount { num: 0, den: 1 },
            "tx1".into(), 100, 1, "test_owner".into(), 0,
        );
        assert!(id.is_none());
    }

    #[test]
    fn test_invalid_trail_percent_zero() {
        let mut book = TrailingStopBook::new();
        let id = book.add(
            "pair1".into(), TrailingStopSide::Sell,
            TrailSpec::Percent(0.0),
            "tx1".into(), 100, 1, "test_owner".into(), 0,
        );
        assert!(id.is_none());
    }

    #[test]
    fn test_invalid_trail_percent_over_99() {
        let mut book = TrailingStopBook::new();
        let id = book.add(
            "pair1".into(), TrailingStopSide::Sell,
            TrailSpec::Percent(99.5),
            "tx1".into(), 100, 1, "test_owner".into(), 0,
        );
        assert!(id.is_none());
    }

    #[test]
    fn test_invalid_price_den_zero() {
        let mut book = TrailingStopBook::new();
        let id = book.add(
            "pair1".into(), TrailingStopSide::Sell,
            TrailSpec::Amount { num: 10, den: 1 },
            "tx1".into(), 100, 0, "test_owner".into(), 0,
        );
        assert!(id.is_none());
    }

    #[test]
    fn test_price_update_nonexistent_pair() {
        let mut book = TrailingStopBook::new();
        let t = book.on_price_update("nonexistent", 100, 1);
        assert!(t.is_empty());
    }

    #[test]
    fn test_simultaneous_trigger_multiple_orders() {
        // Both orders trigger at same price
        let mut book = TrailingStopBook::new();
        book.add(
            "pair1".into(), TrailingStopSide::Sell,
            TrailSpec::Amount { num: 10, den: 1 },
            "tx1".into(), 100, 1, "test_owner".into(), 0,
        );
        book.add(
            "pair1".into(), TrailingStopSide::Sell,
            TrailSpec::Amount { num: 15, den: 1 },
            "tx2".into(), 100, 1, "test_owner".into(), 0,
        );
        // stop1=90, stop2=85. Price=80 triggers both
        let t = book.on_price_update("pair1", 80, 1);
        assert_eq!(t.len(), 2);
        assert_eq!(book.len(), 0);
    }

    #[test]
    fn test_buy_trailing_stop_full_lifecycle() {
        let mut book = TrailingStopBook::new();
        book.add(
            "pair1".into(), TrailingStopSide::Buy,
            TrailSpec::Percent(5.0),
            "buy_tx".into(), 100, 1, "test_owner".into(), 0,
        );

        // Stop = 105 (100 * 1.05)
        let id = 1;
        let order = book.get(id).unwrap();
        let stop = order.current_stop_num as f64 / order.current_stop_den as f64;
        assert!((stop - 105.0).abs() < 0.01);

        // Price drops to 80 => trough=80, stop=84
        book.on_price_update("pair1", 80, 1);
        let order = book.get(id).unwrap();
        let stop = order.current_stop_num as f64 / order.current_stop_den as f64;
        assert!((stop - 84.0).abs() < 0.01);

        // Price rises to 83 => no trigger (below 84)
        let t = book.on_price_update("pair1", 83, 1);
        assert!(t.is_empty());

        // Price rises to 84 => trigger
        let t = book.on_price_update("pair1", 84, 1);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].1, "buy_tx");
    }

    #[test]
    fn test_rational_price_precision() {
        // Prices as rationals: 3/2 with trail 1/4
        let mut book = TrailingStopBook::new();
        book.add(
            "pair1".into(), TrailingStopSide::Sell,
            TrailSpec::Amount { num: 1, den: 4 },
            "tx1".into(), 3, 2, "test_owner".into(), 0,
        );
        // Peak=3/2=1.5, trail=1/4=0.25, stop=1.25=5/4
        let id = 1;
        let order = book.get(id).unwrap();
        let stop = order.current_stop_num as f64 / order.current_stop_den as f64;
        assert!((stop - 1.25).abs() < 0.0001);

        // Price=5/4=1.25 => triggers (at stop)
        assert!(order.should_trigger(5, 4));

        // Price=6/5=1.2 => triggers (below stop)
        assert!(order.should_trigger(6, 5));

        // Price=13/10=1.3 => no trigger (above stop)
        assert!(!order.should_trigger(13, 10));
    }

    // Persistence tests

    fn temp_path(name: &str) -> String {
        std::env::temp_dir().join(format!("kob_trailing_stop_test_{}", name)).to_string_lossy().to_string()
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_persistence_roundtrip() {
        let path = temp_path("roundtrip.jsonl");
        cleanup(&path);

        // Create and add orders
        {
            let mut book = TrailingStopBook::new_with_file(&path);
            book.add(
                "pair1".into(), TrailingStopSide::Sell,
                TrailSpec::Amount { num: 10, den: 1 },
                "tx1".into(), 100, 1, "test_owner".into(), 5000,
            );
            book.add(
                "pair1".into(), TrailingStopSide::Buy,
                TrailSpec::Percent(5.0),
                "tx2".into(), 200, 1, "test_owner".into(), 5001,
            );
        }

        // Reload
        {
            let book = TrailingStopBook::new_with_file(&path);
            assert_eq!(book.len(), 2);
            let orders = book.list_for_pair("pair1");
            assert_eq!(orders.len(), 2);
        }

        cleanup(&path);
    }

    #[test]
    fn test_persistence_triggered_orders_excluded() {
        let path = temp_path("triggered.jsonl");
        cleanup(&path);

        {
            let mut book = TrailingStopBook::new_with_file(&path);
            book.add(
                "pair1".into(), TrailingStopSide::Sell,
                TrailSpec::Amount { num: 10, den: 1 },
                "tx1".into(), 100, 1, "test_owner".into(), 0,
            );
            book.add(
                "pair1".into(), TrailingStopSide::Sell,
                TrailSpec::Amount { num: 5, den: 1 },
                "tx2".into(), 100, 1, "test_owner".into(), 0,
            );
            // Price at 92: triggers only stop=95 (trail=5), not stop=90 (trail=10)
            // Order1: peak=100, trail=10, stop=90 -> 92 > 90, NOT triggered
            // Order2: peak=100, trail=5,  stop=95 -> 92 <= 95, TRIGGERED
            book.on_price_update("pair1", 92, 1);
            // Save full state
            book.save_full(&path).unwrap();
        }

        // Reload: should only have the non-triggered order (trail=10, stop=90)
        {
            let book = TrailingStopBook::new_with_file(&path);
            assert_eq!(book.len(), 1);
        }

        cleanup(&path);
    }

    #[test]
    fn test_gcd_edge_cases() {
        assert_eq!(gcd_u128(0, 0), 1);
        assert_eq!(gcd_u128(0, 5), 5);
        assert_eq!(gcd_u128(12, 8), 4);
        assert_eq!(gcd_u128(7, 13), 1);
    }

    #[test]
    fn test_order_serialization_roundtrip() {
        let order = TrailingStopOrder::new(
            42, "pair_abc".into(), TrailingStopSide::Sell,
            TrailSpec::Amount { num: 10, den: 1 },
            "deadbeef".into(), 100, 1, "test_owner".into(), 9999,
        );
        let json = serde_json::to_string(&order).unwrap();
        let parsed: TrailingStopOrder = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, 42);
        assert_eq!(parsed.pair_id, "pair_abc");
        assert_eq!(parsed.peak_price_num, 100);
        assert!(!parsed.triggered);
    }

    #[test]
    fn test_sell_peak_update_then_trigger_sequence() {
        // Realistic scenario: price rises, then crashes
        let mut book = TrailingStopBook::new();
        book.add(
            "pair1".into(), TrailingStopSide::Sell,
            TrailSpec::Percent(10.0),
            "tx1".into(), 100, 1, "test_owner".into(), 0,
        );

        // Gradual rise
        for p in [102, 105, 108, 112, 115, 118, 120] {
            let t = book.on_price_update("pair1", p, 1);
            assert!(t.is_empty(), "Should not trigger at {}", p);
        }
        // Peak=120, stop=108
        let order = book.get(1).unwrap();
        assert_eq!(order.peak_price_num, 120);
        let stop = order.current_stop_num as f64 / order.current_stop_den as f64;
        assert!((stop - 108.0).abs() < 0.01);

        // Crash to 105 => below 108, trigger
        let t = book.on_price_update("pair1", 105, 1);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn test_buy_trough_update_then_trigger_sequence() {
        // Price drops, then spikes
        let mut book = TrailingStopBook::new();
        book.add(
            "pair1".into(), TrailingStopSide::Buy,
            TrailSpec::Amount { num: 5, den: 1 },
            "tx1".into(), 100, 1, "test_owner".into(), 0,
        );

        // Gradual drop
        for p in [98, 95, 92, 88, 85] {
            let t = book.on_price_update("pair1", p, 1);
            assert!(t.is_empty());
        }
        // Trough=85, stop=90
        let order = book.get(1).unwrap();
        assert_eq!(order.peak_price_num, 85);

        // Spike to 90 => at stop, trigger
        let t = book.on_price_update("pair1", 90, 1);
        assert_eq!(t.len(), 1);
    }
}
