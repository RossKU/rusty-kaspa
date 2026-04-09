//! Perpetual position tracker with mark-to-market and liquidation detection.

use std::collections::HashMap;

/// An open perpetual position tracked by the engine (v6 split-ratio model).
///
/// Created when a Long and Short order are matched and the perp_position
/// covenant UTXO is confirmed on L1.
#[derive(Debug, Clone)]
pub struct PerpPosition {
    /// Transaction ID of the position UTXO.
    pub tx_id: String,
    /// Output index of the position UTXO.
    pub index: u32,
    /// Blake2b-256 hash of the Long party's SPK.
    pub long_spk_hash: [u8; 32],
    /// Blake2b-256 hash of the Short party's SPK.
    pub short_spk_hash: [u8; 32],
    /// Entry price numerator (GCD-normalized).
    pub entry_num: u64,
    /// Entry price denominator (GCD-normalized).
    pub entry_den: u64,
    /// Position size in sompi.
    pub size: u64,
    /// Total margin = UTXO value (changes with add/withdraw margin).
    pub total_margin: u64,
    /// Split ratio numerator: long's share = total_margin * split_num / split_den.
    pub split_num: u64,
    /// Split ratio denominator.
    pub split_den: u64,
    /// Close fee deducted at settlement (sompi).
    pub close_fee: u64,
    /// Maintenance margin percentage numerator.
    pub maint_pct_num: u64,
    /// Maintenance margin percentage denominator.
    pub maint_pct_den: u64,
    /// Keeper fee for liquidation (sompi).
    pub keeper_fee: u64,
    /// DAA score at position creation.
    pub creation_daa: u64,
    /// Grace period DAA: position is not liquidatable before this DAA score.
    pub grace_daa: u64,
    /// Maturity DAA: position expires / can be settled after this DAA score.
    pub maturity_daa: u64,
    /// Emergency DAA: timeout CLTV fallback (return margins proportionally).
    pub emergency_daa: u64,
    /// Min price bound for the position.
    pub min_price: u64,
    /// Max price bound for the position.
    pub max_price: u64,
    /// Cached redeemScript (hex-encoded) for building spend TXs.
    pub redeem_script_hex: String,
    /// Actual Long party SPK (hex-encoded), needed for output construction.
    pub long_spk: Option<String>,
    /// Actual Short party SPK (hex-encoded), needed for output construction.
    pub short_spk: Option<String>,
}

impl PerpPosition {
    /// Outpoint key in "txId:index" format.
    pub fn outpoint_key(&self) -> String {
        format!("{}:{}", self.tx_id, self.index)
    }

    /// Long party's margin derived from split ratio.
    /// margin_long = total_margin * split_num / split_den
    pub fn margin_long(&self) -> u64 {
        if self.split_den == 0 {
            return 0;
        }
        ((self.total_margin as u128) * (self.split_num as u128) / (self.split_den as u128)) as u64
    }

    /// Short party's margin derived from split ratio.
    /// margin_short = total_margin - margin_long
    pub fn margin_short(&self) -> u64 {
        self.total_margin.saturating_sub(self.margin_long())
    }
}

/// Result of marking a position to market at a given oracle price.
#[derive(Debug, Clone, Copy)]
pub struct MarkToMarketResult {
    /// PnL in sompi (positive = long profits, negative = long loses).
    /// Signed: i64 because PnL can be negative.
    pub pnl: i64,
    /// Long party's remaining margin after PnL (clamped to [0, total_margin - close_fee]).
    pub long_remaining: u64,
    /// Short party's remaining margin after PnL (clamped to [0, total_margin - close_fee]).
    pub short_remaining: u64,
    /// Maintenance threshold: total_margin * maint_num / maint_den.
    pub threshold: u64,
    /// True if the long side is below the maintenance threshold.
    pub long_underwater: bool,
    /// True if the short side is below the maintenance threshold.
    pub short_underwater: bool,
}

/// Identifies which side of a position is being liquidated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiquidatedSide {
    Long,
    Short,
}

/// A position that is eligible for liquidation.
#[derive(Debug, Clone)]
pub struct LiquidatablePosition {
    /// The position outpoint key.
    pub outpoint_key: String,
    /// Which side is underwater.
    pub side: LiquidatedSide,
    /// Mark-to-market result at the oracle price.
    pub mtm: MarkToMarketResult,
}

/// Statistics about tracked positions.
#[derive(Debug, Clone, Copy, Default)]
pub struct PositionStats {
    /// Total number of open positions.
    pub total_positions: usize,
    /// Total margin locked across all positions (sompi).
    pub total_margin_locked: u64,
    /// Size of the largest position (sompi).
    pub largest_position_size: u64,
}

/// Open interest statistics across all tracked positions.
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenInterestStats {
    /// Total number of active positions.
    pub total_positions: usize,
    /// Sum of all position sizes (sompi).
    pub total_size: u64,
    /// Sum of all total_margin values (sompi).
    pub total_margin: u64,
    /// Sum of sizes for the long side.
    ///
    /// In this model every position has both a long and short side,
    /// so `long_size` equals `total_size`.
    pub long_size: u64,
}

/// A recorded liquidation event stored in the liquidation feed.
#[derive(Debug, Clone)]
pub struct LiquidationEvent {
    /// Transaction ID of the liquidated position UTXO.
    pub position_tx_id: String,
    /// Which side was liquidated.
    pub liquidated_side: LiquidatedSide,
    /// Position size at liquidation (sompi).
    pub size: u64,
    /// Entry price numerator (GCD-normalized).
    pub entry_price_num: u64,
    /// Entry price denominator (GCD-normalized).
    pub entry_price_den: u64,
    /// Oracle price at the time of liquidation (sompi).
    pub liquidation_price: u64,
    /// Margin lost by the liquidated side (sompi).
    pub margin_lost: u64,
    /// Keeper fee paid at liquidation (sompi).
    pub keeper_fee: u64,
    /// DAA score at the time of liquidation.
    pub timestamp_daa: u64,
}

/// Maximum number of liquidation events retained in the feed.
const LIQUIDATION_FEED_CAP: usize = 256;

/// Tracks all open perpetual positions.
///
/// Positions are indexed by outpoint key for O(1) lookup.
pub struct PositionTracker {
    positions: HashMap<String, PerpPosition>,
    recent_liquidations: Vec<LiquidationEvent>,
}

impl Default for PositionTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl PositionTracker {
    pub fn new() -> Self {
        Self {
            positions: HashMap::new(),
            recent_liquidations: Vec::new(),
        }
    }

    /// Add a new position to the tracker.
    pub fn add(&mut self, position: PerpPosition) {
        let key = position.outpoint_key();
        self.positions.insert(key, position);
    }

    /// Remove a position by outpoint key. Returns the removed position if found.
    pub fn remove(&mut self, outpoint_key: &str) -> Option<PerpPosition> {
        self.positions.remove(outpoint_key)
    }

    /// Look up a position by outpoint key.
    pub fn get(&self, outpoint_key: &str) -> Option<&PerpPosition> {
        self.positions.get(outpoint_key)
    }

    /// Mutable lookup by outpoint key.
    pub fn get_mut(&mut self, outpoint_key: &str) -> Option<&mut PerpPosition> {
        self.positions.get_mut(outpoint_key)
    }

    /// Check if a position exists.
    pub fn contains(&self, outpoint_key: &str) -> bool {
        self.positions.contains_key(outpoint_key)
    }

    /// Number of tracked positions.
    pub fn count(&self) -> usize {
        self.positions.len()
    }

    /// Iterate all positions.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &PerpPosition)> {
        self.positions.iter()
    }

    /// Compute mark-to-market for a single position at the given oracle price.
    ///
    /// v6 model: margins derived from total_margin * split_num / split_den.
    /// long_remaining = clamp(margin_long + pnl, 0, total_margin - close_fee)
    /// short_remaining = (total_margin - close_fee) - long_remaining
    ///
    /// Returns None if arithmetic overflows or split_den/entry_den is zero.
    pub fn mark_to_market(position: &PerpPosition, oracle_price: u64) -> Option<MarkToMarketResult> {
        if position.split_den == 0 || position.entry_den == 0 || position.maint_pct_den == 0 {
            return None;
        }

        // Derive margins from split ratio
        let margin_long = position.margin_long();
        let _margin_short = position.margin_short();

        // PnL = (oracle_price * entry_den - entry_num) * size / entry_den
        // For rational entry prices (e.g., midpoint 3/2), we must scale oracle_price
        // to the same denominator before subtracting entry_num.
        let oracle_scaled = (oracle_price as i128).checked_mul(position.entry_den as i128)?;
        let price_delta = oracle_scaled.checked_sub(position.entry_num as i128)?;
        let pnl_raw = price_delta.checked_mul(position.size as i128)?;
        let pnl_i128 = pnl_raw.checked_div(position.entry_den as i128)?;

        // Clamp PnL to i64 range
        if pnl_i128 > i64::MAX as i128 || pnl_i128 < i64::MIN as i128 {
            return None;
        }
        let pnl = pnl_i128 as i64;

        // Distributable pool = total_margin - close_fee
        let pool = position.total_margin.saturating_sub(position.close_fee);

        // long_remaining = clamp(margin_long + pnl, 0, pool)
        let long_raw = (margin_long as i128).checked_add(pnl_i128)?;
        let long_remaining = if long_raw < 0 {
            0u64
        } else if long_raw > pool as i128 {
            pool
        } else {
            long_raw as u64
        };

        // short_remaining = pool - long_remaining
        let short_remaining = pool.saturating_sub(long_remaining);

        // threshold = total_margin * maint_pct_num / maint_pct_den
        let threshold_raw = (position.total_margin as u128)
            .checked_mul(position.maint_pct_num as u128)?
            .checked_div(position.maint_pct_den as u128)?;
        if threshold_raw > u64::MAX as u128 {
            return None;
        }
        let threshold = threshold_raw as u64;

        Some(MarkToMarketResult {
            pnl,
            long_remaining,
            short_remaining,
            threshold,
            long_underwater: long_remaining < threshold,
            short_underwater: short_remaining < threshold,
        })
    }

    /// Check if a specific position is liquidatable at the given oracle price.
    ///
    /// v6: uses grace_daa — position is not liquidatable until current_daa >= grace_daa.
    /// Returns the liquidation details if one side is below maintenance threshold.
    pub fn check_liquidation(
        &self,
        outpoint_key: &str,
        oracle_price: u64,
        current_daa: u64,
    ) -> Option<LiquidatablePosition> {
        let position = self.positions.get(outpoint_key)?;

        // Grace period: not liquidatable before grace_daa
        if current_daa < position.grace_daa {
            return None;
        }

        let mtm = Self::mark_to_market(position, oracle_price)?;

        if mtm.long_underwater {
            Some(LiquidatablePosition {
                outpoint_key: outpoint_key.to_string(),
                side: LiquidatedSide::Long,
                mtm,
            })
        } else if mtm.short_underwater {
            Some(LiquidatablePosition {
                outpoint_key: outpoint_key.to_string(),
                side: LiquidatedSide::Short,
                mtm,
            })
        } else {
            None
        }
    }

    /// Batch scan all positions for liquidatable ones at the given oracle price.
    ///
    /// v6: respects grace_daa per position.
    pub fn scan_liquidatable(&self, oracle_price: u64, current_daa: u64) -> Vec<LiquidatablePosition> {
        let mut result = Vec::new();
        for (outpoint_key, position) in &self.positions {
            // Grace period check
            if current_daa < position.grace_daa {
                continue;
            }
            if let Some(mtm) = Self::mark_to_market(position, oracle_price) {
                if mtm.long_underwater {
                    result.push(LiquidatablePosition {
                        outpoint_key: outpoint_key.clone(),
                        side: LiquidatedSide::Long,
                        mtm,
                    });
                } else if mtm.short_underwater {
                    result.push(LiquidatablePosition {
                        outpoint_key: outpoint_key.clone(),
                        side: LiquidatedSide::Short,
                        mtm,
                    });
                }
            }
        }
        result
    }

    /// Update total margin for a position (Paths 5/6: add/withdraw margin).
    ///
    /// Returns false if the position was not found.
    pub fn update_margin(&mut self, outpoint_key: &str, new_total_margin: u64) -> bool {
        if let Some(pos) = self.positions.get_mut(outpoint_key) {
            pos.total_margin = new_total_margin;
            true
        } else {
            false
        }
    }

    /// Partial close: reduce size and margin, update the outpoint key (Path 8).
    ///
    /// The old position is removed and a new one is inserted with the updated
    /// outpoint, size, and total_margin. Returns false if old position not found.
    pub fn partial_close(
        &mut self,
        outpoint_key: &str,
        new_size: u64,
        new_total_margin: u64,
        new_tx_id: &str,
        new_index: u32,
    ) -> bool {
        if let Some(mut pos) = self.positions.remove(outpoint_key) {
            pos.size = new_size;
            pos.total_margin = new_total_margin;
            pos.tx_id = new_tx_id.to_string();
            pos.index = new_index;
            let new_key = pos.outpoint_key();
            self.positions.insert(new_key, pos);
            true
        } else {
            false
        }
    }

    /// Compute aggregate statistics across all positions.
    pub fn stats(&self) -> PositionStats {
        let mut stats = PositionStats {
            total_positions: self.positions.len(),
            ..Default::default()
        };
        for position in self.positions.values() {
            stats.total_margin_locked = stats
                .total_margin_locked
                .saturating_add(position.total_margin);
            if position.size > stats.largest_position_size {
                stats.largest_position_size = position.size;
            }
        }
        stats
    }

    /// Compute open-interest statistics across all tracked positions.
    pub fn open_interest(&self) -> OpenInterestStats {
        let mut total_size: u64 = 0;
        let mut total_margin: u64 = 0;
        for position in self.positions.values() {
            total_size = total_size.saturating_add(position.size);
            total_margin = total_margin.saturating_add(position.total_margin);
        }
        OpenInterestStats {
            total_positions: self.positions.len(),
            total_size,
            total_margin,
            // Every position has both a long and short side, so long_size == total_size.
            long_size: total_size,
        }
    }

    /// Record a liquidation event in the feed.
    ///
    /// Call this when removing a position due to liquidation, before calling
    /// `remove()`. The feed is capped at `LIQUIDATION_FEED_CAP` entries; the
    /// oldest entry is evicted when the cap is reached.
    pub fn record_liquidation(&mut self, event: LiquidationEvent) {
        if self.recent_liquidations.len() >= LIQUIDATION_FEED_CAP {
            self.recent_liquidations.remove(0);
        }
        self.recent_liquidations.push(event);
    }

    /// Return the most recent liquidation events, up to `limit` entries.
    ///
    /// Events are ordered oldest-first (the last element is the most recent).
    pub fn liquidation_feed(&self, limit: usize) -> &[LiquidationEvent] {
        let all = self.recent_liquidations.as_slice();
        let start = all.len().saturating_sub(limit);
        &all[start..]
    }

    /// Clear all tracked positions.
    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.positions.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a v6 position with split-ratio margins.
    ///
    /// margin_long = total_margin * split_num / split_den
    /// margin_short = total_margin - margin_long
    fn make_position(
        tx_id: &str,
        entry_num: u64,
        entry_den: u64,
        size: u64,
        total_margin: u64,
        split_num: u64,
        split_den: u64,
    ) -> PerpPosition {
        PerpPosition {
            tx_id: tx_id.to_string(),
            index: 0,
            long_spk_hash: [1; 32],
            short_spk_hash: [2; 32],
            entry_num,
            entry_den,
            size,
            total_margin,
            split_num,
            split_den,
            close_fee: 0,
            maint_pct_num: 5,
            maint_pct_den: 100,
            keeper_fee: 10_000,
            creation_daa: 1000,
            grace_daa: 0,
            maturity_daa: u64::MAX,
            emergency_daa: u64::MAX,
            min_price: 0,
            max_price: u64::MAX,
            redeem_script_hex: String::new(),
            long_spk: None,
            short_spk: None,
        }
    }

    /// Helper with close_fee
    fn make_position_with_fee(
        tx_id: &str,
        entry_num: u64,
        entry_den: u64,
        size: u64,
        total_margin: u64,
        split_num: u64,
        split_den: u64,
        close_fee: u64,
    ) -> PerpPosition {
        let mut pos = make_position(tx_id, entry_num, entry_den, size, total_margin, split_num, split_den);
        pos.close_fee = close_fee;
        pos
    }

    // --- Split Ratio Margin Derivation ---

    #[test]
    fn margin_long_derived() {
        // total=1_000_000, split=1/2 -> long=500_000
        let pos = make_position("tx1", 100, 1, 1000, 1_000_000, 1, 2);
        assert_eq!(pos.margin_long(), 500_000);
        assert_eq!(pos.margin_short(), 500_000);
    }

    #[test]
    fn margin_split_asymmetric() {
        // total=1_000_000, split=3/4 -> long=750_000, short=250_000
        let pos = make_position("tx1", 100, 1, 1000, 1_000_000, 3, 4);
        assert_eq!(pos.margin_long(), 750_000);
        assert_eq!(pos.margin_short(), 250_000);
    }

    #[test]
    fn margin_split_zero_den() {
        let pos = make_position("tx1", 100, 1, 1000, 1_000_000, 1, 0);
        assert_eq!(pos.margin_long(), 0);
        assert_eq!(pos.margin_short(), 1_000_000);
    }

    // --- Basic CRUD ---

    #[test]
    fn add_and_count() {
        let mut tracker = PositionTracker::new();
        tracker.add(make_position("tx1", 100, 1, 1_000_000, 1_000_000, 1, 2));
        assert_eq!(tracker.count(), 1);
        assert!(tracker.contains("tx1:0"));
    }

    #[test]
    fn remove_position() {
        let mut tracker = PositionTracker::new();
        tracker.add(make_position("tx1", 100, 1, 1_000_000, 1_000_000, 1, 2));
        let removed = tracker.remove("tx1:0");
        assert!(removed.is_some());
        assert_eq!(tracker.count(), 0);
    }

    #[test]
    fn get_position() {
        let mut tracker = PositionTracker::new();
        tracker.add(make_position("tx1", 100, 1, 1_000_000, 1_000_000, 1, 2));
        let pos = tracker.get("tx1:0").unwrap();
        assert_eq!(pos.size, 1_000_000);
    }

    #[test]
    fn remove_nonexistent() {
        let mut tracker = PositionTracker::new();
        assert!(tracker.remove("tx99:0").is_none());
    }

    // --- Mark-to-Market ---

    #[test]
    fn mtm_no_price_change() {
        // Oracle price == entry price -> PnL = 0
        // total=1M, split=1/2 -> long=500k, short=500k, close_fee=0
        let pos = make_position("tx1", 100, 1, 1_000_000, 1_000_000, 1, 2);
        let mtm = PositionTracker::mark_to_market(&pos, 100).unwrap();
        assert_eq!(mtm.pnl, 0);
        assert_eq!(mtm.long_remaining, 500_000);
        assert_eq!(mtm.short_remaining, 500_000);
        assert!(!mtm.long_underwater);
        assert!(!mtm.short_underwater);
    }

    #[test]
    fn mtm_price_up_long_profits() {
        // Entry = 100/1, oracle = 110, size = 1_000_000
        // PnL = (110 - 100) * 1_000_000 / 1 = 10_000_000
        // total=1M, split=1/2, close_fee=0 -> pool=1M
        // long_remaining = clamp(500k + 10M, 0, 1M) = 1_000_000
        // short_remaining = 1M - 1M = 0
        let pos = make_position("tx1", 100, 1, 1_000_000, 1_000_000, 1, 2);
        let mtm = PositionTracker::mark_to_market(&pos, 110).unwrap();
        assert_eq!(mtm.pnl, 10_000_000);
        assert_eq!(mtm.long_remaining, 1_000_000);
        assert_eq!(mtm.short_remaining, 0);
    }

    #[test]
    fn mtm_price_down_short_profits() {
        // Entry = 100/1, oracle = 90, size = 1_000_000
        // PnL = (90 - 100) * 1_000_000 / 1 = -10_000_000
        // long_remaining = clamp(500k + (-10M), 0, 1M) = 0
        // short_remaining = 1M - 0 = 1_000_000
        let pos = make_position("tx1", 100, 1, 1_000_000, 1_000_000, 1, 2);
        let mtm = PositionTracker::mark_to_market(&pos, 90).unwrap();
        assert_eq!(mtm.pnl, -10_000_000);
        assert_eq!(mtm.long_remaining, 0);
        assert_eq!(mtm.short_remaining, 1_000_000);
    }

    #[test]
    fn mtm_rational_entry_price() {
        // Entry = 3/2 = 1.5, oracle = 2, size = 100
        // PnL = (oracle * entry_den - entry_num) * size / entry_den
        //      = (2 * 2 - 3) * 100 / 2 = 1 * 100 / 2 = 50
        // Price rose from 1.5 to 2 → long profits
        // total=2000, split=1/2 -> long=1000, short=1000
        // long_remaining = clamp(1000 + 50, 0, 2000) = 1050
        // short_remaining = 2000 - 1050 = 950
        let pos = make_position("tx1", 3, 2, 100, 2000, 1, 2);
        let mtm = PositionTracker::mark_to_market(&pos, 2).unwrap();
        assert_eq!(mtm.pnl, 50);
        assert_eq!(mtm.long_remaining, 1050);
        assert_eq!(mtm.short_remaining, 950);
    }

    #[test]
    fn mtm_with_close_fee() {
        // total=1M, close_fee=10k, split=1/2 -> long=500k, short=500k
        // pool = 1M - 10k = 990_000
        // PnL = 0 (oracle == entry)
        // long_remaining = clamp(500k, 0, 990k) = 500_000
        // short_remaining = 990k - 500k = 490_000
        let pos = make_position_with_fee("tx1", 100, 1, 1000, 1_000_000, 1, 2, 10_000);
        let mtm = PositionTracker::mark_to_market(&pos, 100).unwrap();
        assert_eq!(mtm.pnl, 0);
        assert_eq!(mtm.long_remaining, 500_000);
        assert_eq!(mtm.short_remaining, 490_000);
    }

    #[test]
    fn mtm_close_fee_caps_long_remaining() {
        // total=1M, close_fee=10k, pool=990k
        // PnL huge positive -> long capped at pool
        // long_remaining = 990k, short_remaining = 0
        let pos = make_position_with_fee("tx1", 100, 1, 1_000_000, 1_000_000, 1, 2, 10_000);
        let mtm = PositionTracker::mark_to_market(&pos, 110).unwrap();
        assert_eq!(mtm.long_remaining, 990_000);
        assert_eq!(mtm.short_remaining, 0);
    }

    // --- Liquidation Direction ---

    #[test]
    fn liquidation_long_underwater() {
        // Large price drop: long gets liquidated
        // Entry=100, oracle=50, size=100_000
        // total=1M, split=1/2 -> long=500k, short=500k
        // PnL = (50-100)*100_000/1 = -5_000_000
        // long_remaining = clamp(500k - 5M) = 0
        // threshold = 1M * 5/100 = 50_000
        // 0 < 50_000 -> long underwater
        let pos = make_position("tx1", 100, 1, 100_000, 1_000_000, 1, 2);
        let mtm = PositionTracker::mark_to_market(&pos, 50).unwrap();
        assert!(mtm.long_underwater);
        assert!(!mtm.short_underwater);
    }

    #[test]
    fn liquidation_short_underwater() {
        // Large price rise: short gets liquidated
        // Entry=100, oracle=150, size=100_000
        // total=1M, split=1/2 -> long=500k, short=500k
        // PnL = (150-100)*100_000/1 = 5_000_000
        // long_remaining = clamp(500k + 5M, 0, 1M) = 1M
        // short_remaining = 1M - 1M = 0
        // threshold = 50_000
        // 0 < 50_000 -> short underwater
        let pos = make_position("tx1", 100, 1, 100_000, 1_000_000, 1, 2);
        let mtm = PositionTracker::mark_to_market(&pos, 150).unwrap();
        assert!(!mtm.long_underwater);
        assert!(mtm.short_underwater);
    }

    #[test]
    fn no_liquidation_both_healthy() {
        // Small price move, both sides healthy
        // Entry=100, oracle=101, size=1000
        // total=1M, split=1/2 -> long=500k, short=500k
        // PnL = 1*1000/1 = 1000
        // long_remaining = 501_000, short_remaining = 499_000
        // threshold = 50_000
        let pos = make_position("tx1", 100, 1, 1000, 1_000_000, 1, 2);
        let mtm = PositionTracker::mark_to_market(&pos, 101).unwrap();
        assert!(!mtm.long_underwater);
        assert!(!mtm.short_underwater);
    }

    #[test]
    fn liquidation_at_exact_threshold_boundary() {
        // Edge case: remaining == threshold exactly -> NOT underwater (< threshold required)
        // total=200k, split=1/2 -> long=100k, short=100k
        // threshold = 200k * 5/100 = 10_000
        // long_remaining = 100k + pnl = 10_000 -> pnl = -90_000
        // pnl = (oracle - 100)*90_000 -> oracle = 99
        let pos = make_position("tx1", 100, 1, 90_000, 200_000, 1, 2);
        let mtm = PositionTracker::mark_to_market(&pos, 99).unwrap();
        assert_eq!(mtm.long_remaining, 10_000);
        assert_eq!(mtm.threshold, 10_000);
        assert!(!mtm.long_underwater);
    }

    #[test]
    fn liquidation_one_below_threshold() {
        // Just below threshold -> underwater
        let pos = make_position("tx1", 100, 1, 90_000, 200_000, 1, 2);
        let mtm = PositionTracker::mark_to_market(&pos, 98).unwrap();
        // long_remaining = clamp(100k + (98-100)*90k) = clamp(100k - 180k) = 0
        // threshold = 10_000
        assert_eq!(mtm.long_remaining, 0);
        assert!(mtm.long_underwater);
    }

    // --- Tracker Integration ---

    #[test]
    fn check_liquidation_returns_none_when_healthy() {
        let mut tracker = PositionTracker::new();
        tracker.add(make_position("tx1", 100, 1, 1000, 1_000_000, 1, 2));
        assert!(tracker.check_liquidation("tx1:0", 101, 5000).is_none());
    }

    #[test]
    fn check_liquidation_returns_long_side() {
        let mut tracker = PositionTracker::new();
        tracker.add(make_position("tx1", 100, 1, 100_000, 1_000_000, 1, 2));
        let liq = tracker.check_liquidation("tx1:0", 50, 5000).unwrap();
        assert_eq!(liq.side, LiquidatedSide::Long);
    }

    #[test]
    fn check_liquidation_returns_short_side() {
        let mut tracker = PositionTracker::new();
        tracker.add(make_position("tx1", 100, 1, 100_000, 1_000_000, 1, 2));
        let liq = tracker.check_liquidation("tx1:0", 150, 5000).unwrap();
        assert_eq!(liq.side, LiquidatedSide::Short);
    }

    #[test]
    fn check_liquidation_nonexistent_position() {
        let tracker = PositionTracker::new();
        assert!(tracker.check_liquidation("tx99:0", 100, 5000).is_none());
    }

    #[test]
    fn check_liquidation_grace_period_blocks() {
        // Position with grace_daa=2000, current_daa=1500 -> not liquidatable
        let mut tracker = PositionTracker::new();
        let mut pos = make_position("tx1", 100, 1, 100_000, 1_000_000, 1, 2);
        pos.grace_daa = 2000;
        tracker.add(pos);
        // Even though price crashed, grace period prevents liquidation
        assert!(tracker.check_liquidation("tx1:0", 50, 1500).is_none());
        // After grace period, liquidation proceeds
        let liq = tracker.check_liquidation("tx1:0", 50, 2000).unwrap();
        assert_eq!(liq.side, LiquidatedSide::Long);
    }

    #[test]
    fn scan_liquidatable_batch() {
        let mut tracker = PositionTracker::new();
        // Position 1: healthy at oracle=101
        tracker.add(make_position("tx1", 100, 1, 1000, 1_000_000, 1, 2));
        // Position 2: long underwater at oracle=101 (entry=200, size=500_000)
        // PnL = (101-200)*500_000/1 = -49_500_000
        // long_remaining = clamp(500k - 49.5M) = 0
        // threshold = 1M * 5/100 = 50_000
        tracker.add(make_position("tx2", 200, 1, 500_000, 1_000_000, 1, 2));
        // Position 3: short underwater at oracle=101 (entry=50, size=100_000)
        // PnL = (101-50)*100_000/1 = 5_100_000
        // long_remaining = clamp(500k + 5.1M, 0, 1M) = 1M
        // short_remaining = 1M - 1M = 0 < 50k -> short underwater
        tracker.add(make_position("tx3", 50, 1, 100_000, 1_000_000, 1, 2));

        let liquidatable = tracker.scan_liquidatable(101, 5000);
        assert_eq!(liquidatable.len(), 2);

        let sides: Vec<LiquidatedSide> = liquidatable.iter().map(|l| l.side).collect();
        assert!(sides.contains(&LiquidatedSide::Long));
        assert!(sides.contains(&LiquidatedSide::Short));
    }

    #[test]
    fn scan_liquidatable_respects_grace_daa() {
        let mut tracker = PositionTracker::new();
        let mut pos = make_position("tx1", 100, 1, 100_000, 1_000_000, 1, 2);
        pos.grace_daa = 3000;
        tracker.add(pos);
        // Before grace: nothing
        assert!(tracker.scan_liquidatable(50, 2000).is_empty());
        // After grace: found
        assert_eq!(tracker.scan_liquidatable(50, 3000).len(), 1);
    }

    #[test]
    fn scan_liquidatable_empty_tracker() {
        let tracker = PositionTracker::new();
        assert!(tracker.scan_liquidatable(100, 5000).is_empty());
    }

    // --- v6 New Methods ---

    #[test]
    fn update_margin_basic() {
        let mut tracker = PositionTracker::new();
        tracker.add(make_position("tx1", 100, 1, 1000, 1_000_000, 1, 2));
        assert!(tracker.update_margin("tx1:0", 1_500_000));
        let pos = tracker.get("tx1:0").unwrap();
        assert_eq!(pos.total_margin, 1_500_000);
        // Margins re-derived: 750k long, 750k short
        assert_eq!(pos.margin_long(), 750_000);
        assert_eq!(pos.margin_short(), 750_000);
    }

    #[test]
    fn update_margin_nonexistent() {
        let mut tracker = PositionTracker::new();
        assert!(!tracker.update_margin("tx99:0", 1_000_000));
    }

    #[test]
    fn partial_close_basic() {
        let mut tracker = PositionTracker::new();
        tracker.add(make_position("tx1", 100, 1, 1_000_000, 1_000_000, 1, 2));
        assert!(tracker.partial_close("tx1:0", 500_000, 600_000, "tx2", 0));
        // Old key removed
        assert!(!tracker.contains("tx1:0"));
        // New key exists
        assert!(tracker.contains("tx2:0"));
        let pos = tracker.get("tx2:0").unwrap();
        assert_eq!(pos.size, 500_000);
        assert_eq!(pos.total_margin, 600_000);
        assert_eq!(pos.margin_long(), 300_000);
        assert_eq!(pos.margin_short(), 300_000);
    }

    #[test]
    fn partial_close_nonexistent() {
        let mut tracker = PositionTracker::new();
        assert!(!tracker.partial_close("tx99:0", 500_000, 500_000, "tx100", 0));
    }

    #[test]
    fn partial_close_preserves_other_fields() {
        let mut tracker = PositionTracker::new();
        let mut pos = make_position("tx1", 100, 1, 1_000_000, 1_000_000, 3, 4);
        pos.keeper_fee = 50_000;
        pos.close_fee = 5_000;
        tracker.add(pos);
        tracker.partial_close("tx1:0", 500_000, 700_000, "tx2", 1);
        let pos = tracker.get("tx2:1").unwrap();
        assert_eq!(pos.entry_num, 100);
        assert_eq!(pos.split_num, 3);
        assert_eq!(pos.split_den, 4);
        assert_eq!(pos.keeper_fee, 50_000);
        assert_eq!(pos.close_fee, 5_000);
    }

    // --- Statistics ---

    #[test]
    fn stats_empty() {
        let tracker = PositionTracker::new();
        let stats = tracker.stats();
        assert_eq!(stats.total_positions, 0);
        assert_eq!(stats.total_margin_locked, 0);
        assert_eq!(stats.largest_position_size, 0);
    }

    #[test]
    fn stats_multiple_positions() {
        let mut tracker = PositionTracker::new();
        tracker.add(make_position("tx1", 100, 1, 1_000_000, 1_000_000, 1, 2));
        tracker.add(make_position("tx2", 200, 1, 2_000_000, 600_000, 1, 2));
        tracker.add(make_position("tx3", 50, 1, 500_000, 200_000, 1, 2));

        let stats = tracker.stats();
        assert_eq!(stats.total_positions, 3);
        assert_eq!(stats.total_margin_locked, 1_800_000); // 1M + 600k + 200k
        assert_eq!(stats.largest_position_size, 2_000_000);
    }

    // --- Overflow Safety ---

    #[test]
    fn mtm_overflow_returns_none_on_extreme_values() {
        let pos = PerpPosition {
            tx_id: "tx1".to_string(),
            index: 0,
            long_spk_hash: [1; 32],
            short_spk_hash: [2; 32],
            entry_num: u64::MAX,
            entry_den: 1,
            size: u64::MAX,
            total_margin: 1_000_000,
            split_num: 1,
            split_den: 2,
            close_fee: 0,
            maint_pct_num: 5,
            maint_pct_den: 100,
            keeper_fee: 10_000,
            creation_daa: 1000,
            grace_daa: 0,
            maturity_daa: u64::MAX,
            emergency_daa: u64::MAX,
            min_price: 0,
            max_price: u64::MAX,
            redeem_script_hex: String::new(),
            long_spk: None,
            short_spk: None,
        };
        // Should not panic regardless of outcome
        let _ = PositionTracker::mark_to_market(&pos, 0);
    }

    #[test]
    fn mtm_zero_entry_den_returns_none() {
        let mut pos = make_position("tx1", 100, 1, 1_000_000, 1_000_000, 1, 2);
        pos.entry_den = 0;
        let result = PositionTracker::mark_to_market(&pos, 110);
        assert!(result.is_none());
    }

    #[test]
    fn mtm_zero_maint_den_returns_none() {
        let mut pos = make_position("tx1", 100, 1, 1_000_000, 1_000_000, 1, 2);
        pos.maint_pct_den = 0;
        let result = PositionTracker::mark_to_market(&pos, 110);
        assert!(result.is_none());
    }

    #[test]
    fn mtm_zero_split_den_returns_none() {
        let mut pos = make_position("tx1", 100, 1, 1_000_000, 1_000_000, 1, 2);
        pos.split_den = 0;
        let result = PositionTracker::mark_to_market(&pos, 110);
        assert!(result.is_none());
    }

    #[test]
    fn mtm_large_but_valid_values() {
        // Realistic large position: 10 BTC worth at ~70,000 KAS/BTC
        // total=10B, split=1/2
        let pos = make_position("tx1", 70_000, 1, 10_000_000_000, 10_000_000_000, 1, 2);
        let result = PositionTracker::mark_to_market(&pos, 71_000);
        assert!(result.is_some());
        let mtm = result.unwrap();
        // PnL = (71000 - 70000) * 10B / 1 = 10_000_000_000_000 (10T)
        assert_eq!(mtm.pnl, 10_000_000_000_000);
    }

    // --- Edge Cases ---

    #[test]
    fn both_sides_underwater_simultaneously_impossible() {
        let pos = make_position("tx1", 100, 1, 100_000, 1_000_000, 1, 2);
        for oracle in [1u64, 50, 99, 100, 101, 150, 200, 1000] {
            if let Some(mtm) = PositionTracker::mark_to_market(&pos, oracle) {
                assert!(
                    !(mtm.long_underwater && mtm.short_underwater),
                    "Both sides underwater at oracle={oracle}"
                );
            }
        }
    }

    #[test]
    fn pnl_symmetry_no_close_fee() {
        // With close_fee=0, long+short should sum to total_margin
        let pos = make_position("tx1", 100, 1, 10_000, 1_000_000, 1, 2);
        let mtm = PositionTracker::mark_to_market(&pos, 105).unwrap();
        // PnL = 50_000
        // long = 550_000, short = 450_000, sum = 1_000_000
        assert_eq!(mtm.long_remaining + mtm.short_remaining, pos.total_margin);
    }

    #[test]
    fn pnl_symmetry_with_close_fee() {
        // With close_fee, long+short should sum to total_margin - close_fee
        let pos = make_position_with_fee("tx1", 100, 1, 10_000, 1_000_000, 1, 2, 20_000);
        let mtm = PositionTracker::mark_to_market(&pos, 105).unwrap();
        assert_eq!(mtm.long_remaining + mtm.short_remaining, 980_000);
    }

    #[test]
    fn pnl_clamped_preserves_pool() {
        // When one side is wiped out, other side gets the whole pool
        let pos = make_position("tx1", 100, 1, 100_000, 1_000_000, 1, 2);
        let mtm = PositionTracker::mark_to_market(&pos, 50).unwrap();
        assert_eq!(mtm.long_remaining, 0);
        assert_eq!(mtm.short_remaining, 1_000_000);
        assert_eq!(mtm.long_remaining + mtm.short_remaining, 1_000_000);
    }

    #[test]
    fn clear_tracker() {
        let mut tracker = PositionTracker::new();
        tracker.add(make_position("tx1", 100, 1, 1_000_000, 1_000_000, 1, 2));
        tracker.add(make_position("tx2", 200, 1, 2_000_000, 600_000, 1, 2));
        tracker.clear();
        assert_eq!(tracker.count(), 0);
    }

    #[test]
    fn outpoint_key_format() {
        let pos = make_position("abcdef", 5, 100, 1, 1000, 1, 2);
        assert_eq!(pos.outpoint_key(), "abcdef:0");
    }

    #[test]
    fn iter_all_positions() {
        let mut tracker = PositionTracker::new();
        tracker.add(make_position("tx1", 100, 1, 1_000_000, 1_000_000, 1, 2));
        tracker.add(make_position("tx2", 200, 1, 2_000_000, 600_000, 1, 2));

        let keys: Vec<String> = tracker.iter().map(|(k, _)| k.clone()).collect();
        assert_eq!(keys.len(), 2);
    }

    // --- Open Interest ---

    #[test]
    fn open_interest_empty_tracker() {
        let tracker = PositionTracker::new();
        let oi = tracker.open_interest();
        assert_eq!(oi.total_positions, 0);
        assert_eq!(oi.total_size, 0);
        assert_eq!(oi.total_margin, 0);
        assert_eq!(oi.long_size, 0);
    }

    #[test]
    fn open_interest_single_position() {
        let mut tracker = PositionTracker::new();
        // size=1_000_000, total_margin=2_000_000
        tracker.add(make_position("tx1", 100, 1, 1_000_000, 2_000_000, 1, 2));
        let oi = tracker.open_interest();
        assert_eq!(oi.total_positions, 1);
        assert_eq!(oi.total_size, 1_000_000);
        assert_eq!(oi.total_margin, 2_000_000);
        assert_eq!(oi.long_size, 1_000_000); // long_size == total_size
    }

    #[test]
    fn open_interest_multiple_positions() {
        let mut tracker = PositionTracker::new();
        tracker.add(make_position("tx1", 100, 1, 1_000_000, 1_000_000, 1, 2));
        tracker.add(make_position("tx2", 200, 1, 2_000_000, 600_000, 1, 2));
        tracker.add(make_position("tx3", 50, 1, 500_000, 200_000, 1, 2));
        let oi = tracker.open_interest();
        assert_eq!(oi.total_positions, 3);
        assert_eq!(oi.total_size, 3_500_000); // 1M + 2M + 500k
        assert_eq!(oi.total_margin, 1_800_000); // 1M + 600k + 200k
        assert_eq!(oi.long_size, oi.total_size);
    }

    #[test]
    fn open_interest_decreases_after_removal() {
        let mut tracker = PositionTracker::new();
        tracker.add(make_position("tx1", 100, 1, 1_000_000, 1_000_000, 1, 2));
        tracker.add(make_position("tx2", 200, 1, 2_000_000, 600_000, 1, 2));
        tracker.remove("tx1:0");
        let oi = tracker.open_interest();
        assert_eq!(oi.total_positions, 1);
        assert_eq!(oi.total_size, 2_000_000);
        assert_eq!(oi.total_margin, 600_000);
    }

    // --- Liquidation Feed ---

    fn make_liquidation_event(tx_id: &str, side: LiquidatedSide, price: u64, daa: u64) -> LiquidationEvent {
        LiquidationEvent {
            position_tx_id: tx_id.to_string(),
            liquidated_side: side,
            size: 1_000_000,
            entry_price_num: 100,
            entry_price_den: 1,
            liquidation_price: price,
            margin_lost: 500_000,
            keeper_fee: 10_000,
            timestamp_daa: daa,
        }
    }

    #[test]
    fn liquidation_feed_empty() {
        let tracker = PositionTracker::new();
        assert!(tracker.liquidation_feed(10).is_empty());
    }

    #[test]
    fn liquidation_feed_single_event() {
        let mut tracker = PositionTracker::new();
        tracker.record_liquidation(make_liquidation_event("tx1", LiquidatedSide::Long, 50, 1000));
        let feed = tracker.liquidation_feed(10);
        assert_eq!(feed.len(), 1);
        assert_eq!(feed[0].position_tx_id, "tx1");
        assert_eq!(feed[0].liquidated_side, LiquidatedSide::Long);
        assert_eq!(feed[0].liquidation_price, 50);
        assert_eq!(feed[0].timestamp_daa, 1000);
    }

    #[test]
    fn liquidation_feed_respects_limit() {
        let mut tracker = PositionTracker::new();
        for i in 0..10u64 {
            tracker.record_liquidation(make_liquidation_event(
                &format!("tx{i}"),
                LiquidatedSide::Short,
                100 + i,
                1000 + i,
            ));
        }
        // Ask for only the last 3
        let feed = tracker.liquidation_feed(3);
        assert_eq!(feed.len(), 3);
        // Most-recent event should be the last one recorded (tx9)
        assert_eq!(feed[2].position_tx_id, "tx9");
        assert_eq!(feed[0].position_tx_id, "tx7");
    }

    #[test]
    fn liquidation_feed_limit_exceeds_size() {
        let mut tracker = PositionTracker::new();
        tracker.record_liquidation(make_liquidation_event("tx1", LiquidatedSide::Long, 50, 1000));
        tracker.record_liquidation(make_liquidation_event("tx2", LiquidatedSide::Short, 150, 1001));
        // Requesting more than available returns all
        let feed = tracker.liquidation_feed(100);
        assert_eq!(feed.len(), 2);
    }

    #[test]
    fn liquidation_feed_cap_evicts_oldest() {
        let mut tracker = PositionTracker::new();
        // Fill beyond LIQUIDATION_FEED_CAP (256)
        for i in 0..300u64 {
            tracker.record_liquidation(make_liquidation_event(
                &format!("tx{i}"),
                LiquidatedSide::Long,
                50,
                1000 + i,
            ));
        }
        // Feed should be capped at 256
        let feed = tracker.liquidation_feed(1000);
        assert_eq!(feed.len(), 256);
        // Oldest entries (tx0..tx43) should have been evicted; tx44 is the oldest remaining
        assert_eq!(feed[0].position_tx_id, "tx44");
        // Most recent is tx299
        assert_eq!(feed[255].position_tx_id, "tx299");
    }

    #[test]
    fn liquidation_feed_records_correct_fields() {
        let mut tracker = PositionTracker::new();
        // Simulate a short liquidation with realistic values
        let event = LiquidationEvent {
            position_tx_id: "deadbeef:0".to_string(),
            liquidated_side: LiquidatedSide::Short,
            size: 500_000,
            entry_price_num: 200,
            entry_price_den: 1,
            liquidation_price: 300,
            margin_lost: 250_000,
            keeper_fee: 20_000,
            timestamp_daa: 9999,
        };
        tracker.record_liquidation(event);
        let feed = tracker.liquidation_feed(1);
        assert_eq!(feed.len(), 1);
        let ev = &feed[0];
        assert_eq!(ev.position_tx_id, "deadbeef:0");
        assert_eq!(ev.liquidated_side, LiquidatedSide::Short);
        assert_eq!(ev.size, 500_000);
        assert_eq!(ev.entry_price_num, 200);
        assert_eq!(ev.entry_price_den, 1);
        assert_eq!(ev.liquidation_price, 300);
        assert_eq!(ev.margin_lost, 250_000);
        assert_eq!(ev.keeper_fee, 20_000);
        assert_eq!(ev.timestamp_daa, 9999);
    }

    #[test]
    fn liquidation_feed_integrated_with_position_removal() {
        // Verify the typical workflow: detect liquidation, record event, remove position.
        let mut tracker = PositionTracker::new();
        tracker.add(make_position("tx1", 100, 1, 100_000, 1_000_000, 1, 2));

        // Detect liquidation at oracle=50 (long underwater)
        let liq = tracker.check_liquidation("tx1:0", 50, 5000).unwrap();
        assert_eq!(liq.side, LiquidatedSide::Long);

        let pos = tracker.get("tx1:0").unwrap();
        let event = LiquidationEvent {
            position_tx_id: pos.tx_id.clone(),
            liquidated_side: liq.side,
            size: pos.size,
            entry_price_num: pos.entry_num,
            entry_price_den: pos.entry_den,
            liquidation_price: 50,
            margin_lost: liq.mtm.long_remaining, // 0 in this case
            keeper_fee: pos.keeper_fee,
            timestamp_daa: 5000,
        };
        tracker.record_liquidation(event);
        tracker.remove("tx1:0");

        // Position gone, event recorded
        assert_eq!(tracker.count(), 0);
        let feed = tracker.liquidation_feed(10);
        assert_eq!(feed.len(), 1);
        assert_eq!(feed[0].position_tx_id, "tx1");
        assert_eq!(feed[0].liquidated_side, LiquidatedSide::Long);
        assert_eq!(feed[0].liquidation_price, 50);
    }
}
