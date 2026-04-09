//! OHLCV candle aggregation from trade events.

use serde::Serialize;
use std::collections::{HashMap, VecDeque};

use crate::matcher::trades::Trade;

/// Maximum candles per interval per pair.
pub const MAX_CANDLES_PER_SERIES: usize = 1_000;

/// Supported candle intervals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Interval {
    #[serde(rename = "1m")]
    M1,
    #[serde(rename = "5m")]
    M5,
    #[serde(rename = "15m")]
    M15,
    #[serde(rename = "1h")]
    H1,
    #[serde(rename = "4h")]
    H4,
    #[serde(rename = "1d")]
    D1,
    #[serde(rename = "1w")]
    W1,
}

impl Interval {
    /// Duration of the interval in seconds.
    pub fn seconds(&self) -> u64 {
        match self {
            Interval::M1 => 60,
            Interval::M5 => 300,
            Interval::M15 => 900,
            Interval::H1 => 3600,
            Interval::H4 => 14400,
            Interval::D1 => 86400,
            Interval::W1 => 604800,
        }
    }

    /// All supported intervals.
    pub fn all() -> &'static [Interval] {
        &[
            Interval::M1,
            Interval::M5,
            Interval::M15,
            Interval::H1,
            Interval::H4,
            Interval::D1,
            Interval::W1,
        ]
    }

    /// Parse from string (e.g., "1m", "5m", "1h").
    pub fn parse_interval(s: &str) -> Option<Interval> {
        match s {
            "1m" => Some(Interval::M1),
            "5m" => Some(Interval::M5),
            "15m" => Some(Interval::M15),
            "1h" => Some(Interval::H1),
            "4h" => Some(Interval::H4),
            "1d" => Some(Interval::D1),
            "1w" => Some(Interval::W1),
            _ => None,
        }
    }

    /// String representation.
    #[allow(dead_code)] // Used in tests
    pub fn as_str(&self) -> &'static str {
        match self {
            Interval::M1 => "1m",
            Interval::M5 => "5m",
            Interval::M15 => "15m",
            Interval::H1 => "1h",
            Interval::H4 => "4h",
            Interval::D1 => "1d",
            Interval::W1 => "1w",
        }
    }
}

/// A single OHLCV candle.
#[derive(Debug, Clone, Serialize)]
pub struct Candle {
    /// Interval start (unix seconds, floored to interval boundary).
    pub open_time: u64,
    /// Open price (num, den).
    pub open: (u64, u64),
    /// High price (num, den).
    pub high: (u64, u64),
    /// Close price (num, den).
    pub close: (u64, u64),
    /// Low price (num, den).
    pub low: (u64, u64),
    /// Total volume (token quantity).
    pub volume: u64,
    /// Number of trades in this candle.
    pub trade_count: u32,
}

impl Candle {
    fn new(open_time: u64, price_num: u64, price_den: u64, quantity: u64) -> Self {
        Candle {
            open_time,
            open: (price_num, price_den),
            high: (price_num, price_den),
            low: (price_num, price_den),
            close: (price_num, price_den),
            volume: quantity,
            trade_count: 1,
        }
    }

    fn update(&mut self, price_num: u64, price_den: u64, quantity: u64) {
        // Compare: price_num/price_den vs high.0/high.1
        // Cross multiply: price_num * high.1 vs high.0 * price_den
        let price_cross = (price_num as u128) * (self.high.1 as u128);
        let high_cross = (self.high.0 as u128) * (price_den as u128);
        if price_cross > high_cross {
            self.high = (price_num, price_den);
        }

        let price_cross_low = (price_num as u128) * (self.low.1 as u128);
        let low_cross = (self.low.0 as u128) * (price_den as u128);
        if price_cross_low < low_cross {
            self.low = (price_num, price_den);
        }

        self.close = (price_num, price_den);
        self.volume = self.volume.saturating_add(quantity);
        self.trade_count = self.trade_count.saturating_add(1);
    }
}

/// Candle aggregation key: (pair_id, interval).
type CandleKey = (String, Interval);

/// OHLCV candle aggregator for multiple pairs and intervals.
#[derive(Default)]
pub struct CandleAggregator {
    candles: HashMap<CandleKey, VecDeque<Candle>>,
}

impl CandleAggregator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Process a trade and update candles for all intervals.
    pub fn on_trade(&mut self, trade: &Trade) {
        for &interval in Interval::all() {
            self.update_candle(&trade.pair_id, interval, trade);
        }
    }

    fn update_candle(&mut self, pair_id: &str, interval: Interval, trade: &Trade) {
        let secs = interval.seconds();
        let open_time = (trade.timestamp / secs) * secs;
        let key = (pair_id.to_string(), interval);

        let series = self.candles.entry(key).or_default();

        if let Some(last) = series.back_mut() {
            if last.open_time == open_time {
                // Same candle period, update it
                last.update(trade.price_num, trade.price_den, trade.quantity);
                return;
            }
        }

        // New candle period
        let candle = Candle::new(open_time, trade.price_num, trade.price_den, trade.quantity);
        series.push_back(candle);

        // Enforce capacity
        while series.len() > MAX_CANDLES_PER_SERIES {
            series.pop_front();
        }
    }

    /// Get the most recent candle for a pair+interval.
    pub fn latest_candle(&self, pair_id: &str, interval: Interval) -> Option<&Candle> {
        let key = (pair_id.to_string(), interval);
        self.candles.get(&key).and_then(|deque| deque.back())
    }

    /// Replay a batch of historical trades to rebuild candle state.
    /// Trades must be in chronological order (oldest first).
    pub fn replay_trades(&mut self, trades: &[Trade]) {
        for trade in trades {
            self.on_trade(trade);
        }
    }

    /// Get candles for a pair and interval (oldest first), limited to `limit`.
    pub fn get_candles(&self, pair_id: &str, interval: Interval, limit: usize) -> Vec<&Candle> {
        let key = (pair_id.to_string(), interval);
        if let Some(series) = self.candles.get(&key) {
            let skip = series.len().saturating_sub(limit);
            series.iter().skip(skip).collect()
        } else {
            Vec::new()
        }
    }

    /// Get candles for a pair and interval filtered by time range (oldest first),
    /// limited to `limit`. Returns candles where `open_time >= start_time` and
    /// `open_time <= end_time`.
    pub fn get_candles_range(
        &self,
        pair_id: &str,
        interval: Interval,
        start_time: Option<u64>,
        end_time: Option<u64>,
        limit: usize,
    ) -> Vec<&Candle> {
        let key = (pair_id.to_string(), interval);
        if let Some(series) = self.candles.get(&key) {
            series
                .iter()
                .filter(|c| {
                    if let Some(st) = start_time {
                        if c.open_time < st {
                            return false;
                        }
                    }
                    if let Some(et) = end_time {
                        if c.open_time > et {
                            return false;
                        }
                    }
                    true
                })
                .take(limit)
                .collect()
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::trades::Side;

    fn make_trade(pair: &str, price_num: u64, price_den: u64, qty: u64, ts: u64) -> Trade {
        Trade {
            txid: format!("tx_{}", ts),
            pair_id: pair.to_string(),
            price_num,
            price_den,
            quantity: qty,
            side: Side::Buy,
            daa_score: ts,
            timestamp: ts,
            routing: None,
        }
    }

    #[test]
    fn test_single_trade_creates_candle() {
        let mut agg = CandleAggregator::new();
        let trade = make_trade("pairA", 100, 1, 50, 1000);
        agg.on_trade(&trade);

        let candles = agg.get_candles("pairA", Interval::M1, 100);
        assert_eq!(candles.len(), 1);
        let c = candles[0];
        assert_eq!(c.open, (100, 1));
        assert_eq!(c.high, (100, 1));
        assert_eq!(c.low, (100, 1));
        assert_eq!(c.close, (100, 1));
        assert_eq!(c.volume, 50);
        assert_eq!(c.trade_count, 1);
        // open_time should be floored to 60s boundary: 1000/60*60 = 960
        assert_eq!(c.open_time, 960);
    }

    #[test]
    fn test_two_trades_same_candle() {
        let mut agg = CandleAggregator::new();
        // Both within same 1m candle (960..1020)
        agg.on_trade(&make_trade("pairA", 100, 1, 50, 970));
        agg.on_trade(&make_trade("pairA", 120, 1, 30, 980));

        let candles = agg.get_candles("pairA", Interval::M1, 100);
        assert_eq!(candles.len(), 1);
        let c = candles[0];
        assert_eq!(c.open, (100, 1));
        assert_eq!(c.high, (120, 1));
        assert_eq!(c.low, (100, 1));
        assert_eq!(c.close, (120, 1));
        assert_eq!(c.volume, 80);
        assert_eq!(c.trade_count, 2);
    }

    #[test]
    fn test_trades_across_candle_boundary() {
        let mut agg = CandleAggregator::new();
        agg.on_trade(&make_trade("pairA", 100, 1, 50, 950)); // candle at 900
        agg.on_trade(&make_trade("pairA", 110, 1, 30, 970)); // candle at 960

        let candles = agg.get_candles("pairA", Interval::M1, 100);
        assert_eq!(candles.len(), 2);
        assert_eq!(candles[0].open_time, 900);
        assert_eq!(candles[1].open_time, 960);
    }

    #[test]
    fn test_high_low_with_rationals() {
        let mut agg = CandleAggregator::new();
        // 3/4 = 0.75, 2/3 = 0.666, 5/6 = 0.833
        agg.on_trade(&make_trade("pairA", 3, 4, 10, 100));
        agg.on_trade(&make_trade("pairA", 2, 3, 10, 105));
        agg.on_trade(&make_trade("pairA", 5, 6, 10, 110));

        let candles = agg.get_candles("pairA", Interval::M1, 100);
        assert_eq!(candles.len(), 1);
        let c = candles[0];
        assert_eq!(c.open, (3, 4));
        assert_eq!(c.high, (5, 6)); // 5/6 = 0.833 is highest
        assert_eq!(c.low, (2, 3)); // 2/3 = 0.666 is lowest
        assert_eq!(c.close, (5, 6));
    }

    #[test]
    fn test_multiple_intervals_updated() {
        let mut agg = CandleAggregator::new();
        agg.on_trade(&make_trade("pairA", 100, 1, 50, 1000));

        // Should have candles for all intervals
        for &interval in Interval::all() {
            let candles = agg.get_candles("pairA", interval, 100);
            assert_eq!(candles.len(), 1, "expected candle for {:?}", interval);
        }
    }

    #[test]
    fn test_capacity_enforcement() {
        let mut agg = CandleAggregator::new();
        // Create MAX_CANDLES_PER_SERIES + 10 candles (each in its own 1m period)
        for i in 0..(MAX_CANDLES_PER_SERIES + 10) {
            let ts = (i as u64) * 60; // each trade in a new 1m period
            agg.on_trade(&make_trade("pairA", 100, 1, 1, ts));
        }
        let candles = agg.get_candles("pairA", Interval::M1, MAX_CANDLES_PER_SERIES + 100);
        assert_eq!(candles.len(), MAX_CANDLES_PER_SERIES);
        // Oldest should have been evicted
        assert_eq!(candles[0].open_time, 10 * 60); // first 10 evicted
    }

    #[test]
    fn test_get_candles_limit() {
        let mut agg = CandleAggregator::new();
        for i in 0..5 {
            let ts = (i as u64) * 60;
            agg.on_trade(&make_trade("pairA", 100, 1, 1, ts));
        }
        let candles = agg.get_candles("pairA", Interval::M1, 3);
        assert_eq!(candles.len(), 3);
        // Should return the last 3
        assert_eq!(candles[0].open_time, 120);
        assert_eq!(candles[2].open_time, 240);
    }

    #[test]
    fn test_empty_pair() {
        let agg = CandleAggregator::new();
        assert!(agg.get_candles("nonexistent", Interval::M1, 100).is_empty());
    }

    #[test]
    fn test_interval_from_str() {
        assert_eq!(Interval::parse_interval("1m"), Some(Interval::M1));
        assert_eq!(Interval::parse_interval("5m"), Some(Interval::M5));
        assert_eq!(Interval::parse_interval("15m"), Some(Interval::M15));
        assert_eq!(Interval::parse_interval("1h"), Some(Interval::H1));
        assert_eq!(Interval::parse_interval("4h"), Some(Interval::H4));
        assert_eq!(Interval::parse_interval("1d"), Some(Interval::D1));
        assert_eq!(Interval::parse_interval("1w"), Some(Interval::W1));
        assert_eq!(Interval::parse_interval("2d"), None);
    }

    #[test]
    fn test_interval_roundtrip() {
        for &interval in Interval::all() {
            assert_eq!(Interval::parse_interval(interval.as_str()), Some(interval));
        }
    }

    #[test]
    fn test_replay_trades_rebuilds_candles() {
        // Build candles via on_trade one-by-one
        let mut agg1 = CandleAggregator::new();
        let trades = vec![
            make_trade("pairA", 100, 1, 50, 970),
            make_trade("pairA", 120, 1, 30, 980),
            make_trade("pairA", 110, 1, 20, 1030), // next 1m candle
            make_trade("pairB", 200, 1, 10, 975),
        ];
        for t in &trades {
            agg1.on_trade(t);
        }

        // Rebuild via replay_trades
        let mut agg2 = CandleAggregator::new();
        agg2.replay_trades(&trades);

        // Compare results for pairA 1m
        let c1 = agg1.get_candles("pairA", Interval::M1, 100);
        let c2 = agg2.get_candles("pairA", Interval::M1, 100);
        assert_eq!(c1.len(), c2.len());
        for (a, b) in c1.iter().zip(c2.iter()) {
            assert_eq!(a.open_time, b.open_time);
            assert_eq!(a.open, b.open);
            assert_eq!(a.high, b.high);
            assert_eq!(a.low, b.low);
            assert_eq!(a.close, b.close);
            assert_eq!(a.volume, b.volume);
            assert_eq!(a.trade_count, b.trade_count);
        }

        // pairB should also match
        let c1b = agg1.get_candles("pairB", Interval::M1, 100);
        let c2b = agg2.get_candles("pairB", Interval::M1, 100);
        assert_eq!(c1b.len(), c2b.len());
        assert_eq!(c1b[0].volume, c2b[0].volume);
    }

    #[test]
    fn test_replay_empty_trades() {
        let mut agg = CandleAggregator::new();
        agg.replay_trades(&[]);
        assert!(agg.get_candles("pairA", Interval::M1, 100).is_empty());
    }

    // Time range query tests

    #[test]
    fn test_get_candles_range_start_time() {
        let mut agg = CandleAggregator::new();
        // 3 candles at 0, 60, 120
        agg.on_trade(&make_trade("pairA", 100, 1, 10, 10));
        agg.on_trade(&make_trade("pairA", 110, 1, 10, 70));
        agg.on_trade(&make_trade("pairA", 120, 1, 10, 130));

        let candles = agg.get_candles_range("pairA", Interval::M1, Some(60), None, 100);
        assert_eq!(candles.len(), 2);
        assert_eq!(candles[0].open_time, 60);
        assert_eq!(candles[1].open_time, 120);
    }

    #[test]
    fn test_get_candles_range_end_time() {
        let mut agg = CandleAggregator::new();
        agg.on_trade(&make_trade("pairA", 100, 1, 10, 10));
        agg.on_trade(&make_trade("pairA", 110, 1, 10, 70));
        agg.on_trade(&make_trade("pairA", 120, 1, 10, 130));

        let candles = agg.get_candles_range("pairA", Interval::M1, None, Some(60), 100);
        assert_eq!(candles.len(), 2);
        assert_eq!(candles[0].open_time, 0);
        assert_eq!(candles[1].open_time, 60);
    }

    #[test]
    fn test_get_candles_range_both_bounds() {
        let mut agg = CandleAggregator::new();
        for i in 0..5 {
            agg.on_trade(&make_trade("pairA", 100, 1, 10, i * 60 + 5));
        }
        // Candles at 0, 60, 120, 180, 240
        let candles = agg.get_candles_range("pairA", Interval::M1, Some(60), Some(180), 100);
        assert_eq!(candles.len(), 3);
        assert_eq!(candles[0].open_time, 60);
        assert_eq!(candles[1].open_time, 120);
        assert_eq!(candles[2].open_time, 180);
    }

    #[test]
    fn test_get_candles_range_with_limit() {
        let mut agg = CandleAggregator::new();
        for i in 0..10 {
            agg.on_trade(&make_trade("pairA", 100, 1, 10, i * 60 + 5));
        }
        let candles = agg.get_candles_range("pairA", Interval::M1, Some(0), None, 3);
        assert_eq!(candles.len(), 3);
        assert_eq!(candles[0].open_time, 0);
        assert_eq!(candles[2].open_time, 120);
    }

    #[test]
    fn test_get_candles_range_no_bounds_returns_all() {
        let mut agg = CandleAggregator::new();
        for i in 0..5 {
            agg.on_trade(&make_trade("pairA", 100, 1, 10, i * 60 + 5));
        }
        let candles = agg.get_candles_range("pairA", Interval::M1, None, None, 100);
        assert_eq!(candles.len(), 5);
    }

    #[test]
    fn test_weekly_interval() {
        assert_eq!(Interval::W1.seconds(), 604800);
        assert_eq!(Interval::W1.as_str(), "1w");
        assert_eq!(Interval::parse_interval("1w"), Some(Interval::W1));

        let mut agg = CandleAggregator::new();
        // Two trades within the same week (both in week starting at 0)
        agg.on_trade(&make_trade("pairA", 100, 1, 50, 1000));
        agg.on_trade(&make_trade("pairA", 200, 1, 30, 500_000));

        let candles = agg.get_candles("pairA", Interval::W1, 100);
        assert_eq!(candles.len(), 1);
        assert_eq!(candles[0].open_time, 0);
        assert_eq!(candles[0].open, (100, 1));
        assert_eq!(candles[0].high, (200, 1));
        assert_eq!(candles[0].close, (200, 1));
        assert_eq!(candles[0].volume, 80);
        assert_eq!(candles[0].trade_count, 2);

        // Trade in the next week
        agg.on_trade(&make_trade("pairA", 150, 1, 10, 604_800 + 100));
        let candles = agg.get_candles("pairA", Interval::W1, 100);
        assert_eq!(candles.len(), 2);
        assert_eq!(candles[1].open_time, 604_800);
    }

    #[test]
    fn test_get_candles_range_empty_pair() {
        let agg = CandleAggregator::new();
        let candles = agg.get_candles_range("nonexistent", Interval::M1, Some(0), Some(1000), 100);
        assert!(candles.is_empty());
    }
}
