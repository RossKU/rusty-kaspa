//! Prediction market state tracker for analytics and keeper operations.

use std::collections::HashMap;

use crate::prediction_book::BallotSide;

/// A tracked prediction market with aggregated state.
#[derive(Debug, Clone)]
pub struct TrackedMarket {
    /// Market ID (hex-encoded).
    pub market_id: String,
    /// Market ID raw bytes.
    pub market_id_bytes: [u8; 32],
    /// Current YES BallotBox value (decreasing with votes in v4 model).
    pub yes_value: u64,
    /// Current NO BallotBox value.
    pub no_value: u64,
    /// Initial YES BallotBox value (at creation).
    pub yes_initial_value: u64,
    /// Initial NO BallotBox value (at creation).
    pub no_initial_value: u64,
    /// Reward per vote (sompi, from BallotBox v4 state).
    pub reward_per_vote: u64,
    /// Total value locked across all covenant UTXOs.
    pub total_value: u64,
    /// DAA score at market creation.
    pub created_daa: u64,
    /// DAA score when voting starts.
    pub start_daa: u64,
    /// DAA score when market expires.
    pub expiry_daa: u64,
    /// Whether the market has been settled.
    pub settled: bool,
    /// Winning side after settlement.
    pub outcome: Option<BallotSide>,
    /// SplitMerge pool value (if present).
    pub pool_value: u64,
    /// Number of redemptions processed.
    pub redemptions_processed: u64,
    /// DAA score of last update.
    pub last_update_daa: u64,
}

impl TrackedMarket {
    /// YES vote count (v4 decrease model).
    pub fn yes_votes(&self) -> u64 {
        if self.reward_per_vote == 0 {
            return 0;
        }
        self.yes_initial_value.saturating_sub(self.yes_value) / self.reward_per_vote
    }

    /// NO vote count.
    pub fn no_votes(&self) -> u64 {
        if self.reward_per_vote == 0 {
            return 0;
        }
        self.no_initial_value.saturating_sub(self.no_value) / self.reward_per_vote
    }

    /// Total votes cast.
    pub fn total_votes(&self) -> u64 {
        self.yes_votes().saturating_add(self.no_votes())
    }

    /// Current leading side (lower value = more votes = winner in v4).
    pub fn leading_side(&self) -> BallotSide {
        if self.yes_value < self.no_value {
            BallotSide::Yes
        } else {
            BallotSide::No // tie goes to NO (matches covenant OP_LT semantics)
        }
    }

    /// Check if voting has started.
    pub fn is_voting_active(&self, current_daa: u64) -> bool {
        !self.settled && current_daa >= self.start_daa && current_daa < self.expiry_daa
    }

    /// Check if market has expired.
    pub fn is_expired(&self, current_daa: u64) -> bool {
        current_daa >= self.expiry_daa
    }
}

/// Implied probability for a market's YES/NO outcomes.
#[derive(Debug, Clone, Copy)]
pub struct ImpliedProbability {
    /// YES probability (0.0 to 1.0).
    pub yes_prob: f64,
    /// NO probability (0.0 to 1.0).
    pub no_prob: f64,
}

/// Market statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct MarketStats {
    /// Total active markets.
    pub active_count: usize,
    /// Total settled markets.
    pub settled_count: usize,
    /// Total value locked across all markets (sompi).
    pub total_value_locked: u64,
    /// Total votes cast across all active markets.
    pub total_votes: u64,
}

/// A market event recorded in the tracker.
#[derive(Debug, Clone)]
pub struct MarketEvent {
    /// Market ID.
    pub market_id: String,
    /// Event type.
    pub event_type: MarketEventType,
    /// DAA score when event occurred.
    pub daa_score: u64,
    /// Additional data.
    pub data: String,
}

/// Types of market events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarketEventType {
    Created,
    VoteCast,
    Settled,
    Redeemed,
    Expired,
}

/// Maximum events in the feed.
const EVENT_FEED_CAP: usize = 512;

// MarketTracker

/// Tracks all prediction markets and their states.
pub struct MarketTracker {
    /// Active and settled markets.
    markets: HashMap<String, TrackedMarket>,
    /// Recent events.
    events: Vec<MarketEvent>,
}

impl Default for MarketTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl MarketTracker {
    pub fn new() -> Self {
        Self {
            markets: HashMap::new(),
            events: Vec::new(),
        }
    }

    /// Add a new tracked market.
    pub fn add(&mut self, market: TrackedMarket) {
        let id = market.market_id.clone();
        let daa = market.created_daa;
        self.markets.insert(id.clone(), market);
        self.record_event(MarketEvent {
            market_id: id,
            event_type: MarketEventType::Created,
            daa_score: daa,
            data: String::new(),
        });
    }

    /// Remove a market. Returns the removed market if found.
    pub fn remove(&mut self, market_id: &str) -> Option<TrackedMarket> {
        self.markets.remove(market_id)
    }

    /// Look up a market.
    pub fn get(&self, market_id: &str) -> Option<&TrackedMarket> {
        self.markets.get(market_id)
    }

    /// Mutable lookup.
    pub fn get_mut(&mut self, market_id: &str) -> Option<&mut TrackedMarket> {
        self.markets.get_mut(market_id)
    }

    /// Check if a market exists.
    pub fn contains(&self, market_id: &str) -> bool {
        self.markets.contains_key(market_id)
    }

    /// Total tracked markets.
    pub fn count(&self) -> usize {
        self.markets.len()
    }

    /// Iterate all markets.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &TrackedMarket)> {
        self.markets.iter()
    }

    /// Update a market after a vote is processed on-chain.
    ///
    /// `side`: which BallotBox received the vote.
    /// `new_value`: the BallotBox's new value after the vote.
    /// `current_daa`: DAA score of the block containing the vote TX.
    pub fn record_vote(
        &mut self,
        market_id: &str,
        side: BallotSide,
        new_value: u64,
        current_daa: u64,
    ) -> bool {
        if let Some(market) = self.markets.get_mut(market_id) {
            match side {
                BallotSide::Yes => market.yes_value = new_value,
                BallotSide::No => market.no_value = new_value,
            }
            market.last_update_daa = current_daa;
            self.record_event(MarketEvent {
                market_id: market_id.to_string(),
                event_type: MarketEventType::VoteCast,
                daa_score: current_daa,
                data: format!("{side}:{new_value}"),
            });
            true
        } else {
            false
        }
    }

    /// Update a market after processing a block.
    /// Takes new YES/NO values and total value locked.
    pub fn update_from_block(
        &mut self,
        market_id: &str,
        yes_value: u64,
        no_value: u64,
        total_value: u64,
        current_daa: u64,
    ) -> bool {
        if let Some(market) = self.markets.get_mut(market_id) {
            market.yes_value = yes_value;
            market.no_value = no_value;
            market.total_value = total_value;
            market.last_update_daa = current_daa;
            true
        } else {
            false
        }
    }

    /// Mark a market as settled.
    pub fn settle(
        &mut self,
        market_id: &str,
        winning_side: BallotSide,
        current_daa: u64,
    ) -> bool {
        if let Some(market) = self.markets.get_mut(market_id) {
            market.settled = true;
            market.outcome = Some(winning_side);
            market.last_update_daa = current_daa;
            self.record_event(MarketEvent {
                market_id: market_id.to_string(),
                event_type: MarketEventType::Settled,
                daa_score: current_daa,
                data: format!("{winning_side}"),
            });
            true
        } else {
            false
        }
    }

    /// Record a redemption processed.
    pub fn record_redemption(&mut self, market_id: &str, current_daa: u64) -> bool {
        if let Some(market) = self.markets.get_mut(market_id) {
            market.redemptions_processed += 1;
            market.last_update_daa = current_daa;
            let count = market.redemptions_processed;
            self.record_event(MarketEvent {
                market_id: market_id.to_string(),
                event_type: MarketEventType::Redeemed,
                daa_score: current_daa,
                data: format!("count:{count}"),
            });
            true
        } else {
            false
        }
    }

    // Analytics

    /// Compute implied probability for a market.
    ///
    /// In the v4 decrease model:
    ///   - Lower value = more votes = higher probability of winning
    ///   - YES_prob = NO_value / (YES_value + NO_value)
    ///   - NO_prob  = YES_value / (YES_value + NO_value)
    ///
    /// This is because lower BallotBox value indicates more votes for that side.
    /// More votes → higher implied probability of being the correct outcome.
    pub fn implied_probability(&self, market_id: &str) -> Option<ImpliedProbability> {
        let market = self.markets.get(market_id)?;
        let total = market.yes_value as f64 + market.no_value as f64;
        if total == 0.0 {
            return Some(ImpliedProbability {
                yes_prob: 0.5,
                no_prob: 0.5,
            });
        }
        // Lower value = more votes = higher probability
        // YES probability is proportional to how much NO value remains
        // (more NO remaining = fewer NO votes = YES is winning)
        Some(ImpliedProbability {
            yes_prob: market.no_value as f64 / total,
            no_prob: market.yes_value as f64 / total,
        })
    }

    /// Sort markets by total value (descending).
    pub fn markets_by_volume(&self) -> Vec<&TrackedMarket> {
        let mut v: Vec<&TrackedMarket> = self.markets.values().collect();
        v.sort_by(|a, b| b.total_value.cmp(&a.total_value));
        v
    }

    /// Sort markets by total votes (descending).
    pub fn markets_by_activity(&self) -> Vec<&TrackedMarket> {
        let mut v: Vec<&TrackedMarket> = self.markets.values().collect();
        v.sort_by(|a, b| b.total_votes().cmp(&a.total_votes()));
        v
    }

    /// Get settled markets.
    pub fn settled_markets(&self) -> Vec<&TrackedMarket> {
        self.markets.values().filter(|m| m.settled).collect()
    }

    /// Get active (unsettled) markets.
    pub fn active_markets(&self) -> Vec<&TrackedMarket> {
        self.markets.values().filter(|m| !m.settled).collect()
    }

    /// Get markets where voting is currently active.
    pub fn voting_active_markets(&self, current_daa: u64) -> Vec<&TrackedMarket> {
        self.markets.values().filter(|m| m.is_voting_active(current_daa)).collect()
    }

    /// Get expired markets (past expiry DAA).
    pub fn expired_markets(&self, current_daa: u64) -> Vec<&TrackedMarket> {
        self.markets.values().filter(|m| m.is_expired(current_daa)).collect()
    }

    /// Compute aggregate statistics.
    pub fn stats(&self) -> MarketStats {
        let mut stats = MarketStats::default();
        for market in self.markets.values() {
            if market.settled {
                stats.settled_count += 1;
            } else {
                stats.active_count += 1;
                stats.total_votes = stats.total_votes.saturating_add(market.total_votes());
            }
            stats.total_value_locked = stats.total_value_locked.saturating_add(market.total_value);
        }
        stats
    }

    // Event feed

    fn record_event(&mut self, event: MarketEvent) {
        if self.events.len() >= EVENT_FEED_CAP {
            self.events.remove(0);
        }
        self.events.push(event);
    }

    /// Return recent events, up to `limit`.
    pub fn event_feed(&self, limit: usize) -> &[MarketEvent] {
        let start = self.events.len().saturating_sub(limit);
        &self.events[start..]
    }

    /// Events for a specific market.
    pub fn market_events(&self, market_id: &str) -> Vec<&MarketEvent> {
        self.events.iter().filter(|e| e.market_id == market_id).collect()
    }

    /// Clear all markets (for testing).
    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.markets.clear();
        self.events.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tracked(id: &str, yes_val: u64, no_val: u64) -> TrackedMarket {
        let mut id_bytes = [0u8; 32];
        let bytes = id.as_bytes();
        let len = bytes.len().min(32);
        id_bytes[..len].copy_from_slice(&bytes[..len]);

        TrackedMarket {
            market_id: id.to_string(),
            market_id_bytes: id_bytes,
            yes_value: yes_val,
            no_value: no_val,
            yes_initial_value: 100_000_000,
            no_initial_value: 100_000_000,
            reward_per_vote: 100_000,
            total_value: yes_val + no_val,
            created_daa: 500,
            start_daa: 1000,
            expiry_daa: 100_000,
            settled: false,
            outcome: None,
            pool_value: 0,
            redemptions_processed: 0,
            last_update_daa: 500,
        }
    }

    // --- Basic CRUD ---

    #[test]
    fn new_tracker_empty() {
        let tracker = MarketTracker::new();
        assert_eq!(tracker.count(), 0);
    }

    #[test]
    fn add_and_count() {
        let mut tracker = MarketTracker::new();
        tracker.add(make_tracked("mkt1", 90_000_000, 95_000_000));
        assert_eq!(tracker.count(), 1);
        assert!(tracker.contains("mkt1"));
    }

    #[test]
    fn remove_market() {
        let mut tracker = MarketTracker::new();
        tracker.add(make_tracked("mkt1", 90_000_000, 95_000_000));
        let removed = tracker.remove("mkt1");
        assert!(removed.is_some());
        assert_eq!(tracker.count(), 0);
    }

    #[test]
    fn remove_nonexistent() {
        let mut tracker = MarketTracker::new();
        assert!(tracker.remove("nope").is_none());
    }

    #[test]
    fn get_market() {
        let mut tracker = MarketTracker::new();
        tracker.add(make_tracked("mkt1", 90_000_000, 95_000_000));
        let m = tracker.get("mkt1").unwrap();
        assert_eq!(m.yes_value, 90_000_000);
    }

    #[test]
    fn get_mut_market() {
        let mut tracker = MarketTracker::new();
        tracker.add(make_tracked("mkt1", 90_000_000, 95_000_000));
        let m = tracker.get_mut("mkt1").unwrap();
        m.yes_value = 80_000_000;
        assert_eq!(tracker.get("mkt1").unwrap().yes_value, 80_000_000);
    }

    // --- TrackedMarket methods ---

    #[test]
    fn yes_votes() {
        let m = make_tracked("mkt1", 90_000_000, 95_000_000);
        // (100M - 90M) / 100K = 100
        assert_eq!(m.yes_votes(), 100);
    }

    #[test]
    fn no_votes() {
        let m = make_tracked("mkt1", 90_000_000, 95_000_000);
        // (100M - 95M) / 100K = 50
        assert_eq!(m.no_votes(), 50);
    }

    #[test]
    fn total_votes() {
        let m = make_tracked("mkt1", 90_000_000, 95_000_000);
        assert_eq!(m.total_votes(), 150);
    }

    #[test]
    fn votes_zero_reward() {
        let mut m = make_tracked("mkt1", 90_000_000, 95_000_000);
        m.reward_per_vote = 0;
        assert_eq!(m.yes_votes(), 0);
        assert_eq!(m.no_votes(), 0);
    }

    #[test]
    fn leading_side_yes() {
        let m = make_tracked("mkt1", 80_000_000, 90_000_000);
        assert_eq!(m.leading_side(), BallotSide::Yes);
    }

    #[test]
    fn leading_side_no() {
        let m = make_tracked("mkt1", 90_000_000, 80_000_000);
        assert_eq!(m.leading_side(), BallotSide::No);
    }

    #[test]
    fn leading_side_tie() {
        let m = make_tracked("mkt1", 85_000_000, 85_000_000);
        assert_eq!(m.leading_side(), BallotSide::No); // tie → NO
    }

    #[test]
    fn voting_active() {
        let m = make_tracked("mkt1", 90_000_000, 95_000_000);
        assert!(!m.is_voting_active(500));    // before start
        assert!(m.is_voting_active(1000));    // at start
        assert!(m.is_voting_active(50_000));  // during voting
        assert!(!m.is_voting_active(100_000)); // at expiry
        assert!(!m.is_voting_active(200_000)); // after expiry
    }

    #[test]
    fn voting_inactive_when_settled() {
        let mut m = make_tracked("mkt1", 90_000_000, 95_000_000);
        m.settled = true;
        assert!(!m.is_voting_active(50_000));
    }

    #[test]
    fn is_expired() {
        let m = make_tracked("mkt1", 90_000_000, 95_000_000);
        assert!(!m.is_expired(50_000));
        assert!(m.is_expired(100_000));
        assert!(m.is_expired(200_000));
    }

    // --- record_vote ---

    #[test]
    fn record_vote_yes() {
        let mut tracker = MarketTracker::new();
        tracker.add(make_tracked("mkt1", 90_000_000, 95_000_000));
        assert!(tracker.record_vote("mkt1", BallotSide::Yes, 89_900_000, 2000));
        let m = tracker.get("mkt1").unwrap();
        assert_eq!(m.yes_value, 89_900_000);
        assert_eq!(m.last_update_daa, 2000);
    }

    #[test]
    fn record_vote_no() {
        let mut tracker = MarketTracker::new();
        tracker.add(make_tracked("mkt1", 90_000_000, 95_000_000));
        assert!(tracker.record_vote("mkt1", BallotSide::No, 94_900_000, 2000));
        assert_eq!(tracker.get("mkt1").unwrap().no_value, 94_900_000);
    }

    #[test]
    fn record_vote_nonexistent() {
        let mut tracker = MarketTracker::new();
        assert!(!tracker.record_vote("nope", BallotSide::Yes, 100, 100));
    }

    // --- update_from_block ---

    #[test]
    fn update_from_block() {
        let mut tracker = MarketTracker::new();
        tracker.add(make_tracked("mkt1", 90_000_000, 95_000_000));
        assert!(tracker.update_from_block("mkt1", 80_000_000, 85_000_000, 200_000_000, 3000));
        let m = tracker.get("mkt1").unwrap();
        assert_eq!(m.yes_value, 80_000_000);
        assert_eq!(m.no_value, 85_000_000);
        assert_eq!(m.total_value, 200_000_000);
    }

    #[test]
    fn update_from_block_nonexistent() {
        let mut tracker = MarketTracker::new();
        assert!(!tracker.update_from_block("nope", 0, 0, 0, 0));
    }

    // --- settle ---

    #[test]
    fn settle_market() {
        let mut tracker = MarketTracker::new();
        tracker.add(make_tracked("mkt1", 80_000_000, 90_000_000));
        assert!(tracker.settle("mkt1", BallotSide::Yes, 5000));
        let m = tracker.get("mkt1").unwrap();
        assert!(m.settled);
        assert_eq!(m.outcome, Some(BallotSide::Yes));
    }

    #[test]
    fn settle_nonexistent() {
        let mut tracker = MarketTracker::new();
        assert!(!tracker.settle("nope", BallotSide::Yes, 5000));
    }

    // --- record_redemption ---

    #[test]
    fn record_redemption() {
        let mut tracker = MarketTracker::new();
        tracker.add(make_tracked("mkt1", 80_000_000, 90_000_000));
        assert!(tracker.record_redemption("mkt1", 6000));
        assert_eq!(tracker.get("mkt1").unwrap().redemptions_processed, 1);
        assert!(tracker.record_redemption("mkt1", 6001));
        assert_eq!(tracker.get("mkt1").unwrap().redemptions_processed, 2);
    }

    #[test]
    fn record_redemption_nonexistent() {
        let mut tracker = MarketTracker::new();
        assert!(!tracker.record_redemption("nope", 6000));
    }

    // --- Implied probability ---

    #[test]
    fn implied_probability_basic() {
        let mut tracker = MarketTracker::new();
        tracker.add(make_tracked("mkt1", 80_000_000, 120_000_000));
        let prob = tracker.implied_probability("mkt1").unwrap();
        // YES lower → YES has more votes → higher probability
        // YES_prob = NO_value / total = 120M / 200M = 0.6
        assert!((prob.yes_prob - 0.6).abs() < 1e-10);
        assert!((prob.no_prob - 0.4).abs() < 1e-10);
    }

    #[test]
    fn implied_probability_equal() {
        let mut tracker = MarketTracker::new();
        tracker.add(make_tracked("mkt1", 50_000_000, 50_000_000));
        let prob = tracker.implied_probability("mkt1").unwrap();
        assert!((prob.yes_prob - 0.5).abs() < 1e-10);
        assert!((prob.no_prob - 0.5).abs() < 1e-10);
    }

    #[test]
    fn implied_probability_zero_total() {
        let mut tracker = MarketTracker::new();
        tracker.add(make_tracked("mkt1", 0, 0));
        let prob = tracker.implied_probability("mkt1").unwrap();
        assert!((prob.yes_prob - 0.5).abs() < 1e-10);
    }

    #[test]
    fn implied_probability_nonexistent() {
        let tracker = MarketTracker::new();
        assert!(tracker.implied_probability("nope").is_none());
    }

    // --- Sorting ---

    #[test]
    fn markets_by_volume() {
        let mut tracker = MarketTracker::new();
        tracker.add(make_tracked("mkt1", 80_000_000, 90_000_000));
        tracker.add(make_tracked("mkt2", 60_000_000, 70_000_000));
        tracker.add(make_tracked("mkt3", 90_000_000, 95_000_000));
        let sorted = tracker.markets_by_volume();
        assert_eq!(sorted.len(), 3);
        assert!(sorted[0].total_value >= sorted[1].total_value);
        assert!(sorted[1].total_value >= sorted[2].total_value);
    }

    #[test]
    fn markets_by_activity() {
        let mut tracker = MarketTracker::new();
        // mkt1: (100M-80M)/100K + (100M-90M)/100K = 200+100 = 300 votes
        tracker.add(make_tracked("mkt1", 80_000_000, 90_000_000));
        // mkt2: (100M-95M)/100K + (100M-98M)/100K = 50+20 = 70 votes
        tracker.add(make_tracked("mkt2", 95_000_000, 98_000_000));
        let sorted = tracker.markets_by_activity();
        assert_eq!(sorted[0].market_id, "mkt1"); // more active
    }

    // --- Filtering ---

    #[test]
    fn active_and_settled_markets() {
        let mut tracker = MarketTracker::new();
        tracker.add(make_tracked("mkt1", 80_000_000, 90_000_000));
        tracker.add(make_tracked("mkt2", 70_000_000, 85_000_000));
        tracker.settle("mkt1", BallotSide::Yes, 5000);
        assert_eq!(tracker.active_markets().len(), 1);
        assert_eq!(tracker.settled_markets().len(), 1);
    }

    #[test]
    fn voting_active_markets() {
        let mut tracker = MarketTracker::new();
        tracker.add(make_tracked("mkt1", 80_000_000, 90_000_000));
        let mut mkt2 = make_tracked("mkt2", 70_000_000, 85_000_000);
        mkt2.start_daa = 50_000;
        tracker.add(mkt2);
        // At DAA 2000: mkt1 active (start=1000), mkt2 not yet (start=50000)
        assert_eq!(tracker.voting_active_markets(2000).len(), 1);
        // At DAA 60000: both active
        assert_eq!(tracker.voting_active_markets(60_000).len(), 2);
    }

    #[test]
    fn expired_markets() {
        let mut tracker = MarketTracker::new();
        tracker.add(make_tracked("mkt1", 80_000_000, 90_000_000)); // expiry=100K
        let mut mkt2 = make_tracked("mkt2", 70_000_000, 85_000_000);
        mkt2.expiry_daa = 200_000;
        tracker.add(mkt2);
        assert_eq!(tracker.expired_markets(50_000).len(), 0);
        assert_eq!(tracker.expired_markets(100_000).len(), 1);
        assert_eq!(tracker.expired_markets(200_000).len(), 2);
    }

    // --- Stats ---

    #[test]
    fn stats_basic() {
        let mut tracker = MarketTracker::new();
        tracker.add(make_tracked("mkt1", 80_000_000, 90_000_000));
        tracker.add(make_tracked("mkt2", 70_000_000, 85_000_000));
        tracker.settle("mkt1", BallotSide::Yes, 5000);
        let stats = tracker.stats();
        assert_eq!(stats.active_count, 1);
        assert_eq!(stats.settled_count, 1);
        assert_eq!(stats.total_value_locked, (80_000_000 + 90_000_000) + (70_000_000 + 85_000_000));
    }

    // --- Event feed ---

    #[test]
    fn event_feed_on_add() {
        let mut tracker = MarketTracker::new();
        tracker.add(make_tracked("mkt1", 80_000_000, 90_000_000));
        let events = tracker.event_feed(10);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, MarketEventType::Created);
    }

    #[test]
    fn event_feed_on_vote() {
        let mut tracker = MarketTracker::new();
        tracker.add(make_tracked("mkt1", 80_000_000, 90_000_000));
        tracker.record_vote("mkt1", BallotSide::Yes, 79_900_000, 2000);
        let events = tracker.event_feed(10);
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].event_type, MarketEventType::VoteCast);
    }

    #[test]
    fn event_feed_on_settle() {
        let mut tracker = MarketTracker::new();
        tracker.add(make_tracked("mkt1", 80_000_000, 90_000_000));
        tracker.settle("mkt1", BallotSide::Yes, 5000);
        let events = tracker.event_feed(10);
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].event_type, MarketEventType::Settled);
    }

    #[test]
    fn event_feed_on_redeem() {
        let mut tracker = MarketTracker::new();
        tracker.add(make_tracked("mkt1", 80_000_000, 90_000_000));
        tracker.record_redemption("mkt1", 6000);
        let events = tracker.event_feed(10);
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].event_type, MarketEventType::Redeemed);
    }

    #[test]
    fn event_feed_limit() {
        let mut tracker = MarketTracker::new();
        tracker.add(make_tracked("mkt1", 80_000_000, 90_000_000));
        tracker.record_vote("mkt1", BallotSide::Yes, 79_900_000, 2000);
        tracker.record_vote("mkt1", BallotSide::No, 89_900_000, 2001);
        let events = tracker.event_feed(2);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, MarketEventType::VoteCast);
    }

    #[test]
    fn market_events_filtered() {
        let mut tracker = MarketTracker::new();
        tracker.add(make_tracked("mkt1", 80_000_000, 90_000_000));
        tracker.add(make_tracked("mkt2", 70_000_000, 85_000_000));
        tracker.record_vote("mkt1", BallotSide::Yes, 79_900_000, 2000);
        let mkt1_events = tracker.market_events("mkt1");
        assert_eq!(mkt1_events.len(), 2); // Created + VoteCast
        let mkt2_events = tracker.market_events("mkt2");
        assert_eq!(mkt2_events.len(), 1); // Created only
    }

    #[test]
    fn default_impl() {
        let tracker = MarketTracker::default();
        assert_eq!(tracker.count(), 0);
    }

    #[test]
    fn clear_tracker() {
        let mut tracker = MarketTracker::new();
        tracker.add(make_tracked("mkt1", 80_000_000, 90_000_000));
        tracker.clear();
        assert_eq!(tracker.count(), 0);
        assert_eq!(tracker.event_feed(100).len(), 0);
    }

    // --- Event feed cap ---

    #[test]
    fn event_feed_cap() {
        let mut tracker = MarketTracker::new();
        tracker.add(make_tracked("mkt1", 90_000_000, 95_000_000));
        // Generate many vote events to test cap
        for i in 0..520 {
            tracker.record_vote("mkt1", BallotSide::Yes, 90_000_000 - (i * 100), i as u64 + 1000);
        }
        // 1 Created + 520 VoteCast = 521 events, but capped at 512
        let all_events = tracker.event_feed(600);
        assert!(all_events.len() <= EVENT_FEED_CAP);
    }

    // --- MarketEventType ---

    #[test]
    fn event_type_equality() {
        assert_eq!(MarketEventType::Created, MarketEventType::Created);
        assert_ne!(MarketEventType::Created, MarketEventType::Settled);
    }
}
