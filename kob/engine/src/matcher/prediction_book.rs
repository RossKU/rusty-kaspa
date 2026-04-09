//! Prediction market book tracking BallotBox, SplitMerge, and Redemption UTXOs.

use std::collections::HashMap;

/// Side of a ballot box (YES or NO).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BallotSide {
    Yes,
    No,
}

impl std::fmt::Display for BallotSide {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BallotSide::Yes => write!(f, "YES"),
            BallotSide::No => write!(f, "NO"),
        }
    }
}

/// Entry for the SplitMerge covenant UTXO.
#[derive(Debug, Clone)]
pub struct SplitMergeEntry {
    /// Outpoint key "txId:index".
    pub outpoint: String,
    /// UTXO value (pool value).
    pub value: u64,
    /// RedeemScript bytes.
    pub redeem_script: Vec<u8>,
    /// P2SH ScriptPublicKey bytes.
    pub p2sh_script: Vec<u8>,
    /// YES token covenant ID (32 bytes).
    pub yes_token_cid: [u8; 32],
    /// NO token covenant ID (32 bytes).
    pub no_token_cid: [u8; 32],
    /// Unit value (KAS per token pair).
    pub unit_value: u64,
    /// Creator pubkey hash (Blake2b).
    pub creator_pkh: [u8; 32],
    /// Expiry DAA score.
    pub expiry_daa: u64,
}

/// Entry for a BallotBox UTXO (YES or NO).
#[derive(Debug, Clone)]
pub struct BallotBoxEntry {
    /// Outpoint key "txId:index".
    pub outpoint: String,
    /// Current UTXO value (decreases with votes in v4 model).
    pub value: u64,
    /// Which side this box represents.
    pub side: BallotSide,
    /// RedeemScript bytes.
    pub redeem_script: Vec<u8>,
    /// P2SH ScriptPublicKey bytes.
    pub p2sh_script: Vec<u8>,
    /// Reward per vote (sompi).
    pub reward_per_vote: u64,
    /// Start DAA score (voting begins).
    pub start_daa: u64,
    /// End DAA score (voting ends, cooling period begins).
    pub end_daa: u64,
    /// Expiry DAA score (creator can reclaim).
    pub expiry_daa: u64,
    /// Initial value when the box was created.
    pub initial_value: u64,
}

impl BallotBoxEntry {
    /// Number of votes cast so far.
    /// vote_count = (initial_value - current_value) / reward_per_vote
    pub fn vote_count(&self) -> u64 {
        if self.reward_per_vote == 0 {
            return 0;
        }
        self.initial_value.saturating_sub(self.value) / self.reward_per_vote
    }
}

/// Entry for the Redemption covenant UTXO.
#[derive(Debug, Clone)]
pub struct RedemptionEntry {
    /// Outpoint key "txId:index".
    pub outpoint: String,
    /// UTXO value (remaining pool).
    pub value: u64,
    /// Winning side determined at settlement.
    pub winning_side: BallotSide,
    /// YES BallotBox final value.
    pub yes_final_value: u64,
    /// NO BallotBox final value.
    pub no_final_value: u64,
    /// Payout per winning token.
    pub payout_per_token: u64,
    /// RedeemScript bytes.
    pub redeem_script: Vec<u8>,
    /// P2SH ScriptPublicKey bytes.
    pub p2sh_script: Vec<u8>,
    /// Expiry DAA for refund path.
    pub expiry_daa: u64,
}

/// Full state of a prediction market.
#[derive(Debug, Clone)]
pub struct MarketState {
    /// Market ID (hex-encoded Blake2b hash, 64 hex chars).
    pub market_id: String,
    /// Market ID raw bytes (32 bytes).
    pub market_id_bytes: [u8; 32],
    /// SplitMerge covenant UTXO.
    pub split_merge: Option<SplitMergeEntry>,
    /// YES BallotBox UTXO.
    pub yes_box: Option<BallotBoxEntry>,
    /// NO BallotBox UTXO.
    pub no_box: Option<BallotBoxEntry>,
    /// Redemption covenant (created after settlement).
    pub redemption: Option<RedemptionEntry>,
    /// DAA score when market was discovered.
    pub created_daa: u64,
    /// Whether the market has been settled.
    pub settled: bool,
}

impl MarketState {
    /// Total value locked (YES box + NO box + SplitMerge pool + Redemption pool).
    pub fn total_value_locked(&self) -> u64 {
        let sm = self.split_merge.as_ref().map_or(0, |e| e.value);
        let yes = self.yes_box.as_ref().map_or(0, |e| e.value);
        let no = self.no_box.as_ref().map_or(0, |e| e.value);
        let redemption = self.redemption.as_ref().map_or(0, |e| e.value);
        sm.saturating_add(yes).saturating_add(no).saturating_add(redemption)
    }

    /// Current YES box value.
    pub fn yes_value(&self) -> u64 {
        self.yes_box.as_ref().map_or(0, |e| e.value)
    }

    /// Current NO box value.
    pub fn no_value(&self) -> u64 {
        self.no_box.as_ref().map_or(0, |e| e.value)
    }

    /// YES vote count (v4 decrease model).
    pub fn yes_votes(&self) -> u64 {
        self.yes_box.as_ref().map_or(0, |e| e.vote_count())
    }

    /// NO vote count (v4 decrease model).
    pub fn no_votes(&self) -> u64 {
        self.no_box.as_ref().map_or(0, |e| e.vote_count())
    }

    /// Determine the current leading side based on BallotBox values.
    /// In the v4 decrease model, lower value = more votes = winner.
    /// Returns None if either box is missing.
    pub fn leading_side(&self) -> Option<BallotSide> {
        let yes_val = self.yes_box.as_ref()?.value;
        let no_val = self.no_box.as_ref()?.value;
        if yes_val < no_val {
            Some(BallotSide::Yes)
        } else {
            Some(BallotSide::No) // tie goes to NO
        }
    }

    /// Check if the market is ready for settlement.
    /// Both boxes must be present and the market must not already be settled.
    pub fn is_settleable(&self) -> bool {
        !self.settled && self.yes_box.is_some() && self.no_box.is_some()
    }

    /// Check if the market has all components deployed.
    pub fn is_fully_deployed(&self) -> bool {
        self.split_merge.is_some() && self.yes_box.is_some() && self.no_box.is_some()
    }

    /// Collect all outpoints belonging to this market.
    pub fn outpoints(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(ref sm) = self.split_merge {
            out.push(sm.outpoint.clone());
        }
        if let Some(ref yb) = self.yes_box {
            out.push(yb.outpoint.clone());
        }
        if let Some(ref nb) = self.no_box {
            out.push(nb.outpoint.clone());
        }
        if let Some(ref r) = self.redemption {
            out.push(r.outpoint.clone());
        }
        out
    }
}

// PredictionBook

/// Prediction market order book / state tracker.
///
/// Tracks active markets and their component UTXOs. Provides O(1) lookup
/// by market_id and by outpoint (for processing spent inputs).
pub struct PredictionBook {
    /// Active markets: market_id (hex) -> MarketState.
    markets: HashMap<String, MarketState>,
    /// Reverse index: outpoint -> market_id for O(1) spend lookup.
    outpoint_index: HashMap<String, String>,
}

impl Default for PredictionBook {
    fn default() -> Self {
        Self::new()
    }
}

impl PredictionBook {
    pub fn new() -> Self {
        Self {
            markets: HashMap::new(),
            outpoint_index: HashMap::new(),
        }
    }

    /// Add a new market. Returns false if market_id already exists.
    pub fn add_market(&mut self, state: MarketState) -> bool {
        if self.markets.contains_key(&state.market_id) {
            return false;
        }
        // Index all outpoints
        for outpoint in state.outpoints() {
            self.outpoint_index.insert(outpoint, state.market_id.clone());
        }
        self.markets.insert(state.market_id.clone(), state);
        true
    }

    /// Get a market by ID.
    pub fn get_market(&self, market_id: &str) -> Option<&MarketState> {
        self.markets.get(market_id)
    }

    /// Get a mutable market by ID.
    pub fn get_market_mut(&mut self, market_id: &str) -> Option<&mut MarketState> {
        self.markets.get_mut(market_id)
    }

    /// Look up market_id by outpoint.
    pub fn market_id_for_outpoint(&self, outpoint: &str) -> Option<&str> {
        self.outpoint_index.get(outpoint).map(|s| s.as_str())
    }

    /// Check if an outpoint is tracked.
    pub fn contains_outpoint(&self, outpoint: &str) -> bool {
        self.outpoint_index.contains_key(outpoint)
    }

    /// Collect all tracked outpoint keys.
    pub fn all_outpoint_keys(&self) -> Vec<String> {
        self.outpoint_index.keys().cloned().collect()
    }

    /// Number of tracked markets.
    pub fn market_count(&self) -> usize {
        self.markets.len()
    }

    /// Total outpoints tracked.
    pub fn outpoint_count(&self) -> usize {
        self.outpoint_index.len()
    }

    /// Update the SplitMerge entry for a market.
    /// Replaces old outpoint index if present.
    pub fn update_split_merge(&mut self, market_id: &str, entry: SplitMergeEntry) -> bool {
        if let Some(market) = self.markets.get_mut(market_id) {
            // Remove old outpoint index
            if let Some(ref old) = market.split_merge {
                self.outpoint_index.remove(&old.outpoint);
            }
            // Add new outpoint index
            self.outpoint_index.insert(entry.outpoint.clone(), market_id.to_string());
            market.split_merge = Some(entry);
            true
        } else {
            false
        }
    }

    /// Update a BallotBox entry for a market.
    /// The side is determined by the entry's `side` field.
    pub fn update_ballot_box(&mut self, market_id: &str, entry: BallotBoxEntry) -> bool {
        if let Some(market) = self.markets.get_mut(market_id) {
            let box_ref = match entry.side {
                BallotSide::Yes => &mut market.yes_box,
                BallotSide::No => &mut market.no_box,
            };
            // Remove old outpoint index
            if let Some(ref old) = box_ref {
                self.outpoint_index.remove(&old.outpoint);
            }
            // Add new outpoint index
            self.outpoint_index.insert(entry.outpoint.clone(), market_id.to_string());
            *box_ref = Some(entry);
            true
        } else {
            false
        }
    }

    /// Settle a market: mark as settled and set the Redemption entry.
    pub fn settle_market(&mut self, market_id: &str, redemption: RedemptionEntry) -> bool {
        if let Some(market) = self.markets.get_mut(market_id) {
            // Remove old redemption outpoint if any
            if let Some(ref old) = market.redemption {
                self.outpoint_index.remove(&old.outpoint);
            }
            self.outpoint_index.insert(redemption.outpoint.clone(), market_id.to_string());
            market.redemption = Some(redemption);
            market.settled = true;
            true
        } else {
            false
        }
    }

    /// Update redemption entry (e.g., after a payout decreases pool).
    pub fn update_redemption(&mut self, market_id: &str, entry: RedemptionEntry) -> bool {
        if let Some(market) = self.markets.get_mut(market_id) {
            if let Some(ref old) = market.redemption {
                self.outpoint_index.remove(&old.outpoint);
            }
            self.outpoint_index.insert(entry.outpoint.clone(), market_id.to_string());
            market.redemption = Some(entry);
            true
        } else {
            false
        }
    }

    /// Remove an outpoint from the book (e.g., when spent on L1).
    /// Returns the market_id if the outpoint was found.
    ///
    /// This removes the specific UTXO entry from the market state.
    /// The market itself is NOT removed — it may still have other UTXOs.
    pub fn remove_by_outpoint(&mut self, outpoint: &str) -> Option<String> {
        let market_id = self.outpoint_index.remove(outpoint)?;
        if let Some(market) = self.markets.get_mut(&market_id) {
            if market.split_merge.as_ref().map_or(false, |e| e.outpoint == outpoint) {
                market.split_merge = None;
            }
            if market.yes_box.as_ref().map_or(false, |e| e.outpoint == outpoint) {
                market.yes_box = None;
            }
            if market.no_box.as_ref().map_or(false, |e| e.outpoint == outpoint) {
                market.no_box = None;
            }
            if market.redemption.as_ref().map_or(false, |e| e.outpoint == outpoint) {
                market.redemption = None;
            }
        }
        Some(market_id)
    }

    /// Remove an entire market. Returns the removed MarketState if found.
    pub fn remove_market(&mut self, market_id: &str) -> Option<MarketState> {
        if let Some(state) = self.markets.remove(market_id) {
            for outpoint in state.outpoints() {
                self.outpoint_index.remove(&outpoint);
            }
            Some(state)
        } else {
            None
        }
    }

    /// Iterate all active (unsettled) markets.
    pub fn active_markets(&self) -> Vec<&MarketState> {
        self.markets.values().filter(|m| !m.settled).collect()
    }

    /// Iterate all settled markets.
    pub fn settled_markets(&self) -> Vec<&MarketState> {
        self.markets.values().filter(|m| m.settled).collect()
    }

    /// All markets (both active and settled).
    pub fn all_markets(&self) -> impl Iterator<Item = (&String, &MarketState)> {
        self.markets.iter()
    }

    /// Get market odds as (yes_value, no_value).
    /// In v4 decrease model, lower value = more votes.
    /// Returns None if either box is missing.
    pub fn market_odds(&self, market_id: &str) -> Option<(u64, u64)> {
        let market = self.markets.get(market_id)?;
        let yes_val = market.yes_box.as_ref()?.value;
        let no_val = market.no_box.as_ref()?.value;
        Some((yes_val, no_val))
    }

    /// Total value across both ballot boxes.
    pub fn ballot_total_value(&self, market_id: &str) -> Option<u64> {
        let market = self.markets.get(market_id)?;
        let yes_val = market.yes_box.as_ref()?.value;
        let no_val = market.no_box.as_ref()?.value;
        Some(yes_val.saturating_add(no_val))
    }

    /// Get markets that are ready for settlement (both boxes present, not settled).
    pub fn settleable_markets(&self) -> Vec<&MarketState> {
        self.markets.values().filter(|m| m.is_settleable()).collect()
    }

    /// Get fully deployed markets (SplitMerge + YES box + NO box all present).
    pub fn fully_deployed_markets(&self) -> Vec<&MarketState> {
        self.markets.values().filter(|m| m.is_fully_deployed()).collect()
    }

    /// Sort markets by total value locked (descending).
    pub fn markets_by_tvl(&self) -> Vec<&MarketState> {
        let mut v: Vec<&MarketState> = self.markets.values().collect();
        v.sort_by(|a, b| b.total_value_locked().cmp(&a.total_value_locked()));
        v
    }

    /// Clear all markets (for testing).
    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.markets.clear();
        self.outpoint_index.clear();
    }

    /// Serialize market state for persistence (JSON-compatible).
    pub fn to_snapshot(&self) -> Vec<MarketSnapshot> {
        self.markets.values().map(|m| MarketSnapshot {
            market_id: m.market_id.clone(),
            market_id_bytes: m.market_id_bytes,
            yes_value: m.yes_value(),
            no_value: m.no_value(),
            total_value_locked: m.total_value_locked(),
            created_daa: m.created_daa,
            settled: m.settled,
            winning_side: m.redemption.as_ref().map(|r| r.winning_side),
            yes_votes: m.yes_votes(),
            no_votes: m.no_votes(),
        }).collect()
    }

    /// Serialize the book to JSON for persistence.
    pub fn to_json(&self) -> serde_json::Value {
        let markets: Vec<serde_json::Value> = self.markets.values().map(|m| {
            let sm = m.split_merge.as_ref().map(|s| serde_json::json!({
                "outpoint": s.outpoint,
                "value": s.value,
                "redeem_script": hex::encode(&s.redeem_script),
                "p2sh_script": hex::encode(&s.p2sh_script),
                "yes_token_cid": hex::encode(s.yes_token_cid),
                "no_token_cid": hex::encode(s.no_token_cid),
                "unit_value": s.unit_value,
                "creator_pkh": hex::encode(s.creator_pkh),
                "expiry_daa": s.expiry_daa,
            }));
            let yes_box = m.yes_box.as_ref().map(|b| Self::ballot_to_json(b));
            let no_box = m.no_box.as_ref().map(|b| Self::ballot_to_json(b));
            let redemption = m.redemption.as_ref().map(|r| serde_json::json!({
                "outpoint": r.outpoint,
                "value": r.value,
                "winning_side": match r.winning_side { BallotSide::Yes => "Yes", BallotSide::No => "No" },
                "yes_final_value": r.yes_final_value,
                "no_final_value": r.no_final_value,
                "payout_per_token": r.payout_per_token,
                "redeem_script": hex::encode(&r.redeem_script),
                "p2sh_script": hex::encode(&r.p2sh_script),
                "expiry_daa": r.expiry_daa,
            }));
            serde_json::json!({
                "market_id": m.market_id,
                "market_id_bytes": hex::encode(m.market_id_bytes),
                "split_merge": sm,
                "yes_box": yes_box,
                "no_box": no_box,
                "redemption": redemption,
                "created_daa": m.created_daa,
                "settled": m.settled,
            })
        }).collect();
        serde_json::json!({ "markets": markets })
    }

    fn ballot_to_json(b: &BallotBoxEntry) -> serde_json::Value {
        serde_json::json!({
            "outpoint": b.outpoint,
            "value": b.value,
            "side": match b.side { BallotSide::Yes => "Yes", BallotSide::No => "No" },
            "redeem_script": hex::encode(&b.redeem_script),
            "p2sh_script": hex::encode(&b.p2sh_script),
            "reward_per_vote": b.reward_per_vote,
            "start_daa": b.start_daa,
            "end_daa": b.end_daa,
            "expiry_daa": b.expiry_daa,
            "initial_value": b.initial_value,
        })
    }

    /// Deserialize the book from JSON. Returns None if the structure is invalid.
    pub fn from_json(json: &serde_json::Value) -> Option<Self> {
        let mut book = Self::new();
        let markets = json.get("markets")?.as_array()?;
        for m in markets {
            let market_id = m.get("market_id")?.as_str()?.to_string();
            let id_hex = m.get("market_id_bytes")?.as_str()?;
            let id_bytes_vec = hex::decode(id_hex).ok()?;
            if id_bytes_vec.len() != 32 { continue; }
            let mut market_id_bytes = [0u8; 32];
            market_id_bytes.copy_from_slice(&id_bytes_vec);
            let created_daa = m.get("created_daa").and_then(|v| v.as_u64()).unwrap_or(0);
            let settled = m.get("settled").and_then(|v| v.as_bool()).unwrap_or(false);

            let split_merge = m.get("split_merge").and_then(|v| {
                if v.is_null() { return None; }
                Some(SplitMergeEntry {
                    outpoint: v.get("outpoint")?.as_str()?.to_string(),
                    value: v.get("value")?.as_u64()?,
                    redeem_script: hex::decode(v.get("redeem_script")?.as_str()?).ok()?,
                    p2sh_script: hex::decode(v.get("p2sh_script")?.as_str()?).ok()?,
                    yes_token_cid: Self::parse_32b(v.get("yes_token_cid")?.as_str()?)?,
                    no_token_cid: Self::parse_32b(v.get("no_token_cid")?.as_str()?)?,
                    unit_value: v.get("unit_value")?.as_u64()?,
                    creator_pkh: Self::parse_32b(v.get("creator_pkh")?.as_str()?)?,
                    expiry_daa: v.get("expiry_daa")?.as_u64()?,
                })
            });
            let yes_box = m.get("yes_box").and_then(|v| Self::ballot_from_json(v));
            let no_box = m.get("no_box").and_then(|v| Self::ballot_from_json(v));
            let redemption = m.get("redemption").and_then(|v| {
                if v.is_null() { return None; }
                let side_str = v.get("winning_side")?.as_str()?;
                let winning_side = match side_str {
                    "Yes" => BallotSide::Yes,
                    "No" => BallotSide::No,
                    _ => return None,
                };
                Some(RedemptionEntry {
                    outpoint: v.get("outpoint")?.as_str()?.to_string(),
                    value: v.get("value")?.as_u64()?,
                    winning_side,
                    yes_final_value: v.get("yes_final_value")?.as_u64()?,
                    no_final_value: v.get("no_final_value")?.as_u64()?,
                    payout_per_token: v.get("payout_per_token")?.as_u64()?,
                    redeem_script: hex::decode(v.get("redeem_script")?.as_str()?).ok()?,
                    p2sh_script: hex::decode(v.get("p2sh_script")?.as_str()?).ok()?,
                    expiry_daa: v.get("expiry_daa")?.as_u64()?,
                })
            });

            let state = MarketState {
                market_id,
                market_id_bytes,
                split_merge,
                yes_box,
                no_box,
                redemption,
                created_daa,
                settled,
            };
            book.add_market(state);
        }
        Some(book)
    }

    fn parse_32b(hex_str: &str) -> Option<[u8; 32]> {
        let bytes = hex::decode(hex_str).ok()?;
        if bytes.len() != 32 { return None; }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(arr)
    }

    fn ballot_from_json(v: &serde_json::Value) -> Option<BallotBoxEntry> {
        if v.is_null() { return None; }
        let side_str = v.get("side")?.as_str()?;
        let side = match side_str {
            "Yes" => BallotSide::Yes,
            "No" => BallotSide::No,
            _ => return None,
        };
        Some(BallotBoxEntry {
            outpoint: v.get("outpoint")?.as_str()?.to_string(),
            value: v.get("value")?.as_u64()?,
            side,
            redeem_script: hex::decode(v.get("redeem_script")?.as_str()?).ok()?,
            p2sh_script: hex::decode(v.get("p2sh_script")?.as_str()?).ok()?,
            reward_per_vote: v.get("reward_per_vote")?.as_u64()?,
            start_daa: v.get("start_daa")?.as_u64()?,
            end_daa: v.get("end_daa")?.as_u64()?,
            expiry_daa: v.get("expiry_daa")?.as_u64()?,
            initial_value: v.get("initial_value")?.as_u64()?,
        })
    }
}

/// Serializable snapshot of a market for persistence / API responses.
#[derive(Debug, Clone)]
pub struct MarketSnapshot {
    pub market_id: String,
    pub market_id_bytes: [u8; 32],
    pub yes_value: u64,
    pub no_value: u64,
    pub total_value_locked: u64,
    pub created_daa: u64,
    pub settled: bool,
    pub winning_side: Option<BallotSide>,
    pub yes_votes: u64,
    pub no_votes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_market(id: &str, yes_val: u64, no_val: u64) -> MarketState {
        let mut id_bytes = [0u8; 32];
        let bytes = id.as_bytes();
        let len = bytes.len().min(32);
        id_bytes[..len].copy_from_slice(&bytes[..len]);

        MarketState {
            market_id: id.to_string(),
            market_id_bytes: id_bytes,
            split_merge: None,
            yes_box: Some(BallotBoxEntry {
                outpoint: format!("{id}_yes:0"),
                value: yes_val,
                side: BallotSide::Yes,
                redeem_script: vec![0x01],
                p2sh_script: vec![0x02],
                reward_per_vote: 100_000,
                start_daa: 1000,
                end_daa: 50_000,
                expiry_daa: 100_000,
                initial_value: 100_000_000,
            }),
            no_box: Some(BallotBoxEntry {
                outpoint: format!("{id}_no:0"),
                value: no_val,
                side: BallotSide::No,
                redeem_script: vec![0x03],
                p2sh_script: vec![0x04],
                reward_per_vote: 100_000,
                start_daa: 1000,
                end_daa: 50_000,
                expiry_daa: 100_000,
                initial_value: 100_000_000,
            }),
            redemption: None,
            created_daa: 500,
            settled: false,
        }
    }

    fn make_split_merge(market_id: &str) -> SplitMergeEntry {
        SplitMergeEntry {
            outpoint: format!("{market_id}_sm:0"),
            value: 50_000_000,
            redeem_script: vec![0x10],
            p2sh_script: vec![0x11],
            yes_token_cid: [0xaa; 32],
            no_token_cid: [0xbb; 32],
            unit_value: 100_000_000,
            creator_pkh: [0xcc; 32],
            expiry_daa: 200_000,
        }
    }

    fn make_redemption(market_id: &str, side: BallotSide) -> RedemptionEntry {
        RedemptionEntry {
            outpoint: format!("{market_id}_redeem:0"),
            value: 10_000_000,
            winning_side: side,
            yes_final_value: 80_000_000,
            no_final_value: 90_000_000,
            payout_per_token: 100_000_000,
            redeem_script: vec![0x20],
            p2sh_script: vec![0x21],
            expiry_daa: 200_000,
        }
    }

    // --- Basic CRUD ---

    #[test]
    fn new_book_is_empty() {
        let book = PredictionBook::new();
        assert_eq!(book.market_count(), 0);
        assert_eq!(book.outpoint_count(), 0);
    }

    #[test]
    fn add_market() {
        let mut book = PredictionBook::new();
        let market = make_market("mkt1", 90_000_000, 95_000_000);
        assert!(book.add_market(market));
        assert_eq!(book.market_count(), 1);
        assert!(book.get_market("mkt1").is_some());
    }

    #[test]
    fn add_duplicate_market_fails() {
        let mut book = PredictionBook::new();
        let m1 = make_market("mkt1", 90_000_000, 95_000_000);
        let m2 = make_market("mkt1", 80_000_000, 85_000_000);
        assert!(book.add_market(m1));
        assert!(!book.add_market(m2));
        assert_eq!(book.market_count(), 1);
    }

    #[test]
    fn outpoint_index_populated() {
        let mut book = PredictionBook::new();
        let market = make_market("mkt1", 90_000_000, 95_000_000);
        book.add_market(market);
        assert!(book.contains_outpoint("mkt1_yes:0"));
        assert!(book.contains_outpoint("mkt1_no:0"));
        assert_eq!(book.market_id_for_outpoint("mkt1_yes:0"), Some("mkt1"));
    }

    #[test]
    fn remove_by_outpoint() {
        let mut book = PredictionBook::new();
        book.add_market(make_market("mkt1", 90_000_000, 95_000_000));
        let mid = book.remove_by_outpoint("mkt1_yes:0");
        assert_eq!(mid.as_deref(), Some("mkt1"));
        let market = book.get_market("mkt1").unwrap();
        assert!(market.yes_box.is_none());
        assert!(market.no_box.is_some());
    }

    #[test]
    fn remove_market() {
        let mut book = PredictionBook::new();
        book.add_market(make_market("mkt1", 90_000_000, 95_000_000));
        let removed = book.remove_market("mkt1");
        assert!(removed.is_some());
        assert_eq!(book.market_count(), 0);
        assert_eq!(book.outpoint_count(), 0);
    }

    #[test]
    fn remove_nonexistent_market() {
        let mut book = PredictionBook::new();
        assert!(book.remove_market("nonexistent").is_none());
    }

    #[test]
    fn remove_nonexistent_outpoint() {
        let mut book = PredictionBook::new();
        assert!(book.remove_by_outpoint("nonexistent:0").is_none());
    }

    // --- Update operations ---

    #[test]
    fn update_split_merge() {
        let mut book = PredictionBook::new();
        book.add_market(make_market("mkt1", 90_000_000, 95_000_000));
        let sm = make_split_merge("mkt1");
        assert!(book.update_split_merge("mkt1", sm));
        assert!(book.contains_outpoint("mkt1_sm:0"));
        let market = book.get_market("mkt1").unwrap();
        assert!(market.split_merge.is_some());
    }

    #[test]
    fn update_split_merge_replaces_outpoint() {
        let mut book = PredictionBook::new();
        book.add_market(make_market("mkt1", 90_000_000, 95_000_000));
        let sm1 = make_split_merge("mkt1");
        book.update_split_merge("mkt1", sm1);
        assert!(book.contains_outpoint("mkt1_sm:0"));

        let mut sm2 = make_split_merge("mkt1");
        sm2.outpoint = "mkt1_sm:1".to_string();
        book.update_split_merge("mkt1", sm2);
        assert!(!book.contains_outpoint("mkt1_sm:0"));
        assert!(book.contains_outpoint("mkt1_sm:1"));
    }

    #[test]
    fn update_ballot_box() {
        let mut book = PredictionBook::new();
        book.add_market(make_market("mkt1", 90_000_000, 95_000_000));
        let new_yes = BallotBoxEntry {
            outpoint: "mkt1_yes:1".to_string(),
            value: 89_900_000,
            side: BallotSide::Yes,
            redeem_script: vec![0x01],
            p2sh_script: vec![0x02],
            reward_per_vote: 100_000,
            start_daa: 1000,
            end_daa: 50_000,
            expiry_daa: 100_000,
            initial_value: 100_000_000,
        };
        assert!(book.update_ballot_box("mkt1", new_yes));
        assert!(!book.contains_outpoint("mkt1_yes:0"));
        assert!(book.contains_outpoint("mkt1_yes:1"));
    }

    #[test]
    fn update_ballot_box_nonexistent_market() {
        let mut book = PredictionBook::new();
        let entry = BallotBoxEntry {
            outpoint: "x:0".to_string(),
            value: 100,
            side: BallotSide::Yes,
            redeem_script: vec![],
            p2sh_script: vec![],
            reward_per_vote: 100_000,
            start_daa: 1000,
            end_daa: 50_000,
            expiry_daa: 100_000,
            initial_value: 100_000_000,
        };
        assert!(!book.update_ballot_box("nonexistent", entry));
    }

    #[test]
    fn settle_market() {
        let mut book = PredictionBook::new();
        book.add_market(make_market("mkt1", 80_000_000, 90_000_000));
        let redemption = make_redemption("mkt1", BallotSide::Yes);
        assert!(book.settle_market("mkt1", redemption));
        let market = book.get_market("mkt1").unwrap();
        assert!(market.settled);
        assert!(market.redemption.is_some());
        assert!(book.contains_outpoint("mkt1_redeem:0"));
    }

    #[test]
    fn settle_nonexistent_market() {
        let mut book = PredictionBook::new();
        let r = make_redemption("mkt1", BallotSide::Yes);
        assert!(!book.settle_market("mkt1", r));
    }

    #[test]
    fn update_redemption() {
        let mut book = PredictionBook::new();
        book.add_market(make_market("mkt1", 80_000_000, 90_000_000));
        let r1 = make_redemption("mkt1", BallotSide::Yes);
        book.settle_market("mkt1", r1);

        let mut r2 = make_redemption("mkt1", BallotSide::Yes);
        r2.outpoint = "mkt1_redeem:1".to_string();
        r2.value = 9_000_000;
        assert!(book.update_redemption("mkt1", r2));
        assert!(!book.contains_outpoint("mkt1_redeem:0"));
        assert!(book.contains_outpoint("mkt1_redeem:1"));
    }

    // --- Query operations ---

    #[test]
    fn market_odds() {
        let mut book = PredictionBook::new();
        book.add_market(make_market("mkt1", 80_000_000, 90_000_000));
        let odds = book.market_odds("mkt1");
        assert_eq!(odds, Some((80_000_000, 90_000_000)));
    }

    #[test]
    fn market_odds_missing_box() {
        let mut book = PredictionBook::new();
        let mut market = make_market("mkt1", 80_000_000, 90_000_000);
        market.yes_box = None;
        book.add_market(market);
        assert!(book.market_odds("mkt1").is_none());
    }

    #[test]
    fn ballot_total_value() {
        let mut book = PredictionBook::new();
        book.add_market(make_market("mkt1", 80_000_000, 90_000_000));
        assert_eq!(book.ballot_total_value("mkt1"), Some(170_000_000));
    }

    #[test]
    fn active_markets() {
        let mut book = PredictionBook::new();
        book.add_market(make_market("mkt1", 80_000_000, 90_000_000));
        book.add_market(make_market("mkt2", 70_000_000, 85_000_000));
        let r = make_redemption("mkt1", BallotSide::Yes);
        book.settle_market("mkt1", r);
        assert_eq!(book.active_markets().len(), 1);
        assert_eq!(book.settled_markets().len(), 1);
    }

    #[test]
    fn settleable_markets() {
        let mut book = PredictionBook::new();
        book.add_market(make_market("mkt1", 80_000_000, 90_000_000));
        let mut market2 = make_market("mkt2", 70_000_000, 85_000_000);
        market2.yes_box = None;
        book.add_market(market2);
        assert_eq!(book.settleable_markets().len(), 1);
    }

    #[test]
    fn fully_deployed_markets() {
        let mut book = PredictionBook::new();
        let mut market = make_market("mkt1", 80_000_000, 90_000_000);
        market.split_merge = Some(make_split_merge("mkt1"));
        book.add_market(market);
        assert_eq!(book.fully_deployed_markets().len(), 1);

        book.add_market(make_market("mkt2", 70_000_000, 85_000_000));
        assert_eq!(book.fully_deployed_markets().len(), 1);
    }

    #[test]
    fn markets_by_tvl() {
        let mut book = PredictionBook::new();
        book.add_market(make_market("mkt1", 80_000_000, 90_000_000));
        book.add_market(make_market("mkt2", 70_000_000, 85_000_000));
        let sorted = book.markets_by_tvl();
        assert_eq!(sorted.len(), 2);
        assert!(sorted[0].total_value_locked() >= sorted[1].total_value_locked());
    }

    // --- MarketState methods ---

    #[test]
    fn market_state_total_value_locked() {
        let mut market = make_market("mkt1", 80_000_000, 90_000_000);
        market.split_merge = Some(make_split_merge("mkt1"));
        assert_eq!(market.total_value_locked(), 80_000_000 + 90_000_000 + 50_000_000);
    }

    #[test]
    fn market_state_votes() {
        let market = make_market("mkt1", 90_000_000, 95_000_000);
        // YES: (100M - 90M) / 100K = 100 votes
        assert_eq!(market.yes_votes(), 100);
        // NO: (100M - 95M) / 100K = 50 votes
        assert_eq!(market.no_votes(), 50);
    }

    #[test]
    fn leading_side_yes_lower() {
        // Lower value = more votes = winner
        let market = make_market("mkt1", 80_000_000, 90_000_000);
        assert_eq!(market.leading_side(), Some(BallotSide::Yes));
    }

    #[test]
    fn leading_side_no_lower() {
        let market = make_market("mkt1", 90_000_000, 80_000_000);
        assert_eq!(market.leading_side(), Some(BallotSide::No));
    }

    #[test]
    fn leading_side_tie_goes_to_no() {
        let market = make_market("mkt1", 85_000_000, 85_000_000);
        assert_eq!(market.leading_side(), Some(BallotSide::No));
    }

    #[test]
    fn leading_side_missing_box() {
        let mut market = make_market("mkt1", 80_000_000, 90_000_000);
        market.yes_box = None;
        assert!(market.leading_side().is_none());
    }

    #[test]
    fn ballot_box_vote_count() {
        let entry = BallotBoxEntry {
            outpoint: "tx:0".to_string(),
            value: 90_000_000,
            side: BallotSide::Yes,
            redeem_script: vec![],
            p2sh_script: vec![],
            reward_per_vote: 100_000,
            start_daa: 1000,
            end_daa: 50_000,
            expiry_daa: 100_000,
            initial_value: 100_000_000,
        };
        assert_eq!(entry.vote_count(), 100);
    }

    #[test]
    fn ballot_box_vote_count_zero_reward() {
        let entry = BallotBoxEntry {
            outpoint: "tx:0".to_string(),
            value: 90_000_000,
            side: BallotSide::Yes,
            redeem_script: vec![],
            p2sh_script: vec![],
            reward_per_vote: 0,
            start_daa: 1000,
            end_daa: 50_000,
            expiry_daa: 100_000,
            initial_value: 100_000_000,
        };
        assert_eq!(entry.vote_count(), 0);
    }

    #[test]
    fn is_settleable() {
        let market = make_market("mkt1", 80_000_000, 90_000_000);
        assert!(market.is_settleable());
    }

    #[test]
    fn not_settleable_when_settled() {
        let mut market = make_market("mkt1", 80_000_000, 90_000_000);
        market.settled = true;
        assert!(!market.is_settleable());
    }

    #[test]
    fn not_settleable_when_missing_box() {
        let mut market = make_market("mkt1", 80_000_000, 90_000_000);
        market.no_box = None;
        assert!(!market.is_settleable());
    }

    #[test]
    fn snapshot() {
        let mut book = PredictionBook::new();
        book.add_market(make_market("mkt1", 80_000_000, 90_000_000));
        let snapshots = book.to_snapshot();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].yes_value, 80_000_000);
        assert_eq!(snapshots[0].no_value, 90_000_000);
        assert!(!snapshots[0].settled);
    }

    #[test]
    fn default_impl() {
        let book = PredictionBook::default();
        assert_eq!(book.market_count(), 0);
    }

    #[test]
    fn display_ballot_side() {
        assert_eq!(format!("{}", BallotSide::Yes), "YES");
        assert_eq!(format!("{}", BallotSide::No), "NO");
    }

    #[test]
    fn clear_book() {
        let mut book = PredictionBook::new();
        book.add_market(make_market("mkt1", 80_000_000, 90_000_000));
        book.add_market(make_market("mkt2", 70_000_000, 85_000_000));
        book.clear();
        assert_eq!(book.market_count(), 0);
        assert_eq!(book.outpoint_count(), 0);
    }

    #[test]
    fn outpoints_collected() {
        let mut market = make_market("mkt1", 80_000_000, 90_000_000);
        market.split_merge = Some(make_split_merge("mkt1"));
        let outpoints = market.outpoints();
        assert_eq!(outpoints.len(), 3); // sm + yes + no
    }

    #[test]
    fn update_split_merge_nonexistent() {
        let mut book = PredictionBook::new();
        let sm = make_split_merge("mkt1");
        assert!(!book.update_split_merge("mkt1", sm));
    }

    #[test]
    fn update_redemption_nonexistent() {
        let mut book = PredictionBook::new();
        let r = make_redemption("mkt1", BallotSide::Yes);
        assert!(!book.update_redemption("mkt1", r));
    }

    #[test]
    fn multiple_markets_independent() {
        let mut book = PredictionBook::new();
        book.add_market(make_market("mkt1", 80_000_000, 90_000_000));
        book.add_market(make_market("mkt2", 70_000_000, 85_000_000));

        book.remove_by_outpoint("mkt1_yes:0");
        assert!(book.get_market("mkt1").unwrap().yes_box.is_none());
        assert!(book.get_market("mkt2").unwrap().yes_box.is_some());
    }
}
