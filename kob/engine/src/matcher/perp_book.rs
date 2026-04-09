//! Perpetual futures order book with price-priority matching.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};

/// Side of a perpetual futures order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerpSide {
    Long,
    Short,
}

/// A perpetual futures order resting on the book.
#[derive(Debug, Clone)]
pub struct PerpOrder {
    /// Transaction ID of the deploy UTXO.
    pub tx_id: String,
    /// Output index within the deploy TX.
    pub index: u32,
    /// Order side (Long = buy perp, Short = sell perp).
    pub side: PerpSide,
    /// Margin deposited by this order (sompi).
    pub margin: u64,
    /// Leverage numerator (e.g., 10 for 10x).
    pub leverage_num: u64,
    /// Leverage denominator (e.g., 1 for 10x).
    pub leverage_den: u64,
    /// Desired entry price numerator.
    pub price_num: u64,
    /// Desired entry price denominator.
    pub price_den: u64,
    /// Blake2b-256 hash of the owner's scriptPublicKey.
    pub owner_spk_hash: [u8; 32],
    /// Actual owner SPK bytes (hex-encoded), needed for output construction.
    /// None if not available from payload.
    pub owner_spk: Option<String>,
    /// Cached redeemScript (hex-encoded).
    pub redeem_script_hex: String,
    /// Cached P2SH script (hex-encoded).
    pub p2sh_script_hex: String,
    /// UTXO value (total deposited in the order UTXO).
    pub value: u64,
    /// Maintenance margin percentage numerator.
    pub maint_pct_num: u64,
    /// Maintenance margin percentage denominator.
    pub maint_pct_den: u64,
    /// Keeper fee for liquidation (sompi).
    pub keeper_fee: u64,
    /// DAA score when this order was discovered.
    pub discovered_daa: u64,
    /// If true, this order may only reduce or close an existing position,
    /// never open a new one or increase an existing one.
    /// This is an engine-level constraint; not encoded in the covenant.
    pub reduce_only: bool,
}

impl PerpOrder {
    /// Outpoint key in "txId:index" format.
    pub fn outpoint_key(&self) -> String {
        format!("{}:{}", self.tx_id, self.index)
    }

    /// Check whether a reduce_only order is valid given the trader's current
    /// position on this instrument.
    ///
    /// - `existing_side`: the side of the trader's current open position, or
    ///   `None` if no position exists.
    ///
    /// Rules:
    /// - `reduce_only == false` → always valid (normal order).
    /// - `reduce_only == true` + no existing position → **invalid** (would
    ///   open a new position).
    /// - `reduce_only == true` + existing position is the **opposite** side →
    ///   **valid** (closes / reduces the position).
    /// - `reduce_only == true` + existing position is the **same** side →
    ///   **invalid** (would increase the position).
    pub fn is_valid_reduce_only(&self, existing_side: Option<PerpSide>) -> bool {
        if !self.reduce_only {
            return true;
        }
        match existing_side {
            None => false,
            Some(pos_side) => pos_side != self.side,
        }
    }
}

// BTreeMap sort keys (same pattern as spot order_book.rs)

/// Sort key for price-priority ordering.
#[derive(Debug, Clone)]
struct PriceKey {
    price_num: u64,
    price_den: u64,
    margin: u64,
    outpoint_key: String,
}

impl PriceKey {
    fn price_cmp(&self, other: &Self) -> Ordering {
        let lhs = (self.price_num as u128) * (other.price_den as u128);
        let rhs = (other.price_num as u128) * (self.price_den as u128);
        lhs.cmp(&rhs)
    }
}

/// Long key: highest price first (DESC), then highest margin first.
#[derive(Debug, Clone)]
struct LongKey(PriceKey);

impl PartialEq for LongKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.outpoint_key == other.0.outpoint_key
    }
}
impl Eq for LongKey {}

impl PartialOrd for LongKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LongKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse price (DESC): higher price first
        let price_ord = other.0.price_cmp(&self.0);
        if price_ord != Ordering::Equal {
            return price_ord;
        }
        // Tiebreak: higher margin first
        let margin_ord = other.0.margin.cmp(&self.0.margin);
        if margin_ord != Ordering::Equal {
            return margin_ord;
        }
        self.0.outpoint_key.cmp(&other.0.outpoint_key)
    }
}

/// Short key: lowest price first (ASC), then lowest margin first.
#[derive(Debug, Clone)]
struct ShortKey(PriceKey);

impl PartialEq for ShortKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.outpoint_key == other.0.outpoint_key
    }
}
impl Eq for ShortKey {}

impl PartialOrd for ShortKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ShortKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // Normal price (ASC): lower price first
        let price_ord = self.0.price_cmp(&other.0);
        if price_ord != Ordering::Equal {
            return price_ord;
        }
        // Tiebreak: lower margin first
        let margin_ord = self.0.margin.cmp(&other.0.margin);
        if margin_ord != Ordering::Equal {
            return margin_ord;
        }
        self.0.outpoint_key.cmp(&other.0.outpoint_key)
    }
}

// PerpOrderBook

/// A crossing pair of Long + Short perp orders ready to be matched.
#[derive(Debug, Clone)]
pub struct PerpCrossingPair {
    pub long_order: PerpOrder,
    pub short_order: PerpOrder,
    /// Agreed entry price numerator (midpoint or aggressor price).
    pub entry_price_num: u64,
    /// Agreed entry price denominator.
    pub entry_price_den: u64,
}

/// Perpetual futures order book.
///
/// Maintains separate Long (bid) and Short (ask) sides with price-priority
/// ordering. Uses a HashMap for O(1) outpoint lookup and BTreeMap for
/// sorted iteration.
pub struct PerpOrderBook {
    longs: BTreeMap<LongKey, PerpOrder>,
    shorts: BTreeMap<ShortKey, PerpOrder>,
    /// Reverse lookup: outpoint_key -> side for O(1) removal.
    long_outpoints: HashMap<String, LongKey>,
    short_outpoints: HashMap<String, ShortKey>,
}

impl Default for PerpOrderBook {
    fn default() -> Self {
        Self::new()
    }
}

impl PerpOrderBook {
    pub fn new() -> Self {
        Self {
            longs: BTreeMap::new(),
            shorts: BTreeMap::new(),
            long_outpoints: HashMap::new(),
            short_outpoints: HashMap::new(),
        }
    }

    /// Insert a perp order into the appropriate side.
    ///
    /// If an order with the same outpoint key already exists, it is removed
    /// first to prevent stale entries leaking in the BTreeMap (MEDIUM-3 fix).
    pub fn insert(&mut self, order: PerpOrder) {
        let outpoint = order.outpoint_key();
        // Remove any existing entry with the same outpoint to prevent leaks
        self.remove(&outpoint);
        match order.side {
            PerpSide::Long => {
                let key = LongKey(PriceKey {
                    price_num: order.price_num,
                    price_den: order.price_den,
                    margin: order.margin,
                    outpoint_key: outpoint.clone(),
                });
                self.long_outpoints.insert(outpoint, key.clone());
                self.longs.insert(key, order);
            }
            PerpSide::Short => {
                let key = ShortKey(PriceKey {
                    price_num: order.price_num,
                    price_den: order.price_den,
                    margin: order.margin,
                    outpoint_key: outpoint.clone(),
                });
                self.short_outpoints.insert(outpoint, key.clone());
                self.shorts.insert(key, order);
            }
        }
    }

    /// Remove an order by outpoint key. Returns the removed order if found.
    pub fn remove(&mut self, outpoint_key: &str) -> Option<PerpOrder> {
        if let Some(key) = self.long_outpoints.remove(outpoint_key) {
            return self.longs.remove(&key);
        }
        if let Some(key) = self.short_outpoints.remove(outpoint_key) {
            return self.shorts.remove(&key);
        }
        None
    }

    /// Look up an order by outpoint key (O(1) via HashMap).
    pub fn get(&self, outpoint_key: &str) -> Option<&PerpOrder> {
        if let Some(key) = self.long_outpoints.get(outpoint_key) {
            return self.longs.get(key);
        }
        if let Some(key) = self.short_outpoints.get(outpoint_key) {
            return self.shorts.get(key);
        }
        None
    }

    /// Check if an outpoint exists in the book.
    pub fn contains(&self, outpoint_key: &str) -> bool {
        self.long_outpoints.contains_key(outpoint_key)
            || self.short_outpoints.contains_key(outpoint_key)
    }

    /// Collect all outpoint keys from both sides.
    pub fn all_outpoint_keys(&self) -> Vec<String> {
        self.long_outpoints
            .keys()
            .chain(self.short_outpoints.keys())
            .cloned()
            .collect()
    }

    /// Number of Long orders.
    pub fn long_count(&self) -> usize {
        self.longs.len()
    }

    /// Number of Short orders.
    pub fn short_count(&self) -> usize {
        self.shorts.len()
    }

    /// Total orders in the book.
    pub fn total_count(&self) -> usize {
        self.longs.len() + self.shorts.len()
    }

    /// Get the best (highest) Long bid price as (num, den), or None if empty.
    pub fn best_long_price(&self) -> Option<(u64, u64)> {
        self.longs
            .iter()
            .next()
            .map(|(_, o)| (o.price_num, o.price_den))
    }

    /// Get the best (lowest) Short ask price as (num, den), or None if empty.
    pub fn best_short_price(&self) -> Option<(u64, u64)> {
        self.shorts
            .iter()
            .next()
            .map(|(_, o)| (o.price_num, o.price_den))
    }

    /// Find all crossing pairs where Long bid >= Short ask.
    ///
    /// Returns pairs sorted by price overlap (best crossings first).
    /// Excludes self-trades (same owner_spk_hash on both sides).
    ///
    /// Entry price for each crossing is the midpoint:
    ///   entry = (long_price + short_price) / 2
    /// Encoded as: num = long_num * short_den + short_num * long_den,
    ///             den = 2 * long_den * short_den
    pub fn find_crossing_pairs(&self) -> Vec<PerpCrossingPair> {
        let mut pairs = Vec::new();
        let max_iterations: usize = 50_000;
        let mut iterations: usize = 0;

        for (_, long_order) in self.longs.iter() {
            for (_, short_order) in self.shorts.iter() {
                iterations += 1;
                if iterations > max_iterations {
                    return pairs;
                }

                // Check crossing: long_price >= short_price
                // long_num/long_den >= short_num/short_den
                // long_num * short_den >= short_num * long_den
                let lhs = (long_order.price_num as u128)
                    .checked_mul(short_order.price_den as u128);
                let rhs = (short_order.price_num as u128)
                    .checked_mul(long_order.price_den as u128);

                let (lhs, rhs) = match (lhs, rhs) {
                    (Some(l), Some(r)) => (l, r),
                    _ => continue, // overflow, skip
                };

                if lhs < rhs {
                    // Long price < Short price: no crossing (and no further
                    // shorts can cross since they're ASC).
                    break;
                }

                // Self-trade prevention
                if long_order.owner_spk_hash == short_order.owner_spk_hash {
                    continue;
                }

                // Compute midpoint entry price:
                // (long_num/long_den + short_num/short_den) / 2
                // = (long_num * short_den + short_num * long_den) / (2 * long_den * short_den)
                let num = (long_order.price_num as u128)
                    .checked_mul(short_order.price_den as u128)
                    .and_then(|a| {
                        (short_order.price_num as u128)
                            .checked_mul(long_order.price_den as u128)
                            .and_then(|b| a.checked_add(b))
                    });
                let den = (long_order.price_den as u128)
                    .checked_mul(short_order.price_den as u128)
                    .and_then(|d| d.checked_mul(2));

                let (entry_num, entry_den) = match (num, den) {
                    (Some(n), Some(d)) if d > 0 => {
                        // Try to fit in u64 by GCD reduction
                        let g = gcd_u128(n, d);
                        let n_reduced = n / g;
                        let d_reduced = d / g;
                        if n_reduced > u64::MAX as u128 || d_reduced > u64::MAX as u128 {
                            continue; // overflow, skip this pair
                        }
                        (n_reduced as u64, d_reduced as u64)
                    }
                    _ => continue,
                };

                pairs.push(PerpCrossingPair {
                    long_order: long_order.clone(),
                    short_order: short_order.clone(),
                    entry_price_num: entry_num,
                    entry_price_den: entry_den,
                });
            }
        }

        pairs
    }

    /// Iterate all Long orders in price-priority order (highest first).
    pub fn iter_longs(&self) -> impl Iterator<Item = &PerpOrder> {
        self.longs.values()
    }

    /// Iterate all Short orders in price-priority order (lowest first).
    pub fn iter_shorts(&self) -> impl Iterator<Item = &PerpOrder> {
        self.shorts.values()
    }

    /// Clear all orders from the book.
    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.longs.clear();
        self.shorts.clear();
        self.long_outpoints.clear();
        self.short_outpoints.clear();
    }


    /// Serialize the book to JSON for persistence.
    pub fn to_json(&self) -> serde_json::Value {
        let orders: Vec<serde_json::Value> = self
            .longs
            .values()
            .chain(self.shorts.values())
            .map(|o| {
                let side_str = match o.side {
                    PerpSide::Long => "Long",
                    PerpSide::Short => "Short",
                };
                serde_json::json!({
                    "tx_id": o.tx_id,
                    "index": o.index,
                    "side": side_str,
                    "margin": o.margin,
                    "leverage_num": o.leverage_num,
                    "leverage_den": o.leverage_den,
                    "price_num": o.price_num,
                    "price_den": o.price_den,
                    "owner_spk_hash": hex::encode(o.owner_spk_hash),
                    "owner_spk": o.owner_spk,
                    "redeem_script_hex": o.redeem_script_hex,
                    "p2sh_script_hex": o.p2sh_script_hex,
                    "value": o.value,
                    "maint_pct_num": o.maint_pct_num,
                    "maint_pct_den": o.maint_pct_den,
                    "keeper_fee": o.keeper_fee,
                    "discovered_daa": o.discovered_daa,
                    "reduce_only": o.reduce_only,
                })
            })
            .collect();

        serde_json::json!({ "orders": orders })
    }

    /// Deserialize the book from JSON. Returns None if the structure is invalid.
    pub fn from_json(json: &serde_json::Value) -> Option<Self> {
        let mut book = Self::new();

        let orders = json.get("orders")?.as_array()?;
        for o in orders {
            let tx_id = o.get("tx_id")?.as_str()?.to_string();
            let index = o.get("index")?.as_u64()? as u32;
            let side_str = o.get("side")?.as_str()?;
            let side = match side_str {
                "Long" => PerpSide::Long,
                "Short" => PerpSide::Short,
                _ => continue,
            };
            let margin = o.get("margin")?.as_u64()?;
            let leverage_num = o.get("leverage_num")?.as_u64()?;
            let leverage_den = o.get("leverage_den")?.as_u64()?;
            let price_num = o.get("price_num")?.as_u64()?;
            let price_den = o.get("price_den")?.as_u64()?;

            let owner_hash_hex = o.get("owner_spk_hash")?.as_str()?;
            let owner_hash_bytes = hex::decode(owner_hash_hex).ok()?;
            if owner_hash_bytes.len() != 32 {
                continue;
            }
            let mut owner_spk_hash = [0u8; 32];
            owner_spk_hash.copy_from_slice(&owner_hash_bytes);

            let owner_spk = o
                .get("owner_spk")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let redeem_script_hex = o.get("redeem_script_hex")?.as_str()?.to_string();
            let p2sh_script_hex = o.get("p2sh_script_hex")?.as_str()?.to_string();
            let value = o.get("value")?.as_u64()?;
            let maint_pct_num = o.get("maint_pct_num")?.as_u64()?;
            let maint_pct_den = o.get("maint_pct_den")?.as_u64()?;
            let keeper_fee = o.get("keeper_fee")?.as_u64()?;
            let discovered_daa = o.get("discovered_daa").and_then(|v| v.as_u64()).unwrap_or(0);
            let reduce_only = o.get("reduce_only").and_then(|v| v.as_bool()).unwrap_or(false);

            book.insert(PerpOrder {
                tx_id,
                index,
                side,
                margin,
                leverage_num,
                leverage_den,
                price_num,
                price_den,
                owner_spk_hash,
                owner_spk,
                redeem_script_hex,
                p2sh_script_hex,
                value,
                maint_pct_num,
                maint_pct_den,
                keeper_fee,
                discovered_daa,
                reduce_only,
            });
        }

        Some(book)
    }
}

/// GCD for u128 values (used in midpoint price normalization).
fn gcd_u128(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_order(
        tx_id: &str,
        index: u32,
        side: PerpSide,
        price_num: u64,
        price_den: u64,
        margin: u64,
        owner: [u8; 32],
    ) -> PerpOrder {
        PerpOrder {
            tx_id: tx_id.to_string(),
            index,
            side,
            margin,
            leverage_num: 10,
            leverage_den: 1,
            price_num,
            price_den,
            owner_spk_hash: owner,
            owner_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            value: margin,
            maint_pct_num: 5,
            maint_pct_den: 100,
            keeper_fee: 10_000,
            discovered_daa: 1000,
            reduce_only: false,
        }
    }

    #[test]
    fn insert_and_count() {
        let mut book = PerpOrderBook::new();
        assert_eq!(book.total_count(), 0);

        book.insert(make_order("tx1", 0, PerpSide::Long, 100, 1, 50_000, [1; 32]));
        book.insert(make_order("tx2", 0, PerpSide::Short, 110, 1, 60_000, [2; 32]));

        assert_eq!(book.long_count(), 1);
        assert_eq!(book.short_count(), 1);
        assert_eq!(book.total_count(), 2);
    }

    #[test]
    fn remove_order() {
        let mut book = PerpOrderBook::new();
        book.insert(make_order("tx1", 0, PerpSide::Long, 100, 1, 50_000, [1; 32]));
        book.insert(make_order("tx2", 0, PerpSide::Short, 110, 1, 60_000, [2; 32]));

        let removed = book.remove("tx1:0");
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().tx_id, "tx1");
        assert_eq!(book.long_count(), 0);
        assert_eq!(book.short_count(), 1);

        // Remove non-existent
        assert!(book.remove("tx99:0").is_none());
    }

    #[test]
    fn get_order() {
        let mut book = PerpOrderBook::new();
        book.insert(make_order("tx1", 0, PerpSide::Long, 100, 1, 50_000, [1; 32]));

        let order = book.get("tx1:0");
        assert!(order.is_some());
        assert_eq!(order.unwrap().margin, 50_000);

        assert!(book.get("tx99:0").is_none());
    }

    #[test]
    fn contains_order() {
        let mut book = PerpOrderBook::new();
        book.insert(make_order("tx1", 0, PerpSide::Long, 100, 1, 50_000, [1; 32]));

        assert!(book.contains("tx1:0"));
        assert!(!book.contains("tx99:0"));
    }

    #[test]
    fn best_prices() {
        let mut book = PerpOrderBook::new();

        assert!(book.best_long_price().is_none());
        assert!(book.best_short_price().is_none());

        book.insert(make_order("tx1", 0, PerpSide::Long, 100, 1, 50_000, [1; 32]));
        book.insert(make_order("tx2", 0, PerpSide::Long, 105, 1, 50_000, [2; 32]));
        book.insert(make_order("tx3", 0, PerpSide::Short, 110, 1, 50_000, [3; 32]));
        book.insert(make_order("tx4", 0, PerpSide::Short, 108, 1, 50_000, [4; 32]));

        // Best long = highest price = 105
        assert_eq!(book.best_long_price(), Some((105, 1)));
        // Best short = lowest price = 108
        assert_eq!(book.best_short_price(), Some((108, 1)));
    }

    #[test]
    fn long_price_ordering_desc() {
        let mut book = PerpOrderBook::new();
        book.insert(make_order("tx1", 0, PerpSide::Long, 100, 1, 50_000, [1; 32]));
        book.insert(make_order("tx2", 0, PerpSide::Long, 105, 1, 50_000, [2; 32]));
        book.insert(make_order("tx3", 0, PerpSide::Long, 103, 1, 50_000, [3; 32]));

        let prices: Vec<u64> = book.iter_longs().map(|o| o.price_num).collect();
        assert_eq!(prices, vec![105, 103, 100]);
    }

    #[test]
    fn short_price_ordering_asc() {
        let mut book = PerpOrderBook::new();
        book.insert(make_order("tx1", 0, PerpSide::Short, 110, 1, 50_000, [1; 32]));
        book.insert(make_order("tx2", 0, PerpSide::Short, 108, 1, 50_000, [2; 32]));
        book.insert(make_order("tx3", 0, PerpSide::Short, 115, 1, 50_000, [3; 32]));

        let prices: Vec<u64> = book.iter_shorts().map(|o| o.price_num).collect();
        assert_eq!(prices, vec![108, 110, 115]);
    }

    #[test]
    fn crossing_pair_found() {
        let mut book = PerpOrderBook::new();
        // Long at 110, Short at 108 -> crosses (Long bid >= Short ask)
        book.insert(make_order("tx1", 0, PerpSide::Long, 110, 1, 50_000, [1; 32]));
        book.insert(make_order("tx2", 0, PerpSide::Short, 108, 1, 50_000, [2; 32]));

        let pairs = book.find_crossing_pairs();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].long_order.tx_id, "tx1");
        assert_eq!(pairs[0].short_order.tx_id, "tx2");
        // Midpoint: (110 + 108) / 2 = 109
        assert_eq!(pairs[0].entry_price_num, 109);
        assert_eq!(pairs[0].entry_price_den, 1);
    }

    #[test]
    fn no_crossing_when_long_below_short() {
        let mut book = PerpOrderBook::new();
        // Long at 100, Short at 110 -> no crossing
        book.insert(make_order("tx1", 0, PerpSide::Long, 100, 1, 50_000, [1; 32]));
        book.insert(make_order("tx2", 0, PerpSide::Short, 110, 1, 50_000, [2; 32]));

        let pairs = book.find_crossing_pairs();
        assert!(pairs.is_empty());
    }

    #[test]
    fn self_trade_prevention() {
        let mut book = PerpOrderBook::new();
        let owner = [1; 32];
        // Same owner on both sides -> excluded
        book.insert(make_order("tx1", 0, PerpSide::Long, 110, 1, 50_000, owner));
        book.insert(make_order("tx2", 0, PerpSide::Short, 108, 1, 50_000, owner));

        let pairs = book.find_crossing_pairs();
        assert!(pairs.is_empty());
    }

    #[test]
    fn crossing_with_rational_prices() {
        let mut book = PerpOrderBook::new();
        // Long at 3/2 = 1.5, Short at 4/3 = 1.333... -> crosses (1.5 >= 1.333)
        book.insert(make_order("tx1", 0, PerpSide::Long, 3, 2, 50_000, [1; 32]));
        book.insert(make_order("tx2", 0, PerpSide::Short, 4, 3, 50_000, [2; 32]));

        let pairs = book.find_crossing_pairs();
        assert_eq!(pairs.len(), 1);
        // Midpoint: (3/2 + 4/3) / 2 = (9/6 + 8/6) / 2 = 17/12
        assert_eq!(pairs[0].entry_price_num, 17);
        assert_eq!(pairs[0].entry_price_den, 12);
    }

    #[test]
    fn exact_price_match_crosses() {
        let mut book = PerpOrderBook::new();
        // Both at same price -> crosses
        book.insert(make_order("tx1", 0, PerpSide::Long, 100, 1, 50_000, [1; 32]));
        book.insert(make_order("tx2", 0, PerpSide::Short, 100, 1, 50_000, [2; 32]));

        let pairs = book.find_crossing_pairs();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].entry_price_num, 100);
        assert_eq!(pairs[0].entry_price_den, 1);
    }

    #[test]
    fn multiple_crossings() {
        let mut book = PerpOrderBook::new();
        book.insert(make_order("long1", 0, PerpSide::Long, 110, 1, 50_000, [1; 32]));
        book.insert(make_order("long2", 0, PerpSide::Long, 105, 1, 50_000, [2; 32]));
        book.insert(make_order("short1", 0, PerpSide::Short, 100, 1, 50_000, [3; 32]));
        book.insert(make_order("short2", 0, PerpSide::Short, 108, 1, 50_000, [4; 32]));

        let pairs = book.find_crossing_pairs();
        // long1 (110) crosses short1 (100) and short2 (108)
        // long2 (105) crosses short1 (100) but NOT short2 (108)
        assert_eq!(pairs.len(), 3);
    }

    #[test]
    fn remove_clears_from_both_indices() {
        let mut book = PerpOrderBook::new();
        book.insert(make_order("tx1", 0, PerpSide::Long, 100, 1, 50_000, [1; 32]));
        book.remove("tx1:0");

        assert!(!book.contains("tx1:0"));
        assert!(book.get("tx1:0").is_none());
        assert_eq!(book.long_count(), 0);
    }

    #[test]
    fn clear_empties_book() {
        let mut book = PerpOrderBook::new();
        book.insert(make_order("tx1", 0, PerpSide::Long, 100, 1, 50_000, [1; 32]));
        book.insert(make_order("tx2", 0, PerpSide::Short, 110, 1, 50_000, [2; 32]));
        book.clear();

        assert_eq!(book.total_count(), 0);
        assert!(!book.contains("tx1:0"));
        assert!(!book.contains("tx2:0"));
    }

    #[test]
    fn margin_tiebreak_for_longs() {
        let mut book = PerpOrderBook::new();
        // Same price, different margin -> higher margin first for longs
        book.insert(make_order("tx1", 0, PerpSide::Long, 100, 1, 50_000, [1; 32]));
        book.insert(make_order("tx2", 0, PerpSide::Long, 100, 1, 80_000, [2; 32]));

        let first = book.iter_longs().next().unwrap();
        assert_eq!(first.margin, 80_000);
    }

    #[test]
    fn margin_tiebreak_for_shorts() {
        let mut book = PerpOrderBook::new();
        // Same price, different margin -> lower margin first for shorts
        book.insert(make_order("tx1", 0, PerpSide::Short, 100, 1, 80_000, [1; 32]));
        book.insert(make_order("tx2", 0, PerpSide::Short, 100, 1, 50_000, [2; 32]));

        let first = book.iter_shorts().next().unwrap();
        assert_eq!(first.margin, 50_000);
    }

    #[test]
    fn empty_book_no_crossings() {
        let book = PerpOrderBook::new();
        assert!(book.find_crossing_pairs().is_empty());
    }

    #[test]
    fn only_longs_no_crossings() {
        let mut book = PerpOrderBook::new();
        book.insert(make_order("tx1", 0, PerpSide::Long, 100, 1, 50_000, [1; 32]));
        assert!(book.find_crossing_pairs().is_empty());
    }

    #[test]
    fn only_shorts_no_crossings() {
        let mut book = PerpOrderBook::new();
        book.insert(make_order("tx1", 0, PerpSide::Short, 100, 1, 50_000, [1; 32]));
        assert!(book.find_crossing_pairs().is_empty());
    }

    #[test]
    fn gcd_u128_basic() {
        assert_eq!(gcd_u128(12, 8), 4);
        assert_eq!(gcd_u128(17, 13), 1);
        assert_eq!(gcd_u128(0, 5), 5);
        assert_eq!(gcd_u128(100, 100), 100);
    }

    #[test]
    fn outpoint_key_format() {
        let order = make_order("abcdef1234", 3, PerpSide::Long, 100, 1, 50_000, [1; 32]);
        assert_eq!(order.outpoint_key(), "abcdef1234:3");
    }

    #[test]
    fn insert_duplicate_outpoint_overwrites() {
        let mut book = PerpOrderBook::new();
        book.insert(make_order("tx1", 0, PerpSide::Long, 100, 1, 50_000, [1; 32]));
        book.insert(make_order("tx1", 0, PerpSide::Long, 105, 1, 60_000, [1; 32]));

        // MEDIUM-3 fix: insert now calls remove() first, so no leak
        assert!(book.contains("tx1:0"));
        assert_eq!(book.long_count(), 1, "duplicate insert must not leak entries");
        let order = book.get("tx1:0").unwrap();
        assert_eq!(order.price_num, 105, "second insert must win");
        assert_eq!(order.margin, 60_000);
    }

    #[test]
    fn remove_long_does_not_affect_shorts() {
        let mut book = PerpOrderBook::new();
        book.insert(make_order("tx1", 0, PerpSide::Long, 100, 1, 50_000, [1; 32]));
        book.insert(make_order("tx2", 0, PerpSide::Short, 110, 1, 60_000, [2; 32]));

        book.remove("tx1:0");
        assert_eq!(book.short_count(), 1);
        assert!(book.contains("tx2:0"));
    }

    // reduce_only tests

    /// Normal (non-reduce_only) order is always valid regardless of position.
    #[test]
    fn reduce_only_false_always_valid() {
        let order = make_order("tx1", 0, PerpSide::Long, 100, 1, 50_000, [1; 32]);
        assert!(!order.reduce_only);

        assert!(order.is_valid_reduce_only(None));
        assert!(order.is_valid_reduce_only(Some(PerpSide::Long)));
        assert!(order.is_valid_reduce_only(Some(PerpSide::Short)));
    }

    /// reduce_only Long with no existing position → invalid (would open new).
    #[test]
    fn reduce_only_long_no_position_invalid() {
        let mut order = make_order("tx1", 0, PerpSide::Long, 100, 1, 50_000, [1; 32]);
        order.reduce_only = true;

        assert!(!order.is_valid_reduce_only(None));
    }

    /// reduce_only Short with no existing position → invalid (would open new).
    #[test]
    fn reduce_only_short_no_position_invalid() {
        let mut order = make_order("tx1", 0, PerpSide::Short, 100, 1, 50_000, [1; 32]);
        order.reduce_only = true;

        assert!(!order.is_valid_reduce_only(None));
    }

    /// reduce_only Long when trader already holds a Short position → valid (reduces/closes).
    #[test]
    fn reduce_only_long_opposite_position_valid() {
        let mut order = make_order("tx1", 0, PerpSide::Long, 100, 1, 50_000, [1; 32]);
        order.reduce_only = true;

        assert!(order.is_valid_reduce_only(Some(PerpSide::Short)));
    }

    /// reduce_only Short when trader already holds a Long position → valid (reduces/closes).
    #[test]
    fn reduce_only_short_opposite_position_valid() {
        let mut order = make_order("tx1", 0, PerpSide::Short, 100, 1, 50_000, [1; 32]);
        order.reduce_only = true;

        assert!(order.is_valid_reduce_only(Some(PerpSide::Long)));
    }

    /// reduce_only Long when trader already holds a Long position → invalid (would increase).
    #[test]
    fn reduce_only_long_same_position_invalid() {
        let mut order = make_order("tx1", 0, PerpSide::Long, 100, 1, 50_000, [1; 32]);
        order.reduce_only = true;

        assert!(!order.is_valid_reduce_only(Some(PerpSide::Long)));
    }

    /// reduce_only Short when trader already holds a Short position → invalid (would increase).
    #[test]
    fn reduce_only_short_same_position_invalid() {
        let mut order = make_order("tx1", 0, PerpSide::Short, 100, 1, 50_000, [1; 32]);
        order.reduce_only = true;

        assert!(!order.is_valid_reduce_only(Some(PerpSide::Short)));
    }

    /// reduce_only orders can still be inserted into the book and participate
    /// in crossing detection; validation happens at execution time.
    #[test]
    fn reduce_only_order_participates_in_crossing() {
        let mut book = PerpOrderBook::new();
        let mut long_order = make_order("tx1", 0, PerpSide::Long, 110, 1, 50_000, [1; 32]);
        long_order.reduce_only = true;
        book.insert(long_order);
        book.insert(make_order("tx2", 0, PerpSide::Short, 108, 1, 50_000, [2; 32]));

        // Crossing is detected regardless of reduce_only flag
        let pairs = book.find_crossing_pairs();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].long_order.tx_id, "tx1");
        assert!(pairs[0].long_order.reduce_only);
    }

    /// Verify the reduce_only field is correctly stored and retrieved via get().
    #[test]
    fn reduce_only_field_stored_in_book() {
        let mut book = PerpOrderBook::new();
        let mut order = make_order("tx1", 0, PerpSide::Long, 100, 1, 50_000, [1; 32]);
        order.reduce_only = true;
        book.insert(order);

        let retrieved = book.get("tx1:0").unwrap();
        assert!(retrieved.reduce_only);
    }
}
