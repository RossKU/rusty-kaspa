//! P2P lending order book with rate-priority matching.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};

/// Scale factor for normalizing rational rates to u128 sort keys.
const RATE_SCALE: u128 = 1_000_000_000_000;

/// Identifies which kind of lending item an outpoint represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LendingItemType {
    Offer,
    Request,
}

// LendingOffer — lender locks principal with rate/collateral terms

/// A lending offer resting on the book.
///
/// Corresponds to a loan_offer covenant UTXO on L1.
#[derive(Debug, Clone)]
pub struct LendingOffer {
    /// Outpoint key "txId:index".
    pub outpoint: String,
    /// Locked principal in sompi (UTXO value).
    pub value: u64,
    /// Annual rate numerator (e.g., 500 for 5.00%).
    pub rate_num: u64,
    /// Annual rate denominator (e.g., 10000).
    pub rate_den: u64,
    /// Minimum collateral ratio (e.g., 15000 for 150.00%).
    pub min_collateral_pct: u64,
    /// Maximum loan duration in DAA score units.
    pub max_duration_daa: u64,
    /// 32B covenant ID of accepted collateral (all-zero = KAS).
    pub collateral_cov_id: [u8; 32],
    /// 0 = fixed only, 1 = variable ok.
    pub rate_mode: u64,
    /// Variable rate floor numerator (lender protection).
    /// Matches loan_offer state field d0 (rate_floor_num).
    pub rate_floor: u64,
    /// Blake2b-256 hash of the lender's scriptPublicKey.
    pub owner_spk_hash: [u8; 32],
    /// Cached redeemScript bytes.
    pub redeem_script: Vec<u8>,
    /// Cached P2SH script bytes.
    pub p2sh_script: Vec<u8>,
    /// Actual owner SPK bytes (hex-encoded).
    pub owner_spk: Option<String>,
    /// DAA score when this offer was discovered on L1.
    pub discovered_daa: u64,
}

impl LendingOffer {
    /// Normalized rate for sorting: rate_num * RATE_SCALE / rate_den.
    pub fn normalized_rate(&self) -> u128 {
        if self.rate_den == 0 {
            return u128::MAX;
        }
        (self.rate_num as u128) * RATE_SCALE / (self.rate_den as u128)
    }
}

// BorrowRequest — borrower locks collateral with desired loan terms

/// A borrow request resting on the book.
///
/// Corresponds to a borrow_request covenant UTXO on L1.
#[derive(Debug, Clone)]
pub struct BorrowRequest {
    /// Outpoint key "txId:index".
    pub outpoint: String,
    /// Locked collateral in sompi (UTXO value).
    pub value: u64,
    /// Desired principal amount in sompi.
    pub desired_principal: u64,
    /// Maximum acceptable annual rate numerator.
    pub max_rate_num: u64,
    /// Maximum acceptable annual rate denominator.
    pub max_rate_den: u64,
    /// Desired loan duration in DAA score units.
    pub duration_daa: u64,
    /// Rate mode: 0=fixed, 1=variable, 2=either.
    pub rate_mode: u64,
    /// Variable rate cap numerator (borrower protection).
    /// Matches borrow_request state field d0 (rate_cap_num).
    pub rate_cap: u64,
    /// Blake2b-256 hash of the borrower's scriptPublicKey.
    pub owner_spk_hash: [u8; 32],
    /// Cached redeemScript bytes.
    pub redeem_script: Vec<u8>,
    /// Cached P2SH script bytes.
    pub p2sh_script: Vec<u8>,
    /// Actual owner SPK bytes (hex-encoded), needed for principal delivery output.
    /// B-1: Must be populated during scanning from TX payload or UTXO query.
    /// None if not available (lending match will be skipped).
    pub owner_spk: Option<String>,
    /// 32B covenant ID of the collateral token (all-zero = KAS).
    pub collateral_cov_id: [u8; 32],
    /// DAA score when this request was discovered on L1.
    pub discovered_daa: u64,
}

impl BorrowRequest {
    /// Normalized max rate for sorting: max_rate_num * RATE_SCALE / max_rate_den.
    pub fn normalized_max_rate(&self) -> u128 {
        if self.max_rate_den == 0 {
            return u128::MAX;
        }
        (self.max_rate_num as u128) * RATE_SCALE / (self.max_rate_den as u128)
    }
}

// Sort keys

/// Sort key for offers: ascending rate (lowest first).
///
/// Lower rate = more attractive to borrowers = higher priority.
/// Tiebreak: higher value (larger principal) first, then outpoint.
#[derive(Debug, Clone)]
struct OfferRateKey {
    normalized_rate: u128,
    value: u64,
    outpoint: String,
}

impl PartialEq for OfferRateKey {
    fn eq(&self, other: &Self) -> bool {
        self.outpoint == other.outpoint
    }
}
impl Eq for OfferRateKey {}

impl PartialOrd for OfferRateKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OfferRateKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // ASC by rate (lowest first)
        let rate_ord = self.normalized_rate.cmp(&other.normalized_rate);
        if rate_ord != Ordering::Equal {
            return rate_ord;
        }
        // Tiebreak: higher value first (DESC)
        let value_ord = other.value.cmp(&self.value);
        if value_ord != Ordering::Equal {
            return value_ord;
        }
        self.outpoint.cmp(&other.outpoint)
    }
}

/// Sort key for requests: descending max rate (highest first).
///
/// Higher max rate = more attractive to lenders = higher priority.
/// Tiebreak: higher collateral value first, then outpoint.
#[derive(Debug, Clone)]
struct RequestRateKey {
    normalized_max_rate: u128,
    value: u64,
    outpoint: String,
}

impl PartialEq for RequestRateKey {
    fn eq(&self, other: &Self) -> bool {
        self.outpoint == other.outpoint
    }
}
impl Eq for RequestRateKey {}

impl PartialOrd for RequestRateKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RequestRateKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // DESC by max rate (highest first)
        let rate_ord = other.normalized_max_rate.cmp(&self.normalized_max_rate);
        if rate_ord != Ordering::Equal {
            return rate_ord;
        }
        // Tiebreak: higher collateral value first (DESC)
        let value_ord = other.value.cmp(&self.value);
        if value_ord != Ordering::Equal {
            return value_ord;
        }
        self.outpoint.cmp(&other.outpoint)
    }
}

// LendingMatch — a crossing pair ready for execution

/// A matched pair of LendingOffer + BorrowRequest.
#[derive(Debug, Clone)]
pub struct LendingMatch {
    /// The lending offer (provides principal).
    pub offer: LendingOffer,
    /// The borrow request (provides collateral).
    pub request: BorrowRequest,
    /// Agreed rate numerator (offer's rate, since offer <= request max).
    pub agreed_rate_num: u64,
    /// Agreed rate denominator.
    pub agreed_rate_den: u64,
    /// Actual principal amount (min of offer value, request desired_principal).
    pub principal: u64,
    /// Actual duration in DAA (min of offer max_duration, request duration).
    pub duration_daa: u64,
}

// LendingBook

/// Lending order book managing offers and requests.
///
/// Offers sorted by rate ASC (lowest rate first — best for borrowers).
/// Requests sorted by max rate DESC (highest max rate first — best for lenders).
/// HashMap for O(1) outpoint lookup.
pub struct LendingBook {
    offers: BTreeMap<OfferRateKey, LendingOffer>,
    requests: BTreeMap<RequestRateKey, BorrowRequest>,
    /// Reverse lookup: outpoint -> (type, key index for BTreeMap).
    offer_outpoints: HashMap<String, OfferRateKey>,
    request_outpoints: HashMap<String, RequestRateKey>,
}

impl Default for LendingBook {
    fn default() -> Self {
        Self::new()
    }
}

impl LendingBook {
    pub fn new() -> Self {
        Self {
            offers: BTreeMap::new(),
            requests: BTreeMap::new(),
            offer_outpoints: HashMap::new(),
            request_outpoints: HashMap::new(),
        }
    }

    // Insert

    /// Insert a lending offer. Removes any existing entry with the same outpoint.
    ///
    /// Silently rejects offers with rate_den == 0 (would cause division by zero).
    pub fn add_offer(&mut self, offer: LendingOffer) {
        if offer.rate_den == 0 {
            return;
        }
        let outpoint = offer.outpoint.clone();
        self.remove_by_outpoint(&outpoint);
        let key = OfferRateKey {
            normalized_rate: offer.normalized_rate(),
            value: offer.value,
            outpoint: outpoint.clone(),
        };
        self.offer_outpoints.insert(outpoint, key.clone());
        self.offers.insert(key, offer);
    }

    /// Insert a borrow request. Removes any existing entry with the same outpoint.
    ///
    /// Silently rejects requests with max_rate_den == 0 (would cause division by zero).
    pub fn add_request(&mut self, request: BorrowRequest) {
        if request.max_rate_den == 0 {
            return;
        }
        let outpoint = request.outpoint.clone();
        self.remove_by_outpoint(&outpoint);
        let key = RequestRateKey {
            normalized_max_rate: request.normalized_max_rate(),
            value: request.value,
            outpoint: outpoint.clone(),
        };
        self.request_outpoints.insert(outpoint, key.clone());
        self.requests.insert(key, request);
    }

    // Remove

    /// Remove an item by outpoint key. Returns the type removed, or None.
    pub fn remove_by_outpoint(&mut self, outpoint: &str) -> Option<LendingItemType> {
        if let Some(key) = self.offer_outpoints.remove(outpoint) {
            self.offers.remove(&key);
            return Some(LendingItemType::Offer);
        }
        if let Some(key) = self.request_outpoints.remove(outpoint) {
            self.requests.remove(&key);
            return Some(LendingItemType::Request);
        }
        None
    }

    // Lookup

    /// Look up an offer by outpoint.
    pub fn get_offer(&self, outpoint: &str) -> Option<&LendingOffer> {
        let key = self.offer_outpoints.get(outpoint)?;
        self.offers.get(key)
    }

    /// Look up a request by outpoint.
    pub fn get_request(&self, outpoint: &str) -> Option<&BorrowRequest> {
        let key = self.request_outpoints.get(outpoint)?;
        self.requests.get(key)
    }

    /// Check if an outpoint exists in the book.
    pub fn contains(&self, outpoint: &str) -> bool {
        self.offer_outpoints.contains_key(outpoint)
            || self.request_outpoints.contains_key(outpoint)
    }

    /// Collect all outpoint keys from both sides.
    pub fn all_outpoint_keys(&self) -> std::collections::HashSet<String> {
        self.offer_outpoints
            .keys()
            .chain(self.request_outpoints.keys())
            .cloned()
            .collect()
    }

    /// Get the item type for an outpoint, if present.
    pub fn item_type(&self, outpoint: &str) -> Option<LendingItemType> {
        if self.offer_outpoints.contains_key(outpoint) {
            Some(LendingItemType::Offer)
        } else if self.request_outpoints.contains_key(outpoint) {
            Some(LendingItemType::Request)
        } else {
            None
        }
    }

    // Counts

    /// Number of lending offers.
    pub fn offer_count(&self) -> usize {
        self.offers.len()
    }

    /// Number of borrow requests.
    pub fn request_count(&self) -> usize {
        self.requests.len()
    }

    /// Total items in the book.
    pub fn total_count(&self) -> usize {
        self.offers.len() + self.requests.len()
    }

    // Best rates

    /// Best (lowest) offer rate as (num, den), or None if no offers.
    pub fn best_offer_rate(&self) -> Option<(u64, u64)> {
        self.offers
            .values()
            .next()
            .map(|o| (o.rate_num, o.rate_den))
    }

    /// Best (highest) request max rate as (num, den), or None if no requests.
    pub fn best_request_rate(&self) -> Option<(u64, u64)> {
        self.requests
            .values()
            .next()
            .map(|r| (r.max_rate_num, r.max_rate_den))
    }

    // Iteration

    /// Iterate offers in rate-priority order (lowest rate first).
    pub fn iter_offers(&self) -> impl Iterator<Item = &LendingOffer> {
        self.offers.values()
    }

    /// Iterate requests in rate-priority order (highest max rate first).
    pub fn iter_requests(&self) -> impl Iterator<Item = &BorrowRequest> {
        self.requests.values()
    }

    // Filtering

    /// Filter offers by accepted collateral covenant ID.
    pub fn offers_for_collateral(&self, cov_id: &[u8; 32]) -> Vec<&LendingOffer> {
        self.offers
            .values()
            .filter(|o| &o.collateral_cov_id == cov_id)
            .collect()
    }

    /// Filter offers by rate mode.
    pub fn offers_by_rate_mode(&self, rate_mode: u64) -> Vec<&LendingOffer> {
        self.offers
            .values()
            .filter(|o| o.rate_mode == rate_mode)
            .collect()
    }

    // Matching (crossing detection)

    /// Find all crossing matches where offer.rate <= request.max_rate,
    /// collateral is sufficient, and duration is within limits.
    ///
    /// Excludes self-trades (same owner_spk_hash on both sides).
    ///
    /// Returns matches with agreed rate = offer's rate (better for borrower).
    pub fn find_matches(&self) -> Vec<LendingMatch> {
        let mut matches = Vec::new();
        let max_iterations: usize = 50_000;
        let mut iterations: usize = 0;

        for (_, offer) in self.offers.iter() {
            for (_, request) in self.requests.iter() {
                iterations += 1;
                if iterations > max_iterations {
                    return matches;
                }

                // Rate condition: offer_rate <= request_max_rate
                // offer_rate_num/offer_rate_den <= request_max_rate_num/request_max_rate_den
                // offer_rate_num * request_max_rate_den <= request_max_rate_num * offer_rate_den
                let lhs = (offer.rate_num as u128)
                    .checked_mul(request.max_rate_den as u128);
                let rhs = (request.max_rate_num as u128)
                    .checked_mul(offer.rate_den as u128);

                let (lhs, rhs) = match (lhs, rhs) {
                    (Some(l), Some(r)) => (l, r),
                    _ => continue,
                };

                if lhs > rhs {
                    // Offer rate > request max rate: no match.
                    // Since offers are ASC by rate, no further offers can
                    // match this request at higher rates either.
                    // But we need to continue to other requests, so just break inner.
                    break;
                }

                // Collateral token must match
                if offer.collateral_cov_id != request.collateral_cov_id {
                    continue;
                }

                // Rate mode compatibility:
                // offer 0(fixed) matches request 0 or 2; offer 1(variable) matches request 1 or 2;
                // request 2(either) matches any offer mode.
                let rate_compatible = match (offer.rate_mode, request.rate_mode) {
                    (0, 0) | (0, 2) => true, // fixed offer, fixed or either request
                    (1, 1) | (1, 2) => true, // variable offer, variable or either request
                    _ => false,
                };
                if !rate_compatible {
                    continue;
                }

                // Self-trade prevention
                if offer.owner_spk_hash == request.owner_spk_hash {
                    continue;
                }

                // Collateral condition:
                // request.value (collateral) >= offer.min_collateral_pct * principal / 10000
                // where principal = min(offer.value, request.desired_principal)
                let principal = offer.value.min(request.desired_principal);
                if principal == 0 {
                    continue;
                }

                let required_collateral = (principal as u128)
                    .checked_mul(offer.min_collateral_pct as u128)
                    .map(|v| v / 10_000);
                let required_collateral = match required_collateral {
                    Some(v) if v <= u64::MAX as u128 => v as u64,
                    _ => continue,
                };

                if request.value < required_collateral {
                    continue;
                }

                // Duration condition:
                // request.duration_daa <= offer.max_duration_daa
                if request.duration_daa > offer.max_duration_daa {
                    continue;
                }

                // Agreed rate is the offer's rate (better for borrower).
                // Agreed duration is the request's duration.
                let duration = request.duration_daa.min(offer.max_duration_daa);

                matches.push(LendingMatch {
                    offer: offer.clone(),
                    request: request.clone(),
                    agreed_rate_num: offer.rate_num,
                    agreed_rate_den: offer.rate_den,
                    principal,
                    duration_daa: duration,
                });
            }
        }

        matches
    }

    // Serialization (JSON for persistence)

    /// Serialize the book to JSON.
    pub fn to_json(&self) -> serde_json::Value {
        let offers: Vec<serde_json::Value> = self
            .offers
            .values()
            .map(|o| {
                serde_json::json!({
                    "outpoint": o.outpoint,
                    "value": o.value,
                    "rate_num": o.rate_num,
                    "rate_den": o.rate_den,
                    "min_collateral_pct": o.min_collateral_pct,
                    "max_duration_daa": o.max_duration_daa,
                    "collateral_cov_id": hex::encode(o.collateral_cov_id),
                    "rate_mode": o.rate_mode,
                    "rate_floor": o.rate_floor,
                    "owner_spk_hash": hex::encode(o.owner_spk_hash),
                    "redeem_script": hex::encode(&o.redeem_script),
                    "p2sh_script": hex::encode(&o.p2sh_script),
                    "owner_spk": o.owner_spk.as_deref().unwrap_or(""),
                    "discovered_daa": o.discovered_daa,
                })
            })
            .collect();

        let requests: Vec<serde_json::Value> = self
            .requests
            .values()
            .map(|r| {
                serde_json::json!({
                    "outpoint": r.outpoint,
                    "value": r.value,
                    "desired_principal": r.desired_principal,
                    "max_rate_num": r.max_rate_num,
                    "max_rate_den": r.max_rate_den,
                    "duration_daa": r.duration_daa,
                    "rate_mode": r.rate_mode,
                    "rate_cap": r.rate_cap,
                    "collateral_cov_id": hex::encode(r.collateral_cov_id),
                    "owner_spk_hash": hex::encode(r.owner_spk_hash),
                    "redeem_script": hex::encode(&r.redeem_script),
                    "p2sh_script": hex::encode(&r.p2sh_script),
                    "owner_spk": r.owner_spk.as_deref().unwrap_or(""),
                    "discovered_daa": r.discovered_daa,
                })
            })
            .collect();

        serde_json::json!({
            "offers": offers,
            "requests": requests,
        })
    }

    /// Deserialize the book from JSON.
    ///
    /// Returns None if the JSON structure is invalid.
    pub fn from_json(json: &serde_json::Value) -> Option<Self> {
        let mut book = Self::new();

        let offers = json.get("offers")?.as_array()?;
        for o in offers {
            let outpoint = o.get("outpoint")?.as_str()?.to_string();
            let value = o.get("value")?.as_u64()?;
            let rate_num = o.get("rate_num")?.as_u64()?;
            let rate_den = o.get("rate_den")?.as_u64()?;
            let min_collateral_pct = o.get("min_collateral_pct")?.as_u64()?;
            let max_duration_daa = o.get("max_duration_daa")?.as_u64()?;
            let cov_id_hex = o.get("collateral_cov_id")?.as_str()?;
            let cov_id_bytes = hex::decode(cov_id_hex).ok()?;
            if cov_id_bytes.len() != 32 {
                return None;
            }
            let mut collateral_cov_id = [0u8; 32];
            collateral_cov_id.copy_from_slice(&cov_id_bytes);
            let rate_mode = o.get("rate_mode")?.as_u64()?;
            let rate_floor = o.get("rate_floor")?.as_u64()?;
            let owner_hex = o.get("owner_spk_hash")?.as_str()?;
            let owner_bytes = hex::decode(owner_hex).ok()?;
            if owner_bytes.len() != 32 {
                return None;
            }
            let mut owner_spk_hash = [0u8; 32];
            owner_spk_hash.copy_from_slice(&owner_bytes);
            let rs_hex = o.get("redeem_script")?.as_str()?;
            let redeem_script = hex::decode(rs_hex).ok()?;
            let p2sh_hex = o.get("p2sh_script")?.as_str()?;
            let p2sh_script = hex::decode(p2sh_hex).ok()?;
            let owner_spk = o.get("owner_spk").and_then(|v| v.as_str())
                .and_then(|s| if s.is_empty() { None } else { Some(s.to_string()) });
            let discovered_daa = o.get("discovered_daa")?.as_u64()?;

            book.add_offer(LendingOffer {
                outpoint,
                value,
                rate_num,
                rate_den,
                min_collateral_pct,
                max_duration_daa,
                collateral_cov_id,
                rate_mode,
                rate_floor,
                owner_spk_hash,
                redeem_script,
                p2sh_script,
                owner_spk,
                discovered_daa,
            });
        }

        let requests = json.get("requests")?.as_array()?;
        for r in requests {
            let outpoint = r.get("outpoint")?.as_str()?.to_string();
            let value = r.get("value")?.as_u64()?;
            let desired_principal = r.get("desired_principal")?.as_u64()?;
            let max_rate_num = r.get("max_rate_num")?.as_u64()?;
            let max_rate_den = r.get("max_rate_den")?.as_u64()?;
            let duration_daa = r.get("duration_daa")?.as_u64()?;
            let owner_hex = r.get("owner_spk_hash")?.as_str()?;
            let owner_bytes = hex::decode(owner_hex).ok()?;
            if owner_bytes.len() != 32 {
                return None;
            }
            let mut owner_spk_hash = [0u8; 32];
            owner_spk_hash.copy_from_slice(&owner_bytes);
            let rs_hex = r.get("redeem_script")?.as_str()?;
            let redeem_script = hex::decode(rs_hex).ok()?;
            let p2sh_hex = r.get("p2sh_script")?.as_str()?;
            let p2sh_script = hex::decode(p2sh_hex).ok()?;
            let owner_spk = r.get("owner_spk").and_then(|v| v.as_str())
                .and_then(|s| if s.is_empty() { None } else { Some(s.to_string()) });
            let discovered_daa = r.get("discovered_daa")?.as_u64()?;

            let rate_mode = r.get("rate_mode").and_then(|v| v.as_u64()).unwrap_or(0);
            let rate_cap = r.get("rate_cap").and_then(|v| v.as_u64()).unwrap_or(0);

            let mut req_collateral_cov_id = [0u8; 32];
            if let Some(cid_hex) = r.get("collateral_cov_id").and_then(|v| v.as_str()) {
                if let Ok(cid_bytes) = hex::decode(cid_hex) {
                    if cid_bytes.len() == 32 {
                        req_collateral_cov_id.copy_from_slice(&cid_bytes);
                    }
                }
            }

            book.add_request(BorrowRequest {
                outpoint,
                value,
                desired_principal,
                max_rate_num,
                max_rate_den,
                duration_daa,
                rate_mode,
                rate_cap,
                collateral_cov_id: req_collateral_cov_id,
                owner_spk_hash,
                redeem_script,
                p2sh_script,
                owner_spk,
                discovered_daa,
            });
        }

        Some(book)
    }

    /// Clear all items from the book.
    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.offers.clear();
        self.requests.clear();
        self.offer_outpoints.clear();
        self.request_outpoints.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_offer(
        outpoint: &str,
        value: u64,
        rate_num: u64,
        rate_den: u64,
        min_collateral_pct: u64,
        max_duration_daa: u64,
        owner: [u8; 32],
    ) -> LendingOffer {
        LendingOffer {
            outpoint: outpoint.to_string(),
            value,
            rate_num,
            rate_den,
            min_collateral_pct,
            max_duration_daa,
            collateral_cov_id: [0u8; 32],
            rate_mode: 0,
            rate_floor: 0,
            owner_spk_hash: owner,
            redeem_script: Vec::new(),
            p2sh_script: Vec::new(),
            owner_spk: None,
            discovered_daa: 1000,
        }
    }

    fn make_request(
        outpoint: &str,
        value: u64,
        desired_principal: u64,
        max_rate_num: u64,
        max_rate_den: u64,
        duration_daa: u64,
        owner: [u8; 32],
    ) -> BorrowRequest {
        BorrowRequest {
            outpoint: outpoint.to_string(),
            value,
            desired_principal,
            max_rate_num,
            max_rate_den,
            duration_daa,
            rate_mode: 0,
            rate_cap: 0,
            collateral_cov_id: [0u8; 32],
            owner_spk_hash: owner,
            redeem_script: Vec::new(),
            p2sh_script: Vec::new(),
            owner_spk: None,
            discovered_daa: 1000,
        }
    }

    // Basic insert / count / remove

    #[test]
    fn insert_offer_and_count() {
        let mut book = LendingBook::new();
        assert_eq!(book.total_count(), 0);
        book.add_offer(make_offer("tx1:0", 1_000_000, 500, 10000, 15000, 31536000, [1; 32]));
        assert_eq!(book.offer_count(), 1);
        assert_eq!(book.total_count(), 1);
    }

    #[test]
    fn insert_request_and_count() {
        let mut book = LendingBook::new();
        book.add_request(make_request("tx2:0", 2_000_000, 1_000_000, 800, 10000, 31536000, [2; 32]));
        assert_eq!(book.request_count(), 1);
        assert_eq!(book.total_count(), 1);
    }

    #[test]
    fn remove_offer() {
        let mut book = LendingBook::new();
        book.add_offer(make_offer("tx1:0", 1_000_000, 500, 10000, 15000, 31536000, [1; 32]));
        let removed = book.remove_by_outpoint("tx1:0");
        assert_eq!(removed, Some(LendingItemType::Offer));
        assert_eq!(book.offer_count(), 0);
    }

    #[test]
    fn remove_request() {
        let mut book = LendingBook::new();
        book.add_request(make_request("tx2:0", 2_000_000, 1_000_000, 800, 10000, 31536000, [2; 32]));
        let removed = book.remove_by_outpoint("tx2:0");
        assert_eq!(removed, Some(LendingItemType::Request));
        assert_eq!(book.request_count(), 0);
    }

    #[test]
    fn remove_nonexistent() {
        let mut book = LendingBook::new();
        assert!(book.remove_by_outpoint("tx99:0").is_none());
    }

    // Lookup

    #[test]
    fn get_offer_by_outpoint() {
        let mut book = LendingBook::new();
        book.add_offer(make_offer("tx1:0", 1_000_000, 500, 10000, 15000, 31536000, [1; 32]));
        let offer = book.get_offer("tx1:0").unwrap();
        assert_eq!(offer.value, 1_000_000);
    }

    #[test]
    fn get_request_by_outpoint() {
        let mut book = LendingBook::new();
        book.add_request(make_request("tx2:0", 2_000_000, 1_000_000, 800, 10000, 31536000, [2; 32]));
        let req = book.get_request("tx2:0").unwrap();
        assert_eq!(req.desired_principal, 1_000_000);
    }

    #[test]
    fn get_nonexistent() {
        let book = LendingBook::new();
        assert!(book.get_offer("tx99:0").is_none());
        assert!(book.get_request("tx99:0").is_none());
    }

    #[test]
    fn contains_check() {
        let mut book = LendingBook::new();
        book.add_offer(make_offer("tx1:0", 1_000_000, 500, 10000, 15000, 31536000, [1; 32]));
        assert!(book.contains("tx1:0"));
        assert!(!book.contains("tx99:0"));
    }

    #[test]
    fn item_type_check() {
        let mut book = LendingBook::new();
        book.add_offer(make_offer("tx1:0", 1_000_000, 500, 10000, 15000, 31536000, [1; 32]));
        book.add_request(make_request("tx2:0", 2_000_000, 1_000_000, 800, 10000, 31536000, [2; 32]));
        assert_eq!(book.item_type("tx1:0"), Some(LendingItemType::Offer));
        assert_eq!(book.item_type("tx2:0"), Some(LendingItemType::Request));
        assert_eq!(book.item_type("tx99:0"), None);
    }

    // Rate ordering

    #[test]
    fn offers_sorted_by_rate_ascending() {
        let mut book = LendingBook::new();
        // 5% rate
        book.add_offer(make_offer("tx1:0", 1_000_000, 500, 10000, 15000, 31536000, [1; 32]));
        // 3% rate
        book.add_offer(make_offer("tx2:0", 1_000_000, 300, 10000, 15000, 31536000, [2; 32]));
        // 8% rate
        book.add_offer(make_offer("tx3:0", 1_000_000, 800, 10000, 15000, 31536000, [3; 32]));

        let rates: Vec<u64> = book.iter_offers().map(|o| o.rate_num).collect();
        assert_eq!(rates, vec![300, 500, 800]);
    }

    #[test]
    fn requests_sorted_by_max_rate_descending() {
        let mut book = LendingBook::new();
        // 5% max rate
        book.add_request(make_request("tx1:0", 2_000_000, 1_000_000, 500, 10000, 31536000, [1; 32]));
        // 10% max rate
        book.add_request(make_request("tx2:0", 2_000_000, 1_000_000, 1000, 10000, 31536000, [2; 32]));
        // 3% max rate
        book.add_request(make_request("tx3:0", 2_000_000, 1_000_000, 300, 10000, 31536000, [3; 32]));

        let rates: Vec<u64> = book.iter_requests().map(|r| r.max_rate_num).collect();
        assert_eq!(rates, vec![1000, 500, 300]);
    }

    #[test]
    fn offer_value_tiebreak() {
        let mut book = LendingBook::new();
        // Same rate, different value -> higher value first
        book.add_offer(make_offer("tx1:0", 500_000, 500, 10000, 15000, 31536000, [1; 32]));
        book.add_offer(make_offer("tx2:0", 1_000_000, 500, 10000, 15000, 31536000, [2; 32]));

        let first = book.iter_offers().next().unwrap();
        assert_eq!(first.value, 1_000_000);
    }

    #[test]
    fn request_value_tiebreak() {
        let mut book = LendingBook::new();
        // Same max rate, different collateral value -> higher first
        book.add_request(make_request("tx1:0", 1_000_000, 500_000, 500, 10000, 31536000, [1; 32]));
        book.add_request(make_request("tx2:0", 2_000_000, 500_000, 500, 10000, 31536000, [2; 32]));

        let first = book.iter_requests().next().unwrap();
        assert_eq!(first.value, 2_000_000);
    }

    // Best rates

    #[test]
    fn best_offer_rate_returns_lowest() {
        let mut book = LendingBook::new();
        book.add_offer(make_offer("tx1:0", 1_000_000, 500, 10000, 15000, 31536000, [1; 32]));
        book.add_offer(make_offer("tx2:0", 1_000_000, 300, 10000, 15000, 31536000, [2; 32]));
        assert_eq!(book.best_offer_rate(), Some((300, 10000)));
    }

    #[test]
    fn best_request_rate_returns_highest() {
        let mut book = LendingBook::new();
        book.add_request(make_request("tx1:0", 2_000_000, 1_000_000, 500, 10000, 31536000, [1; 32]));
        book.add_request(make_request("tx2:0", 2_000_000, 1_000_000, 800, 10000, 31536000, [2; 32]));
        assert_eq!(book.best_request_rate(), Some((800, 10000)));
    }

    #[test]
    fn best_rates_empty_book() {
        let book = LendingBook::new();
        assert!(book.best_offer_rate().is_none());
        assert!(book.best_request_rate().is_none());
    }

    // Matching (crossing detection)

    #[test]
    fn match_found_rate_crosses() {
        let mut book = LendingBook::new();
        // Offer at 5%, request accepts up to 8%
        // Collateral: 2M > 1M * 150% = 1.5M
        // Duration: 31M < 63M max
        book.add_offer(make_offer("tx1:0", 1_000_000, 500, 10000, 15000, 63_000_000, [1; 32]));
        book.add_request(make_request("tx2:0", 2_000_000, 1_000_000, 800, 10000, 31_000_000, [2; 32]));

        let matches = book.find_matches();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].agreed_rate_num, 500);
        assert_eq!(matches[0].agreed_rate_den, 10000);
        assert_eq!(matches[0].principal, 1_000_000);
    }

    #[test]
    fn no_match_rate_too_high() {
        let mut book = LendingBook::new();
        // Offer at 10%, request accepts up to 5% -> no crossing
        book.add_offer(make_offer("tx1:0", 1_000_000, 1000, 10000, 15000, 63_000_000, [1; 32]));
        book.add_request(make_request("tx2:0", 2_000_000, 1_000_000, 500, 10000, 31_000_000, [2; 32]));

        assert!(book.find_matches().is_empty());
    }

    #[test]
    fn no_match_insufficient_collateral() {
        let mut book = LendingBook::new();
        // Offer needs 150% collateral: 1M * 150% = 1.5M. Request has only 1M.
        book.add_offer(make_offer("tx1:0", 1_000_000, 500, 10000, 15000, 63_000_000, [1; 32]));
        book.add_request(make_request("tx2:0", 1_000_000, 1_000_000, 800, 10000, 31_000_000, [2; 32]));

        assert!(book.find_matches().is_empty());
    }

    #[test]
    fn no_match_duration_too_long() {
        let mut book = LendingBook::new();
        // Offer max duration 30M, request wants 60M
        book.add_offer(make_offer("tx1:0", 1_000_000, 500, 10000, 15000, 30_000_000, [1; 32]));
        book.add_request(make_request("tx2:0", 2_000_000, 1_000_000, 800, 10000, 60_000_000, [2; 32]));

        assert!(book.find_matches().is_empty());
    }

    #[test]
    fn self_trade_prevention() {
        let mut book = LendingBook::new();
        let owner = [1; 32];
        book.add_offer(make_offer("tx1:0", 1_000_000, 500, 10000, 15000, 63_000_000, owner));
        book.add_request(make_request("tx2:0", 2_000_000, 1_000_000, 800, 10000, 31_000_000, owner));

        assert!(book.find_matches().is_empty());
    }

    #[test]
    fn exact_rate_match() {
        let mut book = LendingBook::new();
        // Offer at 5%, request max at 5% -> crosses (offer_rate <= max_rate)
        book.add_offer(make_offer("tx1:0", 1_000_000, 500, 10000, 15000, 63_000_000, [1; 32]));
        book.add_request(make_request("tx2:0", 2_000_000, 1_000_000, 500, 10000, 31_000_000, [2; 32]));

        let matches = book.find_matches();
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn rational_rate_crossing() {
        let mut book = LendingBook::new();
        // Offer at 1/3 (~3.33%), request max at 1/2 (~50%) -> crosses
        book.add_offer(make_offer("tx1:0", 1_000_000, 1, 3, 15000, 63_000_000, [1; 32]));
        book.add_request(make_request("tx2:0", 2_000_000, 1_000_000, 1, 2, 31_000_000, [2; 32]));

        let matches = book.find_matches();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].agreed_rate_num, 1);
        assert_eq!(matches[0].agreed_rate_den, 3);
    }

    #[test]
    fn multiple_matches() {
        let mut book = LendingBook::new();
        // Two offers at different rates
        book.add_offer(make_offer("o1:0", 500_000, 300, 10000, 15000, 63_000_000, [1; 32]));
        book.add_offer(make_offer("o2:0", 500_000, 500, 10000, 15000, 63_000_000, [2; 32]));
        // Request accepts up to 6%
        book.add_request(make_request("r1:0", 2_000_000, 500_000, 600, 10000, 31_000_000, [3; 32]));

        let matches = book.find_matches();
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn principal_is_min_of_offer_and_request() {
        let mut book = LendingBook::new();
        // Offer has 2M, request wants only 500k
        book.add_offer(make_offer("tx1:0", 2_000_000, 500, 10000, 15000, 63_000_000, [1; 32]));
        // Collateral: 3M > 500k * 150% = 750k
        book.add_request(make_request("tx2:0", 3_000_000, 500_000, 800, 10000, 31_000_000, [2; 32]));

        let matches = book.find_matches();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].principal, 500_000);
    }

    #[test]
    fn empty_book_no_matches() {
        let book = LendingBook::new();
        assert!(book.find_matches().is_empty());
    }

    #[test]
    fn only_offers_no_matches() {
        let mut book = LendingBook::new();
        book.add_offer(make_offer("tx1:0", 1_000_000, 500, 10000, 15000, 63_000_000, [1; 32]));
        assert!(book.find_matches().is_empty());
    }

    #[test]
    fn only_requests_no_matches() {
        let mut book = LendingBook::new();
        book.add_request(make_request("tx1:0", 2_000_000, 1_000_000, 800, 10000, 31_000_000, [1; 32]));
        assert!(book.find_matches().is_empty());
    }

    // Filtering

    #[test]
    fn offers_for_collateral_filters_correctly() {
        let mut book = LendingBook::new();
        let kas_cov = [0u8; 32];
        let mut token_cov = [0u8; 32];
        token_cov[0] = 0xAB;

        let mut offer1 = make_offer("tx1:0", 1_000_000, 500, 10000, 15000, 63_000_000, [1; 32]);
        offer1.collateral_cov_id = kas_cov;
        let mut offer2 = make_offer("tx2:0", 1_000_000, 500, 10000, 15000, 63_000_000, [2; 32]);
        offer2.collateral_cov_id = token_cov;

        book.add_offer(offer1);
        book.add_offer(offer2);

        let kas_offers = book.offers_for_collateral(&kas_cov);
        assert_eq!(kas_offers.len(), 1);
        assert_eq!(kas_offers[0].outpoint, "tx1:0");

        let token_offers = book.offers_for_collateral(&token_cov);
        assert_eq!(token_offers.len(), 1);
        assert_eq!(token_offers[0].outpoint, "tx2:0");
    }

    #[test]
    fn offers_by_rate_mode_filters_correctly() {
        let mut book = LendingBook::new();
        let mut offer_fixed = make_offer("tx1:0", 1_000_000, 500, 10000, 15000, 63_000_000, [1; 32]);
        offer_fixed.rate_mode = 0;
        let mut offer_var = make_offer("tx2:0", 1_000_000, 500, 10000, 15000, 63_000_000, [2; 32]);
        offer_var.rate_mode = 1;

        book.add_offer(offer_fixed);
        book.add_offer(offer_var);

        assert_eq!(book.offers_by_rate_mode(0).len(), 1);
        assert_eq!(book.offers_by_rate_mode(1).len(), 1);
        assert_eq!(book.offers_by_rate_mode(2).len(), 0);
    }

    // Duplicate outpoint handling

    #[test]
    fn duplicate_offer_outpoint_overwrites() {
        let mut book = LendingBook::new();
        book.add_offer(make_offer("tx1:0", 1_000_000, 500, 10000, 15000, 63_000_000, [1; 32]));
        book.add_offer(make_offer("tx1:0", 2_000_000, 300, 10000, 15000, 63_000_000, [1; 32]));

        assert_eq!(book.offer_count(), 1);
        let offer = book.get_offer("tx1:0").unwrap();
        assert_eq!(offer.value, 2_000_000);
        assert_eq!(offer.rate_num, 300);
    }

    #[test]
    fn duplicate_request_outpoint_overwrites() {
        let mut book = LendingBook::new();
        book.add_request(make_request("tx1:0", 1_000_000, 500_000, 500, 10000, 31_000_000, [1; 32]));
        book.add_request(make_request("tx1:0", 2_000_000, 800_000, 800, 10000, 31_000_000, [1; 32]));

        assert_eq!(book.request_count(), 1);
        let req = book.get_request("tx1:0").unwrap();
        assert_eq!(req.value, 2_000_000);
        assert_eq!(req.max_rate_num, 800);
    }

    // Clear

    #[test]
    fn clear_empties_book() {
        let mut book = LendingBook::new();
        book.add_offer(make_offer("tx1:0", 1_000_000, 500, 10000, 15000, 63_000_000, [1; 32]));
        book.add_request(make_request("tx2:0", 2_000_000, 1_000_000, 800, 10000, 31_000_000, [2; 32]));
        book.clear();

        assert_eq!(book.total_count(), 0);
        assert!(!book.contains("tx1:0"));
        assert!(!book.contains("tx2:0"));
    }

    // Serialization

    #[test]
    fn json_roundtrip() {
        let mut book = LendingBook::new();
        book.add_offer(make_offer("tx1:0", 1_000_000, 500, 10000, 15000, 63_000_000, [1; 32]));
        book.add_request(make_request("tx2:0", 2_000_000, 1_000_000, 800, 10000, 31_000_000, [2; 32]));

        let json = book.to_json();
        let restored = LendingBook::from_json(&json).unwrap();

        assert_eq!(restored.offer_count(), 1);
        assert_eq!(restored.request_count(), 1);
        let offer = restored.get_offer("tx1:0").unwrap();
        assert_eq!(offer.value, 1_000_000);
        assert_eq!(offer.rate_num, 500);
        let req = restored.get_request("tx2:0").unwrap();
        assert_eq!(req.desired_principal, 1_000_000);
    }

    #[test]
    fn json_empty_book_roundtrip() {
        let book = LendingBook::new();
        let json = book.to_json();
        let restored = LendingBook::from_json(&json).unwrap();
        assert_eq!(restored.total_count(), 0);
    }

    #[test]
    fn from_json_invalid_returns_none() {
        let bad = serde_json::json!({ "not": "a book" });
        assert!(LendingBook::from_json(&bad).is_none());
    }

    // Normalized rate

    #[test]
    fn normalized_rate_basic() {
        let offer = make_offer("tx1:0", 1_000_000, 500, 10000, 15000, 63_000_000, [1; 32]);
        // 500 * 10^12 / 10000 = 50_000_000_000 (= 5% as 10^12 scaled)
        assert_eq!(offer.normalized_rate(), 50_000_000_000);
    }

    #[test]
    fn normalized_rate_zero_den() {
        let mut offer = make_offer("tx1:0", 1_000_000, 500, 10000, 15000, 63_000_000, [1; 32]);
        offer.rate_den = 0;
        assert_eq!(offer.normalized_rate(), u128::MAX);
    }

    #[test]
    fn normalized_max_rate_basic() {
        let req = make_request("tx1:0", 2_000_000, 1_000_000, 800, 10000, 31_000_000, [1; 32]);
        // 800 * 10^12 / 10000 = 80_000_000_000
        assert_eq!(req.normalized_max_rate(), 80_000_000_000);
    }

    // Default trait

    #[test]
    fn default_creates_empty_book() {
        let book = LendingBook::default();
        assert_eq!(book.total_count(), 0);
    }

    // Edge cases

    #[test]
    fn match_with_zero_collateral_requirement() {
        let mut book = LendingBook::new();
        // min_collateral_pct=0 means no collateral required
        book.add_offer(make_offer("tx1:0", 1_000_000, 500, 10000, 0, 63_000_000, [1; 32]));
        book.add_request(make_request("tx2:0", 100, 1_000_000, 800, 10000, 31_000_000, [2; 32]));

        let matches = book.find_matches();
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn match_principal_bounded_by_both_sides() {
        let mut book = LendingBook::new();
        // Offer has 500k, request wants 2M -> principal = 500k
        // Collateral: 2M > 500k * 150% = 750k -> OK
        book.add_offer(make_offer("tx1:0", 500_000, 500, 10000, 15000, 63_000_000, [1; 32]));
        book.add_request(make_request("tx2:0", 2_000_000, 2_000_000, 800, 10000, 31_000_000, [2; 32]));

        let matches = book.find_matches();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].principal, 500_000);
    }

    #[test]
    fn remove_offer_does_not_affect_requests() {
        let mut book = LendingBook::new();
        book.add_offer(make_offer("tx1:0", 1_000_000, 500, 10000, 15000, 63_000_000, [1; 32]));
        book.add_request(make_request("tx2:0", 2_000_000, 1_000_000, 800, 10000, 31_000_000, [2; 32]));
        book.remove_by_outpoint("tx1:0");
        assert_eq!(book.request_count(), 1);
        assert!(book.contains("tx2:0"));
    }

    #[test]
    fn remove_request_does_not_affect_offers() {
        let mut book = LendingBook::new();
        book.add_offer(make_offer("tx1:0", 1_000_000, 500, 10000, 15000, 63_000_000, [1; 32]));
        book.add_request(make_request("tx2:0", 2_000_000, 1_000_000, 800, 10000, 31_000_000, [2; 32]));
        book.remove_by_outpoint("tx2:0");
        assert_eq!(book.offer_count(), 1);
        assert!(book.contains("tx1:0"));
    }

    #[test]
    fn match_duration_uses_min() {
        let mut book = LendingBook::new();
        // Offer max 100M DAA, request wants 50M
        book.add_offer(make_offer("tx1:0", 1_000_000, 500, 10000, 15000, 100_000_000, [1; 32]));
        book.add_request(make_request("tx2:0", 2_000_000, 1_000_000, 800, 10000, 50_000_000, [2; 32]));

        let matches = book.find_matches();
        assert_eq!(matches[0].duration_daa, 50_000_000);
    }

    #[test]
    fn many_offers_many_requests() {
        let mut book = LendingBook::new();
        for i in 0..10 {
            let rate = 300 + i * 50;
            let mut owner = [0u8; 32];
            owner[0] = (i + 1) as u8;
            book.add_offer(make_offer(
                &format!("o{i}:0"),
                1_000_000,
                rate,
                10000,
                15000,
                63_000_000,
                owner,
            ));
        }
        for i in 0..10 {
            let max_rate = 400 + i * 50;
            let mut owner = [0u8; 32];
            owner[0] = (i + 11) as u8;
            book.add_request(make_request(
                &format!("r{i}:0"),
                2_000_000,
                1_000_000,
                max_rate,
                10000,
                31_000_000,
                owner,
            ));
        }

        assert_eq!(book.offer_count(), 10);
        assert_eq!(book.request_count(), 10);
        // There should be some matches
        let matches = book.find_matches();
        assert!(!matches.is_empty());
    }
}
