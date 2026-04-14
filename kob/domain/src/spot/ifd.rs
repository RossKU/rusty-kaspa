//! If-Done (IFD) and If-Done-OCO (IFO) contingent order book.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Unique identifier for an IFD rule (monotonic counter).
pub type IfdId = u64;

/// Status of an IFD rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IfdStatus {
    /// Registered but order A not yet detected on L1.
    Pending,
    /// Order A detected on L1, waiting for fill.
    Active,
    /// Order A filled, order B deployed as extra output.
    Triggered,
    /// Failed to deploy B (e.g., TX construction error).
    Failed,
    /// Cancelled by user before trigger.
    Cancelled,
}

/// Side of an order in the IFD pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IfdSide {
    Buy,
    Sell,
}

/// Parameters for order B in an IFD rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderBParams {
    pub side: IfdSide,
    pub token: String,
    pub price_num: u64,
    pub price_den: u64,
    /// 0 = use proceeds from A.
    pub amount: u64,
    pub min_fill: u64,
    pub expiry_daa: u64,
}

/// Parameters for order A in an IFD rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderAParams {
    pub side: IfdSide,
    pub token: String,
    pub price_num: u64,
    pub price_den: u64,
    pub amount: u64,
    pub min_fill: u64,
    pub expiry_daa: u64,
}

/// IFO sub-parameters: order B is an OCO pair (take-profit + stop-loss).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IfoOcoParams {
    /// Take-profit side (typically sell for a buy entry).
    pub tp_side: IfdSide,
    pub tp_price_num: u64,
    pub tp_price_den: u64,
    pub tp_min_fill: u64,
    /// Stop-loss side (typically sell for a buy entry).
    pub sl_side: IfdSide,
    pub sl_price_num: u64,
    pub sl_price_den: u64,
    pub sl_min_fill: u64,
}

/// The type of contingent order B.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OrderBType {
    /// Simple limit order (IFD).
    Simple(OrderBParams),
    /// OCO pair (IFO): take-profit + stop-loss.
    Oco {
        token: String,
        /// 0 = use proceeds from A.
        amount: u64,
        expiry_daa: u64,
        oco: IfoOcoParams,
    },
}

impl OrderBType {
    /// Extract the expiry DAA score from order B params (0 = GTC).
    pub fn expiry_daa(&self) -> u64 {
        match self {
            OrderBType::Simple(p) => p.expiry_daa,
            OrderBType::Oco { expiry_daa, .. } => *expiry_daa,
        }
    }
}

/// An IFD/IFO rule stored by the Engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IfdRule {
    /// Unique identifier assigned by the Engine.
    pub id: IfdId,
    /// Order A parameters (for redeem script reconstruction).
    pub order_a_params: OrderAParams,
    /// Order A's pre-computed P2SH address (hex).
    pub order_a_p2sh: String,
    /// Order A's outpoint once detected on L1 (txid:index).
    pub order_a_outpoint: Option<String>,
    /// Order B specification.
    pub order_b: OrderBType,
    /// Order B's pre-computed redeem script (hex).
    pub order_b_rs_hex: String,
    /// Order B's pre-computed P2SH address (hex).
    pub order_b_p2sh: String,
    /// SPK hash of B's P2SH (used as bspkh in A for buy->sell flow).
    pub order_b_spk_hash: String,
    /// Current status.
    pub status: IfdStatus,
    /// TX ID of the fill TX that triggered B (set on trigger).
    pub trigger_tx_id: Option<String>,
    /// Creation timestamp (unix seconds).
    pub created_at: u64,
    /// Owner identifier for auth.
    pub owner_id: String,
    /// Secret token required for cancellation (not exposed in list responses).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancel_secret: Option<String>,
}

// IFD Book

/// Maximum IFD/IFO rules.
pub const MAX_IFD_RULES: usize = 1_000;

/// The IFD order book: stores pending contingent order rules.
#[derive(Debug)]
pub struct IfdBook {
    /// All rules indexed by ID.
    rules: HashMap<IfdId, IfdRule>,
    /// Index: order A P2SH -> IFD ID (for matching when A is detected).
    p2sh_index: HashMap<String, IfdId>,
    /// Index: order A outpoint -> IFD ID (for matching when A fills).
    outpoint_index: HashMap<String, IfdId>,
    /// Next ID to assign.
    next_id: IfdId,
}

impl Default for IfdBook {
    fn default() -> Self {
        IfdBook {
            rules: HashMap::new(),
            p2sh_index: HashMap::new(),
            outpoint_index: HashMap::new(),
            next_id: 1,
        }
    }
}

impl IfdBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new IFD/IFO rule. Returns the assigned ID.
    pub fn register(&mut self, mut rule: IfdRule) -> Result<IfdId, String> {
        if self.rules.len() >= MAX_IFD_RULES {
            return Err(format!(
                "IFD rule limit reached ({}/{})",
                self.rules.len(),
                MAX_IFD_RULES
            ));
        }

        let id = self.next_id;
        self.next_id += 1;
        rule.id = id;
        rule.status = IfdStatus::Pending;

        // Index by A's P2SH for detection
        self.p2sh_index.insert(rule.order_a_p2sh.clone(), id);

        self.rules.insert(id, rule);
        Ok(id)
    }

    /// Look up an IFD rule by order A's P2SH address.
    /// Used when the scanner detects a new order at a known P2SH.
    pub fn find_by_a_p2sh(&self, p2sh: &str) -> Option<&IfdRule> {
        self.p2sh_index
            .get(p2sh)
            .and_then(|id| self.rules.get(id))
    }

    /// Activate an IFD rule: order A has been detected on L1.
    pub fn activate(&mut self, id: IfdId, outpoint: &str) -> bool {
        if let Some(rule) = self.rules.get_mut(&id) {
            if rule.status == IfdStatus::Pending {
                rule.status = IfdStatus::Active;
                rule.order_a_outpoint = Some(outpoint.to_string());
                self.outpoint_index.insert(outpoint.to_string(), id);
                return true;
            }
        }
        false
    }

    /// Look up an IFD rule by order A's outpoint (txid:index).
    /// Used when the executor fills order A to check for contingent B.
    pub fn find_by_a_outpoint(&self, outpoint: &str) -> Option<&IfdRule> {
        self.outpoint_index
            .get(outpoint)
            .and_then(|id| self.rules.get(id))
    }

    /// Mark an IFD rule as triggered (B deployed).
    pub fn trigger(&mut self, id: IfdId, tx_id: &str) -> bool {
        if let Some(rule) = self.rules.get_mut(&id) {
            if rule.status == IfdStatus::Active {
                rule.status = IfdStatus::Triggered;
                rule.trigger_tx_id = Some(tx_id.to_string());
                return true;
            }
        }
        false
    }

    /// Mark an IFD rule as failed.
    pub fn mark_failed(&mut self, id: IfdId) -> bool {
        if let Some(rule) = self.rules.get_mut(&id) {
            if rule.status == IfdStatus::Active {
                rule.status = IfdStatus::Failed;
                return true;
            }
        }
        false
    }

    /// Cancel an IFD rule (only if Pending or Active, and cancel_secret matches).
    pub fn cancel(&mut self, id: IfdId, owner_id: &str, cancel_secret: Option<&str>) -> Option<IfdRule> {
        if let Some(rule) = self.rules.get(&id) {
            if rule.owner_id != owner_id {
                return None;
            }
            // Verify cancel_secret
            match (&rule.cancel_secret, cancel_secret) {
                (Some(stored), Some(provided)) if stored != provided => return None,
                (Some(_), None) => return None, // secret required but not provided
                _ => {} // OK
            }
            if rule.status != IfdStatus::Pending && rule.status != IfdStatus::Active {
                return None;
            }
        } else {
            return None;
        }

        let rule = self.rules.remove(&id).expect("IFD rule must exist: id was checked above");
        self.p2sh_index.remove(&rule.order_a_p2sh);
        if let Some(ref outpoint) = rule.order_a_outpoint {
            self.outpoint_index.remove(outpoint);
        }
        Some(rule)
    }

    /// Get a rule by ID.
    pub fn get(&self, id: IfdId) -> Option<&IfdRule> {
        self.rules.get(&id)
    }

    /// List all rules for a given owner.
    pub fn list_by_owner(&self, owner_id: &str) -> Vec<&IfdRule> {
        let mut result: Vec<&IfdRule> = self
            .rules
            .values()
            .filter(|r| r.owner_id == owner_id)
            .collect();
        result.sort_by_key(|r| r.id);
        result
    }

    /// List all active (non-terminal) rules.
    pub fn list_active(&self) -> Vec<&IfdRule> {
        let mut result: Vec<&IfdRule> = self
            .rules
            .values()
            .filter(|r| r.status == IfdStatus::Pending || r.status == IfdStatus::Active)
            .collect();
        result.sort_by_key(|r| r.id);
        result
    }

    /// Total number of rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Number of active (non-terminal) rules.
    pub fn active_count(&self) -> usize {
        self.rules
            .values()
            .filter(|r| r.status == IfdStatus::Pending || r.status == IfdStatus::Active)
            .count()
    }

    /// Check if there are no rules.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Remove terminal rules (Triggered, Failed, Cancelled) to free memory.
    pub fn cleanup(&mut self) -> usize {
        let terminal: Vec<IfdId> = self
            .rules
            .iter()
            .filter(|(_, r)| {
                r.status == IfdStatus::Triggered
                    || r.status == IfdStatus::Failed
                    || r.status == IfdStatus::Cancelled
            })
            .map(|(id, _)| *id)
            .collect();

        let count = terminal.len();
        for id in terminal {
            if let Some(rule) = self.rules.remove(&id) {
                self.p2sh_index.remove(&rule.order_a_p2sh);
                if let Some(ref outpoint) = rule.order_a_outpoint {
                    self.outpoint_index.remove(outpoint);
                }
            }
        }
        count
    }

    /// Serialize the IFD book to JSON for persistence.
    pub fn to_json(&self) -> Result<String, String> {
        let rules: Vec<&IfdRule> = self.rules.values().collect();
        serde_json::to_string_pretty(&rules).map_err(|e| e.to_string())
    }

    /// Deserialize the IFD book from JSON, restoring state and indices.
    pub fn from_json(json: &str) -> Result<Self, String> {
        let rules_vec: Vec<IfdRule> =
            serde_json::from_str(json).map_err(|e| e.to_string())?;

        let mut book = IfdBook::new();
        let mut max_id: IfdId = 0;

        for rule in rules_vec {
            if rule.id > max_id {
                max_id = rule.id;
            }
            // Rebuild indices for active rules
            if rule.status == IfdStatus::Pending || rule.status == IfdStatus::Active {
                book.p2sh_index.insert(rule.order_a_p2sh.clone(), rule.id);
                if let Some(ref outpoint) = rule.order_a_outpoint {
                    book.outpoint_index.insert(outpoint.clone(), rule.id);
                }
            }
            book.rules.insert(rule.id, rule);
        }

        book.next_id = max_id + 1;
        Ok(book)
    }
}

// Helpers: build B's redeem script and P2SH

/// Build order B's redeem script and P2SH from IFD parameters.
///
/// Returns (rs_bytes, p2sh_script_hex, spk_hash_hex).
///
/// For a sell order B, the RS does not include token_covenant_id in state
/// (it's implicit via covenant binding). The P2SH is derived from blake2b(RS).
pub fn compute_order_b_scripts(
    params: &OrderBParams,
    owner_hash: &[u8; 32],
    owner_spk_hash: &[u8; 32],
    _max_matcher_fee: u64, // v13: ignored, kept for API compat
) -> Result<(Vec<u8>, String, String), String> {
    let token_bytes = parse_hex_32(&params.token)?;

    let rs = match params.side {
        IfdSide::Buy => kob_core::contract::build_buy_redeem_script(
            &token_bytes,
            params.price_num,
            params.price_den,
            params.min_fill,
            owner_hash,
            owner_spk_hash, crate::DEFAULT_MAX_MATCHER_FEE,
            0, // cancel_pending
            params.expiry_daa,).map_err(|e| e.to_string())?,
        IfdSide::Sell => kob_core::contract::build_sell_redeem_script(
            params.price_num,
            params.price_den,
            params.min_fill,
            owner_hash,
            owner_spk_hash, crate::DEFAULT_MAX_MATCHER_FEE,
            0, // cancel_pending
            params.expiry_daa,).map_err(|e| e.to_string())?,
    };

    let p2sh_spk = kob_core::p2sh::build_p2sh(&rs);
    let p2sh_hex = hex::encode(&p2sh_spk.script());
    let spk_hash = kob_core::p2sh::compute_spk_hash(p2sh_spk.version, &p2sh_spk.script());
    let spk_hash_hex = hex::encode(spk_hash);

    Ok((rs, p2sh_hex, spk_hash_hex))
}

/// Build order B's OCO sell redeem script for IFO.
///
/// Creates a single oco_sell UTXO with TP and SL paths.
/// Spending one path naturally cancels the other (UTXO model).
///
/// Returns (rs, p2sh_hex) -- single RS and its P2SH script hex.
pub fn compute_oco_b_scripts(
    _token: &str,
    oco: &IfoOcoParams,
    owner_hash: &[u8; 32],
    owner_spk: &[u8; 36],
    _amount: u64,
) -> Result<(Vec<u8>, String), String> {
    // Derive seller SPK hash from owner_spk (P2PK SPK: version 2B + script 34B)
    let seller_spk_hash = kob_core::p2sh::blake2b_256(owner_spk);

    let rs = kob_core::contract::build_oco_sell_redeem_script(
        oco.tp_price_num,
        oco.tp_price_den,
        oco.tp_min_fill,
        oco.sl_price_num,
        oco.sl_price_den,
        oco.sl_min_fill,
        owner_hash,
        &seller_spk_hash,
        crate::DEFAULT_MAX_MATCHER_FEE,
        0, // cancel_pending
        0, // expiry_daa (GTC)
    ).map_err(|e| e.to_string())?;

    let p2sh = kob_core::p2sh::build_p2sh(&rs);

    Ok((
        rs,
        hex::encode(&p2sh.script()),
    ))
}

fn parse_hex_32(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

// Persistence

/// Save IFD rules to a JSON file (atomic write).
pub fn save_ifd_rules(path: &str, book: &IfdBook) -> Result<(), String> {
    let json = book.to_json()?;
    let tmp_path = format!("{}.tmp", path);
    std::fs::write(&tmp_path, &json)
        .map_err(|e| format!("Failed to write {}: {}", tmp_path, e))?;
    std::fs::rename(&tmp_path, path)
        .map_err(|e| format!("Failed to rename {} -> {}: {}", tmp_path, path, e))?;
    tracing::info!("[IFD BOOK] Saved {} rules to {}", book.len(), path);
    Ok(())
}

/// Load IFD rules from a JSON file.
pub fn load_ifd_rules(path: &str) -> Result<IfdBook, String> {
    let path_ref = std::path::Path::new(path);
    if !path_ref.exists() {
        tracing::info!("[IFD BOOK] No persisted file at {}, starting empty", path);
        return Ok(IfdBook::new());
    }
    let json = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path, e))?;
    let book = IfdBook::from_json(&json)?;
    tracing::info!(
        "[IFD BOOK] Loaded {} rules ({} active) from {}",
        book.len(),
        book.active_count(),
        path,
    );
    Ok(book)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_order_a_params() -> OrderAParams {
        OrderAParams {
            side: IfdSide::Buy,
            token: "aa".repeat(32),
            price_num: 100,
            price_den: 1,
            amount: 1_000_000,
            min_fill: 100_000,
            expiry_daa: 0,
        }
    }

    fn make_order_b_params() -> OrderBParams {
        OrderBParams {
            side: IfdSide::Sell,
            token: "aa".repeat(32),
            price_num: 120,
            price_den: 1,
            amount: 0, // use proceeds from A
            min_fill: 100_000,
            expiry_daa: 0,
        }
    }

    fn make_rule(owner: &str) -> IfdRule {
        IfdRule {
            id: 0,
            order_a_params: make_order_a_params(),
            order_a_p2sh: "p2sh_a_001".to_string(),
            order_a_outpoint: None,
            order_b: OrderBType::Simple(make_order_b_params()),
            order_b_rs_hex: "deadbeef".to_string(),
            order_b_p2sh: "p2sh_b_001".to_string(),
            order_b_spk_hash: "spkhash_b_001".to_string(),
            status: IfdStatus::Pending,
            trigger_tx_id: None,
            created_at: 1000,
            owner_id: owner.to_string(),
            cancel_secret: None,
        }
    }


    #[test]
    fn register_assigns_incremental_ids() {
        let mut book = IfdBook::new();
        let mut r1 = make_rule("alice");
        r1.order_a_p2sh = "p2sh_1".to_string();
        let id1 = book.register(r1).unwrap();
        assert_eq!(id1, 1);

        let mut r2 = make_rule("alice");
        r2.order_a_p2sh = "p2sh_2".to_string();
        let id2 = book.register(r2).unwrap();
        assert_eq!(id2, 2);
    }

    #[test]
    fn register_enforces_limit() {
        let mut book = IfdBook::new();
        for i in 0..MAX_IFD_RULES {
            let mut r = make_rule("alice");
            r.order_a_p2sh = format!("p2sh_{}", i);
            book.register(r).unwrap();
        }
        let mut r = make_rule("alice");
        r.order_a_p2sh = "p2sh_overflow".to_string();
        assert!(book.register(r).is_err());
    }


    #[test]
    fn find_by_a_p2sh() {
        let mut book = IfdBook::new();
        let mut r = make_rule("alice");
        r.order_a_p2sh = "unique_p2sh".to_string();
        let id = book.register(r).unwrap();

        let found = book.find_by_a_p2sh("unique_p2sh").unwrap();
        assert_eq!(found.id, id);
        assert!(book.find_by_a_p2sh("nonexistent").is_none());
    }


    #[test]
    fn activate_and_find_by_outpoint() {
        let mut book = IfdBook::new();
        let r = make_rule("alice");
        let id = book.register(r).unwrap();

        assert!(book.activate(id, "txid_a:0"));
        assert_eq!(book.get(id).unwrap().status, IfdStatus::Active);

        let found = book.find_by_a_outpoint("txid_a:0").unwrap();
        assert_eq!(found.id, id);
    }

    #[test]
    fn activate_only_from_pending() {
        let mut book = IfdBook::new();
        let r = make_rule("alice");
        let id = book.register(r).unwrap();

        // Activate once
        assert!(book.activate(id, "txid_a:0"));
        // Second activate should fail (already Active)
        assert!(!book.activate(id, "txid_a:1"));
    }


    #[test]
    fn trigger_transitions_to_triggered() {
        let mut book = IfdBook::new();
        let r = make_rule("alice");
        let id = book.register(r).unwrap();

        book.activate(id, "txid_a:0");
        assert!(book.trigger(id, "fill_tx_001"));

        let rule = book.get(id).unwrap();
        assert_eq!(rule.status, IfdStatus::Triggered);
        assert_eq!(rule.trigger_tx_id.as_deref(), Some("fill_tx_001"));
    }

    #[test]
    fn trigger_only_from_active() {
        let mut book = IfdBook::new();
        let r = make_rule("alice");
        let id = book.register(r).unwrap();

        // Cannot trigger from Pending
        assert!(!book.trigger(id, "fill_tx"));
    }


    #[test]
    fn mark_failed_transitions() {
        let mut book = IfdBook::new();
        let r = make_rule("alice");
        let id = book.register(r).unwrap();

        book.activate(id, "txid_a:0");
        assert!(book.mark_failed(id));
        assert_eq!(book.get(id).unwrap().status, IfdStatus::Failed);
    }


    #[test]
    fn cancel_removes_rule() {
        let mut book = IfdBook::new();
        let r = make_rule("alice");
        let id = book.register(r).unwrap();

        let cancelled = book.cancel(id, "alice", None).unwrap();
        assert_eq!(cancelled.id, id);
        assert!(book.get(id).is_none());
        assert!(book.find_by_a_p2sh("p2sh_a_001").is_none());
    }

    #[test]
    fn cancel_wrong_owner_fails() {
        let mut book = IfdBook::new();
        let r = make_rule("alice");
        let id = book.register(r).unwrap();

        assert!(book.cancel(id, "bob", None).is_none());
        assert!(book.get(id).is_some()); // still exists
    }

    #[test]
    fn cancel_triggered_fails() {
        let mut book = IfdBook::new();
        let r = make_rule("alice");
        let id = book.register(r).unwrap();

        book.activate(id, "txid_a:0");
        book.trigger(id, "fill_tx");

        assert!(book.cancel(id, "alice", None).is_none());
    }


    #[test]
    fn list_by_owner() {
        let mut book = IfdBook::new();
        let mut r1 = make_rule("alice");
        r1.order_a_p2sh = "p2sh_1".to_string();
        book.register(r1).unwrap();

        let mut r2 = make_rule("bob");
        r2.order_a_p2sh = "p2sh_2".to_string();
        book.register(r2).unwrap();

        let mut r3 = make_rule("alice");
        r3.order_a_p2sh = "p2sh_3".to_string();
        book.register(r3).unwrap();

        let alice_rules = book.list_by_owner("alice");
        assert_eq!(alice_rules.len(), 2);

        let bob_rules = book.list_by_owner("bob");
        assert_eq!(bob_rules.len(), 1);
    }

    #[test]
    fn list_active_excludes_terminal() {
        let mut book = IfdBook::new();
        let mut r1 = make_rule("alice");
        r1.order_a_p2sh = "p2sh_1".to_string();
        let id1 = book.register(r1).unwrap();

        let mut r2 = make_rule("alice");
        r2.order_a_p2sh = "p2sh_2".to_string();
        let id2 = book.register(r2).unwrap();

        // Trigger r1
        book.activate(id1, "txid:0");
        book.trigger(id1, "fill_tx");

        let active = book.list_active();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, id2);
    }


    #[test]
    fn cleanup_removes_terminal_rules() {
        let mut book = IfdBook::new();
        let mut r1 = make_rule("alice");
        r1.order_a_p2sh = "p2sh_1".to_string();
        let id1 = book.register(r1).unwrap();

        let mut r2 = make_rule("alice");
        r2.order_a_p2sh = "p2sh_2".to_string();
        book.register(r2).unwrap();

        book.activate(id1, "txid:0");
        book.trigger(id1, "fill_tx");

        let removed = book.cleanup();
        assert_eq!(removed, 1);
        assert_eq!(book.len(), 1);
    }


    #[test]
    fn json_roundtrip() {
        let mut book = IfdBook::new();
        let mut r1 = make_rule("alice");
        r1.order_a_p2sh = "p2sh_1".to_string();
        let id1 = book.register(r1).unwrap();

        let mut r2 = make_rule("bob");
        r2.order_a_p2sh = "p2sh_2".to_string();
        let id2 = book.register(r2).unwrap();

        book.activate(id1, "txid:0");

        let json = book.to_json().unwrap();
        let restored = IfdBook::from_json(&json).unwrap();

        assert_eq!(restored.len(), 2);
        assert_eq!(restored.get(id1).unwrap().status, IfdStatus::Active);
        assert_eq!(restored.get(id2).unwrap().status, IfdStatus::Pending);

        // Indices should be rebuilt
        assert!(restored.find_by_a_p2sh("p2sh_1").is_some());
        assert!(restored.find_by_a_p2sh("p2sh_2").is_some());
        assert!(restored.find_by_a_outpoint("txid:0").is_some());
    }

    #[test]
    fn json_roundtrip_empty() {
        let book = IfdBook::new();
        let json = book.to_json().unwrap();
        let restored = IfdBook::from_json(&json).unwrap();
        assert!(restored.is_empty());
    }

    #[test]
    fn file_persistence_roundtrip() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_ifd_book.json");
        let path_str = path.to_str().unwrap();

        let mut book = IfdBook::new();
        let mut r = make_rule("alice");
        r.order_a_p2sh = "p2sh_persist".to_string();
        book.register(r).unwrap();

        save_ifd_rules(path_str, &book).unwrap();
        let loaded = load_ifd_rules(path_str).unwrap();

        assert_eq!(loaded.len(), 1);
        assert!(loaded.find_by_a_p2sh("p2sh_persist").is_some());

        // Cleanup
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_nonexistent_returns_empty() {
        let result = load_ifd_rules("/tmp/nonexistent_ifd_book_test.json");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }


    #[test]
    fn active_count_tracks_correctly() {
        let mut book = IfdBook::new();
        let mut r1 = make_rule("alice");
        r1.order_a_p2sh = "p2sh_1".to_string();
        let id1 = book.register(r1).unwrap();

        let mut r2 = make_rule("alice");
        r2.order_a_p2sh = "p2sh_2".to_string();
        book.register(r2).unwrap();

        assert_eq!(book.active_count(), 2);

        book.activate(id1, "txid:0");
        assert_eq!(book.active_count(), 2); // Active is still "active"

        book.trigger(id1, "fill_tx");
        assert_eq!(book.active_count(), 1); // Triggered is terminal
    }


    #[test]
    fn compute_order_b_scripts_sell() {
        let owner_hash = [0xbb; 32];
        let spk_hash = [0xcc; 32];
        let params = OrderBParams {
            side: IfdSide::Sell,
            token: "aa".repeat(32),
            price_num: 120,
            price_den: 1,
            amount: 0,
            min_fill: 100_000,
            expiry_daa: 0,
        };

        let result = compute_order_b_scripts(&params, &owner_hash, &spk_hash, 5000);
        assert!(result.is_ok());

        let (rs, p2sh_hex, spk_hash_hex) = result.unwrap();
        // Sell v12 RS should be 103 + body length
        assert!(!rs.is_empty());
        assert!(!p2sh_hex.is_empty());
        assert!(!spk_hash_hex.is_empty());
        // P2SH script is 35 bytes: 0xaa + 0x20 + hash(32) + 0x87
        assert_eq!(p2sh_hex.len(), 70); // 35 bytes * 2
    }

    #[test]
    fn compute_order_b_scripts_buy() {
        let owner_hash = [0xbb; 32];
        let spk_hash = [0xcc; 32];
        let params = OrderBParams {
            side: IfdSide::Buy,
            token: "aa".repeat(32),
            price_num: 80,
            price_den: 1,
            amount: 500_000,
            min_fill: 50_000,
            expiry_daa: 0,
        };

        let result = compute_order_b_scripts(&params, &owner_hash, &spk_hash, 5000);
        assert!(result.is_ok());

        let (rs, p2sh_hex, _) = result.unwrap();
        // Buy v14 RS = 396 bytes
        assert_eq!(rs.len(), 396);
        assert_eq!(p2sh_hex.len(), 70);
    }

    #[test]
    fn compute_order_b_scripts_invalid_token() {
        let owner_hash = [0xbb; 32];
        let spk_hash = [0xcc; 32];
        let params = OrderBParams {
            side: IfdSide::Sell,
            token: "invalid_hex".to_string(),
            price_num: 100,
            price_den: 1,
            amount: 0,
            min_fill: 100_000,
            expiry_daa: 0,
        };

        let result = compute_order_b_scripts(&params, &owner_hash, &spk_hash, 5000);
        assert!(result.is_err());
    }


    #[test]
    fn compute_oco_b_scripts_produces_valid_oco_sell() {
        let owner_hash = [0xbb; 32];
        let mut owner_spk = [0u8; 36];
        // version=0 (2B LE) + script (34B: 0x20 + pk(32) + 0xac)
        owner_spk[2] = 0x20;
        owner_spk[3..35].copy_from_slice(&[0xdd; 32]);
        owner_spk[35] = 0xac;

        let oco = IfoOcoParams {
            tp_side: IfdSide::Sell,
            tp_price_num: 150,
            tp_price_den: 1,
            tp_min_fill: 100_000,
            sl_side: IfdSide::Sell,
            sl_price_num: 80,
            sl_price_den: 1,
            sl_min_fill: 100_000,
        };

        let result = compute_oco_b_scripts(
            &"aa".repeat(32),
            &oco,
            &owner_hash,
            &owner_spk,
            500_000,
        );
        assert!(result.is_ok());

        let (rs, p2sh) = result.unwrap();
        // oco_sell RS = 139B state + 194B body = 333 bytes
        assert_eq!(rs.len(), kob_core::OCO_SELL_RS_SIZE);
        assert_eq!(p2sh.len(), 70); // P2SH script hex = 35 bytes * 2
    }


    #[test]
    fn order_b_type_serde_roundtrip_simple() {
        let b = OrderBType::Simple(make_order_b_params());
        let json = serde_json::to_string(&b).unwrap();
        let restored: OrderBType = serde_json::from_str(&json).unwrap();
        match restored {
            OrderBType::Simple(p) => {
                assert_eq!(p.price_num, 120);
                assert_eq!(p.side, IfdSide::Sell);
            }
            _ => panic!("expected Simple variant"),
        }
    }

    #[test]
    fn order_b_type_serde_roundtrip_oco() {
        let b = OrderBType::Oco {
            token: "bb".repeat(32),
            amount: 0,
            expiry_daa: 0,
            oco: IfoOcoParams {
                tp_side: IfdSide::Sell,
                tp_price_num: 150,
                tp_price_den: 1,
                tp_min_fill: 100_000,
                sl_side: IfdSide::Sell,
                sl_price_num: 80,
                sl_price_den: 1,
                sl_min_fill: 100_000,
            },
        };
        let json = serde_json::to_string(&b).unwrap();
        let restored: OrderBType = serde_json::from_str(&json).unwrap();
        match restored {
            OrderBType::Oco { oco, .. } => {
                assert_eq!(oco.tp_price_num, 150);
                assert_eq!(oco.sl_price_num, 80);
            }
            _ => panic!("expected Oco variant"),
        }
    }
}
