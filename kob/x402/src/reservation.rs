//! Minimal reservation provider for the KIP-10 additive "exact" scheme.
//!
//! Tracks borrow terms: for each reservation the merchant funds a UTXO to the
//! additive-borrow covenant P2SH; this provider computes that covenant, records
//! the terms, and emits the v2 `PaymentRequirements.extra` the client needs.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use kob_core::contract::x402_borrow::build_x402_borrow_redeem_script;
use kob_settle::{blake2b_256, build_p2sh};

use crate::wire_v2::{BINDING_EXACT, TEMPLATE_KIP10_ADDITIVE, TX_ENCODING_SAFE_JSON};

/// Default reservation time-to-live. `/reserve` is unauthenticated, so a
/// reservation that is never settled must not live forever in memory.
pub const RESERVATION_TTL: Duration = Duration::from_secs(3600);
/// Hard cap on live reservations. Once expired entries are evicted, a new
/// reservation past this cap is rejected (fail-closed) rather than growing
/// memory without bound.
pub const MAX_RESERVATIONS: usize = 100_000;

/// Recorded borrow terms for one reservation.
#[derive(Debug, Clone)]
pub struct BorrowTerms {
    pub reservation_id: String,
    pub pay_to: String,
    pub amount: u64,
    pub borrow_txid: String,
    pub borrow_index: u32,
    pub borrow_amount: u64,
    pub additive_threshold: u64,
    /// `borrow_amount + additive_threshold` — the covenant continuation minimum.
    pub min_continuation: u64,
    pub redeem_script: Vec<u8>,
    /// P2SH scriptPublicKey bytes (version 0).
    pub p2sh_script: Vec<u8>,
    pub payment_output_index: u32,
    /// blake2b(version||merchant_spk) — the covenant's continuation target hash.
    /// Enforced unique per active reservation (aggregate-drain prevention).
    pub merchant_spk_hash: [u8; 32],
    /// Expected request hash; when set the client payload MUST carry it.
    pub request_hash: Option<String>,
    pub consumed: bool,
    /// When this reservation was recorded — drives TTL eviction.
    pub created_at: Instant,
}

impl BorrowTerms {
    /// `extra` object for the exact-scheme PaymentRequirements (v2).
    pub fn requirements_extra(&self) -> serde_json::Value {
        serde_json::json!({
            "binding": BINDING_EXACT,
            "finality": "accepted",
            "templateId": TEMPLATE_KIP10_ADDITIVE,
            "transactionEncoding": TX_ENCODING_SAFE_JSON,
            "borrowOutpoint": { "txid": self.borrow_txid, "index": self.borrow_index },
            "borrowAmount": self.borrow_amount.to_string(),
            "borrowScriptPublicKey": format!("0000{}", hex::encode(&self.p2sh_script)),
            "borrowRedeemScript": hex::encode(&self.redeem_script),
            "additiveThresholdSompi": self.additive_threshold.to_string(),
            "paymentOutputIndex": self.payment_output_index,
            "reservationId": self.reservation_id,
            "assetKind": "native",
            "assetDecimals": 8,
        })
    }
}

/// blake2b(version_u16LE || merchant_spk); version 0. This is the covenant's
/// continuation-target hash — the value that MUST differ between concurrent
/// reservations so no two borrow UTXOs can be satisfied by one shared
/// continuation output (the aggregate-inputs drain).
pub fn merchant_spk_hash_of(pay_to: &str) -> Result<[u8; 32], String> {
    let merchant_spk = kob_settle::bech32::address_to_spk(pay_to).map_err(|e| e.to_string())?;
    let mut buf = Vec::with_capacity(2 + merchant_spk.len());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&merchant_spk);
    Ok(blake2b_256(&buf))
}

/// The additive-borrow covenant address/script for a merchant `pay_to`, holding
/// `borrow_amount`, requiring the continuation to return
/// `borrow_amount + additive_threshold` to the merchant.
pub fn borrow_covenant(
    pay_to: &str,
    borrow_amount: u64,
    additive_threshold: u64,
) -> Result<(Vec<u8>, Vec<u8>, String), String> {
    let merchant_spk_hash = merchant_spk_hash_of(pay_to)?;
    let min_continuation = borrow_amount
        .checked_add(additive_threshold)
        .ok_or("borrow_amount + additive_threshold overflow")?;
    let rs = build_x402_borrow_redeem_script(&merchant_spk_hash, min_continuation);
    let p2sh = build_p2sh(&rs);
    let prefix = if pay_to.starts_with("kaspatest") { "kaspatest" } else { "kaspa" };
    let addr = kob_settle::bech32::spk_to_address(p2sh.script(), prefix).map_err(|e| e.to_string())?;
    Ok((rs, p2sh.script().to_vec(), addr))
}

/// In-memory reservation store.
pub struct ReservationProvider {
    by_id: HashMap<String, BorrowTerms>,
    /// merchant_spk_hashes of active (unconsumed) reservations. Enforced unique
    /// so no two live borrow UTXOs share a continuation target: a single
    /// continuation output can then never satisfy two covenants at once, which
    /// is what the aggregate-inputs drain relied on.
    active_hashes: HashSet<[u8; 32]>,
    ttl: Duration,
    max_entries: usize,
}

impl Default for ReservationProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ReservationProvider {
    pub fn new() -> Self {
        Self {
            by_id: HashMap::new(),
            active_hashes: HashSet::new(),
            ttl: RESERVATION_TTL,
            max_entries: MAX_RESERVATIONS,
        }
    }

    /// Construct with explicit TTL/cap limits (tests).
    pub fn with_limits(ttl: Duration, max_entries: usize) -> Self {
        Self { by_id: HashMap::new(), active_hashes: HashSet::new(), ttl, max_entries }
    }

    /// Drop reservations older than the TTL, freeing their continuation
    /// targets. Called at each `reserve` so abandoned (never-settled)
    /// reservations from an unauthenticated caller cannot accumulate forever.
    fn evict_expired(&mut self) {
        let ttl = self.ttl;
        let active = &mut self.active_hashes;
        self.by_id.retain(|_, t| {
            let keep = t.created_at.elapsed() < ttl;
            if !keep {
                active.remove(&t.merchant_spk_hash);
            }
            keep
        });
    }

    /// Record a reservation for an already-funded borrow outpoint and return the
    /// terms (whose `requirements_extra()` populates the 402 offer).
    ///
    /// Rejects any reservation whose merchant continuation target
    /// (`merchant_spk_hash`, derived from `pay_to`) collides with an existing
    /// active reservation. The merchant MUST use a fresh continuation address
    /// per concurrent reservation; reuse would let a payer aggregate-spend the
    /// two borrow UTXOs against one shared continuation output and pocket the
    /// difference.
    #[allow(clippy::too_many_arguments)]
    pub fn reserve(
        &mut self,
        reservation_id: String,
        pay_to: &str,
        amount: u64,
        borrow_txid: &str,
        borrow_index: u32,
        borrow_amount: u64,
        additive_threshold: u64,
        payment_output_index: u32,
        request_hash: Option<String>,
    ) -> Result<BorrowTerms, String> {
        // Reclaim abandoned reservations first so TTL churn keeps memory
        // bounded without a background task.
        self.evict_expired();
        // Fail closed at the cap (post-eviction): an unauthenticated caller
        // must not be able to grow the map without bound.
        if self.by_id.len() >= self.max_entries {
            return Err("reservation capacity reached; try again later".to_string());
        }
        let merchant_spk_hash = merchant_spk_hash_of(pay_to)?;
        if self.active_hashes.contains(&merchant_spk_hash) {
            return Err(format!(
                "merchant continuation target for pay_to={} is already in use by an active \
                 reservation; supply a fresh merchant address per concurrent reservation \
                 (shared continuation targets enable the aggregate-inputs drain)",
                pay_to
            ));
        }
        let (redeem_script, p2sh_script, _addr) = borrow_covenant(pay_to, borrow_amount, additive_threshold)?;
        let terms = BorrowTerms {
            reservation_id: reservation_id.clone(),
            pay_to: pay_to.to_string(),
            amount,
            borrow_txid: borrow_txid.to_string(),
            borrow_index,
            borrow_amount,
            additive_threshold,
            min_continuation: borrow_amount + additive_threshold,
            redeem_script,
            p2sh_script,
            payment_output_index,
            merchant_spk_hash,
            request_hash,
            consumed: false,
            created_at: Instant::now(),
        };
        self.active_hashes.insert(merchant_spk_hash);
        self.by_id.insert(reservation_id, terms.clone());
        Ok(terms)
    }

    pub fn get(&self, reservation_id: &str) -> Option<&BorrowTerms> {
        self.by_id.get(reservation_id)
    }

    /// Mark a reservation consumed and free its continuation target for reuse
    /// (its borrow UTXO is spent, so it can no longer be part of a drain).
    pub fn mark_consumed(&mut self, reservation_id: &str) {
        if let Some(t) = self.by_id.get_mut(reservation_id) {
            t.consumed = true;
            self.active_hashes.remove(&t.merchant_spk_hash);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn testnet_addr(seed: u8) -> String {
        kob_settle::wallet::pubkey_to_address(&[seed; 32], kob_settle::types::Network::Testnet)
    }

    #[test]
    fn covenant_address_is_p2sh() {
        let (rs, spk, addr) = borrow_covenant(&testnet_addr(1), 100_000_000, 3000).unwrap();
        assert_eq!(rs.len(), kob_core::contract::x402_borrow::X402_BORROW_RS_SIZE);
        assert_eq!(spk[0], 0xaa); // P2SH
        assert!(addr.starts_with("kaspatest:"));
    }

    #[test]
    fn reserve_records_and_extra_conforms() {
        let mut rp = ReservationProvider::new();
        let rid = "ab".repeat(32);
        let t = rp.reserve(rid.clone(), &testnet_addr(1), 250, &"cd".repeat(32), 0, 100_000_000, 3000, 1, None).unwrap();
        let extra = t.requirements_extra();
        assert_eq!(extra["binding"], BINDING_EXACT);
        assert_eq!(extra["templateId"], TEMPLATE_KIP10_ADDITIVE);
        assert_eq!(extra["borrowAmount"], "100000000");
        assert_eq!(extra["additiveThresholdSompi"], "3000");
        assert!(extra["borrowScriptPublicKey"].as_str().unwrap().starts_with("0000aa"));
        assert_eq!(extra["reservationId"], rid);
        assert!(rp.get(&rid).is_some());
        rp.mark_consumed(&rid);
        assert!(rp.get(&rid).unwrap().consumed);
    }

    #[test]
    fn rejects_duplicate_merchant_continuation_target() {
        let mut rp = ReservationProvider::new();
        let merchant = testnet_addr(7);
        let t1 = rp.reserve("11".repeat(32), &merchant, 250, &"aa".repeat(32), 0, 100_000_000, 3000, 1, None).unwrap();
        // Second concurrent reservation to the SAME merchant address is rejected:
        // a shared continuation target is exactly what the aggregate-drain needs.
        let dup = rp.reserve("22".repeat(32), &merchant, 250, &"bb".repeat(32), 0, 100_000_000, 3000, 1, None);
        assert!(dup.is_err(), "reusing a merchant continuation target must be rejected");

        // A distinct merchant address is accepted and yields a DISTINCT covenant
        // (distinct merchant_spk_hash => distinct P2SH), so the two live borrow
        // UTXOs cannot be satisfied by one shared continuation output.
        let t2 = rp.reserve("33".repeat(32), &testnet_addr(8), 250, &"cc".repeat(32), 0, 100_000_000, 3000, 1, None).unwrap();
        assert_ne!(t1.merchant_spk_hash, t2.merchant_spk_hash);
        assert_ne!(t1.p2sh_script, t2.p2sh_script);

        // Consuming a reservation frees its target for later reuse (UTXO spent).
        rp.mark_consumed(&"11".repeat(32));
        let reuse = rp.reserve("44".repeat(32), &merchant, 250, &"dd".repeat(32), 0, 100_000_000, 3000, 1, None);
        assert!(reuse.is_ok(), "target must be reusable after the prior reservation is consumed");
    }

    #[test]
    fn rejects_new_reservation_at_capacity() {
        // Cap = 1: a second (distinct-merchant) reservation is rejected once
        // the map is full, so an unauthenticated caller can't grow it forever.
        let mut rp = ReservationProvider::with_limits(RESERVATION_TTL, 1);
        rp.reserve("11".repeat(32), &testnet_addr(1), 250, &"aa".repeat(32), 0, 100_000_000, 3000, 1, None).unwrap();
        let over = rp.reserve("22".repeat(32), &testnet_addr(2), 250, &"bb".repeat(32), 0, 100_000_000, 3000, 1, None);
        assert!(over.is_err(), "reservation past the cap must be rejected");
    }

    #[test]
    fn evicts_expired_reservations_and_reclaims_capacity() {
        // TTL ~ 0: the prior reservation is expired at the next reserve, so the
        // cap-1 slot is reclaimed and a fresh reservation succeeds. The
        // expired one (and its continuation target) is gone.
        let mut rp = ReservationProvider::with_limits(Duration::from_millis(1), 1);
        let t1 = rp.reserve("11".repeat(32), &testnet_addr(1), 250, &"aa".repeat(32), 0, 100_000_000, 3000, 1, None).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        let t2 = rp.reserve("22".repeat(32), &testnet_addr(2), 250, &"bb".repeat(32), 0, 100_000_000, 3000, 1, None);
        assert!(t2.is_ok(), "expired reservation must be evicted to make room");
        assert!(rp.get(&t1.reservation_id).is_none(), "expired reservation must be gone");
    }
}
