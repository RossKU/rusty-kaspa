//! Minimal reservation provider for the KIP-10 additive "exact" scheme.
//!
//! Tracks borrow terms: for each reservation the merchant funds a UTXO to the
//! additive-borrow covenant P2SH; this provider computes that covenant, records
//! the terms, and emits the v2 `PaymentRequirements.extra` the client needs.

use std::collections::HashMap;

use kob_core::contract::x402_borrow::build_x402_borrow_redeem_script;
use kob_settle::{blake2b_256, build_p2sh};

use crate::wire_v2::{BINDING_EXACT, TEMPLATE_KIP10_ADDITIVE, TX_ENCODING_SAFE_JSON};

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
    pub consumed: bool,
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

/// The additive-borrow covenant address/script for a merchant `pay_to`, holding
/// `borrow_amount`, requiring the continuation to return
/// `borrow_amount + additive_threshold` to the merchant.
pub fn borrow_covenant(
    pay_to: &str,
    borrow_amount: u64,
    additive_threshold: u64,
) -> Result<(Vec<u8>, Vec<u8>, String), String> {
    let merchant_spk = kob_settle::bech32::address_to_spk(pay_to).map_err(|e| e.to_string())?;
    // merchant_spk_hash = blake2b(version_u16LE || script); version 0.
    let mut buf = Vec::with_capacity(2 + merchant_spk.len());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&merchant_spk);
    let merchant_spk_hash = blake2b_256(&buf);
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
#[derive(Default)]
pub struct ReservationProvider {
    by_id: HashMap<String, BorrowTerms>,
}

impl ReservationProvider {
    pub fn new() -> Self {
        Self { by_id: HashMap::new() }
    }

    /// Record a reservation for an already-funded borrow outpoint and return the
    /// terms (whose `requirements_extra()` populates the 402 offer).
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
    ) -> Result<BorrowTerms, String> {
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
            consumed: false,
        };
        self.by_id.insert(reservation_id, terms.clone());
        Ok(terms)
    }

    pub fn get(&self, reservation_id: &str) -> Option<&BorrowTerms> {
        self.by_id.get(reservation_id)
    }

    pub fn mark_consumed(&mut self, reservation_id: &str) {
        if let Some(t) = self.by_id.get_mut(reservation_id) {
            t.consumed = true;
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
        let t = rp.reserve(rid.clone(), &testnet_addr(1), 250, &"cd".repeat(32), 0, 100_000_000, 3000, 1).unwrap();
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
}
