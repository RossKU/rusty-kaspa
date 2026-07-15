//! Scheme: KIP-10 additive "exact" — the strict-interop scheme (binding
//! `kaspa-exact-v1`). Verifies a client exact-transaction that spends the
//! reserved borrow outpoint, pays exactly `amount` to `payTo` at
//! `paymentOutputIndex`, and returns >= `borrowAmount + additiveThreshold` to
//! the merchant via the additive covenant continuation.

use kob_settle::observe::ObservedOutput;

use crate::reservation::BorrowTerms;
use crate::scheme_native::{artifact_id, normalize_tx};
use crate::wire_v2::TX_ENCODING_SAFE_JSON;

#[derive(Debug, Clone)]
pub struct ExactVerified {
    pub artifact_id: String,
    pub payer: String,
    pub payment_output_index: u32,
    pub amount_paid: u64,
    pub input_outpoints: Vec<String>,
    pub borrow_outpoint: String,
    pub confirm_address: String,
    pub tx: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactReject {
    Malformed,
    BadEncoding,
    WrongBorrowOutpoint,
    WrongPaymentOutputIndex,
    WrongRecipient,
    Underpayment,
    UnderThreshold,
    FingerprintMismatch,
    NoInputs,
}

fn spk_of(addr: &str) -> Option<Vec<u8>> {
    kob_settle::bech32::address_to_spk(addr).ok()
}

fn input_outpoints(tx: &serde_json::Value) -> Vec<String> {
    tx.get("inputs")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|inp| {
                    let op = inp.get("previousOutpoint")?;
                    let txid = op.get("transactionId").and_then(|v| v.as_str())?;
                    let idx = op.get("index").and_then(|v| v.as_u64()).unwrap_or(0);
                    Some(format!("{}:{}", txid, idx))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Verify a KIP-10 additive exact-transaction (pure, node-independent).
///
/// All economic terms (`amount`, `payTo`, borrow outpoint/amount, threshold,
/// payment output index) come from the SERVER-AUTHORITATIVE `terms` — never
/// from caller-supplied requirements. `expected_request_hash` binds the
/// request when the merchant set one on the reservation.
pub fn verify_exact_kip10(
    transaction_encoded: &str,
    encoding: &str,
    payment_output_index: u32,
    request_hash: Option<&str>,
    payer: &str,
    expected_request_hash: Option<&str>,
    terms: &BorrowTerms,
) -> Result<ExactVerified, ExactReject> {
    if encoding != TX_ENCODING_SAFE_JSON {
        return Err(ExactReject::BadEncoding);
    }
    let outer: serde_json::Value =
        serde_json::from_str(transaction_encoded).map_err(|_| ExactReject::Malformed)?;
    let tx = normalize_tx(&outer);
    if !tx.is_object() {
        return Err(ExactReject::Malformed);
    }

    let required = terms.amount;
    let min_continuation = terms.min_continuation;
    let pay_to_spk = spk_of(&terms.pay_to).ok_or(ExactReject::WrongRecipient)?;
    if payment_output_index != terms.payment_output_index {
        return Err(ExactReject::WrongPaymentOutputIndex);
    }

    // Request-hash binding.
    if let Some(exp) = expected_request_hash {
        match request_hash {
            Some(got) if got == exp => {}
            _ => return Err(ExactReject::FingerprintMismatch),
        }
    }

    // Must spend exactly the reserved borrow outpoint.
    let outpoints = input_outpoints(&tx);
    if outpoints.is_empty() {
        return Err(ExactReject::NoInputs);
    }
    let borrow_key = format!("{}:{}", terms.borrow_txid, terms.borrow_index);
    if !outpoints.iter().any(|o| o == &borrow_key) {
        return Err(ExactReject::WrongBorrowOutpoint);
    }

    // Parse outputs.
    let raw_outputs = tx
        .get("outputs")
        .and_then(|v| v.as_array())
        .ok_or(ExactReject::Malformed)?;
    let outputs: Vec<ObservedOutput> =
        raw_outputs.iter().filter_map(ObservedOutput::from_rpc_json).collect();
    if outputs.len() != raw_outputs.len() {
        return Err(ExactReject::Malformed);
    }

    // Payment output: exactly `amount` to `payTo` at `paymentOutputIndex`.
    let pay = outputs
        .get(payment_output_index as usize)
        .ok_or(ExactReject::WrongRecipient)?;
    if pay.spk_version != 0 || pay.spk_script != pay_to_spk {
        return Err(ExactReject::WrongRecipient);
    }
    if pay.value < required {
        return Err(ExactReject::Underpayment);
    }

    // Additive continuation: some OTHER output returns >= min_continuation to
    // the merchant (the covenant enforces this on-chain; we double-check).
    let has_continuation = outputs.iter().enumerate().any(|(i, o)| {
        i as u32 != payment_output_index
            && o.spk_version == 0
            && o.spk_script == pay_to_spk
            && o.value >= min_continuation
    });
    if !has_continuation {
        return Err(ExactReject::UnderThreshold);
    }

    Ok(ExactVerified {
        artifact_id: artifact_id(&tx),
        payer: payer.to_string(),
        payment_output_index,
        amount_paid: pay.value,
        input_outpoints: outpoints,
        borrow_outpoint: borrow_key,
        confirm_address: terms.pay_to.clone(),
        tx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reservation::ReservationProvider;

    fn testnet_addr(seed: u8) -> String {
        kob_settle::wallet::pubkey_to_address(&[seed; 32], kob_settle::types::Network::Testnet)
    }
    fn spk_hex(addr: &str) -> String {
        hex::encode(kob_settle::bech32::address_to_spk(addr).unwrap())
    }

    fn terms(pay_to: &str, amount: u64, borrow_txid: &str) -> BorrowTerms {
        let mut rp = ReservationProvider::new();
        rp.reserve("11".repeat(32), pay_to, amount, borrow_txid, 0, 100_000_000, 3000, 0)
            .unwrap()
    }

    /// Encoded tx spending `borrow_txid:0`, paying `pay_amt` to `pay_to` at
    /// output 0, and returning `cont` to `pay_to` at output 1.
    fn encoded_tx(pay_to: &str, borrow_txid: &str, pay_amt: u64, cont: u64) -> String {
        let tx = serde_json::json!({
            "transaction": {
                "version": 0,
                "inputs": [
                    { "previousOutpoint": { "transactionId": borrow_txid, "index": 0 }, "signatureScript": "00", "sequence": 0, "sigOpCount": 0 },
                    { "previousOutpoint": { "transactionId": "ff".repeat(32), "index": 0 }, "signatureScript": "41".to_string() + &"cd".repeat(65), "sequence": 0, "sigOpCount": 1 }
                ],
                "outputs": [
                    { "value": pay_amt, "scriptPublicKey": { "version": 0, "script": spk_hex(pay_to) } },
                    { "value": cont, "scriptPublicKey": { "version": 0, "script": spk_hex(pay_to) } }
                ],
                "lockTime": 0,
                "subnetworkId": "0000000000000000000000000000000000000000",
                "payload": ""
            }
        });
        serde_json::to_string(&tx).unwrap()
    }

    #[test]
    fn accepts_valid_additive_exact() {
        let merchant = testnet_addr(2);
        let payer = testnet_addr(1);
        let bt = "aa".repeat(32);
        let t = terms(&merchant, 250, &bt);
        // pays 250 to merchant, continuation 100_003_000 (>= 100M+3000).
        let enc = encoded_tx(&merchant, &bt, 250, 100_003_000);
        let v = verify_exact_kip10(&enc, TX_ENCODING_SAFE_JSON, 0, None, &payer, None, &t).unwrap();
        assert_eq!(v.amount_paid, 250);
        assert_eq!(v.borrow_outpoint, format!("{}:0", bt));
    }

    #[test]
    fn rejects_wrong_borrow_outpoint() {
        let merchant = testnet_addr(2);
        let t = terms(&merchant, 250, &"aa".repeat(32));
        // tx spends a DIFFERENT borrow outpoint.
        let enc = encoded_tx(&merchant, &"be".repeat(32), 250, 100_003_000);
        assert_eq!(
            verify_exact_kip10(&enc, TX_ENCODING_SAFE_JSON, 0, None, &testnet_addr(1), None, &t).unwrap_err(),
            ExactReject::WrongBorrowOutpoint
        );
    }

    #[test]
    fn rejects_under_threshold_continuation() {
        let merchant = testnet_addr(2);
        let bt = "aa".repeat(32);
        let t = terms(&merchant, 250, &bt);
        // continuation only 100M (< 100M + 3000).
        let enc = encoded_tx(&merchant, &bt, 250, 100_000_000);
        assert_eq!(
            verify_exact_kip10(&enc, TX_ENCODING_SAFE_JSON, 0, None, &testnet_addr(1), None, &t).unwrap_err(),
            ExactReject::UnderThreshold
        );
    }

    #[test]
    fn rejects_underpayment() {
        let merchant = testnet_addr(2);
        let bt = "aa".repeat(32);
        let t = terms(&merchant, 250, &bt);
        let enc = encoded_tx(&merchant, &bt, 249, 100_003_000);
        assert_eq!(
            verify_exact_kip10(&enc, TX_ENCODING_SAFE_JSON, 0, None, &testnet_addr(1), None, &t).unwrap_err(),
            ExactReject::Underpayment
        );
    }

    #[test]
    fn rejects_wrong_recipient() {
        let merchant = testnet_addr(2);
        let other = testnet_addr(9);
        let bt = "aa".repeat(32);
        let t = terms(&merchant, 250, &bt);
        // payment goes to `other`, not the required merchant.
        let enc = encoded_tx(&other, &bt, 250, 100_003_000);
        assert_eq!(
            verify_exact_kip10(&enc, TX_ENCODING_SAFE_JSON, 0, None, &testnet_addr(1), None, &t).unwrap_err(),
            ExactReject::WrongRecipient
        );
    }

    #[test]
    fn rejects_request_hash_mismatch() {
        let merchant = testnet_addr(2);
        let bt = "aa".repeat(32);
        let t = terms(&merchant, 250, &bt);
        let enc = encoded_tx(&merchant, &bt, 250, 100_003_000);
        let err = verify_exact_kip10(
            &enc, TX_ENCODING_SAFE_JSON, 0, Some(&"11".repeat(32)), &testnet_addr(1), Some(&"22".repeat(32)), &t,
        ).unwrap_err();
        assert_eq!(err, ExactReject::FingerprintMismatch);
    }
}
