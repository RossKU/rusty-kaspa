//! Scheme: strict-interop "exact" (binding `kaspa-exact-v2`, alpha.8 profile
//! split).
//!
//! - `standard-native` (default profile): a plain v0 native transfer paying
//!   EXACTLY `amount` to `payTo` at `paymentOutputIndex`, empty tx payload,
//!   at most one change output ([`verify_exact_standard_native`]).
//! - `additive` (optional profile): verifies a client exact-transaction that
//!   spends the reserved head (borrow) outpoint, pays `amount` to `payTo` at
//!   `paymentOutputIndex`, and returns >= `headAmount + additiveThreshold` to
//!   the merchant via KOB's additive covenant continuation
//!   ([`verify_exact_kip10`] — KOB's own on-chain template; the upstream
//!   reference folds the payment into the head successor instead).

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
    /// alpha.8 exact is an equality: a larger merchant gain is refused too.
    Overpayment,
    UnderThreshold,
    FingerprintMismatch,
    NoInputs,
    /// standard-native requires a version-0 transaction.
    WrongVersion,
    /// standard-native requires an empty tx payload (request binding lives in
    /// the signed authorization, not a payload memo).
    NonEmptyPayload,
    /// standard-native: exactly one output may pay the merchant script.
    DuplicateMerchantOutput,
    /// standard-native: at most one non-merchant (change) output.
    TooManyOutputs,
}

fn spk_of(addr: &str) -> Option<Vec<u8>> {
    kob_settle::bech32::address_to_spk(addr).ok()
}

/// Decode the continuation output index the borrow input's own signature
/// script designates. Mirrors `kob_core::contract::helpers::push_index`'s
/// encoding — the SAME bytes `X402_BORROW_BODY`'s `Op2 OpPick` reads on-chain
/// (`kob/core/src/contract/x402_borrow.rs`), so this must decode identically
/// or the off-chain check can disagree with what the covenant will actually
/// enforce. Returns `None` on anything unrecognized (fail closed).
fn decode_continuation_index(sigscript_hex: &str) -> Option<u32> {
    let bytes = hex::decode(sigscript_hex).ok()?;
    match *bytes.first()? {
        0x00 => Some(0),
        b @ 0x51..=0x60 => Some((b - 0x50) as u32),
        0x01 => bytes.get(1).map(|&b| b as u32),
        0x02 => {
            let lo = *bytes.get(1)? as u32;
            let hi = *bytes.get(2)? as u32;
            Some(lo | (hi << 8))
        }
        _ => None,
    }
}

fn input_outpoints(tx: &serde_json::Value) -> Vec<String> {
    tx.get("inputs")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|inp| {
                    let op = inp.get("previousOutpoint")?;
                    // KOB rpc/safe-json shape uses `transactionId`; the
                    // upstream consensus vectors use `txid`.
                    let txid = op
                        .get("transactionId")
                        .or_else(|| op.get("txid"))
                        .and_then(|v| v.as_str())?;
                    let idx = op.get("index").and_then(|v| v.as_u64()).unwrap_or(0);
                    Some(format!("{}:{}", txid, idx))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Parse one tx output leniently: KOB's rpc shape carries numeric
/// `value`/`amount`, while the upstream `kaspa-sdk-safe-json-v2.0.0` encoding
/// carries them as decimal STRINGS (and the SPK as a flat
/// `<version4hex><scripthex>` string, which `ObservedOutput` already handles).
/// Normalizes string-numeric fields to numbers, then delegates.
pub(crate) fn observed_output_lenient(out: &serde_json::Value) -> Option<ObservedOutput> {
    if let Some(o) = ObservedOutput::from_rpc_json(out) {
        return Some(o);
    }
    let mut fixed = out.clone();
    for key in ["value", "amount"] {
        let parsed = fixed.get(key).and_then(|v| v.as_str()).and_then(|s| s.parse::<u64>().ok());
        if let Some(n) = parsed {
            fixed[key] = serde_json::json!(n);
        }
    }
    ObservedOutput::from_rpc_json(&fixed)
}

/// Successful pure verification of a `standard-native` exact payment.
#[derive(Debug, Clone)]
pub struct StdVerified {
    pub artifact_id: String,
    pub payer: String,
    pub payment_output_index: u32,
    pub amount_paid: u64,
    pub input_outpoints: Vec<String>,
    pub tx: serde_json::Value,
}

/// Verify a `standard-native` exact-transaction (pure, node-independent) —
/// the alpha.8 default profile: a plain version-0 native transfer.
///
/// Canonical-shape rules enforced here (spec/kaspa-exact-v2.md):
/// - exactly one output pays `pay_to`'s script, at `payment_output_index`,
///   with value EXACTLY `required_amount` (over- and underpayment refused);
/// - at most one other (change) output;
/// - version 0, empty payload, no output covenants;
/// - at least one input.
///
/// On-chain input existence, request-hash binding, and the signed payer
/// request authorization are checked by the facilitator.
pub fn verify_exact_standard_native(
    transaction_encoded: &str,
    encoding: &str,
    payment_output_index: u32,
    payer: &str,
    pay_to: &str,
    required_amount: u64,
) -> Result<StdVerified, ExactReject> {
    if encoding != TX_ENCODING_SAFE_JSON {
        return Err(ExactReject::BadEncoding);
    }
    let outer: serde_json::Value =
        serde_json::from_str(transaction_encoded).map_err(|_| ExactReject::Malformed)?;
    let tx = normalize_tx(&outer);
    if !tx.is_object() {
        return Err(ExactReject::Malformed);
    }

    // Version 0, native subnetwork shape, empty payload.
    if tx.get("version").and_then(|v| v.as_u64()).unwrap_or(u64::MAX) != 0 {
        return Err(ExactReject::WrongVersion);
    }
    if tx.get("payload").and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false) {
        return Err(ExactReject::NonEmptyPayload);
    }

    let pay_to_spk = spk_of(pay_to).ok_or(ExactReject::WrongRecipient)?;

    // Outputs: parse (lenient about the safe-json string-numeric encoding).
    let raw_outputs = tx
        .get("outputs")
        .and_then(|v| v.as_array())
        .ok_or(ExactReject::Malformed)?;
    let outputs: Vec<ObservedOutput> =
        raw_outputs.iter().filter_map(observed_output_lenient).collect();
    if outputs.len() != raw_outputs.len() {
        return Err(ExactReject::Malformed);
    }
    // No covenants anywhere (native profile).
    if outputs.iter().any(|o| o.covenant_id.is_some()) {
        return Err(ExactReject::Malformed);
    }

    // Exactly one merchant output; at most one other output.
    let merchant_outputs = outputs
        .iter()
        .filter(|o| o.spk_version == 0 && o.spk_script == pay_to_spk)
        .count();
    if merchant_outputs > 1 {
        return Err(ExactReject::DuplicateMerchantOutput);
    }
    if outputs.len() > 2 {
        return Err(ExactReject::TooManyOutputs);
    }

    let pay = outputs
        .get(payment_output_index as usize)
        .ok_or(ExactReject::WrongRecipient)?;
    if pay.spk_version != 0 || pay.spk_script != pay_to_spk {
        return Err(ExactReject::WrongRecipient);
    }
    // Exact equality: the merchant gain is precisely the advertised amount.
    if pay.value < required_amount {
        return Err(ExactReject::Underpayment);
    }
    if pay.value > required_amount {
        return Err(ExactReject::Overpayment);
    }

    let outpoints = input_outpoints(&tx);
    if outpoints.is_empty() {
        return Err(ExactReject::NoInputs);
    }

    Ok(StdVerified {
        artifact_id: artifact_id(&tx),
        payer: payer.to_string(),
        payment_output_index,
        amount_paid: pay.value,
        input_outpoints: outpoints,
        tx,
    })
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
    let borrow_input_idx = match outpoints.iter().position(|o| o == &borrow_key) {
        Some(i) => i,
        None => return Err(ExactReject::WrongBorrowOutpoint),
    };

    // Parse outputs (lenient about the safe-json string-numeric encoding).
    let raw_outputs = tx
        .get("outputs")
        .and_then(|v| v.as_array())
        .ok_or(ExactReject::Malformed)?;
    let outputs: Vec<ObservedOutput> =
        raw_outputs.iter().filter_map(observed_output_lenient).collect();
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

    // Additive continuation: the SAME output the borrow input's own signature
    // script designates as `continuation_output_idx` must return >=
    // min_continuation to the merchant. This must check EXACTLY that index
    // (not "any output at the merchant's address"): `X402_BORROW_BODY` only
    // ever reads the sigscript-designated index on-chain (`Op2 OpPick`), so a
    // scan-all-outputs heuristic can be satisfied by an unrelated output that
    // coincidentally lands at the merchant's SPK with enough value -- e.g. the
    // payer's own change output in a self-pay setup -- even when the real
    // designated continuation is under threshold. Regression: found live,
    // documented in E2E_LIVE_RESULTS.md ("x402 KIP-10 exact CASE R2").
    let raw_inputs = tx.get("inputs").and_then(|v| v.as_array()).ok_or(ExactReject::Malformed)?;
    let sigscript_hex = raw_inputs
        .get(borrow_input_idx)
        .and_then(|i| i.get("signatureScript"))
        .and_then(|v| v.as_str())
        .ok_or(ExactReject::Malformed)?;
    let cont_idx = decode_continuation_index(sigscript_hex).ok_or(ExactReject::Malformed)? as usize;
    let has_continuation = match outputs.get(cont_idx) {
        Some(o) => o.spk_version == 0 && o.spk_script == pay_to_spk && o.value >= min_continuation,
        None => false,
    };
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
        rp.reserve("11".repeat(32), pay_to, amount, borrow_txid, 0, 100_000_000, 3000, 0, None)
            .unwrap()
    }

    /// Encoded tx spending `borrow_txid:0` (signature script designates
    /// output 1 as the continuation index, matching
    /// `build_x402_borrow_spend_sigscript(1, ..)` — push_index(1) = 0x51),
    /// paying `pay_amt` to `pay_to` at output 0, and returning `cont` to
    /// `pay_to` at output 1. `extra_outputs` are appended after (e.g. an
    /// incidental change output, for the self-pay false-positive regression
    /// test below).
    fn encoded_tx_ex(
        pay_to: &str,
        borrow_txid: &str,
        pay_amt: u64,
        cont: u64,
        extra_outputs: &[(String, u64)],
    ) -> String {
        let mut outputs = vec![
            serde_json::json!({ "value": pay_amt, "scriptPublicKey": { "version": 0, "script": spk_hex(pay_to) } }),
            serde_json::json!({ "value": cont, "scriptPublicKey": { "version": 0, "script": spk_hex(pay_to) } }),
        ];
        for (spk_addr, value) in extra_outputs {
            outputs.push(serde_json::json!({ "value": value, "scriptPublicKey": { "version": 0, "script": spk_hex(spk_addr) } }));
        }
        let tx = serde_json::json!({
            "transaction": {
                "version": 0,
                "inputs": [
                    { "previousOutpoint": { "transactionId": borrow_txid, "index": 0 }, "signatureScript": "51", "sequence": 0, "sigOpCount": 0 },
                    { "previousOutpoint": { "transactionId": "ff".repeat(32), "index": 0 }, "signatureScript": "41".to_string() + &"cd".repeat(65), "sequence": 0, "sigOpCount": 1 }
                ],
                "outputs": outputs,
                "lockTime": 0,
                "subnetworkId": "0000000000000000000000000000000000000000",
                "payload": ""
            }
        });
        serde_json::to_string(&tx).unwrap()
    }

    fn encoded_tx(pay_to: &str, borrow_txid: &str, pay_amt: u64, cont: u64) -> String {
        encoded_tx_ex(pay_to, borrow_txid, pay_amt, cont, &[])
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

    /// Regression for the live-found CASE R2 false-accept: in a self-pay
    /// setup (payer == merchant), the designated continuation (output 1) is
    /// genuinely under threshold, but an incidental extra output (e.g. the
    /// payer's own change, at output 2) coincidentally lands at the SAME
    /// merchant address with enough value. The old "scan all outputs"
    /// heuristic accepted this; checking only the sigscript-designated index
    /// must still reject it.
    #[test]
    fn rejects_under_threshold_continuation_despite_incidental_matching_change() {
        let merchant = testnet_addr(2); // self-pay: payer == merchant
        let bt = "aa".repeat(32);
        let t = terms(&merchant, 250, &bt);
        // designated continuation (output 1) is only 100M (< 100M + 3000)...
        let enc = encoded_tx_ex(
            &merchant,
            &bt,
            250,
            100_000_000,
            // ...but an unrelated change output at the SAME address easily
            // clears the threshold.
            &[(merchant.clone(), 500_000_000)],
        );
        assert_eq!(
            verify_exact_kip10(&enc, TX_ENCODING_SAFE_JSON, 0, None, &merchant, None, &t).unwrap_err(),
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

    // --- standard-native profile (alpha.8 default) ---

    /// Encoded plain v0 transfer: pays `pay` to `pay_to` at output 0, change
    /// to `change_to` at output 1. `string_numbers` emits values as decimal
    /// strings (the upstream safe-json encoding) instead of JSON numbers.
    fn encoded_std_tx(pay_to: &str, change_to: &str, pay: u64, change: u64, string_numbers: bool) -> String {
        let val = |v: u64| -> serde_json::Value {
            if string_numbers { serde_json::json!(v.to_string()) } else { serde_json::json!(v) }
        };
        let tx = serde_json::json!({
            "transaction": {
                "version": 0,
                "inputs": [
                    { "previousOutpoint": { "transactionId": "aa".repeat(32), "index": 0 }, "signatureScript": "41".to_string() + &"cd".repeat(65), "sequence": 0, "sigOpCount": 1 }
                ],
                "outputs": [
                    { "value": val(pay), "scriptPublicKey": { "version": 0, "script": spk_hex(pay_to) } },
                    { "value": val(change), "scriptPublicKey": { "version": 0, "script": spk_hex(change_to) } }
                ],
                "lockTime": 0,
                "subnetworkId": "0000000000000000000000000000000000000000",
                "payload": ""
            }
        });
        serde_json::to_string(&tx).unwrap()
    }

    #[test]
    fn standard_native_accepts_exact_payment() {
        let merchant = testnet_addr(2);
        let payer = testnet_addr(1);
        for string_numbers in [false, true] {
            let enc = encoded_std_tx(&merchant, &payer, 20_000_000, 5_000_000, string_numbers);
            let v = verify_exact_standard_native(&enc, TX_ENCODING_SAFE_JSON, 0, &payer, &merchant, 20_000_000)
                .unwrap_or_else(|e| panic!("string_numbers={}: {:?}", string_numbers, e));
            assert_eq!(v.amount_paid, 20_000_000);
            assert_eq!(v.payment_output_index, 0);
            assert_eq!(v.input_outpoints.len(), 1);
        }
    }

    #[test]
    fn standard_native_is_an_equality_not_a_floor() {
        let merchant = testnet_addr(2);
        let payer = testnet_addr(1);
        // Underpayment refused...
        let enc = encoded_std_tx(&merchant, &payer, 19_999_999, 5_000_000, false);
        assert_eq!(
            verify_exact_standard_native(&enc, TX_ENCODING_SAFE_JSON, 0, &payer, &merchant, 20_000_000).unwrap_err(),
            ExactReject::Underpayment
        );
        // ...and unlike the KOB-native binding, OVERPAYMENT is refused too
        // (upstream mutation vector `standardMerchantOverpayment`).
        let enc = encoded_std_tx(&merchant, &payer, 20_000_001, 5_000_000, false);
        assert_eq!(
            verify_exact_standard_native(&enc, TX_ENCODING_SAFE_JSON, 0, &payer, &merchant, 20_000_000).unwrap_err(),
            ExactReject::Overpayment
        );
    }

    #[test]
    fn standard_native_rejects_wrong_recipient_and_duplicate_merchant_output() {
        let merchant = testnet_addr(2);
        let payer = testnet_addr(1);
        let other = testnet_addr(9);
        // Pays `other` instead of the merchant.
        let enc = encoded_std_tx(&other, &payer, 20_000_000, 5_000_000, false);
        assert_eq!(
            verify_exact_standard_native(&enc, TX_ENCODING_SAFE_JSON, 0, &payer, &merchant, 20_000_000).unwrap_err(),
            ExactReject::WrongRecipient
        );
        // Both outputs pay the merchant (upstream mutation vector
        // `standardDuplicateMerchantOutput`).
        let enc = encoded_std_tx(&merchant, &merchant, 20_000_000, 5_000_000, false);
        assert_eq!(
            verify_exact_standard_native(&enc, TX_ENCODING_SAFE_JSON, 0, &payer, &merchant, 20_000_000).unwrap_err(),
            ExactReject::DuplicateMerchantOutput
        );
    }

    #[test]
    fn standard_native_rejects_wrong_version_and_nonempty_payload() {
        let merchant = testnet_addr(2);
        let payer = testnet_addr(1);
        let enc = encoded_std_tx(&merchant, &payer, 20_000_000, 5_000_000, false);

        let mut v1: serde_json::Value = serde_json::from_str(&enc).unwrap();
        v1["transaction"]["version"] = serde_json::json!(1);
        assert_eq!(
            verify_exact_standard_native(&v1.to_string(), TX_ENCODING_SAFE_JSON, 0, &payer, &merchant, 20_000_000).unwrap_err(),
            ExactReject::WrongVersion
        );

        // Request binding lives in the signed authorization for this profile;
        // a payload memo (upstream mutation vector `standardPayload`) is refused.
        let mut vp: serde_json::Value = serde_json::from_str(&enc).unwrap();
        vp["transaction"]["payload"] = serde_json::json!("ab");
        assert_eq!(
            verify_exact_standard_native(&vp.to_string(), TX_ENCODING_SAFE_JSON, 0, &payer, &merchant, 20_000_000).unwrap_err(),
            ExactReject::NonEmptyPayload
        );
    }

    #[test]
    fn standard_native_rejects_extra_outputs_and_bad_encoding() {
        let merchant = testnet_addr(2);
        let payer = testnet_addr(1);
        let enc = encoded_std_tx(&merchant, &payer, 20_000_000, 5_000_000, false);
        assert_eq!(
            verify_exact_standard_native(&enc, "base64", 0, &payer, &merchant, 20_000_000).unwrap_err(),
            ExactReject::BadEncoding
        );
        let mut v: serde_json::Value = serde_json::from_str(&enc).unwrap();
        v["transaction"]["outputs"].as_array_mut().unwrap().push(serde_json::json!(
            { "value": 1_000_000, "scriptPublicKey": { "version": 0, "script": spk_hex(&testnet_addr(9)) } }
        ));
        assert_eq!(
            verify_exact_standard_native(&v.to_string(), TX_ENCODING_SAFE_JSON, 0, &payer, &merchant, 20_000_000).unwrap_err(),
            ExactReject::TooManyOutputs
        );
    }
}
