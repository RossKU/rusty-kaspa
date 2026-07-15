//! Scheme (A): native-KAS "exact" verification (the pure, node-independent part).
//!
//! Given the signed transaction artifact and the `PaymentRequirements`, decide
//! whether the transaction is a well-formed native-KAS payment of at least the
//! required amount to the required recipient, bound to the required request
//! fingerprint. The on-chain checks (inputs unspent, actually broadcastable)
//! and settlement live in `facilitator.rs` because they need RPC.

use kob_settle::observe::{ObservedOutput, PaymentObserver};

use crate::fingerprint;
use crate::wire_v2::PaymentRequirements;

/// Successful pure-verification result for a native-KAS payment.
#[derive(Debug, Clone)]
pub struct NativeVerified {
    /// Deterministic replay key for this artifact (hash of the signed tx).
    pub artifact_id: String,
    /// Payer address (echoed from the payload `from`).
    pub payer: String,
    /// Index of the output paying `payTo`.
    pub pay_output_index: u32,
    /// Amount paid to `payTo` (sompi).
    pub amount_paid: u64,
    /// Consumed input outpoints ("txid:index").
    pub input_outpoints: Vec<String>,
    /// The normalized inner transaction object (kaspad tx shape), ready to be
    /// wrapped in a `submitTransaction` envelope for broadcast.
    pub tx: serde_json::Value,
}

/// Reason a native payment failed pure verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeReject {
    Malformed(String),
    WrongRecipient,
    Underpayment { required: u64, paid: u64 },
    CovenantNotAllowed,
    FingerprintMissing,
    FingerprintMismatch { expected: String, got: Option<String> },
    NoInputs,
}

impl std::fmt::Display for NativeReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NativeReject::Malformed(m) => write!(f, "malformed payment: {}", m),
            NativeReject::WrongRecipient => write!(f, "no output pays the required recipient"),
            NativeReject::Underpayment { required, paid } => {
                write!(f, "underpayment: required {} sompi, paid {}", required, paid)
            }
            NativeReject::CovenantNotAllowed => {
                write!(f, "native-KAS scheme does not allow covenant outputs")
            }
            NativeReject::FingerprintMissing => {
                write!(f, "transaction payload is missing the X402 request fingerprint")
            }
            NativeReject::FingerprintMismatch { expected, got } => write!(
                f,
                "fingerprint mismatch: expected {}, got {}",
                expected,
                got.as_deref().unwrap_or("<none>")
            ),
            NativeReject::NoInputs => write!(f, "transaction has no inputs"),
        }
    }
}

/// Pull the inner transaction object out of the payload's `transaction` field,
/// accepting either a `submitTransaction` envelope (`{ "transaction": {...} }`)
/// or a bare transaction object.
pub fn normalize_tx(transaction: &serde_json::Value) -> serde_json::Value {
    match transaction.get("transaction") {
        Some(inner) if inner.is_object() => inner.clone(),
        _ => transaction.clone(),
    }
}

/// Deterministic artifact id: `blake2b_256(compact_json(tx))`, hex. Stable
/// across identical artifacts (same signed tx -> same id), so it can key the
/// replay store before the tx is broadcast and its on-chain id is known.
pub fn artifact_id(tx: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(tx).unwrap_or_default();
    hex::encode(kob_settle::blake2b_256(&bytes))
}

/// Collect consumed input outpoints ("txid:index") from a tx object.
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

/// Verify a native-KAS "exact" payment against the requirements (pure checks).
///
/// `payer` is the payload `from` field; `transaction` is the payload
/// `transaction` field (envelope or bare).
pub fn verify_native_exact(
    transaction: &serde_json::Value,
    payer: &str,
    requirements: &PaymentRequirements,
) -> Result<NativeVerified, NativeReject> {
    let required = requirements
        .amount_sompi()
        .map_err(NativeReject::Malformed)?;

    let tx = normalize_tx(transaction);
    if !tx.is_object() {
        return Err(NativeReject::Malformed("transaction is not an object".into()));
    }

    // Parse outputs generically.
    let raw_outputs = tx
        .get("outputs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| NativeReject::Malformed("transaction has no outputs array".into()))?;
    let outputs: Vec<ObservedOutput> =
        raw_outputs.iter().filter_map(ObservedOutput::from_rpc_json).collect();
    if outputs.len() != raw_outputs.len() {
        return Err(NativeReject::Malformed("an output failed to parse".into()));
    }

    // Native scheme: no covenant outputs anywhere.
    if outputs.iter().any(|o| o.covenant_id.is_some())
        || raw_outputs.iter().any(|o| o.get("covenant").is_some())
    {
        return Err(NativeReject::CovenantNotAllowed);
    }

    // Match the paying output via the generic observer (SPK-based; covenant-blind).
    let mut observer = PaymentObserver::new();
    observer
        .watch(&requirements.pay_to)
        .map_err(|e| NativeReject::Malformed(format!("bad payTo address: {}", e)))?;
    let events = observer.scan_tx_outputs("artifact", &outputs);

    let best = events.iter().max_by_key(|e| e.value);
    let Some(paying) = best else {
        return Err(NativeReject::WrongRecipient);
    };
    if paying.value < required {
        return Err(NativeReject::Underpayment { required, paid: paying.value });
    }

    // Fingerprint binding: if the resource server issued one, the tx payload
    // must carry a matching X402 tag.
    if let Some(expected_fp) = requirements.fingerprint() {
        let payload_bytes = tx
            .get("payload")
            .and_then(|v| v.as_str())
            .and_then(|s| if s.is_empty() { Some(vec![]) } else { hex::decode(s).ok() })
            .unwrap_or_default();
        match fingerprint::extract_fingerprint(&payload_bytes) {
            None => return Err(NativeReject::FingerprintMissing),
            Some(got) if got != expected_fp => {
                return Err(NativeReject::FingerprintMismatch {
                    expected: expected_fp.to_string(),
                    got: Some(got),
                })
            }
            Some(_) => {}
        }
    }

    let outpoints = input_outpoints(&tx);
    if outpoints.is_empty() {
        return Err(NativeReject::NoInputs);
    }

    Ok(NativeVerified {
        artifact_id: artifact_id(&tx),
        payer: payer.to_string(),
        pay_output_index: paying.output_index,
        amount_paid: paying.value,
        input_outpoints: outpoints,
        tx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire_v2::{ASSET_KAS, BINDING_NATIVE, NETWORK_TESTNET10, SCHEME_EXACT};

    fn testnet_addr(seed: u8) -> String {
        let pk = [seed; 32];
        kob_settle::wallet::pubkey_to_address(&pk, kob_settle::types::Network::Testnet)
    }

    fn spk_hex(addr: &str) -> String {
        hex::encode(kob_settle::bech32::address_to_spk(addr).unwrap())
    }

    fn requirements(pay_to: &str, amount: u64, fp: Option<&str>) -> PaymentRequirements {
        let mut extra = serde_json::json!({ "binding": BINDING_NATIVE });
        if let Some(f) = fp {
            extra["fingerprint"] = serde_json::json!(f);
        }
        PaymentRequirements {
            scheme: SCHEME_EXACT.to_string(),
            network: NETWORK_TESTNET10.to_string(),
            amount: amount.to_string(),
            asset: ASSET_KAS.to_string(),
            pay_to: pay_to.to_string(),
            max_timeout_seconds: 60,
            extra,
        }
    }

    /// Build a signed-tx artifact paying `pay_to` `amount` sompi with `change`
    /// back to `from`, optionally embedding a fingerprint in the payload.
    fn artifact(from: &str, pay_to: &str, amount: u64, change: u64, fp: Option<&str>) -> serde_json::Value {
        let payload_hex = match fp {
            Some(f) => hex::encode(fingerprint::embed_fingerprint(f)),
            None => String::new(),
        };
        serde_json::json!({
            "transaction": {
                "version": 0,
                "inputs": [{
                    "previousOutpoint": { "transactionId": "aa".repeat(32), "index": 0 },
                    "signatureScript": "41".to_string() + &"cd".repeat(65),
                    "sequence": 0,
                    "sigOpCount": 1
                }],
                "outputs": [
                    { "value": amount, "scriptPublicKey": { "version": 0, "script": spk_hex(pay_to) } },
                    { "value": change, "scriptPublicKey": { "version": 0, "script": spk_hex(from) } }
                ],
                "lockTime": 0,
                "subnetworkId": "0000000000000000000000000000000000000000",
                "payload": payload_hex,
            }
        })
    }

    #[test]
    fn accepts_exact_payment_with_fingerprint() {
        let from = testnet_addr(1);
        let pay_to = testnet_addr(2);
        let fp = fingerprint::compute_fingerprint("GET", "/r", &pay_to, "100000000", "n");
        let art = artifact(&from, &pay_to, 100_000_000, 5_000_000, Some(&fp));
        let req = requirements(&pay_to, 100_000_000, Some(&fp));
        let v = verify_native_exact(&art["transaction"], &from, &req).unwrap();
        assert_eq!(v.amount_paid, 100_000_000);
        assert_eq!(v.pay_output_index, 0);
        assert_eq!(v.payer, from);
        assert_eq!(v.input_outpoints.len(), 1);
        assert_eq!(v.artifact_id.len(), 64);
    }

    #[test]
    fn overpayment_is_accepted() {
        let from = testnet_addr(1);
        let pay_to = testnet_addr(2);
        let art = artifact(&from, &pay_to, 150_000_000, 1_000_000, None);
        let req = requirements(&pay_to, 100_000_000, None);
        let v = verify_native_exact(&art["transaction"], &from, &req).unwrap();
        assert_eq!(v.amount_paid, 150_000_000);
    }

    #[test]
    fn rejects_underpayment() {
        let from = testnet_addr(1);
        let pay_to = testnet_addr(2);
        let art = artifact(&from, &pay_to, 99_999_999, 1_000_000, None);
        let req = requirements(&pay_to, 100_000_000, None);
        let err = verify_native_exact(&art["transaction"], &from, &req).unwrap_err();
        assert_eq!(err, NativeReject::Underpayment { required: 100_000_000, paid: 99_999_999 });
    }

    #[test]
    fn rejects_wrong_recipient() {
        let from = testnet_addr(1);
        let pay_to = testnet_addr(2);
        let wrong = testnet_addr(3);
        // Pays `wrong`, but requirements demand `pay_to`.
        let art = artifact(&from, &wrong, 100_000_000, 1_000_000, None);
        let req = requirements(&pay_to, 100_000_000, None);
        let err = verify_native_exact(&art["transaction"], &from, &req).unwrap_err();
        assert_eq!(err, NativeReject::WrongRecipient);
    }

    #[test]
    fn rejects_missing_fingerprint_when_required() {
        let from = testnet_addr(1);
        let pay_to = testnet_addr(2);
        let fp = fingerprint::compute_fingerprint("GET", "/r", &pay_to, "100000000", "n");
        let art = artifact(&from, &pay_to, 100_000_000, 1_000_000, None); // no fp embedded
        let req = requirements(&pay_to, 100_000_000, Some(&fp));
        let err = verify_native_exact(&art["transaction"], &from, &req).unwrap_err();
        assert_eq!(err, NativeReject::FingerprintMissing);
    }

    #[test]
    fn rejects_fingerprint_mismatch() {
        let from = testnet_addr(1);
        let pay_to = testnet_addr(2);
        let embedded = fingerprint::compute_fingerprint("GET", "/other", &pay_to, "100000000", "n");
        let expected = fingerprint::compute_fingerprint("GET", "/r", &pay_to, "100000000", "n");
        let art = artifact(&from, &pay_to, 100_000_000, 1_000_000, Some(&embedded));
        let req = requirements(&pay_to, 100_000_000, Some(&expected));
        let err = verify_native_exact(&art["transaction"], &from, &req).unwrap_err();
        assert!(matches!(err, NativeReject::FingerprintMismatch { .. }));
    }

    #[test]
    fn rejects_covenant_output() {
        let from = testnet_addr(1);
        let pay_to = testnet_addr(2);
        let mut art = artifact(&from, &pay_to, 100_000_000, 1_000_000, None);
        // Attach a covenant binding to the paying output.
        art["transaction"]["outputs"][0]["covenant"] =
            serde_json::json!({ "authorizingInput": 0, "covenantId": "ab".repeat(32) });
        let req = requirements(&pay_to, 100_000_000, None);
        let err = verify_native_exact(&art["transaction"], &from, &req).unwrap_err();
        assert_eq!(err, NativeReject::CovenantNotAllowed);
    }

    #[test]
    fn artifact_id_is_deterministic() {
        let from = testnet_addr(1);
        let pay_to = testnet_addr(2);
        let art = artifact(&from, &pay_to, 100_000_000, 1_000_000, None);
        let tx = normalize_tx(&art["transaction"]);
        assert_eq!(artifact_id(&tx), artifact_id(&tx));
    }

    #[test]
    fn accepts_bare_tx_object_not_only_envelope() {
        let from = testnet_addr(1);
        let pay_to = testnet_addr(2);
        let art = artifact(&from, &pay_to, 100_000_000, 1_000_000, None);
        // Pass the inner tx object directly (no envelope).
        let bare = art["transaction"].clone();
        let req = requirements(&pay_to, 100_000_000, None);
        let v = verify_native_exact(&bare, &from, &req).unwrap();
        assert_eq!(v.amount_paid, 100_000_000);
    }
}
