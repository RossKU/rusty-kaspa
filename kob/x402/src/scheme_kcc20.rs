//! Scheme (B): KCC20 covenant `token_unit` transfer as an "exact" payment
//! (the pure, node-independent part).
//!
//! A KCC20 payment moves token value by spending the payer's `token_unit`
//! covenant UTXO and creating a new `token_unit` covenant output owned by the
//! recipient. Per the KCC20 Standard State Header spec, the token `amount` is
//! the output's native sompi value, and the owner is encoded in the
//! covenant's redeem script (P2SH). So the "output that pays the recipient"
//! is the one whose scriptPublicKey is `P2SH(token_unit_redeem_script(
//! recipient_pubkey))` AND that carries a covenant binding to the token's
//! covenant id (`asset`). Reuses the KCC20 builders in `kob-core`.

use kob_settle::observe::ObservedOutput;

use crate::fingerprint;
use crate::wire_v2::PaymentRequirements;

/// Successful pure-verification result for a KCC20 token payment.
#[derive(Debug, Clone)]
pub struct Kcc20Verified {
    pub artifact_id: String,
    /// Payer identity address (P2PK), echoed from payload `from`.
    pub payer: String,
    /// Index of the token_unit output paying the recipient.
    pub pay_output_index: u32,
    /// Token amount paid (== output native sompi value).
    pub amount_paid: u64,
    /// Consumed input outpoints.
    pub input_outpoints: Vec<String>,
    /// Token covenant id (hex) this payment is denominated in.
    pub asset: String,
    /// The payer's own `token_unit` P2SH address for `asset` — the address
    /// whose UTXO set must contain the spent token input on-chain.
    pub payer_token_address: String,
    /// The recipient's `token_unit` P2SH address — where the payment output
    /// lives on-chain (this is what finality confirmation must poll, NOT the
    /// recipient's P2PK identity address).
    pub recipient_token_address: String,
    /// Normalized inner transaction object, ready to broadcast.
    pub tx: serde_json::Value,
}

/// Reason a KCC20 payment failed pure verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kcc20Reject {
    Malformed(String),
    BadAsset(String),
    BadRecipient(String),
    BadPayer(String),
    WrongRecipient,
    Underpayment { required: u64, paid: u64 },
    MissingCovenantBinding,
    FingerprintMissing,
    FingerprintMismatch { expected: String, got: Option<String> },
    NoInputs,
}

impl std::fmt::Display for Kcc20Reject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Kcc20Reject::Malformed(m) => write!(f, "malformed payment: {}", m),
            Kcc20Reject::BadAsset(m) => write!(f, "bad token asset: {}", m),
            Kcc20Reject::BadRecipient(m) => write!(f, "bad recipient: {}", m),
            Kcc20Reject::BadPayer(m) => write!(f, "bad payer: {}", m),
            Kcc20Reject::WrongRecipient => {
                write!(f, "no token_unit output pays the required recipient for this asset")
            }
            Kcc20Reject::Underpayment { required, paid } => {
                write!(f, "underpayment: required {} token units, paid {}", required, paid)
            }
            Kcc20Reject::MissingCovenantBinding => {
                write!(f, "recipient output is missing the token covenant binding")
            }
            Kcc20Reject::FingerprintMissing => {
                write!(f, "transaction payload is missing the X402 request fingerprint")
            }
            Kcc20Reject::FingerprintMismatch { expected, got } => write!(
                f,
                "fingerprint mismatch: expected {}, got {}",
                expected,
                got.as_deref().unwrap_or("<none>")
            ),
            Kcc20Reject::NoInputs => write!(f, "transaction has no inputs"),
        }
    }
}

/// Extract the 32-byte Schnorr pubkey from a Kaspa P2PK address.
fn pubkey_from_p2pk(addr: &str) -> Result<[u8; 32], String> {
    let spk = kob_settle::bech32::address_to_spk(addr).map_err(|e| e.to_string())?;
    if spk.len() == 34 && spk[0] == 0x20 && spk[33] == 0xac {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&spk[1..33]);
        Ok(pk)
    } else {
        Err(format!("address {} is not a P2PK identity address", addr))
    }
}

/// The `token_unit` P2SH scriptPublicKey bytes (35B, version 0) for `pubkey`.
fn token_unit_p2sh_script(pubkey: &[u8; 32]) -> Vec<u8> {
    let rs = kob_core::build_token_unit_redeem_script(pubkey);
    kob_settle::build_p2sh(&rs).script().to_vec()
}

/// The `token_unit` P2SH address for `pubkey` on the given network.
fn token_unit_address(pubkey: &[u8; 32], network: kob_settle::types::Network) -> Result<String, String> {
    let spk = token_unit_p2sh_script(pubkey);
    kob_settle::bech32::spk_to_address(&spk, network.address_prefix()).map_err(|e| e.to_string())
}

/// Detect the network from an address prefix.
fn network_of(addr: &str) -> kob_settle::types::Network {
    if addr.starts_with("kaspatest") || addr.starts_with("kaspadev") || addr.starts_with("kaspasim") {
        kob_settle::types::Network::Testnet
    } else {
        kob_settle::types::Network::Mainnet
    }
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

/// Verify a KCC20 `token_unit` "exact" payment against the requirements
/// (pure checks). `payer` is the payload `from`; `transaction` is the payload
/// `transaction` (envelope or bare).
pub fn verify_kcc20_exact(
    transaction: &serde_json::Value,
    payer: &str,
    requirements: &PaymentRequirements,
) -> Result<Kcc20Verified, Kcc20Reject> {
    let required = requirements.amount_sompi().map_err(Kcc20Reject::Malformed)?;

    // Token covenant id (KOB KCC20 binding) lives in extra.assetId.
    let asset = requirements.kcc20_covenant_id().unwrap_or_default().to_lowercase();
    if asset.len() != 64 || hex::decode(&asset).map(|b| b.len() != 32).unwrap_or(true) {
        return Err(Kcc20Reject::BadAsset(format!(
            "extra.assetId must be a 32-byte covenant id (hex), got '{}'",
            asset
        )));
    }

    let recipient_pk =
        pubkey_from_p2pk(&requirements.pay_to).map_err(Kcc20Reject::BadRecipient)?;
    let payer_pk = pubkey_from_p2pk(payer).map_err(Kcc20Reject::BadPayer)?;

    let tx = crate::scheme_native::normalize_tx(transaction);
    if !tx.is_object() {
        return Err(Kcc20Reject::Malformed("transaction is not an object".into()));
    }

    let raw_outputs = tx
        .get("outputs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| Kcc20Reject::Malformed("transaction has no outputs array".into()))?;

    let expected_spk = token_unit_p2sh_script(&recipient_pk);

    // Find the token_unit output paying the recipient: SPK == recipient's
    // token P2SH AND carrying the token's covenant binding.
    let mut recipient_output: Option<(u32, u64, bool)> = None; // (idx, value, has_covenant)
    for (idx, raw) in raw_outputs.iter().enumerate() {
        let Some(out) = ObservedOutput::from_rpc_json(raw) else {
            return Err(Kcc20Reject::Malformed(format!("output {} failed to parse", idx)));
        };
        if out.spk_version == 0 && out.spk_script == expected_spk {
            let has_cov = out.covenant_id.as_deref() == Some(asset.as_str());
            // Prefer the highest-value matching output.
            match recipient_output {
                Some((_, v, _)) if v >= out.value => {}
                _ => recipient_output = Some((idx as u32, out.value, has_cov)),
            }
        }
    }

    let Some((pay_idx, paid, has_cov)) = recipient_output else {
        return Err(Kcc20Reject::WrongRecipient);
    };
    if !has_cov {
        return Err(Kcc20Reject::MissingCovenantBinding);
    }
    if paid < required {
        return Err(Kcc20Reject::Underpayment { required, paid });
    }

    // Fingerprint binding (identical to native scheme).
    if let Some(expected_fp) = requirements.fingerprint() {
        let payload_bytes = tx
            .get("payload")
            .and_then(|v| v.as_str())
            .and_then(|s| if s.is_empty() { Some(vec![]) } else { hex::decode(s).ok() })
            .unwrap_or_default();
        match fingerprint::extract_fingerprint(&payload_bytes) {
            None => return Err(Kcc20Reject::FingerprintMissing),
            Some(got) if got != expected_fp => {
                return Err(Kcc20Reject::FingerprintMismatch {
                    expected: expected_fp.to_string(),
                    got: Some(got),
                })
            }
            Some(_) => {}
        }
    }

    let outpoints = input_outpoints(&tx);
    if outpoints.is_empty() {
        return Err(Kcc20Reject::NoInputs);
    }

    let payer_token_address =
        token_unit_address(&payer_pk, network_of(payer)).map_err(Kcc20Reject::BadPayer)?;
    let recipient_token_address =
        token_unit_address(&recipient_pk, network_of(&requirements.pay_to)).map_err(Kcc20Reject::BadRecipient)?;

    Ok(Kcc20Verified {
        artifact_id: crate::scheme_native::artifact_id(&tx),
        payer: payer.to_string(),
        pay_output_index: pay_idx,
        amount_paid: paid,
        input_outpoints: outpoints,
        asset,
        payer_token_address,
        recipient_token_address,
        tx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire_v2::{ASSET_KAS, BINDING_KCC20, NETWORK_TESTNET10, SCHEME_EXACT};

    fn testnet_addr(seed: u8) -> String {
        kob_settle::wallet::pubkey_to_address(&[seed; 32], kob_settle::types::Network::Testnet)
    }
    fn pk(seed: u8) -> [u8; 32] {
        [seed; 32]
    }
    fn token_spk_hex(pubkey: &[u8; 32]) -> String {
        hex::encode(token_unit_p2sh_script(pubkey))
    }

    fn requirements(pay_to: &str, asset: &str, amount: u64, fp: Option<&str>) -> PaymentRequirements {
        let mut extra = serde_json::json!({ "binding": BINDING_KCC20, "assetId": asset });
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
            additional: Default::default(),
        }
    }

    /// Build a token_unit transfer artifact: spends payer's token UTXO,
    /// creates a recipient token_unit output of `amount` bound to `asset`.
    fn artifact(
        recipient_pk: &[u8; 32],
        asset: &str,
        amount: u64,
        with_covenant: bool,
        fp: Option<&str>,
    ) -> serde_json::Value {
        let payload_hex = match fp {
            Some(f) => hex::encode(fingerprint::embed_fingerprint(f)),
            None => String::new(),
        };
        let mut out = serde_json::json!({
            "value": amount,
            "scriptPublicKey": { "version": 0, "script": token_spk_hex(recipient_pk) }
        });
        if with_covenant {
            out["covenant"] = serde_json::json!({ "authorizingInput": 0, "covenantId": asset });
        }
        serde_json::json!({
            "transaction": {
                "version": 1,
                "inputs": [{
                    "previousOutpoint": { "transactionId": "aa".repeat(32), "index": 0 },
                    "signatureScript": "cd".repeat(70),
                    "sequence": 0,
                    "sigOpCount": 1
                }],
                "outputs": [ out ],
                "lockTime": 0,
                "subnetworkId": "0000000000000000000000000000000000000000",
                "payload": payload_hex,
            }
        })
    }

    #[test]
    fn accepts_token_payment_with_covenant() {
        let payer = testnet_addr(1);
        let recipient = testnet_addr(2);
        let asset = "ab".repeat(32);
        let art = artifact(&pk(2), &asset, 50_000_000, true, None);
        let req = requirements(&recipient, &asset, 50_000_000, None);
        let v = verify_kcc20_exact(&art["transaction"], &payer, &req).unwrap();
        assert_eq!(v.amount_paid, 50_000_000);
        assert_eq!(v.pay_output_index, 0);
        assert_eq!(v.asset, asset);
        assert!(v.payer_token_address.starts_with("kaspatest:"));
    }

    #[test]
    fn rejects_missing_covenant_binding() {
        let payer = testnet_addr(1);
        let recipient = testnet_addr(2);
        let asset = "ab".repeat(32);
        // Output goes to the right token P2SH but WITHOUT the covenant binding.
        let art = artifact(&pk(2), &asset, 50_000_000, false, None);
        let req = requirements(&recipient, &asset, 50_000_000, None);
        let err = verify_kcc20_exact(&art["transaction"], &payer, &req).unwrap_err();
        assert_eq!(err, Kcc20Reject::MissingCovenantBinding);
    }

    #[test]
    fn rejects_wrong_recipient() {
        let payer = testnet_addr(1);
        let recipient = testnet_addr(2);
        let asset = "ab".repeat(32);
        // Output pays a DIFFERENT recipient's token address.
        let art = artifact(&pk(7), &asset, 50_000_000, true, None);
        let req = requirements(&recipient, &asset, 50_000_000, None);
        let err = verify_kcc20_exact(&art["transaction"], &payer, &req).unwrap_err();
        assert_eq!(err, Kcc20Reject::WrongRecipient);
    }

    #[test]
    fn rejects_underpayment() {
        let payer = testnet_addr(1);
        let recipient = testnet_addr(2);
        let asset = "ab".repeat(32);
        let art = artifact(&pk(2), &asset, 49_999_999, true, None);
        let req = requirements(&recipient, &asset, 50_000_000, None);
        let err = verify_kcc20_exact(&art["transaction"], &payer, &req).unwrap_err();
        assert_eq!(err, Kcc20Reject::Underpayment { required: 50_000_000, paid: 49_999_999 });
    }

    #[test]
    fn rejects_wrong_asset_binding() {
        let payer = testnet_addr(1);
        let recipient = testnet_addr(2);
        let asset = "ab".repeat(32);
        let other_asset = "cd".repeat(32);
        // Covenant binds a DIFFERENT asset than requirements demand.
        let art = artifact(&pk(2), &other_asset, 50_000_000, true, None);
        let req = requirements(&recipient, &asset, 50_000_000, None);
        let err = verify_kcc20_exact(&art["transaction"], &payer, &req).unwrap_err();
        assert_eq!(err, Kcc20Reject::MissingCovenantBinding);
    }

    #[test]
    fn rejects_bad_asset() {
        let payer = testnet_addr(1);
        let recipient = testnet_addr(2);
        let art = artifact(&pk(2), "ab".repeat(32).as_str(), 50_000_000, true, None);
        let req = requirements(&recipient, "not-hex", 50_000_000, None);
        let err = verify_kcc20_exact(&art["transaction"], &payer, &req).unwrap_err();
        assert!(matches!(err, Kcc20Reject::BadAsset(_)));
    }

    #[test]
    fn enforces_fingerprint_binding() {
        let payer = testnet_addr(1);
        let recipient = testnet_addr(2);
        let asset = "ab".repeat(32);
        let fp = fingerprint::compute_fingerprint("GET", "/r", &recipient, "50000000", "n");
        let art = artifact(&pk(2), &asset, 50_000_000, true, Some(&fp));
        let req = requirements(&recipient, &asset, 50_000_000, Some(&fp));
        assert!(verify_kcc20_exact(&art["transaction"], &payer, &req).is_ok());

        // Missing fingerprint when required -> reject.
        let art2 = artifact(&pk(2), &asset, 50_000_000, true, None);
        let err = verify_kcc20_exact(&art2["transaction"], &payer, &req).unwrap_err();
        assert_eq!(err, Kcc20Reject::FingerprintMissing);
    }
}
