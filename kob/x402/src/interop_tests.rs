//! Interop tests against the vendored upstream alpha.8 vectors
//! (elldeeone/kaspa-x402 @ 0345cbd7b8d26520b4dffe0fcc94d127acd1fcb0, vendored
//! under `kob/x402/interop/vectors/`).
//!
//! Coverage note, updated 2026-07-20: upstream PR#3 (merged 07-19, released in
//! alpha.9) shipped the preimage bytes the earlier note said were missing, as
//! `vectors/exact/interop-v1.json` (vendored alongside the alpha.8 vectors).
//! Both gaps that note described are now addressable:
//!
//! - **Authorization digest — DONE.** The vector publishes both canonical JSON
//!   preimages, both SHA-256 results, the signer key and a valid signature.
//!   [`crate::exact_authorization`] implements them and is tested against it
//!   byte-for-byte; the facilitator now recomputes the digest and Schnorr-
//!   verifies the signature instead of only checking their shapes.
//! - **Transaction id — DONE.** The vector publishes the identifier pre-images
//!   for both profiles (version 0's keyed-BLAKE2b pre-image, and version 1's
//!   payload/rest/id BLAKE3 stages). [`crate::transaction_id`] implements the
//!   canonical serialization and both constructions, tested against them
//!   byte-for-byte; the facilitator recomputes the id rather than reading the
//!   artifact's own `id`, and refuses an artifact whose self-declared id
//!   disagrees with its contents.
//!
//! The tests below still cross-check the STRUCTURAL and accounting fields of
//! the alpha.8 vectors.

use crate::scheme_exact;
use crate::wire_v2::{
    decode_header, encode_header, errors, PaymentPayload, PaymentRequired, SettlementResponse,
    AUTHORIZATION_VERSION, BINDING_EXACT, PROFILE_ADDITIVE, PROFILE_STANDARD_NATIVE,
    TEMPLATE_KIP10_ADDITIVE, TX_ENCODING_SAFE_JSON,
};

const CONSENSUS_PROFILES: &str = include_str!("../interop/vectors/exact/consensus-profiles.json");
const HTTP_EXACT_TRANSACTION: &str =
    include_str!("../interop/vectors/x402-http/exact-transaction.json");
const SETTLEMENT_FAILURE: &str =
    include_str!("../interop/vectors/settlement-response/failure.json");

fn consensus() -> serde_json::Value {
    serde_json::from_str(CONSENSUS_PROFILES).unwrap()
}

fn sum_str(values: impl Iterator<Item = serde_json::Value>) -> u64 {
    values
        .map(|v| v.as_str().and_then(|s| s.parse::<u64>().ok()).or_else(|| v.as_u64()).unwrap())
        .sum()
}

/// Output value, tolerant of both spellings (`value` in the KOB/http-vector
/// shape, `amount` in the consensus-vector shape) and both JSON types.
fn out_value(o: &serde_json::Value) -> serde_json::Value {
    if o.get("value").is_some() { o["value"].clone() } else { o["amount"].clone() }
}

fn tx_output_sum(tx: &serde_json::Value) -> u64 {
    sum_str(tx["outputs"].as_array().unwrap().iter().map(out_value))
}

fn tx_input_utxo_sum(tx: &serde_json::Value) -> u64 {
    sum_str(tx["inputs"].as_array().unwrap().iter().map(|i| i["utxo"]["amount"].clone()))
}

fn assert_hash32(s: &str) {
    assert!(s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()), "not 32-byte hex: {}", s);
}

/// Merchant address recovered from a flat serialized SPK (`0000` + script hex).
fn addr_of_flat_spk(flat: &str) -> String {
    assert!(flat.starts_with("0000"), "vector SPK not version 0: {}", flat);
    let script = hex::decode(&flat[4..]).unwrap();
    kob_settle::bech32::spk_to_address(&script, "kaspatest").unwrap()
}

#[test]
fn consensus_vector_metadata_is_the_profile_split() {
    let v = consensus();
    assert_eq!(v["kind"], "exact-consensus-profiles");
    assert_eq!(v["validation"]["status"], "full-consensus-cross-validated");
    assert_eq!(v["expected"]["standardNative"]["profile"], PROFILE_STANDARD_NATIVE);
    assert_eq!(v["expected"]["additive"]["profile"], PROFILE_ADDITIVE);
    // Profile canon: standard-native is a v0 tx, additive is a v1 tx.
    assert_eq!(v["expected"]["standardNative"]["version"], 0);
    assert_eq!(v["expected"]["additive"]["version"], 1);
    // The mutation ledger distinguishes consensus rejections from
    // profile-layer rejections; the profile-layer ones are exactly the rules
    // our wire verifier enforces (exact equality, single merchant output,
    // empty payload).
    let m = &v["expected"]["mutations"];
    for k in ["standardMerchantOverpayment", "standardExcessiveFee"] {
        assert_eq!(m[k], "profile-rejected", "{}", k);
    }
    for k in ["standardDuplicateMerchantOutput", "standardPayload", "additiveExcessiveDelta"] {
        assert_eq!(m[k], "profile-rejected-after-consensus-acceptance", "{}", k);
    }
}

#[test]
fn consensus_vector_standard_native_passes_the_wire_verifier() {
    let v = consensus();
    let std = &v["expected"]["standardNative"];
    let tx = &std["transaction"];
    let amount: u64 = std["amount"].as_str().unwrap().parse().unwrap();
    let fee: u64 = std["fee"].as_str().unwrap().parse().unwrap();

    // The upstream consensus tx (safe-json field shapes: string values, flat
    // SPKs, `txid` outpoint key) must pass KOB's standard-native verifier.
    let merchant = addr_of_flat_spk(tx["outputs"][0]["scriptPublicKey"].as_str().unwrap());
    let enc = serde_json::to_string(tx).unwrap();
    let ver = scheme_exact::verify_exact_standard_native(
        &enc, TX_ENCODING_SAFE_JSON, 0, "kaspatest:payer", &merchant, amount,
    )
    .expect("upstream standard-native consensus tx must verify");
    assert_eq!(ver.amount_paid, amount);
    assert_eq!(ver.input_outpoints.len() as u64, std["inputs"].as_u64().unwrap());
    assert_eq!(tx["outputs"].as_array().unwrap().len() as u64, std["outputs"].as_u64().unwrap());

    // Accounting cross-check: inputs = outputs + fee (from embedded UTXO hints).
    assert_eq!(tx_input_utxo_sum(tx), tx_output_sum(tx) + fee);

    // Expected ids are well-formed, but NOT recomputable from this vector:
    // upstream publishes no byte-level serialization preimages (see module
    // note); KOB's stack has no independent consensus serializer to validate
    // against without them.
    assert_hash32(std["transactionId"].as_str().unwrap());
    assert_hash32(std["transactionHash"].as_str().unwrap());
}

#[test]
fn consensus_vector_additive_is_an_exact_successor_delta() {
    let v = consensus();
    let add = &v["expected"]["additive"];
    let tx = &add["transaction"];
    let amount: u64 = add["amount"].as_str().unwrap().parse().unwrap();
    let fee: u64 = add["fee"].as_str().unwrap().parse().unwrap();

    // Upstream additive canon (v1 tx): the head input at index 0 recreates
    // the SAME script at output 0 with value = headAmount + amount — no
    // separate merchant output. KOB's additive covenant template differs
    // (separate merchant payment output + continuation), so this transaction
    // is cross-checked structurally rather than through verify_exact_kip10.
    assert_eq!(tx["version"], 1);
    let inputs = tx["inputs"].as_array().unwrap();
    let outputs = tx["outputs"].as_array().unwrap();
    assert_eq!(inputs.len(), 2);
    assert_eq!(outputs.len(), 2);
    let head_spk = inputs[0]["utxo"]["scriptPublicKey"].as_str().unwrap();
    assert_eq!(outputs[0]["scriptPublicKey"].as_str().unwrap(), head_spk, "same-script successor");
    let head_amount: u64 = inputs[0]["utxo"]["amount"].as_str().unwrap().parse().unwrap();
    let successor: u64 = out_value(&outputs[0]).as_str().unwrap().parse().unwrap();
    assert_eq!(successor, head_amount + amount, "successor delta is EXACTLY the advertised amount");
    // Funding conservation: payer input covers amount + fee + change.
    assert_eq!(tx_input_utxo_sum(tx), tx_output_sum(tx) + fee);
    assert_hash32(add["transactionId"].as_str().unwrap());
    assert_hash32(add["transactionHash"].as_str().unwrap());
}

#[test]
fn http_vector_decodes_through_the_wire_structs() {
    let v: serde_json::Value = serde_json::from_str(HTTP_EXACT_TRANSACTION).unwrap();

    // PAYMENT-REQUIRED header -> PaymentRequired.
    let pr: PaymentRequired =
        decode_header(v["headers"]["paymentRequired"].as_str().unwrap()).unwrap();
    assert_eq!(pr.x402_version, 2);
    let req = &pr.accepts[0];
    assert_eq!(req.binding(), Some(BINDING_EXACT));
    assert_eq!(req.profile(), Some(PROFILE_ADDITIVE));
    assert_eq!(req.template_id(), Some(TEMPLATE_KIP10_ADDITIVE));
    assert_eq!(req.head_version(), Some("0"));
    assert_eq!(req.head_amount_sompi(), Some(100_000_000));
    assert_eq!(req.additive_threshold_sompi(), Some(10_000_000));
    assert_eq!(req.payment_output_index(), Some(0));
    let head = req.expected_head_outpoint().unwrap();
    assert_eq!(head.txid, "71".repeat(32));
    assert_eq!(head.index, 0);
    assert_eq!(req.challenge_id(), Some("91".repeat(32)).as_deref());
    assert!(req.pay_to_script_public_key().unwrap().starts_with("0000aa20"), "head P2SH payTo");
    // The alpha.7 vocabulary is gone from the upstream offer.
    for k in ["borrowOutpoint", "borrowAmount", "reservationId"] {
        assert!(req.extra.get(k).is_none(), "{} in upstream alpha.8 offer", k);
    }

    // PAYMENT-SIGNATURE header -> PaymentPayload (+ typed ExactPayload).
    let pp: PaymentPayload =
        decode_header(v["headers"]["paymentSignature"].as_str().unwrap()).unwrap();
    assert_eq!(pp.x402_version, 2);
    assert_eq!(pp.profile(), Some(PROFILE_ADDITIVE));
    assert_eq!(pp.challenge_id(), pp.accepted.challenge_id());
    assert_eq!(pp.request_hash(), Some("99".repeat(32)).as_deref());
    let auth = pp.authorization().expect("alpha.8 payload carries the request authorization");
    assert_eq!(auth.version, AUTHORIZATION_VERSION);
    assert_eq!(auth.input_index, 1, "the P2PK funding input authorizes, never the head input");
    assert_hash32(&auth.digest);
    assert_eq!(auth.signature.len(), 128);
    let typed: crate::wire_v2::ExactPayload = serde_json::from_value(pp.payload.clone()).unwrap();
    assert_eq!(typed.kind, "exact-transaction");
    assert_eq!(typed.transaction_encoding, TX_ENCODING_SAFE_JSON);
    assert_eq!(typed.payment_output_index, 0);

    // The embedded safe-json transaction parses, and its successor output
    // matches the offer's head terms (structural cross-check; KOB's covenant
    // template differs from upstream's, see consensus test above).
    let tx: serde_json::Value = serde_json::from_str(&typed.transaction).unwrap();
    let successor: u64 = tx["outputs"][0]["value"].as_str().unwrap().parse().unwrap();
    let amount: u64 = pp.accepted.amount.parse().unwrap();
    assert_eq!(successor, req.head_amount_sompi().unwrap() + amount);
    assert_eq!(
        tx["inputs"][0]["previousOutpoint"]["transactionId"].as_str().unwrap(),
        head.txid
    );

    // PAYMENT-RESPONSE header -> SettlementResponse, losslessly (every field
    // upstream emits is typed on our struct — nothing silently dropped).
    let sr: SettlementResponse =
        decode_header(v["headers"]["paymentResponse"].as_str().unwrap()).unwrap();
    assert!(sr.success);
    assert_eq!(sr.transaction, v["settlementResponse"]["transaction"].as_str().unwrap());
    let ext = sr.extensions.as_ref().unwrap().kaspa.clone();
    assert_eq!(ext.exact_profile.as_deref(), Some(PROFILE_ADDITIVE));
    assert_eq!(ext.template_id.as_deref(), Some(TEMPLATE_KIP10_ADDITIVE));
    assert_eq!(ext.head_version.as_deref(), Some("0"));
    assert_eq!(ext.head_outpoint.as_ref().map(|o| o.txid.as_str()), Some(head.txid.as_str()));
    assert_eq!(serde_json::to_value(&sr).unwrap(), v["settlementResponse"]);

    // And our encoder reproduces the upstream response header byte-for-byte
    // modulo key order: decode(encode(x)) == x.
    let re: SettlementResponse = decode_header(&encode_header(&sr).unwrap()).unwrap();
    assert_eq!(serde_json::to_value(&re).unwrap(), v["settlementResponse"]);
}

#[test]
fn settlement_failure_vector_uses_the_closed_error_enum() {
    let v: serde_json::Value = serde_json::from_str(SETTLEMENT_FAILURE).unwrap();
    let sr: SettlementResponse = serde_json::from_value(v["response"].clone()).unwrap();
    assert!(!sr.success);
    assert_eq!(sr.transaction, "");
    let reason = sr.error_reason.as_deref().unwrap();
    assert!(
        [
            errors::INVALID_X402_VERSION,
            errors::INVALID_SCHEME,
            errors::INVALID_NETWORK,
            errors::INVALID_PAYMENT_REQUIREMENTS,
            errors::INVALID_PAYLOAD,
            errors::INVALID_TRANSACTION_STATE,
            errors::UNSUPPORTED_SCHEME,
            errors::UNEXPECTED_SETTLE_ERROR,
        ]
        .contains(&reason),
        "errorReason {} outside the closed enum",
        reason
    );
}
