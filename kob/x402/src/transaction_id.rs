//! Independent recomputation of the canonical Kaspa transaction id from an
//! exact-v2 safe-JSON artifact (`spec/kaspa-exact-v2.md`, "Version 0/1
//! transaction id").
//!
//! # Why this exists
//!
//! The authorization digest binds `transactionId`, and the spec is explicit
//! that the verifier MUST derive it from the canonical transaction: "A separate
//! client-authoritative transaction id is forbidden. If the interchange format
//! includes a convenience `id`, it MUST equal the independently recomputed
//! identifier." Until upstream PR#3 (merged 2026-07-19, alpha.9) published the
//! byte-level pre-images, an independent stack could not do that; the vendored
//! `interop/vectors/exact/interop-v1.json` now ships them for both profiles and
//! the tests below check this module against them byte-for-byte.
//!
//! # The two algorithms
//!
//! - **version 0** (`standard-native`): one pre-image, hashed with BLAKE2b-256
//!   keyed by the UTF-8 bytes `TransactionID`. Signature scripts, sigop counts
//!   and storage mass are excluded (the sig scripts are serialized as empty
//!   byte strings, which is what makes the id stable while a transaction is
//!   still being signed).
//! - **version 1** (`additive`): a three-stage BLAKE3 construction --
//!   `payloadDigest` over the raw payload, `restDigest` over the same
//!   serialization with signature scripts and payload emptied and compute
//!   budgets / storage mass omitted, then the id over their 64-byte
//!   concatenation. Each stage is keyed with its ASCII domain copied into a
//!   zero-filled 32-byte key. Version-1 outputs additionally carry a
//!   covenant-presence byte.
//!
//! Integers are unsigned little-endian; a variable byte string is
//! `u64(length) || bytes`; `scriptPublicKey` arrives as the two-byte
//! BIG-endian script version followed by the script bytes, and that version is
//! re-emitted little-endian like every other integer.

use crate::wire_v2::TX_ENCODING_SAFE_JSON;

/// Anything that makes an artifact non-projectable onto the consensus
/// transaction. Callers treat all of these the same (`invalid_payload`); the
/// variants exist so a rejection can be logged precisely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxIdError {
    /// Not the safe-JSON encoding this binding requires.
    UnsupportedEncoding,
    /// The artifact is not a JSON object, or a required field is missing.
    Malformed(&'static str),
    /// A field is present but not in its consensus domain (bad hex, a uint64
    /// that is not a canonical decimal string, an out-of-range version).
    BadField(&'static str),
    /// Only transaction versions 0 and 1 have a defined identifier here.
    UnsupportedVersion(u64),
    /// The artifact carries a convenience `id` that disagrees with the
    /// independently recomputed identifier. The spec forbids trusting it, so
    /// this is a hard rejection rather than a silent preference for ours.
    IdMismatch { claimed: String, computed: String },
}

/// BLAKE3 keyed with an ASCII domain copied into a zero-filled 32-byte key.
fn blake3_domain(domain: &str, data: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    let bytes = domain.as_bytes();
    debug_assert!(bytes.len() <= 32, "domain must fit the 32-byte key");
    key[..bytes.len()].copy_from_slice(bytes);
    let mut hasher = blake3::Hasher::new_keyed(&key);
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// A uint64 that travels as a canonical decimal STRING (values, sequences,
/// gas, lock time), tolerating the JSON-number spelling some producers emit.
fn u64_field(value: Option<&serde_json::Value>, field: &'static str) -> Result<u64, TxIdError> {
    match value {
        None => Ok(0),
        Some(serde_json::Value::Null) => Ok(0),
        Some(serde_json::Value::String(s)) => s.parse().map_err(|_| TxIdError::BadField(field)),
        Some(serde_json::Value::Number(n)) => n.as_u64().ok_or(TxIdError::BadField(field)),
        Some(_) => Err(TxIdError::BadField(field)),
    }
}

fn u32_field(value: Option<&serde_json::Value>, field: &'static str) -> Result<u32, TxIdError> {
    u64_field(value, field)?.try_into().map_err(|_| TxIdError::BadField(field))
}

fn hex_field(value: Option<&serde_json::Value>, field: &'static str) -> Result<Vec<u8>, TxIdError> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(Vec::new()),
        Some(serde_json::Value::String(s)) => hex::decode(s).map_err(|_| TxIdError::BadField(field)),
        Some(_) => Err(TxIdError::BadField(field)),
    }
}

fn hash32_field(value: Option<&serde_json::Value>, field: &'static str) -> Result<[u8; 32], TxIdError> {
    let bytes = hex_field(value, field)?;
    let mut out = [0u8; 32];
    if bytes.len() != 32 {
        return Err(TxIdError::BadField(field));
    }
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Parse a `scriptPublicKey` into `(version, script bytes)`.
///
/// Two spellings are accepted, because both occur in practice:
/// - the interop spelling, a single hex string whose first two bytes are the
///   BIG-endian script version followed by the script;
/// - the split object `{ "version": u16, "script": "<hex>" }`, which KOB's own
///   safe-JSON pipeline emits.
///
/// Either way the version is re-emitted LITTLE-endian in the pre-image, like
/// every other integer.
fn script_public_key(value: Option<&serde_json::Value>) -> Result<(u16, Vec<u8>), TxIdError> {
    match value {
        Some(serde_json::Value::Object(map)) => {
            let version = u64_field(map.get("version"), "scriptPublicKey.version")?;
            let version = u16::try_from(version).map_err(|_| TxIdError::BadField("scriptPublicKey.version"))?;
            let script = hex_field(map.get("script"), "scriptPublicKey.script")?;
            Ok((version, script))
        }
        Some(serde_json::Value::String(_)) => {
            let raw = hex_field(value, "scriptPublicKey")?;
            if raw.len() < 2 {
                return Err(TxIdError::BadField("scriptPublicKey"));
            }
            Ok((u16::from_be_bytes([raw[0], raw[1]]), raw[2..].to_vec()))
        }
        _ => Err(TxIdError::BadField("scriptPublicKey")),
    }
}

fn put_varbytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// Serialize the consensus projection of `tx`.
///
/// `include_covenant_byte` follows the transaction version (version-1 outputs
/// append a covenant-presence byte). Signature scripts and the payload are
/// always emitted empty: version 0 excludes signature scripts by definition,
/// and version 1's `restPreimage` empties both because the payload is
/// committed separately through `payloadDigest`.
fn serialize_consensus_projection(
    tx: &serde_json::Value,
    include_covenant_byte: bool,
) -> Result<Vec<u8>, TxIdError> {
    let version = u64_field(tx.get("version"), "version")?;
    let inputs = tx.get("inputs").and_then(|v| v.as_array()).ok_or(TxIdError::Malformed("inputs"))?;
    let outputs = tx.get("outputs").and_then(|v| v.as_array()).ok_or(TxIdError::Malformed("outputs"))?;

    let mut out = Vec::with_capacity(128 + inputs.len() * 52 + outputs.len() * 64);
    out.extend_from_slice(&(u16::try_from(version).map_err(|_| TxIdError::BadField("version"))?).to_le_bytes());

    out.extend_from_slice(&(inputs.len() as u64).to_le_bytes());
    for input in inputs {
        let outpoint = input.get("previousOutpoint").ok_or(TxIdError::Malformed("previousOutpoint"))?;
        out.extend_from_slice(&hash32_field(outpoint.get("transactionId"), "previousOutpoint.transactionId")?);
        out.extend_from_slice(&u32_field(outpoint.get("index"), "previousOutpoint.index")?.to_le_bytes());
        put_varbytes(&mut out, &[]); // signature script, excluded from the id
        out.extend_from_slice(&u64_field(input.get("sequence"), "sequence")?.to_le_bytes());
    }

    out.extend_from_slice(&(outputs.len() as u64).to_le_bytes());
    for output in outputs {
        out.extend_from_slice(&u64_field(output.get("value"), "value")?.to_le_bytes());
        let (script_version, script) = script_public_key(output.get("scriptPublicKey"))?;
        out.extend_from_slice(&script_version.to_le_bytes());
        put_varbytes(&mut out, &script);
        if include_covenant_byte {
            let present = !matches!(output.get("covenant"), None | Some(serde_json::Value::Null));
            out.push(u8::from(present));
            if present {
                // This binding requires `covenant: null` on every output, so a
                // present binding is out of scope rather than something to
                // serialize a guessed layout for.
                return Err(TxIdError::BadField("covenant"));
            }
        }
    }

    out.extend_from_slice(&u64_field(tx.get("lockTime"), "lockTime")?.to_le_bytes());
    let subnetwork = hex_field(tx.get("subnetworkId"), "subnetworkId")?;
    if subnetwork.is_empty() {
        out.extend_from_slice(&[0u8; 20]);
    } else if subnetwork.len() == 20 {
        out.extend_from_slice(&subnetwork);
    } else {
        return Err(TxIdError::BadField("subnetworkId"));
    }
    out.extend_from_slice(&u64_field(tx.get("gas"), "gas")?.to_le_bytes());
    put_varbytes(&mut out, &[]); // payload, emptied in both id constructions

    Ok(out)
}

/// The canonical transaction id of a normalized safe-JSON artifact, lowercase
/// hex. See the module doc for the two constructions.
pub fn transaction_id(tx: &serde_json::Value) -> Result<String, TxIdError> {
    let version = u64_field(tx.get("version"), "version")?;
    let digest = match version {
        0 => {
            let preimage = serialize_consensus_projection(tx, false)?;
            let mut hasher = kob_settle::p2sh::Blake2bSimple::new_keyed(b"TransactionID");
            hasher.update(&preimage);
            hasher.finalize()
        }
        1 => {
            let payload = hex_field(tx.get("payload"), "payload")?;
            let payload_digest = blake3_domain("PayloadDigest", &payload);
            let rest_digest = blake3_domain("TransactionRest", &serialize_consensus_projection(tx, true)?);
            let mut preimage = [0u8; 64];
            preimage[..32].copy_from_slice(&payload_digest);
            preimage[32..].copy_from_slice(&rest_digest);
            blake3_domain("TransactionV1Id", &preimage)
        }
        other => return Err(TxIdError::UnsupportedVersion(other)),
    };
    Ok(hex::encode(digest))
}

/// Recompute the transaction id of an ENCODED artifact and, when it carries a
/// convenience `id`, require agreement.
///
/// This is the function the facilitator calls: an artifact whose self-declared
/// id disagrees with its own contents is rejected rather than quietly re-labelled.
pub fn transaction_id_from_encoded(
    transaction_encoded: &str,
    encoding: &str,
) -> Result<String, TxIdError> {
    if encoding != TX_ENCODING_SAFE_JSON {
        return Err(TxIdError::UnsupportedEncoding);
    }
    let outer: serde_json::Value =
        serde_json::from_str(transaction_encoded).map_err(|_| TxIdError::Malformed("json"))?;
    let tx = crate::scheme_native::normalize_tx(&outer);
    let computed = transaction_id(&tx)?;
    if let Some(claimed) = tx.get("id").or_else(|| tx.get("transactionId")).and_then(|v| v.as_str()) {
        if !claimed.eq_ignore_ascii_case(&computed) {
            return Err(TxIdError::IdMismatch { claimed: claimed.to_string(), computed });
        }
    }
    Ok(computed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INTEROP_V1: &str = include_str!("../interop/vectors/exact/interop-v1.json");

    fn vector() -> serde_json::Value {
        serde_json::from_str(INTEROP_V1).unwrap()
    }

    #[test]
    fn version_0_preimage_and_id_match_the_vector() {
        let v = vector();
        let profile = &v["transactionEncoding"]["profiles"]["standardNative"];
        let preimage = serialize_consensus_projection(&profile["artifact"], false).unwrap();
        assert_eq!(hex::encode(&preimage), profile["txid"]["preimage"].as_str().unwrap());
        assert_eq!(profile["txid"]["algorithm"].as_str().unwrap(), "blake2b-256-keyed");
        assert_eq!(profile["txid"]["domain"].as_str().unwrap(), "TransactionID");
        let id = transaction_id(&profile["artifact"]).unwrap();
        assert_eq!(id, profile["txid"]["digest"].as_str().unwrap());
        // ... and the artifact's own convenience id agrees, which is the
        // property the facilitator enforces.
        assert_eq!(id, profile["artifact"]["id"].as_str().unwrap());
    }

    #[test]
    fn version_1_stages_and_id_match_the_vector() {
        let v = vector();
        let profile = &v["transactionEncoding"]["profiles"]["additive"];
        let txid = &profile["txid"];

        let rest_preimage = serialize_consensus_projection(&profile["artifact"], true).unwrap();
        assert_eq!(hex::encode(&rest_preimage), txid["restPreimage"].as_str().unwrap());

        let payload = hex_field(profile["artifact"].get("payload"), "payload").unwrap();
        let payload_digest = blake3_domain(txid["payloadDomain"].as_str().unwrap(), &payload);
        assert_eq!(hex::encode(payload_digest), txid["payloadDigest"].as_str().unwrap());

        let rest_digest = blake3_domain(txid["restDomain"].as_str().unwrap(), &rest_preimage);
        assert_eq!(hex::encode(rest_digest), txid["restDigest"].as_str().unwrap());

        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(&payload_digest);
        preimage[32..].copy_from_slice(&rest_digest);
        assert_eq!(hex::encode(preimage), txid["preimage"].as_str().unwrap());

        let id = transaction_id(&profile["artifact"]).unwrap();
        assert_eq!(id, txid["digest"].as_str().unwrap());
        assert_eq!(id, profile["artifact"]["id"].as_str().unwrap());
    }

    #[test]
    fn signature_scripts_do_not_affect_the_id() {
        // The whole point of excluding them: the id is stable across signing,
        // and a re-signed artifact cannot claim to be a different payment.
        let v = vector();
        let mut artifact = v["transactionEncoding"]["profiles"]["standardNative"]["artifact"].clone();
        let before = transaction_id(&artifact).unwrap();
        artifact["inputs"][0]["signatureScript"] = serde_json::json!("41".to_string() + &"cd".repeat(65));
        assert_eq!(transaction_id(&artifact).unwrap(), before);
    }

    #[test]
    fn mutating_any_committed_field_changes_the_id() {
        let v = vector();
        let base = v["transactionEncoding"]["profiles"]["standardNative"]["artifact"].clone();
        let id = transaction_id(&base).unwrap();
        let mutations: Vec<(&str, Box<dyn Fn(&mut serde_json::Value)>)> = vec![
            ("output value", Box::new(|a: &mut serde_json::Value| a["outputs"][0]["value"] = serde_json::json!("1"))),
            ("recipient script", Box::new(|a: &mut serde_json::Value| {
                a["outputs"][0]["scriptPublicKey"] = serde_json::json!("000020".to_string() + &"11".repeat(32) + "ac")
            })),
            ("outpoint", Box::new(|a: &mut serde_json::Value| {
                a["inputs"][0]["previousOutpoint"]["transactionId"] = serde_json::json!("aa".repeat(32))
            })),
            ("outpoint index", Box::new(|a: &mut serde_json::Value| a["inputs"][0]["previousOutpoint"]["index"] = serde_json::json!(7))),
            ("sequence", Box::new(|a: &mut serde_json::Value| a["inputs"][0]["sequence"] = serde_json::json!("0"))),
            ("lockTime", Box::new(|a: &mut serde_json::Value| a["lockTime"] = serde_json::json!("5"))),
        ];
        for (what, mutate) in mutations {
            let mut artifact = base.clone();
            mutate(&mut artifact);
            assert_ne!(transaction_id(&artifact).unwrap(), id, "mutating {what} must change the id");
        }
    }

    #[test]
    fn a_lying_convenience_id_is_rejected() {
        let v = vector();
        let mut artifact = v["transactionEncoding"]["profiles"]["standardNative"]["artifact"].clone();
        let honest = artifact["id"].as_str().unwrap().to_string();
        artifact["id"] = serde_json::json!("ff".repeat(32));
        let encoded = serde_json::to_string(&artifact).unwrap();
        match transaction_id_from_encoded(&encoded, TX_ENCODING_SAFE_JSON) {
            Err(TxIdError::IdMismatch { claimed, computed }) => {
                assert_eq!(claimed, "ff".repeat(32));
                assert_eq!(computed, honest);
            }
            other => panic!("a client-authoritative id must be refused, got {other:?}"),
        }
    }

    #[test]
    fn an_artifact_with_no_convenience_id_still_yields_one() {
        let v = vector();
        let mut artifact = v["transactionEncoding"]["profiles"]["additive"]["artifact"].clone();
        let expected = artifact["id"].as_str().unwrap().to_string();
        artifact.as_object_mut().unwrap().remove("id");
        let encoded = serde_json::to_string(&artifact).unwrap();
        assert_eq!(transaction_id_from_encoded(&encoded, TX_ENCODING_SAFE_JSON).unwrap(), expected);
    }
}
