//! Canonical JSON, the exact request-authorization digest, and its Schnorr
//! verification (`spec/kaspa-exact-v2.md`, "Canonical request authorization").
//!
//! # Why this exists
//!
//! An on-chain Kaspa signature authorizes a value transfer; it says nothing
//! about WHICH HTTP resource or MCP operation that payment is for. The exact
//! request authorization closes that audience boundary: the payer signs a
//! digest binding the transaction id, profile, payment output index, amount,
//! recipient (`payTo` and its serialized script), the accepted requirements,
//! the normalized request hash, the additive challenge, the authorizing input
//! index, and an expiry. Removing or changing any of those MUST invalidate the
//! payment before protected work happens.
//!
//! Until upstream PR#3 (merged 2026-07-19, released in alpha.9) the byte-exact
//! pre-image layout was unpublished, so this crate could only check the
//! digest/signature SHAPES. PR#3 ships both canonical JSON pre-images, both
//! SHA-256 results, the signer key and a valid signature as a language-
//! independent vector (`interop/vectors/exact/interop-v1.json`), which is what
//! the tests below verify this module against.
//!
//! # Canonical JSON
//!
//! Recursive, per the spec: object keys sorted ascending by UTF-16 code unit,
//! arrays keep their order, compact encoding, no inserted whitespace,
//! `undefined`/non-finite/non-JSON values invalid. All documented field names
//! are ASCII, so bytewise and code-point ordering coincide; [`canonical_json`]
//! sorts explicitly rather than relying on `serde_json`'s map type, so the
//! result does not depend on whether the `preserve_order` feature is enabled
//! anywhere in the dependency graph.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// `scope` of the authorization digest object, and the `version` an
/// [`crate::wire_v2::ExactAuthorization`] must carry.
pub const EXACT_REQUEST_AUTHORIZATION_VERSION: &str = "kaspa-x402-exact-request-authorization-v1";

/// Why an authorization failed to verify. Kept separate from the wire error
/// codes so callers decide how much to reveal (they all map to
/// `invalid_payload` today).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// A value in the object is not canonically serializable (non-finite
    /// number, or a non-JSON value).
    NotSerializable,
    /// `digest`/`signature` is not the expected length, or not hex.
    MalformedField(&'static str),
    /// The recomputed digest disagrees with the one the payer sent.
    DigestMismatch { computed: String, claimed: String },
    /// The signer's key could not be derived from the payer address.
    UnknownSigner,
    /// Schnorr verification of `signature` over the digest failed.
    BadSignature,
}

/// Recursively serialize `value` as canonical JSON.
pub fn canonical_json(value: &serde_json::Value) -> Result<String, AuthError> {
    let mut out = String::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &serde_json::Value, out: &mut String) -> Result<(), AuthError> {
    match value {
        serde_json::Value::Null => out.push_str("null"),
        serde_json::Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        serde_json::Value::Number(n) => {
            if n.is_i64() || n.is_u64() {
                out.push_str(&n.to_string());
            } else {
                // JavaScript has no integer/float distinction, so
                // `JSON.stringify(1.0)` is `1`, while serde_json's Float
                // variant always prints a decimal point (`1.0`). An offer that
                // spells a whole number with a decimal point anywhere in
                // `extra` or an unmodelled top-level field would otherwise hash
                // differently here than in the JS reference implementation --
                // it fails closed (digest mismatch), but it fails.
                let f = n.as_f64().ok_or(AuthError::NotSerializable)?;
                if !f.is_finite() {
                    return Err(AuthError::NotSerializable);
                }
                if f.fract() == 0.0 && f.abs() < 9_007_199_254_740_992.0 {
                    out.push_str(&format!("{}", f as i64));
                } else {
                    // Both sides emit the shortest representation that
                    // round-trips. They can still differ in exponent spelling
                    // for extreme magnitudes; no documented x402 field is a
                    // non-integral number, so that residue stays theoretical.
                    out.push_str(&n.to_string());
                }
            }
        }
        serde_json::Value::String(s) => write_json_string(s, out),
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        serde_json::Value::Object(map) => {
            // Sort by UTF-16 code units. Rust's `str` ordering is by Unicode
            // scalar value, which differs from UTF-16 order only for
            // supplementary-plane keys (U+10000..) versus the surrogate range
            // -- no documented field name is affected, and the spec itself
            // notes the two coincide for the ASCII names it defines.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| utf16_cmp(a, b));
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json_string(key, out);
                out.push(':');
                write_canonical(&map[key.as_str()], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn utf16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// Write a JSON string literal the way `JSON.stringify` does: escape only
/// `"`/`\`/control characters, with `\b\f\n\r\t` short forms and `\u00XX` for
/// the rest. Non-ASCII characters are emitted literally (as UTF-8), matching
/// both `JSON.stringify` and `serde_json`.
fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// `paymentRequirementsHash`: SHA-256 over the canonical JSON of the COMPLETE
/// selected `PaymentRequirements` object.
///
/// "Complete" is load-bearing: implementations that accept additional fields
/// must still include them, so this takes the requirements as a raw JSON value
/// rather than a typed struct that would silently drop unknown keys.
pub fn payment_requirements_hash(requirements: &serde_json::Value) -> Result<String, AuthError> {
    Ok(sha256_hex(canonical_json(requirements)?.as_bytes()))
}

/// The fields the authorization digest binds. Hex fields are lowercased and
/// `challenge_id` becomes an explicit `null` for standard-native, per spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationDigestInput {
    pub network: String,
    pub profile: String,
    pub transaction_id: String,
    pub payment_output_index: u32,
    /// Decimal sompi string (NOT a number -- it is a string in the digest).
    pub amount: String,
    pub pay_to: String,
    pub pay_to_script_public_key: String,
    pub payment_requirements_hash: String,
    pub request_hash: String,
    pub challenge_id: Option<String>,
    pub input_index: u32,
    pub expires_at: String,
}

impl AuthorizationDigestInput {
    /// The exact object the spec hashes.
    fn to_canonical_value(&self) -> serde_json::Value {
        serde_json::json!({
            "scope": EXACT_REQUEST_AUTHORIZATION_VERSION,
            "network": self.network,
            "profile": self.profile,
            "transactionId": self.transaction_id.to_lowercase(),
            "paymentOutputIndex": self.payment_output_index,
            "amount": self.amount,
            "payTo": self.pay_to,
            "payToScriptPublicKey": self.pay_to_script_public_key.to_lowercase(),
            "paymentRequirementsHash": self.payment_requirements_hash.to_lowercase(),
            "requestHash": self.request_hash.to_lowercase(),
            "challengeId": match &self.challenge_id {
                Some(c) => serde_json::Value::String(c.to_lowercase()),
                None => serde_json::Value::Null,
            },
            "inputIndex": self.input_index,
            "expiresAt": self.expires_at,
        })
    }

    /// The UTF-8 canonical-JSON bytes that get hashed. Exposed because the
    /// interop vector publishes this pre-image, so it is directly testable.
    pub fn preimage(&self) -> Result<String, AuthError> {
        canonical_json(&self.to_canonical_value())
    }

    /// The 32-byte digest, lowercase hex.
    pub fn digest(&self) -> Result<String, AuthError> {
        Ok(sha256_hex(self.preimage()?.as_bytes()))
    }
}

fn decode_fixed_hex<const N: usize>(s: &str, field: &'static str) -> Result<[u8; N], AuthError> {
    if s.len() != N * 2 {
        return Err(AuthError::MalformedField(field));
    }
    let bytes = hex::decode(s).map_err(|_| AuthError::MalformedField(field))?;
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Full verification: recompute the digest from the fields the facilitator
/// independently knows, require the payer's claimed digest to match it, then
/// Schnorr-verify the signature over those 32 bytes under `signer_x_only_pubkey`.
///
/// The signature signs the DIGEST directly (not a re-hash of it), per spec.
pub fn verify_authorization(
    input: &AuthorizationDigestInput,
    claimed_digest: &str,
    signature_hex: &str,
    signer_x_only_pubkey: &[u8; 32],
) -> Result<(), AuthError> {
    let computed = input.digest()?;
    if !computed.eq_ignore_ascii_case(claimed_digest) {
        return Err(AuthError::DigestMismatch {
            computed,
            claimed: claimed_digest.to_string(),
        });
    }
    let digest_bytes = decode_fixed_hex::<32>(&computed, "digest")?;
    let signature = decode_fixed_hex::<64>(signature_hex, "signature")?;
    match kob_settle::signing::schnorr_verify(&digest_bytes, &signature, signer_x_only_pubkey) {
        Ok(true) => Ok(()),
        // A malformed key/signature and a well-formed-but-wrong one are the
        // same answer to the caller: this payer did not authorize this request.
        Ok(false) | Err(_) => Err(AuthError::BadSignature),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vendored from elldeeone/kaspa-x402 PR#3 (merged 2026-07-19, alpha.9):
    /// the language-independent exact interoperability vector.
    const INTEROP_V1: &str = include_str!("../interop/vectors/exact/interop-v1.json");

    fn vector() -> serde_json::Value {
        serde_json::from_str(INTEROP_V1).unwrap()
    }

    #[test]
    fn payment_requirements_canonical_json_and_hash_match_the_vector() {
        let v = vector();
        let pr = &v["paymentRequirements"];
        let canonical = canonical_json(&pr["value"]).unwrap();
        assert_eq!(canonical, pr["canonicalJsonUtf8"].as_str().unwrap());
        assert_eq!(payment_requirements_hash(&pr["value"]).unwrap(), pr["sha256"].as_str().unwrap());
    }

    fn digest_input_from_vector(v: &serde_json::Value) -> AuthorizationDigestInput {
        let i = &v["requestAuthorization"]["input"];
        AuthorizationDigestInput {
            network: i["network"].as_str().unwrap().to_string(),
            profile: i["profile"].as_str().unwrap().to_string(),
            transaction_id: i["transactionId"].as_str().unwrap().to_string(),
            payment_output_index: i["paymentOutputIndex"].as_u64().unwrap() as u32,
            amount: i["amount"].as_str().unwrap().to_string(),
            pay_to: i["payTo"].as_str().unwrap().to_string(),
            pay_to_script_public_key: i["payToScriptPublicKey"].as_str().unwrap().to_string(),
            payment_requirements_hash: i["paymentRequirementsHash"].as_str().unwrap().to_string(),
            request_hash: i["requestHash"].as_str().unwrap().to_string(),
            challenge_id: i["challengeId"].as_str().map(str::to_string),
            input_index: i["inputIndex"].as_u64().unwrap() as u32,
            expires_at: i["expiresAt"].as_str().unwrap().to_string(),
        }
    }

    #[test]
    fn authorization_preimage_and_digest_match_the_vector() {
        let v = vector();
        let input = digest_input_from_vector(&v);
        let ra = &v["requestAuthorization"];
        assert_eq!(input.preimage().unwrap(), ra["canonicalJsonUtf8"].as_str().unwrap());
        assert_eq!(input.digest().unwrap(), ra["sha256"].as_str().unwrap());
    }

    #[test]
    fn vector_signature_verifies_under_the_published_signer_key() {
        let v = vector();
        let input = digest_input_from_vector(&v);
        let ra = &v["requestAuthorization"];
        assert_eq!(ra["expected"].as_str().unwrap(), "valid-schnorr-signature");
        let pubkey =
            decode_fixed_hex::<32>(ra["signerPublicKey"].as_str().unwrap(), "signerPublicKey").unwrap();
        verify_authorization(
            &input,
            ra["sha256"].as_str().unwrap(),
            ra["signature"].as_str().unwrap(),
            &pubkey,
        )
        .expect("the published vector signature must verify");
    }

    #[test]
    fn tampering_with_any_bound_field_breaks_verification() {
        let v = vector();
        let ra = &v["requestAuthorization"];
        let pubkey =
            decode_fixed_hex::<32>(ra["signerPublicKey"].as_str().unwrap(), "signerPublicKey").unwrap();
        let claimed = ra["sha256"].as_str().unwrap();
        let signature = ra["signature"].as_str().unwrap();

        // Each mutation must change the digest, so verification fails at the
        // digest comparison -- this is the audience binding the whole
        // mechanism exists for: none of these fields can be swapped after the
        // payer signed.
        let mutations: Vec<(&str, Box<dyn Fn(&mut AuthorizationDigestInput)>)> = vec![
            ("amount", Box::new(|i: &mut AuthorizationDigestInput| i.amount = "1".into())),
            ("payTo", Box::new(|i: &mut AuthorizationDigestInput| i.pay_to = "kaspatest:other".into())),
            ("requestHash", Box::new(|i: &mut AuthorizationDigestInput| i.request_hash = "aa".repeat(32))),
            ("paymentRequirementsHash", Box::new(|i: &mut AuthorizationDigestInput| i.payment_requirements_hash = "bb".repeat(32))),
            ("profile", Box::new(|i: &mut AuthorizationDigestInput| i.profile = "standard-native".into())),
            ("challengeId", Box::new(|i: &mut AuthorizationDigestInput| i.challenge_id = None)),
            ("inputIndex", Box::new(|i: &mut AuthorizationDigestInput| i.input_index += 1)),
            ("paymentOutputIndex", Box::new(|i: &mut AuthorizationDigestInput| i.payment_output_index += 1)),
            ("transactionId", Box::new(|i: &mut AuthorizationDigestInput| i.transaction_id = "cc".repeat(32))),
            ("expiresAt", Box::new(|i: &mut AuthorizationDigestInput| i.expires_at = "2099-01-02T00:00:00.000Z".into())),
        ];
        for (field, mutate) in mutations {
            let mut input = digest_input_from_vector(&v);
            mutate(&mut input);
            let res = verify_authorization(&input, claimed, signature, &pubkey);
            assert!(
                matches!(res, Err(AuthError::DigestMismatch { .. })),
                "mutating {field} must break the digest binding, got {res:?}"
            );
        }
    }

    #[test]
    fn a_valid_digest_with_a_foreign_signer_key_is_rejected() {
        // The digest itself is public, so a matching digest proves nothing on
        // its own: the signature must verify under the key committed by the
        // authorizing funding input.
        let v = vector();
        let input = digest_input_from_vector(&v);
        let ra = &v["requestAuthorization"];
        let mut foreign =
            decode_fixed_hex::<32>(ra["signerPublicKey"].as_str().unwrap(), "signerPublicKey").unwrap();
        foreign[0] ^= 0x01;
        let res = verify_authorization(
            &input,
            ra["sha256"].as_str().unwrap(),
            ra["signature"].as_str().unwrap(),
            &foreign,
        );
        assert_eq!(res, Err(AuthError::BadSignature));
    }

    #[test]
    fn whole_numbers_serialize_the_way_javascript_prints_them() {
        // `JSON.stringify({a: 1.0, b: 1e3})` is `{"a":1,"b":1000}`. serde_json's
        // Float variant would print `1.0`/`1000.0`, which would make every
        // digest computed from an offer carrying such a literal disagree with
        // the JS reference implementation.
        let v: serde_json::Value = serde_json::from_str(r#"{"a":1.0,"b":1e3,"c":-2.0}"#).unwrap();
        assert_eq!(canonical_json(&v).unwrap(), r#"{"a":1,"b":1000,"c":-2}"#);
        // Genuine integers are untouched.
        let v2: serde_json::Value = serde_json::from_str(r#"{"a":1,"b":18446744073709551615}"#).unwrap();
        assert_eq!(canonical_json(&v2).unwrap(), r#"{"a":1,"b":18446744073709551615}"#);
    }

    #[test]
    fn canonical_json_sorts_keys_and_inserts_no_whitespace() {
        let v = serde_json::json!({ "b": 1, "a": { "d": [3, 1, 2], "c": "x" } });
        assert_eq!(canonical_json(&v).unwrap(), r#"{"a":{"c":"x","d":[3,1,2]},"b":1}"#);
    }

    #[test]
    fn canonical_json_escapes_like_json_stringify() {
        let v = serde_json::json!({ "k": "a\"b\\c\nd\u{1}e\u{e9}" });
        assert_eq!(canonical_json(&v).unwrap(), "{\"k\":\"a\\\"b\\\\c\\nd\\u0001e\u{e9}\"}");
    }
}
