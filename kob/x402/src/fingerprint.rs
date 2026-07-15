//! Request-fingerprint <-> payment binding.
//!
//! To stop a client from replaying one paid transaction against a *different*
//! resource/request, the resource server derives a fingerprint from the
//! request context and puts it in `PaymentRequirements.extra.fingerprint`.
//! The client embeds `X402:<fingerprint_hex>` in the Kaspa transaction's
//! payload bytes (reusing the same tagged-payload convention KOB already uses
//! for order discovery). The facilitator recomputes / reads back the expected
//! fingerprint and rejects a mismatch.

use sha2::{Digest, Sha256};

/// Tag that prefixes an x402 fingerprint inside a transaction payload.
pub const FINGERPRINT_TAG: &[u8] = b"X402:";

/// Derive a request fingerprint from the request context.
///
/// `sha256(method \0 path \0 payTo \0 maxAmountRequired \0 nonce)`, hex-encoded.
/// The nonce lets the resource server make each 402 challenge single-use
/// (e.g. a random value it also stores) — replaying a payment for an expired
/// challenge then fails the fingerprint check.
pub fn compute_fingerprint(
    method: &str,
    path: &str,
    pay_to: &str,
    max_amount_required: &str,
    nonce: &str,
) -> String {
    let mut h = Sha256::new();
    for part in [method, path, pay_to, max_amount_required, nonce] {
        h.update(part.as_bytes());
        h.update([0u8]);
    }
    hex::encode(h.finalize())
}

/// Build the transaction-payload bytes that bind a payment to `fingerprint_hex`.
///
/// The result (`X402:<hex>`) is what the client sets as the Kaspa transaction
/// `payload`.
pub fn embed_fingerprint(fingerprint_hex: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(FINGERPRINT_TAG.len() + fingerprint_hex.len());
    v.extend_from_slice(FINGERPRINT_TAG);
    v.extend_from_slice(fingerprint_hex.as_bytes());
    v
}

/// Extract the embedded fingerprint hex from transaction-payload bytes, if the
/// `X402:` tag is present.
pub fn extract_fingerprint(payload: &[u8]) -> Option<String> {
    if payload.len() < FINGERPRINT_TAG.len() || &payload[..FINGERPRINT_TAG.len()] != FINGERPRINT_TAG {
        return None;
    }
    let rest = &payload[FINGERPRINT_TAG.len()..];
    // The fingerprint is ASCII hex; reject anything else so a random covenant
    // payload that happens to start with the tag can't smuggle bytes.
    let s = std::str::from_utf8(rest).ok()?;
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_deterministic_and_context_sensitive() {
        let a = compute_fingerprint("GET", "/a", "kaspatest:qz", "100", "n1");
        let b = compute_fingerprint("GET", "/a", "kaspatest:qz", "100", "n1");
        let c = compute_fingerprint("GET", "/b", "kaspatest:qz", "100", "n1");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64); // sha256 hex
    }

    #[test]
    fn embed_then_extract_roundtrip() {
        let fp = compute_fingerprint("POST", "/pay", "kaspatest:qz", "500", "nonce");
        let payload = embed_fingerprint(&fp);
        assert_eq!(extract_fingerprint(&payload).as_deref(), Some(fp.as_str()));
    }

    #[test]
    fn extract_rejects_untagged_or_nonhex() {
        assert_eq!(extract_fingerprint(b"KOB:2:whatever"), None);
        assert_eq!(extract_fingerprint(b"X402:"), None);
        assert_eq!(extract_fingerprint(b"X402:nothex!!"), None);
        assert_eq!(extract_fingerprint(&[]), None);
    }
}
