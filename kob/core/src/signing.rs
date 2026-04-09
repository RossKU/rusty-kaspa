//! Schnorr signature support for Kaspa transactions (BIP-340).
//!
//! Kaspa uses secp256k1 Schnorr signatures (same as Bitcoin Taproot/BIP-340).
//! The input to signing is a 32-byte sighash (already computed via `compute_sighash`),
//! and the output is a 64-byte signature.
//!
//! This module wraps the `k256` crate's Schnorr implementation.

use k256::schnorr::SigningKey;
use signature::hazmat::PrehashSigner;

use crate::wallet::SecureKey;

/// Sign a pre-computed sighash with Schnorr (BIP-340) using a `SecureKey`.
///
/// This is the preferred signing method. The `SecureKey` zeroes its memory on drop.
///
/// # Example
/// ```
/// # use kob_core::signing::schnorr_sign_secure;
/// # use kob_core::wallet::SecureKey;
/// let key = SecureKey::from_bytes([1u8; 32]);
/// let sighash = [0xab; 32];
/// let sig = schnorr_sign_secure(&sighash, &key).unwrap();
/// assert_eq!(sig.len(), 64);
/// ```
pub fn schnorr_sign_secure(sighash: &[u8; 32], key: &SecureKey) -> crate::Result<[u8; 64]> {
    schnorr_sign(sighash, key.as_bytes())
}

/// Sign a pre-computed sighash with Schnorr (BIP-340).
///
/// Takes a 32-byte sighash (from `compute_sighash`) and a 32-byte private key.
/// Returns a 64-byte Schnorr signature.
///
/// The signing is deterministic (aux_rand = [0; 32]) which matches Kaspa's
/// consensus expectations.
///
/// # Example
/// ```
/// # use kob_core::signing::{schnorr_sign, get_public_key};
/// let privkey = [1u8; 32]; // Example key (not a real key)
/// let sighash = [0xab; 32]; // Example sighash
/// // Note: privkey [1; 32] is a valid secp256k1 scalar
/// let sig = schnorr_sign(&sighash, &privkey).unwrap();
/// assert_eq!(sig.len(), 64);
/// ```
pub fn schnorr_sign(sighash: &[u8; 32], privkey: &[u8; 32]) -> crate::Result<[u8; 64]> {
    let signing_key = SigningKey::from_bytes(privkey)
        .map_err(|e| crate::KobError::Transaction(format!("Invalid private key: {}", e)))?;
    let sig = signing_key.sign_prehash(sighash)
        .map_err(|e| crate::KobError::Transaction(format!("Signing failed: {}", e)))?;
    Ok(sig.to_bytes())
}

/// Get the x-only public key (32 bytes) from a private key.
///
/// This is the BIP-340 x-only representation used in Kaspa addresses.
pub fn get_public_key(privkey: &[u8; 32]) -> crate::Result<[u8; 32]> {
    let signing_key = SigningKey::from_bytes(privkey)
        .map_err(|e| crate::KobError::Transaction(format!("Invalid private key: {}", e)))?;
    let vk = signing_key.verifying_key();
    Ok(vk.to_bytes().into())
}

/// Get the x-only public key from a `SecureKey`.
pub fn get_public_key_secure(key: &SecureKey) -> crate::Result<[u8; 32]> {
    get_public_key(key.as_bytes())
}

/// Verify a Schnorr signature against a public key and sighash.
///
/// Used for testing. In production, Kaspa nodes verify signatures.
pub fn schnorr_verify(sighash: &[u8; 32], signature: &[u8; 64], pubkey: &[u8; 32]) -> crate::Result<bool> {
    use k256::schnorr::{Signature, VerifyingKey};
    use signature::hazmat::PrehashVerifier;

    let vk = VerifyingKey::from_bytes(pubkey)
        .map_err(|e| crate::KobError::Transaction(format!("Invalid public key: {}", e)))?;
    let sig = Signature::try_from(signature.as_slice())
        .map_err(|e| crate::KobError::Transaction(format!("Invalid signature: {}", e)))?;
    Ok(vk.verify_prehash(sighash, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP-340 test vector 0: known key, message, expected signature.
    #[test]
    fn bip340_test_vector_0() {
        let privkey: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        ];
        let expected_pubkey_hex = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

        let pubkey = get_public_key(&privkey).unwrap();
        assert_eq!(hex::encode(pubkey).to_lowercase(), expected_pubkey_hex.to_lowercase());
    }

    /// Signing produces a 64-byte output.
    #[test]
    fn sign_produces_64_bytes() {
        let privkey = [1u8; 32];
        let sighash = [0xab; 32];
        let sig = schnorr_sign(&sighash, &privkey).unwrap();
        assert_eq!(sig.len(), 64);
    }

    /// Deterministic signing: same inputs produce same signature.
    /// (sign_prehash uses aux_rand = [0; 32], so it is deterministic.)
    #[test]
    fn sign_is_deterministic() {
        let privkey = [1u8; 32];
        let sighash = [0xcd; 32];
        let sig1 = schnorr_sign(&sighash, &privkey).unwrap();
        let sig2 = schnorr_sign(&sighash, &privkey).unwrap();
        assert_eq!(sig1, sig2, "Schnorr signing must be deterministic with default aux_rand");
    }

    /// Different sighash produces different signature.
    #[test]
    fn different_sighash_different_sig() {
        let privkey = [1u8; 32];
        let sighash_a = [0x11; 32];
        let sighash_b = [0x22; 32];
        let sig_a = schnorr_sign(&sighash_a, &privkey).unwrap();
        let sig_b = schnorr_sign(&sighash_b, &privkey).unwrap();
        assert_ne!(sig_a, sig_b, "Different sighashes must produce different signatures");
    }

    /// Sign-then-verify roundtrip.
    #[test]
    fn sign_verify_roundtrip() {
        let privkey = [1u8; 32];
        let sighash = [0xef; 32];
        let pubkey = get_public_key(&privkey).unwrap();
        let sig = schnorr_sign(&sighash, &privkey).unwrap();
        let ok = schnorr_verify(&sighash, &sig, &pubkey).unwrap();
        assert!(ok, "Signature must verify against own public key");
    }

    /// Verification fails with wrong sighash.
    #[test]
    fn verify_fails_wrong_sighash() {
        let privkey = [1u8; 32];
        let sighash = [0xef; 32];
        let wrong_sighash = [0xfe; 32];
        let pubkey = get_public_key(&privkey).unwrap();
        let sig = schnorr_sign(&sighash, &privkey).unwrap();
        let ok = schnorr_verify(&wrong_sighash, &sig, &pubkey).unwrap();
        assert!(!ok, "Signature must not verify against wrong sighash");
    }

    /// Use the actual wallet key from wallet.json to verify pubkey derivation.
    #[test]
    fn wallet_key_pubkey_derivation() {
        let privkey_hex = "ae4ef0f30537c81653c2213b4b1ad84053fec52c547cb590277a7015850359a4";
        let expected_pubkey_hex = "3509e6f574e705aa233b7f9713e979bb27f463116d6a754369c19479d3fe6583";
        let privkey: [u8; 32] = hex::decode(privkey_hex).unwrap().try_into().unwrap();
        let pubkey = get_public_key(&privkey).unwrap();
        assert_eq!(
            hex::encode(pubkey).to_lowercase(),
            expected_pubkey_hex.to_lowercase(),
            "Derived pubkey must match wallet.json publicKey"
        );
    }

    /// Invalid (zero) private key is rejected.
    #[test]
    fn zero_privkey_rejected() {
        let privkey = [0u8; 32];
        let result = schnorr_sign(&[0; 32], &privkey);
        assert!(result.is_err(), "Zero private key must be rejected");
    }

    /// SecureKey-based signing produces the same result as raw signing.
    #[test]
    fn secure_key_signing_matches_raw() {
        let privkey = [1u8; 32];
        let sighash = [0xab; 32];
        let key = SecureKey::from_bytes(privkey);

        let sig_raw = schnorr_sign(&sighash, &privkey).unwrap();
        let sig_secure = schnorr_sign_secure(&sighash, &key).unwrap();
        assert_eq!(sig_raw, sig_secure, "SecureKey signing must match raw signing");
    }

    /// SecureKey-based public key derivation matches raw derivation.
    #[test]
    fn secure_key_pubkey_matches_raw() {
        let privkey = [1u8; 32];
        let key = SecureKey::from_bytes(privkey);

        let pk_raw = get_public_key(&privkey).unwrap();
        let pk_secure = get_public_key_secure(&key).unwrap();
        assert_eq!(pk_raw, pk_secure);
    }

    /// SecureKey from wallet file works for signing.
    #[test]
    fn secure_key_from_wallet_signs() {
        use crate::wallet::WalletFile;
        let wallet = WalletFile {
            private_key: "ae4ef0f30537c81653c2213b4b1ad84053fec52c547cb590277a7015850359a4".into(),
            public_key: "3509e6f574e705aa233b7f9713e979bb27f463116d6a754369c19479d3fe6583".into(),
            address: "kaspatest:qxapemh4t8qp4rf3eek88m98u0a2y78xzes52jrjd8gclj5c0l9svhkkwmwc5".into(),
        };
        let key = SecureKey::from_wallet(&wallet).unwrap();
        let sighash = [0x42; 32];
        let sig = schnorr_sign_secure(&sighash, &key).unwrap();
        let pubkey = wallet.public_key_bytes().unwrap();
        let ok = schnorr_verify(&sighash, &sig, &pubkey).unwrap();
        assert!(ok, "SecureKey from wallet must produce valid signatures");
    }

    /// SecureKey Debug does not leak key material.
    #[test]
    fn secure_key_debug_redacted() {
        let key = SecureKey::from_bytes([0xaa; 32]);
        let debug = format!("{:?}", key);
        assert_eq!(debug, "SecureKey([REDACTED])");
        assert!(!debug.contains("aa"), "Debug must not leak key bytes");
    }
}
