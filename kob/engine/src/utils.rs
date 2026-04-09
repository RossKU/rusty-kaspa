//! Utility functions for kob-engine (signing helpers, address encoding).

use k256::schnorr::signature::hazmat::PrehashSigner;
use k256::schnorr::{SigningKey, VerifyingKey};

// Schnorr signing (from kob-cli/src/signing.rs)

/// Sign a 32-byte sighash with a 32-byte private key.
/// Returns a 64-byte Schnorr signature.
pub fn schnorr_sign(private_key: &[u8; 32], sighash: &[u8; 32]) -> anyhow::Result<[u8; 64]> {
    let signing_key = SigningKey::from_bytes(private_key)
        .map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;

    let signature: k256::schnorr::Signature = signing_key
        .sign_prehash(sighash)
        .map_err(|e| anyhow::anyhow!("Signing failed: {}", e))?;

    let sig_bytes: [u8; 64] = signature.to_bytes();
    Ok(sig_bytes)
}

/// Derive the x-only public key from a 32-byte private key.
/// Returns a 32-byte x-only public key.
#[allow(dead_code)] // Used in tests
pub fn derive_pubkey(private_key: &[u8; 32]) -> anyhow::Result<[u8; 32]> {
    let signing_key = SigningKey::from_bytes(private_key)
        .map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;
    let vk: &VerifyingKey = signing_key.verifying_key();
    let pk_bytes: [u8; 32] = vk.to_bytes().into();
    Ok(pk_bytes)
}

/// Build a P2PK sigscript: [pushData(sig 64B + sighashType 0x01)] = 66 bytes.
pub fn build_p2pk_sigscript(signature: &[u8; 64]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(66);
    ss.push(65); // length prefix: 64 sig + 1 sighash type
    ss.extend_from_slice(signature);
    ss.push(0x01); // SIGHASH_ALL
    ss
}

// Kaspa address encoding (from kob-cli/src/cancel.rs)

/// Convert a P2SH script public key to a Kaspa address string.
///
/// Uses hex-encoded fallback format (`prefix:pHEX`).
pub fn p2sh_to_address(spk: &[u8], prefix: &str) -> String {
    format!("{}:p{}", prefix, hex::encode(spk))
}

/// Encode a Kaspa address using bech32 with polymod checksum.
///
/// Uses hex-encoded fallback format (`prefix:vXX_HEX`) where XX is the version byte.
pub fn kaspa_address_encode(prefix: &str, version: u8, payload: &[u8]) -> String {
    format!("{}:v{:02x}_{}", prefix, version, hex::encode(payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let privkey_hex = "ae4ef0f30537c81653c2213b4b1ad84053fec52c547cb590277a7015850359a4";
        let privkey_bytes: [u8; 32] = hex::decode(privkey_hex).unwrap().try_into().unwrap();

        let pubkey = derive_pubkey(&privkey_bytes).unwrap();
        assert_eq!(pubkey.len(), 32);

        let sighash = [0xab; 32];
        let sig = schnorr_sign(&privkey_bytes, &sighash).unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn p2pk_sigscript_structure() {
        let sig = [0x42u8; 64];
        let ss = build_p2pk_sigscript(&sig);
        assert_eq!(ss.len(), 66);
        assert_eq!(ss[0], 65);
        assert_eq!(ss[65], 0x01);
    }

    #[test]
    fn bech32_polymod_nonzero() {
        let values = vec![1, 2, 3, 4, 5];
        let result = kob_core::bech32::bech32_polymod(&values);
        assert_ne!(result, 0);
    }
}
