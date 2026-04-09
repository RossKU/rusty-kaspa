//! Schnorr signing for Kaspa transactions.
//!
//! Uses the k256 crate to produce Schnorr signatures over secp256k1.
//! Kaspa uses x-only (32-byte) public keys and 64-byte Schnorr signatures,
//! matching the BIP-340 scheme.

use k256::schnorr::signature::hazmat::PrehashSigner;
use k256::schnorr::{SigningKey, VerifyingKey};
use kob_core::wallet::SecureKey;

/// Sign a 32-byte sighash using a `SecureKey` (preferred — key is zeroized on drop).
/// Returns a 64-byte Schnorr signature.
pub fn schnorr_sign_secure(key: &SecureKey, sighash: &[u8; 32]) -> anyhow::Result<[u8; 64]> {
    schnorr_sign(key.as_bytes(), sighash)
}

/// Sign a 32-byte sighash with a 32-byte private key.
/// Returns a 64-byte Schnorr signature.
///
/// Prefer `schnorr_sign_secure` for production use — it accepts a `SecureKey`
/// that zeroizes memory on drop.
pub fn schnorr_sign(private_key: &[u8; 32], sighash: &[u8; 32]) -> anyhow::Result<[u8; 64]> {
    let signing_key = SigningKey::from_bytes(private_key)
        .map_err(|e| anyhow::anyhow!("Invalid private key. The wallet file may be corrupted or contain an invalid key: {}", e))?;

    let signature: k256::schnorr::Signature = signing_key
        .sign_prehash(sighash)
        .map_err(|e| anyhow::anyhow!("Transaction signing failed. The private key may be invalid: {}", e))?;

    let sig_bytes: [u8; 64] = signature.to_bytes();
    Ok(sig_bytes)
}

/// Derive the x-only public key from a 32-byte private key.
/// Returns a 32-byte x-only public key.
#[allow(dead_code)] // Public API: key derivation utility
pub fn derive_pubkey(private_key: &[u8; 32]) -> anyhow::Result<[u8; 32]> {
    let signing_key = SigningKey::from_bytes(private_key)
        .map_err(|e| anyhow::anyhow!("Invalid private key. The wallet file may be corrupted or contain an invalid key: {}", e))?;
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

/// Build a P2SH sigscript: [pushData(sig+sighashType)] [pushData(pubkey)] [pushData(redeemScript)]
///
/// This is the standard P2SH spend pattern for token_unit and token_mint UTXOs.
/// The script engine evaluates the redeemScript with sig and pk on the stack.
pub fn build_p2sh_sigscript(signature: &[u8; 64], pubkey: &[u8; 32], redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::new();
    // Push signature + sighash type
    ss.push(65); // length: 64 sig + 1 sighash type
    ss.extend_from_slice(signature);
    ss.push(0x01); // SIGHASH_ALL
    // Push public key
    ss.push(32); // length: 32 bytes
    ss.extend_from_slice(pubkey);
    // Push redeemScript (may need OP_PUSHDATA1/2 for length)
    let rs_len = redeem_script.len();
    if rs_len <= 75 {
        ss.push(rs_len as u8);
    } else if rs_len <= 255 {
        ss.push(0x4c); // OP_PUSHDATA1
        ss.push(rs_len as u8);
    } else {
        ss.push(0x4d); // OP_PUSHDATA2
        ss.push((rs_len & 0xff) as u8);
        ss.push(((rs_len >> 8) & 0xff) as u8);
    }
    ss.extend_from_slice(redeem_script);
    ss
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        // Use the test wallet private key
        let privkey_hex = "ae4ef0f30537c81653c2213b4b1ad84053fec52c547cb590277a7015850359a4";
        let privkey_bytes: [u8; 32] = hex::decode(privkey_hex).unwrap().try_into().unwrap();

        let pubkey = derive_pubkey(&privkey_bytes).unwrap();
        assert_eq!(pubkey.len(), 32);
        assert_ne!(pubkey, [0u8; 32]);

        // The public key should match the wallet file
        let expected_pub = "3509e6f574e705aa233b7f9713e979bb27f463116d6a754369c19479d3fe6583";
        assert_eq!(hex::encode(pubkey), expected_pub);

        // Sign a dummy hash
        let sighash = [0xab; 32];
        let sig = schnorr_sign(&privkey_bytes, &sighash).unwrap();
        assert_eq!(sig.len(), 64);
        assert_ne!(sig, [0u8; 64]);
    }

    #[test]
    fn p2pk_sigscript_structure() {
        let sig = [0x42u8; 64];
        let ss = build_p2pk_sigscript(&sig);
        assert_eq!(ss.len(), 66);
        assert_eq!(ss[0], 65); // length prefix
        assert_eq!(ss[65], 0x01); // SIGHASH_ALL
    }
}
