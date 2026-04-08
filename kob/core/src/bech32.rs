//! Kaspa bech32 address encoding/decoding utilities.
//!
//! Thin wrappers around `kaspa_addresses` for backward compatibility.
//! The hand-rolled bech32 implementation has been replaced with Kaspad's
//! canonical `kaspa-addresses` crate to ensure address-level compatibility.

use crate::{KobError, Result};
use kaspa_addresses::{Address, Prefix, Version};

/// Convert a KOB `Network` to a `kaspa_addresses::Prefix`.
fn prefix_from_str(prefix: &str) -> Result<Prefix> {
    Prefix::try_from(prefix).map_err(|e| KobError::InvalidData(format!("{}", e)))
}

/// Encode a Kaspa address using bech32 with polymod checksum.
///
/// `prefix` is e.g. "kaspa" or "kaspatest".
/// `version` is the address type byte (0x00 = P2PK Schnorr, 0x08 = P2SH).
/// `payload` is the raw bytes (32-byte pubkey or 32-byte script hash).
///
/// Returns the full address string `{prefix}:{bech32_data}{checksum}`.
pub fn bech32_encode(prefix: &str, version: u8, payload: &[u8]) -> String {
    let p = Prefix::try_from(prefix).expect("invalid address prefix");
    let v = Version::try_from(version).expect("invalid address version");
    let addr = Address::new(p, v, payload);
    String::from(&addr)
}

/// Decode a bech32-encoded payload string (the part after the ':').
///
/// Returns the 8-bit payload bytes (version + hash/pubkey).
/// NOTE: Without the prefix, checksum cannot be verified.
/// For full verification use `bech32_decode_full` or `address_to_spk`.
pub fn bech32_decode(payload_str: &str) -> Result<Vec<u8>> {
    // We don't have the prefix here, so we try all known prefixes
    // to find one that validates. This preserves backward compatibility.
    // In practice, callers that use this function already split on ':'.
    for prefix in &[Prefix::Mainnet, Prefix::Testnet, Prefix::Devnet, Prefix::Simnet] {
        let full = format!("{}:{}", prefix, payload_str);
        if let Ok(addr) = Address::try_from(full.as_str()) {
            let mut result = Vec::with_capacity(1 + addr.payload.len());
            result.push(addr.version as u8);
            result.extend_from_slice(&addr.payload);
            return Ok(result);
        }
    }

    // If no prefix matched with checksum verification, fall back to
    // raw 5-to-8 conversion without checksum (matches old behavior
    // where bech32_decode didn't verify checksum either).
    let chars: Vec<u8> = payload_str
        .chars()
        .map(|c| {
            charset_rev(c).ok_or_else(|| KobError::InvalidData(format!("invalid bech32 character: {}", c)))
        })
        .collect::<Result<Vec<u8>>>()?;

    if chars.len() < 8 {
        return Err(KobError::InvalidData("bech32 payload too short".into()));
    }

    // Strip the 8-character checksum
    let data5 = &chars[..chars.len() - 8];

    // Convert 5-bit groups back to 8-bit
    let data8 = convert_bits(data5, 5, 8, false);

    if data8.is_empty() {
        return Err(KobError::InvalidData("bech32 decoded to empty payload".into()));
    }

    Ok(data8)
}

/// Parse a Kaspa address and return the corresponding script public key bytes.
///
/// Supported address types:
/// - P2PK (version 0x00): SPK = `[0x20][32-byte pubkey][0xac]`
/// - P2SH (version 0x08): SPK = `[0xaa][0x20][32-byte hash][0x87]`
pub fn address_to_spk(addr: &str) -> Result<Vec<u8>> {
    let address = Address::try_from(addr)
        .map_err(|e| KobError::InvalidData(format!("{}", e)))?;

    let hash = address.payload.as_slice();

    match address.version {
        // P2PK (Schnorr): OP_DATA_32 <32-byte pubkey> OP_CHECKSIG
        Version::PubKey => {
            if hash.len() != 32 {
                return Err(KobError::InvalidData(format!(
                    "P2PK payload must be 32 bytes, got {}",
                    hash.len()
                )));
            }
            let mut spk = Vec::with_capacity(34);
            spk.push(0x20); // OP_DATA_32
            spk.extend_from_slice(hash);
            spk.push(0xac); // OP_CHECKSIG
            Ok(spk)
        }
        // P2SH: OP_BLAKE2B OP_DATA_32 <32-byte hash> OP_EQUAL
        Version::ScriptHash => {
            if hash.len() != 32 {
                return Err(KobError::InvalidData(format!(
                    "P2SH payload must be 32 bytes, got {}",
                    hash.len()
                )));
            }
            let mut spk = Vec::with_capacity(35);
            spk.push(0xaa); // OP_BLAKE2B
            spk.push(0x20); // OP_DATA_32
            spk.extend_from_slice(hash);
            spk.push(0x87); // OP_EQUAL
            Ok(spk)
        }
        _ => Err(KobError::InvalidData(format!(
            "unsupported address version: {:?}",
            address.version
        ))),
    }
}

/// Convert a script public key to a Kaspa address string.
///
/// Recognizes P2PK and P2SH layouts:
/// - P2PK: `[0x20][32B][0xac]` -> version 0x00
/// - P2SH: `[0xaa][0x20][32B][0x87]` -> version 0x08
pub fn spk_to_address(spk: &[u8], prefix: &str) -> Result<String> {
    let p = prefix_from_str(prefix)?;

    // P2PK: 34 bytes = 0x20 + 32 + 0xac
    if spk.len() == 34 && spk[0] == 0x20 && spk[33] == 0xac {
        let addr = Address::new(p, Version::PubKey, &spk[1..33]);
        return Ok(String::from(&addr));
    }

    // P2SH: 35 bytes = 0xaa + 0x20 + 32 + 0x87
    if spk.len() == 35 && spk[0] == 0xaa && spk[1] == 0x20 && spk[34] == 0x87 {
        let addr = Address::new(p, Version::ScriptHash, &spk[2..34]);
        return Ok(String::from(&addr));
    }

    Err(KobError::InvalidData(format!(
        "unrecognized SPK layout ({} bytes)",
        spk.len()
    )))
}

// --- Legacy helpers kept for backward compatibility with tests ---

/// Convert between bit groups (e.g., 8-bit to 5-bit for bech32).
pub fn convert_bits(data: &[u8], from_bits: u32, to_bits: u32, pad: bool) -> Vec<u8> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let max_v: u32 = (1 << to_bits) - 1;
    let mut result = Vec::new();

    for &value in data {
        acc = (acc << from_bits) | (value as u32);
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            result.push(((acc >> bits) & max_v) as u8);
        }
    }

    if pad && bits > 0 {
        result.push(((acc << (to_bits - bits)) & max_v) as u8);
    }

    result
}

/// Compute Kaspa bech32 polymod checksum (40-bit, 8-character checksums).
///
/// Kept for backward compatibility with tests in kob-cli and kob-engine.
pub fn bech32_polymod(values: &[u8]) -> u64 {
    let gen: [u64; 5] = [
        0x98f2bc8e61,
        0x79b76d99e2,
        0xf33e5fb3c4,
        0xae2eabe2a8,
        0x1e4f43e470,
    ];
    let mut chk: u64 = 1;
    for &v in values {
        let b = chk >> 35;
        chk = ((chk & 0x07_ffff_ffff) << 5) ^ (v as u64);
        for (i, &g) in gen.iter().enumerate() {
            if (b >> i) & 1 != 0 {
                chk ^= g;
            }
        }
    }
    chk
}

/// Reverse lookup: bech32 char -> 5-bit value. Returns None for invalid chars.
fn charset_rev(c: char) -> Option<u8> {
    const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    CHARSET.iter().position(|&ch| ch == c as u8).map(|i| i as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_bits_roundtrip() {
        let data = vec![0xAB, 0xCD, 0xEF];
        let bits5 = convert_bits(&data, 8, 5, true);
        for &b in &bits5 {
            assert!(b < 32);
        }
        let back = convert_bits(&bits5, 5, 8, false);
        assert_eq!(back, data);
    }

    #[test]
    fn encode_decode_p2pk_roundtrip() {
        let pubkey = [0x42u8; 32];
        let addr = bech32_encode("kaspatest", 0x00, &pubkey);
        assert!(addr.starts_with("kaspatest:"));

        let spk = address_to_spk(&addr).unwrap();
        assert_eq!(spk.len(), 34);
        assert_eq!(spk[0], 0x20);
        assert_eq!(&spk[1..33], &pubkey);
        assert_eq!(spk[33], 0xac);

        let back = spk_to_address(&spk, "kaspatest").unwrap();
        assert_eq!(back, addr);
    }

    #[test]
    fn encode_decode_p2sh_roundtrip() {
        let hash = [0x77u8; 32];
        let addr = bech32_encode("kaspa", 0x08, &hash);
        assert!(addr.starts_with("kaspa:"));

        let spk = address_to_spk(&addr).unwrap();
        assert_eq!(spk.len(), 35);
        assert_eq!(spk[0], 0xaa);
        assert_eq!(spk[1], 0x20);
        assert_eq!(&spk[2..34], &hash);
        assert_eq!(spk[34], 0x87);

        let back = spk_to_address(&spk, "kaspa").unwrap();
        assert_eq!(back, addr);
    }

    #[test]
    fn address_to_spk_rejects_bad_prefix() {
        assert!(address_to_spk("bitcoin:qr12345").is_err());
    }

    #[test]
    fn address_to_spk_rejects_no_colon() {
        assert!(address_to_spk("nocolon").is_err());
    }

    #[test]
    fn polymod_nonzero() {
        let values = vec![1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0];
        let pm = bech32_polymod(&values);
        assert_ne!(pm, 0);
    }

    /// Verify kaspa-addresses produces same output as old hand-rolled bech32.
    #[test]
    fn cross_check_known_address() {
        // Use a known test vector from kaspa-addresses
        let pubkey = [0u8; 32];
        let addr = bech32_encode("kaspatest", 0x00, &pubkey);
        assert_eq!(addr, "kaspatest:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhqrxplya");

        let mainnet = bech32_encode("kaspa", 0x00, &pubkey);
        assert_eq!(mainnet, "kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e");
    }
}
