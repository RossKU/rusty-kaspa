//! Primitive encoding helpers for KOB transaction building.

/// Encode u64 as 8-byte little-endian.
pub fn u64_le(n: u64) -> [u8; 8] {
    n.to_le_bytes()
}

/// Encode u32 as 4-byte little-endian.
pub fn u32_le(n: u32) -> [u8; 4] {
    n.to_le_bytes()
}

/// Encode u16 as 2-byte little-endian.
pub fn u16_le(n: u16) -> [u8; 2] {
    n.to_le_bytes()
}

/// Bitcoin-style pushdata encoding (returns new Vec).
///
/// - len <= 75: `[len, data...]`
/// - len <= 255: `[0x4c, len, data...]` (OP_PUSHDATA1)
/// - len > 255: `[0x4d, len_lo, len_hi, data...]` (OP_PUSHDATA2)
pub fn push_data(data: &[u8]) -> Vec<u8> {
    let len = data.len();
    let mut result = Vec::with_capacity(len + 3);
    if len <= 75 {
        result.push(len as u8);
        result.extend_from_slice(data);
    } else if len <= 255 {
        result.push(0x4c);
        result.push(len as u8);
        result.extend_from_slice(data);
    } else {
        result.push(0x4d);
        result.extend_from_slice(&(len as u16).to_le_bytes());
        result.extend_from_slice(data);
    }
    result
}

/// Append pushdata-encoded bytes to a target buffer (in-place).
pub fn push_data_to(target: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len <= 75 {
        target.push(len as u8);
        target.extend_from_slice(data);
    } else if len <= 255 {
        target.push(0x4c);
        target.push(len as u8);
        target.extend_from_slice(data);
    } else {
        target.push(0x4d);
        target.extend_from_slice(&(len as u16).to_le_bytes());
        target.extend_from_slice(data);
    }
}

/// Encode a u64 as a minimal Bitcoin/Kaspa script integer (CScriptNum style).
///
/// - Little-endian, no unnecessary leading zero bytes.
/// - If the high bit of the last byte is set, a 0x00 sign byte is appended (positive).
/// - 0 encodes as empty vec (OP_0 semantics).
///
/// This matches the on-stack representation produced by arithmetic opcodes
/// (OP_ADD, OP_TXLOCKTIME, etc.), which is essential for OP_CAT-based
/// redeemScript construction where the Rust builder and on-stack bytes must agree.
pub fn minimal_script_encode(n: u64) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }
    let mut bytes = Vec::new();
    let mut val = n;
    while val > 0 {
        bytes.push((val & 0xff) as u8);
        val >>= 8;
    }
    // If high bit is set, append 0x00 (positive sign byte)
    if bytes.last().unwrap() & 0x80 != 0 {
        bytes.push(0x00);
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_data_small() {
        let data = vec![0xab; 50];
        let encoded = push_data(&data);
        assert_eq!(encoded[0], 50);
        assert_eq!(encoded.len(), 51);
    }

    #[test]
    fn push_data_medium() {
        let data = vec![0xab; 200];
        let encoded = push_data(&data);
        assert_eq!(encoded[0], 0x4c);
        assert_eq!(encoded[1], 200);
        assert_eq!(encoded.len(), 202);
    }

    #[test]
    fn push_data_large() {
        let data = vec![0xab; 300];
        let encoded = push_data(&data);
        assert_eq!(encoded[0], 0x4d);
        assert_eq!(u16::from_le_bytes([encoded[1], encoded[2]]), 300);
        assert_eq!(encoded.len(), 303);
    }

    #[test]
    fn minimal_script_encode_zero() {
        assert_eq!(minimal_script_encode(0), Vec::<u8>::new());
    }

    #[test]
    fn minimal_script_encode_small() {
        // 1 = [0x01]
        assert_eq!(minimal_script_encode(1), vec![0x01]);
        // 127 = [0x7f]
        assert_eq!(minimal_script_encode(127), vec![0x7f]);
        // 128 = [0x80, 0x00] (high bit set, needs sign byte)
        assert_eq!(minimal_script_encode(128), vec![0x80, 0x00]);
        // 255 = [0xff, 0x00]
        assert_eq!(minimal_script_encode(255), vec![0xff, 0x00]);
        // 256 = [0x00, 0x01]
        assert_eq!(minimal_script_encode(256), vec![0x00, 0x01]);
    }

    #[test]
    fn minimal_script_encode_medium() {
        // 1000020 = 0x0F4254 -> [0x54, 0x42, 0x0f] (3 bytes, high bit clear)
        assert_eq!(minimal_script_encode(1_000_020), vec![0x54, 0x42, 0x0f]);
    }

    #[test]
    fn minimal_script_encode_large() {
        // 10_000_000 = 0x989680 -> [0x80, 0x96, 0x98, 0x00] (high bit set on 0x98? no, 0x98 & 0x80 = 0x80 yes)
        // Wait: 0x989680 = [0x80, 0x96, 0x98] -> 0x98 & 0x80 = 0x80 -> needs sign byte
        assert_eq!(minimal_script_encode(10_000_000), vec![0x80, 0x96, 0x98, 0x00]);
    }

    #[test]
    fn minimal_script_encode_typical_daa() {
        // Typical DAA score ~ 100_000_000 = 0x05F5E100
        // [0x00, 0xe1, 0xf5, 0x05] -> high bit of 0x05 clear -> 4 bytes
        let enc = minimal_script_encode(100_000_000);
        assert_eq!(enc, vec![0x00, 0xe1, 0xf5, 0x05]);
        assert_eq!(enc.len(), 4);
    }
}
