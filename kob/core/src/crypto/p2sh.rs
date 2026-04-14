use kaspa_consensus_core::tx::ScriptPublicKey;

/// Compute unkeyed Blake2b-256 hash.
pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .hash(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// Compute the SPK hash for v5/v4 contracts.
///
/// The SPK hash is Blake2b-256 of the full scriptPublicKey in the format
/// returned by OpTxOutputSpk: `version_u16LE + script_bytes`.
///
/// For a P2PK output with version=0 and pubkey, this is:
/// Blake2b-256([0x00, 0x00, 0x20, pubkey_32B, 0xac]) = Blake2b-256(36 bytes)
pub fn compute_spk_hash(version: u16, script: &[u8]) -> [u8; 32] {
    let mut spk_bytes = Vec::with_capacity(2 + script.len());
    spk_bytes.extend_from_slice(&version.to_le_bytes());
    spk_bytes.extend_from_slice(script);
    blake2b_256(&spk_bytes)
}

/// Compute the SPK hash for a P2PK public key (version=0, script=[0x20][pk][0xac]).
pub fn compute_p2pk_spk_hash(pubkey: &[u8; 32]) -> [u8; 32] {
    let mut script = Vec::with_capacity(34);
    script.push(0x20); // push 32 bytes
    script.extend_from_slice(pubkey);
    script.push(0xac); // OpCheckSig
    compute_spk_hash(0, &script)
}

/// Build P2SH script public key from redeemScript
///
/// SPK = [OpBlake2b(0xaa)] [push32(0x20)] [blake2b256(rs)] [OpEqual(0x87)]
pub fn build_p2sh(rs: &[u8]) -> ScriptPublicKey {
    let hash = blake2b_256(rs);
    let mut script = Vec::with_capacity(35);
    script.push(0xaa); // OpBlake2b
    script.push(0x20); // push 32 bytes
    script.extend_from_slice(&hash);
    script.push(0x87); // OpEqual
    ScriptPublicKey::new(0, script.into())
}

/// Keyed Blake2b-256 hasher backed by blake2b_simd.
///
/// Drop-in replacement for the hand-rolled Blake2bSimple that was here before.
/// Only exposes the API surface that KOB actually uses (new, new_keyed, update, finalize).
pub struct Blake2bSimple {
    state: blake2b_simd::State,
}

impl Default for Blake2bSimple {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake2bSimple {
    pub fn new() -> Self {
        let state = blake2b_simd::Params::new()
            .hash_length(32)
            .to_state();
        Blake2bSimple { state }
    }

    pub fn new_keyed(key: &[u8]) -> Self {
        assert!(key.len() <= 64, "Blake2b key must be <= 64 bytes");
        let state = blake2b_simd::Params::new()
            .hash_length(32)
            .key(key)
            .to_state();
        Blake2bSimple { state }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        let hash = self.state.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify unkeyed Blake2b-256 of empty string.
    /// dkLen=32 gives a different hash than dkLen=64 (RFC 7693 default).
    #[test]
    fn blake2b_256_empty() {
        let h = blake2b_256(b"");
        let hex_str = hex::encode(h);
        // Blake2b with digest_length=32 of empty string
        assert_eq!(
            hex_str,
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
    }

    /// Verify Blake2b-256 of "test" against known value.
    #[test]
    fn blake2b_256_test() {
        let h = blake2b_256(b"test");
        let hex_str = hex::encode(h);
        assert_eq!(
            hex_str,
            "928b20366943e2afd11ebc0eae2e53a93bf177a4fcf35bcc64d503704e65e202"
        );
    }

    /// Verify keyed Blake2b works (key="CovenantID", data=zeros).
    #[test]
    fn blake2b_keyed_nonzero() {
        let mut h = Blake2bSimple::new_keyed(b"CovenantID");
        h.update(&[0u8; 32]);
        let result = h.finalize();
        assert_ne!(result, [0u8; 32], "keyed hash must not be zero");
    }

    /// Verify P2SH SPK structure: [0xaa, 0x20, <32-byte hash>, 0x87]
    #[test]
    fn build_p2sh_structure() {
        let rs = vec![0x51]; // minimal redeemScript: Op1
        let spk = build_p2sh(&rs);
        assert_eq!(spk.version(), 0);
        assert_eq!(spk.script().len(), 35);
        assert_eq!(spk.script()[0], 0xaa, "first byte must be OpBlake2b");
        assert_eq!(spk.script()[1], 0x20, "second byte must be push32");
        assert_eq!(spk.script()[34], 0x87, "last byte must be OpEqual");
    }

    /// Verify compute_p2pk_spk_hash produces consistent 32-byte hash.
    #[test]
    fn p2pk_spk_hash_consistency() {
        let pk = [0x02u8; 32];
        let h1 = compute_p2pk_spk_hash(&pk);
        let h2 = compute_p2pk_spk_hash(&pk);
        assert_eq!(h1, h2, "SPK hash must be deterministic");
        assert_ne!(h1, [0u8; 32], "SPK hash must not be zero");

        // Verify it equals blake2b(version_u16LE + script)
        let mut spk_bytes = Vec::new();
        spk_bytes.extend_from_slice(&0u16.to_le_bytes()); // version 0
        spk_bytes.push(0x20);
        spk_bytes.extend_from_slice(&pk);
        spk_bytes.push(0xac);
        let expected = blake2b_256(&spk_bytes);
        assert_eq!(h1, expected, "SPK hash must match manual computation");
    }

    /// Verify compute_spk_hash works for arbitrary version/script.
    #[test]
    fn spk_hash_arbitrary_version() {
        let mut script = vec![0x20];
        script.extend_from_slice(&[0xAA; 33]);
        let h1 = compute_spk_hash(0, &script);
        let h2 = compute_spk_hash(1, &script);
        assert_ne!(h1, h2, "Different versions must produce different hashes");
    }

    /// Verify P2SH: hash of a known redeemScript.
    #[test]
    fn build_p2sh_hash_consistency() {
        let rs = vec![0x75, 0x75, 0x75, 0x75, 0x51]; // trade_receipt body
        let spk1 = build_p2sh(&rs);
        let spk2 = build_p2sh(&rs);
        assert_eq!(spk1.script(), spk2.script(), "P2SH must be deterministic");

        // The inner hash should match blake2b_256(rs)
        let expected_hash = blake2b_256(&rs);
        assert_eq!(&spk1.script()[2..34], &expected_hash);
    }
}
