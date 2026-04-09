//! ZK proof support for OpZkPrecompile (0xa6) freezable token covenants.

pub mod circuit;
pub mod freezable;
pub mod merkle;
pub mod prover;
pub mod sigscript;
pub mod verifier;

use std::fmt;

/// OpZkPrecompile opcode byte.
pub const OP_ZK_PRECOMPILE: u8 = 0xa6;

/// Tag bytes identifying the proof system.
pub const TAG_GROTH16: u8 = 0x20;
pub const TAG_RISC_ZERO: u8 = 0x21;

/// Check whether a redeemScript contains the ZK precompile opcode at all,
/// regardless of whether the tag is recognized.
pub fn has_zk_opcode(redeem_script: &[u8]) -> bool {
    redeem_script.contains(&OP_ZK_PRECOMPILE)
}

/// Supported ZK proof systems.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZkProofSystem {
    /// Groth16 over BN254 — tag 0x20, 140 sigops
    Groth16,
    /// RISC Zero zkVM — tag 0x21, 250 sigops
    RiscZero,
}

impl ZkProofSystem {
    /// Returns the on-chain tag byte for this proof system.
    pub fn tag(&self) -> u8 {
        match self {
            ZkProofSystem::Groth16 => TAG_GROTH16,
            ZkProofSystem::RiscZero => TAG_RISC_ZERO,
        }
    }

    /// Sigop cost for this proof system.
    pub fn sigops(&self) -> u32 {
        match self {
            ZkProofSystem::Groth16 => 140,
            ZkProofSystem::RiscZero => 250,
        }
    }

    /// Parse a tag byte into a proof system, if recognized.
    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            TAG_GROTH16 => Some(ZkProofSystem::Groth16),
            TAG_RISC_ZERO => Some(ZkProofSystem::RiscZero),
            _ => None,
        }
    }
}

impl fmt::Display for ZkProofSystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZkProofSystem::Groth16 => write!(f, "Groth16/BN254"),
            ZkProofSystem::RiscZero => write!(f, "RISC Zero"),
        }
    }
}

/// A request to generate a ZK proof.
#[derive(Debug, Clone)]
pub struct ZkProofRequest {
    /// Proof system tag (0x20 or 0x21).
    pub tag: u8,
    /// Public inputs to the circuit (serialized field elements).
    pub public_inputs: Vec<u8>,
    /// Verification key bytes.
    pub verification_key: Vec<u8>,
}

/// Result of proof generation.
#[derive(Debug, Clone)]
pub struct ZkProofResult {
    /// Raw proof bytes (Groth16: ~192 bytes, RISC Zero: variable).
    pub proof: Vec<u8>,
}

/// Trait for ZK proof generators.
#[allow(async_fn_in_trait)]
pub trait ZkProver: Send + Sync {
    /// Generate a ZK proof for the given request.
    async fn generate_proof(&self, request: &ZkProofRequest) -> Result<ZkProofResult, ZkError>;
}

/// Errors from ZK operations.
#[derive(Debug, Clone)]
pub enum ZkError {
    /// No prover backend is configured.
    NoProverConfigured,
    /// The proof system tag is not recognized.
    UnsupportedProofSystem(u8),
    /// Proof generation failed.
    ProofGenerationFailed(String),
    /// Blacklist check failed.
    BlacklistCheckFailed(String),
}

impl fmt::Display for ZkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZkError::NoProverConfigured => write!(f, "no ZK prover backend configured"),
            ZkError::UnsupportedProofSystem(tag) => {
                write!(f, "unsupported ZK proof system tag: 0x{:02x}", tag)
            }
            ZkError::ProofGenerationFailed(msg) => {
                write!(f, "ZK proof generation failed: {}", msg)
            }
            ZkError::BlacklistCheckFailed(msg) => {
                write!(f, "blacklist check failed: {}", msg)
            }
        }
    }
}

impl std::error::Error for ZkError {}

/// Stub prover that returns `ZkError::NoProverConfigured` for every request.
pub struct StubProver;

impl ZkProver for StubProver {
    async fn generate_proof(&self, _request: &ZkProofRequest) -> Result<ZkProofResult, ZkError> {
        Err(ZkError::NoProverConfigured)
    }
}

/// Scan a redeemScript for the OpZkPrecompile opcode (0xa6).
///
/// Returns `Some(ZkProofSystem)` if a recognized tag+opcode pair is found,
/// `None` otherwise.
pub fn detect_zk_opcode(redeem_script: &[u8]) -> Option<ZkProofSystem> {
    for i in 0..redeem_script.len() {
        if redeem_script[i] == OP_ZK_PRECOMPILE && i > 0 {
            let tag = redeem_script[i - 1];
            if let Some(system) = ZkProofSystem::from_tag(tag) {
                return Some(system);
            }
        }
    }
    None
}

/// Push data with minimal pushdata encoding (Bitcoin/Kaspa convention).
pub fn push_data(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len == 0 {
        buf.push(0x00); // OP_0
    } else if len <= 75 {
        buf.push(len as u8);
        buf.extend_from_slice(data);
    } else if len <= 255 {
        buf.push(0x4c); // OP_PUSHDATA1
        buf.push(len as u8);
        buf.extend_from_slice(data);
    } else if len <= 65535 {
        buf.push(0x4d); // OP_PUSHDATA2
        buf.extend_from_slice(&(len as u16).to_le_bytes());
        buf.extend_from_slice(data);
    } else {
        buf.push(0x4e); // OP_PUSHDATA4
        buf.extend_from_slice(&(len as u32).to_le_bytes());
        buf.extend_from_slice(data);
    }
}

/// Build a sigscript for spending a UTXO guarded by OpZkPrecompile.
pub fn build_zk_sigscript(
    proof: &ZkProofResult,
    request: &ZkProofRequest,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig = Vec::new();
    push_data(&mut sig, &[request.tag]);
    push_data(&mut sig, &proof.proof);
    push_data(&mut sig, &request.public_inputs);
    push_data(&mut sig, &request.verification_key);
    push_data(&mut sig, redeem_script);
    sig
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- detect_zk_opcode ---

    #[test]
    fn detect_groth16_opcode() {
        let rs = vec![0x51, 0x52, TAG_GROTH16, OP_ZK_PRECOMPILE, 0x87];
        assert_eq!(detect_zk_opcode(&rs), Some(ZkProofSystem::Groth16));
    }

    #[test]
    fn detect_risc_zero_opcode() {
        let rs = vec![0x51, TAG_RISC_ZERO, OP_ZK_PRECOMPILE, 0x87];
        assert_eq!(detect_zk_opcode(&rs), Some(ZkProofSystem::RiscZero));
    }

    #[test]
    fn detect_no_zk_opcode_in_normal_script() {
        let rs = vec![0xb9, 0xc9, 0x76, 0x02, 0x77, 0x01, 0x9f, 0x63];
        assert_eq!(detect_zk_opcode(&rs), None);
    }

    #[test]
    fn detect_unknown_tag_returns_none() {
        let rs = vec![0x51, 0xff, OP_ZK_PRECOMPILE, 0x87];
        assert_eq!(detect_zk_opcode(&rs), None);
    }

    #[test]
    fn detect_zk_at_start_of_script_returns_none() {
        let rs = vec![OP_ZK_PRECOMPILE, TAG_GROTH16];
        assert_eq!(detect_zk_opcode(&rs), None);
    }

    #[test]
    fn detect_empty_script() {
        assert_eq!(detect_zk_opcode(&[]), None);
    }

    // --- has_zk_opcode ---

    #[test]
    fn has_zk_opcode_positive() {
        let rs = vec![0x51, 0x20, OP_ZK_PRECOMPILE, 0x87];
        assert!(has_zk_opcode(&rs));
    }

    #[test]
    fn has_zk_opcode_negative() {
        let rs = vec![0x51, 0x52, 0x87];
        assert!(!has_zk_opcode(&rs));
    }

    // --- ZkProofSystem ---

    #[test]
    fn proof_system_tag_roundtrip() {
        assert_eq!(ZkProofSystem::from_tag(TAG_GROTH16), Some(ZkProofSystem::Groth16));
        assert_eq!(ZkProofSystem::from_tag(TAG_RISC_ZERO), Some(ZkProofSystem::RiscZero));
        assert_eq!(ZkProofSystem::from_tag(0x99), None);

        assert_eq!(ZkProofSystem::Groth16.tag(), TAG_GROTH16);
        assert_eq!(ZkProofSystem::RiscZero.tag(), TAG_RISC_ZERO);
    }

    #[test]
    fn proof_system_sigops() {
        assert_eq!(ZkProofSystem::Groth16.sigops(), 140);
        assert_eq!(ZkProofSystem::RiscZero.sigops(), 250);
    }

    // --- build_zk_sigscript ---

    #[test]
    fn build_sigscript_basic_structure() {
        let proof = ZkProofResult {
            proof: vec![0xaa; 32],
        };
        let request = ZkProofRequest {
            tag: TAG_GROTH16,
            public_inputs: vec![0xbb; 16],
            verification_key: vec![0xcc; 48],
        };
        let rs = vec![0x51, TAG_GROTH16, OP_ZK_PRECOMPILE, 0x87];

        let sig = build_zk_sigscript(&proof, &request, &rs);

        assert!(!sig.is_empty());
        assert_eq!(sig[0], 1);
        assert_eq!(sig[1], TAG_GROTH16);
        assert_eq!(sig[2], 32);
        assert_eq!(&sig[3..35], &[0xaa; 32]);
        assert_eq!(sig[35], 16);
        assert_eq!(&sig[36..52], &[0xbb; 16]);
        assert_eq!(sig[52], 48);
        assert_eq!(&sig[53..101], &[0xcc; 48]);
        assert_eq!(sig[101], 4);
        assert_eq!(&sig[102..106], &rs[..]);
    }

    #[test]
    fn build_sigscript_pushdata1_for_large_data() {
        let proof = ZkProofResult {
            proof: vec![0xaa; 192],
        };
        let request = ZkProofRequest {
            tag: TAG_GROTH16,
            public_inputs: vec![0xbb; 8],
            verification_key: vec![0xcc; 64],
        };
        let rs = vec![0x51, TAG_GROTH16, OP_ZK_PRECOMPILE, 0x87];

        let sig = build_zk_sigscript(&proof, &request, &rs);
        assert!(!sig.is_empty());
        assert_eq!(sig[2], 0x4c); // OP_PUSHDATA1
        assert_eq!(sig[3], 192);
        assert_eq!(&sig[4..196], &[0xaa; 192]);
    }

    // --- push_data encoding ---

    #[test]
    fn push_data_empty() {
        let mut buf = Vec::new();
        push_data(&mut buf, &[]);
        assert_eq!(buf, vec![0x00]);
    }

    #[test]
    fn push_data_small() {
        let mut buf = Vec::new();
        push_data(&mut buf, &[0x42, 0x43]);
        assert_eq!(buf, vec![2, 0x42, 0x43]);
    }

    #[test]
    fn push_data_boundary_75() {
        let data = vec![0xff; 75];
        let mut buf = Vec::new();
        push_data(&mut buf, &data);
        assert_eq!(buf[0], 75);
        assert_eq!(buf.len(), 76);
    }

    #[test]
    fn push_data_76_uses_pushdata1() {
        let data = vec![0xff; 76];
        let mut buf = Vec::new();
        push_data(&mut buf, &data);
        assert_eq!(buf[0], 0x4c);
        assert_eq!(buf[1], 76);
        assert_eq!(buf.len(), 78);
    }

    #[test]
    fn push_data_256_uses_pushdata2() {
        let data = vec![0xff; 256];
        let mut buf = Vec::new();
        push_data(&mut buf, &data);
        assert_eq!(buf[0], 0x4d);
        let len = u16::from_le_bytes([buf[1], buf[2]]);
        assert_eq!(len, 256);
        assert_eq!(buf.len(), 259);
    }

    // --- StubProver ---

    #[tokio::test]
    async fn stub_prover_returns_error() {
        let prover = StubProver;
        let request = ZkProofRequest {
            tag: TAG_GROTH16,
            public_inputs: vec![],
            verification_key: vec![],
        };
        let result = prover.generate_proof(&request).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ZkError::NoProverConfigured => {}
            other => panic!("expected NoProverConfigured, got: {:?}", other),
        }
    }

    // --- Display ---

    #[test]
    fn zk_error_display() {
        let e = ZkError::NoProverConfigured;
        assert!(e.to_string().contains("no ZK prover"));

        let e = ZkError::UnsupportedProofSystem(0xff);
        assert!(e.to_string().contains("0xff"));

        let e = ZkError::ProofGenerationFailed("timeout".into());
        assert!(e.to_string().contains("timeout"));
    }
}
