//! Kaspa transaction signing hash (sighash) computation.
//!
//! Delegates to kaspad's `calc_schnorr_signature_hash` via the compat layer.
//! The KOB `Transaction` is converted to kaspad types, then kaspad computes
//! the sighash. This guarantees exact hash compatibility with the network.

use crate::compat;
use crate::p2sh::Blake2bSimple;
use crate::primitives::{u16_le, u32_le, u64_le};
use crate::tx::{AuthOutput, Transaction};

use kaspa_consensus_core::hashing::sighash::{
    calc_schnorr_signature_hash, SigHashReusedValuesUnsync,
};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::PopulatedTransaction;

/// Compute the Kaspa transaction signing hash for a specific input.
///
/// Returns a 32-byte hash that must be signed with Schnorr to produce a valid signature.
pub fn compute_sighash(tx: &Transaction, input_index: usize) -> crate::Result<[u8; 32]> {
    if tx.inputs.is_empty() {
        return Err(crate::KobError::Transaction("transaction has no inputs".into()));
    }
    if tx.outputs.is_empty() {
        return Err(crate::KobError::Transaction("transaction has no outputs".into()));
    }
    if input_index >= tx.inputs.len() {
        return Err(crate::KobError::Transaction(format!(
            "sighash input_index {} out of bounds (tx has {} inputs)",
            input_index, tx.inputs.len()
        )));
    }

    let (kaspa_tx, entries) = compat::to_kaspa_transaction(tx)?;
    let populated = PopulatedTransaction::new(&kaspa_tx, entries);
    let reused = SigHashReusedValuesUnsync::new();
    let hash = calc_schnorr_signature_hash(&populated, input_index, SIG_HASH_ALL, &reused);

    Ok(hash.as_bytes())
}

/// Compute covenant ID from genesis outpoint and authorized outputs.
///
/// Uses keyed Blake2b with key "CovenantID" and dkLen=32.
///
/// Matches the JS implementation:
/// ```js
/// const h = blake2b.create({ dkLen: 32, key: Buffer.from('CovenantID') });
/// h.update(Buffer.from(genesisTxId, 'hex'));
/// h.update(u32LE(genesisIndex));
/// h.update(u64LE(authOutputs.length));
/// for (const ao of authOutputs) { ... }
/// ```
pub fn compute_covenant_id(
    genesis_tx_id: &str,
    genesis_index: u32,
    auth_outputs: &[AuthOutput],
) -> crate::Result<[u8; 32]> {
    let mut h = Blake2bSimple::new_keyed(b"CovenantID");
    h.update(&hex::decode(genesis_tx_id)?);
    h.update(&u32_le(genesis_index));
    h.update(&u64_le(auth_outputs.len() as u64));
    for ao in auth_outputs {
        h.update(&u32_le(ao.index));
        h.update(&u64_le(ao.value));
        h.update(&u16_le(ao.spk_version));
        h.update(&u64_le(ao.spk_script.len() as u64));
        h.update(&ao.spk_script);
    }
    Ok(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::{TxInput, TxOutput};

    /// Test sighash of a minimal version-0 transaction with 1 input, 1 output, no covenant.
    #[test]
    fn sighash_deterministic() {
        let tx = Transaction {
            version: 0,
            inputs: vec![TxInput {
                prev_tx_id: "a".repeat(64),
                prev_index: 0,
                sequence: 0,
                sig_op_count: 1,
                script_version: 0,
                script_bytes: vec![0xaa, 0x20],
                value: 1_000_000,
            }],
            outputs: vec![TxOutput {
                value: 990_000,
                script_public_key: kaspa_consensus_core::tx::ScriptPublicKey::new(0, vec![0xaa, 0x20].into()),
                covenant: None,
            }],
            lock_time: 0,
            subnetwork_id: "0000000000000000000000000000000000000000".to_string(),
            gas: 0,
            payload: vec![],
        };

        let hash1 = compute_sighash(&tx, 0).unwrap();
        let hash2 = compute_sighash(&tx, 0).unwrap();
        assert_eq!(hash1, hash2, "sighash must be deterministic");
        assert_ne!(hash1, [0u8; 32], "sighash must not be zero");
    }

    /// Test that different inputs produce different sighashes.
    #[test]
    fn sighash_input_sensitivity() {
        let make_tx = |value: u64| Transaction {
            version: 0,
            inputs: vec![TxInput {
                prev_tx_id: "b".repeat(64),
                prev_index: 0,
                sequence: 0,
                sig_op_count: 1,
                script_version: 0,
                script_bytes: vec![0xaa],
                value,
            }],
            outputs: vec![TxOutput {
                value: 500_000,
                script_public_key: kaspa_consensus_core::tx::ScriptPublicKey::new(0, vec![0xaa].into()),
                covenant: None,
            }],
            lock_time: 0,
            subnetwork_id: "0000000000000000000000000000000000000000".to_string(),
            gas: 0,
            payload: vec![],
        };

        let h1 = compute_sighash(&make_tx(1_000_000), 0).unwrap();
        let h2 = compute_sighash(&make_tx(2_000_000), 0).unwrap();
        assert_ne!(h1, h2, "different values must produce different sighashes");
    }

    /// Test covenant ID computation is deterministic and non-zero.
    #[test]
    fn covenant_id_deterministic() {
        let tx_id = "c".repeat(64);
        let auth = vec![AuthOutput {
            index: 0,
            value: 3_500_000,
            spk_version: 0,
            spk_script: vec![0xaa, 0x20, 0x00, 0x87],
        }];
        let id1 = compute_covenant_id(&tx_id, 0, &auth).unwrap();
        let id2 = compute_covenant_id(&tx_id, 0, &auth).unwrap();
        assert_eq!(id1, id2);
        assert_ne!(id1, [0u8; 32]);
    }

    /// Test version >= 1 includes covenant bindings in output hash.
    #[test]
    fn sighash_v1_covenant() {
        let make_tx = |version: u16, covenant: bool| {
            let cov = if covenant {
                Some(crate::tx::CovenantBinding::new(
                    0,
                    crate::compat::parse_hash(&"d".repeat(64)).unwrap(),
                ))
            } else {
                None
            };
            Transaction {
                version,
                inputs: vec![TxInput {
                    prev_tx_id: "e".repeat(64),
                    prev_index: 0,
                    sequence: 0,
                    sig_op_count: 1,
                    script_version: 0,
                    script_bytes: vec![0xaa],
                    value: 1_000_000,
                }],
                outputs: vec![TxOutput {
                    value: 900_000,
                    script_public_key: kaspa_consensus_core::tx::ScriptPublicKey::new(0, vec![0xaa].into()),
                    covenant: cov,
                }],
                lock_time: 0,
                subnetwork_id: "0000000000000000000000000000000000000000".to_string(),
                gas: 0,
                payload: vec![],
            }
        };

        // Version 0: covenant field is NOT included in hash
        let h0_with = compute_sighash(&make_tx(0, true), 0).unwrap();
        let h0_without = compute_sighash(&make_tx(0, false), 0).unwrap();
        assert_eq!(h0_with, h0_without, "v0 ignores covenant bindings");

        // Version 1: covenant field IS included in hash
        let h1_with = compute_sighash(&make_tx(1, true), 0).unwrap();
        let h1_without = compute_sighash(&make_tx(1, false), 0).unwrap();
        assert_ne!(h1_with, h1_without, "v1 must include covenant bindings");
    }

    /// Test that non-empty payload produces a different sighash than empty payload.
    #[test]
    fn sighash_payload_sensitivity() {
        let make_tx = |payload: Vec<u8>| Transaction {
            version: 0,
            inputs: vec![TxInput {
                prev_tx_id: "a".repeat(64),
                prev_index: 0,
                sequence: 0,
                sig_op_count: 1,
                script_version: 0,
                script_bytes: vec![0xaa, 0x20],
                value: 1_000_000,
            }],
            outputs: vec![TxOutput {
                value: 990_000,
                script_public_key: kaspa_consensus_core::tx::ScriptPublicKey::new(0, vec![0xaa, 0x20].into()),
                covenant: None,
            }],
            lock_time: 0,
            subnetwork_id: "0000000000000000000000000000000000000000".to_string(),
            gas: 0,
            payload,
        };

        let empty = compute_sighash(&make_tx(vec![]), 0).unwrap();
        let with_payload = compute_sighash(&make_tx(b"KOB:1:TEST".to_vec()), 0).unwrap();
        assert_ne!(empty, with_payload, "non-empty payload must produce different sighash");

        // Different payloads must produce different sighashes
        let payload_a = compute_sighash(&make_tx(b"KOB:1:A".to_vec()), 0).unwrap();
        let payload_b = compute_sighash(&make_tx(b"KOB:1:B".to_vec()), 0).unwrap();
        assert_ne!(payload_a, payload_b, "different payloads must produce different sighashes");

        // Empty payload deterministic
        let empty2 = compute_sighash(&make_tx(vec![]), 0).unwrap();
        assert_eq!(empty, empty2, "empty payload sighash must be deterministic");
    }

    /// Cross-verify: compute sighash via kaspad's known test vectors.
    ///
    /// This uses the same transaction from kaspad's own sighash test to verify
    /// that KOB's conversion + delegation produces the correct hash.
    #[test]
    fn sighash_cross_verify_with_kaspad_test_vector() {
        // Reproduce the native-all-0 test vector from kaspad's sighash.rs
        let prev_tx_id = "880eb9819a31821d9d2399e2f35e2433b72637e393d71ecc9b8d0250f49153c3";
        let spk1_hex = "208325613d2eeaf7176ac6c670b13c0043156c427438ed72d74b7800862ad884e8ac";
        let spk2_hex = "20fcef4c106cf11135bbd70f02a726a92162d2fb8b22f0469126f800862ad884e8ac";
        let spk1 = hex::decode(spk1_hex).unwrap();
        let spk2 = hex::decode(spk2_hex).unwrap();

        let tx = Transaction {
            version: 0,
            inputs: vec![
                TxInput {
                    prev_tx_id: prev_tx_id.to_string(),
                    prev_index: 0,
                    sequence: 0,
                    sig_op_count: 0,
                    script_version: 0,
                    script_bytes: spk1.clone(),
                    value: 100,
                },
                TxInput {
                    prev_tx_id: prev_tx_id.to_string(),
                    prev_index: 1,
                    sequence: 1,
                    sig_op_count: 0,
                    script_version: 0,
                    script_bytes: spk2.clone(),
                    value: 200,
                },
                TxInput {
                    prev_tx_id: prev_tx_id.to_string(),
                    prev_index: 2,
                    sequence: 2,
                    sig_op_count: 0,
                    script_version: 0,
                    script_bytes: spk2.clone(),
                    value: 300,
                },
            ],
            outputs: vec![
                TxOutput {
                    value: 300,
                    script_public_key: kaspa_consensus_core::tx::ScriptPublicKey::new(0, spk2.clone().into()),
                    covenant: None,
                },
                TxOutput {
                    value: 300,
                    script_public_key: kaspa_consensus_core::tx::ScriptPublicKey::new(0, spk1.clone().into()),
                    covenant: None,
                },
            ],
            lock_time: 1615462089000,
            subnetwork_id: "0000000000000000000000000000000000000000".to_string(),
            gas: 0,
            payload: vec![],
        };

        let hash = compute_sighash(&tx, 0).unwrap();
        let hash_hex = hex::encode(hash);
        assert_eq!(
            hash_hex,
            "03b7ac6927b2b67100734c3cc313ff8c2e8b3ce3e746d46dd660b706a916b1f5",
            "KOB sighash must match kaspad's native-all-0 test vector"
        );
    }
}
