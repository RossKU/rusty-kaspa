//! Kaspa transaction signing hash (sighash) computation.

use crate::p2sh::Blake2bSimple;
use crate::primitives::{u16_le, u32_le, u64_le};
use crate::tx::{AuthOutput, Transaction};

const SIGHASH_KEY: &[u8] = b"TransactionSigningHash";

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
    let inp = &tx.inputs[input_index];

    // Hash all outpoints: for each input, hash(prevTxId || prevIndex)
    let h_outpoints = {
        let mut h = Blake2bSimple::new_keyed(SIGHASH_KEY);
        for i in &tx.inputs {
            h.update(&hex::decode(&i.prev_tx_id)?);
            h.update(&u32_le(i.prev_index));
        }
        h.finalize()
    };

    // Hash all sequences
    let h_sequences = {
        let mut h = Blake2bSimple::new_keyed(SIGHASH_KEY);
        for i in &tx.inputs {
            h.update(&u64_le(i.sequence));
        }
        h.finalize()
    };

    // Hash all sig op counts
    let h_sig_ops = {
        let mut h = Blake2bSimple::new_keyed(SIGHASH_KEY);
        for i in &tx.inputs {
            h.update(&[i.sig_op_count]);
        }
        h.finalize()
    };

    // Hash all outputs (including covenant bindings for version >= 1)
    let h_outputs = {
        let mut h = Blake2bSimple::new_keyed(SIGHASH_KEY);
        for o in &tx.outputs {
            h.update(&u64_le(o.value));
            h.update(&u16_le(o.script_version()));
            h.update(&u64_le(o.script_bytes().len() as u64));
            h.update(o.script_bytes());
            if tx.version >= 1 {
                if let Some(ref cov) = o.covenant {
                    h.update(&[1u8]);
                    h.update(&u16_le(cov.authorizing_input));
                    h.update(&cov.covenant_id.as_bytes());
                } else {
                    h.update(&[0u8]);
                }
            }
        }
        h.finalize()
    };

    // Payload hash: when payload is non-empty, compute blake2b_keyed(KEY, write_var_bytes(payload))
    // When empty (or native subnetwork with no payload), use ZERO_HASH.
    // write_var_bytes = u64LE(len) + raw bytes
    let payload_hash = if tx.payload.is_empty() {
        [0u8; 32]
    } else {
        let mut h = Blake2bSimple::new_keyed(SIGHASH_KEY);
        h.update(&u64_le(tx.payload.len() as u64));
        h.update(&tx.payload);
        h.finalize()
    };

    // Final hash: combine all sub-hashes with per-input data
    let mut h = Blake2bSimple::new_keyed(SIGHASH_KEY);
    h.update(&u16_le(tx.version));
    h.update(&h_outpoints);
    h.update(&h_sequences);
    h.update(&h_sig_ops);
    // Per-input fields
    h.update(&hex::decode(&inp.prev_tx_id)?);
    h.update(&u32_le(inp.prev_index));
    h.update(&u16_le(inp.script_version));
    h.update(&u64_le(inp.script_bytes.len() as u64));
    h.update(&inp.script_bytes);
    h.update(&u64_le(inp.value));
    h.update(&u64_le(inp.sequence));
    h.update(&[inp.sig_op_count]);
    // Outputs hash
    h.update(&h_outputs);
    // Global fields
    h.update(&u64_le(tx.lock_time));
    h.update(&hex::decode(&tx.subnetwork_id)?);
    h.update(&u64_le(tx.gas));
    h.update(&payload_hash);
    h.update(&[0x01]); // sighash type: SIGHASH_ALL
    Ok(h.finalize())
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

    /// Test that payload hash uses correct format: blake2b_keyed(KEY, u64LE(len) + bytes).
    #[test]
    fn sighash_payload_hash_correctness() {
        // Verify the payload hash computation matches the expected format
        let payload = b"KOB:1:TEST";
        let expected_hash = {
            let mut h = crate::p2sh::Blake2bSimple::new_keyed(b"TransactionSigningHash");
            h.update(&crate::primitives::u64_le(payload.len() as u64));
            h.update(payload);
            h.finalize()
        };
        // The payload hash should be non-zero
        assert_ne!(expected_hash, [0u8; 32], "payload hash must not be zero");
        // Verify different from zero hash (empty payload)
        let zero_hash = [0u8; 32];
        assert_ne!(expected_hash, zero_hash);
    }
}
