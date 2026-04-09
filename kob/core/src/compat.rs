//! Conversion helpers between KOB hex-string types and kaspa-consensus-core types.
//!
//! KOB uses hex strings for transaction IDs, covenant IDs, and subnetwork IDs
//! because the Kaspa JSON-RPC wire format uses hex encoding. Kaspad uses
//! fixed-size byte arrays (`Hash`, `TransactionId`, `SubnetworkId`).
//!
//! This module provides zero-cost-ish conversions between the two representations.

use kaspa_consensus_core::subnets::SubnetworkId;
use kaspa_consensus_core::tx::{
    ScriptPublicKey, TransactionId, TransactionOutpoint,
};
use kaspa_hashes::Hash;

/// Parse a 64-char hex string into a `TransactionId` (`Hash`).
pub fn parse_tx_id(hex: &str) -> crate::Result<TransactionId> {
    parse_hash(hex)
}

/// Convert a `TransactionId` to a 64-char lowercase hex string.
pub fn tx_id_to_hex(id: &TransactionId) -> String {
    hash_to_hex(id)
}

/// Parse a 64-char hex string into a `Hash`.
pub fn parse_hash(hex: &str) -> crate::Result<Hash> {
    let bytes = hex::decode(hex).map_err(|e| {
        crate::KobError::Transaction(format!("invalid hex for Hash: {}", e))
    })?;
    if bytes.len() != 32 {
        return Err(crate::KobError::Transaction(format!(
            "expected 32 bytes for Hash, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Hash::from_bytes(arr))
}

/// Convert a `Hash` to a 64-char lowercase hex string.
pub fn hash_to_hex(h: &Hash) -> String {
    hex::encode(h.as_bytes())
}

/// Parse a 40-char hex string into a `SubnetworkId`.
pub fn parse_subnetwork_id(hex: &str) -> crate::Result<SubnetworkId> {
    let bytes = hex::decode(hex).map_err(|e| {
        crate::KobError::Transaction(format!("invalid hex for SubnetworkId: {}", e))
    })?;
    if bytes.len() != 20 {
        return Err(crate::KobError::Transaction(format!(
            "expected 20 bytes for SubnetworkId, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&bytes);
    Ok(SubnetworkId::from_bytes(arr))
}

/// Convert a `SubnetworkId` to a 40-char lowercase hex string.
pub fn subnetwork_id_to_hex(id: &SubnetworkId) -> String {
    hex::encode(id.as_ref() as &[u8])
}

/// Build a `TransactionOutpoint` from hex txid + index.
pub fn parse_outpoint(tx_id_hex: &str, index: u32) -> crate::Result<TransactionOutpoint> {
    let id = parse_tx_id(tx_id_hex)?;
    Ok(TransactionOutpoint::new(id, index))
}

/// Convert a `TransactionOutpoint` to `(hex_txid, index)`.
pub fn outpoint_to_hex(op: &TransactionOutpoint) -> (String, u32) {
    (tx_id_to_hex(&op.transaction_id), op.index)
}

/// Build a `ScriptPublicKey` from version + script bytes.
pub fn build_spk(version: u16, script: Vec<u8>) -> ScriptPublicKey {
    ScriptPublicKey::new(version, script.into())
}

/// Build a `CovenantBinding` from a hex covenant ID string.
///
/// Convenience for migration: callers that had `CovenantBinding { authorizing_input, covenant_id: hex }`
/// can use `covenant_binding_from_hex(auth_input, &hex)` instead.
pub fn covenant_binding_from_hex(
    authorizing_input: u16,
    covenant_id_hex: &str,
) -> crate::Result<kaspa_consensus_core::tx::CovenantBinding> {
    let id = parse_hash(covenant_id_hex)?;
    Ok(kaspa_consensus_core::tx::CovenantBinding::new(authorizing_input, id))
}

/// Convert KOB's `types::Outpoint` to kaspad's `TransactionOutpoint`.
pub fn kob_outpoint_to_kaspa(op: &crate::types::Outpoint) -> crate::Result<TransactionOutpoint> {
    parse_outpoint(&op.transaction_id, op.index)
}

/// Convert kaspad's `TransactionOutpoint` to KOB's `types::Outpoint`.
pub fn kaspa_outpoint_to_kob(op: &TransactionOutpoint) -> crate::types::Outpoint {
    let (hex, index) = outpoint_to_hex(op);
    crate::types::Outpoint {
        transaction_id: hex,
        index,
    }
}

/// Convert a KOB `Transaction` into a kaspad `Transaction` and a `Vec<UtxoEntry>`.
///
/// The kaspad `Transaction` is suitable for sighash computation (via
/// `PopulatedTransaction`). The returned `UtxoEntry` vec contains one entry per
/// input, built from the KOB input's `value`, `script_version`, and `script_bytes`.
///
/// Fields that are not relevant for sighash (`block_daa_score`, `is_coinbase`,
/// `covenant_id`) are set to their zero/false/None defaults.
pub fn to_kaspa_transaction(
    tx: &crate::tx::Transaction,
) -> crate::Result<(
    kaspa_consensus_core::tx::Transaction,
    Vec<kaspa_consensus_core::tx::UtxoEntry>,
)> {
    use kaspa_consensus_core::tx::{
        Transaction as KaspaTransaction, TransactionInput, TransactionOutput,
        TransactionOutpoint, UtxoEntry,
    };

    // Build kaspad inputs
    let inputs: Vec<TransactionInput> = tx
        .inputs
        .iter()
        .map(|inp| {
            let tx_id = parse_tx_id(&inp.prev_tx_id)?;
            Ok(TransactionInput::new(
                TransactionOutpoint::new(tx_id, inp.prev_index),
                vec![], // signature_script is empty at sighash time
                inp.sequence,
                inp.sig_op_count,
            ))
        })
        .collect::<crate::Result<Vec<_>>>()?;

    // Build kaspad outputs
    let outputs: Vec<TransactionOutput> = tx
        .outputs
        .iter()
        .map(|out| TransactionOutput::with_covenant(
            out.value,
            out.script_public_key.clone(),
            out.covenant,
        ))
        .collect();

    // Build UTXO entries from KOB input data
    let entries: Vec<UtxoEntry> = tx
        .inputs
        .iter()
        .map(|inp| UtxoEntry {
            amount: inp.value,
            script_public_key: ScriptPublicKey::new(inp.script_version, inp.script_bytes.clone().into()),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        })
        .collect();

    let subnetwork_id = parse_subnetwork_id(&tx.subnetwork_id)?;
    let kaspa_tx = KaspaTransaction::new(
        tx.version,
        inputs,
        outputs,
        tx.lock_time,
        subnetwork_id,
        tx.gas,
        tx.payload.clone(),
    );

    Ok((kaspa_tx, entries))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_tx_id() {
        let hex = "a".repeat(64);
        let id = parse_tx_id(&hex).unwrap();
        assert_eq!(tx_id_to_hex(&id), hex);
    }

    #[test]
    fn roundtrip_subnetwork_id() {
        let hex = "0".repeat(40);
        let id = parse_subnetwork_id(&hex).unwrap();
        assert_eq!(subnetwork_id_to_hex(&id), hex);
    }

    #[test]
    fn roundtrip_outpoint() {
        let tx_hex = "b".repeat(64);
        let op = parse_outpoint(&tx_hex, 3).unwrap();
        let (hex_back, idx) = outpoint_to_hex(&op);
        assert_eq!(hex_back, tx_hex);
        assert_eq!(idx, 3);
    }

    #[test]
    fn kob_kaspa_outpoint_roundtrip() {
        let kob_op = crate::types::Outpoint {
            transaction_id: "c".repeat(64),
            index: 7,
        };
        let kaspa_op = kob_outpoint_to_kaspa(&kob_op).unwrap();
        let kob_op2 = kaspa_outpoint_to_kob(&kaspa_op);
        assert_eq!(kob_op, kob_op2);
    }

    #[test]
    fn parse_hash_invalid() {
        assert!(parse_hash("not_hex").is_err());
        assert!(parse_hash("aabb").is_err()); // too short
    }
}
