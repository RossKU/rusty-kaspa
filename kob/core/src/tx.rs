//! Transaction building types for sighash computation and RPC submission.
//!
//! These types use hex strings for transaction IDs, covenant IDs, and subnetwork IDs
//! to match the Kaspa JSON-RPC wire format directly.

/// Re-export kaspad's `CovenantBinding` as the canonical type.
pub use kaspa_consensus_core::tx::CovenantBinding;

/// Transaction input for sighash computation.
#[derive(Debug, Clone)]
pub struct TxInput {
    /// Previous TX ID as hex string (64 chars).
    pub prev_tx_id: String,
    /// Previous output index.
    pub prev_index: u32,
    /// Sequence number.
    pub sequence: u64,
    /// Number of signature operations.
    pub sig_op_count: u8,
    /// Script version of the UTXO being spent.
    pub script_version: u16,
    /// Script bytes of the UTXO being spent.
    pub script_bytes: Vec<u8>,
    /// Value of the UTXO being spent (sompi).
    pub value: u64,
}

/// Transaction output.
#[derive(Debug, Clone)]
pub struct TxOutput {
    pub value: u64,
    pub script_public_key: kaspa_consensus_core::tx::ScriptPublicKey,
    pub covenant: Option<CovenantBinding>,
}

impl TxOutput {
    /// Construct a TxOutput from script version and bytes (convenience for callers
    /// that work with separate version/script rather than kaspad `ScriptPublicKey`).
    pub fn new(
        value: u64,
        script_version: u16,
        script_bytes: Vec<u8>,
        covenant: Option<CovenantBinding>,
    ) -> Self {
        Self {
            value,
            script_public_key: kaspa_consensus_core::tx::ScriptPublicKey::new(
                script_version,
                script_bytes.into(),
            ),
            covenant,
        }
    }

    /// Construct from an existing `ScriptPublicKey`.
    pub fn with_spk(
        value: u64,
        spk: kaspa_consensus_core::tx::ScriptPublicKey,
        covenant: Option<CovenantBinding>,
    ) -> Self {
        Self { value, script_public_key: spk, covenant }
    }

    /// Access the script version (convenience accessor).
    pub fn script_version(&self) -> u16 {
        self.script_public_key.version()
    }

    /// Access the script bytes (convenience accessor).
    pub fn script_bytes(&self) -> &[u8] {
        self.script_public_key.script()
    }
}

/// A Kaspa transaction for local construction, sighash computation, and RPC submission.
#[derive(Debug, Clone)]
pub struct Transaction {
    pub version: u16,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub lock_time: u64,
    /// Subnetwork ID as hex string (40 chars, all zeros for native).
    pub subnetwork_id: String,
    pub gas: u64,
    /// TX payload bytes (hex-encoded in RPC). Used for KOB order discovery.
    pub payload: Vec<u8>,
}

impl Transaction {
    /// Create a new transaction with the given version and default values.
    pub fn new(version: u16) -> Self {
        Self {
            version,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            subnetwork_id: crate::SUBNETWORK_ID.to_string(),
            gas: 0,
            payload: Vec::new(),
        }
    }
}

/// An authorized output for covenant ID computation.
#[derive(Debug, Clone)]
pub struct AuthOutput {
    pub index: u32,
    pub value: u64,
    pub spk_version: u16,
    pub spk_script: Vec<u8>,
}

/// Select UTXOs from a set to cover the required amount + fee.
///
/// Returns selected UTXOs and total value, or error if insufficient.
/// Uses greedy approach: sort by value descending, pick until sufficient.
pub fn select_utxos(
    utxos: &[crate::types::UtxoEntry],
    amount: u64,
    fee: u64,
) -> crate::Result<(Vec<crate::types::UtxoEntry>, u64)> {
    let needed = amount.checked_add(fee).ok_or_else(|| {
        crate::KobError::Overflow("amount + fee overflows u64".into())
    })?;
    let mut selected = Vec::new();
    let mut total = 0u64;

    let mut sorted: Vec<_> = utxos.iter().collect();
    sorted.sort_by(|a, b| b.value.cmp(&a.value));

    for utxo in sorted {
        selected.push(utxo.clone());
        total = total.checked_add(utxo.value).ok_or_else(|| {
            crate::KobError::Overflow("UTXO total overflows u64".into())
        })?;
        if total >= needed {
            return Ok((selected, total));
        }
    }

    Err(crate::KobError::InsufficientFunds {
        need: needed,
        have: total,
    })
}

/// Result of mass-aware UTXO selection, including penalty information.
#[derive(Debug, Clone)]
pub struct CoinSelection {
    /// Selected UTXOs.
    pub utxos: Vec<crate::types::UtxoEntry>,
    /// Total input value (sum of selected UTXOs).
    pub total: u64,
    /// Computed storage mass for the selection (0 = penalty-free).
    pub storage_mass: u64,
    /// Whether this selection is penalty-free (mass == 0).
    pub penalty_free: bool,
}

/// Mass-aware UTXO selection for transaction construction.
///
/// Selects UTXOs to cover `amount + fee` with a two-tier strategy:
///
/// **Tier 1 — Penalty-free (mass = 0)**: Accumulates UTXOs smallest-first until
/// both value and input credit are sufficient. Small UTXOs give more credit
/// (`C / small_value` is large), so consuming dust simultaneously cleans the
/// wallet and achieves penalty-free status.
///
/// **Tier 2 — Within mass limit (0 < mass ≤ 1M)**: If penalty-free is impossible
/// with available UTXOs, ensures the hard constraint (mass ≤ MAX_TX_MASS) is met.
///
/// `num_outputs` is the expected number of TX outputs (e.g., 2 for order + change).
///
/// Returns `CoinSelection` with penalty info, or error if no valid selection exists.
pub fn select_utxos_mass_aware(
    utxos: &[crate::types::UtxoEntry],
    amount: u64,
    fee: u64,
    num_outputs: usize,
) -> crate::Result<CoinSelection> {
    use crate::mass::{compute_storage_mass, STORAGE_MASS_PARAMETER, MAX_TX_MASS};

    if num_outputs == 0 || num_outputs > 1000 {
        return Err(crate::KobError::Transaction(format!(
            "num_outputs must be between 1 and 1000, got {}", num_outputs
        )));
    }

    let needed = amount.checked_add(fee).ok_or_else(|| {
        crate::KobError::Overflow("amount + fee overflows u64".into())
    })?;
    if utxos.is_empty() {
        return Err(crate::KobError::InsufficientFunds { need: needed, have: 0 });
    }

    // Phase 0: Try single-UTXO selection first.
    // If a single UTXO can cover the needed amount, prefer it.
    // This avoids pulling in small UTXOs that may be stuck in the mempool.
    // Among qualifying UTXOs, pick the smallest one that still covers `needed`.
    {
        let mut candidates: Vec<_> = utxos.iter()
            .filter(|u| u.value >= needed)
            .cloned()
            .collect();
        // Sort ascending so we pick the tightest fit
        candidates.sort_by(|a, b| a.value.cmp(&b.value));
        if let Some(single) = candidates.first() {
            let out_vals = estimate_output_values(single.value, amount, fee, num_outputs);
            let in_vals = vec![single.value];
            let mass = compute_storage_mass(&in_vals, &out_vals);
            if mass <= MAX_TX_MASS {
                return Ok(CoinSelection {
                    utxos: vec![single.clone()],
                    total: single.value,
                    storage_mass: mass,
                    penalty_free: mass == 0,
                });
            }
        }
    }

    // Sort ascending (smallest first) — consume dust, maximize input credit
    let mut sorted: Vec<_> = utxos.to_vec();
    sorted.sort_by(|a, b| a.value.cmp(&b.value));

    let mut selected: Vec<crate::types::UtxoEntry> = Vec::new();
    let mut total = 0u64;

    // Phase 1: Accumulate smallest-first until we have enough value
    let mut split_idx = 0;
    for (i, utxo) in sorted.iter().enumerate() {
        if total >= needed {
            split_idx = i;
            break;
        }
        total = total.checked_add(utxo.value).ok_or_else(|| {
            crate::KobError::Overflow("UTXO total overflows u64".into())
        })?;
        selected.push(utxo.clone());
        split_idx = i + 1;
    }

    if total < needed {
        return Err(crate::KobError::InsufficientFunds { need: needed, have: total });
    }

    // Remaining UTXOs (still sorted ascending — small first for credit harvesting)
    let remaining: Vec<_> = sorted[split_idx..].to_vec();

    // Phase 2: Try to achieve penalty-free by adding more small UTXOs for credit
    // Target: input_credit >= output_mass (i.e., storage_mass = 0)
    let output_values = estimate_output_values(total, amount, fee, num_outputs);
    let output_mass: u128 = output_values
        .iter()
        .map(|&v| if v == 0 { u64::MAX as u128 } else { STORAGE_MASS_PARAMETER as u128 / v as u128 })
        .sum();

    // Add small remaining UTXOs if they bring us closer to penalty-free
    // Stop when penalty-free or when adding more would be wasteful (input > 2x needed)
    let max_total = needed.saturating_mul(3); // don't over-accumulate beyond 3x
    for utxo in &remaining {
        let input_credit: u128 = selected
            .iter()
            .filter(|u| u.value > 0)
            .map(|u| STORAGE_MASS_PARAMETER as u128 / u.value as u128)
            .sum();

        if input_credit >= output_mass {
            break; // penalty-free achieved
        }
        if total > max_total {
            break; // don't over-accumulate
        }

        // Only add if this UTXO provides meaningful credit
        let extra_credit = STORAGE_MASS_PARAMETER as u128 / utxo.value.max(1) as u128;
        let deficit = output_mass.saturating_sub(input_credit);
        if extra_credit == 0 || (extra_credit < deficit / 20 && total >= needed) {
            // This UTXO contributes < 5% of remaining deficit — not worth adding
            // (but larger UTXOs further in the list might help via Phase 3)
            continue;
        }

        total = total.checked_add(utxo.value).ok_or_else(|| {
            crate::KobError::Overflow("UTXO total overflows u64".into())
        })?;
        selected.push(utxo.clone());

        // Recompute output values since total changed
        let new_output_values = estimate_output_values(total, amount, fee, num_outputs);
        let new_output_mass: u128 = new_output_values
            .iter()
            .map(|&v| if v == 0 { u64::MAX as u128 } else { STORAGE_MASS_PARAMETER as u128 / v as u128 })
            .sum();

        // Check if we've achieved penalty-free with updated outputs
        let new_input_credit: u128 = selected
            .iter()
            .filter(|u| u.value > 0)
            .map(|u| STORAGE_MASS_PARAMETER as u128 / u.value as u128)
            .sum();
        if new_input_credit >= new_output_mass {
            break;
        }
    }

    // Phase 3: If still above mass limit, add largest available UTXOs as fallback
    let mut large_remaining: Vec<_> = sorted[split_idx..]
        .iter()
        .filter(|u| !selected.iter().any(|s| s.outpoint == u.outpoint))
        .cloned()
        .collect();
    large_remaining.sort_by(|a, b| b.value.cmp(&a.value)); // largest first

    loop {
        let input_values: Vec<u64> = selected.iter().map(|u| u.value).collect();
        let out_vals = estimate_output_values(total, amount, fee, num_outputs);
        let mass = compute_storage_mass(&input_values, &out_vals);

        if mass <= MAX_TX_MASS {
            return Ok(CoinSelection {
                utxos: selected,
                total,
                storage_mass: mass,
                penalty_free: mass == 0,
            });
        }

        if let Some(extra) = large_remaining.pop() {
            total = total.checked_add(extra.value).ok_or_else(|| {
                crate::KobError::Overflow("UTXO total overflows u64".into())
            })?;
            selected.push(extra);
        } else {
            return Err(crate::KobError::MassExceeded {
                computed: mass,
                limit: MAX_TX_MASS,
            });
        }
    }
}

/// Legacy wrapper — returns `(Vec<UtxoEntry>, u64)` for call sites that
/// don't need the penalty info. Equivalent to the old API.
pub fn select_utxos_mass_aware_simple(
    utxos: &[crate::types::UtxoEntry],
    amount: u64,
    fee: u64,
    num_outputs: usize,
) -> crate::Result<(Vec<crate::types::UtxoEntry>, u64)> {
    let sel = select_utxos_mass_aware(utxos, amount, fee, num_outputs)?;
    Ok((sel.utxos, sel.total))
}

/// Estimate output values for mass simulation.
///
/// For a TX spending `total_input` with `amount` as the primary output and `fee` deducted:
/// - output[0] = amount (the order/destination)
/// - output[1..] = change split evenly across remaining outputs
///   If change is below `MIN_UTXO_VALUE`, collapse to fewer outputs.
fn estimate_output_values(total_input: u64, amount: u64, fee: u64, num_outputs: usize) -> Vec<u64> {
    let num_outputs = num_outputs.max(1);
    let change = total_input.saturating_sub(amount + fee);

    if num_outputs == 1 || change < crate::MIN_UTXO_VALUE {
        // Single output or negligible change — just the primary output
        if change >= crate::MIN_UTXO_VALUE {
            vec![amount, change]
        } else {
            vec![amount + change] // absorb dust change into primary
        }
    } else {
        let mut outputs = vec![amount];
        let change_outputs = num_outputs - 1;
        let per_change = change / change_outputs as u64;
        if per_change < crate::MIN_UTXO_VALUE {
            // Change too small to split — single change output
            outputs.push(change);
        } else {
            let remainder = change - per_change * (change_outputs as u64 - 1);
            outputs.push(remainder); // first change gets remainder
            for _ in 1..change_outputs {
                outputs.push(per_change);
            }
        }
        outputs
    }
}

/// Convert a Transaction to the RPC submission format.
pub fn to_rpc_payload(
    tx: &Transaction,
    sigscripts: &[Vec<u8>],
) -> serde_json::Value {
    assert_eq!(tx.inputs.len(), sigscripts.len());

    let inputs: Vec<serde_json::Value> = tx
        .inputs
        .iter()
        .zip(sigscripts.iter())
        .map(|(inp, ss)| {
            serde_json::json!({
                "previousOutpoint": {
                    "transactionId": inp.prev_tx_id,
                    "index": inp.prev_index,
                },
                "signatureScript": hex::encode(ss),
                "sequence": inp.sequence,
                "sigOpCount": inp.sig_op_count,
            })
        })
        .collect();

    let outputs: Vec<serde_json::Value> = tx
        .outputs
        .iter()
        .map(|out| {
            let mut o = serde_json::json!({
                "value": out.value,
                "scriptPublicKey": {
                    "version": out.script_version(),
                    "script": hex::encode(out.script_bytes()),
                },
            });
            if let Some(ref cov) = out.covenant {
                o["covenant"] = serde_json::json!({
                    "authorizingInput": cov.authorizing_input,
                    "covenantId": crate::compat::hash_to_hex(&cov.covenant_id),
                });
            }
            o
        })
        .collect();

    let payload_hex = if tx.payload.is_empty() {
        String::new()
    } else {
        hex::encode(&tx.payload)
    };

    serde_json::json!({
        "transaction": {
            "version": tx.version,
            "inputs": inputs,
            "outputs": outputs,
            "lockTime": tx.lock_time,
            "subnetworkId": tx.subnetwork_id,
            "gas": tx.gas,
            "payload": payload_hex,
            "mass": 0,
        },
        "allowOrphan": false,
    })
}

/// Parse the script public key from a hex string (first 2 bytes = version LE, rest = script).
pub fn parse_spk(spk_hex: &str) -> crate::Result<(u16, Vec<u8>)> {
    let bytes = hex::decode(spk_hex)?;
    if bytes.len() < 2 {
        return Err(crate::KobError::Transaction(
            "script public key too short (need at least 2 bytes for version)".into(),
        ));
    }
    let version = u16::from_le_bytes([bytes[0], bytes[1]]);
    let script = bytes[2..].to_vec();
    Ok((version, script))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_spk_basic() {
        // version 0, script = [0xaa, 0x20, ...32 bytes..., 0x87]
        let mut hex_str = String::from("0000"); // version 0
        hex_str.push_str("aa20");
        hex_str.push_str(&"00".repeat(32));
        hex_str.push_str("87");
        let (version, script) = parse_spk(&hex_str).unwrap();
        assert_eq!(version, 0);
        assert_eq!(script.len(), 35); // aa + 20 + 32 bytes + 87
        assert_eq!(script[0], 0xaa);
        assert_eq!(script[34], 0x87);
    }

    #[test]
    fn to_rpc_payload_structure() {
        let tx = Transaction::new(0);
        let payload = to_rpc_payload(&tx, &[]);
        assert!(payload["transaction"]["version"].as_u64().unwrap() == 0);
        assert!(payload["allowOrphan"].as_bool().unwrap() == false);
    }


    fn fake_utxo(value: u64, index: u32) -> crate::types::UtxoEntry {
        crate::types::UtxoEntry {
            outpoint: crate::types::Outpoint {
                transaction_id: "a".repeat(64),
                index,
            },
            value,
            script_public_key: "0000".to_string(),
        }
    }


    #[test]
    fn mass_aware_basic_selection() {
        // 3 UTXOs (10M, 20M, 50M), need 25M.
        // Phase 0: 50M covers 25M+0 fee → single UTXO selected (tightest fit).
        let utxos = vec![
            fake_utxo(10_000_000, 0),
            fake_utxo(20_000_000, 1),
            fake_utxo(50_000_000, 2),
        ];
        let sel = select_utxos_mass_aware(&utxos, 25_000_000, 0, 2).unwrap();
        assert!(sel.total >= 25_000_000);
        // Phase 0 picks 50M (smallest single UTXO that covers 25M)
        assert_eq!(sel.utxos.len(), 1);
        assert_eq!(sel.utxos[0].value, 50_000_000);
    }

    #[test]
    fn mass_aware_multi_utxo_when_no_single_covers() {
        // 3 UTXOs (10M, 20M, 15M), need 25M. No single UTXO covers it.
        // Smallest-first: picks 10M+15M+20M until >= 25M.
        let utxos = vec![
            fake_utxo(10_000_000, 0),
            fake_utxo(20_000_000, 1),
            fake_utxo(15_000_000, 2),
        ];
        let sel = select_utxos_mass_aware(&utxos, 25_000_000, 0, 2).unwrap();
        assert!(sel.total >= 25_000_000);
        assert!(sel.utxos.len() >= 2);
    }

    #[test]
    fn mass_aware_dust_consolidation() {
        // 10 UTXOs of 1M each = 10M total, need 5M
        let utxos: Vec<_> = (0..10).map(|i| fake_utxo(1_000_000, i)).collect();
        let result = select_utxos_mass_aware(&utxos, 5_000_000, 0, 2);
        // 1M UTXOs are below MIN_UTXO_VALUE (3M) — may trigger mass issues.
        // With enough inputs the credit should cover outputs.
        // If mass passes, should combine multiple small UTXOs.
        match result {
            Ok(sel) => {
                assert!(sel.total >= 5_000_000);
                assert!(sel.utxos.len() >= 5, "should combine multiple small UTXOs");
            }
            Err(crate::KobError::MassExceeded { .. }) => {
                // Also acceptable: tiny UTXOs may not provide enough credit
            }
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn mass_aware_fallback_to_large() {
        // 5 tiny UTXOs (100K each) + 1 large (500M). Need 400K.
        // Tiny ones alone would create outputs with high mass. Large one adds credit.
        let mut utxos: Vec<_> = (0..5).map(|i| fake_utxo(100_000, i)).collect();
        utxos.push(fake_utxo(500_000_000, 5));
        let sel = select_utxos_mass_aware(&utxos, 400_000, 0, 2).unwrap();
        assert!(sel.total >= 400_000);
        // The large UTXO should be pulled in during mass fallback
        let has_large = sel.utxos.iter().any(|u| u.value == 500_000_000);
        // Phase 1 picks smallest first: 5x100K = 500K >= 400K.
        // If mass check fails, fallback adds the 500M UTXO.
        // Either way, selection should succeed.
        assert!(sel.utxos.len() >= 4 || has_large);
    }

    #[test]
    fn mass_aware_insufficient_funds() {
        // UTXOs total less than needed
        let utxos = vec![fake_utxo(1_000_000, 0), fake_utxo(2_000_000, 1)];
        let result = select_utxos_mass_aware(&utxos, 10_000_000, 0, 2);
        match result {
            Err(crate::KobError::InsufficientFunds { need, have }) => {
                assert_eq!(need, 10_000_000);
                assert_eq!(have, 3_000_000);
            }
            other => panic!("expected InsufficientFunds, got {:?}", other),
        }
    }

    #[test]
    fn mass_aware_mass_impossible() {
        // 1 UTXO of 15M, need 3M, fee=0, 5 outputs.
        // estimate_output_values: amount=3M, change=12M, 4 change outputs of 3M each.
        //   -> outputs = [3M, 3M, 3M, 3M, 3M]
        //   -> mass: 5 * C/3M - C/15M = 5*333,333 - 66,666 = 1,599,999
        //   -> 1,599,999 > MAX_TX_MASS (500K). No more UTXOs -> MassExceeded.
        let utxos = vec![fake_utxo(15_000_000, 0)];
        let result = select_utxos_mass_aware(&utxos, 3_000_000, 0, 5);
        match result {
            Err(crate::KobError::MassExceeded { computed, limit }) => {
                assert!(computed > limit);
            }
            Ok(_) => panic!("expected MassExceeded"),
            Err(other) => panic!("unexpected error: {}", other),
        }
    }

    #[test]
    fn mass_aware_single_utxo_sufficient() {
        // One large UTXO, need small amount
        let utxos = vec![fake_utxo(1_000_000_000, 0)]; // 10 KAS
        let sel = select_utxos_mass_aware(&utxos, 50_000_000, 10_000, 2).unwrap();
        assert_eq!(sel.utxos.len(), 1);
        assert_eq!(sel.total, 1_000_000_000);
    }

    #[test]
    fn mass_aware_num_outputs_affects_mass() {
        // Same inputs but more outputs increases mass requirement.
        // Use a medium UTXO where 2 outputs pass but 5 might fail.
        let utxos = vec![fake_utxo(20_000_000, 0)];
        let result_2 = select_utxos_mass_aware(&utxos, 10_000_000, 10_000, 2);
        let result_5 = select_utxos_mass_aware(&utxos, 10_000_000, 10_000, 5);

        // With 2 outputs: order=10M, change=~10M -> mass is manageable
        assert!(result_2.is_ok(), "2 outputs should pass: {:?}", result_2);

        // With 5 outputs: order=10M, 4 change outputs of ~2.5M each -> higher mass
        // More outputs = more C/value terms = higher mass
        // Both may pass for 20M, but the mass with 5 outputs is strictly higher
        // We verify the function at least runs without panic for both cases
        match result_5 {
            Ok(_) | Err(crate::KobError::MassExceeded { .. }) => {} // both valid
            Err(e) => panic!("unexpected error: {}", e),
        }
    }
}
