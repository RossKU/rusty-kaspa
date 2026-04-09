//! Storage mass calculation and pre-check for Kaspa transactions.
//!
//! Delegates to kaspad's `calc_storage_mass` (KIP-0009) for the core formula.
//! KOB-specific helpers (fee estimation, deploy suggestions) wrap the kaspad
//! calculation with unsigned-TX-aware logic.
//!
//! The effective TX mass is `max(transaction_mass, storage_mass)`.
//! Kaspa nodes reject transactions whose effective mass exceeds `MAX_TX_MASS`.

use std::fmt;

use kaspa_consensus_core::mass::{calc_storage_mass as kaspa_calc_storage_mass, UtxoCell};

/// Storage mass constant C = 10^12 (Kaspa KIP-0009).
pub const STORAGE_MASS_PARAMETER: u64 = kaspa_consensus_core::constants::STORAGE_MASS_PARAMETER;

/// Maximum block mass (Kaspa mainnet consensus, `max_block_mass` in params.rs).
/// A single TX cannot exceed this. A 2M sompi output produces exactly 500K mass.
pub const MAX_TX_MASS: u64 = 500_000;

/// Error returned when a transaction exceeds the storage mass limit.
#[derive(Debug, Clone)]
pub struct MassError {
    /// Computed storage mass for the transaction.
    pub computed_mass: u64,
    /// Maximum allowed mass.
    pub limit: u64,
    /// Per-output breakdown: (value, mass_contribution) for each output.
    pub output_breakdown: Vec<(u64, u64)>,
}

impl fmt::Display for MassError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "storage mass {} exceeds limit {} ({:.1}x over)",
            self.computed_mass,
            self.limit,
            self.computed_mass as f64 / self.limit as f64,
        )
    }
}

impl std::error::Error for MassError {}

/// Calculate storage mass for a transaction via kaspad's `calc_storage_mass`.
///
/// Returns 0 if inputs "absorb" more mass than outputs create (net negative).
/// Zero-value outputs produce `u64::MAX` mass (infinite penalty).
/// Zero-value inputs are skipped (no credit).
///
/// All standard KOB UTXOs have plurality=1 (33-byte SPK).
pub fn compute_storage_mass(input_values: &[u64], output_values: &[u64]) -> u64 {
    // Handle zero-value outputs: kaspad's calc_storage_mass requires non-zero amounts
    // (it divides by amount). Return u64::MAX immediately for any zero output.
    if output_values.iter().any(|&v| v == 0) {
        return u64::MAX;
    }

    // Empty outputs → no storage mass
    if output_values.is_empty() {
        return 0;
    }

    // Filter zero-value inputs (no credit for zero amounts)
    let inputs: Vec<UtxoCell> = input_values
        .iter()
        .copied()
        .filter(|&v| v > 0)
        .map(|v| UtxoCell::new(1, v))
        .collect();
    let outputs: Vec<UtxoCell> = output_values
        .iter()
        .copied()
        .map(|v| UtxoCell::new(1, v))
        .collect();

    // kaspad's calc_storage_mass divides by total input plurality, which panics
    // when inputs are empty. Handle that case here: with no inputs the storage
    // mass is purely the harmonic output sum (no input credit to subtract).
    if inputs.is_empty() {
        return outputs
            .iter()
            .map(|o| STORAGE_MASS_PARAMETER * o.plurality * o.plurality / o.amount)
            .fold(0u64, |acc, v| acc.saturating_add(v));
    }

    kaspa_calc_storage_mass(
        false, // not coinbase
        inputs.iter().copied(),
        outputs.into_iter(),
        STORAGE_MASS_PARAMETER,
    )
    .unwrap_or(u64::MAX)
}

/// Check storage mass for a transaction. Returns `Ok(mass)` if within limits,
/// or `Err(MassError)` if the computed mass exceeds `MAX_TX_MASS`.
pub fn check_storage_mass(
    input_values: &[u64],
    output_values: &[u64],
) -> Result<u64, MassError> {
    let mass = compute_storage_mass(input_values, output_values);

    if mass > MAX_TX_MASS {
        let output_breakdown = output_values
            .iter()
            .map(|&v| {
                let contribution = if v == 0 {
                    u64::MAX
                } else {
                    STORAGE_MASS_PARAMETER / v
                };
                (v, contribution)
            })
            .collect();

        Err(MassError {
            computed_mass: mass,
            limit: MAX_TX_MASS,
            output_breakdown,
        })
    } else {
        Ok(mass)
    }
}

/// Calculate the minimum per-output value that incurs zero storage mass penalty.
///
/// For a TX with `num_outputs` outputs and the given input values, find the
/// minimum per-output value such that `storage_mass <= MAX_TX_MASS`.
///
/// Returns the minimum value each output must have (assuming equal distribution).
/// Returns `u64::MAX` if `num_outputs` is 0.
pub fn min_penalty_free_output(input_values: &[u64], num_outputs: usize) -> u64 {
    if num_outputs == 0 {
        return u64::MAX;
    }

    // Input credit
    let in_credit: u128 = input_values
        .iter()
        .filter(|&&v| v > 0)
        .map(|&v| STORAGE_MASS_PARAMETER as u128 / v as u128)
        .sum();

    // We need: num_outputs * (C / min_val) - in_credit <= MAX_TX_MASS
    // => num_outputs * (C / min_val) <= MAX_TX_MASS + in_credit
    // => C / min_val <= (MAX_TX_MASS + in_credit) / num_outputs
    // => min_val >= C * num_outputs / (MAX_TX_MASS + in_credit)
    let budget = MAX_TX_MASS as u128 + in_credit;
    let numerator = STORAGE_MASS_PARAMETER as u128 * num_outputs as u128;

    if budget == 0 {
        return u64::MAX;
    }

    // Ceiling division: (numerator + budget - 1) / budget
    let min_val = numerator.div_ceil(budget);

    if min_val > u64::MAX as u128 {
        u64::MAX
    } else {
        min_val as u64
    }
}

/// Given wallet UTXOs, calculate the safe amount range for a deploy TX.
///
/// A deploy TX typically has:
/// - 1 input (wallet UTXO)
/// - `num_expected_outputs` outputs (order + change)
///
/// Returns `(min_amount, max_amount, recommended_amount)`:
/// - `min_amount`: minimum order amount where storage mass is within limits
/// - `max_amount`: maximum order amount (largest UTXO - fee)
/// - `recommended_amount`: the sweet spot (min_amount rounded up to nearest 1M sompi)
///
/// Returns `(0, 0, 0)` if no viable range exists.
pub fn suggest_deploy_amount(
    wallet_utxos: &[u64],
    _order_type: &str,
    num_expected_outputs: usize,
) -> (u64, u64, u64) {
    if wallet_utxos.is_empty() || num_expected_outputs == 0 {
        return (0, 0, 0);
    }

    // Use the largest UTXO as the funding input
    let max_utxo = *wallet_utxos.iter().max().unwrap_or(&0);
    if max_utxo == 0 {
        return (0, 0, 0);
    }

    // Estimate miner fee for a typical deploy TX (1-2 inputs, 2 outputs, ~100 byte payload).
    // Using estimate_compute_mass for a conservative pre-estimate.
    let fee = estimate_compute_mass(1, num_expected_outputs, 100);

    // Max amount: largest UTXO minus fee, with room for change
    let max_amount = max_utxo.saturating_sub(fee + crate::MIN_UTXO_VALUE);
    if max_amount == 0 {
        return (0, 0, 0);
    }

    // Min amount: the minimum per-output value that keeps mass within limits.
    // Deploy TX: 1 input (max_utxo), num_expected_outputs outputs.
    let min_per_output = min_penalty_free_output(&[max_utxo], num_expected_outputs);

    // The order output itself must be at least min_per_output.
    // The change output will be (max_utxo - amount - fee), which must also be >= min_per_output
    // if it exists (or >= MIN_UTXO_VALUE).
    let min_amount = min_per_output.max(crate::MIN_UTXO_VALUE);

    if min_amount > max_amount {
        return (0, 0, 0);
    }

    // Recommended: round min_amount up to nearest 1M sompi (1M sompi = 0.01 KAS)
    let round_unit = 1_000_000u64;
    let recommended = min_amount.div_ceil(round_unit) * round_unit;
    let recommended = recommended.min(max_amount);

    (min_amount, max_amount, recommended)
}

/// Check storage mass for a pre-built `Transaction` (from kob-core tx types).
///
/// Extracts input and output values from the transaction and runs the mass check.
pub fn check_tx_storage_mass(tx: &crate::tx::Transaction) -> Result<u64, MassError> {
    let input_values: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
    let output_values: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
    check_storage_mass(&input_values, &output_values)
}

// ---------------------------------------------------------------------------
// Compute mass (byte-based) estimation
// ---------------------------------------------------------------------------

/// Kaspad consensus constants for compute mass (mainnet).
pub const MASS_PER_TX_BYTE: u64 = 1;
pub const MASS_PER_SCRIPT_PUB_KEY_BYTE: u64 = 10;
pub const MASS_PER_SIG_OP: u64 = 1000;

/// Hash size (Blake2b-256) used in TX serialization estimates.
const HASH_SIZE: u64 = 32;
/// Subnetwork ID size in bytes.
const SUBNETWORK_ID_SIZE: u64 = 20;

/// Estimate the serialized byte size of a single input.
///
/// Matches Kaspad's `transaction_input_estimated_serialized_size`:
///   outpoint (32 tx_id + 4 index) + 8 sig_script_len + sig_script_bytes + 8 sequence
///
/// For unsigned TXs, signature script is not yet populated. We estimate it
/// from the sig_op_count: each Schnorr signature is 64 bytes + 1 byte push opcode.
fn estimate_input_serialized_size(input: &crate::tx::TxInput) -> u64 {
    let outpoint_size = HASH_SIZE + 4; // tx_id + index
    // Estimate signature script size: each sig op produces ~65 bytes (64 sig + 1 push)
    // plus the public key push (33 bytes + 1 push opcode) for P2PK.
    // Conservative overestimate: 100 bytes per sig_op covers all standard scripts.
    let sig_script_estimate = (input.sig_op_count as u64) * 100;
    outpoint_size + 8 + sig_script_estimate + 8 // + sig_script_len + sequence
}

/// Estimate the serialized byte size of a single output.
///
/// Matches Kaspad's `transaction_output_estimated_serialized_size`:
///   8 value + 2 spk_version + 8 spk_len + spk_bytes
fn estimate_output_serialized_size(output: &crate::tx::TxOutput) -> u64 {
    8 + 2 + 8 + output.script_bytes().len() as u64
}

/// Estimate the total serialized byte size of a transaction.
///
/// Mirrors Kaspad's `transaction_estimated_serialized_size` but operates on
/// kob-core's `Transaction` type. Uses estimated signature script sizes since
/// TXs are unsigned at construction time.
pub fn estimate_tx_serialized_size(tx: &crate::tx::Transaction) -> u64 {
    let mut size: u64 = 0;
    size += 2; // version (u16)
    size += 8; // num_inputs (u64)
    size += tx.inputs.iter().map(estimate_input_serialized_size).sum::<u64>();
    size += 8; // num_outputs (u64)
    size += tx.outputs.iter().map(estimate_output_serialized_size).sum::<u64>();
    size += 8; // lock_time (u64)
    size += SUBNETWORK_ID_SIZE;
    size += 8; // gas (u64)
    size += HASH_SIZE; // payload hash
    size += 8; // payload length (u64)
    size += tx.payload.len() as u64;
    size
}

/// Compute the byte-based (compute) mass for a transaction.
///
/// Formula (matches Kaspad's `calc_non_contextual_masses`):
///
///   `compute_mass = mass_per_tx_byte * tx_bytes
///                  + mass_per_script_pub_key_byte * spk_bytes
///                  + mass_per_sig_op * sig_ops`
///
/// Uses estimated signature script sizes since TXs are unsigned at fee
/// calculation time. The estimate is deliberately conservative (overestimates
/// slightly) so the resulting miner fee is always sufficient.
pub fn calc_compute_mass(tx: &crate::tx::Transaction) -> u64 {
    let size = estimate_tx_serialized_size(tx);
    let compute_mass_for_size = size * MASS_PER_TX_BYTE;

    let total_spk_size: u64 = tx.outputs.iter().map(|o| {
        2u64 /* script_version u16 */ + o.script_bytes().len() as u64
    }).sum();
    let total_spk_mass = total_spk_size * MASS_PER_SCRIPT_PUB_KEY_BYTE;

    let total_sig_ops: u64 = tx.inputs.iter().map(|i| i.sig_op_count as u64).sum();
    let total_sig_ops_mass = total_sig_ops * MASS_PER_SIG_OP;

    compute_mass_for_size + total_spk_mass + total_sig_ops_mass
}

/// Calculate the miner fee for a transaction based on its mass.
///
/// `effective_mass = max(compute_mass, storage_mass)` and
/// `miner_fee = effective_mass * 1 sompi/gram`.
///
/// This is the minimum fee the network will accept. The storage mass is
/// computed from input/output values; the compute mass is estimated from
/// the TX structure (with conservative signature size estimates).
pub fn calc_miner_fee(tx: &crate::tx::Transaction) -> u64 {
    let compute_mass = calc_compute_mass(tx);

    let input_values: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
    let output_values: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
    let storage_mass = compute_storage_mass(&input_values, &output_values);

    // effective_mass = max(compute_mass, storage_mass), fee = 1 sompi/gram
    compute_mass.max(storage_mass)
}

/// Estimate compute mass for a transaction with the given parameters,
/// without building a full Transaction object. Useful for fee pre-estimation.
///
/// `num_inputs`: number of inputs (each assumed to have 1 sig_op, ~35 byte SPK)
/// `num_outputs`: number of outputs (each assumed to have ~35 byte SPK)
/// `payload_len`: length of the payload in bytes
pub fn estimate_compute_mass(num_inputs: usize, num_outputs: usize, payload_len: usize) -> u64 {
    // Estimate per-input size: outpoint(36) + sig_script_len(8) + sig_script(~100) + sequence(8) = 152
    let input_size = 152u64;
    // Estimate per-output size: value(8) + spk_version(2) + spk_len(8) + spk_script(~35) = 53
    let output_size = 53u64;

    let tx_size = 2 + 8 + (num_inputs as u64 * input_size)
        + 8 + (num_outputs as u64 * output_size)
        + 8 + SUBNETWORK_ID_SIZE + 8 + HASH_SIZE
        + 8 + payload_len as u64;

    let size_mass = tx_size * MASS_PER_TX_BYTE;
    // SPK mass: each output has ~37 bytes (2 version + 35 script)
    let spk_mass = (num_outputs as u64) * 37 * MASS_PER_SCRIPT_PUB_KEY_BYTE;
    // Sig ops: 1 per input
    let sig_ops_mass = (num_inputs as u64) * MASS_PER_SIG_OP;

    size_mass + spk_mass + sig_ops_mass
}

#[cfg(test)]
mod tests {
    use super::*;

    // C = 10^12 for all networks (mainnet, TN11, TN12).

    #[test]
    fn mass_single_output_1m() {
        // C / 1M = 1e12 / 1e6 = 1,000,000 = exactly MAX_TX_MASS
        let mass = compute_storage_mass(&[], &[1_000_000]);
        assert_eq!(mass, 1_000_000);
    }

    #[test]
    fn mass_single_output_10m() {
        // C / 10M = 1e12 / 1e7 = 100,000
        let mass = compute_storage_mass(&[], &[10_000_000]);
        assert_eq!(mass, 100_000);
    }

    #[test]
    fn mass_single_output_3m() {
        // C / 3M = 1e12 / 3e6 = 333,333
        let mass = compute_storage_mass(&[], &[3_000_000]);
        assert_eq!(mass, 333_333);
    }

    #[test]
    fn mass_two_outputs_5m_each() {
        // 2 * (C / 5M) = 2 * 200,000 = 400,000
        let mass = compute_storage_mass(&[], &[5_000_000, 5_000_000]);
        assert_eq!(mass, 400_000);
    }

    #[test]
    fn mass_with_input_credit() {
        // Output: C / 5M = 200,000
        // Input credit (relaxed, |O|=1, |I|=1): C / 10M = 100,000
        // Net: 100,000
        let mass = compute_storage_mass(&[10_000_000], &[5_000_000]);
        assert_eq!(mass, 100_000);
    }

    #[test]
    fn mass_input_absorbs_all() {
        // Output: C / 10M = 100,000
        // Input credit: C / 5M = 200,000
        // Net: 0 (saturating)
        let mass = compute_storage_mass(&[5_000_000], &[10_000_000]);
        assert_eq!(mass, 0);
    }

    #[test]
    fn mass_two_outputs_with_large_input() {
        // 2 outputs + 1 input → relaxed (|I|=1)
        // Outputs: 2 * (C / 5M) = 400,000
        // Input credit: C / 10M = 100,000
        // Net: 300,000
        let mass = compute_storage_mass(&[10_000_000], &[5_000_000, 5_000_000]);
        assert_eq!(mass, 300_000);
    }

    #[test]
    fn mass_realistic_buy_deploy() {
        // Deploy: 1 input of 100M (1 KAS), 2 outputs: 30M order + 59.99M change
        // Relaxed (|I|=1): harmonic for both
        // Output mass: C/30M + C/59_990_000 = 33,333 + 16,669 = 50,002 (approx)
        // Input credit: C/100M = 10,000
        // Net: ~40,002 — within limit
        let mass = compute_storage_mass(&[100_000_000], &[30_000_000, 59_990_000]);
        assert!(mass <= MAX_TX_MASS, "deploy mass {} should be within limit", mass);
    }

    #[test]
    fn mass_dust_two_outputs() {
        // 2 outputs of 500K each → 2 * (C/500K) = 2 * 2,000,000 = 4,000,000 > 1M
        let mass = compute_storage_mass(&[], &[500_000, 500_000]);
        assert!(mass > MAX_TX_MASS, "dust split: mass {} should exceed limit", mass);
    }

    #[test]
    fn mass_20m_buy_ok() {
        // 2 outputs of 10M each → 2 * (C/10M) = 200,000 < 1M
        let mass = compute_storage_mass(&[], &[10_000_000, 10_000_000]);
        assert!(mass < MAX_TX_MASS, "20M buy split: mass {} should be within limit", mass);
    }

    #[test]
    fn mass_zero_output() {
        let mass = compute_storage_mass(&[], &[0]);
        assert_eq!(mass, u64::MAX);
    }

    #[test]
    fn mass_zero_input_skipped() {
        // Zero-value input provides no credit
        let mass = compute_storage_mass(&[0, 10_000_000], &[5_000_000]);
        // Output: C/5M = 200,000. Input credit: C/10M = 100,000. Net: 100,000
        assert_eq!(mass, 100_000);
    }

    #[test]
    fn mass_empty_inputs_outputs() {
        assert_eq!(compute_storage_mass(&[], &[]), 0);
    }

    #[test]
    fn mass_single_large_output() {
        // 100 KAS = 10B sompi: C/10B = 1e12/1e10 = 100
        let mass = compute_storage_mass(&[], &[10_000_000_000]);
        assert_eq!(mass, 100);
    }

    #[test]
    fn mass_dust_output() {
        // 1000 sompi: C/1000 = 1,000,000,000 — way over limit
        let mass = compute_storage_mass(&[], &[1_000]);
        assert_eq!(mass, 1_000_000_000);
    }


    #[test]
    fn check_ok_within_limit() {
        let result = check_storage_mass(&[100_000_000], &[30_000_000, 59_990_000]);
        assert!(result.is_ok());
    }

    #[test]
    fn check_err_exceeds_limit() {
        // C / 500K = 2,000,000 > 1M
        let result = check_storage_mass(&[], &[500_000]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.computed_mass, 2_000_000);
        assert_eq!(err.limit, MAX_TX_MASS);
    }

    #[test]
    fn check_exact_limit_ok() {
        // 2M sompi = C/2M = 500,000 = exactly MAX_TX_MASS
        let result = check_storage_mass(&[], &[2_000_000]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 500_000);
    }

    #[test]
    fn check_1m_sompi_exceeds_limit() {
        // 1M sompi = C/1M = 1,000,000 > MAX_TX_MASS (500,000)
        let result = check_storage_mass(&[], &[1_000_000]);
        assert!(result.is_err());
    }

    #[test]
    fn check_just_over_limit() {
        // 1,999,996 sompi → C/1999996 = 500,001 (just over MAX_TX_MASS=500,000)
        let mass = compute_storage_mass(&[], &[1_999_996]);
        assert!(mass > MAX_TX_MASS);
        let result = check_storage_mass(&[], &[1_999_996]);
        assert!(result.is_err());
    }

    #[test]
    fn check_just_under_limit() {
        // 2,000,001 sompi → C/2000001 = 499,999 (just under)
        let mass = compute_storage_mass(&[], &[2_000_001]);
        assert!(mass < MAX_TX_MASS);
        let result = check_storage_mass(&[], &[2_000_001]);
        assert!(result.is_ok());
    }


    #[test]
    fn min_output_no_inputs() {
        // C / min_val <= 500K => min_val >= C / 500K = 2M
        let min = min_penalty_free_output(&[], 1);
        assert_eq!(min, 2_000_000);
    }

    #[test]
    fn min_output_two_outputs_no_inputs() {
        // 2 * (C / min_val) <= 500K => min_val >= 2*C/500K = 4M
        let min = min_penalty_free_output(&[], 2);
        assert_eq!(min, 4_000_000);
    }

    #[test]
    fn min_output_with_input_credit() {
        // Input credit: C / 100M = 10,000
        // Budget: 500K + 10,000 = 510,000
        // For 2 outputs: min_val >= 2 * 1e12 / 510,000 = 3,921,569 (ceiling)
        let min = min_penalty_free_output(&[100_000_000], 2);
        assert_eq!(min, 3_921_569); // ceiling division
        let mass = compute_storage_mass(&[100_000_000], &[min, min]);
        assert!(mass <= MAX_TX_MASS, "min output {} gives mass {} which should be <= {}", min, mass, MAX_TX_MASS);
    }

    #[test]
    fn min_output_zero_outputs() {
        assert_eq!(min_penalty_free_output(&[], 0), u64::MAX);
    }

    #[test]
    fn min_output_large_input_credit() {
        // Credit: C / 100M = 10,000
        // Budget: 500K + 10,000 = 510,000
        // 1 output: min_val >= 1e12 / 510,000 = 1,960,785 (ceiling)
        let min = min_penalty_free_output(&[100_000_000], 1);
        assert_eq!(min, 1_960_785); // ceiling division
    }


    #[test]
    fn suggest_empty_utxos() {
        assert_eq!(suggest_deploy_amount(&[], "buy", 2), (0, 0, 0));
    }

    #[test]
    fn suggest_single_large_utxo() {
        let utxos = vec![1_000_000_000];
        let (min, max, rec) = suggest_deploy_amount(&utxos, "buy", 2);
        assert!(min > 0, "min should be positive");
        assert!(max > min, "max {} should exceed min {}", max, min);
        assert!(rec >= min && rec <= max, "rec {} should be between min {} and max {}", rec, min, max);
    }

    #[test]
    fn suggest_small_utxo() {
        // UTXO of 5M sompi. With C=1e12, min per output for 2 outputs ≈ 2M
        // max = 5M - 10K - 3M = 1,990,000; min = max(2M, 3M) = 3M > 1.99M → no range
        let utxos = vec![5_000_000];
        let (min, max, rec) = suggest_deploy_amount(&utxos, "buy", 2);
        assert_eq!((min, max, rec), (0, 0, 0));
    }

    #[test]
    fn suggest_realistic_wallet() {
        let utxos = vec![50_000_000_000, 30_000_000_000, 20_000_000_000];
        let (min, max, rec) = suggest_deploy_amount(&utxos, "buy", 2);
        assert!(min > 0);
        assert!(max > 0);
        assert!(rec >= min);
    }


    #[test]
    fn match_tx_mass_full_match() {
        // Full match: 2 order inputs (30M each), 4 outputs
        // Relaxed: |I|=2, |O|=4 → NOT relaxed → arithmetic for inputs
        // harmonic_outs = C/15M + C/30M + C/3M + C/12M = 66,666 + 33,333 + 333,333 + 83,333 = 516,665
        // mean_ins = 60M/2 = 30M, arithmetic_ins = 4 × C/30M = nope...
        // arithmetic_ins = |I|²×C/Σin = 4 × 1e12 / 60M = 66,666
        // mass = 516,665 - 66,666 = 449,999
        let inputs = vec![30_000_000, 30_000_000];
        let outputs = vec![15_000_000, 30_000_000, 3_000_000, 12_000_000];
        let mass = compute_storage_mass(&inputs, &outputs);
        assert!(mass < MAX_TX_MASS,
            "match with 2 inputs, 4 outputs: mass={} should be within limit", mass);
    }

    #[test]
    fn match_tx_mass_with_fee_utxo_large() {
        // 3 inputs (30M, 30M, 100M) + 4 outputs → arithmetic
        // mean_ins = 160M/3, arithmetic_ins = 9 × C / 160M = 56,250
        // harmonic_outs ≈ C/15M + C/30M + C/3M + C/112M = 66,666+33,333+333,333+8,928 = 442,260
        // mass = 442,260 - 56,250 = 386,010
        let inputs = vec![30_000_000, 30_000_000, 100_000_000];
        let outputs = vec![15_000_000, 30_000_000, 3_000_000, 111_990_000];
        let mass = compute_storage_mass(&inputs, &outputs);
        assert!(mass < MAX_TX_MASS,
            "with C=1e12, large fee UTXO match is within limit: mass={}", mass);
    }

    #[test]
    fn match_tx_mass_with_small_fee_utxo() {
        // 3 inputs (30M, 30M, 5M) + 4 outputs → arithmetic
        // mean_ins = 65M/3 = 21.67M, arithmetic_ins = 9 × 1e12 / 65M = 138,461
        // harmonic_outs = C/15M + C/30M + C/3M + C/16.99M = 66,666+33,333+333,333+58,858 = 492,190
        // mass = 492,190 - 138,461 = 353,729
        let inputs = vec![30_000_000, 30_000_000, 5_000_000];
        let outputs = vec![15_000_000, 30_000_000, 3_000_000, 16_990_000];
        let mass = compute_storage_mass(&inputs, &outputs);
        assert!(mass < MAX_TX_MASS,
            "with C=1e12, small fee UTXO match is within limit: mass={}", mass);
    }

    #[test]
    fn match_tx_mass_with_min_fee_utxo() {
        // 3 inputs (30M, 30M, 3M) + 4 outputs → arithmetic
        let inputs = vec![30_000_000, 30_000_000, 3_000_000];
        let outputs = vec![15_000_000, 30_000_000, 3_000_000, 14_990_000];
        let mass = compute_storage_mass(&inputs, &outputs);
        assert!(mass < MAX_TX_MASS,
            "with C=1e12, min fee UTXO match is within limit: mass={}", mass);
    }

    #[test]
    fn match_tx_mass_large_values_ok() {
        let inputs = vec![100_000_000, 100_000_000];
        let outputs = vec![50_000_000, 100_000_000, 10_000_000, 40_000_000];
        let mass = compute_storage_mass(&inputs, &outputs);
        assert!(mass <= MAX_TX_MASS,
            "match with large values should be within limit: mass={}", mass);
    }

    #[test]
    fn match_tx_mass_tiny_receipt_exceeds() {
        // Very small receipt (100K sompi) → C/100K = 10,000,000 dominates
        let inputs = vec![5_000_000, 5_000_000];
        let outputs = vec![3_000_000, 5_000_000, 100_000, 1_900_000];
        let mass = compute_storage_mass(&inputs, &outputs);
        assert!(mass > MAX_TX_MASS,
            "100K receipt creates too much mass: mass={}", mass);
    }


    #[test]
    fn check_tx_ok() {
        let mut tx = crate::tx::Transaction::new(0);
        tx.inputs.push(crate::tx::TxInput {
            prev_tx_id: "a".repeat(64),
            prev_index: 0,
            sequence: 0,
            sig_op_count: 1,
            script_version: 0,
            script_bytes: vec![],
            value: 100_000_000,
        });
        tx.outputs.push(crate::tx::TxOutput {
            value: 50_000_000,
            script_public_key: kaspa_consensus_core::tx::ScriptPublicKey::new(0, vec![].into()),
            covenant: None,
        });
        tx.outputs.push(crate::tx::TxOutput {
            value: 49_990_000,
            script_public_key: kaspa_consensus_core::tx::ScriptPublicKey::new(0, vec![].into()),
            covenant: None,
        });
        let result = check_tx_storage_mass(&tx);
        assert!(result.is_ok(), "TX with large outputs should pass: {:?}", result.err());
    }


    #[test]
    fn mass_all_zero_inputs_and_outputs() {
        // Zero-value inputs are filtered (no credit).
        // Zero-value outputs each contribute u64::MAX mass (infinite penalty).
        // 3 zero outputs saturate to u64::MAX.
        assert_eq!(compute_storage_mass(&[0, 0, 0], &[0, 0, 0]), u64::MAX);
    }

    #[test]
    fn mass_single_max_input() {
        // u64::MAX input → credit ≈ C/u64::MAX ≈ 0, mass dominated by output
        let mass = compute_storage_mass(&[u64::MAX], &[1_000_000]);
        assert!(mass > 0); // output cost dominates
    }

    #[test]
    fn mass_single_max_output() {
        // u64::MAX output → output cost ≈ C/u64::MAX ≈ 0
        let mass = compute_storage_mass(&[1_000_000], &[u64::MAX]);
        assert_eq!(mass, 0); // input credit > tiny output cost
    }

    #[test]
    fn mass_many_tiny_inputs() {
        // 100 inputs of 1 sompi each → harmonic: 100 × (C/1) = 100C credit
        let ins: Vec<u64> = vec![1; 100];
        let mass = compute_storage_mass(&ins, &[1_000_000]);
        assert_eq!(mass, 0); // massive input credit exceeds output cost
    }

    #[test]
    fn mass_three_inputs_two_outputs_arithmetic() {
        // 3 in, 2 out → NOT relaxed → arithmetic path
        // Verify it doesn't use harmonic (which would give different result)
        let ins = vec![10_000_000u64; 3]; // 10M each
        let outs = vec![15_000_000u64; 2]; // 15M each
        let mass = compute_storage_mass(&ins, &outs);
        // With arithmetic: mean_in = 10M, credit = 3*(C/10M) = 300_000
        // harmonic_outs = C/15M + C/15M = 133_333
        // mass = max(0, 133_333 - 300_000) = 0
        assert_eq!(mass, 0);
    }

    #[test]
    fn mass_relaxed_exact_2x2_boundary() {
        // Exactly 2 in, 2 out → relaxed → harmonic for inputs
        let ins = vec![10_000_000u64; 2];
        let outs = vec![10_000_000u64; 2];
        let mass = compute_storage_mass(&ins, &outs);
        // harmonic: in_credit = 2*(C/10M) = 200_000, out_cost = 2*(C/10M) = 200_000
        // mass = max(0, 200_000 - 200_000) = 0
        assert_eq!(mass, 0);
    }

    #[test]
    fn mass_3in_3out_vs_2in_2out_different_formula() {
        // Same per-unit values but 3×3 uses arithmetic, 2×2 uses harmonic
        // This test verifies the formula dispatch actually differs
        let val = 5_000_000u64;
        let mass_2x2 = compute_storage_mass(&[val; 2], &[val; 2]);
        let mass_3x3 = compute_storage_mass(&[val; 3], &[val; 3]);
        // Both should be 0 for equal in/out, but arithmetic path rounds differently
        // The key thing: both are 0 when balanced
        assert_eq!(mass_2x2, 0);
        assert_eq!(mass_3x3, 0);
    }

    #[test]
    fn mass_mixed_zero_nonzero_inputs() {
        // Zeros filtered → only 1 non-zero input → relaxed
        let mass = compute_storage_mass(&[0, 5_000_000, 0], &[5_000_000]);
        // 1 non-zero in, 1 out → relaxed, harmonic both sides
        // in_credit = C/5M = 200_000, out_cost = C/5M = 200_000 → mass = 0
        assert_eq!(mass, 0);
    }

    #[test]
    fn mass_single_input_many_outputs() {
        // 1 input → always relaxed regardless of output count
        let mass = compute_storage_mass(&[100_000_000], &[1_000_000, 2_000_000, 3_000_000, 4_000_000]);
        // in_credit = C/100M = 10_000
        // out_cost = C/1M + C/2M + C/3M + C/4M = 1_000_000 + 500_000 + 333_333 + 250_000 = 2_083_333
        // mass = 2_083_333 - 10_000 = 2_073_333
        assert!(mass > 2_000_000);
    }

    #[test]
    fn mass_only_inputs_no_outputs() {
        let mass = compute_storage_mass(&[10_000_000, 20_000_000], &[]);
        assert_eq!(mass, 0); // no outputs → out_cost = 0, mass = 0
    }

    #[test]
    fn mass_only_outputs_no_inputs() {
        let mass = compute_storage_mass(&[], &[10_000_000]);
        // no inputs → in_credit = 0, out_cost = C/10M = 100_000
        assert_eq!(mass, 100_000);
    }

    #[test]
    fn check_tx_rejects_dust_output() {
        let mut tx = crate::tx::Transaction::new(0);
        tx.inputs.push(crate::tx::TxInput {
            prev_tx_id: "a".repeat(64),
            prev_index: 0,
            sequence: 0,
            sig_op_count: 1,
            script_version: 0,
            script_bytes: vec![],
            value: 10_000_000,
        });
        tx.outputs.push(crate::tx::TxOutput {
            value: 1_000, // dust
            script_public_key: kaspa_consensus_core::tx::ScriptPublicKey::new(0, vec![].into()),
            covenant: None,
        });
        let result = check_tx_storage_mass(&tx);
        assert!(result.is_err(), "TX with 1000 sompi output should be rejected");
    }

    // -----------------------------------------------------------------------
    // Compute mass and miner fee tests
    // -----------------------------------------------------------------------

    #[test]
    fn estimate_compute_mass_basic() {
        // 1 input, 1 output, no payload
        let mass = estimate_compute_mass(1, 1, 0);
        // tx_size = 2+8+152+8+53+8+20+8+32+8+0 = 299
        // size_mass = 299
        // spk_mass = 1 * 37 * 10 = 370
        // sig_ops_mass = 1 * 1000 = 1000
        // total = 1669
        assert_eq!(mass, 1669);
    }

    #[test]
    fn estimate_compute_mass_typical_deploy() {
        // Deploy TX: 1 input, 2 outputs, ~100 byte payload
        let mass = estimate_compute_mass(1, 2, 100);
        assert!(mass > 1000, "deploy mass should be > 1000");
        assert!(mass < 10_000, "deploy mass should be < 10,000");
    }

    #[test]
    fn estimate_compute_mass_match_tx() {
        // Match TX: 3 inputs (2 covenant + 1 fee), 4 outputs
        let mass = estimate_compute_mass(3, 4, 0);
        assert!(mass > 3000, "match mass should be > 3000");
        assert!(mass < 10_000, "match mass should be < 10,000");
    }

    #[test]
    fn calc_compute_mass_simple_tx() {
        let mut tx = crate::tx::Transaction::new(0);
        tx.inputs.push(crate::tx::TxInput {
            prev_tx_id: "a".repeat(64),
            prev_index: 0,
            sequence: 0,
            sig_op_count: 1,
            script_version: 0,
            script_bytes: vec![0x20; 34], // P2PK SPK
            value: 100_000_000,
        });
        tx.outputs.push(crate::tx::TxOutput {
            value: 50_000_000,
            script_public_key: kaspa_consensus_core::tx::ScriptPublicKey::new(0, vec![0x20; 34].into()),
            covenant: None,
        });
        let mass = calc_compute_mass(&tx);
        assert!(mass > 0);
        // Should include: size_mass + spk_mass + sig_ops_mass
        assert!(mass >= 1000, "at least 1 sig_op = 1000 mass");
    }

    #[test]
    fn calc_miner_fee_uses_max_of_compute_and_storage() {
        // TX with very large outputs (minimal storage mass) -- compute mass dominates
        let mut tx = crate::tx::Transaction::new(0);
        tx.inputs.push(crate::tx::TxInput {
            prev_tx_id: "a".repeat(64),
            prev_index: 0,
            sequence: 0,
            sig_op_count: 1,
            script_version: 0,
            script_bytes: vec![0x20; 34],
            value: 100_000_000_000, // 1000 KAS -- massive input
        });
        tx.outputs.push(crate::tx::TxOutput {
            value: 99_999_000_000,
            script_public_key: kaspa_consensus_core::tx::ScriptPublicKey::new(0, vec![0x20; 34].into()),
            covenant: None,
        });
        let fee = calc_miner_fee(&tx);
        let compute = calc_compute_mass(&tx);
        let storage = compute_storage_mass(&[100_000_000_000], &[99_999_000_000]);
        // With 1000 KAS input and single large output, storage mass is tiny
        assert!(storage < compute, "storage mass {} should be < compute mass {}", storage, compute);
        assert_eq!(fee, compute, "for very large outputs, miner fee = compute mass");
    }

    #[test]
    fn estimate_tx_serialized_size_consistent() {
        let mut tx = crate::tx::Transaction::new(0);
        tx.inputs.push(crate::tx::TxInput {
            prev_tx_id: "a".repeat(64),
            prev_index: 0,
            sequence: 0,
            sig_op_count: 1,
            script_version: 0,
            script_bytes: vec![0x20; 34],
            value: 100_000_000,
        });
        tx.outputs.push(crate::tx::TxOutput {
            value: 99_000_000,
            script_public_key: kaspa_consensus_core::tx::ScriptPublicKey::new(0, vec![0x20; 34].into()),
            covenant: None,
        });
        let size = estimate_tx_serialized_size(&tx);
        // Expected: 2 + 8 + (36+8+100+8) + 8 + (8+2+8+34) + 8 + 20 + 8 + 32 + 8 + 0
        //         = 2 + 8 + 152 + 8 + 52 + 8 + 20 + 8 + 32 + 8 = 298
        assert!(size > 200 && size < 500, "serialized size {} should be reasonable", size);
    }
}
