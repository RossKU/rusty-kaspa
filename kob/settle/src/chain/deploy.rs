//! RPC transaction-payload builders.
//!
//! Generic JSON-shaping helpers for the kaspad wRPC `submitTransaction`
//! call: no order-book / covenant-order domain logic lives here, just the
//! wire-format construction (and the post-Toccata sigOpCount -> computeBudget
//! rewrite every caller needs). Extracted from `kob-engine`'s deploy module.

use crate::SUBNETWORK_ID;

/// Rewrite already-built RPC input JSON so its compute-cost commitment matches
/// the transaction's version, mirroring `kob_settle::tx::to_rpc_payload`.
///
/// Post-Toccata, version >= 1 transaction inputs commit a `computeBudget`
/// (u16), not a `sigOpCount` (u8); the node rejects a nonzero `sigOpCount` on
/// such an input ("RpcTransactionInput.sig_op_count is inconsistent with
/// transaction version N"). Callers emit `sigOpCount` unconditionally, so
/// this pass converts each input to `sigOpCount: 0` + `computeBudget =
/// sig_ops * 10` when the tx is version >= 1 (a no-op for version 0).
/// Applied centrally here so every `build_submit_payload*` caller is
/// covered at once.
fn finalize_inputs_for_version(inputs: &mut [serde_json::Value], version: u16) {
    if !crate::tx::tx_expects_compute_budget(version) {
        return;
    }
    for inp in inputs.iter_mut() {
        let sig_ops = inp.get("sigOpCount").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
        inp["sigOpCount"] = serde_json::json!(0);
        inp["computeBudget"] = serde_json::json!(crate::tx::compute_budget_for_sig_ops(sig_ops));
    }
}

/// Build the RPC transaction JSON for submitting.
pub fn build_submit_payload(
    version: u16,
    mut inputs: Vec<serde_json::Value>,
    outputs: Vec<serde_json::Value>,
) -> serde_json::Value {
    finalize_inputs_for_version(&mut inputs, version);
    serde_json::json!({
        "transaction": {
            "version": version,
            "inputs": inputs,
            "outputs": outputs,
            "lockTime": 0u64,
            "subnetworkId": SUBNETWORK_ID,
            "gas": 0u64,
            "payload": "",
            "mass": 0u64,
        },
        "allowOrphan": false,
    })
}

/// Build the RPC transaction JSON with a custom TX-level payload.
///
/// Used by flows that embed a tagged payload (e.g. `KOB:1:<...>` or an
/// x402 request-fingerprint tag `X402:<...>`) so a watcher can discover
/// what the transaction is for.
pub fn build_submit_payload_with_tx_payload(
    version: u16,
    mut inputs: Vec<serde_json::Value>,
    outputs: Vec<serde_json::Value>,
    tx_payload_hex: &str,
    lock_time: u64,
) -> serde_json::Value {
    finalize_inputs_for_version(&mut inputs, version);
    serde_json::json!({
        "transaction": {
            "version": version,
            "inputs": inputs,
            "outputs": outputs,
            "lockTime": lock_time,
            "subnetworkId": SUBNETWORK_ID,
            "gas": 0u64,
            "payload": tx_payload_hex,
            "mass": 0u64,
        },
        "allowOrphan": false,
    })
}

/// Build the RPC transaction JSON for submitting, with a custom lockTime.
///
/// Used by expire TXs where lockTime must be >= expiry_daa for CLTV to pass.
pub fn build_submit_payload_with_lock_time(
    version: u16,
    mut inputs: Vec<serde_json::Value>,
    outputs: Vec<serde_json::Value>,
    lock_time: u64,
) -> serde_json::Value {
    finalize_inputs_for_version(&mut inputs, version);
    serde_json::json!({
        "transaction": {
            "version": version,
            "inputs": inputs,
            "outputs": outputs,
            "lockTime": lock_time,
            "subnetworkId": SUBNETWORK_ID,
            "gas": 0u64,
            "payload": "",
            "mass": 0u64,
        },
        "allowOrphan": false,
    })
}

/// Build an RPC input JSON.
pub fn build_rpc_input(tx_id: &str, index: u32, sig_script_hex: &str, sig_op_count: u8) -> serde_json::Value {
    build_rpc_input_with_sequence(tx_id, index, sig_script_hex, sig_op_count, 0)
}

/// Build an RPC input JSON with a custom sequence number.
///
/// Covenant fill inputs require sequence=50 for OP_CSV compliance.
pub fn build_rpc_input_with_sequence(tx_id: &str, index: u32, sig_script_hex: &str, sig_op_count: u8, sequence: u64) -> serde_json::Value {
    serde_json::json!({
        "previousOutpoint": {
            "transactionId": tx_id,
            "index": index,
        },
        "signatureScript": sig_script_hex,
        "sequence": sequence,
        "sigOpCount": sig_op_count,
    })
}

/// Build an RPC output JSON (without covenant).
pub fn build_rpc_output(value: u64, spk_version: u16, spk_script_hex: &str) -> serde_json::Value {
    serde_json::json!({
        "value": value,
        "scriptPublicKey": {
            "version": spk_version,
            "script": spk_script_hex,
        },
    })
}

/// Build an RPC output JSON with covenant binding.
pub fn build_rpc_output_with_covenant(
    value: u64,
    spk_version: u16,
    spk_script_hex: &str,
    auth_input: u16,
    covenant_id: &str,
) -> serde_json::Value {
    serde_json::json!({
        "value": value,
        "scriptPublicKey": {
            "version": spk_version,
            "script": spk_script_hex,
        },
        "covenant": {
            "authorizingInput": auth_input,
            "covenantId": covenant_id,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_submit_payload_shape() {
        let inputs = vec![build_rpc_input("ab".repeat(32).as_str(), 0, "cd", 1)];
        let outputs = vec![build_rpc_output(1_000_000, 0, "20abcd")];
        let payload = build_submit_payload(0, inputs, outputs);
        let tx = &payload["transaction"];
        assert_eq!(tx["version"], 0);
        assert_eq!(tx["subnetworkId"], SUBNETWORK_ID);
        assert_eq!(payload["allowOrphan"], false);
    }

    #[test]
    fn version_ge_1_rewrites_sig_op_count_to_compute_budget() {
        let inputs = vec![build_rpc_input("ab".repeat(32).as_str(), 0, "cd", 3)];
        let outputs = vec![build_rpc_output(1_000_000, 0, "20abcd")];
        let payload = build_submit_payload(1, inputs, outputs);
        let inp0 = &payload["transaction"]["inputs"][0];
        assert_eq!(inp0["sigOpCount"], 0);
        assert_eq!(inp0["computeBudget"], 30); // 3 sig ops * 10
    }

    #[test]
    fn version_0_leaves_sig_op_count_alone() {
        let inputs = vec![build_rpc_input("ab".repeat(32).as_str(), 0, "cd", 2)];
        let outputs = vec![];
        let payload = build_submit_payload(0, inputs, outputs);
        let inp0 = &payload["transaction"]["inputs"][0];
        assert_eq!(inp0["sigOpCount"], 2);
        assert!(inp0.get("computeBudget").is_none());
    }

    #[test]
    fn output_with_covenant_carries_binding() {
        let out = build_rpc_output_with_covenant(500_000, 0, "20abcd", 1, &"ab".repeat(32));
        assert_eq!(out["covenant"]["authorizingInput"], 1);
        assert_eq!(out["covenant"]["covenantId"], "ab".repeat(32));
    }
}
