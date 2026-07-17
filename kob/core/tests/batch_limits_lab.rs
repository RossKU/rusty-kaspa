//! EXPERIMENTAL batch-limit measurement campaign (kob/BATCH_LIMITS.md).
//!
//! Measures how far one settle transaction scales, per pattern, against the
//! real post-Toccata `kaspa-txscript` `TxScriptEngine` and the vendored
//! consensus mass model. Nothing here changes shipping bytecode: the
//! shipping covenants come from the product builders, the large-N variants
//! from the clearly-experimental `contract::spot::lab` module (whose
//! `max_n = 8` is pinned byte-identical to shipping).
//!
//! Mass model (tn10 post-Toccata, all reproduced from this repo's vendored
//! consensus — see `consensus/core/src/mass/mod.rs`, `mining/src/mempool/
//! check_transaction_standard.rs`):
//!   size        = transaction_estimated_serialized_size (v1: +2B/input
//!                 compute_budget, +34B/covenant output)
//!   compute     = size*1 + spk_bytes*10 + 100*sum(compute_budget units)
//!   transient   = size*4  (block-fit limit 1,000,000)
//!   storage     = KIP-9 with plurality (covenant P2SH outputs = 2);
//!                 block-fit limit 500,000
//!   fee floor   = max(compute, ceil(transient*0.5)) * 100 sompi/gram
//!   per input   = compute_budget*10,000 + 9,999 free script units
//!   pre-Toccata standard cap (the conservative 100k budget quoted in
//!   E2E_LIVE_RESULTS Stage F) = 100,000 per dimension.
//!
//! Run with:
//!   CARGO_TARGET_DIR=/root/kob-rust-target4 cargo test -p kob-core \
//!     --test batch_limits_lab -- --nocapture

use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::mass::{
    calc_storage_mass, transaction_estimated_serialized_size, utxo_plurality, ComputeBudget,
    Gram, ScriptUnits, UtxoCell, GRAMS_PER_COMPUTE_BUDGET_UNIT,
};
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput,
    TransactionOutpoint, TransactionOutput, UtxoEntry, VerifiableTransaction,
};
use kaspa_hashes::Hash;
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::engine_context::EngineCtx;
use kaspa_txscript::{EngineFlags, TxScriptEngine};

use kob_core::contract::spot::bracket::{
    build_bracket_fill_sigscript, build_bracket_redeem_script,
};
use kob_core::contract::spot::lab::{
    build_buy_fill_sigscript_lab, build_buy_partial_fill_sigscript_lab,
    build_buy_redeem_script_lab,
};
use kob_core::contract::spot::oco::{
    build_oco_sell_redeem_script, build_oco_sell_tp_fill_sigscript,
};
use kob_core::contract::spot::order::{
    build_sell_fill_sigscript, build_sell_ioc_fill_sigscript, build_sell_redeem_script,
    BUY_ORDER_MAX_N,
};
use kob_core::contract::spot::swap::{build_swap_fill_sigscript, build_swap_redeem_script};
use kob_core::{blake2b_256, build_p2sh, compute_p2pk_spk_hash};

const PUBKEY_HEX: &str = "b40c46552bc5fcf450d7026e8933b78b6f32b6812c9a94bcbf075cfcb4c249e0";
const TOKEN_HEX: &str = "0c113120cb56668a5aa984752496f8cc4ac65e9044f2fa85d64e7bbcb5fc6039";

/// tn10 post-Toccata block-fit limits (params.rs TESTNET_PARAMS).
const BLOCK_COMPUTE_LIMIT: u64 = 500_000;
const BLOCK_TRANSIENT_LIMIT: u64 = 1_000_000;
const BLOCK_STORAGE_LIMIT: u64 = 500_000;
/// Pre-Toccata per-dimension standard cap — the conservative budget quoted
/// in the Stage F results (6,563 grams vs 100,000).
const STANDARD_CAP: u64 = 100_000;
const STORAGE_MASS_PARAMETER: u64 = 1_000_000_000_000;

fn hash32(hex: &str) -> Hash {
    let b = hex::decode(hex).unwrap();
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    Hash::from_bytes(a)
}
fn arr32(hex: &str) -> [u8; 32] {
    let b = hex::decode(hex).unwrap();
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    a
}
fn p2pk_spk(pubkey: &[u8; 32]) -> ScriptPublicKey {
    let mut s = Vec::with_capacity(34);
    s.push(0x20);
    s.extend_from_slice(pubkey);
    s.push(0xac);
    ScriptPublicKey::new(0, s.into())
}

// ===========================================================================
// Metered execution + node-faithful mass accounting
// ===========================================================================

#[derive(Debug, Clone)]
struct Meter {
    size: u64,
    compute: u64,
    transient: u64,
    #[allow(dead_code)] // folded into `fee`; kept for debugging dumps
    norm_transient: u64,
    storage: u64,
    fee: u64,
    /// Per executed covenant input: script units actually consumed.
    used_units: Vec<u64>,
    /// Total compute-budget units the tx must declare (shipping default =
    /// 10/sig-op; covenant inputs bump this only when they exceed the 9,999
    /// free units).
    budget_units: u64,
    /// max(used units on a covenant input) — must fit a u16 budget * 10,000
    /// + 9,999 to be executable at all.
    max_units: u64,
}

impl Meter {
    fn max_dim(&self) -> u64 {
        self.compute.max(self.transient).max(self.storage)
    }
    fn fits_standard_cap(&self) -> bool {
        self.max_dim() <= STANDARD_CAP
    }
    fn fits_block(&self) -> bool {
        self.compute <= BLOCK_COMPUTE_LIMIT
            && self.transient <= BLOCK_TRANSIENT_LIMIT
            && self.storage <= BLOCK_STORAGE_LIMIT
    }
}

/// Execute the scripts of `exec_idxs` inputs and return per-input
/// (result, used_script_units). Uses an unlimited meter so we can OBSERVE
/// the cost; budget feasibility is judged afterwards.
fn exec_metered(
    tx: &Transaction,
    entries: &[UtxoEntry],
    exec_idxs: &[usize],
) -> Vec<(Result<(), String>, u64)> {
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let cov_ctx = match CovenantsContext::from_tx(&populated) {
        Ok(c) => c,
        Err(e) => {
            return vec![(Err(format!("ctx: {e:?}")), 0); exec_idxs.len()];
        }
    };
    let cache = Cache::new(1000);
    let flags = EngineFlags { covenants_enabled: true, sigop_script_units: Gram(1000).into() };
    let mut out = Vec::new();
    for &idx in exec_idxs {
        let reused = SigHashReusedValuesUnsync::new();
        let ctx = EngineCtx::new(&cache).with_covenants_ctx(&cov_ctx).with_reused(&reused);
        let (input, entry) = populated.populated_input(idx);
        let mut vm = TxScriptEngine::from_transaction_input_with_script_units_limit(
            &populated,
            input,
            idx,
            entry,
            ctx,
            flags,
            ScriptUnits(u64::MAX),
        );
        let res = vm.execute().map_err(|e| format!("{e:?}"));
        out.push((res, u64::from(vm.used_script_units())));
    }
    out
}

/// Node-faithful masses for a fully-signed tx. `sig_ops` gives the wallet
/// (signature) inputs' sig-op counts by input index; covenant inputs are 0.
/// Budgets follow the shipping mapping (10 units/sig-op) plus whatever a
/// covenant input's measured execution requires above the free allowance.
fn measure(
    tx_version: u16,
    inputs: &[(TransactionInput, UtxoEntry, u8)],
    outputs: &[TransactionOutput],
    lock_time: u64,
    exec_idxs: &[usize],
) -> (Meter, Vec<Result<(), String>>) {
    // Assemble with shipping budgets first (execution ignores budgets since
    // the harness meters with an unlimited cap).
    let entries: Vec<UtxoEntry> = inputs.iter().map(|(_, e, _)| e.clone()).collect();
    let raw_inputs: Vec<TransactionInput> = inputs.iter().map(|(i, _, _)| i.clone()).collect();
    let tx = Transaction::new(
        tx_version,
        raw_inputs,
        outputs.to_vec(),
        lock_time,
        Default::default(),
        0,
        vec![],
    );

    let execd = exec_metered(&tx, &entries, exec_idxs);
    let results: Vec<Result<(), String>> = execd.iter().map(|(r, _)| r.clone()).collect();
    let used_units: Vec<u64> = execd.iter().map(|(_, u)| *u).collect();

    // Budgets: shipping default per sig-op, raised where measured units
    // exceed the free allowance.
    let mut budget_units: u64 = 0;
    let mut max_units: u64 = 0;
    let mut needed: Vec<u64> = inputs.iter().map(|(_, _, so)| (*so as u64) * 10).collect();
    for (pos, &idx) in exec_idxs.iter().enumerate() {
        let u = used_units[pos];
        max_units = max_units.max(u);
        let req = ComputeBudget::checked_covering_script_units(ScriptUnits(u))
            .map(|b| b.value() as u64)
            .unwrap_or(u64::MAX);
        if req > needed[idx] {
            needed[idx] = req;
        }
    }
    for n in &needed {
        budget_units += n;
    }

    let size = transaction_estimated_serialized_size(&tx);
    let spk_bytes: u64 = tx
        .outputs
        .iter()
        .map(|o| 2 + o.script_public_key.script().len() as u64)
        .sum();
    let compute = size + spk_bytes * 10 + budget_units * GRAMS_PER_COMPUTE_BUDGET_UNIT;
    let transient = size * 4;
    // tn10 cofactors: reference = compute limit 500k; transient limit 1M
    // -> cofactor 0.5 (mass/mod.rs MassCofactors).
    let norm_transient = transient.div_ceil(2);
    let storage = calc_storage_mass(
        false,
        entries
            .iter()
            .map(|e| UtxoCell::new(utxo_plurality(&e.script_public_key, e.covenant_id.is_some()), e.amount))
            .collect::<Vec<_>>()
            .into_iter(),
        tx.outputs
            .iter()
            .map(|o| UtxoCell::new(utxo_plurality(&o.script_public_key, o.covenant.is_some()), o.value)),
        STORAGE_MASS_PARAMETER,
    )
    .unwrap_or(u64::MAX);
    let fee = compute.max(norm_transient) * 100;

    (
        Meter { size, compute, transient, norm_transient, storage, fee, used_units, budget_units, max_units },
        results,
    )
}

// ===========================================================================
// Pattern builders (values parameterized so the storage-mass edge can sweep)
// ===========================================================================

struct Ctx {
    #[allow(dead_code)]
    pubkey: [u8; 32],
    token: Hash,
    tcid: [u8; 32],
    owner_hash: [u8; 32],
    spk_hash: [u8; 32],
    wallet_spk: ScriptPublicKey,
}

impl Ctx {
    fn new() -> Self {
        let pubkey = arr32(PUBKEY_HEX);
        Ctx {
            pubkey,
            token: hash32(TOKEN_HEX),
            tcid: arr32(TOKEN_HEX),
            owner_hash: blake2b_256(&pubkey),
            spk_hash: compute_p2pk_spk_hash(&pubkey),
            wallet_spk: p2pk_spk(&pubkey),
        }
    }
    fn op(&self, b: u8, i: u32) -> TransactionOutpoint {
        TransactionOutpoint::new(Hash::from_bytes([b; 32]), i)
    }
    fn wallet_entry(&self, amount: u64) -> UtxoEntry {
        UtxoEntry {
            amount,
            script_public_key: self.wallet_spk.clone(),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        }
    }
}

type TxParts = (Vec<(TransactionInput, UtxoEntry, u8)>, Vec<TransactionOutput>, Vec<usize>, usize);

/// N-sell sweep against one buy (GTC/IOC via `ioc`, optional Op2 partial via
/// `residual`). Distinct-seller shape: N seller-KAS outputs + N delivery
/// outputs + change. `max_n` = covenant slot count (8 = shipping bytecode).
fn sweep_parts(cx: &Ctx, max_n: usize, n: usize, v: u64, ioc: bool, residual: Option<u64>, fee_in: u64) -> TxParts {
    let mut inputs = Vec::new();
    for i in 0..n {
        let rs = build_sell_redeem_script(99, 100, 1, &cx.owner_hash, &cx.spk_hash, &cx.spk_hash, 30, 0, 0).unwrap();
        let ss = build_sell_fill_sigscript(i as u16, 99, 100, &rs);
        inputs.push((
            TransactionInput::new(cx.op(0x10, i as u32), ss, 50, 0),
            UtxoEntry {
                amount: v,
                script_public_key: build_p2sh(&rs),
                block_daa_score: 0,
                is_coinbase: false,
                covenant_id: Some(cx.token),
            },
            0u8,
        ));
    }
    let kas_in = v * n as u64 + residual.unwrap_or(0);
    let buy_rs = build_buy_redeem_script_lab(
        max_n, &cx.tcid, 1, 1, 1_000_000, &cx.owner_hash, &cx.spk_hash, &cx.spk_hash, 2000, 0, 0,
    )
    .unwrap();
    let rs_len = buy_rs.len();
    let tii: Vec<u16> = (0..n as u16).collect();
    let buy_ss = match residual {
        None => build_buy_fill_sigscript_lab(max_n, &tii, ioc, &buy_rs),
        Some(_) => build_buy_partial_fill_sigscript_lab(max_n, &tii, (2 * n) as u16, &buy_rs),
    };
    let buy_idx = inputs.len();
    inputs.push((
        TransactionInput::new(cx.op(0x20, 0), buy_ss, 50, 0),
        UtxoEntry {
            amount: kas_in,
            script_public_key: build_p2sh(&buy_rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        },
        0u8,
    ));
    inputs.push((
        TransactionInput::new(cx.op(0x30, 0), vec![0x41; 66], 0, 1),
        cx.wallet_entry(fee_in),
        1u8,
    ));

    let mut outputs = Vec::new();
    for _ in 0..n {
        outputs.push(TransactionOutput::with_covenant(v * 99 / 100, cx.wallet_spk.clone(), None));
    }
    for i in 0..n {
        outputs.push(TransactionOutput::with_covenant(
            v,
            cx.wallet_spk.clone(),
            Some(CovenantBinding::new(i as u16, cx.token)),
        ));
    }
    if let Some(r) = residual {
        outputs.push(TransactionOutput::with_covenant(r, build_p2sh(&buy_rs), None));
    }
    outputs.push(TransactionOutput::with_covenant(500_000_000, cx.wallet_spk.clone(), None));

    let mut exec: Vec<usize> = (0..n).collect();
    exec.push(buy_idx);
    (inputs, outputs, exec, rs_len)
}

/// Merged-seller sweep (the ENGINE's product shape: one seller, one merged
/// KAS output at koi=0): outputs [merged KAS, delivery_0..delivery_{n-1},
/// change]. This is also the only shape valid past N=255 distinct sellers
/// (the canonical attestation forces koi into one byte).
fn sweep_parts_merged(cx: &Ctx, max_n: usize, n: usize, v: u64) -> TxParts {
    let mut inputs = Vec::new();
    let rs = build_sell_redeem_script(99, 100, 1, &cx.owner_hash, &cx.spk_hash, &cx.spk_hash, 30, 0, 0).unwrap();
    for i in 0..n {
        let ss = build_sell_fill_sigscript(0, 99, 100, &rs);
        inputs.push((
            TransactionInput::new(cx.op(0x10, i as u32), ss, 50, 0),
            UtxoEntry {
                amount: v,
                script_public_key: build_p2sh(&rs),
                block_daa_score: 0,
                is_coinbase: false,
                covenant_id: Some(cx.token),
            },
            0u8,
        ));
    }
    let buy_rs = build_buy_redeem_script_lab(
        max_n, &cx.tcid, 1, 1, 1_000_000, &cx.owner_hash, &cx.spk_hash, &cx.spk_hash, 2000, 0, 0,
    )
    .unwrap();
    let rs_len = buy_rs.len();
    let tii: Vec<u16> = (0..n as u16).collect();
    let buy_ss = build_buy_fill_sigscript_lab(max_n, &tii, false, &buy_rs);
    let buy_idx = inputs.len();
    inputs.push((
        TransactionInput::new(cx.op(0x20, 0), buy_ss, 50, 0),
        UtxoEntry {
            amount: v * n as u64,
            script_public_key: build_p2sh(&buy_rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        },
        0u8,
    ));
    inputs.push((
        TransactionInput::new(cx.op(0x30, 0), vec![0x41; 66], 0, 1),
        cx.wallet_entry(1_000_000_000),
        1u8,
    ));
    let mut outputs = vec![TransactionOutput::with_covenant(
        v * 99 / 100 * n as u64,
        cx.wallet_spk.clone(),
        None,
    )];
    for i in 0..n {
        outputs.push(TransactionOutput::with_covenant(
            v,
            cx.wallet_spk.clone(),
            Some(CovenantBinding::new(i as u16, cx.token)),
        ));
    }
    outputs.push(TransactionOutput::with_covenant(500_000_000, cx.wallet_spk.clone(), None));
    let mut exec: Vec<usize> = (0..n).collect();
    exec.push(buy_idx);
    (inputs, outputs, exec, rs_len)
}

/// The live Stage-F form-3 shape (merged seller KAS, D2 token_unit P2SH
/// deliveries, no change output): 5-in/4-out at N=3, 30M sells @99/100.
/// Reproduces the 6,563-gram data point.
fn live_form3_parts(cx: &Ctx) -> TxParts {
    let n = 3usize;
    let v = 30_000_000u64;
    let mut inputs = Vec::new();
    for i in 0..n {
        let rs = build_sell_redeem_script(99, 100, 1, &cx.owner_hash, &cx.spk_hash, &cx.spk_hash, 30, 0, 0).unwrap();
        let ss = build_sell_fill_sigscript(0, 99, 100, &rs);
        inputs.push((
            TransactionInput::new(cx.op(0x10, i as u32), ss, 50, 0),
            UtxoEntry {
                amount: v,
                script_public_key: build_p2sh(&rs),
                block_daa_score: 0,
                is_coinbase: false,
                covenant_id: Some(cx.token),
            },
            0u8,
        ));
    }
    // D2 deliveries land on a token_unit P2SH (35B SPK) — model with a P2SH
    // of the same length class and commit ITS hash as the buy's bspkh seat.
    let tu_spk = build_p2sh(
        &build_sell_redeem_script(1, 1, 1, &cx.owner_hash, &cx.spk_hash, &cx.spk_hash, 30, 0, 0)
            .unwrap(),
    );
    let tu_spkh = kob_core::compute_spk_hash(tu_spk.version(), tu_spk.script());
    let buy_rs = build_buy_redeem_script_lab(
        8, &cx.tcid, 1, 1, 1_000_000, &cx.owner_hash, &tu_spkh, &cx.spk_hash, 2000, 0, 0,
    )
    .unwrap();
    let rs_len = buy_rs.len();
    let buy_ss = build_buy_fill_sigscript_lab(8, &[0, 1, 2], false, &buy_rs);
    inputs.push((
        TransactionInput::new(cx.op(0x20, 0), buy_ss, 50, 0),
        UtxoEntry {
            amount: 3 * v,
            script_public_key: build_p2sh(&buy_rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        },
        0u8,
    ));
    inputs.push((
        TransactionInput::new(cx.op(0x30, 0), vec![0x41; 66], 0, 1),
        cx.wallet_entry(2_000_000),
        1u8,
    ));
    let mut outputs = vec![TransactionOutput::with_covenant(3 * v * 99 / 100, cx.wallet_spk.clone(), None)];
    for i in 0..n {
        outputs.push(TransactionOutput::with_covenant(
            v,
            tu_spk.clone(),
            Some(CovenantBinding::new(i as u16, cx.token)),
        ));
    }
    (inputs, outputs, vec![0, 1, 2, 3], rs_len)
}

/// N independent sell-side IOC fills paid by one wallet input:
/// outputs [kas_0..kas_{n-1}] then per sell [residual_i, delivery_i], change.
fn sell_ioc_parts(cx: &Ctx, n: usize, v: u64, fta: u64) -> TxParts {
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();
    let rs = build_sell_redeem_script(99, 100, 1, &cx.owner_hash, &cx.spk_hash, &cx.spk_hash, 30, 0, 0).unwrap();
    let rs_len = rs.len();
    for i in 0..n {
        let ss = build_sell_ioc_fill_sigscript(i as u16, 99, 100, fta, &rs);
        inputs.push((
            TransactionInput::new(cx.op(0x10, i as u32), ss, 50, 0),
            UtxoEntry {
                amount: v,
                script_public_key: build_p2sh(&rs),
                block_daa_score: 0,
                is_coinbase: false,
                covenant_id: Some(cx.token),
            },
            0u8,
        ));
    }
    inputs.push((
        TransactionInput::new(cx.op(0x30, 0), vec![0x41; 66], 0, 1),
        cx.wallet_entry(1_000_000_000),
        1u8,
    ));
    for _ in 0..n {
        outputs.push(TransactionOutput::with_covenant(fta * 99 / 100, cx.wallet_spk.clone(), None));
    }
    for i in 0..n {
        // auth slot 0 = residual continuation (self-SPK), slot 1 = delivery.
        outputs.push(TransactionOutput::with_covenant(
            v - fta,
            build_p2sh(&rs),
            Some(CovenantBinding::new(i as u16, cx.token)),
        ));
        outputs.push(TransactionOutput::with_covenant(
            fta,
            cx.wallet_spk.clone(),
            Some(CovenantBinding::new(i as u16, cx.token)),
        ));
    }
    outputs.push(TransactionOutput::with_covenant(500_000_000, cx.wallet_spk.clone(), None));
    (inputs, outputs, (0..n).collect(), rs_len)
}

/// N OCO sells (TP branch, 2/1) swept by one buy (max 8 on shipping).
fn oco_sweep_parts(cx: &Ctx, max_n: usize, n: usize, v: u64) -> TxParts {
    let mut inputs = Vec::new();
    for i in 0..n {
        let rs = build_oco_sell_redeem_script(2, 1, 1, 1, 2, 1, &cx.owner_hash, &cx.spk_hash, &cx.spk_hash, 30, 0, 0).unwrap();
        let ss = build_oco_sell_tp_fill_sigscript(i as u16, 2, 1, &rs);
        inputs.push((
            TransactionInput::new(cx.op(0x10, i as u32), ss, 50, 0),
            UtxoEntry {
                amount: v,
                script_public_key: build_p2sh(&rs),
                block_daa_score: 0,
                is_coinbase: false,
                covenant_id: Some(cx.token),
            },
            0u8,
        ));
    }
    // Buy at the inverted TP rate: floor = kas_in/2*1 = n*v.
    let buy_rs = build_buy_redeem_script_lab(
        max_n, &cx.tcid, 1, 2, 1_000_000, &cx.owner_hash, &cx.spk_hash, &cx.spk_hash, 2000, 0, 0,
    )
    .unwrap();
    let rs_len = buy_rs.len();
    let tii: Vec<u16> = (0..n as u16).collect();
    let buy_ss = build_buy_fill_sigscript_lab(max_n, &tii, false, &buy_rs);
    let buy_idx = inputs.len();
    inputs.push((
        TransactionInput::new(cx.op(0x20, 0), buy_ss, 50, 0),
        UtxoEntry {
            amount: 2 * v * n as u64,
            script_public_key: build_p2sh(&buy_rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        },
        0u8,
    ));
    inputs.push((
        TransactionInput::new(cx.op(0x30, 0), vec![0x41; 66], 0, 1),
        cx.wallet_entry(1_000_000_000),
        1u8,
    ));
    let mut outputs = Vec::new();
    for _ in 0..n {
        outputs.push(TransactionOutput::with_covenant(2 * v, cx.wallet_spk.clone(), None));
    }
    for i in 0..n {
        outputs.push(TransactionOutput::with_covenant(
            v,
            cx.wallet_spk.clone(),
            Some(CovenantBinding::new(i as u16, cx.token)),
        ));
    }
    outputs.push(TransactionOutput::with_covenant(500_000_000, cx.wallet_spk.clone(), None));
    let mut exec: Vec<usize> = (0..n).collect();
    exec.push(buy_idx);
    (inputs, outputs, exec, rs_len)
}

/// n-leg ring on the SHIPPING swap covenant (per-leg checks are local; the
/// 2..=3 cap is a planner policy, not bytecode).
fn ring_parts(cx: &Ctx, n: usize, v: u64) -> TxParts {
    let mmfee_bps = 100u64;
    let token_id = |i: usize| -> [u8; 32] {
        let mut t = [0xd0u8; 32];
        t[0] = (i & 0xff) as u8;
        t[1] = (i >> 8) as u8;
        t
    };
    let tokens: Vec<Hash> = (0..n).map(|i| Hash::from_bytes(token_id(i))).collect();
    let token_arrs: Vec<[u8; 32]> = (0..n).map(token_id).collect();
    let amounts: Vec<u64> = (0..n).map(|_| v).collect();
    let fee = |amt: u64| amt / 10000 * mmfee_bps;
    let mut rss = Vec::new();
    for i in 0..n {
        let tgt = (i + 1) % n;
        let min_target = amounts[tgt] - fee(amounts[tgt]);
        rss.push(
            build_swap_redeem_script(
                &token_arrs[i], &token_arrs[tgt], min_target, &cx.owner_hash, &cx.spk_hash,
                &[0xee; 32], mmfee_bps,
            )
            .unwrap(),
        );
    }
    let rs_len = rss[0].len();
    let mut inputs = Vec::new();
    for i in 0..n {
        let tgt = (i + 1) % n;
        let ss = build_swap_fill_sigscript(tgt as u16, tgt as u16, &rss[i]);
        inputs.push((
            TransactionInput::new(cx.op(0x60, i as u32), ss, 50, 0),
            UtxoEntry {
                amount: amounts[i],
                script_public_key: build_p2sh(&rss[i]),
                block_daa_score: 0,
                is_coinbase: false,
                covenant_id: Some(tokens[i]),
            },
            0u8,
        ));
    }
    inputs.push((
        TransactionInput::new(cx.op(0x70, 0), vec![0x41; 66], 0, 1),
        cx.wallet_entry(1_000_000_000),
        1u8,
    ));
    let mut outputs = Vec::new();
    for j in 0..n {
        outputs.push(TransactionOutput::with_covenant(
            amounts[j],
            cx.wallet_spk.clone(),
            Some(CovenantBinding::new(j as u16, tokens[j])),
        ));
    }
    outputs.push(TransactionOutput::with_covenant(500_000_000, cx.wallet_spk.clone(), None));
    (inputs, outputs, (0..n).collect(), rs_len)
}

/// Buy-entry bracket fill (rigid 4-in/4-out shape) — same as the proven
/// spot_contracts harness happy path.
fn bracket_parts(cx: &Ctx) -> TxParts {
    let receipt_cov = Hash::from_bytes([0xE1; 32]);
    let matcher_spk = p2pk_spk(&[0xcc; 32]);
    let oco_rs = build_oco_sell_redeem_script(2, 1, 1, 1, 2, 1, &cx.owner_hash, &cx.spk_hash, &cx.spk_hash, 30, 0, 0).unwrap();
    let oco_p2sh = build_p2sh(&oco_rs);
    let mut oco_spk37 = [0u8; 37];
    oco_spk37[0..2].copy_from_slice(&oco_p2sh.version.to_le_bytes());
    oco_spk37[2..37].copy_from_slice(oco_p2sh.script());
    let rs = build_bracket_redeem_script(
        0, &cx.tcid, 1, 1, &oco_spk37, 30_000_000, 1_000_000, 5_000_000, &[0xE1; 32],
        &cx.spk_hash, &cx.owner_hash,
    )
    .unwrap();
    let rs_len = rs.len();
    let ss = build_bracket_fill_sigscript(&rs);
    let inputs = vec![
        (
            TransactionInput::new(cx.op(0x80, 0), ss, 50, 0),
            UtxoEntry {
                amount: 30_000_000,
                script_public_key: build_p2sh(&rs),
                block_daa_score: 0,
                is_coinbase: false,
                covenant_id: None,
            },
            0u8,
        ),
        (
            TransactionInput::new(cx.op(0x81, 0), vec![0x41; 66], 0, 1),
            UtxoEntry {
                amount: 100_000_000,
                script_public_key: matcher_spk.clone(),
                block_daa_score: 0,
                is_coinbase: false,
                covenant_id: None,
            },
            1u8,
        ),
        (
            TransactionInput::new(cx.op(0x82, 0), vec![0x41; 66], 0, 1),
            UtxoEntry {
                amount: 5_000_000,
                script_public_key: matcher_spk.clone(),
                block_daa_score: 0,
                is_coinbase: false,
                covenant_id: Some(receipt_cov),
            },
            1u8,
        ),
        (
            TransactionInput::new(cx.op(0x83, 0), vec![0x41; 66], 0, 1),
            UtxoEntry {
                amount: 100_000_000,
                script_public_key: matcher_spk.clone(),
                block_daa_score: 0,
                is_coinbase: false,
                covenant_id: Some(cx.token),
            },
            1u8,
        ),
    ];
    let oco_spk_full = ScriptPublicKey::new(
        u16::from_le_bytes([oco_spk37[0], oco_spk37[1]]),
        oco_spk37[2..37].to_vec().into(),
    );
    // Live form-13 scale: 30M entry, 30M delivery, 30M OCO spawn.
    let outputs = vec![
        TransactionOutput::with_covenant(30_000_000, matcher_spk.clone(), None),
        TransactionOutput::with_covenant(30_000_000, cx.wallet_spk.clone(), Some(CovenantBinding::new(3, cx.token))),
        TransactionOutput::with_covenant(30_000_000, oco_spk_full, Some(CovenantBinding::new(3, cx.token))),
        TransactionOutput::with_covenant(35_000_000, matcher_spk.clone(), None),
    ];
    (inputs, outputs, vec![0], rs_len)
}

// ===========================================================================
// Reporting
// ===========================================================================

fn assert_all_pass(label: &str, results: &[Result<(), String>]) {
    for (i, r) in results.iter().enumerate() {
        assert!(r.is_ok(), "{label}: executed input #{i} must pass: {r:?}");
    }
}

fn row(label: &str, n: usize, rs_len: usize, m: &Meter) {
    println!(
        "| {label} | {n} | {rs_len} | {} | {} | {} | {} | {} | {} | {} | {} |",
        m.size,
        m.compute,
        m.transient,
        m.storage,
        m.max_dim(),
        m.fee,
        m.used_units.last().copied().unwrap_or(0),
        m.budget_units,
    );
}

fn header() {
    println!("| pattern | N | RS bytes | tx bytes | compute | transient | storage | max-dim | min fee (sompi) | buy units | budget units |");
    println!("|---|---|---|---|---|---|---|---|---|---|---|");
}

// ===========================================================================
// 0) model validation against the live Stage-F 6,563-gram data point
// ===========================================================================

#[test]
fn live_form3_compute_mass_reproduced() {
    let cx = Ctx::new();
    let (inputs, outputs, exec, rs_len) = live_form3_parts(&cx);
    let (m, results) = measure(1, &inputs, &outputs, 50, &exec);
    assert_all_pass("live-form3", &results);
    println!("live form-3 GTC 3:1 (merged seller, D2 deliveries):");
    header();
    row("GTC 3:1 live shape", 3, rs_len, &m);
    assert_eq!(
        m.compute, 6_563,
        "offline mass model must reproduce the live Stage-F compute mass"
    );
}

// ===========================================================================
// 1) shipping covenant, GTC sweep N in {1,2,4,8} + linear model
// ===========================================================================

#[test]
fn shipping_gtc_sweep_masses() {
    let cx = Ctx::new();
    let v = 100_000_000u64; // 1 KAS-scale token value keeps storage subordinate
    println!("shipping GTC sweep (distinct sellers, v={v}):");
    header();
    let mut pts = Vec::new();
    for n in [1usize, 2, 4, 8] {
        let (inputs, outputs, exec, rs_len) = sweep_parts(&cx, BUY_ORDER_MAX_N, n, v, false, None, 1_000_000_000);
        let (m, results) = measure(1, &inputs, &outputs, 50, &exec);
        assert_all_pass(&format!("GTC N={n}"), &results);
        assert!(m.fits_block(), "shipping N={n} must fit block limits: {m:?}");
        row("GTC (ship)", n, rs_len, &m);
        pts.push((n as f64, m.compute as f64));
        assert!(
            m.max_units <= 9_999,
            "shipping sweeps must run on budget-0 inputs (free allowance); N={n} used {}",
            m.max_units
        );
    }
    // Merged-seller (product engine) shape at N=8 for live comparison.
    let (inputs, outputs, exec, rs_len) = sweep_parts_merged(&cx, BUY_ORDER_MAX_N, 8, v);
    let (m, results) = measure(1, &inputs, &outputs, 50, &exec);
    assert_all_pass("GTC merged N=8", &results);
    row("GTC merged (ship)", 8, rs_len, &m);

    // Least-squares fit compute = a + b*N.
    let k = pts.len() as f64;
    let sx: f64 = pts.iter().map(|p| p.0).sum();
    let sy: f64 = pts.iter().map(|p| p.1).sum();
    let sxx: f64 = pts.iter().map(|p| p.0 * p.0).sum();
    let sxy: f64 = pts.iter().map(|p| p.0 * p.1).sum();
    let b = (k * sxy - sx * sy) / (k * sxx - sx * sx);
    let a = (sy - b * sx) / k;
    println!("fit: compute ~= {a:.0} + {b:.0} * N (distinct-seller shape)");
}

// ===========================================================================
// 2) experimental covenants MAX_N in {16,32,64} + N_max search
// ===========================================================================

fn probe_gtc(cx: &Ctx, n: usize, v: u64) -> (Meter, Vec<Result<(), String>>, usize) {
    let (inputs, outputs, exec, rs_len) = sweep_parts(cx, n, n, v, false, None, 1_000_000_000);
    let (m, results) = measure(1, &inputs, &outputs, 50, &exec);
    (m, results, rs_len)
}

#[test]
fn experimental_gtc_variants_and_ceiling() {
    let cx = Ctx::new();
    let v = 400_000_000u64;
    println!("experimental GTC sweeps at N = MAX_N (v={v}):");
    header();
    for n in [16usize, 32, 64] {
        let (m, results, rs_len) = probe_gtc(&cx, n, v);
        assert_all_pass(&format!("exp GTC N={n}"), &results);
        row("GTC (exp)", n, rs_len, &m);
    }
    // RS growth per slot.
    let rs8 = build_buy_redeem_script_lab(8, &cx.tcid, 1, 1, 1, &cx.owner_hash, &cx.spk_hash, &cx.spk_hash, 30, 0, 0).unwrap().len();
    let rs16 = build_buy_redeem_script_lab(16, &cx.tcid, 1, 1, 1, &cx.owner_hash, &cx.spk_hash, &cx.spk_hash, 30, 0, 0).unwrap().len();
    let rs64 = build_buy_redeem_script_lab(64, &cx.tcid, 1, 1, 1, &cx.owner_hash, &cx.spk_hash, &cx.spk_hash, 30, 0, 0).unwrap().len();
    println!("RS growth: 8->{rs8}B, 16->{rs16}B ({}B/slot), 64->{rs64}B ({}B/slot)",
        (rs16 - rs8) / 8, (rs64 - rs16) / 48);

    // Binary search: largest N with compute <= 100k standard cap AND engine PASS.
    let ok = |n: usize| -> bool {
        let (m, results, _) = probe_gtc(&cx, n, v);
        results.iter().all(|r| r.is_ok()) && m.compute <= STANDARD_CAP
    };
    let (mut lo, mut hi) = (8usize, 128usize);
    assert!(ok(lo) && !ok(hi), "search bracket must hold");
    while hi - lo > 1 {
        let mid = (lo + hi) / 2;
        if ok(mid) { lo = mid } else { hi = mid }
    }
    let (m_at, _, rs_at) = probe_gtc(&cx, lo, v);
    println!("N_max (compute <= 100k standard cap, engine PASS): {lo}");
    header();
    row("GTC @N_max(100k)", lo, rs_at, &m_at);
    let (m_over, _, _) = probe_gtc(&cx, lo + 1, v);
    println!("first over-cap N={}: compute {}", lo + 1, m_over.compute);

    // Merged-seller (product engine shape) N_max under the 100k cap.
    let ok_merged = |n: usize| -> bool {
        let (inputs, outputs, exec, _) = sweep_parts_merged(&cx, n, n, v);
        let (m, results) = measure(1, &inputs, &outputs, 50, &exec);
        results.iter().all(|r| r.is_ok()) && m.compute <= STANDARD_CAP
    };
    let (mut lo1, mut hi1) = (8usize, 128usize);
    assert!(ok_merged(lo1) && !ok_merged(hi1), "merged bracket must hold");
    while hi1 - lo1 > 1 {
        let mid = (lo1 + hi1) / 2;
        if ok_merged(mid) { lo1 = mid } else { hi1 = mid }
    }
    let (inputs, outputs, exec, rs_m) = sweep_parts_merged(&cx, lo1, lo1, v);
    let (m_m, results_m) = measure(1, &inputs, &outputs, 50, &exec);
    assert_all_pass("merged @N_max", &results_m);
    println!("N_max merged-seller shape (compute <= 100k, engine PASS): {lo1}");
    header();
    row("GTC merged @N_max", lo1, rs_m, &m_m);

    // Engine-only ceiling (ignore mass): where does the VM itself stop?
    // Merged shape — the distinct-seller shape is separately capped at
    // N=255 by the one-byte koi attestation convention.
    let engine_ok = |n: usize| -> bool {
        let (inputs, outputs, exec, _) = sweep_parts_merged(&cx, n, n, v);
        let (m, results) = measure(1, &inputs, &outputs, 50, &exec);
        results.iter().all(|r| r.is_ok())
            && ComputeBudget::checked_covering_script_units(ScriptUnits(m.max_units)).is_some()
    };
    let (mut lo2, mut hi2) = (64usize, 300usize);
    assert!(engine_ok(lo2) && !engine_ok(hi2), "engine bracket must hold");
    while hi2 - lo2 > 1 {
        let mid = (lo2 + hi2) / 2;
        if engine_ok(mid) { lo2 = mid } else { hi2 = mid }
    }
    let (inputs, outputs, exec, rs_eng) = sweep_parts_merged(&cx, lo2, lo2, v);
    let (m_eng, _) = measure(1, &inputs, &outputs, 50, &exec);
    println!("N_max (TxScriptEngine hard limit, mass ignored, merged shape): {lo2}");
    header();
    row("GTC @engine-limit", lo2, rs_eng, &m_eng);
    let (inputs, outputs, exec, _) = sweep_parts_merged(&cx, lo2 + 1, lo2 + 1, v);
    let (_, res_fail) = measure(1, &inputs, &outputs, 50, &exec);
    let first_err = res_fail.iter().find(|r| r.is_err()).map(|r| r.clone().unwrap_err());
    println!("first engine failure at N={}: {:?}", lo2 + 1, first_err);

    // Live-planning probe: minimum per-sell value keeping storage <= 450k
    // (50k margin under the 500k block limit) for candidate live N.
    for n in [16usize, 24, 32, 60] {
        let storage_at = |vv: u64| -> u64 {
            let (inputs, outputs, _, _) = sweep_parts_merged(&cx, n, n, vv);
            storage_of(&inputs, &outputs)
        };
        let (mut lo, mut hi) = (1_000_000u64, 8_000_000_000);
        if storage_at(hi) > 450_000 {
            println!("N={n}: no viable value under 8e9");
            continue;
        }
        while hi - lo > 100_000 {
            let mid = lo + (hi - lo) / 2;
            if storage_at(mid) <= 450_000 { hi = mid } else { lo = mid }
        }
        println!("N={n} merged sweep: min per-sell value for storage<=450k ~= {hi} sompi-units ({} total)", hi * n as u64);
    }
}

/// Storage mass of assembled parts (no execution).
fn storage_of(inputs: &[(TransactionInput, UtxoEntry, u8)], outputs: &[TransactionOutput]) -> u64 {
    calc_storage_mass(
        false,
        inputs
            .iter()
            .map(|(_, e, _)| UtxoCell::new(utxo_plurality(&e.script_public_key, e.covenant_id.is_some()), e.amount))
            .collect::<Vec<_>>()
            .into_iter(),
        outputs
            .iter()
            .map(|o| UtxoCell::new(utxo_plurality(&o.script_public_key, o.covenant.is_some()), o.value)),
        STORAGE_MASS_PARAMETER,
    )
    .unwrap_or(u64::MAX)
}

// ===========================================================================
// 3) other patterns at their maxima
// ===========================================================================

#[test]
fn other_patterns_masses() {
    let cx = Ctx::new();
    let v = 100_000_000u64;
    println!("other patterns:");
    header();

    // IOC sweep at N=8 (shipping).
    let (inputs, outputs, exec, rs_len) = sweep_parts(&cx, 8, 8, v, true, None, 1_000_000_000);
    let (m, results) = measure(1, &inputs, &outputs, 50, &exec);
    assert_all_pass("IOC N=8", &results);
    row("IOC sweep (ship)", 8, rs_len, &m);

    // Buy Op2 partial with residual at N=8 (shipping).
    let (inputs, outputs, exec, rs_len) = sweep_parts(&cx, 8, 8, v, false, Some(50_000_000), 1_000_000_000);
    let (m, results) = measure(1, &inputs, &outputs, 50, &exec);
    assert_all_pass("partial N=8", &results);
    row("Op2 partial (ship)", 8, rs_len, &m);

    // Experimental partial ceiling: the self-instance uniqueness guard scans
    // 16 inputs -> N=14 sells (16 inputs total) passes, N=15 (17) fails.
    let (inputs, outputs, exec, rs_len) = sweep_parts(&cx, 14, 14, v, false, Some(50_000_000), 1_000_000_000);
    let (m, results) = measure(1, &inputs, &outputs, 50, &exec);
    assert_all_pass("partial N=14", &results);
    row("Op2 partial (exp)", 14, rs_len, &m);
    let (inputs, outputs, exec, _) = sweep_parts(&cx, 15, 15, v, false, Some(50_000_000), 1_000_000_000);
    let (_, results) = measure(1, &inputs, &outputs, 50, &exec);
    assert!(
        results.last().unwrap().is_err(),
        "partial with 17 tx inputs must trip the 16-input uniqueness guard"
    );
    println!("(Op2 partial hard ceiling: N=14 — 17th input trips the P5 guard, engine-verified)");

    // Sell-side IOC batch at N=8 (shipping; one payer wallet). Values sized
    // so the 2N covenant outputs (residual + delivery per sell) stay inside
    // the 500k storage block limit.
    let (inputs, outputs, exec, rs_len) = sell_ioc_parts(&cx, 8, 400_000_000, 200_000_000);
    let (m, results) = measure(1, &inputs, &outputs, 50, &exec);
    assert_all_pass("sell IOC N=8", &results);
    row("sell IOC batch", 8, rs_len, &m);

    // OCO-heavy sweep: 8 OCO sells against one buy (shipping).
    let (inputs, outputs, exec, rs_len) = oco_sweep_parts(&cx, 8, 8, v);
    let (m, results) = measure(1, &inputs, &outputs, 50, &exec);
    assert_all_pass("OCO sweep N=8", &results);
    row("OCO sweep (ship)", 8, rs_len, &m);

    // Rings: shipping bytecode, 2..6 legs (planner caps at 3; the covenant
    // has no leg bound — checks are local).
    for legs in [2usize, 3, 4, 5, 6] {
        let (inputs, outputs, exec, rs_len) = ring_parts(&cx, legs, v);
        let (m, results) = measure(1, &inputs, &outputs, 50, &exec);
        assert_all_pass(&format!("ring {legs}"), &results);
        row("ring (ship bytecode)", legs, rs_len, &m);
    }
    // Ring ceiling under the 100k standard cap.
    let ring_ok = |legs: usize| -> bool {
        let (inputs, outputs, exec, _) = ring_parts(&cx, legs, 400_000_000);
        let (m, results) = measure(1, &inputs, &outputs, 50, &exec);
        results.iter().all(|r| r.is_ok()) && m.compute <= STANDARD_CAP
    };
    let (mut lo, mut hi) = (6usize, 400usize);
    assert!(ring_ok(lo) && !ring_ok(hi));
    while hi - lo > 1 {
        let mid = (lo + hi) / 2;
        if ring_ok(mid) { lo = mid } else { hi = mid }
    }
    let (inputs, outputs, exec, rs_len) = ring_parts(&cx, lo, 400_000_000);
    let (m, results) = measure(1, &inputs, &outputs, 50, &exec);
    assert_all_pass("ring @max", &results);
    println!("ring legs_max (compute <= 100k, engine PASS): {lo}");
    row("ring @legs_max", lo, rs_len, &m);

    // Bracket fill (rigid shape).
    let (inputs, outputs, exec, rs_len) = bracket_parts(&cx);
    let (m, results) = measure(1, &inputs, &outputs, 0, &exec);
    assert_all_pass("bracket", &results);
    row("bracket fill", 1, rs_len, &m);
}

// ===========================================================================
// 4) storage-mass edge: value floor + in/out cancellation
// ===========================================================================

#[test]
fn storage_mass_value_floor() {
    let cx = Ctx::new();
    println!("storage-mass edge, shipping GTC N=8 (distinct sellers, 10-KAS fee input):");
    println!("| v (sompi/units per sell) | compute | storage | binding dim | fits 500k block? | fits 100k cap? |");
    println!("|---|---|---|---|---|---|");
    let mut floor_500k = None;
    let mut floor_compute = None;
    for v in [
        20_000_000u64, 40_000_000, 60_000_000, 65_000_000, 80_000_000, 100_000_000,
        200_000_000, 400_000_000, 800_000_000, 2_000_000_000, 4_000_000_000, 8_000_000_000,
    ] {
        let (inputs, outputs, exec, _) = sweep_parts(&cx, 8, 8, v, false, None, 1_000_000_000);
        let (m, results) = measure(1, &inputs, &outputs, 50, &exec);
        assert_all_pass(&format!("storage v={v}"), &results);
        let binding = if m.storage > m.compute { "storage" } else { "compute" };
        println!(
            "| {v} | {} | {} | {binding} | {} | {} |",
            m.compute,
            m.storage,
            m.storage <= BLOCK_STORAGE_LIMIT && m.fits_block(),
            m.fits_standard_cap(),
        );
        if floor_500k.is_none() && m.storage <= BLOCK_STORAGE_LIMIT {
            floor_500k = Some(v);
        }
        if floor_compute.is_none() && m.storage <= m.compute {
            floor_compute = Some(v);
        }
    }
    println!("coarse floors: storage<=500k from v~{floor_500k:?}; storage<=compute from v~{floor_compute:?}");

    // Bisect the exact 500k-block floor value for N=8.
    let storage_at = |v: u64| -> u64 {
        let (inputs, outputs, _, _) = sweep_parts(&cx, 8, 8, v, false, None, 1_000_000_000);
        let entries: Vec<UtxoEntry> = inputs.iter().map(|(_, e, _)| e.clone()).collect();
        calc_storage_mass(
            false,
            entries
                .iter()
                .map(|e| UtxoCell::new(utxo_plurality(&e.script_public_key, e.covenant_id.is_some()), e.amount))
                .collect::<Vec<_>>()
                .into_iter(),
            outputs
                .iter()
                .map(|o| UtxoCell::new(utxo_plurality(&o.script_public_key, o.covenant.is_some()), o.value)),
            STORAGE_MASS_PARAMETER,
        )
        .unwrap_or(u64::MAX)
    };
    let (mut lo, mut hi) = (1_000_000u64, 8_000_000_000);
    assert!(storage_at(lo) > BLOCK_STORAGE_LIMIT && storage_at(hi) <= BLOCK_STORAGE_LIMIT);
    while hi - lo > 1_000 {
        let mid = lo + (hi - lo) / 2;
        if storage_at(mid) <= BLOCK_STORAGE_LIMIT { hi = mid } else { lo = mid }
    }
    println!("exact N=8 storage floor (<=500k block limit): v ~= {hi} sompi/units per sell");

    // In/out cancellation: matched trade (token escrows in = deliveries out)
    // vs the same outputs conjured from one wallet UTXO (deploy-like shape).
    let v = 100_000_000u64;
    let (inputs, outputs, _, _) = sweep_parts(&cx, 8, 8, v, false, None, 1_000_000_000);
    let matched = {
        let entries: Vec<UtxoEntry> = inputs.iter().map(|(_, e, _)| e.clone()).collect();
        calc_storage_mass(
            false,
            entries
                .iter()
                .map(|e| UtxoCell::new(utxo_plurality(&e.script_public_key, e.covenant_id.is_some()), e.amount))
                .collect::<Vec<_>>()
                .into_iter(),
            outputs
                .iter()
                .map(|o| UtxoCell::new(utxo_plurality(&o.script_public_key, o.covenant.is_some()), o.value)),
            STORAGE_MASS_PARAMETER,
        )
        .unwrap()
    };
    let single_funder = calc_storage_mass(
        false,
        vec![UtxoCell::new(1, 2_500_000_000u64)].into_iter(),
        outputs
            .iter()
            .map(|o| UtxoCell::new(utxo_plurality(&o.script_public_key, o.covenant.is_some()), o.value)),
        STORAGE_MASS_PARAMETER,
    )
    .unwrap();
    println!(
        "in/out cancellation at v={v}: matched-sweep storage {matched} vs single-funder {single_funder} \
         (matched trades get the escrow inputs' plurality credit)"
    );
    assert!(matched < single_funder);
}
