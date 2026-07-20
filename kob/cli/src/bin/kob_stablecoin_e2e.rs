//! Testnet-10 live E2E harness for the **robust** KCC-0020 stablecoin
//! (`STABLECOIN_ROBUST_DESIGN.md`, `kob_core::contract::stablecoin` +
//! `kob_core::contract::stablecoin::mint_authority`).
//!
//! This binary builds, signs, submits, and polls the FULL lifecycle against a
//! live node, in order:
//!
//!   1. DEPLOY TX1  -- anchor output tagged with the mint-authority's
//!      genesis `covenant_id` (G).
//!   2. DEPLOY TX2  -- spends the anchor, creates the real mint-authority
//!      covenant with G baked in (`running_supply=0`, `current_cap=CAP`).
//!   3. MINT        -- mints `MINT_AMOUNT` sompi of the stablecoin to
//!      `owner`.
//!   4. TRANSFER    -- `owner` -> `owner2` (OPS-attested).
//!   5. FREEZE      -- FREEZE-role sets `frozen_flag=1` (no owner sig).
//!   6. SEIZE       -- 2-of-3 SEIZE quorum force-moves the (still frozen)
//!      coin to `recovery`.
//!   7. UNFREEZE    -- a second FREEZE op (`new_frozen_flag=0`) clearing the
//!      gate so the coin is burnable again (see "Frozen-gate ordering"
//!      below) -- NOT one of the task's 7 named ops, but required for BURN
//!      to succeed given the FREEZE->SEIZE ordering above.
//!   8. BURN        -- `recovery` (owner) + MINT-role attestation moves the
//!      coin's full value to the canonical unspendable sink: a P2SH wrapping
//!      of a bare `OpReturn` redeem script (standard/relayable output form,
//!      provably unspendable underneath -- see `BURN_SINK_SCRIPT`'s doc in
//!      `core/src/contract/stablecoin/body.rs`).
//!      With `MIGRATE_DEMO=1`, step 8 runs **MIGRATE** instead: `recovery`
//!      (owner) + a cold 2-of-3 SEIZE quorum move the coin to a wholly
//!      different template (here a plain wallet P2PK output -- the branch
//!      never inspects the destination), so the coin leaves covenant
//!      governance by deliberate cold decision. The two are alternatives, not
//!      successive steps, because this harness mints exactly one coin; both
//!      leave a wallet change output at index 1, which step 9 chains off.
//!   9. RAISE_CAP   -- 2-of-3 `cap_authority` quorum raises the mint
//!      authority's `current_cap` (independent of the coin lifecycle above;
//!      run last only because the task's sequence lists it last).
//!
//! This binary is NOT executed as part of this change -- it only needs to
//! COMPILE. The live run happens in a separate step.
//!
//! # Frozen-gate ordering (why step 7 exists)
//!
//! TRANSFER/BURN/MIGRATE all hard-gate on `frozen_flag == 0` (a frozen coin
//! is fully owner-immobile: `core/src/contract/stablecoin/body.rs`'s
//! `build_transfer_branch`/`build_burn_branch`/`build_migrate_branch` each
//! roll `frozen_flag` to the top, compare against the explicit literal
//! `[0x00]`, and `OpVerify`). SEIZE has NO frozen gate at all (by design --
//! it must be able to force-move a frozen/sanctioned coin, or rescue a
//! lost-key coin regardless of its frozen state) but it PRESERVES
//! `frozen_flag` unchanged into the successor
//! (`build_seize_branch`'s doc: "This implementation PRESERVES the input's
//! current `frozen_flag` unchanged into the successor"). So after step 5
//! (FREEZE, `frozen_flag` 0->1) and step 6 (SEIZE, ownership moves but
//! `frozen_flag` stays 1), the coin is STILL frozen -- an unmodified step 8
//! (BURN) would be rejected by the same `frozen_flag == 0` gate. Step 7
//! inserts an explicit UNFREEZE (a second FREEZE spend, `new_frozen_flag=0`,
//! owner_pubkey unchanged = `recovery`) between SEIZE and BURN to clear it.
//!
//! # 2-transaction genesis (avoids the hash-fixed-point)
//!
//! The mint-authority body bakes its OWN genesis `covenant_id` (`G`) as a
//! literal (the anti-parallel-authority SUB-FIX B in
//! `STABLECOIN_ROBUST_DESIGN.md` §9) -- but `G` cannot be derived from the
//! same script it is baked into (a literal that is a hash of the script
//! containing that literal is a hash fixed-point). Deployment is therefore
//! two transactions (design doc §9, "Deploy consequence: two-transaction
//! bootstrap"): **TX1** creates a plain (non-covenant-bytecode) anchor
//! output -- this harness reuses the wallet's own P2PK script, so TX2 can
//! spend it with an ordinary signature -- tagged with a `CovenantBinding` for
//! `G` (computed via `compute_covenant_id` from the wallet funding UTXO's
//! OWN outpoint, which is not circular since the anchor's SPK does not
//! depend on `G`). **TX2** spends that anchor as its sole input and creates
//! the REAL mint-authority redeem script with `G` now baked in
//! (`build_mint_authority_redeem_script`'s last argument), binding its own
//! output to the SAME `G` -- a continuation, not a fresh genesis.
//!
//! # Per-coin covenant_id (distinct from the mint authority's G)
//!
//! Every MINT creates a brand-new stablecoin coin with ITS OWN fresh
//! `covenant_id` (design doc: "each MINT output gets its own fresh genesis
//! `covenant_id`, exactly as a self-funded lookalike coin would get its own
//! fresh genesis `covenant_id`") -- the mint-authority's self-continuation
//! output[0] keeps propagating `G` unchanged (a direct continuation, no
//! recompute), while the newly-minted coin at output[1] gets an
//! INDEPENDENTLY computed `compute_covenant_id(mint_authority_outpoint.txid,
//! mint_authority_outpoint.index, &[AuthOutput{index: 1, ...}])` -- i.e. the
//! SAME genesis-outpoint convention every other single-output genesis in
//! this codebase uses (`cli/src/stablecoin.rs`'s old case-A deploy,
//! `cli/src/token.rs`, `cli/src/receipt.rs`), with the auth_outputs list
//! containing ONLY that one new output. This is the harness's own
//! prediction of what the (out-of-repo, vendored) consensus code assigns;
//! see the FINAL REPORT for why this is flagged as an assumption to verify
//! on the live run rather than a certainty.

use std::env;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kob_cli::node::NodeClient;
use kob_cli::rpc::RpcUtxo;
use kob_cli::signing;
use kob_core::contract::stablecoin::attestation::op_type as coin_op_type;
use kob_core::contract::stablecoin::mint_authority::attestation::{
    build_mint_attestation_message, build_raise_cap_attestation_message, check_mint_amount_floor,
};
use kob_core::contract::stablecoin::mint_authority::body::build_mint_authority_redeem_script;
use kob_core::contract::stablecoin::mint_authority::sigscript::{
    build_mint_authority_mint_sigscript, build_mint_authority_raise_cap_sigscript,
};
use kob_core::contract::stablecoin::state::{compute_role_registry_root, frozen_flag};
use kob_core::contract::stablecoin::{
    build_attestation_message, build_freeze_attestation_message, build_migrate_attestation_message,
    build_seize_attestation_message, build_stablecoin_burn_sigscript, build_stablecoin_freeze_sigscript,
    build_stablecoin_migrate_sigscript, build_stablecoin_redeem_script, build_stablecoin_seize_sigscript,
    build_stablecoin_transfer_sigscript,
};
use kob_core::contract::token::identifier_type as id_type;
use kob_core::mass::{calc_mass_with_sigscripts, check_tx_storage_mass, min_relay_fee};
use kob_core::p2sh::build_p2sh;
use kob_core::sighash::{compute_covenant_id, compute_sighash};
use kob_core::tx::{to_rpc_payload, AuthOutput, CovenantBinding, Transaction, TxInput, TxOutput};
use kob_core::wallet::WalletContext;

use serde::{Deserialize, Serialize};

/// REST fallback verify-URL base (testnet-10 explorer/indexer API).
const REST_VERIFY_BASE: &str = "https://api-tn10.kaspa.org/transactions/";

fn verify_url(txid: &str) -> String {
    format!("{REST_VERIFY_BASE}{txid}")
}

/// Exact-fee with an optional `KOB_FEE_FLOOR` override (sompi) -- mirrors
/// `kob_e2e_util.rs`'s helper of the same name (the node's transient-mass
/// floor can exceed the compute-mass fee when a large redeem script rides
/// in the sigscript, which is routine for this covenant's multi-hundred-byte
/// bodies).
fn fee_with_floor(computed: u64) -> u64 {
    let floor = env::var("KOB_FEE_FLOOR").ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    computed.max(floor)
}

/// Pre-submission checks every op runs on its fully-assembled transaction
/// (audit 2026-07-20 §B3/§B5). Catches, locally, two classes of failure that
/// otherwise only surface as an opaque node rejection:
///
/// 1. **KIP-9 storage mass** -- authoritative dust check. A covenant-bound
///    output occupies two 100-byte storage units, so a small-value coin
///    contributes `4e12 / value` to the transaction's harmonic term; past the
///    network's storage limit the transaction cannot be mined at all. This is
///    the whole-transaction check that `MIN_MINT_AMOUNT` explicitly is NOT a
///    substitute for.
/// 2. **Mandatory fee input** -- FREEZE/SEIZE/MINT/RAISE_CAP pin the covenant
///    output's value to its input exactly (`dr_value_continuity_check` /
///    `value_continuity_check_output0`), so none of the covenant coin's value
///    can become a miner fee. A single-input build is therefore necessarily
///    zero-fee and gets rejected as non-standard; a separate wallet-funded
///    input is structurally required, not an optimization.
fn preflight(tx: &Transaction, label: &str, requires_fee_input: bool) -> anyhow::Result<()> {
    if requires_fee_input && tx.inputs.len() < 2 {
        anyhow::bail!(
            "{label}: exact value-continuity leaves no room for a fee from the covenant coin, \
             so a separate wallet fee input is mandatory (got {} input(s))",
            tx.inputs.len()
        );
    }
    match check_tx_storage_mass(tx) {
        Ok(mass) => {
            println!("{label} storage mass: {} (limit {})", mass, kob_core::mass::MAX_TX_MASS);
            Ok(())
        }
        Err(e) => anyhow::bail!("{label}: {e}"),
    }
}

/// Per-input `sig_op_count` to declare for every input that spends a
/// STABLECOIN/mint-authority COVENANT branch (MINT, TRANSFER, FREEZE/UNFREEZE,
/// SEIZE, BURN, RAISE_CAP) -- NOT the paired plain wallet fee input, which
/// keeps its own real (small) `sig_op_count`.
///
/// # The bug this fixes
///
/// A live testnet-10 run rejected MINT (`sig_op_count: 1`) with: "script
/// units exceeded the amount committed in the input: used=127801,
/// limit=109999". Root cause: for version >= 1 ("post-Toccata") transactions
/// the node does not read `sig_op_count` off the wire at all -- `to_rpc_payload`
/// (`kob_settle::tx`, re-exported as `kob_core::tx`) always emits
/// `sigOpCount: 0` plus a `computeBudget` DERIVED from this harness's local
/// `sig_op_count` via `compute_budget_for_sig_ops(n) = n * 10`
/// (`COMPUTE_BUDGET_UNITS_PER_SIG_OP`). The node then caps the script units
/// the covenant script's execution may consume at
/// `allowed = computeBudget * SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT (10_000)
///           + free_script_units_per_input() (9_999)`
/// (`consensus/core/src/mass/units.rs`, `consensus/core/src/tx.rs`'s
/// `ComputeCommit::allowed_script_units`) -- so `sig_op_count: 1` ->
/// `computeBudget: 10` -> a 109,999-unit ceiling, exactly the rejected
/// `limit`. The mint-authority/coin covenant's MINT branch (role-registry
/// introspection + Blake3 + OpCat reconstruction of the emitted coin) simply
/// costs more script units (127,801, measured) than the 9,999-unit free
/// per-input allowance can cover -- the free allowance is sized for ordinary
/// stack work, not this shape of heavy script.
///
/// This is the SAME mechanism the (working) spot covenant-fill path uses
/// (`domain/src/spot/batch.rs`'s buy-fill input, `cli/src/bin/kob_e2e_util.rs`)
/// -- there is no separate "compute the actual script-unit cost" engine
/// anywhere in this codebase; every covenant-spending input just declares a
/// `sig_op_count` big enough to buy a large-enough `computeBudget`. The spot
/// path's `sig_op_count: 1` (109,999-unit capacity) happens to be enough for
/// its lighter fill scripts; it is NOT enough for this contract's heavier
/// MINT-shaped branches.
///
/// # Why bumping `sig_op_count` here is safe
///
/// `sig_op_count` is never transmitted on the wire for these (version 1)
/// transactions (see above), so raising it does not misrepresent an
/// on-chain-checked signature-operation count to the node -- it purely (a)
/// buys more `computeBudget` headroom and (b) proportionally raises this
/// harness's own fee/mass estimate in lockstep
/// (`calc_mass_with_sigscripts`/`calc_compute_mass` in `kob_settle::mass`
/// sum the same `sig_op_count` field into `total_sig_ops_mass`, which is
/// exactly `100 * computeBudget` grams by construction -- matching what the
/// real node's `MassCalculator::calc_non_contextual_masses` charges for a
/// version >= 1 input), so the tx still pays a correct, sufficient fee.
///
/// # Sizing
///
/// `8` -> `computeBudget = 80` -> an 809,999-unit ceiling: ~6.3x the one
/// measured heavy-branch cost (127,801, MINT), comfortably covering
/// TRANSFER/FREEZE/SEIZE/BURN/RAISE_CAP's structurally-identical
/// introspection+Blake3+OpCat cost even though only MINT has been measured
/// live. The extra committed budget costs a trivial amount of additional fee
/// (8_000 grams -> ~800,000 sompi at the 100 sompi/gram post-Toccata
/// min-relay rate) and stays far under any practical ceiling (the `u8`
/// `sig_op_count` field alone tops out at `255 * 10 = 2550` ->
/// 25,509,999 script units; `ComputeBudget` itself is a `u16`).
const COVENANT_COMPUTE_BUDGET_SIG_OPS: u8 = 8;

/// Reproduce the (crate-private, test-only) `spk_to_bytes` helper from
/// `core/tests/stablecoin_contracts.rs`: the 2-byte BIG-ENDIAN version
/// followed by the script -- exactly the bytes `OpTxOutputSpk` pushes, and
/// what every attestation preimage's `successor_spk`/`recipient_spk`
/// parameter must be `Blake3`-hashed from off-chain to match the on-chain
/// reconstruction byte-for-byte.
fn spk_bytes_be(spk: &kaspa_consensus_core::tx::ScriptPublicKey) -> Vec<u8> {
    let mut v = spk.version().to_be_bytes().to_vec();
    v.extend_from_slice(spk.script());
    v
}

/// Decode a hex txid string into raw 32 bytes (the attestation builders take
/// `&[u8; 32]`, not the wire hex form).
fn txid_bytes(txid_hex: &str) -> anyhow::Result<[u8; 32]> {
    let b = hex::decode(txid_hex)?;
    <[u8; 32]>::try_from(b.as_slice()).map_err(|_| anyhow::anyhow!("txid must be 32 bytes"))
}

/// Plain P2PK locking script for a 32-byte x-only pubkey: `[0x20][pk][0xac]`.
fn p2pk_script(pubkey: &[u8; 32]) -> Vec<u8> {
    let mut spk = Vec::with_capacity(34);
    spk.push(0x20);
    spk.extend_from_slice(pubkey);
    spk.push(0xac);
    spk
}

/// Poll an address's UTXO set for a specific outpoint, then assert its
/// value (and, if given, its tracked `covenant_id`) match expectations.
/// Mirrors the poll-then-verify pattern in `cli/src/prediction.rs`'s 2-step
/// market deploy (`step1_confirmed` loop).
#[allow(clippy::too_many_arguments)]
async fn verify_utxo(
    rpc: &NodeClient,
    label: &str,
    address: &str,
    txid: &str,
    index: u32,
    expected_value: u64,
    expected_covenant_id: Option<&[u8; 32]>,
    attempts: u32,
    interval: Duration,
) -> anyhow::Result<()> {
    for attempt in 1..=attempts {
        tokio::time::sleep(interval).await;
        match rpc.get_utxos_by_addresses(&[address]).await {
            Ok(utxos) => {
                if let Some(u) =
                    utxos.iter().find(|u| u.outpoint.transaction_id == txid && u.outpoint.index == index)
                {
                    println!(
                        "  [{label}] ACCEPTED (attempt {attempt}/{attempts}): {txid}:{index} value={} covenant_id={:?}",
                        u.utxo_entry.amount, u.utxo_entry.covenant_id
                    );
                    if u.utxo_entry.amount != expected_value {
                        anyhow::bail!(
                            "[{label}] value mismatch: on-chain {} != expected {}",
                            u.utxo_entry.amount,
                            expected_value
                        );
                    }
                    if let Some(expected_cov) = expected_covenant_id {
                        let expected_hex = hex::encode(expected_cov);
                        match &u.utxo_entry.covenant_id {
                            Some(actual) if actual.eq_ignore_ascii_case(&expected_hex) => {}
                            other => anyhow::bail!(
                                "[{label}] covenant_id mismatch: on-chain {:?} != expected {}",
                                other,
                                expected_hex
                            ),
                        }
                    }
                    println!("  [{label}] shape OK.");
                    return Ok(());
                }
            }
            Err(e) => {
                tracing::debug!("[{label}] UTXO query attempt {attempt}/{attempts} failed: {e}");
            }
        }
    }
    anyhow::bail!(
        "[{label}] {txid}:{index} not observed on-chain after {attempts} attempts \
         (rejected, orphaned, or still propagating -- check {})",
        verify_url(txid)
    );
}

/// Pick a spendable wallet P2PK UTXO with at least `min_value` sompi,
/// smallest-first (mirrors the `.min_by_key` selection idiom used
/// throughout `kob_e2e_util.rs`/`cli/src/stablecoin.rs`).
async fn pick_wallet_utxo(rpc: &NodeClient, wallet: &WalletContext, min_value: u64) -> anyhow::Result<RpcUtxo> {
    let utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    utxos
        .into_iter()
        .filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= min_value)
        .min_by_key(|u| u.utxo_entry.amount)
        .ok_or_else(|| anyhow::anyhow!("no wallet P2PK UTXO with >= {} sompi at {}", min_value, wallet.address))
}

// ---------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------

struct Config {
    node_url: String,
    wallet_path: PathBuf,
    keys_manifest_path: PathBuf,
    /// Initial supply cap baked into the mint authority at genesis.
    cap: u64,
    /// Amount minted in the single MINT op this harness exercises.
    mint_amount: u64,
    /// The mint authority's permanent "operating balance" (native sompi
    /// value, preserved unchanged across every MINT/RAISE_CAP spend per the
    /// value-continuity fix) -- also TX1's anchor value, since TX2 (the
    /// mint-authority genesis) has no separate fee input and must pay its
    /// own fee out of the anchor.
    authority_value: u64,
    /// RAISE_CAP's target ceiling (must be a strict increase over `cap`).
    new_cap: u64,
}

impl Config {
    fn from_env() -> Self {
        let node_url = env::var("NODE").unwrap_or_else(|_| "ws://65.108.107.30:18210".to_string());
        let wallet_path = PathBuf::from(env::var("WALLET").unwrap_or_else(|_| "wallet.json".to_string()));
        let keys_manifest_path =
            PathBuf::from(env::var("KEYS_MANIFEST").unwrap_or_else(|_| "stablecoin_e2e_keys.json".to_string()));
        let cap: u64 = env::var("CAP").ok().and_then(|s| s.parse().ok()).unwrap_or(100_000_000_000); // 1000 KAS
        let mint_amount: u64 = env::var("MINT_AMOUNT").ok().and_then(|s| s.parse().ok()).unwrap_or(50_000_000); // 0.5 KAS
        let authority_value: u64 = env::var("MINT_AUTHORITY_VALUE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100_000_000); // 1 KAS operating balance, well above MIN_UTXO_VALUE + fees
        let new_cap: u64 = env::var("NEW_CAP").ok().and_then(|s| s.parse().ok()).unwrap_or_else(|| cap.saturating_mul(2));
        Self { node_url, wallet_path, keys_manifest_path, cap, mint_amount, authority_value, new_cap }
    }
}

// ---------------------------------------------------------------------
// Role keys + run-state manifest (auditable, reproducible across restarts)
// ---------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
struct KeyPairHex {
    privkey: String,
    pubkey: String,
}

impl KeyPairHex {
    fn privkey_bytes(&self) -> anyhow::Result<[u8; 32]> {
        let b = hex::decode(&self.privkey)?;
        <[u8; 32]>::try_from(b.as_slice()).map_err(|_| anyhow::anyhow!("privkey must be 32 bytes"))
    }

    fn pubkey_bytes(&self) -> anyhow::Result<[u8; 32]> {
        let b = hex::decode(&self.pubkey)?;
        <[u8; 32]>::try_from(b.as_slice()).map_err(|_| anyhow::anyhow!("pubkey must be 32 bytes"))
    }
}

/// Generate a fresh Schnorr keypair. Retries (astronomically unlikely) on a
/// malformed scalar rather than unwrapping, mirroring the "generate and
/// validate" discipline `signing::derive_pubkey` callers use elsewhere.
fn gen_keypair() -> anyhow::Result<KeyPairHex> {
    loop {
        let priv_bytes: [u8; 32] = rand::random();
        if let Ok(pubkey) = signing::derive_pubkey(&priv_bytes) {
            return Ok(KeyPairHex { privkey: hex::encode(priv_bytes), pubkey: hex::encode(pubkey) });
        }
    }
}

/// Every governance role key the robust stablecoin design names (§2), plus
/// two demo-only coin-holder keys this harness needs to exercise a 2-hop
/// TRANSFER and a SEIZE-to-recovery (`owner2`, `recovery` -- NOT covenant
/// governance roles, just successive holders of the one demo coin).
#[derive(Serialize, Deserialize, Clone)]
struct RoleKeys {
    /// Initial holder of the minted coin.
    owner: KeyPairHex,
    /// TRANSFER destination (second holder) -- demo-only, not a role.
    owner2: KeyPairHex,
    /// SEIZE destination (rescued/seized-to holder) -- demo-only, not a role.
    recovery: KeyPairHex,
    ops: KeyPairHex,
    freeze: KeyPairHex,
    seize: [KeyPairHex; 3],
    mint: KeyPairHex,
    cap_authority: [KeyPairHex; 3],
    /// Opaque `role_registry_root` commitment (§2/§3) -- never individually
    /// verified on-chain in this phase (baked role pubkeys are compared
    /// directly instead), computed once at generation time and carried
    /// forward unchanged for every coin/authority this harness deploys.
    role_registry_root: String,
}

/// Every txid/outpoint produced as the run proceeds, plus the two
/// covenant ids once known -- persisted so a crashed/interrupted run is
/// auditable (which step it reached) even though this harness does not
/// itself auto-resume mid-sequence.
#[derive(Serialize, Deserialize, Default, Clone)]
struct RunState {
    genesis_covenant_id: Option<String>, // G, the mint authority's own id
    coin_covenant_id: Option<String>,    // C_coin, the minted coin's own id
    tx1_anchor: Option<String>,
    tx2_authority_genesis: Option<String>,
    tx3_mint: Option<String>,
    tx4_transfer: Option<String>,
    tx5_freeze: Option<String>,
    tx6_seize: Option<String>,
    tx7_unfreeze: Option<String>,
    tx8_burn: Option<String>,
    tx9_raise_cap: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    keys: RoleKeys,
    #[serde(default)]
    state: RunState,
}

fn save_manifest(path: &Path, manifest: &Manifest) -> anyhow::Result<()> {
    let data = serde_json::to_string_pretty(manifest)?;
    std::fs::write(path, data)?;
    Ok(())
}

/// Load the keys/manifest if `path` exists; otherwise generate a fresh set
/// of role keypairs (+ derive `role_registry_root`) and save immediately, so
/// the SAME identities are reused across repeated invocations against the
/// same live deployment.
fn load_or_init_manifest(path: &Path) -> anyhow::Result<Manifest> {
    if path.exists() {
        let data = std::fs::read_to_string(path)?;
        let manifest: Manifest = serde_json::from_str(&data)?;
        println!("Loaded existing role keys + run state from {}", path.display());
        return Ok(manifest);
    }

    println!("No manifest at {} -- generating fresh role keypairs.", path.display());
    let seize = [gen_keypair()?, gen_keypair()?, gen_keypair()?];
    let cap_authority = [gen_keypair()?, gen_keypair()?, gen_keypair()?];
    let ops = gen_keypair()?;
    let freeze = gen_keypair()?;
    let mint = gen_keypair()?;

    let ops_pk = ops.pubkey_bytes()?;
    let freeze_pk = freeze.pubkey_bytes()?;
    let mint_pk = mint.pubkey_bytes()?;
    let seize_pks = [seize[0].pubkey_bytes()?, seize[1].pubkey_bytes()?, seize[2].pubkey_bytes()?];
    // seize_multisig_commit / rotate_multisig_commit are opaque off-chain
    // inputs to the root formula (never individually re-derived on-chain in
    // this phase, see state.rs's module doc) -- a real deployment would
    // commit to genuine multisig descriptors; this harness uses a simple
    // Blake2b commitment over the three baked SEIZE pubkeys, and an
    // all-zero placeholder for the (unimplemented, deferred) ROTATE role.
    let seize_commit = kob_core::blake2b_256(&[seize_pks[0], seize_pks[1], seize_pks[2]].concat());
    let rotate_commit = [0u8; 32];
    let root = compute_role_registry_root(&ops_pk, &freeze_pk, &seize_commit, &mint_pk, &rotate_commit, 0);

    let keys = RoleKeys {
        owner: gen_keypair()?,
        owner2: gen_keypair()?,
        recovery: gen_keypair()?,
        ops,
        freeze,
        seize,
        mint,
        cap_authority,
        role_registry_root: hex::encode(root),
    };
    let manifest = Manifest { keys, state: RunState::default() };
    save_manifest(path, &manifest)?;
    println!("Saved fresh role keys + manifest to {}", path.display());
    Ok(manifest)
}

// ---------------------------------------------------------------------
// Resolved role context (decoded pubkeys/privkeys, ready to bake/sign with)
// ---------------------------------------------------------------------

// `owner2_sk` is part of the complete generated role/key set (every
// KeyPairHex the manifest persists has a matching privkey field) even
// though this particular op sequence never needs `owner2` to SIGN anything
// (it's TRANSFER's destination only; SEIZE/FREEZE/BURN never touch it
// again) -- kept for symmetry/reuse rather than special-cased out.
#[allow(dead_code)]
struct RoleCtx {
    owner_pk: [u8; 32],
    owner_sk: [u8; 32],
    owner2_pk: [u8; 32],
    owner2_sk: [u8; 32],
    recovery_pk: [u8; 32],
    recovery_sk: [u8; 32],
    ops_pk: [u8; 32],
    ops_sk: [u8; 32],
    freeze_pk: [u8; 32],
    freeze_sk: [u8; 32],
    seize_pk: [[u8; 32]; 3],
    seize_sk: [[u8; 32]; 3],
    mint_pk: [u8; 32],
    mint_sk: [u8; 32],
    cap_authority_pk: [[u8; 32]; 3],
    cap_authority_sk: [[u8; 32]; 3],
    root: [u8; 32],
}

impl RoleCtx {
    fn from_keys(k: &RoleKeys) -> anyhow::Result<Self> {
        let root_bytes = hex::decode(&k.role_registry_root)?;
        let root = <[u8; 32]>::try_from(root_bytes.as_slice()).map_err(|_| anyhow::anyhow!("role_registry_root must be 32 bytes"))?;
        Ok(Self {
            owner_pk: k.owner.pubkey_bytes()?,
            owner_sk: k.owner.privkey_bytes()?,
            owner2_pk: k.owner2.pubkey_bytes()?,
            owner2_sk: k.owner2.privkey_bytes()?,
            recovery_pk: k.recovery.pubkey_bytes()?,
            recovery_sk: k.recovery.privkey_bytes()?,
            ops_pk: k.ops.pubkey_bytes()?,
            ops_sk: k.ops.privkey_bytes()?,
            freeze_pk: k.freeze.pubkey_bytes()?,
            freeze_sk: k.freeze.privkey_bytes()?,
            seize_pk: [k.seize[0].pubkey_bytes()?, k.seize[1].pubkey_bytes()?, k.seize[2].pubkey_bytes()?],
            seize_sk: [k.seize[0].privkey_bytes()?, k.seize[1].privkey_bytes()?, k.seize[2].privkey_bytes()?],
            mint_pk: k.mint.pubkey_bytes()?,
            mint_sk: k.mint.privkey_bytes()?,
            cap_authority_pk: [
                k.cap_authority[0].pubkey_bytes()?,
                k.cap_authority[1].pubkey_bytes()?,
                k.cap_authority[2].pubkey_bytes()?,
            ],
            cap_authority_sk: [
                k.cap_authority[0].privkey_bytes()?,
                k.cap_authority[1].privkey_bytes()?,
                k.cap_authority[2].privkey_bytes()?,
            ],
            root,
        })
    }

    /// Build a stablecoin coin's redeem script for `owner_pubkey` at the
    /// given `frozen`/`epoch` state, with this run's baked role constants.
    fn coin_rs(&self, owner_pubkey: &[u8; 32], frozen: u8, epoch: u32) -> Vec<u8> {
        build_stablecoin_redeem_script(
            owner_pubkey,
            id_type::PUBKEY,
            &self.root,
            frozen,
            epoch,
            &self.ops_pk,
            &self.freeze_pk,
            &self.seize_pk,
            &self.mint_pk,
        )
    }

    /// Build the mint authority's redeem script at the given mutable-state
    /// values, with this run's baked role constants + genesis id.
    fn authority_rs(&self, running_supply: u64, current_cap: u64, genesis_covenant_id: &[u8; 32]) -> Vec<u8> {
        build_mint_authority_redeem_script(
            running_supply,
            current_cap,
            &self.mint_pk,
            &self.cap_authority_pk,
            &self.ops_pk,
            &self.freeze_pk,
            &self.seize_pk,
            &self.root,
            id_type::PUBKEY,
            genesis_covenant_id,
        )
    }
}

// ---------------------------------------------------------------------
// DEPLOY: TX1 (anchor) + TX2 (mint-authority genesis)
// ---------------------------------------------------------------------

struct DeployResult {
    genesis_covenant_id: [u8; 32],
    tx2_txid: String,
    authority_value: u64,
    authority_rs: Vec<u8>,
}

/// TX1: fund a plain wallet-P2PK anchor output, tagged with the
/// mint-authority's genesis `covenant_id` `G` (computed from the WALLET
/// FUNDING outpoint -- not circular, since the anchor's SPK is just the
/// wallet's own P2PK script and does not depend on `G`).
async fn deploy_tx1_anchor(
    rpc: &NodeClient,
    wallet: &WalletContext,
    anchor_value: u64,
) -> anyhow::Result<([u8; 32], String)> {
    let privkey = *wallet.privkey_bytes();
    let wallet_spk = p2pk_script(&wallet.pubkey);

    let funding = pick_wallet_utxo(rpc, wallet, anchor_value + 200_000).await?;
    println!(
        "TX1 funding UTXO: {}:{} ({} sompi)",
        funding.outpoint.transaction_id, funding.outpoint.index, funding.utxo_entry.amount
    );

    let genesis_covenant_id = compute_covenant_id(
        &funding.outpoint.transaction_id,
        funding.outpoint.index,
        &[AuthOutput { index: 0, value: anchor_value, spk_version: 0, spk_script: wallet_spk.clone() }],
    )?;
    println!("Mint-authority genesis covenant_id (G): {}", hex::encode(genesis_covenant_id));

    let mut tx = Transaction::new(1);
    tx.inputs.push(TxInput {
        prev_tx_id: funding.outpoint.transaction_id.clone(),
        prev_index: funding.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: funding.utxo_entry.script_public_key.version,
        script_bytes: funding.script_bytes(),
        value: funding.utxo_entry.amount,
    });
    tx.outputs.push(TxOutput::new(
        anchor_value,
        0,
        wallet_spk.clone(),
        Some(CovenantBinding::new(0, genesis_covenant_id.into())),
    ));
    let total_in = funding.utxo_entry.amount;
    let tent_change = total_in.saturating_sub(anchor_value + 200_000);
    if tent_change >= kob_core::MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(tent_change, 0, wallet_spk.clone(), None));
    }

    let sign_all = |tx: &Transaction| -> anyhow::Result<Vec<Vec<u8>>> {
        let sh = compute_sighash(tx, 0)?;
        let sig = signing::schnorr_sign(&privkey, &sh)?;
        Ok(vec![signing::build_p2pk_sigscript(&sig)])
    };
    let sigs = sign_all(&tx)?;
    let exact_fee = fee_with_floor(min_relay_fee(calc_mass_with_sigscripts(&tx, &sigs)));
    if tx.outputs.len() > 1 {
        let change_idx = tx.outputs.len() - 1;
        let new_change = total_in.saturating_sub(anchor_value + exact_fee);
        if new_change >= kob_core::MIN_UTXO_VALUE {
            tx.outputs[change_idx].value = new_change;
        } else {
            tx.outputs.pop();
        }
    }
    let sigs = sign_all(&tx)?;
    println!("TX1 exact fee: {} sompi", exact_fee);

    preflight(&tx, "TX1", false)?;
    let payload = to_rpc_payload(&tx, &sigs);
    let txid = rpc.submit_transaction(payload).await?;
    println!("TX1 SUBMITTED. TXID: {}  verify: {}", txid, verify_url(&txid));

    verify_utxo(
        rpc,
        "TX1 anchor",
        &wallet.address,
        &txid,
        0,
        anchor_value,
        Some(&genesis_covenant_id),
        20,
        Duration::from_secs(3),
    )
    .await?;

    Ok((genesis_covenant_id, txid))
}

/// TX2: spend TX1's anchor as the sole input, creating the REAL
/// mint-authority covenant (`running_supply=0`, `current_cap=CAP`) with `G`
/// now baked in as a literal, continuing the SAME covenant_id.
async fn deploy_tx2_authority(
    rpc: &NodeClient,
    wallet: &WalletContext,
    roles: &RoleCtx,
    genesis_covenant_id: &[u8; 32],
    tx1_txid: &str,
    anchor_value: u64,
    cap: u64,
) -> anyhow::Result<DeployResult> {
    let privkey = *wallet.privkey_bytes();
    let wallet_spk = p2pk_script(&wallet.pubkey);

    let authority_rs = roles.authority_rs(0, cap, genesis_covenant_id);
    let authority_p2sh = build_p2sh(&authority_rs);
    let authority_addr = kob_cli::cancel::p2sh_to_address(authority_p2sh.script(), "kaspatest");
    println!("Mint-authority P2SH address: {}", authority_addr);

    let mut tx = Transaction::new(1);
    tx.inputs.push(TxInput {
        prev_tx_id: tx1_txid.to_string(),
        prev_index: 0,
        sequence: 0,
        sig_op_count: 1,
        script_version: 0,
        script_bytes: wallet_spk.clone(),
        value: anchor_value,
    });

    let sign_all = |tx: &Transaction, value: u64| -> anyhow::Result<Vec<Vec<u8>>> {
        let mut t = tx.clone();
        t.outputs[0].value = value;
        let sh = compute_sighash(&t, 0)?;
        let sig = signing::schnorr_sign(&privkey, &sh)?;
        Ok(vec![signing::build_p2pk_sigscript(&sig)])
    };

    tx.outputs.push(TxOutput::new(
        anchor_value,
        authority_p2sh.version(),
        authority_p2sh.script().to_vec(),
        Some(CovenantBinding::new(0, (*genesis_covenant_id).into())),
    ));

    let sigs = sign_all(&tx, anchor_value)?;
    let exact_fee = fee_with_floor(min_relay_fee(calc_mass_with_sigscripts(&tx, &sigs)));
    let authority_value = anchor_value.saturating_sub(exact_fee);
    if authority_value < kob_core::MIN_UTXO_VALUE {
        anyhow::bail!(
            "TX2: authority value {} after fee {} would be below MIN_UTXO_VALUE -- raise MINT_AUTHORITY_VALUE",
            authority_value,
            exact_fee
        );
    }
    tx.outputs[0].value = authority_value;
    let sigs = sign_all(&tx, authority_value)?;
    println!("TX2 exact fee: {} sompi, authority operating value: {} sompi", exact_fee, authority_value);

    preflight(&tx, "TX2", false)?;
    let payload = to_rpc_payload(&tx, &sigs);
    let txid = rpc.submit_transaction(payload).await?;
    println!("TX2 SUBMITTED. TXID: {}  verify: {}", txid, verify_url(&txid));

    verify_utxo(rpc, "TX2 mint authority", &authority_addr, &txid, 0, authority_value, Some(genesis_covenant_id), 20, Duration::from_secs(3))
        .await?;

    Ok(DeployResult { genesis_covenant_id: *genesis_covenant_id, tx2_txid: txid, authority_value, authority_rs })
}

// ---------------------------------------------------------------------
// MINT
// ---------------------------------------------------------------------

struct MintResult {
    coin_covenant_id: [u8; 32],
    coin_rs: Vec<u8>,
    coin_value: u64,
    tx3_txid: String,
    authority_rs: Vec<u8>,
    authority_value: u64,
}

/// Mint `mint_amount` sompi of the stablecoin to `roles.owner_pk`, spending
/// the mint authority's CURRENT UTXO (value preserved to output[0]) plus a
/// wallet-funding input (funds the coin's native value + fee).
#[allow(clippy::too_many_arguments)]
async fn op_mint(
    rpc: &NodeClient,
    wallet: &WalletContext,
    roles: &RoleCtx,
    genesis_cov_id: &[u8; 32],
    authority_txid: &str,
    authority_value: u64,
    authority_rs_old: &[u8],
    cap: u64,
    mint_amount: u64,
) -> anyhow::Result<MintResult> {
    // Dust floor (audit 2026-07-20 §B3): a mint below MIN_MINT_AMOUNT drives
    // the tx's KIP-9 storage mass past what the network will relay. Necessary
    // condition only -- the whole-tx storage-mass check below is authoritative.
    check_mint_amount_floor(mint_amount)?;

    let privkey = *wallet.privkey_bytes();
    let wallet_spk = p2pk_script(&wallet.pubkey);

    // The newly-minted coin's shape (owner = roles.owner_pk, frozen=CLEAR,
    // epoch=0 -- every freshly-minted coin starts here per
    // mint_authority::body's `build_fixed_mid`).
    let coin_rs = roles.coin_rs(&roles.owner_pk, frozen_flag::CLEAR, 0);
    let coin_p2sh = build_p2sh(&coin_rs);

    // Predicted new-coin covenant_id: a fresh single-output genesis rooted
    // at the mint-authority's OWN outpoint being spent here -- see this
    // file's top doc, "Per-coin covenant_id" section, for the reasoning
    // (and the fact that this is a live-run ASSUMPTION to verify, not a
    // Rust-API certainty).
    let coin_cov_id = compute_covenant_id(
        authority_txid,
        0,
        &[AuthOutput { index: 1, value: mint_amount, spk_version: coin_p2sh.version(), spk_script: coin_p2sh.script().to_vec() }],
    )?;
    println!("Predicted new coin covenant_id: {}", hex::encode(coin_cov_id));

    let new_running_supply = mint_amount; // old running_supply (0) + mint_amount
    let new_authority_rs = roles.authority_rs(new_running_supply, cap, genesis_cov_id);
    let new_authority_p2sh = build_p2sh(&new_authority_rs);
    let authority_addr = kob_cli::cancel::p2sh_to_address(new_authority_p2sh.script(), "kaspatest");
    let coin_addr = kob_cli::cancel::p2sh_to_address(coin_p2sh.script(), "kaspatest");

    let old_authority_p2sh = build_p2sh(authority_rs_old);

    let fee_utxo = pick_wallet_utxo(rpc, wallet, mint_amount + 300_000).await?;
    println!(
        "MINT fee/funding UTXO: {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    let mut tx = Transaction::new(1);
    tx.inputs.push(TxInput {
        prev_tx_id: authority_txid.to_string(),
        prev_index: 0,
        sequence: 0,
        // MINT branch: single OpCheckSigFromStack, no owner sig -- bumped to
        // COVENANT_COMPUTE_BUDGET_SIG_OPS for compute-budget headroom (see
        // that constant's doc: the real count here would be 1, which is what
        // got rejected live with "used=127801, limit=109999").
        sig_op_count: COVENANT_COMPUTE_BUDGET_SIG_OPS,
        script_version: old_authority_p2sh.version(),
        script_bytes: old_authority_p2sh.script().to_vec(),
        value: authority_value,
    });
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_utxo.script_bytes(),
        value: fee_utxo.utxo_entry.amount,
    });

    // Output[0]: continued authority, value PRESERVED unchanged (value-
    // continuity fix -- mint_authority::body's `value_continuity_check_output0`).
    tx.outputs.push(TxOutput::new(
        authority_value,
        new_authority_p2sh.version(),
        new_authority_p2sh.script().to_vec(),
        Some(CovenantBinding::new(0, (*genesis_cov_id).into())),
    ));
    // Output[1]: the newly-minted coin (FIXED index 1, per build_mint_branch).
    tx.outputs.push(TxOutput::new(
        mint_amount,
        coin_p2sh.version(),
        coin_p2sh.script().to_vec(),
        Some(CovenantBinding::new(0, coin_cov_id.into())),
    ));
    // Output[2]: wallet change from the funding input.
    let est_fee = 250_000u64;
    tx.outputs.push(TxOutput::new(fee_utxo.utxo_entry.amount.saturating_sub(mint_amount + est_fee), 0, wallet_spk.clone(), None));

    // MINT attestation covers only fixed semantic fields (covenant_id /
    // outpoint / mint_amount / new_running_supply / recipient_spk) -- none
    // of which change as the fee/change output is adjusted below, so it's
    // computed ONCE and reused across both fee-convergence passes (unlike
    // the fee input's SIGHASH_ALL signature, which covers the whole tx and
    // must be recomputed after the change value is finalized).
    let authority_txid_bytes = txid_bytes(authority_txid)?;
    let mint_msg = build_mint_attestation_message(
        genesis_cov_id,
        &authority_txid_bytes,
        0,
        mint_amount,
        new_running_supply,
        &spk_bytes_be(&coin_p2sh),
    );
    let mint_sig = signing::schnorr_sign(&roles.mint_sk, &mint_msg)?;
    let sigscript0 =
        build_mint_authority_mint_sigscript(&mint_sig, authority_rs_old, &new_authority_rs, mint_amount, &roles.owner_pk, authority_rs_old);

    let sign_fee = |tx: &Transaction| -> anyhow::Result<Vec<u8>> {
        let sh = compute_sighash(tx, 1)?;
        let sig = signing::schnorr_sign(&privkey, &sh)?;
        Ok(signing::build_p2pk_sigscript(&sig))
    };
    let sig1 = sign_fee(&tx)?;
    let exact_fee = fee_with_floor(min_relay_fee(calc_mass_with_sigscripts(&tx, &[sigscript0.clone(), sig1])));
    let change_idx = 2;
    let new_change = fee_utxo.utxo_entry.amount.saturating_sub(mint_amount + exact_fee);
    if new_change < kob_core::MIN_UTXO_VALUE {
        anyhow::bail!(
            "MINT: fee UTXO {} too small after mint_amount {} + fee {}",
            fee_utxo.utxo_entry.amount,
            mint_amount,
            exact_fee
        );
    }
    tx.outputs[change_idx].value = new_change;
    let sig1 = sign_fee(&tx)?;
    println!("MINT exact fee: {} sompi", exact_fee);

    preflight(&tx, "MINT", true)?;
    let payload = to_rpc_payload(&tx, &[sigscript0, sig1]);
    let txid = rpc.submit_transaction(payload).await?;
    println!("MINT SUBMITTED. TXID: {}  verify: {}", txid, verify_url(&txid));

    verify_utxo(rpc, "MINT continuation", &authority_addr, &txid, 0, authority_value, Some(genesis_cov_id), 20, Duration::from_secs(3))
        .await?;
    verify_utxo(rpc, "MINT coin", &coin_addr, &txid, 1, mint_amount, Some(&coin_cov_id), 20, Duration::from_secs(3)).await?;

    Ok(MintResult {
        coin_covenant_id: coin_cov_id,
        coin_rs,
        coin_value: mint_amount,
        tx3_txid: txid,
        authority_rs: new_authority_rs,
        authority_value,
    })
}

// ---------------------------------------------------------------------
// TRANSFER
// ---------------------------------------------------------------------

struct CoinResult {
    rs: Vec<u8>,
    value: u64,
    txid: String,
    /// Successor output index (this harness always uses the 1:1 same-index
    /// convention: index 0 for every coin-lifecycle op after MINT, since
    /// each op's coin input sits alone at input index 0).
    index: u32,
    owner_pk: [u8; 32],
    frozen: u8,
    /// Always 0 in this harness -- ROTATE (the only op that would ever
    /// change it) is deferred post-Live and not modeled here.
    epoch: u32,
}

/// TRANSFER: owner authorizes moving the coin to `new_owner_pk`, gated by
/// the OWNER's SIGHASH_ALL signature PLUS the OPS role's attestation.
#[allow(clippy::too_many_arguments)]
async fn op_transfer(
    rpc: &NodeClient,
    wallet: &WalletContext,
    roles: &RoleCtx,
    coin_cov_id: &[u8; 32],
    coin: &CoinResult,
    owner_sk: &[u8; 32],
    new_owner_pk: &[u8; 32],
) -> anyhow::Result<CoinResult> {
    let privkey = *wallet.privkey_bytes();
    let wallet_spk = p2pk_script(&wallet.pubkey);

    let current_p2sh = build_p2sh(&coin.rs);
    let successor_rs = roles.coin_rs(new_owner_pk, coin.frozen, coin.epoch);
    let successor_p2sh = build_p2sh(&successor_rs);
    let successor_addr = kob_cli::cancel::p2sh_to_address(successor_p2sh.script(), "kaspatest");

    let fee_utxo = pick_wallet_utxo(rpc, wallet, 300_000).await?;
    println!(
        "TRANSFER fee UTXO: {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    let mut tx = Transaction::new(1);
    tx.inputs.push(TxInput {
        prev_tx_id: coin.txid.clone(),
        prev_index: coin.index,
        sequence: 0,
        // owner OpCheckSigVerify + OPS OpCheckSigFromStack (real count: 2) --
        // bumped to COVENANT_COMPUTE_BUDGET_SIG_OPS for compute-budget
        // headroom, see that constant's doc.
        sig_op_count: COVENANT_COMPUTE_BUDGET_SIG_OPS,
        script_version: current_p2sh.version(),
        script_bytes: current_p2sh.script().to_vec(),
        value: coin.value,
    });
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_utxo.script_bytes(),
        value: fee_utxo.utxo_entry.amount,
    });
    // Output[0]: successor coin, FULL value preserved (1:1, no split -- see
    // stablecoin/mod.rs's ISSUE-15 doc).
    tx.outputs.push(TxOutput::new(
        coin.value,
        successor_p2sh.version(),
        successor_p2sh.script().to_vec(),
        Some(CovenantBinding::new(0, (*coin_cov_id).into())),
    ));
    // Output[1]: fee change.
    let est_fee = 250_000u64;
    tx.outputs.push(TxOutput::new(fee_utxo.utxo_entry.amount.saturating_sub(est_fee), 0, wallet_spk.clone(), None));

    let outpoint_txid = txid_bytes(&coin.txid)?;
    let ops_msg = build_attestation_message(
        coin_cov_id,
        coin_op_type::TRANSFER,
        coin.epoch,
        &outpoint_txid,
        coin.index,
        &spk_bytes_be(&successor_p2sh),
        coin.value,
    );
    let ops_sig = signing::schnorr_sign(&roles.ops_sk, &ops_msg)?;

    let sign_all = |tx: &Transaction| -> anyhow::Result<Vec<Vec<u8>>> {
        let sh0 = compute_sighash(tx, 0)?;
        let owner_sig = signing::schnorr_sign(owner_sk, &sh0)?;
        let sigscript0 = build_stablecoin_transfer_sigscript(&owner_sig, &ops_sig, &successor_rs, &coin.rs);
        let sh1 = compute_sighash(tx, 1)?;
        let fee_sig = signing::schnorr_sign(&privkey, &sh1)?;
        Ok(vec![sigscript0, signing::build_p2pk_sigscript(&fee_sig)])
    };
    let sigs = sign_all(&tx)?;
    let exact_fee = fee_with_floor(min_relay_fee(calc_mass_with_sigscripts(&tx, &sigs)));
    let new_change = fee_utxo.utxo_entry.amount.saturating_sub(exact_fee);
    if new_change < kob_core::MIN_UTXO_VALUE {
        anyhow::bail!("TRANSFER: fee UTXO {} too small after fee {}", fee_utxo.utxo_entry.amount, exact_fee);
    }
    tx.outputs[1].value = new_change;
    let sigs = sign_all(&tx)?;
    println!("TRANSFER exact fee: {} sompi", exact_fee);

    preflight(&tx, "TRANSFER", false)?;
    let payload = to_rpc_payload(&tx, &sigs);
    let txid = rpc.submit_transaction(payload).await?;
    println!("TRANSFER SUBMITTED. TXID: {}  verify: {}", txid, verify_url(&txid));

    verify_utxo(rpc, "TRANSFER successor", &successor_addr, &txid, 0, coin.value, Some(coin_cov_id), 20, Duration::from_secs(3)).await?;

    Ok(CoinResult { rs: successor_rs, value: coin.value, txid, index: 0, owner_pk: *new_owner_pk, frozen: coin.frozen, epoch: coin.epoch })
}

// ---------------------------------------------------------------------
// FREEZE (also used, with new_frozen_flag=0, as the extra UNFREEZE step)
// ---------------------------------------------------------------------

/// FREEZE: the FREEZE role alone (no owner signature) sets
/// `frozen_flag = new_frozen_flag`. `owner_pubkey`/`role_registry_root`/
/// `identifier_type`/`epoch` are all pinned unchanged into the successor
/// (`build_freeze_branch`'s doc); native value is explicitly pinned too
/// (`dr_value_continuity_check`, since there's no owner SIGHASH_ALL to pin
/// it "for free"), so a separate wallet fee input is required.
///
/// Calling this with `new_frozen_flag = 0` on an already-frozen coin is
/// exactly the harness's UNFREEZE step (see top-of-file doc) -- FREEZE is
/// symmetric (it "must work from either starting state, 0->1 or 1->0" per
/// `build_freeze_branch`'s doc), so no separate builder exists or is needed.
async fn op_freeze(
    rpc: &NodeClient,
    wallet: &WalletContext,
    roles: &RoleCtx,
    coin_cov_id: &[u8; 32],
    coin: &CoinResult,
    new_frozen_flag: u8,
) -> anyhow::Result<CoinResult> {
    let privkey = *wallet.privkey_bytes();
    let wallet_spk = p2pk_script(&wallet.pubkey);

    let successor_rs = roles.coin_rs(&coin.owner_pk, new_frozen_flag, coin.epoch);
    let successor_p2sh = build_p2sh(&successor_rs);
    let successor_addr = kob_cli::cancel::p2sh_to_address(successor_p2sh.script(), "kaspatest");
    // The coin's OWN P2SH (the input's real prevout locking script) -- see
    // `op_burn`'s `current_p2sh` doc for why this must be the P2SH-wrapped
    // bytes, not the raw redeem script. Currently inert here (FREEZE has no
    // owner signature -- no `compute_sighash(tx, 0)` call below -- so nothing
    // consumes a wrong value), but kept correct/consistent with
    // TRANSFER/BURN's `current_p2sh` rather than leaving the same latent trap.
    let current_p2sh = build_p2sh(&coin.rs);

    let fee_utxo = pick_wallet_utxo(rpc, wallet, 300_000).await?;
    println!(
        "FREEZE(new_flag={}) fee UTXO: {}:{} ({} sompi)",
        new_frozen_flag, fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    let mut tx = Transaction::new(1);
    tx.inputs.push(TxInput {
        prev_tx_id: coin.txid.clone(),
        prev_index: coin.index,
        sequence: 0,
        // FREEZE role only: single OpCheckSigFromStack, no owner sig (real
        // count: 1) -- bumped to COVENANT_COMPUTE_BUDGET_SIG_OPS for
        // compute-budget headroom, see that constant's doc.
        sig_op_count: COVENANT_COMPUTE_BUDGET_SIG_OPS,
        script_version: current_p2sh.version(),
        script_bytes: current_p2sh.script().to_vec(),
        value: coin.value,
    });
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_utxo.script_bytes(),
        value: fee_utxo.utxo_entry.amount,
    });
    // Output[0]: successor, value PRESERVED unchanged (dr_value_continuity_check).
    tx.outputs.push(TxOutput::new(
        coin.value,
        successor_p2sh.version(),
        successor_p2sh.script().to_vec(),
        Some(CovenantBinding::new(0, (*coin_cov_id).into())),
    ));
    // Output[1]: fee change.
    let est_fee = 250_000u64;
    tx.outputs.push(TxOutput::new(fee_utxo.utxo_entry.amount.saturating_sub(est_fee), 0, wallet_spk.clone(), None));

    let outpoint_txid = txid_bytes(&coin.txid)?;
    let freeze_msg = build_freeze_attestation_message(
        coin_cov_id,
        coin.epoch,
        &outpoint_txid,
        coin.index,
        &spk_bytes_be(&successor_p2sh),
        coin.value,
        new_frozen_flag,
    );
    let freeze_sig = signing::schnorr_sign(&roles.freeze_sk, &freeze_msg)?;
    let sigscript0 = build_stablecoin_freeze_sigscript(&freeze_sig, new_frozen_flag, &successor_rs, &coin.rs);

    let sign_fee = |tx: &Transaction| -> anyhow::Result<Vec<u8>> {
        let sh = compute_sighash(tx, 1)?;
        let sig = signing::schnorr_sign(&privkey, &sh)?;
        Ok(signing::build_p2pk_sigscript(&sig))
    };
    let sig1 = sign_fee(&tx)?;
    let exact_fee = fee_with_floor(min_relay_fee(calc_mass_with_sigscripts(&tx, &[sigscript0.clone(), sig1])));
    let new_change = fee_utxo.utxo_entry.amount.saturating_sub(exact_fee);
    if new_change < kob_core::MIN_UTXO_VALUE {
        anyhow::bail!("FREEZE: fee UTXO {} too small after fee {}", fee_utxo.utxo_entry.amount, exact_fee);
    }
    tx.outputs[1].value = new_change;
    let sig1 = sign_fee(&tx)?;
    println!("FREEZE(new_flag={}) exact fee: {} sompi", new_frozen_flag, exact_fee);

    preflight(&tx, "FREEZE", true)?;
    let payload = to_rpc_payload(&tx, &[sigscript0, sig1]);
    let txid = rpc.submit_transaction(payload).await?;
    println!("FREEZE(new_flag={}) SUBMITTED. TXID: {}  verify: {}", new_frozen_flag, txid, verify_url(&txid));

    verify_utxo(rpc, "FREEZE successor", &successor_addr, &txid, 0, coin.value, Some(coin_cov_id), 20, Duration::from_secs(3)).await?;

    Ok(CoinResult { rs: successor_rs, value: coin.value, txid, index: 0, owner_pk: coin.owner_pk, frozen: new_frozen_flag, epoch: coin.epoch })
}

// ---------------------------------------------------------------------
// SEIZE
// ---------------------------------------------------------------------

/// SEIZE: a 2-of-3 SEIZE quorum force-moves the coin to `new_owner_pk`
/// REGARDLESS of the current owner or `frozen_flag` (no owner signature, no
/// frozen gate -- `build_seize_branch`'s doc). `frozen_flag` is PRESERVED
/// unchanged into the successor (the harness's documented reason for the
/// extra UNFREEZE step afterward). This harness signs with all THREE real
/// SEIZE keys (a valid superset of the 2-of-3 threshold) rather than
/// simulating a genuine 2-key holder with a placeholder third signature.
async fn op_seize(
    rpc: &NodeClient,
    wallet: &WalletContext,
    roles: &RoleCtx,
    coin_cov_id: &[u8; 32],
    coin: &CoinResult,
    new_owner_pk: &[u8; 32],
) -> anyhow::Result<CoinResult> {
    let privkey = *wallet.privkey_bytes();
    let wallet_spk = p2pk_script(&wallet.pubkey);

    let successor_rs = roles.coin_rs(new_owner_pk, coin.frozen, coin.epoch);
    let successor_p2sh = build_p2sh(&successor_rs);
    let successor_addr = kob_cli::cancel::p2sh_to_address(successor_p2sh.script(), "kaspatest");
    // The coin's OWN P2SH (the input's real prevout locking script) -- see
    // `op_burn`'s `current_p2sh` doc for why this must be the P2SH-wrapped
    // bytes, not the raw redeem script. Currently inert here (SEIZE has no
    // owner signature -- no `compute_sighash(tx, 0)` call below -- so nothing
    // consumes a wrong value), but kept correct/consistent with
    // TRANSFER/BURN's `current_p2sh` rather than leaving the same latent trap.
    let current_p2sh = build_p2sh(&coin.rs);

    let fee_utxo = pick_wallet_utxo(rpc, wallet, 300_000).await?;
    println!(
        "SEIZE fee UTXO: {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    let mut tx = Transaction::new(1);
    tx.inputs.push(TxInput {
        prev_tx_id: coin.txid.clone(),
        prev_index: coin.index,
        sequence: 0,
        // 2-of-3 SEIZE quorum: three OpCheckSigFromStack calls (real count:
        // 3) -- bumped to COVENANT_COMPUTE_BUDGET_SIG_OPS for compute-budget
        // headroom, see that constant's doc.
        sig_op_count: COVENANT_COMPUTE_BUDGET_SIG_OPS,
        script_version: current_p2sh.version(),
        script_bytes: current_p2sh.script().to_vec(),
        value: coin.value,
    });
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_utxo.script_bytes(),
        value: fee_utxo.utxo_entry.amount,
    });
    // Output[0]: successor, owner replaced, value PRESERVED unchanged.
    tx.outputs.push(TxOutput::new(
        coin.value,
        successor_p2sh.version(),
        successor_p2sh.script().to_vec(),
        Some(CovenantBinding::new(0, (*coin_cov_id).into())),
    ));
    // Output[1]: fee change.
    let est_fee = 250_000u64;
    tx.outputs.push(TxOutput::new(fee_utxo.utxo_entry.amount.saturating_sub(est_fee), 0, wallet_spk.clone(), None));

    let outpoint_txid = txid_bytes(&coin.txid)?;
    let seize_msg = build_seize_attestation_message(
        coin_cov_id,
        coin.epoch,
        &outpoint_txid,
        coin.index,
        &spk_bytes_be(&successor_p2sh),
        coin.value,
        new_owner_pk,
    );
    // Fixed positional convention: sig1<->seize_pk[0], sig2<->seize_pk[1], sig3<->seize_pk[2].
    let sig1 = signing::schnorr_sign(&roles.seize_sk[0], &seize_msg)?;
    let sig2 = signing::schnorr_sign(&roles.seize_sk[1], &seize_msg)?;
    let sig3 = signing::schnorr_sign(&roles.seize_sk[2], &seize_msg)?;
    let sigscript0 = build_stablecoin_seize_sigscript(&sig1, &sig2, &sig3, new_owner_pk, &successor_rs, &coin.rs);

    let sign_fee = |tx: &Transaction| -> anyhow::Result<Vec<u8>> {
        let sh = compute_sighash(tx, 1)?;
        let sig = signing::schnorr_sign(&privkey, &sh)?;
        Ok(signing::build_p2pk_sigscript(&sig))
    };
    let sig_fee = sign_fee(&tx)?;
    let exact_fee = fee_with_floor(min_relay_fee(calc_mass_with_sigscripts(&tx, &[sigscript0.clone(), sig_fee])));
    let new_change = fee_utxo.utxo_entry.amount.saturating_sub(exact_fee);
    if new_change < kob_core::MIN_UTXO_VALUE {
        anyhow::bail!("SEIZE: fee UTXO {} too small after fee {}", fee_utxo.utxo_entry.amount, exact_fee);
    }
    tx.outputs[1].value = new_change;
    let sig_fee = sign_fee(&tx)?;
    println!("SEIZE exact fee: {} sompi", exact_fee);

    preflight(&tx, "SEIZE", true)?;
    let payload = to_rpc_payload(&tx, &[sigscript0, sig_fee]);
    let txid = rpc.submit_transaction(payload).await?;
    println!("SEIZE SUBMITTED. TXID: {}  verify: {}", txid, verify_url(&txid));

    verify_utxo(rpc, "SEIZE successor", &successor_addr, &txid, 0, coin.value, Some(coin_cov_id), 20, Duration::from_secs(3)).await?;

    Ok(CoinResult { rs: successor_rs, value: coin.value, txid, index: 0, owner_pk: *new_owner_pk, frozen: coin.frozen, epoch: coin.epoch })
}

// ---------------------------------------------------------------------
// MIGRATE
// ---------------------------------------------------------------------

struct MigrateResult {
    txid: String,
    migrated_value: u64,
    /// MIGRATE's own wallet-change output (output[1]) -- threaded forward as
    /// RAISE_CAP's fee input for exactly the reason BURN's is (see
    /// `BurnResult::change_value`).
    change_value: u64,
}

/// MIGRATE: move the coin to a WHOLLY DIFFERENT covenant template, gated by
/// the owner's SIGHASH_ALL signature PLUS a cold 2-of-3 SEIZE-quorum
/// attestation (Decision 2026-07-20 -- see `build_migrate_branch`'s
/// "Authorizer" doc). The initial Live shipped a single hot OPS key here,
/// which made MIGRATE a governance exit: since the destination template is
/// arbitrary, owner + a stolen OPS key could walk an unfrozen coin out of
/// FREEZE/SEIZE/BURN reach entirely.
///
/// # What the destination is, and what the covenant checks about it
///
/// The branch verifies only that `Blake3(the successor output's SPK)` equals
/// the `new_template_hash` the quorum attested. It never parses the
/// destination -- it "does not even need to be another stablecoin covenant at
/// all" -- so vetting the target is the quorum's off-chain responsibility.
/// This harness migrates to a plain wallet P2PK output, which is the honest
/// demonstration of that: the coin genuinely leaves covenant governance, by
/// deliberate cold-quorum decision.
///
/// # Shape
///
/// Owner-signed, so value continuity comes free from SIGHASH_ALL and the
/// branch deliberately omits `dr_value_continuity_check` -- which means
/// MIGRATE, unlike FREEZE/SEIZE, *could* pay its fee from the coin itself.
/// The harness still uses a separate fee input so the migrated value is
/// exactly the coin's value (a clean, verifiable assertion afterward), and
/// `preflight`'s fee-input requirement is therefore NOT asserted for this op.
///
/// The coin must be UNFROZEN: the branch keeps the `frozen_flag == 0` gate on
/// top of the quorum, so a sanctioned coin cannot be migrated out even by the
/// cold keys (only SEIZE acts on a frozen coin).
async fn op_migrate(
    rpc: &NodeClient,
    wallet: &WalletContext,
    roles: &RoleCtx,
    coin_cov_id: &[u8; 32],
    coin: &CoinResult,
    owner_sk: &[u8; 32],
) -> anyhow::Result<MigrateResult> {
    if coin.frozen != frozen_flag::CLEAR {
        anyhow::bail!("MIGRATE: refusing to attempt a frozen coin -- the branch's frozen_flag==0 gate would reject it");
    }
    let privkey = *wallet.privkey_bytes();
    let wallet_spk = p2pk_script(&wallet.pubkey);

    // The destination: a plain wallet P2PK output. Not a covenant -- see the
    // fn doc. Its SPK is what the quorum attests, by hash.
    let dest_spk = kaspa_consensus_core::tx::ScriptPublicKey::new(0, wallet_spk.clone().into());
    let dest_addr = kob_core::wallet::pubkey_to_address(&wallet.pubkey, kob_core::types::Network::Testnet);

    // The coin's OWN P2SH (the input's real prevout locking script) -- the
    // owner's SIGHASH_ALL commits it, so it must be the P2SH-wrapped bytes,
    // not the raw redeem script (see op_burn's `current_p2sh` doc).
    let current_p2sh = build_p2sh(&coin.rs);

    let fee_utxo = pick_wallet_utxo(rpc, wallet, 300_000).await?;
    println!(
        "MIGRATE fee UTXO: {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    let mut tx = Transaction::new(1);
    tx.inputs.push(TxInput {
        prev_tx_id: coin.txid.clone(),
        prev_index: coin.index,
        sequence: 0,
        // Owner OpCheckSigVerify + three quorum OpCheckSigFromStack (real
        // count: 4) -- bumped to COVENANT_COMPUTE_BUDGET_SIG_OPS for
        // compute-budget headroom, see that constant's doc. Note this value is
        // committed by the sighash, so it must be identical in every pass.
        sig_op_count: COVENANT_COMPUTE_BUDGET_SIG_OPS,
        script_version: current_p2sh.version(),
        script_bytes: current_p2sh.script().to_vec(),
        value: coin.value,
    });
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_utxo.script_bytes(),
        value: fee_utxo.utxo_entry.amount,
    });
    // Output[0]: the migrated coin at its new template, value carried forward
    // unchanged. No CovenantBinding -- this coin's covenant life under the
    // stablecoin template ends here (same shape as BURN's plain successor).
    tx.outputs.push(TxOutput::new(coin.value, dest_spk.version(), dest_spk.script().to_vec(), None));
    // Output[1]: fee change.
    let est_fee = 250_000u64;
    tx.outputs.push(TxOutput::new(fee_utxo.utxo_entry.amount.saturating_sub(est_fee), 0, wallet_spk.clone(), None));

    // The attested target: Blake3 of the successor output's SPK bytes, exactly
    // what the branch recomputes on-chain from OpTxOutputSpk.
    let new_template_hash: [u8; 32] = *blake3::hash(&spk_bytes_be(&dest_spk)).as_bytes();
    let outpoint_txid = txid_bytes(&coin.txid)?;
    let migrate_msg = build_migrate_attestation_message(
        coin_cov_id,
        coin.epoch,
        &outpoint_txid,
        coin.index,
        &spk_bytes_be(&dest_spk),
        coin.value,
        &new_template_hash,
    );
    // Fixed positional convention, shared with SEIZE: sig1<->seize_pk[0], etc.
    // All three real keys are signed here (a valid superset of 2-of-3) rather
    // than simulating a 2-key holder with a placeholder third signature.
    let sig1 = signing::schnorr_sign(&roles.seize_sk[0], &migrate_msg)?;
    let sig2 = signing::schnorr_sign(&roles.seize_sk[1], &migrate_msg)?;
    let sig3 = signing::schnorr_sign(&roles.seize_sk[2], &migrate_msg)?;

    let sign_all = |tx: &Transaction| -> anyhow::Result<Vec<Vec<u8>>> {
        let sh0 = compute_sighash(tx, 0)?;
        let owner_sig = signing::schnorr_sign(owner_sk, &sh0)?;
        let sigscript0 =
            build_stablecoin_migrate_sigscript(&owner_sig, &sig1, &sig2, &sig3, &new_template_hash, &coin.rs);
        let sh1 = compute_sighash(tx, 1)?;
        let fee_sig = signing::schnorr_sign(&privkey, &sh1)?;
        Ok(vec![sigscript0, signing::build_p2pk_sigscript(&fee_sig)])
    };
    let sigs = sign_all(&tx)?;
    let exact_fee = fee_with_floor(min_relay_fee(calc_mass_with_sigscripts(&tx, &sigs)));
    let new_change = fee_utxo.utxo_entry.amount.saturating_sub(exact_fee);
    if new_change < kob_core::MIN_UTXO_VALUE {
        anyhow::bail!("MIGRATE: fee UTXO {} too small after fee {}", fee_utxo.utxo_entry.amount, exact_fee);
    }
    tx.outputs[1].value = new_change;
    let sigs = sign_all(&tx)?;
    println!("MIGRATE exact fee: {} sompi", exact_fee);

    preflight(&tx, "MIGRATE", false)?;
    let payload = to_rpc_payload(&tx, &sigs);
    let txid = rpc.submit_transaction(payload).await?;
    println!("MIGRATE SUBMITTED. TXID: {}  verify: {}", txid, verify_url(&txid));

    verify_utxo(rpc, "MIGRATE destination", &dest_addr, &txid, 0, coin.value, None, 20, Duration::from_secs(3)).await?;

    Ok(MigrateResult { txid, migrated_value: coin.value, change_value: new_change })
}

// ---------------------------------------------------------------------
// BURN
// ---------------------------------------------------------------------

struct BurnResult {
    txid: String,
    burned_value: u64,
    /// BURN's own wallet-change output (output[1]: the wallet P2PK change
    /// left over from BURN's fee input) -- threaded forward as RAISE_CAP's
    /// fee input (see `op_raise_cap`'s doc: BURN never confirms-and-waits,
    /// so an independent `pick_wallet_utxo` re-query in RAISE_CAP could
    /// still observe BURN's already-spent fee input as "spendable" and pick
    /// that same stale outpoint).
    change_value: u64,
}

/// BURN: owner (SIGHASH_ALL) + MINT-role attestation moves the coin's full
/// native value to the canonical unspendable sink: the P2SH wrapping of a
/// bare `OpReturn` redeem script (`body::BURN_SINK_SCRIPT`/`burn_sink_spk`)
/// -- a bare `OpReturn` LOCKING script is non-standard on Kaspa (this was the
/// live-discovered bug: the node's mempool rejected it with "non-standard
/// script form"), so the sink is now P2SH-wrapped to be a standard/relayable
/// output while remaining exactly as unspendable (see `BURN_SINK_SCRIPT`'s
/// doc in `body.rs`). Requires
/// `frozen_flag == 0` (the same owner-immobility gate as TRANSFER/MIGRATE)
/// -- this harness only ever calls it after the UNFREEZE step, by
/// construction. A separate wallet fee input keeps the FULL coin value
/// flowing into the sink (a clean "this exact amount was destroyed" record)
/// rather than shaving the burn amount to cover the fee.
async fn op_burn(rpc: &NodeClient, wallet: &WalletContext, roles: &RoleCtx, coin_cov_id: &[u8; 32], coin: &CoinResult) -> anyhow::Result<BurnResult> {
    if coin.frozen != frozen_flag::CLEAR {
        anyhow::bail!("BURN: coin is frozen (frozen_flag={}) -- run UNFREEZE first", coin.frozen);
    }
    let owner_sk = &roles.recovery_sk; // this harness always burns the post-SEIZE coin, owned by `recovery`
    let privkey = *wallet.privkey_bytes();
    let wallet_spk = p2pk_script(&wallet.pubkey);

    // The coin's OWN P2SH (the input's real prevout locking script) -- MUST
    // be the P2SH-WRAPPED bytes (`current_p2sh.script()`, 35B: OpBlake2b
    // OpData32 <hash> OpEqual), NOT the raw redeem script (`coin.rs`, the
    // multi-hundred-byte state+body bytecode) it wraps. This mirrors
    // `op_transfer`'s `current_p2sh` exactly (see that fn): `TxInput::
    // script_bytes` feeds `compute_sighash`'s locally-reconstructed
    // `UtxoEntry.script_public_key` (`settle::compat::to_kaspa_transaction`),
    // which `calc_schnorr_signature_hash` commits into the OWNER's SIGHASH_ALL
    // preimage (`hash_script_public_key` on THIS input's own prevout, per
    // `crypto/txscript`'s vendored `calc_schnorr_signature_hash`) -- it is
    // NOT sent to the node (which independently uses the coin's REAL on-chain
    // P2SH), so a wrong value here just makes the owner's locally-computed
    // signature invalid against the real network sighash: "script ran, but
    // verification failed" on OWNER's `OpCheckSigVerify`. FREEZE/SEIZE have
    // the identical field but no owner signature to break (no
    // `compute_sighash(tx, 0)` call in either), which is why only BURN
    // (owner sig REQUIRED, unlike FREEZE/SEIZE) ever surfaced this live.
    let current_p2sh = build_p2sh(&coin.rs);

    let sink_spk = build_p2sh(&kob_core::contract::stablecoin::BURN_SINK_SCRIPT);

    let fee_utxo = pick_wallet_utxo(rpc, wallet, 300_000).await?;
    println!(
        "BURN fee UTXO: {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    let mut tx = Transaction::new(1);
    tx.inputs.push(TxInput {
        prev_tx_id: coin.txid.clone(),
        prev_index: coin.index,
        sequence: 0,
        // owner OpCheckSigVerify + MINT-role OpCheckSigFromStack (real count:
        // 2) -- bumped to COVENANT_COMPUTE_BUDGET_SIG_OPS for compute-budget
        // headroom, see that constant's doc.
        sig_op_count: COVENANT_COMPUTE_BUDGET_SIG_OPS,
        script_version: current_p2sh.version(),
        script_bytes: current_p2sh.script().to_vec(),
        value: coin.value,
    });
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_utxo.script_bytes(),
        value: fee_utxo.utxo_entry.amount,
    });
    // Output[0]: the canonical unspendable sink, FULL coin value destroyed.
    tx.outputs.push(TxOutput::with_spk(coin.value, sink_spk.clone(), None));
    // Output[1]: fee change.
    let est_fee = 250_000u64;
    tx.outputs.push(TxOutput::new(fee_utxo.utxo_entry.amount.saturating_sub(est_fee), 0, wallet_spk.clone(), None));

    // The MINT-role attestation is the 121B BASE preimage with op_type=BURN
    // (no op-specific tail -- `build_burn_branch`'s doc: "sink pinned
    // structurally, not via preimage"), fixed regardless of fee/change.
    let outpoint_txid = txid_bytes(&coin.txid)?;
    let burn_msg =
        build_attestation_message(coin_cov_id, coin_op_type::BURN, coin.epoch, &outpoint_txid, coin.index, &spk_bytes_be(&sink_spk), coin.value);
    let mint_sig = signing::schnorr_sign(&roles.mint_sk, &burn_msg)?;

    let sign_all = |tx: &Transaction| -> anyhow::Result<Vec<Vec<u8>>> {
        let sh0 = compute_sighash(tx, 0)?;
        let owner_sig = signing::schnorr_sign(owner_sk, &sh0)?;
        let sigscript0 = build_stablecoin_burn_sigscript(&owner_sig, &mint_sig, &coin.rs);
        let sh1 = compute_sighash(tx, 1)?;
        let fee_sig = signing::schnorr_sign(&privkey, &sh1)?;
        Ok(vec![sigscript0, signing::build_p2pk_sigscript(&fee_sig)])
    };
    let sigs = sign_all(&tx)?;
    let exact_fee = fee_with_floor(min_relay_fee(calc_mass_with_sigscripts(&tx, &sigs)));
    let new_change = fee_utxo.utxo_entry.amount.saturating_sub(exact_fee);
    if new_change < kob_core::MIN_UTXO_VALUE {
        anyhow::bail!("BURN: fee UTXO {} too small after fee {}", fee_utxo.utxo_entry.amount, exact_fee);
    }
    tx.outputs[1].value = new_change;
    let sigs = sign_all(&tx)?;
    println!("BURN exact fee: {} sompi", exact_fee);

    preflight(&tx, "BURN", false)?;
    let payload = to_rpc_payload(&tx, &sigs);
    let txid = rpc.submit_transaction(payload).await?;
    println!("BURN SUBMITTED. TXID: {}  verify: {}", txid, verify_url(&txid));

    // Unlike the old bare-OpReturn sink, this P2SH sink DOES enter the UTXO
    // set (P2SH is a standard output form) -- but it remains provably
    // unspendable: no sigscript can satisfy the `[0x6a]` OpReturn redeem
    // script it commits to (see `BURN_SINK_SCRIPT`'s doc in `body.rs`). This
    // harness holds no key for it (there is none to hold), so verify via the
    // REST explorer rather than a wallet-tracked UTXO query.
    println!("BURN sink output (unspendable, {} sompi destroyed): {}:0. Verify via {}.", coin.value, txid, verify_url(&txid));

    Ok(BurnResult { txid, burned_value: coin.value, change_value: new_change })
}

// ---------------------------------------------------------------------
// RAISE_CAP
// ---------------------------------------------------------------------

// `authority_rs`/`authority_value` are carried for a caller that might chain
// a further op onto the raised-cap authority (e.g. a second MINT); this
// harness's op sequence ends at RAISE_CAP, so they go unread here.
#[allow(dead_code)]
struct RaiseCapResult {
    txid: String,
    authority_rs: Vec<u8>,
    authority_value: u64,
    current_cap: u64,
}

/// RAISE_CAP: a cold 2-of-3 `cap_authority` quorum raises the mint
/// authority's `current_cap` (STRICT increase); `running_supply` and native
/// value are both preserved unchanged, and no coin is emitted. Independent
/// of the coin lifecycle above -- this harness runs it against the mint
/// authority's LATEST UTXO (post-MINT: `running_supply = mint_amount`).
///
/// # Fee input: threaded from BURN, NOT re-queried (the orphan bug)
///
/// A live testnet-10 run rejected RAISE_CAP with "transaction ... is an
/// orphan where orphan is disallowed". Root cause: every OTHER op in this
/// file (TRANSFER/FREEZE/SEIZE/BURN) independently calls `pick_wallet_utxo`,
/// which re-queries the node's live UTXO set and picks the smallest P2PK
/// UTXO >= a floor -- but that query has no notion of "already spent by a
/// tx this harness itself just submitted and is still sitting unconfirmed
/// in the mempool". This "happens" to be safe for TRANSFER->FREEZE->
/// SEIZE->UNFREEZE->BURN because each of THOSE ops (except BURN) calls
/// `verify_utxo` after submitting, which POLLS (up to ~60s) for its own
/// covenant successor output to appear before returning -- in practice long
/// enough for the node to also settle the wallet fee spend out of its
/// "spendable" listing. `op_burn` is the one op with NO such wait (its
/// output is an unspendable P2SH sink this wallet holds no key for, so
/// there is nothing wallet-owned to poll for) -- it returns essentially
/// immediately after `submit_transaction`. RAISE_CAP used to run right
/// after that, re-query via `pick_wallet_utxo`, and pick the SAME
/// still-"spendable"-per-the-node outpoint BURN had just consumed as ITS
/// fee input (`de8d0093...:1` in the observed failure) -- a double-spend of
/// an unconfirmed output, rejected as an orphan.
///
/// The fix: RAISE_CAP's fee input is BURN's own wallet-change output
/// (`BurnResult::change_value`, BURN's output[1]) passed in directly by the
/// caller, continuing the same change-chain the coin-track ops rely on
/// instead of re-deriving it from a node UTXO-set snapshot that may lag an
/// unconfirmed spend. This sidesteps node freshness entirely: the fee input
/// used is exactly the one this harness itself just created and knows was
/// never spent by anything else.
#[allow(clippy::too_many_arguments)]
async fn op_raise_cap(
    rpc: &NodeClient,
    wallet: &WalletContext,
    roles: &RoleCtx,
    genesis_cov_id: &[u8; 32],
    authority_txid: &str,
    authority_value: u64,
    authority_rs_old: &[u8],
    running_supply: u64,
    new_cap: u64,
    fee_txid: &str,
    fee_index: u32,
    fee_value: u64,
) -> anyhow::Result<RaiseCapResult> {
    let privkey = *wallet.privkey_bytes();
    let wallet_spk = p2pk_script(&wallet.pubkey);

    let old_authority_p2sh = build_p2sh(authority_rs_old);
    let new_authority_rs = roles.authority_rs(running_supply, new_cap, genesis_cov_id);
    let new_authority_p2sh = build_p2sh(&new_authority_rs);
    let authority_addr = kob_cli::cancel::p2sh_to_address(new_authority_p2sh.script(), "kaspatest");

    // Fee input: BURN's own wallet change (see this fn's doc) -- a plain
    // P2PK output this harness itself just created, script version 0 and
    // `wallet_spk` bytes exactly as `op_burn` wrote it, NOT re-queried from
    // the node.
    println!("RAISE_CAP fee UTXO (BURN change, threaded -- not re-queried): {}:{} ({} sompi)", fee_txid, fee_index, fee_value);

    let mut tx = Transaction::new(1);
    tx.inputs.push(TxInput {
        prev_tx_id: authority_txid.to_string(),
        prev_index: 0,
        sequence: 0,
        // 2-of-3 cap_authority quorum: three OpCheckSigFromStack calls (real
        // count: 3) -- bumped to COVENANT_COMPUTE_BUDGET_SIG_OPS for
        // compute-budget headroom, see that constant's doc.
        sig_op_count: COVENANT_COMPUTE_BUDGET_SIG_OPS,
        script_version: old_authority_p2sh.version(),
        script_bytes: old_authority_p2sh.script().to_vec(),
        value: authority_value,
    });
    tx.inputs.push(TxInput {
        prev_tx_id: fee_txid.to_string(),
        prev_index: fee_index,
        sequence: 0,
        sig_op_count: 1,
        script_version: 0,
        script_bytes: wallet_spk.clone(),
        value: fee_value,
    });
    // Output[0]: continued authority (FIXED index 0), value PRESERVED, current_cap raised.
    tx.outputs.push(TxOutput::new(
        authority_value,
        new_authority_p2sh.version(),
        new_authority_p2sh.script().to_vec(),
        Some(CovenantBinding::new(0, (*genesis_cov_id).into())),
    ));
    // Output[1]: fee change.
    let est_fee = 250_000u64;
    tx.outputs.push(TxOutput::new(fee_value.saturating_sub(est_fee), 0, wallet_spk.clone(), None));

    let authority_txid_bytes = txid_bytes(authority_txid)?;
    let raise_cap_msg = build_raise_cap_attestation_message(genesis_cov_id, &authority_txid_bytes, 0, new_cap);
    let sig1 = signing::schnorr_sign(&roles.cap_authority_sk[0], &raise_cap_msg)?;
    let sig2 = signing::schnorr_sign(&roles.cap_authority_sk[1], &raise_cap_msg)?;
    let sig3 = signing::schnorr_sign(&roles.cap_authority_sk[2], &raise_cap_msg)?;
    let sigscript0 = build_mint_authority_raise_cap_sigscript(&sig1, &sig2, &sig3, authority_rs_old, &new_authority_rs, new_cap, authority_rs_old);

    let sign_fee = |tx: &Transaction| -> anyhow::Result<Vec<u8>> {
        let sh = compute_sighash(tx, 1)?;
        let sig = signing::schnorr_sign(&privkey, &sh)?;
        Ok(signing::build_p2pk_sigscript(&sig))
    };
    let sig_fee = sign_fee(&tx)?;
    let exact_fee = fee_with_floor(min_relay_fee(calc_mass_with_sigscripts(&tx, &[sigscript0.clone(), sig_fee])));
    let new_change = fee_value.saturating_sub(exact_fee);
    if new_change < kob_core::MIN_UTXO_VALUE {
        anyhow::bail!("RAISE_CAP: fee UTXO {} too small after fee {}", fee_value, exact_fee);
    }
    tx.outputs[1].value = new_change;
    let sig_fee = sign_fee(&tx)?;
    println!("RAISE_CAP exact fee: {} sompi", exact_fee);

    preflight(&tx, "RAISE_CAP", true)?;
    let payload = to_rpc_payload(&tx, &[sigscript0, sig_fee]);
    let txid = rpc.submit_transaction(payload).await?;
    println!("RAISE_CAP SUBMITTED. TXID: {}  verify: {}", txid, verify_url(&txid));

    verify_utxo(rpc, "RAISE_CAP continuation", &authority_addr, &txid, 0, authority_value, Some(genesis_cov_id), 20, Duration::from_secs(3))
        .await?;

    Ok(RaiseCapResult { txid, authority_rs: new_authority_rs, authority_value, current_cap: new_cap })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cfg = Config::from_env();
    println!("=== kob-stablecoin-e2e (testnet-10 live harness) ===");
    println!("NODE:           {}", cfg.node_url);
    println!("WALLET:         {}", cfg.wallet_path.display());
    println!("KEYS_MANIFEST:  {}", cfg.keys_manifest_path.display());
    println!("CAP:            {} sompi", cfg.cap);
    println!("MINT_AMOUNT:    {} sompi", cfg.mint_amount);
    println!("NEW_CAP:        {} sompi", cfg.new_cap);
    println!();

    let manifest = load_or_init_manifest(&cfg.keys_manifest_path)?;
    let roles = RoleCtx::from_keys(&manifest.keys)?;
    let mut state = manifest.state;

    let wallet = WalletContext::load(&cfg.wallet_path)?;
    println!("Wallet address: {}", wallet.address);
    println!("Connecting to {}...", cfg.node_url);
    let rpc = NodeClient::connect(&cfg.node_url).await?;
    println!("Connected via {}.", rpc.backend_name());
    println!();

    // ---- Step 1+2: DEPLOY (2-tx genesis bootstrap) ----
    println!("--- DEPLOY: TX1 (anchor) ---");
    let (genesis_cov_id, tx1_txid) = deploy_tx1_anchor(&rpc, &wallet, cfg.authority_value).await?;
    state.genesis_covenant_id = Some(hex::encode(genesis_cov_id));
    state.tx1_anchor = Some(tx1_txid.clone());
    save_manifest(&cfg.keys_manifest_path, &Manifest { keys: manifest.keys.clone(), state: state.clone() })?;

    println!("--- DEPLOY: TX2 (mint-authority genesis) ---");
    let deploy = deploy_tx2_authority(&rpc, &wallet, &roles, &genesis_cov_id, &tx1_txid, cfg.authority_value, cfg.cap).await?;
    state.tx2_authority_genesis = Some(deploy.tx2_txid.clone());
    save_manifest(&cfg.keys_manifest_path, &Manifest { keys: manifest.keys.clone(), state: state.clone() })?;

    println!();
    println!("DEPLOY complete. Mint authority live at {}:0 (G={}).", deploy.tx2_txid, hex::encode(deploy.genesis_covenant_id));

    // ---- Step 3: MINT ----
    println!("--- MINT ---");
    let mint = op_mint(
        &rpc,
        &wallet,
        &roles,
        &genesis_cov_id,
        &deploy.tx2_txid,
        deploy.authority_value,
        &deploy.authority_rs,
        cfg.cap,
        cfg.mint_amount,
    )
    .await?;
    state.coin_covenant_id = Some(hex::encode(mint.coin_covenant_id));
    state.tx3_mint = Some(mint.tx3_txid.clone());
    save_manifest(&cfg.keys_manifest_path, &Manifest { keys: manifest.keys.clone(), state: state.clone() })?;

    println!();
    println!(
        "MINT complete. Coin live at {}:1 (covenant_id={}), owner={}.",
        mint.tx3_txid,
        hex::encode(mint.coin_covenant_id),
        hex::encode(roles.owner_pk)
    );

    // (cloned, not moved -- `mint`'s authority fields are still needed below
    // for the independent RAISE_CAP step)
    let coin = CoinResult {
        rs: mint.coin_rs.clone(),
        value: mint.coin_value,
        txid: mint.tx3_txid.clone(),
        index: 1,
        owner_pk: roles.owner_pk,
        frozen: frozen_flag::CLEAR,
        epoch: 0,
    };

    // ---- Step 4: TRANSFER (owner -> owner2) ----
    println!("--- TRANSFER ---");
    let coin = op_transfer(&rpc, &wallet, &roles, &mint.coin_covenant_id, &coin, &roles.owner_sk, &roles.owner2_pk).await?;
    state.tx4_transfer = Some(coin.txid.clone());
    save_manifest(&cfg.keys_manifest_path, &Manifest { keys: manifest.keys.clone(), state: state.clone() })?;
    println!();
    println!("TRANSFER complete. Coin live at {}:0, owner={}.", coin.txid, hex::encode(roles.owner2_pk));

    // ---- Step 5: FREEZE (frozen_flag 0 -> 1) ----
    println!("--- FREEZE ---");
    let coin = op_freeze(&rpc, &wallet, &roles, &mint.coin_covenant_id, &coin, frozen_flag::SET).await?;
    state.tx5_freeze = Some(coin.txid.clone());
    save_manifest(&cfg.keys_manifest_path, &Manifest { keys: manifest.keys.clone(), state: state.clone() })?;
    println!();
    println!("FREEZE complete. Coin live at {}:0, frozen={}.", coin.txid, coin.frozen);

    // ---- Step 6: SEIZE (owner2 -> recovery, still frozen) ----
    println!("--- SEIZE ---");
    let coin = op_seize(&rpc, &wallet, &roles, &mint.coin_covenant_id, &coin, &roles.recovery_pk).await?;
    state.tx6_seize = Some(coin.txid.clone());
    save_manifest(&cfg.keys_manifest_path, &Manifest { keys: manifest.keys.clone(), state: state.clone() })?;
    println!();
    println!("SEIZE complete. Coin live at {}:0, owner={}, frozen={}.", coin.txid, hex::encode(roles.recovery_pk), coin.frozen);

    // ---- Step 7: UNFREEZE (extra step -- see top-of-file doc) ----
    println!("--- UNFREEZE (extra step: clears the frozen gate before BURN) ---");
    let coin = op_freeze(&rpc, &wallet, &roles, &mint.coin_covenant_id, &coin, frozen_flag::CLEAR).await?;
    state.tx7_unfreeze = Some(coin.txid.clone());
    save_manifest(&cfg.keys_manifest_path, &Manifest { keys: manifest.keys.clone(), state: state.clone() })?;
    println!();
    println!("UNFREEZE complete. Coin live at {}:0, frozen={}.", coin.txid, coin.frozen);

    // ---- Step 8: BURN, or MIGRATE when asked for ----
    // Both consume the one coin this harness mints, so they are alternatives
    // rather than successive steps. MIGRATE is opt-in (`MIGRATE_DEMO=1`)
    // because BURN is what the original 7-op task sequence names; the two
    // produce the same shape (a spent coin plus a wallet change output at
    // index 1), so RAISE_CAP chains off whichever ran.
    let migrate_demo = env::var("MIGRATE_DEMO").ok().as_deref() == Some("1");
    let (spend_txid, spend_change) = if migrate_demo {
        println!("--- MIGRATE (in place of BURN; MIGRATE_DEMO=1) ---");
        let migrate = op_migrate(&rpc, &wallet, &roles, &mint.coin_covenant_id, &coin, &roles.recovery_sk).await?;
        state.tx8_burn = Some(migrate.txid.clone());
        save_manifest(&cfg.keys_manifest_path, &Manifest { keys: manifest.keys.clone(), state: state.clone() })?;
        println!();
        println!(
            "MIGRATE complete. {} sompi left covenant governance in TX {} (owner + cold 2-of-3).",
            migrate.migrated_value, migrate.txid
        );
        (migrate.txid, migrate.change_value)
    } else {
        println!("--- BURN ---");
        let burn = op_burn(&rpc, &wallet, &roles, &mint.coin_covenant_id, &coin).await?;
        state.tx8_burn = Some(burn.txid.clone());
        save_manifest(&cfg.keys_manifest_path, &Manifest { keys: manifest.keys.clone(), state: state.clone() })?;
        println!();
        println!("BURN complete. {} sompi destroyed in TX {}.", burn.burned_value, burn.txid);
        (burn.txid, burn.change_value)
    };

    // ---- Step 9: RAISE_CAP (independent of the coin lifecycle above) ----
    println!("--- RAISE_CAP ---");
    // Fee input: BURN's own wallet change (output[1]), threaded forward
    // rather than re-queried from the node -- see `op_raise_cap`'s doc for
    // why (BURN has no confirm-and-wait, so a fresh `pick_wallet_utxo` query
    // here could still see BURN's already-spent fee input as "spendable"
    // and pick that same stale outpoint -- the live orphan-rejection bug).
    let raise_cap = op_raise_cap(
        &rpc,
        &wallet,
        &roles,
        &genesis_cov_id,
        &mint.tx3_txid,
        mint.authority_value,
        &mint.authority_rs,
        cfg.mint_amount, // running_supply after the one MINT this harness performed
        cfg.new_cap,
        &spend_txid,
        1,
        spend_change,
    )
    .await?;
    state.tx9_raise_cap = Some(raise_cap.txid.clone());
    save_manifest(&cfg.keys_manifest_path, &Manifest { keys: manifest.keys.clone(), state: state.clone() })?;
    println!();
    println!(
        "RAISE_CAP complete. Authority live at {}:0, current_cap={}.",
        raise_cap.txid, raise_cap.current_cap
    );
    println!();
    println!("=== ALL 7 OPS COMPLETE (DEPLOY, MINT, TRANSFER, FREEZE, SEIZE, BURN, RAISE_CAP; +1 extra UNFREEZE) ===");

    Ok(())
}
