//! `kob-cli perp` -- Perpetual futures order management.

use clap::Subcommand;
use std::path::Path;
use tracing::info;

use crate::cancel::p2sh_to_address;
use crate::node::NodeClient;
use crate::signing;
use kob_core::p2sh::{blake2b_256, build_p2sh};
use kob_core::perp;
use kob_core::sighash::compute_sighash;
use kob_core::tx::{to_rpc_payload, select_utxos_mass_aware, Transaction, TxInput, TxOutput, CoinSelection};
use kob_core::types::{Network, UtxoEntry, Outpoint};
use kob_core::wallet::WalletFile;
use kob_core::mass::{calc_mass_with_sigscripts, compute_storage_mass, converge_fee, estimate_compute_mass, MAX_TX_MASS};
use kob_core::MIN_UTXO_VALUE;

/// Subcommands for `perp`.
#[derive(Subcommand, Debug)]
pub enum PerpCommand {
    /// Deploy a long perp order (lock margin, specify limit price).
    DeployLong {
        /// Token / pair identifier (hex, 64 chars) -- used for payload tagging.
        #[arg(long)]
        token: String,

        /// Margin amount in sompi to lock in the deploy UTXO.
        #[arg(long)]
        margin: u64,

        /// Limit price numerator.
        #[arg(long)]
        price_num: u64,

        /// Limit price denominator.
        #[arg(long)]
        price_den: u64,

        /// Minimum fill amount in sompi (anti-dust).
        #[arg(long)]
        min_fill: u64,

        /// Maintenance margin percentage numerator (default: 5 for 5%).
        #[arg(long, default_value = "5")]
        maint_pct_num: u64,

        /// Maintenance margin percentage denominator (default: 100).
        #[arg(long, default_value = "100")]
        maint_pct_den: u64,

        /// Keeper fee in sompi for the resulting position (default: 3_000_000).
        #[arg(long, default_value = "3000000")]
        keeper_fee: u64,

        /// Emergency timeout in DAA scores for the resulting position.
        #[arg(long, default_value = "5000000")]
        emergency_daa: u64,

        /// Maximum fee matcher can extract from margin (default: 500_000 sompi).
        #[arg(long, default_value = "500000")]
        max_matcher_fee: u64,
    },

    /// Deploy a short perp order (lock margin, specify limit price).
    DeployShort {
        /// Token / pair identifier (hex, 64 chars) -- used for payload tagging.
        #[arg(long)]
        token: String,

        /// Margin amount in sompi to lock in the deploy UTXO.
        #[arg(long)]
        margin: u64,

        /// Limit price numerator.
        #[arg(long)]
        price_num: u64,

        /// Limit price denominator.
        #[arg(long)]
        price_den: u64,

        /// Minimum fill amount in sompi (anti-dust).
        #[arg(long)]
        min_fill: u64,

        /// Maintenance margin percentage numerator (default: 5 for 5%).
        #[arg(long, default_value = "5")]
        maint_pct_num: u64,

        /// Maintenance margin percentage denominator (default: 100).
        #[arg(long, default_value = "100")]
        maint_pct_den: u64,

        /// Keeper fee in sompi for the resulting position (default: 3_000_000).
        #[arg(long, default_value = "3000000")]
        keeper_fee: u64,

        /// Emergency timeout in DAA scores for the resulting position.
        #[arg(long, default_value = "5000000")]
        emergency_daa: u64,

        /// Maximum fee matcher can extract from margin (default: 500_000 sompi).
        #[arg(long, default_value = "500000")]
        max_matcher_fee: u64,
    },

    /// Cancel an unmatched perp deploy order (owner reclaims margin).
    Cancel {
        /// Outpoint of the perp deploy order to cancel (txid:index).
        #[arg(long)]
        outpoint: String,

        /// Limit price numerator (must match the deployed order).
        #[arg(long)]
        price_num: u64,

        /// Limit price denominator (must match the deployed order).
        #[arg(long)]
        price_den: u64,

        /// Minimum fill amount (must match the deployed order).
        #[arg(long)]
        min_fill: u64,

        /// Maintenance margin percentage numerator (must match).
        #[arg(long, default_value = "5")]
        maint_pct_num: u64,

        /// Maintenance margin percentage denominator (must match).
        #[arg(long, default_value = "100")]
        maint_pct_den: u64,

        /// Keeper fee in sompi (must match).
        #[arg(long, default_value = "3000000")]
        keeper_fee: u64,

        /// Emergency DAA (must match).
        #[arg(long, default_value = "5000000")]
        emergency_daa: u64,

        /// Maximum matcher fee (must match).
        #[arg(long, default_value = "500000")]
        max_matcher_fee: u64,

        /// Order UTXO value in sompi (queried from chain if omitted).
        #[arg(long)]
        order_value: Option<u64>,

        /// Fee UTXO outpoint (txid:index) to use instead of auto-selection.
        #[arg(long)]
        fee_utxo: Option<String>,
    },

    /// List open perp positions.
    ///
    /// With --engine-url: queries the engine REST API for positions.
    /// Without: scans node UTXOs for perp position covenants owned by wallet.
    Positions {
        /// Engine API URL (e.g. http://localhost:8080).
        #[arg(long)]
        engine_url: Option<String>,

        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Cooperatively close a perp position (requires counterparty signature).
    ///
    /// Both parties must agree on the split. The counterparty provides their
    /// pre-signed signature over the close TX. This command adds the local
    /// wallet's signature and submits.
    Close {
        /// Outpoint of the position UTXO (txid:index).
        #[arg(long)]
        outpoint: String,

        /// Position UTXO value in sompi.
        #[arg(long)]
        position_value: u64,

        /// Counterparty's signature (hex, 128 chars = 64 bytes).
        #[arg(long)]
        counterparty_sig: String,

        /// Counterparty's public key (hex, 64 chars = 32 bytes).
        #[arg(long)]
        counterparty_pubkey: String,

        /// Amount to send to the local wallet (long payout or short payout).
        #[arg(long)]
        my_payout: u64,

        /// Amount to send to counterparty.
        #[arg(long)]
        their_payout: u64,

        /// Hex-encoded redeemScript of the position covenant.
        #[arg(long)]
        rs: String,

        /// Whether the local wallet is the long side (default: true).
        #[arg(long, default_value = "true")]
        is_long: bool,

        /// Fee UTXO outpoint (txid:index).
        #[arg(long)]
        fee_utxo: Option<String>,
    },

    /// Liquidate an underwater perp position (permissionless, keeper earns fee).
    ///
    /// Anyone can call this. The covenant validates that the position is below
    /// the maintenance margin threshold. The keeper_fee from the position is
    /// paid to the submitter (liquidator).
    Liquidate {
        /// Outpoint of the position UTXO (txid:index).
        #[arg(long)]
        outpoint: String,

        /// Position UTXO value in sompi.
        #[arg(long)]
        position_value: u64,

        /// Hex-encoded redeemScript of the position covenant.
        #[arg(long)]
        rs: String,

        /// Keeper payout address (defaults to wallet address).
        #[arg(long)]
        keeper_address: Option<String>,

        /// Fee UTXO outpoint (txid:index).
        #[arg(long)]
        fee_utxo: Option<String>,
    },

    /// Add margin to an open perp position (owner only, self-continuation).
    ///
    /// The owner tops up the position by sending additional margin. The output
    /// must be a self-continuation (same P2SH covenant, higher value).
    AddMargin {
        /// Outpoint of the position UTXO (txid:index).
        #[arg(long)]
        outpoint: String,

        /// Current position UTXO value in sompi.
        #[arg(long)]
        position_value: u64,

        /// Additional margin to add in sompi.
        #[arg(long)]
        amount: u64,

        /// Hex-encoded redeemScript of the position covenant.
        #[arg(long)]
        rs: String,

        /// Fee UTXO outpoint (txid:index).
        #[arg(long)]
        fee_utxo: Option<String>,
    },

    /// Settle a matured perp position (permissionless, CLTV-gated).
    ///
    /// After maturity_daa has passed, anyone can settle the position.
    /// The covenant enforces the PnL split based on the price feed.
    /// TX lockTime must be >= maturity_daa.
    Settle {
        /// Outpoint of the position UTXO (txid:index).
        #[arg(long)]
        outpoint: String,

        /// Position UTXO value in sompi.
        #[arg(long)]
        position_value: u64,

        /// Hex-encoded redeemScript of the position covenant.
        #[arg(long)]
        rs: String,

        /// Long side payout in sompi.
        #[arg(long)]
        long_payout: u64,

        /// Short side payout in sompi.
        #[arg(long)]
        short_payout: u64,

        /// Long side public key (hex, 64 chars = 32 bytes).
        #[arg(long)]
        long_pubkey: String,

        /// Short side public key (hex, 64 chars = 32 bytes).
        #[arg(long)]
        short_pubkey: String,

        /// TX lockTime (DAA score, must be >= maturity_daa).
        #[arg(long)]
        lock_time: u64,

        /// Fee UTXO outpoint (txid:index).
        #[arg(long)]
        fee_utxo: Option<String>,
    },
}

// Deploy implementation (shared between long and short)

/// Deploy a perp order (long or short). Builds the perp deploy covenant,
/// wraps in P2SH, funds from wallet UTXOs, and submits to node RPC.
#[allow(clippy::too_many_arguments)]
async fn deploy_perp(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    side: &str,
    _token: &str,
    margin: u64,
    price_num: u64,
    price_den: u64,
    min_fill: u64,
    maint_pct_num: u64,
    maint_pct_den: u64,
    keeper_fee: u64,
    emergency_daa: u64,
    max_matcher_fee: u64,
    fee: u64,
) -> anyhow::Result<String> {
    // Input validation
    if price_num == 0 {
        anyhow::bail!("price_num must be > 0");
    }
    if price_den == 0 {
        anyhow::bail!("price_den must be > 0");
    }
    if min_fill == 0 {
        anyhow::bail!("min_fill must be > 0");
    }
    if margin == 0 {
        anyhow::bail!("margin must be > 0");
    }
    if margin < perp::MIN_MARGIN_SOMPI {
        anyhow::bail!(
            "margin ({}) must be >= MIN_MARGIN_SOMPI ({})",
            margin,
            perp::MIN_MARGIN_SOMPI
        );
    }
    if margin < min_fill {
        anyhow::bail!(
            "margin ({}) must be >= min_fill ({}) (order must be fillable)",
            margin,
            min_fill
        );
    }
    if maint_pct_den == 0 {
        anyhow::bail!("maint_pct_den must be > 0");
    }

    let wallet = WalletFile::load(wallet_path)?;
    let pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.secure_key()?;
    let spk_hash = blake2b_256(&pubkey);

    // Build perp_deploy_v1 redeemScript
    let redeem_script = perp::build_perp_deploy_redeem_script(
        &spk_hash,
        price_num,
        price_den,
        maint_pct_num,
        maint_pct_den,
        keeper_fee,
        emergency_daa,
        min_fill,
        max_matcher_fee,
    );

    let p2sh = build_p2sh(&redeem_script);

    println!("Deploy Perp {} Order", side.to_uppercase());
    println!("==========================");
    println!(
        "Price:          {}/{} ({:.6})",
        price_num,
        price_den,
        price_num as f64 / price_den as f64
    );
    println!("Min Fill:       {} sompi", min_fill);
    println!(
        "Margin:         {} sompi ({:.8} KAS)",
        margin,
        margin as f64 / 1e8
    );
    println!("Maint %:        {}/{}", maint_pct_num, maint_pct_den);
    println!("Keeper Fee:     {} sompi", keeper_fee);
    println!("Emergency DAA:  {}", emergency_daa);
    println!("Max Matcher Fee:{} sompi", max_matcher_fee);
    println!("Owner:          {}", wallet.public_key);
    println!("Owner SPK Hash: {}", hex::encode(spk_hash));
    println!();
    println!("RedeemScript:   {} bytes", redeem_script.len());
    println!("RS hex:         {}", hex::encode(&redeem_script));
    println!("P2SH SPK:       {}", hex::encode(&p2sh.script()));
    println!();

    // Connect and fetch UTXOs
    info!(
        address = %wallet.address,
        margin = margin,
        side = side,
        "deploying perp order"
    );
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    let rpc_utxos = rpc.get_spendable_utxos(&wallet.address).await?;

    // Filter to P2PK UTXOs and convert for mass-aware selection
    let p2pk_rpc: Vec<_> = rpc_utxos.iter().filter(|u| !u.is_p2sh()).collect();
    let core_utxos: Vec<UtxoEntry> = p2pk_rpc
        .iter()
        .map(|u| UtxoEntry {
            outpoint: Outpoint {
                transaction_id: u.outpoint.transaction_id.clone(),
                index: u.outpoint.index,
            },
            value: u.utxo_entry.amount,
            script_public_key: format!(
                "{:04x}{}",
                u.utxo_entry.script_public_key.version,
                u.utxo_entry.script_public_key.script
            ),
        })
        .collect();

    // Mass-aware UTXO selection: 2 outputs (order + change)
    let coin_sel: CoinSelection =
        select_utxos_mass_aware(&core_utxos, margin, fee, 2).map_err(|e| {
            anyhow::anyhow!(
                "UTXO selection failed: {}. {} P2PK UTXOs available.",
                e,
                core_utxos.len()
            )
        })?;

    let selected_utxos = &coin_sel.utxos;
    let total_input = coin_sel.total;
    println!(
        "Selected {} funding UTXOs (total {} sompi)",
        selected_utxos.len(),
        total_input
    );
    for u in selected_utxos {
        println!(
            "  {}:{} ({} sompi)",
            &u.outpoint.transaction_id[..16],
            u.outpoint.index,
            u.value
        );
    }
    if !coin_sel.penalty_free {
        println!(
            "  Warning: storage mass penalty {}/{} (run `kob wallet consolidate` to reduce)",
            coin_sel.storage_mass,
            kob_core::MAX_TX_MASS
        );
    }

    // Build transaction
    let mut tx = Transaction::new(0);

    // Inputs: selected wallet P2PK UTXOs
    for sel in selected_utxos {
        let rpc_utxo = p2pk_rpc
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == sel.outpoint.transaction_id
                    && u.outpoint.index == sel.outpoint.index
            })
            .ok_or_else(|| anyhow::anyhow!("UTXO spent during TX construction, please retry."))?;
        tx.inputs.push(TxInput {
            prev_tx_id: rpc_utxo.outpoint.transaction_id.clone(),
            prev_index: rpc_utxo.outpoint.index,
            sequence: 0,
            sig_op_count: 1,
            script_version: rpc_utxo.utxo_entry.script_public_key.version,
            script_bytes: rpc_utxo.script_bytes(),
            value: rpc_utxo.utxo_entry.amount,
        });
    }

    // Output 0: P2SH covenant output (the perp deploy order)
    tx.outputs.push(TxOutput::new(margin, 0, p2sh.script().to_vec(), None));

    // TX payload: RS for matcher L1 discovery (KOB:P:<side><RS> format)
    let side_byte = if side == "long" { perp::PERP_SIDE_LONG } else { perp::PERP_SIDE_SHORT };
    tx.payload = perp::build_perp_deploy_payload(&redeem_script, side_byte);

    // Output 1: tentative change
    let tent_change = total_input.saturating_sub(margin + fee);
    let first_rpc = p2pk_rpc
        .iter()
        .find(|u| {
            u.outpoint.transaction_id == selected_utxos[0].outpoint.transaction_id
                && u.outpoint.index == selected_utxos[0].outpoint.index
        })
        .ok_or_else(|| anyhow::anyhow!("UTXO spent during TX construction, please retry."))?;
    let wallet_spk = hex::decode(&first_rpc.utxo_entry.script_public_key.script)?;
    if tent_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(tent_change, first_rpc.utxo_entry.script_public_key.version, wallet_spk.clone(), None));
    }

    // Phase 1: converge fee on change output
    let min_fee_override = if fee > 0 { fee } else { 0 };
    let has_change_deploy = tx.outputs.len() > 1;
    let change_idx_deploy = tx.outputs.len().saturating_sub(1);
    let (est_fee_deploy, _) = if has_change_deploy {
        converge_fee(&mut tx, total_input, change_idx_deploy, min_fee_override)
    } else {
        let f = kob_core::mass::calc_miner_fee(&tx).max(min_fee_override);
        (f, 0)
    };

    if has_change_deploy && tx.outputs[change_idx_deploy].value < MIN_UTXO_VALUE {
        let change_val = tx.outputs[change_idx_deploy].value;
        tx.outputs.pop();
        if change_val > 0 {
            println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", change_val);
        }
    } else if !has_change_deploy && tent_change > 0 {
        println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", tent_change);
    }

    // Sign each input (phase 1)
    let mut sigscripts: Vec<Vec<u8>> = Vec::new();
    for i in 0..tx.inputs.len() {
        let sighash = compute_sighash(&tx, i)?;
        let signature = signing::schnorr_sign_secure(&privkey, &sighash)?;
        sigscripts.push(signing::build_p2pk_sigscript(&signature));
    }

    // Phase 2: exact mass check
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts);
    let exact_fee = exact_mass.max(min_fee_override);

    let actual_fee = if exact_fee != est_fee_deploy {
        if tx.outputs.len() > 1 {
            let change_idx = tx.outputs.len() - 1;
            let new_change = total_input.saturating_sub(margin + exact_fee);
            if new_change >= MIN_UTXO_VALUE {
                tx.outputs[change_idx].value = new_change;
            } else {
                tx.outputs.pop();
                if new_change > 0 {
                    println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", new_change);
                }
            }
            sigscripts.clear();
            for i in 0..tx.inputs.len() {
                let sighash = compute_sighash(&tx, i)?;
                let signature = signing::schnorr_sign_secure(&privkey, &sighash)?;
                sigscripts.push(signing::build_p2pk_sigscript(&signature));
            }
        }
        exact_fee
    } else {
        est_fee_deploy
    };

    println!("Signed {} input(s)", sigscripts.len());
    println!();

    // Storage mass pre-check
    if let Err(e) = kob_core::check_tx_storage_mass(&tx) {
        anyhow::bail!(
            "Deploy TX would be rejected by node: {}. \
             Increase the margin or use a larger funding UTXO.",
            e
        );
    }

    // Fee transparency summary
    {
        let in_vals: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let out_vals: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        let storage_mass = compute_storage_mass(&in_vals, &out_vals);
        let exact_compute = calc_mass_with_sigscripts(&tx, &sigscripts);
        println!("Fee Summary");
        println!("-----------");
        println!(
            "Storage mass:     {:>9} / {:>9} ({})",
            storage_mass,
            MAX_TX_MASS,
            if storage_mass <= MAX_TX_MASS { "OK" } else { "OVER" }
        );
        println!("Compute mass:     {:>9} (exact, post-sign)", exact_compute);
        println!("Miner fee:        {:>9} sompi", actual_fee);
        println!("Matcher fee cap:  {:>9} sompi", max_matcher_fee);
        println!();
    }

    // Submit
    let payload = to_rpc_payload(&tx, &sigscripts);
    println!("Submitting transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Perp {} deploy submitted.", side);
    println!("TXID: {}", tx_id);
    println!();
    println!("Order deployed at output {}:0", tx_id);

    Ok(tx_id)
}

// Cancel implementation

/// Cancel an unmatched perp deploy order. Reconstructs the redeemScript,
/// builds a cancel TX (sigLen >= T2), signs, and submits.
#[allow(clippy::too_many_arguments)]
async fn cancel_perp(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    outpoint_str: &str,
    price_num: u64,
    price_den: u64,
    min_fill: u64,
    maint_pct_num: u64,
    maint_pct_den: u64,
    keeper_fee: u64,
    emergency_daa: u64,
    max_matcher_fee: u64,
    order_value_override: Option<u64>,
    fee: u64,
    fee_utxo_override: Option<&str>,
) -> anyhow::Result<()> {
    let wallet = WalletFile::load(wallet_path)?;
    let outpoint = Outpoint::parse(outpoint_str)?;
    let pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.secure_key()?;
    let spk_hash = blake2b_256(&pubkey);

    // Reconstruct the redeemScript
    let redeem_script = perp::build_perp_deploy_redeem_script(
        &spk_hash,
        price_num,
        price_den,
        maint_pct_num,
        maint_pct_den,
        keeper_fee,
        emergency_daa,
        min_fill,
        max_matcher_fee,
    );

    let p2sh = build_p2sh(&redeem_script);

    println!("Cancel Perp Deploy Order");
    println!("========================");
    println!("Outpoint:       {}", outpoint);
    println!("Price:          {}/{}", price_num, price_den);
    println!("Min Fill:       {}", min_fill);
    println!("Owner:          {}", wallet.public_key);
    println!("RedeemScript:   {} bytes", redeem_script.len());
    println!("P2SH SPK:       {}", hex::encode(&p2sh.script()));
    println!();

    // Connect to node
    info!(outpoint = %outpoint, "cancelling perp deploy order");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Determine order UTXO value
    let order_value = if let Some(v) = order_value_override {
        v
    } else {
        let p2sh_address = p2sh_to_address(&p2sh.script(), network.address_prefix());
        println!("P2SH Address:   {}", p2sh_address);
        println!("Querying order UTXO value from chain...");
        let order_utxos = rpc.get_utxos_by_addresses(&[&p2sh_address]).await?;
        let order_utxo = order_utxos
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == outpoint.transaction_id
                    && u.outpoint.index == outpoint.index
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Order UTXO {} not found at P2SH address {}. It may be spent or use --order-value.",
                    outpoint,
                    p2sh_address
                )
            })?;
        order_utxo.utxo_entry.amount
    };

    println!("Order Value:    {} sompi", order_value);

    // Estimate fee for UTXO selection (will be refined after TX construction).
    let est_fee = estimate_compute_mass(2, 1, 0) + 500;

    // Get a fee UTXO from the wallet
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let fee_utxo = if let Some(fee_op_str) = fee_utxo_override {
        let fee_op = Outpoint::parse(fee_op_str)?;
        wallet_utxos
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == fee_op.transaction_id
                    && u.outpoint.index == fee_op.index
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Fee UTXO {} not found in wallet UTXOs.",
                    fee_op_str
                )
            })?
    } else {
        let mut candidates: Vec<_> = wallet_utxos
            .iter()
            .filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= est_fee + MIN_UTXO_VALUE)
            .collect();
        candidates.sort_by(|a, b| a.utxo_entry.amount.cmp(&b.utxo_entry.amount));
        candidates.first().copied().ok_or_else(|| {
            anyhow::anyhow!(
                "No P2PK UTXO with >= {} sompi for fee payment",
                est_fee + MIN_UTXO_VALUE
            )
        })?
    };

    println!(
        "Fee UTXO:       {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id,
        fee_utxo.outpoint.index,
        fee_utxo.utxo_entry.amount
    );

    // Build the cancel transaction with tentative output value
    let total_in = order_value + fee_utxo.utxo_entry.amount;
    let tentative_output = total_in - est_fee;
    let mut tx = Transaction::new(0);

    // Input 0: order UTXO (P2SH, cancel sigscript)
    tx.inputs.push(TxInput {
        prev_tx_id: outpoint.transaction_id.clone(),
        prev_index: outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: p2sh.version,
        script_bytes: p2sh.script().to_vec(),
        value: order_value,
    });

    // Input 1: fee UTXO (P2PK)
    let fee_spk_bytes = fee_utxo.script_bytes();
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_spk_bytes.clone(),
        value: fee_utxo.utxo_entry.amount,
    });

    // Output 0: recovered funds to wallet
    let wallet_spk = hex::decode(&fee_utxo.utxo_entry.script_public_key.script)?;
    tx.outputs.push(TxOutput::new(tentative_output, fee_utxo.utxo_entry.script_public_key.version, wallet_spk, None));

    // Phase 1: converge fee on output 0
    let min_fee_override = if fee > 0 { fee } else { 0 };
    let (est_fee, _) = converge_fee(&mut tx, total_in, 0, min_fee_override);

    // Sign input 0 (cancel path signature)
    let sighash_0 = compute_sighash(&tx, 0)?;
    let sig_0 = signing::schnorr_sign_secure(&privkey, &sighash_0)?;

    // Build perp deploy cancel sigscript (sigLen >= T2=251 triggers cancel)
    let cancel_sigscript =
        perp::build_perp_deploy_cancel_sigscript(&sig_0, &pubkey, &redeem_script);

    // Sign input 1 (fee UTXO, P2PK)
    let sighash_1 = compute_sighash(&tx, 1)?;
    let sig_1 = signing::schnorr_sign_secure(&privkey, &sighash_1)?;
    let fee_sigscript = signing::build_p2pk_sigscript(&sig_1);

    // Phase 2: exact mass check with real sigscripts
    let sigscripts_cancel = vec![cancel_sigscript.clone(), fee_sigscript.clone()];
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts_cancel);
    let exact_fee = exact_mass.max(min_fee_override);

    let (cancel_sigscript, fee_sigscript, actual_fee) = if exact_fee != est_fee {
        let output_value = total_in.saturating_sub(exact_fee);
        tx.outputs[0].value = output_value;
        let sighash_0 = compute_sighash(&tx, 0)?;
        let sig_0 = signing::schnorr_sign_secure(&privkey, &sighash_0)?;
        let cancel_sigscript = perp::build_perp_deploy_cancel_sigscript(&sig_0, &pubkey, &redeem_script);
        let sighash_1 = compute_sighash(&tx, 1)?;
        let sig_1 = signing::schnorr_sign_secure(&privkey, &sighash_1)?;
        let fee_sigscript = signing::build_p2pk_sigscript(&sig_1);
        (cancel_sigscript, fee_sigscript, exact_fee)
    } else {
        (cancel_sigscript, fee_sigscript, est_fee)
    };

    let output_value = tx.outputs[0].value;

    println!("Cancel SigScript: {} bytes", cancel_sigscript.len());
    println!(
        "  (>= T2=251 triggers cancel path: {})",
        if cancel_sigscript.len() >= 251 { "YES" } else { "NO -- ERROR" }
    );
    println!("Output Value:   {} sompi", output_value);
    println!();

    // Fee transparency summary
    {
        let in_vals: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let out_vals: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        let storage_mass = compute_storage_mass(&in_vals, &out_vals);
        let exact_compute = calc_mass_with_sigscripts(&tx, &[cancel_sigscript.clone(), fee_sigscript.clone()]);
        println!("Fee Summary");
        println!("-----------");
        println!(
            "Storage mass:     {:>9} / {:>9} ({})",
            storage_mass, MAX_TX_MASS,
            if storage_mass <= MAX_TX_MASS { "OK" } else { "OVER" }
        );
        println!("Compute mass:     {:>9} (exact, post-sign)", exact_compute);
        println!("Miner fee:        {:>9} sompi", actual_fee);
        let surplus = fee_utxo.utxo_entry.amount.saturating_sub(actual_fee);
        if surplus > 0 && surplus < MIN_UTXO_VALUE {
            println!("Surplus:          {:>9} sompi (donated as fee)", surplus);
        }
        println!();
    }

    // Submit
    let payload = to_rpc_payload(&tx, &[cancel_sigscript, fee_sigscript]);
    println!("Submitting cancel transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Perp cancel transaction submitted.");
    println!("TXID: {}", tx_id);
    println!();
    println!("Recovered {} sompi to wallet.", output_value);

    Ok(())
}

// Positions implementation

/// List open perp positions. If engine_url is provided, query the engine API.
/// Otherwise, scan node UTXOs for perp position covenants.
async fn list_positions(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    engine_url: Option<&str>,
    json: bool,
) -> anyhow::Result<()> {
    if let Some(url) = engine_url {
        // Query engine REST API
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()?;

        let api_url = format!("{}/api/v1/perp/positions", url.trim_end_matches('/'));
        println!("Querying engine API: {}", api_url);

        let resp = client.get(&api_url).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("Engine API returned HTTP {}", resp.status());
        }

        let body = resp.text().await?;
        if json {
            println!("{}", body);
        } else {
            // Parse and display in human-readable format
            let positions: serde_json::Value = serde_json::from_str(&body)?;
            if let Some(arr) = positions.as_array() {
                if arr.is_empty() {
                    println!("No open positions.");
                    return Ok(());
                }
                println!("Open Perp Positions ({}):", arr.len());
                println!("{:-<80}", "");
                for pos in arr {
                    println!(
                        "  UTXO:    {}:{}",
                        pos["txid"].as_str().unwrap_or("?"),
                        pos["index"].as_u64().unwrap_or(0)
                    );
                    println!(
                        "  Side:    {}  Size: {}  Entry: {}/{}",
                        pos["side"].as_str().unwrap_or("?"),
                        pos["size"].as_u64().unwrap_or(0),
                        pos["entry_num"].as_u64().unwrap_or(0),
                        pos["entry_den"].as_u64().unwrap_or(0),
                    );
                    println!(
                        "  Margin:  {} sompi",
                        pos["margin"].as_u64().unwrap_or(0)
                    );
                    println!("{:-<80}", "");
                }
            } else {
                println!("{}", body);
            }
        }
    } else {
        // Scan node UTXOs for perp position covenants
        let wallet = WalletFile::load(wallet_path)?;
        let pubkey = wallet.public_key_bytes()?;
        let spk_hash = blake2b_256(&pubkey);

        println!("Scanning node UTXOs for perp positions...");
        println!("Owner SPK Hash: {}", hex::encode(spk_hash));
        println!();

        let rpc = NodeClient::connect(node_url).await?;
        let utxos = rpc.get_spendable_utxos(&wallet.address).await?;

        // Filter P2SH UTXOs (potential perp positions)
        let p2sh_utxos: Vec<_> = utxos.iter().filter(|u| u.is_p2sh()).collect();
        if p2sh_utxos.is_empty() {
            println!("No P2SH UTXOs found. No perp positions detected.");
            return Ok(());
        }

        println!(
            "Found {} P2SH UTXOs (potential positions):",
            p2sh_utxos.len()
        );
        for u in &p2sh_utxos {
            println!(
                "  {}:{} ({} sompi)",
                &u.outpoint.transaction_id[..16],
                u.outpoint.index,
                u.utxo_entry.amount
            );
        }
        println!();
        println!(
            "Note: Without engine API, positions cannot be fully decoded from UTXOs alone."
        );
        println!(
            "Use --engine-url for detailed position information."
        );
    }

    Ok(())
}

// Cooperative close implementation

/// Cooperatively close a perp position.
///
/// NOTE: v7 position covenant removed cooperative close (2-of-2 sig path).
/// Positions are now closed via unilateral close or maturity settle.
/// This subcommand is retained for CLI structure but not functional.
#[allow(clippy::too_many_arguments)]
async fn close_perp(
    _wallet_path: &Path,
    _node_url: &str,
    _network: Network,
    _outpoint_str: &str,
    _position_value: u64,
    _counterparty_sig_hex: &str,
    _counterparty_pubkey_hex: &str,
    _my_payout: u64,
    _their_payout: u64,
    _rs_hex: &str,
    _is_long: bool,
    _fee: u64,
    _fee_utxo_override: Option<&str>,
) -> anyhow::Result<()> {
    anyhow::bail!(
        "cooperative close (2-of-2) was removed in v7 position covenant.\n\
         In v7, each party owns their position UTXO independently.\n\
         Use 'perp cancel' to reclaim your margin, or 'perp unilateral-close'\n\
         with a spot co-spend for atomic settlement."
    )
}

// Liquidate implementation

/// Liquidate an underwater perp position. Permissionless: anyone can submit.
/// The covenant validates the position is below maintenance margin.
/// The keeper_fee is paid to the liquidator.
#[allow(clippy::too_many_arguments)]
async fn liquidate_perp(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    outpoint_str: &str,
    position_value: u64,
    rs_hex: &str,
    keeper_address: Option<&str>,
    fee: u64,
    fee_utxo_override: Option<&str>,
) -> anyhow::Result<()> {
    let redeem_script = hex::decode(rs_hex)?;
    if redeem_script.is_empty() {
        anyhow::bail!("redeemScript cannot be empty");
    }

    let wallet = WalletFile::load(wallet_path)?;
    let outpoint = Outpoint::parse(outpoint_str)?;
    let pubkey = wallet.public_key_bytes()?;

    let p2sh = build_p2sh(&redeem_script);

    println!("Liquidate Perp Position");
    println!("=======================");
    println!("Outpoint:       {}", outpoint);
    println!("Position Value: {} sompi", position_value);
    println!("RS:             {} bytes", redeem_script.len());
    println!();

    info!(outpoint = %outpoint, "liquidating perp position");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Build the liquidation transaction
    let mut tx = Transaction::new(0);

    // Input 0: position UTXO (P2SH, liquidation path)
    tx.inputs.push(TxInput {
        prev_tx_id: outpoint.transaction_id.clone(),
        prev_index: outpoint.index,
        sequence: 0,
        sig_op_count: 0, // liquidation is permissionless (no CheckSig)
        script_version: p2sh.version,
        script_bytes: p2sh.script().to_vec(),
        value: position_value,
    });

    // Get fee UTXO
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let fee_utxo = if let Some(fee_op_str) = fee_utxo_override {
        let fee_op = Outpoint::parse(fee_op_str)?;
        wallet_utxos
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == fee_op.transaction_id
                    && u.outpoint.index == fee_op.index
            })
            .ok_or_else(|| anyhow::anyhow!("Fee UTXO {} not found.", fee_op_str))?
    } else {
        let mut candidates: Vec<_> = wallet_utxos
            .iter()
            .filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= fee + MIN_UTXO_VALUE)
            .collect();
        candidates.sort_by(|a, b| a.utxo_entry.amount.cmp(&b.utxo_entry.amount));
        candidates.first().copied().ok_or_else(|| {
            anyhow::anyhow!(
                "No P2PK UTXO with >= {} sompi for fee payment",
                fee + MIN_UTXO_VALUE
            )
        })?
    };

    let fee_spk_bytes = fee_utxo.script_bytes();
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_spk_bytes.clone(),
        value: fee_utxo.utxo_entry.amount,
    });

    // Output 0: position value (minus fee) to liquidator
    // Use keeper_address if provided, else wallet P2PK
    let keeper_spk = if let Some(addr) = keeper_address {
        kob_core::bech32::address_to_spk(&addr)
            .map_err(|e| anyhow::anyhow!(e))?
    } else {
        let mut spk = Vec::with_capacity(34);
        spk.push(0x20);
        spk.extend_from_slice(&pubkey);
        spk.push(0xac);
        spk
    };

    let total_in = position_value + fee_utxo.utxo_entry.amount;
    let tent_output = total_in.saturating_sub(estimate_compute_mass(2, 1, 0));
    if tent_output >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(tent_output, 0, keeper_spk, None));
    }

    // Phase 1: converge fee on output 0
    let min_fee_override = if fee > 0 { fee } else { 0 };
    let (est_fee_liq, _) = converge_fee(&mut tx, total_in, 0, min_fee_override);

    // Build liquidation sigscript (selector=3, permissionless)
    let liq_sigscript = perp::build_perp_liquidation_sigscript(&redeem_script);
    println!("Liquidation SigScript: {} bytes", liq_sigscript.len());

    // Sign fee UTXO input (P2PK)
    let privkey = wallet.secure_key()?;
    let sighash_1 = compute_sighash(&tx, 1)?;
    let sig_1 = signing::schnorr_sign_secure(&privkey, &sighash_1)?;
    let fee_sigscript = signing::build_p2pk_sigscript(&sig_1);

    // Phase 2: exact mass check
    let sigscripts_liq = vec![liq_sigscript.clone(), fee_sigscript.clone()];
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts_liq);
    let exact_fee = exact_mass.max(min_fee_override);

    let (liq_sigscript, fee_sigscript, actual_fee) = if exact_fee != est_fee_liq {
        let output_value = total_in.saturating_sub(exact_fee);
        tx.outputs[0].value = output_value;
        let liq_sigscript = perp::build_perp_liquidation_sigscript(&redeem_script);
        let sighash_1 = compute_sighash(&tx, 1)?;
        let sig_1 = signing::schnorr_sign_secure(&privkey, &sighash_1)?;
        let fee_sigscript = signing::build_p2pk_sigscript(&sig_1);
        (liq_sigscript, fee_sigscript, exact_fee)
    } else {
        (liq_sigscript, fee_sigscript, est_fee_liq)
    };

    let output_value = tx.outputs[0].value;
    println!();

    // Fee transparency summary
    {
        let in_vals: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let out_vals: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        let storage_mass = compute_storage_mass(&in_vals, &out_vals);
        let exact_compute = calc_mass_with_sigscripts(&tx, &[liq_sigscript.clone(), fee_sigscript.clone()]);
        println!("Fee Summary");
        println!("-----------");
        println!(
            "Liquidation TX mass: {:>9} / {:>9} ({})",
            storage_mass, MAX_TX_MASS,
            if storage_mass <= MAX_TX_MASS { "OK" } else { "OVER" }
        );
        println!("Compute mass:        {:>9} (exact, post-sign)", exact_compute);
        println!("Miner fee:           {:>9} sompi", actual_fee);
        println!();
    }

    // Submit
    let payload = to_rpc_payload(&tx, &[liq_sigscript, fee_sigscript]);
    println!("Submitting liquidation transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Liquidation submitted.");
    println!("TXID: {}", tx_id);
    println!();
    println!("Recovered {} sompi to liquidator.", output_value);

    Ok(())
}

// Add margin implementation

/// Add margin to an open perp position. Owner-only: signs with wallet key.
/// Builds a self-continuation TX where output[0] is the same P2SH covenant
/// with a higher value (original + added margin).
#[allow(clippy::too_many_arguments)]
async fn add_margin_perp(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    outpoint_str: &str,
    position_value: u64,
    amount: u64,
    rs_hex: &str,
    fee: u64,
    fee_utxo_override: Option<&str>,
) -> anyhow::Result<()> {
    if amount == 0 {
        anyhow::bail!("amount must be > 0");
    }

    let redeem_script = hex::decode(rs_hex)?;
    if redeem_script.is_empty() {
        anyhow::bail!("redeemScript cannot be empty");
    }

    let wallet = WalletFile::load(wallet_path)?;
    let outpoint = Outpoint::parse(outpoint_str)?;
    let pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.secure_key()?;

    let p2sh = build_p2sh(&redeem_script);

    let new_position_value = position_value + amount;

    println!("Add Margin to Perp Position");
    println!("===========================");
    println!("Outpoint:         {}", outpoint);
    println!("Current Value:    {} sompi", position_value);
    println!("Adding:           {} sompi", amount);
    println!("New Value:        {} sompi", new_position_value);
    println!("RS:               {} bytes", redeem_script.len());
    println!();

    info!(outpoint = %outpoint, amount = amount, "adding margin to perp position");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Build the add-margin transaction
    let mut tx = Transaction::new(0);

    // Input 0: position UTXO (P2SH, add-margin path)
    tx.inputs.push(TxInput {
        prev_tx_id: outpoint.transaction_id.clone(),
        prev_index: outpoint.index,
        sequence: 0,
        sig_op_count: 1, // owner CheckSig
        script_version: p2sh.version,
        script_bytes: p2sh.script().to_vec(),
        value: position_value,
    });

    // Get funding UTXOs for additional margin + fee
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;

    // If fee_utxo specified, use it; else select from wallet
    let needed = amount + fee;
    let funding_utxos: Vec<_> = if let Some(fee_op_str) = fee_utxo_override {
        let fee_op = Outpoint::parse(fee_op_str)?;
        let u = wallet_utxos
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == fee_op.transaction_id
                    && u.outpoint.index == fee_op.index
            })
            .ok_or_else(|| anyhow::anyhow!("Fee UTXO {} not found.", fee_op_str))?;
        if u.utxo_entry.amount < needed {
            anyhow::bail!(
                "Fee UTXO {} has {} sompi but need {} (amount + fee)",
                fee_op_str,
                u.utxo_entry.amount,
                needed
            );
        }
        vec![u]
    } else {
        // Mass-aware selection for amount + fee
        let p2pk_rpc: Vec<_> = wallet_utxos.iter().filter(|u| !u.is_p2sh()).collect();
        let core_utxos: Vec<UtxoEntry> = p2pk_rpc
            .iter()
            .map(|u| UtxoEntry {
                outpoint: Outpoint {
                    transaction_id: u.outpoint.transaction_id.clone(),
                    index: u.outpoint.index,
                },
                value: u.utxo_entry.amount,
                script_public_key: format!(
                    "{:04x}{}",
                    u.utxo_entry.script_public_key.version,
                    u.utxo_entry.script_public_key.script
                ),
            })
            .collect();

        // Select UTXOs for amount + fee; 2 outputs (position continuation + change)
        let coin_sel = select_utxos_mass_aware(&core_utxos, needed, 0, 2).map_err(|e| {
            anyhow::anyhow!(
                "UTXO selection failed: {}. {} P2PK UTXOs available.",
                e,
                core_utxos.len()
            )
        })?;

        let selected: Vec<_> = coin_sel
            .utxos
            .iter()
            .map(|sel| {
                *p2pk_rpc
                    .iter()
                    .find(|u| {
                        u.outpoint.transaction_id == sel.outpoint.transaction_id
                            && u.outpoint.index == sel.outpoint.index
                    })
                    .expect("coin_sel UTXOs are a subset of p2pk_rpc")
            })
            .collect();
        selected
    };

    let mut funding_total: u64 = 0;
    for fu in &funding_utxos {
        tx.inputs.push(TxInput {
            prev_tx_id: fu.outpoint.transaction_id.clone(),
            prev_index: fu.outpoint.index,
            sequence: 0,
            sig_op_count: 1,
            script_version: fu.utxo_entry.script_public_key.version,
            script_bytes: fu.script_bytes(),
            value: fu.utxo_entry.amount,
        });
        funding_total += fu.utxo_entry.amount;
    }

    println!(
        "Funding:          {} UTXO(s), {} sompi total",
        funding_utxos.len(),
        funding_total
    );

    // Output 0: self-continuation (same P2SH covenant, higher value)
    tx.outputs.push(TxOutput::new(new_position_value, p2sh.version, p2sh.script().to_vec(), None));

    // Output 1: tentative change back to wallet
    let tent_change_am = funding_total.saturating_sub(amount + fee);
    if tent_change_am >= MIN_UTXO_VALUE {
        let wallet_spk = hex::decode(&funding_utxos[0].utxo_entry.script_public_key.script)?;
        tx.outputs.push(TxOutput::new(tent_change_am, funding_utxos[0].utxo_entry.script_public_key.version, wallet_spk, None));
    }

    // Phase 1: converge fee on change output
    let min_fee_override = if fee > 0 { fee } else { 0 };
    let has_change_am = tx.outputs.len() > 1;
    let change_idx_am = tx.outputs.len().saturating_sub(1);
    let (est_fee_am, _) = if has_change_am {
        converge_fee(&mut tx, funding_total, change_idx_am, min_fee_override)
    } else {
        let f = kob_core::mass::calc_miner_fee(&tx).max(min_fee_override);
        (f, 0)
    };

    if has_change_am && tx.outputs[change_idx_am].value < MIN_UTXO_VALUE {
        let change_val = tx.outputs[change_idx_am].value;
        tx.outputs.pop();
        if change_val > 0 {
            println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", change_val);
        }
    } else if !has_change_am && tent_change_am > 0 {
        println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", tent_change_am);
    }

    // Helper: sign all inputs for add-margin
    let sign_add_margin = |tx: &Transaction| -> anyhow::Result<Vec<Vec<u8>>> {
        let sighash_0 = compute_sighash(tx, 0)?;
        let sig_0 = signing::schnorr_sign_secure(&privkey, &sighash_0)?;
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_0);
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pubkey);
        let add_margin_sigscript = perp::build_perp_add_margin_sigscript(&sig_arr, &pk_arr, &redeem_script);
        let mut all_sigscripts = vec![add_margin_sigscript];
        for i in 1..tx.inputs.len() {
            let sighash_i = compute_sighash(tx, i)?;
            let sig_i = signing::schnorr_sign_secure(&privkey, &sighash_i)?;
            all_sigscripts.push(signing::build_p2pk_sigscript(&sig_i));
        }
        Ok(all_sigscripts)
    };

    let mut all_sigscripts = sign_add_margin(&tx)?;

    // Phase 2: exact mass check
    let exact_mass = calc_mass_with_sigscripts(&tx, &all_sigscripts);
    let exact_fee = exact_mass.max(min_fee_override);

    let actual_fee = if exact_fee != est_fee_am {
        if tx.outputs.len() > 1 {
            let change_idx = tx.outputs.len() - 1;
            let new_change = funding_total.saturating_sub(amount + exact_fee);
            if new_change >= MIN_UTXO_VALUE {
                tx.outputs[change_idx].value = new_change;
            } else {
                tx.outputs.pop();
                if new_change > 0 {
                    println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", new_change);
                }
            }
            all_sigscripts = sign_add_margin(&tx)?;
        }
        exact_fee
    } else {
        est_fee_am
    };

    println!("Add-Margin SigScript: {} bytes", all_sigscripts[0].len());
    println!();

    // Fee transparency summary
    {
        let in_vals: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let out_vals: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        let storage_mass = compute_storage_mass(&in_vals, &out_vals);
        let exact_compute = calc_mass_with_sigscripts(&tx, &all_sigscripts);
        println!("Fee Summary");
        println!("-----------");
        println!(
            "Add-Margin TX mass: {:>9} / {:>9} ({})",
            storage_mass, MAX_TX_MASS,
            if storage_mass <= MAX_TX_MASS { "OK" } else { "OVER" }
        );
        println!("Compute mass:       {:>9} (exact, post-sign)", exact_compute);
        println!("Miner fee:          {:>9} sompi", actual_fee);
        println!();
    }

    // Submit
    let payload = to_rpc_payload(&tx, &all_sigscripts);
    println!("Submitting add-margin transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Add-margin submitted.");
    println!("TXID: {}", tx_id);
    println!();
    println!(
        "Position value: {} -> {} sompi (+{} margin)",
        position_value, new_position_value, amount
    );

    Ok(())
}

// Maturity settle implementation

/// Settle a matured perp position. Permissionless: anyone can submit after
/// maturity_daa has passed. The covenant enforces CLTV and PnL split.
/// TX lockTime must be >= maturity_daa.
#[allow(clippy::too_many_arguments)]
async fn settle_perp(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    outpoint_str: &str,
    position_value: u64,
    rs_hex: &str,
    long_payout: u64,
    short_payout: u64,
    long_pubkey_hex: &str,
    short_pubkey_hex: &str,
    lock_time: u64,
    fee: u64,
    fee_utxo_override: Option<&str>,
) -> anyhow::Result<()> {
    let redeem_script = hex::decode(rs_hex)?;
    if redeem_script.is_empty() {
        anyhow::bail!("redeemScript cannot be empty");
    }

    let long_pk_bytes = hex::decode(long_pubkey_hex)?;
    if long_pk_bytes.len() != 32 {
        anyhow::bail!(
            "long-pubkey must be 32 bytes (64 hex chars), got {}",
            long_pk_bytes.len()
        );
    }
    let short_pk_bytes = hex::decode(short_pubkey_hex)?;
    if short_pk_bytes.len() != 32 {
        anyhow::bail!(
            "short-pubkey must be 32 bytes (64 hex chars), got {}",
            short_pk_bytes.len()
        );
    }

    // Validate payouts
    let total_payout = long_payout + short_payout + fee;
    if total_payout > position_value {
        anyhow::bail!(
            "long_payout ({}) + short_payout ({}) + fee ({}) = {} exceeds position_value ({})",
            long_payout,
            short_payout,
            fee,
            total_payout,
            position_value
        );
    }

    let wallet = WalletFile::load(wallet_path)?;
    let outpoint = Outpoint::parse(outpoint_str)?;
    let privkey = wallet.secure_key()?;

    let p2sh = build_p2sh(&redeem_script);

    println!("Settle Matured Perp Position");
    println!("============================");
    println!("Outpoint:       {}", outpoint);
    println!("Position Value: {} sompi", position_value);
    println!("Long Payout:    {} sompi", long_payout);
    println!("Short Payout:   {} sompi", short_payout);
    println!("LockTime:       {} (DAA score)", lock_time);
    println!("RS:             {} bytes", redeem_script.len());
    println!();

    info!(outpoint = %outpoint, lock_time = lock_time, "settling matured perp position");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Build the settle transaction with lockTime
    let mut tx = Transaction::new(0);
    tx.lock_time = lock_time;

    // Input 0: position UTXO (P2SH, maturity settle path)
    tx.inputs.push(TxInput {
        prev_tx_id: outpoint.transaction_id.clone(),
        prev_index: outpoint.index,
        sequence: 0,
        sig_op_count: 0, // maturity settle is permissionless
        script_version: p2sh.version,
        script_bytes: p2sh.script().to_vec(),
        value: position_value,
    });

    // Fee UTXO
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let fee_utxo = if let Some(fee_op_str) = fee_utxo_override {
        let fee_op = Outpoint::parse(fee_op_str)?;
        Some(
            wallet_utxos
                .iter()
                .find(|u| {
                    u.outpoint.transaction_id == fee_op.transaction_id
                        && u.outpoint.index == fee_op.index
                })
                .ok_or_else(|| anyhow::anyhow!("Fee UTXO {} not found.", fee_op_str))?,
        )
    } else {
        // Position value should cover payouts; fee from position surplus or extra UTXO
        let surplus = position_value.saturating_sub(long_payout + short_payout);
        if surplus < fee {
            // Need an external fee UTXO
            let mut candidates: Vec<_> = wallet_utxos
                .iter()
                .filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= fee + MIN_UTXO_VALUE)
                .collect();
            candidates.sort_by(|a, b| a.utxo_entry.amount.cmp(&b.utxo_entry.amount));
            Some(candidates.first().copied().ok_or_else(|| {
                anyhow::anyhow!(
                    "No P2PK UTXO with >= {} sompi for fee payment",
                    fee + MIN_UTXO_VALUE
                )
            })?)
        } else {
            None // fee comes from position surplus
        }
    };

    if let Some(fu) = fee_utxo {
        tx.inputs.push(TxInput {
            prev_tx_id: fu.outpoint.transaction_id.clone(),
            prev_index: fu.outpoint.index,
            sequence: 0,
            sig_op_count: 1,
            script_version: fu.utxo_entry.script_public_key.version,
            script_bytes: fu.script_bytes(),
            value: fu.utxo_entry.amount,
        });
    }

    // Output 0: long payout
    if long_payout >= MIN_UTXO_VALUE {
        let mut long_spk = Vec::with_capacity(34);
        long_spk.push(0x20);
        long_spk.extend_from_slice(&long_pk_bytes);
        long_spk.push(0xac);
        tx.outputs.push(TxOutput::new(long_payout, 0, long_spk, None));
    }

    // Output 1: short payout
    if short_payout >= MIN_UTXO_VALUE {
        let mut short_spk = Vec::with_capacity(34);
        short_spk.push(0x20);
        short_spk.extend_from_slice(&short_pk_bytes);
        short_spk.push(0xac);
        tx.outputs.push(TxOutput::new(short_payout, 0, short_spk, None));
    }

    // Change from fee UTXO (if present)
    let total_in_settle: u64 = tx.inputs.iter().map(|i| i.value).sum();
    let fixed_sum_settle: u64 = tx.outputs.iter().map(|o| o.value).sum();
    if let Some(fu) = fee_utxo {
        let tent_fee_change = fu.utxo_entry.amount.saturating_sub(fee);
        if tent_fee_change >= MIN_UTXO_VALUE {
            let wallet_spk = hex::decode(&fu.utxo_entry.script_public_key.script)?;
            tx.outputs.push(TxOutput::new(tent_fee_change, fu.utxo_entry.script_public_key.version, wallet_spk, None));
        }
    }

    // Phase 1: converge fee on change output if present
    let min_fee_override = if fee > 0 { fee } else { 0 };
    let has_change_settle = fee_utxo.is_some() && tx.outputs.len() > 2; // payout outputs + change
    let change_idx_settle = tx.outputs.len().saturating_sub(1);
    let (est_fee_settle, _) = if has_change_settle {
        converge_fee(&mut tx, total_in_settle, change_idx_settle, min_fee_override)
    } else {
        let f = kob_core::mass::calc_miner_fee(&tx).max(min_fee_override);
        (f, 0)
    };

    if has_change_settle && tx.outputs[change_idx_settle].value < MIN_UTXO_VALUE {
        tx.outputs.pop();
    }

    // Build maturity settle sigscript (selector=4, permissionless)
    let settle_sigscript = perp::build_perp_maturity_settle_sigscript(&redeem_script);
    println!("Settle SigScript: {} bytes", settle_sigscript.len());

    let mut all_sigscripts = vec![settle_sigscript.clone()];

    // Sign fee UTXO input if present
    if fee_utxo.is_some() {
        let sighash_1 = compute_sighash(&tx, 1)?;
        let sig_1 = signing::schnorr_sign_secure(&privkey, &sighash_1)?;
        all_sigscripts.push(signing::build_p2pk_sigscript(&sig_1));
    }

    // Phase 2: exact mass check
    let exact_mass = calc_mass_with_sigscripts(&tx, &all_sigscripts);
    let exact_fee = exact_mass.max(min_fee_override);

    let actual_fee = if exact_fee != est_fee_settle {
        if has_change_settle && tx.outputs.len() > 2 {
            let change_idx = tx.outputs.len() - 1;
            let new_change = total_in_settle.saturating_sub(fixed_sum_settle + exact_fee);
            if new_change >= MIN_UTXO_VALUE {
                tx.outputs[change_idx].value = new_change;
            } else {
                tx.outputs.pop();
            }
            // Re-sign fee UTXO
            all_sigscripts = vec![settle_sigscript];
            if fee_utxo.is_some() {
                let sighash_1 = compute_sighash(&tx, 1)?;
                let sig_1 = signing::schnorr_sign_secure(&privkey, &sighash_1)?;
                all_sigscripts.push(signing::build_p2pk_sigscript(&sig_1));
            }
        }
        exact_fee
    } else {
        est_fee_settle
    };

    println!();

    // Fee transparency summary
    {
        let in_vals: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let out_vals: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        let storage_mass = compute_storage_mass(&in_vals, &out_vals);
        let exact_compute = calc_mass_with_sigscripts(&tx, &all_sigscripts);
        println!("Fee Summary");
        println!("-----------");
        println!(
            "Settle TX mass:   {:>9} / {:>9} ({})",
            storage_mass, MAX_TX_MASS,
            if storage_mass <= MAX_TX_MASS { "OK" } else { "OVER" }
        );
        println!("Compute mass:     {:>9} (exact, post-sign)", exact_compute);
        println!("Miner fee:        {:>9} sompi", actual_fee);
        println!();
    }

    // Submit
    let payload = to_rpc_payload(&tx, &all_sigscripts);
    println!("Submitting settle transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Maturity settle submitted.");
    println!("TXID: {}", tx_id);
    println!();
    println!("Long payout:  {} sompi", long_payout);
    println!("Short payout: {} sompi", short_payout);

    Ok(())
}

// Public dispatch

/// Run a perp subcommand.
pub async fn run(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    fee: u64,
    action: &PerpCommand,
) -> anyhow::Result<()> {
    match action {
        PerpCommand::DeployLong {
            token,
            margin,
            price_num,
            price_den,
            min_fill,
            maint_pct_num,
            maint_pct_den,
            keeper_fee,
            emergency_daa,
            max_matcher_fee,
        } => {
            deploy_perp(
                wallet_path,
                node_url,
                network,
                "long",
                token,
                *margin,
                *price_num,
                *price_den,
                *min_fill,
                *maint_pct_num,
                *maint_pct_den,
                *keeper_fee,
                *emergency_daa,
                *max_matcher_fee,
                fee,
            )
            .await?;
        }
        PerpCommand::DeployShort {
            token,
            margin,
            price_num,
            price_den,
            min_fill,
            maint_pct_num,
            maint_pct_den,
            keeper_fee,
            emergency_daa,
            max_matcher_fee,
        } => {
            deploy_perp(
                wallet_path,
                node_url,
                network,
                "short",
                token,
                *margin,
                *price_num,
                *price_den,
                *min_fill,
                *maint_pct_num,
                *maint_pct_den,
                *keeper_fee,
                *emergency_daa,
                *max_matcher_fee,
                fee,
            )
            .await?;
        }
        PerpCommand::Cancel {
            outpoint,
            price_num,
            price_den,
            min_fill,
            maint_pct_num,
            maint_pct_den,
            keeper_fee,
            emergency_daa,
            max_matcher_fee,
            order_value,
            fee_utxo,
        } => {
            cancel_perp(
                wallet_path,
                node_url,
                network,
                outpoint,
                *price_num,
                *price_den,
                *min_fill,
                *maint_pct_num,
                *maint_pct_den,
                *keeper_fee,
                *emergency_daa,
                *max_matcher_fee,
                *order_value,
                fee,
                fee_utxo.as_deref(),
            )
            .await?;
        }
        PerpCommand::Positions { engine_url, json } => {
            list_positions(
                wallet_path,
                node_url,
                network,
                engine_url.as_deref(),
                *json,
            )
            .await?;
        }
        PerpCommand::Close {
            outpoint,
            position_value,
            counterparty_sig,
            counterparty_pubkey,
            my_payout,
            their_payout,
            rs,
            is_long,
            fee_utxo,
        } => {
            close_perp(
                wallet_path,
                node_url,
                network,
                outpoint,
                *position_value,
                counterparty_sig,
                counterparty_pubkey,
                *my_payout,
                *their_payout,
                rs,
                *is_long,
                fee,
                fee_utxo.as_deref(),
            )
            .await?;
        }
        PerpCommand::Liquidate {
            outpoint,
            position_value,
            rs,
            keeper_address,
            fee_utxo,
        } => {
            liquidate_perp(
                wallet_path,
                node_url,
                network,
                outpoint,
                *position_value,
                rs,
                keeper_address.as_deref(),
                fee,
                fee_utxo.as_deref(),
            )
            .await?;
        }
        PerpCommand::AddMargin {
            outpoint,
            position_value,
            amount,
            rs,
            fee_utxo,
        } => {
            add_margin_perp(
                wallet_path,
                node_url,
                network,
                outpoint,
                *position_value,
                *amount,
                rs,
                fee,
                fee_utxo.as_deref(),
            )
            .await?;
        }
        PerpCommand::Settle {
            outpoint,
            position_value,
            rs,
            long_payout,
            short_payout,
            long_pubkey,
            short_pubkey,
            lock_time,
            fee_utxo,
        } => {
            settle_perp(
                wallet_path,
                node_url,
                network,
                outpoint,
                *position_value,
                rs,
                *long_payout,
                *short_payout,
                long_pubkey,
                short_pubkey,
                *lock_time,
                fee,
                fee_utxo.as_deref(),
            )
            .await?;
        }
    }

    Ok(())
}

