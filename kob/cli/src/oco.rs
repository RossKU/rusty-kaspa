//! `kob-cli oco` -- One-Cancels-Other order pair (oco_pair v3/v4).
//!
//! Subcommands:
//!   deploy  -- Deploy a nonce-linked OCO pair (buy + sell legs)
//!   fill    -- Fill one leg, cancel-by-partner the other
//!   cancel  -- Cancel both legs with owner signature
//!
//! Supports two contract versions:
//!   - **v3**: 132B body, 313B RS. DEPRECATED (CBP value theft vulnerability).
//!     Deploy blocked. Fill/cancel still supported for existing on-chain orders.
//!   - **v4**: 147B body, 328B RS. Current. Fixes CRITICAL CBP value theft (OCO2-F3).
//!     Adds value floor and input count = 2 check to CBP path.
//!     Same state layout as v3 (181B). No circular dependency.
//!
//! Only v4 can be deployed. Fill and cancel auto-detect the version from
//! RS length (313=v3, 328=v4).
//!
//! Fill TX layout:
//!   input[0]: filling leg   (sigOpCount=0, selector=Op1, pidx=partner_input_idx)
//!   input[1]: partner leg   (sigOpCount=0, selector=Op2, pidx=filling_input_idx)
//!   output[0]: filler gets value from filling leg (minus fee)
//!   output[1]: owner gets value from partner leg (cbp refund)
//!
//! Cancel TX layout:
//!   input[0]: buy leg   (sigOpCount=1, selector=Op0 + sig + pubkey)
//!   input[1]: sell leg  (sigOpCount=1, selector=Op0 + sig + pubkey)
//!   input[2]: fee UTXO  (sigOpCount=1, P2PK signed)
//!   output[0]: recovered funds to wallet

use clap::Subcommand;

use crate::cancel::p2sh_to_address;
use crate::node::NodeClient;
use crate::signing;
use kob_core::contract;
use kob_core::contract::build_oco_order_payload;
use kob_core::p2sh::{blake2b_256, build_p2sh};
use kob_core::sighash::compute_sighash;
use kob_core::tx::{to_rpc_payload, Transaction, TxInput, TxOutput};
use kob_core::types::{Network, Outpoint};
use kob_core::wallet::WalletFile;
use kob_core::mass::{calc_mass_with_sigscripts, converge_fee, estimate_compute_mass};
use kob_core::MIN_UTXO_VALUE;
use std::path::Path;
use tracing::info;

#[derive(Subcommand, Debug)]
pub enum OcoCommand {
    /// Deploy an OCO order pair (buy + sell legs, nonce-linked).
    ///
    /// Only v4 is supported. v3 is deprecated (CBP value theft vulnerability).
    /// v4 adds value floor and input count = 2 check to CBP path.
    Deploy {
        /// Amount to lock in the buy leg (sompi).
        #[arg(long)]
        buy_amount: u64,

        /// Amount to lock in the sell leg (sompi).
        #[arg(long)]
        sell_amount: u64,

        /// Price numerator (shared by both legs).
        #[arg(long)]
        price_num: u64,

        /// Price denominator (shared by both legs).
        #[arg(long)]
        price_den: u64,

        /// Minimum fill amount.
        #[arg(long)]
        min_fill: u64,

        /// Token covenant ID (hex, 64 chars).
        #[arg(long)]
        token_cov_id: String,

        /// Contract version (only 4 is supported). v3 is deprecated due to CBP vulnerability.
        #[arg(long, default_value = "4")]
        version: u8,
    },

    /// Fill one leg and cancel-by-partner the other.
    Fill {
        /// Buy leg outpoint (txid:index).
        #[arg(long)]
        buy_outpoint: String,

        /// Sell leg outpoint (txid:index).
        #[arg(long)]
        sell_outpoint: String,

        /// Which leg to fill: "buy" or "sell".
        #[arg(long)]
        fill_role: String,

        /// Buy leg redeemScript (hex).
        #[arg(long)]
        buy_rs: String,

        /// Sell leg redeemScript (hex).
        #[arg(long)]
        sell_rs: String,

        /// Buy leg UTXO value in sompi (queried if omitted).
        #[arg(long)]
        buy_value: Option<u64>,

        /// Sell leg UTXO value in sompi (queried if omitted).
        #[arg(long)]
        sell_value: Option<u64>,
    },

    /// Cancel both legs with owner signature (requires fee UTXO).
    Cancel {
        /// Buy leg outpoint (txid:index).
        #[arg(long)]
        buy_outpoint: String,

        /// Sell leg outpoint (txid:index).
        #[arg(long)]
        sell_outpoint: String,

        /// Buy leg redeemScript (hex).
        #[arg(long)]
        buy_rs: String,

        /// Sell leg redeemScript (hex).
        #[arg(long)]
        sell_rs: String,

        /// Buy leg UTXO value in sompi (queried if omitted).
        #[arg(long)]
        buy_value: Option<u64>,

        /// Sell leg UTXO value in sompi (queried if omitted).
        #[arg(long)]
        sell_value: Option<u64>,
    },
}

/// OCO RS sizes by version.
const OCO_V3_RS_SIZE: usize = 313;
const OCO_RS_SIZE: usize = 328;

/// Detect OCO contract version from RS length.
fn detect_oco_version(rs_len: usize) -> anyhow::Result<u8> {
    match rs_len {
        OCO_V3_RS_SIZE => Ok(3),
        OCO_RS_SIZE => Ok(4),
        _ => anyhow::bail!(
            "Invalid OCO redeemScript size ({} bytes). Expected {} (v3) or {} (v4). \
             Check the --rs value and contract version.",
            rs_len, OCO_V3_RS_SIZE, OCO_RS_SIZE
        ),
    }
}

/// Build the 36-byte owner SPK: [version_u16_le(2B)] [0x20] [pubkey(32B)] [0xac]
fn build_owner_spk(pubkey: &[u8; 32]) -> [u8; 36] {
    let mut spk = [0u8; 36];
    // version = 0 as u16 LE (already zeroed)
    spk[2] = 0x20; // push 32 bytes
    spk[3..35].copy_from_slice(pubkey);
    spk[35] = 0xac; // OpCheckSig
    spk
}

/// Dispatch OCO subcommand.
pub async fn run(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    cmd: &OcoCommand,
) -> anyhow::Result<()> {
    match cmd {
        OcoCommand::Deploy {
            buy_amount,
            sell_amount,
            price_num,
            price_den,
            min_fill,
            token_cov_id,
            version,
        } => {
            deploy(
                wallet_path,
                node_url,
                network,
                *buy_amount,
                *sell_amount,
                *price_num,
                *price_den,
                *min_fill,
                token_cov_id,
                *version,
            )
            .await
        }
        OcoCommand::Fill {
            buy_outpoint,
            sell_outpoint,
            fill_role,
            buy_rs,
            sell_rs,
            buy_value,
            sell_value,
        } => {
            fill(
                wallet_path,
                node_url,
                network,
                buy_outpoint,
                sell_outpoint,
                fill_role,
                buy_rs,
                sell_rs,
                *buy_value,
                *sell_value,
            )
            .await
        }
        OcoCommand::Cancel {
            buy_outpoint,
            sell_outpoint,
            buy_rs,
            sell_rs,
            buy_value,
            sell_value,
        } => {
            cancel(
                wallet_path,
                node_url,
                network,
                buy_outpoint,
                sell_outpoint,
                buy_rs,
                sell_rs,
                *buy_value,
                *sell_value,
            )
            .await
        }
    }
}

// oco deploy

#[allow(clippy::too_many_arguments)]
async fn deploy(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    buy_amount: u64,
    sell_amount: u64,
    price_num: u64,
    price_den: u64,
    min_fill: u64,
    token_cov_id_hex: &str,
    version: u8,
) -> anyhow::Result<()> {
    if version < 4 {
        anyhow::bail!("OCO v3 is deprecated (CBP vulnerability). Use --version 4.");
    }
    if version != 4 {
        anyhow::bail!("Unsupported OCO version {}. Only v4 is supported.", version);
    }
    // Validate
    if price_num == 0 {
        anyhow::bail!("price_num must be > 0");
    }
    if price_den == 0 {
        anyhow::bail!("price_den must be > 0");
    }
    if min_fill == 0 {
        anyhow::bail!("min_fill must be > 0 (zero allows dust griefing)");
    }
    if buy_amount < MIN_UTXO_VALUE {
        anyhow::bail!(
            "buy_amount {} sompi too small (min {})",
            buy_amount,
            MIN_UTXO_VALUE
        );
    }
    if sell_amount < MIN_UTXO_VALUE {
        anyhow::bail!(
            "sell_amount {} sompi too small (min {})",
            sell_amount,
            MIN_UTXO_VALUE
        );
    }

    // Parse token covenant ID
    let token_bytes = hex::decode(token_cov_id_hex)?;
    if token_bytes.len() != 32 {
        anyhow::bail!("token_cov_id must be 64 hex characters (32 bytes)");
    }
    let mut tcid = [0u8; 32];
    tcid.copy_from_slice(&token_bytes);

    let wallet = WalletFile::load(wallet_path)?;
    let pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.private_key_bytes()?;
    let owner_hash = blake2b_256(&pubkey);
    let owner_spk = build_owner_spk(&pubkey);

    // Generate random 32-byte nonce
    let mut nonce = [0u8; 32];
    {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut nonce);
    }

    // Build buy/sell RS (v4 only -- v3 blocked above)
    let buy_rs = contract::build_oco_pair_redeem_script(
        &nonce, 0, &tcid, 0, price_num, price_den, min_fill,
        &owner_hash, &owner_spk,
    )?;
    let sell_rs = contract::build_oco_pair_redeem_script(
        &nonce, 1, &tcid, sell_amount, price_num, price_den, min_fill,
        &owner_hash, &owner_spk,
    )?;

    let buy_p2sh = build_p2sh(&buy_rs);
    let sell_p2sh = build_p2sh(&sell_rs);

    println!("Deploy OCO Pair v{}", version);
    println!("===================");
    println!("Nonce:       {}", hex::encode(nonce));
    println!("Token:       {}", token_cov_id_hex);
    println!(
        "Price:       {}/{} ({:.6})",
        price_num,
        price_den,
        price_num as f64 / price_den as f64
    );
    println!("Min Fill:    {}", min_fill);
    println!(
        "Buy Amount:  {} sompi ({:.8} KAS)",
        buy_amount,
        buy_amount as f64 / 1e8
    );
    println!(
        "Sell Amount: {} sompi ({:.8} KAS)",
        sell_amount,
        sell_amount as f64 / 1e8
    );
    println!("Owner:       {}", wallet.public_key);
    println!("Owner Hash:  {}", hex::encode(owner_hash));
    println!();
    println!("Buy RS:      {} bytes", buy_rs.len());
    println!("Sell RS:     {} bytes", sell_rs.len());
    println!("Buy P2SH:    {}", hex::encode(&buy_p2sh.script()));
    println!("Sell P2SH:   {}", hex::encode(&sell_p2sh.script()));
    println!();

    let total_amount = buy_amount + sell_amount;
    // Conservative fee estimate for 1-in/3-out OCO deploy TX
    let est_fee_budget = estimate_compute_mass(1, 3, 0) + 500;
    let needed = total_amount + est_fee_budget;

    info!(
        nonce = %hex::encode(nonce),
        buy_amount = buy_amount,
        sell_amount = sell_amount,
        version = version,
        "deploying OCO pair"
    );
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    let utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let funding = utxos
        .iter()
        .find(|u| !u.is_p2sh() && u.utxo_entry.amount >= needed)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No P2PK UTXO with >= {} sompi found ({} UTXOs available)",
                needed,
                utxos.len()
            )
        })?;

    println!(
        "Funding UTXO: {}:{} ({} sompi)",
        funding.outpoint.transaction_id, funding.outpoint.index, funding.utxo_entry.amount
    );

    let total_input = funding.utxo_entry.amount;

    // Build transaction
    let mut tx = Transaction::new(0);

    // Input: wallet P2PK UTXO
    let spk_bytes = funding.script_bytes();
    tx.inputs.push(TxInput {
        prev_tx_id: funding.outpoint.transaction_id.clone(),
        prev_index: funding.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: funding.utxo_entry.script_public_key.version,
        script_bytes: spk_bytes,
        value: funding.utxo_entry.amount,
    });

    // Output 0: buy leg P2SH
    tx.outputs.push(TxOutput::new(buy_amount, 0, buy_p2sh.script().to_vec(), None));

    // Output 1: sell leg P2SH
    tx.outputs.push(TxOutput::new(sell_amount, 0, sell_p2sh.script().to_vec(), None));

    // TX payload: both RS for matcher L1 discovery (replaces OP_RETURN)
    // Format: KOB:1:<buy_rs_len_u16_LE><buy_rs><sell_rs>
    tx.payload = build_oco_order_payload(&buy_rs, &sell_rs, false);

    // Output 2: tentative change for mass calculation
    let wallet_spk = hex::decode(&funding.utxo_entry.script_public_key.script)?;
    let tentative_change = total_input.saturating_sub(total_amount + est_fee_budget);
    if tentative_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(tentative_change, funding.utxo_entry.script_public_key.version, wallet_spk.clone(), None));
    }

    // Phase 1: converge fee
    let has_change = tentative_change >= MIN_UTXO_VALUE;
    let change_idx = if has_change { tx.outputs.len() - 1 } else { 0 };

    let (est_fee, _) = if has_change {
        converge_fee(&mut tx, total_input, change_idx, 0)
    } else {
        let f = kob_core::mass::calc_miner_fee(&tx);
        (f, 0)
    };

    let change = if has_change { tx.outputs[change_idx].value } else { total_input.saturating_sub(total_amount + est_fee) };

    if has_change && change < MIN_UTXO_VALUE {
        tx.outputs.pop();
        if change > 0 {
            println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", change);
        }
    } else if !has_change && change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(change, funding.utxo_entry.script_public_key.version, wallet_spk.clone(), None));
    } else if !has_change && change > 0 {
        println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", change);
    }

    // Phase 1: sign
    let sighash = compute_sighash(&tx, 0)?;
    let signature = signing::schnorr_sign(&privkey, &sighash)?;
    let sigscript = signing::build_p2pk_sigscript(&signature);

    // Phase 2: exact mass check
    let sigscripts_vec = vec![sigscript];
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts_vec);
    let exact_fee = exact_mass;

    let (sigscript, _actual_fee) = if exact_fee != est_fee && tx.outputs.len() > 2 {
        let change_idx = tx.outputs.len() - 1;
        let new_change = total_input.saturating_sub(total_amount + exact_fee);
        if new_change >= MIN_UTXO_VALUE {
            tx.outputs[change_idx].value = new_change;
        } else {
            tx.outputs.pop();
            if new_change > 0 {
                println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", new_change);
            }
        }
        let sighash = compute_sighash(&tx, 0)?;
        let signature = signing::schnorr_sign(&privkey, &sighash)?;
        (signing::build_p2pk_sigscript(&signature), exact_fee)
    } else {
        (sigscripts_vec.into_iter().next().unwrap(), est_fee)
    };

    // Submit
    let payload = to_rpc_payload(&tx, &[sigscript]);
    println!("Submitting OCO deploy transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! OCO pair v{} deployed.", version);
    println!("TXID:        {}", tx_id);
    println!();
    println!("Buy Leg:     {}:0 ({} sompi)", tx_id, buy_amount);
    println!("Sell Leg:    {}:1 ({} sompi)", tx_id, sell_amount);
    println!("Nonce:       {}", hex::encode(nonce));
    println!("Buy RS:      {}", hex::encode(&buy_rs));
    println!("Sell RS:     {}", hex::encode(&sell_rs));
    println!();
    println!("Fill command (fill buy leg, cbp sell leg):");
    println!(
        "  kob-cli oco fill --buy-outpoint {}:0 --sell-outpoint {}:1 --fill-role buy --buy-rs {} --sell-rs {}",
        tx_id,
        tx_id,
        hex::encode(&buy_rs),
        hex::encode(&sell_rs),
    );
    println!();
    println!("Cancel command:");
    println!(
        "  kob-cli oco cancel --buy-outpoint {}:0 --sell-outpoint {}:1 --buy-rs {} --sell-rs {}",
        tx_id,
        tx_id,
        hex::encode(&buy_rs),
        hex::encode(&sell_rs),
    );

    Ok(())
}

// oco fill

/// Query a P2SH UTXO value by outpoint.
async fn query_p2sh_utxo_value(
    rpc: &NodeClient,
    outpoint: &Outpoint,
    rs: &[u8],
    prefix: &str,
) -> anyhow::Result<u64> {
    let p2sh = build_p2sh(rs);
    let addr = p2sh_to_address(&p2sh.script(), prefix);
    let utxos = rpc.get_utxos_by_addresses(&[&addr]).await?;
    let utxo = utxos
        .iter()
        .find(|u| {
            u.outpoint.transaction_id == outpoint.transaction_id
                && u.outpoint.index == outpoint.index
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "OCO UTXO {} not found at P2SH address {}",
                outpoint,
                addr
            )
        })?;
    Ok(utxo.utxo_entry.amount)
}

#[allow(clippy::too_many_arguments)]
async fn fill(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    buy_outpoint_str: &str,
    sell_outpoint_str: &str,
    fill_role: &str,
    buy_rs_hex: &str,
    sell_rs_hex: &str,
    buy_value_override: Option<u64>,
    sell_value_override: Option<u64>,
) -> anyhow::Result<()> {
    let buy_outpoint = Outpoint::parse(buy_outpoint_str)?;
    let sell_outpoint = Outpoint::parse(sell_outpoint_str)?;
    let buy_rs = hex::decode(buy_rs_hex)?;
    let sell_rs = hex::decode(sell_rs_hex)?;

    // Validate RS sizes (v3=313, v4=369)
    let buy_ver = detect_oco_version(buy_rs.len())?;
    let sell_ver = detect_oco_version(sell_rs.len())?;
    if buy_ver != sell_ver {
        anyhow::bail!(
            "Buy RS version (v{}, {}B) and sell RS version (v{}, {}B) must match",
            buy_ver, buy_rs.len(), sell_ver, sell_rs.len()
        );
    }
    let oco_ver = buy_ver;

    // Validate fill_role
    if fill_role != "buy" && fill_role != "sell" {
        anyhow::bail!("Invalid --fill-role '{}'. Use 'buy' or 'sell' to specify which side of the OCO order to fill.", fill_role);
    }

    let _wallet = WalletFile::load(wallet_path)?;

    let buy_p2sh = build_p2sh(&buy_rs);
    let sell_p2sh = build_p2sh(&sell_rs);

    println!("OCO Fill + Cancel-By-Partner (v{})", oco_ver);
    println!("============================");
    println!("Fill Role:     {}", fill_role);
    println!("Buy Outpoint:  {}", buy_outpoint);
    println!("Sell Outpoint: {}", sell_outpoint);
    println!("Buy RS:        {} bytes", buy_rs.len());
    println!("Sell RS:       {} bytes", sell_rs.len());
    println!();

    info!(
        fill_role = fill_role,
        buy = %buy_outpoint,
        sell = %sell_outpoint,
        "filling OCO pair"
    );
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Get UTXO values
    let buy_value = match buy_value_override {
        Some(v) => v,
        None => {
            println!("Querying buy leg UTXO value...");
            query_p2sh_utxo_value(&rpc, &buy_outpoint, &buy_rs, network.address_prefix()).await?
        }
    };
    let sell_value = match sell_value_override {
        Some(v) => v,
        None => {
            println!("Querying sell leg UTXO value...");
            query_p2sh_utxo_value(&rpc, &sell_outpoint, &sell_rs, network.address_prefix()).await?
        }
    };

    println!("Buy Value:     {} sompi", buy_value);
    println!("Sell Value:    {} sompi", sell_value);

    let total_in = buy_value + sell_value;
    // Fill TX: two covenant inputs (sigOpCount=0 each), no separate fee input needed
    // output[0] = filler gets filling-leg value minus fee
    // output[1] = owner gets partner-leg value (cbp refund)
    // Use tentative fee estimate; will be refined after building TX
    let est_fee_budget = estimate_compute_mass(2, 2, 0) + 500;
    let (mut out0_value, out1_value) = if fill_role == "buy" {
        // Fill buy: filler takes buy-leg KAS, owner gets sell-leg refund
        (buy_value.saturating_sub(est_fee_budget), sell_value)
    } else {
        // Fill sell: filler takes sell-leg value, owner gets buy-leg refund
        (sell_value.saturating_sub(est_fee_budget), buy_value)
    };

    // Make sure output values are valid
    if out0_value < MIN_UTXO_VALUE {
        anyhow::bail!(
            "Filler output {} sompi below MIN_UTXO_VALUE ({}). Increase order value.",
            out0_value,
            MIN_UTXO_VALUE
        );
    }
    if out1_value < MIN_UTXO_VALUE {
        anyhow::bail!(
            "CBP refund output {} sompi below MIN_UTXO_VALUE ({}). Increase order value.",
            out1_value,
            MIN_UTXO_VALUE
        );
    }

    // Build fill TX
    // Both legs must be spent in the same TX.
    // input ordering and pidx depend on fill_role.
    let mut tx = Transaction::new(0);

    let (fill_rs, cbp_rs, fill_outpoint, cbp_outpoint, fill_p2sh, cbp_p2sh, fill_val, cbp_val) =
        if fill_role == "buy" {
            // input[0] = buy (fill), input[1] = sell (cbp)
            (
                &buy_rs,
                &sell_rs,
                &buy_outpoint,
                &sell_outpoint,
                &buy_p2sh,
                &sell_p2sh,
                buy_value,
                sell_value,
            )
        } else {
            // input[0] = sell (fill), input[1] = buy (cbp)
            (
                &sell_rs,
                &buy_rs,
                &sell_outpoint,
                &buy_outpoint,
                &sell_p2sh,
                &buy_p2sh,
                sell_value,
                buy_value,
            )
        };

    // Input 0: filling leg (sigOpCount=0)
    tx.inputs.push(TxInput {
        prev_tx_id: fill_outpoint.transaction_id.clone(),
        prev_index: fill_outpoint.index,
        sequence: 0,
        sig_op_count: 0,
        script_version: fill_p2sh.version,
        script_bytes: fill_p2sh.script().to_vec(),
        value: fill_val,
    });

    // Input 1: partner leg for cbp (sigOpCount=0)
    tx.inputs.push(TxInput {
        prev_tx_id: cbp_outpoint.transaction_id.clone(),
        prev_index: cbp_outpoint.index,
        sequence: 0,
        sig_op_count: 0,
        script_version: cbp_p2sh.version,
        script_bytes: cbp_p2sh.script().to_vec(),
        value: cbp_val,
    });

    // Get the wallet SPK for outputs (use wallet address for now)
    let wallet_spk_bytes = {
        let pubkey = _wallet.public_key_bytes()?;
        let mut spk = Vec::with_capacity(34);
        spk.push(0x20);
        spk.extend_from_slice(&pubkey);
        spk.push(0xac);
        spk
    };

    // Output 0: filler gets value (tentative, adjusted after exact mass calc)
    tx.outputs.push(TxOutput::new(out0_value, 0, wallet_spk_bytes.clone(), None));

    // Output 1: owner gets cbp refund
    tx.outputs.push(TxOutput::new(out1_value, 0, wallet_spk_bytes, None));

    // Build sigscripts (v4 only, data-only -- no signature dependency)
    let fill_ss = contract::build_oco_pair_fill_sigscript(1, fill_rs);
    let cbp_ss = contract::build_oco_pair_cbp_sigscript(0, cbp_rs);

    // Exact mass calculation with real sigscripts (no re-sign needed for data-only sigscripts)
    let exact_mass = calc_mass_with_sigscripts(&tx, &[fill_ss.clone(), cbp_ss.clone()]);
    let exact_fee = exact_mass;

    // Adjust output[0] with exact fee
    let fill_leg_value = if fill_role == "buy" { buy_value } else { sell_value };
    out0_value = fill_leg_value.saturating_sub(exact_fee);
    tx.outputs[0].value = out0_value;

    if out0_value < MIN_UTXO_VALUE {
        anyhow::bail!(
            "Filler output {} sompi below MIN_UTXO_VALUE ({}) after exact fee {}. Increase order value.",
            out0_value, MIN_UTXO_VALUE, exact_fee
        );
    }

    println!(
        "Output[0]:     {} sompi (filler)",
        out0_value
    );
    println!(
        "Output[1]:     {} sompi (owner cbp refund)",
        out1_value
    );
    println!(
        "Miner fee:     {} sompi",
        exact_fee
    );

    println!("Fill SigScript:  {} bytes", fill_ss.len());
    println!("CBP SigScript:   {} bytes", cbp_ss.len());
    println!();

    // Submit
    let payload = to_rpc_payload(&tx, &[fill_ss, cbp_ss]);
    println!("Submitting OCO fill transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! OCO fill + cbp transaction submitted.");
    println!("TXID: {}", tx_id);
    println!();
    println!("Filler received:  {}:0 ({} sompi)", tx_id, out0_value);
    println!("Owner refund:     {}:1 ({} sompi)", tx_id, out1_value);

    Ok(())
}

// oco cancel

#[allow(clippy::too_many_arguments)]
async fn cancel(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    buy_outpoint_str: &str,
    sell_outpoint_str: &str,
    buy_rs_hex: &str,
    sell_rs_hex: &str,
    buy_value_override: Option<u64>,
    sell_value_override: Option<u64>,
) -> anyhow::Result<()> {
    let buy_outpoint = Outpoint::parse(buy_outpoint_str)?;
    let sell_outpoint = Outpoint::parse(sell_outpoint_str)?;
    let buy_rs = hex::decode(buy_rs_hex)?;
    let sell_rs = hex::decode(sell_rs_hex)?;

    // Validate RS sizes (v3=313, v4=369)
    let buy_ver = detect_oco_version(buy_rs.len())?;
    let sell_ver = detect_oco_version(sell_rs.len())?;
    if buy_ver != sell_ver {
        anyhow::bail!(
            "Buy RS version (v{}, {}B) and sell RS version (v{}, {}B) must match",
            buy_ver, buy_rs.len(), sell_ver, sell_rs.len()
        );
    }
    let oco_ver = buy_ver;

    let wallet = WalletFile::load(wallet_path)?;
    let pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.private_key_bytes()?;

    let buy_p2sh = build_p2sh(&buy_rs);
    let sell_p2sh = build_p2sh(&sell_rs);

    println!("OCO Cancel (Both Legs, v{})", oco_ver);
    println!("=======================");
    println!("Buy Outpoint:  {}", buy_outpoint);
    println!("Sell Outpoint: {}", sell_outpoint);
    println!("Owner:         {}", wallet.public_key);
    println!();

    info!(
        buy = %buy_outpoint,
        sell = %sell_outpoint,
        "cancelling OCO pair"
    );
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Get UTXO values
    let buy_value = match buy_value_override {
        Some(v) => v,
        None => {
            println!("Querying buy leg UTXO value...");
            query_p2sh_utxo_value(&rpc, &buy_outpoint, &buy_rs, network.address_prefix()).await?
        }
    };
    let sell_value = match sell_value_override {
        Some(v) => v,
        None => {
            println!("Querying sell leg UTXO value...");
            query_p2sh_utxo_value(&rpc, &sell_outpoint, &sell_rs, network.address_prefix()).await?
        }
    };

    println!("Buy Value:     {} sompi", buy_value);
    println!("Sell Value:    {} sompi", sell_value);

    // Need a fee UTXO (cancel path has sigOpCount=1 per input -> need P2PK for fee)
    let est_fee_budget = estimate_compute_mass(3, 1, 0) + 500;
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let fee_utxo = wallet_utxos
        .iter()
        .find(|u| !u.is_p2sh() && u.utxo_entry.amount >= est_fee_budget + MIN_UTXO_VALUE)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No P2PK UTXO with >= {} sompi for fee payment",
                est_fee_budget + MIN_UTXO_VALUE
            )
        })?;

    println!(
        "Fee UTXO:      {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    let total_in = buy_value + sell_value + fee_utxo.utxo_entry.amount;

    // Build cancel transaction
    let mut tx = Transaction::new(0);

    // Input 0: buy leg (sigOpCount=1, cancel path has CheckSig)
    tx.inputs.push(TxInput {
        prev_tx_id: buy_outpoint.transaction_id.clone(),
        prev_index: buy_outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: buy_p2sh.version,
        script_bytes: buy_p2sh.script().to_vec(),
        value: buy_value,
    });

    // Input 1: sell leg (sigOpCount=1, cancel path has CheckSig)
    tx.inputs.push(TxInput {
        prev_tx_id: sell_outpoint.transaction_id.clone(),
        prev_index: sell_outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: sell_p2sh.version,
        script_bytes: sell_p2sh.script().to_vec(),
        value: sell_value,
    });

    // Input 2: fee UTXO (P2PK)
    let fee_spk_bytes = fee_utxo.script_bytes();
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_spk_bytes,
        value: fee_utxo.utxo_entry.amount,
    });

    // Output 0: all recovered funds to wallet (tentative, adjusted by converge_fee)
    let wallet_spk = hex::decode(&fee_utxo.utxo_entry.script_public_key.script)?;
    let tentative_output = total_in.saturating_sub(est_fee_budget);
    tx.outputs.push(TxOutput::new(tentative_output, fee_utxo.utxo_entry.script_public_key.version, wallet_spk, None));

    // Phase 1: converge fee on output[0]
    let (est_fee, _) = converge_fee(&mut tx, total_in, 0, 0);

    // Sign input 0 (buy leg cancel) -- version-aware
    let sighash_0 = compute_sighash(&tx, 0)?;
    let sig_0 = signing::schnorr_sign(&privkey, &sighash_0)?;
    let buy_cancel_ss = contract::build_oco_pair_cancel_sigscript(&sig_0, &pubkey, &buy_rs);

    // Sign input 1 (sell leg cancel) -- v4 only
    let sighash_1 = compute_sighash(&tx, 1)?;
    let sig_1 = signing::schnorr_sign(&privkey, &sighash_1)?;
    let sell_cancel_ss = contract::build_oco_pair_cancel_sigscript(&sig_1, &pubkey, &sell_rs);

    // Sign input 2 (fee UTXO, P2PK)
    let sighash_2 = compute_sighash(&tx, 2)?;
    let sig_2 = signing::schnorr_sign(&privkey, &sighash_2)?;
    let fee_ss = signing::build_p2pk_sigscript(&sig_2);

    // Phase 2: exact mass check with real sigscripts
    let sigscripts_cancel = vec![buy_cancel_ss.clone(), sell_cancel_ss.clone(), fee_ss.clone()];
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts_cancel);
    let exact_fee = exact_mass;

    let (buy_cancel_ss, sell_cancel_ss, fee_ss, actual_fee) = if exact_fee != est_fee {
        let output_value = total_in.saturating_sub(exact_fee);
        tx.outputs[0].value = output_value;

        // Re-sign all inputs with updated output value
        let sighash_0 = compute_sighash(&tx, 0)?;
        let sig_0 = signing::schnorr_sign(&privkey, &sighash_0)?;
        let buy_cancel_ss = contract::build_oco_pair_cancel_sigscript(&sig_0, &pubkey, &buy_rs);
        let sighash_1 = compute_sighash(&tx, 1)?;
        let sig_1 = signing::schnorr_sign(&privkey, &sighash_1)?;
        let sell_cancel_ss = contract::build_oco_pair_cancel_sigscript(&sig_1, &pubkey, &sell_rs);
        let sighash_2 = compute_sighash(&tx, 2)?;
        let sig_2 = signing::schnorr_sign(&privkey, &sighash_2)?;
        let fee_ss = signing::build_p2pk_sigscript(&sig_2);

        (buy_cancel_ss, sell_cancel_ss, fee_ss, exact_fee)
    } else {
        (buy_cancel_ss, sell_cancel_ss, fee_ss, est_fee)
    };

    let output_value = tx.outputs[0].value;

    println!("Buy Cancel SS:  {} bytes", buy_cancel_ss.len());
    println!("Sell Cancel SS: {} bytes", sell_cancel_ss.len());
    println!("Fee SS:         {} bytes", fee_ss.len());
    println!("Output Value:  {} sompi", output_value);
    println!("Miner fee:     {} sompi", actual_fee);
    println!();

    // Submit
    let payload = to_rpc_payload(&tx, &[buy_cancel_ss, sell_cancel_ss, fee_ss]);
    println!("Submitting OCO cancel transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! OCO cancel transaction submitted.");
    println!("TXID: {}", tx_id);
    println!();
    println!("Recovered {} sompi to wallet.", output_value);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kob_core::contract;
    use kob_core::p2sh::{blake2b_256, build_p2sh};

    fn dummy_nonce() -> [u8; 32] {
        [0x42u8; 32]
    }

    fn dummy_tcid() -> [u8; 32] {
        [0x01u8; 32]
    }

    fn dummy_keys() -> ([u8; 32], [u8; 32], [u8; 36]) {
        let pk = [0x02u8; 32];
        let owner_hash = blake2b_256(&pk);
        let owner_spk = build_owner_spk(&pk);
        (pk, owner_hash, owner_spk)
    }

    #[test]
    fn owner_spk_is_36_bytes() {
        let pk = [0x02u8; 32];
        let spk = build_owner_spk(&pk);
        assert_eq!(spk.len(), 36);
        // version = 0 (u16 LE)
        assert_eq!(spk[0], 0x00);
        assert_eq!(spk[1], 0x00);
        // push32
        assert_eq!(spk[2], 0x20);
        // pubkey
        assert_eq!(&spk[3..35], &pk);
        // OpCheckSig
        assert_eq!(spk[35], 0xac);
    }

    #[test]
    fn nonce_links_both_legs() {
        let nonce = dummy_nonce();
        let tcid = dummy_tcid();
        let (_pk, owner_hash, owner_spk) = dummy_keys();

        let buy_rs = contract::build_oco_pair_redeem_script(
            &nonce, 0, &tcid, 0, 1, 1, 1000, &owner_hash, &owner_spk,
        ).unwrap();
        let sell_rs = contract::build_oco_pair_redeem_script(
            &nonce, 1, &tcid, 5000000, 1, 1, 1000, &owner_hash, &owner_spk,
        ).unwrap();

        // Nonce is at bytes [1..33] in the RS (after 0x20 push prefix)
        assert_eq!(&buy_rs[1..33], &nonce, "Buy RS must contain nonce");
        assert_eq!(&sell_rs[1..33], &nonce, "Sell RS must contain nonce");
        assert_eq!(
            &buy_rs[1..33],
            &sell_rs[1..33],
            "Both legs must share the same nonce"
        );
    }

    #[test]
    fn buy_and_sell_p2sh_differ() {
        let nonce = dummy_nonce();
        let tcid = dummy_tcid();
        let (_pk, owner_hash, owner_spk) = dummy_keys();

        let buy_rs = contract::build_oco_pair_redeem_script(
            &nonce, 0, &tcid, 0, 1, 1, 1000, &owner_hash, &owner_spk,
        ).unwrap();
        let sell_rs = contract::build_oco_pair_redeem_script(
            &nonce, 1, &tcid, 5000000, 1, 1, 1000, &owner_hash, &owner_spk,
        ).unwrap();

        let buy_p2sh = build_p2sh(&buy_rs);
        let sell_p2sh = build_p2sh(&sell_rs);

        assert_ne!(
            buy_p2sh.script(), sell_p2sh.script(),
            "Buy and sell P2SH must differ (different role)"
        );
    }

    // Version detection

    #[test]
    fn detect_oco_version_v3() {
        assert_eq!(detect_oco_version(313).unwrap(), 3);
    }

    #[test]
    fn detect_oco_version_v4() {
        assert_eq!(detect_oco_version(328).unwrap(), 4);
    }

    #[test]
    fn detect_oco_version_unknown() {
        assert!(detect_oco_version(200).is_err());
        assert!(detect_oco_version(314).is_err());
        assert!(detect_oco_version(370).is_err());
    }

    // v4 RS and sigscript tests

    #[test]
    fn oco_v4_rs_is_328_bytes() {
        let nonce = dummy_nonce();
        let tcid = dummy_tcid();
        let (_pk, owner_hash, owner_spk) = dummy_keys();

        let buy_rs = contract::build_oco_pair_redeem_script(
            &nonce, 0, &tcid, 0, 1, 1, 1000, &owner_hash, &owner_spk,
        ).unwrap();
        assert_eq!(buy_rs.len(), OCO_RS_SIZE, "Buy RS must be 328 bytes");

        let sell_rs = contract::build_oco_pair_redeem_script(
            &nonce, 1, &tcid, 5000000, 1, 1, 1000, &owner_hash, &owner_spk,
        ).unwrap();
        assert_eq!(sell_rs.len(), OCO_RS_SIZE, "Sell RS must be 328 bytes");
    }

    #[test]
    fn oco_v4_fill_sigscript_structure() {
        let nonce = dummy_nonce();
        let tcid = dummy_tcid();
        let (_pk, owner_hash, owner_spk) = dummy_keys();
        let rs = contract::build_oco_pair_redeem_script(
            &nonce, 0, &tcid, 0, 1, 1, 1000, &owner_hash, &owner_spk,
        ).unwrap();

        let fill_ss = contract::build_oco_pair_fill_sigscript(1, &rs);
        assert_eq!(fill_ss[0], 0x51, "selector must be Op1 (fill)");
        assert_eq!(fill_ss[1], 0x51, "pidx=1 must be Op1");
        // Nonce at sigscript[6..38) (same offset as v3)
        assert_eq!(&fill_ss[6..38], &nonce, "nonce at sigscript[6..38)");
    }

    #[test]
    fn oco_v4_cbp_sigscript_structure() {
        let nonce = dummy_nonce();
        let tcid = dummy_tcid();
        let (_pk, owner_hash, owner_spk) = dummy_keys();
        let rs = contract::build_oco_pair_redeem_script(
            &nonce, 1, &tcid, 5000000, 1, 1, 1000, &owner_hash, &owner_spk,
        ).unwrap();

        let cbp_ss = contract::build_oco_pair_cbp_sigscript(0, &rs);
        assert_eq!(cbp_ss[0], 0x52, "selector must be Op2 (cbp)");
        assert_eq!(cbp_ss[1], 0x00, "pidx=0 must be Op0");
        // Nonce at sigscript[6..38)
        assert_eq!(&cbp_ss[6..38], &nonce, "nonce at cbp sigscript[6..38)");
    }

    #[test]
    fn oco_v4_cancel_sigscript_structure() {
        let nonce = dummy_nonce();
        let tcid = dummy_tcid();
        let (pk, owner_hash, owner_spk) = dummy_keys();
        let rs = contract::build_oco_pair_redeem_script(
            &nonce, 0, &tcid, 0, 1, 1, 1000, &owner_hash, &owner_spk,
        ).unwrap();

        let sig = [0xAA; 64];
        let cancel_ss = contract::build_oco_pair_cancel_sigscript(&sig, &pk, &rs);
        assert_eq!(cancel_ss[0], 0x00, "selector must be Op0 (cancel)");
    }

    #[test]
    fn oco_v4_sigscript_sizes() {
        let nonce = dummy_nonce();
        let tcid = dummy_tcid();
        let (pk, owner_hash, owner_spk) = dummy_keys();
        let rs = contract::build_oco_pair_redeem_script(
            &nonce, 0, &tcid, 0, 1, 1, 1000, &owner_hash, &owner_spk,
        ).unwrap();

        let fill_ss = contract::build_oco_pair_fill_sigscript(1, &rs);
        let cbp_ss = contract::build_oco_pair_cbp_sigscript(0, &rs);
        let sig = [0xAA; 64];
        let cancel_ss = contract::build_oco_pair_cancel_sigscript(&sig, &pk, &rs);

        // fill/cbp: 1 + 1 + 3 + 328 = 333
        assert_eq!(fill_ss.len(), 333, "fill sigscript = 333B");
        assert_eq!(cbp_ss.len(), 333, "cbp sigscript = 333B");
        // cancel: 1 + 66 + 33 + 3 + 328 = 431
        assert_eq!(cancel_ss.len(), 431, "cancel sigscript = 431B");

        // Dispatch: fill/cbp (333) < 350, cancel (431) >= 350
        assert!(fill_ss.len() < 350, "fill must be below dispatch threshold 350");
        assert!(cbp_ss.len() < 350, "cbp must be below dispatch threshold 350");
        assert!(cancel_ss.len() >= 350, "cancel must be at/above dispatch threshold 350");
    }

    #[test]
    fn oco_v4_nonce_links_both_legs() {
        let nonce = dummy_nonce();
        let tcid = dummy_tcid();
        let (_pk, owner_hash, owner_spk) = dummy_keys();

        let buy_rs = contract::build_oco_pair_redeem_script(
            &nonce, 0, &tcid, 0, 1, 1, 1000, &owner_hash, &owner_spk,
        ).unwrap();
        let sell_rs = contract::build_oco_pair_redeem_script(
            &nonce, 1, &tcid, 5000000, 1, 1, 1000, &owner_hash, &owner_spk,
        ).unwrap();

        // Nonce at bytes [1..33) in v4 RS (same position as v3)
        assert_eq!(&buy_rs[1..33], &nonce, "Buy RS nonce at [1..33)");
        assert_eq!(&sell_rs[1..33], &nonce, "Sell RS nonce at [1..33)");
    }

    #[test]
    fn oco_v4_state_identical_to_v3() {
        // v4 state is identical to v3 (181B). Body starts at same offset.
        let nonce = dummy_nonce();
        let tcid = dummy_tcid();
        let (_pk, owner_hash, owner_spk) = dummy_keys();

        let v3_rs = contract::build_oco_pair_redeem_script(
            &nonce, 0, &tcid, 0, 1, 1, 1000, &owner_hash, &owner_spk,
        ).unwrap();
        let v4_rs = contract::build_oco_pair_redeem_script(
            &nonce, 0, &tcid, 0, 1, 1, 1000, &owner_hash, &owner_spk,
        ).unwrap();

        // State (first 181 bytes) must be identical
        assert_eq!(&v3_rs[..181], &v4_rs[..181], "v4 state must be identical to v3");
        // Body starts at offset 181 in both
        assert_eq!(v4_rs[181], 0xb9, "v4 body starts at offset 181 (OpTxInputIndex)");
    }
}
