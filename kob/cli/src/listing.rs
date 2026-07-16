//! `kob-cli listing` -- English/Dutch/fixed auction listing lifecycle.
//!
//! The listing covenant (`kob_core::listing`) is a permissionless auction over
//! a KAS-denominated listing UTXO. This subcommand exercises the two ends of
//! its lifecycle that need no external position covenant:
//!
//!   deploy  -- fund a listing P2SH (the listing/collateral UTXO).
//!   settle  -- after `expiry_daa`, permissionlessly pay the accrued value
//!              (the listing UTXO's own value = highest english bid, or the
//!              initial deposit if there were no bids) to the seller (PATH 6).
//!
//! Bidding (PATH 5) and buy/fill (PATH 1/3) transfer ownership of an external
//! position covenant and are out of scope for this minimal smoke.

use crate::node::NodeClient;
use crate::signing;
use clap::Subcommand;
use kob_core::listing::{build_listing_redeem_script, build_listing_settle_sigscript};
use kob_core::mass::{calc_mass_with_sigscripts, estimate_compute_mass, min_relay_fee};
use kob_core::p2sh::{build_p2sh, compute_p2pk_spk_hash};
use kob_core::sighash::compute_sighash;
use kob_core::tx::{to_rpc_payload, Transaction, TxInput, TxOutput};
use kob_core::types::Network;
use kob_core::wallet::WalletContext;
use kob_core::MIN_UTXO_VALUE;
use std::path::Path;

/// Listing subcommands.
#[derive(Subcommand, Debug)]
pub enum ListingCommand {
    /// Deploy a listing (fund the auction UTXO).
    Deploy {
        /// Auction type: "fixed", "dutch", or "english".
        #[arg(long, default_value = "english")]
        listing_type: String,

        /// Asking / start price in sompi.
        #[arg(long)]
        asking_price: u64,

        /// Expiry as a DAA-score offset from the current tip (settle allowed after).
        #[arg(long)]
        expiry_daa: u64,

        /// Type-specific parameter in sompi (english: min bid increment;
        /// dutch: tick decrement). Ignored for fixed.
        #[arg(long, default_value = "0")]
        param: u64,

        /// Value locked in the listing UTXO (the collateral / starting value).
        #[arg(long)]
        value: u64,
    },

    /// Settle a listing after expiry: pay the accrued value to the seller (PATH 6).
    Settle {
        /// Listing outpoint (txid:index).
        #[arg(long)]
        outpoint: String,

        /// Listing UTXO current value in sompi (auto-queried if omitted).
        #[arg(long)]
        value: Option<u64>,

        /// Listing redeemScript (hex), printed by `deploy`.
        #[arg(long)]
        rs: String,

        /// Expiry DAA score the listing was deployed with (printed by `deploy`).
        #[arg(long)]
        expiry_daa: u64,
    },
}

/// 34-byte P2PK scriptPublicKey `[0x20][pubkey][0xac]`.
fn p2pk_spk(pubkey: &[u8; 32]) -> [u8; 34] {
    let mut spk = [0u8; 34];
    spk[0] = 0x20;
    spk[1..33].copy_from_slice(pubkey);
    spk[33] = 0xac;
    spk
}

fn listing_type_code(s: &str) -> anyhow::Result<u64> {
    match s.to_lowercase().as_str() {
        "fixed" => Ok(0),
        "dutch" => Ok(1),
        "english" => Ok(2),
        other => anyhow::bail!("unknown listing type '{}' (use fixed/dutch/english)", other),
    }
}

pub async fn run(
    cmd: &ListingCommand,
    wallet_path: &Path,
    node_url: &str,
    network: Network,
) -> anyhow::Result<()> {
    match cmd {
        ListingCommand::Deploy { listing_type, asking_price, expiry_daa, param, value } => {
            deploy_listing(wallet_path, node_url, network, listing_type, *asking_price, *expiry_daa, *param, *value).await
        }
        ListingCommand::Settle { outpoint, value, rs, expiry_daa } => {
            settle_listing(wallet_path, node_url, network, outpoint, *value, rs, *expiry_daa).await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn deploy_listing(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    listing_type_str: &str,
    asking_price: u64,
    expiry_offset: u64,
    param: u64,
    value: u64,
) -> anyhow::Result<()> {
    if value < MIN_UTXO_VALUE {
        anyhow::bail!("value {} < MIN_UTXO_VALUE {}", value, MIN_UTXO_VALUE);
    }
    let listing_type = listing_type_code(listing_type_str)?;

    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = wallet.privkey();
    let seller_spk = p2pk_spk(&pubkey);
    let seller_spk_hash = compute_p2pk_spk_hash(&pubkey);

    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;
    let current_daa = rpc.get_daa_score().await?;
    let expiry_daa = current_daa + expiry_offset;

    let rs = build_listing_redeem_script(&seller_spk_hash, &seller_spk, asking_price, listing_type, expiry_daa, param);
    let p2sh = build_p2sh(&rs);

    println!();
    println!("Deploy Listing ({})", listing_type_str);
    println!("=====================");
    println!("Asking price:  {} sompi", asking_price);
    println!("Value:         {} sompi", value);
    println!("Current DAA:   {}", current_daa);
    println!("Expiry DAA:    {} (+{})", expiry_daa, expiry_offset);
    println!("Param:         {}", param);
    println!("P2SH SPK:      {}", hex::encode(p2sh.script()));
    println!();

    // Fund from a P2PK UTXO: output[0] = listing P2SH (value), output[1] = change.
    let utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let est_fee = min_relay_fee(estimate_compute_mass(1, 2, 0));
    let need = value + est_fee + MIN_UTXO_VALUE;
    let funding = utxos.iter()
        .filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= need)
        .min_by_key(|u| u.utxo_entry.amount)
        .ok_or_else(|| anyhow::anyhow!("no P2PK UTXO with >= {} sompi found", need))?;
    println!("Funding UTXO:  {}:{} ({} sompi)", funding.outpoint.transaction_id, funding.outpoint.index, funding.utxo_entry.amount);

    let funding_spk = funding.script_bytes();
    let change_spk = hex::decode(&funding.utxo_entry.script_public_key.script)?;

    let mut tx = Transaction::new(0);
    tx.inputs.push(TxInput {
        prev_tx_id: funding.outpoint.transaction_id.clone(),
        prev_index: funding.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: funding.utxo_entry.script_public_key.version,
        script_bytes: funding_spk.clone(),
        value: funding.utxo_entry.amount,
    });
    tx.outputs.push(TxOutput::new(value, p2sh.version, p2sh.script().to_vec(), None));
    let change = funding.utxo_entry.amount - value - est_fee;
    tx.outputs.push(TxOutput::new(change, funding.utxo_entry.script_public_key.version, change_spk, None));

    // Sign, then recompute the exact fee and re-sign once (P2PK funding input).
    let sign = |tx: &Transaction| -> anyhow::Result<Vec<Vec<u8>>> {
        let sighash = compute_sighash(tx, 0)?;
        let sig = signing::schnorr_sign_secure(&privkey, &sighash)?;
        Ok(vec![signing::build_p2pk_sigscript(&sig)])
    };
    let mut sigscripts = sign(&tx)?;
    let exact_fee = min_relay_fee(calc_mass_with_sigscripts(&tx, &sigscripts));
    if exact_fee != est_fee {
        let new_change = funding.utxo_entry.amount.checked_sub(value + exact_fee)
            .ok_or_else(|| anyhow::anyhow!("funding too small for exact fee {}", exact_fee))?;
        tx.outputs[1].value = new_change;
        sigscripts = sign(&tx)?;
    }

    let payload = to_rpc_payload(&tx, &sigscripts);
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Listing deployed.");
    println!("TXID:          {}", tx_id);
    println!("Listing:       {}:0 ({} sompi)", tx_id, value);
    println!("Expiry DAA:    {}", expiry_daa);
    println!("RS:            {}", hex::encode(&rs));
    Ok(())
}

async fn settle_listing(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    outpoint: &str,
    value_override: Option<u64>,
    rs_hex: &str,
    expiry_daa: u64,
) -> anyhow::Result<()> {
    let (listing_txid, listing_index) = parse_outpoint(outpoint)?;
    let rs = hex::decode(rs_hex)?;
    let p2sh = build_p2sh(&rs);

    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = wallet.privkey();
    // Self-smoke: the seller is the wallet. PATH 6 pays the accrued value to
    // whichever SPK hashes to the state's seller_spk_hash (this wallet's P2PK).
    let seller_spk = p2pk_spk(&pubkey).to_vec();

    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;
    let current_daa = rpc.get_daa_score().await?;
    if current_daa < expiry_daa {
        anyhow::bail!("listing not expired: current DAA {} < expiry {} (wait {} more)",
            current_daa, expiry_daa, expiry_daa - current_daa);
    }

    // Resolve the listing UTXO value (the accrued bid).
    let listing_value = if let Some(v) = value_override {
        v
    } else {
        let addr = crate::cancel::p2sh_to_address(&p2sh.script(), network.address_prefix());
        let ls = rpc.get_utxos_by_addresses(&[&addr]).await?;
        ls.iter()
            .find(|u| u.outpoint.transaction_id == listing_txid && u.outpoint.index == listing_index)
            .map(|u| u.utxo_entry.amount)
            .ok_or_else(|| anyhow::anyhow!("listing {} not found (spent?) -- pass --value", outpoint))?
    };

    // Fee UTXO (P2PK) large enough to leave output[0] change >= MIN_UTXO.
    let utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let est_fee = min_relay_fee(estimate_compute_mass(2, 2, 0));
    let fee_need = MIN_UTXO_VALUE + est_fee;
    let fee_utxo = utxos.iter()
        .filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= fee_need
            && !(u.outpoint.transaction_id == listing_txid && u.outpoint.index == listing_index))
        .min_by_key(|u| u.utxo_entry.amount)
        .ok_or_else(|| anyhow::anyhow!("no P2PK fee UTXO with >= {} sompi", fee_need))?;

    println!();
    println!("Settle Listing");
    println!("==============");
    println!("Listing:       {} ({} sompi accrued)", outpoint, listing_value);
    println!("Expiry DAA:    {} (current {})", expiry_daa, current_daa);
    println!("Fee UTXO:      {}:{} ({} sompi)", fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount);
    println!();

    let settle_ss = build_listing_settle_sigscript(&rs);
    let fee_spk = fee_utxo.script_bytes();
    let wallet_change_spk = hex::decode(&fee_utxo.utxo_entry.script_public_key.script)?;

    // Layout: input[0] = listing (settle), input[1] = P2PK fee.
    // output[0] = change to wallet, output[1] = accrued value to the seller.
    // lockTime = expiry_daa (in the past -> finality-safe, satisfies PATH 6 CLTV).
    let mut tx = Transaction::new(1);
    tx.lock_time = expiry_daa;
    tx.inputs.push(TxInput {
        prev_tx_id: listing_txid.clone(),
        prev_index: listing_index,
        sequence: 0,
        sig_op_count: 0,
        script_version: p2sh.version,
        script_bytes: p2sh.script().to_vec(),
        value: listing_value,
    });
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_spk.clone(),
        value: fee_utxo.utxo_entry.amount,
    });
    let change = fee_utxo.utxo_entry.amount - est_fee;
    tx.outputs.push(TxOutput::new(change, fee_utxo.utxo_entry.script_public_key.version, wallet_change_spk.clone(), None));
    tx.outputs.push(TxOutput::new(listing_value, 0, seller_spk.clone(), None));

    // Sign the fee input (index 1); the listing input uses the settle sigscript.
    let build_sigs = |tx: &Transaction| -> anyhow::Result<Vec<Vec<u8>>> {
        let sighash = compute_sighash(tx, 1)?;
        let sig = signing::schnorr_sign_secure(&privkey, &sighash)?;
        Ok(vec![settle_ss.clone(), signing::build_p2pk_sigscript(&sig)])
    };
    let mut sigscripts = build_sigs(&tx)?;
    let exact_fee = min_relay_fee(calc_mass_with_sigscripts(&tx, &sigscripts));
    if exact_fee != est_fee {
        let new_change = fee_utxo.utxo_entry.amount.checked_sub(exact_fee)
            .ok_or_else(|| anyhow::anyhow!("fee UTXO too small for exact fee {}", exact_fee))?;
        if new_change < MIN_UTXO_VALUE {
            anyhow::bail!("change {} below MIN_UTXO after exact fee {}", new_change, exact_fee);
        }
        tx.outputs[0].value = new_change;
        sigscripts = build_sigs(&tx)?;
    }

    let payload = to_rpc_payload(&tx, &sigscripts);
    let tx_id = rpc.submit_transaction(payload).await?;

    println!("SUCCESS! Listing settled.");
    println!("TXID:          {}", tx_id);
    println!("Seller paid:   {}:1 ({} sompi)", tx_id, listing_value);
    Ok(())
}

fn parse_outpoint(s: &str) -> anyhow::Result<(String, u32)> {
    let (txid, idx) = s.split_once(':').ok_or_else(|| anyhow::anyhow!("invalid outpoint '{}' (want txid:index)", s))?;
    Ok((txid.to_string(), idx.parse()?))
}
