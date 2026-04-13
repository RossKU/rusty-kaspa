//! `kob-cli auction` -- Auction lifecycle commands.
//!
//! Subcommands:
//!   english-deploy  -- Deploy an English auction (ascending bids)
//!   english-bid     -- Bid on an English auction
//!   english-settle  -- Settle/cancel an English auction (seller only)
//!   dutch-deploy    -- Deploy a Dutch auction (descending price)
//!   dutch-tick      -- Tick a Dutch auction (reduce price by one step)
//!   dutch-buy       -- Buy from a Dutch auction at current price
//!   dutch-cancel    -- Cancel a Dutch auction (seller only)

use crate::node::NodeClient;
use crate::signing;
use clap::Subcommand;
use kob_core::auction::{
    build_auction_payload,
    build_dutch_auction_redeem_script,
    build_dutch_buy_sigscript, build_dutch_cancel_sigscript, build_dutch_tick_sigscript,
    build_english_auction_redeem_script, build_english_bid_sigscript,
    build_english_settle_sigscript,
    DUTCH_AUCTION_BODY, DUTCH_AUCTION_STATE_SIZE,
};
use kob_core::mass::MAX_TX_MASS;
use kob_core::p2sh::build_p2sh;
use kob_core::sighash::compute_sighash;
use kob_core::tx::{select_utxos_mass_aware, to_rpc_payload, CoinSelection, Transaction, TxInput, TxOutput};
use kob_core::types::{Network, Outpoint, UtxoEntry};
use kob_core::wallet::WalletContext;
use kob_core::MIN_UTXO_VALUE;
use std::path::Path;

/// Auction subcommands.
#[derive(Subcommand, Debug)]
pub enum AuctionCommand {
    /// Deploy an English auction v2 (ascending bids, highest wins).
    ///
    /// Seller locks a reserve price as the initial UTXO value.
    /// Bids must increase by at least min_increment. Each bid refunds
    /// the previous bid amount via output[1]. Seller settles at any time.
    EnglishDeploy {
        /// Reserve price (initial UTXO value) in sompi.
        #[arg(long)]
        reserve: u64,

        /// Minimum bid increment in sompi (must be > 0).
        #[arg(long)]
        min_increment: u64,
    },

    /// Bid on an English auction v2 (increase the UTXO value).
    ///
    /// The bid TX refunds the previous bid amount via output[1].
    /// --refund-spk: hex SPK of the previous bidder (looked up from TX graph).
    /// If omitted, refund goes to self (assumes you are the previous bidder).
    EnglishBid {
        /// Auction outpoint (txid:index).
        #[arg(long)]
        outpoint: String,

        /// Bid amount in sompi (must be >= current value + min_increment).
        #[arg(long)]
        amount: u64,

        /// Auction redeemScript (hex).
        #[arg(long)]
        rs: String,

        /// Current auction UTXO value in sompi.
        #[arg(long)]
        current_value: u64,

        /// Hex SPK of the previous bidder for refund output.
        /// If omitted, refund goes to self (the bidder's own address).
        #[arg(long)]
        refund_spk: Option<String>,
    },

    /// Settle or cancel an English auction (seller only).
    EnglishSettle {
        /// Auction outpoint (txid:index).
        #[arg(long)]
        outpoint: String,

        /// Auction redeemScript (hex).
        #[arg(long)]
        rs: String,

        /// Current auction UTXO value in sompi.
        #[arg(long)]
        current_value: u64,
    },

    /// Deploy a Dutch auction (descending price, first buyer wins).
    ///
    /// Seller deploys at starting_price. Anyone can "tick" to reduce by step.
    /// Anyone can "buy" at the current price. Price floor = reserve.
    DutchDeploy {
        /// Starting price in sompi (initial UTXO value).
        #[arg(long)]
        start_price: u64,

        /// Reserve (price floor) in sompi.
        #[arg(long)]
        reserve: u64,

        /// Price step (decrement per tick) in sompi.
        #[arg(long)]
        step: u64,
    },

    /// Tick a Dutch auction (reduce price by one step).
    DutchTick {
        /// Auction outpoint (txid:index).
        #[arg(long)]
        outpoint: String,

        /// Auction redeemScript (hex).
        #[arg(long)]
        rs: String,

        /// Current auction UTXO value in sompi.
        #[arg(long)]
        current_value: u64,

        /// Step size in sompi (must match contract).
        #[arg(long)]
        step: u64,
    },

    /// Buy from a Dutch auction at current price.
    DutchBuy {
        /// Auction outpoint (txid:index).
        #[arg(long)]
        outpoint: String,

        /// Auction redeemScript (hex).
        #[arg(long)]
        rs: String,

        /// Current auction UTXO value (= current price) in sompi.
        #[arg(long)]
        current_value: u64,
    },

    /// Cancel a Dutch auction (seller only).
    DutchCancel {
        /// Auction outpoint (txid:index).
        #[arg(long)]
        outpoint: String,

        /// Auction redeemScript (hex).
        #[arg(long)]
        rs: String,

        /// Current auction UTXO value in sompi.
        #[arg(long)]
        current_value: u64,
    },
}

/// Parse an outpoint string "txid:index" into (txid, index).
fn parse_outpoint(s: &str) -> anyhow::Result<(String, u32)> {
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    if parts.len() != 2 {
        anyhow::bail!("outpoint must be in txid:index format");
    }
    let txid = parts[0].to_string();
    let index: u32 = parts[1].parse()?;
    Ok((txid, index))
}

/// Dispatch auction subcommand.
pub async fn run(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    fee: u64,
    action: &AuctionCommand,
) -> anyhow::Result<()> {
    match action {
        AuctionCommand::EnglishDeploy { reserve, min_increment } => {
            deploy_english(wallet_path, node_url, network, *reserve, *min_increment, fee).await?;
        }
        AuctionCommand::EnglishBid { outpoint, amount, rs, current_value, refund_spk } => {
            bid_english(wallet_path, node_url, network, outpoint, *amount, rs, *current_value, refund_spk.as_deref(), fee).await?;
        }
        AuctionCommand::EnglishSettle { outpoint, rs, current_value } => {
            settle_english(wallet_path, node_url, network, outpoint, rs, *current_value, fee).await?;
        }
        AuctionCommand::DutchDeploy { start_price, reserve, step } => {
            deploy_dutch(wallet_path, node_url, network, *start_price, *reserve, *step, fee).await?;
        }
        AuctionCommand::DutchTick { outpoint, rs, current_value, step } => {
            tick_dutch(wallet_path, node_url, network, outpoint, rs, *current_value, *step, fee).await?;
        }
        AuctionCommand::DutchBuy { outpoint, rs, current_value } => {
            buy_dutch(wallet_path, node_url, network, outpoint, rs, *current_value, fee).await?;
        }
        AuctionCommand::DutchCancel { outpoint, rs, current_value } => {
            cancel_dutch(wallet_path, node_url, network, outpoint, rs, *current_value, fee).await?;
        }
    }
    Ok(())
}

// English Auction

async fn deploy_english(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    reserve: u64,
    min_increment: u64,
    fee: u64,
) -> anyhow::Result<String> {
    if reserve == 0 {
        anyhow::bail!("reserve must be > 0");
    }
    if min_increment == 0 {
        anyhow::bail!("min_increment must be > 0");
    }

    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = wallet.privkey();

    let redeem_script = build_english_auction_redeem_script(&pubkey, min_increment)?;
    let p2sh = build_p2sh(&redeem_script);

    println!("Deploy English Auction v2");
    println!("==========================");
    println!("Reserve:       {} sompi ({:.8} KAS)", reserve, reserve as f64 / 1e8);
    println!("Min Increment: {} sompi ({:.8} KAS)", min_increment, min_increment as f64 / 1e8);
    println!("Seller:        {}", wallet.pubkey_hex());
    println!("RS:            {} bytes", redeem_script.len());
    println!("P2SH SPK:      {}", hex::encode(&p2sh.script()));
    println!();

    let rpc = NodeClient::connect(node_url).await?;
    let (core_utxos, p2pk_rpc) = fetch_p2pk_utxos(&rpc, &wallet).await?;

    let coin_sel = select_utxos_mass_aware(&core_utxos, reserve, fee, 2)
        .map_err(|e| anyhow::anyhow!("UTXO selection failed: {}. {} P2PK UTXOs.", e, core_utxos.len()))?;

    print_utxo_selection(&coin_sel);

    let change = coin_sel.total - reserve - fee;
    let mut tx = Transaction::new(0);
    add_p2pk_inputs(&mut tx, &coin_sel.utxos, &p2pk_rpc)?;

    tx.outputs.push(TxOutput::new(reserve, 0, p2sh.script().to_vec(), None));
    tx.payload = build_auction_payload(&redeem_script);

    add_change_output(&mut tx, change, &p2pk_rpc, &coin_sel.utxos)?;

    if let Err(e) = kob_core::check_tx_storage_mass(&tx) {
        anyhow::bail!("TX rejected: {}. Increase reserve or consolidate UTXOs.", e);
    }

    let sigscripts = sign_all_p2pk(&tx, &privkey)?;
    let payload = to_rpc_payload(&tx, &sigscripts);
    println!("Submitting...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!("\nSUCCESS! English auction deployed.");
    println!("TXID:     {}", tx_id);
    println!("Outpoint: {}:0", tx_id);
    println!("RS (hex): {}", hex::encode(&redeem_script));
    Ok(tx_id)
}

async fn bid_english(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    outpoint_str: &str,
    amount: u64,
    rs_hex: &str,
    current_value: u64,
    refund_spk_hex: Option<&str>,
    fee: u64,
) -> anyhow::Result<String> {
    if amount <= current_value {
        anyhow::bail!("bid amount {} must be > current value {}", amount, current_value);
    }

    let wallet = WalletContext::load(wallet_path)?;
    let privkey = wallet.privkey();

    let redeem_script = hex::decode(rs_hex)?;
    let p2sh = build_p2sh(&redeem_script);
    let (auction_txid, auction_idx) = parse_outpoint(outpoint_str)?;

    println!("English Auction Bid (v2)");
    println!("========================");
    println!("Current:  {} sompi", current_value);
    println!("Bid:      {} sompi", amount);
    println!("Increase: {} sompi", amount - current_value);
    println!("Refund:   {} sompi to previous bidder", current_value);
    println!();

    let rpc = NodeClient::connect(node_url).await?;
    let (core_utxos, p2pk_rpc) = fetch_p2pk_utxos(&rpc, &wallet).await?;

    // Bidder needs to fund: new_bid amount + refund of old bid + fee
    // inputs:  auction UTXO (current_value) + bidder funding
    // outputs: new auction (amount) + refund (current_value) + change
    // So bidder funds: amount + current_value - current_value + fee = amount + fee
    // But auction UTXO contributes current_value, so:
    // bidder funds = amount - current_value + current_value + fee = amount + fee
    // Wait: total_out = amount + current_value + change
    //        total_in = current_value + bidder_funds
    //        bidder_funds = amount + current_value + change + fee - current_value = amount + change + fee
    // With change = bidder_funds - (amount + fee) ... so bidder_funds >= amount + fee
    // Actually: bidder needs to provide the FULL new bid (amount) plus the refund
    // No — the refund comes from the old auction UTXO value.
    // total_in = current_value (auction) + bidder_funding
    // total_out = amount (new auction) + current_value (refund) + change
    // bidder_funding = amount + current_value + change - current_value = amount + change
    // bidder_funding - change = amount → need at least `amount` from bidder + fee
    let funding_needed = amount + fee;
    let coin_sel = select_utxos_mass_aware(&core_utxos, funding_needed, 0, 3)
        .map_err(|e| anyhow::anyhow!("UTXO selection failed: {}", e))?;

    let total_in = current_value + coin_sel.total;
    let total_out_fixed = amount + current_value; // new auction + refund
    let change = total_in - total_out_fixed - fee;

    let bid_sigscript = build_english_bid_sigscript(&redeem_script);

    let mut tx = Transaction::new(0);

    // Input 0: auction UTXO (covenant, sigOpCount=0)
    tx.inputs.push(TxInput {
        prev_tx_id: auction_txid,
        prev_index: auction_idx,
        sequence: 0,
        sig_op_count: 0,
        script_version: 0,
        script_bytes: p2sh.script().to_vec(),
        value: current_value,
    });

    // Input 1+: bidder funding UTXOs
    add_p2pk_inputs(&mut tx, &coin_sel.utxos, &p2pk_rpc)?;

    // Output 0: self-continuation (same P2SH, higher value)
    tx.outputs.push(TxOutput::new(amount, 0, p2sh.script().to_vec(), None));

    // Output 1: refund to previous bidder (>= current_value, enforced by covenant)
    let refund_spk = if let Some(hex_spk) = refund_spk_hex {
        hex::decode(hex_spk)?
    } else {
        // Default: refund to self (bidder's own address)
        let first_rpc = find_rpc_utxo(&p2pk_rpc, &coin_sel.utxos[0])?;
        hex::decode(&first_rpc.utxo_entry.script_public_key.script)?
    };

    tx.outputs.push(TxOutput::new(current_value, 0, refund_spk, None));

    // Output 2: change to bidder
    add_change_output(&mut tx, change, &p2pk_rpc, &coin_sel.utxos)?;

    // Sign: input 0 = covenant sigscript, input 1+ = P2PK
    let mut sigscripts: Vec<Vec<u8>> = Vec::new();
    sigscripts.push(bid_sigscript);
    for i in 1..tx.inputs.len() {
        let sighash = compute_sighash(&tx, i)?;
        let sig = signing::schnorr_sign_secure(&privkey, &sighash)?;
        sigscripts.push(signing::build_p2pk_sigscript(&sig));
    }

    if let Err(e) = kob_core::check_tx_storage_mass(&tx) {
        anyhow::bail!("TX rejected: {}", e);
    }

    let payload = to_rpc_payload(&tx, &sigscripts);
    println!("Submitting...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!("\nSUCCESS! Bid placed.");
    println!("TXID: {}", tx_id);
    println!("New auction outpoint: {}:0", tx_id);
    Ok(tx_id)
}

async fn settle_english(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    outpoint_str: &str,
    rs_hex: &str,
    current_value: u64,
    fee: u64,
) -> anyhow::Result<String> {
    let wallet = WalletContext::load(wallet_path)?;
    let privkey = wallet.privkey();

    let redeem_script = hex::decode(rs_hex)?;
    let p2sh = build_p2sh(&redeem_script);
    let (auction_txid, auction_idx) = parse_outpoint(outpoint_str)?;

    println!("English Auction Settle");
    println!("=======================");
    println!("Settling:  {} sompi ({:.8} KAS)", current_value, current_value as f64 / 1e8);
    println!();

    let rpc = NodeClient::connect(node_url).await?;
    let (core_utxos, p2pk_rpc) = fetch_p2pk_utxos(&rpc, &wallet).await?;

    // Need a fee-funding UTXO
    let coin_sel = select_utxos_mass_aware(&core_utxos, fee, 0, 2)
        .map_err(|e| anyhow::anyhow!("UTXO selection failed for fee: {}", e))?;

    let change = coin_sel.total - fee;

    let mut tx = Transaction::new(0);

    // Input 0: auction UTXO (sigOpCount=1 for settle path)
    tx.inputs.push(TxInput {
        prev_tx_id: auction_txid,
        prev_index: auction_idx,
        sequence: 0,
        sig_op_count: 1,
        script_version: 0,
        script_bytes: p2sh.script().to_vec(),
        value: current_value,
    });

    // Input 1+: fee-funding UTXOs
    add_p2pk_inputs(&mut tx, &coin_sel.utxos, &p2pk_rpc)?;

    // Output 0: seller receives auction proceeds
    let first_rpc = p2pk_rpc.iter().find(|u| {
        u.outpoint.transaction_id == coin_sel.utxos[0].outpoint.transaction_id
            && u.outpoint.index == coin_sel.utxos[0].outpoint.index
    }).ok_or_else(|| anyhow::anyhow!("UTXO spent"))?;
    let wallet_spk = hex::decode(&first_rpc.utxo_entry.script_public_key.script)?;

    tx.outputs.push(TxOutput::new(current_value, first_rpc.utxo_entry.script_public_key.version, wallet_spk.clone(), None));

    if change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(change, first_rpc.utxo_entry.script_public_key.version, wallet_spk, None));
    }

    // Sign: input 0 = covenant settle sigscript, input 1+ = P2PK
    let sighash_0 = compute_sighash(&tx, 0)?;
    let sig_0 = signing::schnorr_sign_secure(&privkey, &sighash_0)?;
    let settle_sigscript = build_english_settle_sigscript(&sig_0, &redeem_script);

    let mut sigscripts: Vec<Vec<u8>> = Vec::new();
    sigscripts.push(settle_sigscript);
    for i in 1..tx.inputs.len() {
        let sighash = compute_sighash(&tx, i)?;
        let sig = signing::schnorr_sign_secure(&privkey, &sighash)?;
        sigscripts.push(signing::build_p2pk_sigscript(&sig));
    }

    if let Err(e) = kob_core::check_tx_storage_mass(&tx) {
        anyhow::bail!("TX rejected: {}", e);
    }

    let payload = to_rpc_payload(&tx, &sigscripts);
    println!("Submitting...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!("\nSUCCESS! Auction settled.");
    println!("TXID: {}", tx_id);
    Ok(tx_id)
}

// Dutch Auction

async fn deploy_dutch(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    start_price: u64,
    reserve: u64,
    step: u64,
    fee: u64,
) -> anyhow::Result<String> {
    if start_price <= reserve {
        anyhow::bail!("start_price must be > reserve");
    }
    if step == 0 {
        anyhow::bail!("step must be > 0");
    }

    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = wallet.privkey();

    let redeem_script = build_dutch_auction_redeem_script(&pubkey, reserve, step)?;
    let p2sh = build_p2sh(&redeem_script);

    println!("Deploy Dutch Auction");
    println!("=====================");
    println!("Start Price:  {} sompi ({:.8} KAS)", start_price, start_price as f64 / 1e8);
    println!("Reserve:      {} sompi ({:.8} KAS)", reserve, reserve as f64 / 1e8);
    println!("Step:         {} sompi ({:.8} KAS)", step, step as f64 / 1e8);
    println!("Ticks to floor: {}", (start_price - reserve) / step);
    println!("Seller:       {}", wallet.pubkey_hex());
    println!("RS:           {} bytes", redeem_script.len());
    println!();

    let rpc = NodeClient::connect(node_url).await?;
    let (core_utxos, p2pk_rpc) = fetch_p2pk_utxos(&rpc, &wallet).await?;

    let coin_sel = select_utxos_mass_aware(&core_utxos, start_price, fee, 2)
        .map_err(|e| anyhow::anyhow!("UTXO selection failed: {}", e))?;

    print_utxo_selection(&coin_sel);

    let change = coin_sel.total - start_price - fee;
    let mut tx = Transaction::new(0);
    add_p2pk_inputs(&mut tx, &coin_sel.utxos, &p2pk_rpc)?;

    tx.outputs.push(TxOutput::new(start_price, 0, p2sh.script().to_vec(), None));
    tx.payload = build_auction_payload(&redeem_script);

    add_change_output(&mut tx, change, &p2pk_rpc, &coin_sel.utxos)?;

    if let Err(e) = kob_core::check_tx_storage_mass(&tx) {
        anyhow::bail!("TX rejected: {}", e);
    }

    let sigscripts = sign_all_p2pk(&tx, &privkey)?;
    let payload = to_rpc_payload(&tx, &sigscripts);
    println!("Submitting...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!("\nSUCCESS! Dutch auction deployed.");
    println!("TXID:     {}", tx_id);
    println!("Outpoint: {}:0", tx_id);
    println!("RS (hex): {}", hex::encode(&redeem_script));
    Ok(tx_id)
}

async fn tick_dutch(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    outpoint_str: &str,
    rs_hex: &str,
    current_value: u64,
    step: u64,
    fee: u64,
) -> anyhow::Result<String> {
    let new_value = current_value.checked_sub(step)
        .ok_or_else(|| anyhow::anyhow!("tick would underflow (current {} < step {})", current_value, step))?;

    let wallet = WalletContext::load(wallet_path)?;
    let privkey = wallet.privkey();

    let redeem_script = hex::decode(rs_hex)?;
    let p2sh = build_p2sh(&redeem_script);
    let (auction_txid, auction_idx) = parse_outpoint(outpoint_str)?;

    println!("Dutch Auction Tick");
    println!("===================");
    println!("Current: {} sompi", current_value);
    println!("New:     {} sompi (−{})", new_value, step);
    println!();

    let rpc = NodeClient::connect(node_url).await?;
    let (core_utxos, p2pk_rpc) = fetch_p2pk_utxos(&rpc, &wallet).await?;

    let coin_sel = select_utxos_mass_aware(&core_utxos, fee, 0, 2)
        .map_err(|e| anyhow::anyhow!("UTXO selection for fee failed: {}", e))?;

    // Ticker gets the step delta back (current - new) minus fee
    let ticker_return = step;
    let change = coin_sel.total + ticker_return - fee;

    let tick_sigscript = build_dutch_tick_sigscript(&redeem_script);

    let mut tx = Transaction::new(0);

    // Input 0: auction UTXO (sigOpCount=0)
    tx.inputs.push(TxInput {
        prev_tx_id: auction_txid,
        prev_index: auction_idx,
        sequence: 0,
        sig_op_count: 0,
        script_version: 0,
        script_bytes: p2sh.script().to_vec(),
        value: current_value,
    });

    add_p2pk_inputs(&mut tx, &coin_sel.utxos, &p2pk_rpc)?;

    // Output 0: self-continuation (same P2SH, lower value)
    tx.outputs.push(TxOutput::new(new_value, 0, p2sh.script().to_vec(), None));

    // Output 1: change to ticker
    if change >= MIN_UTXO_VALUE {
        let first_rpc = find_rpc_utxo(&p2pk_rpc, &coin_sel.utxos[0])?;
        let wallet_spk = hex::decode(&first_rpc.utxo_entry.script_public_key.script)?;
        tx.outputs.push(TxOutput::new(change, first_rpc.utxo_entry.script_public_key.version, wallet_spk, None));
    }

    let mut sigscripts: Vec<Vec<u8>> = Vec::new();
    sigscripts.push(tick_sigscript);
    for i in 1..tx.inputs.len() {
        let sighash = compute_sighash(&tx, i)?;
        let sig = signing::schnorr_sign_secure(&privkey, &sighash)?;
        sigscripts.push(signing::build_p2pk_sigscript(&sig));
    }

    if let Err(e) = kob_core::check_tx_storage_mass(&tx) {
        anyhow::bail!("TX rejected: {}", e);
    }

    let payload = to_rpc_payload(&tx, &sigscripts);
    println!("Submitting...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!("\nSUCCESS! Tick executed.");
    println!("TXID: {}", tx_id);
    println!("New auction outpoint: {}:0 (value: {} sompi)", tx_id, new_value);
    Ok(tx_id)
}

async fn buy_dutch(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    outpoint_str: &str,
    rs_hex: &str,
    current_value: u64,
    fee: u64,
) -> anyhow::Result<String> {
    let wallet = WalletContext::load(wallet_path)?;
    let privkey = wallet.privkey();

    let redeem_script = hex::decode(rs_hex)?;
    let p2sh = build_p2sh(&redeem_script);
    let (auction_txid, auction_idx) = parse_outpoint(outpoint_str)?;

    println!("Dutch Auction Buy");
    println!("==================");
    println!("Price: {} sompi ({:.8} KAS)", current_value, current_value as f64 / 1e8);
    println!();

    let rpc = NodeClient::connect(node_url).await?;
    let (core_utxos, p2pk_rpc) = fetch_p2pk_utxos(&rpc, &wallet).await?;

    // Buyer needs to pay current_value to the seller (output[0] >= input.value)
    let coin_sel = select_utxos_mass_aware(&core_utxos, current_value + fee, 0, 2)
        .map_err(|e| anyhow::anyhow!("UTXO selection failed: {}", e))?;

    let change = coin_sel.total - current_value - fee;

    let buy_sigscript = build_dutch_buy_sigscript(&redeem_script);

    let mut tx = Transaction::new(0);

    // Input 0: auction UTXO (sigOpCount=0)
    tx.inputs.push(TxInput {
        prev_tx_id: auction_txid,
        prev_index: auction_idx,
        sequence: 0,
        sig_op_count: 0,
        script_version: 0,
        script_bytes: p2sh.script().to_vec(),
        value: current_value,
    });

    add_p2pk_inputs(&mut tx, &coin_sel.utxos, &p2pk_rpc)?;

    // Output 0: seller payment (>= current_value)
    // Extract seller_pk from v2 RS state: [0x20][seller_pk 32B][0x08][reserve 8B][0x08][step 8B][0x20][seller_spk_hash 32B]
    if redeem_script.len() < DUTCH_AUCTION_STATE_SIZE + DUTCH_AUCTION_BODY.len() {
        anyhow::bail!("invalid dutch auction v2 redeemScript ({} bytes, expected {})",
            redeem_script.len(), DUTCH_AUCTION_STATE_SIZE + DUTCH_AUCTION_BODY.len());
    }
    if redeem_script[0] != 0x20 {
        anyhow::bail!("invalid dutch auction v2 redeemScript: expected 0x20 prefix");
    }
    if &redeem_script[DUTCH_AUCTION_STATE_SIZE..] != DUTCH_AUCTION_BODY {
        anyhow::bail!("invalid dutch auction v2 redeemScript: body mismatch");
    }
    let seller_pk = &redeem_script[1..33];
    // P2PK SPK: [0x20][pubkey 32B][0xac (OpCheckSig)]
    let mut seller_spk = Vec::with_capacity(34);
    seller_spk.push(0x20);
    seller_spk.extend_from_slice(seller_pk);
    seller_spk.push(0xac);

    tx.outputs.push(TxOutput::new(current_value, 0, seller_spk, None));

    if change >= MIN_UTXO_VALUE {
        let first_rpc = find_rpc_utxo(&p2pk_rpc, &coin_sel.utxos[0])?;
        let wallet_spk = hex::decode(&first_rpc.utxo_entry.script_public_key.script)?;
        tx.outputs.push(TxOutput::new(change, first_rpc.utxo_entry.script_public_key.version, wallet_spk, None));
    }

    let mut sigscripts: Vec<Vec<u8>> = Vec::new();
    sigscripts.push(buy_sigscript);
    for i in 1..tx.inputs.len() {
        let sighash = compute_sighash(&tx, i)?;
        let sig = signing::schnorr_sign_secure(&privkey, &sighash)?;
        sigscripts.push(signing::build_p2pk_sigscript(&sig));
    }

    if let Err(e) = kob_core::check_tx_storage_mass(&tx) {
        anyhow::bail!("TX rejected: {}", e);
    }

    let payload = to_rpc_payload(&tx, &sigscripts);
    println!("Submitting...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!("\nSUCCESS! Auction purchased.");
    println!("TXID: {}", tx_id);
    Ok(tx_id)
}

async fn cancel_dutch(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    outpoint_str: &str,
    rs_hex: &str,
    current_value: u64,
    fee: u64,
) -> anyhow::Result<String> {
    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = wallet.privkey();

    let redeem_script = hex::decode(rs_hex)?;
    let p2sh = build_p2sh(&redeem_script);
    let (auction_txid, auction_idx) = parse_outpoint(outpoint_str)?;

    println!("Dutch Auction Cancel");
    println!("=====================");
    println!("Reclaiming: {} sompi ({:.8} KAS)", current_value, current_value as f64 / 1e8);
    println!();

    let rpc = NodeClient::connect(node_url).await?;
    let (core_utxos, p2pk_rpc) = fetch_p2pk_utxos(&rpc, &wallet).await?;

    let coin_sel = select_utxos_mass_aware(&core_utxos, fee, 0, 2)
        .map_err(|e| anyhow::anyhow!("UTXO selection for fee failed: {}", e))?;

    let change = coin_sel.total + current_value - fee;

    let mut tx = Transaction::new(0);

    // Input 0: auction UTXO (sigOpCount=1 for cancel path)
    tx.inputs.push(TxInput {
        prev_tx_id: auction_txid,
        prev_index: auction_idx,
        sequence: 0,
        sig_op_count: 1,
        script_version: 0,
        script_bytes: p2sh.script().to_vec(),
        value: current_value,
    });

    add_p2pk_inputs(&mut tx, &coin_sel.utxos, &p2pk_rpc)?;

    // Output 0: seller reclaims
    let first_rpc = find_rpc_utxo(&p2pk_rpc, &coin_sel.utxos[0])?;
    let wallet_spk = hex::decode(&first_rpc.utxo_entry.script_public_key.script)?;

    tx.outputs.push(TxOutput::new(change, first_rpc.utxo_entry.script_public_key.version, wallet_spk, None));

    // Sign: input 0 = covenant cancel, input 1+ = P2PK
    let sighash_0 = compute_sighash(&tx, 0)?;
    let sig_0 = signing::schnorr_sign_secure(&privkey, &sighash_0)?;
    let cancel_sigscript = build_dutch_cancel_sigscript(&sig_0, &pubkey, &redeem_script);

    let mut sigscripts: Vec<Vec<u8>> = Vec::new();
    sigscripts.push(cancel_sigscript);
    for i in 1..tx.inputs.len() {
        let sighash = compute_sighash(&tx, i)?;
        let sig = signing::schnorr_sign_secure(&privkey, &sighash)?;
        sigscripts.push(signing::build_p2pk_sigscript(&sig));
    }

    if let Err(e) = kob_core::check_tx_storage_mass(&tx) {
        anyhow::bail!("TX rejected: {}", e);
    }

    let payload = to_rpc_payload(&tx, &sigscripts);
    println!("Submitting...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!("\nSUCCESS! Dutch auction cancelled.");
    println!("TXID: {}", tx_id);
    Ok(tx_id)
}

/// RPC UTXO type alias for brevity.
type RpcUtxo = crate::rpc::RpcUtxo;

async fn fetch_p2pk_utxos(
    rpc: &NodeClient,
    wallet: &WalletContext,
) -> anyhow::Result<(Vec<UtxoEntry>, Vec<RpcUtxo>)> {
    let rpc_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let p2pk_rpc: Vec<_> = rpc_utxos.into_iter().filter(|u| !u.is_p2sh()).collect();
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
    Ok((core_utxos, p2pk_rpc))
}

fn find_rpc_utxo<'a>(
    p2pk_rpc: &'a [RpcUtxo],
    utxo: &UtxoEntry,
) -> anyhow::Result<&'a RpcUtxo> {
    p2pk_rpc
        .iter()
        .find(|u| {
            u.outpoint.transaction_id == utxo.outpoint.transaction_id
                && u.outpoint.index == utxo.outpoint.index
        })
        .ok_or_else(|| anyhow::anyhow!("UTXO spent during TX construction, please retry."))
}

fn add_p2pk_inputs(
    tx: &mut Transaction,
    utxos: &[UtxoEntry],
    p2pk_rpc: &[RpcUtxo],
) -> anyhow::Result<()> {
    for sel in utxos {
        let rpc_utxo = find_rpc_utxo(p2pk_rpc, sel)?;
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
    Ok(())
}

fn add_change_output(
    tx: &mut Transaction,
    change: u64,
    p2pk_rpc: &[RpcUtxo],
    selected: &[UtxoEntry],
) -> anyhow::Result<()> {
    if change >= MIN_UTXO_VALUE {
        let first_rpc = find_rpc_utxo(p2pk_rpc, &selected[0])?;
        let wallet_spk = hex::decode(&first_rpc.utxo_entry.script_public_key.script)?;
        tx.outputs.push(TxOutput::new(change, first_rpc.utxo_entry.script_public_key.version, wallet_spk, None));
    } else if change > 0 {
        println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", change);
    }
    Ok(())
}

fn sign_all_p2pk(
    tx: &Transaction,
    privkey: &kob_core::SecureKey,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut sigscripts = Vec::new();
    for i in 0..tx.inputs.len() {
        let sighash = compute_sighash(tx, i)?;
        let sig = signing::schnorr_sign_secure(privkey, &sighash)?;
        sigscripts.push(signing::build_p2pk_sigscript(&sig));
    }
    Ok(sigscripts)
}

fn print_utxo_selection(coin_sel: &CoinSelection) {
    println!(
        "Selected {} funding UTXOs (total {} sompi)",
        coin_sel.utxos.len(),
        coin_sel.total
    );
    for u in &coin_sel.utxos {
        println!("  {}:{} ({} sompi)", &u.outpoint.transaction_id[..16], u.outpoint.index, u.value);
    }
    if !coin_sel.penalty_free {
        println!(
            "  Warning: storage mass penalty {}/{}",
            coin_sel.storage_mass, MAX_TX_MASS
        );
    }
    println!();
}
