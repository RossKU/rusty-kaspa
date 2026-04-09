//! `kob-cli list` -- List active orders.
//!
//! Queries UTXOs for the wallet address and identifies P2SH outputs
//! that belong to KOB order contracts. Since we cannot decode the
//! redeemScript from the P2SH hash alone, this command shows raw
//! P2SH UTXOs and any locally-tracked orders.

use crate::node::NodeClient;
use kob_core::types::Network;
use kob_core::wallet::WalletFile;
use std::path::Path;
use tracing::info;

pub async fn run(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    token_filter: Option<&str>,
) -> anyhow::Result<()> {
    let wallet = WalletFile::load(wallet_path)?;

    println!("Active Orders");
    println!("==============");
    println!("Owner:      {}", wallet.address);
    println!("Network:    {:?}", network);
    println!("Node:       {}", node_url);
    if let Some(token) = token_filter {
        println!("Filter:     token={}", token);
    }
    println!();

    info!(address = %wallet.address, "listing active orders");

    // Connect and fetch UTXOs
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    let utxos = rpc.get_spendable_utxos(&wallet.address).await?;

    // Separate P2PK and P2SH UTXOs
    let p2pk_utxos: Vec<_> = utxos.iter().filter(|u| !u.is_p2sh()).collect();
    let p2sh_utxos: Vec<_> = utxos.iter().filter(|u| u.is_p2sh()).collect();

    println!("Wallet UTXOs: {} P2PK, {} P2SH", p2pk_utxos.len(), p2sh_utxos.len());
    println!();

    // P2SH UTXOs at the wallet address are unusual -- they would only appear
    // if the wallet address itself is a P2SH address, which is unlikely.
    // KOB orders are deployed to separate P2SH addresses.
    //
    // To list orders, we need to know the P2SH addresses.
    // This requires either:
    //   a) A local cache of deployed orders (orders.json)
    //   b) Scanning common parameter combinations
    //   c) Using the matcher's order book state
    //
    // For now, we show all UTXOs and explain the limitation.

    if p2sh_utxos.is_empty() && p2pk_utxos.is_empty() {
        println!("(no UTXOs found for this address)");
        return Ok(());
    }

    // Show P2PK UTXOs (regular wallet balance)
    if !p2pk_utxos.is_empty() {
        let p2pk_total: u64 = p2pk_utxos.iter().map(|u| u.utxo_entry.amount).sum();
        println!("P2PK Balance: {} sompi ({:.8} KAS)", p2pk_total, p2pk_total as f64 / 1e8);
        println!();
    }

    // Show any P2SH UTXOs
    if !p2sh_utxos.is_empty() {
        println!("P2SH UTXOs (potential orders at wallet address):");
        println!("{:<66}  {:>4}  {:>14}  SPK_HASH", "TXID", "IDX", "AMOUNT");
        println!("{}", "-".repeat(120));
        for u in &p2sh_utxos {
            let spk = &u.utxo_entry.script_public_key.script;
            let hash_hex = if spk.len() >= 68 {
                // P2SH SPK: aa20<32-byte-hash>87 => extract the hash
                &spk[4..68]
            } else {
                spk.as_str()
            };
            println!(
                "{}  {:>4}  {:>14}  {}",
                u.outpoint.transaction_id,
                u.outpoint.index,
                u.utxo_entry.amount,
                hash_hex,
            );
        }
        println!();
    }

    // Explain how to find orders
    println!("--- Order Discovery ---");
    println!("KOB orders are deployed to unique P2SH addresses derived from");
    println!("the order parameters (token, price, min_fill, owner_hash).");
    println!();
    println!("To find your orders, you need the original deploy parameters.");
    println!("Use 'kob-cli deploy buy --token <T> --price-num <N> --price-den <D> ...'");
    println!("to compute the P2SH address, then query that address directly.");
    println!();
    println!("A future version will cache deployed orders in a local orders.json file");
    println!("for automatic discovery.");

    Ok(())
}
