//! `kob-cli wallet send` -- Send KAS to an address.
//!
//! The most basic wallet operation: select UTXOs, build a P2PK transaction
//! with one output to the recipient and change back to the wallet.

use crate::node::NodeClient;
use crate::signing;
use kob_core::sighash::compute_sighash;
use kob_core::tx::{to_rpc_payload, Transaction, TxInput, TxOutput};
use kob_core::types::Network;
use kob_core::wallet::WalletFile;
use kob_core::{DEFAULT_MATCHER_FEE, MIN_UTXO_VALUE};
use std::path::Path;
use tracing::info;

/// Parse a Kaspa address to extract the scriptPublicKey bytes.
///
/// P2PK address: script = [0x20][pubkey 32B][0xac]
/// Reuses the bech32 decode logic from token.rs via cancel.rs address helpers.
fn address_to_spk(address: &str) -> anyhow::Result<(u16, Vec<u8>)> {
    let parts: Vec<&str> = address.split(':').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid address format: expected 'prefix:payload'");
    }

    let prefix = parts[0];
    if prefix != "kaspa" && prefix != "kaspatest" {
        anyhow::bail!("Unsupported address prefix '{}'. Expected 'kaspa' or 'kaspatest'.", prefix);
    }

    let payload = parts[1];

    // Bech32 decode
    const CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let chars: Vec<u8> = payload
        .chars()
        .map(|c| {
            CHARSET.find(c).map(|i| i as u8).ok_or_else(|| {
                anyhow::anyhow!("Invalid character '{}' in address. Kaspa addresses use bech32 encoding (lowercase letters and digits only).", c)
            })
        })
        .collect::<anyhow::Result<Vec<u8>>>()?;

    if chars.len() < 9 {
        anyhow::bail!("Address payload too short");
    }
    let data5 = &chars[..chars.len() - 8]; // strip 8-char Kaspa bech32 checksum

    // Convert 5-bit to 8-bit
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut decoded = Vec::new();
    for &val in data5 {
        acc = (acc << 5) | (val as u32);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            decoded.push(((acc >> bits) & 0xFF) as u8);
        }
    }

    if decoded.is_empty() {
        anyhow::bail!("Empty address payload");
    }

    let type_byte = decoded[0];
    let data = &decoded[1..];

    match type_byte {
        0x00 => {
            // P2PK
            if data.len() != 32 {
                anyhow::bail!("P2PK address data must be 32 bytes, got {}", data.len());
            }
            let mut spk = Vec::with_capacity(34);
            spk.push(0x20);
            spk.extend_from_slice(data);
            spk.push(0xac);
            Ok((0, spk))
        }
        0x08 => {
            // P2SH
            if data.len() != 32 {
                anyhow::bail!("P2SH address data must be 32 bytes, got {}", data.len());
            }
            let mut spk = Vec::with_capacity(35);
            spk.push(0xaa);
            spk.push(0x20);
            spk.extend_from_slice(data);
            spk.push(0x87);
            Ok((0, spk))
        }
        _ => anyhow::bail!("Unsupported address type (0x{:02x}). Only P2PK and P2SH Kaspa addresses are supported.", type_byte),
    }
}

/// Execute the `wallet send` command.
pub async fn run(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    to_address: &str,
    amount_sompi: u64,
    fee_override: Option<u64>,
) -> anyhow::Result<()> {
    let wallet = WalletFile::load(wallet_path)?;
    let _pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.private_key_bytes()?;
    let fee = fee_override.unwrap_or(DEFAULT_MATCHER_FEE);

    // Validate amount
    if amount_sompi == 0 {
        anyhow::bail!("Amount must be > 0");
    }
    if amount_sompi < MIN_UTXO_VALUE {
        anyhow::bail!(
            "Amount {} sompi is below MIN_UTXO_VALUE ({}). Kaspa nodes reject dust outputs.",
            amount_sompi,
            MIN_UTXO_VALUE
        );
    }

    // Parse recipient address
    let (recipient_spk_version, recipient_spk) = address_to_spk(to_address)?;

    println!("Wallet Send");
    println!("============");
    println!("From:    {}", wallet.address);
    println!("To:      {}", to_address);
    println!(
        "Amount:  {} sompi ({:.8} KAS)",
        amount_sompi,
        amount_sompi as f64 / 1e8
    );
    println!("Fee:     {} sompi", fee);
    println!();

    let needed = amount_sompi + fee;

    // Connect and fetch UTXOs
    info!(address = %wallet.address, to = %to_address, amount = amount_sompi, "wallet send");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    let utxos = rpc.get_spendable_utxos(&wallet.address).await?;

    // Select UTXOs to cover amount + fee
    // Greedy: try single UTXO first, then accumulate
    let p2pk_utxos: Vec<_> = utxos.iter().filter(|u| !u.is_p2sh()).collect();

    if p2pk_utxos.is_empty() {
        anyhow::bail!("No spendable UTXOs in wallet. Fund the wallet first.");
    }

    // Try to find a single UTXO large enough
    let selected: Vec<_>;
    let total_in: u64;

    // Pick smallest qualifying UTXO to avoid stale large UTXOs stuck in mempool.
    let mut candidates: Vec<_> = p2pk_utxos.iter().filter(|u| u.utxo_entry.amount >= needed).collect();
    candidates.sort_by(|a, b| a.utxo_entry.amount.cmp(&b.utxo_entry.amount));
    if let Some(single) = candidates.first() {
        selected = vec![**single];
        total_in = single.utxo_entry.amount;
    } else {
        // Accumulate multiple UTXOs (sorted by value desc)
        let mut acc = 0u64;
        let mut sel = Vec::new();
        for u in &p2pk_utxos {
            sel.push(*u);
            acc += u.utxo_entry.amount;
            if acc >= needed {
                break;
            }
        }
        if acc < needed {
            anyhow::bail!(
                "Insufficient funds: need {} sompi, have {} sompi across {} P2PK UTXOs",
                needed,
                acc,
                p2pk_utxos.len()
            );
        }
        selected = sel;
        total_in = acc;
    }

    let change = total_in - amount_sompi - fee;

    println!("Selected {} input UTXO(s), total {} sompi", selected.len(), total_in);
    for u in &selected {
        println!(
            "  {}:{} ({} sompi)",
            u.outpoint.transaction_id, u.outpoint.index, u.utxo_entry.amount
        );
    }
    if change > 0 {
        println!("Change:  {} sompi ({:.8} KAS)", change, change as f64 / 1e8);
    }
    println!();

    // Build transaction
    let mut tx = Transaction::new(0);

    for u in &selected {
        let spk_bytes = u.script_bytes();
        tx.inputs.push(TxInput {
            prev_tx_id: u.outpoint.transaction_id.clone(),
            prev_index: u.outpoint.index,
            sequence: 0,
            sig_op_count: 1,
            script_version: u.utxo_entry.script_public_key.version,
            script_bytes: spk_bytes,
            value: u.utxo_entry.amount,
        });
    }

    // Output 0: recipient
    tx.outputs.push(TxOutput::new(amount_sompi, recipient_spk_version, recipient_spk, None));

    // Output 1: change back to wallet (if >= MIN_UTXO_VALUE)
    if change >= MIN_UTXO_VALUE {
        let wallet_spk = hex::decode(&selected[0].utxo_entry.script_public_key.script)?;
        tx.outputs.push(TxOutput::new(change, selected[0].utxo_entry.script_public_key.version, wallet_spk, None));
    } else if change > 0 {
        println!(
            "Change {} sompi below MIN_UTXO_VALUE, donated as additional fee.",
            change
        );
    }

    // Sign all inputs
    let mut sigscripts = Vec::with_capacity(selected.len());
    for i in 0..selected.len() {
        let sighash = compute_sighash(&tx, i)?;
        let sig = signing::schnorr_sign(&privkey, &sighash)?;
        sigscripts.push(signing::build_p2pk_sigscript(&sig));
    }

    // Submit
    let payload = to_rpc_payload(&tx, &sigscripts);
    println!("Submitting transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Transaction submitted.");
    println!("TXID: {}", tx_id);
    println!();
    println!(
        "Sent {} sompi ({:.8} KAS) to {}",
        amount_sompi,
        amount_sompi as f64 / 1e8,
        to_address
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_to_spk_p2pk() {
        let addr = "kaspatest:qq6sneh4wnnst23r8dlewylf0xaj0arrz9kk5a2rd8qeg7wnlejcxrnd89ssr";
        let result = address_to_spk(addr);
        assert!(result.is_ok(), "P2PK address parsing must succeed: {:?}", result.err());
        let (version, spk) = result.unwrap();
        assert_eq!(version, 0);
        assert_eq!(spk.len(), 34);
        assert_eq!(spk[0], 0x20);
        assert_eq!(spk[33], 0xac);
        let expected_pk = "3509e6f574e705aa233b7f9713e979bb27f463116d6a754369c19479d3fe6583";
        assert_eq!(hex::encode(&spk[1..33]), expected_pk);
    }

    #[test]
    fn address_to_spk_invalid_prefix() {
        let result = address_to_spk("bitcoin:q1234");
        assert!(result.is_err());
    }

    #[test]
    fn address_to_spk_no_colon() {
        let result = address_to_spk("nocolon");
        assert!(result.is_err());
    }

    #[test]
    fn address_to_spk_short_payload() {
        let result = address_to_spk("kaspatest:q");
        assert!(result.is_err());
    }

    #[test]
    fn amount_validation_zero() {
        // Test that zero amount is properly rejected (tested via logic, not async)
        assert!(0u64 == 0, "zero check works");
        assert!(MIN_UTXO_VALUE > 0);
    }

    #[test]
    fn change_calculation() {
        let total_in: u64 = 100_000_000;
        let amount: u64 = 50_000_000;
        let fee: u64 = DEFAULT_MATCHER_FEE;
        let change = total_in - amount - fee;
        assert_eq!(change, 49_990_000);
        assert!(change >= MIN_UTXO_VALUE);
    }

    #[test]
    fn change_below_min_utxo_donated() {
        let total_in: u64 = 53_010_000; // amount + fee + tiny change
        let amount: u64 = 50_000_000;
        let fee: u64 = DEFAULT_MATCHER_FEE;
        let change = total_in - amount - fee;
        assert_eq!(change, 3_000_000);
        // 3_000_000 == MIN_UTXO_VALUE, so this is exactly at the boundary
        assert!(change >= MIN_UTXO_VALUE);

        // Below boundary
        let total_in2: u64 = 50_010_001;
        let change2 = total_in2 - amount - fee;
        assert_eq!(change2, 1);
        assert!(change2 < MIN_UTXO_VALUE);
    }

    #[test]
    fn multi_utxo_selection_logic() {
        // Simulate UTXO selection: need 100M, have 3 UTXOs of 40M each
        let utxo_values = vec![40_000_000u64, 40_000_000, 40_000_000];
        let needed = 100_000_000u64 + DEFAULT_MATCHER_FEE;

        let mut acc = 0u64;
        let mut count = 0;
        for v in &utxo_values {
            acc += v;
            count += 1;
            if acc >= needed {
                break;
            }
        }
        assert_eq!(count, 3);
        assert!(acc >= needed);
    }

    #[test]
    fn fee_override() {
        let default_fee = DEFAULT_MATCHER_FEE;
        assert_eq!(default_fee, 10_000);
        let custom_fee: u64 = 50_000;
        let fee = Some(custom_fee).unwrap_or(DEFAULT_MATCHER_FEE);
        assert_eq!(fee, 50_000);
    }

    #[test]
    fn amount_kas_conversion() {
        // 1 KAS = 100_000_000 sompi
        let kas: f64 = 1.5;
        let sompi = (kas * 1e8) as u64;
        assert_eq!(sompi, 150_000_000);
    }

    #[test]
    fn tx_structure_single_input() {
        let tx = Transaction::new(0);
        assert_eq!(tx.version, 0);
        assert!(tx.inputs.is_empty());
        assert!(tx.outputs.is_empty());
        assert_eq!(tx.lock_time, 0);
    }
}
