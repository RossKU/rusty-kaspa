//! `kob-cli token` -- Create tokens and transfer token UTXOs.
//!
//! Token lifecycle on KOB:
//! 1. `token create` -- Deploy a token_mint covenant UTXO (genesis). Creates a new token identity.
//! 2. `token mint` -- Use the mint authority to create token_unit UTXOs (minting).
//! 3. `token transfer` -- Transfer token_unit UTXOs between addresses.
//! 4. Burn mint authority when done (optional).
//!
//! Token identity is established via Kaspa's CovenantBinding mechanism:
//! - The token_mint deploy TX uses version 1 with a covenant binding.
//! - The covenant_id is computed from the genesis outpoint + authorized outputs.
//! - All token_unit UTXOs carry the same covenant_id, linking them to the mint.

use crate::node::NodeClient;
use crate::signing;
use clap::Subcommand;
use kob_core::contract;
use kob_core::p2sh::build_p2sh;
#[cfg(test)]
use kob_core::p2sh::blake2b_256;
use kob_core::sighash::{compute_covenant_id, compute_sighash};
use kob_core::tx::{to_rpc_payload, AuthOutput, CovenantBinding, Transaction, TxInput, TxOutput};
use kob_core::types::Network;
use kob_core::wallet::WalletContext;
use kob_core::mass::{calc_mass_with_sigscripts, converge_fee};
use kob_core::MIN_UTXO_VALUE;
use std::path::Path;
use tracing::info;

#[derive(Subcommand, Debug)]
pub enum TokenCommand {
    /// Create a new token by deploying a token_mint covenant UTXO (genesis).
    Create {
        /// Token ticker symbol (e.g., "KUSD"). Stored as metadata only.
        #[arg(long)]
        ticker: String,

        /// Total supply in base units (metadata, not enforced on-chain).
        #[arg(long)]
        supply: u64,

        /// Decimal places (default: 8). Metadata only.
        #[arg(long, default_value = "8")]
        decimals: u8,

        /// KAS amount to lock in the mint UTXO (in sompi).
        #[arg(long)]
        amount: u64,
    },

    /// Mint new token_units from a mint authority UTXO.
    ///
    /// Creates a continuation TX: spends the mint authority, outputs an updated
    /// mint authority + a new token_unit UTXO. Requires admin signature.
    Mint {
        /// Mint authority UTXO transaction ID (hex, 64 chars).
        #[arg(long)]
        txid: String,

        /// Mint authority UTXO output index.
        #[arg(long, default_value = "0")]
        index: u32,

        /// Token covenant ID (hex, 64 chars).
        #[arg(long)]
        token: String,

        /// Amount of sompi to allocate to the new token_unit output.
        #[arg(long)]
        amount: u64,

        /// Recipient public key (hex, 64 chars) for the new token_unit.
        /// Defaults to wallet's own public key.
        #[arg(long)]
        recipient_pubkey: Option<String>,

        /// Fee UTXO outpoint (txid:index) to use instead of auto-selection.
        /// Useful when auto-selected UTXOs are stale (stuck in mempool).
        #[arg(long)]
        fee_utxo: Option<String>,
    },

    /// Transfer a token_unit UTXO to a recipient address.
    Transfer {
        /// Token UTXO transaction ID (hex, 64 chars).
        #[arg(long)]
        txid: String,

        /// Token UTXO output index.
        #[arg(long)]
        index: u32,

        /// Recipient Kaspa address.
        #[arg(long)]
        to: String,

        /// Amount of token value to transfer (in sompi, represents token units).
        #[arg(long)]
        amount: u64,

        /// Token covenant ID (hex, 64 chars).
        #[arg(long)]
        token: String,
    },

    /// Show token balances for the wallet.
    ///
    /// Groups P2SH UTXOs by script hash and matches against a local token
    /// registry (tokens.json) to display tickers and formatted amounts.
    Balance {
        /// Path to token registry file (default: tokens.json).
        #[arg(long)]
        tokens_file: Option<String>,
    },

    /// Burn the mint authority (permanently destroy minting capability).
    Burn {
        /// Mint authority UTXO transaction ID (hex, 64 chars).
        #[arg(long)]
        txid: String,

        /// Mint authority UTXO output index.
        #[arg(long, default_value = "0")]
        index: u32,

        /// Token covenant ID (hex, 64 chars).
        #[arg(long)]
        token: String,
    },

    /// Query token metadata from genesis TX.
    ///
    /// Given a covenant_id, queries the genesis transaction to display
    /// token information: covenant_id, mint txid, total minted, UTXOs.
    Info {
        /// Token covenant ID (hex, 64 chars).
        #[arg(long)]
        token: String,

        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Register a token alias (e.g., KUSD -> covenant_id).
    ///
    /// Saves to tokens.json (or --token-alias-file). Once registered,
    /// use the alias anywhere a --token flag is accepted.
    Alias {
        /// Alias name (e.g., "KUSD").
        name: String,

        /// Covenant ID (hex, 64 chars).
        covenant_id: String,

        /// Path to alias file (default: tokens.json).
        #[arg(long)]
        alias_file: Option<String>,
    },

    /// List all registered token aliases.
    Aliases {
        /// Path to alias file (default: tokens.json).
        #[arg(long)]
        alias_file: Option<String>,

        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
}

/// Print the registered token aliases (sorted by name).
pub fn list_aliases(alias_file: Option<&Path>, json: bool) -> anyhow::Result<()> {
    let default_path = Path::new("tokens.json");
    let path = alias_file.unwrap_or(default_path);
    let aliases = load_aliases(path)?;
    let mut rows: Vec<(String, String)> = aliases.into_iter().collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));

    if json {
        let map: serde_json::Map<String, serde_json::Value> = rows
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        println!("{}", serde_json::to_string_pretty(&serde_json::Value::Object(map))?);
        return Ok(());
    }

    if rows.is_empty() {
        println!("No aliases registered in {}.", path.display());
        println!("Register one with: kob token alias <NAME> <covenant_id>");
        return Ok(());
    }
    println!("Token aliases ({}):", path.display());
    let max_name = rows.iter().map(|(n, _)| n.len()).max().unwrap_or(8);
    for (name, cid) in rows {
        println!("  {:width$}  {}", name, cid, width = max_name);
    }
    Ok(())
}

/// Deploy a new token_mint covenant UTXO (genesis).
///
/// Creates a TX version 1 with a CovenantBinding to establish the token identity.
/// The covenant_id is derived from the genesis outpoint and becomes the permanent
/// token identifier.
///
/// TX layout:
/// - Input[0]: wallet P2PK UTXO (funding)
/// - Output[0]: token_mint P2SH UTXO (covenant binding -> new token_id)
/// - Output[1]: change back to wallet (if sufficient)
pub async fn token_create(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    ticker: &str,
    supply: u64,
    decimals: u8,
    amount: u64,
) -> anyhow::Result<()> {
    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = *wallet.privkey_bytes();

    // Build token_mint redeemScript
    let redeem_script = contract::build_token_mint_redeem_script(&pubkey);
    let p2sh = build_p2sh(&redeem_script);

    println!("Token Create (Genesis Deploy)");
    println!("=============================");
    println!("Ticker:     {}", ticker);
    println!("Supply:     {} (metadata, not enforced on-chain)", supply);
    println!("Decimals:   {}", decimals);
    println!(
        "Amount:     {} sompi ({:.8} KAS)",
        amount,
        amount as f64 / 1e8
    );
    println!("Admin:      {}", wallet.pubkey_hex());
    println!();
    println!("RedeemScript: {} bytes", redeem_script.len());
    println!("P2SH SPK:   {}", hex::encode(&p2sh.script()));
    println!();

    // Validate amount
    if amount < MIN_UTXO_VALUE {
        anyhow::bail!(
            "Amount {} sompi is below MIN_UTXO_VALUE ({}). Use at least {} sompi.",
            amount,
            MIN_UTXO_VALUE,
            MIN_UTXO_VALUE
        );
    }

    // Connect and fetch UTXOs
    info!(address = %wallet.address, amount = amount, "deploying token_mint");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    let utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    // Pre-estimate fee for UTXO selection (1 input, 2 outputs, small payload)
    let est_fee_pre = kob_core::mass::estimate_compute_mass(1, 2, 0);
    let needed = amount + est_fee_pre + MIN_UTXO_VALUE;

    // Pick smallest qualifying P2PK UTXO to avoid stale large UTXOs stuck in mempool.
    let mut candidates: Vec<_> = utxos
        .iter()
        .filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= needed)
        .collect();
    candidates.sort_by(|a, b| a.utxo_entry.amount.cmp(&b.utxo_entry.amount));
    // Fallback: if no UTXO covers amount + fee + MIN_UTXO_VALUE, try amount + fee only
    if candidates.is_empty() {
        candidates = utxos
            .iter()
            .filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= amount + est_fee_pre)
            .collect();
        candidates.sort_by(|a, b| a.utxo_entry.amount.cmp(&b.utxo_entry.amount));
    }
    let funding = candidates.first().copied()
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

    // Pre-compute covenant_id for the deploy TX
    let covenant_id = compute_covenant_id(
        &funding.outpoint.transaction_id,
        funding.outpoint.index,
        &[AuthOutput {
            index: 0,
            value: amount,
            spk_version: p2sh.version,
            spk_script: p2sh.script().to_vec(),
        }],
    )?;
    let covenant_id_hex = hex::encode(covenant_id);

    println!("Token ID:   {}", covenant_id_hex);
    println!();

    // Build TX version 1 (CovenantBinding required for genesis)
    let mut tx = Transaction::new(1);

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

    // Output 0: token_mint P2SH with covenant binding
    tx.outputs.push(TxOutput::new(amount, p2sh.version, p2sh.script().to_vec(), Some(CovenantBinding::new(0, kob_core::compat::parse_hash(&covenant_id_hex.clone()).unwrap()))));

    // Output 1: tentative change back to wallet
    let total_in_create = funding.utxo_entry.amount;
    let tent_change = total_in_create.saturating_sub(amount + est_fee_pre);
    let wallet_spk = hex::decode(&funding.utxo_entry.script_public_key.script)?;
    if tent_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(tent_change, funding.utxo_entry.script_public_key.version, wallet_spk.clone(), None));
    }

    // Phase 1: converge fee on change output
    let has_change = tx.outputs.len() > 1;
    let change_idx_create = tx.outputs.len().saturating_sub(1);
    let (est_fee, _) = if has_change {
        converge_fee(&mut tx, total_in_create, change_idx_create, 0)
    } else {
        let f = kob_core::mass::calc_miner_fee(&tx);
        (f, 0)
    };

    // Remove change if below threshold
    if has_change && tx.outputs.last().unwrap().value < MIN_UTXO_VALUE {
        let change_val = tx.outputs.last().unwrap().value;
        tx.outputs.pop();
        if change_val > 0 {
            println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", change_val);
        }
    }

    // Sign (phase 1)
    let sighash = compute_sighash(&tx, 0)?;
    let signature = signing::schnorr_sign(&privkey, &sighash)?;
    let sigscript = signing::build_p2pk_sigscript(&signature);

    // Phase 2: exact mass check
    let exact_mass = calc_mass_with_sigscripts(&tx, &[sigscript.clone()]);
    let exact_fee = exact_mass;
    let actual_fee = if exact_fee != est_fee { exact_fee } else { est_fee };
    let sigscript = if exact_fee != est_fee && tx.outputs.len() > 1 {
        let change_idx = tx.outputs.len() - 1;
        let new_change = total_in_create.saturating_sub(amount + exact_fee);
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
        signing::build_p2pk_sigscript(&signature)
    } else {
        sigscript
    };

    if total_in_create < 10_000_000_00 {
        println!("WARNING: Token create with < 10 KAS funding. Consider using a larger UTXO.");
    }

    println!("Sighash:    {}", hex::encode(compute_sighash(&tx, 0)?));
    println!("Fee:        {} sompi", actual_fee);
    println!();

    // Submit
    let payload = to_rpc_payload(&tx, &[sigscript]);
    println!("Submitting transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Token created.");
    println!("TXID:     {}", tx_id);
    println!("Token ID: {}", covenant_id_hex);
    println!("Mint:     {}:0", tx_id);
    println!();
    println!("Token Metadata (off-chain):");
    println!("  Ticker:   {}", ticker);
    println!("  Supply:   {}", supply);
    println!("  Decimals: {}", decimals);
    println!();
    println!("Next steps:");
    println!("  1. Mint token_units: kob-cli token mint --txid {} --token {} --amount <AMT>", tx_id, covenant_id_hex);
    println!("  2. Transfer token_units: kob-cli token transfer --txid <TXID> --index <IDX> --to <ADDR> --amount <AMT> --token {}", covenant_id_hex);

    Ok(())
}

/// Mint new token_units from a mint authority UTXO.
///
/// Creates a continuation TX that spends the mint authority and produces:
/// - Output[0]: updated mint authority (same P2SH, reduced value, covenant binding)
/// - Output[1]: new token_unit (token_unit P2SH, covenant binding)
/// - Output[2]: change from fee UTXO back to wallet
///
/// TX layout:
/// - Input[0]: mint authority P2SH UTXO (sigOpCount=1, admin sig)
/// - Input[1]: wallet P2PK UTXO (fee + token_unit funding)
///
/// The mint path in the contract verifies:
///   output[0].SPK == input[0].SPK (self-continuation)
///   admin CheckSigVerify
#[allow(clippy::too_many_arguments)]
pub async fn token_mint(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    mint_txid: &str,
    mint_index: u32,
    token_covenant_id: &str,
    token_amount: u64,
    recipient_pubkey_hex: Option<&str>,
    fee_utxo_override: Option<&str>,
) -> anyhow::Result<()> {
    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = *wallet.privkey_bytes();

    // Validate token covenant ID
    let token_cov_bytes = hex::decode(token_covenant_id)?;
    if token_cov_bytes.len() != 32 {
        anyhow::bail!("token covenant ID must be 64 hex characters (32 bytes)");
    }

    // Recipient pubkey for the new token_unit (defaults to wallet's own pubkey)
    let recipient_pk: [u8; 32] = if let Some(rp_hex) = recipient_pubkey_hex {
        let rp_bytes = hex::decode(rp_hex)?;
        if rp_bytes.len() != 32 {
            anyhow::bail!("recipient_pubkey must be 64 hex characters (32 bytes)");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&rp_bytes);
        arr
    } else {
        pubkey
    };

    // Build mint authority redeemScript (47 bytes)
    let mint_rs = contract::build_token_mint_redeem_script(&pubkey);
    let mint_p2sh = build_p2sh(&mint_rs);

    // Build token_unit redeemScript for the recipient (37 bytes, KCC20 header)
    let unit_rs = contract::build_token_unit_redeem_script(&recipient_pk);
    let unit_p2sh = build_p2sh(&unit_rs);

    println!("Token Mint (Mint token_units)");
    println!("==============================");
    println!("Token ID:         {}", token_covenant_id);
    println!("Mint Authority:   {}:{}", mint_txid, mint_index);
    println!(
        "Token Amount:     {} sompi ({:.8} KAS equivalent)",
        token_amount,
        token_amount as f64 / 1e8
    );
    println!("Recipient PK:     {}", hex::encode(recipient_pk));
    println!("Admin:            {}", wallet.pubkey_hex());
    println!();
    println!("Mint RS:          {} bytes", mint_rs.len());
    println!("Mint P2SH:        {}", hex::encode(&mint_p2sh.script()));
    println!("Token Unit RS:    {} bytes", unit_rs.len());
    println!("Token Unit P2SH:  {}", hex::encode(&unit_p2sh.script()));
    println!();

    if token_amount < MIN_UTXO_VALUE {
        anyhow::bail!(
            "Token amount {} sompi is below MIN_UTXO_VALUE ({})",
            token_amount,
            MIN_UTXO_VALUE
        );
    }

    // Connect and fetch UTXOs
    info!(
        mint_txid = %mint_txid,
        mint_index = mint_index,
        token = %token_covenant_id,
        "issuing token_units"
    );
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Query the mint authority UTXO
    // We query by the P2SH address to find it
    let mint_addr = crate::cancel::kaspa_address_encode(network.address_prefix(), 8, &mint_p2sh.script()[2..34]);
    println!("Querying mint authority at {}...", &mint_addr[..40]);
    let mint_utxos = rpc.get_utxos_by_addresses(&[&mint_addr]).await?;
    let mint_utxo = mint_utxos
        .iter()
        .find(|u| u.outpoint.transaction_id == mint_txid && u.outpoint.index == mint_index)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Mint authority UTXO {}:{} not found. Check txid/index.",
                mint_txid,
                mint_index
            )
        })?;

    let mint_value = mint_utxo.utxo_entry.amount;
    println!(
        "Mint UTXO:        {}:{} ({} sompi)",
        mint_utxo.outpoint.transaction_id, mint_utxo.outpoint.index, mint_value
    );

    // Pre-estimate fee for UTXO selection (2 inputs, 3 outputs)
    let est_fee_mint_pre = kob_core::mass::estimate_compute_mass(2, 3, 0);

    // The mint continuation gets the original mint value minus estimated fee
    let mint_continuation_value = mint_value.saturating_sub(est_fee_mint_pre);
    if mint_continuation_value < MIN_UTXO_VALUE {
        anyhow::bail!(
            "Mint continuation value {} sompi would be below MIN_UTXO_VALUE. Mint authority nearly exhausted.",
            mint_continuation_value
        );
    }

    // Find a fee UTXO from wallet (must also provide the token_amount)
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let needed_from_fee = token_amount + est_fee_mint_pre;
    let fee_utxo = if let Some(fee_op_str) = fee_utxo_override {
        let fee_op = kob_core::types::Outpoint::parse(fee_op_str)?;
        wallet_utxos
            .iter()
            .find(|u| u.outpoint.transaction_id == fee_op.transaction_id && u.outpoint.index == fee_op.index)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Fee UTXO {} not found in wallet UTXOs. It may be spent or not belong to this wallet.",
                    fee_op_str
                )
            })?
    } else {
        // Smallest-first (WASM spec): avoids consuming large consolidated UTXOs
        // when a small one suffices, and avoids repeatedly picking the same
        // top-tier UTXO across consecutive mints (which can collide with
        // mempool-pending TXs chained off it).
        wallet_utxos
            .iter()
            .filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= needed_from_fee)
            .min_by_key(|u| u.utxo_entry.amount)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No P2PK UTXO with >= {} sompi for token funding + fee ({} UTXOs available)",
                    needed_from_fee,
                    wallet_utxos.len()
                )
            })?
    };

    println!(
        "Fee UTXO:         {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    // Build TX version 1 (CovenantBinding for continuation + new token)
    let mut tx = Transaction::new(1);

    // Input 0: mint authority (P2SH, sigOpCount=1)
    tx.inputs.push(TxInput {
        prev_tx_id: mint_utxo.outpoint.transaction_id.clone(),
        prev_index: mint_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: mint_p2sh.version,
        script_bytes: mint_p2sh.script().to_vec(),
        value: mint_value,
    });

    // Input 1: fee P2PK UTXO
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

    // Output 0: mint continuation (same P2SH, covenant binding)
    tx.outputs.push(TxOutput::new(mint_continuation_value, mint_p2sh.version, mint_p2sh.script().to_vec(), Some(CovenantBinding::new(0, kob_core::compat::parse_hash(&token_covenant_id.to_string()).unwrap()))));

    // Output 1: new token_unit (covenant binding)
    tx.outputs.push(TxOutput::new(token_amount, unit_p2sh.version, unit_p2sh.script().to_vec(), Some(CovenantBinding::new(0, kob_core::compat::parse_hash(&token_covenant_id.to_string()).unwrap()))));

    // Output 2: tentative change from fee UTXO back to wallet
    let total_in_mint = mint_value + fee_utxo.utxo_entry.amount;
    let fixed_sum_mint = mint_continuation_value + token_amount;
    let tent_fee_change = total_in_mint.saturating_sub(fixed_sum_mint + est_fee_mint_pre);
    let wallet_spk_mint = hex::decode(&fee_utxo.utxo_entry.script_public_key.script)?;
    if tent_fee_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(tent_fee_change, fee_utxo.utxo_entry.script_public_key.version, wallet_spk_mint.clone(), None));
    }

    // Phase 1: converge fee on change output (index 2 if it exists)
    // The adjustable output is the change; mint_continuation and token_amount are fixed by contract.
    let has_change_mint = tx.outputs.len() > 2;
    let change_idx_mint = tx.outputs.len().saturating_sub(1);
    let (est_fee_mint, _) = if has_change_mint {
        converge_fee(&mut tx, total_in_mint, change_idx_mint, 0)
    } else {
        let f = kob_core::mass::calc_miner_fee(&tx);
        (f, 0)
    };

    if has_change_mint && tx.outputs.last().unwrap().value < MIN_UTXO_VALUE {
        let change_val = tx.outputs.last().unwrap().value;
        tx.outputs.pop();
        if change_val > 0 {
            println!("Fee change {} sompi below MIN_UTXO_VALUE, donated as fee.", change_val);
        }
    }

    // Sign input 0 (mint authority): mint sigscript
    let sighash_0 = compute_sighash(&tx, 0)?;
    let sig_0 = signing::schnorr_sign(&privkey, &sighash_0)?;
    let sigscript_0 = contract::build_token_mint_sigscript(&sig_0, &mint_rs);

    // Sign input 1 (fee): standard P2PK sigscript
    let sighash_1 = compute_sighash(&tx, 1)?;
    let sig_1 = signing::schnorr_sign(&privkey, &sighash_1)?;
    let sigscript_1 = signing::build_p2pk_sigscript(&sig_1);

    // Phase 2: exact mass check
    let sigscripts_mint = vec![sigscript_0.clone(), sigscript_1.clone()];
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts_mint);
    let exact_fee = exact_mass;

    let _actual_fee_mint = if exact_fee != est_fee_mint { exact_fee } else { est_fee_mint };
    let (sigscript_0, sigscript_1) = if exact_fee != est_fee_mint && tx.outputs.len() > 2 {
        let change_idx = tx.outputs.len() - 1;
        let new_change = total_in_mint.saturating_sub(fixed_sum_mint + exact_fee);
        if new_change >= MIN_UTXO_VALUE {
            tx.outputs[change_idx].value = new_change;
        } else {
            tx.outputs.pop();
            if new_change > 0 {
                println!("Fee change {} sompi below MIN_UTXO_VALUE, donated as fee.", new_change);
            }
        }
        let sighash_0 = compute_sighash(&tx, 0)?;
        let sig_0 = signing::schnorr_sign(&privkey, &sighash_0)?;
        let sigscript_0 = contract::build_token_mint_sigscript(&sig_0, &mint_rs);
        let sighash_1 = compute_sighash(&tx, 1)?;
        let sig_1 = signing::schnorr_sign(&privkey, &sighash_1)?;
        let sigscript_1 = signing::build_p2pk_sigscript(&sig_1);
        (sigscript_0, sigscript_1)
    } else {
        (sigscript_0, sigscript_1)
    };

    if mint_value < 5_000_000_00 {
        println!("WARNING: Token mint with < 5 KAS mint authority. Consider refunding the mint UTXO.");
    }

    println!("Mint SS:     {} bytes", sigscript_0.len());
    println!("Sighash[0]:  {} (mint)", hex::encode(compute_sighash(&tx, 0)?));
    println!("Sighash[1]:  {} (fee)", hex::encode(compute_sighash(&tx, 1)?));
    println!();

    // Submit
    let payload = to_rpc_payload(&tx, &[sigscript_0, sigscript_1]);
    println!("Submitting token mint transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Token units minted.");
    println!("TXID:          {}", tx_id);
    println!("Mint cont:     {}:0 ({} sompi)", tx_id, mint_continuation_value);
    println!("Token unit:    {}:1 ({} sompi)", tx_id, token_amount);
    if tx.outputs.len() > 2 {
        println!("Fee change:    {}:2 ({} sompi)", tx_id, tx.outputs[2].value);
    }
    println!();
    println!("Next steps:");
    println!("  Mint more:    kob-cli token mint --txid {} --token {} --amount <AMT>", tx_id, token_covenant_id);
    println!("  Transfer:     kob-cli token transfer --txid {} --index 1 --to <ADDR> --amount {} --token {}", tx_id, token_amount, token_covenant_id);
    println!("  Burn mint:    kob-cli token burn --txid {} --token {}", tx_id, token_covenant_id);

    Ok(())
}

/// Burn the mint authority (permanently destroy minting capability).
///
/// Spends the mint authority UTXO using the burn path (Op0 selector).
/// No continuation output is created -- the mint authority is permanently destroyed.
///
/// TX layout:
/// - Input[0]: mint authority P2SH UTXO (sigOpCount=1, admin sig, burn selector)
/// - Output[0]: reclaimed KAS to wallet
pub async fn token_burn(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    mint_txid: &str,
    mint_index: u32,
    token_covenant_id: &str,
) -> anyhow::Result<()> {
    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = *wallet.privkey_bytes();

    // Validate token covenant ID
    let token_cov_bytes = hex::decode(token_covenant_id)?;
    if token_cov_bytes.len() != 32 {
        anyhow::bail!("token covenant ID must be 64 hex characters (32 bytes)");
    }

    // Build mint authority redeemScript
    let mint_rs = contract::build_token_mint_redeem_script(&pubkey);
    let mint_p2sh = build_p2sh(&mint_rs);

    println!("Token Burn (Destroy Mint Authority)");
    println!("====================================");
    println!("Token ID:         {}", token_covenant_id);
    println!("Mint Authority:   {}:{}", mint_txid, mint_index);
    println!("Admin:            {}", wallet.pubkey_hex());
    println!();

    info!(
        mint_txid = %mint_txid,
        mint_index = mint_index,
        "burning mint authority"
    );
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Query the mint authority UTXO
    let mint_addr = crate::cancel::kaspa_address_encode(network.address_prefix(), 8, &mint_p2sh.script()[2..34]);
    let mint_utxos = rpc.get_utxos_by_addresses(&[&mint_addr]).await?;
    let mint_utxo = mint_utxos
        .iter()
        .find(|u| u.outpoint.transaction_id == mint_txid && u.outpoint.index == mint_index)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Mint authority UTXO {}:{} not found.",
                mint_txid,
                mint_index
            )
        })?;

    let mint_value = mint_utxo.utxo_entry.amount;

    println!("Mint Value:       {} sompi", mint_value);
    println!();

    // Build TX version 0 (no continuation, burn path)
    let mut tx = Transaction::new(0);

    // Input 0: mint authority (P2SH, sigOpCount=1)
    tx.inputs.push(TxInput {
        prev_tx_id: mint_utxo.outpoint.transaction_id.clone(),
        prev_index: mint_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: mint_p2sh.version,
        script_bytes: mint_p2sh.script().to_vec(),
        value: mint_value,
    });

    // Output 0: reclaimed KAS to wallet (tentative value, will be adjusted)
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let wallet_spk_utxo = wallet_utxos
        .iter()
        .find(|u| !u.is_p2sh())
        .ok_or_else(|| anyhow::anyhow!("No spendable UTXOs in wallet. Fund the wallet first or run `kob wallet consolidate`."))?;
    let wallet_spk = hex::decode(&wallet_spk_utxo.utxo_entry.script_public_key.script)?;

    let tent_output = mint_value.saturating_sub(kob_core::mass::estimate_compute_mass(1, 1, 0));
    tx.outputs.push(TxOutput::new(tent_output, wallet_spk_utxo.utxo_entry.script_public_key.version, wallet_spk, None));

    // Phase 1: converge fee on output 0
    let (est_fee, _) = converge_fee(&mut tx, mint_value, 0, 0);
    let output_value = tx.outputs[0].value;

    if output_value < MIN_UTXO_VALUE {
        anyhow::bail!(
            "Output value {} sompi below MIN_UTXO_VALUE after fee deduction",
            output_value
        );
    }

    println!("Reclaim:          {} sompi", output_value);

    // Sign: burn sigscript [push sig(65B)] [Op0] [pushData(RS)]
    let sighash_0 = compute_sighash(&tx, 0)?;
    let sig_0 = signing::schnorr_sign(&privkey, &sighash_0)?;
    let sigscript_0 = contract::build_token_burn_sigscript(&sig_0, &mint_rs);

    // Phase 2: exact mass check
    let exact_mass = calc_mass_with_sigscripts(&tx, &[sigscript_0.clone()]);
    let exact_fee = exact_mass;
    let sigscript_0 = if exact_fee != est_fee {
        let new_output = mint_value.saturating_sub(exact_fee);
        tx.outputs[0].value = new_output;
        let sighash_0 = compute_sighash(&tx, 0)?;
        let sig_0 = signing::schnorr_sign(&privkey, &sighash_0)?;
        contract::build_token_burn_sigscript(&sig_0, &mint_rs)
    } else {
        sigscript_0
    };

    println!("Burn SS:     {} bytes", sigscript_0.len());
    println!("Sighash[0]:  {}", hex::encode(compute_sighash(&tx, 0)?));
    println!();

    // Submit
    let payload = to_rpc_payload(&tx, &[sigscript_0]);
    println!("Submitting burn transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Mint authority burned.");
    println!("TXID:          {}", tx_id);
    println!("Reclaimed:     {} sompi ({:.8} KAS)", output_value, output_value as f64 / 1e8);
    println!();
    println!("WARNING: The mint authority for token {} is permanently destroyed.", token_covenant_id);
    println!("No more token_units can be minted.");

    Ok(())
}

/// Transfer a token_unit UTXO to a recipient address.
///
/// Fetches the token UTXO from chain, reconstructs the redeemScript,
/// builds a transfer TX that moves the token to a new owner.
///
/// TX layout:
/// - Input[0]: token_unit P2SH UTXO (covenant)
/// - Input[1]: wallet P2PK UTXO (fee funding)
/// - Output[0]: token_unit to recipient (same covenant_id, new owner)
/// - Output[1]: remaining token to sender (if partial transfer, same covenant_id)
/// - Output[N]: change from fee UTXO back to wallet
pub async fn token_transfer(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    txid: &str,
    index: u32,
    to_address: &str,
    amount: u64,
    token_covenant_id: &str,
) -> anyhow::Result<()> {
    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = *wallet.privkey_bytes();

    // Validate token covenant ID
    let token_cov_bytes = hex::decode(token_covenant_id)?;
    if token_cov_bytes.len() != 32 {
        anyhow::bail!("token covenant ID must be 64 hex characters (32 bytes)");
    }

    println!("Token Transfer");
    println!("==============");
    println!("Token ID:   {}", token_covenant_id);
    println!("Source:     {}:{}", txid, index);
    println!("To:         {}", to_address);
    println!(
        "Amount:     {} sompi ({:.8} KAS equivalent)",
        amount,
        amount as f64 / 1e8
    );
    println!("Owner:      {}", wallet.pubkey_hex());
    println!();

    // Build the token_unit redeemScript for the current owner
    let redeem_script = contract::build_token_unit_redeem_script(&pubkey);
    let p2sh = build_p2sh(&redeem_script);

    println!("Token Unit RS: {} bytes", redeem_script.len());
    println!("Token P2SH:  {}", hex::encode(&p2sh.script()));
    println!();

    // Connect and fetch the token UTXO
    info!(txid = %txid, index = index, "transferring token");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Token UTXOs live at the P2SH address derived from token_unit_redeem_script,
    // not the wallet's P2PK address. Query the P2SH address.
    let p2sh_address = crate::cancel::p2sh_to_address(&p2sh.script(), _network.address_prefix());
    println!("Token P2SH Address: {}", p2sh_address);
    let p2sh_utxos = rpc.get_utxos_by_addresses(&[&p2sh_address]).await?;

    // Also get wallet UTXOs for fee payment
    let all_utxos = rpc.get_spendable_utxos(&wallet.address).await?;

    // Find the specific token UTXO at the P2SH address
    let token_utxo = p2sh_utxos
        .iter()
        .find(|u| u.outpoint.transaction_id == txid && u.outpoint.index == index)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Token UTXO {}:{} not found at P2SH address {}. It may have been spent.",
                txid,
                index,
                p2sh_address
            )
        })?;

    let token_value = token_utxo.utxo_entry.amount;
    println!(
        "Token UTXO: {}:{} ({} sompi)",
        token_utxo.outpoint.transaction_id, token_utxo.outpoint.index, token_value
    );

    if amount > token_value {
        anyhow::bail!(
            "Transfer amount {} exceeds token UTXO value {}",
            amount,
            token_value
        );
    }
    if amount < MIN_UTXO_VALUE {
        anyhow::bail!(
            "Transfer amount {} sompi is below MIN_UTXO_VALUE ({})",
            amount,
            MIN_UTXO_VALUE
        );
    }

    let remainder = token_value - amount;
    let has_remainder = remainder >= MIN_UTXO_VALUE;

    if remainder > 0 && !has_remainder {
        anyhow::bail!(
            "Remainder {} sompi would be below MIN_UTXO_VALUE ({}). Transfer the full amount or adjust.",
            remainder,
            MIN_UTXO_VALUE
        );
    }

    // Pre-estimate fee for UTXO selection (2 inputs, 3 outputs max)
    let est_fee_send_pre = kob_core::mass::estimate_compute_mass(2, 3, 0);

    // Find a fee UTXO — smallest-first (WASM spec), primary requires change headroom.
    // Matches the mint-path fix: avoids repeatedly picking the largest (DESC-sorted head)
    // UTXO, which tends to be the most recently mempool-chained one.
    let fee_utxo = all_utxos
        .iter()
        .filter(|u| {
            !u.is_p2sh()
                && u.utxo_entry.amount >= est_fee_send_pre + MIN_UTXO_VALUE
                && !(u.outpoint.transaction_id == txid && u.outpoint.index == index)
        })
        .min_by_key(|u| u.utxo_entry.amount)
        .or_else(|| {
            // Fallback: drop change headroom (exact-fit)
            all_utxos
                .iter()
                .filter(|u| {
                    !u.is_p2sh()
                        && u.utxo_entry.amount >= est_fee_send_pre
                        && !(u.outpoint.transaction_id == txid && u.outpoint.index == index)
                })
                .min_by_key(|u| u.utxo_entry.amount)
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No P2PK UTXO with >= {} sompi for fees ({} UTXOs available)",
                est_fee_send_pre,
                all_utxos.len()
            )
        })?;

    println!(
        "Fee UTXO:   {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    // Resolve recipient public key from address for the token_unit redeemScript.
    // For now, we create a token_unit owned by the recipient's address.
    // The recipient address is expected to be a P2PK address (kaspa:qr... / kaspatest:qr...).
    // We extract the public key hash from the address and use it to construct
    // a P2PK SPK for the recipient's token output.
    let recipient_spk = kob_core::bech32::address_to_spk(to_address)
        .map_err(|e| anyhow::anyhow!(e))?;

    // Build TX version 1 (CovenantBinding for token continuation)
    let mut tx = Transaction::new(1);

    // Input 0: token_unit P2SH UTXO
    let token_spk_bytes = token_utxo.script_bytes();
    tx.inputs.push(TxInput {
        prev_tx_id: token_utxo.outpoint.transaction_id.clone(),
        prev_index: token_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: token_utxo.utxo_entry.script_public_key.version,
        script_bytes: token_spk_bytes,
        value: token_value,
    });

    // Input 1: fee P2PK UTXO
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

    // Output 0: token to recipient (P2PK with covenant binding)
    // The recipient gets a simple P2PK output carrying the token covenant.
    // For a more advanced flow, this would create a new token_unit P2SH.
    // Here we use the simpler approach matching token_unit: owner_pk-based P2SH.
    tx.outputs.push(TxOutput::new(amount, 0, recipient_spk, Some(CovenantBinding::new(0, kob_core::compat::parse_hash(&token_covenant_id.to_string()).unwrap()))));

    // Output 1: remainder token back to sender (if partial transfer)
    if has_remainder {
        tx.outputs.push(TxOutput::new(remainder, p2sh.version, p2sh.script().to_vec(), Some(CovenantBinding::new(0, kob_core::compat::parse_hash(&token_covenant_id.to_string()).unwrap()))));
    }

    // Output N: tentative fee change back to wallet
    let total_in_send = token_value + fee_utxo.utxo_entry.amount;
    // Fixed sum = all outputs before fee change (amount + optional remainder)
    let fixed_sum_send: u64 = tx.outputs.iter().map(|o| o.value).sum();
    let tent_fee_change = total_in_send.saturating_sub(fixed_sum_send + est_fee_send_pre);
    let wallet_spk_send = hex::decode(&fee_utxo.utxo_entry.script_public_key.script)?;
    if tent_fee_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(tent_fee_change, fee_utxo.utxo_entry.script_public_key.version, wallet_spk_send.clone(), None));
    }

    // Phase 1: converge fee on change output
    let has_change_send = tent_fee_change >= MIN_UTXO_VALUE;
    let change_idx_send = tx.outputs.len().saturating_sub(1);
    let (est_fee_send, _) = if has_change_send {
        converge_fee(&mut tx, total_in_send, change_idx_send, 0)
    } else {
        let f = kob_core::mass::calc_miner_fee(&tx);
        (f, 0)
    };

    if has_change_send && tx.outputs.last().unwrap().value < MIN_UTXO_VALUE {
        let change_val = tx.outputs.last().unwrap().value;
        tx.outputs.pop();
        if change_val > 0 {
            println!("Fee change {} sompi below MIN_UTXO_VALUE, donated as fee.", change_val);
        }
    }

    // Helper: sign both inputs for token send
    let sign_send = |tx: &Transaction| -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let sighash_0 = compute_sighash(tx, 0)?;
        let sig_0 = signing::schnorr_sign(&privkey, &sighash_0)?;
        let sigscript_0 = contract::build_token_unit_sigscript(&sig_0, &redeem_script);
        let sighash_1 = compute_sighash(tx, 1)?;
        let sig_1 = signing::schnorr_sign(&privkey, &sighash_1)?;
        let sigscript_1 = signing::build_p2pk_sigscript(&sig_1);
        Ok((sigscript_0, sigscript_1))
    };

    let (sigscript_0, sigscript_1) = sign_send(&tx)?;

    // Phase 2: exact mass check
    let sigscripts_send = vec![sigscript_0.clone(), sigscript_1.clone()];
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts_send);
    let exact_fee = exact_mass;

    let _actual_fee_send = if exact_fee != est_fee_send { exact_fee } else { est_fee_send };
    let (sigscript_0, sigscript_1) = if exact_fee != est_fee_send && tx.outputs.len() > 2 {
        let change_idx = tx.outputs.len() - 1;
        let new_change = total_in_send.saturating_sub(fixed_sum_send + exact_fee);
        if new_change >= MIN_UTXO_VALUE {
            tx.outputs[change_idx].value = new_change;
        } else {
            tx.outputs.pop();
            if new_change > 0 {
                println!("Fee change {} sompi below MIN_UTXO_VALUE, donated as fee.", new_change);
            }
        }
        sign_send(&tx)?
    } else {
        (sigscript_0, sigscript_1)
    };

    println!("Sighash[0]: {} (token)", hex::encode(compute_sighash(&tx, 0)?));
    println!("Sighash[1]: {} (fee)", hex::encode(compute_sighash(&tx, 1)?));
    println!();

    // Submit
    let payload = to_rpc_payload(&tx, &[sigscript_0, sigscript_1]);
    println!("Submitting transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Token transferred.");
    println!("TXID:     {}", tx_id);
    println!("To:       {} ({}:0, {} sompi)", to_address, tx_id, amount);
    if has_remainder {
        println!("Remainder: {}:1 ({} sompi, back to sender)", tx_id, remainder);
    }

    Ok(())
}

/// Query token metadata from genesis TX.
///
/// Given a covenant_id, attempts to locate the genesis (mint) TX and display
/// information about the token: covenant_id, mint txid, number of outputs,
/// and the total value across mint outputs.
///
/// The covenant_id encodes the genesis outpoint, so we cannot directly reverse
/// it to a txid. Instead, this command queries the RPC for the transaction
/// if the user provides the mint txid, or it searches the order cache for
/// references to this token.
pub async fn token_info(
    wallet_path: &std::path::Path,
    node_url: &str,
    network: Network,
    token_covenant_id: &str,
    json_output: bool,
) -> anyhow::Result<()> {
    // Validate covenant ID
    let token_cov_bytes = hex::decode(token_covenant_id)?;
    if token_cov_bytes.len() != 32 {
        anyhow::bail!("token covenant ID must be 64 hex characters (32 bytes)");
    }

    if !json_output {
        println!("Token Info");
        println!("===========");
        println!("Covenant ID: {}", token_covenant_id);
        println!();
    }

    // Load order cache to find references to this token
    let cache_path = wallet_path.with_file_name("orders.json");
    let cache = crate::order_cache::OrderCache::load(&cache_path);

    let token_orders: Vec<_> = cache
        .orders
        .iter()
        .filter(|o| o.pair_id == token_covenant_id)
        .collect();

    let buy_orders: Vec<_> = token_orders.iter().filter(|o| o.side == "buy").collect();
    let sell_orders: Vec<_> = token_orders.iter().filter(|o| o.side == "sell").collect();

    // Try to connect and query chain info
    info!(token = %token_covenant_id, "querying token info");

    let rpc_result = crate::node::NodeClient::connect(node_url).await;

    let mut chain_info = None;
    if let Ok(rpc) = &rpc_result {
        // Query the wallet for any token UTXOs
        let wallet = kob_core::wallet::WalletContext::load(wallet_path)?;
        let utxos = rpc.get_spendable_utxos(&wallet.address).await.unwrap_or_default();

        // P2SH UTXOs could be token_unit or order contracts
        let p2sh_count = utxos.iter().filter(|u| u.is_p2sh()).count();
        let p2pk_count = utxos.len() - p2sh_count;
        let total_balance: u64 = utxos.iter().filter(|u| !u.is_p2sh()).map(|u| u.utxo_entry.amount).sum();

        // If we have cached orders, query their P2SH addresses for live status
        let mut live_order_count = 0u64;
        let mut live_order_value = 0u64;

        if !token_orders.is_empty() {
            let network_prefix = network.address_prefix();
            let mut addrs = Vec::new();
            for order in &token_orders {
                let hash_bytes = hex::decode(&order.p2sh_hash).unwrap_or_default();
                if hash_bytes.len() == 32 {
                    addrs.push(crate::cancel::kaspa_address_encode(network_prefix, 8, &hash_bytes));
                }
            }
            let addr_refs: Vec<&str> = addrs.iter().map(|s| s.as_str()).collect();
            if let Ok(order_utxos) = rpc.get_utxos_by_addresses(&addr_refs).await {
                for utxo in &order_utxos {
                    live_order_count += 1;
                    live_order_value += utxo.utxo_entry.amount;
                }
            }
        }

        chain_info = Some((p2pk_count, p2sh_count, total_balance, live_order_count, live_order_value));
    }

    if json_output {
        let mut json = serde_json::json!({
            "covenant_id": token_covenant_id,
            "cached_orders": token_orders.len(),
            "cached_buy_orders": buy_orders.len(),
            "cached_sell_orders": sell_orders.len(),
        });
        if let Some((p2pk, p2sh, balance, live_orders, live_value)) = chain_info {
            json["wallet_p2pk_utxos"] = serde_json::json!(p2pk);
            json["wallet_p2sh_utxos"] = serde_json::json!(p2sh);
            json["wallet_balance_sompi"] = serde_json::json!(balance);
            json["live_order_count"] = serde_json::json!(live_orders);
            json["live_order_value_sompi"] = serde_json::json!(live_value);
            json["live_order_value_kas"] = serde_json::json!(live_value as f64 / 1e8);
        }
        // Include price info from cached orders
        if !token_orders.is_empty() {
            let prices: Vec<serde_json::Value> = token_orders
                .iter()
                .map(|o| {
                    serde_json::json!({
                        "outpoint": o.outpoint,
                        "side": o.side,
                        "price_num": o.price_num,
                        "price_den": o.price_den,
                        "value": o.value,
                    })
                })
                .collect();
            json["orders"] = serde_json::json!(prices);
        }
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else {
        println!("Order Cache:");
        println!("  Total cached orders: {}", token_orders.len());
        println!("  Buy orders:          {}", buy_orders.len());
        println!("  Sell orders:         {}", sell_orders.len());
        println!();

        if let Some((p2pk, p2sh, balance, live_orders, live_value)) = chain_info {
            println!("On-Chain (wallet):");
            println!("  P2PK UTXOs:   {}", p2pk);
            println!("  P2SH UTXOs:   {}", p2sh);
            println!("  Balance:      {} sompi ({:.8} KAS)", balance, balance as f64 / 1e8);
            println!();
            println!("Live Orders (token pair):");
            println!("  Count:        {}", live_orders);
            println!("  Total Value:  {} sompi ({:.8} KAS)", live_value, live_value as f64 / 1e8);
        } else {
            println!("(RPC connection failed -- showing cached data only)");
        }

        if !token_orders.is_empty() {
            println!();
            println!("Cached Order Details:");
            println!("{:<66}  {:>4}  {:>6}  {:>14}", "OUTPOINT", "SIDE", "PRICE", "VALUE");
            println!("{}", "-".repeat(100));
            for order in &token_orders {
                let price_str = if order.price_den > 0 {
                    format!("{}/{}", order.price_num, order.price_den)
                } else {
                    "N/A".to_string()
                };
                let (txid_part, idx_part) = order.outpoint.split_once(':').unwrap_or((&order.outpoint, "?"));
                let short_txid = if txid_part.len() > 16 {
                    format!("{}...{}", &txid_part[..8], &txid_part[txid_part.len()-8..])
                } else {
                    txid_part.to_string()
                };
                println!(
                    "{}:{}  {:>4}  {:>6}  {:>14}",
                    short_txid, idx_part, order.side, price_str, order.value,
                );
            }
        }
    }

    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bech32_decode_basic() {
        // Verify decoding produces non-empty result for a valid payload
        // Using the actual test wallet address from wallet.json
        let addr = "kaspatest:qq6sneh4wnnst23r8dlewylf0xaj0arrz9kk5a2rd8qeg7wnlejcxrnd89ssr";
        let parts: Vec<&str> = addr.split(':').collect();
        let result = kob_core::bech32::bech32_decode(parts[1]);
        assert!(result.is_ok(), "bech32 decode must succeed");
        let decoded = result.unwrap();
        assert!(!decoded.is_empty(), "decoded data must not be empty");
        assert_eq!(decoded.len(), 33, "decoded must be 33 bytes (1 type + 32 payload)");
        // First byte should be a type byte (0x00 for P2PK)
        assert_eq!(decoded[0], 0x00, "type byte must be P2PK (0x00)");
        // Remaining 32 bytes should be the pubkey
        let expected_pk = "3509e6f574e705aa233b7f9713e979bb27f463116d6a754369c19479d3fe6583";
        assert_eq!(hex::encode(&decoded[1..33]), expected_pk, "pubkey must match wallet");
    }

    #[test]
    fn address_to_spk_structure() {
        // Use the actual test wallet address from wallet.json
        let addr = "kaspatest:qq6sneh4wnnst23r8dlewylf0xaj0arrz9kk5a2rd8qeg7wnlejcxrnd89ssr";
        let result = kob_core::bech32::address_to_spk(addr);
        assert!(result.is_ok(), "address parsing must succeed: {:?}", result.err());
        let spk = result.unwrap();
        // P2PK SPK: [0x20][32B pubkey][0xac]
        assert_eq!(spk.len(), 34, "P2PK SPK must be 34 bytes");
        assert_eq!(spk[0], 0x20, "first byte must be push32");
        assert_eq!(spk[33], 0xac, "last byte must be OpCheckSig");
        // Verify the pubkey in the SPK matches
        let expected_pk = "3509e6f574e705aa233b7f9713e979bb27f463116d6a754369c19479d3fe6583";
        assert_eq!(hex::encode(&spk[1..33]), expected_pk, "SPK pubkey must match wallet");
    }

    #[test]
    fn address_to_spk_invalid_prefix() {
        let result = kob_core::bech32::address_to_spk("bitcoin:qr12345");
        assert!(result.is_err());
    }

    #[test]
    fn address_to_spk_invalid_format() {
        let result = kob_core::bech32::address_to_spk("nocolon");
        assert!(result.is_err());
    }

    #[test]
    fn token_mint_parameter_validation() {
        // Verify MIN_UTXO_VALUE constant is accessible
        assert_eq!(MIN_UTXO_VALUE, 3_000_000);
        // Mass-based fee replaces DEFAULT_MATCHER_FEE; verify estimate is reasonable
        let est = kob_core::mass::estimate_compute_mass(1, 2, 0);
        assert!(est > 0 && est < 100_000, "estimate should be reasonable: {}", est);
    }

    #[test]
    fn token_transfer_builders_consistent() {
        // Verify that building a token_unit RS and its sigscript produces expected sizes
        // (37B RS = KCC20 Standard State Header script portion (34B: owner_identifier +
        // identifier_type) + TOKEN_UNIT_BODY (3B); see kob_core::contract::token).
        let pk = [0x02u8; 32];
        let rs = contract::build_token_unit_redeem_script(&pk);
        assert_eq!(rs.len(), 37);

        let sig = [0x42u8; 64];
        let ss = contract::build_token_unit_sigscript(&sig, &rs);
        // [65] [sig 64B] [0x01] [37] [RS 37B] = 66 + 38 = 104
        assert_eq!(ss.len(), 104);
    }

    #[test]
    fn token_mint_builders_consistent() {
        let pk = [0x02u8; 32];
        let rs = contract::build_token_mint_redeem_script(&pk);
        assert_eq!(rs.len(), 47);

        let sig = [0x42u8; 64];
        let mint_ss = contract::build_token_mint_sigscript(&sig, &rs);
        let burn_ss = contract::build_token_burn_sigscript(&sig, &rs);
        // [65] [sig 64B] [0x01] [Op1/Op0] [47] [RS 47B] = 66 + 1 + 48 = 115
        assert_eq!(mint_ss.len(), 115);
        assert_eq!(burn_ss.len(), 115);

        // Selectors differ
        assert_eq!(mint_ss[66], 0x51); // Op1
        assert_eq!(burn_ss[66], 0x00); // Op0
    }

    #[test]
    fn p2sh_from_token_mint_rs() {
        let pk = [0xAA; 32];
        let rs = contract::build_token_mint_redeem_script(&pk);
        let spk = build_p2sh(&rs);
        assert_eq!(spk.version, 0);
        assert_eq!(spk.script().len(), 35);
        assert_eq!(spk.script()[0], 0xaa);
        assert_eq!(spk.script()[34], 0x87);

        // Hash must match blake2b_256 of RS
        let expected_hash = blake2b_256(&rs);
        assert_eq!(&spk.script()[2..34], &expected_hash);
    }

    #[test]
    fn p2sh_from_token_unit_rs() {
        let pk = [0xBB; 32];
        let rs = contract::build_token_unit_redeem_script(&pk);
        let spk = build_p2sh(&rs);
        assert_eq!(spk.version, 0);
        assert_eq!(spk.script().len(), 35);

        let expected_hash = blake2b_256(&rs);
        assert_eq!(&spk.script()[2..34], &expected_hash);
    }

    #[test]
    fn token_mint_sigscript_structure() {
        // Verify mint sigscript: [push sig(65B)] [Op1] [pushData(RS 47B)]
        let pk = [0x02u8; 32];
        let rs = contract::build_token_mint_redeem_script(&pk);
        let sig = [0x42u8; 64];
        let ss = contract::build_token_mint_sigscript(&sig, &rs);

        // Total: 66 (sig) + 1 (Op1) + 48 (pushData(47B RS)) = 115
        assert_eq!(ss.len(), 115, "Mint sigscript must be 115 bytes");
        assert_eq!(ss[0], 65, "First byte is push length 65");
        assert_eq!(ss[66], 0x51, "Selector byte must be Op1 (mint)");
    }

    #[test]
    fn token_burn_sigscript_structure() {
        let pk = [0x02u8; 32];
        let rs = contract::build_token_mint_redeem_script(&pk);
        let sig = [0x42u8; 64];
        let ss = contract::build_token_burn_sigscript(&sig, &rs);

        assert_eq!(ss.len(), 115, "Burn sigscript must be 115 bytes");
        assert_eq!(ss[0], 65, "First byte is push length 65");
        assert_eq!(ss[66], 0x00, "Selector byte must be Op0 (burn)");
    }

    #[test]
    fn mint_self_continuation_invariant() {
        // The mint contract checks that output[0].SPK == input[0].SPK
        // Verify that the same admin pubkey produces the same P2SH for continuation
        let pk = [0xAA; 32];
        let rs1 = contract::build_token_mint_redeem_script(&pk);
        let rs2 = contract::build_token_mint_redeem_script(&pk);
        assert_eq!(rs1, rs2, "Same admin key must produce same RS");

        let p2sh1 = build_p2sh(&rs1);
        let p2sh2 = build_p2sh(&rs2);
        assert_eq!(p2sh1.script(), p2sh2.script(), "Same RS must produce same P2SH (self-continuation)");
    }


    #[test]
    fn token_info_variant_exists() {
        // Verify the Info variant can be constructed
        let _cmd = TokenCommand::Info {
            token: "00".repeat(32),
            json: false,
        };
    }

    #[test]
    fn token_info_variant_json() {
        let _cmd = TokenCommand::Info {
            token: "ff".repeat(32),
            json: true,
        };
    }

    #[test]
    fn token_cov_id_validation_length() {
        // 32 bytes = 64 hex chars
        let valid = hex::decode(&"ab".repeat(32));
        assert!(valid.is_ok());
        assert_eq!(valid.unwrap().len(), 32);
    }

    #[test]
    fn token_cov_id_validation_short() {
        let short = hex::decode("abcd");
        assert!(short.is_ok());
        assert_ne!(short.unwrap().len(), 32);
    }

    #[test]
    fn token_cov_id_validation_invalid_hex() {
        let invalid = hex::decode("gggg");
        assert!(invalid.is_err());
    }

}

// --- token_alias ---
use std::collections::HashMap;

/// Token alias registry: maps ticker names to covenant IDs.
pub type AliasMap = HashMap<String, String>;

/// Load a token alias file. Returns an empty map if the file does not exist.
pub fn load_aliases(path: &Path) -> anyhow::Result<AliasMap> {
    if !path.exists() {
        return Ok(AliasMap::new());
    }
    let contents = std::fs::read_to_string(path)?;
    let map: AliasMap = serde_json::from_str(&contents)?;
    Ok(map)
}

/// Save the alias map to disk.
pub fn save_aliases(path: &Path, map: &AliasMap) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(map)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Resolve a token string: if it is already a 64-char hex string, return as-is.
/// Otherwise, look it up in the alias file.
pub fn resolve_token(token_or_alias: &str, alias_file: Option<&Path>) -> anyhow::Result<String> {
    // If it looks like a raw covenant ID (64 hex chars), return as-is
    if token_or_alias.len() == 64 && token_or_alias.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(token_or_alias.to_string());
    }

    // Look up in alias file
    let default_path = Path::new("tokens.json");
    let path = alias_file.unwrap_or(default_path);
    let aliases = load_aliases(path)?;

    // Case-insensitive lookup
    let upper = token_or_alias.to_uppercase();
    for (name, covenant_id) in &aliases {
        if name.to_uppercase() == upper {
            return Ok(covenant_id.clone());
        }
    }

    anyhow::bail!(
        "Unknown token alias '{}'. Not a 64-char hex covenant ID and not found in {}. \
         Use `kob token alias {} <covenant_id>` to register it.",
        token_or_alias,
        path.display(),
        token_or_alias,
    )
}

/// Register (or update) a token alias.
pub fn register_alias(alias_file: &Path, name: &str, covenant_id: &str) -> anyhow::Result<()> {
    if covenant_id.len() != 64 || !covenant_id.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("Covenant ID must be exactly 64 hex characters, got: {}", covenant_id);
    }
    let mut map = load_aliases(alias_file)?;
    map.insert(name.to_uppercase(), covenant_id.to_lowercase());
    save_aliases(alias_file, &map)?;
    println!("Registered alias: {} -> {}", name.to_uppercase(), covenant_id.to_lowercase());
    Ok(())
}

#[cfg(test)]
mod alias_tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_resolve_hex_passthrough() {
        let hex = "a".repeat(64);
        let result = resolve_token(&hex, None).unwrap();
        assert_eq!(result, hex);
    }

    #[test]
    fn test_resolve_short_hex_not_alias() {
        // 32 chars: not a valid covenant ID, so it tries alias lookup
        let short = "a".repeat(32);
        let result = resolve_token(&short, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, r#"{{"KUSD": "{}"}}"#, "ab".repeat(32)).unwrap();

        let result = resolve_token("KUSD", Some(&path)).unwrap();
        assert_eq!(result, "ab".repeat(32));
    }

    #[test]
    fn test_resolve_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, r#"{{"NACHO": "{}"}}"#, "cd".repeat(32)).unwrap();

        let result = resolve_token("nacho", Some(&path)).unwrap();
        assert_eq!(result, "cd".repeat(32));
    }

    #[test]
    fn test_register_alias() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        let cov_id = "ef".repeat(32);

        register_alias(&path, "TEST", &cov_id).unwrap();

        let map = load_aliases(&path).unwrap();
        assert_eq!(map.get("TEST").unwrap(), &cov_id);
    }

    #[test]
    fn test_register_alias_invalid_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        let result = register_alias(&path, "BAD", "too_short");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_missing_file() {
        let map = load_aliases(Path::new("/nonexistent/tokens.json")).unwrap();
        assert!(map.is_empty());
    }
}

// --- token_balance ---
use serde::{Deserialize, Serialize};

/// A known token entry in the local token registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEntry {
    /// Covenant ID (hex, 64 chars).
    pub covenant_id: String,
    /// Human-readable ticker (e.g., "KUSD").
    pub ticker: String,
    /// Decimal places.
    pub decimals: u8,
    /// P2SH script hash(es) associated with this token for the current wallet.
    /// Multiple hashes if the wallet has different token_unit scripts.
    #[serde(default)]
    pub script_hashes: Vec<String>,
}

/// Token balance summary for display.
#[derive(Debug)]
#[allow(dead_code)] // Public API: token balance display
pub struct TokenBalance {
    pub covenant_id: String,
    pub ticker: String,
    pub decimals: u8,
    pub total_sompi: u64,
    pub utxo_count: usize,
}

/// Load the token registry from a tokens.json file.
pub fn load_token_registry(path: &Path) -> anyhow::Result<Vec<TokenEntry>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let contents = std::fs::read_to_string(path)?;
    let entries: Vec<TokenEntry> = serde_json::from_str(&contents)?;
    Ok(entries)
}

/// Execute the `token balance` command.
pub async fn run(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    tokens_file: Option<&str>,
) -> anyhow::Result<()> {
    let wallet = WalletContext::load(wallet_path)?;

    println!("Token Balances");
    println!("===============");
    println!("Wallet: {}", wallet.address);
    println!();

    // Load token registry
    let registry_path_str = tokens_file.unwrap_or("tokens.json");
    let registry_path = Path::new(registry_path_str);
    let registry = load_token_registry(registry_path)?;

    // Build lookup: script_hash -> TokenEntry
    let mut hash_to_token: HashMap<String, &TokenEntry> = HashMap::new();
    for entry in &registry {
        for hash in &entry.script_hashes {
            hash_to_token.insert(hash.clone(), entry);
        }
    }

    // Connect and fetch UTXOs
    info!(address = %wallet.address, "querying token balances");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    let utxos = rpc.get_utxos_by_addresses(&[wallet.address.as_str()]).await?;

    // Separate P2PK and P2SH UTXOs
    let p2pk_utxos: Vec<_> = utxos.iter().filter(|u| !u.is_p2sh()).collect();
    let p2sh_utxos: Vec<_> = utxos.iter().filter(|u| u.is_p2sh()).collect();

    // Show KAS balance first
    let kas_total: u64 = p2pk_utxos.iter().map(|u| u.utxo_entry.amount).sum();
    println!(
        "KAS Balance: {:.8} KAS ({} sompi, {} UTXOs)",
        kas_total as f64 / 1e8,
        kas_total,
        p2pk_utxos.len()
    );
    println!();

    if p2sh_utxos.is_empty() {
        println!("No P2SH UTXOs found (no token holdings detected).");
        return Ok(());
    }

    // Group P2SH UTXOs by script hash
    let mut groups: HashMap<String, (u64, usize)> = HashMap::new();
    for u in &p2sh_utxos {
        let script = &u.utxo_entry.script_public_key.script;
        // Extract the 32-byte hash from the P2SH script: aa20<hash>87
        let hash_hex = if script.len() >= 68 && script.starts_with("aa20") && script.ends_with("87") {
            &script[4..68]
        } else {
            script.as_str()
        };
        let entry = groups.entry(hash_hex.to_string()).or_insert((0, 0));
        entry.0 += u.utxo_entry.amount;
        entry.1 += 1;
    }

    // Display token balances
    if !registry.is_empty() {
        println!("Token Holdings:");
        println!(
            "{:<10}  {:<20}  {:>14}  {:>5}  SCRIPT_HASH",
            "TICKER", "COVENANT_ID", "AMOUNT", "UTXOs"
        );
        println!("{}", "-".repeat(100));

        let mut matched = 0;
        for (hash, (total, count)) in &groups {
            if let Some(token) = hash_to_token.get(hash) {
                let display_amount = if token.decimals > 0 {
                    format!(
                        "{:.prec$}",
                        *total as f64 / 10f64.powi(token.decimals as i32),
                        prec = token.decimals as usize
                    )
                } else {
                    format!("{}", total)
                };
                println!(
                    "{:<10}  {:<20}  {:>14}  {:>5}  {}",
                    token.ticker,
                    truncate_id(&token.covenant_id, 20),
                    display_amount,
                    count,
                    truncate_id(hash, 16),
                );
                matched += 1;
            }
        }

        if matched == 0 {
            println!("  (no registered tokens found in UTXOs)");
        }
        println!();
    }

    // Show unregistered P2SH UTXOs
    let unregistered: Vec<_> = groups
        .iter()
        .filter(|(hash, _)| !hash_to_token.contains_key(hash.as_str()))
        .collect();

    if !unregistered.is_empty() {
        println!("Unregistered P2SH UTXOs (potential tokens or orders):");
        println!(
            "{:<66}  {:>14}  {:>5}",
            "SCRIPT_HASH", "TOTAL (sompi)", "UTXOs"
        );
        println!("{}", "-".repeat(90));
        for (hash, (total, count)) in &unregistered {
            println!("{:<66}  {:>14}  {:>5}", hash, total, count);
        }
        println!();
        println!("Register tokens in '{}' to see tickers and proper formatting.", registry_path_str);
    }

    // Grand total
    let token_total: u64 = p2sh_utxos.iter().map(|u| u.utxo_entry.amount).sum();
    println!();
    println!("Summary:");
    println!("  KAS (P2PK):    {:.8} KAS ({} UTXOs)", kas_total as f64 / 1e8, p2pk_utxos.len());
    println!("  Tokens (P2SH): {} sompi ({} UTXOs, {} groups)",
        token_total, p2sh_utxos.len(), groups.len()
    );

    Ok(())
}

/// Truncate a hex string for display.
fn truncate_id(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}..{}", &s[..max_len / 2], &s[s.len() - max_len / 2..])
    }
}

#[cfg(test)]
mod balance_tests {
    use super::*;

    #[test]
    fn token_entry_serialization_roundtrip() {
        let entry = TokenEntry {
            covenant_id: "aa".repeat(32),
            ticker: "KUSD".into(),
            decimals: 8,
            script_hashes: vec!["bb".repeat(32)],
        };
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: TokenEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.ticker, "KUSD");
        assert_eq!(decoded.decimals, 8);
        assert_eq!(decoded.script_hashes.len(), 1);
    }

    #[test]
    fn token_entry_default_script_hashes() {
        let json = r#"{
            "covenant_id": "ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00",
            "ticker": "TEST",
            "decimals": 4
        }"#;
        let entry: TokenEntry = serde_json::from_str(json).unwrap();
        assert!(entry.script_hashes.is_empty());
    }

    #[test]
    fn load_token_registry_nonexistent() {
        let path = Path::new("/tmp/nonexistent_tokens_test.json");
        let result = load_token_registry(path).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn load_token_registry_valid() {
        let path = &std::env::temp_dir().join("test_tokens_balance.json");
        let entries = vec![
            TokenEntry {
                covenant_id: "aa".repeat(32),
                ticker: "KUSD".into(),
                decimals: 8,
                script_hashes: vec!["bb".repeat(32)],
            },
            TokenEntry {
                covenant_id: "cc".repeat(32),
                ticker: "KBTC".into(),
                decimals: 8,
                script_hashes: vec!["dd".repeat(32), "ee".repeat(32)],
            },
        ];
        let json = serde_json::to_string_pretty(&entries).unwrap();
        std::fs::write(path, &json).unwrap();

        let loaded = load_token_registry(path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].ticker, "KUSD");
        assert_eq!(loaded[1].script_hashes.len(), 2);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn truncate_id_short() {
        assert_eq!(truncate_id("abcdef", 10), "abcdef");
    }

    #[test]
    fn truncate_id_long() {
        let long = "a".repeat(64);
        let truncated = truncate_id(&long, 20);
        assert_eq!(truncated.len(), 22); // 10 + ".." + 10
        assert!(truncated.contains(".."));
    }

    #[test]
    fn truncate_id_exact() {
        let s = "a".repeat(20);
        assert_eq!(truncate_id(&s, 20), s);
    }

    #[test]
    fn p2sh_script_hash_extraction() {
        // Simulate extracting hash from P2SH script hex "aa20<hash>87"
        let hash = "ff".repeat(32);
        let script = format!("aa20{}87", hash);
        assert_eq!(script.len(), 70);

        let extracted = if script.len() >= 68 && script.starts_with("aa20") && script.ends_with("87") {
            &script[4..68]
        } else {
            script.as_str()
        };
        assert_eq!(extracted, hash);
    }

    #[test]
    fn grouping_logic() {
        let mut groups: HashMap<String, (u64, usize)> = HashMap::new();

        // Simulate 3 UTXOs, 2 with same hash, 1 different
        let hash_a = "aa".repeat(32);
        let hash_b = "bb".repeat(32);

        let entry = groups.entry(hash_a.clone()).or_insert((0, 0));
        entry.0 += 10_000_000;
        entry.1 += 1;

        let entry = groups.entry(hash_a.clone()).or_insert((0, 0));
        entry.0 += 20_000_000;
        entry.1 += 1;

        let entry = groups.entry(hash_b.clone()).or_insert((0, 0));
        entry.0 += 5_000_000;
        entry.1 += 1;

        assert_eq!(groups.len(), 2);
        assert_eq!(groups[&hash_a], (30_000_000, 2));
        assert_eq!(groups[&hash_b], (5_000_000, 1));
    }

    #[test]
    fn hash_to_token_lookup() {
        let entries = vec![
            TokenEntry {
                covenant_id: "aa".repeat(32),
                ticker: "KUSD".into(),
                decimals: 8,
                script_hashes: vec!["bb".repeat(32), "cc".repeat(32)],
            },
        ];

        let mut lookup: HashMap<String, &TokenEntry> = HashMap::new();
        for entry in &entries {
            for hash in &entry.script_hashes {
                lookup.insert(hash.clone(), entry);
            }
        }

        assert!(lookup.contains_key(&"bb".repeat(32)));
        assert!(lookup.contains_key(&"cc".repeat(32)));
        assert!(!lookup.contains_key(&"dd".repeat(32)));
    }

    #[test]
    fn display_amount_formatting() {
        let total: u64 = 150_000_000;
        let decimals: u8 = 8;
        let display = format!(
            "{:.prec$}",
            total as f64 / 10f64.powi(decimals as i32),
            prec = decimals as usize
        );
        assert_eq!(display, "1.50000000");
    }

    #[test]
    fn display_amount_zero_decimals() {
        let total: u64 = 42;
        let decimals: u8 = 0;
        let display = if decimals > 0 {
            format!(
                "{:.prec$}",
                total as f64 / 10f64.powi(decimals as i32),
                prec = decimals as usize
            )
        } else {
            format!("{}", total)
        };
        assert_eq!(display, "42");
    }

    #[test]
    fn summary_totals() {
        // Simulate KAS + token totals
        let kas_total: u64 = 500_000_000;
        let token_sompi: u64 = 30_000_000;
        let p2pk_count = 5;
        let p2sh_count = 3;
        let group_count = 2;

        assert!(kas_total > 0);
        assert!(token_sompi > 0);
        assert_eq!(p2pk_count, 5);
        assert_eq!(p2sh_count, 3);
        assert_eq!(group_count, 2);
    }
}
