//! `kob-cli deploy` -- Deploy buy/sell/bracket orders.
//!
//! Supports:
//!   - `--market` flag: deploys a market order (extreme price, immediate fill expected)
//!   - `--expiry <daa_score>` flag: deploys a GTD (Good-Till-Date) order

use crate::order_cache::{OrderCache, OrderCacheEntry};
use crate::cancel_all;
use crate::node::NodeClient;
use crate::signing;
use kob_core::contract;
use kob_core::p2sh::{blake2b_256, build_p2sh, compute_p2pk_spk_hash};
use kob_core::sighash::compute_sighash;
use kob_core::tx::{to_rpc_payload, select_utxos_mass_aware, Transaction, TxInput, TxOutput, CoinSelection};
use kob_core::types::{Network, Price, UtxoEntry, Outpoint};
use kob_core::wallet::WalletFile;
use kob_core::mass::{calc_mass_with_sigscripts, compute_storage_mass, converge_fee, min_penalty_free_output, MAX_TX_MASS};
use kob_core::MIN_UTXO_VALUE;
use kob_core::contract::{build_order_payload, build_order_payload_full};
use std::path::Path;

/// Default max_matcher_fee in sompi (0.1 KAS).
///
/// The on-chain F6 check enforces `kas_in - out[0].value <= mmfee`.  When
/// mmfee = 0, partial fills are impossible because the contract requires all
/// locked KAS to stay in the residual output.  A non-zero value lets the
/// matcher extract a bounded fee to cover miner costs and earn a spread.
pub const DEFAULT_MAX_MATCHER_FEE: u64 = 10_000_000;
use tracing::info;

/// GCD helper for simplifying fractions.
fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// Parse a decimal price string into a (numerator, denominator) pair.
///
/// The string is parsed exactly (no floating point). Digits after the decimal
/// point determine the denominator as a power of 10, then the fraction is
/// simplified by GCD.
///
/// # Examples
/// - "100"   -> (100, 1)
/// - "0.05"  -> (1, 20)
/// - "1.5"   -> (3, 2)
/// - "0.001" -> (1, 1000)
pub fn parse_decimal_price(s: &str) -> anyhow::Result<(u64, u64)> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("Price cannot be empty. Example: \"0.05\" or \"100\"");
    }

    let (integer_part, frac_part) = if let Some(dot_pos) = s.find('.') {
        let int_str = &s[..dot_pos];
        let frac_str = &s[dot_pos + 1..];
        if frac_str.is_empty() {
            anyhow::bail!("Trailing decimal point without digits: '{}'", s);
        }
        if !frac_str.chars().all(|c| c.is_ascii_digit()) {
            anyhow::bail!("Invalid characters in decimal part: '{}'", s);
        }
        let int_val: u64 = if int_str.is_empty() {
            0
        } else {
            int_str.parse::<u64>().map_err(|e| anyhow::anyhow!("Invalid integer part: {}", e))?
        };
        (int_val, frac_str.to_string())
    } else {
        // No decimal point: integer
        if !s.chars().all(|c| c.is_ascii_digit()) {
            anyhow::bail!("Invalid characters in price string: '{}'", s);
        }
        let val: u64 = s.parse::<u64>().map_err(|e| anyhow::anyhow!("Invalid price: {}", e))?;
        return Ok((val, 1));
    };

    let frac_digits = frac_part.len() as u32;
    let den = 10u64.checked_pow(frac_digits)
        .ok_or_else(|| anyhow::anyhow!("Too many decimal places in price (max 18). Use fewer decimal places"))?;
    let frac_val: u64 = frac_part.parse::<u64>()
        .map_err(|e| anyhow::anyhow!("Invalid fractional part: {}", e))?;

    let num = integer_part.checked_mul(den)
        .and_then(|v| v.checked_add(frac_val))
        .ok_or_else(|| anyhow::anyhow!("Price value is too large to represent. Use a smaller number"))?;

    if num == 0 {
        anyhow::bail!("Price must be > 0");
    }

    let g = gcd(num, den);
    Ok((num / g, den / g))
}

/// SOMPI_PER_KAS: 1 KAS = 100_000_000 sompi.
const SOMPI_PER_KAS: u64 = 100_000_000;

/// Parse a KAS amount string (decimal) into sompi.
///
/// # Examples
/// - "5"   -> 500_000_000
/// - "0.1" -> 10_000_000
/// - "1.5" -> 150_000_000
pub fn parse_kas_amount(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("Amount cannot be empty. Example: \"1.5\" or \"1000\"");
    }

    let (integer_part, frac_part) = if let Some(dot_pos) = s.find('.') {
        let int_str = &s[..dot_pos];
        let frac_str = &s[dot_pos + 1..];
        if frac_str.is_empty() {
            anyhow::bail!("Trailing decimal point without digits: '{}'", s);
        }
        if frac_str.len() > 8 {
            anyhow::bail!("Too many decimal places in amount (max 8 for KAS). Use fewer decimal places");
        }
        if !frac_str.chars().all(|c| c.is_ascii_digit()) {
            anyhow::bail!("Invalid characters in decimal part: '{}'", s);
        }
        let int_val: u64 = if int_str.is_empty() {
            0
        } else {
            int_str.parse::<u64>().map_err(|e| anyhow::anyhow!("Invalid integer part: {}", e))?
        };
        // Pad fractional part to 8 digits
        let mut padded = frac_str.to_string();
        while padded.len() < 8 {
            padded.push('0');
        }
        (int_val, padded)
    } else {
        if !s.chars().all(|c| c.is_ascii_digit()) {
            anyhow::bail!("Invalid characters in amount string: '{}'", s);
        }
        let val: u64 = s.parse::<u64>().map_err(|e| anyhow::anyhow!("Invalid amount: {}", e))?;
        return val.checked_mul(SOMPI_PER_KAS)
            .ok_or_else(|| anyhow::anyhow!("Amount value is too large to represent. Use a smaller number"));
    };

    let frac_val: u64 = frac_part.parse::<u64>()
        .map_err(|e| anyhow::anyhow!("Invalid fractional part: {}", e))?;

    integer_part.checked_mul(SOMPI_PER_KAS)
        .and_then(|v| v.checked_add(frac_val))
        .ok_or_else(|| anyhow::anyhow!("Amount value is too large to represent. Use a smaller number"))
}

/// Resolve price for market orders. Returns (price_num, price_den).
///
/// Market buy: willing to pay all KAS for any tokens -> extreme high price.
/// Market sell: willing to accept minimal KAS for tokens -> extreme low price.
pub fn resolve_market_price(side: &str, amount: u64) -> (u64, u64) {
    match side {
        "buy" => (amount, 1),
        "sell" => (1, amount),
        _ => (0, 1),
    }
}

/// Build an expiry-annotated payload for GTD orders.
/// Standard RS payload + ":GTD:" + daa_score as LE u64 bytes.
#[allow(dead_code)] // Public API: GTD order type for future use
pub fn build_gtd_order_payload(redeem_script: &[u8], expiry_daa: Option<u64>) -> Vec<u8> {
    let mut payload = build_order_payload(redeem_script, false);
    if let Some(daa) = expiry_daa {
        payload.extend_from_slice(b":GTD:");
        payload.extend_from_slice(&daa.to_le_bytes());
    }
    payload
}

/// Build the appropriate order payload, selecting v1 or v2 format.
///
/// - `post_only = false` and `expiry_daa = None`: uses v1 (`KOB:1:`) for backward compatibility.
/// - `post_only = true` or `expiry_daa = Some`: uses v2 (`KOB:2:<flags><RS>[<expiry>]`).
pub fn build_payload_auto(redeem_script: &[u8], post_only: bool) -> Vec<u8> {
    build_payload_auto_full(redeem_script, post_only, None)
}

/// Build the appropriate order payload with full options.
///
/// Uses v2 format when any extended feature (post_only or GTD expiry) is set;
/// otherwise falls back to v1 for backward compatibility.
pub fn build_payload_auto_full(
    redeem_script: &[u8],
    post_only: bool,
    expiry_daa: Option<u64>,
) -> Vec<u8> {
    if post_only || expiry_daa.is_some() {
        build_order_payload_full(redeem_script, post_only, expiry_daa)
    } else {
        build_order_payload(redeem_script, false)
    }
}

/// Deploy a buy order (lock KAS, request tokens at a given price).
#[allow(clippy::too_many_arguments)]
pub async fn deploy_buy(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    token_covenant_id: &str,
    price_num: u64,
    price_den: u64,
    min_fill: u64,
    amount: u64,
    version: u8,
    fee: u64,
    post_only: bool,
    expiry_daa: Option<u64>,
    max_matcher_fee: u64,
) -> anyhow::Result<String> {
    if version != 13 {
        anyhow::bail!("Unsupported contract version {}. Only v13 is supported for deployment.", version);
    }

    let wallet = WalletFile::load(wallet_path)?;
    let _price = Price::new(price_num, price_den)?;

    // Input validation (defense-in-depth against zero-fill attack, TN12 T79)
    if price_num == 0 {
        anyhow::bail!("price_num must be > 0");
    }
    if price_den == 0 {
        anyhow::bail!("price_den must be > 0");
    }
    if min_fill == 0 {
        anyhow::bail!("min_fill must be > 0. A zero minimum would allow free token extraction");
    }
    if amount == 0 {
        anyhow::bail!("amount must be > 0");
    }
    if amount < min_fill {
        anyhow::bail!("amount ({}) must be >= min_fill ({}) (order must be fillable)", amount, min_fill);
    }
    // Overflow guard: amount * price_num must fit in i64 (Kaspa script arithmetic is i64).
    if (amount as u128) * (price_num as u128) > (i64::MAX as u128) {
        anyhow::bail!(
            "amount ({}) * price_num ({}) = {} overflows i64 (max {}). \
             Reduce amount or simplify the price ratio.",
            amount, price_num,
            (amount as u128) * (price_num as u128),
            i64::MAX
        );
    }

    // Warn about suboptimal UTXO economics for small buy orders.
    const BUY_DEPLOY_MIN_RECOMMENDED: u64 = 500_000_000; // 5 KAS
    if amount < BUY_DEPLOY_MIN_RECOMMENDED {
        println!("WARNING: Amount {} sompi ({:.2} KAS) is below the recommended minimum of {} sompi ({} KAS).",
            amount, amount as f64 / 1e8,
            BUY_DEPLOY_MIN_RECOMMENDED, BUY_DEPLOY_MIN_RECOMMENDED / 100_000_000,
        );
        println!("         Small buy orders may have suboptimal UTXO economics.");
        println!("         Consider using --amount {} or higher.", BUY_DEPLOY_MIN_RECOMMENDED);
        println!();
    }

    let pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.secure_key()?;

    // Parse token covenant ID
    let token_cov_bytes = hex::decode(token_covenant_id)?;
    if token_cov_bytes.len() != 32 {
        anyhow::bail!("token covenant ID must be 64 hex characters (32 bytes)");
    }
    let mut token_cov_id = [0u8; 32];
    token_cov_id.copy_from_slice(&token_cov_bytes);

    let owner_hash = blake2b_256(&pubkey);
    let buyer_spk_hash = compute_p2pk_spk_hash(&pubkey);

    let redeem_script = contract::build_buy_redeem_script(
        &token_cov_id,
        price_num,
        price_den,
        min_fill,
        &owner_hash,
        &buyer_spk_hash,
        max_matcher_fee,
        0, // cancel_pending = 0 (active order)
        expiry_daa.unwrap_or(0),
    )?;

    let p2sh = build_p2sh(&redeem_script);

    println!("Deploy Buy Order (v{})", version);
    println!("======================");
    println!("Token:      {}", token_covenant_id);
    println!(
        "Price:      {}/{} ({:.6})",
        price_num,
        price_den,
        price_num as f64 / price_den as f64
    );
    println!("Min Fill:   {} token units", min_fill);
    println!(
        "Amount:     {} sompi ({:.8} KAS)",
        amount,
        amount as f64 / 1e8
    );
    println!("Max Matcher Fee: {} sompi ({:.8} KAS)", max_matcher_fee, max_matcher_fee as f64 / 1e8);
    println!("Owner:      {}", wallet.public_key);
    println!("Owner Hash: {}", hex::encode(owner_hash));
    println!("Buyer SPK Hash: {}", hex::encode(buyer_spk_hash));
    println!();
    println!("RedeemScript: {} bytes (v{})", redeem_script.len(), version);
    println!("RS hex:     {}", hex::encode(&redeem_script));
    println!("P2SH SPK:   {}", hex::encode(&p2sh.script()));
    // ZK-GATE: Warn if the redeemScript contains OpZkPrecompile (0xa6).
    // Current KOB contracts do not use 0xa6, but future versions or
    // freezable tokens (e.g. USDC) may require the matcher to have a
    // ZK prover configured.
    if redeem_script.contains(&0xa6) {
        println!();
        println!("WARNING: This order's redeemScript contains OpZkPrecompile (0xa6).");
        println!("         The matcher must have --zk-prover enabled to fill this order.");
    }
    println!();

    // Connect and fetch UTXOs
    info!(address = %wallet.address, amount = amount, "deploying buy order");
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

    // Pre-estimate miner fee from compute mass for UTXO selection.
    // Final fee is computed after TX construction from actual mass.
    let estimated_fee = kob_core::mass::estimate_compute_mass(2, 2, 100);
    let selection_fee = if fee > 0 { fee.max(estimated_fee) } else { estimated_fee };

    // Mass-aware UTXO selection: 2 outputs (order + change)
    // The amount is the user's intended order size — never adjusted.
    // Penalty-free is achieved by selecting additional input UTXOs for credit.
    let coin_sel: CoinSelection =
        select_utxos_mass_aware(&core_utxos, amount, selection_fee, 2).map_err(|e| {
            anyhow::anyhow!(
                "UTXO selection failed: {}. {} P2PK UTXOs available.",
                e,
                core_utxos.len()
            )
        })?;

    let selected_utxos = &coin_sel.utxos;
    let total_input = coin_sel.total;
    println!("Selected {} funding UTXOs (total {} sompi)", selected_utxos.len(), total_input);
    for u in selected_utxos {
        println!("  {}:{} ({} sompi)", &u.outpoint.transaction_id[..16], u.outpoint.index, u.value);
    }

    // Build transaction (version 0 for buy orders -- no covenant binding needed on deploy)
    let mut tx = Transaction::new(0);

    // Inputs: selected wallet P2PK UTXOs
    for sel in selected_utxos {
        let rpc_utxo = p2pk_rpc
            .iter()
            .find(|u| u.outpoint.transaction_id == sel.outpoint.transaction_id
                && u.outpoint.index == sel.outpoint.index)
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

    // Output 0: P2SH covenant output (the buy order)
    tx.outputs.push(TxOutput::new(amount, 0, p2sh.script().to_vec(), None));

    // TX payload: RS for matcher L1 discovery (replaces OP_RETURN)
    // Use v2 format when post_only or expiry is set, v1 otherwise for backward compat.
    // NOTE: TN12 (pre-HF) does not include payload in sighash for native subnetwork.
    // Payload is omitted pre-HF; the matcher discovers orders via P2SH address instead.
    tx.payload = build_payload_auto_full(&redeem_script, post_only, expiry_daa);

    // Add a temporary change output so mass calculation includes both outputs.
    // We'll adjust its value after computing the actual fee.
    let tentative_change = total_input.saturating_sub(amount + selection_fee);
    let first_rpc = p2pk_rpc
        .iter()
        .find(|u| u.outpoint.transaction_id == selected_utxos[0].outpoint.transaction_id
            && u.outpoint.index == selected_utxos[0].outpoint.index)
        .ok_or_else(|| anyhow::anyhow!("UTXO spent during TX construction, please retry."))?;
    let wallet_spk = hex::decode(&first_rpc.utxo_entry.script_public_key.script)?;
    if tentative_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(tentative_change, first_rpc.utxo_entry.script_public_key.version, wallet_spk.clone(), None));
    }

    // Phase 1: converge fee on change output (last output if it exists)
    let min_fee_override = if fee > 0 { fee } else { 0 };
    let has_change = tentative_change >= MIN_UTXO_VALUE;
    let change_idx = if has_change { tx.outputs.len() - 1 } else { 0 };

    let (est_fee, _) = if has_change {
        converge_fee(&mut tx, total_input - amount, change_idx, min_fee_override)
    } else {
        // No change output — fee is total_input - amount
        let f = kob_core::mass::calc_miner_fee(&tx).max(min_fee_override);
        (f, 0)
    };

    let change = if has_change { tx.outputs[change_idx].value } else { total_input.saturating_sub(amount + est_fee) };

    // Remove change output if below MIN_UTXO_VALUE
    if has_change && change < MIN_UTXO_VALUE {
        tx.outputs.pop();
        if change > 0 {
            println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", change);
        }
    } else if !has_change && change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(change, first_rpc.utxo_entry.script_public_key.version, wallet_spk.clone(), None));
    } else if !has_change && change > 0 {
        println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", change);
    }

    // Sign all inputs (phase 1)
    let mut sigscripts: Vec<Vec<u8>> = Vec::new();
    for i in 0..tx.inputs.len() {
        let sighash = compute_sighash(&tx, i)?;
        let signature = signing::schnorr_sign_secure(&privkey, &sighash)?;
        sigscripts.push(signing::build_p2pk_sigscript(&signature));
    }

    // Phase 2: exact mass check with real sigscripts
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts);
    let storage_mass_val = {
        let in_vals: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let out_vals: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        compute_storage_mass(&in_vals, &out_vals)
    };
    let exact_fee = exact_mass.max(storage_mass_val).max(min_fee_override);

    let actual_fee = if exact_fee > est_fee && tx.outputs.len() > 1 {
        // Re-adjust change output
        let change_idx = tx.outputs.len() - 1;
        let new_change = total_input.saturating_sub(amount + exact_fee);
        if new_change >= MIN_UTXO_VALUE {
            tx.outputs[change_idx].value = new_change;
        } else {
            tx.outputs.pop();
            if new_change > 0 {
                println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", new_change);
            }
        }
        // Re-sign
        sigscripts.clear();
        for i in 0..tx.inputs.len() {
            let sighash = compute_sighash(&tx, i)?;
            let signature = signing::schnorr_sign_secure(&privkey, &sighash)?;
            sigscripts.push(signing::build_p2pk_sigscript(&signature));
        }
        exact_fee
    } else {
        est_fee
    };

    println!("Signed {} input(s)", sigscripts.len());
    println!();

    // Storage mass pre-check
    if let Err(e) = kob_core::check_tx_storage_mass(&tx) {
        anyhow::bail!(
            "Deploy TX would be rejected by node: {}. \
             Increase the order amount or use a larger funding UTXO.",
            e
        );
    }

    // Fee transparency summary
    {
        let in_vals: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let out_vals: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        let storage_mass = compute_storage_mass(&in_vals, &out_vals);
        let exact_compute = calc_mass_with_sigscripts(&tx, &sigscripts);
        let min_pf = min_penalty_free_output(&in_vals, out_vals.len());
        println!("Fee Summary");
        println!("-----------");
        println!(
            "Storage mass:     {:>9} / {:>9} ({})",
            storage_mass, MAX_TX_MASS,
            if storage_mass <= MAX_TX_MASS { "OK" } else { "OVER" }
        );
        println!("Compute mass:     {:>9} (exact, post-sign)", exact_compute);
        println!("Penalty-free min: {:>9} sompi/output", min_pf);
        println!("Miner fee:        {:>9} sompi", actual_fee);
        println!("Net order value:  {:>9} sompi", amount);
        println!();
    }

    // Submit
    let payload = to_rpc_payload(&tx, &sigscripts);
    println!("Submitting transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Transaction submitted.");
    println!("TXID: {}", tx_id);
    println!();
    println!("Order deployed at output {}:0", tx_id);

    // Append to orders cache (unified OrderCache format)
    let cache_path = cancel_all::orders_cache_path(wallet_path);
    let p2sh_hash = hex::encode(&p2sh.script()[2..34]);
    let entry = OrderCacheEntry {
        outpoint: format!("{}:0", tx_id),
        side: "buy".into(),
        pair_id: token_covenant_id.to_string(),
        price_num,
        price_den,
        min_fill,
        owner_hash: hex::encode(owner_hash),
        spk_hash: hex::encode(buyer_spk_hash),
        p2sh_hash,
        value: amount,
        cancel_pending: false,
        token: Some(token_covenant_id.to_string()),
        version,
        expiry_daa: expiry_daa.unwrap_or(0),
        max_matcher_fee,
    };
    let mut cache = OrderCache::load(&cache_path);
    cache.orders.push(entry);
    if let Err(e) = cache.save(&cache_path) {
        println!("WARNING: Failed to write orders cache: {}", e);
    } else {
        println!("Order cached in {}", cache_path.display());
    }

    Ok(tx_id)
}

/// Deploy a sell order (lock tokens, request KAS at a given price).
#[allow(clippy::too_many_arguments)]
pub async fn deploy_sell(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    token_covenant_id: Option<&str>,
    price_num: u64,
    price_den: u64,
    min_fill: u64,
    amount: u64,
    version: u8,
    fee: u64,
    post_only: bool,
    expiry_daa: Option<u64>,
    max_matcher_fee: u64,
    token_utxo_str: Option<&str>,
    fee_utxo_str: Option<&str>,
) -> anyhow::Result<String> {
    if version != 13 {
        anyhow::bail!("Unsupported contract version {}. Only v13 is supported for deployment.", version);
    }

    let wallet = WalletFile::load(wallet_path)?;
    let _price = Price::new(price_num, price_den)?;

    // Input validation (defense-in-depth against zero-fill attack, TN12 T79)
    if price_num == 0 {
        anyhow::bail!("price_num must be > 0");
    }
    if price_den == 0 {
        anyhow::bail!("price_den must be > 0");
    }
    if min_fill == 0 {
        anyhow::bail!("min_fill must be > 0. A zero minimum would allow free token extraction");
    }
    if amount == 0 {
        anyhow::bail!("amount must be > 0");
    }
    if amount < min_fill {
        anyhow::bail!("amount ({}) must be >= min_fill ({}) (order must be fillable)", amount, min_fill);
    }
    // Overflow guard: amount * price_num must fit in i64 (Kaspa script arithmetic is i64).
    if (amount as u128) * (price_num as u128) > (i64::MAX as u128) {
        anyhow::bail!(
            "amount ({}) * price_num ({}) = {} overflows i64 (max {}). \
             Reduce amount or simplify the price ratio.",
            amount, price_num,
            (amount as u128) * (price_num as u128),
            i64::MAX
        );
    }

    if token_covenant_id.is_none() {
        anyhow::bail!("--token is required for sell orders. Specify the token covenant ID.");
    }

    // Warn about storage mass penalty for small sell orders.
    const SELL_DEPLOY_MIN_RECOMMENDED: u64 = 1_000_000_000; // 10 KAS
    if amount < SELL_DEPLOY_MIN_RECOMMENDED {
        println!("WARNING: Amount {} sompi ({:.2} KAS) is below the recommended minimum of {} sompi ({} KAS).",
            amount, amount as f64 / 1e8,
            SELL_DEPLOY_MIN_RECOMMENDED, SELL_DEPLOY_MIN_RECOMMENDED / 100_000_000,
        );
        println!("         Small sell orders with covenant binding (version=1 TX) incur high storage mass and may get stuck in mempool.");
        println!("         Consider using --amount {} or higher.", SELL_DEPLOY_MIN_RECOMMENDED);
        println!();
    }

    let pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.secure_key()?;

    let owner_hash = blake2b_256(&pubkey);
    let seller_spk_hash = compute_p2pk_spk_hash(&pubkey);

    let redeem_script = contract::build_sell_redeem_script(
        price_num, price_den, min_fill, &owner_hash, &seller_spk_hash,
        max_matcher_fee,
        0, // cancel_pending
        expiry_daa.unwrap_or(0),
    )?;

    let p2sh = build_p2sh(&redeem_script);

    println!("Deploy Sell Order (v{})", version);
    println!("=======================");
    if let Some(token) = token_covenant_id {
        println!("Token:      {}", token);
    }
    println!(
        "Price:      {}/{} ({:.6})",
        price_num,
        price_den,
        price_num as f64 / price_den as f64
    );
    println!("Min Fill:   {} sompi", min_fill);
    println!(
        "Amount:     {} sompi ({:.8} KAS)",
        amount,
        amount as f64 / 1e8
    );
    println!("Max Matcher Fee: {} sompi ({:.8} KAS)", max_matcher_fee, max_matcher_fee as f64 / 1e8);
    println!("Owner:      {}", wallet.public_key);
    println!("Owner Hash: {}", hex::encode(owner_hash));
    println!("Seller SPK Hash: {}", hex::encode(seller_spk_hash));
    println!();
    println!("RedeemScript: {} bytes (v{})", redeem_script.len(), version);
    println!("RS hex:     {}", hex::encode(&redeem_script));
    println!("P2SH SPK:   {}", hex::encode(&p2sh.script()));
    // ZK-GATE: Warn if the redeemScript contains OpZkPrecompile (0xa6).
    if redeem_script.contains(&0xa6) {
        println!();
        println!("WARNING: This order's redeemScript contains OpZkPrecompile (0xa6).");
        println!("         The matcher must have --zk-prover enabled to fill this order.");
    }
    println!();

    info!(address = %wallet.address, amount = amount, "deploying sell order");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    let rpc_utxos = rpc.get_spendable_utxos(&wallet.address).await?;

    // Filter to P2PK UTXOs and convert for mass-aware selection
    let p2pk_rpc: Vec<_> = rpc_utxos.iter().filter(|u| !u.is_p2sh()).collect();

    // Sell orders that need covenant binding use TX version 1
    let tx_version = if token_covenant_id.is_some() { 1 } else { 0 };
    let mut tx = Transaction::new(tx_version);

    // If --token-utxo is provided, add the token UTXO as input[0] for covenant lineage.
    // This is required for sell orders with --token because the Kaspa covenant system
    // requires an input carrying the covenant_id to authorize covenant-bound outputs.
    let mut token_input_value: u64 = 0;
    let token_input_idx: u32;
    if let Some(token_op_str) = token_utxo_str {
        let token_op = Outpoint::parse(token_op_str)?;
        // Find the token UTXO in the full UTXO list (including P2SH).
        // If not found in wallet UTXOs (P2PK), try the token_unit P2SH address.
        let mut found_utxo = rpc_utxos
            .iter()
            .find(|u| u.outpoint.transaction_id == token_op.transaction_id && u.outpoint.index == token_op.index)
            .cloned();
        let extra_utxos;
        if found_utxo.is_none() {
            // Query token_mint and token_unit P2SH addresses for this pubkey
            let mint_rs = kob_core::contract::build_token_mint_redeem_script(&pubkey);
            let mint_p2sh = build_p2sh(&mint_rs);
            let mint_addr = crate::cancel::kaspa_address_encode(network.address_prefix(), 8, &mint_p2sh.script()[2..34]);
            let unit_rs = kob_core::contract::build_token_unit_redeem_script(&pubkey);
            let unit_p2sh = build_p2sh(&unit_rs);
            let unit_addr = crate::cancel::kaspa_address_encode(network.address_prefix(), 8, &unit_p2sh.script()[2..34]);
            println!("Token UTXO not in wallet. Querying P2SH addresses...");
            extra_utxos = rpc.get_utxos_by_addresses(&[&mint_addr, &unit_addr]).await?;
            found_utxo = extra_utxos
                .iter()
                .find(|u| u.outpoint.transaction_id == token_op.transaction_id && u.outpoint.index == token_op.index)
                .cloned();
        }
        let token_utxo = found_utxo
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Token UTXO {} not found. It may be spent or not belong to this wallet.",
                    token_op_str
                )
            })?;
        token_input_value = token_utxo.utxo_entry.amount;
        token_input_idx = 0;
        println!("Token UTXO: {}:{} ({} sompi)", &token_utxo.outpoint.transaction_id[..16], token_utxo.outpoint.index, token_input_value);
        tx.inputs.push(TxInput {
            prev_tx_id: token_utxo.outpoint.transaction_id.clone(),
            prev_index: token_utxo.outpoint.index,
            sequence: 0,
            sig_op_count: 1,
            script_version: token_utxo.utxo_entry.script_public_key.version,
            script_bytes: token_utxo.script_bytes(),
            value: token_input_value,
        });
    } else if token_covenant_id.is_some() {
        // Auto-discover token UTXO: query token_mint P2SH address for this wallet.
        let mint_rs = kob_core::contract::build_token_mint_redeem_script(&pubkey);
        let mint_p2sh = build_p2sh(&mint_rs);
        let mint_addr = crate::cancel::kaspa_address_encode(
            network.address_prefix(), 8, &mint_p2sh.script()[2..34],
        );
        println!("Auto-discovering token UTXO at mint address {}...", &mint_addr[..40]);
        let mint_utxos = rpc.get_utxos_by_addresses(&[&mint_addr]).await?;

        // Also check token_unit P2SH address
        let unit_rs = kob_core::contract::build_token_unit_redeem_script(&pubkey);
        let unit_p2sh = build_p2sh(&unit_rs);
        let unit_addr = crate::cancel::kaspa_address_encode(
            network.address_prefix(), 8, &unit_p2sh.script()[2..34],
        );
        let unit_utxos = rpc.get_utxos_by_addresses(&[&unit_addr]).await?;

        // Combine and pick the first available token UTXO
        let all_token_utxos: Vec<_> = mint_utxos.iter().chain(unit_utxos.iter()).collect();
        if let Some(token_utxo) = all_token_utxos.first() {
            token_input_value = token_utxo.utxo_entry.amount;
            token_input_idx = 0;
            println!("Token UTXO: {}:{} ({} sompi)",
                &token_utxo.outpoint.transaction_id[..16],
                token_utxo.outpoint.index,
                token_input_value,
            );
            tx.inputs.push(TxInput {
                prev_tx_id: token_utxo.outpoint.transaction_id.clone(),
                prev_index: token_utxo.outpoint.index,
                sequence: 0,
                sig_op_count: 1,
                script_version: token_utxo.utxo_entry.script_public_key.version,
                script_bytes: token_utxo.script_bytes(),
                value: token_input_value,
            });
        } else {
            println!("WARNING: No token UTXO found at mint or unit P2SH addresses.");
            println!("  Mint addr: {}", &mint_addr[..40]);
            println!("  Unit addr: {}", &unit_addr[..40]);
            println!("  Deploying without covenant input (TX version 0).");
            tx.version = 0;
            token_input_idx = 0;
        }
    } else {
        token_input_idx = 0; // No token, no covenant needed
    }

    // Select fee/funding UTXO(s) from P2PK UTXOs
    let fee_utxo = if let Some(fee_op_str) = fee_utxo_str {
        let fee_op = Outpoint::parse(fee_op_str)?;
        let found = p2pk_rpc
            .iter()
            .find(|u| u.outpoint.transaction_id == fee_op.transaction_id && u.outpoint.index == fee_op.index)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Fee UTXO {} not found in wallet P2PK UTXOs.",
                    fee_op_str
                )
            })?;
        println!("Fee UTXO:   {}:{} ({} sompi)", &found.outpoint.transaction_id[..16], found.outpoint.index, found.utxo_entry.amount);
        vec![*found]
    } else {
        // Auto-select: need enough for amount + estimated miner fee (minus token_input_value if any)
        let est_fee = kob_core::mass::estimate_compute_mass(2, 3, 100);
        let sel_fee = if fee > 0 { fee.max(est_fee) } else { est_fee };
        let needed = if token_input_value >= amount + sel_fee {
            sel_fee // Token UTXO covers the order amount, just need fee
        } else {
            amount + sel_fee - token_input_value
        };
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

        if token_input_value >= amount {
            // Token UTXO covers the order amount. We only need a fee UTXO.
            // Skip mass-aware selection (it would misestimate outputs).
            // Just pick the smallest P2PK UTXO that covers the fee.
            let mut candidates = core_utxos.clone();
            candidates.sort_by(|a, b| a.value.cmp(&b.value));
            let fee_entry = candidates.into_iter()
                .find(|u| u.value >= sel_fee)
                .ok_or_else(|| anyhow::anyhow!(
                    "No P2PK UTXO with >= {} sompi for fee. {} available.",
                    sel_fee, core_utxos.len()
                ))?;
            println!("Selected 1 fee UTXO (total {} sompi)", fee_entry.value);
            println!("  {}:{} ({} sompi)", &fee_entry.outpoint.transaction_id[..16], fee_entry.outpoint.index, fee_entry.value);
            vec![p2pk_rpc.iter().find(|u| u.outpoint.transaction_id == fee_entry.outpoint.transaction_id
                && u.outpoint.index == fee_entry.outpoint.index)
                .copied()
                .ok_or_else(|| anyhow::anyhow!("UTXO spent during TX construction, please retry."))?]
        } else {
            let coin_sel: CoinSelection =
                select_utxos_mass_aware(&core_utxos, needed, 0, 3).map_err(|e| {
                    anyhow::anyhow!("UTXO selection failed: {}. {} P2PK UTXOs available.", e, core_utxos.len())
                })?;
            println!("Selected {} funding UTXOs (total {} sompi)", coin_sel.utxos.len(), coin_sel.total);
            for u in &coin_sel.utxos {
                println!("  {}:{} ({} sompi)", &u.outpoint.transaction_id[..16], u.outpoint.index, u.value);
            }
            // Find matching RPC UTXOs
            coin_sel.utxos.iter().map(|sel| {
                p2pk_rpc.iter().find(|u| u.outpoint.transaction_id == sel.outpoint.transaction_id
                    && u.outpoint.index == sel.outpoint.index)
                    .copied()
                    .ok_or_else(|| anyhow::anyhow!("UTXO spent during TX construction, please retry."))
            }).collect::<Result<Vec<_>, _>>()?
        }
    };

    // Add P2PK funding inputs
    let mut total_p2pk_input: u64 = 0;
    for u in &fee_utxo {
        total_p2pk_input += u.utxo_entry.amount;
        tx.inputs.push(TxInput {
            prev_tx_id: u.outpoint.transaction_id.clone(),
            prev_index: u.outpoint.index,
            sequence: 0,
            sig_op_count: 1,
            script_version: u.utxo_entry.script_public_key.version,
            script_bytes: u.script_bytes(),
            value: u.utxo_entry.amount,
        });
    }

    let total_input = token_input_value + total_p2pk_input;

    // Output 0: P2SH sell order (with covenant binding if token specified)
    let covenant_binding = token_covenant_id.map(|token_cov_hex| kob_core::tx::CovenantBinding::new(token_input_idx as u16, kob_core::compat::parse_hash(&token_cov_hex.to_string()).unwrap()));

    tx.outputs.push(TxOutput::new(amount, 0, p2sh.script().to_vec(), covenant_binding));

    // TX payload: RS for matcher L1 discovery (replaces OP_RETURN)
    tx.payload = build_payload_auto_full(&redeem_script, post_only, expiry_daa);

    // Output 1: change (plain KAS, no covenant)
    let wallet_spk = if let Some(u) = fee_utxo.first() {
        hex::decode(&u.utxo_entry.script_public_key.script)?
    } else {
        // Fallback: derive from wallet public key
        let mut spk = Vec::with_capacity(34);
        spk.push(0x20);
        spk.extend_from_slice(&pubkey);
        spk.push(0xac);
        spk
    };

    // Add tentative change output for mass calculation, then adjust
    let est_fee_sell = kob_core::mass::estimate_compute_mass(tx.inputs.len(), 2, tx.payload.len());
    let tent_change = total_input.saturating_sub(amount + est_fee_sell);
    if tent_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(tent_change, 0, wallet_spk.clone(), None));
    }

    // Phase 1: converge fee on change output
    let min_fee_override = if fee > 0 { fee } else { 0 };
    let has_change_sell = tent_change >= MIN_UTXO_VALUE;
    let (est_fee_sell, _) = if has_change_sell {
        let change_idx = tx.outputs.len() - 1;
        converge_fee(&mut tx, total_input - amount, change_idx, min_fee_override)
    } else {
        let f = kob_core::mass::calc_miner_fee(&tx).max(min_fee_override);
        (f, 0)
    };

    let change = if has_change_sell {
        tx.outputs.last().unwrap().value
    } else {
        total_input.saturating_sub(amount + est_fee_sell)
    };

    if has_change_sell && change < MIN_UTXO_VALUE {
        tx.outputs.pop();
        if change > 0 {
            println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", change);
        }
    } else if !has_change_sell && change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(change, 0, wallet_spk.clone(), None));
    } else if !has_change_sell && change > 0 {
        println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", change);
    }

    // Helper closure: sign all inputs with correct sigscript type
    let sign_all_inputs = |tx: &Transaction, privkey: &kob_core::wallet::SecureKey, pubkey: &[u8; 32], token_input_value: u64| -> anyhow::Result<Vec<Vec<u8>>> {
        let mut sigscripts: Vec<Vec<u8>> = Vec::new();
        for i in 0..tx.inputs.len() {
            let sighash = compute_sighash(tx, i)?;
            let signature = signing::schnorr_sign_secure(privkey, &sighash)?;
            if token_input_value > 0 && i == 0 {
                let mint_rs = contract::build_token_mint_redeem_script(pubkey);
                let unit_rs = contract::build_token_unit_redeem_script(pubkey);
                let token_rs = if tx.inputs[0].script_bytes == build_p2sh(&mint_rs).script() {
                    mint_rs
                } else {
                    unit_rs
                };
                let mut ss = Vec::with_capacity(66 + 2 + token_rs.len());
                ss.push(65);
                ss.extend_from_slice(&signature);
                ss.push(0x01);
                if token_rs.len() < 76 {
                    ss.push(token_rs.len() as u8);
                } else {
                    ss.push(0x4c);
                    ss.push(token_rs.len() as u8);
                }
                ss.extend_from_slice(&token_rs);
                sigscripts.push(ss);
            } else {
                sigscripts.push(signing::build_p2pk_sigscript(&signature));
            }
        }
        Ok(sigscripts)
    };

    let mut sigscripts = sign_all_inputs(&tx, &privkey, &pubkey, token_input_value)?;

    // Phase 2: exact mass check with real sigscripts
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts);
    let storage_mass_val = {
        let in_vals: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let out_vals: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        compute_storage_mass(&in_vals, &out_vals)
    };
    let exact_fee = exact_mass.max(storage_mass_val).max(min_fee_override);

    let actual_fee = if exact_fee > est_fee_sell && tx.outputs.len() > 1 {
        let change_idx = tx.outputs.len() - 1;
        let new_change = total_input.saturating_sub(amount + exact_fee);
        if new_change >= MIN_UTXO_VALUE {
            tx.outputs[change_idx].value = new_change;
        } else {
            tx.outputs.pop();
            if new_change > 0 {
                println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", new_change);
            }
        }
        sigscripts = sign_all_inputs(&tx, &privkey, &pubkey, token_input_value)?;
        exact_fee
    } else {
        est_fee_sell
    };

    println!("Signed {} input(s)", sigscripts.len());
    println!();

    // Storage mass pre-check
    if let Err(e) = kob_core::check_tx_storage_mass(&tx) {
        anyhow::bail!(
            "Deploy TX would be rejected by node: {}. \
             Increase the order amount or use a larger funding UTXO.",
            e
        );
    }

    // Fee transparency summary
    {
        let in_vals: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let out_vals: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        let storage_mass = compute_storage_mass(&in_vals, &out_vals);
        let exact_compute = calc_mass_with_sigscripts(&tx, &sigscripts);
        let min_pf = min_penalty_free_output(&in_vals, out_vals.len());
        println!("Fee Summary");
        println!("-----------");
        println!(
            "Storage mass:     {:>9} / {:>9} ({})",
            storage_mass, MAX_TX_MASS,
            if storage_mass <= MAX_TX_MASS { "OK" } else { "OVER" }
        );
        println!("Penalty-free min: {:>9} sompi/output", min_pf);
        println!("Compute mass:     {:>9} (exact, post-sign)", exact_compute);
        println!("Miner fee:        {:>9} sompi", actual_fee);
        println!("Net order value:  {:>9} sompi", amount);
        println!();
    }

    let payload = to_rpc_payload(&tx, &sigscripts);
    println!("Submitting transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Transaction submitted.");
    println!("TXID: {}", tx_id);
    println!();
    println!("Order deployed at output {}:0", tx_id);

    // Append to orders cache (unified OrderCache format)
    let cache_path = cancel_all::orders_cache_path(wallet_path);
    let p2sh_hash = hex::encode(&p2sh.script()[2..34]);
    let entry = OrderCacheEntry {
        outpoint: format!("{}:0", tx_id),
        side: "sell".into(),
        pair_id: token_covenant_id.unwrap_or("00".repeat(32).as_str()).to_string(),
        price_num,
        price_den,
        min_fill,
        owner_hash: hex::encode(owner_hash),
        spk_hash: hex::encode(seller_spk_hash),
        p2sh_hash,
        value: amount,
        cancel_pending: false,
        token: token_covenant_id.map(|s| s.to_string()),
        version,
        expiry_daa: expiry_daa.unwrap_or(0),
        max_matcher_fee,
    };
    let mut cache = OrderCache::load(&cache_path);
    cache.orders.push(entry);
    if let Err(e) = cache.save(&cache_path) {
        println!("WARNING: Failed to write orders cache: {}", e);
    } else {
        println!("Order cached in {}", cache_path.display());
    }

    Ok(tx_id)
}

/// Deploy a bracket order (OTOCO: entry + take-profit + stop-loss).
#[allow(clippy::too_many_arguments)]
pub async fn deploy_bracket(
    wallet_path: &Path,
    _node_url: &str,
    _network: Network,
    token_covenant_id: &str,
    side: &str,
    entry_num: u64,
    entry_den: u64,
    tp_num: u64,
    tp_den: u64,
    sl_num: u64,
    sl_den: u64,
    amount: u64,
) -> anyhow::Result<()> {
    let wallet = WalletFile::load(wallet_path)?;
    let entry_price = Price::new(entry_num, entry_den)?;
    let tp_price = Price::new(tp_num, tp_den)?;
    let sl_price = Price::new(sl_num, sl_den)?;

    println!("Deploy Bracket Order (OTOCO)");
    println!("============================");
    println!("Token:       {}", token_covenant_id);
    println!("Side:        {}", side);
    println!("Entry:       {}", entry_price);
    println!("Take Profit: {}", tp_price);
    println!("Stop Loss:   {}", sl_price);
    println!(
        "Amount:      {} sompi ({:.8} KAS)",
        amount,
        amount as f64 / 1e8
    );
    println!("Owner:       {}", wallet.public_key);
    println!();

    info!(
        address = %wallet.address,
        side = side,
        amount = amount,
        "deploying bracket order"
    );

    println!("This command is deprecated. Use the real bracket_order_v4 contract:");
    println!();
    println!("  kob-cli bracket deploy \\");
    println!("    --token {} \\", token_covenant_id);
    println!("    --entry-type {} \\", if side == "buy" { "0" } else { "1" });
    println!("    --entry-num {} --entry-den {} \\", entry_num, entry_den);
    println!("    --tp-spk <hex_74_chars> --tp-min-value <sompi> \\");
    println!("    --sl-spk <hex_74_chars> --sl-min-value <sompi> \\");
    println!("    --min-fill <min_fill> \\");
    println!("    --receipt-cov-id <hex_64_chars> \\");
    println!("    --amount {}", amount);
    println!();
    println!("bracket_order_v4 deploys as a single UTXO (380B RS) with");
    println!("TP/SL SPKs and receipt covenant_id verification (N4 fix).");

    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn market_buy_price_is_extreme_high() {
        let (num, den) = resolve_market_price("buy", 50_000_000);
        assert_eq!(num, 50_000_000);
        assert_eq!(den, 1);
        assert!(num as f64 / den as f64 > 1_000_000.0);
    }

    #[test]
    fn market_sell_price_is_extreme_low() {
        let (num, den) = resolve_market_price("sell", 50_000_000);
        assert_eq!(num, 1);
        assert_eq!(den, 50_000_000);
        assert!((num as f64 / den as f64) < 0.001);
    }

    #[test]
    fn market_buy_small_amount() {
        let (num, den) = resolve_market_price("buy", 1_000);
        assert_eq!(num, 1_000);
        assert_eq!(den, 1);
    }

    #[test]
    fn market_sell_small_amount() {
        let (num, den) = resolve_market_price("sell", 1_000);
        assert_eq!(num, 1);
        assert_eq!(den, 1_000);
    }

    #[test]
    fn market_buy_large_amount() {
        let (num, den) = resolve_market_price("buy", 1_000_000_000_000);
        assert_eq!(num, 1_000_000_000_000);
        assert_eq!(den, 1);
    }

    #[test]
    fn market_sell_large_amount() {
        let (num, den) = resolve_market_price("sell", 1_000_000_000_000);
        assert_eq!(num, 1);
        assert_eq!(den, 1_000_000_000_000);
    }

    #[test]
    fn market_invalid_side_returns_zero() {
        let (num, den) = resolve_market_price("invalid", 100);
        assert_eq!(num, 0);
        assert_eq!(den, 1);
    }

    #[test]
    fn gtd_payload_without_expiry_is_standard() {
        let rs = vec![0x75, 0x75, 0x51];
        let standard = build_order_payload(&rs, false);
        let gtd = build_gtd_order_payload(&rs, None);
        assert_eq!(standard, gtd);
    }

    #[test]
    fn gtd_payload_with_expiry_appends_marker() {
        let rs = vec![0x75, 0x75, 0x51];
        let standard = build_order_payload(&rs, false);
        let gtd = build_gtd_order_payload(&rs, Some(1_000_000));
        assert_eq!(gtd.len(), standard.len() + 5 + 8);
        let marker = &gtd[standard.len()..standard.len() + 5];
        assert_eq!(marker, b":GTD:");
    }

    #[test]
    fn gtd_payload_expiry_encoding() {
        let rs = vec![0x75, 0x75, 0x51];
        let daa: u64 = 12345678;
        let gtd = build_gtd_order_payload(&rs, Some(daa));
        let standard = build_order_payload(&rs, false);
        let daa_bytes = &gtd[standard.len() + 5..];
        assert_eq!(daa_bytes.len(), 8);
        let decoded = u64::from_le_bytes(daa_bytes.try_into().unwrap());
        assert_eq!(decoded, daa);
    }

    #[test]
    fn gtd_payload_zero_expiry() {
        let rs = vec![0xAA; 100];
        let gtd = build_gtd_order_payload(&rs, Some(0));
        let standard = build_order_payload(&rs, false);
        assert!(gtd.len() > standard.len());
        let daa_bytes = &gtd[standard.len() + 5..];
        let decoded = u64::from_le_bytes(daa_bytes.try_into().unwrap());
        assert_eq!(decoded, 0);
    }

    #[test]
    fn gtd_payload_max_expiry() {
        let rs = vec![0xBB; 50];
        let daa = u64::MAX;
        let gtd = build_gtd_order_payload(&rs, Some(daa));
        let standard = build_order_payload(&rs, false);
        let daa_bytes = &gtd[standard.len() + 5..];
        let decoded = u64::from_le_bytes(daa_bytes.try_into().unwrap());
        assert_eq!(decoded, u64::MAX);
    }

    #[test]
    fn market_buy_generates_valid_price() {
        let amount = 10_000_000u64;
        let (num, den) = resolve_market_price("buy", amount);
        let price = Price::new(num, den);
        assert!(price.is_ok());
    }

    #[test]
    fn market_sell_generates_valid_price() {
        let amount = 10_000_000u64;
        let (num, den) = resolve_market_price("sell", amount);
        let price = Price::new(num, den);
        assert!(price.is_ok());
    }

    // --- parse_decimal_price tests ---

    #[test]
    fn price_integer() {
        assert_eq!(parse_decimal_price("100").unwrap(), (100, 1));
    }

    #[test]
    fn price_zero_point_zero_five() {
        // 0.05 = 5/100 = 1/20
        assert_eq!(parse_decimal_price("0.05").unwrap(), (1, 20));
    }

    #[test]
    fn price_one_point_five() {
        // 1.5 = 15/10 = 3/2
        assert_eq!(parse_decimal_price("1.5").unwrap(), (3, 2));
    }

    #[test]
    fn price_zero_point_zero_zero_one() {
        assert_eq!(parse_decimal_price("0.001").unwrap(), (1, 1000));
    }

    #[test]
    fn price_with_whitespace() {
        assert_eq!(parse_decimal_price("  2.5  ").unwrap(), (5, 2));
    }

    #[test]
    fn price_many_decimals() {
        // 0.00001 = 1/100000
        assert_eq!(parse_decimal_price("0.00001").unwrap(), (1, 100000));
    }

    #[test]
    fn price_integer_one() {
        assert_eq!(parse_decimal_price("1").unwrap(), (1, 1));
    }

    #[test]
    fn price_trailing_dot_errors() {
        assert!(parse_decimal_price("5.").is_err());
    }

    #[test]
    fn price_empty_errors() {
        assert!(parse_decimal_price("").is_err());
    }

    #[test]
    fn price_zero_errors() {
        assert!(parse_decimal_price("0.0").is_err());
    }

    #[test]
    fn price_letters_errors() {
        assert!(parse_decimal_price("abc").is_err());
    }

    #[test]
    fn price_no_leading_zero() {
        // ".5" should parse as 0.5 = 1/2
        assert_eq!(parse_decimal_price(".5").unwrap(), (1, 2));
    }

    #[test]
    fn price_large_integer() {
        assert_eq!(parse_decimal_price("1000000").unwrap(), (1000000, 1));
    }

    #[test]
    fn price_simplifies_gcd() {
        // 0.25 = 25/100 = 1/4
        assert_eq!(parse_decimal_price("0.25").unwrap(), (1, 4));
    }

    // --- parse_kas_amount tests ---

    #[test]
    fn kas_integer() {
        assert_eq!(parse_kas_amount("5").unwrap(), 500_000_000);
    }

    #[test]
    fn kas_decimal() {
        assert_eq!(parse_kas_amount("0.1").unwrap(), 10_000_000);
    }

    #[test]
    fn kas_one_point_five() {
        assert_eq!(parse_kas_amount("1.5").unwrap(), 150_000_000);
    }

    #[test]
    fn kas_small_fraction() {
        // 0.00000001 = 1 sompi
        assert_eq!(parse_kas_amount("0.00000001").unwrap(), 1);
    }

    #[test]
    fn kas_too_many_decimals() {
        assert!(parse_kas_amount("0.000000001").is_err());
    }

    #[test]
    fn kas_empty_errors() {
        assert!(parse_kas_amount("").is_err());
    }

    #[test]
    fn kas_ten() {
        assert_eq!(parse_kas_amount("10").unwrap(), 1_000_000_000);
    }

    #[test]
    fn kas_zero_point_five() {
        assert_eq!(parse_kas_amount("0.5").unwrap(), 50_000_000);
    }
}
