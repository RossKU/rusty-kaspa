//! `kob-cli match-batch` -- Execute an N:M atomic batch match.
//!
//! Builds a single Kaspa transaction that settles N sell orders against M buy
//! orders atomically, using 2-phase fee convergence for exact miner fee.
//!
//! Input layout:
//!   `[sell_0 .. sell_{N-1}] [buy_0 .. buy_{M-1}] [wallet_fee_utxo]`
//!
//! Output layout:
//!   `[seller_kas_0 .. seller_kas_{N-1}] [buyer_tokens_0 .. buyer_tokens_{M-1}] [matcher_fee?]`

use crate::node::NodeClient;
use crate::order_cache::{self, OrderCache};
use crate::signing;
use kob_core::contract;
use kob_core::mass::{calc_mass_with_sigscripts, compute_storage_mass, MAX_TX_MASS};
use kob_core::p2sh::{blake2b_256, build_p2sh, compute_p2pk_spk_hash};
use kob_core::sighash::compute_sighash;
use kob_core::tx::{to_rpc_payload, CovenantBinding, TxInput, TxOutput};
use kob_core::types::{Network, Outpoint};
use kob_core::wallet::WalletFile;
use kob_core::MIN_UTXO_VALUE;
use kob_engine::matcher::batch::{BatchOrder, BatchPlan, OrderType};
use std::path::Path;
use tracing::info;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    sell_outpoint_strs: &[String],
    buy_outpoint_strs: &[String],
    token_hex: &str,
    max_matcher_fee: u64,
    fee_bps: Option<u16>,
    ioc: bool,
) -> anyhow::Result<()> {
    let wallet = WalletFile::load(wallet_path)?;
    let privkey = wallet.private_key_bytes()?;
    let pubkey = wallet.public_key_bytes()?;

    // Parse token covenant ID
    let token_bytes = hex::decode(token_hex)?;
    if token_bytes.len() != 32 {
        anyhow::bail!("--token must be 64 hex characters (32 bytes)");
    }
    let mut tcid = [0u8; 32];
    tcid.copy_from_slice(&token_bytes);

    // Parse outpoints
    let sell_outpoints: Vec<Outpoint> = sell_outpoint_strs
        .iter()
        .map(|s| Outpoint::parse(s))
        .collect::<Result<_, _>>()?;
    let buy_outpoints: Vec<Outpoint> = buy_outpoint_strs
        .iter()
        .map(|s| Outpoint::parse(s))
        .collect::<Result<_, _>>()?;

    if sell_outpoints.is_empty() {
        anyhow::bail!("At least one --sell-outpoint is required");
    }
    if buy_outpoints.is_empty() {
        anyhow::bail!("At least one --buy-outpoint is required");
    }

    // Load order cache for parameter lookup
    let cache_path = order_cache::orders_cache_path(wallet_path);
    let cache = OrderCache::load(&cache_path);

    println!("Batch Match");
    println!("===========");
    println!("Token:          {}", token_hex);
    println!("Sell orders:    {}", sell_outpoints.len());
    println!("Buy orders:     {}", buy_outpoints.len());
    println!("Matcher:        {}", wallet.address);
    println!();

    // Connect
    info!(sells = sell_outpoints.len(), buys = buy_outpoints.len(), "executing batch match");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Build matcher P2PK SPK
    let mut matcher_spk = Vec::with_capacity(34);
    matcher_spk.push(0x20);
    matcher_spk.extend_from_slice(&pubkey);
    matcher_spk.push(0xac);

    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);

    // Build BatchOrders from cache + chain queries
    let mut sells = Vec::new();
    for op in &sell_outpoints {
        let op_str = format!("{}:{}", op.transaction_id, op.index);
        let entry = cache.orders.iter()
            .find(|e| e.outpoint == op_str)
            .ok_or_else(|| anyhow::anyhow!(
                "Sell order {} not found in orders.json cache. Deploy it first or add manually.", op_str
            ))?;

        let sell_owner: [u8; 32] = if !entry.owner_hash.is_empty() {
            hex::decode(&entry.owner_hash)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid owner_hash in cache for {}", op_str))?
        } else {
            owner_hash
        };
        let sell_spkh: [u8; 32] = if !entry.spk_hash.is_empty() {
            hex::decode(&entry.spk_hash)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid spk_hash in cache for {}", op_str))?
        } else {
            spk_hash
        };

        let rs = contract::build_sell_redeem_script(
            entry.price_num,
            entry.price_den,
            entry.min_fill,
            &sell_owner,
            &sell_spkh,
            entry.max_matcher_fee,
            0, // cancel_pending
            entry.expiry_daa,
        )?;
        let p2sh = build_p2sh(&rs);

        // Query value from chain
        let addr = crate::cancel::kaspa_address_encode(
            network.address_prefix(), 8, &p2sh.script()[2..34],
        );
        let utxos = rpc.get_utxos_by_addresses(&[&addr]).await?;
        let value = utxos.iter()
            .find(|u| u.outpoint.transaction_id == op.transaction_id && u.outpoint.index == op.index)
            .map(|u| u.utxo_entry.amount)
            .ok_or_else(|| anyhow::anyhow!("Sell order {} not found on chain", op_str))?;

        // Seller SPK = derived from seller pubkey in owner_hash
        // For self-deployed orders, seller = wallet owner
        let mut seller_spk = Vec::with_capacity(34);
        seller_spk.push(0x20);
        seller_spk.extend_from_slice(&pubkey);
        seller_spk.push(0xac);

        println!("  sell {}: value={} price={}/{}", op_str, value, entry.price_num, entry.price_den);

        sells.push(BatchOrder {
            outpoint: (op.transaction_id.clone(), op.index),
            order_type: OrderType::Sell,
            version: entry.version,
            token_cov_id: tcid,
            price_num: entry.price_num,
            price_den: entry.price_den,
            amount: value, // sell amount = token amount = UTXO value
            redeem_script: rs,
            utxo_value: value,
            counterparty_spk: seller_spk,
            counterparty_spk_version: 0,
        });
    }

    let mut buys = Vec::new();
    for op in &buy_outpoints {
        let op_str = format!("{}:{}", op.transaction_id, op.index);
        let entry = cache.orders.iter()
            .find(|e| e.outpoint == op_str)
            .ok_or_else(|| anyhow::anyhow!(
                "Buy order {} not found in orders.json cache. Deploy it first or add manually.", op_str
            ))?;

        let buy_owner: [u8; 32] = if !entry.owner_hash.is_empty() {
            hex::decode(&entry.owner_hash)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid owner_hash in cache for {}", op_str))?
        } else {
            owner_hash
        };
        let buy_spkh: [u8; 32] = if !entry.spk_hash.is_empty() {
            hex::decode(&entry.spk_hash)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid spk_hash in cache for {}", op_str))?
        } else {
            spk_hash
        };

        let rs = contract::build_buy_redeem_script(
            &tcid,
            entry.price_num,
            entry.price_den,
            entry.min_fill,
            &buy_owner,
            &buy_spkh,
            entry.max_matcher_fee,
            0, // cancel_pending
            entry.expiry_daa,
        )?;
        let p2sh = build_p2sh(&rs);

        // Query value from chain
        let addr = crate::cancel::kaspa_address_encode(
            network.address_prefix(), 8, &p2sh.script()[2..34],
        );
        let utxos = rpc.get_utxos_by_addresses(&[&addr]).await?;
        let value = utxos.iter()
            .find(|u| u.outpoint.transaction_id == op.transaction_id && u.outpoint.index == op.index)
            .map(|u| u.utxo_entry.amount)
            .ok_or_else(|| anyhow::anyhow!("Buy order {} not found on chain", op_str))?;

        // Buyer SPK = buyer's address
        let mut buyer_spk = Vec::with_capacity(34);
        buyer_spk.push(0x20);
        buyer_spk.extend_from_slice(&pubkey);
        buyer_spk.push(0xac);

        println!("  buy  {}: value={} price={}/{}", op_str, value, entry.price_num, entry.price_den);

        buys.push(BatchOrder {
            outpoint: (op.transaction_id.clone(), op.index),
            order_type: OrderType::Buy,
            version: entry.version,
            token_cov_id: tcid,
            price_num: entry.price_num,
            price_den: entry.price_den,
            amount: value, // buy amount = KAS amount
            redeem_script: rs,
            utxo_value: value,
            counterparty_spk: buyer_spk,
            counterparty_spk_version: 0,
        });
    }

    // Get wallet UTXOs for fee payment
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;

    // Select wallet UTXO for fee payment
    let fee_utxo = wallet_utxos.iter()
        .find(|u| !u.is_p2sh())
        .ok_or_else(|| anyhow::anyhow!(
            "No spendable UTXO for fee. Fund the wallet or run `kob wallet consolidate`."
        ))?;

    let wallet_utxo_info = (
        fee_utxo.outpoint.transaction_id.clone(),
        fee_utxo.outpoint.index,
        fee_utxo.utxo_entry.amount,
    );

    println!();
    println!("Fee UTXO:       {}:{} ({} sompi)", wallet_utxo_info.0, wallet_utxo_info.1, wallet_utxo_info.2);

    // ---- Phase 1: Plan with estimated fee ----
    let mut plan = if ioc {
        // Auto-detect IOC direction:
        //   1 buy  + N sells → buy sweeps sells (plan_ioc_match)
        //   N buys + 1 sell  → sell sweeps buys (plan_sell_ioc_match)
        if buys.len() == 1 && sells.len() >= 1 {
            println!("IOC direction: buy sweeps {} sells", sells.len());
            kob_engine::matcher::batch::plan_ioc_match(
                &sells,
                &buys[0],
                Some(wallet_utxo_info.clone()),
                &matcher_spk,
                0,
                fee_bps,
            )?
        } else if sells.len() == 1 && buys.len() >= 1 {
            println!("IOC direction: sell sweeps {} buys", buys.len());
            kob_engine::matcher::batch::plan_sell_ioc_match(
                &sells[0],
                &buys,
                Some(wallet_utxo_info.clone()),
                &matcher_spk,
                0,
                fee_bps,
            )?
        } else {
            anyhow::bail!(
                "--ioc requires asymmetric orders: 1 buy + N sells or N buys + 1 sell, got {} buys + {} sells",
                buys.len(), sells.len()
            );
        }
    } else {
        kob_engine::matcher::batch::plan_batch_match(
            &sells,
            &buys,
            Some(wallet_utxo_info.clone()),
            &matcher_spk,
            0,
            fee_bps,
        )?
    };
    plan.validate()?;

    println!();
    println!("Phase 1 Plan:");
    println!("  Estimated fee:    {} sompi", plan.total_fee);
    println!("  Matcher surplus:  {} sompi", plan.matcher_surplus);
    println!("  Outputs:          {}", plan.outputs.len());

    // Build transaction from plan
    let mut tx = plan.to_transaction();

    // Fix wallet input SPK (to_transaction uses dummy, we need the real one)
    if let Some(last_input) = tx.inputs.last_mut() {
        if plan.wallet_input.is_some() {
            last_input.script_bytes = fee_utxo.script_bytes();
            last_input.script_version = fee_utxo.utxo_entry.script_public_key.version;
        }
    }

    // Set covenant bindings on token outputs.
    // Buyer token outputs and sell remainder (IOC token change) need covenant
    // binding authorized by the sell input that provides the tokens.
    let token_hash = kob_core::compat::parse_hash(&token_hex.to_string()).unwrap();
    for (idx, planned) in plan.outputs.iter().enumerate() {
        use kob_engine::matcher::batch::OutputPurpose;
        match planned.purpose {
            OutputPurpose::BuyerTokens => {
                let authorizing_input = plan.buy_seller_map
                    .get(&idx)
                    .copied()
                    .unwrap_or(0) as u16;
                tx.outputs[idx].covenant = Some(CovenantBinding::new(
                    authorizing_input,
                    token_hash,
                ));
            }
            OutputPurpose::SellRemainder => {
                // Sell IOC: token change back to seller, authorized by sell input (0)
                tx.outputs[idx].covenant = Some(CovenantBinding::new(
                    0,
                    token_hash,
                ));
            }
            _ => {}
        }
    }

    // Build sigscripts from plan
    let batch_tx = plan.build_tx()?;

    // Collect sigscripts in order (sell, buy, wallet)
    let mut sigscripts: Vec<Vec<u8>> = batch_tx.inputs.iter()
        .map(|i| i.sigscript.clone())
        .collect();

    // Sign wallet input (last input if present)
    if plan.wallet_input.is_some() {
        let wallet_idx = tx.inputs.len() - 1;
        let sighash = compute_sighash(&tx, wallet_idx)?;
        let sig = signing::schnorr_sign(&privkey, &sighash)?;
        let wallet_ss = signing::build_p2pk_sigscript(&sig);
        sigscripts[wallet_idx] = wallet_ss;
    }

    // ---- Phase 2: Exact mass with real sigscripts ----
    let (exact_fee, delta) = plan.converge_fee_exact(&tx, &sigscripts);
    println!();
    println!("Phase 2 Convergence:");
    println!("  Exact compute mass: {} sompi", exact_fee);
    println!("  Fee delta:          {} sompi (recovered)", delta);

    if delta > 0 {
        // Re-adjust outputs
        plan.apply_exact_fee(exact_fee);

        // Rebuild tx outputs from adjusted plan
        tx.outputs.clear();
        for planned in &plan.outputs {
            tx.outputs.push(TxOutput::new(
                planned.value,
                planned.spk_version,
                planned.script_public_key.clone(),
                None,
            ));
        }

        // Re-set covenant bindings
        for (idx, planned) in plan.outputs.iter().enumerate() {
            use kob_engine::matcher::batch::OutputPurpose;
            match planned.purpose {
                OutputPurpose::BuyerTokens => {
                    let authorizing_input = plan.buy_seller_map
                        .get(&idx)
                        .copied()
                        .unwrap_or(0) as u16;
                    tx.outputs[idx].covenant = Some(CovenantBinding::new(
                        authorizing_input,
                        token_hash,
                    ));
                }
                OutputPurpose::SellRemainder => {
                    tx.outputs[idx].covenant = Some(CovenantBinding::new(
                        0,
                        token_hash,
                    ));
                }
                _ => {}
            }
        }

        // Re-sign wallet input (outputs changed -> sighash changed)
        if plan.wallet_input.is_some() {
            let wallet_idx = tx.inputs.len() - 1;
            let sighash = compute_sighash(&tx, wallet_idx)?;
            let sig = signing::schnorr_sign(&privkey, &sighash)?;
            sigscripts[wallet_idx] = signing::build_p2pk_sigscript(&sig);
        }

        // Verify final mass
        let final_mass = calc_mass_with_sigscripts(&tx, &sigscripts);
        println!("  Final compute mass: {} sompi (after re-sign)", final_mass);
    }

    // Fee transparency summary
    {
        let in_vals: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let out_vals: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        let storage_mass = compute_storage_mass(&in_vals, &out_vals);
        let exact_compute = calc_mass_with_sigscripts(&tx, &sigscripts);
        let total_out: u64 = out_vals.iter().sum();
        let total_in: u64 = in_vals.iter().sum();
        let actual_fee = total_in.saturating_sub(total_out);

        println!();
        println!("Fee Summary");
        println!("-----------");
        println!(
            "Storage mass:     {:>9} / {:>9} ({})",
            storage_mass, MAX_TX_MASS,
            if storage_mass <= MAX_TX_MASS { "OK" } else { "OVER" }
        );
        println!("Compute mass:     {:>9} (exact, post-sign)", exact_compute);
        println!("Miner fee:        {:>9} sompi", actual_fee);
        println!("Fee == mass:      {}", if actual_fee == exact_compute { "YES (exact)" } else { "NO (mismatch)" });
    }

    // Debug: print TX details
    println!();
    println!("TX Debug:");
    println!("  Version: {}", tx.version);
    println!("  Inputs: {}", tx.inputs.len());
    for (i, inp) in tx.inputs.iter().enumerate() {
        println!("    [{i}] {}:{} seq={} sigop={} spk_v={} spk_len={} val={}",
            &inp.prev_tx_id[..16], inp.prev_index, inp.sequence,
            inp.sig_op_count, inp.script_version,
            inp.script_bytes.len(), inp.value);
        println!("        ss_len={}", sigscripts[i].len());
    }
    println!("  Outputs: {}", tx.outputs.len());
    for (i, out) in tx.outputs.iter().enumerate() {
        println!("    [{i}] val={} spk_len={} cov={:?}",
            out.value, out.script_bytes().len(),
            out.covenant.as_ref().map(|c| format!("auth={} id={}", c.authorizing_input, &hex::encode(c.covenant_id.as_bytes())[..16])));
    }

    // Submit
    let payload = to_rpc_payload(&tx, &sigscripts);
    println!();
    println!("Submitting batch match transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Batch match transaction submitted.");
    println!("TXID: {}", tx_id);
    println!();
    for (i, sell) in sells.iter().enumerate() {
        println!("  Seller[{}] received: {} sompi KAS ({}:{})",
            i, plan.outputs[i].value, sell.outpoint.0, sell.outpoint.1);
    }
    for (j, buy) in buys.iter().enumerate() {
        println!("  Buyer[{}]  received: {} sompi tokens ({}:{})",
            j, plan.outputs[sells.len() + j].value, buy.outpoint.0, buy.outpoint.1);
    }
    if plan.matcher_surplus > 0 {
        println!("  Matcher surplus:    {} sompi", plan.matcher_surplus);
    }
    println!("  Miner fee:          {} sompi", plan.total_fee);

    Ok(())
}
