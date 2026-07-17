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
use kob_core::tx::{to_rpc_payload, CovenantBinding, TxOutput};
use kob_core::types::{Network, Outpoint};
use kob_core::wallet::WalletContext;
use kob_engine::matcher::batch::{BatchOrder, OrderType, OutputPurpose};
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
    _max_matcher_fee: u64,
    fee_bps: Option<u16>,
    ioc: bool,
    partial: bool,
) -> anyhow::Result<()> {
    let wallet = WalletContext::load(wallet_path)?;
    let privkey = *wallet.privkey_bytes();
    let pubkey = wallet.pubkey;

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

        let rs = if entry.version == 18 {
            contract::spot::order::build_sell_redeem_script(
                entry.price_num,
                entry.price_den,
                entry.min_fill,
                &sell_owner,
                &sell_spkh,
                &contract::compute_token_unit_spk_hash(&pubkey), // otspkh (E1 expire seat)
                entry.max_matcher_fee, // v18 caches store BPS
                0, // cancel_pending
                entry.expiry_daa,
            )?
        } else {
            anyhow::bail!("Sell order {} has unsupported version {} (pre-v18 removed in Stage E)", op_str, entry.version);
        };
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
            min_fill: entry.min_fill,
            oco_path: None,
            bracket_meta: None,
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
        } else if entry.version == 18 {
            // v18 delivery re-wrap: v18 buys commit the owner's token_unit
            // P2SH hash (fills deliver spendable KCC20 token_units).
            contract::compute_token_unit_spk_hash(&pubkey)
        } else {
            spk_hash
        };

        let rs = if entry.version == 18 {
            contract::spot::order::build_buy_redeem_script(
                &tcid,
                entry.price_num,
                entry.price_den,
                entry.min_fill,
                &buy_owner,
                &buy_spkh,
                &kob_core::compute_p2pk_spk_hash(&pubkey), // okspkh (E1 expire seat)
                entry.max_matcher_fee, // v18 caches store BPS
                0, // cancel_pending
                entry.expiry_daa,
            )?
        } else {
            anyhow::bail!("Buy order {} has unsupported version {} (pre-v18 removed in Stage E)", op_str, entry.version);
        };
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

        // Buyer delivery SPK: MUST hash (OpTxOutputSpk blake2b) to the buy's
        // committed bspkh or the covenant F2 check rejects the fill. This is
        // a self-match utility (the buyer is this wallet), so the candidates
        // are the raw P2PK SPK (pre-D2 orders) and the token_unit P2SH SPK
        // (D2 delivery re-wrap).
        let mut p2pk_spk = Vec::with_capacity(34);
        p2pk_spk.push(0x20);
        p2pk_spk.extend_from_slice(&pubkey);
        p2pk_spk.push(0xac);
        let (buyer_spk, buyer_spk_version): (Vec<u8>, u16) =
            if kob_core::compute_spk_hash(0, &p2pk_spk) == buy_spkh {
                (p2pk_spk, 0)
            } else if contract::compute_token_unit_spk_hash(&pubkey) == buy_spkh {
                let tu = contract::build_token_unit_p2sh_spk(&pubkey);
                (tu.script().to_vec(), tu.version)
            } else {
                anyhow::bail!(
                    "Buy order {} commits a delivery SPK hash that matches neither this \
                     wallet's P2PK SPK nor its token_unit P2SH SPK. Cannot construct the \
                     token delivery output.",
                    op_str
                );
            };

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
            counterparty_spk_version: buyer_spk_version,
            min_fill: entry.min_fill,
            oco_path: None,
            bracket_meta: None,
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
    let mut plan = if partial {
        // v18 Op2 partial (item C): ONE v18 buy spends part of its KAS
        // against the sells and keeps a byte-exact self-SPK residual UTXO.
        if buys.len() != 1 {
            anyhow::bail!("--partial requires exactly 1 buy order (got {})", buys.len());
        }
        if buys[0].version != 18 {
            anyhow::bail!("--partial requires a v18 buy (Op2 partial fill); got v{}", buys[0].version);
        }
        println!("Partial (Op2): buy fills {} sell(s), residual continues", sells.len());
        kob_engine::matcher::batch::plan_partial_match(
            &sells,
            &buys[0],
            Some(wallet_utxo_info.clone()),
            &matcher_spk,
            0,
            fee_bps,
        )?
    } else if ioc {
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
                // v17/v18 plans provide the per-output authorizing sell input
                // in output_auth_input; legacy plans fall back to
                // buy_seller_map. BuyResidual (v18 Op2) is deliberately NOT
                // covenant-bound: it is plain KAS under the buy's P2SH.
                let authorizing_input = plan.output_auth_input
                    .get(&idx)
                    .copied()
                    .or_else(|| plan.buy_seller_map.get(&idx).map(|&v| v as u16))
                    .unwrap_or(0);
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
    let (mut exact_fee, delta) = plan.converge_fee_exact(&tx, &sigscripts);
    println!();
    println!("Phase 2 Convergence:");
    println!("  Exact compute mass: {} sompi", exact_fee);
    println!("  Fee delta:          {} sompi (recovered)", delta);

    // Optional fee floor override (sompi): the node's transient-mass floor
    // (byte-proportional) can exceed the compute-mass fee on covenant-heavy
    // shapes; KOB_FEE_FLOOR lets the operator force a higher exact fee.
    let mut fee_bumped = false;
    if let Ok(v) = std::env::var("KOB_FEE_FLOOR") {
        if let Ok(floor) = v.parse::<u64>() {
            if floor > exact_fee {
                println!("  Fee floor override: {} sompi (KOB_FEE_FLOOR)", floor);
                exact_fee = floor;
                fee_bumped = true;
            }
        }
    }

    if delta > 0 || fee_bumped {
        // Re-adjust outputs
        plan.apply_exact_fee(exact_fee);

        // Fee floor bump: apply_exact_fee only recovers a Phase-1 surplus; a
        // floor ABOVE the converged fee must come out of the matcher-side
        // outputs (WalletChange first, then MatcherFee) — never seller/buyer.
        if fee_bumped {
            let mut need = exact_fee.saturating_sub(plan.total_fee);
            if need > 0 {
                for purpose in [OutputPurpose::WalletChange, OutputPurpose::MatcherFee] {
                    if need == 0 { break; }
                    if let Some(o) = plan.outputs.iter_mut().find(|o| o.purpose == purpose) {
                        let take = need.min(o.value.saturating_sub(1_000_000));
                        o.value -= take;
                        need -= take;
                    }
                }
                if need > 0 {
                    anyhow::bail!("KOB_FEE_FLOOR: no matcher-side output can absorb the fee bump ({} sompi short)", need);
                }
                plan.total_fee = exact_fee;
            }
        }

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
                    let authorizing_input = plan.output_auth_input
                        .get(&idx)
                        .copied()
                        .or_else(|| plan.buy_seller_map.get(&idx).map(|&v| v as u16))
                        .unwrap_or(0);
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

/// `kob-cli match-ring` — settle a v18 swap ring (2-cycle or triangle).
///
/// Each `--leg` is `txid:index:rs_hex[:owner_spk_hex]` in cycle order (leg
/// i's target token == leg (i+1)%n's source token). The plan is produced by
/// `plan_ring_match` (per-leg F2/F3/F4 feasibility, all-or-nothing); every
/// delivery/skim output carries the GIVER leg's token CovenantBinding.
pub async fn run_ring(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    leg_strs: &[String],
) -> anyhow::Result<()> {
    use kob_engine::matcher::batch::{plan_ring_match, RingLegOrder};

    let wallet = WalletContext::load(wallet_path)?;
    let privkey = *wallet.privkey_bytes();
    let pubkey = wallet.pubkey;

    // Wallet P2PK SPK: matcher skim destination + default leg owner SPK.
    let mut wallet_p2pk = Vec::with_capacity(34);
    wallet_p2pk.push(0x20);
    wallet_p2pk.extend_from_slice(&pubkey);
    wallet_p2pk.push(0xac);

    println!("v18 Ring Settle ({} legs)", leg_strs.len());
    println!("==========================");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Parse legs.
    let mut legs: Vec<RingLegOrder> = Vec::with_capacity(leg_strs.len());
    for (i, leg_str) in leg_strs.iter().enumerate() {
        let parts: Vec<&str> = leg_str.split(':').collect();
        if parts.len() != 3 && parts.len() != 4 {
            anyhow::bail!(
                "--leg[{}] must be txid:index:rs_hex[:owner_spk_hex], got {} parts",
                i, parts.len()
            );
        }
        let tx_id = parts[0].to_string();
        let index: u32 = parts[1].parse()
            .map_err(|_| anyhow::anyhow!("--leg[{}]: invalid output index '{}'", i, parts[1]))?;
        let rs = hex::decode(parts[2])
            .map_err(|e| anyhow::anyhow!("--leg[{}]: invalid RS hex: {}", i, e))?;
        let parsed = contract::spot::swap::parse_swap_order_rs(&rs)
            .ok_or_else(|| anyhow::anyhow!(
                "--leg[{}]: not a v18 swap RS (expected {} bytes, got {})",
                i, contract::spot::swap::SWAP_RS_SIZE, rs.len()
            ))?;

        // Owner SPK: explicit per-leg (2B version LE + script), or derived
        // for this wallet by matching the RS's committed owner_spk_hash --
        // token_unit P2SH first (D2 delivery re-wrap), raw P2PK for pre-D2
        // legs. plan_ring_match re-verifies blake2b(spk) == owner_spk_hash
        // (F3) either way.
        let (owner_spk_version, owner_spk) = if parts.len() == 4 {
            let raw = hex::decode(parts[3])
                .map_err(|e| anyhow::anyhow!("--leg[{}]: invalid owner SPK hex: {}", i, e))?;
            if raw.len() <= 2 {
                anyhow::bail!("--leg[{}]: owner SPK must be 2B version + script bytes", i);
            }
            (u16::from_le_bytes([raw[0], raw[1]]), raw[2..].to_vec())
        } else if contract::compute_token_unit_spk_hash(&pubkey) == parsed.owner_spk_hash {
            let tu = contract::build_token_unit_p2sh_spk(&pubkey);
            (tu.version, tu.script().to_vec())
        } else {
            (0u16, wallet_p2pk.clone())
        };

        // Resolve the leg UTXO value from the RS P2SH address.
        let p2sh = build_p2sh(&rs);
        let addr = crate::cancel::kaspa_address_encode(
            network.address_prefix(), 8, &p2sh.script()[2..34],
        );
        let utxos = rpc.get_utxos_by_addresses(&[&addr]).await?;
        let value = utxos.iter()
            .find(|u| u.outpoint.transaction_id == tx_id && u.outpoint.index == index)
            .map(|u| u.utxo_entry.amount)
            .ok_or_else(|| anyhow::anyhow!(
                "--leg[{}]: swap UTXO {}:{} not found on chain (spent or wrong RS?)",
                i, tx_id, index
            ))?;

        println!(
            "  leg[{}] {}:{}  {} token sompi  {} -> {}",
            i, &tx_id[..16.min(tx_id.len())], index, value,
            &hex::encode(parsed.source_token_cov_id)[..12],
            &hex::encode(parsed.target_token_cov_id)[..12],
        );

        legs.push(RingLegOrder {
            outpoint: (tx_id, index),
            redeem_script: rs,
            utxo_value: value,
            owner_spk,
            owner_spk_version,
        });
    }

    // Wallet fee UTXO.
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
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
    println!("Fee UTXO:  {}:{} ({} sompi)", wallet_utxo_info.0, wallet_utxo_info.1, wallet_utxo_info.2);

    // Plan (F2/F3/F4 checked exactly here).
    let plan = plan_ring_match(&legs, Some(wallet_utxo_info), &wallet_p2pk, 0)?;
    plan.validate()?;
    let batch_tx = plan.build_tx()?;

    println!();
    println!("Ring plan:");
    println!("  Miner fee:       {} sompi", plan.total_fee);
    println!("  Matcher skim:    {} token sompi", plan.matcher_surplus);
    println!("  Outputs:         {}", plan.outputs.len());

    // Build the TX: version 1 (covenant bindings), lock_time 50, leg inputs
    // CSV(50), wallet last.
    let mut tx = kob_core::tx::Transaction::new(1);
    tx.lock_time = 50;
    for (leg, _idx) in &plan.legs {
        let p2sh = build_p2sh(&leg.redeem_script);
        tx.inputs.push(kob_core::tx::TxInput {
            prev_tx_id: leg.outpoint.0.clone(),
            prev_index: leg.outpoint.1,
            sequence: 50,
            sig_op_count: 0,
            script_version: p2sh.version,
            script_bytes: p2sh.script().to_vec(),
            value: leg.utxo_value,
        });
    }
    tx.inputs.push(kob_core::tx::TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_utxo.script_bytes(),
        value: fee_utxo.utxo_entry.amount,
    });
    for (i, out) in batch_tx.outputs.iter().enumerate() {
        let covenant = plan.output_auth_input.get(&i).map(|&auth| {
            CovenantBinding::new(
                auth,
                kob_core::compat::parse_hash(&hex::encode(plan.leg_source_tokens[auth as usize])).unwrap(),
            )
        });
        tx.outputs.push(TxOutput::new(
            out.value,
            out.spk_version,
            out.script_public_key.clone(),
            covenant,
        ));
    }

    // Sigscripts: legs from the plan, wallet signed last.
    let mut sigscripts: Vec<Vec<u8>> = batch_tx.inputs.iter()
        .map(|i| i.sigscript.clone())
        .collect();
    let wallet_idx = tx.inputs.len() - 1;
    let sighash = compute_sighash(&tx, wallet_idx)?;
    let sig = signing::schnorr_sign(&privkey, &sighash)?;
    sigscripts[wallet_idx] = signing::build_p2pk_sigscript(&sig);

    // Mass summary.
    {
        let in_vals: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let out_vals: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        let storage_mass = compute_storage_mass(&in_vals, &out_vals);
        let exact_compute = calc_mass_with_sigscripts(&tx, &sigscripts);
        println!();
        println!(
            "Storage mass:  {:>9} / {:>9} ({})",
            storage_mass, MAX_TX_MASS,
            if storage_mass <= MAX_TX_MASS { "OK" } else { "OVER" }
        );
        println!("Compute mass:  {:>9} (exact, post-sign)", exact_compute);
    }

    // Submit.
    let payload = to_rpc_payload(&tx, &sigscripts);
    println!();
    println!("Submitting ring settle transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! v18 ring settled ({} legs, all-or-nothing).", legs.len());
    println!("TXID: {}", tx_id);
    for (i, out) in plan.outputs.iter().enumerate() {
        println!("  [{}] {:?}: {} sompi", i, out.purpose, out.value);
    }

    Ok(())
}
