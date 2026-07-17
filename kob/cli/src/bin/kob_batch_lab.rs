//! EXPERIMENTAL batch-limit lab bin (kob/BATCH_LIMITS.md) — testnet only.
//!
//! Deploys and settles LARGE-N experimental buy covenants
//! (`kob_core::contract::spot::lab`, slot count > the shipping MAX_N=8) to
//! prove on a live node what the offline lab measures. NOT product code:
//! the shipping deploy/parse/settle paths refuse these RS lengths by
//! design, so this bin drives the node directly.
//!
//! Commands (env: NODE, WALLET):
//!   deploy-buy <token_hex> <max_n> <kas_amount_sompi>
//!       Escrow `kas_amount` at the experimental buy P2SH (price 1/1,
//!       min_fill 30M tokens, mmfee 2000 bps, GTC). Prints RS length,
//!       address, TXID.
//!   settle <token_hex> <max_n> <buy_txid:idx> <sell_pnum> <sell_pden>
//!          <sell_min_fill> <sell_mmfee_bps>
//!       Sweeps ALL resting sells at the (single-price, self-owned) sell
//!       address into the experimental buy in ONE transaction: merged
//!       seller-KAS output at koi=0, per-sell token_unit deliveries with
//!       CovenantBinding, wallet change. Pads with small wallet inputs
//!       until KIP-9 storage mass fits the 500k block limit. Prints the
//!       predicted compute/transient/storage masses and the TXID.

use std::env;
use std::path::PathBuf;

use kob_cli::cancel::kaspa_address_encode;
use kob_cli::node::NodeClient;
use kob_cli::signing;
use kob_core::contract::spot::lab;
use kob_core::contract::spot::order;
use kob_core::mass::{calc_mass_with_sigscripts, compute_storage_mass_ex};
use kob_core::p2sh::{blake2b_256, build_p2sh, compute_p2pk_spk_hash};
use kob_core::sighash::compute_sighash;
use kob_core::tx::{to_rpc_payload, CovenantBinding, Transaction, TxInput, TxOutput};
use kob_core::rpc_types::RpcUtxo;
use kob_core::wallet::WalletContext;

const STORAGE_BLOCK_LIMIT: u64 = 500_000;
const STORAGE_TARGET: u64 = 460_000; // margin under the block limit

fn parse_outpoint(s: &str) -> anyhow::Result<(String, u32)> {
    let (txid, idx) = s
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("outpoint must be TXID:IDX"))?;
    Ok((txid.to_string(), idx.parse()?))
}

/// Exact serialized size (the node's estimate formula) for fee purposes:
/// v1 = header 94 + per input (54 + sigscript) + outputs.
fn tx_size_with_sigs(tx: &Transaction, sigs: &[Vec<u8>]) -> u64 {
    let mut size = 2 + 8 + 8 + 8 + 20 + 8 + 32 + 8 + tx.payload.len() as u64;
    for ss in sigs {
        size += 36 + 8 + ss.len() as u64 + 8 + 2; // outpoint+len+ss+seq+budget
    }
    for o in &tx.outputs {
        size += 8 + 2 + 8 + o.script_bytes().len() as u64;
        if o.covenant.is_some() {
            size += 34;
        }
    }
    size
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let node_url = env::var("NODE").unwrap_or_else(|_| "ws://65.108.107.30:18210".to_string());
    let wallet_path =
        PathBuf::from(env::var("WALLET").unwrap_or_else(|_| "wallet.json".to_string()));
    let cmd = args.get(1).map(String::as_str).unwrap_or("");

    match cmd {
        // deploy-buy <token_hex> <max_n> <kas_amount_sompi>
        "deploy-buy" => {
            let wallet = WalletContext::load(&wallet_path)?;
            let privkey = *wallet.privkey_bytes();
            let token = hex::decode(&args[2])?;
            let mut tcid = [0u8; 32];
            tcid.copy_from_slice(&token);
            let max_n: usize = args[3].parse()?;
            let amount: u64 = args[4].parse()?;

            let owner_hash = blake2b_256(&wallet.pubkey);
            let bspkh = kob_core::contract::compute_token_unit_spk_hash(&wallet.pubkey);
            let okspkh = compute_p2pk_spk_hash(&wallet.pubkey);
            let rs = lab::build_buy_redeem_script_lab(
                max_n, &tcid, 1, 1, 30_000_000, &owner_hash, &bspkh, &okspkh, 2000, 0, 0,
            )?;
            let p2sh = build_p2sh(&rs);
            let addr = kaspa_address_encode("kaspatest", 8, &p2sh.script()[2..34]);
            println!("experimental buy RS: {} bytes (max_n={max_n})", rs.len());
            println!("address: {addr}");

            let rpc = NodeClient::connect(&node_url).await?;
            let utxos = rpc.get_spendable_utxos(&wallet.address).await?;
            // Multi-input funding, LARGEST first, skipping sub-0.6-KAS
            // pieces (those are the settle's storage-credit padding).
            let mut funds: Vec<&RpcUtxo> = utxos
                .iter()
                .filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= 60_000_000)
                .collect();
            funds.sort_by_key(|u| std::cmp::Reverse(u.utxo_entry.amount));
            let mut picked: Vec<&RpcUtxo> = Vec::new();
            let mut total = 0u64;
            for u in funds {
                picked.push(u);
                total += u.utxo_entry.amount;
                if total >= amount + 50_000_000 {
                    break;
                }
            }
            if total < amount + 50_000_000 {
                anyhow::bail!("insufficient wallet funds: {total} < {}", amount + 50_000_000);
            }

            let mut wallet_spk = Vec::with_capacity(34);
            wallet_spk.push(0x20);
            wallet_spk.extend_from_slice(&wallet.pubkey);
            wallet_spk.push(0xac);

            let mut tx = Transaction::new(0);
            for u in picked.iter() {
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
            tx.outputs.push(TxOutput::new(
                amount,
                p2sh.version,
                p2sh.script().to_vec(),
                None,
            ));
            let est_fee = 100_000u64;
            tx.outputs.push(TxOutput::new(total - amount - est_fee, 0, wallet_spk.clone(), None));
            let sign_all = |tx: &Transaction| -> anyhow::Result<Vec<Vec<u8>>> {
                let mut sigs = Vec::new();
                for i in 0..tx.inputs.len() {
                    let sh = compute_sighash(tx, i)?;
                    sigs.push(signing::build_p2pk_sigscript(&signing::schnorr_sign(
                        &privkey, &sh,
                    )?));
                }
                Ok(sigs)
            };
            let sigs = sign_all(&tx)?;
            let exact_fee =
                kob_core::mass::min_relay_fee(calc_mass_with_sigscripts(&tx, &sigs)).max(100_000);
            tx.outputs[1].value = total - amount - exact_fee;
            let sigs = sign_all(&tx)?;
            let payload = to_rpc_payload(&tx, &sigs);
            let txid = rpc.submit_transaction(payload).await?;
            println!("deployed experimental buy escrow: {amount} sompi");
            println!("TXID: {txid}");
            println!("buy outpoint: {txid}:0");
        }

        // settle <token_hex> <max_n> <buy_txid:idx> <pnum> <pden> <min_fill> <mmfee_bps>
        "settle" => {
            let wallet = WalletContext::load(&wallet_path)?;
            let privkey = *wallet.privkey_bytes();
            let token_hash = kob_core::compat::parse_hash(&args[2])
                .map_err(|e| anyhow::anyhow!("token hash: {e:?}"))?;
            let token = hex::decode(&args[2])?;
            let mut tcid = [0u8; 32];
            tcid.copy_from_slice(&token);
            let max_n: usize = args[3].parse()?;
            let (buy_txid, buy_idx) = parse_outpoint(&args[4])?;
            let pnum: u64 = args[5].parse()?;
            let pden: u64 = args[6].parse()?;
            let min_fill: u64 = args[7].parse()?;
            let mmfee_bps: u64 = args[8].parse()?;

            let owner_hash = blake2b_256(&wallet.pubkey);
            let sspkh = compute_p2pk_spk_hash(&wallet.pubkey);
            let otspkh = kob_core::contract::compute_token_unit_spk_hash(&wallet.pubkey);

            // Reconstruct the (shipping) sell RS all resting sells share.
            let sell_rs = order::build_sell_redeem_script(
                pnum, pden, min_fill, &owner_hash, &sspkh, &otspkh, mmfee_bps, 0, 0,
            )?;
            let sell_p2sh = build_p2sh(&sell_rs);
            let sell_addr = kaspa_address_encode("kaspatest", 8, &sell_p2sh.script()[2..34]);
            println!("sell address: {sell_addr}");

            // Reconstruct the experimental buy RS (deploy-buy parameters).
            let bspkh = kob_core::contract::compute_token_unit_spk_hash(&wallet.pubkey);
            let okspkh = compute_p2pk_spk_hash(&wallet.pubkey);
            let buy_rs = lab::build_buy_redeem_script_lab(
                max_n, &tcid, 1, 1, 30_000_000, &owner_hash, &bspkh, &okspkh, 2000, 0, 0,
            )?;
            let buy_p2sh = build_p2sh(&buy_rs);
            let buy_addr = kaspa_address_encode("kaspatest", 8, &buy_p2sh.script()[2..34]);

            let rpc = NodeClient::connect(&node_url).await?;
            let mut sell_utxos = rpc.get_utxos_by_addresses(&[&sell_addr]).await?;
            sell_utxos.sort_by(|a, b| {
                (a.outpoint.transaction_id.clone(), a.outpoint.index)
                    .cmp(&(b.outpoint.transaction_id.clone(), b.outpoint.index))
            });
            if sell_utxos.len() > max_n {
                sell_utxos.truncate(max_n);
            }
            let n = sell_utxos.len();
            if n == 0 {
                anyhow::bail!("no resting sells at {sell_addr}");
            }
            let buy_utxos = rpc.get_utxos_by_addresses(&[&buy_addr]).await?;
            let buy_utxo = buy_utxos
                .iter()
                .find(|u| u.outpoint.transaction_id == buy_txid && u.outpoint.index == buy_idx)
                .ok_or_else(|| anyhow::anyhow!("buy UTXO not found at {buy_addr}"))?;
            let kas_in = buy_utxo.utxo_entry.amount;
            let token_sum: u64 = sell_utxos.iter().map(|u| u.utxo_entry.amount).sum();
            println!("sweeping N={n} sells, token_sum={token_sum}, buy kas_in={kas_in}");
            if token_sum < kas_in {
                anyhow::bail!("GTC floor unmet: token_sum {token_sum} < kas_in {kas_in}");
            }

            let mut wallet_spk = Vec::with_capacity(34);
            wallet_spk.push(0x20);
            wallet_spk.extend_from_slice(&wallet.pubkey);
            wallet_spk.push(0xac);
            let tu_spk = kob_core::contract::build_token_unit_p2sh_spk(&wallet.pubkey);

            // Merged seller KAS at koi=0: sum of each sell's expected KAS.
            let fill_kas: u64 = sell_utxos
                .iter()
                .map(|u| u.utxo_entry.amount * pnum / pden)
                .sum();
            let surplus = kas_in - fill_kas;
            if surplus > kas_in / 10_000 * 2000 {
                anyhow::bail!("surplus {surplus} exceeds the buy's 2000 bps cap");
            }

            // Fee input: SMALLEST viable wallet UTXO — the KIP-9 credit is
            // C*|I|^2/sum(inputs), so large inputs dilute the credit.
            let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
            let fee_utxo = wallet_utxos
                .iter()
                .filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= 30_000_000)
                .min_by_key(|u| u.utxo_entry.amount)
                .ok_or_else(|| anyhow::anyhow!("no wallet fee UTXO >= 0.3 KAS"))?;

            // Storage-mass planning: pad with the SMALLEST wallet inputs
            // (plurality credit) until the KIP-9 mass fits; stop when a
            // candidate no longer improves it.
            let mut extras: Vec<&RpcUtxo> = Vec::new();
            let mut pool: Vec<&RpcUtxo> = wallet_utxos
                .iter()
                .filter(|u| {
                    !u.is_p2sh()
                        && u.utxo_entry.amount >= 5_000_000
                        && !(u.outpoint.transaction_id == fee_utxo.outpoint.transaction_id
                            && u.outpoint.index == fee_utxo.outpoint.index)
                })
                .collect();
            pool.sort_by_key(|u| u.utxo_entry.amount);
            let storage = |extras: &Vec<&RpcUtxo>| -> u64 {
                let mut ins: Vec<(u64, u64)> =
                    sell_utxos.iter().map(|u| (u.utxo_entry.amount, 2)).collect();
                ins.push((kas_in, 1));
                ins.push((fee_utxo.utxo_entry.amount, 1));
                for e in extras.iter() {
                    ins.push((e.utxo_entry.amount, 1));
                }
                let mut outs: Vec<(u64, u64)> = vec![(fill_kas, 1)];
                for u in sell_utxos.iter() {
                    outs.push((u.utxo_entry.amount, 2));
                }
                let extra_sum: u64 = extras.iter().map(|e| e.utxo_entry.amount).sum();
                let change = fee_utxo.utxo_entry.amount + extra_sum + surplus;
                outs.push((change.saturating_sub(10_000_000), 1)); // ~fee slack
                compute_storage_mass_ex(&ins, &outs)
            };
            while storage(&extras) > STORAGE_TARGET && !pool.is_empty() && extras.len() < 60 {
                let before = storage(&extras);
                extras.push(pool.remove(0));
                if storage(&extras) >= before {
                    extras.pop();
                    break; // remaining candidates are larger => no improvement
                }
            }
            let predicted_storage = storage(&extras);
            println!(
                "storage plan: {} extra wallet inputs, predicted storage mass {} (block limit {})",
                extras.len(),
                predicted_storage,
                STORAGE_BLOCK_LIMIT
            );
            if predicted_storage > STORAGE_BLOCK_LIMIT {
                anyhow::bail!(
                    "storage mass {predicted_storage} exceeds the block limit even with padding; \
                     use larger per-sell values"
                );
            }

            // Assemble: [sells 0..n-1][buy][fee][extras...]
            let mut tx = Transaction::new(1);
            tx.lock_time = 0;
            for u in sell_utxos.iter() {
                tx.inputs.push(TxInput {
                    prev_tx_id: u.outpoint.transaction_id.clone(),
                    prev_index: u.outpoint.index,
                    sequence: 50,
                    sig_op_count: 0,
                    script_version: sell_p2sh.version,
                    script_bytes: sell_p2sh.script().to_vec(),
                    value: u.utxo_entry.amount,
                });
            }
            let buy_input_idx = tx.inputs.len();
            tx.inputs.push(TxInput {
                prev_tx_id: buy_txid.clone(),
                prev_index: buy_idx,
                sequence: 50,
                // sig_op_count 1 => computeBudget 10 on the wire (the lab
                // buy's execution exceeds the 9,999 free script units from
                // N~15; 10 budget units allow 109,999).
                sig_op_count: 1,
                script_version: buy_p2sh.version,
                script_bytes: buy_p2sh.script().to_vec(),
                value: kas_in,
            });
            let fee_input_idx = tx.inputs.len();
            tx.inputs.push(TxInput {
                prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
                prev_index: fee_utxo.outpoint.index,
                sequence: 0,
                sig_op_count: 1,
                script_version: fee_utxo.utxo_entry.script_public_key.version,
                script_bytes: fee_utxo.script_bytes(),
                value: fee_utxo.utxo_entry.amount,
            });
            for u in extras.iter() {
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

            // Outputs: [0] merged seller KAS, [1..n] deliveries, [n+1] change.
            tx.outputs.push(TxOutput::new(fill_kas, 0, wallet_spk.clone(), None));
            for (i, u) in sell_utxos.iter().enumerate() {
                tx.outputs.push(TxOutput::new(
                    u.utxo_entry.amount,
                    tu_spk.version(),
                    tu_spk.script().to_vec(),
                    Some(CovenantBinding::new(i as u16, token_hash)),
                ));
            }
            let extra_sum: u64 = extras.iter().map(|e| e.utxo_entry.amount).sum();
            let est_fee = 6_000_000u64;
            tx.outputs.push(TxOutput::new(
                fee_utxo.utxo_entry.amount + extra_sum + surplus - est_fee,
                0,
                wallet_spk.clone(),
                None,
            ));

            let tii: Vec<u16> = (0..n as u16).collect();
            let sign_all = |tx: &Transaction| -> anyhow::Result<Vec<Vec<u8>>> {
                let mut sigs = Vec::with_capacity(tx.inputs.len());
                for i in 0..n {
                    let _ = i;
                    sigs.push(order::build_sell_fill_sigscript(0, pnum, pden, &sell_rs));
                }
                sigs.push(lab::build_buy_fill_sigscript_lab(max_n, &tii, false, &buy_rs));
                for i in fee_input_idx..tx.inputs.len() {
                    let sh = compute_sighash(tx, i)?;
                    sigs.push(signing::build_p2pk_sigscript(&signing::schnorr_sign(
                        &privkey, &sh,
                    )?));
                }
                Ok(sigs)
            };
            let _ = buy_input_idx;

            let sigs = sign_all(&tx)?;
            let compute = calc_mass_with_sigscripts(&tx, &sigs);
            let size = tx_size_with_sigs(&tx, &sigs);
            let transient = size * 4;
            // fee = max(compute, normalized transient (cofactor 0.5)) * 100
            let fee_mass = compute.max(transient / 2 + (transient % 2));
            let exact_fee = fee_mass * 100 + 10_000; // small headroom
            tx.outputs.last_mut().unwrap().value =
                fee_utxo.utxo_entry.amount + extra_sum + surplus - exact_fee;
            let sigs = sign_all(&tx)?;
            println!(
                "predicted masses: compute={compute} transient={transient} storage={predicted_storage} size={size}B fee={exact_fee}"
            );

            let payload = to_rpc_payload(&tx, &sigs);
            let txid = rpc.submit_transaction(payload).await?;
            println!("SUCCESS! experimental N={n} sweep settled in one tx.");
            println!("TXID: {txid}");
        }

        // split <count> <amount_sompi> — prep small wallet UTXOs (KIP-9
        // plurality credit for the settle) out of one large UTXO.
        "split" => {
            let wallet = WalletContext::load(&wallet_path)?;
            let privkey = *wallet.privkey_bytes();
            let count: usize = args[2].parse()?;
            let amount: u64 = args[3].parse()?;
            let need = amount * count as u64 + 100_000_000;

            let rpc = NodeClient::connect(&node_url).await?;
            let utxos = rpc.get_spendable_utxos(&wallet.address).await?;
            let fund = utxos
                .iter()
                .filter(|u| !u.is_p2sh())
                .find(|u| u.utxo_entry.amount >= need)
                .ok_or_else(|| anyhow::anyhow!("no wallet UTXO >= {need}"))?;

            let mut wallet_spk = Vec::with_capacity(34);
            wallet_spk.push(0x20);
            wallet_spk.extend_from_slice(&wallet.pubkey);
            wallet_spk.push(0xac);

            let mut tx = Transaction::new(0);
            tx.inputs.push(TxInput {
                prev_tx_id: fund.outpoint.transaction_id.clone(),
                prev_index: fund.outpoint.index,
                sequence: 0,
                sig_op_count: 1,
                script_version: fund.utxo_entry.script_public_key.version,
                script_bytes: fund.script_bytes(),
                value: fund.utxo_entry.amount,
            });
            for _ in 0..count {
                tx.outputs.push(TxOutput::new(amount, 0, wallet_spk.clone(), None));
            }
            let est_fee = 100_000u64;
            tx.outputs.push(TxOutput::new(
                fund.utxo_entry.amount - amount * count as u64 - est_fee,
                0,
                wallet_spk.clone(),
                None,
            ));
            let sign_all = |tx: &Transaction| -> anyhow::Result<Vec<Vec<u8>>> {
                let sh = compute_sighash(tx, 0)?;
                Ok(vec![signing::build_p2pk_sigscript(&signing::schnorr_sign(
                    &privkey, &sh,
                )?)])
            };
            let sigs = sign_all(&tx)?;
            let exact_fee =
                kob_core::mass::min_relay_fee(calc_mass_with_sigscripts(&tx, &sigs)).max(100_000);
            let last = tx.outputs.len() - 1;
            tx.outputs[last].value = fund.utxo_entry.amount - amount * count as u64 - exact_fee;
            let sigs = sign_all(&tx)?;
            let payload = to_rpc_payload(&tx, &sigs);
            let txid = rpc.submit_transaction(payload).await?;
            println!("split {count} x {amount} sompi. TXID: {txid}");
        }

        _ => {
            eprintln!("usage: kob-batch-lab deploy-buy|settle|split ... (see module docs)");
            std::process::exit(2);
        }
    }
    Ok(())
}
