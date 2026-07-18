//! E2E glue utility for the v18 live matrix (testnet-10).
//!
//! Three helpers that the main CLI has no subcommand for yet:
//!
//! - `oco-spk`: compute a v18 OCO sell RS + its P2SH SPK (37B hex) for this
//!   wallet, without deploying. Needed by `kob-cli deploy bracket --oco-spk`
//!   (the bracket state pins the spawn output to this exact SPK) and to
//!   fill/cancel the spawned OCO later (same RS).
//!
//! - `sell-partial`: direct v18 sell Op2 PARTIAL settle where the KAS payer
//!   is this wallet (no buy covenant on the other side) -- by design no
//!   planner composes a v18 sell partial with a v18 buy, so the covenant
//!   path is demonstrated with a minimal direct spend. Shape mirrors the
//!   proven harness (`core/tests/v18_spot.rs::run_sell_partial`):
//!   inputs  [0] sell covenant (seq 50, CSV), [1] wallet P2PK (fee + KAS leg)
//!   outputs [0] seller KAS = fta*pnum/pden (koi=0, blake2b(spk)==sspkh),
//!           [1] residual token continuation at the sell's own P2SH,
//!               covenant-bound auth=input0 (Fix-3 auth slot 0),
//!           [2] taker token delivery to wallet SPK, covenant-bound
//!               auth=input0 (slot 1; not contract-checked, keeps accounting),
//!           [3] wallet change.
//!
//! - `expire`: permissionless v18 Op4 expire-claim. The v18 expire branch
//!   demands a FULL refund (`out[0].value >= input.value`), so unlike the
//!   engine's legacy 1-in/1-out builder the fee must come from a second
//!   wallet input: inputs [0] order (seq 0), [1] wallet fee; outputs
//!   [0] full refund to owner SPK (token-covenant-bound for a sell),
//!   [1] change. lockTime = expiry_daa.

use std::env;
use std::path::PathBuf;

use kob_cli::cancel::kaspa_address_encode;
use kob_cli::node::NodeClient;
use kob_cli::signing;
use kob_core::contract::spot::{decay, oco, order};
use kob_core::mass::{calc_mass_with_sigscripts, min_relay_fee};
use kob_core::p2sh::{blake2b_256, build_p2sh, compute_p2pk_spk_hash};
use kob_core::sighash::compute_sighash;
use kob_core::tx::{to_rpc_payload, CovenantBinding, Transaction, TxInput, TxOutput};
use kob_core::wallet::WalletContext;

fn u64le(b: &[u8]) -> u64 {
    u64::from_le_bytes(b.try_into().unwrap())
}

/// Exact-fee with an optional KOB_FEE_FLOOR override (sompi): the node's
/// transient-mass floor (byte-proportional) can exceed the compute-mass fee
/// when a large RS rides in the sigscript.
fn fee_with_floor(computed: u64) -> u64 {
    let floor = std::env::var("KOB_FEE_FLOOR")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    computed.max(floor)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let node_url = env::var("NODE").unwrap_or_else(|_| "ws://65.108.107.30:18210".to_string());
    let wallet_path =
        PathBuf::from(env::var("WALLET").unwrap_or_else(|_| "wallet.json".to_string()));
    let cmd = args.get(1).map(String::as_str).unwrap_or("");

    match cmd {
        // oco-spk <tp_num> <tp_den> <tp_min_fill> <sl_num> <sl_den> <sl_min_fill> <mmfee_bps> <expiry_daa>
        "oco-spk" => {
            let wallet = WalletContext::load(&wallet_path)?;
            let p: Vec<u64> = args[2..10]
                .iter()
                .map(|s| s.parse::<u64>())
                .collect::<Result<_, _>>()?;
            let owner_hash = blake2b_256(&wallet.pubkey);
            let sspkh = compute_p2pk_spk_hash(&wallet.pubkey);
            let rs = oco::build_oco_sell_redeem_script(
                p[0], p[1], p[2], p[3], p[4], p[5], &owner_hash, &sspkh,
                &kob_core::contract::compute_token_unit_spk_hash(&wallet.pubkey), p[6], 0, p[7],
            )?;
            let p2sh = build_p2sh(&rs);
            let mut spk = Vec::with_capacity(37);
            spk.extend_from_slice(&p2sh.version.to_le_bytes());
            spk.extend_from_slice(p2sh.script());
            let addr = kaspa_address_encode("kaspatest", 8, &p2sh.script()[2..34]);
            println!("RS: {}", hex::encode(&rs));
            println!("SPK: {}", hex::encode(&spk));
            println!("ADDRESS: {}", addr);
        }

        // buy-rs <token_hex> <pnum> <pden> <mfill> <mmfee_bps> <cpend> <expiry>
        "buy-rs" => {
            let wallet = WalletContext::load(&wallet_path)?;
            let token = hex::decode(&args[2])?;
            let mut tcid = [0u8; 32];
            tcid.copy_from_slice(&token);
            let p: Vec<u64> = args[3..9]
                .iter()
                .map(|s| s.parse::<u64>())
                .collect::<Result<_, _>>()?;
            let owner_hash = blake2b_256(&wallet.pubkey);
            // D2 delivery re-wrap: v18 buys commit the token_unit P2SH hash.
            // KOB_E2E_LEGACY_P2PK_SPKH=1 reconstructs pre-D2 orders instead.
            let spkh = if env::var("KOB_E2E_LEGACY_P2PK_SPKH").ok().as_deref() == Some("1") {
                compute_p2pk_spk_hash(&wallet.pubkey)
            } else {
                kob_core::contract::compute_token_unit_spk_hash(&wallet.pubkey)
            };
            let rs = order::build_buy_redeem_script(
                &tcid, p[0], p[1], p[2], &owner_hash, &spkh,
                &compute_p2pk_spk_hash(&wallet.pubkey), p[3], p[4] as u8, p[5],
            )?;
            let p2sh = build_p2sh(&rs);
            println!("RS: {}", hex::encode(&rs));
            println!(
                "ADDRESS: {}",
                kaspa_address_encode("kaspatest", 8, &p2sh.script()[2..34])
            );
        }

        // sell-rs <pnum> <pden> <mfill> <mmfee_bps> <cpend> <expiry>
        "sell-rs" => {
            let wallet = WalletContext::load(&wallet_path)?;
            let p: Vec<u64> = args[2..8]
                .iter()
                .map(|s| s.parse::<u64>())
                .collect::<Result<_, _>>()?;
            let owner_hash = blake2b_256(&wallet.pubkey);
            let spkh = compute_p2pk_spk_hash(&wallet.pubkey);
            let rs = order::build_sell_redeem_script(
                p[0], p[1], p[2], &owner_hash, &spkh,
                &kob_core::contract::compute_token_unit_spk_hash(&wallet.pubkey), p[3], p[4] as u8, p[5],
            )?;
            let p2sh = build_p2sh(&rs);
            println!("RS: {}", hex::encode(&rs));
            println!(
                "ADDRESS: {}",
                kaspa_address_encode("kaspatest", 8, &p2sh.script()[2..34])
            );
        }

        // ratchet-rs <rstep> <rgap> <rwin> <mrv> <tp_num> <tp_den> <tp_mfill>
        //            <sl_num> <sl_den> <sl_mfill> <mmfee_bps> <expiry> [k]
        // Prints the deploy ratchet_oco RS + P2SH address for this wallet,
        // and (k > 0) the k-step continuation RS/address (pnum_sl += k*rstep)
        // via the same `derive_ratchet_continuation_rs` splice the engine and
        // covenant R13 enforce. Stage-G glue: the deploy path prints neither.
        "ratchet-rs" => {
            let wallet = WalletContext::load(&wallet_path)?;
            let p: Vec<u64> = args[2..14]
                .iter()
                .map(|s| s.parse::<u64>())
                .collect::<Result<_, _>>()?;
            let k: u64 = args.get(14).map(|s| s.parse()).transpose()?.unwrap_or(0);
            let owner_hash = blake2b_256(&wallet.pubkey);
            let sspkh = compute_p2pk_spk_hash(&wallet.pubkey);
            let mut rs = kob_core::contract::spot::ratchet::build_ratchet_oco_redeem_script(
                p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9],
                &owner_hash, &sspkh,
                &kob_core::contract::compute_token_unit_spk_hash(&wallet.pubkey),
                p[10], 0, p[11],
            )?;
            let p2sh = build_p2sh(&rs);
            println!("RS: {}", hex::encode(&rs));
            println!(
                "ADDRESS: {}",
                kaspa_address_encode("kaspatest", 8, &p2sh.script()[2..34])
            );
            for step in 1..=k {
                rs = kob_core::contract::spot::ratchet::derive_ratchet_continuation_rs(&rs)?;
                let p2sh = build_p2sh(&rs);
                println!("K{} RS: {}", step, hex::encode(&rs));
                println!(
                    "K{} ADDRESS: {}",
                    step,
                    kaspa_address_encode("kaspatest", 8, &p2sh.script()[2..34])
                );
            }
        }

        // receipt-rs <pair_id_hex> <price_num> <price_den> <exec_amount> <min_receipt_value>
        "receipt-rs" => {
            let wallet = WalletContext::load(&wallet_path)?;
            let pair = hex::decode(&args[2])?;
            let mut pair_id = [0u8; 32];
            pair_id.copy_from_slice(&pair);
            let p: Vec<u64> = args[3..7]
                .iter()
                .map(|s| s.parse::<u64>())
                .collect::<Result<_, _>>()?;
            let recipient_hash = blake2b_256(&wallet.pubkey);
            let rs = kob_core::contract::build_receipt_redeem_script(
                &pair_id, p[0], p[1], p[2], p[3], &recipient_hash,
            )?;
            println!("RS: {}", hex::encode(&rs));
        }

        // oco-cancel <txid:idx> <rs_hex>
        "oco-cancel" => {
            let wallet = WalletContext::load(&wallet_path)?;
            let privkey = *wallet.privkey_bytes();
            let (op_txid, op_idx) = parse_outpoint(&args[2])?;
            let rs = hex::decode(&args[3])?;
            let p2sh = build_p2sh(&rs);
            let addr = kaspa_address_encode("kaspatest", 8, &p2sh.script()[2..34]);

            let rpc = NodeClient::connect(&node_url).await?;
            let utxos = rpc.get_utxos_by_addresses(&[&addr]).await?;
            let oco_utxo = utxos
                .iter()
                .find(|u| u.outpoint.transaction_id == op_txid && u.outpoint.index == op_idx)
                .ok_or_else(|| anyhow::anyhow!("OCO UTXO {} not found on chain", args[2]))?;
            let oco_value = oco_utxo.utxo_entry.amount;

            let mut wallet_spk = Vec::with_capacity(34);
            wallet_spk.push(0x20);
            wallet_spk.extend_from_slice(&wallet.pubkey);
            wallet_spk.push(0xac);

            let mut tx = Transaction::new(0);
            tx.inputs.push(TxInput {
                prev_tx_id: op_txid.clone(),
                prev_index: op_idx,
                sequence: 0,
                sig_op_count: 1,
                script_version: p2sh.version,
                script_bytes: p2sh.script().to_vec(),
                value: oco_value,
            });
            let est_fee = 30_000u64;
            tx.outputs
                .push(TxOutput::new(oco_value - est_fee, 0, wallet_spk.clone(), None));

            let sign_all = |tx: &Transaction| -> anyhow::Result<Vec<Vec<u8>>> {
                let sh = compute_sighash(tx, 0)?;
                let sig = signing::schnorr_sign(&privkey, &sh)?;
                Ok(vec![oco::build_oco_sell_cancel_sigscript(
                    &sig,
                    &wallet.pubkey,
                    &rs,
                )])
            };
            let sigs = sign_all(&tx)?;
            let exact_fee = fee_with_floor(min_relay_fee(calc_mass_with_sigscripts(&tx, &sigs)));
            tx.outputs[0].value = oco_value - exact_fee;
            let sigs = sign_all(&tx)?;
            println!("exact fee: {} sompi", exact_fee);

            let payload = to_rpc_payload(&tx, &sigs);
            let txid = rpc.submit_transaction(payload).await?;
            println!("SUCCESS! v18 OCO cancelled (owner sig, tokens unlocked to KAS).");
            println!("TXID: {}", txid);
        }

        // sell-partial <txid:idx> <rs_hex> <token_hex> <fta>
        "sell-partial" => {
            let wallet = WalletContext::load(&wallet_path)?;
            let privkey = *wallet.privkey_bytes();
            let (op_txid, op_idx) = parse_outpoint(&args[2])?;
            let rs = hex::decode(&args[3])?;
            let token_hash = kob_core::compat::parse_hash(&args[4])
                .map_err(|e| anyhow::anyhow!("token hash: {e:?}"))?;
            let fta: u64 = args[5].parse()?;

            // Parse sell v18 state (E1: [0x20 otspkh] prefix, +33):
            // pnum@34, pden@43, mfill@52 (8B LE each).
            let pnum = u64le(&rs[34..42]);
            let pden = u64le(&rs[43..51]);
            let mfill = u64le(&rs[52..60]);
            let p2sh = build_p2sh(&rs);
            let sell_addr = kaspa_address_encode("kaspatest", 8, &p2sh.script()[2..34]);

            let rpc = NodeClient::connect(&node_url).await?;
            let utxos = rpc.get_utxos_by_addresses(&[&sell_addr]).await?;
            let sell_utxo = utxos
                .iter()
                .find(|u| u.outpoint.transaction_id == op_txid && u.outpoint.index == op_idx)
                .ok_or_else(|| anyhow::anyhow!("sell UTXO {} not found on chain", args[2]))?;
            let token_in = sell_utxo.utxo_entry.amount;
            if fta >= token_in {
                anyhow::bail!("fta {} must be < token_in {} (partial guard)", fta, token_in);
            }
            let fill_kas = fta * pnum / pden;
            let residual = token_in - fta;
            println!(
                "sell-partial: token_in={} fta={} residual={} fill_kas={} (pnum/pden={}/{}, mfill={})",
                token_in, fta, residual, fill_kas, pnum, pden, mfill
            );

            let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
            let fee_utxo = wallet_utxos
                .iter()
                .find(|u| !u.is_p2sh() && u.utxo_entry.amount >= fill_kas + 50_000_000)
                .ok_or_else(|| anyhow::anyhow!("no wallet UTXO large enough for KAS leg + fee"))?;

            let mut wallet_spk = Vec::with_capacity(34);
            wallet_spk.push(0x20);
            wallet_spk.extend_from_slice(&wallet.pubkey);
            wallet_spk.push(0xac);

            // KOB_NO_COV=1: omit covenant bindings (fill attempt on a
            // cancel-marked order whose UTXO no longer carries the token
            // covenant — exercises the F5 cpend script check directly).
            let no_cov = std::env::var("KOB_NO_COV").ok().as_deref() == Some("1");
            let mut tx = Transaction::new(if no_cov { 0 } else { 1 });
            tx.lock_time = 50;
            tx.inputs.push(TxInput {
                prev_tx_id: op_txid.clone(),
                prev_index: op_idx,
                sequence: 50,
                sig_op_count: 0,
                script_version: p2sh.version,
                script_bytes: p2sh.script().to_vec(),
                value: token_in,
            });
            tx.inputs.push(TxInput {
                prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
                prev_index: fee_utxo.outpoint.index,
                sequence: 0,
                sig_op_count: 1,
                script_version: fee_utxo.utxo_entry.script_public_key.version,
                script_bytes: fee_utxo.script_bytes(),
                value: fee_utxo.utxo_entry.amount,
            });

            let est_fee = 60_000u64;
            // [0] seller KAS (koi=0)
            tx.outputs
                .push(TxOutput::new(fill_kas, 0, wallet_spk.clone(), None));
            // [1] residual continuation (auth slot 0 of input 0)
            tx.outputs.push(TxOutput::new(
                residual,
                p2sh.version,
                p2sh.script().to_vec(),
                if no_cov { None } else { Some(CovenantBinding::new(0, token_hash)) },
            ));
            // [2] taker token delivery (auth slot 1 of input 0) -- D2: the
            // taker's tokens land on their token_unit P2SH (spendable KCC20
            // token_unit), not a bare P2PK output.
            let taker_tu = kob_core::contract::build_token_unit_p2sh_spk(&wallet.pubkey);
            tx.outputs.push(TxOutput::new(
                fta,
                taker_tu.version(),
                taker_tu.script().to_vec(),
                if no_cov { None } else { Some(CovenantBinding::new(0, token_hash)) },
            ));
            // [3] wallet change (KAS leg is paid out of the fee input)
            let change = fee_utxo.utxo_entry.amount - fill_kas - est_fee;
            tx.outputs.push(TxOutput::new(change, 0, wallet_spk.clone(), None));

            let sign_all = |tx: &Transaction| -> anyhow::Result<Vec<Vec<u8>>> {
                let mut sigs = Vec::with_capacity(2);
                sigs.push(order::build_sell_partial_fill_sigscript(
                    0, pnum, pden, fta, 1, &rs,
                ));
                let sh = compute_sighash(tx, 1)?;
                sigs.push(signing::build_p2pk_sigscript(&signing::schnorr_sign(
                    &privkey, &sh,
                )?));
                Ok(sigs)
            };
            let sigs = sign_all(&tx)?;
            let exact_fee = fee_with_floor(min_relay_fee(calc_mass_with_sigscripts(&tx, &sigs)));
            tx.outputs[3].value = fee_utxo.utxo_entry.amount - fill_kas - exact_fee;
            let sigs = sign_all(&tx)?;
            println!("exact fee: {} sompi", exact_fee);

            let payload = to_rpc_payload(&tx, &sigs);
            let txid = rpc.submit_transaction(payload).await?;
            println!("SUCCESS! v18 sell partial settled (direct spend).");
            println!("TXID: {}", txid);
            println!("residual continuation at {}:1 ({} token sompi)", txid, residual);
        }

        // expire <txid:idx> <rs_hex> <buy|sell> [token_hex]
        "expire" => {
            let wallet = WalletContext::load(&wallet_path)?;
            let privkey = *wallet.privkey_bytes();
            let (op_txid, op_idx) = parse_outpoint(&args[2])?;
            let rs = hex::decode(&args[3])?;
            let side = args[4].as_str();

            let (expiry_daa, expire_ss) = match side {
                "buy" => (
                    u64le(&rs[172..180]), // +2 for the n_max state prefix
                    order::build_buy_expire_sigscript(&rs),
                ),
                "sell" => (
                    u64le(&rs[140..148]), // +3 for the batch_max state prefix
                    order::build_sell_expire_sigscript(&rs),
                ),
                _ => anyhow::bail!("side must be buy|sell"),
            };
            if expiry_daa == 0 {
                anyhow::bail!("order is GTC (expiry 0); expire branch is unreachable");
            }
            let p2sh = build_p2sh(&rs);
            let addr = kaspa_address_encode("kaspatest", 8, &p2sh.script()[2..34]);

            let rpc = NodeClient::connect(&node_url).await?;
            let daa = rpc.get_daa_score().await?;
            println!("expiry_daa={} current_daa={}", expiry_daa, daa);
            if daa < expiry_daa {
                anyhow::bail!("not yet expired (need DAA >= {})", expiry_daa);
            }
            let utxos = rpc.get_utxos_by_addresses(&[&addr]).await?;
            let order_utxo = utxos
                .iter()
                .find(|u| u.outpoint.transaction_id == op_txid && u.outpoint.index == op_idx)
                .ok_or_else(|| anyhow::anyhow!("order UTXO {} not found on chain", args[2]))?;
            let order_value = order_utxo.utxo_entry.amount;

            let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
            let fee_utxo = wallet_utxos
                .iter()
                .find(|u| !u.is_p2sh() && u.utxo_entry.amount >= 50_000_000)
                .ok_or_else(|| anyhow::anyhow!("no wallet fee UTXO"))?;

            let mut wallet_spk = Vec::with_capacity(34);
            wallet_spk.push(0x20);
            wallet_spk.extend_from_slice(&wallet.pubkey);
            wallet_spk.push(0xac);

            // E1 expire seats: the refund SPK-hash is the OWNER SEAT at
            // rs[1..33] (buy okspkh = raw P2PK hash; sell otspkh =
            // token_unit P2SH hash) -- pick whichever candidate matches,
            // or fail loudly.
            let committed_spkh: [u8; 32] = {
                let mut h = [0u8; 32];
                h.copy_from_slice(&rs[1..33]);
                h
            };
            let (refund_spk_version, refund_spk): (u16, Vec<u8>) =
                if kob_core::compute_spk_hash(0, &wallet_spk) == committed_spkh {
                    (0, wallet_spk.clone())
                } else if kob_core::contract::compute_token_unit_spk_hash(&wallet.pubkey)
                    == committed_spkh
                {
                    let tu = kob_core::contract::build_token_unit_p2sh_spk(&wallet.pubkey);
                    (tu.version(), tu.script().to_vec())
                } else {
                    anyhow::bail!(
                        "committed refund spkh matches neither the wallet P2PK nor its token_unit P2SH"
                    );
                };

            // Full-refund covenant binding: a sell refund carries the token
            // covenant (conservation check `OpCovOutCount >= 1`); buy is KAS.
            let refund_cov = if side == "sell" {
                let token_hex = args
                    .get(5)
                    .ok_or_else(|| anyhow::anyhow!("sell expire needs <token_hex>"))?;
                let token_hash = kob_core::compat::parse_hash(token_hex)
                    .map_err(|e| anyhow::anyhow!("token hash: {e:?}"))?;
                Some(CovenantBinding::new(0, token_hash))
            } else {
                None
            };

            let mut tx = Transaction::new(if refund_cov.is_some() { 1 } else { 0 });
            tx.lock_time = expiry_daa;
            tx.inputs.push(TxInput {
                prev_tx_id: op_txid.clone(),
                prev_index: op_idx,
                sequence: 0,
                sig_op_count: 0,
                script_version: p2sh.version,
                script_bytes: p2sh.script().to_vec(),
                value: order_value,
            });
            tx.inputs.push(TxInput {
                prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
                prev_index: fee_utxo.outpoint.index,
                sequence: 0,
                sig_op_count: 1,
                script_version: fee_utxo.utxo_entry.script_public_key.version,
                script_bytes: fee_utxo.script_bytes(),
                value: fee_utxo.utxo_entry.amount,
            });
            // [0] full refund (SPK forced by the committed spkh)
            tx.outputs
                .push(TxOutput::new(order_value, refund_spk_version, refund_spk, refund_cov));
            // [1] change
            let est_fee = 60_000u64;
            tx.outputs.push(TxOutput::new(
                fee_utxo.utxo_entry.amount - est_fee,
                0,
                wallet_spk.clone(),
                None,
            ));

            let sign_all = |tx: &Transaction| -> anyhow::Result<Vec<Vec<u8>>> {
                let mut sigs = Vec::with_capacity(2);
                sigs.push(expire_ss.clone());
                let sh = compute_sighash(tx, 1)?;
                sigs.push(signing::build_p2pk_sigscript(&signing::schnorr_sign(
                    &privkey, &sh,
                )?));
                Ok(sigs)
            };
            let sigs = sign_all(&tx)?;
            let exact_fee = fee_with_floor(min_relay_fee(calc_mass_with_sigscripts(&tx, &sigs)));
            tx.outputs[1].value = fee_utxo.utxo_entry.amount - exact_fee;
            let sigs = sign_all(&tx)?;
            println!("exact fee: {} sompi", exact_fee);

            let payload = to_rpc_payload(&tx, &sigs);
            let txid = rpc.submit_transaction(payload).await?;
            println!("SUCCESS! v18 {} expire-claimed (permissionless Op4).", side);
            println!("TXID: {}", txid);
        }

        // sweep-unit-kas <txid:idx> [<txid:idx> ...]
        //
        // Recover BINDING-LESS KAS parked at the wallet's token_unit P2SH
        // (v18 covenant seats commit the token_unit SPK hash, so IOC buyer
        // change / marked-order cancel refunds land there as plain KAS).
        // Spends the listed unit-P2SH UTXOs via the token_unit owner-sig
        // path into one wallet P2PK output. TX version 0, no covenant
        // bindings -- if any listed UTXO actually carries a token covenant
        // the node rejects the whole sweep (fail-closed, tokens are safe).
        "sweep-unit-kas" => {
            let wallet = WalletContext::load(&wallet_path)?;
            let privkey = *wallet.privkey_bytes();
            let unit_rs = kob_core::contract::build_token_unit_redeem_script(&wallet.pubkey);
            let unit_p2sh = build_p2sh(&unit_rs);
            let unit_addr = kaspa_address_encode("kaspatest", 8, &unit_p2sh.script()[2..34]);

            let outpoints: Vec<(String, u32)> = args[2..]
                .iter()
                .map(|s| parse_outpoint(s))
                .collect::<anyhow::Result<_>>()?;
            if outpoints.is_empty() {
                anyhow::bail!("sweep-unit-kas needs at least one <txid:idx>");
            }

            let rpc = NodeClient::connect(&node_url).await?;
            let utxos = rpc.get_utxos_by_addresses(&[&unit_addr]).await?;

            let mut tx = Transaction::new(0);
            let mut total_in = 0u64;
            for (txid, idx) in &outpoints {
                let u = utxos
                    .iter()
                    .find(|u| u.outpoint.transaction_id == *txid && u.outpoint.index == *idx)
                    .ok_or_else(|| {
                        anyhow::anyhow!("unit UTXO {}:{} not found at {}", txid, idx, unit_addr)
                    })?;
                total_in += u.utxo_entry.amount;
                tx.inputs.push(TxInput {
                    prev_tx_id: txid.clone(),
                    prev_index: *idx,
                    sequence: 0,
                    sig_op_count: 1,
                    script_version: unit_p2sh.version,
                    script_bytes: unit_p2sh.script().to_vec(),
                    value: u.utxo_entry.amount,
                });
            }

            let mut wallet_spk = Vec::with_capacity(34);
            wallet_spk.push(0x20);
            wallet_spk.extend_from_slice(&wallet.pubkey);
            wallet_spk.push(0xac);
            let est_fee = 50_000u64 * tx.inputs.len() as u64;
            tx.outputs
                .push(TxOutput::new(total_in - est_fee, 0, wallet_spk.clone(), None));

            let sign_all = |tx: &Transaction| -> anyhow::Result<Vec<Vec<u8>>> {
                (0..tx.inputs.len())
                    .map(|i| {
                        let sh = compute_sighash(tx, i)?;
                        let sig = signing::schnorr_sign(&privkey, &sh)?;
                        Ok(kob_core::contract::build_token_unit_sigscript(&sig, &unit_rs))
                    })
                    .collect()
            };
            let sigs = sign_all(&tx)?;
            let exact_fee = fee_with_floor(min_relay_fee(calc_mass_with_sigscripts(&tx, &sigs)));
            tx.outputs[0].value = total_in - exact_fee;
            let sigs = sign_all(&tx)?;
            println!("sweeping {} unit UTXOs, total {} sompi, fee {} sompi", tx.inputs.len(), total_in, exact_fee);

            let payload = to_rpc_payload(&tx, &sigs);
            let txid = rpc.submit_transaction(payload).await?;
            println!("SUCCESS! binding-less unit-P2SH KAS swept to wallet P2PK.");
            println!("TXID: {}", txid);
        }

        // decay-fill <txid:idx> <rs_hex> <token_hex> <att_pnum> <att_pden> <lock_time>
        //
        // Direct decay_sell FULL fill (Op1) where the wallet is the taker
        // (pays the KAS leg, receives all the tokens). Unlike `match-batch`
        // (which always attests the correct f(L) and sets lock_time = tip),
        // this lets you choose the attested price pair AND the tx lock_time,
        // so it drives the whole decay adversarial matrix:
        //   - honest:    att = f(L), lock_time = tip          -> ACCEPT (DK-1)
        //   - stale D3:  att = start price, lock_time > t0     -> REJECT (D3)
        //   - L=0:       lock_time = 0, att = start price      -> ACCEPT (DK-3i)
        //   - NotFinal:  lock_time > tip                       -> node reject (DK-3ii)
        //   - unix-ms:   lock_time >= 500_000_000_000, att=floor -> REJECT (D1, DK-4)
        //
        // Shape mirrors the proven harness `run_decay_sell_fill`:
        //   in  [0] decay_sell covenant (seq 50, CSV), [1] wallet KAS+fee
        //   out [0] seller KAS = token_in*att_pnum/att_pden (koi=0, sspkh)
        //       [1] taker delivery = token_in (token_unit P2SH, cov auth 0)
        //       [2] wallet change
        "decay-fill" => {
            let wallet = WalletContext::load(&wallet_path)?;
            let privkey = *wallet.privkey_bytes();
            let (op_txid, op_idx) = parse_outpoint(&args[2])?;
            let rs = hex::decode(&args[3])?;
            let token_hash = kob_core::compat::parse_hash(&args[4])
                .map_err(|e| anyhow::anyhow!("token hash: {e:?}"))?;
            let att_pnum: u64 = args[5].parse()?;
            let att_pden: u64 = args[6].parse()?;
            let lock_time: u64 = args[7].parse()?;

            let p2sh = build_p2sh(&rs);
            let addr = kaspa_address_encode("kaspatest", 8, &p2sh.script()[2..34]);
            let rpc = NodeClient::connect(&node_url).await?;
            let utxos = rpc.get_utxos_by_addresses(&[&addr]).await?;
            let sell_utxo = utxos
                .iter()
                .find(|u| u.outpoint.transaction_id == op_txid && u.outpoint.index == op_idx)
                .ok_or_else(|| anyhow::anyhow!("decay_sell UTXO {} not found on chain", args[2]))?;
            let token_in = sell_utxo.utxo_entry.amount;
            let seller_kas = token_in.saturating_mul(att_pnum) / att_pden;
            println!(
                "decay-fill: token_in={} att={}/{} seller_kas={} lock_time={}",
                token_in, att_pnum, att_pden, seller_kas, lock_time
            );

            let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
            let fee_utxo = wallet_utxos
                .iter()
                .find(|u| !u.is_p2sh() && u.utxo_entry.amount >= seller_kas + 60_000_000)
                .ok_or_else(|| anyhow::anyhow!("no wallet UTXO large enough for KAS leg + fee"))?;

            let mut wallet_spk = Vec::with_capacity(34);
            wallet_spk.push(0x20);
            wallet_spk.extend_from_slice(&wallet.pubkey);
            wallet_spk.push(0xac);

            let mut tx = Transaction::new(1);
            tx.lock_time = lock_time;
            tx.inputs.push(TxInput {
                prev_tx_id: op_txid.clone(),
                prev_index: op_idx,
                sequence: 50,
                sig_op_count: 0,
                script_version: p2sh.version,
                script_bytes: p2sh.script().to_vec(),
                value: token_in,
            });
            tx.inputs.push(TxInput {
                prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
                prev_index: fee_utxo.outpoint.index,
                sequence: 0,
                sig_op_count: 1,
                script_version: fee_utxo.utxo_entry.script_public_key.version,
                script_bytes: fee_utxo.script_bytes(),
                value: fee_utxo.utxo_entry.amount,
            });
            let est_fee = 60_000u64;
            // [0] seller KAS (koi=0)
            tx.outputs.push(TxOutput::new(seller_kas, 0, wallet_spk.clone(), None));
            // [1] taker token delivery (cov auth slot 0), spendable token_unit
            let taker_tu = kob_core::contract::build_token_unit_p2sh_spk(&wallet.pubkey);
            tx.outputs.push(TxOutput::new(
                token_in,
                taker_tu.version(),
                taker_tu.script().to_vec(),
                Some(CovenantBinding::new(0, token_hash)),
            ));
            // [2] wallet change
            tx.outputs.push(TxOutput::new(
                fee_utxo.utxo_entry.amount - seller_kas - est_fee,
                0,
                wallet_spk.clone(),
                None,
            ));

            let sign_all = |tx: &Transaction| -> anyhow::Result<Vec<Vec<u8>>> {
                let mut sigs = Vec::with_capacity(2);
                sigs.push(decay::build_decay_sell_fill_sigscript(0, att_pnum, att_pden, &rs));
                let sh = compute_sighash(tx, 1)?;
                sigs.push(signing::build_p2pk_sigscript(&signing::schnorr_sign(&privkey, &sh)?));
                Ok(sigs)
            };
            let sigs = sign_all(&tx)?;
            let exact_fee = fee_with_floor(min_relay_fee(calc_mass_with_sigscripts(&tx, &sigs)));
            tx.outputs[2].value = fee_utxo.utxo_entry.amount - seller_kas - exact_fee;
            let sigs = sign_all(&tx)?;
            println!("exact fee: {} sompi", exact_fee);

            let payload = to_rpc_payload(&tx, &sigs);
            match rpc.submit_transaction(payload).await {
                Ok(txid) => {
                    println!("SUCCESS! decay_sell full fill accepted.");
                    println!("TXID: {}", txid);
                }
                Err(e) => {
                    println!("SUBMIT REJECTED: {}", e);
                }
            }
        }

        // twap-fill <txid:idx> <rs_hex> <token_hex> <pnum> <pden> <sequence> <full|FTA>
        //
        // Direct twap_sell fill with a CHOSEN input sequence and volume, to
        // drive the pacing/cap covenant checks directly:
        //   - full-fill token_in <= mpw, seq = twin  -> ACCEPT
        //   - full-fill token_in >  mpw, seq = twin  -> REJECT (W2 bypass pin, TW-2)
        //   - seq < twin                             -> node reject (CSV, TW-1)
        //   - partial FTA (<token_in) leaves a residual that must itself age
        //     `twin` before the next fill (TW-1 spacing).
        // twap fill-family uses the PLAIN v18 sell sigscripts (§3.3).
        //   in  [0] twap covenant (seq = <sequence>, CSV), [1] wallet KAS+fee
        //   full:    out[0] seller KAS, [1] delivery token_in (cov auth0), [2] change
        //   partial: out[0] seller KAS, [1] residual (self-P2SH, cov auth0),
        //            [2] delivery FTA (cov auth0), [3] change
        "twap-fill" => {
            let wallet = WalletContext::load(&wallet_path)?;
            let privkey = *wallet.privkey_bytes();
            let (op_txid, op_idx) = parse_outpoint(&args[2])?;
            let rs = hex::decode(&args[3])?;
            let token_hash = kob_core::compat::parse_hash(&args[4])
                .map_err(|e| anyhow::anyhow!("token hash: {e:?}"))?;
            let pnum: u64 = args[5].parse()?;
            let pden: u64 = args[6].parse()?;
            let sequence: u64 = args[7].parse()?;
            let vol_arg = args.get(8).map(String::as_str).unwrap_or("full");

            let p2sh = build_p2sh(&rs);
            let addr = kaspa_address_encode("kaspatest", 8, &p2sh.script()[2..34]);
            let rpc = NodeClient::connect(&node_url).await?;
            let utxos = rpc.get_utxos_by_addresses(&[&addr]).await?;
            let sell_utxo = utxos
                .iter()
                .find(|u| u.outpoint.transaction_id == op_txid && u.outpoint.index == op_idx)
                .ok_or_else(|| anyhow::anyhow!("twap_sell UTXO {} not found on chain", args[2]))?;
            let token_in = sell_utxo.utxo_entry.amount;
            let full = vol_arg == "full";
            let fta = if full { token_in } else { vol_arg.parse()? };
            let seller_kas = fta.saturating_mul(pnum) / pden;
            let residual = token_in - fta;
            println!(
                "twap-fill: token_in={} fta={} residual={} seller_kas={} seq={} full={}",
                token_in, fta, residual, seller_kas, sequence, full
            );

            let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
            let fee_utxo = wallet_utxos
                .iter()
                .find(|u| !u.is_p2sh() && u.utxo_entry.amount >= seller_kas + 60_000_000)
                .ok_or_else(|| anyhow::anyhow!("no wallet UTXO large enough for KAS leg + fee"))?;

            let mut wallet_spk = Vec::with_capacity(34);
            wallet_spk.push(0x20);
            wallet_spk.extend_from_slice(&wallet.pubkey);
            wallet_spk.push(0xac);
            let taker_tu = kob_core::contract::build_token_unit_p2sh_spk(&wallet.pubkey);

            let mut tx = Transaction::new(1);
            tx.lock_time = 0;
            tx.inputs.push(TxInput {
                prev_tx_id: op_txid.clone(),
                prev_index: op_idx,
                sequence,
                sig_op_count: 0,
                script_version: p2sh.version,
                script_bytes: p2sh.script().to_vec(),
                value: token_in,
            });
            tx.inputs.push(TxInput {
                prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
                prev_index: fee_utxo.outpoint.index,
                sequence: 0,
                sig_op_count: 1,
                script_version: fee_utxo.utxo_entry.script_public_key.version,
                script_bytes: fee_utxo.script_bytes(),
                value: fee_utxo.utxo_entry.amount,
            });
            let est_fee = 60_000u64;
            tx.outputs.push(TxOutput::new(seller_kas, 0, wallet_spk.clone(), None));
            let residual_idx;
            if full {
                residual_idx = 0u16; // unused
                tx.outputs.push(TxOutput::new(
                    token_in,
                    taker_tu.version(),
                    taker_tu.script().to_vec(),
                    Some(CovenantBinding::new(0, token_hash)),
                ));
                tx.outputs.push(TxOutput::new(
                    fee_utxo.utxo_entry.amount - seller_kas - est_fee,
                    0,
                    wallet_spk.clone(),
                    None,
                ));
            } else {
                // [1] residual continuation at the twap's own P2SH (cov auth0)
                residual_idx = 1u16;
                tx.outputs.push(TxOutput::new(
                    residual,
                    p2sh.version,
                    p2sh.script().to_vec(),
                    Some(CovenantBinding::new(0, token_hash)),
                ));
                // [2] taker delivery FTA (cov auth0)
                tx.outputs.push(TxOutput::new(
                    fta,
                    taker_tu.version(),
                    taker_tu.script().to_vec(),
                    Some(CovenantBinding::new(0, token_hash)),
                ));
                // [3] change
                tx.outputs.push(TxOutput::new(
                    fee_utxo.utxo_entry.amount - seller_kas - est_fee,
                    0,
                    wallet_spk.clone(),
                    None,
                ));
            }

            let sign_all = |tx: &Transaction| -> anyhow::Result<Vec<Vec<u8>>> {
                let mut sigs = Vec::with_capacity(2);
                if full {
                    sigs.push(order::build_sell_fill_sigscript(0, pnum, pden, &rs));
                } else {
                    sigs.push(order::build_sell_partial_fill_sigscript(
                        0, pnum, pden, fta, residual_idx, &rs,
                    ));
                }
                let sh = compute_sighash(tx, 1)?;
                sigs.push(signing::build_p2pk_sigscript(&signing::schnorr_sign(&privkey, &sh)?));
                Ok(sigs)
            };
            let sigs = sign_all(&tx)?;
            let exact_fee = fee_with_floor(min_relay_fee(calc_mass_with_sigscripts(&tx, &sigs)));
            let change_idx = tx.outputs.len() - 1;
            tx.outputs[change_idx].value = fee_utxo.utxo_entry.amount - seller_kas - exact_fee;
            let sigs = sign_all(&tx)?;
            println!("exact fee: {} sompi", exact_fee);

            let payload = to_rpc_payload(&tx, &sigs);
            match rpc.submit_transaction(payload).await {
                Ok(txid) => {
                    println!("SUCCESS! twap_sell fill accepted.");
                    println!("TXID: {}", txid);
                    if !full {
                        println!("residual continuation at {}:1 ({} token sompi)", txid, residual);
                    }
                }
                Err(e) => {
                    println!("SUBMIT REJECTED: {}", e);
                }
            }
        }

        _ => {
            eprintln!("usage:");
            eprintln!("  kob-e2e-util oco-spk <tp_num> <tp_den> <tp_mfill> <sl_num> <sl_den> <sl_mfill> <mmfee_bps> <expiry>");
            eprintln!("  kob-e2e-util sell-partial <txid:idx> <rs_hex> <token_hex> <fta>");
            eprintln!("  kob-e2e-util decay-fill <txid:idx> <rs_hex> <token_hex> <att_pnum> <att_pden> <lock_time>");
            eprintln!("  kob-e2e-util twap-fill <txid:idx> <rs_hex> <token_hex> <pnum> <pden> <sequence> <full|FTA>");
            eprintln!("  kob-e2e-util expire <txid:idx> <rs_hex> <buy|sell> [token_hex]");
            eprintln!("  kob-e2e-util sweep-unit-kas <txid:idx> [<txid:idx> ...]");
            eprintln!("env: NODE (ws url), WALLET (wallet.json path)");
            std::process::exit(2);
        }
    }
    Ok(())
}

fn parse_outpoint(s: &str) -> anyhow::Result<(String, u32)> {
    let (t, i) = s
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("outpoint must be txid:idx"))?;
    Ok((t.to_string(), i.parse()?))
}
