//! x402 native-KAS payment client (for the testnet E2E harness).
//!
//! Builds and signs a real native-KAS transfer as an x402 payment artifact —
//! WITHOUT broadcasting — then emits a ready-to-POST facilitator request
//! (`{ x402Version, paymentPayload, paymentRequirements }`). The facilitator
//! (kob-x402 server) is the one that broadcasts and confirms.
//!
//! Scenario flags let the harness produce the rejection cases:
//!   --require <sompi>       requirements demand more than the tx pays (underpayment)
//!   --tx-pay-to <addr>      the tx actually pays this address, but requirements
//!                           demand --pay-to (wrong recipient)
//!   --replay-out <file>     also emit a SECOND artifact spending the SAME input
//!                           (a different amount -> different artifact) for the
//!                           replay-rejection case
//!
//! This binary collapses the client + resource-server roles for the E2E: it
//! computes the request fingerprint itself and binds it both into the tx
//! payload and into requirements.extra.fingerprint.

use std::path::Path;

use kob_settle::mass::{calc_mass_with_sigscripts, min_relay_fee};
use kob_settle::rpc::{RpcClient, RpcUtxo};
use kob_settle::sighash::compute_sighash;
use kob_settle::tx::{to_rpc_payload, Transaction, TxInput, TxOutput};
use kob_settle::wallet::WalletContext;
use kob_settle::MIN_UTXO_VALUE;

use kob_x402::fingerprint;
use kob_x402::wire_v2::{
    PaymentPayload, PaymentRequirements, ASSET_KAS, BINDING_KCC20, BINDING_NATIVE, SCHEME_EXACT,
    X402_VERSION,
};

struct Args {
    node: String,
    wallet: String,
    network: String,
    pay_to: String,
    tx_pay_to: Option<String>,
    amount: u64,
    require: Option<u64>,
    resource: String,
    method: String,
    path: String,
    nonce: String,
    out: Option<String>,
    replay_out: Option<String>,
    /// PULL mode: broadcast the payment ourselves (facilitator only discovers).
    broadcast: bool,
    /// Explicit fingerprint hex (pull mode: the merchant issues it; the client
    /// embeds it). When set, overrides the computed fingerprint.
    fingerprint: Option<String>,
}

fn arg_val(it: &mut std::vec::IntoIter<String>) -> String {
    it.next().unwrap_or_default()
}

fn parse_args() -> Args {
    let mut a = Args {
        node: String::new(),
        wallet: String::new(),
        network: "kaspa:testnet-10".to_string(),
        pay_to: String::new(),
        tx_pay_to: None,
        amount: 0,
        require: None,
        resource: "https://example/resource".to_string(),
        method: "GET".to_string(),
        path: "/resource".to_string(),
        nonce: "nonce".to_string(),
        out: None,
        replay_out: None,
        broadcast: false,
        fingerprint: None,
    };
    let mut it = std::env::args().skip(1).collect::<Vec<_>>().into_iter();
    while let Some(k) = it.next() {
        match k.as_str() {
            "--node" => a.node = arg_val(&mut it),
            "--wallet" => a.wallet = arg_val(&mut it),
            "--network" => a.network = arg_val(&mut it),
            "--pay-to" => a.pay_to = arg_val(&mut it),
            "--tx-pay-to" => a.tx_pay_to = Some(arg_val(&mut it)),
            "--amount" => a.amount = arg_val(&mut it).parse().unwrap_or(0),
            "--require" => a.require = arg_val(&mut it).parse().ok(),
            "--resource" => a.resource = arg_val(&mut it),
            "--method" => a.method = arg_val(&mut it),
            "--path" => a.path = arg_val(&mut it),
            "--nonce" => a.nonce = arg_val(&mut it),
            "--out" => a.out = Some(arg_val(&mut it)),
            "--replay-out" => a.replay_out = Some(arg_val(&mut it)),
            "--broadcast" => a.broadcast = true,
            "--fingerprint" => a.fingerprint = Some(arg_val(&mut it)),
            other => eprintln!("[client] ignoring unknown arg: {}", other),
        }
    }
    a
}

/// Build and sign a native-KAS transfer over `selected`, paying `amount` to
/// `recipient_spk`, change back to `wallet_spk`, with `payload_bytes` as the tx
/// payload. Returns the `submitTransaction`-shaped tx JSON.
fn build_signed_tx(
    selected: &[RpcUtxo],
    total_in: u64,
    amount: u64,
    recipient_spk_version: u16,
    recipient_spk: &[u8],
    wallet_spk_version: u16,
    wallet_spk: &[u8],
    payload_bytes: &[u8],
    privkey: &[u8; 32],
) -> anyhow::Result<serde_json::Value> {
    let mut tx = Transaction::new(0);
    tx.payload = payload_bytes.to_vec();

    for u in selected {
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

    // Output 0: recipient.
    tx.outputs.push(TxOutput::new(amount, recipient_spk_version, recipient_spk.to_vec(), None));

    // Output 1: change slot (placeholder value — corrected once mass, hence the
    // real min-relay fee, is known). A P2PK sigscript is a fixed 66 bytes, so
    // the transaction mass does not depend on the change output's *value*; we
    // can measure mass with a placeholder and then set the exact change.
    let has_change = total_in > amount + MIN_UTXO_VALUE;
    if has_change {
        tx.outputs.push(TxOutput::new(
            total_in.saturating_sub(amount),
            wallet_spk_version,
            wallet_spk.to_vec(),
            None,
        ));
    }

    let sign = |tx: &Transaction| -> anyhow::Result<Vec<Vec<u8>>> {
        let mut ss = Vec::with_capacity(tx.inputs.len());
        for i in 0..tx.inputs.len() {
            let sighash = compute_sighash(tx, i)?;
            let sig = kob_settle::signing::schnorr_sign(&sighash, privkey)?;
            ss.push(kob_settle::utils::build_p2pk_sigscript(&sig));
        }
        Ok(ss)
    };

    // Measure mass with real sigscript sizes, then the node-required fee is
    // min_relay_fee(mass) = mass * 100 sompi/gram (post-Toccata rule).
    let sigscripts = sign(&tx)?;
    let mass = calc_mass_with_sigscripts(&tx, &sigscripts);
    let fee = min_relay_fee(mass);

    // Set the exact change and re-sign (value change alters the sighash but not
    // the sigscript length, so mass/fee stay valid).
    let final_sigscripts = if has_change {
        let change = total_in.saturating_sub(amount + fee);
        if change >= MIN_UTXO_VALUE {
            let cidx = tx.outputs.len() - 1;
            tx.outputs[cidx].value = change;
        } else {
            tx.outputs.pop(); // remainder donated to fee
        }
        sign(&tx)?
    } else {
        // No change output: the entire remainder (total_in - amount) is the
        // fee. Ensure it clears the min-relay floor.
        if total_in.saturating_sub(amount) < fee {
            anyhow::bail!("insufficient funds to cover min-relay fee {}", fee);
        }
        sigscripts
    };

    Ok(to_rpc_payload(&tx, &final_sigscripts))
}

fn facilitator_request(
    network: &str,
    tx: serde_json::Value,
    from: &str,
    pay_to: &str,
    require: u64,
    fingerprint_hex: &str,
) -> serde_json::Value {
    let requirements = PaymentRequirements {
        scheme: SCHEME_EXACT.to_string(),
        network: network.to_string(),
        amount: require.to_string(),
        asset: ASSET_KAS.to_string(),
        pay_to: pay_to.to_string(),
        max_timeout_seconds: 60,
        extra: serde_json::json!({ "binding": BINDING_NATIVE, "fingerprint": fingerprint_hex }),
        additional: Default::default(),
    };
    let payload = PaymentPayload {
        x402_version: X402_VERSION,
        accepted: requirements.clone(),
        payload: serde_json::json!({
            "type": "kob-native-transfer",
            "payerAddress": from,
            "transaction": tx,
        }),
        extensions: None,
    };
    serde_json::json!({
        "x402Version": X402_VERSION,
        "paymentPayload": payload,
        "paymentRequirements": requirements,
    })
}

fn write_out(target: &Option<String>, value: &serde_json::Value) -> anyhow::Result<()> {
    let s = serde_json::to_string(value)?;
    match target {
        Some(path) => std::fs::write(path, s)?,
        None => println!("{}", s),
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Helper: `x402-client derive-address <pubkey_hex> [testnet|mainnet]` prints
    // a valid Kaspa P2PK address for the given pubkey and exits. The E2E harness
    // uses it to get a valid, distinct 'intended' recipient for the
    // wrong-recipient case (so the refusal is for the right reason).
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.first().map(|s| s.as_str()) == Some("derive-address") {
        let pk_hex = raw.get(1).cloned().unwrap_or_default();
        let net = match raw.get(2).map(|s| s.as_str()) {
            Some("mainnet") => kob_settle::types::Network::Mainnet,
            _ => kob_settle::types::Network::Testnet,
        };
        let bytes = hex::decode(&pk_hex).map_err(|e| anyhow::anyhow!("bad pubkey hex: {}", e))?;
        let pk: [u8; 32] = bytes.try_into().map_err(|_| anyhow::anyhow!("pubkey must be 32 bytes"))?;
        println!("{}", kob_settle::wallet::pubkey_to_address(&pk, net));
        return Ok(());
    }

    // KCC20 (scheme B) mode: build a SPEC-FORM token_unit-P2SH transfer artifact.
    if raw.first().map(|s| s.as_str()) == Some("kcc20") {
        return kcc20::run(&raw[1..]).await;
    }

    // `exact-address <payTo> <borrowAmount> <threshold> [testnet|mainnet]` prints
    // the KIP-10 additive borrow covenant P2SH address (merchant funds it).
    if raw.first().map(|s| s.as_str()) == Some("exact-address") {
        let pay_to = raw.get(1).cloned().unwrap_or_default();
        let ba: u64 = raw.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
        let th: u64 = raw.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
        let (_rs, _spk, addr) = kob_x402::reservation::borrow_covenant(&pay_to, ba, th)
            .map_err(|e| anyhow::anyhow!(e))?;
        println!("{}", addr);
        return Ok(());
    }

    // KIP-10 additive "exact" mode: build the additive exact-transaction.
    if raw.first().map(|s| s.as_str()) == Some("exact") {
        return exact::run(&raw[1..]).await;
    }

    let args = parse_args();
    if args.node.is_empty() || args.wallet.is_empty() || args.pay_to.is_empty() || args.amount == 0 {
        anyhow::bail!("required: --node --wallet --pay-to --amount");
    }

    let wallet = WalletContext::load(Path::new(&args.wallet))?;
    let privkey = *wallet.privkey_bytes();

    let require = args.require.unwrap_or(args.amount);
    // Pull mode: the merchant issues the fingerprint (passed via --fingerprint);
    // otherwise compute it from the request context (push mode / self-issued).
    let fingerprint_hex = args.fingerprint.clone().unwrap_or_else(|| {
        fingerprint::compute_fingerprint(&args.method, &args.path, &args.pay_to, &require.to_string(), &args.nonce)
    });
    let payload_bytes = fingerprint::embed_fingerprint(&fingerprint_hex);

    // The address the tx actually pays (wrong-recipient case overrides it).
    let tx_pay_to = args.tx_pay_to.clone().unwrap_or_else(|| args.pay_to.clone());
    let (recipient_spk_version, recipient_spk) = spk_of(&tx_pay_to)?;
    let (wallet_spk_version, wallet_spk) = spk_of(&wallet.address)?;

    let rpc = RpcClient::connect(&args.node)
        .await
        .map_err(|e| anyhow::anyhow!("connect failed: {}", e))?;

    let utxos = rpc
        .get_spendable_utxos(&wallet.address, None)
        .await
        .map_err(|e| anyhow::anyhow!("get utxos failed: {}", e))?;
    let p2pk: Vec<RpcUtxo> = utxos.into_iter().filter(|u| !u.is_p2sh()).collect();
    if p2pk.is_empty() {
        anyhow::bail!("no spendable P2PK UTXOs; fund the wallet");
    }

    // Select one UTXO large enough for amount + generous fee headroom.
    let needed = args.amount + 1_000_000;
    let mut cand: Vec<RpcUtxo> = p2pk.iter().filter(|u| u.utxo_entry.amount >= needed).cloned().collect();
    cand.sort_by(|a, b| a.utxo_entry.amount.cmp(&b.utxo_entry.amount));
    let selected: Vec<RpcUtxo> = if let Some(u) = cand.into_iter().next() {
        vec![u]
    } else {
        // Accumulate.
        let mut acc = 0u64;
        let mut sel = Vec::new();
        for u in &p2pk {
            sel.push(u.clone());
            acc += u.utxo_entry.amount;
            if acc >= needed {
                break;
            }
        }
        if acc < needed {
            anyhow::bail!("insufficient funds: need {} have {}", needed, acc);
        }
        sel
    };
    let total_in: u64 = selected.iter().map(|u| u.utxo_entry.amount).sum();

    eprintln!(
        "[client] from={} pay_to={} tx_pay_to={} amount={} require={} inputs={} total_in={}",
        wallet.address, args.pay_to, tx_pay_to, args.amount, require, selected.len(), total_in
    );

    let tx = build_signed_tx(
        &selected,
        total_in,
        args.amount,
        recipient_spk_version,
        &recipient_spk,
        wallet_spk_version,
        &wallet_spk,
        &payload_bytes,
        &privkey,
    )?;

    // PULL mode: the client broadcasts the payment ITSELF (the facilitator only
    // discovers it). Prints the txid; does not emit a facilitator artifact.
    if args.broadcast {
        // `tx` is already a `{transaction, allowOrphan}` submit envelope.
        let res = rpc.submit_transaction(tx).await.map_err(|e| anyhow::anyhow!("broadcast: {}", e))?;
        if !res.ok {
            anyhow::bail!("broadcast rejected: {}", res.error.unwrap_or_default());
        }
        let txid = res.tx_id.unwrap_or_default();
        eprintln!("[client] PULL broadcast txid={} (fingerprint={})", txid, fingerprint_hex);
        println!("{}", txid);
        return Ok(());
    }

    let req = facilitator_request(
        &args.network,
        tx,
        &wallet.address,
        &args.pay_to,
        require,
        &fingerprint_hex,
    );
    write_out(&args.out, &req)?;

    // Replay partner: a SECOND artifact over the SAME input, paying a slightly
    // different amount (so the tx bytes -> artifact id differ, but the consumed
    // outpoint is identical). The facilitator must refuse to settle it once the
    // first has been settled.
    if let Some(replay_path) = &args.replay_out {
        let second_amount = args.amount.saturating_sub(1_000);
        let tx2 = build_signed_tx(
            &selected,
            total_in,
            second_amount,
            recipient_spk_version,
            &recipient_spk,
            wallet_spk_version,
            &wallet_spk,
            &payload_bytes,
            &privkey,
        )?;
        let req2 = facilitator_request(
            &args.network,
            tx2,
            &wallet.address,
            &args.pay_to,
            second_amount,
            &fingerprint_hex,
        );
        write_out(&Some(replay_path.clone()), &req2)?;
        eprintln!("[client] replay-partner written to {}", replay_path);
    }

    Ok(())
}

/// (version, script bytes) for a Kaspa address.
fn spk_of(addr: &str) -> anyhow::Result<(u16, Vec<u8>)> {
    let spk = kob_settle::bech32::address_to_spk(addr).map_err(|e| anyhow::anyhow!("{}", e))?;
    Ok((0u16, spk))
}

/// KCC20 (scheme B): build a SPEC-FORM `token_unit` transfer as an x402 payment.
///
/// Spends the payer's `token_unit` P2SH covenant UTXO and creates a NEW
/// `token_unit` P2SH covenant output for the recipient — i.e. the recipient
/// output SPK is `P2SH(build_token_unit_redeem_script(recipient_pk))` carrying
/// a covenant binding to the token `asset`, and its native sompi value is the
/// token amount (per the KCC20 Standard State Header spec). This is exactly
/// what `kob-cli token mint` produces (proving the node accepts token_unit-P2SH
/// covenant outputs); `kob-cli token transfer` instead emits a non-spec
/// P2PK+covenant output, which is why we build the transfer here.
mod kcc20 {
    use super::*;
    use kob_core::{build_token_unit_redeem_script, build_token_unit_sigscript};
    use kob_settle::tx::CovenantBinding;

    struct Args {
        node: String,
        wallet: String,
        network: String,
        pay_to: String,           // requirements.payTo (recipient identity, P2PK)
        tx_recipient: String,     // who the tx output actually pays (defaults to pay_to)
        amount: u64,              // token units to send (== output native value)
        require: u64,             // requirements.amount
        asset: String,            // token covenant id (hex)
        token_utxo: String,       // "txid:index" of the payer's token_unit UTXO
        out: Option<String>,
        replay_out: Option<String>,
        replay_recipient: Option<String>,
        // Request-binding is mandatory (Phase 2): the fingerprint is embedded
        // in the tx payload AND set in requirements.extra.fingerprint.
        fingerprint: Option<String>,
        nonce: String,
    }

    fn parse(raw: &[String]) -> anyhow::Result<Args> {
        let mut a = Args {
            node: String::new(),
            wallet: String::new(),
            network: "kaspa:testnet-10".to_string(),
            pay_to: String::new(),
            tx_recipient: String::new(),
            amount: 0,
            require: 0,
            asset: String::new(),
            token_utxo: String::new(),
            out: None,
            replay_out: None,
            replay_recipient: None,
            fingerprint: None,
            nonce: "kob-kcc20".to_string(),
        };
        let mut it = raw.to_vec().into_iter();
        while let Some(k) = it.next() {
            match k.as_str() {
                "--node" => a.node = it.next().unwrap_or_default(),
                "--wallet" => a.wallet = it.next().unwrap_or_default(),
                "--network" => a.network = it.next().unwrap_or_default(),
                "--pay-to" => a.pay_to = it.next().unwrap_or_default(),
                "--tx-recipient" => a.tx_recipient = it.next().unwrap_or_default(),
                "--amount" => a.amount = it.next().unwrap_or_default().parse().unwrap_or(0),
                "--require" => a.require = it.next().unwrap_or_default().parse().unwrap_or(0),
                "--asset" => a.asset = it.next().unwrap_or_default(),
                "--token-utxo" => a.token_utxo = it.next().unwrap_or_default(),
                "--out" => a.out = Some(it.next().unwrap_or_default()),
                "--replay-out" => a.replay_out = Some(it.next().unwrap_or_default()),
                "--replay-recipient" => a.replay_recipient = Some(it.next().unwrap_or_default()),
                "--fingerprint" => a.fingerprint = Some(it.next().unwrap_or_default()),
                "--nonce" => a.nonce = it.next().unwrap_or_default(),
                other => eprintln!("[kcc20] ignoring unknown arg: {}", other),
            }
        }
        if a.tx_recipient.is_empty() {
            a.tx_recipient = a.pay_to.clone();
        }
        if a.require == 0 {
            a.require = a.amount;
        }
        Ok(a)
    }

    fn pubkey_from_p2pk(addr: &str) -> anyhow::Result<[u8; 32]> {
        let spk = kob_settle::bech32::address_to_spk(addr).map_err(|e| anyhow::anyhow!("{}", e))?;
        if spk.len() == 34 && spk[0] == 0x20 && spk[33] == 0xac {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&spk[1..33]);
            Ok(pk)
        } else {
            anyhow::bail!("{} is not a P2PK identity address", addr)
        }
    }

    /// (spk_version, spk_script_bytes) of the `token_unit` P2SH for `pubkey`.
    fn token_unit_p2sh(pubkey: &[u8; 32]) -> (u16, Vec<u8>) {
        let spk = kob_settle::build_p2sh(&build_token_unit_redeem_script(pubkey));
        (spk.version(), spk.script().to_vec())
    }

    /// Build the signed token_unit-P2SH transfer for a given recipient pubkey +
    /// amount, over `token_utxo` (value `token_value`) and `fee_utxo`. Returns
    /// the `submitTransaction`-shaped tx JSON.
    #[allow(clippy::too_many_arguments)]
    fn build_transfer(
        token_txid: &str,
        token_index: u32,
        token_value: u64,
        payer_pk: &[u8; 32],
        recipient_pk: &[u8; 32],
        amount: u64,
        fee_utxo: &RpcUtxo,
        wallet_spk_version: u16,
        wallet_spk: &[u8],
        asset: &str,
        fingerprint_hex: &str,
        privkey: &[u8; 32],
    ) -> anyhow::Result<serde_json::Value> {
        let payer_rs = build_token_unit_redeem_script(payer_pk);
        let payer_p2sh = kob_settle::build_p2sh(&payer_rs);
        let (payer_p2sh_ver, payer_p2sh_script) = (payer_p2sh.version(), payer_p2sh.script().to_vec());
        let (recipient_p2sh_ver, recipient_p2sh_script) = token_unit_p2sh(recipient_pk);
        let cov = || CovenantBinding::new(0, kob_settle::compat::parse_hash(asset).unwrap());

        let remainder = token_value.saturating_sub(amount);
        let has_remainder = remainder >= MIN_UTXO_VALUE;
        if remainder > 0 && !has_remainder {
            anyhow::bail!("remainder {} below MIN_UTXO_VALUE; transfer the full amount", remainder);
        }

        let mut tx = Transaction::new(1);
        // Bind the request: embed X402:<fingerprint> in the tx payload so the
        // verifier's mandatory fingerprint check (Phase 2) matches
        // requirements.extra.fingerprint. Set before signing/mass so the fee
        // covers the payload bytes.
        tx.payload = fingerprint::embed_fingerprint(fingerprint_hex);
        // Input 0: token_unit P2SH.
        tx.inputs.push(TxInput {
            prev_tx_id: token_txid.to_string(),
            prev_index: token_index,
            sequence: 0,
            sig_op_count: 1,
            script_version: payer_p2sh_ver,
            script_bytes: payer_p2sh_script.clone(),
            value: token_value,
        });
        // Input 1: fee P2PK.
        tx.inputs.push(TxInput {
            prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
            prev_index: fee_utxo.outpoint.index,
            sequence: 0,
            sig_op_count: 1,
            script_version: fee_utxo.utxo_entry.script_public_key.version,
            script_bytes: fee_utxo.script_bytes(),
            value: fee_utxo.utxo_entry.amount,
        });

        // Output 0: recipient token_unit P2SH (SPEC FORM) + covenant.
        tx.outputs.push(TxOutput::new(amount, recipient_p2sh_ver, recipient_p2sh_script, Some(cov())));
        // Output 1: remainder token back to payer (token_unit P2SH) + covenant.
        if has_remainder {
            tx.outputs.push(TxOutput::new(remainder, payer_p2sh_ver, payer_p2sh_script.clone(), Some(cov())));
        }

        let token_out_sum = amount + if has_remainder { remainder } else { 0 };
        let total_in = token_value + fee_utxo.utxo_entry.amount;
        // Tentative fee change (corrected after mass is known).
        let has_fee_change = fee_utxo.utxo_entry.amount > MIN_UTXO_VALUE;
        if has_fee_change {
            tx.outputs.push(TxOutput::new(
                total_in.saturating_sub(token_out_sum),
                wallet_spk_version,
                wallet_spk.to_vec(),
                None,
            ));
        }

        let sign = |tx: &Transaction| -> anyhow::Result<Vec<Vec<u8>>> {
            let sh0 = compute_sighash(tx, 0)?;
            let sig0 = kob_settle::signing::schnorr_sign(&sh0, privkey)?;
            let ss0 = build_token_unit_sigscript(&sig0, &payer_rs);
            let sh1 = compute_sighash(tx, 1)?;
            let sig1 = kob_settle::signing::schnorr_sign(&sh1, privkey)?;
            let ss1 = kob_settle::utils::build_p2pk_sigscript(&sig1);
            Ok(vec![ss0, ss1])
        };

        let sigscripts = sign(&tx)?;
        let mass = calc_mass_with_sigscripts(&tx, &sigscripts);
        let fee = min_relay_fee(mass);

        let final_ss = if has_fee_change {
            let change = total_in.saturating_sub(token_out_sum + fee);
            if change >= MIN_UTXO_VALUE {
                let ci = tx.outputs.len() - 1;
                tx.outputs[ci].value = change;
            } else {
                tx.outputs.pop();
            }
            sign(&tx)?
        } else {
            if fee_utxo.utxo_entry.amount < fee {
                anyhow::bail!("fee UTXO {} cannot cover min-relay fee {}", fee_utxo.utxo_entry.amount, fee);
            }
            sigscripts
        };

        Ok(to_rpc_payload(&tx, &final_ss))
    }

    #[allow(clippy::too_many_arguments)]
    fn kcc20_request(net: &str, tx: serde_json::Value, from: &str, pay_to: &str, asset: &str, require: u64, fingerprint_hex: &str) -> serde_json::Value {
        // Request-binding is mandatory (Phase 2): extra.fingerprint MUST be
        // present and match the X402:<fp> memo embedded in the tx payload.
        let requirements = PaymentRequirements {
            scheme: SCHEME_EXACT.to_string(),
            network: net.to_string(),
            amount: require.to_string(),
            asset: ASSET_KAS.to_string(),
            pay_to: pay_to.to_string(),
            max_timeout_seconds: 60,
            extra: serde_json::json!({ "binding": BINDING_KCC20, "assetId": asset, "fingerprint": fingerprint_hex }),
            additional: Default::default(),
        };
        let payload = PaymentPayload {
            x402_version: X402_VERSION,
            accepted: requirements.clone(),
            payload: serde_json::json!({
                "type": "kob-kcc20-transfer",
                "payerAddress": from,
                "transaction": tx,
            }),
            extensions: None,
        };
        serde_json::json!({
            "x402Version": X402_VERSION,
            "paymentPayload": payload,
            "paymentRequirements": requirements,
        })
    }

    pub async fn run(raw: &[String]) -> anyhow::Result<()> {
        let a = parse(raw)?;
        if a.node.is_empty() || a.wallet.is_empty() || a.pay_to.is_empty() || a.amount == 0
            || a.asset.is_empty() || a.token_utxo.is_empty()
        {
            anyhow::bail!("kcc20 requires: --node --wallet --pay-to --amount --asset --token-utxo");
        }
        if hex::decode(&a.asset).map(|b| b.len() != 32).unwrap_or(true) {
            anyhow::bail!("--asset must be a 32-byte covenant id (hex)");
        }

        let (token_txid, token_index) = {
            let (t, i) = a.token_utxo.split_once(':').ok_or_else(|| anyhow::anyhow!("--token-utxo must be txid:index"))?;
            (t.to_string(), i.parse::<u32>()?)
        };

        let wallet = WalletContext::load(Path::new(&a.wallet))?;
        let privkey = *wallet.privkey_bytes();
        let payer_pk = wallet.pubkey;
        let (wallet_spk_version, wallet_spk) = spk_of(&wallet.address)?;

        let net = if a.pay_to.starts_with("kaspatest") {
            kob_settle::types::Network::Testnet
        } else {
            kob_settle::types::Network::Mainnet
        };
        let prefix = net.address_prefix();

        let rpc = RpcClient::connect(&a.node).await.map_err(|e| anyhow::anyhow!("connect: {}", e))?;

        // Locate the payer's token_unit UTXO (at the payer's token_unit P2SH address).
        let (_pv, payer_token_spk_bytes) = token_unit_p2sh(&payer_pk);
        let payer_token_addr = kob_settle::bech32::spk_to_address(&payer_token_spk_bytes, prefix)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        let token_utxos = rpc.get_utxos_by_addresses(&[&payer_token_addr]).await.map_err(|e| anyhow::anyhow!("{}", e))?;
        let token_utxo = token_utxos.iter()
            .find(|u| u.outpoint.transaction_id == token_txid && u.outpoint.index == token_index)
            .ok_or_else(|| anyhow::anyhow!("token UTXO {} not found at {} (spent?)", a.token_utxo, payer_token_addr))?;
        let token_value = token_utxo.utxo_entry.amount;

        // A fee UTXO (smallest P2PK with change headroom, not the token UTXO).
        let est_fee = kob_settle::mass::estimate_compute_mass(2, 3, 0);
        let wallet_utxos = rpc.get_spendable_utxos(&wallet.address, None).await.map_err(|e| anyhow::anyhow!("{}", e))?;
        let mut fee_cands: Vec<RpcUtxo> = wallet_utxos.into_iter()
            .filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= est_fee + MIN_UTXO_VALUE)
            .collect();
        fee_cands.sort_by_key(|u| u.utxo_entry.amount);
        let fee_utxo = fee_cands.into_iter().next()
            .ok_or_else(|| anyhow::anyhow!("no P2PK fee UTXO with >= {} sompi", est_fee + MIN_UTXO_VALUE))?;

        eprintln!(
            "[kcc20] token_utxo={}:{} value={} asset={} pay_to={} tx_recipient={} amount={} require={} fee_utxo={}:{}",
            token_txid, token_index, token_value, a.asset, a.pay_to, a.tx_recipient, a.amount, a.require,
            fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index,
        );

        // Request-binding is mandatory: derive (or accept) the fingerprint,
        // embed it in the tx payload, and set it in requirements.extra.
        let fingerprint_hex = a.fingerprint.clone().unwrap_or_else(|| {
            fingerprint::compute_fingerprint("KCC20", &a.asset, &a.pay_to, &a.require.to_string(), &a.nonce)
        });

        // Primary artifact: pays the tx-recipient's token_unit P2SH.
        let tx_recipient_pk = pubkey_from_p2pk(&a.tx_recipient)?;
        let tx = build_transfer(
            &token_txid, token_index, token_value, &payer_pk, &tx_recipient_pk, a.amount,
            &fee_utxo, wallet_spk_version, &wallet_spk, &a.asset, &fingerprint_hex, &privkey,
        )?;
        let req = kcc20_request(&a.network, tx, &wallet.address, &a.pay_to, &a.asset, a.require, &fingerprint_hex);
        write_out(&a.out, &req)?;

        // Replay partner: a second artifact over the SAME token + fee inputs,
        // paying a DIFFERENT recipient (distinct output -> distinct artifact id).
        if let Some(replay_path) = &a.replay_out {
            let alt = a.replay_recipient.clone().unwrap_or_else(|| a.pay_to.clone());
            // Derive a distinct recipient if none provided (flip a byte of the pubkey).
            let alt_pk = if a.replay_recipient.is_some() {
                pubkey_from_p2pk(&alt)?
            } else {
                let mut pk = tx_recipient_pk;
                pk[0] ^= 0x01;
                pk
            };
            let alt_addr = kob_settle::wallet::pubkey_to_address(&alt_pk, net);
            // The partner artifact pays a DIFFERENT recipient, so it carries
            // its own fingerprint (bound to alt_addr) — both remain valid,
            // distinct bindings.
            let alt_fp = fingerprint::compute_fingerprint("KCC20", &a.asset, &alt_addr, &a.amount.to_string(), &a.nonce);
            let tx2 = build_transfer(
                &token_txid, token_index, token_value, &payer_pk, &alt_pk, a.amount,
                &fee_utxo, wallet_spk_version, &wallet_spk, &a.asset, &alt_fp, &privkey,
            )?;
            let req2 = kcc20_request(&a.network, tx2, &wallet.address, &alt_addr, &a.asset, a.amount, &alt_fp);
            write_out(&Some(replay_path.clone()), &req2)?;
            eprintln!("[kcc20] replay-partner written to {}", replay_path);
        }

        Ok(())
    }
}

/// KIP-10 additive "exact" (strict interop, alpha.8 `additive` profile of
/// `kaspa-exact-v2`): build the additive exact-transaction from a `/reserve`
/// PaymentRequirements and emit the v2 FacilitatorRequest.
mod exact {
    use super::*;
    use kob_core::contract::x402_borrow::build_x402_borrow_spend_sigscript;
    use kob_settle::build_p2sh;
    use kob_x402::wire_v2::{
        iso8601_from_unix_secs, AUTHORIZATION_VERSION, PROFILE_ADDITIVE, TX_ENCODING_SAFE_JSON,
    };

    struct Args {
        node: String,
        wallet: String,
        requirements_file: String,
        scenario: String,
        out: Option<String>,
        // Request-binding is mandatory (Phase 2): the reservation binds a
        // requestHash and the payload MUST echo the same value.
        request_hash: Option<String>,
    }

    fn parse(raw: &[String]) -> Args {
        let mut a = Args { node: String::new(), wallet: String::new(), requirements_file: String::new(), scenario: "happy".into(), out: None, request_hash: None };
        let mut it = raw.to_vec().into_iter();
        while let Some(k) = it.next() {
            match k.as_str() {
                "--node" => a.node = it.next().unwrap_or_default(),
                "--wallet" => a.wallet = it.next().unwrap_or_default(),
                "--requirements-file" => a.requirements_file = it.next().unwrap_or_default(),
                "--scenario" => a.scenario = it.next().unwrap_or_default(),
                "--out" => a.out = Some(it.next().unwrap_or_default()),
                "--request-hash" => a.request_hash = Some(it.next().unwrap_or_default()),
                other => eprintln!("[exact] ignoring unknown arg: {}", other),
            }
        }
        a
    }

    pub async fn run(raw: &[String]) -> anyhow::Result<()> {
        let a = parse(raw);
        if a.node.is_empty() || a.wallet.is_empty() || a.requirements_file.is_empty() {
            anyhow::bail!("exact requires: --node --wallet --requirements-file");
        }
        let req: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&a.requirements_file)?)?;
        let pay_to = req["payTo"].as_str().ok_or_else(|| anyhow::anyhow!("no payTo"))?.to_string();
        let amount: u64 = req["amount"].as_str().unwrap_or("0").parse()?;
        let extra = &req["extra"];
        // alpha.8 additive field names (head/challenge vocabulary).
        let borrow_txid = extra["expectedHeadOutpoint"]["txid"].as_str().ok_or_else(|| anyhow::anyhow!("no expectedHeadOutpoint"))?.to_string();
        let borrow_index = extra["expectedHeadOutpoint"]["index"].as_u64().unwrap_or(0) as u32;
        let borrow_rs = hex::decode(extra["headRedeemScript"].as_str().ok_or_else(|| anyhow::anyhow!("no headRedeemScript"))?)?;
        let borrow_amount: u64 = extra["headAmount"].as_str().unwrap_or("0").parse()?;
        let threshold: u64 = extra["additiveThresholdSompi"].as_str().unwrap_or("0").parse()?;
        let challenge_id = extra["challengeId"].as_str().ok_or_else(|| anyhow::anyhow!("no challengeId"))?.to_string();

        let wallet = WalletContext::load(Path::new(&a.wallet))?;
        let privkey = *wallet.privkey_bytes();
        let (wallet_spk_ver, wallet_spk) = spk_of(&wallet.address)?;
        let (pay_spk_ver, pay_spk) = spk_of(&pay_to)?;
        let borrow_p2sh = build_p2sh(&borrow_rs);

        // Scenario adjustments.
        let (in0_txid, in0_index) = if a.scenario == "wrong-borrow" {
            ("ba".repeat(32), 0) // a non-reserved outpoint
        } else {
            (borrow_txid.clone(), borrow_index)
        };
        let cont_base = borrow_amount + threshold;
        let cont_value = match a.scenario.as_str() {
            "under-threshold" => cont_base.saturating_sub(1_000_000),
            "replay" => cont_base + 1_000_000, // distinct artifact, same borrow outpoint
            _ => cont_base,
        };
        // wrong-recipient: pay a distinct valid address instead of payTo.
        let (payment_spk_ver, payment_spk) = if a.scenario == "wrong-recipient" {
            let other = kob_settle::wallet::pubkey_to_address(&[0x3c; 32], kob_settle::types::Network::Testnet);
            spk_of(&other)?
        } else {
            (pay_spk_ver, pay_spk.clone())
        };

        let rpc = RpcClient::connect(&a.node).await.map_err(|e| anyhow::anyhow!("connect: {}", e))?;
        let need = amount + threshold + 3_000_000;
        let utxos = rpc.get_spendable_utxos(&wallet.address, None).await.map_err(|e| anyhow::anyhow!("{}", e))?;
        let mut fund: Vec<RpcUtxo> = utxos.into_iter()
            .filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= need
                && !(u.outpoint.transaction_id == in0_txid && u.outpoint.index == in0_index))
            .collect();
        fund.sort_by_key(|u| u.utxo_entry.amount);
        let funding = fund.into_iter().next().ok_or_else(|| anyhow::anyhow!("no funding UTXO >= {}", need))?;
        let total_in = borrow_amount + funding.utxo_entry.amount;

        eprintln!("[exact] scenario={} pay_to={} amount={} borrow={}:{} borrow_amount={} threshold={} cont={} funding={}:{}",
            a.scenario, pay_to, amount, in0_txid, in0_index, borrow_amount, threshold, cont_value,
            funding.outpoint.transaction_id, funding.outpoint.index);

        let mut tx = Transaction::new(0);
        // input0 = borrow outpoint (sig-less additive spend).
        tx.inputs.push(TxInput {
            prev_tx_id: in0_txid.clone(), prev_index: in0_index, sequence: 0, sig_op_count: 0,
            script_version: borrow_p2sh.version(), script_bytes: borrow_p2sh.script().to_vec(), value: borrow_amount,
        });
        // input1 = P2PK funding.
        tx.inputs.push(TxInput {
            prev_tx_id: funding.outpoint.transaction_id.clone(), prev_index: funding.outpoint.index, sequence: 0, sig_op_count: 1,
            script_version: funding.utxo_entry.script_public_key.version, script_bytes: funding.script_bytes(), value: funding.utxo_entry.amount,
        });
        // output0 = payment; output1 = continuation; output2 = change.
        tx.outputs.push(TxOutput::new(amount, payment_spk_ver, payment_spk, None));
        tx.outputs.push(TxOutput::new(cont_value, pay_spk_ver, pay_spk, None));
        let fixed_out = amount + cont_value;
        tx.outputs.push(TxOutput::new(total_in.saturating_sub(fixed_out), wallet_spk_ver, wallet_spk.clone(), None));

        // input0 sigscript = borrow additive spend (continuation at output index 1).
        let borrow_ss = build_x402_borrow_spend_sigscript(1, &borrow_rs);
        let sign = |tx: &Transaction| -> anyhow::Result<Vec<Vec<u8>>> {
            let sh = compute_sighash(tx, 1)?;
            let sig = kob_settle::signing::schnorr_sign(&sh, &privkey)?;
            Ok(vec![borrow_ss.clone(), kob_settle::utils::build_p2pk_sigscript(&sig)])
        };
        let sigscripts = sign(&tx)?;
        let mass = calc_mass_with_sigscripts(&tx, &sigscripts);
        let fee = min_relay_fee(mass);
        let change = total_in.saturating_sub(fixed_out + fee);
        if change >= MIN_UTXO_VALUE {
            let ci = tx.outputs.len() - 1;
            tx.outputs[ci].value = change;
        } else {
            tx.outputs.pop();
        }
        let final_ss = sign(&tx)?;
        let envelope = to_rpc_payload(&tx, &final_ss);
        let encoded = serde_json::to_string(&envelope)?;

        // alpha.8 mandatory signed payer request authorization. The digest
        // binds the encoded artifact + request hash and is Schnorr-signed by
        // the P2PK funding key (input 1 — the head input cannot authorize).
        // NOTE: the facilitator's structural checks (version/expiry/shapes)
        // are what an interop peer can verify today; upstream's exact digest
        // preimage layout has no published byte-level vectors yet.
        let rh_for_digest = a.request_hash.clone().unwrap_or_default();
        let mut digest_preimage = encoded.as_bytes().to_vec();
        digest_preimage.extend_from_slice(rh_for_digest.as_bytes());
        let digest = kob_settle::blake2b_256(&digest_preimage);
        let auth_sig = kob_settle::signing::schnorr_sign(&digest, &privkey)?;
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let authorization = serde_json::json!({
            "version": AUTHORIZATION_VERSION,
            "inputIndex": 1,
            "expiresAt": iso8601_from_unix_secs(now_secs + 3600),
            "digest": hex::encode(digest),
            "signature": hex::encode(auth_sig),
        });

        let mut payload = serde_json::json!({
            "type": "exact-transaction",
            "profile": PROFILE_ADDITIVE,
            "payerAddress": wallet.address,
            "transaction": encoded,
            "transactionEncoding": TX_ENCODING_SAFE_JSON,
            "paymentOutputIndex": 0,
            "challengeId": challenge_id,
            "authorization": authorization
        });
        // Request-binding is mandatory: echo the requestHash the reservation
        // was bound to (the `wrong-request-hash` scenario perturbs it to prove
        // the binding is enforced).
        if let Some(rh) = &a.request_hash {
            let rh = if a.scenario == "wrong-request-hash" {
                let mut b = rh.clone();
                b.replace_range(0..2, if rh.starts_with("00") { "11" } else { "00" });
                b
            } else {
                rh.clone()
            };
            payload["requestHash"] = serde_json::json!(rh);
        }
        let facreq = serde_json::json!({
            "x402Version": X402_VERSION,
            "paymentPayload": { "x402Version": X402_VERSION, "accepted": req, "payload": payload },
            "paymentRequirements": req
        });
        write_out(&a.out, &facreq)?;
        Ok(())
    }
}
