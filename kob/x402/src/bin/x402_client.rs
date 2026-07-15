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
use kob_x402::wire::{
    NativeExactPayload, PaymentPayload, PaymentRequirements, ASSET_NATIVE_KAS, SCHEME_EXACT,
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
    amount: u64,
    require: u64,
    fingerprint_hex: &str,
) -> serde_json::Value {
    let payload = PaymentPayload {
        x402_version: X402_VERSION,
        scheme: SCHEME_EXACT.to_string(),
        network: network.to_string(),
        payload: serde_json::to_value(NativeExactPayload {
            transaction: tx,
            from: from.to_string(),
            pay_to: pay_to.to_string(),
            amount: amount.to_string(),
        })
        .unwrap(),
    };
    let requirements = PaymentRequirements {
        scheme: SCHEME_EXACT.to_string(),
        network: network.to_string(),
        max_amount_required: require.to_string(),
        resource: "https://example/resource".to_string(),
        description: "x402 e2e".to_string(),
        mime_type: "application/json".to_string(),
        pay_to: pay_to.to_string(),
        max_timeout_seconds: 60,
        asset: ASSET_NATIVE_KAS.to_string(),
        extra: serde_json::json!({ "fingerprint": fingerprint_hex }),
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

    let args = parse_args();
    if args.node.is_empty() || args.wallet.is_empty() || args.pay_to.is_empty() || args.amount == 0 {
        anyhow::bail!("required: --node --wallet --pay-to --amount");
    }

    let wallet = WalletContext::load(Path::new(&args.wallet))?;
    let privkey = *wallet.privkey_bytes();

    let require = args.require.unwrap_or(args.amount);
    let fingerprint_hex = fingerprint::compute_fingerprint(
        &args.method,
        &args.path,
        &args.pay_to,
        &require.to_string(),
        &args.nonce,
    );
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

    let req = facilitator_request(
        &args.network,
        tx,
        &wallet.address,
        &args.pay_to,
        args.amount,
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
