//! Standalone CPU miner used only to fund the KOB testnet-10 E2E wallet.
//!
//! The external kaspa-wasm SDK miner (tests/miner.mjs derivative) hits an
//! immediate "WebSocket disconnected" from this node on every real RPC call
//! (getInfo/getUtxosByAddresses/getBlockTemplate all fail the same way,
//! across both borsh and json encodings) -- a protocol/version mismatch
//! between that external wasm build and this node. kob-cli's own hand-rolled
//! JSON-RPC websocket client (`kob_cli::rpc::RpcClient`) talks to the same
//! node fine (balance queries work), so this binary reuses it verbatim and
//! does the block-template mining loop natively with `kaspa_pow`, using the
//! real rpc-core wire types (`GetBlockTemplateRequest`/`SubmitBlockRequest`)
//! so the JSON shape matches exactly what the node's wRPC JSON handler
//! expects (these ARE the server-side (de)serialization structs).
//!
//! Env vars: NODE, WALLET, MAX_BLOCKS (default 12), TIME_BUDGET_S (default
//! 900), TARGET_KAS (optional early-stop once wallet balance query --
//! done externally by the caller between runs -- this binary itself just
//! mines a bounded number of blocks and exits).

use std::env;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use kaspa_consensus_core::header::Header;
use kaspa_pow::State;
use kaspa_rpc_core::{
    GetBlockTemplateRequest, GetBlockTemplateResponse, RpcAddress, SubmitBlockRequest,
    SubmitBlockResponse,
};

use kob_cli::rpc::RpcClient;
use kob_core::wallet::WalletContext;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let node_url =
        env::var("NODE").unwrap_or_else(|_| "ws://65.108.107.30:18210".to_string());
    let wallet_path =
        PathBuf::from(env::var("WALLET").unwrap_or_else(|_| "wallet.json".to_string()));
    let max_blocks: u64 = env::var("MAX_BLOCKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(12);
    let time_budget_s: u64 = env::var("TIME_BUDGET_S")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(900);

    let wallet = WalletContext::load(&wallet_path)?;
    let addr: RpcAddress = RpcAddress::try_from(wallet.address.as_str())
        .map_err(|e| anyhow::anyhow!("bad wallet address {}: {:?}", wallet.address, e))?;

    eprintln!("[miner] connecting to {} ...", node_url);
    let mut rpc = RpcClient::connect(&node_url).await?;
    eprintln!(
        "[miner] connected. mining to {} (max_blocks={} time_budget_s={})",
        wallet.address, max_blocks, time_budget_s
    );

    let start = Instant::now();
    let mut submitted = 0u64;
    let mut accepted = 0u64;
    let mut consecutive_errs = 0u32;

    while submitted < max_blocks && start.elapsed().as_secs() < time_budget_s {
        if !rpc.is_alive() {
            eprintln!("[miner] connection dropped, reconnecting...");
            match RpcClient::connect(&node_url).await {
                Ok(c) => {
                    rpc = c;
                    eprintln!("[miner] reconnected.");
                }
                Err(e) => {
                    eprintln!("[miner] reconnect failed: {e}. sleeping 2s");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            }
        }

        let req = GetBlockTemplateRequest::new(addr.clone(), vec![]);
        let req_val = serde_json::to_value(&req)?;
        let resp_val = match rpc.call("getBlockTemplate", req_val).await {
            Ok(v) => v,
            Err(e) => {
                consecutive_errs += 1;
                eprintln!("[miner] getBlockTemplate err ({consecutive_errs}): {e}");
                if consecutive_errs > 20 {
                    anyhow::bail!("too many consecutive getBlockTemplate errors");
                }
                tokio::time::sleep(Duration::from_millis(800)).await;
                continue;
            }
        };
        let resp: GetBlockTemplateResponse = match serde_json::from_value(resp_val.clone()) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[miner] parse template err: {e}; raw={resp_val}");
                tokio::time::sleep(Duration::from_millis(800)).await;
                continue;
            }
        };
        if !resp.is_synced {
            eprintln!("[miner] node reports not synced -- mining anyway (testnet-10 dev node)");
        }
        consecutive_errs = 0;

        let mut raw_block = resp.block;
        let header: Header = match (&raw_block.header).try_into() {
            Ok(h) => h,
            Err(e) => {
                eprintln!("[miner] header convert err: {:?}", e);
                continue;
            }
        };

        let state = State::new(&header);
        let round_deadline = Instant::now() + Duration::from_millis(4000);
        let mut nonce: u64 = {
            use std::collections::hash_map::RandomState;
            use std::hash::{BuildHasher, Hasher};
            RandomState::new().build_hasher().finish() ^ (Instant::now().elapsed().as_nanos() as u64)
        };
        let mut found = None;
        while Instant::now() < round_deadline {
            for _ in 0..200_000u32 {
                let (ok, _) = state.check_pow(nonce);
                if ok {
                    found = Some(nonce);
                    break;
                }
                nonce = nonce.wrapping_add(1);
            }
            if found.is_some() {
                break;
            }
        }
        let Some(nonce) = found else {
            continue;
        };
        raw_block.header.nonce = nonce;

        let submit_req = SubmitBlockRequest::new(raw_block, false);
        let submit_val = serde_json::to_value(&submit_req)?;
        match rpc.call("submitBlock", submit_val).await {
            Ok(v) => {
                submitted += 1;
                let parsed: Option<SubmitBlockResponse> =
                    serde_json::from_value(v.clone()).ok();
                let is_ok = parsed.map(|r| r.report.is_success()).unwrap_or(false);
                if is_ok {
                    accepted += 1;
                }
                eprintln!(
                    "[miner] submit #{submitted} nonce={nonce} accepted={is_ok} (total_accepted={accepted}) resp={v}"
                );
            }
            Err(e) => {
                submitted += 1;
                eprintln!("[miner] submitBlock err on attempt #{submitted}: {e}");
            }
        }
    }

    eprintln!(
        "[miner] done. submitted={submitted} accepted={accepted} elapsed={:?}",
        start.elapsed()
    );
    Ok(())
}
