//! Kaspa x402 facilitator server binary.
//!
//! Usage:
//!   kob-x402 --node wss://host:port --bind 0.0.0.0:8402 \
//!            --network kaspa:testnet-10 --replay-log ./x402_replay.jsonl
//!
//! Connects to a Kaspa node over wRPC, opens the durable replay log, and
//! serves the facilitator's /verify, /settle, /supported, /health endpoints.

use std::sync::Arc;

use kob_settle::observe::ReplayStore;
use kob_settle::rpc::{ConfirmConfig, RpcClient};
use kob_x402::facilitator::{Facilitator, FacilitatorConfig};
use kob_x402::wire_v2::NETWORK_TESTNET10;

struct Args {
    node: String,
    bind: String,
    network: String,
    replay_log: String,
}

fn parse_args() -> Args {
    let mut node = String::new();
    let mut bind = "0.0.0.0:8402".to_string();
    let mut network = NETWORK_TESTNET10.to_string();
    let mut replay_log = "x402_replay.jsonl".to_string();

    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--node" => node = it.next().unwrap_or_default(),
            "--bind" => bind = it.next().unwrap_or(bind),
            "--network" => network = it.next().unwrap_or(network),
            "--replay-log" => replay_log = it.next().unwrap_or(replay_log),
            "-h" | "--help" => {
                eprintln!(
                    "kob-x402 --node <wss-url> [--bind 0.0.0.0:8402] \
                     [--network kaspa:testnet-10] [--replay-log x402_replay.jsonl]"
                );
                std::process::exit(0);
            }
            other => eprintln!("[x402] ignoring unknown arg: {}", other),
        }
    }
    Args { node, bind, network, replay_log }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = parse_args();
    if args.node.is_empty() {
        anyhow::bail!("--node <wss-url> is required");
    }

    let rpc = RpcClient::connect(&args.node)
        .await
        .map_err(|e| anyhow::anyhow!("failed to connect to node {}: {}", args.node, e))?;
    tracing::info!("[x402] connected to node {}", args.node);

    let replay = ReplayStore::open(&args.replay_log)
        .map_err(|e| anyhow::anyhow!("failed to open replay log {}: {}", args.replay_log, e))?;
    tracing::info!(
        "[x402] replay log {} ({} record(s))",
        args.replay_log,
        replay.len()
    );

    let config = FacilitatorConfig {
        network: args.network.clone(),
        // Generous finality window for real-network latency (~10 BPS): poll for
        // roughly 10s before declaring a broadcast unconfirmed. A retry is
        // idempotent and re-confirms from the durable log, so this is a soft cap.
        confirm: ConfirmConfig {
            initial_delay: std::time::Duration::from_millis(500),
            max_polls: 15,
            poll_interval: std::time::Duration::from_millis(700),
        },
    };
    let fac = Arc::new(Facilitator::new(rpc, replay, config));

    tracing::info!("[x402] settling on network {}", args.network);
    kob_x402::server::serve(fac, &args.bind).await
}
