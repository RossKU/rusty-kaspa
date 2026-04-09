#![allow(clippy::too_many_arguments)]

use clap::Parser;
use tracing::{error, info};

use kob_cli::Commands;

/// KOB CLI -- Kaspa Order Book management tool.
///
/// Deploy, cancel, fill, and match orders on the KOB L1 DEX protocol.
#[derive(Parser, Debug)]
#[command(name = "kob-cli", version, about)]
struct Cli {
    /// Kaspa node WebSocket URL (required). Set via --node or KOB_NODE_URL env var.
    #[arg(long, env = "KOB_NODE_URL")]
    node: String,

    /// REST API base URL for fallback when wRPC is unavailable.
    /// Default: https://api-tn12.kaspa.org
    #[arg(long)]
    rest_api: Option<String>,

    /// Path to wallet.json file.
    #[arg(long, default_value = "wallet.json")]
    wallet: String,

    /// Network: mainnet or testnet.
    #[arg(long, default_value = "testnet")]
    network: String,

    /// Miner fee override in sompi. If omitted, fee is computed from TX mass.
    /// When set, uses max(mass_fee, this_value). Only needed to force a higher fee.
    #[arg(long)]
    fee_rate: Option<u64>,

    #[command(subcommand)]
    command: Commands,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let fee = cli.fee_rate.unwrap_or(0); // 0 = auto-compute from TX mass

    // Set global REST API URL override if provided
    if let Some(ref rest_url) = cli.rest_api {
        kob_cli::node::set_rest_url(rest_url);
    }

    info!(node = %cli.node, wallet = %cli.wallet, network = %cli.network, fee = fee, "KOB CLI starting");

    let wallet_path = std::path::Path::new(&cli.wallet);
    let network = match cli.network.as_str() {
        "mainnet" => kob_core::types::Network::Mainnet,
        "testnet" => kob_core::types::Network::Testnet,
        other => {
            error!("unknown network '{}'. Use 'mainnet' or 'testnet'.", other);
            std::process::exit(1);
        }
    };

    kob_cli::dispatch(&cli.node, wallet_path, network, fee, cli.command).await
}
