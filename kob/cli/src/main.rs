#![allow(clippy::too_many_arguments)]

use clap::Parser;
use tracing::{error, info};

use kob_cli::Commands;

const EXAMPLES: &str = "\
EXAMPLES:
  Wallet & balance:
    kob-cli --node ws://127.0.0.1:18210 wallet create
    kob-cli --node ws://127.0.0.1:18210 balance
    kob-cli --node ws://127.0.0.1:18210 send --to kaspatest:... --amount-kas 1.5

  Token aliases:
    kob-cli --node <URL> token alias KUSD <covenant_id_64hex>
    kob-cli --node <URL> token aliases

  Deploy & cancel:
    kob-cli --node <URL> deploy buy --token KUSD --price-num 100 --price-den 1 \\
        --min-fill 10000000 --amount-kas 5
    kob-cli --node <URL> cancel --outpoint <txid>:0      # resolves rest from cache
    kob-cli --node <URL> cancel-all --token KUSD --yes

  Market making (with shutdown cleanup):
    kob-cli --node <URL> mm --token KUSD --mid-price-num 100 --mid-price-den 1 \\
        --amount 100000000 --levels 3 --interval 10

  Requote (cache-resolved):
    kob-cli --node <URL> requote --outpoint <old>:0 \\
        --new-side buy --new-token KUSD --new-price-num 105 --new-price-den 1 \\
        --new-min-fill 10000000 --new-amount 100000000

ENV:
  KOB_NODE_URL   default for --node
  KOB_ENGINE_URL default for --engine-url (routes UTXO queries via engine)
";

/// KOB CLI -- Kaspa Order Book management tool.
///
/// Deploy, cancel, fill, and match orders on the KOB L1 DEX protocol.
#[derive(Parser, Debug)]
#[command(name = "kob-cli", version, about, after_help = EXAMPLES)]
struct Cli {
    /// Kaspa node WebSocket URL (required). Set via --node or KOB_NODE_URL env var.
    #[arg(long, env = "KOB_NODE_URL")]
    node: String,

    /// REST API base URL for fallback when wRPC is unavailable.
    /// Default: https://api-tn12.kaspa.org
    #[arg(long)]
    rest_api: Option<String>,

    /// KOB engine base URL (e.g. http://127.0.0.1:7070). When set, UTXO
    /// queries route through the engine's `/api/v1/wallet/utxos` endpoint so
    /// concurrent CLI invocations share the engine's in-flight spent-outpoint
    /// tracking and don't collide on the same UTXO. Falls back to direct node
    /// query when unset.
    #[arg(long, env = "KOB_ENGINE_URL")]
    engine_url: Option<String>,

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

    // Set global engine-URL override if provided (flag or KOB_ENGINE_URL env).
    if let Some(ref eurl) = cli.engine_url {
        if !eurl.is_empty() {
            kob_cli::node::set_engine_url(eurl);
            info!(engine_url = %eurl, "Routing UTXO queries through engine");
        }
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
