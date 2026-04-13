//! KOB matching engine and market maker binary.

#![allow(clippy::too_many_arguments)]

use clap::Parser;
use tracing::error;

use kob_engine::config::AppConfig;

/// KOB Engine -- Kaspa Order Book L1 DEX matching engine + market maker
#[derive(Parser, Debug)]
#[command(name = "kob-engine", version, about = "KOB Matching Engine + Market Maker")]
struct Cli {
    /// Run mode: deploy-test, deploy-test-multi, continuous, dry-run
    #[arg(long, default_value = "continuous")]
    mode: String,

    /// Scan interval in milliseconds (continuous mode)
    #[arg(long, default_value_t = 5000)]
    interval: u64,

    /// Config file path (JSON with "node" and optional "fallback" URLs)
    #[arg(long, default_value = "config.json")]
    config: String,

    /// Node RPC URL (overrides config.json "node" field)
    #[arg(long)]
    node: Option<String>,

    /// Wallet file path (JSON with privateKey, publicKey, address)
    #[arg(long, default_value = "wallet.json")]
    wallet: String,

    /// Order book persistence file path
    #[arg(long, default_value = "orderbook.json")]
    orderbook: String,

    /// Trade history persistence file (JSONL format, empty string to disable)
    #[arg(long, default_value = "trades.jsonl")]
    trades_file: String,

    /// Enable cross-pair routing (Token A -> KAS -> Token B, requires v8 contracts)
    #[arg(long)]
    cross_pair: bool,

    /// Allow self-trade (same address on both sides of a match)
    #[arg(long)]
    allow_self_trade: bool,

    /// API server port (0 to disable)
    #[arg(long, default_value_t = 8080)]
    api_port: u16,

    /// API server bind address
    #[arg(long, default_value = "127.0.0.1")]
    api_bind: String,

    /// Also run MM bot in-process (continuous mode only)
    #[arg(long)]
    mm: bool,

    // MM args (only used when --mm):
    /// MM: Token covenant ID (hex, 64 chars)
    #[arg(long)]
    mm_token: Option<String>,

    /// MM: Mid-price numerator
    #[arg(long)]
    mm_mid_num: Option<u64>,

    /// MM: Mid-price denominator
    #[arg(long)]
    mm_mid_den: Option<u64>,

    /// MM: Spread per level in basis points (100 = 1%)
    #[arg(long, default_value_t = 100)]
    mm_spread_bps: u64,

    /// MM: Number of levels per side
    #[arg(long, default_value_t = 3)]
    mm_levels: u32,

    /// MM: KAS amount per order (sompi)
    #[arg(long)]
    mm_amount: Option<u64>,

    /// MM: Min fill per order (sompi)
    #[arg(long, default_value_t = 1_000_000)]
    mm_min_fill: u64,

    /// Enable ZK prover for freezable token covenants (e.g. USDC).
    /// When disabled (default), orders on freezable pairs are accepted but
    /// skipped during matching. Enable only when a prover backend is available.
    #[arg(long)]
    zk_prover: bool,

    /// Matcher fee in basis points (default 30 = 0.30%, max 100 = 1.00%)
    #[arg(long, default_value_t = 30)]
    fee_bps: u16,

    /// SQLite history database path (empty string to disable)
    #[arg(long, default_value = "history.db")]
    history_db: String,

    /// Passphrase for encrypted wallet file.
    /// If not provided, falls back to KOB_WALLET_PASSWORD or KOB_PASSPHRASE env var.
    #[arg(long)]
    wallet_password: Option<String>,
}

#[tokio::main]
async fn main() {
    // Initialize tracing subscriber
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .with_thread_ids(false)
        .init();

    let cli = Cli::parse();

    // Resolve wallet passphrase: CLI arg > KOB_WALLET_PASSWORD env > KOB_PASSPHRASE env > None
    let wallet_passphrase = cli
        .wallet_password
        .or_else(|| std::env::var("KOB_WALLET_PASSWORD").ok().filter(|s| !s.is_empty()))
        .or_else(|| std::env::var("KOB_PASSPHRASE").ok().filter(|s| !s.is_empty()));

    // Load configuration
    let app_config = match AppConfig::load_with_passphrase(
        &cli.config,
        &cli.wallet,
        wallet_passphrase.as_deref(),
    ) {
        Ok(mut c) => {
            c.zk_prover_enabled = cli.zk_prover;
            // CLI --node overrides config.json node URL
            if let Some(ref node_url) = cli.node {
                c.node_url = node_url.clone();
            }
            // H-5: Apply and validate fee_bps from CLI
            if cli.fee_bps > kob_engine::matcher::executor::MAX_FEE_BPS {
                error!(
                    "fee_bps={} exceeds maximum allowed value of {} (1.00%)",
                    cli.fee_bps,
                    kob_engine::matcher::executor::MAX_FEE_BPS,
                );
                std::process::exit(1);
            }
            c.fee_bps = cli.fee_bps;
            c
        }
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    };

    let history_db = if cli.history_db.is_empty() {
        None
    } else {
        Some(cli.history_db.clone())
    };

    if let Err(e) = kob_engine::run_engine(
        &app_config,
        &cli.mode,
        cli.interval,
        cli.api_port,
        &cli.api_bind,
        cli.mm,
        cli.mm_token.clone(),
        Some(cli.mm_spread_bps),
        Some(cli.mm_levels as u64),
        cli.mm_mid_num,
        cli.mm_mid_den,
        history_db,
        &cli.orderbook,
        &cli.trades_file,
        cli.cross_pair,
        cli.allow_self_trade,
        &cli.wallet,
        cli.mm_amount,
        cli.mm_min_fill,
        None,
        None,
    )
    .await
    {
        error!("FATAL: {}", e);
        std::process::exit(1);
    }
}
