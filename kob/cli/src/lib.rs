#![allow(clippy::too_many_arguments)]

pub mod auto_match;
pub mod batch;
pub mod bracket;
pub mod cancel;
pub mod cancel_all;
pub mod dca;
pub mod cancel_mark;
pub mod consolidate;
pub mod deploy;
pub mod estimate;
pub mod history;
pub mod ifd;
pub mod lending;
pub mod list;
pub mod market;
pub mod match_batch;
pub mod matching;
pub mod mm;
pub mod my_orders;
pub mod node;
pub mod order_cache;
pub mod options;
pub mod orderbook;
pub mod partial_fill;
pub mod perp;
pub mod receipt;
pub mod recover;
pub mod requote;
pub mod rest;
pub mod rpc;
pub mod scan;
pub mod signing;
pub mod status;
pub mod stop;
pub mod tif;
pub mod token;
pub mod wallet;
pub mod wallet_send;
pub mod prediction;
pub mod insurance;
pub mod swap;
pub mod watch;
pub mod listing;

use clap::Subcommand;

/// C5: interactive confirmation for destructive commands.
///
/// - If `skip` (e.g. `--yes`) is set, auto-confirm.
/// - If stdin is not a terminal (pipes, E2E scripts, CI), auto-confirm with
///   a warning so non-interactive flows are not broken.
/// - Otherwise, prompt and require the user to type `yes` exactly.
pub fn confirm_or_abort(prompt: &str, skip: bool) -> anyhow::Result<()> {
    if skip {
        return Ok(());
    }
    use std::io::{IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        eprintln!("[CONFIRM] non-interactive stdin — auto-confirming: {}", prompt);
        return Ok(());
    }
    eprintln!("{}", prompt);
    eprint!("Type 'yes' to proceed (anything else aborts): ");
    std::io::stderr().flush().ok();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim() == "yes" {
        Ok(())
    } else {
        anyhow::bail!("aborted by user");
    }
}

/// Subcommand enum for the top-level CLI.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Wallet management: create, import, list, derive, export, balance.
    ///
    /// Run `kob wallet info` for basic wallet info (legacy behavior).
    /// Run `kob wallet create` to create a new HD wallet.
    Wallet {
        #[command(subcommand)]
        action: Option<wallet::WalletCommand>,
    },

    /// Show wallet KAS balance (shortcut for `wallet balance`).
    Balance {
        /// HD account index (default: 0).
        #[arg(long, default_value = "0")]
        account: u32,

        /// Number of derived addresses to scan (default: 20).
        #[arg(long, default_value = "20")]
        count: u32,
    },

    /// Deploy an order.
    Deploy {
        #[command(subcommand)]
        order_type: DeployCommands,
    },

    /// Cancel an active order by outpoint.
    ///
    /// If --side, --price-num, --price-den, --min-fill are omitted, they are
    /// looked up from the local orders.json cache (written by deploy).
    Cancel {
        /// Outpoint of the order to cancel (txid:index).
        #[arg(long)]
        outpoint: String,

        /// Order side: buy or sell. Resolved from cache if omitted.
        #[arg(long)]
        side: Option<String>,

        /// Token covenant ID (hex, 64 chars). Required for buy orders. Resolved from cache if omitted.
        #[arg(long)]
        token: Option<String>,

        /// Price numerator. Resolved from cache if omitted.
        #[arg(long)]
        price_num: Option<u64>,

        /// Price denominator. Resolved from cache if omitted.
        #[arg(long)]
        price_den: Option<u64>,

        /// Minimum fill amount. Resolved from cache if omitted.
        #[arg(long)]
        min_fill: Option<u64>,

        /// Order UTXO value in sompi (queried from chain if omitted).
        #[arg(long)]
        order_value: Option<u64>,

        /// Contract version (14, 16, or 17). Must match the version used to
        /// deploy the order. For v16/v17 buys, --max-matcher-fee is the bps
        /// value embedded at deploy time, not raw sompi.
        #[arg(long)]
        version: Option<u8>,

        /// Expiry DAA score (required for v14 orders to reconstruct RS). 0 = GTC.
        #[arg(long)]
        expiry: Option<u64>,

        /// Fee UTXO outpoint (txid:index) to use instead of auto-selection.
        /// Useful when auto-selected UTXOs are stale (stuck in mempool).
        #[arg(long)]
        fee_utxo: Option<String>,

        /// Cancel-pending flag (0 = normal, 1 = after cancel-mark).
        /// Use --cpend 1 to cancel an order that was previously cancel-marked.
        #[arg(long, default_value_t = 0)]
        cpend: u8,

        /// Max matcher fee (sompi) embedded in the redeemScript. Overrides cache value.
        #[arg(long)]
        max_matcher_fee: Option<u64>,
    },

    /// Safely retire an order in two steps: first mark it, then cancel it.
    ///
    /// This is step 1 of a 2-step cancel. It flips the order's cancel-pending
    /// flag from 0 to 1, which immediately blocks any new fills or partial
    /// fills. The order funds stay locked in a new P2SH UTXO (same parameters,
    /// cpend=1) that only you can spend via `kob-cli cancel` (step 2).
    ///
    /// Use this when you want to retire an order without racing an incoming
    /// fill: once marked, the order cannot match, and you can safely follow
    /// up with `cancel` to recover the KAS. One-shot `cancel` skips the mark
    /// and races with the mempool -- mark first if funds are large.
    ///
    /// EXAMPLES:
    ///   kob-cli cancel-mark --outpoint <txid:0> --side buy  --token <covid> \
    ///       --price-num 100 --price-den 1 --min-fill 1000000
    ///   kob-cli cancel --outpoint <new_txid:0> --cpend 1   # step 2
    CancelMark {
        /// Outpoint of the order to mark (txid:index).
        #[arg(long)]
        outpoint: String,

        /// Order side: buy or sell.
        #[arg(long)]
        side: String,

        /// Token covenant ID (hex, 64 chars). Required for buy orders.
        #[arg(long)]
        token: Option<String>,

        /// Price numerator.
        #[arg(long)]
        price_num: u64,

        /// Price denominator.
        #[arg(long)]
        price_den: u64,

        /// Minimum fill amount.
        #[arg(long)]
        min_fill: u64,

        /// Order UTXO value in sompi (queried from chain if omitted).
        #[arg(long)]
        order_value: Option<u64>,

        /// Contract version (14 or 16). Must match the version used to deploy the order.
        #[arg(long, default_value_t = 14)]
        version: u8,

        /// Expiry DAA score (required for v14 orders to reconstruct RS). 0 = GTC.
        #[arg(long, default_value = "0")]
        expiry: u64,

        /// Fee UTXO outpoint (txid:index). Auto-selected from wallet if omitted.
        #[arg(long)]
        fee_utxo: Option<String>,

        /// Max matcher fee (sompi) embedded in the redeemScript.
        #[arg(long, default_value = "10000000")]
        max_matcher_fee: u64,
    },

    /// Partially fill a buy or sell order.
    ///
    /// Fills a portion of an order, leaving a residual order UTXO with reduced value.
    /// The residual order keeps the same parameters (price, min_fill, owner) and the
    /// same P2SH address.
    PartialFill {
        /// Order outpoint to partially fill (txid:index).
        #[arg(long)]
        outpoint: String,

        /// Order side: buy or sell.
        #[arg(long)]
        side: String,

        /// Token covenant ID (hex, 64 chars).
        #[arg(long)]
        token: String,

        /// Price numerator.
        #[arg(long)]
        price_num: u64,

        /// Price denominator.
        #[arg(long)]
        price_den: u64,

        /// Minimum fill amount.
        #[arg(long)]
        min_fill: u64,

        /// Amount to fill: KAS sompi for buy orders, token sompi for sell orders.
        #[arg(long)]
        fill_amount: u64,

        /// Order UTXO value in sompi (queried from chain if omitted).
        #[arg(long)]
        order_value: Option<u64>,

        /// Owner hash (hex, 64 chars). Defaults to wallet owner hash.
        #[arg(long)]
        owner_hash: Option<String>,

        /// SPK hash (hex, 64 chars). Defaults to wallet P2PK SPK hash.
        #[arg(long)]
        spk_hash: Option<String>,

        /// Token UTXO outpoint for buy partial fill (txid:index). Provides tokens to buyer.
        #[arg(long)]
        token_outpoint: Option<String>,

        /// Fee input outpoint (txid:index).
        #[arg(long)]
        fee_input: Option<String>,

        /// Contract version (only 14 is supported).
        #[arg(long, default_value = "14")]
        version: u8,

        /// Expiry DAA score (required for v14 RS reconstruction). 0 = GTC.
        #[arg(long, default_value = "0")]
        expiry: u64,

        /// Max matcher fee (sompi) embedded in the redeemScript.
        #[arg(long, default_value = "10000000")]
        max_matcher_fee: u64,
    },

    /// List active orders (query UTXOs at known P2SH addresses).
    List {
        /// Token covenant ID to filter by (hex).
        #[arg(long)]
        token: Option<String>,
    },

    /// Execute a match between a buy order and a sell order.
    ///
    /// Standard match: buy and sell orders for the same token pair.
    /// Cross-pair match: sell Token A, buy Token B via a bridging token UTXO.
    ///   --cross-pair --token-outpoint <TXID:IDX>
    ///   TX layout: sell[0] buy[1] token[2] fee[3]
    Match {
        /// Buy order outpoint (txid:index).
        #[arg(long)]
        buy: String,

        /// Sell order outpoint (txid:index).
        #[arg(long)]
        sell: String,

        /// Token covenant ID (hex, 64 chars).
        #[arg(long)]
        token: String,

        /// Buy price numerator.
        #[arg(long)]
        buy_price_num: u64,

        /// Buy price denominator.
        #[arg(long)]
        buy_price_den: u64,

        /// Buy minimum fill.
        #[arg(long)]
        buy_min_fill: u64,

        /// Buy order value in sompi (queried if omitted).
        #[arg(long)]
        buy_value: Option<u64>,

        /// Buy owner hash (hex, 64 chars). Defaults to wallet owner hash.
        #[arg(long)]
        buy_owner_hash: Option<String>,

        /// Buy SPK hash (hex, 64 chars). Defaults to wallet P2PK SPK hash.
        #[arg(long)]
        buy_spk_hash: Option<String>,

        /// Sell price numerator.
        #[arg(long)]
        sell_price_num: u64,

        /// Sell price denominator.
        #[arg(long)]
        sell_price_den: u64,

        /// Sell minimum fill.
        #[arg(long)]
        sell_min_fill: u64,

        /// Sell order value in sompi (queried if omitted).
        #[arg(long)]
        sell_value: Option<u64>,

        /// Sell owner hash (hex, 64 chars). Defaults to wallet owner hash.
        #[arg(long)]
        sell_owner_hash: Option<String>,

        /// Sell SPK hash (hex, 64 chars). Defaults to wallet P2PK SPK hash.
        #[arg(long)]
        sell_spk_hash: Option<String>,

        /// Buyer's public key (hex, 64 chars / 32 bytes). Required.
        /// Used to build the buyer's P2PK SPK for token output and to derive owner/spk hashes.
        #[arg(long)]
        buyer_pubkey: String,

        /// Seller's public key (hex, 64 chars / 32 bytes). Required.
        /// Used to build the seller's P2PK SPK for KAS output and to derive owner/spk hashes.
        #[arg(long)]
        seller_pubkey: String,

        /// Fee input outpoint, if needed (txid:index).
        #[arg(long)]
        fee_input: Option<String>,

        /// Enable cross-pair matching mode. Requires --token-outpoint.
        #[arg(long)]
        cross_pair: bool,

        /// Token UTXO outpoint for cross-pair matching (txid:index).
        /// Provides Token B to the buy order when sell order carries Token A.
        #[arg(long)]
        token_outpoint: Option<String>,

        /// Buy token covenant ID (hex, 64 chars). For cross-pair: the token the buy order wants.
        /// Defaults to --token if not specified.
        #[arg(long)]
        buy_token: Option<String>,

        /// Contract version: 13/14 (legacy, shared RS layout) or 16 (F6-fix
        /// buy contract, --mmfee-bps semantics). Sell orders are always v14
        /// -- there is no v16 sell contract.
        #[arg(long, default_value = "14")]
        version: u8,

        /// Buy order expiry DAA score (for v14 RS reconstruction). 0 = GTC.
        #[arg(long, default_value = "0")]
        buy_expiry: u64,

        /// Sell order expiry DAA score (for v14 RS reconstruction). 0 = GTC.
        #[arg(long, default_value = "0")]
        sell_expiry: u64,

        /// Max matcher fee (sompi) embedded in the reconstructed v14 buy/sell
        /// redeemScripts. Must match the value the orders were deployed
        /// with, or the reconstructed P2SH won't match the on-chain order.
        /// Ignored for the buy side when --version 16 (use --mmfee-bps).
        #[arg(long, default_value = "10000000")]
        max_matcher_fee: u64,

        /// Max matcher fee in basis points, embedded in a v16 buy
        /// redeemScript (must match the deployed value). Sets --version to
        /// 16 automatically. Also used (unless --fee-bps overrides it) as
        /// the canonical planner's matcher-fee cap, so the built tx never
        /// asks for more surplus than the buy's own on-chain F6 check
        /// allows. Default when --version 16 and unset: 30 (0.30%).
        #[arg(long)]
        mmfee_bps: Option<u64>,

        /// Matcher fee cap in basis points passed to the canonical planner
        /// (same semantics as `match-batch --fee-bps`). Overrides the
        /// --mmfee-bps-derived default. Excess surplus is returned to the
        /// buyer as change.
        #[arg(long)]
        fee_bps: Option<u16>,

        /// Adversarial tamper mode for security testing. Deliberately constructs
        /// an invalid match TX to verify covenant rejection. The node MUST reject.
        ///
        /// Modes: f2-redirect-seller, f2-redirect-buyer, f4-remove-binding, f4-reduce-value
        #[arg(long)]
        tamper: Option<String>,
    },

    /// N:M atomic batch match -- fills multiple sell and buy orders in a single TX.
    ///
    /// Uses 2-phase fee convergence for exact miner fee (compute mass == fee).
    /// Orders are looked up from the local orders.json cache.
    MatchBatch {
        /// Sell order outpoints (comma-separated, e.g. TXID:0,TXID:1).
        #[arg(long, value_delimiter = ',')]
        sell_outpoints: Vec<String>,

        /// Buy order outpoints (comma-separated, e.g. TXID:0,TXID:1).
        #[arg(long, value_delimiter = ',')]
        buy_outpoints: Vec<String>,

        /// Token covenant ID (hex, 64 chars).
        #[arg(long)]
        token: String,

        /// Maximum matcher fee in sompi (default: 10_000_000 = 0.1 KAS).
        #[arg(long, default_value = "10000000")]
        max_matcher_fee: u64,

        /// Matcher fee cap in basis points (e.g. 50 = 0.5% of trade value).
        /// When set, matcher surplus is capped at (trade_value * fee_bps / 10000).
        /// Excess is returned to buyers as change.
        #[arg(long)]
        fee_bps: Option<u16>,

        /// IOC (Immediate-Or-Cancel) mode: single buy sweeps multiple sells.
        /// Sells are consumed in order until the buy's KAS is exhausted.
        /// Unspent KAS is returned to the buyer as change.
        /// Requires exactly one --buy-outpoints entry.
        #[arg(long)]
        ioc: bool,
    },

    /// Trade receipt operations: create, consume (v3), trigger, consume-v1 (legacy).
    Receipt {
        #[command(subcommand)]
        action: receipt::ReceiptCommand,
    },

    /// Show current configuration and contract info.
    Config,

    /// Show system status: node info, sync state, wallet balance.
    Status,

    /// Scan for P2SH covenant UTXOs at an address.
    Scan {
        /// Address to scan (defaults to wallet address).
        #[arg(long)]
        address: Option<String>,

        /// Filter by covenant type: buy, sell, receipt, bracket, config, all.
        #[arg(long, name = "type")]
        cov_type: Option<String>,
    },

    /// Token operations: create, mint, and transfer tokens.
    Token {
        #[command(subcommand)]
        action: token::TokenCommand,
    },

    /// Automated continuous scanning and matching for a token pair.
    AutoMatch {
        /// Token pair ID (hex, 64 chars).
        #[arg(long)]
        pair_id: String,

        /// Scan interval in seconds (default: 10).
        #[arg(long, default_value = "10")]
        interval: u64,

        /// Show matches without submitting transactions.
        #[arg(long)]
        dry_run: bool,

        /// Minimum price spread to match (default: 0).
        #[arg(long, default_value = "0")]
        min_spread: f64,

        /// Stop after N successful matches (default: 0 = unlimited).
        #[arg(long, default_value = "0")]
        max_matches: u64,

        /// Enable cross-pair routing (Token A -> KAS -> Token B).
        /// Requires v8 contracts. Scans all pairs for arbitrage routes.
        #[arg(long)]
        cross_pair: bool,
    },

    /// Bracket order (bracket_order_v5): deploy, fill, cancel.
    Bracket {
        #[command(subcommand)]
        action: bracket::BracketCommand,
    },

    /// Listing auction (english/dutch/fixed): deploy, settle.
    Listing {
        #[command(subcommand)]
        action: listing::ListingCommand,
    },

    /// Option contracts: deploy-call, deploy-put, exercise, cancel, expire.
    Option {
        #[command(subcommand)]
        action: options::OptionCommand,
    },

    /// Execute multiple operations from a JSON batch file.
    Batch {
        /// Path to the JSON operations file.
        #[arg(long)]
        file: String,
    },

    /// Recover stuck UTXOs from the mempool using RBF (Replace-By-Fee).
    ///
    /// Queries all confirmed UTXOs for the wallet address, then checks the mempool
    /// for any pending transactions spending them. For each stuck UTXO, builds a
    /// self-send replacement transaction at a higher fee and submits it via
    /// `submitTransactionReplacement`. Fee escalation: 0.0001 -> 0.001 -> 0.01 KAS.
    Recover,

    /// Recover lost orders.json from the Kaspa REST API.
    ///
    /// Scans all transactions involving the wallet address, extracts KOB order
    /// payloads (KOB:1:<RS>), parses the redeemScript to recover order parameters,
    /// verifies owner_hash matches the wallet, and checks UTXO liveness via RPC.
    /// Writes recovered live orders to orders_recovered.json (or --output path).
    RecoverOrders {
        /// Kaspa REST API base URL (e.g., http://localhost:18110).
        #[arg(long)]
        rest: String,

        /// Output file path (default: orders_recovered.json).
        #[arg(long)]
        output: Option<String>,

        /// Print what would be recovered without writing any file.
        #[arg(long)]
        dry_run: bool,
    },

    /// Query the on-chain order book for a token pair.
    ///
    /// Displays bids and asks sorted by price. Uses the local order cache
    /// (orders.json) for parameter mapping. With --cache-file, reads directly
    /// from cache without RPC. Without --cache-file, queries live UTXOs.
    Orderbook {
        /// Token covenant ID to filter by (hex, 64 chars). Shows all pairs if omitted.
        #[arg(long)]
        token: Option<String>,

        /// Number of price levels to show per side (default: 10).
        #[arg(long, default_value = "10")]
        depth: usize,

        /// Output as JSON.
        #[arg(long)]
        json: bool,

        /// Use cached orders.json directly (no RPC, fastest).
        #[arg(long)]
        cache_file: Option<String>,
    },

    /// Show best bid, best ask, and spread for a token pair.
    ///
    /// Reads the local order cache to compute the current spread.
    Spread {
        /// Token covenant ID (hex, 64 chars).
        #[arg(long)]
        token: String,

        /// Output as JSON.
        #[arg(long)]
        json: bool,

        /// Use cached orders.json directly (no RPC, fastest).
        #[arg(long)]
        cache_file: Option<String>,
    },

    /// Check the status of a specific order (open, filled, cancelled, etc.).
    ///
    /// Queries the UTXO set and transaction history to determine the current
    /// state of an order deployed at the given outpoint.
    OrderStatus {
        /// Outpoint of the order to check (txid:index).
        #[arg(long)]
        outpoint: String,

        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Requote: atomic cancel-old + deploy-new for market makers.
    ///
    /// Cancels an existing order and immediately deploys a new one at
    /// updated parameters. Essential for continuous quoting.
    Requote {
        /// Outpoint of the old order to cancel (txid:index).
        #[arg(long)]
        outpoint: String,

        /// Old order side: buy or sell. Resolved from orders cache if omitted.
        #[arg(long)]
        old_side: Option<String>,

        /// Old order token covenant ID (hex, 64 chars). Required for buy if not in cache.
        #[arg(long)]
        old_token: Option<String>,

        /// Old order price numerator. Resolved from orders cache if omitted.
        #[arg(long)]
        old_price_num: Option<u64>,

        /// Old order price denominator. Resolved from orders cache if omitted.
        #[arg(long)]
        old_price_den: Option<u64>,

        /// Old order minimum fill. Resolved from orders cache if omitted.
        #[arg(long)]
        old_min_fill: Option<u64>,

        /// Old order UTXO value in sompi (queried from chain if omitted).
        #[arg(long)]
        old_order_value: Option<u64>,

        /// New order side: buy or sell.
        #[arg(long)]
        new_side: String,

        /// New order token covenant ID (hex, 64 chars).
        #[arg(long)]
        new_token: String,

        /// New order price numerator.
        #[arg(long)]
        new_price_num: u64,

        /// New order price denominator.
        #[arg(long)]
        new_price_den: u64,

        /// New order minimum fill.
        #[arg(long)]
        new_min_fill: u64,

        /// New order amount in sompi.
        #[arg(long)]
        new_amount: u64,

        /// Contract version of the old order being cancelled (14, 16, or 17).
        /// Resolved from orders cache if omitted (defaults to 14).
        #[arg(long)]
        old_version: Option<u8>,

        /// Contract version for the new order. Sell: only 14. Buy: only 17
        /// (v14/v16 are rejected for new deploys, same as `deploy buy`);
        /// auto-bumped from the default to 17 when --new-side buy.
        #[arg(long, default_value = "14")]
        new_version: u8,

        /// Old order expiry DAA score. Resolved from orders cache if omitted (0 = GTC).
        #[arg(long)]
        old_expiry: Option<u64>,

        /// New order expiry DAA score (for v14 RS construction). 0 = GTC.
        #[arg(long, default_value = "0")]
        new_expiry: u64,

        /// Submit deploy immediately without waiting for cancel confirmation.
        #[arg(long)]
        no_wait: bool,

        /// Fee UTXO outpoint (txid:index). Auto-selected from wallet if omitted.
        #[arg(long)]
        fee_utxo: Option<String>,

        /// Max matcher fee (sompi) for the old order's redeemScript. Resolved from orders cache if omitted.
        #[arg(long)]
        old_max_matcher_fee: Option<u64>,

        /// Max matcher fee (sompi) for the new order's redeemScript.
        #[arg(long, default_value = "10000000")]
        new_max_matcher_fee: u64,
    },

    /// Cancel all open orders owned by the wallet.
    CancelAll {
        /// Token covenant ID filter (hex, 64 chars). Cancel only orders for this token.
        #[arg(long)]
        token: Option<String>,

        /// Preview orders that would be cancelled without submitting TXs.
        #[arg(long)]
        dry_run: bool,

        /// Path to orders cache file (default: orders.json).
        #[arg(long)]
        orders_file: Option<String>,

        /// Skip the interactive confirmation prompt (C5).
        #[arg(long)]
        yes: bool,
    },

    /// List all MY open orders across all pairs.
    MyOrders {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Show completed trade history for the wallet.
    TradeHistory {
        /// Maximum number of trades to show (default: 50).
        #[arg(long, default_value = "50")]
        limit: usize,

        /// Output as JSON.
        #[arg(long)]
        json: bool,

        /// Engine API URL to enrich trade records with fill details
        /// (fill_txid, filled_amount). Defaults to http://localhost:8080;
        /// pass an empty string to skip enrichment.
        #[arg(long, default_value = "http://localhost:8080")]
        engine_url: String,
    },

    /// Send KAS to an address.
    Send {
        /// Recipient address.
        #[arg(long)]
        to: String,

        /// Amount in sompi to send. Mutually exclusive with --amount-kas.
        #[arg(long, conflicts_with = "amount_kas")]
        amount: Option<u64>,

        /// Amount in KAS (e.g., 1.5 = 150_000_000 sompi). Mutually exclusive with --amount.
        #[arg(long)]
        amount_kas: Option<f64>,

        /// Override the default fee (in sompi).
        #[arg(long)]
        fee: Option<u64>,

        /// Skip the interactive confirmation prompt (C5).
        #[arg(long)]
        yes: bool,
    },

    /// Estimate transaction mass and fees before submitting.
    ///
    /// Computes mass = max(transaction_mass, storage_mass) and required fee.
    /// No wallet or network connection required -- purely offline calculation.
    EstimateFee {
        #[command(subcommand)]
        action: estimate::EstimateCommand,
    },

    /// Market maker bot: deploy symmetric orders around a mid-price.
    ///
    /// Maintains continuous two-sided liquidity by deploying buy/sell orders
    /// at configurable levels and spreads. Monitors for fills and re-deploys.
    Mm {
        /// Token covenant ID (hex, 64 chars).
        #[arg(long)]
        token: String,

        /// Mid-price numerator.
        #[arg(long)]
        mid_price_num: u64,

        /// Mid-price denominator.
        #[arg(long)]
        mid_price_den: u64,

        /// Spread per level in basis points (100 = 1%).
        #[arg(long, default_value = "100")]
        spread_bps: u64,

        /// Number of levels per side (default: 3).
        #[arg(long, default_value = "3")]
        levels: u32,

        /// KAS amount per order in sompi.
        #[arg(long)]
        amount: u64,

        /// Min fill per order in sompi (default: 10_000_000 = 0.1 KAS, from storage mass).
        #[arg(long, default_value = "10000000")]
        min_fill: u64,

        /// Requote check interval in seconds (default: 10).
        #[arg(long, default_value = "10")]
        interval: u64,

        /// Contract version (only 14 is supported).
        #[arg(long, default_value = "14")]
        version: u8,

        /// Print orders without deploying.
        #[arg(long)]
        dry_run: bool,

        /// Requote all if mid drifts more than this many bps (default: 500 = 5%).
        #[arg(long, default_value = "500")]
        requote_threshold_bps: u64,

        /// Skip the on-shutdown cancel sweep (orders stay on-chain when Ctrl+C).
        #[arg(long)]
        no_cleanup: bool,

        /// Delay (seconds) between successive deploy TXs (H12).
        #[arg(long, default_value = "2")]
        deploy_delay_secs: u64,
    },

    /// Watch blocks for fill TXs (trustless price discovery).
    ///
    /// Scans recent blocks for v14 fill transactions, displays price info,
    /// then subscribes to new blocks and prints fills as they appear.
    Watch {
        /// Token covenant ID to filter by (hex, 64 chars). Shows all fills if omitted.
        #[arg(long, default_value = "")]
        token: String,
    },

    /// Stop orders: deploy, cancel, list. Conditional orders held by the Matcher.
    ///
    /// The Matcher holds a pre-signed deploy TX and broadcasts it to L1 when
    /// the market price crosses the stop price. Supports stop-limit and stop-market.
    Stop {
        #[command(subcommand)]
        action: stop::StopCommand,
    },

    /// Trailing stop orders: deploy, cancel, list.
    ///
    /// The Matcher tracks market price and adjusts the stop price dynamically.
    /// When the price reverses by the trail distance, the pre-signed TX is broadcast.
    TrailingStop {
        #[command(subcommand)]
        action: stop::TrailingStopCommand,
    },

    /// Prediction market operations: create, vote, split, merge, settle, redeem, expire, refund.
    Prediction {
        #[command(subcommand)]
        action: prediction::PredictionCommand,
    },

    /// Perpetual futures: deploy-long, deploy-short, cancel, positions, close,
    /// liquidate, add-margin, settle.
    ///
    /// Bilateral P2P perp contracts on Kaspa L1 covenants.
    Perp {
        #[command(subcommand)]
        action: perp::PerpCommand,
    },

    /// DCA (Dollar-Cost Averaging): deploy, fill, cancel.
    ///
    /// Automated periodic token purchases at a limit price.
    /// Permissionless fills -- anyone can execute a tranche when the
    /// next_execution_daa window is reached.
    Dca {
        #[command(subcommand)]
        action: dca::DcaCommand,
    },

    /// P2P lending: deploy offers/requests, cancel, repay, list loans.
    Lending {
        #[command(subcommand)]
        action: LendingCommands,
    },

    /// Insurance (CDS): deploy-offer, cancel-offer, replace-offer, claim, release,
    /// mutual-cancel, timeout.
    ///
    /// On-chain credit default swap for lending positions.
    Insurance {
        #[command(subcommand)]
        action: insurance::InsuranceCommand,
    },

    /// Cross-token swap: deploy, cancel, info.
    ///
    /// Lock source tokens and specify a target token + minimum receive amount.
    /// A matcher routes through KAS-denominated order books to deliver target
    /// tokens in a single atomic TX.
    Swap {
        #[command(subcommand)]
        action: swap::SwapCommand,
    },
}

/// Subcommands for `deploy`.
#[derive(Subcommand, Debug)]
pub enum DeployCommands {
    /// Deploy a buy order (lock KAS, request tokens).
    Buy {
        /// Token covenant ID (hex, 64 chars) or alias (e.g., "KUSD").
        #[arg(long)]
        token: String,

        /// Price as decimal (e.g., 0.05). Converted to price_num/price_den internally.
        /// Mutually exclusive with --price-num/--price-den.
        #[arg(long, conflicts_with_all = ["price_num", "price_den"])]
        price: Option<String>,

        /// Price numerator (tokens per KAS). Auto-set if --market.
        #[arg(long)]
        price_num: Option<u64>,

        /// Price denominator (tokens per KAS). Auto-set if --market.
        #[arg(long)]
        price_den: Option<u64>,

        /// Minimum fill amount in sompi. Auto-calculated from storage mass
        /// constraints if omitted.
        #[arg(long)]
        min_fill: Option<u64>,

        /// Amount of KAS to lock (in sompi). Values below 100,000 sompi (0.001 KAS)
        /// are rejected as likely mistakes. Use --amount-kas for KAS denomination.
        /// Mutually exclusive with --amount-kas.
        #[arg(long, required_unless_present = "amount_kas")]
        amount: Option<u64>,

        /// Amount of KAS as decimal (e.g., "5" = 5 KAS = 500_000_000 sompi).
        /// Preferred over --amount for human-friendly input.
        /// Mutually exclusive with --amount.
        #[arg(long, conflicts_with = "amount")]
        amount_kas: Option<String>,

        /// Contract version. Only v17 (N:M sweep) may be deployed for new
        /// orders; v14 (no matcher-fee cap) and v16 (1:1-only F6 cap) are
        /// rejected here and retained solely for managing pre-existing
        /// on-chain orders via cancel/cancel-all/requote --old-version.
        /// v17 uses --mmfee-bps (BPS) instead of --max-matcher-fee
        /// (see NM_BUY_DESIGN.md / V16_STATUS.md).
        #[arg(long, default_value = "17")]
        version: u8,

        /// Time-in-force: GTC (default), IOC, or FOK.
        #[arg(long, default_value = "GTC")]
        time_in_force: String,

        /// Deploy as a market order. First tries trustless price discovery
        /// by scanning recent blocks for fill TXs. Falls back to --matcher-url
        /// only if explicitly provided and no on-chain data found.
        #[arg(long)]
        market: bool,

        /// Slippage tolerance in basis points for market orders (default: 100 = 1%).
        #[arg(long, default_value = "100")]
        slippage_bps: u64,

        /// Matcher API URL for market order fallback (no default -- must opt in).
        /// Only used if no on-chain fill data is available.
        #[arg(long)]
        matcher_url: Option<String>,

        /// GTD expiry: DAA score after which the order is considered expired.
        /// For v14, this is enforced on-chain via CLTV (0 = GTC, no expiry).
        /// For older versions, matchers enforce expiry off-chain.
        #[arg(long)]
        expiry: Option<u64>,

        /// Post-only: the order will only rest on the book as a maker.
        /// If it would cross the spread (immediately match as a taker),
        /// the Matcher rejects it. Uses KOB:2: payload format.
        #[arg(long)]
        post_only: bool,

        /// Maximum fee (in sompi) the matcher may extract per fill (v14).
        /// The on-chain F6 check enforces `kas_in - out[0].value <= mmfee`.
        /// mmfee=0 makes partial fills impossible. Default: 10_000_000 (0.1 KAS).
        /// Ignored when --mmfee-bps is set (v17).
        #[arg(long, default_value = "10000000")]
        max_matcher_fee: u64,

        /// Maximum matcher fee in basis points (v17 contract).
        /// Sets --version to 17 automatically (no-op given the v17 default).
        /// E.g., 30 = 0.30% of trade value. Range: 0..=10000.
        /// When set, --max-matcher-fee is ignored.
        #[arg(long)]
        mmfee_bps: Option<u64>,
    },

    /// Deploy a sell order (lock tokens, request KAS).
    Sell {
        /// Token covenant ID (hex, 64 chars) or alias (e.g., "KUSD"). Used for CovenantBinding on deploy TX.
        #[arg(long)]
        token: Option<String>,

        /// Price as decimal (e.g., 0.05). Converted to price_num/price_den internally.
        /// Mutually exclusive with --price-num/--price-den.
        #[arg(long, conflicts_with_all = ["price_num", "price_den"])]
        price: Option<String>,

        /// Price numerator (tokens per KAS). Auto-set if --market.
        #[arg(long)]
        price_num: Option<u64>,

        /// Price denominator (tokens per KAS). Auto-set if --market.
        #[arg(long)]
        price_den: Option<u64>,

        /// Minimum fill amount in sompi. Auto-calculated from storage mass
        /// constraints if omitted.
        #[arg(long)]
        min_fill: Option<u64>,

        /// Amount of tokens to lock (in sompi value). Values below 100,000 sompi
        /// (0.001 KAS) are rejected as likely mistakes. Use --amount-kas for KAS denomination.
        /// Mutually exclusive with --amount-kas.
        #[arg(long, required_unless_present = "amount_kas")]
        amount: Option<u64>,

        /// Amount as decimal KAS (e.g., "5" = 500_000_000 sompi).
        /// Preferred over --amount for human-friendly input.
        /// Mutually exclusive with --amount.
        #[arg(long, conflicts_with = "amount")]
        amount_kas: Option<String>,

        /// Contract version (only 14 is supported).
        #[arg(long, default_value = "14")]
        version: u8,

        /// Time-in-force: GTC (default), IOC, or FOK.
        #[arg(long, default_value = "GTC")]
        time_in_force: String,

        /// Deploy as a market order. First tries trustless price discovery
        /// by scanning recent blocks for fill TXs. Falls back to --matcher-url
        /// only if explicitly provided and no on-chain data found.
        #[arg(long)]
        market: bool,

        /// Slippage tolerance in basis points for market orders (default: 100 = 1%).
        #[arg(long, default_value = "100")]
        slippage_bps: u64,

        /// Matcher API URL for market order fallback (no default -- must opt in).
        /// Only used if no on-chain fill data is available.
        #[arg(long)]
        matcher_url: Option<String>,

        /// GTD expiry: DAA score after which the order is considered expired.
        /// For v14, this is enforced on-chain via CLTV (0 = GTC, no expiry).
        #[arg(long)]
        expiry: Option<u64>,

        /// Post-only: the order will only rest on the book as a maker.
        /// If it would cross the spread (immediately match as a taker),
        /// the Matcher rejects it. Uses KOB:2: payload format.
        #[arg(long)]
        post_only: bool,

        /// Token UTXO outpoint (txid:index) to authorize covenant binding.
        /// Required for sell orders with --token. The token UTXO must carry
        /// the same covenant_id as --token for covenant lineage.
        #[arg(long)]
        token_utxo: Option<String>,

        /// Fee UTXO outpoint (txid:index) to use instead of auto-selection.
        /// Useful when auto-selected UTXOs are stale (stuck in mempool).
        #[arg(long)]
        fee_utxo: Option<String>,

        /// Maximum fee (in sompi) the matcher may extract per fill.
        /// The on-chain F6 check enforces `kas_in - out[0].value <= mmfee`.
        /// mmfee=0 makes partial fills impossible. Default: 10_000_000 (0.1 KAS).
        #[arg(long, default_value = "10000000")]
        max_matcher_fee: u64,
    },

    /// Deploy a bracket order (OTOCO: entry + take-profit + stop-loss).
    Bracket {
        /// Token covenant ID (hex, 64 chars).
        #[arg(long)]
        token: String,

        /// Entry side: buy or sell.
        #[arg(long)]
        side: String,

        /// Entry price numerator.
        #[arg(long)]
        entry_num: u64,

        /// Entry price denominator.
        #[arg(long)]
        entry_den: u64,

        /// Take-profit price numerator.
        #[arg(long)]
        tp_num: u64,

        /// Take-profit price denominator.
        #[arg(long)]
        tp_den: u64,

        /// Stop-loss price numerator.
        #[arg(long)]
        sl_num: u64,

        /// Stop-loss price denominator.
        #[arg(long)]
        sl_den: u64,

        /// Amount to lock (in sompi).
        #[arg(long)]
        amount: u64,

        /// Receipt covenant ID (hex, 64 chars). Used for N4 security check.
        /// If omitted, defaults to the token covenant ID (suitable for testing).
        #[arg(long)]
        receipt_cov_id: Option<String>,
    },

    /// Deploy an IFD order (If Done: buy entry, auto-deploy sell exit on fill).
    ///
    /// Payload-based: both order RSs are embedded in the deploy TX.
    /// No Matcher API needed. Fully trustless.
    Ifd {
        /// Token covenant ID (hex, 64 chars).
        #[arg(long)]
        token: String,

        /// Buy (entry) price numerator.
        #[arg(long)]
        buy_price_num: u64,

        /// Buy (entry) price denominator.
        #[arg(long)]
        buy_price_den: u64,

        /// Buy amount in sompi.
        #[arg(long)]
        buy_amount: u64,

        /// Buy minimum fill.
        #[arg(long)]
        buy_min_fill: u64,

        /// Sell (exit) price numerator.
        #[arg(long)]
        sell_price_num: u64,

        /// Sell (exit) price denominator.
        #[arg(long)]
        sell_price_den: u64,

        /// Sell minimum fill.
        #[arg(long)]
        sell_min_fill: u64,

        /// Sell order expiry DAA score (0 = GTC).
        #[arg(long, default_value = "0")]
        sell_expiry: u64,

        /// Matcher API URL (unused, kept for backwards compatibility).
        #[arg(long)]
        matcher_url: Option<String>,
    },

    /// Deploy an IFO order (If Done + OCO: buy entry, auto-deploy TP+SL on fill).
    ///
    /// Like IFD but the exit order is an OCO pair (take-profit + stop-loss).
    Ifo {
        /// Token covenant ID (hex, 64 chars).
        #[arg(long)]
        token: String,

        /// Buy (entry) price numerator.
        #[arg(long)]
        buy_price_num: u64,

        /// Buy (entry) price denominator.
        #[arg(long)]
        buy_price_den: u64,

        /// Buy amount in sompi.
        #[arg(long)]
        buy_amount: u64,

        /// Buy minimum fill.
        #[arg(long)]
        buy_min_fill: u64,

        /// Take-profit price numerator.
        #[arg(long)]
        tp_price_num: u64,

        /// Take-profit price denominator.
        #[arg(long)]
        tp_price_den: u64,

        /// Take-profit minimum fill.
        #[arg(long)]
        tp_min_fill: u64,

        /// Stop-loss price numerator.
        #[arg(long)]
        sl_price_num: u64,

        /// Stop-loss price denominator.
        #[arg(long)]
        sl_price_den: u64,

        /// Stop-loss minimum fill.
        #[arg(long)]
        sl_min_fill: u64,

        /// Matcher API URL.
        #[arg(long)]
        matcher_url: String,
    },

    /// Deploy a trustless IFO (bracket) order via IFD payload.
    ///
    /// Buy entry + OCO sell (TP+SL) exit, all embedded in the deploy TX
    /// payload. No Matcher API needed. When the buy fills, the OCO sell
    /// is auto-deployed as an extra output. Scanner detects 333B OCO sell
    /// RS and inserts TP/SL virtual orders into the order book.
    IfoTrustless {
        /// Token covenant ID (hex, 64 chars).
        #[arg(long)]
        token: String,

        /// Buy (entry) price numerator.
        #[arg(long)]
        buy_price_num: u64,

        /// Buy (entry) price denominator.
        #[arg(long)]
        buy_price_den: u64,

        /// Buy amount in sompi.
        #[arg(long)]
        buy_amount: u64,

        /// Buy minimum fill.
        #[arg(long)]
        buy_min_fill: u64,

        /// Take-profit price numerator.
        #[arg(long)]
        tp_price_num: u64,

        /// Take-profit price denominator.
        #[arg(long)]
        tp_price_den: u64,

        /// Take-profit minimum fill.
        #[arg(long)]
        tp_min_fill: u64,

        /// Stop-loss price numerator.
        #[arg(long)]
        sl_price_num: u64,

        /// Stop-loss price denominator.
        #[arg(long)]
        sl_price_den: u64,

        /// Stop-loss minimum fill.
        #[arg(long)]
        sl_min_fill: u64,

        /// GTD expiry: DAA score after which exit orders expire (0 = GTC).
        #[arg(long, default_value = "0")]
        expiry: u64,

        /// Maximum fee (in sompi) the matcher may extract per fill.
        #[arg(long, default_value = "10000000")]
        max_matcher_fee: u64,
    },

    /// Deploy a single-UTXO OCO sell order (take-profit + stop-loss in one UTXO).
    ///
    /// One P2SH UTXO encodes both TP and SL sell orders. The UTXO model
    /// provides natural OCO behavior: filling either path spends the UTXO,
    /// canceling the other. 333B redeem script, FOK-only v1.
    OcoSell {
        /// Token covenant ID (hex, 64 chars) or alias.
        #[arg(long)]
        token: String,

        /// Take-profit price numerator.
        #[arg(long)]
        tp_price_num: u64,

        /// Take-profit price denominator.
        #[arg(long)]
        tp_price_den: u64,

        /// Take-profit minimum fill (sompi).
        #[arg(long)]
        tp_min_fill: u64,

        /// Stop-loss price numerator.
        #[arg(long)]
        sl_price_num: u64,

        /// Stop-loss price denominator.
        #[arg(long)]
        sl_price_den: u64,

        /// Stop-loss minimum fill (sompi).
        #[arg(long)]
        sl_min_fill: u64,

        /// Amount of tokens to lock (in sompi value).
        #[arg(long)]
        amount: u64,

        /// GTD expiry: DAA score after which the order expires (0 = GTC).
        #[arg(long, default_value = "0")]
        expiry: u64,

        /// Maximum fee (in sompi) the matcher may extract per fill.
        #[arg(long, default_value = "10000000")]
        max_matcher_fee: u64,

        /// Token UTXO outpoint (txid:index) for covenant binding.
        #[arg(long)]
        token_utxo: Option<String>,

        /// Fee UTXO outpoint (txid:index) override.
        #[arg(long)]
        fee_utxo: Option<String>,
    },
}

/// Subcommands for `lending`.
#[derive(Subcommand, Debug)]
pub enum LendingCommands {
    /// Deploy a loan offer (lender locks principal KAS with rate/collateral terms).
    Offer {
        /// Principal amount to lend (sompi).
        #[arg(long)]
        amount: u64,

        /// Annual rate numerator (e.g., 500 for 5.00%).
        #[arg(long)]
        rate_num: u64,

        /// Annual rate denominator (e.g., 10000).
        #[arg(long)]
        rate_den: u64,

        /// Maximum loan duration in DAA units.
        #[arg(long)]
        duration_daa: u64,

        /// Minimum collateral ratio (e.g., 15000 for 150.00%).
        #[arg(long)]
        min_collateral_ratio: u64,

        /// Accepted collateral token covenant ID (hex, 64 chars). All zeros = KAS.
        #[arg(long)]
        token: String,

        /// Rate mode: 0 = fixed only, 1 = variable ok.
        #[arg(long, default_value = "0")]
        rate_mode: u64,

        /// Variable rate floor numerator (lender protection). 0 for fixed.
        #[arg(long, default_value = "0")]
        rate_floor_num: u64,
    },

    /// Deploy a borrow request (borrower locks collateral).
    Request {
        /// Collateral amount to lock (sompi).
        #[arg(long)]
        collateral: u64,

        /// Maximum acceptable annual rate numerator.
        #[arg(long)]
        max_rate_num: u64,

        /// Maximum acceptable annual rate denominator.
        #[arg(long)]
        max_rate_den: u64,

        /// Desired principal amount (sompi).
        #[arg(long)]
        amount_requested: u64,

        /// Desired loan duration in DAA units.
        #[arg(long)]
        duration_daa: u64,

        /// Collateral token covenant ID (hex, 64 chars). All zeros = KAS.
        #[arg(long)]
        token: String,

        /// Rate mode: 0 = fixed, 1 = variable, 2 = either.
        #[arg(long, default_value = "0")]
        rate_mode: u64,

        /// Variable rate cap numerator (borrower protection). 0 for fixed.
        #[arg(long, default_value = "0")]
        rate_cap_num: u64,
    },

    /// Cancel an unmatched loan offer or borrow request.
    Cancel {
        /// Outpoint of the lending UTXO to cancel (txid:index).
        #[arg(long)]
        outpoint: String,

        /// Side: "offer" or "request".
        #[arg(long)]
        side: String,

        /// Token covenant ID (hex, 64 chars).
        #[arg(long)]
        token: String,

        /// (Offer) Principal amount.
        #[arg(long, default_value = "0")]
        principal: u64,

        /// (Offer) Rate numerator.
        #[arg(long, default_value = "0")]
        rate_num: u64,

        /// (Offer) Rate denominator.
        #[arg(long, default_value = "1")]
        rate_den: u64,

        /// (Offer) Min collateral ratio.
        #[arg(long, default_value = "0")]
        min_collateral_ratio: u64,

        /// (Offer) Max duration DAA.
        #[arg(long, default_value = "0")]
        max_duration_daa: u64,

        /// (Offer) Rate mode.
        #[arg(long, default_value = "0")]
        rate_mode: u64,

        /// (Offer) Rate floor numerator.
        #[arg(long, default_value = "0")]
        rate_floor_num: u64,

        /// (Request) Desired amount.
        #[arg(long, default_value = "0")]
        desired_amount: u64,

        /// (Request) Max rate numerator.
        #[arg(long, default_value = "0")]
        max_rate_num: u64,

        /// (Request) Max rate denominator.
        #[arg(long, default_value = "1")]
        max_rate_den: u64,

        /// (Request) Min duration DAA.
        #[arg(long, default_value = "0")]
        min_duration_daa: u64,

        /// (Request) Rate mode.
        #[arg(long, default_value = "0")]
        req_rate_mode: u64,

        /// (Request) Rate cap numerator.
        #[arg(long, default_value = "0")]
        rate_cap_num: u64,

        /// UTXO value override (sompi). Queried from chain if omitted.
        #[arg(long)]
        order_value: Option<u64>,

        /// Fee UTXO outpoint override (txid:index).
        #[arg(long)]
        fee_utxo: Option<String>,
    },

    /// Repay an active loan (borrower).
    Repay {
        /// Active loan outpoint (txid:index).
        #[arg(long)]
        loan_outpoint: String,

        /// Insurer SPK hash (hex, 64 chars).
        #[arg(long)]
        insurer_spk_hash: String,

        /// Lender SPK hash (hex, 64 chars).
        #[arg(long)]
        lender_spk_hash: String,

        /// Loan principal (sompi).
        #[arg(long)]
        principal: u64,

        /// Rate numerator.
        #[arg(long)]
        rate_num: u64,

        /// Rate denominator.
        #[arg(long)]
        rate_den: u64,

        /// Loan start DAA score.
        #[arg(long)]
        start_daa: u64,

        /// Loan expiry DAA score.
        #[arg(long)]
        expiry_daa: u64,

        /// Collateral token covenant ID (hex, 64 chars).
        #[arg(long)]
        collateral_token: String,

        /// Rate mode: 0 = fixed, 1 = variable.
        #[arg(long, default_value = "0")]
        rate_mode: u64,

        /// Rate floor numerator.
        #[arg(long, default_value = "0")]
        rate_floor_num: u64,

        /// Rate cap numerator.
        #[arg(long, default_value = "0")]
        rate_cap_num: u64,

        /// Grace period DAA.
        #[arg(long)]
        grace_daa: u64,

        /// Liquidation threshold (e.g. 15000 = 150%).
        #[arg(long)]
        liq_threshold: u64,

        /// Lender destination SPK (hex). Where principal+interest goes.
        #[arg(long)]
        lender_spk: String,

        /// Collateral value override (sompi). Queried from chain if omitted.
        #[arg(long)]
        collateral: Option<u64>,
    },

    /// Claim collateral from a defaulted loan (lender only).
    ///
    /// After expiry_daa + grace_daa has passed without repayment,
    /// the lender can claim the borrower's locked collateral.
    ClaimDefault {
        /// Active loan outpoint (txid:index).
        #[arg(long)]
        loan_outpoint: String,

        /// Insurer SPK hash (hex, 64 chars).
        #[arg(long)]
        insurer_spk_hash: String,

        /// Lender SPK hash (hex, 64 chars).
        #[arg(long)]
        lender_spk_hash: String,

        /// Borrower SPK hash (hex, 64 chars).
        #[arg(long)]
        borrower_spk_hash: String,

        /// Loan principal (sompi).
        #[arg(long)]
        principal: u64,

        /// Rate numerator.
        #[arg(long)]
        rate_num: u64,

        /// Rate denominator.
        #[arg(long)]
        rate_den: u64,

        /// Loan start DAA score.
        #[arg(long)]
        start_daa: u64,

        /// Loan expiry DAA score.
        #[arg(long)]
        expiry_daa: u64,

        /// Collateral token covenant ID (hex, 64 chars).
        #[arg(long)]
        collateral_token: String,

        /// Rate mode: 0 = fixed, 1 = variable.
        #[arg(long, default_value = "0")]
        rate_mode: u64,

        /// Rate floor numerator.
        #[arg(long, default_value = "0")]
        rate_floor_num: u64,

        /// Rate cap numerator.
        #[arg(long, default_value = "0")]
        rate_cap_num: u64,

        /// Grace period DAA.
        #[arg(long)]
        grace_daa: u64,

        /// Liquidation threshold (e.g. 15000 = 150%).
        #[arg(long)]
        liq_threshold: u64,

        /// Collateral value override (sompi). Queried from chain if omitted.
        #[arg(long)]
        collateral: Option<u64>,
    },

    /// Liquidate an undercollateralized active loan (permissionless).
    ///
    /// Anyone can trigger liquidation when the collateral ratio drops
    /// below liq_threshold. Requires a price oracle input.
    Liquidate {
        /// Active loan outpoint (txid:index).
        #[arg(long)]
        loan_outpoint: String,

        /// Insurer SPK hash (hex, 64 chars).
        #[arg(long)]
        insurer_spk_hash: String,

        /// Lender SPK hash (hex, 64 chars).
        #[arg(long)]
        lender_spk_hash: String,

        /// Borrower SPK hash (hex, 64 chars).
        #[arg(long)]
        borrower_spk_hash: String,

        /// Loan principal (sompi).
        #[arg(long)]
        principal: u64,

        /// Rate numerator.
        #[arg(long)]
        rate_num: u64,

        /// Rate denominator.
        #[arg(long)]
        rate_den: u64,

        /// Loan start DAA score.
        #[arg(long)]
        start_daa: u64,

        /// Loan expiry DAA score.
        #[arg(long)]
        expiry_daa: u64,

        /// Collateral token covenant ID (hex, 64 chars).
        #[arg(long)]
        collateral_token: String,

        /// Rate mode: 0 = fixed, 1 = variable.
        #[arg(long, default_value = "0")]
        rate_mode: u64,

        /// Rate floor numerator.
        #[arg(long, default_value = "0")]
        rate_floor_num: u64,

        /// Rate cap numerator.
        #[arg(long, default_value = "0")]
        rate_cap_num: u64,

        /// Grace period DAA.
        #[arg(long)]
        grace_daa: u64,

        /// Liquidation threshold (e.g. 15000 = 150%).
        #[arg(long)]
        liq_threshold: u64,

        /// Lender destination SPK (hex). Where outstanding debt goes.
        #[arg(long)]
        lender_spk: String,

        /// Borrower destination SPK (hex). Where remaining collateral goes.
        #[arg(long)]
        borrower_spk: String,

        /// Price oracle input outpoint (txid:index).
        #[arg(long)]
        price_outpoint: String,

        /// Liquidator bonus (sompi) — paid from collateral surplus.
        #[arg(long, default_value = "0")]
        liquidator_bonus: u64,

        /// Collateral value override (sompi). Queried from chain if omitted.
        #[arg(long)]
        collateral: Option<u64>,
    },

    /// List active loans (query engine REST API).
    Loans {
        /// Engine REST API URL (e.g., http://localhost:8080).
        #[arg(long)]
        engine_url: Option<String>,
    },
}

/// Dispatch a parsed command to the appropriate handler.
///
/// Parameters:
/// - `node`: Kaspa node WebSocket URL
/// - `wallet_path`: path to wallet.json
/// - `network`: parsed network enum
/// - `fee`: fee rate in sompi
/// - `command`: the parsed CLI subcommand
pub async fn dispatch(
    node: &str,
    wallet_path: &std::path::Path,
    network: kob_core::types::Network,
    fee: u64,
    command: Commands,
) -> anyhow::Result<()> {
    match command {
        Commands::Wallet { action } => {
            if let Some(cmd) = action {
                wallet::run_command(wallet_path, node, network, &cmd).await?;
            } else {
                wallet::run(wallet_path, node, network).await?;
            }
        }
        Commands::Balance { account, count } => {
            let cmd = wallet::WalletCommand::Balance { account, count };
            wallet::run_command(wallet_path, node, network, &cmd).await?;
        }
        Commands::Deploy { order_type } => match order_type {
            DeployCommands::Buy {
                token,
                price,
                price_num,
                price_den,
                min_fill,
                amount,
                amount_kas,
                version,
                time_in_force,
                market,
                slippage_bps,
                matcher_url,
                expiry,
                post_only,
                max_matcher_fee,
                mmfee_bps,
            } => {
                // v17 (N:M sweep) is the sole deploy target; --mmfee-bps bumps
                // an explicit --version 14 up to 17 for convenience.
                // deploy_buy rejects any non-v17 version for new orders (v14
                // has no on-chain F6 cap; v16 cannot settle an N:M sweep).
                let version = if mmfee_bps.is_some() && version == 14 { 17 } else { version };

                // Resolve token alias
                let token = token::resolve_token(&token, None)?;

                // Resolve amount: --amount-kas takes priority via conflicts_with
                let amount = if let Some(ref kas_str) = amount_kas {
                    deploy::parse_kas_amount(kas_str)?
                } else {
                    let raw = amount.ok_or_else(|| anyhow::anyhow!("Either --amount or --amount-kas is required"))?;
                    deploy::validate_amount_not_dust(raw, "--amount")?
                };

                // Resolve price: --price takes priority via conflicts_with.
                // Neither --price nor --price-num/--price-den have defaults;
                // the user must supply a price explicitly (or use --market).
                let (price_num, price_den) = if let Some(ref p) = price {
                    deploy::parse_decimal_price(p)?
                } else {
                    match (price_num, price_den) {
                        (Some(n), Some(d)) => (n, d),
                        (Some(_), None) | (None, Some(_)) => {
                            anyhow::bail!("Both --price-num and --price-den are required when specifying price as a fraction");
                        }
                        (None, None) => {
                            if !market {
                                anyhow::bail!(
                                    "Price is required. Use --price <decimal> (e.g. --price 0.05), \
                                     --price-num/--price-den, or --market"
                                );
                            }
                            // Placeholder; will be overwritten by market price below
                            (0, 1)
                        }
                    }
                };

                let mut tif_policy: tif::TimeInForce = time_in_force.parse()
                    .map_err(|e: String| anyhow::anyhow!("{}", e))?;
                let (final_num, final_den) = if market {
                    let (pn, pd) = market::resolve_market_price_smart(
                        node,
                        &token,
                        "buy",
                        amount,
                        slippage_bps,
                        matcher_url.as_deref(),
                    ).await?;
                    // Auto-set IOC for market orders so unfilled remainder is cancelled
                    if tif_policy == tif::TimeInForce::Gtc {
                        tif_policy = tif::TimeInForce::Ioc;
                        println!("  Time-in-force:         IOC (auto-set for market order)");
                    }
                    (pn, pd)
                } else {
                    if price_num == 0 {
                        anyhow::bail!("--price-num is required (or use --price/--market for pricing)");
                    }
                    (price_num, price_den)
                };
                if let Some(daa) = expiry {
                    println!("GTD order: expiry DAA score = {}", daa);
                }
                if post_only {
                    println!("Post-only order: will be rejected if it would cross the spread.");
                }
                if let Some(bps) = mmfee_bps {
                    if bps > 10000 {
                        anyhow::bail!("--mmfee-bps must be 0..=10000 (basis points). Got {}.", bps);
                    }
                    println!("V{} buy order: mmfee_bps = {} ({}%)", version, bps, bps as f64 / 100.0);
                }
                let min_fill = min_fill.unwrap_or_else(kob_core::minimum_sell_min_fill);
                let deploy_txid = deploy::deploy_buy(
                    wallet_path,
                    node,
                    network,
                    &token,
                    final_num,
                    final_den,
                    min_fill,
                    amount,
                    version,
                    fee,
                    post_only,
                    expiry,
                    max_matcher_fee,
                    mmfee_bps,
                )
                .await?;
                if tif_policy != tif::TimeInForce::Gtc {
                    let result = tif::tif_execute(
                        tif_policy,
                        &deploy_txid,
                        "buy",
                        &token,
                        final_num,
                        final_den,
                        min_fill,
                        amount,
                        wallet_path,
                        node,
                        network,
                        fee,
                        version,
                        expiry.unwrap_or(0),
                    ).await?;
                    result.print_summary();
                }
            }
            DeployCommands::Sell {
                token,
                price,
                price_num,
                price_den,
                min_fill,
                amount,
                amount_kas,
                version,
                time_in_force,
                market,
                slippage_bps,
                matcher_url,
                expiry,
                post_only,
                token_utxo,
                fee_utxo,
                max_matcher_fee,
            } => {
                // Resolve token alias
                let token = if let Some(t) = token {
                    Some(token::resolve_token(&t, None)?)
                } else {
                    None
                };

                // Resolve amount: --amount-kas takes priority via conflicts_with
                let amount = if let Some(ref kas_str) = amount_kas {
                    deploy::parse_kas_amount(kas_str)?
                } else {
                    let raw = amount.ok_or_else(|| anyhow::anyhow!("Either --amount or --amount-kas is required"))?;
                    deploy::validate_amount_not_dust(raw, "--amount")?
                };

                // Resolve price: --price takes priority via conflicts_with.
                // Neither --price nor --price-num/--price-den have defaults;
                // the user must supply a price explicitly (or use --market).
                let (price_num, price_den) = if let Some(ref p) = price {
                    deploy::parse_decimal_price(p)?
                } else {
                    match (price_num, price_den) {
                        (Some(n), Some(d)) => (n, d),
                        (Some(_), None) | (None, Some(_)) => {
                            anyhow::bail!("Both --price-num and --price-den are required when specifying price as a fraction");
                        }
                        (None, None) => {
                            if !market {
                                anyhow::bail!(
                                    "Price is required. Use --price <decimal> (e.g. --price 0.05), \
                                     --price-num/--price-den, or --market"
                                );
                            }
                            // Placeholder; will be overwritten by market price below
                            (0, 1)
                        }
                    }
                };

                let mut tif_policy: tif::TimeInForce = time_in_force.parse()
                    .map_err(|e: String| anyhow::anyhow!("{}", e))?;
                let (final_num, final_den) = if market {
                    let sell_token = token.as_deref().unwrap_or("");
                    if sell_token.is_empty() {
                        anyhow::bail!("--token is required for market sell orders");
                    }
                    let (pn, pd) = market::resolve_market_price_smart(
                        node,
                        sell_token,
                        "sell",
                        amount,
                        slippage_bps,
                        matcher_url.as_deref(),
                    ).await?;
                    // Auto-set IOC for market orders
                    if tif_policy == tif::TimeInForce::Gtc {
                        tif_policy = tif::TimeInForce::Ioc;
                        println!("  Time-in-force:         IOC (auto-set for market order)");
                    }
                    (pn, pd)
                } else {
                    if price_num == 0 {
                        anyhow::bail!("--price-num is required (or use --price/--market for pricing)");
                    }
                    (price_num, price_den)
                };
                if let Some(daa) = expiry {
                    println!("GTD order: expiry DAA score = {}", daa);
                }
                if post_only {
                    println!("Post-only order: will be rejected if it would cross the spread.");
                }
                if max_matcher_fee == 0 {
                    println!("WARNING: --max-matcher-fee=0 prevents partial fills (F6 constraint).");
                }
                let min_fill = min_fill.unwrap_or_else(kob_core::minimum_sell_min_fill);
                let deploy_txid = deploy::deploy_sell(
                    wallet_path,
                    node,
                    network,
                    token.as_deref(),
                    final_num,
                    final_den,
                    min_fill,
                    amount,
                    version,
                    fee,
                    post_only,
                    expiry,
                    max_matcher_fee,
                    token_utxo.as_deref(),
                    fee_utxo.as_deref(),
                )
                .await?;
                if tif_policy != tif::TimeInForce::Gtc {
                    let result = tif::tif_execute(
                        tif_policy,
                        &deploy_txid,
                        "sell",
                        token.as_deref().unwrap_or(""),
                        final_num,
                        final_den,
                        min_fill,
                        amount,
                        wallet_path,
                        node,
                        network,
                        fee,
                        version,
                        expiry.unwrap_or(0),
                    ).await?;
                    result.print_summary();
                }
            }
            DeployCommands::Bracket {
                token,
                side,
                entry_num,
                entry_den,
                tp_num,
                tp_den,
                sl_num,
                sl_den,
                amount,
                receipt_cov_id,
            } => {
                deploy::validate_amount_not_dust(amount, "--amount")?;
                let token = token::resolve_token(&token, None)?;
                let rcid = receipt_cov_id.unwrap_or_else(|| token.clone());
                bracket::run(
                    wallet_path,
                    node,
                    network,
                    &token,
                    &side,
                    entry_num,
                    entry_den,
                    tp_num,
                    tp_den,
                    sl_num,
                    sl_den,
                    amount,
                    kob_core::MIN_UTXO_VALUE, // min_receipt_value
                    &rcid,
                )
                .await?;
            }
            DeployCommands::Ifd {
                token,
                buy_price_num,
                buy_price_den,
                buy_amount,
                buy_min_fill,
                sell_price_num,
                sell_price_den,
                sell_min_fill,
                sell_expiry,
                matcher_url: _,
            } => {
                deploy::validate_amount_not_dust(buy_amount, "--buy-amount")?;
                let token = token::resolve_token(&token, None)?;
                ifd::deploy_ifd(
                    wallet_path,
                    node,
                    network,
                    &token,
                    buy_price_num,
                    buy_price_den,
                    buy_amount,
                    buy_min_fill,
                    sell_price_num,
                    sell_price_den,
                    sell_min_fill,
                    sell_expiry,
                    fee,
                )
                .await?;
            }
            DeployCommands::Ifo {
                token,
                buy_price_num,
                buy_price_den,
                buy_amount,
                buy_min_fill,
                tp_price_num,
                tp_price_den,
                tp_min_fill,
                sl_price_num,
                sl_price_den,
                sl_min_fill,
                matcher_url,
            } => {
                deploy::validate_amount_not_dust(buy_amount, "--buy-amount")?;
                let token = token::resolve_token(&token, None)?;
                ifd::deploy_ifo(
                    wallet_path,
                    node,
                    network,
                    &matcher_url,
                    &token,
                    buy_price_num,
                    buy_price_den,
                    buy_amount,
                    buy_min_fill,
                    tp_price_num,
                    tp_price_den,
                    tp_min_fill,
                    sl_price_num,
                    sl_price_den,
                    sl_min_fill,
                    fee,
                )
                .await?;
            }
            DeployCommands::IfoTrustless {
                token,
                buy_price_num,
                buy_price_den,
                buy_amount,
                buy_min_fill,
                tp_price_num,
                tp_price_den,
                tp_min_fill,
                sl_price_num,
                sl_price_den,
                sl_min_fill,
                expiry,
                max_matcher_fee,
            } => {
                deploy::validate_amount_not_dust(buy_amount, "--buy-amount")?;
                let token = token::resolve_token(&token, None)?;
                ifd::deploy_ifo_trustless(
                    wallet_path,
                    node,
                    network,
                    &token,
                    buy_price_num,
                    buy_price_den,
                    buy_amount,
                    buy_min_fill,
                    tp_price_num,
                    tp_price_den,
                    tp_min_fill,
                    sl_price_num,
                    sl_price_den,
                    sl_min_fill,
                    expiry,
                    max_matcher_fee,
                    fee,
                )
                .await?;
            }
            DeployCommands::OcoSell {
                token,
                tp_price_num,
                tp_price_den,
                tp_min_fill,
                sl_price_num,
                sl_price_den,
                sl_min_fill,
                amount,
                expiry,
                max_matcher_fee,
                token_utxo,
                fee_utxo,
            } => {
                deploy::validate_amount_not_dust(amount, "--amount")?;
                let token = token::resolve_token(&token, None)?;
                if tp_price_num == 0 || tp_price_den == 0 {
                    anyhow::bail!("TP price must be > 0");
                }
                if sl_price_num == 0 || sl_price_den == 0 {
                    anyhow::bail!("SL price must be > 0");
                }
                if tp_min_fill == 0 || sl_min_fill == 0 {
                    anyhow::bail!("min_fill must be > 0");
                }
                if amount == 0 {
                    anyhow::bail!("amount must be > 0");
                }
                let expiry_opt = if expiry == 0 { None } else { Some(expiry) };
                deploy::deploy_oco_sell(
                    wallet_path,
                    node,
                    network,
                    &token,
                    tp_price_num,
                    tp_price_den,
                    tp_min_fill,
                    sl_price_num,
                    sl_price_den,
                    sl_min_fill,
                    amount,
                    fee,
                    expiry_opt,
                    max_matcher_fee,
                    token_utxo.as_deref(),
                    fee_utxo.as_deref(),
                )
                .await?;
            }
        },
        Commands::Cancel {
            outpoint,
            side,
            token,
            price_num,
            price_den,
            min_fill,
            order_value,
            version,
            expiry,
            fee_utxo,
            cpend,
            max_matcher_fee,
        } => {
            let token = if let Some(t) = token {
                Some(token::resolve_token(&t, None)?)
            } else {
                None
            };
            cancel::run(
                wallet_path,
                node,
                network,
                &outpoint,
                side.as_deref(),
                token.as_deref(),
                price_num,
                price_den,
                min_fill,
                order_value,
                fee,
                version,
                expiry,
                fee_utxo.as_deref(),
                cpend,
                max_matcher_fee,
            )
            .await?;
        }
        Commands::CancelMark {
            outpoint,
            side,
            token,
            price_num,
            price_den,
            min_fill,
            order_value,
            version,
            expiry,
            fee_utxo,
            max_matcher_fee,
        } => {
            let token = if let Some(t) = token {
                Some(token::resolve_token(&t, None)?)
            } else {
                None
            };
            cancel_mark::run(
                wallet_path,
                node,
                network,
                &outpoint,
                &side,
                token.as_deref(),
                price_num,
                price_den,
                min_fill,
                order_value,
                fee,
                version,
                expiry,
                fee_utxo.as_deref(),
                max_matcher_fee,
            )
            .await?;
        }
        Commands::PartialFill {
            outpoint,
            side,
            token,
            price_num,
            price_den,
            min_fill,
            fill_amount,
            order_value,
            owner_hash,
            spk_hash,
            token_outpoint,
            fee_input,
            version,
            expiry,
            max_matcher_fee,
        } => {
            let token = token::resolve_token(&token, None)?;
            partial_fill::run(
                wallet_path,
                node,
                network,
                &outpoint,
                &side,
                &token,
                price_num,
                price_den,
                min_fill,
                fill_amount,
                order_value,
                owner_hash.as_deref(),
                spk_hash.as_deref(),
                token_outpoint.as_deref(),
                fee_input.as_deref(),
                version,
                fee,
                expiry,
                max_matcher_fee,
            )
            .await?;
        }
        Commands::List { token } => {
            let token = if let Some(t) = token {
                Some(token::resolve_token(&t, None)?)
            } else {
                None
            };
            list::run(wallet_path, node, network, token.as_deref()).await?;
        }
        Commands::Match {
            buy,
            sell,
            token,
            buy_price_num,
            buy_price_den,
            buy_min_fill,
            buy_value,
            buy_owner_hash,
            buy_spk_hash,
            sell_price_num,
            sell_price_den,
            sell_min_fill,
            sell_value,
            sell_owner_hash,
            sell_spk_hash,
            buyer_pubkey,
            seller_pubkey,
            fee_input,
            cross_pair,
            token_outpoint,
            buy_token,
            version,
            buy_expiry,
            sell_expiry,
            max_matcher_fee,
            mmfee_bps,
            fee_bps,
            tamper,
        } => {
            let token = token::resolve_token(&token, None)?;
            let buy_token = if let Some(bt) = buy_token {
                Some(token::resolve_token(&bt, None)?)
            } else {
                None
            };
            let tamper_mode = if let Some(ref t) = tamper {
                Some(matching::TamperMode::parse(t).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Unknown --tamper mode '{}'. Valid: f2-redirect-seller, f2-redirect-buyer, f4-remove-binding, f4-reduce-value",
                        t
                    )
                })?)
            } else {
                None
            };
            if cross_pair {
                if tamper_mode.is_some() {
                    anyhow::bail!("--tamper is not supported with --cross-pair");
                }
                matching::run_cross_pair(
                    wallet_path,
                    node,
                    network,
                    &buy,
                    &sell,
                    &token,
                    buy_token.as_deref(),
                    buy_price_num,
                    buy_price_den,
                    buy_min_fill,
                    buy_value,
                    buy_owner_hash.as_deref(),
                    buy_spk_hash.as_deref(),
                    sell_price_num,
                    sell_price_den,
                    sell_min_fill,
                    sell_value,
                    sell_owner_hash.as_deref(),
                    sell_spk_hash.as_deref(),
                    &buyer_pubkey,
                    &seller_pubkey,
                    token_outpoint.as_deref()
                        .ok_or_else(|| anyhow::anyhow!("--token-outpoint is required for --cross-pair"))?,
                    fee_input.as_deref(),
                    version,
                    fee,
                    buy_expiry,
                    sell_expiry,
                )
                .await?;
            } else {
                matching::run(
                    wallet_path,
                    node,
                    network,
                    &buy,
                    &sell,
                    &token,
                    buy_price_num,
                    buy_price_den,
                    buy_min_fill,
                    buy_value,
                    buy_owner_hash.as_deref(),
                    buy_spk_hash.as_deref(),
                    sell_price_num,
                    sell_price_den,
                    sell_min_fill,
                    sell_value,
                    sell_owner_hash.as_deref(),
                    sell_spk_hash.as_deref(),
                    &buyer_pubkey,
                    &seller_pubkey,
                    fee_input.as_deref(),
                    version,
                    fee,
                    buy_expiry,
                    sell_expiry,
                    max_matcher_fee,
                    mmfee_bps,
                    fee_bps,
                    tamper_mode,
                )
                .await?;
            }
        }
        Commands::MatchBatch {
            sell_outpoints,
            buy_outpoints,
            token,
            max_matcher_fee,
            fee_bps,
            ioc,
        } => {
            let token = token::resolve_token(&token, None)?;
            match_batch::run(
                wallet_path,
                node,
                network,
                &sell_outpoints,
                &buy_outpoints,
                &token,
                max_matcher_fee,
                fee_bps,
                ioc,
            )
            .await?;
        }
        Commands::Receipt { action } => match action {
            receipt::ReceiptCommand::Create {
                pair_id,
                price_num,
                price_den,
                exec_amount,
                min_receipt_value,
                recipient_hash,
                amount,
            } => {
                receipt::receipt_create(
                    wallet_path,
                    node,
                    network,
                    &pair_id,
                    price_num,
                    price_den,
                    exec_amount,
                    min_receipt_value,
                    recipient_hash.as_deref(),
                    amount,
                )
                .await?;
            }
            receipt::ReceiptCommand::Consume {
                outpoint,
                pair_id,
                price_num,
                price_den,
                exec_amount,
                min_receipt_value,
                recipient_hash,
                receipt_value,
                fee_input,
            } => {
                receipt::receipt_consume(
                    wallet_path,
                    node,
                    network,
                    &outpoint,
                    &pair_id,
                    price_num,
                    price_den,
                    exec_amount,
                    min_receipt_value,
                    recipient_hash.as_deref(),
                    receipt_value,
                    fee_input.as_deref(),
                )
                .await?;
            }
            receipt::ReceiptCommand::Trigger {
                outpoint,
                pair_id,
                price_num,
                price_den,
                exec_amount,
                min_receipt_value,
                recipient_hash,
                receipt_value,
                fee_input,
            } => {
                receipt::receipt_trigger(
                    wallet_path,
                    node,
                    network,
                    &outpoint,
                    &pair_id,
                    price_num,
                    price_den,
                    exec_amount,
                    min_receipt_value,
                    recipient_hash.as_deref(),
                    receipt_value,
                    fee_input.as_deref(),
                )
                .await?;
            }
            receipt::ReceiptCommand::ConsumeV1 {
                outpoint,
                pair_id,
                price_num,
                price_den,
                exec_amount,
                receipt_value,
                fee_input,
            } => {
                receipt::receipt_consume_v1(
                    wallet_path,
                    node,
                    network,
                    &outpoint,
                    &pair_id,
                    price_num,
                    price_den,
                    exec_amount,
                    receipt_value,
                    fee_input.as_deref(),
                )
                .await?;
            }
        },
        Commands::Config => {
            cmd_config(wallet_path, node, network);
        }
        Commands::Status => {
            status::run(wallet_path, node, network).await?;
        }
        Commands::Scan { address, cov_type } => {
            scan::run(
                wallet_path,
                node,
                network,
                address.as_deref(),
                cov_type.as_deref(),
            )
            .await?;
        }
        Commands::Token { action } => match action {
            token::TokenCommand::Create {
                ticker,
                supply,
                decimals,
                amount,
            } => {
                token::token_create(
                    wallet_path,
                    node,
                    network,
                    &ticker,
                    supply,
                    decimals,
                    amount,
                )
                .await?;
            }
            token::TokenCommand::Mint {
                txid,
                index,
                token: token_cov_id,
                amount,
                recipient_pubkey,
                fee_utxo,
            } => {
                let token_cov_id = token::resolve_token(&token_cov_id, None)?;
                token::token_mint(
                    wallet_path,
                    node,
                    network,
                    &txid,
                    index,
                    &token_cov_id,
                    amount,
                    recipient_pubkey.as_deref(),
                    fee_utxo.as_deref(),
                )
                .await?;
            }
            token::TokenCommand::Transfer {
                txid,
                index,
                to,
                amount,
                token: token_cov_id,
            } => {
                let token_cov_id = token::resolve_token(&token_cov_id, None)?;
                token::token_transfer(
                    wallet_path,
                    node,
                    network,
                    &txid,
                    index,
                    &to,
                    amount,
                    &token_cov_id,
                )
                .await?;
            }
            token::TokenCommand::Burn {
                txid,
                index,
                token: token_cov_id,
            } => {
                let token_cov_id = token::resolve_token(&token_cov_id, None)?;
                token::token_burn(
                    wallet_path,
                    node,
                    network,
                    &txid,
                    index,
                    &token_cov_id,
                )
                .await?;
            }
            token::TokenCommand::Info {
                token: token_cov_id,
                json,
            } => {
                let token_cov_id = token::resolve_token(&token_cov_id, None)?;
                token::token_info(
                    wallet_path,
                    node,
                    network,
                    &token_cov_id,
                    json,
                )
                .await?;
            }
            token::TokenCommand::Balance {
                tokens_file,
            } => {
                token::run(
                    wallet_path,
                    node,
                    network,
                    tokens_file.as_deref(),
                )
                .await?;
            }
            token::TokenCommand::Alias {
                name,
                covenant_id,
                alias_file,
            } => {
                let path_str = alias_file.as_deref().unwrap_or("tokens.json");
                let path = std::path::Path::new(path_str);
                token::register_alias(path, &name, &covenant_id)?;
            }
            token::TokenCommand::Aliases { alias_file, json } => {
                let path = alias_file.as_deref().map(std::path::Path::new);
                token::list_aliases(path, json)?;
            }
        },
        Commands::AutoMatch {
            pair_id,
            interval,
            dry_run,
            min_spread,
            max_matches,
            cross_pair,
        } => {
            auto_match::run(
                wallet_path,
                node,
                network,
                &pair_id,
                interval,
                dry_run,
                min_spread,
                max_matches,
                cross_pair,
            )
            .await?;
        }
        Commands::Bracket { action } => match action {
            bracket::BracketCommand::Deploy {
                token,
                entry_type,
                entry_num,
                entry_den,
                oco_spk,
                oco_min_value,
                min_fill,
                receipt_cov_id,
                amount,
            } => {
                bracket::deploy_bracket_v4(
                    wallet_path,
                    node,
                    network,
                    &token,
                    entry_type,
                    entry_num,
                    entry_den,
                    &oco_spk,
                    oco_min_value,
                    min_fill,
                    &receipt_cov_id,
                    amount,
                )
                .await?;
            }
            bracket::BracketCommand::Fill {
                order,
                order_value,
                rs,
                receipt,
                receipt_value,
                seller_kas,
                buyer_tokens,
                oco_value,
                receipt_rs,
                fee_input,
            } => {
                bracket::fill_bracket_v4(
                    wallet_path,
                    node,
                    network,
                    &order,
                    order_value,
                    &rs,
                    &receipt,
                    receipt_value,
                    seller_kas,
                    buyer_tokens,
                    oco_value,
                    &receipt_rs,
                    fee_input.as_deref(),
                )
                .await?;
            }
            bracket::BracketCommand::Cancel {
                order,
                order_value,
                rs,
            } => {
                bracket::cancel_bracket_v4(
                    wallet_path,
                    node,
                    network,
                    &order,
                    order_value,
                    &rs,
                )
                .await?;
            }
        },
        Commands::Option { action } => {
            options::run(wallet_path, node, network, &action).await?;
        }
        Commands::Listing { action } => {
            listing::run(&action, wallet_path, node, network).await?;
        }
        Commands::Batch { file } => {
            batch::run(wallet_path, node, network, &file, fee).await?;
        }
        Commands::Recover => {
            recover::recover(wallet_path, node).await?;
        }
        Commands::RecoverOrders {
            rest,
            output,
            dry_run,
        } => {
            recover::recover_orders(
                wallet_path,
                node,
                &rest,
                network,
                output.as_deref(),
                dry_run,
            )
            .await?;
        }
        Commands::Orderbook {
            token,
            depth,
            json,
            cache_file,
        } => {
            let token = if let Some(t) = token {
                Some(token::resolve_token(&t, None)?)
            } else {
                None
            };
            orderbook::run_orderbook(
                wallet_path,
                node,
                network,
                token.as_deref(),
                depth,
                json,
                cache_file.as_deref(),
            )
            .await?;
        }
        Commands::Spread {
            token,
            json,
            cache_file,
        } => {
            let token = token::resolve_token(&token, None)?;
            orderbook::run_spread(
                wallet_path,
                node,
                network,
                &token,
                json,
                cache_file.as_deref(),
            )
            .await?;
        }
        Commands::OrderStatus { outpoint, json } => {
            orderbook::run_order_status(
                wallet_path,
                node,
                network,
                &outpoint,
                json,
            )
            .await?;
        }
        Commands::Requote {
            outpoint,
            old_side,
            old_token,
            old_price_num,
            old_price_den,
            old_min_fill,
            old_order_value,
            old_version,
            new_side,
            new_token,
            new_price_num,
            new_price_den,
            new_min_fill,
            new_amount,
            new_version,
            old_expiry,
            new_expiry,
            no_wait,
            fee_utxo,
            old_max_matcher_fee,
            new_max_matcher_fee,
        } => {
            let old_token = if let Some(t) = old_token {
                Some(token::resolve_token(&t, None)?)
            } else {
                None
            };
            deploy::validate_amount_not_dust(new_amount, "--new-amount")?;
            let new_token = token::resolve_token(&new_token, None)?;
            // v17 is the sole creatable buy contract (mirrors deploy.rs's
            // deploy_buy gate); auto-bump the shared --new-version flag's
            // default (14) to 17 for a new buy side so `--new-side buy`
            // keeps working without requiring an explicit --new-version.
            // Sell has no v16/v17 analogue and stays at 14.
            let new_version = if new_side == "buy" && new_version == 14 { 17 } else { new_version };
            let new_params = requote::NewOrderParams {
                side: new_side,
                token: new_token,
                price_num: new_price_num,
                price_den: new_price_den,
                min_fill: new_min_fill,
                amount: new_amount,
                version: new_version,
            };
            requote::run(
                wallet_path,
                node,
                network,
                &outpoint,
                old_side.as_deref(),
                old_token.as_deref(),
                old_price_num,
                old_price_den,
                old_min_fill,
                old_order_value,
                old_version,
                old_expiry,
                &new_params,
                new_expiry,
                no_wait,
                fee_utxo.as_deref(),
                old_max_matcher_fee,
                new_max_matcher_fee,
            )
            .await?;
        }
        Commands::CancelAll { token, dry_run, orders_file, yes } => {
            let token = if let Some(t) = token {
                Some(token::resolve_token(&t, None)?)
            } else {
                None
            };
            if !dry_run {
                let scope = token.as_deref().unwrap_or("ALL tokens");
                confirm_or_abort(
                    &format!(
                        "[CONFIRM] This will cancel all live orders for: {}\n\
                         This is irreversible and will submit on-chain cancel TXs.",
                        scope,
                    ),
                    yes,
                )?;
            }
            cancel_all::run(
                wallet_path,
                node,
                network,
                token.as_deref(),
                dry_run,
                orders_file.as_deref(),
            )
            .await?;
        }
        Commands::MyOrders { json } => {
            my_orders::run(
                wallet_path,
                node,
                network,
                json,
            )
            .await?;
        }
        Commands::TradeHistory { limit, json, engine_url } => {
            let engine_url = if engine_url.is_empty() { None } else { Some(engine_url) };
            history::run(
                wallet_path,
                node,
                network,
                limit,
                json,
                engine_url.as_deref(),
            )
            .await?;
        }
        Commands::Send { to, amount, amount_kas, fee: send_fee, yes } => {
            let amount = match (amount, amount_kas) {
                (Some(s), None) => s,
                (None, Some(k)) => {
                    if !k.is_finite() || k <= 0.0 {
                        anyhow::bail!("--amount-kas must be a positive finite number");
                    }
                    (k * 1e8).round() as u64
                }
                (Some(_), Some(_)) => anyhow::bail!("Pass either --amount or --amount-kas, not both"),
                (None, None) => anyhow::bail!("Missing --amount (sompi) or --amount-kas"),
            };
            deploy::validate_amount_not_dust(amount, "--amount")?;
            let amount_kas_disp = amount as f64 / 100_000_000.0;
            confirm_or_abort(
                &format!(
                    "[CONFIRM] Send {} sompi ({:.8} KAS) to {}\n\
                     KAS transfers are IRREVERSIBLE. Verify the address is correct.",
                    amount, amount_kas_disp, to,
                ),
                yes,
            )?;
            wallet_send::run(
                wallet_path,
                node,
                network,
                &to,
                amount,
                send_fee,
            )
            .await?;
        }
        Commands::EstimateFee { action } => {
            estimate::run(&action);
        }
        Commands::Watch { token } => {
            let token = if token.is_empty() { token } else { token::resolve_token(&token, None)? };
            watch::run_watch(node, &token).await?;
        }
        Commands::Stop { action } => {
            stop::run_stop(wallet_path, node, network, fee, &action).await?;
        }
        Commands::TrailingStop { action } => {
            stop::run_trailing_stop(wallet_path, node, network, fee, &action).await?;
        }
        Commands::Prediction { action } => {
            prediction::run(wallet_path, node, network, fee, &action).await?;
        }
        Commands::Mm {
            token,
            mid_price_num,
            mid_price_den,
            spread_bps,
            levels,
            amount,
            min_fill,
            interval,
            version,
            dry_run,
            requote_threshold_bps,
            no_cleanup,
            deploy_delay_secs,
        } => {
            deploy::validate_amount_not_dust(amount, "--amount")?;
            let token = token::resolve_token(&token, None)?;
            let config = mm::MmConfig {
                token,
                mid_price_num,
                mid_price_den,
                spread_bps,
                levels,
                amount,
                interval_secs: interval,
                dry_run,
                version,
                min_fill,
                requote_threshold_bps,
                deploy_delay_secs,
            };
            mm::run(wallet_path, node, network, &config, !no_cleanup).await?;
        }
        Commands::Perp { action } => {
            perp::run(wallet_path, node, network, fee, &action).await?;
        }
        Commands::Dca { action } => {
            dca::run(wallet_path, node, network, &action).await?;
        }
        Commands::Lending { action } => match action {
            LendingCommands::Offer {
                amount,
                rate_num,
                rate_den,
                duration_daa,
                min_collateral_ratio,
                token,
                rate_mode,
                rate_floor_num,
            } => {
                deploy::validate_amount_not_dust(amount, "--amount")?;
                lending::deploy_offer(
                    wallet_path, node, network, amount, rate_num, rate_den,
                    duration_daa, min_collateral_ratio, &token, fee,
                    rate_mode, rate_floor_num,
                ).await?;
            }
            LendingCommands::Request {
                collateral,
                max_rate_num,
                max_rate_den,
                amount_requested,
                duration_daa,
                token,
                rate_mode,
                rate_cap_num,
            } => {
                lending::deploy_request(
                    wallet_path, node, network, collateral, max_rate_num,
                    max_rate_den, amount_requested, duration_daa, &token,
                    fee, rate_mode, rate_cap_num,
                ).await?;
            }
            LendingCommands::Cancel {
                outpoint,
                side,
                token,
                principal,
                rate_num,
                rate_den,
                min_collateral_ratio,
                max_duration_daa,
                rate_mode,
                rate_floor_num,
                desired_amount,
                max_rate_num,
                max_rate_den,
                min_duration_daa,
                req_rate_mode,
                rate_cap_num,
                order_value,
                fee_utxo,
            } => {
                lending::cancel(
                    wallet_path, node, network, &outpoint, &side,
                    principal, rate_num, rate_den, min_collateral_ratio,
                    max_duration_daa, rate_mode, rate_floor_num,
                    desired_amount, max_rate_num, max_rate_den,
                    min_duration_daa, req_rate_mode, rate_cap_num,
                    &token, order_value, fee,
                    fee_utxo.as_deref(),
                ).await?;
            }
            LendingCommands::Repay {
                loan_outpoint,
                insurer_spk_hash,
                lender_spk_hash,
                principal,
                rate_num,
                rate_den,
                start_daa,
                expiry_daa,
                collateral_token,
                rate_mode,
                rate_floor_num,
                rate_cap_num,
                grace_daa,
                liq_threshold,
                lender_spk,
                collateral,
            } => {
                let insurer_hash = parse_hash32(&insurer_spk_hash)?;
                let lender_hash = parse_hash32(&lender_spk_hash)?;
                let coll_cov = parse_hash32(&collateral_token)?;
                lending::repay(
                    wallet_path, node, network, &loan_outpoint,
                    &insurer_hash, &lender_hash, principal, rate_num,
                    rate_den, start_daa, expiry_daa, &coll_cov,
                    rate_mode, rate_floor_num, rate_cap_num, grace_daa,
                    liq_threshold, &lender_spk, collateral, fee,
                ).await?;
            }
            LendingCommands::ClaimDefault {
                loan_outpoint,
                insurer_spk_hash,
                lender_spk_hash,
                borrower_spk_hash,
                principal,
                rate_num,
                rate_den,
                start_daa,
                expiry_daa,
                collateral_token,
                rate_mode,
                rate_floor_num,
                rate_cap_num,
                grace_daa,
                liq_threshold,
                collateral,
            } => {
                let insurer_hash = parse_hash32(&insurer_spk_hash)?;
                let lender_hash = parse_hash32(&lender_spk_hash)?;
                let borrower_hash = parse_hash32(&borrower_spk_hash)?;
                let coll_cov = parse_hash32(&collateral_token)?;
                lending::claim_default(
                    wallet_path, node, network, &loan_outpoint,
                    &insurer_hash, &lender_hash, &borrower_hash,
                    principal, rate_num, rate_den, start_daa, expiry_daa,
                    &coll_cov, rate_mode, rate_floor_num, rate_cap_num,
                    grace_daa, liq_threshold, collateral, fee,
                ).await?;
            }
            LendingCommands::Liquidate {
                loan_outpoint,
                insurer_spk_hash,
                lender_spk_hash,
                borrower_spk_hash,
                principal,
                rate_num,
                rate_den,
                start_daa,
                expiry_daa,
                collateral_token,
                rate_mode,
                rate_floor_num,
                rate_cap_num,
                grace_daa,
                liq_threshold,
                lender_spk,
                borrower_spk,
                price_outpoint,
                liquidator_bonus,
                collateral,
            } => {
                let insurer_hash = parse_hash32(&insurer_spk_hash)?;
                let lender_hash = parse_hash32(&lender_spk_hash)?;
                let borrower_hash = parse_hash32(&borrower_spk_hash)?;
                let coll_cov = parse_hash32(&collateral_token)?;
                lending::liquidate(
                    wallet_path, node, network, &loan_outpoint,
                    &insurer_hash, &lender_hash, &borrower_hash,
                    principal, rate_num, rate_den, start_daa, expiry_daa,
                    &coll_cov, rate_mode, rate_floor_num, rate_cap_num,
                    grace_daa, liq_threshold, &lender_spk, &borrower_spk,
                    &price_outpoint, liquidator_bonus, collateral, fee,
                ).await?;
            }
            LendingCommands::Loans { engine_url } => {
                lending::list_loans(engine_url.as_deref()).await?;
            }
        },
        Commands::Insurance { action } => {
            insurance::run(wallet_path, node, network, fee, &action).await?;
        }
        Commands::Swap { action } => {
            swap::run(wallet_path, node, network, &action).await?;
        }
    }

    Ok(())
}


/// Parse a 64-char hex string into a 32-byte array.
fn parse_hash32(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 32 {
        anyhow::bail!("expected 64 hex chars (32 bytes), got {} chars", hex_str.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}
/// Print configuration info to stdout.
pub fn cmd_config(wallet_path: &std::path::Path, node: &str, network: kob_core::types::Network) {
    println!("KOB Configuration");
    println!("==================");
    println!("Node:       {}", node);
    println!("Wallet:     {}", wallet_path.display());
    println!("Network:    {:?}", network);
    println!();
    println!("Contract Sizes (v3):");
    println!("  buy_order:     224B redeemScript (93B state + 131B body)");
    println!("  sell_order:    177B redeemScript (60B state + 117B body)");
    println!("  trade_receipt: 141B redeemScript v3 (102B state + 39B body)");
    println!();
    println!("Contract Sizes (v6 -- current default fallback):");
    println!("  buy_order:     348B redeemScript (136B state + 212B body)");
    println!("  sell_order:    284B redeemScript (94B state + 190B body)");
    println!();
    println!("Contract Sizes (v8 -- parameterized indices, cross-pair ready, TN12 VERIFIED):");
    println!("  buy_order:     356B redeemScript (136B state + 220B body)");
    println!("  sell_order:    287B redeemScript (94B state + 193B body)");
    println!("  v8 fill SS:    buy +2B (token_output_idx + token_input_idx), sell +1B (kas_output_idx)");
    println!();
    println!("Dispatch Thresholds (buy_order v3):");
    println!("  T1 = 232: sigLen < T1 -> full fill");
    println!("  T2 = 282: T1 <= sigLen < T2 -> partial fill");
    println!("           sigLen >= T2 -> cancel");
    println!();
    println!("Dispatch (sell_order v3):");
    println!("  Op4 OpRoll selector: 0=cancel, 1=fill, 2=partial_fill");
    println!();
    println!("Dispatch (v8 buy/sell):");
    println!("  Same as v6. Fill sigscripts push index args before selector.");
    println!("  buy_v8 fill SS: [tok_out_idx] [tok_in_idx] [cov_out_idx] [Op1] [pushData(RS)]");
    println!("  sell_v8 fill SS: [kas_out_idx] [Op1] [pushData(RS)]");
    println!();
    println!("Constants:");
    println!("  DEFAULT_MATCHER_FEE:           {} sompi", kob_core::DEFAULT_MATCHER_FEE);
    println!("  MIN_UTXO:      {} sompi", kob_core::MIN_UTXO_VALUE);
    println!("  RECEIPT_VALUE: {} sompi", kob_core::RECEIPT_VALUE);
    println!();
    println!("Contract Sizes (v6):");
    println!("  bracket_order: 365B redeemScript (224B state + 141B body)");
    println!("    Fill:   369B sigscript (< 400 threshold)");
    println!("    Cancel: 468B sigscript (>= 400 threshold)");
    println!();
    println!("Cross-Pair Matching (v8):");
    println!("  TX layout: sell[0] buy[1] token[2] fee[3]");
    println!("  sell_v8 SS: kas_output_idx=0");
    println!("  buy_v8 SS:  token_output_idx=1, token_input_idx=2");
    println!("  Use: kob-cli match --cross-pair --sell <> --buy <> --token-outpoint <>");
    println!();
    println!("Commands (17):");
    println!("  wallet, deploy, cancel, cancel-mark, partial-fill,");
    println!("  list, match, receipt (create/consume/trigger/consume-v1),");
    println!("  config, status, scan, token (create/mint/transfer/burn),");
    println!("  auto-match, oco, bracket (deploy/fill/cancel), batch, recover");
    println!();
    println!("TN12 Nodes:");
    println!("  Primary:  ws://79.99.46.67:18210");
    println!("  Fallback: ws://65.108.107.30:18210");
    println!("  DNS:      tn12-dnsseed.kasia.fyi");
}
