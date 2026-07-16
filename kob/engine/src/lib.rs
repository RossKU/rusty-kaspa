//! KOB matching engine library.

#![allow(clippy::too_many_arguments)]

/// Default maximum matcher fee (in sompi) embedded in PRE-v18 deploy
/// redeemScripts. Must match `kob-cli`'s `DEFAULT_MAX_MATCHER_FEE` to avoid
/// P2SH mismatch.
///
/// Re-exported from `kob-domain` for backward compatibility.
pub use kob_domain::DEFAULT_MAX_MATCHER_FEE;

/// Default maximum matcher fee in BASIS POINTS — the shared constant for
/// every v18 builder call site (v18 builders reject values > 10000).
pub use kob_domain::DEFAULT_MAX_MATCHER_FEE_BPS;

pub mod config;
pub mod chain;
pub mod storage;
pub mod api;
pub mod reporting;
pub mod matcher;
pub mod mm;

// RPC client and signing/address utils now live in `kob-settle` (Phase 1
// extraction, see kob/x402/X402_STATUS.md). Re-exported so every existing
// `kob_engine::{rpc,utils}` / `crate::{rpc,utils}` path keeps resolving.
pub use kob_settle::rpc;
pub use kob_settle::utils;

use std::sync::Arc;
use tokio::sync::{broadcast, Mutex, RwLock};
use tracing::{error, info, warn};

use config::AppConfig;
use matcher::api::{AppState, SharedState};
use matcher::dca_book::DcaBook;
use matcher::ifd::IfdBook;
use matcher::lending_book::LendingBook;
use matcher::lending_tracker::LoanTracker;
use matcher::order_book::OrderBook;
use matcher::perp_book::PerpOrderBook;
use matcher::perp_tracker::PositionTracker;
use matcher::prediction_book::PredictionBook;
use matcher::prediction_tracker::MarketTracker;
use matcher::stop_book::StopOrderBook;
use matcher::swap_book::SwapBook;
use matcher::trailing_stop::TrailingStopBook;
use rpc::RpcClient;

/// Connect to primary RPC node, falling back to secondary if primary fails.
/// Automatically subscribes to UTXO changes for the wallet address.
pub async fn connect_rpc(config: &AppConfig) -> Result<RpcClient, String> {
    let rpc = match RpcClient::connect(&config.node_url).await {
        Ok(rpc) => {
            info!("Connected to: {}", config.node_url);
            rpc
        }
        Err(e) => {
            warn!("Primary node failed: {}", e);
            if let Some(ref fallback) = config.fallback_url {
                match RpcClient::connect(fallback).await {
                    Ok(rpc) => {
                        info!("Connected to fallback: {}", fallback);
                        rpc
                    }
                    Err(e2) => return Err(format!("Primary: {}, Fallback: {}", e, e2)),
                }
            } else {
                return Err(e.to_string());
            }
        }
    };

    // Auto-subscribe to UTXO changes for wallet address
    if let Err(e) = rpc.subscribe_utxos_changed(&[&config.address]).await {
        warn!("[UTXO] Failed to subscribe utxosChanged for wallet {}: {}", config.address, e);
    }

    Ok(rpc)
}

/// Bundle of all shared order books and trackers used by the continuous engine.
///
/// Groups the twelve `Arc<Mutex<_>>` handles that the executor, API, and MM
/// bot need so they can be threaded through the orchestration layer as a
/// single value rather than a dozen positional arguments.
struct SharedBooks {
    order: Arc<Mutex<OrderBook>>,
    stop: Arc<Mutex<StopOrderBook>>,
    trailing_stop: Arc<Mutex<TrailingStopBook>>,
    ifd: Arc<Mutex<IfdBook>>,
    perp: Arc<Mutex<PerpOrderBook>>,
    perp_tracker: Arc<Mutex<PositionTracker>>,
    lending: Arc<Mutex<LendingBook>>,
    loan_tracker: Arc<Mutex<LoanTracker>>,
    prediction: Arc<Mutex<PredictionBook>>,
    market_tracker: Arc<Mutex<MarketTracker>>,
    dca: Arc<Mutex<DcaBook>>,
    swap: Arc<Mutex<SwapBook>>,
}

/// Parameters for running the engine in `continuous` mode.
///
/// Bundles the wiring knobs (paths, ports, cross-pair flags, MM config) so
/// `run_continuous_mode` has a tractable signature.
pub struct ContinuousParams<'a> {
    pub interval: u64,
    pub api_port: u16,
    pub api_bind: &'a str,
    pub orderbook_path: &'a str,
    pub trades_file: &'a str,
    pub cross_pair: bool,
    pub allow_self_trade: bool,
    pub wallet_path: &'a str,
    pub history_db: Option<String>,
    pub enable_mm: bool,
    pub mm_token: Option<String>,
    pub mm_spread_bps: Option<u64>,
    pub mm_levels: Option<u64>,
    pub mm_mid_num: Option<u64>,
    pub mm_mid_den: Option<u64>,
    pub mm_amount: Option<u64>,
    pub mm_min_fill: u64,
}

/// Load persisted auxiliary books (stop / trailing / IFD / perp / lending /
/// prediction / swap) from disk, logging load counts on success and falling
/// back to empty books on I/O failure.
///
/// The caller-provided `order_book` is placed in the returned bundle as-is —
/// the primary order book is loaded separately by `run_continuous_mode`
/// because validation against the live chain needs an RPC handle.
async fn load_shared_books(
    order_book: Arc<Mutex<OrderBook>>,
    orderbook_path: &str,
) -> SharedBooks {
    let stop_orders_path = format!("{}.stops.json", orderbook_path);
    let trailing_stops_path = format!("{}.trailing.jsonl", orderbook_path);
    let ifd_path = format!("{}.ifd.json", orderbook_path);
    let perp_book_path = format!("{}.perp.json", orderbook_path);
    let lending_book_path = format!("{}.lending.json", orderbook_path);
    let prediction_book_path = format!("{}.prediction.json", orderbook_path);
    let swap_book_path = format!("{}.swap.json", orderbook_path);

    let stop = Arc::new(Mutex::new(match matcher::stop_book::load_stop_orders(&stop_orders_path) {
        Ok(b) => {
            if !b.is_empty() {
                info!("[STOP BOOK] Loaded {} stop order(s)", b.len());
            }
            b
        }
        Err(e) => {
            warn!("[STOP BOOK] Failed to load: {}, starting empty", e);
            StopOrderBook::new()
        }
    }));

    let trailing_stop = Arc::new(Mutex::new({
        let book = TrailingStopBook::new_with_file(&trailing_stops_path);
        if !book.is_empty() {
            info!("[TRAILING STOP] Loaded {} trailing stop order(s)", book.len());
        }
        book
    }));

    let ifd = Arc::new(Mutex::new(match matcher::ifd::load_ifd_rules(&ifd_path) {
        Ok(b) => {
            if !b.is_empty() {
                info!("[IFD BOOK] Loaded {} rule(s) ({} active)", b.len(), b.active_count());
            }
            b
        }
        Err(e) => {
            warn!("[IFD BOOK] Failed to load: {}, starting empty", e);
            IfdBook::new()
        }
    }));

    let perp = Arc::new(Mutex::new(match matcher::persistence::load_perp_book(&perp_book_path) {
        Ok(b) => {
            if b.total_count() > 0 {
                info!("[PERP BOOK] Loaded {} order(s) ({} longs, {} shorts)", b.total_count(), b.long_count(), b.short_count());
            }
            b
        }
        Err(e) => {
            warn!("[PERP BOOK] Failed to load: {}, starting empty", e);
            PerpOrderBook::new()
        }
    }));
    let perp_tracker = Arc::new(Mutex::new(PositionTracker::new()));

    let lending = Arc::new(Mutex::new(match matcher::persistence::load_lending_book(&lending_book_path) {
        Ok(b) => {
            if b.offer_count() > 0 || b.request_count() > 0 {
                info!("[LENDING BOOK] Loaded {} offer(s), {} request(s)", b.offer_count(), b.request_count());
            }
            b
        }
        Err(e) => {
            warn!("[LENDING BOOK] Failed to load: {}, starting empty", e);
            LendingBook::new()
        }
    }));
    let loan_tracker = Arc::new(Mutex::new(LoanTracker::new()));

    let prediction = Arc::new(Mutex::new(match matcher::persistence::load_prediction_book(&prediction_book_path) {
        Ok(b) => {
            if b.market_count() > 0 {
                info!("[PREDICTION BOOK] Loaded {} market(s)", b.market_count());
            }
            b
        }
        Err(e) => {
            warn!("[PREDICTION BOOK] Failed to load: {}, starting empty", e);
            PredictionBook::new()
        }
    }));
    let market_tracker = Arc::new(Mutex::new(MarketTracker::new()));
    let dca = Arc::new(Mutex::new(DcaBook::new()));

    let swap = Arc::new(Mutex::new(match matcher::persistence::load_swap_book(&swap_book_path) {
        Ok(b) => {
            if b.len() > 0 {
                info!("[SWAP BOOK] Loaded {} swap order(s)", b.len());
            }
            b
        }
        Err(_) => {
            info!("[SWAP BOOK] No persisted file at {}, starting empty", swap_book_path);
            SwapBook::new()
        }
    }));

    SharedBooks {
        order: order_book,
        stop,
        trailing_stop,
        ifd,
        perp,
        perp_tracker,
        lending,
        loan_tracker,
        prediction,
        market_tracker,
        dca,
        swap,
    }
}

/// Wire the HTTP/WS API server and `SharedState`, spawning the server task
/// when `api_port > 0`. Returns `(Some(ws_tx), Some(shared_state))` when the
/// API is enabled so the executor can publish events, or `(None, None)`
/// otherwise.
async fn setup_api_server(
    api_port: u16,
    api_bind: &str,
    trades_file: &str,
    books: &SharedBooks,
    rpc: Arc<Mutex<RpcClient>>,
) -> (Option<broadcast::Sender<matcher::api::WsEvent>>, Option<AppState>) {
    if api_port == 0 {
        return (None, None);
    }

    let (ws_tx, _) = broadcast::channel(1000);
    let ws_tx_clone = ws_tx.clone();
    let state_core = if trades_file.is_empty() {
        SharedState::new_with_ifd(
            ws_tx,
            books.order.clone(),
            books.stop.clone(),
            books.trailing_stop.clone(),
            books.ifd.clone(),
        )
    } else {
        info!("[TradeLog] File persistence enabled: {}", trades_file);
        SharedState::new_with_trades_file_and_ifd(
            ws_tx,
            trades_file,
            books.order.clone(),
            books.stop.clone(),
            books.trailing_stop.clone(),
            books.ifd.clone(),
        )
    };
    let shared_state: AppState = Arc::new(RwLock::new(state_core.with_rpc(rpc)));

    // Wire perp/lending/prediction books into SharedState.
    {
        let mut ss = shared_state.write().await;
        ss.perp_book = Some(books.perp.clone());
        ss.perp_tracker = Some(books.perp_tracker.clone());
        ss.lending_book = Some(books.lending.clone());
        ss.loan_tracker = Some(books.loan_tracker.clone());
        ss.prediction_book = Some(books.prediction.clone());
        ss.market_tracker = Some(books.market_tracker.clone());
    }

    let api_state = shared_state.clone();
    let executor_state = shared_state;
    let bind = api_bind.to_string();
    tokio::spawn(async move {
        matcher::api::start_server(api_state, api_port, &bind).await;
    });
    info!("[API] Server starting on {}:{}", api_bind, api_port);
    (Some(ws_tx_clone), Some(executor_state))
}

/// Initialise the SQLite history store if `history_db` is configured, wiring
/// it into `SharedState` and spawning a periodic purge task.
async fn init_history_store(
    history_db: Option<&str>,
    trades_file: &str,
    executor_state: &Option<AppState>,
) {
    let Some(db_name) = history_db.filter(|n| !n.is_empty()) else { return; };
    let Some(executor_state) = executor_state else { return; };

    let mut hc = config::HistoryConfig::default();
    let db_path = if !trades_file.is_empty() {
        let p = std::path::Path::new(trades_file)
            .parent()
            .unwrap_or(std::path::Path::new("."));
        p.join(db_name).to_string_lossy().to_string()
    } else {
        db_name.to_string()
    };
    hc.db_path = db_path;

    match matcher::history::HistoryStore::open(&hc) {
        Ok(store) => {
            let store = Arc::new(store);
            executor_state.write().await.history = Some(store.clone());
            info!("[History] SQLite DB initialized: {}", hc.db_path);

            let purge_store = store.clone();
            let purge_interval = hc.purge_interval_secs;
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(
                    std::time::Duration::from_secs(purge_interval),
                );
                loop {
                    interval.tick().await;
                    if let Err(e) = purge_store.purge_expired() {
                        warn!("History purge failed: {}", e);
                    }
                }
            });
        }
        Err(e) => {
            warn!(
                "Failed to open history DB: {} — running without persistence",
                e
            );
        }
    }
}

/// Spawn the in-process market maker task when `params.enable_mm` is true.
/// Logs a config-validation error and skips the task on invalid input so the
/// engine keeps running without MM instead of aborting.
fn spawn_mm_bot(app_config: &AppConfig, params: &ContinuousParams<'_>) {
    if !params.enable_mm {
        return;
    }

    let mm_config = match build_mm_config(
        params.mm_token.clone(),
        params.mm_mid_num,
        params.mm_mid_den,
        params.mm_spread_bps.unwrap_or(100),
        params.mm_levels.map(|l| l as u32).unwrap_or(3),
        params.mm_amount,
        params.mm_min_fill,
        params.interval,
    ) {
        Ok(c) => c,
        Err(e) => {
            error!("[MM] Invalid MM configuration: {}. MM bot not started.", e);
            return;
        }
    };

    let wp = std::path::PathBuf::from(params.wallet_path);
    let node_url = app_config.node_url.clone();
    let network = if app_config.address.starts_with("kaspatest") {
        kob_core::types::Network::Testnet
    } else {
        kob_core::types::Network::Mainnet
    };
    info!("[MM] Starting in-process market maker for {}", mm_config.token);
    tokio::spawn(async move {
        // In-process MM (engine `continuous` mode) defaults to cleanup_on_shutdown=true
        // so a Ctrl+C on the engine cancels MM-deployed orders too.
        if let Err(e) = mm::run(&wp, &node_url, network, &mm_config, true).await {
            error!("[MM] Bot exited with error: {}", e);
        }
    });
}

/// Run the engine in `continuous` mode: preload the order book, load auxiliary
/// books from disk, wire the API server and optional history/MM subsystems,
/// and hand off to the main executor loop.
async fn run_continuous_mode(
    rpc: Arc<Mutex<RpcClient>>,
    order_book: Arc<Mutex<OrderBook>>,
    app_config: &AppConfig,
    params: ContinuousParams<'_>,
) {
    // Pre-load the primary order book and prune entries whose UTXOs have
    // already been spent on-chain.
    if let Err(e) = matcher::persistence::load_order_book(params.orderbook_path, &order_book).await {
        warn!("Failed to load persisted order book: {}", e);
    } else {
        let rpc_lock = rpc.lock().await;
        matcher::persistence::validate_and_prune_order_book(
            &rpc_lock,
            &order_book,
            &app_config.address,
        )
        .await;
        drop(rpc_lock);
    }

    let books = load_shared_books(order_book, params.orderbook_path).await;

    let (ws_broadcaster, shared_state_for_executor) =
        setup_api_server(params.api_port, params.api_bind, params.trades_file, &books, rpc.clone()).await;

    init_history_store(
        params.history_db.as_deref(),
        params.trades_file,
        &shared_state_for_executor,
    )
    .await;

    spawn_mm_bot(app_config, &params);

    matcher::executor::run_continuous_with_ws(
        rpc,
        books.order.clone(),
        app_config,
        params.interval,
        params.orderbook_path,
        params.cross_pair,
        params.allow_self_trade,
        ws_broadcaster,
        books.stop,
        books.trailing_stop,
        shared_state_for_executor,
        books.ifd,
        books.perp,
        books.perp_tracker,
        books.lending,
        books.loan_tracker,
        books.prediction,
        books.market_tracker,
        books.dca,
        books.swap,
    )
    .await;
}

/// Run the engine in `dry-run` mode: load the persisted order book, prune
/// stale entries, and hand off to the read-only executor loop.
async fn run_dry_run_mode(
    rpc: Arc<Mutex<RpcClient>>,
    order_book: Arc<Mutex<OrderBook>>,
    app_config: &AppConfig,
    orderbook_path: &str,
) {
    if let Err(e) = matcher::persistence::load_order_book(orderbook_path, &order_book).await {
        warn!("Failed to load persisted order book: {}", e);
    } else {
        let rpc_lock = rpc.lock().await;
        matcher::persistence::validate_and_prune_order_book(
            &rpc_lock,
            &order_book,
            &app_config.address,
        )
        .await;
        drop(rpc_lock);
    }
    matcher::executor::run_dry_run(rpc, order_book, app_config).await;
}

/// Run the KOB matching engine with the given configuration.
///
/// This is the main entry point for library consumers. It handles RPC
/// connection and dispatches into per-mode orchestration functions:
/// [`run_continuous_mode`] / [`run_dry_run_mode`] / deploy-test variants.
#[allow(clippy::too_many_arguments)]
pub async fn run_engine(
    app_config: &AppConfig,
    mode: &str,
    interval: u64,
    api_port: u16,
    api_bind: &str,
    enable_mm: bool,
    mm_token: Option<String>,
    mm_spread_bps: Option<u64>,
    mm_levels: Option<u64>,
    mm_mid_num: Option<u64>,
    mm_mid_den: Option<u64>,
    history_db: Option<String>,
    // Extra fields needed by the engine
    orderbook_path: &str,
    trades_file: &str,
    cross_pair: bool,
    allow_self_trade: bool,
    wallet_path: &str,
    mm_amount: Option<u64>,
    mm_min_fill: u64,
    token_cov_id: Option<String>,
    token_utxo: Option<String>,
) -> anyhow::Result<()> {
    tracing::info!("[ENGINE] allow_self_trade={} cross_pair={}", allow_self_trade, cross_pair);
    // Create shared order book
    let order_book = Arc::new(Mutex::new(OrderBook::new()));

    // Connect to RPC node
    let rpc = connect_rpc(app_config)
        .await
        .map_err(|e| anyhow::anyhow!("Cannot connect to any node: {}", e))?;
    let rpc = Arc::new(Mutex::new(rpc));

    match mode {
        "deploy-test" => {
            let tcid = token_cov_id.as_deref().unwrap_or("");
            let tutxo = token_utxo.as_deref().unwrap_or("");
            if tcid.is_empty() || tutxo.is_empty() {
                anyhow::bail!("deploy-test requires --token and --token-utxo");
            }
            matcher::deploy::run_deploy_test(rpc, order_book, app_config, tcid, tutxo).await;
        }
        "deploy-test-multi" => {
            matcher::deploy::run_deploy_test_multi(rpc, order_book, app_config).await;
        }
        "continuous" => {
            let params = ContinuousParams {
                interval,
                api_port,
                api_bind,
                orderbook_path,
                trades_file,
                cross_pair,
                allow_self_trade,
                wallet_path,
                history_db,
                enable_mm,
                mm_token,
                mm_spread_bps,
                mm_levels,
                mm_mid_num,
                mm_mid_den,
                mm_amount,
                mm_min_fill,
            };
            run_continuous_mode(rpc, order_book, app_config, params).await;
        }
        "dry-run" => {
            run_dry_run_mode(rpc, order_book, app_config, orderbook_path).await;
        }
        other => {
            return Err(anyhow::anyhow!(
                "Unknown mode: {}. Use: --mode [deploy-test|deploy-test-multi|continuous|dry-run]",
                other
            ));
        }
    }

    Ok(())
}

/// Build MmConfig from individual parameters.
fn build_mm_config(
    mm_token: Option<String>,
    mm_mid_num: Option<u64>,
    mm_mid_den: Option<u64>,
    mm_spread_bps: u64,
    mm_levels: u32,
    mm_amount: Option<u64>,
    mm_min_fill: u64,
    interval_ms: u64,
) -> anyhow::Result<mm::MmConfig> {
    let token = mm_token
        .ok_or_else(|| anyhow::anyhow!("--mm-token is required when --mm is set"))?;
    let mid_price_num = mm_mid_num
        .ok_or_else(|| anyhow::anyhow!("--mm-mid-num is required when --mm is set"))?;
    let mid_price_den = mm_mid_den
        .ok_or_else(|| anyhow::anyhow!("--mm-mid-den is required when --mm is set"))?;
    let amount = mm_amount
        .ok_or_else(|| anyhow::anyhow!("--mm-amount is required when --mm is set"))?;

    let config = mm::MmConfig {
        token,
        mid_price_num,
        mid_price_den,
        spread_bps: mm_spread_bps,
        levels: mm_levels,
        amount,
        interval_secs: interval_ms / 1000,
        dry_run: false,
        version: 18,
        min_fill: mm_min_fill,
        requote_threshold_bps: 500,
        deploy_delay_secs: 2,
    };
    config.validate()?;
    Ok(config)
}
