//! KOB matching engine library.

#![allow(clippy::too_many_arguments)]

/// Default maximum matcher fee (in sompi) embedded in deploy redeemScripts.
/// Must match `kob-cli`'s `DEFAULT_MAX_MATCHER_FEE` to avoid P2SH mismatch.
pub const DEFAULT_MAX_MATCHER_FEE: u64 = 10_000_000;

pub mod config;
pub mod matcher;
pub mod mm;
pub mod rpc;
pub mod utils;

use std::sync::Arc;
use tokio::sync::{broadcast, Mutex, RwLock};
use tracing::{error, info, warn};

use config::AppConfig;
use matcher::api::{AppState, SharedState};
use matcher::order_book::OrderBook;
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

/// Run the KOB matching engine with the given configuration.
///
/// This is the main entry point for library consumers. It handles RPC
/// connection, order book setup, executor, API server, and optional MM bot.
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
            if let Err(e) =
                matcher::persistence::load_order_book(orderbook_path, &order_book).await
            {
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

            // Create shared stop/trailing stop books
            let stop_orders_path = format!("{}.stops.json", orderbook_path);
            let trailing_stops_path = format!("{}.trailing.jsonl", orderbook_path);

            let shared_stop_book = {
                let book = match matcher::stop_book::load_stop_orders(&stop_orders_path) {
                    Ok(b) => {
                        if !b.is_empty() {
                            info!("[STOP BOOK] Loaded {} stop order(s)", b.len());
                        }
                        b
                    }
                    Err(e) => {
                        warn!("[STOP BOOK] Failed to load: {}, starting empty", e);
                        matcher::stop_book::StopOrderBook::new()
                    }
                };
                Arc::new(Mutex::new(book))
            };

            let shared_trailing_stop_book = {
                let book =
                    matcher::trailing_stop::TrailingStopBook::new_with_file(&trailing_stops_path);
                if !book.is_empty() {
                    info!(
                        "[TRAILING STOP] Loaded {} trailing stop order(s)",
                        book.len()
                    );
                }
                Arc::new(Mutex::new(book))
            };

            // Load IFD/IFO book
            let ifd_path = format!("{}.ifd.json", orderbook_path);
            let shared_ifd_book = {
                let book = match matcher::ifd::load_ifd_rules(&ifd_path) {
                    Ok(b) => {
                        if !b.is_empty() {
                            info!("[IFD BOOK] Loaded {} rule(s) ({} active)", b.len(), b.active_count());
                        }
                        b
                    }
                    Err(e) => {
                        warn!("[IFD BOOK] Failed to load: {}, starting empty", e);
                        matcher::ifd::IfdBook::new()
                    }
                };
                Arc::new(Mutex::new(book))
            };

            // Load perp order book
            let perp_book_path = format!("{}.perp.json", orderbook_path);
            let shared_perp_book = {
                let book = match matcher::persistence::load_perp_book(&perp_book_path) {
                    Ok(b) => {
                        if b.total_count() > 0 {
                            info!("[PERP BOOK] Loaded {} order(s) ({} longs, {} shorts)", b.total_count(), b.long_count(), b.short_count());
                        }
                        b
                    }
                    Err(e) => {
                        warn!("[PERP BOOK] Failed to load: {}, starting empty", e);
                        matcher::perp_book::PerpOrderBook::new()
                    }
                };
                Arc::new(Mutex::new(book))
            };
            let shared_perp_tracker = Arc::new(Mutex::new(matcher::perp_tracker::PositionTracker::new()));

            // Load lending order book
            let lending_book_path = format!("{}.lending.json", orderbook_path);
            let shared_lending_book = {
                let book = match matcher::persistence::load_lending_book(&lending_book_path) {
                    Ok(b) => {
                        if b.offer_count() > 0 || b.request_count() > 0 {
                            info!("[LENDING BOOK] Loaded {} offer(s), {} request(s)", b.offer_count(), b.request_count());
                        }
                        b
                    }
                    Err(e) => {
                        warn!("[LENDING BOOK] Failed to load: {}, starting empty", e);
                        matcher::lending_book::LendingBook::new()
                    }
                };
                Arc::new(Mutex::new(book))
            };
            let shared_loan_tracker = Arc::new(Mutex::new(matcher::lending_tracker::LoanTracker::new()));

            // Load prediction book
            let prediction_book_path = format!("{}.prediction.json", orderbook_path);
            let shared_prediction_book = {
                let book = match matcher::persistence::load_prediction_book(&prediction_book_path) {
                    Ok(b) => {
                        if b.market_count() > 0 {
                            info!("[PREDICTION BOOK] Loaded {} market(s)", b.market_count());
                        }
                        b
                    }
                    Err(e) => {
                        warn!("[PREDICTION BOOK] Failed to load: {}, starting empty", e);
                        matcher::prediction_book::PredictionBook::new()
                    }
                };
                Arc::new(Mutex::new(book))
            };
            let shared_market_tracker = Arc::new(Mutex::new(matcher::prediction_tracker::MarketTracker::new()));
            let shared_dca_book = Arc::new(Mutex::new(matcher::dca_book::DcaBook::new()));

            // Load swap book
            let swap_book_path = format!("{}.swap.json", orderbook_path);
            let shared_swap_book = {
                let book = match matcher::persistence::load_swap_book(&swap_book_path) {
                    Ok(b) => {
                        if b.len() > 0 {
                            info!("[SWAP BOOK] Loaded {} swap order(s)", b.len());
                        }
                        b
                    }
                    Err(_) => {
                        info!("[SWAP BOOK] No persisted file at {}, starting empty", swap_book_path);
                        matcher::swap_book::SwapBook::new()
                    }
                };
                Arc::new(Mutex::new(book))
            };

            // Start API server if port > 0
            let (ws_broadcaster, shared_state_for_executor) = if api_port > 0 {
                let (ws_tx, _) = broadcast::channel(1000);
                let ws_tx_clone = ws_tx.clone();
                let shared_state: AppState = if trades_file.is_empty() {
                    Arc::new(RwLock::new(SharedState::new_with_ifd(
                        ws_tx,
                        order_book.clone(),
                        shared_stop_book.clone(),
                        shared_trailing_stop_book.clone(),
                        shared_ifd_book.clone(),
                    )))
                } else {
                    info!("[TradeLog] File persistence enabled: {}", trades_file);
                    Arc::new(RwLock::new(SharedState::new_with_trades_file_and_ifd(
                        ws_tx,
                        trades_file,
                        order_book.clone(),
                        shared_stop_book.clone(),
                        shared_trailing_stop_book.clone(),
                        shared_ifd_book.clone(),
                    )))
                };

                // Wire perp/lending/prediction books into SharedState
                {
                    let mut ss = shared_state.write().await;
                    ss.perp_book = Some(shared_perp_book.clone());
                    ss.perp_tracker = Some(shared_perp_tracker.clone());
                    ss.lending_book = Some(shared_lending_book.clone());
                    ss.loan_tracker = Some(shared_loan_tracker.clone());
                    ss.prediction_book = Some(shared_prediction_book.clone());
                    ss.market_tracker = Some(shared_market_tracker.clone());
                }

                let api_state = shared_state.clone();
                let executor_state = shared_state;
                let bind = api_bind.to_string();
                tokio::spawn(async move {
                    matcher::api::start_server(api_state, api_port, &bind).await;
                });
                info!("[API] Server starting on {}:{}", api_bind, api_port);
                (Some(ws_tx_clone), Some(executor_state))
            } else {
                (None, None)
            };

            // Initialize SQLite history store
            if let Some(ref db_name) = history_db {
                if !db_name.is_empty() {
                    if let Some(ref executor_state) = shared_state_for_executor {
                        let mut hc = config::HistoryConfig::default();
                        let db_path = if !trades_file.is_empty() {
                            let p = std::path::Path::new(trades_file)
                                .parent()
                                .unwrap_or(std::path::Path::new("."));
                            p.join(db_name).to_string_lossy().to_string()
                        } else {
                            db_name.clone()
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
                }
            }

            // Spawn MM bot if enabled
            if enable_mm {
                match build_mm_config(
                    mm_token,
                    mm_mid_num,
                    mm_mid_den,
                    mm_spread_bps.unwrap_or(100),
                    mm_levels.map(|l| l as u32).unwrap_or(3),
                    mm_amount,
                    mm_min_fill,
                    interval,
                ) {
                    Ok(mm_config) => {
                        let wp = std::path::PathBuf::from(wallet_path);
                        let node_url = app_config.node_url.clone();
                        let network = if app_config.address.starts_with("kaspatest") {
                            kob_core::types::Network::Testnet
                        } else {
                            kob_core::types::Network::Mainnet
                        };
                        info!("[MM] Starting in-process market maker for {}", mm_config.token);
                        tokio::spawn(async move {
                            if let Err(e) = mm::run(&wp, &node_url, network, &mm_config).await {
                                error!("[MM] Bot exited with error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("[MM] Invalid MM configuration: {}. MM bot not started.", e);
                    }
                }
            }

            matcher::executor::run_continuous_with_ws(
                rpc,
                order_book.clone(),
                app_config,
                interval,
                orderbook_path,
                cross_pair,
                allow_self_trade,
                ws_broadcaster,
                shared_stop_book,
                shared_trailing_stop_book,
                shared_state_for_executor,
                shared_ifd_book,
                shared_perp_book,
                shared_perp_tracker,
                shared_lending_book,
                shared_loan_tracker,
                shared_prediction_book,
                shared_market_tracker,
                shared_dca_book,
                shared_swap_book,
            )
            .await;
        }
        "dry-run" => {
            if let Err(e) =
                matcher::persistence::load_order_book(orderbook_path, &order_book).await
            {
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
        version: 11,
        min_fill: mm_min_fill,
        requote_threshold_bps: 500,
    };
    config.validate()?;
    Ok(config)
}
