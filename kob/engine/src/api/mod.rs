//! REST API and WebSocket server for order book data, trades, and candles.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::time::Instant;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, DefaultBodyLimit, Query, State,
    },
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, Mutex, RwLock};
use tower_http::cors::{Any, CorsLayer};

use crate::matcher::candle::{CandleAggregator, Interval};
use crate::matcher::ifd::IfdBook;
use crate::matcher::order_book::{OrderBook, OrderSide};
use crate::matcher::lending_book::LendingBook;
use crate::matcher::lending_tracker::LoanTracker;
use crate::matcher::perp_book::PerpOrderBook;
use crate::matcher::perp_tracker::PositionTracker;
use crate::matcher::prediction_book::PredictionBook;
use crate::matcher::prediction_tracker::MarketTracker;
use crate::matcher::stop_book::StopOrderBook;
use crate::matcher::trades::{PendingTrades, Side, TradeLog};

/// Generate a random 64-char hex cancel secret using OS CSPRNG.
fn generate_cancel_secret() -> String {
    use rand::Rng;
    let bytes: [u8; 32] = rand::rngs::OsRng.gen();
    hex::encode(bytes)
}
use crate::matcher::trailing_stop::TrailingStopBook;

// Sync / liveness snapshot (H4-SYNC: GET /health, GET /sync)

/// Default `lag_blocks` threshold under which the scanner is considered
/// caught up. Matches the design's `caught_up_threshold` knob.
pub const DEFAULT_CAUGHT_UP_THRESHOLD: u64 = 10;

/// Scan-loop liveness classification exposed via `/api/v1/sync`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanningState {
    /// `lag_blocks <= caught_up_threshold`.
    Steady,
    /// Behind, but the lag is shrinking (or this is the first reading).
    CatchingUp,
    /// Behind, and the lag has NOT shrunk since the previous reading --
    /// exactly the signal that would have caught the documented
    /// deterministic 0%-CPU `getBlocks` hangs on large catch-up gaps.
    Stalled,
}

/// Pure state-machine step for `scanning_state`, factored out from
/// `SyncSnapshot::update` so it can be unit-tested directly without a scan
/// loop or RPC client.
pub fn compute_scanning_state(
    lag_blocks: u64,
    caught_up_threshold: u64,
    previous_lag: Option<u64>,
) -> ScanningState {
    if lag_blocks <= caught_up_threshold {
        return ScanningState::Steady;
    }
    match previous_lag {
        // Lag did not shrink since the last reading -- stalled.
        Some(prev) if lag_blocks >= prev => ScanningState::Stalled,
        _ => ScanningState::CatchingUp,
    }
}

/// Snapshot of scan-loop progress, updated by the executor once per scan
/// cycle -- and, during a large catch-up, once per checkpoint chunk (see
/// `CATCHUP_CHUNK_SIZE` in `chain::executor`) -- so `/api/v1/health` and
/// `/api/v1/sync` never need a live RPC call or the order-book mutex to
/// answer, and stay informative even while a catch-up is in progress.
#[derive(Debug, Clone)]
pub struct SyncSnapshot {
    /// DAA score of the last block the scanner has processed (the
    /// persisted H1 cursor). During a catch-up this is an estimate derived
    /// from the sink DAA and the count of not-yet-processed blocks in the
    /// current catch-up batch -- the scanner does not parse a per-block DAA
    /// score today (same "best-effort" caveat as `Trade::daa_score`).
    pub cursor_daa: u64,
    /// Hash of the block `cursor_daa` corresponds to.
    pub cursor_block_hash: String,
    /// Node's sink/virtual DAA as of the last time the scan loop checked.
    pub sink_daa: u64,
    /// Whether the RPC connection was healthy as of the last check.
    pub node_connected: bool,
    pub scanning_state: ScanningState,
    /// `lag_blocks` as of the previous update; used to detect "stalled".
    last_lag_blocks: Option<u64>,
}

impl Default for SyncSnapshot {
    fn default() -> Self {
        SyncSnapshot {
            cursor_daa: 0,
            cursor_block_hash: String::new(),
            sink_daa: 0,
            node_connected: false,
            scanning_state: ScanningState::CatchingUp,
            last_lag_blocks: None,
        }
    }
}

impl SyncSnapshot {
    /// Record a fresh reading, recomputing `scanning_state` against
    /// `caught_up_threshold` and the previous lag.
    pub fn update(
        &mut self,
        cursor_daa: u64,
        cursor_block_hash: String,
        sink_daa: u64,
        node_connected: bool,
        caught_up_threshold: u64,
    ) {
        let lag_blocks = sink_daa.saturating_sub(cursor_daa);
        self.scanning_state = compute_scanning_state(lag_blocks, caught_up_threshold, self.last_lag_blocks);
        self.last_lag_blocks = Some(lag_blocks);
        self.cursor_daa = cursor_daa;
        self.cursor_block_hash = cursor_block_hash;
        self.sink_daa = sink_daa;
        self.node_connected = node_connected;
    }

    pub fn lag_blocks(&self) -> u64 {
        self.sink_daa.saturating_sub(self.cursor_daa)
    }

    pub fn caught_up(&self, threshold: u64) -> bool {
        self.lag_blocks() <= threshold
    }
}

// Shared State

/// Shared application state, accessible by all API handlers.
pub struct SharedState {
    // === Spot ===
    /// Shared reference to the matcher's order book (same instance used by executor).
    pub order_book: Arc<Mutex<OrderBook>>,
    pub trade_log: TradeLog,
    pub candles: CandleAggregator,
    pub ws_broadcaster: broadcast::Sender<WsEvent>,
    pub update_id: u64,
    pub start_time: Instant,
    /// Shared stop order book (used by executor + REST API).
    pub stop_book: Arc<Mutex<StopOrderBook>>,
    /// Shared trailing stop book (used by executor + REST API).
    pub trailing_stop_book: Arc<Mutex<TrailingStopBook>>,
    /// Optional SQLite history store for persistent trade/candle data.
    pub history: Option<Arc<crate::matcher::history::HistoryStore>>,
    /// Trades staged at submission time, awaiting confirmation before being
    /// written to `history`'s durable trade ledger (H3-TRADES).
    pub pending_trades: PendingTrades,
    /// Shared IFD/IFO order book (used by executor + REST API).
    pub ifd_book: Arc<Mutex<IfdBook>>,

    // === Perp ===
    /// Perp order book. None until perp integration is activated.
    pub perp_book: Option<Arc<Mutex<PerpOrderBook>>>,
    /// Perp position tracker. None until perp integration is activated.
    pub perp_tracker: Option<Arc<Mutex<PositionTracker>>>,

    // === Lending ===
    /// Lending order book. None until lending module is implemented.
    pub lending_book: Option<Arc<Mutex<LendingBook>>>,
    /// Active loan tracker. None until lending module is implemented.
    pub loan_tracker: Option<Arc<Mutex<LoanTracker>>>,

    // === Prediction ===
    /// Prediction market book. None until prediction module is implemented.
    pub prediction_book: Option<Arc<Mutex<PredictionBook>>>,
    /// Market settlement tracker. None until prediction module is implemented.
    pub market_tracker: Option<Arc<Mutex<MarketTracker>>>,

    // === Wallet / RPC ===
    /// Shared reference to the engine's RPC client. Used by wallet UTXO query
    /// endpoint (`/api/v1/wallet/utxos`) so CLI callers can route through the
    /// engine's already-subscribed spent_outpoints tracking instead of hitting
    /// the node directly.
    ///
    /// `None` in tests (SharedState constructed without RPC) and when the
    /// engine was built without passing an RPC handle via `with_rpc`.
    pub rpc: Option<Arc<Mutex<crate::rpc::RpcClient>>>,

    // === Sync / liveness (H4-SYNC) ===
    /// Scan-loop progress snapshot backing `/api/v1/health` and
    /// `/api/v1/sync`. Updated by the executor, not by API handlers.
    pub sync: SyncSnapshot,
}

impl SharedState {
    pub fn new(
        ws_broadcaster: broadcast::Sender<WsEvent>,
        order_book: Arc<Mutex<OrderBook>>,
        stop_book: Arc<Mutex<StopOrderBook>>,
        trailing_stop_book: Arc<Mutex<TrailingStopBook>>,
    ) -> Self {
        Self::new_with_ifd(ws_broadcaster, order_book, stop_book, trailing_stop_book, Arc::new(Mutex::new(IfdBook::new())))
    }

    /// Create with a pre-loaded IFD book (e.g., from persistence).
    pub fn new_with_ifd(
        ws_broadcaster: broadcast::Sender<WsEvent>,
        order_book: Arc<Mutex<OrderBook>>,
        stop_book: Arc<Mutex<StopOrderBook>>,
        trailing_stop_book: Arc<Mutex<TrailingStopBook>>,
        ifd_book: Arc<Mutex<IfdBook>>,
    ) -> Self {
        SharedState {
            order_book,
            trade_log: TradeLog::new(),
            candles: CandleAggregator::new(),
            ws_broadcaster,
            update_id: 0,
            start_time: Instant::now(),
            stop_book,
            trailing_stop_book,
            history: None,
            pending_trades: PendingTrades::new(),
            ifd_book,
            perp_book: None,
            perp_tracker: None,
            lending_book: None,
            loan_tracker: None,
            prediction_book: None,
            market_tracker: None,
            rpc: None,
            sync: SyncSnapshot::default(),
        }
    }

    /// Attach an RPC client to this state. Enables the `/api/v1/wallet/utxos`
    /// endpoint. Safe to call at most once during server setup.
    pub fn with_rpc(mut self, rpc: Arc<Mutex<crate::rpc::RpcClient>>) -> Self {
        self.rpc = Some(rpc);
        self
    }

    /// Create with file-backed trade log. Loads existing trades and replays
    /// them through the candle aggregator to rebuild OHLCV state.
    pub fn new_with_trades_file(
        ws_broadcaster: broadcast::Sender<WsEvent>,
        trades_file: &str,
        order_book: Arc<Mutex<OrderBook>>,
        stop_book: Arc<Mutex<StopOrderBook>>,
        trailing_stop_book: Arc<Mutex<TrailingStopBook>>,
    ) -> Self {
        Self::new_with_trades_file_and_ifd(ws_broadcaster, trades_file, order_book, stop_book, trailing_stop_book, Arc::new(Mutex::new(IfdBook::new())))
    }

    /// Create with file-backed trade log and pre-loaded IFD book.
    pub fn new_with_trades_file_and_ifd(
        ws_broadcaster: broadcast::Sender<WsEvent>,
        trades_file: &str,
        order_book: Arc<Mutex<OrderBook>>,
        stop_book: Arc<Mutex<StopOrderBook>>,
        trailing_stop_book: Arc<Mutex<TrailingStopBook>>,
        ifd_book: Arc<Mutex<IfdBook>>,
    ) -> Self {
        let (trade_log, loaded_trades) =
            TradeLog::new_with_file(trades_file, crate::matcher::trades::DEFAULT_MAX_TRADES);
        let mut candles = CandleAggregator::new();
        candles.replay_trades(&loaded_trades);
        SharedState {
            order_book,
            trade_log,
            candles,
            ws_broadcaster,
            update_id: 0,
            start_time: Instant::now(),
            stop_book,
            trailing_stop_book,
            history: None,
            pending_trades: PendingTrades::new(),
            ifd_book,
            perp_book: None,
            perp_tracker: None,
            lending_book: None,
            loan_tracker: None,
            prediction_book: None,
            market_tracker: None,
            rpc: None,
            sync: SyncSnapshot::default(),
        }
    }
}

pub type AppState = Arc<RwLock<SharedState>>;

// WebSocket Events

/// Events broadcast to WebSocket subscribers.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "stream")]
#[allow(dead_code)] // Some variants only constructed in test / process_block_txs paths
pub enum WsEvent {
    #[serde(rename = "depth")]
    DepthUpdate {
        pair: String,
        bids: Vec<[String; 2]>,
        asks: Vec<[String; 2]>,
        #[serde(rename = "updateId")]
        update_id: u64,
    },
    #[serde(rename = "trade")]
    Trade {
        pair: String,
        txid: String,
        /// P1 fix: disambiguates multiple trade events sharing one txid
        /// (cross-pair swaps, v17 N:M sweeps) -- `(txid, leg_index)` is the
        /// stable trade key everywhere (ledger + API + WS).
        #[serde(rename = "legIndex")]
        leg_index: u32,
        price: String,
        qty: String,
        side: Side,
        daa_score: u64,
    },
    #[serde(rename = "kline")]
    Kline {
        pair: String,
        interval: String,
        o: String,
        h: String,
        l: String,
        c: String,
        v: String,
    },

    // User Order Events (private stream, filtered by owner_hash)

    /// A user's order was fully filled by a match TX.
    #[serde(rename = "order_filled")]
    OrderFilled {
        /// Owner hash (Blake2b-256 of the user's scriptPublicKey).
        owner_hash: String,
        /// Outpoint of the consumed order (txid:index).
        outpoint: String,
        /// Match transaction ID.
        tx_id: String,
        /// Fill price as rational string (num/den).
        fill_price: String,
        /// Fill amount in sompi.
        fill_amount: u64,
        /// Order side (Buy or Sell).
        side: OrderSide,
        /// Trading pair (token_covenant_id).
        pair: String,
    },

    /// A user's order was partially filled. The order remains in the book
    /// with the remaining amount.
    #[serde(rename = "order_partially_filled")]
    OrderPartiallyFilled {
        owner_hash: String,
        outpoint: String,
        tx_id: String,
        filled_amount: u64,
        remaining_amount: u64,
        fill_price: String,
        side: OrderSide,
        pair: String,
    },

    /// A user's order was cancelled (spent by a cancel TX, not a match).
    #[serde(rename = "order_cancelled")]
    OrderCancelled {
        owner_hash: String,
        outpoint: String,
        cancel_tx_id: String,
        pair: String,
    },

    /// A new order belonging to the user was detected on L1 by the scanner.
    #[serde(rename = "order_detected")]
    OrderDetected {
        owner_hash: String,
        outpoint: String,
        side: OrderSide,
        price: String,
        amount: u64,
        pair: String,
    },

    // Perp Events

    /// A perpetual futures trade was executed (Long matched Short).
    #[serde(rename = "perp_trade")]
    PerpTrade {
        tx_id: String,
        side: String,
        entry_price: String,
        size: u64,
        daa_score: u64,
    },

    /// A perp position was liquidated (margin below maintenance).
    #[serde(rename = "perp_liquidation")]
    PerpLiquidation {
        tx_id: String,
        side: String,
        price: String,
        size: u64,
    },

    /// Perp order book update (new long/short orders or removals).
    #[serde(rename = "perp_orderbook")]
    PerpOrderBookUpdate {
        longs: usize,
        shorts: usize,
    },

    // Lending Events

    /// A lending match was executed (offer matched with request).
    #[serde(rename = "lending_match")]
    LendingMatch {
        tx_id: String,
        principal: u64,
        rate: String,
        collateral: u64,
        duration_daa: u64,
    },

    /// An active loan was liquidated (collateral below threshold).
    #[serde(rename = "loan_liquidated")]
    LoanLiquidated {
        tx_id: String,
        collateral_seized: u64,
        debt_covered: u64,
    },

    /// A loan was repaid by the borrower.
    #[serde(rename = "loan_repaid")]
    LoanRepaid {
        tx_id: String,
        principal: u64,
        interest_paid: u64,
    },

    // Prediction Market Events

    /// A new prediction market was created (SplitMerge + BallotBoxes deployed).
    #[serde(rename = "market_created")]
    MarketCreated {
        market_id: String,
        tx_id: String,
    },

    /// A vote was cast on a prediction market ballot box.
    #[serde(rename = "ballot_cast")]
    BallotCast {
        market_id: String,
        side: String,
        amount: u64,
        tx_id: String,
    },

    /// A prediction market was settled (threshold reached, outcome determined).
    #[serde(rename = "market_settled")]
    MarketSettled {
        market_id: String,
        outcome: String,
        payout_ratio: String,
    },

}

// Rate Limiter

/// Maximum requests per IP per window.
const RATE_LIMIT_MAX_REQUESTS: u32 = 100;

/// Sliding window duration in seconds.
const RATE_LIMIT_WINDOW_SECS: u64 = 60;

/// Maximum concurrent WebSocket connections (I-2).
const WS_MAX_CONNECTIONS: usize = 1000;
/// Maximum concurrent WebSocket connections per IP address.
const WS_MAX_CONNECTIONS_PER_IP: usize = 10;

/// Maximum subscriptions per WebSocket client (I-2).
const WS_MAX_SUBSCRIPTIONS_PER_CLIENT: usize = 50;

/// Per-IP request counter with sliding window.
#[derive(Clone)]
struct RateLimiterState {
    inner: Arc<Mutex<HashMap<IpAddr, (u32, Instant)>>>,
    last_cleanup: Arc<Mutex<Instant>>,
}

impl RateLimiterState {
    fn new() -> Self {
        RateLimiterState {
            inner: Arc::new(Mutex::new(HashMap::new())),
            last_cleanup: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Check if the request from `ip` should be allowed.
    /// Returns `true` if allowed, `false` if rate-limited.
    ///
    /// Periodically evicts entries older than the rate limit window to prevent
    /// unbounded HashMap growth from unique IPs (I-1 fix).
    async fn check(&self, ip: IpAddr) -> bool {
        let mut map = self.inner.lock().await;
        let now = Instant::now();

        // Periodic eviction: sweep stale entries every RATE_LIMIT_WINDOW_SECS
        {
            let mut last = self.last_cleanup.lock().await;
            if now.duration_since(*last).as_secs() >= RATE_LIMIT_WINDOW_SECS {
                let before = map.len();
                map.retain(|_, (_, ts)| now.duration_since(*ts).as_secs() < RATE_LIMIT_WINDOW_SECS);
                let evicted = before - map.len();
                if evicted > 0 {
                    tracing::debug!(
                        "[RATE LIMIT] Evicted {} stale entries ({} remaining)",
                        evicted,
                        map.len()
                    );
                }
                *last = now;
            }
        }

        let entry = map.entry(ip).or_insert((0, now));

        // If the window has elapsed, reset the counter
        if now.duration_since(entry.1).as_secs() >= RATE_LIMIT_WINDOW_SECS {
            entry.0 = 0;
            entry.1 = now;
        }

        entry.0 += 1;
        entry.0 <= RATE_LIMIT_MAX_REQUESTS
    }
}

/// Axum middleware that enforces per-IP rate limiting.
async fn rate_limit_middleware(
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    axum::extract::State(limiter): axum::extract::State<RateLimiterState>,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> impl IntoResponse {
    if !limiter.check(addr.ip()).await {
        tracing::warn!(
            "[API] Rate limit exceeded for {} ({}/min)",
            addr.ip(),
            RATE_LIMIT_MAX_REQUESTS,
        );
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "rate limit exceeded",
        )
            .into_response();
    }
    next.run(request).await.into_response()
}

// Router

/// Global WebSocket connection counter, shared across all handlers (I-2).
static WS_CONNECTION_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Per-IP WebSocket connection counter to prevent single-IP resource exhaustion.
static WS_PER_IP_CONNECTIONS: std::sync::LazyLock<Mutex<HashMap<IpAddr, usize>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Build the axum Router with all REST and WS endpoints.
///
/// Includes per-IP rate limiting (~100 req/min) and CORS.
pub fn build_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let rate_limiter = RateLimiterState::new();

    Router::new()
        .route("/api/v1/pairs", get(handle_pairs))
        .route("/api/v1/depth", get(handle_depth))
        .route("/api/v1/trades", get(handle_trades))
        .route("/api/v1/klines", get(handle_klines))
        .route("/api/v1/ticker", get(handle_ticker))
        .route("/api/v1/spread", get(handle_spread))
        .route("/api/v1/order", get(handle_order))
        .route("/api/v1/cross-pair-trades", get(handle_cross_pair_trades))
        .route("/api/v1/stop-orders", get(handle_list_stop_orders).post(handle_submit_stop_order))
        .route("/api/v1/stop-orders/cancel", post(handle_cancel_stop_order))
        .route("/api/v1/trailing-stops", get(handle_list_trailing_stops).post(handle_submit_trailing_stop))
        .route("/api/v1/trailing-stops/cancel", post(handle_cancel_trailing_stop))
        .route("/api/v1/ifd", get(handle_list_ifd).post(handle_submit_ifd))
        .route("/api/v1/ifd/cancel", post(handle_cancel_ifd))
        .route("/api/v1/ifo", post(handle_submit_ifo))
        .route("/api/v1/ifo/cancel", post(handle_cancel_ifo))
        .route("/api/v1/status", get(handle_status))
        .route("/api/v1/health", get(handle_health))
        .route("/api/v1/sync", get(handle_sync))
        .route("/api/v1/wallet/utxos", get(handle_wallet_utxos))
        // --- Perp endpoints ---
        .route("/api/v1/perp/orderbook", get(handle_perp_orderbook))
        .route("/api/v1/perp/positions", get(handle_perp_positions))
        // --- Lending endpoints ---
        .route("/api/v1/lending/offers", get(handle_lending_offers))
        .route("/api/v1/lending/requests", get(handle_lending_requests))
        .route("/api/v1/lending/loans", get(handle_lending_loans))
        .route("/api/v1/lending/rates", get(handle_lending_rates))
        // --- Prediction endpoints ---
        .route("/api/v1/prediction/markets", get(handle_pred_markets))
        .route("/ws", get(handle_ws_upgrade))
        .layer(DefaultBodyLimit::max(65_536)) // 64 KB body limit (H-2)
        .layer(cors)
        .route_layer(middleware::from_fn_with_state(
            rate_limiter,
            rate_limit_middleware,
        ))
        .with_state(state)
}

/// Start the API server on the given bind address and port.
pub async fn start_server(state: AppState, port: u16, bind: &str) {
    let router = build_router(state);
    let addr = format!("{}:{}", bind, port);
    tracing::info!("[API] Starting server on {}", addr);

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("[API] Failed to bind {}: {}", addr, e);
            return;
        }
    };

    if let Err(e) = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    {
        tracing::error!("[API] Server error: {}", e);
    }
}

// Query Parameters

#[derive(Deserialize)]
pub struct PairQuery {
    pub pair: String,
}

#[derive(Deserialize)]
pub struct DepthQuery {
    pub pair: String,
    #[serde(default = "default_depth_limit")]
    pub limit: usize,
}

fn default_depth_limit() -> usize {
    20
}

#[derive(Deserialize)]
pub struct TradesQuery {
    pub pair: String,
    #[serde(default = "default_trades_limit")]
    pub limit: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_daa: Option<u64>,
}

fn default_trades_limit() -> usize {
    100
}

#[derive(Deserialize)]
pub struct KlinesQuery {
    pub pair: String,
    #[serde(default = "default_klines_interval")]
    pub interval: String,
    #[serde(default = "default_klines_limit")]
    pub limit: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<u64>,
}

fn default_klines_interval() -> String {
    "1m".to_string()
}

fn default_klines_limit() -> usize {
    100
}

#[derive(Deserialize)]
pub struct OrderQuery {
    pub txid: String,
}

#[derive(Deserialize)]
pub struct CrossPairTradesQuery {
    #[serde(default = "default_cross_pair_limit")]
    pub limit: usize,
}

fn default_cross_pair_limit() -> usize {
    50
}

// Response Types

#[derive(Serialize)]
struct PairInfo {
    pair: String,
    bids: usize,
    asks: usize,
}

#[derive(Serialize)]
struct DepthResponse {
    bids: Vec<[String; 2]>,
    asks: Vec<[String; 2]>,
    #[serde(rename = "lastUpdateId")]
    last_update_id: u64,
}

#[derive(Serialize)]
struct TradeResponse {
    txid: String,
    /// P1 fix: disambiguates multiple trade records that share one
    /// settlement txid (cross-pair swaps, v17 N:M sweeps).
    /// `(txid, leg_index)` is the stable trade key.
    #[serde(rename = "legIndex")]
    leg_index: u32,
    price: String,
    qty: String,
    side: Side,
    #[serde(rename = "daaScore")]
    daa_score: u64,
    timestamp: u64,
}

#[derive(Serialize)]
struct KlineResponse {
    t: u64,
    o: String,
    h: String,
    l: String,
    c: String,
    v: String,
    n: u32,
}

#[derive(Serialize)]
struct TickerResponse {
    last: Option<String>,
    high: Option<String>,
    low: Option<String>,
    volume: u64,
    count: usize,
    bid: Option<String>,
    ask: Option<String>,
    spread: Option<String>,
}

#[derive(Serialize)]
struct SpreadResponse {
    pair: String,
    best_bid: Option<String>,
    best_ask: Option<String>,
    spread: Option<String>,
}

#[derive(Serialize)]
struct OrderResponse {
    txid: String,
    pair: String,
    side: String,
    price: String,
    value: u64,
    #[serde(rename = "minFill")]
    min_fill: u64,
    #[serde(rename = "postOnly")]
    post_only: bool,
}

#[derive(Serialize)]
struct StatusResponse {
    uptime_secs: u64,
    pairs: usize,
    total_orders: usize,
    total_trades: usize,
}

/// `GET /api/v1/health` response.
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    node_connected: bool,
    uptime_secs: u64,
}

/// `GET /api/v1/sync` response.
#[derive(Serialize)]
struct SyncResponse {
    cursor_daa: u64,
    sink_daa: u64,
    lag_blocks: u64,
    caught_up: bool,
    caught_up_threshold: u64,
    scanning_state: ScanningState,
    last_block_hash: String,
    node_connected: bool,
    uptime_secs: u64,
    pairs: usize,
    total_orders: usize,
}

#[derive(Serialize)]
struct CrossPairTradeResponse {
    txid: String,
    #[serde(rename = "legIndex")]
    leg_index: u32,
    #[serde(rename = "pairId")]
    pair_id: String,
    price: String,
    qty: String,
    side: Side,
    #[serde(rename = "daaScore")]
    daa_score: u64,
    timestamp: u64,
    routing: CrossPairRoutingResponse,
}

#[derive(Serialize)]
struct CrossPairRoutingResponse {
    #[serde(rename = "sellPair")]
    sell_pair: String,
    #[serde(rename = "buyPair")]
    buy_pair: String,
    #[serde(rename = "intermediateToken")]
    intermediate_token: String,
    #[serde(rename = "kasThrough")]
    kas_through: u64,
    #[serde(rename = "sellPrice")]
    sell_price: String,
    #[serde(rename = "buyPrice")]
    buy_price: String,
    surplus: u64,
    /// Effective rate: kas_through / quantity (as rational string).
    #[serde(rename = "effectiveRate")]
    effective_rate: String,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

fn price_str(num: u64, den: u64) -> String {
    format!("{}/{}", num, den)
}

fn json_error(status: StatusCode, msg: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: msg.to_string(),
        }),
    )
}

/// Aggregate bids at each price level (sum quantities at same price).
fn aggregate_bids(
    book: &crate::matcher::order_book::PairBook,
    limit: usize,
) -> Vec<[String; 2]> {
    let mut levels: Vec<(u64, u64, u64)> = Vec::new(); // (price_num, price_den, total_value)
    for (_, order) in book.bids.iter().take(limit * 2) {
        if let Some(last) = levels.last_mut() {
            // Same price level? (cross-multiply comparison)
            let same = (last.0 as u128) * (order.price_den as u128)
                == (order.price_num as u128) * (last.1 as u128);
            if same {
                last.2 = last.2.saturating_add(order.value);
                continue;
            }
        }
        if levels.len() >= limit {
            break;
        }
        levels.push((order.price_num, order.price_den, order.value));
    }
    levels
        .into_iter()
        .map(|(n, d, v)| [price_str(n, d), v.to_string()])
        .collect()
}

/// Aggregate asks at each price level (sum quantities at same price).
fn aggregate_asks(
    book: &crate::matcher::order_book::PairBook,
    limit: usize,
) -> Vec<[String; 2]> {
    let mut levels: Vec<(u64, u64, u64)> = Vec::new();
    for (_, order) in book.asks.iter().take(limit * 2) {
        if let Some(last) = levels.last_mut() {
            let same = (last.0 as u128) * (order.price_den as u128)
                == (order.price_num as u128) * (last.1 as u128);
            if same {
                last.2 = last.2.saturating_add(order.value);
                continue;
            }
        }
        if levels.len() >= limit {
            break;
        }
        levels.push((order.price_num, order.price_den, order.value));
    }
    levels
        .into_iter()
        .map(|(n, d, v)| [price_str(n, d), v.to_string()])
        .collect()
}

// REST Handlers

async fn handle_pairs(
    State(state): State<AppState>,
) -> Json<Vec<PairInfo>> {
    let s = state.read().await;
    let ob = s.order_book.lock().await;
    let mut pairs: Vec<PairInfo> = ob
        .pair_books
        .iter()
        .filter(|(_, book)| !book.bids.is_empty() || !book.asks.is_empty())
        .map(|(pair, book)| PairInfo {
            pair: pair.clone(),
            bids: book.bids.len(),
            asks: book.asks.len(),
        })
        .collect();
    pairs.sort_by(|a, b| a.pair.cmp(&b.pair));
    Json(pairs)
}

async fn handle_depth(
    State(state): State<AppState>,
    Query(params): Query<DepthQuery>,
) -> Result<Json<DepthResponse>, (StatusCode, Json<ErrorResponse>)> {
    let limit = params.limit.min(100);
    let s = state.read().await;
    let ob = s.order_book.lock().await;
    let book = ob
        .pair_books
        .get(&params.pair)
        .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "Trading pair not found. Use GET /api/v1/pairs to list available pairs"))?;

    Ok(Json(DepthResponse {
        bids: aggregate_bids(book, limit),
        asks: aggregate_asks(book, limit),
        last_update_id: s.update_id,
    }))
}

async fn handle_trades(
    State(state): State<AppState>,
    Query(params): Query<TradesQuery>,
) -> Json<Vec<TradeResponse>> {
    let limit = params.limit.min(1000);
    let s = state.read().await;
    let mem_trades = if params.start_time.is_some() || params.end_time.is_some() {
        s.trade_log
            .range(&params.pair, params.start_time, params.end_time, limit)
    } else if let Some(from_daa) = params.from_daa {
        let all = s.trade_log.since(&params.pair, from_daa);
        // since() returns oldest-first; reverse to newest-first and limit
        all.into_iter().rev().take(limit).collect()
    } else {
        s.trade_log.recent(&params.pair, limit)
    };

    // Fall back to SQLite history when in-memory is empty and time range given
    if !mem_trades.is_empty() || params.start_time.is_none() {
        return Json(
            mem_trades
                .into_iter()
                .map(|t| TradeResponse {
                    txid: t.txid.clone(),
                    leg_index: t.leg_index,
                    price: price_str(t.price_num, t.price_den),
                    qty: t.quantity.to_string(),
                    side: t.side,
                    daa_score: t.daa_score,
                    timestamp: t.timestamp,
                })
                .collect(),
        );
    }

    // Ticks are in-memory only (clients hold their own tick history)
    Json(vec![])
}

async fn handle_klines(
    State(state): State<AppState>,
    Query(params): Query<KlinesQuery>,
) -> Result<Json<Vec<KlineResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let interval = Interval::parse_interval(&params.interval)
        .ok_or_else(|| json_error(StatusCode::BAD_REQUEST, "Invalid kline interval. Valid values: 1m, 5m, 15m, 1h, 4h, 1d"))?;
    let limit = params.limit.min(1000);
    let s = state.read().await;
    let mem_candles = if params.start_time.is_some() || params.end_time.is_some() {
        s.candles
            .get_candles_range(&params.pair, interval, params.start_time, params.end_time, limit)
    } else {
        s.candles.get_candles(&params.pair, interval, limit)
    };

    // If in-memory is empty and time range given, fall back to SQLite.
    // HistoryStore aggregates higher TFs from M1 on the fly (MT5 style).
    if mem_candles.is_empty() && (params.start_time.is_some() || params.end_time.is_some()) {
        if let Some(ref history) = s.history {
            let start = params.start_time.unwrap_or(0);
            let end = params.end_time.unwrap_or(u64::MAX);
            if let Ok(db_candles) = history.query_candles(&params.pair, interval, start, end, limit) {
                return Ok(Json(
                    db_candles
                        .iter()
                        .map(|c| KlineResponse {
                            t: c.open_time,
                            o: price_str(c.open.0, c.open.1),
                            h: price_str(c.high.0, c.high.1),
                            l: price_str(c.low.0, c.low.1),
                            c: price_str(c.close.0, c.close.1),
                            v: c.volume.to_string(),
                            n: c.trade_count,
                        })
                        .collect(),
                ));
            }
        }
    }

    Ok(Json(
        mem_candles
            .into_iter()
            .map(|c| KlineResponse {
                t: c.open_time,
                o: price_str(c.open.0, c.open.1),
                h: price_str(c.high.0, c.high.1),
                l: price_str(c.low.0, c.low.1),
                c: price_str(c.close.0, c.close.1),
                v: c.volume.to_string(),
                n: c.trade_count,
            })
            .collect(),
    ))
}

async fn handle_ticker(
    State(state): State<AppState>,
    Query(params): Query<PairQuery>,
) -> Result<Json<TickerResponse>, (StatusCode, Json<ErrorResponse>)> {
    let s = state.read().await;

    // Get 24h trades for volume/high/low
    let now_approx = s.start_time.elapsed().as_secs();
    let day_ago_daa = now_approx.saturating_sub(86400);
    let trades_24h = s.trade_log.since(&params.pair, day_ago_daa);

    let (last, high, low, volume, count) = if trades_24h.is_empty() {
        (None, None, None, 0u64, 0usize)
    } else {
        let mut high_n: u64 = 0;
        let mut high_d: u64 = 1;
        let mut low_n: u64 = u64::MAX;
        let mut low_d: u64 = 1;
        let mut vol: u64 = 0;

        for t in &trades_24h {
            // high comparison
            if (t.price_num as u128) * (high_d as u128) > (high_n as u128) * (t.price_den as u128)
            {
                high_n = t.price_num;
                high_d = t.price_den;
            }
            // low comparison
            if (t.price_num as u128) * (low_d as u128) < (low_n as u128) * (t.price_den as u128) {
                low_n = t.price_num;
                low_d = t.price_den;
            }
            vol = vol.saturating_add(t.quantity);
        }

        // SAFETY: trades_24h is non-empty (checked by is_empty() guard above)
        let last_trade = trades_24h.last().expect("trades_24h confirmed non-empty");
        (
            Some(price_str(last_trade.price_num, last_trade.price_den)),
            Some(price_str(high_n, high_d)),
            Some(price_str(low_n, low_d)),
            vol,
            trades_24h.len(),
        )
    };

    // Best bid/ask from order book
    let ob = s.order_book.lock().await;
    let (bid, ask) = if let Some(book) = ob.pair_books.get(&params.pair) {
        let best_bid = book.bids.iter().next().map(|(_, o)| price_str(o.price_num, o.price_den));
        let best_ask = book.asks.iter().next().map(|(_, o)| price_str(o.price_num, o.price_den));
        (best_bid, best_ask)
    } else {
        (None, None)
    };

    // Compute spread as rational string if both bid and ask exist
    let spread = if let (Some(ref b), Some(ref a)) = (&bid, &ask) {
        // Parse back the rationals to compute spread
        if let (Some(bp), Some(ap)) = (parse_price_str(b), parse_price_str(a)) {
            // spread = ask - bid = ap.0/ap.1 - bp.0/bp.1 = (ap.0*bp.1 - bp.0*ap.1) / (ap.1*bp.1)
            // spread = ask - bid = (ap.0*bp.1 - bp.0*ap.1) / (ap.1*bp.1)
            let an = ap.0 as u128 * bp.1 as u128;
            let bn = bp.0 as u128 * ap.1 as u128;
            if an >= bn {
                let sn = an - bn;
                let sd = ap.1 as u128 * bp.1 as u128;
                Some(format!("{}/{}", sn, sd))
            } else {
                Some("0/1".to_string()) // negative spread (crossing)
            }
        } else {
            None
        }
    } else {
        None
    };

    Ok(Json(TickerResponse {
        last,
        high,
        low,
        volume,
        count,
        bid,
        ask,
        spread,
    }))
}

async fn handle_spread(
    State(state): State<AppState>,
    Query(params): Query<PairQuery>,
) -> Result<Json<SpreadResponse>, (StatusCode, Json<ErrorResponse>)> {
    let s = state.read().await;
    let ob = s.order_book.lock().await;

    let (best_bid, best_ask) = if let Some(book) = ob.pair_books.get(&params.pair) {
        let bid = book.bids.iter().next().map(|(_, o)| price_str(o.price_num, o.price_den));
        let ask = book.asks.iter().next().map(|(_, o)| price_str(o.price_num, o.price_den));
        (bid, ask)
    } else {
        (None, None)
    };

    let spread = if let (Some(ref b), Some(ref a)) = (&best_bid, &best_ask) {
        if let (Some(bp), Some(ap)) = (parse_price_str(b), parse_price_str(a)) {
            let an = ap.0 as u128 * bp.1 as u128;
            let bn = bp.0 as u128 * ap.1 as u128;
            if an >= bn {
                let sn = an - bn;
                let sd = ap.1 as u128 * bp.1 as u128;
                Some(format!("{}/{}", sn, sd))
            } else {
                Some("0/1".to_string())
            }
        } else {
            None
        }
    } else {
        None
    };

    Ok(Json(SpreadResponse {
        pair: params.pair,
        best_bid,
        best_ask,
        spread,
    }))
}

fn parse_price_str(s: &str) -> Option<(u64, u64)> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() == 2 {
        let n = parts[0].parse().ok()?;
        let d: u64 = parts[1].parse().ok()?;
        if d == 0 {
            return None;
        }
        Some((n, d))
    } else {
        None
    }
}

async fn handle_order(
    State(state): State<AppState>,
    Query(params): Query<OrderQuery>,
) -> Result<Json<OrderResponse>, (StatusCode, Json<ErrorResponse>)> {
    let s = state.read().await;
    let ob = s.order_book.lock().await;
    if let Some((pair, order)) = ob.get_order_by_txid(&params.txid) {
        let side = match order.side {
            crate::matcher::order_book::OrderSide::Buy => "buy",
            crate::matcher::order_book::OrderSide::Sell => "sell",
        };
        return Ok(Json(OrderResponse {
            txid: order.tx_id.clone(),
            pair: pair.to_string(),
            side: side.to_string(),
            price: price_str(order.price_num, order.price_den),
            value: order.value,
            min_fill: order.min_fill,
            post_only: order.post_only,
        }));
    }
    Err(json_error(StatusCode::NOT_FOUND, "order not found"))
}

async fn handle_cross_pair_trades(
    State(state): State<AppState>,
    Query(params): Query<CrossPairTradesQuery>,
) -> Json<Vec<CrossPairTradeResponse>> {
    let limit = params.limit.min(500);
    let s = state.read().await;
    let trades = s.trade_log.recent_cross_pair(limit);
    Json(
        trades
            .into_iter()
            .filter_map(|t| {
                let routing = t.routing.as_ref()?;
                Some(CrossPairTradeResponse {
                    txid: t.txid.clone(),
                    leg_index: t.leg_index,
                    pair_id: t.pair_id.clone(),
                    price: price_str(t.price_num, t.price_den),
                    qty: t.quantity.to_string(),
                    side: t.side,
                    daa_score: t.daa_score,
                    timestamp: t.timestamp,
                    routing: CrossPairRoutingResponse {
                        sell_pair: routing.sell_pair.clone(),
                        buy_pair: routing.buy_pair.clone(),
                        intermediate_token: routing.intermediate_token.clone(),
                        kas_through: routing.kas_through,
                        sell_price: price_str(routing.sell_price_num, routing.sell_price_den),
                        buy_price: price_str(routing.buy_price_num, routing.buy_price_den),
                        surplus: routing.surplus,
                        effective_rate: if t.quantity > 0 {
                            price_str(routing.kas_through, t.quantity)
                        } else {
                            "0/1".to_string()
                        },
                    },
                })
            })
            .collect(),
    )
}

async fn handle_status(
    State(state): State<AppState>,
) -> Json<StatusResponse> {
    let s = state.read().await;
    let ob = s.order_book.lock().await;
    let stats = ob.stats();
    Json(StatusResponse {
        uptime_secs: s.start_time.elapsed().as_secs(),
        pairs: stats.pairs,
        total_orders: stats.total_bids + stats.total_asks,
        total_trades: s.trade_log.total_count(),
    })
}

/// `GET /api/v1/health` -- cheap liveness/readiness probe for process
/// supervisors / load balancers. Reads only the SharedState RwLock and
/// plain fields; deliberately does NOT touch the order-book mutex (which
/// can be held for the duration of settlement logic) so a busy matcher
/// never makes this endpoint look down. Returns 503 when the node
/// connection is unhealthy.
async fn handle_health(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let s = state.read().await;
    let node_connected = s.sync.node_connected;
    let uptime_secs = s.start_time.elapsed().as_secs();
    let status = if node_connected { "ok" } else { "down" };
    let code = if node_connected { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    (
        code,
        Json(HealthResponse { status, node_connected, uptime_secs }),
    )
}

/// `GET /api/v1/sync` -- is the scanner caught up? Exposes the gap between
/// the persisted scan cursor and the node's sink DAA (`lag_blocks`), the
/// derived `scanning_state` (steady/catching_up/stalled -- see
/// `compute_scanning_state`), and book/pair counts + node connectivity.
/// This is precisely the signal that would have flagged the documented
/// catch-up-hangs-at-0%-CPU failure mode before it silently stalled
/// discovery for hours.
async fn handle_sync(State(state): State<AppState>) -> Json<SyncResponse> {
    let s = state.read().await;
    let lag_blocks = s.sync.lag_blocks();
    let (pairs, total_orders) = {
        let ob = s.order_book.lock().await;
        let stats = ob.stats();
        (stats.pairs, stats.total_bids + stats.total_asks)
    };
    Json(SyncResponse {
        cursor_daa: s.sync.cursor_daa,
        sink_daa: s.sync.sink_daa,
        lag_blocks,
        caught_up: s.sync.caught_up(DEFAULT_CAUGHT_UP_THRESHOLD),
        caught_up_threshold: DEFAULT_CAUGHT_UP_THRESHOLD,
        scanning_state: s.sync.scanning_state,
        last_block_hash: s.sync.cursor_block_hash.clone(),
        node_connected: s.sync.node_connected,
        uptime_secs: s.start_time.elapsed().as_secs(),
        pairs,
        total_orders,
    })
}

// Wallet UTXO endpoint

/// Query params for `/api/v1/wallet/utxos`.
#[derive(Deserialize)]
struct WalletUtxosQuery {
    address: String,
    #[serde(default)]
    min_amount: Option<u64>,
}

/// Response row for `/api/v1/wallet/utxos`.
///
/// Shape mirrors the flattened fields of `kob_core::rpc_types::RpcUtxo`
/// (transactionId + index + amount + scriptPublicKey + ...), with
/// `scriptPublicKey` emitted as a single hex string (`version` LE-encoded as
/// 4 hex chars + script hex) for compactness. Clients should re-wrap into the
/// nested Kaspad shape if they need to pass it back to the node.
///
/// `covenantId` (optional, lowercase hex) mirrors the node's `covenantId`
/// field on `utxoEntry` — required for callers that need to distinguish
/// covenant-bound UTXOs (e.g., fresh token mints vs. incompatible match-
/// merged token UTXOs when auto-selecting a sell-deploy token input).
#[derive(Serialize)]
struct WalletUtxoResponse {
    /// Concatenated outpoint key "txid:index" for convenience.
    outpoint: String,
    #[serde(rename = "transactionId")]
    transaction_id: String,
    index: u32,
    amount: u64,
    #[serde(rename = "scriptPublicKey")]
    script_public_key: String,
    #[serde(rename = "blockDaaScore")]
    block_daa_score: u64,
    #[serde(rename = "isCoinbase")]
    is_coinbase: bool,
    #[serde(rename = "covenantId", skip_serializing_if = "Option::is_none")]
    covenant_id: Option<String>,
}

/// GET `/api/v1/wallet/utxos?address=...&min_amount=...` — return the UTXOs
/// for `address` filtered through the engine's spent-outpoint tracking.
///
/// Returns 503 if the engine was not built with an RPC handle (e.g., in tests
/// or when `with_rpc` was not called), and 502 on node RPC failure.
async fn handle_wallet_utxos(
    State(state): State<AppState>,
    Query(params): Query<WalletUtxosQuery>,
) -> Result<Json<Vec<WalletUtxoResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let s = state.read().await;
    let rpc_arc = s.rpc.clone().ok_or_else(|| {
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Engine RPC not configured",
        )
    })?;
    // Release the SharedState read lock before the (potentially slow) RPC call
    // so other handlers aren't blocked.
    drop(s);

    let rpc = rpc_arc.lock().await;
    let utxos = rpc
        .get_spendable_utxos(&params.address, params.min_amount)
        .await
        .map_err(|e| json_error(StatusCode::BAD_GATEWAY, &format!("RPC error: {}", e)))?;
    drop(rpc);

    let rows: Vec<WalletUtxoResponse> = utxos
        .into_iter()
        .map(|u| WalletUtxoResponse {
            outpoint: format!("{}:{}", u.outpoint.transaction_id, u.outpoint.index),
            transaction_id: u.outpoint.transaction_id,
            index: u.outpoint.index,
            amount: u.utxo_entry.amount,
            script_public_key: format!(
                "{:04x}{}",
                u.utxo_entry.script_public_key.version,
                u.utxo_entry.script_public_key.script
            ),
            block_daa_score: u.utxo_entry.block_daa_score,
            is_coinbase: u.utxo_entry.is_coinbase,
            covenant_id: u.utxo_entry.covenant_id,
        })
        .collect();
    Ok(Json(rows))
}

// IFD / IFO Handlers

/// Request body for submitting an IFD order.
#[derive(Deserialize)]
struct SubmitIfdRequest {
    order_a: IfdOrderARequest,
    order_b: IfdOrderBRequest,
    owner_id: String,
    /// Owner hash (hex, 64 chars) — Blake2b of owner pubkey.
    owner_hash: String,
    /// Owner SPK hash (hex, 64 chars) — for B's bspkh/sspkh.
    owner_spk_hash: String,
    /// Maximum matcher fee (sompi) — PRE-v18 wire field, kept for request
    /// compatibility. v18 IFD builds B with the shared
    /// `DEFAULT_MAX_MATCHER_FEE_BPS` (P2SH must match the trigger-time RS).
    #[serde(default = "default_max_matcher_fee")]
    #[allow(dead_code)]
    max_matcher_fee: u64,
}

fn default_max_matcher_fee() -> u64 {
    5000
}

#[derive(Deserialize)]
struct IfdOrderARequest {
    side: crate::matcher::ifd::IfdSide,
    token: String,
    price_num: u64,
    price_den: u64,
    amount: u64,
    min_fill: u64,
    #[serde(default)]
    expiry_daa: u64,
}

#[derive(Deserialize)]
struct IfdOrderBRequest {
    side: crate::matcher::ifd::IfdSide,
    token: String,
    price_num: u64,
    price_den: u64,
    /// 0 = use proceeds from A.
    amount: u64,
    min_fill: u64,
    #[serde(default)]
    expiry_daa: u64,
}

/// Request body for submitting an IFO order (IFD + OCO).
#[derive(Deserialize)]
struct SubmitIfoRequest {
    order_a: IfdOrderARequest,
    token: String,
    /// 0 = use proceeds from A.
    amount: u64,
    #[serde(default)]
    expiry_daa: u64,
    tp_side: crate::matcher::ifd::IfdSide,
    tp_price_num: u64,
    tp_price_den: u64,
    tp_min_fill: u64,
    sl_side: crate::matcher::ifd::IfdSide,
    sl_price_num: u64,
    sl_price_den: u64,
    sl_min_fill: u64,
    owner_id: String,
    owner_hash: String,
    /// Owner SPK (hex, 72 chars = 36 bytes) — for OCO v4 contracts.
    owner_spk: String,
}

/// Request body for cancelling an IFD/IFO rule.
#[derive(Deserialize)]
struct CancelIfdRequest {
    id: u64,
    owner_id: String,
    /// Cancel secret returned at submission time.
    #[serde(default)]
    cancel_secret: Option<String>,
}

/// Query params for listing IFD rules.
#[derive(Deserialize)]
struct ListIfdQuery {
    #[serde(default)]
    owner_id: Option<String>,
}

async fn handle_list_ifd(
    State(state): State<AppState>,
    Query(params): Query<ListIfdQuery>,
) -> Json<serde_json::Value> {
    let s = state.read().await;
    let book = s.ifd_book.lock().await;

    let rules: Vec<&crate::matcher::ifd::IfdRule> = if let Some(ref owner) = params.owner_id {
        book.list_by_owner(owner)
    } else {
        book.list_active()
    };

    let items: Vec<serde_json::Value> = rules
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "status": r.status,
                "order_a_p2sh": r.order_a_p2sh,
                "order_a_outpoint": r.order_a_outpoint,
                "order_b_p2sh": r.order_b_p2sh,
                "order_b_spk_hash": r.order_b_spk_hash,
                "trigger_tx_id": r.trigger_tx_id,
                "created_at": r.created_at,
                "owner_id": r.owner_id,
            })
        })
        .collect();

    Json(serde_json::json!({
        "rules": items,
        "total": book.len(),
        "active": book.active_count(),
    }))
}

async fn handle_submit_ifd(
    State(state): State<AppState>,
    Json(req): Json<SubmitIfdRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Parse owner hashes
    let owner_hash = match parse_hex_32_api(&req.owner_hash) {
        Ok(h) => h,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))),
    };
    let owner_spk_hash = match parse_hex_32_api(&req.owner_spk_hash) {
        Ok(h) => h,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))),
    };

    // Compute order B's scripts
    let b_params = crate::matcher::ifd::OrderBParams {
        side: req.order_b.side,
        token: req.order_b.token.clone(),
        price_num: req.order_b.price_num,
        price_den: req.order_b.price_den,
        amount: req.order_b.amount,
        min_fill: req.order_b.min_fill,
        expiry_daa: req.order_b.expiry_daa,
    };

    // v18 done-leg: automatically sweep/batch-eligible under the v18
    // planners. The fee is the shared BPS constant (v18 builders reject the
    // legacy sompi-scale value); registration and trigger must agree on it
    // or the precomputed P2SH won't match the deployed order.
    let (b_rs, b_p2sh_hex, b_spk_hash_hex) = match crate::matcher::ifd::compute_order_b_scripts_v18(
        &b_params,
        &owner_hash,
        &owner_spk_hash,
        crate::DEFAULT_MAX_MATCHER_FEE_BPS,
    ) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))),
    };

    // For buy A -> sell B: A's bspkh should be set to B's SPK hash.
    // The CLI must use b_spk_hash when deploying order A.
    // For buy A -> buy B: needs extra KAS funding (TODO: phase 2).

    // Compute order A's P2SH (informational — the user deploys A themselves).
    // We need A's RS to compute its P2SH so we can detect it on L1.
    let a_params_core = crate::matcher::ifd::OrderAParams {
        side: req.order_a.side,
        token: req.order_a.token.clone(),
        price_num: req.order_a.price_num,
        price_den: req.order_a.price_den,
        amount: req.order_a.amount,
        min_fill: req.order_a.min_fill,
        expiry_daa: req.order_a.expiry_daa,
    };

    // Compute A's P2SH. For buy A -> sell B, A's bspkh = B's SPK hash.
    let a_bspkh = if req.order_a.side == crate::matcher::ifd::IfdSide::Buy
        && req.order_b.side == crate::matcher::ifd::IfdSide::Sell
    {
        // Tokens from buy A go to sell B's P2SH
        b_spk_hash_hex.clone()
    } else {
        // Default: tokens go to owner
        req.owner_spk_hash.clone()
    };

    let a_bspkh_bytes = match parse_hex_32_api(&a_bspkh) {
        Ok(h) => h,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))),
    };

    let a_token_bytes = match parse_hex_32_api(&req.order_a.token) {
        Ok(h) => h,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))),
    };

    // Order A is deployed by the user as a v18 order (deploy paths are
    // v18-only); this P2SH must match that deploy byte-exact.
    let a_rs = match req.order_a.side {
        crate::matcher::ifd::IfdSide::Buy => {
            match kob_core::contract::spot::order::build_buy_v18_redeem_script(
                &a_token_bytes,
                req.order_a.price_num,
                req.order_a.price_den,
                req.order_a.min_fill,
                &owner_hash,
                &a_bspkh_bytes, crate::DEFAULT_MAX_MATCHER_FEE_BPS,
                0,
                req.order_a.expiry_daa,) {
                Ok(v) => v,
                Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e.to_string() }))),
            }
        }
        crate::matcher::ifd::IfdSide::Sell => {
            match kob_core::contract::spot::order::build_sell_v18_redeem_script(
                req.order_a.price_num,
                req.order_a.price_den,
                req.order_a.min_fill,
                &owner_hash,
                &a_bspkh_bytes, crate::DEFAULT_MAX_MATCHER_FEE_BPS,
                0,
                req.order_a.expiry_daa,) {
                Ok(v) => v,
                Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e.to_string() }))),
            }
        }
    };

    let a_p2sh_spk = kob_core::p2sh::build_p2sh(&a_rs);
    let a_p2sh_hex = hex::encode(&a_p2sh_spk.script());

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let cancel_secret = generate_cancel_secret();
    let rule = crate::matcher::ifd::IfdRule {
        id: 0,
        order_a_params: a_params_core,
        order_a_p2sh: a_p2sh_hex.clone(),
        order_a_outpoint: None,
        order_b: crate::matcher::ifd::OrderBType::Simple(b_params),
        order_b_rs_hex: hex::encode(&b_rs),
        order_b_p2sh: b_p2sh_hex.clone(),
        order_b_spk_hash: b_spk_hash_hex.clone(),
        status: crate::matcher::ifd::IfdStatus::Pending,
        trigger_tx_id: None,
        created_at: now_unix,
        owner_id: req.owner_id,
        cancel_secret: Some(cancel_secret.clone()),
    };

    let s = state.read().await;
    let mut book = s.ifd_book.lock().await;
    match book.register(rule) {
        Ok(id) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "ifd_id": id,
                "order_a_p2sh": a_p2sh_hex,
                "order_a_bspkh": a_bspkh,
                "order_b_p2sh": b_p2sh_hex,
                "order_b_spk_hash": b_spk_hash_hex,
                "status": "pending",
                "cancel_secret": cancel_secret,
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        ),
    }
}

async fn handle_submit_ifo(
    State(state): State<AppState>,
    Json(req): Json<SubmitIfoRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let owner_hash = match parse_hex_32_api(&req.owner_hash) {
        Ok(h) => h,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))),
    };

    let owner_spk_bytes = match hex::decode(&req.owner_spk) {
        Ok(b) if b.len() == 36 => {
            let mut arr = [0u8; 36];
            arr.copy_from_slice(&b);
            arr
        }
        Ok(b) => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("owner_spk must be 36 bytes, got {}", b.len()) })),
        ),
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": format!("invalid owner_spk hex: {}", e) }))),
    };

    // Compute owner SPK hash from owner_spk bytes
    let owner_spk_hash = kob_core::p2sh::compute_spk_hash(
        u16::from_le_bytes([owner_spk_bytes[0], owner_spk_bytes[1]]),
        &owner_spk_bytes[2..],
    );

    let oco_params = crate::matcher::ifd::IfoOcoParams {
        tp_side: req.tp_side,
        tp_price_num: req.tp_price_num,
        tp_price_den: req.tp_price_den,
        tp_min_fill: req.tp_min_fill,
        sl_side: req.sl_side,
        sl_price_num: req.sl_price_num,
        sl_price_den: req.sl_price_den,
        sl_min_fill: req.sl_min_fill,
    };

    // Compute OCO B script (single v18 oco_sell with TP + SL paths — both
    // branches sweep-eligible via the canonical attestation)
    let (oco_rs, oco_p2sh_hex) = match crate::matcher::ifd::compute_oco_b_scripts_v18(
        &req.token,
        &oco_params,
        &owner_hash,
        &owner_spk_bytes,
        crate::DEFAULT_MAX_MATCHER_FEE_BPS,
    ) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))),
    };

    // Single oco_sell UTXO: both TP and SL share the same P2SH.
    let oco_p2sh_spk = kob_core::p2sh::build_p2sh(&oco_rs);
    let oco_spk_hash = kob_core::p2sh::compute_spk_hash(oco_p2sh_spk.version, &oco_p2sh_spk.script());
    let oco_spk_hash_hex = hex::encode(oco_spk_hash);

    // Compute order A's P2SH
    let a_token_bytes = match parse_hex_32_api(&req.order_a.token) {
        Ok(h) => h,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))),
    };

    // For buy A -> OCO B: A's bspkh = oco_sell's SPK hash (tokens flow to oco_sell)
    let a_bspkh = if req.order_a.side == crate::matcher::ifd::IfdSide::Buy {
        oco_spk_hash
    } else {
        owner_spk_hash
    };

    let a_rs = match req.order_a.side {
        crate::matcher::ifd::IfdSide::Buy => {
            match kob_core::contract::spot::order::build_buy_v18_redeem_script(
                &a_token_bytes,
                req.order_a.price_num,
                req.order_a.price_den,
                req.order_a.min_fill,
                &owner_hash,
                &a_bspkh, crate::DEFAULT_MAX_MATCHER_FEE_BPS,
                0,
                req.order_a.expiry_daa,) {
                Ok(v) => v,
                Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e.to_string() }))),
            }
        }
        crate::matcher::ifd::IfdSide::Sell => {
            match kob_core::contract::spot::order::build_sell_v18_redeem_script(
                req.order_a.price_num,
                req.order_a.price_den,
                req.order_a.min_fill,
                &owner_hash,
                &a_bspkh, crate::DEFAULT_MAX_MATCHER_FEE_BPS,
                0,
                req.order_a.expiry_daa,) {
                Ok(v) => v,
                Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e.to_string() }))),
            }
        }
    };

    let a_p2sh_spk = kob_core::p2sh::build_p2sh(&a_rs);
    let a_p2sh_hex = hex::encode(&a_p2sh_spk.script());

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let a_params_core = crate::matcher::ifd::OrderAParams {
        side: req.order_a.side,
        token: req.order_a.token.clone(),
        price_num: req.order_a.price_num,
        price_den: req.order_a.price_den,
        amount: req.order_a.amount,
        min_fill: req.order_a.min_fill,
        expiry_daa: req.order_a.expiry_daa,
    };

    let cancel_secret = generate_cancel_secret();
    let rule = crate::matcher::ifd::IfdRule {
        id: 0,
        order_a_params: a_params_core,
        order_a_p2sh: a_p2sh_hex.clone(),
        order_a_outpoint: None,
        order_b: crate::matcher::ifd::OrderBType::Oco {
            token: req.token.clone(),
            amount: req.amount,
            expiry_daa: req.expiry_daa,
            oco: oco_params,
        },
        order_b_rs_hex: hex::encode(&oco_rs),
        order_b_p2sh: oco_p2sh_hex.clone(),
        order_b_spk_hash: oco_spk_hash_hex.clone(),
        status: crate::matcher::ifd::IfdStatus::Pending,
        trigger_tx_id: None,
        created_at: now_unix,
        owner_id: req.owner_id,
        cancel_secret: Some(cancel_secret.clone()),
    };

    let s = state.read().await;
    let mut book = s.ifd_book.lock().await;
    match book.register(rule) {
        Ok(id) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "ifo_id": id,
                "order_a_p2sh": a_p2sh_hex,
                "order_a_bspkh": hex::encode(a_bspkh),
                "oco_sell_p2sh": oco_p2sh_hex,
                "oco_sell_spk_hash": oco_spk_hash_hex,
                "status": "pending",
                "cancel_secret": cancel_secret,
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        ),
    }
}

async fn handle_cancel_ifd(
    State(state): State<AppState>,
    Json(req): Json<CancelIfdRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let s = state.read().await;
    let mut book = s.ifd_book.lock().await;
    match book.cancel(req.id, &req.owner_id, req.cancel_secret.as_deref()) {
        Some(_) => (
            StatusCode::OK,
            Json(serde_json::json!({ "id": req.id, "status": "cancelled" })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "IFD rule not found. Verify the rule ID exists, belongs to you, and has not already been triggered" })),
        ),
    }
}

async fn handle_cancel_ifo(
    State(state): State<AppState>,
    Json(req): Json<CancelIfdRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let s = state.read().await;
    let mut book = s.ifd_book.lock().await;
    match book.cancel(req.id, &req.owner_id, req.cancel_secret.as_deref()) {
        Some(_) => (
            StatusCode::OK,
            Json(serde_json::json!({ "id": req.id, "status": "cancelled" })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "IFO rule not found. Verify the rule ID exists, belongs to you, and has not already been triggered" })),
        ),
    }
}

fn parse_hex_32_api(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("must be 64 hex characters (32 bytes), got {} bytes", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

// Stop Order Handlers

/// Request body for submitting a stop order via REST.
#[derive(Deserialize)]
struct SubmitStopOrderRequest {
    pair: String,
    side: crate::matcher::stop_book::StopSide,
    stop_price_num: u64,
    stop_price_den: u64,
    order_type: crate::matcher::stop_book::StopOrderType,
    signed_tx_json: String,
    owner_id: String,
    #[serde(default)]
    expires_at: Option<u64>,
}

/// Request body for cancelling a stop order.
#[derive(Deserialize)]
struct CancelStopOrderRequest {
    id: u64,
    owner_id: String,
    /// Cancel secret returned at submission time.
    #[serde(default)]
    cancel_secret: Option<String>,
}

/// Query params for listing stop orders.
#[derive(Deserialize)]
struct ListStopOrdersQuery {
    #[serde(default)]
    owner_id: Option<String>,
    #[serde(default)]
    pair: Option<String>,
}

async fn handle_list_stop_orders(
    State(state): State<AppState>,
    Query(params): Query<ListStopOrdersQuery>,
) -> Json<serde_json::Value> {
    let s = state.read().await;
    let book = s.stop_book.lock().await;

    let orders: Vec<&crate::matcher::stop_book::StopOrder> = if let Some(ref owner) = params.owner_id {
        book.list_by_owner(owner)
    } else if let Some(ref pair) = params.pair {
        book.list_by_pair(pair).iter().collect()
    } else {
        // Return summary only (no owner/pair filter)
        return Json(serde_json::json!({
            "total": book.len(),
            "pairs": book.pair_count(),
        }));
    };

    let items: Vec<serde_json::Value> = orders
        .iter()
        .map(|o| {
            serde_json::json!({
                "id": o.id,
                "pair": o.pair,
                "side": o.side,
                "stop_price_num": o.stop_price_num,
                "stop_price_den": o.stop_price_den,
                "order_type": o.order_type,
                "owner_id": o.owner_id,
                "created_at": o.created_at,
                "expires_at": o.expires_at,
                "triggered": o.triggered,
            })
        })
        .collect();

    Json(serde_json::json!({ "orders": items }))
}

async fn handle_submit_stop_order(
    State(state): State<AppState>,
    Json(req): Json<SubmitStopOrderRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let cancel_secret = generate_cancel_secret();
    let order = crate::matcher::stop_book::StopOrder {
        id: 0,
        pair: req.pair,
        side: req.side,
        stop_price_num: req.stop_price_num,
        stop_price_den: req.stop_price_den,
        order_type: req.order_type,
        signed_tx_json: req.signed_tx_json,
        owner_id: req.owner_id,
        created_at: now_unix,
        expires_at: req.expires_at,
        triggered: false,
        trigger_tx_id: None,
        cancel_secret: Some(cancel_secret.clone()),
        broadcast_attempts: 0,
    };

    let s = state.read().await;
    let mut book = s.stop_book.lock().await;
    match book.add(order) {
        Ok(id) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "id": id, "status": "accepted", "cancel_secret": cancel_secret })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        ),
    }
}

async fn handle_cancel_stop_order(
    State(state): State<AppState>,
    Json(req): Json<CancelStopOrderRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let s = state.read().await;
    let mut book = s.stop_book.lock().await;
    match book.cancel_by_owner(req.id, &req.owner_id, req.cancel_secret.as_deref()) {
        Some(_) => (
            StatusCode::OK,
            Json(serde_json::json!({ "id": req.id, "status": "cancelled" })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "stop order not found, not owned by you, or wrong cancel_secret" })),
        ),
    }
}

// Trailing Stop Handlers

/// Request body for submitting a trailing stop order.
#[derive(Deserialize)]
struct SubmitTrailingStopRequest {
    pair_id: String,
    side: crate::matcher::trailing_stop::TrailingStopSide,
    trail_spec: crate::matcher::trailing_stop::TrailSpec,
    signed_tx_hex: String,
    initial_price_num: u64,
    initial_price_den: u64,
    owner_id: String,
    #[serde(default)]
    created_at_daa: u64,
}

/// Request body for cancelling a trailing stop.
#[derive(Deserialize)]
struct CancelTrailingStopRequest {
    id: u64,
    owner_id: String,
    /// Cancel secret returned at submission time.
    #[serde(default)]
    cancel_secret: Option<String>,
}

async fn handle_list_trailing_stops(
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    let s = state.read().await;
    let book = s.trailing_stop_book.lock().await;

    let active = book.list_active();
    let items: Vec<serde_json::Value> = active
        .iter()
        .map(|o| {
            serde_json::json!({
                "id": o.id,
                "pair_id": o.pair_id,
                "side": o.side,
                "trail_spec": o.trail_spec,
                "peak_price_num": o.peak_price_num,
                "peak_price_den": o.peak_price_den,
                "current_stop_num": o.current_stop_num,
                "current_stop_den": o.current_stop_den,
                "owner_id": o.owner_id,
                "triggered": o.triggered,
            })
        })
        .collect();

    Json(serde_json::json!({
        "total": book.len(),
        "orders": items,
    }))
}

async fn handle_submit_trailing_stop(
    State(state): State<AppState>,
    Json(req): Json<SubmitTrailingStopRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let cancel_secret = generate_cancel_secret();
    let s = state.read().await;
    let mut book = s.trailing_stop_book.lock().await;

    let add_result = book.add(
        req.pair_id,
        req.side,
        req.trail_spec,
        req.signed_tx_hex,
        req.initial_price_num,
        req.initial_price_den,
        req.owner_id,
        req.created_at_daa,
    );
    match add_result {
        Some(id) => {
            // Set cancel_secret on the newly created order
            if let Some(order) = book.get_mut(id) {
                order.cancel_secret = Some(cancel_secret.clone());
            }
            (
                StatusCode::CREATED,
                Json(serde_json::json!({ "id": id, "status": "accepted", "cancel_secret": cancel_secret })),
            )
        }
        None => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "trailing stop order rejected (capacity or invalid params)" })),
        ),
    }
}

async fn handle_cancel_trailing_stop(
    State(state): State<AppState>,
    Json(req): Json<CancelTrailingStopRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let s = state.read().await;
    let mut book = s.trailing_stop_book.lock().await;

    match book.remove_by_owner(req.id, &req.owner_id, req.cancel_secret.as_deref()) {
        Some(_) => (
            StatusCode::OK,
            Json(serde_json::json!({ "id": req.id, "status": "cancelled" })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "trailing stop order not found, not owned by you, or wrong cancel_secret" })),
        ),
    }
}

// WebSocket Handler

/// WS subscription message from client.
#[derive(Deserialize)]
struct WsRequest {
    method: String,
    #[serde(default)]
    params: Vec<String>,
}

// Perp Handlers

/// Perp order book: list open Long and Short orders.
async fn handle_perp_orderbook(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let s = state.read().await;
    if let Some(ref book) = s.perp_book {
        let b = book.lock().await;
        Json(serde_json::json!({
            "longs": b.long_count(),
            "shorts": b.short_count(),
            "status": "active"
        }))
    } else {
        Json(serde_json::json!({
            "longs": 0,
            "shorts": 0,
            "status": "not_initialized"
        }))
    }
}

/// Perp positions: list tracked open positions.
async fn handle_perp_positions(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let s = state.read().await;
    if let Some(ref tracker) = s.perp_tracker {
        let t: tokio::sync::MutexGuard<'_, PositionTracker> = tracker.lock().await;
        Json(serde_json::json!({
            "positions": t.count(),
            "status": "active"
        }))
    } else {
        Json(serde_json::json!({
            "positions": 0,
            "status": "not_initialized"
        }))
    }
}

// Lending Handlers

/// Lending offers: list open loan offers.
async fn handle_lending_offers(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let s = state.read().await;
    if let Some(ref book) = s.lending_book {
        let b = book.lock().await;
        Json(serde_json::json!({
            "offers": b.offer_count(),
            "status": "active"
        }))
    } else {
        Json(serde_json::json!({
            "offers": 0,
            "status": "not_initialized"
        }))
    }
}

/// Lending requests: list open borrow requests.
async fn handle_lending_requests(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let s = state.read().await;
    if let Some(ref book) = s.lending_book {
        let b = book.lock().await;
        Json(serde_json::json!({
            "requests": b.request_count(),
            "status": "active"
        }))
    } else {
        Json(serde_json::json!({
            "requests": 0,
            "status": "not_initialized"
        }))
    }
}

/// Lending loans: list active loans.
async fn handle_lending_loans(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let s = state.read().await;
    if let Some(ref tracker) = s.loan_tracker {
        let t = tracker.lock().await;
        Json(serde_json::json!({
            "active_loans": t.count(),
            "status": "active"
        }))
    } else {
        Json(serde_json::json!({
            "active_loans": 0,
            "status": "not_initialized"
        }))
    }
}

/// Lending rates: current market rates summary.
async fn handle_lending_rates(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let s = state.read().await;
    if let Some(ref book) = s.lending_book {
        let b = book.lock().await;
        let best_offer = b.best_offer_rate()
            .map(|(n, d)| format!("{}/{}", n, d));
        let best_request = b.best_request_rate()
            .map(|(n, d)| format!("{}/{}", n, d));
        Json(serde_json::json!({
            "best_offer_rate": best_offer,
            "best_request_rate": best_request,
            "status": "active"
        }))
    } else {
        Json(serde_json::json!({
            "best_offer_rate": null,
            "best_request_rate": null,
            "status": "not_initialized"
        }))
    }
}

// Prediction Handlers

/// Prediction markets: list active prediction markets.
async fn handle_pred_markets(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let s = state.read().await;
    if let Some(ref book) = s.prediction_book {
        let b = book.lock().await;
        Json(serde_json::json!({
            "markets": b.market_count(),
            "status": "active"
        }))
    } else {
        Json(serde_json::json!({
            "markets": 0,
            "status": "not_initialized"
        }))
    }
}

// WebSocket

async fn handle_ws_upgrade(
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Enforce global WebSocket connection limit (I-2)
    let current = WS_CONNECTION_COUNT.load(AtomicOrdering::Relaxed);
    if current >= WS_MAX_CONNECTIONS {
        tracing::warn!(
            "[WS] Connection rejected: global limit reached ({}/{})",
            current,
            WS_MAX_CONNECTIONS,
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "WebSocket connection limit reached",
        )
            .into_response();
    }

    // Enforce per-IP WebSocket connection limit
    let ip = addr.ip();
    {
        let map = WS_PER_IP_CONNECTIONS.lock().await;
        let count = map.get(&ip).copied().unwrap_or(0);
        if count >= WS_MAX_CONNECTIONS_PER_IP {
            tracing::warn!(
                "[WS] Connection rejected: per-IP limit reached for {} ({}/{})",
                ip,
                count,
                WS_MAX_CONNECTIONS_PER_IP,
            );
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "Per-IP WebSocket connection limit reached",
            )
                .into_response();
        }
    }

    ws.on_upgrade(move |socket| handle_ws_connection(socket, state, ip))
        .into_response()
}

async fn handle_ws_connection(mut socket: WebSocket, state: AppState, ip: IpAddr) {
    // Track connection count (I-2)
    WS_CONNECTION_COUNT.fetch_add(1, AtomicOrdering::Relaxed);
    let _guard = WsConnectionGuard; // decrements global count on drop

    // Track per-IP connection count
    {
        let mut map = WS_PER_IP_CONNECTIONS.lock().await;
        *map.entry(ip).or_insert(0) += 1;
    }
    let _ip_guard = WsPerIpGuard(ip); // decrements per-IP count on drop

    let mut rx = {
        let s = state.read().await;
        s.ws_broadcaster.subscribe()
    };

    let mut subscriptions: HashSet<String> = HashSet::new();

    loop {
        tokio::select! {
            // Incoming message from client
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(req) = serde_json::from_str::<WsRequest>(&text) {
                            match req.method.as_str() {
                                "subscribe" => {
                                    // Enforce per-client subscription limit (I-2)
                                    let new_count = req.params.iter()
                                        .filter(|p| !subscriptions.contains(*p))
                                        .count();
                                    if subscriptions.len() + new_count > WS_MAX_SUBSCRIPTIONS_PER_CLIENT {
                                        let err = serde_json::json!({
                                            "error": format!(
                                                "subscription limit exceeded (max {})",
                                                WS_MAX_SUBSCRIPTIONS_PER_CLIENT
                                            ),
                                        });
                                        if socket.send(Message::Text(err.to_string())).await.is_err() {
                                            return;
                                        }
                                        continue;
                                    }
                                    for param in &req.params {
                                        subscriptions.insert(param.clone());
                                    }
                                    let ack = serde_json::json!({
                                        "result": "subscribed",
                                        "params": req.params,
                                    });
                                    if socket.send(Message::Text(ack.to_string())).await.is_err() {
                                        return;
                                    }
                                }
                                "unsubscribe" => {
                                    for param in &req.params {
                                        subscriptions.remove(param);
                                    }
                                    let ack = serde_json::json!({
                                        "result": "unsubscribed",
                                        "params": req.params,
                                    });
                                    if socket.send(Message::Text(ack.to_string())).await.is_err() {
                                        return;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => return,
                    Some(Err(_)) => return,
                    _ => {}
                }
            }
            // Broadcast event from matcher
            event = rx.recv() => {
                match event {
                    Ok(ev) => {
                        if should_forward(&ev, &subscriptions) {
                            if let Ok(json) = serde_json::to_string(&ev) {
                                if socket.send(Message::Text(json)).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("[WS] Client lagged, skipped {} events", n);
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        }
    }
}

/// RAII guard that decrements the global WebSocket connection counter on drop.
struct WsConnectionGuard;

impl Drop for WsConnectionGuard {
    fn drop(&mut self) {
        WS_CONNECTION_COUNT.fetch_sub(1, AtomicOrdering::Relaxed);
    }
}

/// RAII guard that decrements the per-IP WebSocket connection counter on drop.
struct WsPerIpGuard(IpAddr);

impl Drop for WsPerIpGuard {
    fn drop(&mut self) {
        // Use try_lock to avoid blocking in drop; if contended, spawn a task.
        match WS_PER_IP_CONNECTIONS.try_lock() {
            Ok(mut map) => {
                if let Some(count) = map.get_mut(&self.0) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        map.remove(&self.0);
                    }
                }
            }
            Err(_) => {
                // Mutex is contended; spawn a task to clean up asynchronously.
                let ip = self.0;
                tokio::spawn(async move {
                    let mut map = WS_PER_IP_CONNECTIONS.lock().await;
                    if let Some(count) = map.get_mut(&ip) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            map.remove(&ip);
                        }
                    }
                });
            }
        }
    }
}

/// Check if a WS event matches any of the client's subscriptions.
///
/// Subscription patterns:
///   - `depth:<pair>`           — order book depth updates
///   - `trades:<pair>`          — public trade feed
///   - `kline:<pair>:<interval>`— OHLCV candles
///   - `user_orders:<owner_hash>` — private order lifecycle events
fn should_forward(event: &WsEvent, subscriptions: &HashSet<String>) -> bool {
    match event {
        WsEvent::DepthUpdate { pair, .. } => {
            subscriptions.contains(&format!("depth:{}", pair))
        }
        WsEvent::Trade { pair, .. } => {
            subscriptions.contains(&format!("trades:{}", pair))
        }
        WsEvent::Kline { pair, interval, .. } => {
            subscriptions.contains(&format!("kline:{}:{}", pair, interval))
        }
        WsEvent::OrderFilled { owner_hash, .. }
        | WsEvent::OrderPartiallyFilled { owner_hash, .. }
        | WsEvent::OrderCancelled { owner_hash, .. }
        | WsEvent::OrderDetected { owner_hash, .. } => {
            subscriptions.contains(&format!("user_orders:{}", owner_hash))
        }
        // --- Perp events ---
        WsEvent::PerpTrade { .. }
        | WsEvent::PerpLiquidation { .. }
        | WsEvent::PerpOrderBookUpdate { .. } => {
            subscriptions.contains("perp")
        }
        // --- Lending events ---
        WsEvent::LendingMatch { .. }
        | WsEvent::LoanLiquidated { .. }
        | WsEvent::LoanRepaid { .. } => {
            subscriptions.contains("lending")
        }
        // --- Prediction events ---
        WsEvent::MarketCreated { .. }
        | WsEvent::BallotCast { .. }
        | WsEvent::MarketSettled { .. } => {
            subscriptions.contains("prediction")
        }
    }
}

// User Order Event Emission Helpers

/// Emit an OrderFilled event through the WS broadcaster.
///
/// Called by the executor after a full match consumes an order.
pub fn emit_order_filled(
    broadcaster: &broadcast::Sender<WsEvent>,
    owner_hash: &str,
    outpoint: &str,
    tx_id: &str,
    fill_price_num: u64,
    fill_price_den: u64,
    fill_amount: u64,
    side: OrderSide,
    pair: &str,
) {
    let event = WsEvent::OrderFilled {
        owner_hash: owner_hash.to_string(),
        outpoint: outpoint.to_string(),
        tx_id: tx_id.to_string(),
        fill_price: price_str(fill_price_num, fill_price_den),
        fill_amount,
        side,
        pair: pair.to_string(),
    };
    // Ignore send errors (no subscribers connected).
    let _ = broadcaster.send(event);
}

/// Emit an OrderPartiallyFilled event through the WS broadcaster.
///
/// Called by the executor after a partial fill leaves a remainder.
pub fn emit_order_partially_filled(
    broadcaster: &broadcast::Sender<WsEvent>,
    owner_hash: &str,
    outpoint: &str,
    tx_id: &str,
    filled_amount: u64,
    remaining_amount: u64,
    fill_price_num: u64,
    fill_price_den: u64,
    side: OrderSide,
    pair: &str,
) {
    let event = WsEvent::OrderPartiallyFilled {
        owner_hash: owner_hash.to_string(),
        outpoint: outpoint.to_string(),
        tx_id: tx_id.to_string(),
        filled_amount,
        remaining_amount,
        fill_price: price_str(fill_price_num, fill_price_den),
        side,
        pair: pair.to_string(),
    };
    let _ = broadcaster.send(event);
}

/// Emit an OrderCancelled event through the WS broadcaster.
///
/// Called by the scanner when a known order is spent by a non-match TX
/// (i.e., a cancel).
pub fn emit_order_cancelled(
    broadcaster: &broadcast::Sender<WsEvent>,
    owner_hash: &str,
    outpoint: &str,
    cancel_tx_id: &str,
    pair: &str,
) {
    let event = WsEvent::OrderCancelled {
        owner_hash: owner_hash.to_string(),
        outpoint: outpoint.to_string(),
        cancel_tx_id: cancel_tx_id.to_string(),
        pair: pair.to_string(),
    };
    let _ = broadcaster.send(event);
}

/// Emit an OrderDetected event through the WS broadcaster.
///
/// Called by the scanner when a new order is discovered on L1.
pub fn emit_order_detected(
    broadcaster: &broadcast::Sender<WsEvent>,
    owner_hash: &str,
    outpoint: &str,
    side: OrderSide,
    price_num: u64,
    price_den: u64,
    amount: u64,
    pair: &str,
) {
    let event = WsEvent::OrderDetected {
        owner_hash: owner_hash.to_string(),
        outpoint: outpoint.to_string(),
        side,
        price: price_str(price_num, price_den),
        amount,
        pair: pair.to_string(),
    };
    let _ = broadcaster.send(event);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::order_book::{BookOrder, OrderSide};

    fn make_state() -> AppState {
        let (tx, _) = broadcast::channel(100);
        let ob = Arc::new(Mutex::new(OrderBook::new()));
        let sb = Arc::new(Mutex::new(StopOrderBook::new()));
        let tb = Arc::new(Mutex::new(TrailingStopBook::new()));
        Arc::new(RwLock::new(SharedState::new(tx, ob, sb, tb)))
    }

    fn make_buy_order(tx_id: &str, pair: &str, price_num: u64, price_den: u64, value: u64) -> BookOrder {
        BookOrder {
            tx_id: tx_id.to_string(),
            index: 0,
            value,
            token_cov_id: pair.to_string(),
            price_num,
            price_den,
            min_fill: 1_000_000,
            owner_hash: "aa".repeat(32),
            spk_hash: "bb".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Buy,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0,
        }
    }

    fn make_sell_order(tx_id: &str, pair: &str, price_num: u64, price_den: u64, value: u64) -> BookOrder {
        BookOrder {
            tx_id: tx_id.to_string(),
            index: 0,
            value,
            token_cov_id: pair.to_string(),
            price_num,
            price_den,
            min_fill: 1_000_000,
            owner_hash: "cc".repeat(32),
            spk_hash: "dd".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Sell,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0,
        }
    }

    #[test]
    fn test_price_str() {
        assert_eq!(price_str(100, 1), "100/1");
        assert_eq!(price_str(3, 4), "3/4");
        assert_eq!(price_str(0, 1), "0/1");
    }

    #[test]
    fn test_parse_price_str() {
        assert_eq!(parse_price_str("100/1"), Some((100, 1)));
        assert_eq!(parse_price_str("3/4"), Some((3, 4)));
        assert_eq!(parse_price_str("invalid"), None);
        assert_eq!(parse_price_str(""), None);
        assert_eq!(parse_price_str("100/0"), None);
    }

    #[test]
    fn test_aggregate_bids() {
        let mut book = crate::matcher::order_book::PairBook::new();
        // Two bids at same price, one at different
        book.add_bid(make_buy_order("tx1", "pair", 100, 1, 5_000_000));
        book.add_bid(make_buy_order("tx2", "pair", 100, 1, 3_000_000));
        book.add_bid(make_buy_order("tx3", "pair", 90, 1, 4_000_000));

        let levels = aggregate_bids(&book, 20);
        assert_eq!(levels.len(), 2);
        assert_eq!(levels[0][0], "100/1");
        assert_eq!(levels[0][1], "8000000"); // 5M + 3M
        assert_eq!(levels[1][0], "90/1");
        assert_eq!(levels[1][1], "4000000");
    }

    #[test]
    fn test_aggregate_asks() {
        let mut book = crate::matcher::order_book::PairBook::new();
        book.add_ask(make_sell_order("tx1", "pair", 110, 1, 2_000_000));
        book.add_ask(make_sell_order("tx2", "pair", 120, 1, 6_000_000));

        let levels = aggregate_asks(&book, 20);
        assert_eq!(levels.len(), 2);
        assert_eq!(levels[0][0], "110/1");
        assert_eq!(levels[1][0], "120/1");
    }

    #[test]
    fn test_depth_limit() {
        let mut book = crate::matcher::order_book::PairBook::new();
        for i in 0..50 {
            book.add_bid(make_buy_order(
                &format!("tx{}", i),
                "pair",
                100 - i as u64,
                1,
                1_000_000,
            ));
        }
        let levels = aggregate_bids(&book, 5);
        assert!(levels.len() <= 5);
    }

    #[test]
    fn test_ws_event_depth_serialization() {
        let event = WsEvent::DepthUpdate {
            pair: "abcd".to_string(),
            bids: vec![["100/1".to_string(), "5000000".to_string()]],
            asks: vec![],
            update_id: 42,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"stream\":\"depth\""));
        assert!(json.contains("\"updateId\":42"));
    }

    #[test]
    fn test_ws_event_trade_serialization() {
        let event = WsEvent::Trade {
            pair: "abcd".to_string(),
            txid: "tx123".to_string(),
            leg_index: 0,
            price: "100/1".to_string(),
            qty: "50".to_string(),
            side: Side::Buy,
            daa_score: 999,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"stream\":\"trade\""));
        assert!(json.contains("\"side\":\"buy\""));
    }

    #[test]
    fn test_ws_event_kline_serialization() {
        let event = WsEvent::Kline {
            pair: "abcd".to_string(),
            interval: "1m".to_string(),
            o: "100/1".to_string(),
            h: "110/1".to_string(),
            l: "90/1".to_string(),
            c: "105/1".to_string(),
            v: "500".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"stream\":\"kline\""));
        assert!(json.contains("\"interval\":\"1m\""));
    }

    #[test]
    fn test_should_forward_depth() {
        let mut subs = HashSet::new();
        subs.insert("depth:pairA".to_string());

        let ev_match = WsEvent::DepthUpdate {
            pair: "pairA".to_string(),
            bids: vec![],
            asks: vec![],
            update_id: 1,
        };
        assert!(should_forward(&ev_match, &subs));

        let ev_no_match = WsEvent::DepthUpdate {
            pair: "pairB".to_string(),
            bids: vec![],
            asks: vec![],
            update_id: 1,
        };
        assert!(!should_forward(&ev_no_match, &subs));
    }

    #[test]
    fn test_should_forward_trade() {
        let mut subs = HashSet::new();
        subs.insert("trades:pairA".to_string());

        let ev = WsEvent::Trade {
            pair: "pairA".to_string(),
            txid: "tx1".to_string(),
            leg_index: 0,
            price: "1/1".to_string(),
            qty: "1".to_string(),
            side: Side::Sell,
            daa_score: 1,
        };
        assert!(should_forward(&ev, &subs));
    }

    #[test]
    fn test_should_forward_kline() {
        let mut subs = HashSet::new();
        subs.insert("kline:pairA:1m".to_string());

        let ev = WsEvent::Kline {
            pair: "pairA".to_string(),
            interval: "1m".to_string(),
            o: "1/1".to_string(),
            h: "1/1".to_string(),
            l: "1/1".to_string(),
            c: "1/1".to_string(),
            v: "1".to_string(),
        };
        assert!(should_forward(&ev, &subs));

        let ev_5m = WsEvent::Kline {
            pair: "pairA".to_string(),
            interval: "5m".to_string(),
            o: "1/1".to_string(),
            h: "1/1".to_string(),
            l: "1/1".to_string(),
            c: "1/1".to_string(),
            v: "1".to_string(),
        };
        assert!(!should_forward(&ev_5m, &subs));
    }

    #[test]
    fn test_ws_subscription_parsing() {
        let json = r#"{"method": "subscribe", "params": ["depth:pairA", "trades:pairA"]}"#;
        let req: WsRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "subscribe");
        assert_eq!(req.params.len(), 2);
        assert_eq!(req.params[0], "depth:pairA");
    }

    #[test]
    fn test_ws_unsubscribe_parsing() {
        let json = r#"{"method": "unsubscribe", "params": ["depth:pairA"]}"#;
        let req: WsRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "unsubscribe");
        assert_eq!(req.params.len(), 1);
    }

    #[tokio::test]
    async fn test_status_endpoint() {
        let state = make_state();
        let response = handle_status(State(state)).await;
        assert_eq!(response.0.pairs, 0);
        assert_eq!(response.0.total_orders, 0);
        assert_eq!(response.0.total_trades, 0);
    }

    // H4-SYNC: compute_scanning_state pure state machine

    #[test]
    fn scanning_state_steady_when_within_threshold() {
        assert_eq!(compute_scanning_state(0, 10, None), ScanningState::Steady);
        assert_eq!(compute_scanning_state(10, 10, None), ScanningState::Steady, "exactly at threshold is steady");
        assert_eq!(compute_scanning_state(5, 10, Some(1000)), ScanningState::Steady, "steady regardless of prior lag");
    }

    #[test]
    fn scanning_state_catching_up_on_first_reading_beyond_threshold() {
        assert_eq!(compute_scanning_state(500, 10, None), ScanningState::CatchingUp, "no prior reading yet -- assume progress");
    }

    #[test]
    fn scanning_state_catching_up_when_lag_shrinking() {
        assert_eq!(compute_scanning_state(400, 10, Some(500)), ScanningState::CatchingUp);
    }

    #[test]
    fn scanning_state_stalled_when_lag_not_decreasing() {
        assert_eq!(compute_scanning_state(500, 10, Some(500)), ScanningState::Stalled, "unchanged lag == stalled");
        assert_eq!(compute_scanning_state(600, 10, Some(500)), ScanningState::Stalled, "growing lag == stalled");
    }

    // H4-SYNC: SyncSnapshot

    #[test]
    fn sync_snapshot_default_is_not_yet_steady() {
        let snap = SyncSnapshot::default();
        assert_eq!(snap.cursor_daa, 0);
        assert_eq!(snap.sink_daa, 0);
        assert!(!snap.node_connected);
        assert_eq!(snap.scanning_state, ScanningState::CatchingUp);
    }

    #[test]
    fn sync_snapshot_update_computes_lag_and_caught_up() {
        let mut snap = SyncSnapshot::default();
        snap.update(1000, "hash_a".to_string(), 1005, true, 10);
        assert_eq!(snap.lag_blocks(), 5);
        assert!(snap.caught_up(10));
        assert_eq!(snap.scanning_state, ScanningState::Steady);
        assert_eq!(snap.cursor_block_hash, "hash_a");
    }

    #[test]
    fn sync_snapshot_update_detects_stall_across_calls() {
        let mut snap = SyncSnapshot::default();
        snap.update(1000, "h1".to_string(), 2000, true, 10); // lag=1000, first reading -> catching_up
        assert_eq!(snap.scanning_state, ScanningState::CatchingUp);
        snap.update(1000, "h1".to_string(), 2000, true, 10); // same lag again -> stalled
        assert_eq!(snap.scanning_state, ScanningState::Stalled);
    }

    // H4-SYNC: /api/v1/health

    #[tokio::test]
    async fn test_health_endpoint_ok_when_connected() {
        let state = make_state();
        {
            let mut s = state.write().await;
            s.sync.node_connected = true;
        }
        let (code, response) = handle_health(State(state)).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(response.0.status, "ok");
        assert!(response.0.node_connected);
    }

    #[tokio::test]
    async fn test_health_endpoint_down_when_disconnected() {
        let state = make_state();
        {
            let mut s = state.write().await;
            s.sync.node_connected = false;
        }
        let (code, response) = handle_health(State(state)).await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.0.status, "down");
        assert!(!response.0.node_connected);
    }

    #[tokio::test]
    async fn test_health_endpoint_reports_uptime() {
        let state = make_state();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let (_, response) = handle_health(State(state)).await;
        // uptime is measured in whole seconds; just prove the field is wired
        // (>= 0 always true for u64, so assert the type/field access compiles
        // and the endpoint does not panic on a freshly-created state).
        let _ = response.0.uptime_secs;
    }

    // H4-SYNC: /api/v1/sync

    #[tokio::test]
    async fn test_sync_endpoint_reports_caught_up_state() {
        let state = make_state();
        {
            let mut s = state.write().await;
            s.sync.update(100, "tip_hash".to_string(), 105, true, 10);
        }
        let response = handle_sync(State(state)).await;
        assert_eq!(response.0.cursor_daa, 100);
        assert_eq!(response.0.sink_daa, 105);
        assert_eq!(response.0.lag_blocks, 5);
        assert!(response.0.caught_up);
        assert_eq!(response.0.caught_up_threshold, DEFAULT_CAUGHT_UP_THRESHOLD);
        assert_eq!(response.0.scanning_state, ScanningState::Steady);
        assert_eq!(response.0.last_block_hash, "tip_hash");
        assert!(response.0.node_connected);
    }

    #[tokio::test]
    async fn test_sync_endpoint_reports_catching_up_state() {
        let state = make_state();
        {
            let mut s = state.write().await;
            s.sync.update(100, "cursor_hash".to_string(), 5000, true, 10);
        }
        let response = handle_sync(State(state)).await;
        assert_eq!(response.0.lag_blocks, 4900);
        assert!(!response.0.caught_up);
        assert_eq!(response.0.scanning_state, ScanningState::CatchingUp);
    }

    #[tokio::test]
    async fn test_sync_endpoint_includes_book_pair_counts() {
        let state = make_state();
        {
            let s = state.write().await;
            s.order_book.lock().await.add_buy_order(make_buy_order(
                &"a".repeat(64), &"ab".repeat(32), 100, 1, 5_000_000,
            ));
        }
        let response = handle_sync(State(state)).await;
        assert_eq!(response.0.pairs, 1);
        assert_eq!(response.0.total_orders, 1);
    }

    #[tokio::test]
    async fn test_pairs_endpoint_empty() {
        let state = make_state();
        let response = handle_pairs(State(state)).await;
        assert!(response.0.is_empty());
    }

    #[tokio::test]
    async fn test_pairs_endpoint_with_orders() {
        let state = make_state();
        {
            let s = state.write().await;
            s.order_book.lock().await.add_buy_order(make_buy_order(
                &"a".repeat(64),
                &"ab".repeat(32),
                100,
                1,
                5_000_000,
            ));
        }
        let response = handle_pairs(State(state)).await;
        assert_eq!(response.0.len(), 1);
        assert_eq!(response.0[0].bids, 1);
    }

    #[tokio::test]
    async fn test_depth_endpoint() {
        let state = make_state();
        let pair = "ab".repeat(32);
        {
            let s = state.write().await;
            s.order_book.lock().await.add_buy_order(make_buy_order(
                &"a".repeat(64),
                &pair,
                100,
                1,
                5_000_000,
            ));
            s.order_book.lock().await.add_sell_order(make_sell_order(
                &"b".repeat(64),
                &pair,
                110,
                1,
                3_000_000,
            ));
        }
        let result = handle_depth(
            State(state),
            Query(DepthQuery {
                pair: pair.clone(),
                limit: 20,
            }),
        )
        .await;
        assert!(result.is_ok());
        let depth = result.unwrap().0;
        assert_eq!(depth.bids.len(), 1);
        assert_eq!(depth.asks.len(), 1);
        assert_eq!(depth.bids[0][0], "100/1");
        assert_eq!(depth.asks[0][0], "110/1");
    }

    #[tokio::test]
    async fn test_depth_endpoint_not_found() {
        let state = make_state();
        let result = handle_depth(
            State(state),
            Query(DepthQuery {
                pair: "nonexistent".to_string(),
                limit: 20,
            }),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_order_endpoint() {
        let state = make_state();
        let pair = "ab".repeat(32);
        let txid = "a".repeat(64);
        {
            let s = state.write().await;
            s.order_book.lock().await.add_buy_order(make_buy_order(&txid, &pair, 100, 1, 5_000_000));
        }
        let result = handle_order(
            State(state),
            Query(OrderQuery { txid: txid.clone() }),
        )
        .await;
        assert!(result.is_ok());
        let order = result.unwrap().0;
        assert_eq!(order.txid, txid);
        assert_eq!(order.side, "buy");
        assert_eq!(order.price, "100/1");
    }

    #[tokio::test]
    async fn test_order_endpoint_not_found() {
        let state = make_state();
        let result = handle_order(
            State(state),
            Query(OrderQuery {
                txid: "nonexistent".to_string(),
            }),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_allows_under_limit() {
        let limiter = RateLimiterState::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..RATE_LIMIT_MAX_REQUESTS {
            assert!(limiter.check(ip).await, "should allow under limit");
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_rejects_over_limit() {
        let limiter = RateLimiterState::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..RATE_LIMIT_MAX_REQUESTS {
            limiter.check(ip).await;
        }
        assert!(!limiter.check(ip).await, "should reject over limit");
    }

    #[tokio::test]
    async fn test_rate_limiter_separate_ips() {
        let limiter = RateLimiterState::new();
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.2".parse().unwrap();
        for _ in 0..RATE_LIMIT_MAX_REQUESTS {
            limiter.check(ip_a).await;
        }
        // ip_a is exhausted
        assert!(!limiter.check(ip_a).await);
        // ip_b should still be allowed
        assert!(limiter.check(ip_b).await, "different IP should have its own bucket");
    }

    #[tokio::test]
    async fn test_rate_limiter_eviction() {
        // Verify that the eviction logic doesn't panic and works correctly.
        // We can't easily test time-based eviction without sleeping, but we
        // can verify the HashMap shrinks after forced cleanup.
        let limiter = RateLimiterState::new();

        // Add many unique IPs
        for i in 0..100u32 {
            let ip: IpAddr = format!("10.0.{}.{}", i / 256, i % 256).parse().unwrap();
            limiter.check(ip).await;
        }

        // Verify all entries exist
        {
            let map = limiter.inner.lock().await;
            assert_eq!(map.len(), 100, "should have 100 entries");
        }

        // The entries are fresh (just created) so eviction won't remove them.
        // This confirms the eviction sweep runs without panic.
        let fresh_ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(limiter.check(fresh_ip).await);
    }

    #[test]
    fn test_ws_connection_count_guard() {
        // Verify the WsConnectionGuard decrements the counter on drop.
        let before = WS_CONNECTION_COUNT.load(AtomicOrdering::Relaxed);
        {
            WS_CONNECTION_COUNT.fetch_add(1, AtomicOrdering::Relaxed);
            let _guard = WsConnectionGuard;
            assert_eq!(
                WS_CONNECTION_COUNT.load(AtomicOrdering::Relaxed),
                before + 1,
            );
        }
        // After guard drop, counter should be back to original
        assert_eq!(WS_CONNECTION_COUNT.load(AtomicOrdering::Relaxed), before);
    }

    #[test]
    fn test_ws_limits_constants() {
        assert!(WS_MAX_CONNECTIONS > 0);
        assert!(WS_MAX_SUBSCRIPTIONS_PER_CLIENT > 0);
        assert!(WS_MAX_SUBSCRIPTIONS_PER_CLIENT <= 100);
    }

    // Cross-pair trades endpoint tests

    use crate::matcher::trades::{RoutingInfo, Trade};

    fn make_normal_trade(txid: &str, pair: &str, daa: u64) -> Trade {
        Trade {
            txid: txid.to_string(),
            leg_index: 0,
            pair_id: pair.to_string(),
            price_num: 1,
            price_den: 2,
            quantity: 10_000_000,
            side: Side::Buy,
            daa_score: daa,
            timestamp: daa,
            routing: None,
        }
    }

    fn make_cp_trade(txid: &str, daa: u64) -> Trade {
        Trade {
            txid: txid.to_string(),
            leg_index: 0,
            pair_id: "cross:TOKEN_A->TOKEN_B".to_string(),
            price_num: 1,
            price_den: 2,
            quantity: 10_000_000,
            side: Side::Buy,
            daa_score: daa,
            timestamp: daa,
            routing: Some(RoutingInfo {
                sell_pair: "TOKEN_A/KAS".to_string(),
                buy_pair: "TOKEN_B/KAS".to_string(),
                intermediate_token: "KAS".to_string(),
                kas_through: 5_000_000,
                sell_price_num: 1,
                sell_price_den: 2,
                buy_price_num: 1,
                buy_price_den: 3,
                surplus: 2_000_000,
            }),
        }
    }

    #[tokio::test]
    async fn test_cross_pair_trades_returns_only_routed() {
        let state = make_state();
        {
            let mut s = state.write().await;
            s.trade_log.push(make_normal_trade("tx1", "pairA", 100));
            s.trade_log.push(make_cp_trade("tx_cp1", 101));
            s.trade_log.push(make_normal_trade("tx2", "pairA", 102));
            s.trade_log.push(make_cp_trade("tx_cp2", 103));
        }

        let s = state.read().await;
        let trades = s.trade_log.recent_cross_pair(50);
        assert_eq!(trades.len(), 2);
        assert_eq!(trades[0].txid, "tx_cp2");
        assert_eq!(trades[1].txid, "tx_cp1");
    }

    #[tokio::test]
    async fn test_cross_pair_trades_routing_fields() {
        let state = make_state();
        {
            let mut s = state.write().await;
            s.trade_log.push(make_cp_trade("tx_cp1", 100));
        }

        let s = state.read().await;
        let trades = s.trade_log.recent_cross_pair(10);
        assert_eq!(trades.len(), 1);
        let routing = trades[0].routing.as_ref().unwrap();
        assert_eq!(routing.sell_pair, "TOKEN_A/KAS");
        assert_eq!(routing.buy_pair, "TOKEN_B/KAS");
        assert_eq!(routing.intermediate_token, "KAS");
        assert_eq!(routing.kas_through, 5_000_000);
        assert_eq!(routing.sell_price_num, 1);
        assert_eq!(routing.sell_price_den, 2);
        assert_eq!(routing.buy_price_num, 1);
        assert_eq!(routing.buy_price_den, 3);
        assert_eq!(routing.surplus, 2_000_000);
    }

    #[test]
    fn test_cross_pair_response_serialization() {
        let resp = CrossPairTradeResponse {
            txid: "tx_cp1".to_string(),
            leg_index: 0,
            pair_id: "cross:A->B".to_string(),
            price: "1/2".to_string(),
            qty: "10000000".to_string(),
            side: Side::Buy,
            daa_score: 100,
            timestamp: 100,
            routing: CrossPairRoutingResponse {
                sell_pair: "TOKEN_A/KAS".to_string(),
                buy_pair: "TOKEN_B/KAS".to_string(),
                intermediate_token: "KAS".to_string(),
                kas_through: 5_000_000,
                sell_price: "1/2".to_string(),
                buy_price: "1/3".to_string(),
                surplus: 2_000_000,
                effective_rate: "5000000/10000000".to_string(),
            },
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"sellPair\":\"TOKEN_A/KAS\""));
        assert!(json.contains("\"buyPair\":\"TOKEN_B/KAS\""));
        assert!(json.contains("\"intermediateToken\":\"KAS\""));
        assert!(json.contains("\"kasThrough\":5000000"));
        assert!(json.contains("\"effectiveRate\":\"5000000/10000000\""));
        assert!(json.contains("\"surplus\":2000000"));
    }

    #[tokio::test]
    async fn test_cross_pair_trades_empty_when_no_routed() {
        let state = make_state();
        {
            let mut s = state.write().await;
            s.trade_log.push(make_normal_trade("tx1", "pairA", 100));
            s.trade_log.push(make_normal_trade("tx2", "pairA", 101));
        }

        let s = state.read().await;
        let trades = s.trade_log.recent_cross_pair(50);
        assert!(trades.is_empty());
    }

    // E2E Integration: WebSocket depth diff and event generation

    /// E2E: WsEvent depth update serializes correctly.
    #[test]
    fn e2e_ws_depth_event_serialization() {
        let event = WsEvent::DepthUpdate {
            pair: "TOKEN_A/KAS".to_string(),
            bids: vec![
                ["100/1".to_string(), "5000000".to_string()],
                ["90/1".to_string(), "3000000".to_string()],
            ],
            asks: vec![
                ["110/1".to_string(), "2000000".to_string()],
            ],
            update_id: 42,
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"stream\":\"depth\""));
        assert!(json.contains("\"pair\":\"TOKEN_A/KAS\""));
        assert!(json.contains("\"updateId\":42"));
        assert!(json.contains("100/1"));
        assert!(json.contains("110/1"));
    }

    /// E2E: WsEvent trade event serializes correctly.
    #[test]
    fn e2e_ws_trade_event_serialization() {
        let event = WsEvent::Trade {
            pair: "TOKEN_B/KAS".to_string(),
            txid: "abcd1234".to_string(),
            leg_index: 0,
            price: "3/2".to_string(),
            qty: "10000000".to_string(),
            side: Side::Buy,
            daa_score: 99999,
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"stream\":\"trade\""));
        assert!(json.contains("\"pair\":\"TOKEN_B/KAS\""));
        assert!(json.contains("\"txid\":\"abcd1234\""));
        assert!(json.contains("\"side\":\"buy\""));
    }

    /// E2E: WsEvent kline event serializes correctly.
    #[test]
    fn e2e_ws_kline_event_serialization() {
        let event = WsEvent::Kline {
            pair: "TOKEN_C/KAS".to_string(),
            interval: "1m".to_string(),
            o: "100".to_string(),
            h: "110".to_string(),
            l: "95".to_string(),
            c: "105".to_string(),
            v: "50000000".to_string(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"stream\":\"kline\""));
        assert!(json.contains("\"interval\":\"1m\""));
    }

    /// E2E: should_forward filters events by subscription.
    #[test]
    fn e2e_ws_should_forward_filtering() {
        let mut subs = std::collections::HashSet::new();
        subs.insert("depth:TOKEN_A/KAS".to_string());
        subs.insert("trades:TOKEN_B/KAS".to_string());

        let depth_a = WsEvent::DepthUpdate {
            pair: "TOKEN_A/KAS".to_string(),
            bids: vec![], asks: vec![], update_id: 1,
        };
        assert!(should_forward(&depth_a, &subs), "subscribed depth should forward");

        let depth_b = WsEvent::DepthUpdate {
            pair: "TOKEN_B/KAS".to_string(),
            bids: vec![], asks: vec![], update_id: 2,
        };
        assert!(!should_forward(&depth_b, &subs), "unsubscribed depth should not forward");

        let trade_b = WsEvent::Trade {
            pair: "TOKEN_B/KAS".to_string(),
            txid: "t".to_string(), leg_index: 0, price: "1".to_string(),
            qty: "1".to_string(), side: Side::Buy, daa_score: 0,
        };
        assert!(should_forward(&trade_b, &subs), "subscribed trade should forward");

        let trade_a = WsEvent::Trade {
            pair: "TOKEN_A/KAS".to_string(),
            txid: "t".to_string(), leg_index: 0, price: "1".to_string(),
            qty: "1".to_string(), side: Side::Buy, daa_score: 0,
        };
        assert!(!should_forward(&trade_a, &subs), "unsubscribed trade stream should not forward");
    }

    /// E2E: WS broadcast channel delivers events.
    #[tokio::test]
    async fn e2e_ws_broadcast_delivery() {
        let (tx, _) = broadcast::channel::<WsEvent>(100);
        let mut rx = tx.subscribe();

        let event = WsEvent::Trade {
            pair: "TOKEN_A/KAS".to_string(),
            txid: "tx123".to_string(),
            leg_index: 0,
            price: "1/2".to_string(),
            qty: "5000000".to_string(),
            side: Side::Sell,
            daa_score: 100,
        };

        tx.send(event.clone()).unwrap();
        let received = rx.recv().await.unwrap();

        match received {
            WsEvent::Trade { pair, txid, .. } => {
                assert_eq!(pair, "TOKEN_A/KAS");
                assert_eq!(txid, "tx123");
            }
            _ => panic!("expected Trade event"),
        }
    }

    /// E2E: Depth diff generation after order book change.
    #[tokio::test]
    async fn e2e_depth_diff_after_order_add() {
        let state = make_state();
        let pair = "ab".repeat(32);

        {
            let s = state.write().await;
            s.order_book.lock().await.add_buy_order(make_buy_order(
                "a".repeat(64).as_str(), &pair, 100, 1, 10_000_000,
            ));
            s.order_book.lock().await.add_sell_order(make_sell_order(
                "b".repeat(64).as_str(), &pair, 110, 1, 5_000_000,
            ));
        }

        let s = state.read().await;
        let ob = s.order_book.lock().await;
        let stats = ob.stats();
        assert_eq!(stats.total_bids, 1);
        assert_eq!(stats.total_asks, 1);

        // Verify book can generate depth levels for WS event
        let book = ob.pair_books.get(&pair).unwrap();
        let bid_levels = aggregate_bids(book, 20);
        let ask_levels = aggregate_asks(book, 20);
        assert_eq!(bid_levels.len(), 1);
        assert_eq!(ask_levels.len(), 1);
        assert_eq!(bid_levels[0][0], "100/1");
        assert_eq!(ask_levels[0][0], "110/1");
    }

    /// E2E: SharedState trade log and candle integration.
    #[tokio::test]
    async fn e2e_shared_state_trade_candle_integration() {
        let state = make_state();

        {
            let mut s = state.write().await;
            let trade = crate::matcher::trades::Trade {
                txid: "match1".to_string(),
                leg_index: 0,
                pair_id: "TOKEN_A/KAS".to_string(),
                price_num: 100,
                price_den: 1,
                quantity: 5_000_000,
                side: Side::Buy,
                daa_score: 1000,
                timestamp: 1700000000,
                routing: None,
            };
            s.candles.on_trade(&trade);
            s.trade_log.push(trade);
            s.update_id += 1;
        }

        let s = state.read().await;
        assert_eq!(s.trade_log.len(), 1);
        assert_eq!(s.update_id, 1);
    }

    // User Order WS Event Tests

    #[test]
    fn test_ws_event_order_filled_serialization() {
        let event = WsEvent::OrderFilled {
            owner_hash: "aa".repeat(32),
            outpoint: "tx1:0".to_string(),
            tx_id: "match_tx".to_string(),
            fill_price: "100/1".to_string(),
            fill_amount: 5_000_000,
            side: OrderSide::Buy,
            pair: "ab".repeat(32),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"stream\":\"order_filled\""));
        assert!(json.contains("\"fill_amount\":5000000"));
        assert!(json.contains("\"side\":\"Buy\""));
    }

    #[test]
    fn test_ws_event_order_partially_filled_serialization() {
        let event = WsEvent::OrderPartiallyFilled {
            owner_hash: "bb".repeat(32),
            outpoint: "tx2:1".to_string(),
            tx_id: "partial_tx".to_string(),
            filled_amount: 3_000_000,
            remaining_amount: 2_000_000,
            fill_price: "50/1".to_string(),
            side: OrderSide::Sell,
            pair: "cd".repeat(32),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"stream\":\"order_partially_filled\""));
        assert!(json.contains("\"filled_amount\":3000000"));
        assert!(json.contains("\"remaining_amount\":2000000"));
    }

    #[test]
    fn test_ws_event_order_cancelled_serialization() {
        let event = WsEvent::OrderCancelled {
            owner_hash: "cc".repeat(32),
            outpoint: "tx3:0".to_string(),
            cancel_tx_id: "cancel_tx".to_string(),
            pair: "ef".repeat(32),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"stream\":\"order_cancelled\""));
        assert!(json.contains("\"cancel_tx_id\":\"cancel_tx\""));
    }

    #[test]
    fn test_ws_event_order_detected_serialization() {
        let event = WsEvent::OrderDetected {
            owner_hash: "dd".repeat(32),
            outpoint: "tx4:0".to_string(),
            side: OrderSide::Buy,
            price: "200/3".to_string(),
            amount: 10_000_000,
            pair: "ab".repeat(32),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"stream\":\"order_detected\""));
        assert!(json.contains("\"price\":\"200/3\""));
        assert!(json.contains("\"amount\":10000000"));
    }

    #[test]
    fn test_should_forward_user_orders() {
        let owner = "aa".repeat(32);
        let mut subs = HashSet::new();
        subs.insert(format!("user_orders:{}", owner));

        // Matching owner_hash -> should forward
        let ev = WsEvent::OrderFilled {
            owner_hash: owner.clone(),
            outpoint: "tx:0".to_string(),
            tx_id: "m".to_string(),
            fill_price: "1/1".to_string(),
            fill_amount: 100,
            side: OrderSide::Buy,
            pair: "p".to_string(),
        };
        assert!(should_forward(&ev, &subs));

        // Different owner_hash -> should NOT forward
        let other_owner = "bb".repeat(32);
        let ev2 = WsEvent::OrderFilled {
            owner_hash: other_owner,
            outpoint: "tx:0".to_string(),
            tx_id: "m".to_string(),
            fill_price: "1/1".to_string(),
            fill_amount: 100,
            side: OrderSide::Buy,
            pair: "p".to_string(),
        };
        assert!(!should_forward(&ev2, &subs));
    }

    #[test]
    fn test_should_forward_user_orders_all_event_types() {
        let owner = "ee".repeat(32);
        let mut subs = HashSet::new();
        subs.insert(format!("user_orders:{}", owner));

        // OrderPartiallyFilled
        let ev_partial = WsEvent::OrderPartiallyFilled {
            owner_hash: owner.clone(),
            outpoint: "tx:0".to_string(),
            tx_id: "m".to_string(),
            filled_amount: 50,
            remaining_amount: 50,
            fill_price: "1/1".to_string(),
            side: OrderSide::Sell,
            pair: "p".to_string(),
        };
        assert!(should_forward(&ev_partial, &subs));

        // OrderCancelled
        let ev_cancel = WsEvent::OrderCancelled {
            owner_hash: owner.clone(),
            outpoint: "tx:0".to_string(),
            cancel_tx_id: "c".to_string(),
            pair: "p".to_string(),
        };
        assert!(should_forward(&ev_cancel, &subs));

        // OrderDetected
        let ev_detect = WsEvent::OrderDetected {
            owner_hash: owner.clone(),
            outpoint: "tx:0".to_string(),
            side: OrderSide::Buy,
            price: "1/1".to_string(),
            amount: 100,
            pair: "p".to_string(),
        };
        assert!(should_forward(&ev_detect, &subs));
    }

    #[test]
    fn test_user_order_events_do_not_forward_to_public_subs() {
        let mut subs = HashSet::new();
        subs.insert("depth:pairA".to_string());
        subs.insert("trades:pairA".to_string());

        let ev = WsEvent::OrderFilled {
            owner_hash: "aa".repeat(32),
            outpoint: "tx:0".to_string(),
            tx_id: "m".to_string(),
            fill_price: "1/1".to_string(),
            fill_amount: 100,
            side: OrderSide::Buy,
            pair: "pairA".to_string(),
        };
        assert!(!should_forward(&ev, &subs), "user order event should not forward to depth/trades subscribers");
    }

    #[tokio::test]
    async fn test_emit_order_filled_broadcast() {
        let (tx, _) = broadcast::channel::<WsEvent>(100);
        let mut rx = tx.subscribe();

        emit_order_filled(&tx, "owner1", "tx:0", "match_tx", 100, 1, 5000, OrderSide::Buy, "pair1");

        let received = rx.recv().await.unwrap();
        match received {
            WsEvent::OrderFilled { owner_hash, outpoint, tx_id, fill_amount, side, .. } => {
                assert_eq!(owner_hash, "owner1");
                assert_eq!(outpoint, "tx:0");
                assert_eq!(tx_id, "match_tx");
                assert_eq!(fill_amount, 5000);
                assert_eq!(side, OrderSide::Buy);
            }
            _ => panic!("expected OrderFilled event"),
        }
    }

    #[tokio::test]
    async fn test_emit_order_partially_filled_broadcast() {
        let (tx, _) = broadcast::channel::<WsEvent>(100);
        let mut rx = tx.subscribe();

        emit_order_partially_filled(&tx, "owner2", "tx:1", "ptx", 3000, 2000, 50, 1, OrderSide::Sell, "pair2");

        let received = rx.recv().await.unwrap();
        match received {
            WsEvent::OrderPartiallyFilled { filled_amount, remaining_amount, fill_price, .. } => {
                assert_eq!(filled_amount, 3000);
                assert_eq!(remaining_amount, 2000);
                assert_eq!(fill_price, "50/1");
            }
            _ => panic!("expected OrderPartiallyFilled event"),
        }
    }

    #[tokio::test]
    async fn test_emit_order_cancelled_broadcast() {
        let (tx, _) = broadcast::channel::<WsEvent>(100);
        let mut rx = tx.subscribe();

        emit_order_cancelled(&tx, "owner3", "tx:2", "cancel_tx", "pair3");

        let received = rx.recv().await.unwrap();
        match received {
            WsEvent::OrderCancelled { owner_hash, cancel_tx_id, .. } => {
                assert_eq!(owner_hash, "owner3");
                assert_eq!(cancel_tx_id, "cancel_tx");
            }
            _ => panic!("expected OrderCancelled event"),
        }
    }

    #[tokio::test]
    async fn test_emit_order_detected_broadcast() {
        let (tx, _) = broadcast::channel::<WsEvent>(100);
        let mut rx = tx.subscribe();

        emit_order_detected(&tx, "owner4", "tx:3", OrderSide::Sell, 200, 3, 10_000_000, "pair4");

        let received = rx.recv().await.unwrap();
        match received {
            WsEvent::OrderDetected { owner_hash, side, price, amount, .. } => {
                assert_eq!(owner_hash, "owner4");
                assert_eq!(side, OrderSide::Sell);
                assert_eq!(price, "200/3");
                assert_eq!(amount, 10_000_000);
            }
            _ => panic!("expected OrderDetected event"),
        }
    }

    #[tokio::test]
    async fn test_emit_no_subscribers_does_not_panic() {
        // broadcaster with no receivers -- send should silently succeed
        let (tx, _) = broadcast::channel::<WsEvent>(100);
        // drop the only receiver
        emit_order_filled(&tx, "x", "y", "z", 1, 1, 1, OrderSide::Buy, "p");
        emit_order_cancelled(&tx, "x", "y", "z", "p");
        emit_order_detected(&tx, "x", "y", OrderSide::Sell, 1, 1, 1, "p");
        // no panic = pass
    }

    #[test]
    fn test_multiple_user_subscriptions_independent() {
        let owner_a = "aa".repeat(32);
        let owner_b = "bb".repeat(32);
        let mut subs = HashSet::new();
        subs.insert(format!("user_orders:{}", owner_a));

        let ev_a = WsEvent::OrderDetected {
            owner_hash: owner_a.clone(),
            outpoint: "tx:0".to_string(),
            side: OrderSide::Buy,
            price: "1/1".to_string(),
            amount: 100,
            pair: "p".to_string(),
        };
        let ev_b = WsEvent::OrderDetected {
            owner_hash: owner_b.clone(),
            outpoint: "tx:1".to_string(),
            side: OrderSide::Sell,
            price: "2/1".to_string(),
            amount: 200,
            pair: "p".to_string(),
        };

        assert!(should_forward(&ev_a, &subs));
        assert!(!should_forward(&ev_b, &subs));

        // Now subscribe to owner_b too
        subs.insert(format!("user_orders:{}", owner_b));
        assert!(should_forward(&ev_b, &subs));
    }
}
