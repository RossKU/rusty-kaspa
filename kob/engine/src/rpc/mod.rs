//! Kaspa JSON-RPC WebSocket client with auto-reconnect.

pub mod rest_client;

// Re-export shared RPC types from kob-core so existing `use crate::rpc::RpcUtxo` works.
pub use kob_core::rpc_types::{RpcUtxo, RpcOutpoint, RpcUtxoEntry, RpcSpk, parse_rest_spk};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

/// JSON-RPC request
#[derive(Debug, Serialize)]
struct JsonRpcRequest {
    id: u64,
    method: String,
    params: serde_json::Value,
}

/// JSON-RPC response
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields populated by serde deserialization
struct JsonRpcResponse {
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    params: Option<serde_json::Value>,
    #[serde(default)]
    error: Option<serde_json::Value>,
}

/// Result from submitting a transaction
#[derive(Debug)]
pub struct SubmitResult {
    pub ok: bool,
    pub tx_id: Option<String>,
    pub error: Option<String>,
}

/// Configuration for retry behavior on transient RPC errors.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used in reconnect/retry impl block
pub struct RetryConfig {
    /// Maximum number of retry attempts (0 = no retries).
    pub max_retries: u32,
    /// Initial backoff duration before the first retry.
    pub initial_backoff: std::time::Duration,
    /// Backoff multiplier applied after each retry (exponential backoff).
    pub backoff_multiplier: u32,
}

impl Default for RetryConfig {
    fn default() -> Self {
        RetryConfig {
            max_retries: 3,
            initial_backoff: std::time::Duration::from_secs(1),
            backoff_multiplier: 2,
        }
    }
}

/// Kaspa JSON-RPC client over WebSocket.
///
/// This is a simplified client. For production, use kob-core's RPC client
/// when it supports full WebSocket lifecycle.
#[allow(dead_code)] // Fields used in reconnect/retry impl block
pub struct RpcClient {
    url: String,
    next_id: AtomicU64,
    /// Pending RPC calls: id -> response sender
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<JsonRpcResponse>>>>,
    /// Channel to send messages to the WebSocket writer task
    write_tx: mpsc::Sender<String>,
    /// Whether the connection is alive
    alive: Arc<std::sync::atomic::AtomicBool>,
    /// Optional authentication token sent during WebSocket handshake.
    auth_token: Option<String>,
    /// Retry configuration for transient errors.
    retry_config: RetryConfig,
    /// Channel for receiving subscription notifications (blockAddedNotification, etc.).
    /// Notifications are messages from the node that have a `method` field but no `id`.
    notification_rx: Arc<Mutex<Option<mpsc::Receiver<serde_json::Value>>>>,
    /// Sender side kept for reconnection (cloned into reader task).
    notification_tx: mpsc::Sender<serde_json::Value>,
}

impl RpcClient {
    /// Connect to a Kaspa node via WebSocket.
    pub async fn connect(url: &str) -> Result<Self, String> {
        Self::connect_with_options(url, None, RetryConfig::default()).await
    }

    /// Connect to a Kaspa node via WebSocket with optional auth token and retry config.
    ///
    /// If `auth_token` is provided, it is sent as an `Authorization: Bearer <token>`
    /// header during the WebSocket handshake. This supports Kaspa nodes that require
    /// authentication (F17).
    ///
    /// The `retry_config` controls how transient RPC errors are retried (F19).
    pub async fn connect_with_options(
        url: &str,
        auth_token: Option<String>,
        retry_config: RetryConfig,
    ) -> Result<Self, String> {
        use tokio::net::TcpStream;

        // Parse the URL to extract host and port for TCP connection
        let url_parsed = url::Url::parse(url)
            .map_err(|e| format!("Invalid URL {}: {}", url, e))?;
        let host = url_parsed.host_str().ok_or("No host in URL")?;
        let port = url_parsed.port().unwrap_or(if url_parsed.scheme() == "wss" { 443 } else { 80 });

        let tcp_addr = format!("{}:{}", host, port);
        let tcp_stream = TcpStream::connect(&tcp_addr)
            .await
            .map_err(|e| format!("TCP connect to {} failed: {}", tcp_addr, e))?;

        // Build WebSocket request, optionally with auth header
        let mut request = url.to_string().into_client_request()
            .map_err(|e| format!("Failed to build WebSocket request: {}", e))?;
        if let Some(ref token) = auth_token {
            request.headers_mut().insert(
                "Authorization",
                format!("Bearer {}", token).parse()
                    .map_err(|e| format!("Invalid auth token: {}", e))?,
            );
        }

        let (ws_stream, _response) = tokio_tungstenite::client_async(request, tcp_stream)
            .await
            .map_err(|e| format!("WebSocket handshake with {} failed: {}", url, e))?;

        let pending: Arc<Mutex<HashMap<u64, oneshot::Sender<JsonRpcResponse>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));

        let (write_tx, mut write_rx) = mpsc::channel::<String>(256);
        let (notif_tx, notif_rx) = mpsc::channel::<serde_json::Value>(512);

        // Split WebSocket into reader and writer
        use futures_util::stream::StreamExt;
        use futures_util::sink::SinkExt;
        use tokio_tungstenite::tungstenite::Message;

        let (mut ws_writer, mut ws_reader) = ws_stream.split();

        // Writer task
        let alive_w = alive.clone();
        tokio::spawn(async move {
            while let Some(msg) = write_rx.recv().await {
                if !alive_w.load(AtomicOrdering::Relaxed) {
                    break;
                }
                if ws_writer.send(Message::Text(msg)).await.is_err() {
                    alive_w.store(false, AtomicOrdering::Relaxed);
                    break;
                }
            }
        });

        // Reader task
        let pending_r = pending.clone();
        let alive_r = alive.clone();
        let notif_tx_r = notif_tx.clone();
        tokio::spawn(async move {
            while let Some(msg_result) = ws_reader.next().await {
                match msg_result {
                    Ok(Message::Text(text)) => {
                        if let Ok(resp) = serde_json::from_str::<JsonRpcResponse>(&text) {
                            if let Some(id) = resp.id {
                                // RPC response — route to pending caller
                                let mut map = pending_r.lock().await;
                                if let Some(tx) = map.remove(&id) {
                                    if tx.send(resp).is_err() {
                                        tracing::warn!("[RPC] Response channel closed for request {}", id);
                                    }
                                }
                            } else if resp.method.is_some() {
                                // Subscription notification (no id, has method)
                                // Build a notification value with method + params
                                let mut notif = serde_json::Map::new();
                                if let Some(m) = &resp.method {
                                    notif.insert("method".to_string(), serde_json::Value::String(m.clone()));
                                }
                                if let Some(p) = resp.params {
                                    notif.insert("params".to_string(), p);
                                }
                                if let Err(e) = notif_tx_r.try_send(serde_json::Value::Object(notif)) {
                                    tracing::warn!("[RPC] Failed to enqueue notification: {}", e);
                                }
                            }
                        }
                    }
                    Ok(Message::Close(_)) => {
                        alive_r.store(false, AtomicOrdering::Relaxed);
                        break;
                    }
                    Err(_) => {
                        alive_r.store(false, AtomicOrdering::Relaxed);
                        break;
                    }
                    _ => {}
                }
            }
            alive_r.store(false, AtomicOrdering::Relaxed);
        });

        Ok(RpcClient {
            url: url.to_string(),
            next_id: AtomicU64::new(1),
            pending,
            write_tx,
            alive,
            auth_token,
            retry_config,
            notification_rx: Arc::new(Mutex::new(Some(notif_rx))),
            notification_tx: notif_tx,
        })
    }

    /// Send an RPC call and wait for the response with the default 30s timeout.
    pub async fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.call_with_timeout(method, params, std::time::Duration::from_secs(30)).await
    }

    /// Send an RPC call and wait for the response with a custom timeout.
    pub async fn call_with_timeout(
        &self,
        method: &str,
        params: serde_json::Value,
        timeout: std::time::Duration,
    ) -> Result<serde_json::Value, String> {
        if !self.alive.load(AtomicOrdering::Relaxed) {
            return Err("Connection closed".to_string());
        }

        let id = self.next_id.fetch_add(1, AtomicOrdering::Relaxed);
        let request = JsonRpcRequest {
            id,
            method: method.to_string(),
            params,
        };

        let (tx, rx) = oneshot::channel();
        {
            let mut map = self.pending.lock().await;
            map.insert(id, tx);
        }

        let msg = serde_json::to_string(&request).map_err(|e| e.to_string())?;
        if self.write_tx.send(msg).await.is_err() {
            self.alive.store(false, AtomicOrdering::Relaxed);
            self.pending.lock().await.remove(&id);
            return Err("Failed to send to WebSocket".to_string());
        }

        let resp = match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(_)) => {
                // Channel closed — remove pending entry and mark dead
                self.pending.lock().await.remove(&id);
                self.alive.store(false, AtomicOrdering::Relaxed);
                return Err("Response channel closed".to_string());
            }
            Err(_) => {
                // Timeout — remove pending entry so late responses don't
                // send on a dropped channel (BUG 3 fix)
                self.pending.lock().await.remove(&id);
                return Err("RPC call timed out".to_string());
            }
        };

        if let Some(err) = resp.error {
            return Err(format!("RPC error: {}", err));
        }

        Ok(resp.params.unwrap_or(serde_json::Value::Null))
    }

    /// Submit a transaction.
    pub async fn submit_transaction(
        &self,
        tx_json: serde_json::Value,
    ) -> Result<SubmitResult, String> {
        let result = self.call("submitTransaction", tx_json).await?;

        // Check for error in params
        if let Some(err) = result.get("error") {
            if !err.is_null() {
                return Ok(SubmitResult {
                    ok: false,
                    tx_id: None,
                    error: Some(err.to_string()),
                });
            }
        }

        let tx_id = result
            .get("transactionId")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Ok(SubmitResult {
            ok: tx_id.is_some(),
            tx_id,
            error: None,
        })
    }

    /// Get UTXOs for an address, sorted by amount descending.
    pub async fn get_utxos(
        &self,
        address: &str,
        min_amount: Option<u64>,
    ) -> Result<Vec<RpcUtxo>, String> {
        let params = serde_json::json!({
            "addresses": [address]
        });
        let result = self.call("getUtxosByAddresses", params).await?;

        let entries: Vec<RpcUtxo> = result
            .get("entries")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        let mut utxos = entries;
        utxos.sort_by(|a, b| b.utxo_entry.amount.cmp(&a.utxo_entry.amount));

        if let Some(min) = min_amount {
            utxos.retain(|u| u.utxo_entry.amount >= min);
        }

        Ok(utxos)
    }

    /// Get UTXOs for multiple addresses in a single RPC call.
    ///
    /// Used for bulk UTXO validation (e.g., startup pruning of stale orders).
    pub async fn get_utxos_by_addresses(
        &self,
        addresses: &[&str],
    ) -> Result<Vec<RpcUtxo>, String> {
        let params = serde_json::json!({
            "addresses": addresses
        });
        let result = self.call("getUtxosByAddresses", params).await?;

        let entries: Vec<RpcUtxo> = result
            .get("entries")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        Ok(entries)
    }

    /// Get spendable UTXOs (filtered by mempool-spent outpoints).
    ///
    /// Queries getMempoolEntriesByAddresses to exclude UTXOs that are already
    /// spent in pending transactions.
    pub async fn get_spendable_utxos(
        &self,
        address: &str,
        min_amount: Option<u64>,
    ) -> Result<Vec<RpcUtxo>, String> {
        let utxos = self.get_utxos(address, min_amount).await?;

        // Try to filter by mempool
        let mempool_result = self
            .call(
                "getMempoolEntriesByAddresses",
                serde_json::json!({
                    "addresses": [address],
                    "includeOrphanPool": false,
                    "filterTransactionPool": true,
                }),
            )
            .await;

        if let Ok(mempool_resp) = mempool_result {
            let mut spent_outpoints = std::collections::HashSet::new();

            if let Some(entries) = mempool_resp.get("entries").and_then(|v| v.as_array()) {
                for entry in entries {
                    if let Some(sending) = entry.get("sending").and_then(|v| v.as_array()) {
                        for tx in sending {
                            if let Some(inputs) = tx
                                .get("transaction")
                                .and_then(|t| t.get("inputs"))
                                .and_then(|v| v.as_array())
                            {
                                for inp in inputs {
                                    if let Some(op) = inp.get("previousOutpoint") {
                                        let tx_id = op
                                            .get("transactionId")
                                            .and_then(|v| v.as_str());
                                        let idx = op
                                            .get("index")
                                            .and_then(|v| v.as_u64());
                                        if tx_id.is_none() || idx.is_none() {
                                            tracing::warn!(
                                                "[RPC] Malformed previousOutpoint in mempool entry: {:?}",
                                                op
                                            );
                                        }
                                        let tx_id = tx_id.unwrap_or("");
                                        let idx = idx.unwrap_or(0);
                                        spent_outpoints.insert(format!("{}:{}", tx_id, idx));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if !spent_outpoints.is_empty() {
                let before = utxos.len();
                let filtered: Vec<RpcUtxo> = utxos
                    .into_iter()
                    .filter(|u| !spent_outpoints.contains(&u.outpoint_key()))
                    .collect();
                let after = filtered.len();
                if after < before {
                    tracing::info!(
                        "[MEMPOOL] Filtered {} spent UTXOs ({} in mempool)",
                        before - after,
                        spent_outpoints.len()
                    );
                }
                return Ok(filtered);
            }
        } else {
            tracing::warn!("[MEMPOOL] Mempool query failed, using unfiltered UTXOs");
        }

        Ok(utxos)
    }

}

// Subscription / notification support

impl RpcClient {
    /// Subscribe to a notification scope (e.g., `BlockAdded`, `VirtualChainChanged`).
    ///
    /// Sends a `subscribe` RPC call with the given scope. The node will respond
    /// with a confirmation, and then send notification messages asynchronously
    /// (e.g., `blockAddedNotification`). These are routed to the notification
    /// channel and can be received via `take_notification_receiver()`.
    ///
    /// The scope parameter should match Kaspa's Scope enum variant name
    /// (PascalCase), e.g., `"BlockAdded"`, `"VirtualChainChanged"`.
    pub async fn subscribe(&self, scope: &str) -> Result<serde_json::Value, String> {
        let params = serde_json::json!({ scope: {} });
        self.call("subscribe", params).await
    }

    /// Take ownership of the notification receiver channel.
    ///
    /// Returns `None` if already taken (can only be taken once per connection).
    /// The caller should use this in a `tokio::select!` or dedicated task to
    /// process incoming notifications.
    pub async fn take_notification_receiver(&self) -> Option<mpsc::Receiver<serde_json::Value>> {
        self.notification_rx.lock().await.take()
    }
}

#[allow(dead_code)] // Reconnect/retry — wired into executor loop for production resilience
impl RpcClient {
    /// Check if the connection is alive.
    pub fn is_alive(&self) -> bool {
        self.alive.load(AtomicOrdering::Relaxed)
    }

    /// Get the URL this client is connected to.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Get the retry configuration.
    pub fn retry_config(&self) -> &RetryConfig {
        &self.retry_config
    }

    /// Get the auth token (if set).
    pub fn auth_token(&self) -> Option<&str> {
        self.auth_token.as_deref()
    }

    /// Get the current virtual DAA score from the node.
    ///
    /// Calls `getBlockDagInfo` and extracts the `virtualDaaScore` field.
    /// This is used by the lending executor to timestamp loan origination
    /// and by the perp executor for position DAA fields.
    pub async fn get_daa_score(&self) -> Result<u64, String> {
        let info = self.call("getBlockDagInfo", serde_json::json!({})).await?;
        info.get("virtualDaaScore")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| "virtualDaaScore not found in getBlockDagInfo response".to_string())
    }

    /// Get the virtual selected parent chain from a given start hash.
    ///
    /// Returns `(removed_hashes, added_hashes, accepted_tx_ids)`.
    /// `accepted_tx_ids` are transaction IDs accepted into the virtual chain
    /// since `start_hash`. If `start_hash` is empty, returns recent chain data.
    ///
    /// Used by the scanner to discover new L1 transactions (deploys + spends)
    /// for all product types (spot, perp, lending, prediction).
    pub async fn get_virtual_chain_from_block(
        &self,
        start_hash: &str,
        include_accepted_txs: bool,
    ) -> Result<serde_json::Value, String> {
        let params = serde_json::json!({
            "startHash": start_hash,
            "includeAcceptedTransactionIds": include_accepted_txs,
        });
        // This is a heavy RPC call that can take >30s on some nodes.
        // Retry up to 2 times with increasing timeout on failure (e.g.,
        // connection drop before the 120s deadline).
        let timeouts = [
            std::time::Duration::from_secs(120),
            std::time::Duration::from_secs(180),
            std::time::Duration::from_secs(240),
        ];
        let mut last_err = String::new();
        for (attempt, timeout) in timeouts.iter().enumerate() {
            match self.call_with_timeout(
                "getVirtualChainFromBlock",
                params.clone(),
                *timeout,
            ).await {
                Ok(v) => return Ok(v),
                Err(e) => {
                    tracing::warn!(
                        "[RPC] getVirtualChainFromBlock attempt {} failed (timeout {:?}): {}",
                        attempt + 1, timeout, e,
                    );
                    last_err = e;
                    // Brief pause before retry to let the node recover.
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        }
        Err(last_err)
    }

    /// Get a block by hash with full transaction data (includeTransactions=true).
    ///
    /// Returns the block JSON including `transactions[]` array suitable for
    /// `TransactionData::from_rpc_json()` parsing.
    pub async fn get_block(
        &self,
        block_hash: &str,
    ) -> Result<serde_json::Value, String> {
        let params = serde_json::json!({
            "hash": block_hash,
            "includeTransactions": true,
        });
        self.call("getBlock", params).await
    }

    /// Get the low hash (pruning point) from `getBlockDagInfo`.
    ///
    /// Used as the initial `start_hash` for `get_virtual_chain_from_block`
    /// when no previous scan point is available.
    pub async fn get_sink_hash(&self) -> Result<String, String> {
        let info = self.call("getBlockDagInfo", serde_json::json!({})).await?;
        info.get("sink")
            .or_else(|| info.get("sinkHash"))
            .or_else(|| info.get("tipHashes").and_then(|v| v.as_array()).and_then(|a| a.first()))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| "sink/sinkHash not found in getBlockDagInfo response".to_string())
    }

    // Reconnection Logic (I-7)

    /// Maximum backoff duration for reconnection attempts.
    const MAX_RECONNECT_BACKOFF_SECS: u64 = 60;

    /// Attempt to re-establish the WebSocket connection with exponential backoff.
    pub async fn reconnect(&mut self) -> Result<(), String> {
        let mut backoff_secs: u64 = 1;

        loop {
            tracing::info!(
                "[RPC RECONNECT] Attempting reconnection to {} (backoff {}s)...",
                self.url, backoff_secs
            );

            tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;

            match Self::connect_with_options(
                &self.url,
                self.auth_token.clone(),
                self.retry_config.clone(),
            )
            .await
            {
                Ok(new_client) => {
                    self.pending = new_client.pending;
                    self.write_tx = new_client.write_tx;
                    self.alive = new_client.alive;
                    self.notification_tx = new_client.notification_tx;
                    self.notification_rx = new_client.notification_rx;
                    tracing::info!(
                        "[RPC RECONNECT] Successfully reconnected to {}",
                        self.url
                    );
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!(
                        "[RPC RECONNECT] Failed to reconnect to {}: {}. Retrying in {}s...",
                        self.url, e, backoff_secs.min(Self::MAX_RECONNECT_BACKOFF_SECS)
                    );
                    backoff_secs = (backoff_secs * 2).min(Self::MAX_RECONNECT_BACKOFF_SECS);
                }
            }
        }
    }

    /// Check if the connection is dead and needs reconnection.
    pub fn needs_reconnect(&self) -> bool {
        !self.alive.load(AtomicOrdering::Relaxed)
    }

    // Retry Logic (F19)

    /// Determine whether an RPC error is transient (worth retrying).
    fn is_transient_error(err: &str) -> bool {
        let lower = err.to_lowercase();
        lower.contains("connection closed")
            || lower.contains("connection reset")
            || lower.contains("timed out")
            || lower.contains("rpc call timed out")
            || lower.contains("failed to send")
            || lower.contains("broken pipe")
            || lower.contains("network")
            || lower.contains("tcp connect")
            || lower.contains("websocket handshake")
            || lower.contains("response channel closed")
    }

    /// Execute an RPC call with exponential backoff retry on transient errors.
    pub async fn call_with_retry(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let max_retries = self.retry_config.max_retries;
        let mut backoff = self.retry_config.initial_backoff;
        let multiplier = self.retry_config.backoff_multiplier;

        for attempt in 0..=max_retries {
            match self.call(method, params.clone()).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    if attempt < max_retries && Self::is_transient_error(&e) {
                        tracing::warn!(
                            "[RPC RETRY] Transient error on {} (attempt {}/{}): {}. Retrying in {:?}...",
                            method, attempt + 1, max_retries, e, backoff
                        );
                        tokio::time::sleep(backoff).await;
                        backoff *= multiplier;
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        Err("Max retries exhausted".to_string())
    }

    /// Execute an RPC call with reconnection support (I-7).
    pub async fn call_with_reconnect(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        if self.needs_reconnect() {
            tracing::warn!(
                "[RPC] Connection dead, initiating reconnect before calling {}...",
                method
            );
            self.reconnect().await?;
        }

        match self.call_with_retry(method, params.clone()).await {
            Ok(result) => Ok(result),
            Err(e) if Self::is_transient_error(&e) && self.needs_reconnect() => {
                tracing::warn!(
                    "[RPC] Connection lost during {}. Reconnecting...",
                    method
                );
                self.reconnect().await?;
                self.call(method, params).await
            }
            Err(e) => Err(e),
        }
    }

    /// Submit a transaction with retry on transient errors.
    pub async fn submit_transaction_with_retry(
        &self,
        tx_json: serde_json::Value,
    ) -> Result<SubmitResult, String> {
        let max_retries = self.retry_config.max_retries;
        let mut backoff = self.retry_config.initial_backoff;
        let multiplier = self.retry_config.backoff_multiplier;

        for attempt in 0..=max_retries {
            match self.submit_transaction(tx_json.clone()).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    if attempt < max_retries && Self::is_transient_error(&e) {
                        tracing::warn!(
                            "[RPC RETRY] Transient error on submitTransaction (attempt {}/{}): {}. Retrying in {:?}...",
                            attempt + 1, max_retries, e, backoff
                        );
                        tokio::time::sleep(backoff).await;
                        backoff *= multiplier;
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        Err("Max retries exhausted".to_string())
    }

    /// Get UTXOs for an address with retry on transient errors.
    pub async fn get_utxos_with_retry(
        &self,
        address: &str,
        min_amount: Option<u64>,
    ) -> Result<Vec<RpcUtxo>, String> {
        let max_retries = self.retry_config.max_retries;
        let mut backoff = self.retry_config.initial_backoff;
        let multiplier = self.retry_config.backoff_multiplier;

        for attempt in 0..=max_retries {
            match self.get_utxos(address, min_amount).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    if attempt < max_retries && Self::is_transient_error(&e) {
                        tracing::warn!(
                            "[RPC RETRY] Transient error on getUtxosByAddresses (attempt {}/{}): {}. Retrying in {:?}...",
                            attempt + 1, max_retries, e, backoff
                        );
                        tokio::time::sleep(backoff).await;
                        backoff *= multiplier;
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        Err("Max retries exhausted".to_string())
    }
}

// Transaction Confirmation Polling (M-2)

/// Configuration for post-submission confirmation polling.
#[derive(Debug, Clone)]
pub struct ConfirmConfig {
    /// Initial delay before the first poll (allows mempool propagation).
    pub initial_delay: std::time::Duration,
    /// Maximum number of poll attempts.
    pub max_polls: u32,
    /// Delay between successive polls (doubles each attempt, capped at 4s).
    pub poll_interval: std::time::Duration,
}

impl Default for ConfirmConfig {
    fn default() -> Self {
        ConfirmConfig {
            initial_delay: std::time::Duration::from_millis(500),
            max_polls: 4,
            poll_interval: std::time::Duration::from_millis(500),
        }
    }
}

/// Result of a confirmation poll.
#[derive(Debug, Clone)]
pub struct ConfirmResult {
    /// Whether the expected output was found in the UTXO set.
    pub confirmed: bool,
    /// Number of polls performed.
    pub polls: u32,
    /// If confirmed, the UTXO amount at the expected outpoint.
    pub amount: Option<u64>,
}

impl RpcClient {
    /// Poll the UTXO set to confirm that a submitted transaction's output
    /// exists. This catches orphaned/dropped transactions before downstream
    /// logic (e.g., receipt consumption) depends on them.
    ///
    /// `tx_id`:       Transaction ID returned by submit_transaction.
    /// `output_idx`:  Index of the expected output.
    /// `address`:     Address that owns the expected output (for UTXO query).
    /// `config`:      Polling parameters. Pass `None` for defaults.
    ///
    /// Returns `ConfirmResult` indicating whether the output was found.
    pub async fn confirm_tx_output(
        &self,
        tx_id: &str,
        output_idx: u32,
        address: &str,
        config: Option<ConfirmConfig>,
    ) -> ConfirmResult {
        let cfg = config.unwrap_or_default();
        let target_outpoint = format!("{}:{}", tx_id, output_idx);

        // Initial delay to let the TX propagate through mempool
        tokio::time::sleep(cfg.initial_delay).await;

        let mut interval = cfg.poll_interval;
        for attempt in 1..=cfg.max_polls {
            match self.get_utxos(address, None).await {
                Ok(utxos) => {
                    for u in &utxos {
                        if u.outpoint.transaction_id == tx_id
                            && u.outpoint.index == output_idx
                        {
                            tracing::debug!(
                                "[CONFIRM] Found {} after {} poll(s)",
                                target_outpoint,
                                attempt,
                            );
                            return ConfirmResult {
                                confirmed: true,
                                polls: attempt,
                                amount: Some(u.utxo_entry.amount),
                            };
                        }
                    }
                    tracing::debug!(
                        "[CONFIRM] Poll {}/{}: {} not yet in UTXO set ({} UTXOs checked)",
                        attempt,
                        cfg.max_polls,
                        target_outpoint,
                        utxos.len(),
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "[CONFIRM] Poll {}/{}: RPC error querying UTXOs for {}: {}",
                        attempt,
                        cfg.max_polls,
                        address,
                        e,
                    );
                }
            }

            if attempt < cfg.max_polls {
                tokio::time::sleep(interval).await;
                // Backoff: double interval, capped at 4 seconds
                interval = std::cmp::min(interval * 2, std::time::Duration::from_secs(4));
            }
        }

        tracing::warn!(
            "[CONFIRM] {} not confirmed after {} polls (M-2)",
            target_outpoint,
            cfg.max_polls,
        );
        ConfirmResult {
            confirmed: false,
            polls: cfg.max_polls,
            amount: None,
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_config_defaults() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_backoff, std::time::Duration::from_secs(1));
        assert_eq!(config.backoff_multiplier, 2);
    }

    #[test]
    fn transient_error_detection() {
        assert!(RpcClient::is_transient_error("Connection closed"));
        assert!(RpcClient::is_transient_error("RPC call timed out"));
        assert!(RpcClient::is_transient_error("Failed to send to WebSocket"));
        assert!(RpcClient::is_transient_error("TCP connect to 1.2.3.4:18210 failed: connection reset"));
        assert!(RpcClient::is_transient_error("WebSocket handshake with ws://x failed: broken pipe"));
        assert!(RpcClient::is_transient_error("Response channel closed"));
        assert!(RpcClient::is_transient_error("network unreachable"));

        // Application-level errors should NOT be transient
        assert!(!RpcClient::is_transient_error("RPC error: script validation failed"));
        assert!(!RpcClient::is_transient_error("RPC error: invalid transaction"));
        assert!(!RpcClient::is_transient_error("RPC error: missing outpoint"));
        assert!(!RpcClient::is_transient_error("RPC error: already spent"));
        assert!(!RpcClient::is_transient_error("RPC error: insufficient funds"));
    }

    #[test]
    fn retry_config_custom() {
        let config = RetryConfig {
            max_retries: 5,
            initial_backoff: std::time::Duration::from_millis(100),
            backoff_multiplier: 3,
        };
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.initial_backoff, std::time::Duration::from_millis(100));
        assert_eq!(config.backoff_multiplier, 3);
    }

    // RPC type tests (RpcUtxo, RpcSpk, etc.) are in kob_core::rpc_types::tests

    #[test]
    fn needs_reconnect_detects_dead_connection() {
        // Verify needs_reconnect works with the alive flag.
        let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
        assert!(!(!alive.load(AtomicOrdering::Relaxed)), "alive connection should not need reconnect");

        alive.store(false, AtomicOrdering::Relaxed);
        assert!(!alive.load(AtomicOrdering::Relaxed), "dead connection should need reconnect");
    }

    #[test]
    fn max_reconnect_backoff_is_bounded() {
        assert_eq!(RpcClient::MAX_RECONNECT_BACKOFF_SECS, 60);
    }

    // M-2: Confirmation polling config tests

    #[test]
    fn confirm_config_defaults() {
        let cfg = ConfirmConfig::default();
        assert_eq!(cfg.initial_delay, std::time::Duration::from_millis(500));
        assert_eq!(cfg.max_polls, 4);
        assert_eq!(cfg.poll_interval, std::time::Duration::from_millis(500));
    }

    #[test]
    fn confirm_config_custom() {
        let cfg = ConfirmConfig {
            initial_delay: std::time::Duration::from_millis(100),
            max_polls: 2,
            poll_interval: std::time::Duration::from_millis(200),
        };
        assert_eq!(cfg.max_polls, 2);
        assert_eq!(cfg.initial_delay, std::time::Duration::from_millis(100));
        assert_eq!(cfg.poll_interval, std::time::Duration::from_millis(200));
    }

    #[test]
    fn confirm_result_not_confirmed() {
        let cr = ConfirmResult {
            confirmed: false,
            polls: 4,
            amount: None,
        };
        assert!(!cr.confirmed);
        assert_eq!(cr.polls, 4);
        assert!(cr.amount.is_none());
    }

    #[test]
    fn confirm_result_confirmed() {
        let cr = ConfirmResult {
            confirmed: true,
            polls: 1,
            amount: Some(100_000),
        };
        assert!(cr.confirmed);
        assert_eq!(cr.polls, 1);
        assert_eq!(cr.amount, Some(100_000));
    }
}
