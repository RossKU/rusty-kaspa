//! Lightweight Kaspa JSON-RPC WebSocket client for kob-cli.
//!
//! Mirrors the kob-engine RPC client pattern but is self-contained.
//! Uses tokio-tungstenite for WebSocket, serde_json for messages.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};


#[derive(Debug, Serialize)]
struct JsonRpcRequest {
    id: u64,
    method: String,
    params: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    params: Option<serde_json::Value>,
    #[serde(default)]
    error: Option<serde_json::Value>,
}


#[derive(Debug, Clone, Deserialize)]
pub struct RpcUtxo {
    pub outpoint: RpcOutpoint,
    #[serde(rename = "utxoEntry")]
    pub utxo_entry: RpcUtxoEntry,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RpcOutpoint {
    #[serde(rename = "transactionId")]
    pub transaction_id: String,
    pub index: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RpcUtxoEntry {
    pub amount: u64,
    #[serde(rename = "scriptPublicKey")]
    pub script_public_key: RpcSpk,
    #[serde(rename = "blockDaaScore", default)]
    pub block_daa_score: u64,
    #[serde(rename = "isCoinbase", default)]
    pub is_coinbase: bool,
}

#[derive(Debug, Clone)]
pub struct RpcSpk {
    pub version: u16,
    pub script: String,
}

impl<'de> serde::Deserialize<'de> for RpcSpk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de;

        struct RpcSpkVisitor;

        impl<'de> de::Visitor<'de> for RpcSpkVisitor {
            type Value = RpcSpk;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a string or {version, script} object for scriptPublicKey")
            }

            /// Plain hex string: first 2 bytes = version (u16 LE), rest = script hex.
            fn visit_str<E: de::Error>(self, v: &str) -> Result<RpcSpk, E> {
                if v.len() < 4 {
                    return Err(E::custom(format!(
                        "scriptPublicKey string too short: '{}'", v
                    )));
                }
                let version = u16::from_str_radix(&v[..4], 16).map_err(E::custom)?;
                Ok(RpcSpk {
                    version,
                    script: v[4..].to_string(),
                })
            }

            /// Object form: {"version": u16, "script": "hex"}
            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<RpcSpk, A::Error> {
                let mut version: Option<u16> = None;
                let mut script: Option<String> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "version" => version = Some(map.next_value()?),
                        "script" | "scriptPublicKey" => script = Some(map.next_value()?),
                        _ => { let _ = map.next_value::<serde_json::Value>(); }
                    }
                }
                Ok(RpcSpk {
                    version: version.unwrap_or(0),
                    script: script.unwrap_or_default(),
                })
            }
        }

        deserializer.deserialize_any(RpcSpkVisitor)
    }
}

impl RpcUtxo {
    /// Script bytes (decoded from hex).
    pub fn script_bytes(&self) -> Vec<u8> {
        match hex::decode(&self.utxo_entry.script_public_key.script) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(
                    "[RPC] Failed to hex-decode scriptPublicKey '{}': {}",
                    self.utxo_entry.script_public_key.script, e
                );
                vec![]
            }
        }
    }

    /// Check if this is a P2SH UTXO (script starts with aa20).
    pub fn is_p2sh(&self) -> bool {
        self.utxo_entry.script_public_key.script.starts_with("aa20")
    }

    /// Outpoint key string "txid:index".
    pub fn outpoint_key(&self) -> String {
        format!("{}:{}", self.outpoint.transaction_id, self.outpoint.index)
    }
}


pub struct RpcClient {
    _url: String,
    next_id: AtomicU64,
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<JsonRpcResponse>>>>,
    write_tx: mpsc::Sender<String>,
    alive: Arc<AtomicBool>,
}

impl RpcClient {
    /// Connect to a Kaspa node via WebSocket.
    pub async fn connect(url: &str) -> anyhow::Result<Self> {
        use futures_util::sink::SinkExt;
        use futures_util::stream::StreamExt;
        use tokio::net::TcpStream;
        use tokio_tungstenite::tungstenite::Message;

        // Validate URL scheme
        if !url.starts_with("wss://") && !url.starts_with("ws://") {
            anyhow::bail!("Node URL must use ws:// or wss:// scheme. Got: {}", url);
        }
        if url.starts_with("ws://") && !url.contains("localhost") && !url.contains("127.0.0.1") {
            eprintln!("WARNING: Using unencrypted ws:// connection to remote node. Consider using wss:// for security.");
        }

        let url_parsed =
            url::Url::parse(url).map_err(|e| anyhow::anyhow!("Invalid URL {}: {}", url, e))?;
        let host = url_parsed
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("No hostname found in the node URL. Expected format: ws://hostname:port"))?;
        let port = url_parsed.port().unwrap_or(if url_parsed.scheme() == "wss" { 443 } else { 80 });

        let tcp = TcpStream::connect(format!("{}:{}", host, port)).await?;
        let (ws, _) = tokio_tungstenite::client_async(url, tcp).await?;

        let pending: Arc<Mutex<HashMap<u64, oneshot::Sender<JsonRpcResponse>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let alive = Arc::new(AtomicBool::new(true));
        let (write_tx, mut write_rx) = mpsc::channel::<String>(256);

        let (mut ws_writer, mut ws_reader) = ws.split();

        // Writer task
        let alive_w = alive.clone();
        tokio::spawn(async move {
            while let Some(msg) = write_rx.recv().await {
                if !alive_w.load(Ordering::Relaxed) {
                    break;
                }
                if ws_writer.send(Message::Text(msg)).await.is_err() {
                    alive_w.store(false, Ordering::Relaxed);
                    break;
                }
            }
        });

        // Reader task
        let pending_r = pending.clone();
        let alive_r = alive.clone();
        tokio::spawn(async move {
            while let Some(msg_result) = ws_reader.next().await {
                match msg_result {
                    Ok(Message::Text(text)) => {
                        if let Ok(resp) = serde_json::from_str::<JsonRpcResponse>(&text) {
                            if let Some(id) = resp.id {
                                let mut map = pending_r.lock().await;
                                if let Some(tx) = map.remove(&id) {
                                    if tx.send(resp).is_err() {
                                        tracing::warn!("[RPC] Response channel closed for request {}", id);
                                    }
                                }
                            }
                        }
                    }
                    Ok(Message::Close(_)) | Err(_) => {
                        alive_r.store(false, Ordering::Relaxed);
                        break;
                    }
                    _ => {}
                }
            }
            alive_r.store(false, Ordering::Relaxed);
        });

        Ok(RpcClient {
            _url: url.to_string(),
            next_id: AtomicU64::new(1),
            pending,
            write_tx,
            alive,
        })
    }

    /// Check if the WebSocket connection is still alive.
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    /// Send an RPC call and wait for the response.
    pub async fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        if !self.alive.load(Ordering::Relaxed) {
            anyhow::bail!("Connection to Kaspa node lost. Check your network and node URL, then retry");
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let request = JsonRpcRequest {
            id,
            method: method.to_string(),
            params,
        };

        let (tx, rx) = oneshot::channel();
        {
            self.pending.lock().await.insert(id, tx);
        }

        let msg = serde_json::to_string(&request)?;
        self.write_tx
            .send(msg)
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send request to the Kaspa node. The connection may have dropped."))?;

        let resp = tokio::time::timeout(std::time::Duration::from_secs(30), rx)
            .await
            .map_err(|_| anyhow::anyhow!("RPC call '{}' timed out after 30s. The node may be overloaded or unreachable", method))?
            .map_err(|_| anyhow::anyhow!("Node connection closed while waiting for response. Try reconnecting."))?;

        if let Some(err) = resp.error {
            anyhow::bail!("RPC error from '{}': {}", method, err);
        }

        Ok(resp.params.unwrap_or(serde_json::Value::Null))
    }

    /// Get UTXOs for one or more addresses, sorted by amount descending.
    pub async fn get_utxos_by_addresses(
        &self,
        addresses: &[&str],
    ) -> anyhow::Result<Vec<RpcUtxo>> {
        let result = self
            .call(
                "getUtxosByAddresses",
                serde_json::json!({ "addresses": addresses }),
            )
            .await?;

        let entries: Vec<RpcUtxo> = match result.get("entries") {
            Some(v) => match serde_json::from_value::<Vec<RpcUtxo>>(v.clone()) {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!("[RPC] Failed to deserialize UTXO entries: {}", e);
                    vec![]
                }
            },
            None => vec![],
        };

        let mut utxos = entries;
        utxos.sort_by(|a, b| b.utxo_entry.amount.cmp(&a.utxo_entry.amount));
        Ok(utxos)
    }

    /// Get spendable UTXOs (exclude mempool-spent).
    pub async fn get_spendable_utxos(&self, address: &str) -> anyhow::Result<Vec<RpcUtxo>> {
        let utxos = self.get_utxos_by_addresses(&[address]).await?;

        // Try mempool filtering
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
            let mut spent = std::collections::HashSet::new();
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
                                        let tid = op
                                            .get("transactionId")
                                            .and_then(|v| v.as_str());
                                        let idx =
                                            op.get("index").and_then(|v| v.as_u64());
                                        if tid.is_none() || idx.is_none() {
                                            tracing::warn!(
                                                "[RPC] Malformed previousOutpoint in mempool entry: {:?}",
                                                op
                                            );
                                        }
                                        let tid = tid.unwrap_or("");
                                        let idx = idx.unwrap_or(0);
                                        spent.insert(format!("{}:{}", tid, idx));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if !spent.is_empty() {
                let filtered: Vec<RpcUtxo> = utxos
                    .into_iter()
                    .filter(|u| !spent.contains(&u.outpoint_key()))
                    .collect();
                return Ok(filtered);
            }
        }

        Ok(utxos)
    }

    /// Submit a transaction. Returns the transaction ID on success.
    pub async fn submit_transaction(
        &self,
        payload: serde_json::Value,
    ) -> anyhow::Result<String> {
        let result = self.call("submitTransaction", payload).await?;

        if let Some(err) = result.get("error") {
            if !err.is_null() {
                anyhow::bail!("submitTransaction error: {}", err);
            }
        }

        let tx_id = result
            .get("transactionId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Node accepted the transaction but did not return a transaction ID. This is unexpected -- check the node logs."))?;

        Ok(tx_id.to_string())
    }
}
