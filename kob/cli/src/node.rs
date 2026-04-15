//! Unified node client with wRPC-first, REST-fallback strategy.
//!
//! [`NodeClient`] wraps either a WebSocket RPC client or a REST API client.
//! Connection logic: try wRPC with a 5-second timeout; if it fails, fall back
//! to the REST API (default: `https://api-tn12.kaspa.org`).
//!
//! # Engine routing
//!
//! If `--engine-url` (or `KOB_ENGINE_URL`) is set at startup, UTXO queries
//! are transparently routed through the engine's `/api/v1/wallet/utxos`
//! endpoint so consecutive CLI invocations share the engine's in-flight
//! spent-outpoint tracking and don't collide on the same UTXO.

use crate::rest::RestClient;
use crate::rpc::{RpcClient, RpcUtxo};
use kob_core::rpc_types::{RpcOutpoint, RpcSpk, RpcUtxoEntry};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::OnceLock;
use std::time::Duration;

/// Global REST API URL override. Set once from CLI `--rest-api` flag.
static REST_URL_OVERRIDE: OnceLock<String> = OnceLock::new();

/// Global engine-URL override. Set once from CLI `--engine-url` flag or the
/// `KOB_ENGINE_URL` env var. When set, UTXO queries route through the
/// engine's `/api/v1/wallet/utxos` endpoint and errors are surfaced (no
/// silent fallback — the user asked for the engine explicitly).
static ENGINE_URL_OVERRIDE: OnceLock<String> = OnceLock::new();

/// Cached auto-detect result. Populated on first UTXO query when no
/// explicit engine URL is configured: tries `DEFAULT_ENGINE_URL` via a
/// short TCP probe. `Some(url)` means engine is reachable and queries
/// route through it with silent per-request fallback to the node on
/// error. `None` means no engine was reachable at startup — stay on
/// direct-node for the process lifetime.
static ENGINE_URL_AUTO: OnceLock<Option<String>> = OnceLock::new();

/// Default REST API URL used when no override is set.
const DEFAULT_REST_URL: &str = "https://api-tn12.kaspa.org";

/// Default engine URL probed when no explicit configuration is given.
/// Matches `kob-engine`'s default `--api-port 8080` and `--api-bind 127.0.0.1`.
const DEFAULT_ENGINE_URL: &str = "http://127.0.0.1:8080";

/// Set the global REST API URL override. Call once at startup from main().
pub fn set_rest_url(url: &str) {
    let _ = REST_URL_OVERRIDE.set(url.to_string());
}

/// Get the configured REST API URL.
pub fn rest_url() -> &'static str {
    REST_URL_OVERRIDE
        .get()
        .map(|s| s.as_str())
        .unwrap_or(DEFAULT_REST_URL)
}

/// Set the global engine URL override. Call once at startup from main().
///
/// Ignored if already set.
pub fn set_engine_url(url: &str) {
    let _ = ENGINE_URL_OVERRIDE.set(url.to_string());
}

/// Explicit engine URL if the user set `--engine-url` / `KOB_ENGINE_URL`.
/// `None` means the user didn't configure it; callers should consider
/// [`auto_engine_url`] before falling back to direct-node.
pub fn engine_url() -> Option<&'static str> {
    ENGINE_URL_OVERRIDE.get().map(|s| s.as_str())
}

/// Auto-detected engine URL (cached per-process). Returns `Some(url)` on
/// first call if `DEFAULT_ENGINE_URL` is reachable via a 500ms TCP probe;
/// returns `None` otherwise and caches that decision for the rest of the
/// process. Intended as a zero-config path so end users don't need to
/// know about the engine — we probe the default port once and use it if
/// it answers.
pub fn auto_engine_url() -> Option<&'static str> {
    ENGINE_URL_AUTO
        .get_or_init(|| {
            if tcp_probe(DEFAULT_ENGINE_URL, Duration::from_millis(500)) {
                tracing::info!(
                    "[node] engine auto-detected at {} — UTXO queries will route via engine",
                    DEFAULT_ENGINE_URL
                );
                Some(DEFAULT_ENGINE_URL.to_string())
            } else {
                None
            }
        })
        .as_deref()
}

/// Quick TCP connect probe to an `http://host:port` URL. Returns true if a
/// TCP connection succeeds within `timeout`. Used only for engine auto-
/// detection — a reachable TCP port is a strong-enough signal; any actual
/// HTTP/engine errors surface later during the real request.
fn tcp_probe(url: &str, timeout: Duration) -> bool {
    let Some(stripped) = url.strip_prefix("http://") else {
        return false;
    };
    let host_port = stripped.split('/').next().unwrap_or("");
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().unwrap_or(80)),
        None => (host_port, 80),
    };
    use std::net::ToSocketAddrs;
    let Ok(mut addrs) = (host, port).to_socket_addrs() else {
        return false;
    };
    let Some(addr) = addrs.next() else {
        return false;
    };
    TcpStream::connect_timeout(&addr, timeout).is_ok()
}

/// Unified Kaspa node client: wRPC or REST.
pub enum NodeClient {
    Wrpc(RpcClient),
    Rest(RestClient),
}

impl std::fmt::Debug for NodeClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeClient::Wrpc(_) => write!(f, "NodeClient::Wrpc"),
            NodeClient::Rest(_) => write!(f, "NodeClient::Rest"),
        }
    }
}

impl NodeClient {
    /// Connect to a Kaspa node. Tries wRPC first (5s timeout), then REST.
    pub async fn connect(wrpc_url: &str) -> anyhow::Result<Self> {
        Self::connect_with_rest(wrpc_url, None).await
    }

    /// Connect with an explicit REST fallback URL.
    pub async fn connect_with_rest(
        wrpc_url: &str,
        rest_url_override: Option<&str>,
    ) -> anyhow::Result<Self> {
        // Try wRPC first with 5s timeout
        let wrpc_result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            RpcClient::connect(wrpc_url),
        )
        .await;

        match wrpc_result {
            Ok(Ok(client)) => {
                tracing::info!("[wRPC] Connected to {}", wrpc_url);
                Ok(NodeClient::Wrpc(client))
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    "[wRPC] Connection to {} failed: {} — trying REST fallback",
                    wrpc_url,
                    e
                );
                Self::try_rest(rest_url_override).await
            }
            Err(_) => {
                tracing::warn!(
                    "[wRPC] Connection to {} timed out (5s) — trying REST fallback",
                    wrpc_url
                );
                Self::try_rest(rest_url_override).await
            }
        }
    }

    /// Try to connect via REST API.
    async fn try_rest(rest_url_override: Option<&str>) -> anyhow::Result<Self> {
        let url = rest_url_override.unwrap_or_else(|| rest_url());
        let client = RestClient::new(url);

        // Health check
        client.health_check().await.map_err(|e| {
            anyhow::anyhow!(
                "Both wRPC and REST connections failed. REST error ({}): {}",
                url,
                e
            )
        })?;

        tracing::info!("[REST] Connected to {} (wRPC unavailable)", url);
        Ok(NodeClient::Rest(client))
    }

    /// Get UTXOs for one or more addresses.
    ///
    /// Routing priority:
    /// 1. If the user explicitly set `--engine-url` / `KOB_ENGINE_URL`, the
    ///    query goes through the engine's `/api/v1/wallet/utxos` endpoint.
    ///    Errors surface — we don't silently fall back, because masking the
    ///    error would defeat the in-flight spent-outpoint tracking the user
    ///    was asking for.
    /// 2. Otherwise, the engine is auto-probed at `DEFAULT_ENGINE_URL`
    ///    (cached for the process). If reachable, the query goes through
    ///    the engine and per-request errors silently fall back to direct
    ///    node query — the user didn't ask for the engine, so treating it
    ///    as best-effort is the right trade-off.
    /// 3. Otherwise, the query goes directly to the node.
    pub async fn get_utxos_by_addresses(
        &self,
        addresses: &[&str],
    ) -> anyhow::Result<Vec<RpcUtxo>> {
        // 1. Explicit engine URL — strict error semantics.
        if let Some(eurl) = engine_url() {
            let mut all = Vec::new();
            for addr in addresses {
                let utxos = get_utxos_via_engine(eurl, addr).map_err(|e| {
                    anyhow::anyhow!(
                        "engine UTXO query via {} failed for {}: {}",
                        eurl, addr, e
                    )
                })?;
                all.extend(utxos);
            }
            return Ok(all);
        }
        // 2. Auto-detected engine — best-effort, silent fallback.
        if let Some(eurl) = auto_engine_url() {
            let mut all = Vec::new();
            let mut engine_failed = false;
            for addr in addresses {
                match get_utxos_via_engine(eurl, addr) {
                    Ok(utxos) => all.extend(utxos),
                    Err(e) => {
                        tracing::debug!(
                            "[node] engine auto UTXO query failed for {} at {}: {} — falling back to direct node",
                            addr, eurl, e
                        );
                        engine_failed = true;
                        break;
                    }
                }
            }
            if !engine_failed {
                return Ok(all);
            }
            // Fall through to direct-node for this request.
        }
        // 3. Direct-node path.
        match self {
            NodeClient::Wrpc(rpc) => rpc.get_utxos_by_addresses(addresses).await,
            NodeClient::Rest(rest) => rest.get_utxos_by_addresses(addresses).await,
        }
    }

    /// Get spendable UTXOs (mempool-filtered for wRPC, unfiltered for REST).
    pub async fn get_spendable_utxos(&self, address: &str) -> anyhow::Result<Vec<RpcUtxo>> {
        match self {
            NodeClient::Wrpc(rpc) => rpc.get_spendable_utxos(address).await,
            NodeClient::Rest(rest) => rest.get_spendable_utxos(address).await,
        }
    }

    /// Submit a transaction. Payload is in wRPC format.
    pub async fn submit_transaction(
        &self,
        payload: serde_json::Value,
    ) -> anyhow::Result<String> {
        match self {
            NodeClient::Wrpc(rpc) => rpc.submit_transaction(payload).await,
            NodeClient::Rest(rest) => rest.submit_transaction(payload).await,
        }
    }

    /// Get the current virtual DAA score.
    pub async fn get_daa_score(&self) -> anyhow::Result<u64> {
        match self {
            NodeClient::Wrpc(rpc) => {
                let result = rpc
                    .call(
                        "getBlockDagInfo",
                        serde_json::json!({}),
                    )
                    .await?;
                result
                    .get("virtualDaaScore")
                    .and_then(|v| {
                        if let Some(s) = v.as_str() {
                            s.parse::<u64>().ok()
                        } else {
                            v.as_u64()
                        }
                    })
                    .ok_or_else(|| anyhow::anyhow!("Missing virtualDaaScore in blockDagInfo"))
            }
            NodeClient::Rest(rest) => rest.get_daa_score().await,
        }
    }

    /// Returns true if using REST backend.
    pub fn is_rest(&self) -> bool {
        matches!(self, NodeClient::Rest(_))
    }

    /// Returns a human-readable backend name.
    pub fn backend_name(&self) -> &str {
        match self {
            NodeClient::Wrpc(_) => "wRPC",
            NodeClient::Rest(_) => "REST",
        }
    }

    /// Access the underlying wRPC client, if connected via wRPC.
    pub fn as_wrpc(&self) -> Option<&RpcClient> {
        match self {
            NodeClient::Wrpc(rpc) => Some(rpc),
            NodeClient::Rest(_) => None,
        }
    }

    /// Call an arbitrary RPC method (wRPC only). Returns error if using REST.
    pub async fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        match self {
            NodeClient::Wrpc(rpc) => rpc.call(method, params).await,
            NodeClient::Rest(_) => {
                anyhow::bail!(
                    "RPC method '{}' is not available via REST API fallback",
                    method
                )
            }
        }
    }
}

// Engine HTTP helpers (stdlib-only)

/// Engine endpoint response row for `/api/v1/wallet/utxos` (see
/// `kob_engine::matcher::api::WalletUtxoResponse`).
#[derive(serde::Deserialize)]
struct EngineWalletUtxo {
    #[serde(rename = "transactionId")]
    transaction_id: String,
    index: u32,
    amount: u64,
    /// Flat hex string: 4 hex chars version LE + script hex.
    #[serde(rename = "scriptPublicKey")]
    script_public_key: String,
    #[serde(rename = "blockDaaScore", default)]
    block_daa_score: u64,
    #[serde(rename = "isCoinbase", default)]
    is_coinbase: bool,
    /// Covenant id hex (when the UTXO carries a covenant binding), mirrors
    /// the node's `covenantId` field. Optional to tolerate older engines.
    #[serde(rename = "covenantId", default)]
    covenant_id: Option<String>,
}

/// Fetch UTXOs for `address` from the engine's wallet endpoint. Synchronous
/// by design so no new async HTTP crate is needed.
fn get_utxos_via_engine(engine_url: &str, address: &str) -> anyhow::Result<Vec<RpcUtxo>> {
    let path = format!("/api/v1/wallet/utxos?address={}", urlencode(address));
    let resp = http_get_json(engine_url, &path)?;
    let rows: Vec<EngineWalletUtxo> = serde_json::from_value(resp)?;
    Ok(rows.into_iter().map(|r| {
        let (version, script) = if r.script_public_key.len() >= 4 {
            let v = u16::from_str_radix(&r.script_public_key[..4], 16).unwrap_or(0);
            (v, r.script_public_key[4..].to_string())
        } else {
            (0, String::new())
        };
        RpcUtxo {
            outpoint: RpcOutpoint {
                transaction_id: r.transaction_id,
                index: r.index,
            },
            utxo_entry: RpcUtxoEntry {
                amount: r.amount,
                script_public_key: RpcSpk { version, script },
                block_daa_score: r.block_daa_score,
                is_coinbase: r.is_coinbase,
                covenant_id: r.covenant_id,
            },
        }
    }).collect())
}

/// Minimal URL-encoder for the single query-parameter value we send (addresses).
/// Encodes anything outside the RFC 3986 unreserved set.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let ok = (b'A'..=b'Z').contains(&b)
            || (b'a'..=b'z').contains(&b)
            || (b'0'..=b'9').contains(&b)
            || matches!(b, b'-' | b'_' | b'.' | b'~' | b':');
        if ok {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

/// GET a JSON payload from an HTTP endpoint. Mirrors `ifd.rs::http_post_json`
/// (stdlib TcpStream + manual HTTP parsing, no reqwest/tokio dependency).
fn http_get_json(base_url: &str, path: &str) -> anyhow::Result<serde_json::Value> {
    let url_str = if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
        format!("http://{}", base_url)
    } else {
        base_url.to_string()
    };
    if url_str.starts_with("https://") {
        anyhow::bail!("engine-url: HTTPS not supported by stdlib HTTP client ({} )", url_str);
    }
    let without_scheme = url_str.strip_prefix("http://").expect("checked above");
    let host_port = match without_scheme.find('/') {
        Some(idx) => &without_scheme[..idx],
        None => without_scheme,
    };
    let (host, port) = match host_port.find(':') {
        Some(idx) => (
            &host_port[..idx],
            host_port[idx + 1..].parse::<u16>().unwrap_or(80),
        ),
        None => (host_port, 80u16),
    };

    let addr = format!("{}:{}", host, port);
    let sock_addr = addr
        .to_socket_addrs_first()
        .map_err(|e| anyhow::anyhow!("Invalid engine address '{}': {}", addr, e))?;
    let mut stream = TcpStream::connect_timeout(&sock_addr, Duration::from_secs(5))
        .map_err(|e| anyhow::anyhow!("Could not connect to engine at {}: {}", base_url, e))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        path, host_port,
    );
    stream.write_all(request.as_bytes())?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let response_str = String::from_utf8_lossy(&response);

    let http_body = response_str
        .find("\r\n\r\n")
        .map(|idx| &response_str[idx + 4..])
        .ok_or_else(|| anyhow::anyhow!("Invalid HTTP response from engine"))?;

    let status_line = response_str.lines().next().unwrap_or("");
    let status_ok = status_line.contains("200") || status_line.contains("201");

    let body_final = if response_str.contains("Transfer-Encoding: chunked") {
        decode_chunked(http_body)
    } else {
        http_body.to_string()
    };

    let parsed: serde_json::Value = serde_json::from_str(&body_final).map_err(|e| {
        anyhow::anyhow!(
            "Failed to parse engine response: {}. Body head: {}",
            e,
            &body_final[..body_final.len().min(200)]
        )
    })?;

    if !status_ok {
        let err_msg = parsed["error"].as_str().unwrap_or(status_line);
        anyhow::bail!("Engine rejected request: {}", err_msg);
    }

    Ok(parsed)
}

/// Decode HTTP chunked transfer encoding.
fn decode_chunked(body: &str) -> String {
    let mut result = String::new();
    let mut remaining = body;
    loop {
        remaining = remaining.trim_start();
        if remaining.is_empty() {
            break;
        }
        let line_end = remaining.find("\r\n").unwrap_or(remaining.len());
        let size_str = &remaining[..line_end];
        let size = usize::from_str_radix(size_str.trim(), 16).unwrap_or(0);
        if size == 0 {
            break;
        }
        remaining = &remaining[line_end + 2..];
        if remaining.len() < size {
            result.push_str(remaining);
            break;
        }
        result.push_str(&remaining[..size]);
        remaining = &remaining[size..];
        if remaining.starts_with("\r\n") {
            remaining = &remaining[2..];
        }
    }
    result
}

/// Tiny helper trait so `host:port` strings can resolve to a `SocketAddr`
/// without pulling in tokio's async resolver. Returns the first resolved
/// IPv4/IPv6 address.
trait ToSocketAddrsFirst {
    fn to_socket_addrs_first(&self) -> std::io::Result<std::net::SocketAddr>;
}

impl ToSocketAddrsFirst for String {
    fn to_socket_addrs_first(&self) -> std::io::Result<std::net::SocketAddr> {
        use std::net::ToSocketAddrs;
        self.to_socket_addrs()?.next().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no address resolved")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_rest_url() {
        assert_eq!(DEFAULT_REST_URL, "https://api-tn12.kaspa.org");
    }

    #[test]
    fn test_backend_name() {
        // We can't easily construct a NodeClient without a real connection,
        // so just test the const.
        assert_eq!(DEFAULT_REST_URL, "https://api-tn12.kaspa.org");
    }

    #[tokio::test]
    async fn test_connect_invalid_wrpc_falls_back() {
        // Both should fail (no real server), but the error should mention both
        let result =
            NodeClient::connect_with_rest("ws://127.0.0.1:1", Some("http://127.0.0.1:2")).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("REST") || err.contains("connection"),
            "Error should mention REST fallback: {}",
            err
        );
    }
}
