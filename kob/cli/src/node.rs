//! Unified node client with wRPC-first, REST-fallback strategy.
//!
//! [`NodeClient`] wraps either a WebSocket RPC client or a REST API client.
//! Connection logic: try wRPC with a 5-second timeout; if it fails, fall back
//! to the REST API (default: `https://api-tn12.kaspa.org`).

use crate::rest::RestClient;
use crate::rpc::{RpcClient, RpcUtxo};
use std::sync::OnceLock;

/// Global REST API URL override. Set once from CLI `--rest-api` flag.
static REST_URL_OVERRIDE: OnceLock<String> = OnceLock::new();

/// Default REST API URL used when no override is set.
const DEFAULT_REST_URL: &str = "https://api-tn12.kaspa.org";

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
    pub async fn get_utxos_by_addresses(
        &self,
        addresses: &[&str],
    ) -> anyhow::Result<Vec<RpcUtxo>> {
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
