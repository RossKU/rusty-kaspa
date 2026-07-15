//! Generic node-connection configuration.
//!
//! `NodeConfig` is the wire format for the node section of a config.json.
//! Extracted from `kob-engine::config` — the rest of that file (`AppConfig`,
//! `HistoryConfig`) stays in `kob-engine` because it carries engine-internal
//! defaults (matcher fee bps, history persistence) that don't belong in a
//! settlement-core crate.

use serde::Deserialize;

/// Node configuration from config.json
#[derive(Debug, Deserialize)]
pub struct NodeConfig {
    pub node: String,
    #[serde(default)]
    pub fallback: Option<String>,
    /// Optional RPC authentication token.
    /// If present, sent as `Authorization: Bearer <token>` during WebSocket handshake.
    #[serde(default)]
    pub rpc_auth: Option<String>,
}
