//! Configuration loading for node connection and wallet keys.

use kob_core::wallet::SecureKey;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Node configuration from config.json
#[derive(Debug, Deserialize)]
pub struct NodeConfig {
    pub node: String,
    #[serde(default)]
    pub fallback: Option<String>,
    /// Optional RPC authentication token (F17).
    /// If present, sent as `Authorization: Bearer <token>` during WebSocket handshake.
    #[serde(default)]
    pub rpc_auth: Option<String>,
}

/// Historical data persistence configuration (MT5 style).
///
/// Only M1 (1-minute) candles are persisted to SQLite. Higher timeframes
/// (5m, 15m, 1h, 4h, 1d, 1w) are aggregated on-the-fly from M1 rows.
/// Tick data stays in-memory only (TradeLog ring buffer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryConfig {
    /// SQLite database path (default: "history.db")
    pub db_path: String,
    /// M1 candle retention in seconds. 0 = forever (default).
    pub m1_retention_secs: u64,
    /// How often to run cleanup in seconds (default: 3600).
    pub purge_interval_secs: u64,
    /// Hard cap on DB file size in MB. When exceeded, oldest M1 candles
    /// are pruned automatically. 0 = no limit.
    pub max_db_size_mb: u64,
}

impl Default for HistoryConfig {
    fn default() -> Self {
        Self {
            db_path: "history.db".to_string(),
            m1_retention_secs: 0,       // forever
            purge_interval_secs: 3600,
            max_db_size_mb: 2048,       // 2GB hard cap
        }
    }
}

/// Combined application configuration
pub struct AppConfig {
    pub node_url: String,
    pub fallback_url: Option<String>,
    pub private_key: SecureKey,
    pub public_key: Vec<u8>,
    pub address: String,
    /// Optional RPC authentication token (F17).
    pub rpc_auth: Option<String>,
    /// Historical data persistence configuration.
    pub history: HistoryConfig,
    /// Whether a ZK prover backend is available for freezable token covenants
    /// (e.g. USDC). When false (default), orders involving freezable tokens
    /// are accepted into the book but skipped during matching.
    pub zk_prover_enabled: bool,
}

// Custom Debug that doesn't leak key material or auth tokens
impl std::fmt::Debug for AppConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppConfig")
            .field("node_url", &self.node_url)
            .field("fallback_url", &self.fallback_url)
            .field("private_key", &"[REDACTED]")
            .field("public_key", &hex::encode(&self.public_key))
            .field("address", &self.address)
            .field("rpc_auth", &self.rpc_auth.as_ref().map(|_| "[REDACTED]"))
            .field("history", &self.history)
            .field("zk_prover_enabled", &self.zk_prover_enabled)
            .finish()
    }
}

impl AppConfig {
    /// Load configuration from node config and wallet JSON files.
    ///
    /// Supports both plaintext and encrypted wallet files. If the wallet
    /// file is encrypted, pass the passphrase. Otherwise pass `None`.
    pub fn load(config_path: &str, wallet_path: &str) -> Result<Self, String> {
        Self::load_with_passphrase(config_path, wallet_path, None)
    }

    /// Load configuration with optional passphrase for encrypted wallets.
    pub fn load_with_passphrase(
        config_path: &str,
        wallet_path: &str,
        passphrase: Option<&str>,
    ) -> Result<Self, String> {
        let config_path = Path::new(config_path);
        let wallet_path = Path::new(wallet_path);

        let config_str = fs::read_to_string(config_path)
            .map_err(|e| format!("Failed to read config {}: {}", config_path.display(), e))?;
        let node_config: NodeConfig = serde_json::from_str(&config_str)
            .map_err(|e| format!("Failed to parse config: {}", e))?;

        // Validate node URL scheme
        if !node_config.node.starts_with("wss://") && !node_config.node.starts_with("ws://") {
            return Err(format!(
                "Node URL must use ws:// or wss:// scheme. Got: {}",
                node_config.node
            ));
        }
        if node_config.node.starts_with("ws://")
            && !node_config.node.contains("localhost")
            && !node_config.node.contains("127.0.0.1")
        {
            eprintln!(
                "WARNING: Using unencrypted ws:// connection to remote node. Consider using wss:// for security."
            );
        }

        // Use kob_core's auto-detecting wallet loader
        let wallet = kob_core::WalletContext::load_full(
            wallet_path, passphrase, None,
        ).map_err(|e| format!("Failed to load wallet: {}", e))?;

        let private_key = kob_core::SecureKey::from_bytes(*wallet.privkey().as_bytes());
        let public_key = wallet.pubkey.to_vec();
        let address = wallet.address.clone();

        Ok(AppConfig {
            node_url: node_config.node,
            fallback_url: node_config.fallback,
            private_key,
            public_key,
            address,
            rpc_auth: node_config.rpc_auth,
            history: HistoryConfig::default(),
            zk_prover_enabled: false,
        })
    }

    /// Get owner hash (blake2b-256 of public key).
    /// Used as owner_hash in buy_order state.
    pub fn owner_hash(&self) -> [u8; 32] {
        kob_core::blake2b_256(&self.public_key)
    }

    /// Get private key as fixed-size array.
    ///
    /// Returns a copy of the key bytes. Caller should zeroize after use.
    pub fn private_key_bytes(&self) -> [u8; 32] {
        *self.private_key.as_bytes()
    }
}

