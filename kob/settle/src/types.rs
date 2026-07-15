use serde::{Deserialize, Serialize};
use std::fmt;

/// A transaction outpoint (txid:index).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Outpoint {
    /// Transaction ID as hex string (64 chars).
    pub transaction_id: String,
    /// Output index.
    pub index: u32,
}

impl Outpoint {
    pub fn parse(s: &str) -> crate::Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(crate::KobError::InvalidOutpoint(
                "expected format txid:index".into(),
            ));
        }
        let transaction_id = parts[0].to_string();
        if transaction_id.len() != 64 {
            return Err(crate::KobError::InvalidOutpoint(
                "txid must be 64 hex characters".into(),
            ));
        }
        // Validate hex charset — reject non-hex like "ZZZZ...ZZZZ"
        if !transaction_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(crate::KobError::InvalidOutpoint(
                "txid contains non-hex characters".into(),
            ));
        }
        let index = parts[1]
            .parse::<u32>()
            .map_err(|e| crate::KobError::InvalidOutpoint(format!("invalid index: {}", e)))?;
        Ok(Self {
            transaction_id,
            index,
        })
    }
}

impl fmt::Display for Outpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.transaction_id, self.index)
    }
}

/// Network selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    pub fn address_prefix(&self) -> &str {
        match self {
            Network::Mainnet => "kaspa",
            Network::Testnet => "kaspatest",
        }
    }
}

/// Order side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderSide {
    Buy,
    Sell,
}

impl fmt::Display for OrderSide {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OrderSide::Buy => write!(f, "buy"),
            OrderSide::Sell => write!(f, "sell"),
        }
    }
}

/// Rational price as numerator/denominator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Price {
    pub num: u64,
    pub den: u64,
}

impl Price {
    pub fn new(num: u64, den: u64) -> crate::Result<Self> {
        if den == 0 {
            return Err(crate::KobError::Contract(
                "price denominator cannot be zero".into(),
            ));
        }
        Ok(Self { num, den })
    }

    pub fn as_f64(&self) -> f64 {
        self.num as f64 / self.den as f64
    }
}

impl fmt::Display for Price {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{} ({:.6})", self.num, self.den, self.as_f64())
    }
}

/// An active order on the KOB order book.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    pub outpoint: Outpoint,
    pub side: OrderSide,
    pub token_covenant_id: String,
    pub price: Price,
    pub min_fill: u64,
    pub owner_hash: String,
    pub value: u64,
}

impl fmt::Display for Order {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let token_short = if self.token_covenant_id.len() >= 16 {
            &self.token_covenant_id[..16]
        } else {
            &self.token_covenant_id
        };
        write!(
            f,
            "{} {} | price {} | value {} sompi | min_fill {} | {}",
            self.side,
            token_short,
            self.price,
            self.value,
            self.min_fill,
            self.outpoint,
        )
    }
}

/// UTXO entry from RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoEntry {
    pub outpoint: Outpoint,
    pub value: u64,
    pub script_public_key: String,
}

/// Re-export kaspad's `ScriptPublicKey` as the canonical type.
pub use kaspa_consensus_core::tx::ScriptPublicKey;

/// Contract version selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractVersion {
    V1,
    V2,
}
