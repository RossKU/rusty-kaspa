use thiserror::Error;

#[derive(Error, Debug)]
pub enum KobError {
    #[error("RPC error: {0}")]
    Rpc(String),

    #[error("Wallet error: {0}")]
    Wallet(String),

    #[error("Transaction error: {0}")]
    Transaction(String),

    #[error("Insufficient funds: need {need} sompi, have {have} sompi")]
    InsufficientFunds { need: u64, have: u64 },

    #[error("No usable UTXO found")]
    NoUsableUtxo,

    #[error("Invalid outpoint format: {0}")]
    InvalidOutpoint(String),

    #[error("Contract error: {0}")]
    Contract(String),

    #[error("Storage mass exceeded: computed {computed} > limit {limit}")]
    MassExceeded { computed: u64, limit: u64 },

    #[error("Arithmetic overflow: {0}")]
    Overflow(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error("Hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
