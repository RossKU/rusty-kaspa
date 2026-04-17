//! `kob-cli batch` -- Execute multiple operations from a JSON file.
//!
//! Reads a JSON file containing an array of operations and executes them
//! sequentially. Supported operation types:
//! - `deploy-buy`: Deploy a buy order
//! - `deploy-sell`: Deploy a sell order
//! - `cancel`: Cancel an existing order
//! - `receipt`: Consume a trade receipt
//!
//! Each operation in the batch is independent. If one fails, subsequent
//! operations still execute (fail-soft). A summary is printed at the end.
//!
//! JSON format:
//! ```json
//! {
//!   "operations": [
//!     { "type": "deploy-buy", "price_num": 1000, "price_den": 1,
//!       "amount": 10000000, "pair_id": "00..01", "min_fill": 3000000 },
//!     { "type": "deploy-sell", "price_num": 1100, "price_den": 1,
//!       "amount": 10000000, "pair_id": "00..01", "min_fill": 3000000 },
//!     { "type": "cancel", "outpoint": "abc...:0", "side": "buy",
//!       "token": "abc...", "price_num": 1000, "price_den": 1, "min_fill": 3000000 },
//!     { "type": "receipt", "outpoint": "abc...:2", "pair_id": "00..01",
//!       "price_num": 1000, "price_den": 1, "exec_amount": 5000000 }
//!   ]
//! }
//! ```

use crate::{cancel, deploy, matching, receipt};
use kob_core::types::Network;
use serde::Deserialize;
use std::path::Path;
use tracing::info;

/// A batch operations file.
#[derive(Debug, Deserialize)]
pub struct BatchFile {
    pub operations: Vec<BatchOperation>,
}

/// A single batch operation.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum BatchOperation {
    #[serde(rename = "deploy-buy")]
    DeployBuy {
        pair_id: String,
        price_num: u64,
        price_den: u64,
        amount: u64,
        #[serde(default = "default_min_fill")]
        min_fill: u64,
    },

    #[serde(rename = "deploy-sell")]
    DeploySell {
        #[serde(default)]
        pair_id: Option<String>,
        price_num: u64,
        price_den: u64,
        amount: u64,
        #[serde(default = "default_min_fill")]
        min_fill: u64,
    },

    #[serde(rename = "cancel")]
    Cancel {
        outpoint: String,
        side: String,
        #[serde(default)]
        token: Option<String>,
        price_num: u64,
        price_den: u64,
        #[serde(default = "default_min_fill")]
        min_fill: u64,
        #[serde(default = "default_version")]
        version: u8,
        #[serde(default)]
        expiry_daa: u64,
    },

    #[serde(rename = "receipt")]
    Receipt {
        outpoint: String,
        pair_id: String,
        price_num: u64,
        price_den: u64,
        exec_amount: u64,
    },

    #[serde(rename = "match")]
    Match {
        buy_outpoint: String,
        sell_outpoint: String,
        token: String,
        buyer_pubkey: String,
        seller_pubkey: String,
        buy_price_num: u64,
        buy_price_den: u64,
        buy_min_fill: u64,
        sell_price_num: u64,
        sell_price_den: u64,
        sell_min_fill: u64,
    },
}

fn default_min_fill() -> u64 {
    kob_core::MIN_UTXO_VALUE
}

fn default_version() -> u8 {
    14
}

/// Result of a single batch operation.
#[derive(Debug)]
pub struct OpResult {
    pub index: usize,
    pub op_type: String,
    pub success: bool,
    pub txid: Option<String>,
    pub error: Option<String>,
}

impl BatchFile {
    /// Load a batch file from JSON.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read batch file '{}': {}", path.display(), e))?;
        let batch: BatchFile = serde_json::from_str(&contents)
            .map_err(|e| anyhow::anyhow!("Failed to parse batch JSON: {}", e))?;
        Ok(batch)
    }

    /// Validate all operations in the batch.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.operations.is_empty() {
            anyhow::bail!("Batch file contains no operations");
        }

        for (i, op) in self.operations.iter().enumerate() {
            match op {
                BatchOperation::DeployBuy {
                    pair_id,
                    price_den,
                    amount,
                    ..
                } => {
                    if pair_id.len() != 64 {
                        anyhow::bail!("Operation {}: pair_id must be 64 hex chars", i);
                    }
                    if *price_den == 0 {
                        anyhow::bail!("Operation {}: price_den cannot be zero", i);
                    }
                    if *amount < kob_core::MIN_UTXO_VALUE {
                        anyhow::bail!(
                            "Operation {}: amount {} below MIN_UTXO_VALUE",
                            i,
                            amount
                        );
                    }
                }
                BatchOperation::DeploySell {
                    price_den, amount, ..
                } => {
                    if *price_den == 0 {
                        anyhow::bail!("Operation {}: price_den cannot be zero", i);
                    }
                    if *amount < kob_core::MIN_UTXO_VALUE {
                        anyhow::bail!(
                            "Operation {}: amount {} below MIN_UTXO_VALUE",
                            i,
                            amount
                        );
                    }
                }
                BatchOperation::Cancel {
                    outpoint,
                    side,
                    price_den,
                    ..
                } => {
                    if !outpoint.contains(':') {
                        anyhow::bail!(
                            "Operation {}: outpoint must be in format txid:index",
                            i
                        );
                    }
                    if side != "buy" && side != "sell" {
                        anyhow::bail!(
                            "Operation {}: side must be 'buy' or 'sell', got '{}'",
                            i,
                            side
                        );
                    }
                    if *price_den == 0 {
                        anyhow::bail!("Operation {}: price_den cannot be zero", i);
                    }
                }
                BatchOperation::Receipt {
                    outpoint,
                    pair_id,
                    price_den,
                    ..
                } => {
                    if !outpoint.contains(':') {
                        anyhow::bail!(
                            "Operation {}: outpoint must be in format txid:index",
                            i
                        );
                    }
                    if pair_id.len() != 64 {
                        anyhow::bail!("Operation {}: pair_id must be 64 hex chars", i);
                    }
                    if *price_den == 0 {
                        anyhow::bail!("Operation {}: price_den cannot be zero", i);
                    }
                }
                BatchOperation::Match {
                    buy_outpoint,
                    sell_outpoint,
                    token,
                    buy_price_den,
                    sell_price_den,
                    ..
                } => {
                    if !buy_outpoint.contains(':') {
                        anyhow::bail!(
                            "Operation {}: buy_outpoint must be in format txid:index",
                            i
                        );
                    }
                    if !sell_outpoint.contains(':') {
                        anyhow::bail!(
                            "Operation {}: sell_outpoint must be in format txid:index",
                            i
                        );
                    }
                    if token.len() != 64 {
                        anyhow::bail!("Operation {}: token must be 64 hex chars", i);
                    }
                    if *buy_price_den == 0 {
                        anyhow::bail!("Operation {}: buy_price_den cannot be zero", i);
                    }
                    if *sell_price_den == 0 {
                        anyhow::bail!("Operation {}: sell_price_den cannot be zero", i);
                    }
                }
            }
        }

        Ok(())
    }
}

/// Run the batch operations.
pub async fn run(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    batch_file_path: &str,
    fee: u64,
) -> anyhow::Result<()> {
    let batch_path = Path::new(batch_file_path);
    let batch = BatchFile::load(batch_path)?;
    batch.validate()?;

    let op_count = batch.operations.len();
    println!("KOB Batch Operations");
    println!("=====================");
    println!("File:       {}", batch_file_path);
    println!("Operations: {}", op_count);
    println!();

    info!(file = %batch_file_path, operations = op_count, "executing batch");

    let mut results: Vec<OpResult> = Vec::with_capacity(op_count);

    for (i, op) in batch.operations.iter().enumerate() {
        println!();
        println!("=== Operation {}/{} ===", i + 1, op_count);

        let result = execute_operation(wallet_path, node_url, network, i, op, fee).await;

        match result {
            Ok(txid) => {
                let op_type = operation_type_name(op);
                println!("  Result: SUCCESS (TXID: {})", txid.as_deref().unwrap_or("N/A"));
                results.push(OpResult {
                    index: i,
                    op_type,
                    success: true,
                    txid,
                    error: None,
                });
            }
            Err(e) => {
                let op_type = operation_type_name(op);
                println!("  Result: FAILED ({})", e);
                results.push(OpResult {
                    index: i,
                    op_type,
                    success: false,
                    txid: None,
                    error: Some(e.to_string()),
                });
            }
        }

        // Small delay between operations to avoid mempool conflicts
        if i + 1 < op_count {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }

    // Summary
    println!();
    println!();
    println!("Batch Summary");
    println!("==============");
    let success_count = results.iter().filter(|r| r.success).count();
    let fail_count = results.iter().filter(|r| !r.success).count();
    println!("Total:   {}", op_count);
    println!("Success: {}", success_count);
    println!("Failed:  {}", fail_count);
    println!();

    println!(
        "  {:>3}  {:>12}  {:>7}  TXID/ERROR",
        "IDX", "TYPE", "STATUS"
    );
    println!("  {}", "-".repeat(80));

    for r in &results {
        let status = if r.success { "OK" } else { "FAILED" };
        let detail = if let Some(ref txid) = r.txid {
            format!("{}...{}", &txid[..8], &txid[txid.len().saturating_sub(8)..])
        } else if let Some(ref err) = r.error {
            err.chars().take(60).collect()
        } else {
            "N/A".to_string()
        };
        println!("  {:>3}  {:>12}  {:>7}  {}", r.index, r.op_type, status, detail);
    }

    if fail_count > 0 {
        println!();
        println!("WARNING: {} operation(s) failed. Check details above.", fail_count);
    }

    Ok(())
}

/// Execute a single batch operation.
async fn execute_operation(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    _index: usize,
    op: &BatchOperation,
    fee: u64,
) -> anyhow::Result<Option<String>> {
    match op {
        BatchOperation::DeployBuy {
            pair_id,
            price_num,
            price_den,
            amount,
            min_fill,
        } => {
            println!("  Type: deploy-buy");
            println!("  Pair: {}...{}", &pair_id[..8], &pair_id[pair_id.len() - 8..]);
            println!("  Price: {}/{}, Amount: {} sompi", price_num, price_den, amount);
            deploy::deploy_buy(
                wallet_path,
                node_url,
                network,
                pair_id,
                *price_num,
                *price_den,
                *min_fill,
                *amount,
                14, // v14 default for batch (match deploy CLI default)
                fee,
                false, // post_only not supported in batch mode
                None,  // expiry_daa: None = GTC
                deploy::DEFAULT_MAX_MATCHER_FEE,
                None,  // mmfee_bps: None = v14
            )
            .await?;
            // deploy_buy prints the TXID; we return None since we don't capture it
            Ok(None)
        }
        BatchOperation::DeploySell {
            pair_id,
            price_num,
            price_den,
            amount,
            min_fill,
        } => {
            println!("  Type: deploy-sell");
            println!("  Price: {}/{}, Amount: {} sompi", price_num, price_den, amount);
            deploy::deploy_sell(
                wallet_path,
                node_url,
                network,
                pair_id.as_deref(),
                *price_num,
                *price_den,
                *min_fill,
                *amount,
                14, // v14 default for batch (match deploy CLI default)
                fee,
                false, // post_only not supported in batch mode
                None,  // expiry_daa: None = GTC
                deploy::DEFAULT_MAX_MATCHER_FEE,
                None,  // token_utxo: not supported in batch mode
                None,  // fee_utxo: not supported in batch mode
            )
            .await?;
            Ok(None)
        }
        BatchOperation::Cancel {
            outpoint,
            side,
            token,
            price_num,
            price_den,
            min_fill,
            version,
            expiry_daa,
        } => {
            println!("  Type: cancel");
            println!("  Outpoint: {}", outpoint);
            println!("  Side: {}", side);
            cancel::run(
                wallet_path,
                node_url,
                network,
                outpoint,
                Some(side.as_str()),
                token.as_deref(),
                Some(*price_num),
                Some(*price_den),
                Some(*min_fill),
                None,
                fee,
                Some(*version),
                Some(*expiry_daa),
                None,
                0,
                None,
            )
            .await?;
            Ok(None)
        }
        BatchOperation::Receipt {
            outpoint,
            pair_id,
            price_num,
            price_den,
            exec_amount,
        } => {
            println!("  Type: receipt");
            println!("  Outpoint: {}", outpoint);
            receipt::receipt_consume_v1(
                wallet_path,
                node_url,
                network,
                outpoint,
                pair_id,
                *price_num,
                *price_den,
                *exec_amount,
                None,
                None,
            )
            .await?;
            Ok(None)
        }
        BatchOperation::Match {
            buy_outpoint,
            sell_outpoint,
            token,
            buyer_pubkey,
            seller_pubkey,
            buy_price_num,
            buy_price_den,
            buy_min_fill,
            sell_price_num,
            sell_price_den,
            sell_min_fill,
        } => {
            println!("  Type: match");
            println!("  Buy:  {}", buy_outpoint);
            println!("  Sell: {}", sell_outpoint);
            println!("  Token: {}...{}", &token[..8], &token[token.len() - 8..]);
            matching::run(
                wallet_path,
                node_url,
                network,
                buy_outpoint,
                sell_outpoint,
                token,
                *buy_price_num,
                *buy_price_den,
                *buy_min_fill,
                None,
                None,
                None,
                *sell_price_num,
                *sell_price_den,
                *sell_min_fill,
                None,
                None,
                None,
                buyer_pubkey,
                seller_pubkey,
                None,
                14, // v14 default for batch (match deploy CLI default)
                fee,
                0, // buy_expiry (GTC)
                0, // sell_expiry (GTC)
                None, // no tamper mode in batch
            )
            .await?;
            Ok(None)
        }
    }
}

/// Get the type name for display.
fn operation_type_name(op: &BatchOperation) -> String {
    match op {
        BatchOperation::DeployBuy { .. } => "deploy-buy".to_string(),
        BatchOperation::DeploySell { .. } => "deploy-sell".to_string(),
        BatchOperation::Cancel { .. } => "cancel".to_string(),
        BatchOperation::Receipt { .. } => "receipt".to_string(),
        BatchOperation::Match { .. } => "match".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_batch_json_deploy_buy() {
        let json = r#"{
            "operations": [
                {
                    "type": "deploy-buy",
                    "pair_id": "0000000000000000000000000000000000000000000000000000000000000001",
                    "price_num": 1000,
                    "price_den": 1,
                    "amount": 10000000,
                    "min_fill": 3000000
                }
            ]
        }"#;
        let batch: BatchFile = serde_json::from_str(json).unwrap();
        assert_eq!(batch.operations.len(), 1);
        match &batch.operations[0] {
            BatchOperation::DeployBuy {
                pair_id,
                price_num,
                price_den,
                amount,
                min_fill,
            } => {
                assert_eq!(pair_id.len(), 64);
                assert_eq!(*price_num, 1000);
                assert_eq!(*price_den, 1);
                assert_eq!(*amount, 10_000_000);
                assert_eq!(*min_fill, 3_000_000);
            }
            _ => panic!("Expected DeployBuy"),
        }
    }

    #[test]
    fn parse_batch_json_deploy_sell() {
        let json = r#"{
            "operations": [
                {
                    "type": "deploy-sell",
                    "price_num": 1100,
                    "price_den": 1,
                    "amount": 10000000
                }
            ]
        }"#;
        let batch: BatchFile = serde_json::from_str(json).unwrap();
        assert_eq!(batch.operations.len(), 1);
        match &batch.operations[0] {
            BatchOperation::DeploySell {
                pair_id,
                price_num,
                price_den,
                amount,
                min_fill,
            } => {
                assert!(pair_id.is_none());
                assert_eq!(*price_num, 1100);
                assert_eq!(*price_den, 1);
                assert_eq!(*amount, 10_000_000);
                assert_eq!(*min_fill, kob_core::MIN_UTXO_VALUE); // default
            }
            _ => panic!("Expected DeploySell"),
        }
    }

    #[test]
    fn parse_batch_json_cancel() {
        let json = r#"{
            "operations": [
                {
                    "type": "cancel",
                    "outpoint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0",
                    "side": "buy",
                    "token": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "price_num": 1000,
                    "price_den": 1,
                    "min_fill": 3000000
                }
            ]
        }"#;
        let batch: BatchFile = serde_json::from_str(json).unwrap();
        assert_eq!(batch.operations.len(), 1);
        match &batch.operations[0] {
            BatchOperation::Cancel {
                outpoint,
                side,
                token,
                price_num,
                price_den,
                min_fill,
                version,
                expiry_daa,
            } => {
                assert!(outpoint.contains(':'));
                assert_eq!(side, "buy");
                assert!(token.is_some());
                assert_eq!(*price_num, 1000);
                assert_eq!(*price_den, 1);
                assert_eq!(*min_fill, 3_000_000);
                assert_eq!(*version, 14); // default_version
                assert_eq!(*expiry_daa, 0); // default
            }
            _ => panic!("Expected Cancel"),
        }
    }

    #[test]
    fn parse_batch_json_receipt() {
        let json = r#"{
            "operations": [
                {
                    "type": "receipt",
                    "outpoint": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc:2",
                    "pair_id": "0000000000000000000000000000000000000000000000000000000000000001",
                    "price_num": 1000,
                    "price_den": 1,
                    "exec_amount": 5000000
                }
            ]
        }"#;
        let batch: BatchFile = serde_json::from_str(json).unwrap();
        assert_eq!(batch.operations.len(), 1);
        match &batch.operations[0] {
            BatchOperation::Receipt {
                outpoint,
                pair_id,
                price_num,
                price_den,
                exec_amount,
            } => {
                assert!(outpoint.contains(':'));
                assert_eq!(pair_id.len(), 64);
                assert_eq!(*price_num, 1000);
                assert_eq!(*price_den, 1);
                assert_eq!(*exec_amount, 5_000_000);
            }
            _ => panic!("Expected Receipt"),
        }
    }

    #[test]
    fn parse_batch_json_multiple_ops() {
        let json = r#"{
            "operations": [
                {
                    "type": "deploy-buy",
                    "pair_id": "0000000000000000000000000000000000000000000000000000000000000001",
                    "price_num": 1000,
                    "price_den": 1,
                    "amount": 10000000
                },
                {
                    "type": "deploy-sell",
                    "price_num": 1100,
                    "price_den": 1,
                    "amount": 10000000
                },
                {
                    "type": "cancel",
                    "outpoint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0",
                    "side": "sell",
                    "price_num": 1100,
                    "price_den": 1
                }
            ]
        }"#;
        let batch: BatchFile = serde_json::from_str(json).unwrap();
        assert_eq!(batch.operations.len(), 3);
    }

    #[test]
    fn validate_empty_batch() {
        let batch = BatchFile {
            operations: vec![],
        };
        assert!(batch.validate().is_err());
    }

    #[test]
    fn validate_deploy_buy_bad_pair_id() {
        let batch = BatchFile {
            operations: vec![BatchOperation::DeployBuy {
                pair_id: "short".to_string(),
                price_num: 1000,
                price_den: 1,
                amount: 10_000_000,
                min_fill: 3_000_000,
            }],
        };
        assert!(batch.validate().is_err());
    }

    #[test]
    fn validate_deploy_buy_zero_den() {
        let batch = BatchFile {
            operations: vec![BatchOperation::DeployBuy {
                pair_id: "00".repeat(32),
                price_num: 1000,
                price_den: 0,
                amount: 10_000_000,
                min_fill: 3_000_000,
            }],
        };
        assert!(batch.validate().is_err());
    }

    #[test]
    fn validate_deploy_buy_amount_too_small() {
        let batch = BatchFile {
            operations: vec![BatchOperation::DeployBuy {
                pair_id: "00".repeat(32),
                price_num: 1000,
                price_den: 1,
                amount: 100, // below MIN_UTXO_VALUE
                min_fill: 3_000_000,
            }],
        };
        assert!(batch.validate().is_err());
    }

    #[test]
    fn validate_cancel_bad_outpoint() {
        let batch = BatchFile {
            operations: vec![BatchOperation::Cancel {
                outpoint: "no_colon_here".to_string(),
                side: "buy".to_string(),
                token: None,
                price_num: 1000,
                price_den: 1,
                min_fill: 3_000_000,
                version: 8,
                expiry_daa: 0,
            }],
        };
        assert!(batch.validate().is_err());
    }

    #[test]
    fn validate_cancel_bad_side() {
        let batch = BatchFile {
            operations: vec![BatchOperation::Cancel {
                outpoint: "aa".repeat(32).to_string() + ":0",
                side: "neither".to_string(),
                token: None,
                price_num: 1000,
                price_den: 1,
                min_fill: 3_000_000,
                version: 8,
                expiry_daa: 0,
            }],
        };
        assert!(batch.validate().is_err());
    }

    #[test]
    fn validate_receipt_bad_pair_id() {
        let batch = BatchFile {
            operations: vec![BatchOperation::Receipt {
                outpoint: "aa".repeat(32).to_string() + ":2",
                pair_id: "short".to_string(),
                price_num: 1000,
                price_den: 1,
                exec_amount: 5_000_000,
            }],
        };
        assert!(batch.validate().is_err());
    }

    #[test]
    fn validate_valid_batch() {
        let batch = BatchFile {
            operations: vec![
                BatchOperation::DeployBuy {
                    pair_id: "00".repeat(32),
                    price_num: 1000,
                    price_den: 1,
                    amount: 10_000_000,
                    min_fill: 3_000_000,
                },
                BatchOperation::DeploySell {
                    pair_id: Some("00".repeat(32)),
                    price_num: 1100,
                    price_den: 1,
                    amount: 10_000_000,
                    min_fill: 3_000_000,
                },
            ],
        };
        assert!(batch.validate().is_ok());
    }

    #[test]
    fn default_min_fill_value() {
        assert_eq!(default_min_fill(), kob_core::MIN_UTXO_VALUE);
    }

    #[test]
    fn operation_type_name_correct() {
        assert_eq!(
            operation_type_name(&BatchOperation::DeployBuy {
                pair_id: String::new(),
                price_num: 0,
                price_den: 1,
                amount: 0,
                min_fill: 0,
            }),
            "deploy-buy"
        );
        assert_eq!(
            operation_type_name(&BatchOperation::DeploySell {
                pair_id: None,
                price_num: 0,
                price_den: 1,
                amount: 0,
                min_fill: 0,
            }),
            "deploy-sell"
        );
        assert_eq!(
            operation_type_name(&BatchOperation::Cancel {
                outpoint: String::new(),
                side: String::new(),
                token: None,
                price_num: 0,
                price_den: 1,
                min_fill: 0,
                version: 8,
                expiry_daa: 0,
            }),
            "cancel"
        );
        assert_eq!(
            operation_type_name(&BatchOperation::Receipt {
                outpoint: String::new(),
                pair_id: String::new(),
                price_num: 0,
                price_den: 1,
                exec_amount: 0,
            }),
            "receipt"
        );
        assert_eq!(
            operation_type_name(&BatchOperation::Match {
                buy_outpoint: String::new(),
                sell_outpoint: String::new(),
                token: String::new(),
                buyer_pubkey: String::new(),
                seller_pubkey: String::new(),
                buy_price_num: 0,
                buy_price_den: 1,
                buy_min_fill: 0,
                sell_price_num: 0,
                sell_price_den: 1,
                sell_min_fill: 0,
            }),
            "match"
        );
    }

    #[test]
    fn op_result_structure() {
        let r = OpResult {
            index: 0,
            op_type: "deploy-buy".to_string(),
            success: true,
            txid: Some("abcdef1234567890".to_string()),
            error: None,
        };
        assert!(r.success);
        assert!(r.txid.is_some());
        assert!(r.error.is_none());
    }

    #[test]
    fn deploy_sell_default_min_fill_from_json() {
        // When min_fill is omitted from JSON, it should default to MIN_UTXO_VALUE
        let json = r#"{
            "type": "deploy-sell",
            "price_num": 1100,
            "price_den": 1,
            "amount": 10000000
        }"#;
        let op: BatchOperation = serde_json::from_str(json).unwrap();
        match op {
            BatchOperation::DeploySell { min_fill, .. } => {
                assert_eq!(min_fill, kob_core::MIN_UTXO_VALUE);
            }
            _ => panic!("Expected DeploySell"),
        }
    }

    #[test]
    fn cancel_default_min_fill_from_json() {
        let json = r#"{
            "type": "cancel",
            "outpoint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0",
            "side": "buy",
            "price_num": 1000,
            "price_den": 1
        }"#;
        let op: BatchOperation = serde_json::from_str(json).unwrap();
        match op {
            BatchOperation::Cancel { min_fill, .. } => {
                assert_eq!(min_fill, kob_core::MIN_UTXO_VALUE);
            }
            _ => panic!("Expected Cancel"),
        }
    }

    #[test]
    fn parse_batch_json_match() {
        let json = r#"{
            "operations": [
                {
                    "type": "match",
                    "buy_outpoint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0",
                    "sell_outpoint": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:0",
                    "token": "0000000000000000000000000000000000000000000000000000000000000001",
                    "buyer_pubkey": "1111111111111111111111111111111111111111111111111111111111111111",
                    "seller_pubkey": "2222222222222222222222222222222222222222222222222222222222222222",
                    "buy_price_num": 1000,
                    "buy_price_den": 1,
                    "buy_min_fill": 3000000,
                    "sell_price_num": 900,
                    "sell_price_den": 1,
                    "sell_min_fill": 3000000
                }
            ]
        }"#;
        let batch: BatchFile = serde_json::from_str(json).unwrap();
        assert_eq!(batch.operations.len(), 1);
        match &batch.operations[0] {
            BatchOperation::Match {
                buy_outpoint,
                sell_outpoint,
                token,
                buy_price_num,
                sell_price_num,
                ..
            } => {
                assert!(buy_outpoint.contains(':'));
                assert!(sell_outpoint.contains(':'));
                assert_eq!(token.len(), 64);
                assert_eq!(*buy_price_num, 1000);
                assert_eq!(*sell_price_num, 900);
            }
            _ => panic!("Expected Match"),
        }
    }

    #[test]
    fn validate_match_bad_buy_outpoint() {
        let batch = BatchFile {
            operations: vec![BatchOperation::Match {
                buy_outpoint: "no_colon".to_string(),
                sell_outpoint: "aa".repeat(32) + ":0",
                token: "00".repeat(32),
                buyer_pubkey: "11".repeat(32),
                seller_pubkey: "22".repeat(32),
                buy_price_num: 1000,
                buy_price_den: 1,
                buy_min_fill: 3_000_000,
                sell_price_num: 900,
                sell_price_den: 1,
                sell_min_fill: 3_000_000,
            }],
        };
        assert!(batch.validate().is_err());
    }

    #[test]
    fn validate_match_bad_sell_outpoint() {
        let batch = BatchFile {
            operations: vec![BatchOperation::Match {
                buy_outpoint: "aa".repeat(32) + ":0",
                sell_outpoint: "no_colon".to_string(),
                token: "00".repeat(32),
                buyer_pubkey: "11".repeat(32),
                seller_pubkey: "22".repeat(32),
                buy_price_num: 1000,
                buy_price_den: 1,
                buy_min_fill: 3_000_000,
                sell_price_num: 900,
                sell_price_den: 1,
                sell_min_fill: 3_000_000,
            }],
        };
        assert!(batch.validate().is_err());
    }

    #[test]
    fn validate_match_bad_token() {
        let batch = BatchFile {
            operations: vec![BatchOperation::Match {
                buy_outpoint: "aa".repeat(32) + ":0",
                sell_outpoint: "bb".repeat(32) + ":0",
                token: "short".to_string(),
                buyer_pubkey: "11".repeat(32),
                seller_pubkey: "22".repeat(32),
                buy_price_num: 1000,
                buy_price_den: 1,
                buy_min_fill: 3_000_000,
                sell_price_num: 900,
                sell_price_den: 1,
                sell_min_fill: 3_000_000,
            }],
        };
        assert!(batch.validate().is_err());
    }

    #[test]
    fn validate_match_zero_buy_den() {
        let batch = BatchFile {
            operations: vec![BatchOperation::Match {
                buy_outpoint: "aa".repeat(32) + ":0",
                sell_outpoint: "bb".repeat(32) + ":0",
                token: "00".repeat(32),
                buyer_pubkey: "11".repeat(32),
                seller_pubkey: "22".repeat(32),
                buy_price_num: 1000,
                buy_price_den: 0,
                buy_min_fill: 3_000_000,
                sell_price_num: 900,
                sell_price_den: 1,
                sell_min_fill: 3_000_000,
            }],
        };
        assert!(batch.validate().is_err());
    }

    #[test]
    fn validate_match_zero_sell_den() {
        let batch = BatchFile {
            operations: vec![BatchOperation::Match {
                buy_outpoint: "aa".repeat(32) + ":0",
                sell_outpoint: "bb".repeat(32) + ":0",
                token: "00".repeat(32),
                buyer_pubkey: "11".repeat(32),
                seller_pubkey: "22".repeat(32),
                buy_price_num: 1000,
                buy_price_den: 1,
                buy_min_fill: 3_000_000,
                sell_price_num: 900,
                sell_price_den: 0,
                sell_min_fill: 3_000_000,
            }],
        };
        assert!(batch.validate().is_err());
    }

    #[test]
    fn validate_match_valid() {
        let batch = BatchFile {
            operations: vec![BatchOperation::Match {
                buy_outpoint: "aa".repeat(32) + ":0",
                sell_outpoint: "bb".repeat(32) + ":0",
                token: "00".repeat(32),
                buyer_pubkey: "11".repeat(32),
                seller_pubkey: "22".repeat(32),
                buy_price_num: 1000,
                buy_price_den: 1,
                buy_min_fill: 3_000_000,
                sell_price_num: 900,
                sell_price_den: 1,
                sell_min_fill: 3_000_000,
            }],
        };
        assert!(batch.validate().is_ok());
    }

    #[test]
    fn parse_batch_mixed_with_match() {
        let json = r#"{
            "operations": [
                {
                    "type": "deploy-buy",
                    "pair_id": "0000000000000000000000000000000000000000000000000000000000000001",
                    "price_num": 1000,
                    "price_den": 1,
                    "amount": 10000000
                },
                {
                    "type": "match",
                    "buy_outpoint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0",
                    "sell_outpoint": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:0",
                    "token": "0000000000000000000000000000000000000000000000000000000000000001",
                    "buyer_pubkey": "1111111111111111111111111111111111111111111111111111111111111111",
                    "seller_pubkey": "2222222222222222222222222222222222222222222222222222222222222222",
                    "buy_price_num": 1000,
                    "buy_price_den": 1,
                    "buy_min_fill": 3000000,
                    "sell_price_num": 900,
                    "sell_price_den": 1,
                    "sell_min_fill": 3000000
                }
            ]
        }"#;
        let batch: BatchFile = serde_json::from_str(json).unwrap();
        assert_eq!(batch.operations.len(), 2);
        assert!(matches!(&batch.operations[0], BatchOperation::DeployBuy { .. }));
        assert!(matches!(&batch.operations[1], BatchOperation::Match { .. }));
    }
}
