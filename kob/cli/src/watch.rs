//! Lightweight block scanner for CLI price discovery.
//!
//! Scans Kaspa blocks for KOB fill transactions by detecting
//! sigscripts containing pushData matching the canonical RS size.
//! Extracts price_num/price_den from the redeemScript bytes to provide
//! trustless price information without depending on the Matcher API.

use kob_core::{BUY_RS_SIZE, SELL_RS_SIZE};

/// Maximum number of fills to keep in the rolling window per token.
const MAX_FILLS_PER_TOKEN: usize = 20;

// Public types

/// Information extracted from a fill transaction.
#[derive(Debug, Clone)]
pub struct FillInfo {
    /// Token covenant ID (hex, 64 chars). Empty for sell fills (tcid not in sell RS).
    pub token_id: String,
    /// Price numerator from the redeemScript.
    pub price_num: u64,
    /// Price denominator from the redeemScript.
    pub price_den: u64,
    /// KAS amount involved (from TX output values).
    pub kas_amount: u64,
    /// DAA score of the block containing this fill.
    pub daa_score: u64,
    /// Transaction ID of the fill TX.
    pub tx_id: String,
    /// Whether this was a buy or sell fill.
    pub side: FillSide,
}

/// Which side of the order was filled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FillSide {
    Buy,
    Sell,
}

impl std::fmt::Display for FillSide {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FillSide::Buy => write!(f, "BUY"),
            FillSide::Sell => write!(f, "SELL"),
        }
    }
}

/// Summary statistics from recent fills.
#[derive(Debug, Clone)]
pub struct FillSummary {
    pub last_price_num: u64,
    pub last_price_den: u64,
    pub vwap_num: u64,
    pub vwap_den: u64,
    pub high_num: u64,
    pub high_den: u64,
    pub low_num: u64,
    pub low_den: u64,
    pub total_volume_kas: u64,
    pub fill_count: usize,
}

// Sigscript parsing — detect fill TXs

/// Extract the last pushData blob from a sigscript.
///
/// Kaspa sigscripts use Bitcoin-style push opcodes:
///   - 0x01..0x4b: direct push of N bytes
///   - 0x4c (OP_PUSHDATA1): next 1 byte = length, then data
///   - 0x4d (OP_PUSHDATA2): next 2 bytes (LE) = length, then data
///   - 0x4e (OP_PUSHDATA4): next 4 bytes (LE) = length, then data
///   - 0x00 = OP_FALSE, 0x51 = OP_1, etc. (single-byte opcodes)
///
/// We walk the entire sigscript, tracking the last data push seen.
fn extract_last_pushdata(sigscript: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;
    let mut last_data: Option<Vec<u8>> = None;

    while pos < sigscript.len() {
        let op = sigscript[pos];
        pos += 1;

        if op == 0x00 {
            // OP_FALSE — not a data push, skip
            continue;
        } else if (0x01..=0x4b).contains(&op) {
            let len = op as usize;
            if pos + len > sigscript.len() {
                break;
            }
            last_data = Some(sigscript[pos..pos + len].to_vec());
            pos += len;
        } else if op == 0x4c {
            // OP_PUSHDATA1
            if pos >= sigscript.len() {
                break;
            }
            let len = sigscript[pos] as usize;
            pos += 1;
            if pos + len > sigscript.len() {
                break;
            }
            last_data = Some(sigscript[pos..pos + len].to_vec());
            pos += len;
        } else if op == 0x4d {
            // OP_PUSHDATA2
            if pos + 2 > sigscript.len() {
                break;
            }
            let len = u16::from_le_bytes([sigscript[pos], sigscript[pos + 1]]) as usize;
            pos += 2;
            if pos + len > sigscript.len() {
                break;
            }
            last_data = Some(sigscript[pos..pos + len].to_vec());
            pos += len;
        } else if op == 0x4e {
            // OP_PUSHDATA4
            if pos + 4 > sigscript.len() {
                break;
            }
            let len = u32::from_le_bytes([
                sigscript[pos],
                sigscript[pos + 1],
                sigscript[pos + 2],
                sigscript[pos + 3],
            ]) as usize;
            pos += 4;
            if pos + len > sigscript.len() {
                break;
            }
            last_data = Some(sigscript[pos..pos + len].to_vec());
            pos += len;
        }
        // else: single-byte opcode (OP_1..OP_16, etc.) — skip
    }

    last_data
}

/// Try to detect a fill TX from a sigscript.
///
/// Returns (token_id, price_num, price_den, side) if the last pushData
/// in the sigscript matches a canonical RS size and parses as a valid order.
pub fn detect_fill_from_sigscript(sigscript: &[u8]) -> Option<(String, u64, u64, FillSide)> {
    let last_push = extract_last_pushdata(sigscript)?;
    let len = last_push.len();

    // Validate full body bytecode matches the canonical contract
    let body_offset = if len == BUY_RS_SIZE {
        let off = len - kob_core::BUY_ORDER_BODY.len();
        if last_push[off..] != *kob_core::BUY_ORDER_BODY {
            return None;
        }
        Some(off)
    } else if len == SELL_RS_SIZE {
        let off = len - kob_core::SELL_ORDER_BODY.len();
        if last_push[off..] != *kob_core::SELL_ORDER_BODY {
            return None;
        }
        Some(off)
    } else {
        None
    };
    body_offset?;

    // Delegate to core's parser for field extraction
    let parsed = kob_core::parse_redeem_script(&last_push)?;
    let side = match parsed.order_type {
        kob_core::OrderSide::Buy => FillSide::Buy,
        kob_core::OrderSide::Sell => FillSide::Sell,
    };
    let tcid = if parsed.token_cov_id == [0u8; 32] {
        String::new()
    } else {
        hex::encode(parsed.token_cov_id)
    };
    Some((tcid, parsed.price_num, parsed.price_den, side))
}

// Block scanning (one-shot via getBlock RPC)

/// Lightweight transaction representation for fill scanning.
/// Unlike the engine's TransactionData, this focuses on sigscript content.
#[derive(Debug, Clone)]
struct ScanTxInput {
    sig_script: Vec<u8>,
}

#[derive(Debug, Clone)]
struct ScanTxOutput {
    value: u64,
}

#[derive(Debug, Clone)]
struct ScanTx {
    tx_id: String,
    inputs: Vec<ScanTxInput>,
    outputs: Vec<ScanTxOutput>,
}

/// Parse a transaction from RPC JSON, keeping sigscript data.
fn parse_scan_tx(json: &serde_json::Value) -> Option<ScanTx> {
    let tx_id = json
        .get("verboseData")
        .and_then(|v| v.get("transactionId"))
        .and_then(|v| v.as_str())
        .or_else(|| json.get("transactionId").and_then(|v| v.as_str()))?
        .to_string();

    let inputs = json
        .get("inputs")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|inp| {
                    let sig_script = inp
                        .get("signatureScript")
                        .and_then(|v| v.as_str())
                        .and_then(|s| hex::decode(s).ok())
                        .unwrap_or_default();
                    ScanTxInput { sig_script }
                })
                .collect()
        })
        .unwrap_or_default();

    let outputs = json
        .get("outputs")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|out| {
                    let value = out.get("amount").and_then(|v| v.as_u64())?;
                    Some(ScanTxOutput { value })
                })
                .collect()
        })
        .unwrap_or_default();

    Some(ScanTx {
        tx_id,
        inputs,
        outputs,
    })
}

/// Scan a block's transactions for v14 fill TXs.
fn scan_block_for_fills(
    block_json: &serde_json::Value,
    token_filter: &str,
) -> Vec<FillInfo> {
    let mut fills = Vec::new();

    // Get DAA score from block header
    let daa_score = block_json
        .get("header")
        .and_then(|h| h.get("daaScore"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u64>().ok())
        .or_else(|| {
            block_json
                .get("header")
                .and_then(|h| h.get("daaScore"))
                .and_then(|v| v.as_u64())
        })
        .unwrap_or(0);

    let txs = block_json
        .get("transactions")
        .and_then(|t| t.as_array());

    let txs = match txs {
        Some(arr) => arr,
        None => return fills,
    };

    for tx_json in txs {
        let tx = match parse_scan_tx(tx_json) {
            Some(t) => t,
            None => continue,
        };

        // Check each input's sigscript for a v14 RS
        for input in &tx.inputs {
            if let Some((tcid, pnum, pden, side)) =
                detect_fill_from_sigscript(&input.sig_script)
            {
                // Apply token filter: if filter is non-empty, match against tcid
                // For sell fills, tcid is empty — match only if filter is also empty
                if !token_filter.is_empty() && (tcid.is_empty() || tcid != token_filter) {
                    continue;
                }

                // Sum all output values as approximate KAS amount
                let kas_amount: u64 = tx.outputs.iter().map(|o| o.value).sum();

                fills.push(FillInfo {
                    token_id: tcid,
                    price_num: pnum,
                    price_den: pden,
                    kas_amount,
                    daa_score,
                    tx_id: tx.tx_id.clone(),
                    side,
                });
                break; // One fill per TX
            }
        }
    }

    fills
}

// Public async API

/// Scan recent blocks for fill TXs (one-shot, no subscription).
///
/// Uses `getBlockDagInfo` to get the current tip, then fetches the last
/// `block_count` blocks via `getBlock` and scans for v14 fills.
///
/// Returns fills matching the given token, most recent first.
pub async fn scan_recent_fills(
    node_url: &str,
    token: &str,
    block_count: u64,
) -> Vec<FillInfo> {
    let rpc = match crate::node::NodeClient::connect(node_url).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("[WATCH] Failed to connect to node: {}", e);
            return Vec::new();
        }
    };

    // Get current tip hash via getBlockDagInfo
    let dag_info = match rpc
        .call("getBlockDagInfo", serde_json::json!({}))
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("[WATCH] getBlockDagInfo failed: {}", e);
            return Vec::new();
        }
    };

    let tip_hash = match dag_info
        .get("tipHashes")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
    {
        Some(h) => h.to_string(),
        None => {
            tracing::warn!("[WATCH] No tip hash found in getBlockDagInfo response");
            return Vec::new();
        }
    };

    // Walk back from tip, fetching blocks
    let mut all_fills = Vec::new();
    let mut current_hash = tip_hash;
    let mut blocks_fetched = 0u64;

    while blocks_fetched < block_count {
        let block_resp = match rpc
            .call(
                "getBlock",
                serde_json::json!({
                    "hash": current_hash,
                    "includeTransactions": true,
                }),
            )
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("[WATCH] getBlock failed for {}: {}", current_hash, e);
                break;
            }
        };

        let block = match block_resp.get("block") {
            Some(b) => b,
            None => &block_resp,
        };

        let fills = scan_block_for_fills(block, token);
        all_fills.extend(fills);
        blocks_fetched += 1;

        // Get parent hash to walk backwards
        let parent = block
            .get("header")
            .and_then(|h| h.get("parents"))
            .and_then(|p| p.as_array())
            .and_then(|arr| arr.first())
            .and_then(|p| {
                // Parents can be an array of objects with parentHashes or just strings
                p.get("parentHashes")
                    .and_then(|ph| ph.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|v| v.as_str())
                    .or_else(|| p.as_str())
            });

        match parent {
            Some(h) => current_hash = h.to_string(),
            None => break,
        }
    }

    // Sort by DAA score descending (most recent first)
    all_fills.sort_by(|a, b| b.daa_score.cmp(&a.daa_score));
    all_fills
}

/// Watch blocks for fill TXs. Returns the first fill matching the token
/// within `timeout_secs`, or None if no fills are seen.
///
/// First scans the last 100 blocks for historical fills, then subscribes
/// to new blocks via `notifyBlockAdded`.
pub async fn watch_fills(
    node_url: &str,
    token: &str,
    timeout_secs: u64,
) -> Option<FillInfo> {
    // First check recent blocks
    let recent = scan_recent_fills(node_url, token, 100).await;
    if let Some(fill) = recent.into_iter().next() {
        return Some(fill);
    }

    // Subscribe to new blocks and wait for a fill
    let rpc = match crate::node::NodeClient::connect(node_url).await {
        Ok(c) => c,
        Err(_) => return None,
    };

    // Subscribe to block notifications
    let _ = rpc
        .call(
            "notifyBlockAdded",
            serde_json::json!({}),
        )
        .await;

    // Poll for new blocks via getBlockDagInfo tip changes
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let mut last_tip = String::new();

    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let dag_info = match rpc
            .call("getBlockDagInfo", serde_json::json!({}))
            .await
        {
            Ok(v) => v,
            Err(_) => continue,
        };

        let tip = dag_info
            .get("tipHashes")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        if tip == last_tip || tip.is_empty() {
            continue;
        }
        last_tip = tip.clone();

        let block_resp = match rpc
            .call(
                "getBlock",
                serde_json::json!({
                    "hash": tip,
                    "includeTransactions": true,
                }),
            )
            .await
        {
            Ok(v) => v,
            Err(_) => continue,
        };

        let block = match block_resp.get("block") {
            Some(b) => b,
            None => &block_resp,
        };

        let fills = scan_block_for_fills(block, token);
        if let Some(fill) = fills.into_iter().next() {
            return Some(fill);
        }
    }

    None
}

/// Compute summary statistics from a list of fills.
pub fn summarize_fills(fills: &[FillInfo]) -> Option<FillSummary> {
    if fills.is_empty() {
        return None;
    }

    let last = &fills[0]; // Most recent (fills sorted by daa_score desc)

    // VWAP: weighted average price. weight = kas_amount.
    // price_f = pnum / pden, so vwap = sum(price_f * kas) / sum(kas)
    // To stay integer: vwap_num/vwap_den = sum(pnum * kas / pden) / sum(kas)
    // Simplify by using f64 for accumulation then converting back.
    let mut total_kas = 0u64;
    let mut weighted_sum = 0.0f64;
    let mut high_price = 0.0f64;
    let mut low_price = f64::MAX;
    let mut high_num = 0u64;
    let mut high_den = 1u64;
    let mut low_num = 0u64;
    let mut low_den = 1u64;

    for fill in fills {
        let price = fill.price_num as f64 / fill.price_den as f64;
        let kas = fill.kas_amount;
        weighted_sum += price * kas as f64;
        total_kas = total_kas.saturating_add(kas);

        if price > high_price {
            high_price = price;
            high_num = fill.price_num;
            high_den = fill.price_den;
        }
        if price < low_price {
            low_price = price;
            low_num = fill.price_num;
            low_den = fill.price_den;
        }
    }

    // Convert VWAP to integer ratio
    let vwap = if total_kas > 0 {
        weighted_sum / total_kas as f64
    } else {
        0.0
    };
    let precision: u64 = 100_000_000;
    let vwap_raw = (vwap * precision as f64).round() as u64;
    let g = gcd(vwap_raw, precision);
    let vwap_num = if g > 0 { vwap_raw / g } else { 0 };
    let vwap_den = if g > 0 { precision / g } else { 1 };

    Some(FillSummary {
        last_price_num: last.price_num,
        last_price_den: last.price_den,
        vwap_num,
        vwap_den,
        high_num,
        high_den,
        low_num,
        low_den,
        total_volume_kas: total_kas,
        fill_count: fills.len(),
    })
}

/// GCD helper (same as in market.rs).
fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// Run the `watch` CLI command: print recent fills, then subscribe.
pub async fn run_watch(node_url: &str, token: &str) -> anyhow::Result<()> {
    println!("Scanning recent blocks for {} fills...", if token.is_empty() { "all" } else { token });

    let fills = scan_recent_fills(node_url, token, 200).await;

    if fills.is_empty() {
        println!("No recent fills found.");
    } else {
        println!("Recent fills ({}):", fills.len());
        println!(
            "{:<6} {:<10} {:<10} {:<14} {:<12} TX_ID",
            "SIDE", "PNUM", "PDEN", "KAS_AMOUNT", "DAA_SCORE"
        );
        for fill in fills.iter().take(MAX_FILLS_PER_TOKEN) {
            println!(
                "{:<6} {:<10} {:<10} {:<14} {:<12} {}",
                fill.side,
                fill.price_num,
                fill.price_den,
                fill.kas_amount,
                fill.daa_score,
                &fill.tx_id[..fill.tx_id.len().min(16)],
            );
        }

        if let Some(summary) = summarize_fills(&fills) {
            println!();
            println!("Summary:");
            println!(
                "  Last price:  {}/{}  ({:.8})",
                summary.last_price_num,
                summary.last_price_den,
                summary.last_price_num as f64 / summary.last_price_den as f64
            );
            println!(
                "  VWAP:        {}/{}  ({:.8})",
                summary.vwap_num,
                summary.vwap_den,
                summary.vwap_num as f64 / summary.vwap_den as f64
            );
            println!(
                "  High:        {}/{}  ({:.8})",
                summary.high_num,
                summary.high_den,
                summary.high_num as f64 / summary.high_den as f64
            );
            println!(
                "  Low:         {}/{}  ({:.8})",
                summary.low_num,
                summary.low_den,
                summary.low_num as f64 / summary.low_den as f64
            );
            println!("  Volume:      {} sompi ({} fills)", summary.total_volume_kas, summary.fill_count);
        }
    }

    // Now subscribe and print new fills as they appear
    println!();
    println!("Watching for new fills (Ctrl+C to stop)...");

    let rpc = crate::node::NodeClient::connect(node_url).await?;
    let mut last_tip = String::new();

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let dag_info = match rpc
            .call("getBlockDagInfo", serde_json::json!({}))
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("[WATCH] getBlockDagInfo error: {}", e);
                continue;
            }
        };

        let tip = dag_info
            .get("tipHashes")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        if tip == last_tip || tip.is_empty() {
            continue;
        }
        last_tip = tip.clone();

        let block_resp = match rpc
            .call(
                "getBlock",
                serde_json::json!({
                    "hash": tip,
                    "includeTransactions": true,
                }),
            )
            .await
        {
            Ok(v) => v,
            Err(_) => continue,
        };

        let block = match block_resp.get("block") {
            Some(b) => b,
            None => &block_resp,
        };

        let fills = scan_block_for_fills(block, token);
        for fill in &fills {
            println!(
                "FILL {} pnum={} pden={} kas={} daa={} tx={}",
                fill.side,
                fill.price_num,
                fill.price_den,
                fill.kas_amount,
                fill.daa_score,
                &fill.tx_id[..fill.tx_id.len().min(16)],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: build a buy RS via core builder (uses coprime pnum/pden to avoid GCD reduction)
    fn make_buy_rs(tcid: &[u8; 32], pnum: u64, pden: u64) -> Vec<u8> {
        let ohash = [0u8; 32];
        let bspkh = [0u8; 32];
        kob_core::build_buy_redeem_script(tcid, pnum, pden, 1_000_000, &ohash, &bspkh, 50_000, 0, 0).unwrap()
    }

    // Helper: build a sell RS via core builder
    fn make_sell_rs(pnum: u64, pden: u64) -> Vec<u8> {
        let ohash = [0u8; 32];
        let sspkh = [0u8; 32];
        kob_core::build_sell_redeem_script(pnum, pden, 1_000_000, &ohash, &sspkh, 50_000, 0, 0).unwrap()
    }

    // Helper: build a sigscript with pushData(rs) as last element
    fn make_fill_sigscript(rs: &[u8], prefix_pushes: &[&[u8]]) -> Vec<u8> {
        let mut ss = Vec::new();
        // Add prefix pushes (small data like indices)
        for push in prefix_pushes {
            if push.len() <= 0x4b {
                ss.push(push.len() as u8);
                ss.extend_from_slice(push);
            }
        }
        // Add OP_1 before RS (selector)
        ss.push(0x51);
        // Add RS as pushData2 (since RS > 255 bytes)
        ss.push(0x4d); // OP_PUSHDATA2
        let len = rs.len() as u16;
        ss.extend_from_slice(&len.to_le_bytes());
        ss.extend_from_slice(rs);
        ss
    }

    // --- core parse_redeem_script integration ---

    #[test]
    fn core_parse_buy_valid() {
        let tcid = [0xab; 32];
        let rs = make_buy_rs(&tcid, 7, 3);
        let parsed = kob_core::parse_redeem_script(&rs).unwrap();
        assert_eq!(parsed.token_cov_id, tcid);
        assert_eq!(parsed.price_num, 7);
        assert_eq!(parsed.price_den, 3);
    }

    #[test]
    fn core_parse_buy_wrong_size() {
        let rs = vec![0u8; 400]; // Wrong size
        assert!(kob_core::parse_redeem_script(&rs).is_none());
    }

    #[test]
    fn core_parse_buy_wrong_prefix() {
        let tcid = [0xab; 32];
        let mut rs = make_buy_rs(&tcid, 7, 3);
        rs[0] = 0x10; // Wrong prefix
        assert!(kob_core::parse_redeem_script(&rs).is_none());
    }

    #[test]
    fn core_parse_sell_valid() {
        let rs = make_sell_rs(3, 7);
        let parsed = kob_core::parse_redeem_script(&rs).unwrap();
        assert_eq!(parsed.price_num, 3);
        assert_eq!(parsed.price_den, 7);
    }

    #[test]
    fn core_parse_sell_wrong_size() {
        let rs = vec![0u8; 200];
        assert!(kob_core::parse_redeem_script(&rs).is_none());
    }

    #[test]
    fn core_parse_sell_wrong_prefix() {
        let mut rs = make_sell_rs(3, 7);
        rs[0] = 0x20; // Wrong prefix
        assert!(kob_core::parse_redeem_script(&rs).is_none());
    }

    // --- extract_last_pushdata ---

    #[test]
    fn extract_last_pushdata_simple() {
        // Push 3 bytes: [0x03, 0xaa, 0xbb, 0xcc]
        let ss = vec![0x03, 0xaa, 0xbb, 0xcc];
        let data = extract_last_pushdata(&ss).unwrap();
        assert_eq!(data, vec![0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn extract_last_pushdata_multiple() {
        // Push 2 bytes, then push 3 bytes
        let ss = vec![0x02, 0x11, 0x22, 0x03, 0xaa, 0xbb, 0xcc];
        let data = extract_last_pushdata(&ss).unwrap();
        assert_eq!(data, vec![0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn extract_last_pushdata_with_op1() {
        // Push 2 bytes, OP_1 (0x51), push 3 bytes
        let ss = vec![0x02, 0x11, 0x22, 0x51, 0x03, 0xaa, 0xbb, 0xcc];
        let data = extract_last_pushdata(&ss).unwrap();
        assert_eq!(data, vec![0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn extract_last_pushdata_pushdata2() {
        // OP_PUSHDATA2 with 4 bytes of data
        let ss = vec![0x4d, 0x04, 0x00, 0x01, 0x02, 0x03, 0x04];
        let data = extract_last_pushdata(&ss).unwrap();
        assert_eq!(data, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn extract_last_pushdata_empty() {
        let ss: Vec<u8> = vec![];
        assert!(extract_last_pushdata(&ss).is_none());
    }

    // --- detect_fill_from_sigscript ---

    #[test]
    fn detect_buy_fill_v12() {
        let tcid = [0x42; 32];
        let rs = make_buy_rs(&tcid, 41, 152);
        let ss = make_fill_sigscript(&rs, &[&[0x01], &[0x02], &[0x00], &[0x03]]);
        let (token, pnum, pden, side) = detect_fill_from_sigscript(&ss).unwrap();
        assert_eq!(token, hex::encode(tcid));
        assert_eq!(pnum, 41);
        assert_eq!(pden, 152);
        assert_eq!(side, FillSide::Buy);
    }

    #[test]
    fn detect_sell_fill_v12() {
        let rs = make_sell_rs(789, 1000);
        let ss = make_fill_sigscript(&rs, &[&[0x01]]);
        let (token, pnum, pden, side) = detect_fill_from_sigscript(&ss).unwrap();
        assert!(token.is_empty()); // Sell RS has no tcid
        assert_eq!(pnum, 789);
        assert_eq!(pden, 1000);
        assert_eq!(side, FillSide::Sell);
    }

    #[test]
    fn detect_fill_no_match() {
        // Random sigscript that doesn't contain a v12 RS
        let ss = vec![0x03, 0xaa, 0xbb, 0xcc, 0x51, 0x02, 0x11, 0x22];
        assert!(detect_fill_from_sigscript(&ss).is_none());
    }

    #[test]
    fn detect_fill_fake_body_rejected() {
        // Correct size and state prefix, but body bytes are all 0xFF (not the canonical bytecode).
        // This simulates an attacker crafting a TX with matching pushData size.
        let buy_body_offset = BUY_RS_SIZE - kob_core::BUY_ORDER_BODY.len();
        let tcid = [0xab; 32];
        let mut rs = vec![0u8; BUY_RS_SIZE];
        rs[0] = 0x20;
        rs[1..33].copy_from_slice(&tcid);
        rs[33] = 0x08;
        rs[34..42].copy_from_slice(&500u64.to_le_bytes());
        rs[42] = 0x08;
        rs[43..51].copy_from_slice(&1000u64.to_le_bytes());
        // Fill body with garbage instead of canonical bytecode
        for b in &mut rs[buy_body_offset..] {
            *b = 0xff;
        }
        let ss = make_fill_sigscript(&rs, &[&[0x01]]);
        assert!(detect_fill_from_sigscript(&ss).is_none(), "fake body must be rejected");

        // Same for sell
        let sell_body_offset = SELL_RS_SIZE - kob_core::SELL_ORDER_BODY.len();
        let mut rs_sell = vec![0u8; SELL_RS_SIZE];
        rs_sell[0] = 0x08;
        rs_sell[1..9].copy_from_slice(&789u64.to_le_bytes());
        rs_sell[9] = 0x08;
        rs_sell[10..18].copy_from_slice(&1000u64.to_le_bytes());
        for b in &mut rs_sell[sell_body_offset..] {
            *b = 0xff;
        }
        let ss_sell = make_fill_sigscript(&rs_sell, &[&[0x01]]);
        assert!(detect_fill_from_sigscript(&ss_sell).is_none(), "fake sell body must be rejected");
    }

    // --- scan_block_for_fills ---

    #[test]
    fn scan_block_with_buy_fill() {
        let tcid = [0xde; 32];
        let rs = make_buy_rs(&tcid, 1, 2);
        let ss = make_fill_sigscript(&rs, &[&[0x01], &[0x02], &[0x00], &[0x03]]);

        let block = serde_json::json!({
            "header": {
                "daaScore": "12345",
                "parents": [{"parentHashes": ["abc123"]}]
            },
            "transactions": [{
                "verboseData": {"transactionId": "deadbeef01234567"},
                "inputs": [{
                    "previousOutpoint": {"transactionId": "prev01", "index": 0},
                    "signatureScript": hex::encode(&ss)
                }],
                "outputs": [
                    {"amount": 500000, "scriptPublicKey": {"version": 0, "scriptPublicKey": "aa20"}},
                    {"amount": 300000, "scriptPublicKey": {"version": 0, "scriptPublicKey": "2020"}}
                ],
                "payload": ""
            }]
        });

        let fills = scan_block_for_fills(&block, &hex::encode(tcid));
        assert_eq!(fills.len(), 1);
        assert_eq!(fills[0].price_num, 1);
        assert_eq!(fills[0].price_den, 2);
        assert_eq!(fills[0].daa_score, 12345);
        assert_eq!(fills[0].kas_amount, 800000);
        assert_eq!(fills[0].tx_id, "deadbeef01234567");
        assert_eq!(fills[0].side, FillSide::Buy);
    }

    #[test]
    fn scan_block_no_fills() {
        let block = serde_json::json!({
            "header": {"daaScore": "100"},
            "transactions": [{
                "verboseData": {"transactionId": "abc"},
                "inputs": [{
                    "previousOutpoint": {"transactionId": "prev", "index": 0},
                    "signatureScript": "0102aabb"
                }],
                "outputs": [{"amount": 1000, "scriptPublicKey": {"version": 0, "scriptPublicKey": ""}}],
                "payload": ""
            }]
        });

        let fills = scan_block_for_fills(&block, "");
        assert!(fills.is_empty());
    }

    #[test]
    fn scan_block_token_filter() {
        let tcid_a = [0xaa; 32];
        let tcid_b = [0xbb; 32];
        let rs_a = make_buy_rs(&tcid_a, 1, 2);
        let rs_b = make_buy_rs(&tcid_b, 3, 4);
        let ss_a = make_fill_sigscript(&rs_a, &[&[0x01]]);
        let ss_b = make_fill_sigscript(&rs_b, &[&[0x01]]);

        let block = serde_json::json!({
            "header": {"daaScore": "100"},
            "transactions": [
                {
                    "verboseData": {"transactionId": "tx_a"},
                    "inputs": [{"previousOutpoint": {"transactionId": "p", "index": 0}, "signatureScript": hex::encode(&ss_a)}],
                    "outputs": [{"amount": 1000, "scriptPublicKey": {"version": 0, "scriptPublicKey": ""}}],
                    "payload": ""
                },
                {
                    "verboseData": {"transactionId": "tx_b"},
                    "inputs": [{"previousOutpoint": {"transactionId": "p", "index": 0}, "signatureScript": hex::encode(&ss_b)}],
                    "outputs": [{"amount": 2000, "scriptPublicKey": {"version": 0, "scriptPublicKey": ""}}],
                    "payload": ""
                }
            ]
        });

        // Filter for token A only
        let fills = scan_block_for_fills(&block, &hex::encode(tcid_a));
        assert_eq!(fills.len(), 1);
        assert_eq!(fills[0].price_num, 1);
    }

    // --- summarize_fills ---

    #[test]
    fn summarize_single_fill() {
        let fills = vec![FillInfo {
            token_id: "ab".repeat(32),
            price_num: 1,
            price_den: 2,
            kas_amount: 1_000_000,
            daa_score: 100,
            tx_id: "tx1".to_string(),
            side: FillSide::Buy,
        }];
        let summary = summarize_fills(&fills).unwrap();
        assert_eq!(summary.last_price_num, 1);
        assert_eq!(summary.last_price_den, 2);
        assert_eq!(summary.fill_count, 1);
        assert_eq!(summary.total_volume_kas, 1_000_000);
    }

    #[test]
    fn summarize_multiple_fills() {
        let fills = vec![
            FillInfo {
                token_id: "ab".repeat(32),
                price_num: 2,
                price_den: 1,
                kas_amount: 500_000,
                daa_score: 200,
                tx_id: "tx2".to_string(),
                side: FillSide::Buy,
            },
            FillInfo {
                token_id: "ab".repeat(32),
                price_num: 1,
                price_den: 1,
                kas_amount: 500_000,
                daa_score: 100,
                tx_id: "tx1".to_string(),
                side: FillSide::Sell,
            },
        ];
        let summary = summarize_fills(&fills).unwrap();
        // Last price = most recent = 2/1
        assert_eq!(summary.last_price_num, 2);
        assert_eq!(summary.last_price_den, 1);
        // High = 2/1, Low = 1/1
        assert_eq!(summary.high_num, 2);
        assert_eq!(summary.high_den, 1);
        assert_eq!(summary.low_num, 1);
        assert_eq!(summary.low_den, 1);
        assert_eq!(summary.total_volume_kas, 1_000_000);
        assert_eq!(summary.fill_count, 2);
    }

    #[test]
    fn summarize_empty() {
        assert!(summarize_fills(&[]).is_none());
    }

    // --- Price calculation with slippage (reused from market.rs logic) ---

    #[test]
    fn fill_price_to_limit_with_slippage() {
        // If last fill was at price 1/2, a buy market order with 100bps slippage
        // should set price to approximately 1/2 * 1.01 = 0.505
        let pnum = 1u64;
        let pden = 2u64;
        let price = pnum as f64 / pden as f64;
        let slippage_bps = 100u64;
        let final_price = price * (1.0 + slippage_bps as f64 / 10_000.0);
        assert!((final_price - 0.505).abs() < 1e-10);
    }

    // --- Fallback chain tests ---

    #[test]
    fn fallback_fills_found_returns_price() {
        // Simulate: fills found, should use them
        let fills = vec![FillInfo {
            token_id: "ab".repeat(32),
            price_num: 3,
            price_den: 4,
            kas_amount: 100_000,
            daa_score: 500,
            tx_id: "tx".to_string(),
            side: FillSide::Buy,
        }];
        let summary = summarize_fills(&fills).unwrap();
        assert_eq!(summary.last_price_num, 3);
        assert_eq!(summary.last_price_den, 4);
    }

    #[test]
    fn fallback_no_fills_no_matcher_is_error() {
        // Simulate: no fills found and no matcher URL → should be error
        let fills: Vec<FillInfo> = vec![];
        let summary = summarize_fills(&fills);
        assert!(summary.is_none()); // None means no price data → error path
    }

    // --- Edge cases ---

    #[test]
    fn detect_fill_truncated_sigscript() {
        // Sigscript that starts a PUSHDATA2 but is truncated
        let ss = vec![0x4d, 0xff, 0x01]; // Says 511 bytes but only 3 bytes total
        assert!(detect_fill_from_sigscript(&ss).is_none());
    }

    #[test]
    fn detect_fill_op_false_ignored() {
        // OP_FALSE (0x00) before actual data push
        let rs = make_sell_rs(1, 2);
        let mut ss = vec![0x00]; // OP_FALSE
        ss.push(0x4d); // OP_PUSHDATA2
        let len = rs.len() as u16;
        ss.extend_from_slice(&len.to_le_bytes());
        ss.extend_from_slice(&rs);
        let (_, pnum, pden, side) = detect_fill_from_sigscript(&ss).unwrap();
        assert_eq!(pnum, 1);
        assert_eq!(pden, 2);
        assert_eq!(side, FillSide::Sell);
    }

    #[test]
    fn core_parse_buy_max_values() {
        let tcid = [0xff; 32];
        // u64::MAX / u64::MAX -> GCD reduces to 1/1
        let rs = make_buy_rs(&tcid, u64::MAX, u64::MAX);
        let parsed = kob_core::parse_redeem_script(&rs).unwrap();
        assert_eq!(parsed.price_num, 1);
        assert_eq!(parsed.price_den, 1);
    }

    #[test]
    fn core_parse_sell_min_values() {
        let rs = make_sell_rs(1, 1);
        let parsed = kob_core::parse_redeem_script(&rs).unwrap();
        assert_eq!(parsed.price_num, 1);
        assert_eq!(parsed.price_den, 1);
    }
}
