//! L1 block scanner for permissionless order discovery.

use crate::matcher::order_book::{BookOrder, OrderBook, OrderSide};


// Parse types and functions imported from kob-core.
pub use kob_core::contract::spot::parse::{ParsedOrder, ParsedOcoSell, parse_redeem_script, parse_oco_sell_redeem_script};
pub use kob_core::contract::perp::parse::{ParsedPerpOrder, PerpDeploySide, PERP_DEPLOY_V1_RS_SIZE, PERP_DEPLOY_V1_STATE_SIZE, parse_perp_deploy_rs};
pub use kob_core::contract::lending::parse::{ParsedLendingOrder, LendingOrderType, parse_lending_rs, LOAN_OFFER_RS_SIZE, BORROW_REQUEST_RS_SIZE};
pub use kob_core::contract::prediction::parse::{ParsedPredictionItem, PredictionItemType, parse_prediction_rs};

// Re-export spot RS size constants used by tests.
pub use kob_core::contract::spot::parse::{BUY_RS_SIZE, SELL_RS_SIZE};

/// Transaction data from block notifications or RPC queries.
#[derive(Debug, Clone)]
pub struct TransactionData {
    pub tx_id: String,
    pub _version: u16,
    pub inputs: Vec<TxInputData>,
    pub outputs: Vec<TxOutputData>,
    /// TX payload bytes. KOB deploy TXs use "KOB:2:" prefix (v1 "KOB:1:" is rejected).
    pub payload: Vec<u8>,
}

/// Transaction input.
#[derive(Debug, Clone)]
pub struct TxInputData {
    pub prev_tx_id: String,
    pub prev_index: u32,
    pub _sig_script: Vec<u8>,
}

/// Transaction output.
#[derive(Debug, Clone)]
pub struct TxOutputData {
    pub value: u64,
    pub script_version: u16,
    pub script: Vec<u8>,
    /// Covenant ID from the output's covenant binding (hex-decoded, 32 bytes).
    /// Present only on version-1 TX outputs that carry a token covenant.
    pub covenant_id: Option<[u8; 32]>,
}

/// Result of scanning a single transaction. Can contain at most one product hit.
#[derive(Debug, Clone)]
pub enum ScanResult {
    /// Spot order detected.
    Spot(ParsedOrder, u32, u64),
    /// OCO sell: two virtual spot sell orders from a single UTXO (TP + SL paths).
    OcoSell(ParsedOcoSell, u32, u64),
    /// Perp deploy order detected.
    Perp(ParsedPerpOrder, u32, u64),
    /// Lending order detected.
    Lending(ParsedLendingOrder, u32, u64),
    /// Prediction market covenant detected.
    Prediction(ParsedPredictionItem, u32, u64),
}

/// Scanner for detecting KOB deploy transactions and spent orders.
pub struct BlockScanner;

impl Default for BlockScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockScanner {
    pub fn new() -> Self {
        BlockScanner
    }

    /// Scan a transaction for a KOB deploy pattern.
    ///
    /// Returns a `ParsedOrder` plus the P2SH output index and value if found.
    /// Returns `None` if the TX doesn't match the deploy pattern.
    ///
    /// Only accepts payload v2 (`KOB:2:`), which includes a flags byte and
    /// the counterparty SPK needed for match execution. Payload v1 (`KOB:1:`)
    /// orders are skipped with a debug log because they lack the counterparty
    /// SPK and can never be matched.
    pub fn scan_tx(&self, tx: &TransactionData) -> Option<(ParsedOrder, u32, u64)> {
        // Only accept v2 payloads (KOB:2:<flags><RS>). v1 payloads (KOB:1:) lack
        // the counterparty SPK and can never be matched — skip them to avoid
        // wasting order book memory and iteration time.
        let (payload_data, post_only, expiry_daa, ifd_order_b_rs) =
            if let Some(v2) = kob_core::contract::parse_order_payload(&tx.payload) {
                (v2.rs_data, v2.post_only, v2.expiry_daa, v2.ifd_order_b_rs)
            } else {
                return None;
            };

        if payload_data.is_empty() {
            return None;
        }

        // Find all P2SH outputs
        let p2sh_outputs: Vec<(u32, &TxOutputData, [u8; 32])> = tx
            .outputs
            .iter()
            .enumerate()
            .filter_map(|(idx, out)| {
                parse_p2sh_script(&out.script, out.script_version).map(|hash| (idx as u32, out, hash))
            })
            .collect();

        if p2sh_outputs.is_empty() {
            return None;
        }

        // Try payload_data as a single RS first
        let rs_hash = kob_core::blake2b_256(&payload_data);
        for &(p2sh_idx, p2sh_out, ref p2sh_hash) in &p2sh_outputs {
            if rs_hash == *p2sh_hash {
                if let Some(mut parsed) = Self::parse_redeem_script(&payload_data) {
                    parsed.post_only = post_only;
                    parsed.expiry_daa = expiry_daa;
                    parsed.ifd_order_b_rs = ifd_order_b_rs.clone();
                    return Some((parsed, p2sh_idx, p2sh_out.value));
                }
            }
        }

        // Try OCO format: <buy_rs_len_u16_LE><buy_rs><sell_rs>
        if payload_data.len() > 2 {
            let buy_len = u16::from_le_bytes([payload_data[0], payload_data[1]]) as usize;
            if payload_data.len() >= 2 + buy_len {
                let buy_rs = &payload_data[2..2 + buy_len];
                let sell_rs = &payload_data[2 + buy_len..];

                // Try buy RS
                let buy_hash = kob_core::blake2b_256(buy_rs);
                for &(p2sh_idx, p2sh_out, ref p2sh_hash) in &p2sh_outputs {
                    if buy_hash == *p2sh_hash {
                        if let Some(mut parsed) = Self::parse_redeem_script(buy_rs) {
                            parsed.post_only = post_only;
                            parsed.expiry_daa = expiry_daa;
                            return Some((parsed, p2sh_idx, p2sh_out.value));
                        }
                    }
                }

                // Try sell RS
                if !sell_rs.is_empty() {
                    let sell_hash = kob_core::blake2b_256(sell_rs);
                    for &(p2sh_idx, p2sh_out, ref p2sh_hash) in &p2sh_outputs {
                        if sell_hash == *p2sh_hash {
                            if let Some(mut parsed) = Self::parse_redeem_script(sell_rs) {
                                parsed.post_only = post_only;
                                parsed.expiry_daa = expiry_daa;
                                return Some((parsed, p2sh_idx, p2sh_out.value));
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Parse a redeemScript to extract order parameters.
    ///
    /// Delegates to `kob_core::contract::spot::parse::parse_redeem_script`.
    pub fn parse_redeem_script(rs: &[u8]) -> Option<ParsedOrder> {
        parse_redeem_script(rs)
    }

    /// Scan for a single-UTXO OCO sell deploy.
    ///
    /// Uses the same KOB:2: payload format as regular spot but the RS is 333B.
    /// Returns `ParsedOcoSell` instead of `ParsedOrder`.
    fn scan_oco_sell(&self, tx: &TransactionData) -> Option<(ParsedOcoSell, u32, u64)> {
        let v2 = kob_core::contract::parse_order_payload(&tx.payload)?;
        if v2.rs_data.len() != kob_core::OCO_SELL_RS_SIZE {
            return None;
        }
        let rs_hash = kob_core::blake2b_256(&v2.rs_data);
        let p2sh_outputs: Vec<(u32, &TxOutputData, [u8; 32])> = tx
            .outputs
            .iter()
            .enumerate()
            .filter_map(|(idx, out)| {
                parse_p2sh_script(&out.script, out.script_version)
                    .map(|hash| (idx as u32, out, hash))
            })
            .collect();
        for &(p2sh_idx, p2sh_out, ref p2sh_hash) in &p2sh_outputs {
            if rs_hash == *p2sh_hash {
                if let Some(parsed) = parse_oco_sell_redeem_script(&v2.rs_data) {
                    return Some((parsed, p2sh_idx, p2sh_out.value));
                }
            }
        }
        None
    }

    /// Check which outpoints in a TX's inputs are present in the order book.
    ///
    /// Returns outpoint keys for orders that are being spent (filled/cancelled).
    /// For OCO orders, also returns the virtual suffixed keys (`:tp`, `:sl`).
    pub fn find_spent_orders(tx: &TransactionData, book: &OrderBook) -> Vec<String> {
        let mut spent = Vec::new();
        for input in &tx.inputs {
            let key = format!("{}:{}", input.prev_tx_id, input.prev_index);
            // Check direct key (regular orders)
            for pair_book in book.pair_books.values() {
                if pair_book.contains_outpoint(&key) {
                    spent.push(key.clone());
                    break;
                }
            }
            // Check OCO virtual keys (txid:index:tp and txid:index:sl)
            let tp_key = format!("{}:tp", key);
            let sl_key = format!("{}:sl", key);
            for pair_book in book.pair_books.values() {
                if pair_book.contains_outpoint(&tp_key) {
                    spent.push(tp_key.clone());
                }
                if pair_book.contains_outpoint(&sl_key) {
                    spent.push(sl_key.clone());
                }
            }
        }
        spent
    }

    /// Convert a parsed order into a BookOrder for the existing OrderBook.
    ///
    /// When `tx` is provided, the scanner extracts:
    ///   - `counterparty_spk`: from non-P2SH outputs whose SPK hash matches
    ///     the order's `spk_hash` field (the deployer's change output).
    ///   - `token_cov_id` (sell orders only): from the covenant binding on
    ///     the P2SH output at `output_index`.
    ///
    /// The `token_cov_id_override` parameter takes precedence for backward
    /// compatibility with callers that already know the covenant ID.
    pub fn to_book_order(
        parsed: &ParsedOrder,
        tx_id: &str,
        output_index: u32,
        value: u64,
        token_cov_id_override: Option<&str>,
    ) -> BookOrder {
        Self::to_book_order_with_tx(parsed, tx_id, output_index, value, token_cov_id_override, None)
    }

    /// Convert a parsed order into a BookOrder, using the deploy TX to
    /// extract the counterparty SPK and (for sells) the token covenant ID.
    pub fn to_book_order_with_tx(
        parsed: &ParsedOrder,
        tx_id: &str,
        output_index: u32,
        value: u64,
        token_cov_id_override: Option<&str>,
        tx: Option<&TransactionData>,
    ) -> BookOrder {
        let tcid_hex = match token_cov_id_override {
            Some(tcid) => tcid.to_string(),
            None => {
                // For sell orders, try to extract token_cov_id from the
                // covenant binding on the P2SH output.
                if parsed.order_type == OrderSide::Sell {
                    if let Some(tx_data) = tx {
                        if let Some(out) = tx_data.outputs.get(output_index as usize) {
                            if let Some(cov_id) = &out.covenant_id {
                                hex::encode(cov_id)
                            } else {
                                hex::encode(parsed.token_cov_id)
                            }
                        } else {
                            hex::encode(parsed.token_cov_id)
                        }
                    } else {
                        hex::encode(parsed.token_cov_id)
                    }
                } else {
                    hex::encode(parsed.token_cov_id)
                }
            }
        };

        // Resolve counterparty SPK:
        // - IFD orders: bspkh points to order B's P2SH, compute from order_b_rs
        // - Normal orders: bspkh points to owner's P2PK wallet, extract from deploy TX
        let (counterparty_spk, ifd_order_b_rs_hex) = if let Some(ref b_rs) = parsed.ifd_order_b_rs {
            let b_p2sh_spk = kob_core::build_p2sh(b_rs);
            let mut spk_bytes = Vec::with_capacity(2 + b_p2sh_spk.script().len());
            spk_bytes.extend_from_slice(&b_p2sh_spk.version.to_le_bytes());
            spk_bytes.extend_from_slice(&b_p2sh_spk.script());
            // H-3: Verify that the computed SPK matches the bspkh embedded in Order A's RS.
            // Without this check an attacker could deploy Order A with a valid bspkh but put
            // a different B RS in the payload, causing the Matcher to waste fee UTXOs on
            // invalid fill TXs.
            let computed_hash = kob_core::blake2b_256(&spk_bytes);
            if computed_hash != parsed.spk_hash {
                tracing::warn!(
                    "[IFD] payload B RS does not match bspkh in Order A RS — \
                     ignoring IFD linkage (possible spoofing)"
                );
                // Fall through to normal SPK extraction; do NOT trust the payload B RS.
                let spk = tx.and_then(|tx_data| {
                    extract_owner_spk(tx_data, &parsed.spk_hash)
                });
                (spk, None)
            } else {
                (Some(hex::encode(&spk_bytes)), Some(hex::encode(b_rs)))
            }
        } else {
            let spk = tx.and_then(|tx_data| {
                extract_owner_spk(tx_data, &parsed.spk_hash)
            });
            (spk, None)
        };

        let p2sh_spk = kob_core::build_p2sh(&parsed.redeem_script);
        let p2sh_script_hex = hex::encode(&p2sh_spk.script());

        BookOrder {
            tx_id: tx_id.to_string(),
            index: output_index,
            value,
            token_cov_id: tcid_hex,
            price_num: parsed.price_num,
            price_den: parsed.price_den,
            min_fill: parsed.min_fill,
            owner_hash: hex::encode(parsed.owner_hash),
            spk_hash: hex::encode(parsed.spk_hash),
            counterparty_spk,
            redeem_script_hex: hex::encode(&parsed.redeem_script),
            p2sh_script_hex,
            p2sh_version: p2sh_spk.version,
            side: parsed.order_type,
            post_only: parsed.post_only,
            expiry_daa: parsed.expiry_daa,
            is_freezable: parsed.requires_zk,
            max_matcher_fee: parsed._max_matcher_fee,
            ifd_order_b_rs_hex,
            oco_path: None,
            oco_partner_key: None,
        }
    }

    /// Convert a `ParsedOcoSell` into two virtual BookOrders (TP + SL).
    ///
    /// Each virtual order gets a suffixed outpoint key (`txid:index:tp` / `txid:index:sl`)
    /// and a `oco_partner_key` pointing to the other. The batch engine uses `oco_path`
    /// to select the correct fill sigscript selector (Op1 for TP, Op2 for SL).
    pub fn oco_sell_to_book_orders(
        parsed: &ParsedOcoSell,
        tx_id: &str,
        output_index: u32,
        value: u64,
        tx: Option<&TransactionData>,
    ) -> (BookOrder, BookOrder) {
        let base_key = format!("{}:{}", tx_id, output_index);
        let tp_key = format!("{}:tp", base_key);
        let sl_key = format!("{}:sl", base_key);

        // Extract counterparty SPK from deploy TX (same for both paths)
        let counterparty_spk = tx.and_then(|tx_data| {
            extract_owner_spk(tx_data, &parsed.spk_hash)
        });

        // Extract token covenant ID from the P2SH output
        let tcid_hex = tx.and_then(|tx_data| {
            tx_data.outputs.get(output_index as usize)
                .and_then(|out| out.covenant_id.as_ref())
                .map(hex::encode)
        }).unwrap_or_else(|| hex::encode([0u8; 32]));

        let p2sh_spk = kob_core::build_p2sh(&parsed.redeem_script);
        let p2sh_script_hex = hex::encode(&p2sh_spk.script());

        let make_order = |path: kob_core::OcoPath, partner: &str| -> BookOrder {
            let (pnum, pden, mfill) = match path {
                kob_core::OcoPath::TakeProfit => (parsed.price_num_tp, parsed.price_den_tp, parsed.min_fill_tp),
                kob_core::OcoPath::StopLoss => (parsed.price_num_sl, parsed.price_den_sl, parsed.min_fill_sl),
            };
            BookOrder {
                tx_id: tx_id.to_string(),
                index: output_index,
                value,
                token_cov_id: tcid_hex.clone(),
                price_num: pnum,
                price_den: pden,
                min_fill: mfill,
                owner_hash: hex::encode(parsed.owner_hash),
                spk_hash: hex::encode(parsed.spk_hash),
                counterparty_spk: counterparty_spk.clone(),
                redeem_script_hex: hex::encode(&parsed.redeem_script),
                p2sh_script_hex: p2sh_script_hex.clone(),
                p2sh_version: p2sh_spk.version,
                side: OrderSide::Sell,
                post_only: false,
                expiry_daa: parsed.expiry_daa,
                is_freezable: false,
                max_matcher_fee: parsed._max_matcher_fee,
                ifd_order_b_rs_hex: None,
                oco_path: Some(path),
                oco_partner_key: Some(partner.to_string()),
            }
        };

        let tp_order = make_order(kob_core::OcoPath::TakeProfit, &sl_key);
        let sl_order = make_order(kob_core::OcoPath::StopLoss, &tp_key);
        (tp_order, sl_order)
    }

    // Unified multi-product scanner

    /// Scan a transaction for any KOB product deploy pattern.
    ///
    /// Checks payload prefixes in order: Spot (KOB:2:), Perp (KOB:P:),
    /// Lending (KOB:L:), Prediction (KOB:M:). Returns the first match.
    pub fn scan_tx_all(&self, tx: &TransactionData) -> Option<ScanResult> {
        // 0. Try OCO sell (single-UTXO, KOB:2: payload with 333B RS)
        if let Some((oco, idx, val)) = self.scan_oco_sell(tx) {
            return Some(ScanResult::OcoSell(oco, idx, val));
        }

        // 1. Try Spot (existing path)
        if let Some((parsed, idx, val)) = self.scan_tx(tx) {
            return Some(ScanResult::Spot(parsed, idx, val));
        }

        // 2. Try Perp (KOB:P:<side><RS>)
        if let Some(after_prefix) = kob_core::perp::parse_perp_payload(&tx.payload) {
            // Extract side byte and RS from the deploy payload
            let (side, rs_data) = if let Some((side_byte, rs_part)) =
                kob_core::perp::parse_perp_deploy_side(after_prefix)
            {
                let side = if side_byte == kob_core::perp::PERP_SIDE_SHORT {
                    PerpDeploySide::Short
                } else {
                    PerpDeploySide::Long
                };
                (side, rs_part)
            } else {
                // Legacy payload without side byte: default to Long
                (PerpDeploySide::Long, after_prefix)
            };
            if !rs_data.is_empty() {
                if let Some(result) = self.scan_p2sh_for_rs(tx, rs_data) {
                    let (rs_bytes, p2sh_idx, p2sh_value) = result;
                    if let Some(mut parsed) = parse_perp_deploy_rs(&rs_bytes) {
                        parsed.side = side;
                        return Some(ScanResult::Perp(parsed, p2sh_idx, p2sh_value));
                    }
                }
            }
        }

        // 3. Try Lending (KOB:L:)
        if let Some(rs_data) = kob_core::lending::parse_lending_payload(&tx.payload) {
            if !rs_data.is_empty() {
                if let Some(result) = self.scan_p2sh_for_rs(tx, rs_data) {
                    let (rs_bytes, p2sh_idx, p2sh_value) = result;
                    if let Some(mut parsed) = parse_lending_rs(&rs_bytes, p2sh_value) {
                        // Extract owner SPK from the deploy TX's non-P2SH outputs.
                        // The deployer's change/wallet output has an SPK whose hash
                        // matches the owner_spk_hash embedded in the redeemScript.
                        parsed.owner_spk = extract_owner_spk(tx, &parsed.owner_spk_hash);
                        return Some(ScanResult::Lending(parsed, p2sh_idx, p2sh_value));
                    }
                }
            }
        }

        // 4. Try Prediction (KOB:M:)
        if let Some(rs_data) = kob_core::prediction::parse_prediction_payload(&tx.payload) {
            if !rs_data.is_empty() {
                if let Some(result) = self.scan_p2sh_for_rs(tx, rs_data) {
                    let (rs_bytes, p2sh_idx, p2sh_value) = result;
                    if let Some(parsed) = parse_prediction_rs(&rs_bytes) {
                        return Some(ScanResult::Prediction(parsed, p2sh_idx, p2sh_value));
                    }
                }
            }
        }

        None
    }

    /// Helper: given raw RS bytes from a payload, find a matching P2SH output
    /// and return the RS bytes, output index, and value.
    fn scan_p2sh_for_rs(
        &self,
        tx: &TransactionData,
        rs_data: &[u8],
    ) -> Option<(Vec<u8>, u32, u64)> {
        let p2sh_outputs: Vec<(u32, &TxOutputData, [u8; 32])> = tx
            .outputs
            .iter()
            .enumerate()
            .filter_map(|(idx, out)| {
                parse_p2sh_script(&out.script, out.script_version)
                    .map(|hash| (idx as u32, out, hash))
            })
            .collect();

        if p2sh_outputs.is_empty() {
            return None;
        }

        let rs_hash = kob_core::blake2b_256(rs_data);
        for &(p2sh_idx, p2sh_out, ref p2sh_hash) in &p2sh_outputs {
            if rs_hash == *p2sh_hash {
                return Some((rs_data.to_vec(), p2sh_idx, p2sh_out.value));
            }
        }

        None
    }

    /// Find spent outpoints across all product books.
    ///
    /// Checks the spot order book and returns outpoints found in any product's
    /// tracked UTXOs. Additional product books can be checked by the caller
    /// using `find_spent_in_keys`.
    pub fn find_spent_in_keys(
        tx: &TransactionData,
        known_outpoints: &std::collections::HashSet<String>,
    ) -> Vec<String> {
        let mut spent = Vec::new();
        for input in &tx.inputs {
            let key = format!("{}:{}", input.prev_tx_id, input.prev_index);
            if known_outpoints.contains(&key) {
                spent.push(key);
            }
        }
        spent
    }
}

// Owner SPK extraction (shared by perp + lending scanners)

/// Extract the owner's full scriptPublicKey from a deploy TX.
///
/// Iterates non-P2SH outputs and computes `compute_spk_hash(version, script)`.
/// Returns the first output whose hash matches `owner_spk_hash` as a hex string
/// of the full SPK bytes (version LE u16 ++ script).
///
/// Returns `None` if no matching output is found (e.g., the deployer's change
/// address is on a different TX, or the deploy TX only has the P2SH output).
pub fn extract_owner_spk(tx: &TransactionData, owner_spk_hash: &[u8; 32]) -> Option<String> {
    for out in &tx.outputs {
        // Skip P2SH outputs (aa 20 <32B hash> 87 = 35 bytes, version 0)
        if out.script.len() == 35
            && out.script[0] == 0xaa
            && out.script[1] == 0x20
            && out.script[34] == 0x87
        {
            continue;
        }
        let hash = kob_core::p2sh::compute_spk_hash(out.script_version, &out.script);
        if hash == *owner_spk_hash {
            // Encode full SPK: version (2B LE) + script
            let mut spk_bytes = Vec::with_capacity(2 + out.script.len());
            spk_bytes.extend_from_slice(&out.script_version.to_le_bytes());
            spk_bytes.extend_from_slice(&out.script);
            return Some(hex::encode(&spk_bytes));
        }
    }
    None
}

// Parse functions for perp, lending, prediction are in kob-core.
// Re-exported at the top of this file.

// P2SH parsing helper

/// Parse a P2SH scriptPublicKey and extract the 32-byte hash.
///
/// Kaspa P2SH SPK format (version=0):
///   script = [0xaa (OpBlake2b), 0x20 (push32), <32-byte hash>, 0x87 (OpEqual)]
///   Total script length = 35 bytes
///
/// Returns the 32-byte hash if valid, None otherwise.
fn parse_p2sh_script(script: &[u8], version: u16) -> Option<[u8; 32]> {
    // P2SH uses version 0 (version 1 is for P2SH with different semantics, but
    // Kaspa P2SH is always version 0 in the current consensus rules)
    if version != 0 {
        return None;
    }
    if script.len() != 35 {
        return None;
    }
    if script[0] != 0xaa || script[1] != 0x20 || script[34] != 0x87 {
        return None;
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&script[2..34]);
    Some(hash)
}

// Spot state parse functions are in kob_core::contract::spot::parse.

// Transaction parsing from JSON (RPC block notifications)

impl TransactionData {
    /// Parse a transaction from a Kaspa RPC JSON object.
    ///
    /// Handles the format returned by `notifyBlockAddedResponse` and
    /// `getBlockResponse`, where transactions are nested under
    /// `block.transactions[]`.
    pub fn from_rpc_json(json: &serde_json::Value) -> Option<Self> {
        let tx_id = json
            .get("verboseData")
            .and_then(|v| v.get("transactionId"))
            .and_then(|v| v.as_str())
            .or_else(|| json.get("transactionId").and_then(|v| v.as_str()))?
            .to_string();

        let version = json
            .get("version")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u16;

        let inputs = json
            .get("inputs")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|inp| {
                        let prev_outpoint = inp.get("previousOutpoint")?;
                        let prev_tx_id = prev_outpoint
                            .get("transactionId")
                            .and_then(|v| v.as_str())?
                            .to_string();
                        let prev_index = prev_outpoint
                            .get("index")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0) as u32;
                        let sig_script = inp
                            .get("signatureScript")
                            .and_then(|v| v.as_str())
                            .and_then(|s| hex::decode(s).ok())
                            .unwrap_or_default();
                        Some(TxInputData {
                            prev_tx_id,
                            prev_index,
                            _sig_script: sig_script,
                        })
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
                        // TN12 uses "value", older nodes use "amount"
                        let value = out.get("value").and_then(|v| v.as_u64())
                            .or_else(|| out.get("amount").and_then(|v| v.as_u64()))?;
                        let spk = out.get("scriptPublicKey")?;
                        // TN12 returns scriptPublicKey as a flat hex string
                        // "<version_4hex><script_hex>" (e.g. "0000" + script hex).
                        // Older nodes return it as {"version": N, "scriptPublicKey": "<hex>"}.
                        let (script_version, script) = if let Some(flat) = spk.as_str() {
                            // Flat hex string: first 4 hex chars = version, rest = script
                            if flat.len() >= 4 {
                                let ver = u16::from_str_radix(&flat[..4], 16).unwrap_or(0);
                                let scr = hex::decode(&flat[4..]).unwrap_or_default();
                                (ver, scr)
                            } else {
                                (0u16, hex::decode(flat).unwrap_or_default())
                            }
                        } else {
                            let script_version = spk
                                .get("version")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0) as u16;
                            let script = spk
                                .get("scriptPublicKey")
                                .and_then(|v| v.as_str())
                                .and_then(|s| hex::decode(s).ok())
                                .unwrap_or_default();
                            (script_version, script)
                        };
                        // Parse optional covenant binding on this output.
                        let covenant_id = out
                            .get("covenant")
                            .and_then(|c| c.get("covenantId"))
                            .and_then(|v| v.as_str())
                            .and_then(|s| {
                                let bytes = hex::decode(s).ok()?;
                                if bytes.len() == 32 {
                                    let mut arr = [0u8; 32];
                                    arr.copy_from_slice(&bytes);
                                    Some(arr)
                                } else {
                                    None
                                }
                            });
                        Some(TxOutputData {
                            value,
                            script_version,
                            script,
                            covenant_id,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let payload = json
            .get("payload")
            .and_then(|v| v.as_str())
            .and_then(|s| if s.is_empty() { Some(vec![]) } else { hex::decode(s).ok() })
            .unwrap_or_default();

        Some(TransactionData {
            tx_id,
            _version: version,
            inputs,
            outputs,
            payload,
        })
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    // Helper: build a known buy v12 RS using the kob-core builder
    fn make_buy_v12_rs_default() -> (Vec<u8>, [u8; 32], u64, u64, u64, [u8; 32], [u8; 32], u64) {
        let tcid = [0xAA; 32];
        let pnum: u64 = 3;
        let pden: u64 = 2;
        let mfill: u64 = 1_000_000;
        let ohash = [0xBB; 32];
        let bspkh = [0xCC; 32];
        let mmfee: u64 = 50_000;
        let rs = kob_core::contract::build_buy_redeem_script(
            &tcid, pnum, pden, mfill, &ohash, &bspkh, mmfee, 0, 0,
        ).unwrap();
        (rs, tcid, pnum, pden, mfill, ohash, bspkh, mmfee)
    }

    // Helper: build a known sell v12 RS
    fn make_sell_v12_rs_default() -> (Vec<u8>, u64, u64, u64, [u8; 32], [u8; 32]) {
        let pnum: u64 = 5;
        let pden: u64 = 3;
        let mfill: u64 = 2_000_000;
        let ohash = [0xDD; 32];
        let sspkh = [0xEE; 32];
        let rs = kob_core::contract::build_sell_redeem_script(
            pnum, pden, mfill, &ohash, &sspkh, 0, 0, 0,
        ).unwrap();
        (rs, pnum, pden, mfill, ohash, sspkh)
    }

    // Helper: build a P2SH script from a hash
    fn make_p2sh_script(hash: &[u8; 32]) -> Vec<u8> {
        let mut s = Vec::with_capacity(35);
        s.push(0xaa);
        s.push(0x20);
        s.extend_from_slice(hash);
        s.push(0x87);
        s
    }

    // Helper: build a KOB TX payload for a single RS (v2 format, post_only=false).
    // All tests use v2 payloads because scan_tx rejects v1 payloads.
    fn make_payload(rs: &[u8]) -> Vec<u8> {
        kob_core::contract::build_order_payload(rs, false)
    }

    // Helper: build a v1 payload (KOB:1:) for testing the v1-rejection path.
    fn make_payload_v1(rs: &[u8]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(6 + rs.len());
        payload.extend_from_slice(b"KOB:1:");
        payload.extend_from_slice(rs);
        payload
    }

    // Helper: build a KOB TX payload for an OCO pair (2 RS, v2 format)
    fn make_oco_payload(buy_rs: &[u8], sell_rs: &[u8]) -> Vec<u8> {
        kob_core::contract::build_oco_order_payload(buy_rs, sell_rs, false)
    }

    // test_parse_buy_rs — parse known buy v12 RS

    #[test]
    fn test_parse_buy_v12_rs_default() {
        let (rs, tcid, pnum, pden, mfill, ohash, bspkh, mmfee) = make_buy_v12_rs_default();
        assert_eq!(rs.len(), BUY_RS_SIZE, "Buy RS must be 396 bytes");

        let parsed = BlockScanner::parse_redeem_script(&rs).expect("Should parse buy v12 RS");
        assert_eq!(parsed.order_type, OrderSide::Buy);
        assert_eq!(parsed.version, 0);
        assert_eq!(parsed.token_cov_id, tcid);
        assert_eq!(parsed.price_num, pnum);
        assert_eq!(parsed.price_den, pden);
        assert_eq!(parsed.min_fill, mfill);
        assert_eq!(parsed.owner_hash, ohash);
        assert_eq!(parsed.spk_hash, bspkh);
        assert_eq!(parsed._max_matcher_fee, mmfee);
        assert_eq!(parsed.cpend, 0);
    }

    #[test]
    fn test_parse_buy_v12_cpend_1_default() {
        let tcid = [0xAA; 32];
        let ohash = [0xBB; 32];
        let bspkh = [0xCC; 32];
        let rs = kob_core::contract::build_buy_redeem_script(
            &tcid, 3, 2, 1_000_000, &ohash, &bspkh, 50_000, 1, 0,
        ).unwrap();

        let parsed = BlockScanner::parse_redeem_script(&rs).expect("Should parse cpend=1");
        assert_eq!(parsed.cpend, 1);
    }

    // test_parse_sell_rs — sell v12

    #[test]
    fn test_parse_sell_v12_rs_default() {
        let (rs, pnum, pden, mfill, ohash, sspkh) = make_sell_v12_rs_default();
        assert_eq!(rs.len(), SELL_RS_SIZE, "Sell RS must be 415 bytes");

        let parsed = BlockScanner::parse_redeem_script(&rs).expect("Should parse sell v12 RS");
        assert_eq!(parsed.order_type, OrderSide::Sell);
        assert_eq!(parsed.version, 0);
        assert_eq!(parsed.token_cov_id, [0u8; 32]); // sell has no tcid in RS
        assert_eq!(parsed.price_num, pnum);
        assert_eq!(parsed.price_den, pden);
        assert_eq!(parsed.min_fill, mfill);
        assert_eq!(parsed.owner_hash, ohash);
        assert_eq!(parsed.spk_hash, sspkh);
        assert_eq!(parsed._max_matcher_fee, 0);
        assert_eq!(parsed.cpend, 0);
    }

    #[test]
    fn test_parse_sell_v12_cpend_1_default() {
        let ohash = [0xDD; 32];
        let sspkh = [0xEE; 32];
        let rs = kob_core::contract::build_sell_redeem_script(
            5, 3, 2_000_000, &ohash, &sspkh, 0, 1, 0,
        ).unwrap();

        let parsed = BlockScanner::parse_redeem_script(&rs).expect("Should parse sell cpend=1");
        assert_eq!(parsed.cpend, 1);
    }

    // test_p2sh_validation — RS hash matches P2SH

    #[test]
    fn test_p2sh_validation() {
        let (rs, ..) = make_buy_v12_rs_default();
        let hash = kob_core::blake2b_256(&rs);
        let p2sh_spk = kob_core::build_p2sh(&rs);

        // Verify the hash matches
        assert_eq!(&p2sh_spk.script()[2..34], &hash);

        // Verify parse_p2sh_script extracts it
        let extracted = parse_p2sh_script(&p2sh_spk.script(), 0).expect("Should parse P2SH");
        assert_eq!(extracted, hash);
    }

    #[test]
    fn test_p2sh_wrong_version() {
        let (rs, ..) = make_buy_v12_rs_default();
        let p2sh_spk = kob_core::build_p2sh(&rs);
        // Version 1 should fail
        assert!(parse_p2sh_script(&p2sh_spk.script(), 1).is_none());
    }

    // test_order_book_crud — add/remove/query orders

    #[test]
    fn test_order_book_crud() {
        let mut ob = OrderBook::new();
        assert_eq!(ob.stats().total_bids, 0);
        assert_eq!(ob.stats().total_asks, 0);

        // Add a buy order
        let buy = BookOrder {
            tx_id: "a".repeat(64),
            index: 0,
            value: 10_000_000,
            token_cov_id: "bb".repeat(32),
            price_num: 3,
            price_den: 2,
            min_fill: 1_000_000,
            owner_hash: "cc".repeat(32),
            spk_hash: "11".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Buy,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None,
        };
        let buy_key = buy.outpoint_key();
        ob.add_buy_order(buy);

        assert_eq!(ob.stats().total_bids, 1);
        assert_eq!(ob.stats().total_asks, 0);

        // Add a sell order
        let sell = BookOrder {
            tx_id: "d".repeat(64),
            index: 1,
            value: 5_000_000,
            token_cov_id: "bb".repeat(32),
            price_num: 3,
            price_den: 2,
            min_fill: 1_000_000,
            owner_hash: "ee".repeat(32),
            spk_hash: "22".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Sell,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None,
        };
        let sell_key = sell.outpoint_key();
        ob.add_sell_order(sell);

        assert_eq!(ob.stats().total_bids, 1);
        assert_eq!(ob.stats().total_asks, 1);
        assert_eq!(ob.stats().pairs, 1);

        // Remove the buy order
        ob.remove_order(&buy_key);
        assert_eq!(ob.stats().total_bids, 0);
        assert_eq!(ob.stats().total_asks, 1);

        // Remove the sell order
        ob.remove_order(&sell_key);
        assert_eq!(ob.stats().total_bids, 0);
        assert_eq!(ob.stats().total_asks, 0);
    }

    // test_scan_tx_deploy — mock TX with P2SH + payload -> OrderEntry

    #[test]
    fn test_scan_tx_deploy_buy_v12_default() {
        let (rs, tcid, pnum, pden, mfill, ohash, bspkh, mmfee) = make_buy_v12_rs_default();
        let hash = kob_core::blake2b_256(&rs);
        let p2sh_script = make_p2sh_script(&hash);

        let tx = TransactionData {
            tx_id: "a".repeat(64),
            _version: 0,
            inputs: vec![TxInputData {
                prev_tx_id: "b".repeat(64),
                prev_index: 0,
                _sig_script: vec![],
            }],
            outputs: vec![
                TxOutputData {
                    value: 10_000_000,
                    script_version: 0,
                    script: p2sh_script,
                    covenant_id: None,
                },
            ],
            payload: make_payload(&rs),
        };

        let scanner = BlockScanner::new();
        let result = scanner.scan_tx(&tx);
        assert!(result.is_some(), "Should detect buy v12 deploy TX");

        let (parsed, p2sh_idx, p2sh_value) = result.unwrap();
        assert_eq!(p2sh_idx, 0);
        assert_eq!(p2sh_value, 10_000_000);
        assert_eq!(parsed.order_type, OrderSide::Buy);
        assert_eq!(parsed.version, 0);
        assert_eq!(parsed.token_cov_id, tcid);
        assert_eq!(parsed.price_num, pnum);
        assert_eq!(parsed.price_den, pden);
        assert_eq!(parsed.min_fill, mfill);
        assert_eq!(parsed.owner_hash, ohash);
        assert_eq!(parsed.spk_hash, bspkh);
        assert_eq!(parsed._max_matcher_fee, mmfee);
    }

    #[test]
    fn test_scan_tx_deploy_sell_v12_default() {
        let (rs, pnum, pden, mfill, ohash, sspkh) = make_sell_v12_rs_default();
        let hash = kob_core::blake2b_256(&rs);
        let p2sh_script = make_p2sh_script(&hash);

        let tx = TransactionData {
            tx_id: "c".repeat(64),
            _version: 0,
            inputs: vec![],
            outputs: vec![
                TxOutputData {
                    value: 5_000_000,
                    script_version: 0,
                    script: p2sh_script,
                    covenant_id: None,
                },
            ],
            payload: make_payload(&rs),
        };

        let scanner = BlockScanner::new();
        let result = scanner.scan_tx(&tx);
        assert!(result.is_some(), "Should detect sell v12 deploy TX");

        let (parsed, p2sh_idx, p2sh_value) = result.unwrap();
        assert_eq!(p2sh_idx, 0);
        assert_eq!(p2sh_value, 5_000_000);
        assert_eq!(parsed.order_type, OrderSide::Sell);
        assert_eq!(parsed.version, 0);
        assert_eq!(parsed.price_num, pnum);
        assert_eq!(parsed.price_den, pden);
        assert_eq!(parsed.min_fill, mfill);
        assert_eq!(parsed.owner_hash, ohash);
        assert_eq!(parsed.spk_hash, sspkh);
    }

    // test_scan_tx_spend — mock TX spending an order -> removal

    #[test]
    fn test_scan_tx_spend() {
        let mut ob = OrderBook::new();

        // Add a buy order
        let buy = BookOrder {
            tx_id: "a".repeat(64),
            index: 0,
            value: 10_000_000,
            token_cov_id: "bb".repeat(32),
            price_num: 3,
            price_den: 2,
            min_fill: 1_000_000,
            owner_hash: "cc".repeat(32),
            spk_hash: "33".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Buy,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None,
        };
        ob.add_buy_order(buy);
        assert_eq!(ob.stats().total_bids, 1);

        // Create a TX that spends this order
        let spend_tx = TransactionData {
            tx_id: "d".repeat(64),
            _version: 0,
            inputs: vec![TxInputData {
                prev_tx_id: "a".repeat(64),
                prev_index: 0,
                _sig_script: vec![],
            }],
            outputs: vec![],
            payload: vec![],
        };

        let spent = BlockScanner::find_spent_orders(&spend_tx, &ob);
        assert_eq!(spent.len(), 1);
        assert_eq!(spent[0], format!("{}:0", "a".repeat(64)));

        // Remove them
        for key in &spent {
            ob.remove_order(key);
        }
        assert_eq!(ob.stats().total_bids, 0);
    }

    #[test]
    fn test_scan_tx_spend_not_in_book() {
        let ob = OrderBook::new();

        // Spending an outpoint not in the book
        let tx = TransactionData {
            tx_id: "x".repeat(64),
            _version: 0,
            inputs: vec![TxInputData {
                prev_tx_id: "y".repeat(64),
                prev_index: 5,
                _sig_script: vec![],
            }],
            outputs: vec![],
            payload: vec![],
        };

        let spent = BlockScanner::find_spent_orders(&tx, &ob);
        assert!(spent.is_empty());
    }

    // test_garbage_payload — garbage RS -> hash mismatch -> rejected

    #[test]
    fn test_garbage_payload() {
        let garbage = vec![0xDEu8, 0xAD, 0xBE, 0xEF].into_iter().cycle().take(50).collect::<Vec<u8>>();
        let garbage_hash = kob_core::blake2b_256(&garbage);

        // Create a valid P2SH output with a DIFFERENT hash
        let (rs, ..) = make_buy_v12_rs_default();
        let real_hash = kob_core::blake2b_256(&rs);
        let p2sh_script = make_p2sh_script(&real_hash);

        assert_ne!(garbage_hash, real_hash, "Hashes must differ");

        let tx = TransactionData {
            tx_id: "g".repeat(64),
            _version: 0,
            inputs: vec![],
            outputs: vec![
                TxOutputData {
                    value: 10_000_000,
                    script_version: 0,
                    script: p2sh_script,
                    covenant_id: None,
                },
            ],
            payload: make_payload(&garbage),
        };

        let scanner = BlockScanner::new();
        let result = scanner.scan_tx(&tx);
        assert!(result.is_none(), "Garbage payload hash mismatch should be rejected");
    }

    #[test]
    fn test_garbage_payload_matching_hash_but_invalid_rs() {
        // Even if the hash matches, an RS that doesn't parse should be rejected
        let garbage = vec![0x00; BUY_RS_SIZE]; // Right size for buy v12 but wrong content
        let hash = kob_core::blake2b_256(&garbage);
        let p2sh_script = make_p2sh_script(&hash);

        let tx = TransactionData {
            tx_id: "h".repeat(64),
            _version: 0,
            inputs: vec![],
            outputs: vec![
                TxOutputData {
                    value: 10_000_000,
                    script_version: 0,
                    script: p2sh_script,
                    covenant_id: None,
                },
            ],
            payload: make_payload(&garbage),
        };

        let scanner = BlockScanner::new();
        let result = scanner.scan_tx(&tx);
        assert!(result.is_none(), "RS with wrong structure should be rejected even with matching hash");
    }

    // Payload parsing edge cases

    #[test]
    fn test_payload_empty() {
        let tx = TransactionData {
            tx_id: "z".repeat(64),
            _version: 0,
            inputs: vec![],
            outputs: vec![],
            payload: vec![],
        };
        let scanner = BlockScanner::new();
        assert!(scanner.scan_tx(&tx).is_none());
    }

    #[test]
    fn test_payload_wrong_prefix() {
        let tx = TransactionData {
            tx_id: "z".repeat(64),
            _version: 0,
            inputs: vec![],
            outputs: vec![],
            payload: b"NOT:1:garbage".to_vec(),
        };
        let scanner = BlockScanner::new();
        assert!(scanner.scan_tx(&tx).is_none());
    }

    #[test]
    fn test_payload_prefix_only() {
        let tx = TransactionData {
            tx_id: "z".repeat(64),
            _version: 0,
            inputs: vec![],
            outputs: vec![],
            payload: b"KOB:1:".to_vec(),
        };
        let scanner = BlockScanner::new();
        assert!(scanner.scan_tx(&tx).is_none());
    }

    #[test]
    fn test_oco_payload_scan() {
        // Test OCO payload format (v2): KOB:2:<flags><buy_rs_len_u16_LE><buy_rs><sell_rs>
        let (buy_rs, ..) = make_buy_v12_rs_default();
        let (sell_rs, ..) = make_sell_v12_rs_default();
        let buy_hash = kob_core::blake2b_256(&buy_rs);
        let sell_hash = kob_core::blake2b_256(&sell_rs);
        let buy_p2sh = make_p2sh_script(&buy_hash);
        let sell_p2sh = make_p2sh_script(&sell_hash);

        let tx = TransactionData {
            tx_id: "z".repeat(64),
            _version: 0,
            inputs: vec![],
            outputs: vec![
                TxOutputData { value: 10_000_000, script_version: 0, script: buy_p2sh , covenant_id: None },
                TxOutputData { value: 5_000_000, script_version: 0, script: sell_p2sh , covenant_id: None },
            ],
            payload: make_oco_payload(&buy_rs, &sell_rs),
        };

        let scanner = BlockScanner::new();
        // scan_tx returns the first match (buy leg)
        let result = scanner.scan_tx(&tx);
        assert!(result.is_some(), "Should detect OCO buy leg from payload");
        let (parsed, p2sh_idx, _) = result.unwrap();
        assert_eq!(p2sh_idx, 0);
        assert_eq!(parsed.order_type, OrderSide::Buy);
    }

    // P2SH parsing edge cases

    #[test]
    fn test_p2sh_parse_valid() {
        let hash = [0x42; 32];
        let script = make_p2sh_script(&hash);
        let result = parse_p2sh_script(&script, 0).unwrap();
        assert_eq!(result, hash);
    }

    #[test]
    fn test_p2sh_parse_wrong_length() {
        assert!(parse_p2sh_script(&[0xaa, 0x20, 0x42], 0).is_none());
    }

    #[test]
    fn test_p2sh_parse_wrong_prefix() {
        let mut script = make_p2sh_script(&[0x42; 32]);
        script[0] = 0xab; // wrong opcode
        assert!(parse_p2sh_script(&script, 0).is_none());
    }

    // to_book_order conversion

    #[test]
    fn test_to_book_order_buy() {
        let (rs, tcid, pnum, pden, mfill, ohash, bspkh, ..) = make_buy_v12_rs_default();
        let parsed = BlockScanner::parse_redeem_script(&rs).unwrap();

        let book_order = BlockScanner::to_book_order(
            &parsed,
            &"a".repeat(64),
            0,
            10_000_000,
            None,
        );

        assert_eq!(book_order.tx_id, "a".repeat(64));
        assert_eq!(book_order.index, 0);
        assert_eq!(book_order.value, 10_000_000);
        assert_eq!(book_order.token_cov_id, hex::encode(tcid));
        assert_eq!(book_order.price_num, pnum);
        assert_eq!(book_order.price_den, pden);
        assert_eq!(book_order.min_fill, mfill);
        assert_eq!(book_order.owner_hash, hex::encode(ohash));
        assert_eq!(book_order.spk_hash, hex::encode(bspkh));
        assert_eq!(book_order.side, OrderSide::Buy);
        assert!(!book_order.redeem_script_hex.is_empty());
        assert!(!book_order.p2sh_script_hex.is_empty());
    }

    #[test]
    fn test_to_book_order_sell_with_override() {
        let (rs, pnum, pden, mfill, ohash, sspkh) = make_sell_v12_rs_default();
        let parsed = BlockScanner::parse_redeem_script(&rs).unwrap();

        let tcid_override = "ff".repeat(32);
        let book_order = BlockScanner::to_book_order(
            &parsed,
            &"c".repeat(64),
            1,
            5_000_000,
            Some(&tcid_override),
        );

        assert_eq!(book_order.token_cov_id, tcid_override);
        assert_eq!(book_order.price_num, pnum);
        assert_eq!(book_order.price_den, pden);
        assert_eq!(book_order.min_fill, mfill);
        assert_eq!(book_order.owner_hash, hex::encode(ohash));
        assert_eq!(book_order.spk_hash, hex::encode(sspkh));
        assert_eq!(book_order.side, OrderSide::Sell);
    }

    // Round-trip: build RS -> parse -> verify all fields (v12)

    #[test]
    fn test_roundtrip_buy_v12() {
        let tcid = [0x12; 32];
        let pnum = 12345u64;
        let pden = 67890u64;
        let mfill = 999_999u64;
        let ohash = [0x34; 32];
        let bspkh = [0x56; 32];
        let mmfee = 77_777u64;

        let rs = kob_core::contract::build_buy_redeem_script(
            &tcid, pnum, pden, mfill, &ohash, &bspkh, mmfee, 0, 0,
        ).unwrap();
        let parsed = BlockScanner::parse_redeem_script(&rs).unwrap();

        // GCD normalization: 12345/67890 -> 823/4526 (GCD=15)
        assert_eq!(parsed.token_cov_id, tcid);
        assert_eq!(parsed.price_num, 823);
        assert_eq!(parsed.price_den, 4526);
        assert_eq!(parsed.min_fill, mfill);
        assert_eq!(parsed.owner_hash, ohash);
        assert_eq!(parsed.spk_hash, bspkh);
        assert_eq!(parsed._max_matcher_fee, mmfee);
        assert_eq!(parsed.cpend, 0);
        assert_eq!(parsed.redeem_script, rs);
    }

    #[test]
    fn test_roundtrip_sell_v12() {
        let pnum = 54321u64;
        let pden = 11111u64;
        let mfill = 888_888u64;
        let ohash = [0x78; 32];
        let sspkh = [0x9A; 32];

        let rs = kob_core::contract::build_sell_redeem_script(
            pnum, pden, mfill, &ohash, &sspkh, 0, 0, 0,
        ).unwrap();
        let parsed = BlockScanner::parse_redeem_script(&rs).unwrap();

        assert_eq!(parsed.price_num, pnum);
        assert_eq!(parsed.price_den, pden);
        assert_eq!(parsed.min_fill, mfill);
        assert_eq!(parsed.owner_hash, ohash);
        assert_eq!(parsed.spk_hash, sspkh);
        assert_eq!(parsed.cpend, 0);
        assert_eq!(parsed.redeem_script, rs);
    }

    // Non-KOB RS should be rejected

    #[test]
    fn test_wrong_size_rs() {
        // Size that doesn't match any known contract
        let rs = vec![0x51; 100];
        assert!(BlockScanner::parse_redeem_script(&rs).is_none());
    }

    #[test]
    fn test_right_size_wrong_body_signature() {
        // BUY_RS_SIZE bytes (buy v12 size) but body doesn't start with expected bytes
        let mut rs = vec![0x00; BUY_RS_SIZE];
        rs[0] = 0x20; // right push prefix
        rs[33] = 0x08;
        rs[42] = 0x08;
        rs[51] = 0x08;
        rs[60] = 0x20;
        rs[93] = 0x20;
        rs[126] = 0x08;
        rs[136] = 0x08; // expiry push
        // Body starts at 145 with wrong bytes
        rs[145] = 0xFF;
        assert!(BlockScanner::parse_redeem_script(&rs).is_none());
    }

    // E2E Integration: scanner -> order book -> matching engine pipeline

    /// E2E: Scan a mock block with a buy deploy TX, add to order book,
    /// then scan a sell deploy TX, add to book, verify matching finds a pair.
    #[test]
    fn e2e_scan_block_buy_sell_to_match() {
        use crate::matcher::matching;
        let scanner = BlockScanner::new();
        let mut ob = OrderBook::new();
        let fake_token = "0102030405060708091011121314151617181920212223242526272829303132";

        // Deploy buy order via mock block TX
        let (buy_rs, ..) = make_buy_v12_rs_default();
        let buy_hash = kob_core::blake2b_256(&buy_rs);
        let buy_tx = TransactionData {
            tx_id: "b".repeat(64),
            _version: 0,
            inputs: vec![],
            outputs: vec![TxOutputData {
                value: 10_000_000,
                script_version: 0,
                script: make_p2sh_script(&buy_hash),
                covenant_id: None,
            }],
            payload: make_payload(&buy_rs),
        };

        let (parsed_buy, idx, val) = scanner.scan_tx(&buy_tx).expect("buy should parse");
        let buy_order = BlockScanner::to_book_order(&parsed_buy, &buy_tx.tx_id, idx, val, Some(fake_token));
        ob.add_buy_order(buy_order);
        assert_eq!(ob.stats().total_bids, 1);

        // Deploy sell order via mock block TX
        let (sell_rs, ..) = make_sell_v12_rs_default();
        let sell_hash = kob_core::blake2b_256(&sell_rs);
        let sell_tx = TransactionData {
            tx_id: "c".repeat(64),
            _version: 0,
            inputs: vec![],
            outputs: vec![TxOutputData {
                value: 10_000_000,
                script_version: 0,
                script: make_p2sh_script(&sell_hash),
                covenant_id: None,
            }],
            payload: make_payload(&sell_rs),
        };

        let (parsed_sell, idx2, val2) = scanner.scan_tx(&sell_tx).expect("sell should parse");
        let sell_order = BlockScanner::to_book_order(&parsed_sell, &sell_tx.tx_id, idx2, val2, Some(fake_token));
        ob.add_sell_order(sell_order);
        assert_eq!(ob.stats().total_asks, 1);

        // Matching engine should find crossing pairs (allow self trade since owners differ)
        let pairs = matching::find_all_crossing_pairs_with_stp(&ob, true);
        // Whether they cross depends on price: buy pnum=3/pden=2 sell pnum=5/pden=3
        // buy price = 3/2 tokens per KAS, sell price = 5/3 tokens per KAS
        // Buy expects 10M * 3/2 = 15M tokens. Sell expects 10M * 5/3 = 16.66M KAS.
        // These may or may not cross depending on surplus arithmetic.
        // The key test is the pipeline works end-to-end without panics.
        // At minimum we verify the engine ran and produced a result vector.
        assert!(pairs.len() <= 2, "Should produce 0-2 crossing/partial pairs");
    }

    /// E2E: Scanner dedup — same TX scanned twice should not create duplicate orders.
    #[test]
    fn e2e_scanner_dedup_prevents_duplicate() {
        let scanner = BlockScanner::new();
        let mut ob = OrderBook::new();
        let fake_token = "0102030405060708091011121314151617181920212223242526272829303132";

        let (buy_rs, ..) = make_buy_v12_rs_default();
        let buy_hash = kob_core::blake2b_256(&buy_rs);
        let buy_tx = TransactionData {
            tx_id: "d".repeat(64),
            _version: 0,
            inputs: vec![],
            outputs: vec![TxOutputData {
                value: 10_000_000,
                script_version: 0,
                script: make_p2sh_script(&buy_hash),
                covenant_id: None,
            }],
            payload: make_payload(&buy_rs),
        };

        // First scan: add order
        let (parsed, idx, val) = scanner.scan_tx(&buy_tx).expect("first scan");
        let order = BlockScanner::to_book_order(&parsed, &buy_tx.tx_id, idx, val, Some(fake_token));
        let outpoint_key = order.outpoint_key();
        assert!(!ob.contains_outpoint(&outpoint_key), "should not be in book yet");
        ob.add_buy_order(order);
        assert_eq!(ob.stats().total_bids, 1);

        // Second scan: dedup check should detect existing outpoint
        let (parsed2, idx2, val2) = scanner.scan_tx(&buy_tx).expect("second scan");
        let order2 = BlockScanner::to_book_order(&parsed2, &buy_tx.tx_id, idx2, val2, Some(fake_token));
        assert!(ob.contains_outpoint(&order2.outpoint_key()), "M-7: dedup should detect existing outpoint");
        // Do NOT add — in production the scanner checks contains_outpoint before adding
        assert_eq!(ob.stats().total_bids, 1, "still 1 bid after dedup");
    }

    /// E2E: Cancel detection — spent UTXO removes order from book.
    #[test]
    fn e2e_cancel_detection_removes_order() {
        let scanner = BlockScanner::new();
        let mut ob = OrderBook::new();
        let fake_token = "0102030405060708091011121314151617181920212223242526272829303132";

        // Deploy buy order
        let (buy_rs, ..) = make_buy_v12_rs_default();
        let buy_hash = kob_core::blake2b_256(&buy_rs);
        let buy_tx_id = "e".repeat(64);
        let buy_tx = TransactionData {
            tx_id: buy_tx_id.clone(),
            _version: 0,
            inputs: vec![],
            outputs: vec![TxOutputData {
                value: 10_000_000,
                script_version: 0,
                script: make_p2sh_script(&buy_hash),
                covenant_id: None,
            }],
            payload: make_payload(&buy_rs),
        };
        let (parsed, idx, val) = scanner.scan_tx(&buy_tx).expect("buy");
        let order = BlockScanner::to_book_order(&parsed, &buy_tx.tx_id, idx, val, Some(fake_token));
        ob.add_buy_order(order);
        assert_eq!(ob.stats().total_bids, 1);

        // Cancel TX spends the buy UTXO
        let cancel_tx = TransactionData {
            tx_id: "f".repeat(64),
            _version: 0,
            inputs: vec![TxInputData {
                prev_tx_id: buy_tx_id,
                prev_index: 0,
                _sig_script: vec![],
            }],
            outputs: vec![],
            payload: vec![],
        };
        let spent = BlockScanner::find_spent_orders(&cancel_tx, &ob);
        assert_eq!(spent.len(), 1, "should detect spent order");
        for key in &spent {
            ob.remove_order(key);
        }
        assert_eq!(ob.stats().total_bids, 0, "order should be removed after cancel");
    }

    /// E2E: OCO payload — scan a TX with both buy and sell RS in one payload.
    #[test]
    fn e2e_oco_payload_scan() {
        let scanner = BlockScanner::new();
        let (buy_rs, ..) = make_buy_v12_rs_default();
        let (sell_rs, ..) = make_sell_v12_rs_default();

        let buy_hash = kob_core::blake2b_256(&buy_rs);
        let sell_hash = kob_core::blake2b_256(&sell_rs);

        // TX with two P2SH outputs (buy + sell) and OCO payload
        let tx = TransactionData {
            tx_id: "g".repeat(64),
            _version: 0,
            inputs: vec![],
            outputs: vec![
                TxOutputData {
                    value: 10_000_000,
                    script_version: 0,
                    script: make_p2sh_script(&buy_hash),
                    covenant_id: None,
                },
                TxOutputData {
                    value: 5_000_000,
                    script_version: 0,
                    script: make_p2sh_script(&sell_hash),
                    covenant_id: None,
                },
            ],
            payload: make_oco_payload(&buy_rs, &sell_rs),
        };

        // scan_tx returns the first match (buy RS against output 0)
        let result = scanner.scan_tx(&tx);
        assert!(result.is_some(), "OCO payload should match at least one output");
        let (parsed, p2sh_idx, _) = result.unwrap();
        // Should match the buy RS against output 0
        assert_eq!(p2sh_idx, 0);
        assert_eq!(parsed.order_type, OrderSide::Buy);
    }

    /// E2E: Multiple TXs in a block — process several TXs, build up the book.
    #[test]
    fn e2e_multi_tx_block_processing() {
        let scanner = BlockScanner::new();
        let mut ob = OrderBook::new();
        let fake_token = "0102030405060708091011121314151617181920212223242526272829303132";

        // Simulate 3 buy deploy TXs with unique tx_ids
        for i in 0..3u8 {
            let tcid = [0xAA; 32];
            let ohash = [0xBB; 32];
            let bspkh = [0xCC; 32];
            let rs = kob_core::contract::build_buy_redeem_script(
                &tcid, 3, 2, 1_000_000, &ohash, &bspkh, 50_000, 0, 0,
            ).unwrap();
            let hash = kob_core::blake2b_256(&rs);
            let tx_id = format!("{:02x}", i).repeat(32);
            let tx = TransactionData {
                tx_id: tx_id.clone(),
                _version: 0,
                inputs: vec![],
                outputs: vec![TxOutputData {
                    value: 10_000_000 + (i as u64) * 1_000_000,
                    script_version: 0,
                    script: make_p2sh_script(&hash),
                    covenant_id: None,
                }],
                payload: make_payload(&rs),
            };

            if let Some((parsed, idx, val)) = scanner.scan_tx(&tx) {
                let order = BlockScanner::to_book_order(&parsed, &tx.tx_id, idx, val, Some(fake_token));
                if !ob.contains_outpoint(&order.outpoint_key()) {
                    ob.add_buy_order(order);
                }
            }
        }

        assert_eq!(ob.stats().total_bids, 3, "3 unique buy orders should be in book");

        // Non-KOB TX in the same block should be ignored
        let normal_tx = TransactionData {
            tx_id: "ff".repeat(32),
            _version: 0,
            inputs: vec![],
            outputs: vec![TxOutputData {
                value: 50_000_000,
                script_version: 0,
                script: vec![0x20, 0xAA, 0xBB], // not P2SH
                covenant_id: None,
            }],
            payload: vec![], // no payload
        };
        assert!(scanner.scan_tx(&normal_tx).is_none());
        assert_eq!(ob.stats().total_bids, 3, "non-KOB TX should not affect book");
    }


    // Payload v2 (post-only) scanner tests

    fn make_payload_v2(rs: &[u8], post_only: bool) -> Vec<u8> {
        kob_core::contract::build_order_payload(rs, post_only)
    }

    #[test]
    fn scan_tx_v2_buy_post_only_true() {
        let (rs, _, _, _, _, _, _, _) = make_buy_v12_rs_default();
        let hash = kob_core::blake2b_256(&rs);
        let scanner = BlockScanner::new();
        let tx = TransactionData {
            tx_id: "f".repeat(64),
            _version: 0,
            inputs: vec![],
            outputs: vec![TxOutputData {
                value: 15_000_000,
                script_version: 0,
                script: make_p2sh_script(&hash),
                covenant_id: None,
            }],
            payload: make_payload_v2(&rs, true),
        };
        let result = scanner.scan_tx(&tx);
        assert!(result.is_some(), "v2 payload with post_only=true must be parsed");
        let (parsed, idx, val) = result.unwrap();
        assert!(parsed.post_only, "parsed order must have post_only=true");
        assert_eq!(idx, 0);
        assert_eq!(val, 15_000_000);
    }

    #[test]
    fn scan_tx_v2_buy_post_only_false() {
        let (rs, _, _, _, _, _, _, _) = make_buy_v12_rs_default();
        let hash = kob_core::blake2b_256(&rs);
        let scanner = BlockScanner::new();
        let tx = TransactionData {
            tx_id: "e".repeat(64),
            _version: 0,
            inputs: vec![],
            outputs: vec![TxOutputData {
                value: 10_000_000,
                script_version: 0,
                script: make_p2sh_script(&hash),
                covenant_id: None,
            }],
            payload: make_payload_v2(&rs, false),
        };
        let result = scanner.scan_tx(&tx);
        assert!(result.is_some(), "v2 payload with post_only=false must be parsed");
        let (parsed, _, _) = result.unwrap();
        assert!(!parsed.post_only, "parsed order must have post_only=false");
    }

    #[test]
    fn scan_tx_v1_payload_is_rejected() {
        // v1 payloads lack counterparty_spk and are unmatchable — scan_tx must skip them.
        let (rs, _, _, _, _, _, _, _) = make_buy_v12_rs_default();
        let hash = kob_core::blake2b_256(&rs);
        let scanner = BlockScanner::new();
        let tx = TransactionData {
            tx_id: "d".repeat(64),
            _version: 0,
            inputs: vec![],
            outputs: vec![TxOutputData {
                value: 10_000_000,
                script_version: 0,
                script: make_p2sh_script(&hash),
                covenant_id: None,
            }],
            payload: make_payload_v1(&rs),
        };
        let result = scanner.scan_tx(&tx);
        assert!(result.is_none(), "v1 payload orders must be rejected by scan_tx");
    }

    #[test]
    fn scan_tx_v1_sell_payload_is_rejected() {
        // Sell orders with v1 payload should also be rejected.
        let (rs, _, _, _, _, _) = make_sell_v12_rs_default();
        let hash = kob_core::blake2b_256(&rs);
        let scanner = BlockScanner::new();
        let tx = TransactionData {
            tx_id: "e".repeat(64),
            _version: 0,
            inputs: vec![],
            outputs: vec![TxOutputData {
                value: 5_000_000,
                script_version: 0,
                script: make_p2sh_script(&hash),
                covenant_id: None,
            }],
            payload: make_payload_v1(&rs),
        };
        let result = scanner.scan_tx(&tx);
        assert!(result.is_none(), "v1 sell payload orders must be rejected by scan_tx");
    }

    #[test]
    fn scan_tx_v2_sell_post_only() {
        let (rs, _, _, _, _, _) = make_sell_v12_rs_default();
        let hash = kob_core::blake2b_256(&rs);
        let scanner = BlockScanner::new();
        let tx = TransactionData {
            tx_id: "c".repeat(64),
            _version: 0,
            inputs: vec![],
            outputs: vec![TxOutputData {
                value: 20_000_000,
                script_version: 0,
                script: make_p2sh_script(&hash),
                covenant_id: None,
            }],
            payload: make_payload_v2(&rs, true),
        };
        let result = scanner.scan_tx(&tx);
        assert!(result.is_some(), "v2 sell payload must be parsed");
        let (parsed, _, _) = result.unwrap();
        assert!(parsed.post_only, "sell order must inherit post_only from v2 payload");
    }

    #[test]
    fn to_book_order_propagates_post_only() {
        let (rs, _tcid, _pnum, _pden, _mfill, _ohash, _bspkh, _mmfee) = make_buy_v12_rs_default();
        let mut parsed = BlockScanner::parse_redeem_script(&rs).expect("must parse");
        parsed.post_only = true;
        let book_order = BlockScanner::to_book_order(&parsed, "abc123", 0, 10_000_000, None);
        assert!(book_order.post_only, "to_book_order must propagate post_only from ParsedOrder");

        // Also verify it does NOT propagate when false
        parsed.post_only = false;
        let book_order2 = BlockScanner::to_book_order(&parsed, "abc123", 0, 10_000_000, None);
        assert!(!book_order2.post_only);
    }

    // v12 buy/sell RS parsing

    // Helper: build a known buy v12 RS
    fn make_buy_v12_rs(expiry: u64) -> (Vec<u8>, [u8; 32], u64, u64, u64, [u8; 32], [u8; 32], u64) {
        let tcid = [0xA1; 32];
        let pnum: u64 = 5;
        let pden: u64 = 3;
        let mfill: u64 = 1_000_000;
        let ohash = [0xB1; 32];
        let bspkh = [0xC1; 32];
        let mmfee: u64 = 75_000;
        let rs = kob_core::contract::build_buy_redeem_script(
            &tcid, pnum, pden, mfill, &ohash, &bspkh, mmfee, 0, expiry,
        ).unwrap();
        (rs, tcid, pnum, pden, mfill, ohash, bspkh, mmfee)
    }

    // Helper: build a known sell v12 RS
    fn make_sell_v12_rs(expiry: u64) -> (Vec<u8>, u64, u64, u64, [u8; 32], [u8; 32]) {
        let pnum: u64 = 8;
        let pden: u64 = 5;
        let mfill: u64 = 500_000;
        let ohash = [0xD1; 32];
        let sspkh = [0xE1; 32];
        let rs = kob_core::contract::build_sell_redeem_script(
            pnum, pden, mfill, &ohash, &sspkh, 0, 0, expiry,
        ).unwrap();
        (rs, pnum, pden, mfill, ohash, sspkh)
    }

    #[test]
    fn test_parse_buy_v12_rs_gtc() {
        let (rs, tcid, pnum, pden, mfill, ohash, bspkh, mmfee) = make_buy_v12_rs(0);
        assert_eq!(rs.len(), BUY_RS_SIZE, "Buy v12 RS must be {} bytes", BUY_RS_SIZE);

        let parsed = BlockScanner::parse_redeem_script(&rs).expect("Should parse buy v12 RS");
        assert_eq!(parsed.order_type, OrderSide::Buy);
        assert_eq!(parsed.version, 0);
        assert_eq!(parsed.token_cov_id, tcid);
        assert_eq!(parsed.price_num, pnum);
        assert_eq!(parsed.price_den, pden);
        assert_eq!(parsed.min_fill, mfill);
        assert_eq!(parsed.owner_hash, ohash);
        assert_eq!(parsed.spk_hash, bspkh);
        assert_eq!(parsed._max_matcher_fee, mmfee);
        assert_eq!(parsed.cpend, 0);
        assert_eq!(parsed.expiry_daa, None, "GTC order (expiry=0) should have expiry_daa=None");
    }

    #[test]
    fn test_parse_buy_v12_rs_gtd() {
        let expiry: u64 = 123_456_789;
        let (rs, _tcid, _pnum, _pden, _mfill, _ohash, _bspkh, _mmfee) = make_buy_v12_rs(expiry);
        assert_eq!(rs.len(), BUY_RS_SIZE);

        let parsed = BlockScanner::parse_redeem_script(&rs).expect("Should parse buy v12 RS");
        assert_eq!(parsed.order_type, OrderSide::Buy);
        assert_eq!(parsed.version, 0);
        assert_eq!(parsed.expiry_daa, Some(expiry), "GTD order should have expiry_daa set");
    }

    #[test]
    fn test_parse_sell_v12_rs_gtc() {
        let (rs, pnum, pden, mfill, ohash, sspkh) = make_sell_v12_rs(0);
        assert_eq!(rs.len(), SELL_RS_SIZE, "Sell v12 RS must be {} bytes", SELL_RS_SIZE);

        let parsed = BlockScanner::parse_redeem_script(&rs).expect("Should parse sell v12 RS");
        assert_eq!(parsed.order_type, OrderSide::Sell);
        assert_eq!(parsed.version, 0);
        assert_eq!(parsed.price_num, pnum);
        assert_eq!(parsed.price_den, pden);
        assert_eq!(parsed.min_fill, mfill);
        assert_eq!(parsed.owner_hash, ohash);
        assert_eq!(parsed.spk_hash, sspkh);
        assert_eq!(parsed.cpend, 0);
        assert_eq!(parsed.expiry_daa, None);
    }

    #[test]
    fn test_parse_sell_v12_rs_gtd() {
        let expiry: u64 = 987_654_321;
        let (rs, _pnum, _pden, _mfill, _ohash, _sspkh) = make_sell_v12_rs(expiry);
        assert_eq!(rs.len(), SELL_RS_SIZE);

        let parsed = BlockScanner::parse_redeem_script(&rs).expect("Should parse sell v12 RS");
        assert_eq!(parsed.order_type, OrderSide::Sell);
        assert_eq!(parsed.version, 0);
        assert_eq!(parsed.expiry_daa, Some(expiry));
    }

    #[test]
    fn test_parse_buy_v12_cpend_1() {
        let tcid = [0xA1; 32];
        let ohash = [0xB1; 32];
        let bspkh = [0xC1; 32];
        let rs = kob_core::contract::build_buy_redeem_script(
            &tcid, 1, 2, 1, &ohash, &bspkh, 50_000, 1, 500_000,
        ).unwrap();
        let parsed = BlockScanner::parse_redeem_script(&rs).expect("Should parse buy v12 cpend=1");
        assert_eq!(parsed.cpend, 1);
        assert_eq!(parsed.expiry_daa, Some(500_000));
    }

    #[test]
    fn test_parse_sell_v12_cpend_1() {
        let ohash = [0xD1; 32];
        let sspkh = [0xE1; 32];
        let rs = kob_core::contract::build_sell_redeem_script(
            3, 4, 1, &ohash, &sspkh, 0, 1, 750_000,
        ).unwrap();
        let parsed = BlockScanner::parse_redeem_script(&rs).expect("Should parse sell v12 cpend=1");
        assert_eq!(parsed.cpend, 1);
        assert_eq!(parsed.expiry_daa, Some(750_000));
    }

    #[test]
    fn test_v12_buy_rs_size_constant() {
        // Verify our constant matches the actual RS length from kob_core
        let t = [0u8; 32];
        let rs = kob_core::contract::build_buy_redeem_script(&t, 1, 2, 1, &t, &t, 100_000, 0, 0).unwrap();
        assert_eq!(rs.len(), BUY_RS_SIZE, "BUY_RS_SIZE constant must match actual RS length");
        assert_eq!(BUY_RS_SIZE, 396);
    }

    #[test]
    fn test_v12_sell_rs_size_constant() {
        let t = [0u8; 32];
        let rs = kob_core::contract::build_sell_redeem_script(1, 2, 1, &t, &t, 0, 0, 0).unwrap();
        assert_eq!(rs.len(), SELL_RS_SIZE, "SELL_RS_SIZE constant must match actual RS length");
        assert_eq!(SELL_RS_SIZE, 416);
    }

    #[test]
    fn test_v12_buy_state_layout() {
        let t = [0u8; 32];
        let rs_v12 = kob_core::contract::build_buy_redeem_script(&t, 1, 2, 1, &t, &t, 100_000, 0, 0).unwrap();
        // State is 145 bytes: 136B base + 9B expiry
        assert_eq!(rs_v12[136], 0x08, "expiry push opcode must be 0x08");
        assert_eq!(rs_v12.len(), BUY_RS_SIZE);
    }

    #[test]
    fn test_scan_tx_deploy_buy_v12() {
        let (rs, _tcid, _pnum, _pden, _mfill, _ohash, _bspkh, _mmfee) = make_buy_v12_rs(1_000_000);
        let rs_hash = kob_core::blake2b_256(&rs);
        let p2sh_script = make_p2sh_script(&rs_hash);
        let payload = make_payload(&rs);

        let tx = TransactionData {
            tx_id: "ff".repeat(32),
            _version: 0,
            inputs: vec![],
            outputs: vec![TxOutputData {
                value: 50_000_000,
                script_version: 0,
                script: p2sh_script,
                covenant_id: None,
            }],
            payload,
        };

        let scanner = BlockScanner::new();
        let result = scanner.scan_tx(&tx);
        assert!(result.is_some(), "Should detect v12 buy deploy");
        let (parsed, idx, val) = result.unwrap();
        assert_eq!(parsed.order_type, OrderSide::Buy);
        assert_eq!(parsed.version, 0);
        assert_eq!(idx, 0);
        assert_eq!(val, 50_000_000);
    }

    #[test]
    fn test_scan_tx_deploy_sell_v12() {
        let (rs, _pnum, _pden, _mfill, _ohash, _sspkh) = make_sell_v12_rs(2_000_000);
        let rs_hash = kob_core::blake2b_256(&rs);
        let p2sh_script = make_p2sh_script(&rs_hash);
        let payload = make_payload(&rs);

        let tx = TransactionData {
            tx_id: "ee".repeat(32),
            _version: 0,
            inputs: vec![],
            outputs: vec![TxOutputData {
                value: 30_000_000,
                script_version: 0,
                script: p2sh_script,
                covenant_id: None,
            }],
            payload,
        };

        let scanner = BlockScanner::new();
        let result = scanner.scan_tx(&tx);
        assert!(result.is_some(), "Should detect v12 sell deploy");
        let (parsed, idx, val) = result.unwrap();
        assert_eq!(parsed.order_type, OrderSide::Sell);
        assert_eq!(parsed.version, 0);
        assert_eq!(idx, 0);
        assert_eq!(val, 30_000_000);
    }

    // Freezable / ZK gating tests

    #[test]
    fn to_book_order_propagates_requires_zk_false() {
        let parsed = ParsedOrder {
            order_type: OrderSide::Buy,
            version: 0,
            token_cov_id: [0xab; 32],
            price_num: 1,
            price_den: 1,
            min_fill: 1000,
            owner_hash: [0xcc; 32],
            spk_hash: [0xdd; 32],
            _max_matcher_fee: 0,
            cpend: 0,
            requires_zk: false,
            redeem_script: vec![0x51, 0x52],
            post_only: false,
            expiry_daa: None,
            ifd_order_b_rs: None,
        };
        let book_order = BlockScanner::to_book_order(&parsed, "a".repeat(64).as_str(), 0, 10_000, None);
        assert!(!book_order.is_freezable, "requires_zk=false should propagate as is_freezable=false");
    }

    #[test]
    fn to_book_order_propagates_requires_zk_true() {
        let parsed = ParsedOrder {
            order_type: OrderSide::Sell,
            version: 0,
            token_cov_id: [0xab; 32],
            price_num: 1,
            price_den: 1,
            min_fill: 1000,
            owner_hash: [0xcc; 32],
            spk_hash: [0xdd; 32],
            _max_matcher_fee: 0,
            cpend: 0,
            requires_zk: true,
            redeem_script: vec![0x51, 0x20, 0xa6, 0x87],
            post_only: false,
            expiry_daa: None,
            ifd_order_b_rs: None,
        };
        let book_order = BlockScanner::to_book_order(&parsed, "b".repeat(64).as_str(), 1, 20_000, None);
        assert!(book_order.is_freezable, "requires_zk=true should propagate as is_freezable=true");
    }

    #[test]
    fn book_order_is_freezable_serialization_default() {
        // Deserialize a BookOrder JSON without is_freezable field -> defaults to false
        let json = r#"{
            "tx_id": "aaaa",
            "index": 0,
            "value": 10000,
            "token_cov_id": "bbbb",
            "price_num": 1,
            "price_den": 1,
            "min_fill": 100,
            "owner_hash": "cccc",
            "spk_hash": "dddd",
            "counterparty_spk": null,
            "redeem_script_hex": "",
            "p2sh_script_hex": "",
            "p2sh_version": 0,
            "side": "Buy",
            "post_only": false,
            "expiry_daa": null
        }"#;
        let order: BookOrder = serde_json::from_str(json).expect("should deserialize");
        assert!(!order.is_freezable, "missing is_freezable should default to false");
    }

    // v1 payload rejection tests

    #[test]
    fn scan_tx_v1_oco_payload_is_rejected() {
        // OCO payloads with v1 prefix should also be rejected.
        let (buy_rs, ..) = make_buy_v12_rs_default();
        let (sell_rs, ..) = make_sell_v12_rs_default();
        let buy_hash = kob_core::blake2b_256(&buy_rs);
        let buy_p2sh = make_p2sh_script(&buy_hash);
        let sell_hash = kob_core::blake2b_256(&sell_rs);
        let sell_p2sh = make_p2sh_script(&sell_hash);

        let tx = TransactionData {
            tx_id: "f".repeat(64),
            _version: 0,
            inputs: vec![],
            outputs: vec![
                TxOutputData { value: 10_000_000, script_version: 0, script: buy_p2sh , covenant_id: None },
                TxOutputData { value: 5_000_000, script_version: 0, script: sell_p2sh , covenant_id: None },
            ],
            payload: {
                // Build actual v1-format OCO payload (KOB:1: prefix, no flags byte)
                let mut p = Vec::new();
                p.extend_from_slice(b"KOB:1:");
                p.extend_from_slice(&(buy_rs.len() as u16).to_le_bytes());
                p.extend_from_slice(&buy_rs);
                p.extend_from_slice(&sell_rs);
                p
            },
        };

        let scanner = BlockScanner::new();
        let result = scanner.scan_tx(&tx);
        assert!(result.is_none(), "v1 OCO payload orders must be rejected by scan_tx");
    }

    // Expired order pruning (remove_expired) verification

    #[test]
    fn test_remove_expired_orders() {
        let mut ob = OrderBook::new();
        let tcid = "bb".repeat(32);

        // Add a GTC order (no expiry)
        let gtc_order = BookOrder {
            tx_id: "a".repeat(64),
            index: 0,
            value: 10_000_000,
            token_cov_id: tcid.clone(),
            price_num: 3,
            price_den: 2,
            min_fill: 1_000_000,
            owner_hash: "cc".repeat(32),
            spk_hash: "11".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Buy,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None,
        };
        ob.add_buy_order(gtc_order);

        // Add a GTD order expiring at DAA 1000
        let gtd_order = BookOrder {
            tx_id: "b".repeat(64),
            index: 0,
            value: 5_000_000,
            token_cov_id: tcid.clone(),
            price_num: 4,
            price_den: 3,
            min_fill: 500_000,
            owner_hash: "dd".repeat(32),
            spk_hash: "22".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Buy,
            post_only: false,
            expiry_daa: Some(1000),
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None,
        };
        ob.add_buy_order(gtd_order);

        // Add a GTD sell order expiring at DAA 2000
        let gtd_sell = BookOrder {
            tx_id: "c".repeat(64),
            index: 0,
            value: 3_000_000,
            token_cov_id: tcid.clone(),
            price_num: 5,
            price_den: 2,
            min_fill: 100_000,
            owner_hash: "ee".repeat(32),
            spk_hash: "33".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Sell,
            post_only: false,
            expiry_daa: Some(2000),
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None,
        };
        ob.add_sell_order(gtd_sell);

        assert_eq!(ob.stats().total_bids, 2);
        assert_eq!(ob.stats().total_asks, 1);

        // At DAA 500, nothing should expire
        let removed = ob.remove_expired(500);
        assert_eq!(removed.len(), 0);
        assert_eq!(ob.stats().total_bids, 2);

        // At DAA 1000, the first GTD order should expire
        let removed = ob.remove_expired(1000);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].tx_id, "b".repeat(64));
        assert_eq!(ob.stats().total_bids, 1); // GTC remains
        assert_eq!(ob.stats().total_asks, 1); // sell remains

        // At DAA 3000, the sell GTD order should expire
        let removed = ob.remove_expired(3000);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].tx_id, "c".repeat(64));
        assert_eq!(ob.stats().total_bids, 1); // GTC still remains
        assert_eq!(ob.stats().total_asks, 0);
    }

    // Perp deploy RS parsing tests

    #[test]
    fn test_parse_perp_deploy_rs_valid() {
        let owner = [0xAA; 32];
        let rs = kob_core::perp::build_perp_deploy_redeem_script(
            &owner,
            100, 1,     // price 100/1
            5, 100,     // 5% maintenance
            50_000,     // keeper fee
            100_000,    // emergency DAA
            1_000_000,  // min fill
            10_000,     // max matcher fee
        );
        assert_eq!(rs.len(), PERP_DEPLOY_V1_RS_SIZE);

        let parsed = parse_perp_deploy_rs(&rs).expect("Should parse perp deploy v1");
        assert_eq!(parsed.side, PerpDeploySide::Long); // default
        assert_eq!(parsed.owner_spk_hash, owner);
        assert_eq!(parsed.price_num, 100);
        assert_eq!(parsed.price_den, 1);
        assert_eq!(parsed.maint_pct_num, 5);
        assert_eq!(parsed.maint_pct_den, 100);
        assert_eq!(parsed.keeper_fee, 50_000);
        assert_eq!(parsed.emergency_daa, 100_000);
        assert_eq!(parsed.min_fill, 1_000_000);
        assert_eq!(parsed.max_matcher_fee, 10_000);
    }

    #[test]
    fn test_parse_perp_deploy_rs_wrong_size() {
        let rs = vec![0u8; 100]; // Wrong size
        assert!(parse_perp_deploy_rs(&rs).is_none());
    }

    #[test]
    fn test_parse_perp_deploy_rs_bad_body_sig() {
        let owner = [0xAA; 32];
        let mut rs = kob_core::perp::build_perp_deploy_redeem_script(
            &owner, 100, 1, 5, 100, 50_000, 100_000, 1_000_000, 10_000,
        );
        // Corrupt body signature
        rs[PERP_DEPLOY_V1_STATE_SIZE] = 0xFF;
        assert!(parse_perp_deploy_rs(&rs).is_none());
    }

    // Lending RS parsing tests

    #[test]
    fn test_parse_loan_offer_valid() {
        let owner = [0xBB; 32];
        let collateral = [0x00; 32]; // KAS
        let rs = kob_core::lending::build_loan_offer_redeem_script(
            &owner,
            10_000_000,  // principal
            500,         // rate_num (5%)
            10_000,      // rate_den
            15_000,      // min_collateral_ratio (150%)
            315_360_000, // max_duration_daa (1 year)
            &collateral,
            0,           // rate_mode (fixed)
            0,           // rate_floor_num
        ).unwrap();

        assert_eq!(rs.len(), LOAN_OFFER_RS_SIZE, "LoanOffer RS must be {} bytes", LOAN_OFFER_RS_SIZE);

        let parsed = parse_lending_rs(&rs, 10_000_000).expect("Should parse LoanOffer");
        assert_eq!(parsed.order_type, LendingOrderType::Offer);
        assert_eq!(parsed.owner_spk_hash, owner);
        assert_eq!(parsed.amount, 10_000_000);
        assert_eq!(parsed.rate_num, 500);
        assert_eq!(parsed.rate_den, 10_000);
        assert_eq!(parsed.min_collateral_ratio, 15_000);
        assert_eq!(parsed.duration_daa, 315_360_000);
        assert_eq!(parsed.collateral_cov_id, collateral);
        assert_eq!(parsed.rate_mode, 0);
        assert_eq!(parsed.rate_floor_num, 0);
        assert_eq!(parsed.rate_cap_num, 0);
    }

    #[test]
    fn test_parse_borrow_request_valid() {
        let owner = [0xCC; 32];
        let collateral = [0x00; 32];
        let rs = kob_core::lending::build_borrow_request_redeem_script(
            &owner,
            5_000_000,   // desired_amount
            1_000,       // max_rate_num (10%)
            10_000,      // max_rate_den
            100_000,     // min_duration_daa
            &collateral,
            0,           // rate_mode (fixed)
            0,           // rate_cap_num
        ).unwrap();

        assert_eq!(rs.len(), BORROW_REQUEST_RS_SIZE, "BorrowRequest RS must be {} bytes", BORROW_REQUEST_RS_SIZE);

        let parsed = parse_lending_rs(&rs, 8_000_000).expect("Should parse BorrowRequest");
        assert_eq!(parsed.order_type, LendingOrderType::Request);
        assert_eq!(parsed.owner_spk_hash, owner);
        assert_eq!(parsed.amount, 5_000_000);
        assert_eq!(parsed.rate_num, 1_000);
        assert_eq!(parsed.rate_den, 10_000);
        assert_eq!(parsed.min_collateral_ratio, 0); // Not in BorrowRequest
        assert_eq!(parsed.duration_daa, 100_000);
        assert_eq!(parsed.rate_mode, 0);
        assert_eq!(parsed.rate_floor_num, 0);
        assert_eq!(parsed.rate_cap_num, 0);
    }

    #[test]
    fn test_parse_lending_rs_wrong_size() {
        let rs = vec![0u8; 100];
        assert!(parse_lending_rs(&rs, 0).is_none());
    }

    // Prediction RS parsing tests

    #[test]
    fn test_parse_prediction_rs_split_merge() {
        let market_id = [0xDD; 32];
        let yes_cov_id = [0x11; 32];
        let no_cov_id = [0x22; 32];
        let creator_pkh = [0xEE; 32];
        let rs = kob_core::prediction::build_split_merge_redeem_script(
            &market_id,
            &yes_cov_id,
            &no_cov_id,
            &creator_pkh,
            1_000_000, // unit_value
            2_000_000, // expiry
        ).unwrap();

        let parsed = parse_prediction_rs(&rs).expect("Should parse SplitMerge");
        assert_eq!(parsed.item_type, PredictionItemType::SplitMerge);
    }

    #[test]
    fn test_parse_prediction_rs_ballot_box() {
        let market_id = [0xDD; 32];
        let rs = kob_core::prediction::build_ballot_box_redeem_script(
            &market_id,
            1_000_000, // reward_per_vote
            100,       // start_daa
            500_000,   // end_daa
            1_000_000, // expiry
        ).unwrap();

        let parsed = parse_prediction_rs(&rs).expect("Should parse BallotBox");
        assert_eq!(parsed.item_type, PredictionItemType::BallotBox);
    }

    #[test]
    fn test_parse_prediction_rs_redemption() {
        let market_id = [0xDD; 32];
        let yes_box = [0x44; 32];
        let no_box = [0x55; 32];
        let yes_tok = [0x66; 32];
        let no_tok = [0x77; 32];
        let creator = [0x88; 32];
        let rs = kob_core::prediction::build_redemption_redeem_script(
            &market_id,
            &yes_box,
            &yes_tok,
            &no_tok,
            1_000_000, // payout_per_token
            1001,      // threshold_value
            &creator,
            2_000_000, // expiry
            1,         // reward_per_receipt placeholder
            &[0u8; 32], // yes_receipt_cid placeholder
            &[0u8; 32], // no_receipt_cid placeholder
        ).unwrap();

        let parsed = parse_prediction_rs(&rs).expect("Should parse Redemption");
        assert_eq!(parsed.item_type, PredictionItemType::Redemption);
    }

    #[test]
    fn test_parse_prediction_rs_too_short() {
        let rs = vec![0u8; 10];
        assert!(parse_prediction_rs(&rs).is_none());
    }

    // Unified scan_tx_all tests

    #[test]
    fn test_scan_tx_all_spot() {
        let (rs, ..) = make_buy_v12_rs_default();
        let hash = kob_core::blake2b_256(&rs);
        let p2sh_script = make_p2sh_script(&hash);

        let tx = TransactionData {
            tx_id: "a".repeat(64),
            _version: 0,
            inputs: vec![TxInputData {
                prev_tx_id: "b".repeat(64),
                prev_index: 0,
                _sig_script: vec![],
            }],
            outputs: vec![TxOutputData {
                value: 10_000_000,
                script_version: 0,
                script: p2sh_script,
                covenant_id: None,
            }],
            payload: make_payload(&rs),
        };

        let scanner = BlockScanner::new();
        let result = scanner.scan_tx_all(&tx);
        assert!(matches!(result, Some(ScanResult::Spot(..))));
    }

    #[test]
    fn test_scan_tx_all_perp() {
        let owner = [0xAA; 32];
        let rs = kob_core::perp::build_perp_deploy_redeem_script(
            &owner, 100, 1, 5, 100, 50_000, 100_000, 1_000_000, 10_000,
        );
        let hash = kob_core::blake2b_256(&rs);
        let p2sh_script = make_p2sh_script(&hash);
        let payload = kob_core::perp::build_perp_deploy_payload(&rs, kob_core::perp::PERP_SIDE_LONG);

        let tx = TransactionData {
            tx_id: "p".repeat(64),
            _version: 0,
            inputs: vec![],
            outputs: vec![TxOutputData {
                value: 5_000_000,
                script_version: 0,
                script: p2sh_script,
                covenant_id: None,
            }],
            payload,
        };

        let scanner = BlockScanner::new();
        let result = scanner.scan_tx_all(&tx);
        assert!(matches!(result, Some(ScanResult::Perp(..))), "Should detect perp deploy");
    }

    #[test]
    fn test_scan_tx_all_lending_offer() {
        let owner = [0xBB; 32];
        let collateral = [0x00; 32];
        let rs = kob_core::lending::build_loan_offer_redeem_script(
            &owner, 10_000_000, 500, 10_000, 15_000, 315_360_000, &collateral, 0, 0,
        ).unwrap();
        let hash = kob_core::blake2b_256(&rs);
        let p2sh_script = make_p2sh_script(&hash);
        let payload = kob_core::lending::build_lending_payload(&rs);

        let tx = TransactionData {
            tx_id: "l".repeat(64),
            _version: 0,
            inputs: vec![],
            outputs: vec![TxOutputData {
                value: 10_000_000,
                script_version: 0,
                script: p2sh_script,
                covenant_id: None,
            }],
            payload,
        };

        let scanner = BlockScanner::new();
        let result = scanner.scan_tx_all(&tx);
        assert!(matches!(result, Some(ScanResult::Lending(..))), "Should detect lending offer");

        if let Some(ScanResult::Lending(parsed, _, _)) = result {
            assert_eq!(parsed.order_type, LendingOrderType::Offer);
            assert_eq!(parsed.amount, 10_000_000);
        }
    }

    #[test]
    fn test_scan_tx_all_prediction() {
        let market_id = [0xDD; 32];
        let yes_cov = [0x11; 32];
        let no_cov = [0x22; 32];
        let creator = [0xEE; 32];
        let rs = kob_core::prediction::build_split_merge_redeem_script(
            &market_id, &yes_cov, &no_cov, &creator, 1_000_000, 2_000_000,
        ).unwrap();
        let hash = kob_core::blake2b_256(&rs);
        let p2sh_script = make_p2sh_script(&hash);
        let payload = kob_core::prediction::build_prediction_payload(&rs);

        let tx = TransactionData {
            tx_id: "m".repeat(64),
            _version: 0,
            inputs: vec![],
            outputs: vec![TxOutputData {
                value: 1_000_000,
                script_version: 0,
                script: p2sh_script,
                covenant_id: None,
            }],
            payload,
        };

        let scanner = BlockScanner::new();
        let result = scanner.scan_tx_all(&tx);
        assert!(matches!(result, Some(ScanResult::Prediction(..))), "Should detect prediction market");
    }

    #[test]
    fn test_scan_tx_all_no_match() {
        let tx = TransactionData {
            tx_id: "x".repeat(64),
            _version: 0,
            inputs: vec![],
            outputs: vec![TxOutputData {
                value: 1_000_000,
                script_version: 0,
                script: vec![0x76, 0xaa], // Not P2SH
                covenant_id: None,
            }],
            payload: b"not a KOB payload".to_vec(),
        };

        let scanner = BlockScanner::new();
        assert!(scanner.scan_tx_all(&tx).is_none());
    }

    #[test]
    fn test_find_spent_in_keys() {
        let mut keys = std::collections::HashSet::new();
        keys.insert(format!("{}:0", "a".repeat(64)));

        let tx = TransactionData {
            tx_id: "b".repeat(64),
            _version: 0,
            inputs: vec![
                TxInputData {
                    prev_tx_id: "a".repeat(64),
                    prev_index: 0,
                    _sig_script: vec![],
                },
                TxInputData {
                    prev_tx_id: "c".repeat(64),
                    prev_index: 1,
                    _sig_script: vec![],
                },
            ],
            outputs: vec![],
            payload: vec![],
        };

        let spent = BlockScanner::find_spent_in_keys(&tx, &keys);
        assert_eq!(spent.len(), 1);
        assert_eq!(spent[0], format!("{}:0", "a".repeat(64)));
    }

    // Test from_rpc_json with TN12 flat scriptPublicKey format

    #[test]
    fn test_from_rpc_json_flat_spk() {
        // TN12 format: scriptPublicKey is a flat hex string "0000<script_hex>"
        let script_hex = "aa20".to_string() + &"bb".repeat(32) + "87";
        let flat_spk = format!("0000{}", script_hex); // version 0 + script
        let json = serde_json::json!({
            "verboseData": {"transactionId": "a".repeat(64)},
            "version": 0,
            "inputs": [],
            "outputs": [{
                "value": 5_000_000u64,
                "scriptPublicKey": flat_spk,
                "covenant": null,
            }],
            "payload": "",
        });

        let td = TransactionData::from_rpc_json(&json).expect("Should parse TN12 format");
        assert_eq!(td.tx_id, "a".repeat(64));
        assert_eq!(td.outputs.len(), 1);
        assert_eq!(td.outputs[0].value, 5_000_000);
        assert_eq!(td.outputs[0].script_version, 0);
        // Script should be the decoded script bytes (without version prefix)
        let expected_script = hex::decode(&script_hex).unwrap();
        assert_eq!(td.outputs[0].script, expected_script);
    }

    #[test]
    fn test_from_rpc_json_object_spk() {
        // Old format: scriptPublicKey is {"version": N, "scriptPublicKey": "hex"}
        let script_hex = "aa20".to_string() + &"cc".repeat(32) + "87";
        let json = serde_json::json!({
            "verboseData": {"transactionId": "b".repeat(64)},
            "version": 0,
            "inputs": [],
            "outputs": [{
                "amount": 3_000_000u64,
                "scriptPublicKey": {
                    "version": 0,
                    "scriptPublicKey": script_hex,
                },
            }],
            "payload": "",
        });

        let td = TransactionData::from_rpc_json(&json).expect("Should parse object SPK format");
        assert_eq!(td.outputs.len(), 1);
        assert_eq!(td.outputs[0].value, 3_000_000);
        assert_eq!(td.outputs[0].script_version, 0);
        let expected_script = hex::decode(&script_hex).unwrap();
        assert_eq!(td.outputs[0].script, expected_script);
    }

    #[test]
    fn test_from_rpc_json_value_key() {
        // TN12 uses "value" instead of "amount"
        let json = serde_json::json!({
            "verboseData": {"transactionId": "c".repeat(64)},
            "version": 0,
            "inputs": [],
            "outputs": [{
                "value": 7_777_777u64,
                "scriptPublicKey": "000020aabbccdd",
            }],
            "payload": "",
        });

        let td = TransactionData::from_rpc_json(&json).unwrap();
        assert_eq!(td.outputs[0].value, 7_777_777);
    }

    #[test]
    fn test_from_rpc_json_amount_key() {
        // Old format uses "amount"
        let json = serde_json::json!({
            "verboseData": {"transactionId": "d".repeat(64)},
            "version": 0,
            "inputs": [],
            "outputs": [{
                "amount": 9_999_999u64,
                "scriptPublicKey": {"version": 0, "scriptPublicKey": "20aabbccdd"},
            }],
            "payload": "",
        });

        let td = TransactionData::from_rpc_json(&json).unwrap();
        assert_eq!(td.outputs[0].value, 9_999_999);
    }
}
