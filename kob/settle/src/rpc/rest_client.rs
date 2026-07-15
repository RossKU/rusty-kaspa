//! REST API client for kob-engine.
//!
//! Provides UTXO fetch and TX submit over HTTP REST as a fallback
//! when wRPC (WebSocket) is unavailable.

use super::{RpcOutpoint, RpcUtxo, RpcUtxoEntry, SubmitResult, parse_rest_spk};

/// REST API client backed by `reqwest`.
pub struct RestClient {
    base_url: String,
    client: reqwest::Client,
}

impl RestClient {
    /// Create a new REST client for the given base URL.
    pub fn new(base_url: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("failed to build reqwest client");
        RestClient {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        }
    }

    /// Health check: try GET /info/blockdag.
    pub async fn health_check(&self) -> Result<(), String> {
        let url = format!("{}/info/blockdag", self.base_url);
        let resp = self
            .client
            .get(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| format!("REST health check failed: {}", e))?;
        if !resp.status().is_success() {
            return Err(format!("REST health check failed: HTTP {}", resp.status()));
        }
        Ok(())
    }

    /// Get UTXOs for an address, sorted by amount descending.
    pub async fn get_utxos(
        &self,
        address: &str,
        min_amount: Option<u64>,
    ) -> Result<Vec<RpcUtxo>, String> {
        let url = format!("{}/addresses/{}/utxos", self.base_url, address);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("REST UTXO fetch failed: {}", e))?;
        if !resp.status().is_success() {
            return Err(format!(
                "REST GET /addresses/{}/utxos: HTTP {}",
                address,
                resp.status()
            ));
        }
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("REST UTXO parse failed: {}", e))?;

        let raws: Vec<RestUtxoRaw> = serde_json::from_value(body)
            .map_err(|e| format!("REST UTXO deserialize failed: {}", e))?;

        let mut utxos: Vec<RpcUtxo> = raws.into_iter().map(|r| r.into_rpc_utxo()).collect();
        utxos.sort_by(|a, b| b.utxo_entry.amount.cmp(&a.utxo_entry.amount));

        if let Some(min) = min_amount {
            utxos.retain(|u| u.utxo_entry.amount >= min);
        }

        Ok(utxos)
    }

    /// Get UTXOs for multiple addresses.
    pub async fn get_utxos_by_addresses(
        &self,
        addresses: &[&str],
    ) -> Result<Vec<RpcUtxo>, String> {
        let mut all = Vec::new();
        for addr in addresses {
            let utxos = self.get_utxos(addr, None).await?;
            all.extend(utxos);
        }
        Ok(all)
    }

    /// Get spendable UTXOs. REST has no mempool filter — returns all with warning.
    pub async fn get_spendable_utxos(
        &self,
        address: &str,
        min_amount: Option<u64>,
    ) -> Result<Vec<RpcUtxo>, String> {
        tracing::warn!(
            "[REST] Mempool filtering unavailable — UTXOs may include recently spent"
        );
        self.get_utxos(address, min_amount).await
    }

    /// Submit a transaction. Translates wRPC payload to REST format.
    pub async fn submit_transaction(
        &self,
        tx_json: serde_json::Value,
    ) -> Result<SubmitResult, String> {
        let rest_body = translate_wrpc_tx_to_rest(&tx_json)?;
        let url = format!("{}/transactions", self.base_url);
        let resp = self
            .client
            .post(&url)
            .json(&rest_body)
            .send()
            .await
            .map_err(|e| format!("REST submit TX failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| "(no body)".to_string());
            return Ok(SubmitResult {
                ok: false,
                tx_id: None,
                error: Some(format!("HTTP {}: {}", status, body)),
            });
        }

        let result: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("REST submit TX parse failed: {}", e))?;

        let tx_id = result
            .get("transactionId")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Ok(SubmitResult {
            ok: tx_id.is_some(),
            tx_id,
            error: None,
        })
    }

    /// Get the current virtual DAA score.
    pub async fn get_daa_score(&self) -> Result<u64, String> {
        let url = format!("{}/info/virtual-chain-blue-score", self.base_url);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("REST DAA score fetch failed: {}", e))?;
        if !resp.status().is_success() {
            return Err(format!(
                "REST GET /info/virtual-chain-blue-score: HTTP {}",
                resp.status()
            ));
        }
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("REST DAA score parse failed: {}", e))?;
        body.get("blueScore")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| "Missing blueScore in REST response".to_string())
    }

    /// Get blockDAG info.
    pub async fn get_block_dag_info(&self) -> Result<serde_json::Value, String> {
        let url = format!("{}/info/blockdag", self.base_url);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("REST blockdag fetch failed: {}", e))?;
        if !resp.status().is_success() {
            return Err(format!(
                "REST GET /info/blockdag: HTTP {}",
                resp.status()
            ));
        }
        resp.json()
            .await
            .map_err(|e| format!("REST blockdag parse failed: {}", e))
    }

    /// Base URL for display.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

// --- REST response deserialization ---

#[derive(Debug, serde::Deserialize)]
struct RestUtxoRaw {
    #[serde(default)]
    #[allow(dead_code)]
    address: Option<String>,
    outpoint: RestOutpointRaw,
    #[serde(rename = "utxoEntry")]
    utxo_entry: RestUtxoEntryRaw,
}

#[derive(Debug, serde::Deserialize)]
struct RestOutpointRaw {
    #[serde(rename = "transactionId")]
    transaction_id: String,
    index: u32,
}

#[derive(Debug, serde::Deserialize)]
struct RestUtxoEntryRaw {
    amount: u64,
    #[serde(rename = "scriptPublicKey")]
    script_public_key: serde_json::Value,
    #[serde(rename = "blockDaaScore", default)]
    block_daa_score: u64,
    #[serde(rename = "isCoinbase", default)]
    is_coinbase: bool,
    #[serde(rename = "covenantId", default)]
    covenant_id: Option<String>,
}

impl RestUtxoRaw {
    fn into_rpc_utxo(self) -> RpcUtxo {
        let spk = parse_rest_spk(&self.utxo_entry.script_public_key);
        RpcUtxo {
            outpoint: RpcOutpoint {
                transaction_id: self.outpoint.transaction_id,
                index: self.outpoint.index,
            },
            utxo_entry: RpcUtxoEntry {
                amount: self.utxo_entry.amount,
                script_public_key: spk,
                block_daa_score: self.utxo_entry.block_daa_score,
                is_coinbase: self.utxo_entry.is_coinbase,
                covenant_id: self.utxo_entry.covenant_id,
            },
        }
    }
}

// --- TX format translation ---

fn translate_wrpc_tx_to_rest(
    wrpc_payload: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let tx = if let Some(t) = wrpc_payload.get("transaction") {
        t.clone()
    } else {
        wrpc_payload.clone()
    };

    let inputs = tx
        .get("inputs")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|inp| {
                    let mut out = inp.clone();
                    if let Some(obj) = out.as_object_mut() {
                        if let Some(seq) = obj.get("sequence").cloned() {
                            if let Some(s) = seq.as_str() {
                                if let Ok(n) = s.parse::<u64>() {
                                    obj.insert("sequence".to_string(), serde_json::json!(n));
                                }
                            }
                        }
                        if let Some(soc) = obj.get("sigOpCount").cloned() {
                            if let Some(s) = soc.as_str() {
                                if let Ok(n) = s.parse::<u64>() {
                                    obj.insert("sigOpCount".to_string(), serde_json::json!(n));
                                }
                            }
                        }
                    }
                    out
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let outputs = tx
        .get("outputs")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|out_val| {
                    let mut obj = serde_json::Map::new();
                    let amount = if let Some(v) = out_val.get("value") {
                        if let Some(s) = v.as_str() {
                            s.parse::<u64>().unwrap_or(0)
                        } else {
                            v.as_u64().unwrap_or(0)
                        }
                    } else if let Some(v) = out_val.get("amount") {
                        v.as_u64().unwrap_or(0)
                    } else {
                        0
                    };
                    obj.insert("amount".to_string(), serde_json::json!(amount));

                    if let Some(spk) = out_val.get("scriptPublicKey") {
                        let mut spk_obj = serde_json::Map::new();
                        // TN12 returns scriptPublicKey as a flat hex string;
                        // older nodes return {"version": N, "scriptPublicKey"/"script": "hex"}.
                        if let Some(flat) = spk.as_str() {
                            // Flat hex string: first 4 hex chars = version
                            match crate::rpc_types::split_flat_spk_hex(flat) {
                                Some((ver_hex, script_hex)) => {
                                    let version = u16::from_str_radix(ver_hex, 16).unwrap_or(0);
                                    spk_obj.insert("version".to_string(), serde_json::json!(version));
                                    spk_obj.insert("scriptPublicKey".to_string(), serde_json::json!(script_hex));
                                }
                                None => {
                                    spk_obj.insert("version".to_string(), serde_json::json!(0));
                                    spk_obj.insert("scriptPublicKey".to_string(), serde_json::json!(flat));
                                }
                            }
                        } else {
                            let version = spk
                                .get("version")
                                .and_then(|v| {
                                    if let Some(s) = v.as_str() {
                                        s.parse::<u64>().ok()
                                    } else {
                                        v.as_u64()
                                    }
                                })
                                .unwrap_or(0);
                            let script = spk
                                .get("script")
                                .or_else(|| spk.get("scriptPublicKey"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            spk_obj.insert("version".to_string(), serde_json::json!(version));
                            spk_obj.insert("scriptPublicKey".to_string(), serde_json::json!(script));
                        }
                        obj.insert(
                            "scriptPublicKey".to_string(),
                            serde_json::Value::Object(spk_obj),
                        );
                    }

                    serde_json::Value::Object(obj)
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let version = tx
        .get("version")
        .and_then(|v| {
            if let Some(s) = v.as_str() {
                s.parse::<u64>().ok()
            } else {
                v.as_u64()
            }
        })
        .unwrap_or(0);

    let lock_time = tx
        .get("lockTime")
        .and_then(|v| {
            if let Some(s) = v.as_str() {
                s.parse::<u64>().ok()
            } else {
                v.as_u64()
            }
        })
        .unwrap_or(0);

    let subnetwork_id = tx
        .get("subnetworkId")
        .and_then(|v| v.as_str())
        .unwrap_or("0000000000000000000000000000000000000000");

    let mut tx_obj = serde_json::json!({
        "version": version,
        "inputs": inputs,
        "outputs": outputs,
        "lockTime": lock_time,
        "subnetworkId": subnetwork_id,
    });

    // Forward payload field for covenant TXs (redeem script data)
    if let Some(payload) = tx.get("payload") {
        tx_obj.as_object_mut().unwrap().insert("payload".to_string(), payload.clone());
    }

    Ok(serde_json::json!({
        "transaction": tx_obj,
        "allowOrphan": false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // parse_rest_spk tests are in kob_core::rpc_types::tests

    #[test]
    fn test_translate_wrpc_tx() {
        let wrpc = serde_json::json!({
            "transaction": {
                "version": "0",
                "inputs": [{
                    "previousOutpoint": {"transactionId": "abc", "index": 0},
                    "signatureScript": "ff",
                    "sequence": "0",
                    "sigOpCount": "1"
                }],
                "outputs": [{
                    "value": "5000",
                    "scriptPublicKey": {"version": "0", "script": "aa20ab87"}
                }],
                "lockTime": "0",
                "subnetworkId": "0000000000000000000000000000000000000000",
                "gas": "0",
                "payload": "4b4f42"
            }
        });

        let rest = translate_wrpc_tx_to_rest(&wrpc).unwrap();
        let tx = rest.get("transaction").unwrap();
        assert_eq!(tx["version"], 0);
        assert_eq!(tx["outputs"][0]["amount"], 5000);
        assert_eq!(tx["outputs"][0]["scriptPublicKey"]["scriptPublicKey"], "aa20ab87");
        assert_eq!(tx["inputs"][0]["sequence"], 0);
        assert_eq!(tx["inputs"][0]["sigOpCount"], 1);
        assert!(tx.get("gas").is_none());
        assert_eq!(tx["payload"], "4b4f42");
        assert_eq!(rest["allowOrphan"], false);
    }

    #[test]
    fn test_translate_wrpc_tx_rejects_non_boundary_multibyte_spk_cleanly() {
        // DoS regression: a flat scriptPublicKey string with a multibyte
        // UTF-8 char straddling byte offset 4 used to panic even though its
        // byte length is >= 4. Now: falls back to version 0 / raw string,
        // no panic.
        let wrpc = serde_json::json!({
            "transaction": {
                "version": "0",
                "inputs": [],
                "outputs": [{
                    "value": "5000",
                    "scriptPublicKey": "ab\u{20AC}cd",
                }],
                "lockTime": "0",
                "subnetworkId": "0000000000000000000000000000000000000000",
                "payload": ""
            }
        });

        let rest = translate_wrpc_tx_to_rest(&wrpc).unwrap();
        let tx = rest.get("transaction").unwrap();
        assert_eq!(tx["outputs"][0]["scriptPublicKey"]["version"], 0);
        assert_eq!(tx["outputs"][0]["scriptPublicKey"]["scriptPublicKey"], "ab\u{20AC}cd");
    }

    #[test]
    fn test_rest_utxo_conversion() {
        let json = serde_json::json!({
            "outpoint": {"transactionId": "dead", "index": 1},
            "utxoEntry": {
                "amount": 999,
                "scriptPublicKey": {"scriptPublicKey": "2020abcd"},
                "blockDaaScore": 42,
                "isCoinbase": false
            }
        });

        let raw: RestUtxoRaw = serde_json::from_value(json).unwrap();
        let utxo = raw.into_rpc_utxo();
        assert_eq!(utxo.outpoint.transaction_id, "dead");
        assert_eq!(utxo.outpoint.index, 1);
        assert_eq!(utxo.utxo_entry.amount, 999);
        assert_eq!(utxo.utxo_entry.script_public_key.script, "2020abcd");
    }
}
