//! REST API client for Kaspa nodes.
//!
//! Provides the same UTXO/TX operations as the WebSocket RPC client,
//! but over HTTP REST. Used as a fallback when wRPC is unavailable.

use crate::rpc::{RpcOutpoint, RpcUtxo, RpcUtxoEntry, parse_rest_spk};

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

    /// Health check: try GET /info/blockdag with a short timeout.
    pub async fn health_check(&self) -> anyhow::Result<()> {
        let url = format!("{}/info/blockdag", self.base_url);
        let resp = self
            .client
            .get(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("REST health check failed: HTTP {}", resp.status());
        }
        Ok(())
    }

    /// Get UTXOs for one or more addresses, sorted by amount descending.
    pub async fn get_utxos_by_addresses(
        &self,
        addresses: &[&str],
    ) -> anyhow::Result<Vec<RpcUtxo>> {
        let mut all_utxos = Vec::new();
        for addr in addresses {
            let url = format!("{}/addresses/{}/utxos", self.base_url, addr);
            let resp = self.client.get(&url).send().await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!(
                    "REST GET /addresses/{}/utxos failed: HTTP {} — {}",
                    addr,
                    status,
                    body
                );
            }
            let body: serde_json::Value = resp.json().await?;
            // REST returns an array of UTXOs directly
            let entries: Vec<RestUtxoRaw> = serde_json::from_value(
                body.clone(),
            )
            .map_err(|e| {
                tracing::warn!("[REST] Failed to deserialize UTXOs for {}: {} — raw: {}", addr, e, body);
                e
            })?;

            for raw in entries {
                all_utxos.push(raw.into_rpc_utxo());
            }
        }
        all_utxos.sort_by(|a, b| b.utxo_entry.amount.cmp(&a.utxo_entry.amount));
        Ok(all_utxos)
    }

    /// Get spendable UTXOs.
    ///
    /// REST API has no mempool filtering, so this returns all UTXOs with a warning.
    pub async fn get_spendable_utxos(&self, address: &str) -> anyhow::Result<Vec<RpcUtxo>> {
        tracing::warn!(
            "[REST] Mempool filtering unavailable — UTXOs may include recently spent"
        );
        self.get_utxos_by_addresses(&[address]).await
    }

    /// Submit a transaction. The `payload` is in wRPC format; this method
    /// translates it to REST format before sending.
    pub async fn submit_transaction(
        &self,
        payload: serde_json::Value,
    ) -> anyhow::Result<String> {
        let rest_body = translate_wrpc_tx_to_rest(&payload)?;
        let url = format!("{}/transactions", self.base_url);
        let resp = self.client.post(&url).json(&rest_body).send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("REST POST /transactions failed: HTTP {} — {}", status, body);
        }
        let result: serde_json::Value = resp.json().await?;
        let tx_id = result
            .get("transactionId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "REST accepted transaction but did not return transactionId: {}",
                    result
                )
            })?;
        Ok(tx_id.to_string())
    }

    /// Get the current virtual DAA score.
    pub async fn get_daa_score(&self) -> anyhow::Result<u64> {
        let url = format!("{}/info/virtual-chain-blue-score", self.base_url);
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!(
                "REST GET /info/virtual-chain-blue-score failed: HTTP {}",
                resp.status()
            );
        }
        let body: serde_json::Value = resp.json().await?;
        let score = body
            .get("blueScore")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("Missing blueScore in REST response: {}", body))?;
        Ok(score)
    }

    /// Get blockDAG info (raw JSON).
    pub async fn get_block_dag_info(&self) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}/info/blockdag", self.base_url);
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!(
                "REST GET /info/blockdag failed: HTTP {}",
                resp.status()
            );
        }
        Ok(resp.json().await?)
    }

    /// Get fee estimate.
    pub async fn get_fee_estimate(&self) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}/info/fee-estimate", self.base_url);
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!(
                "REST GET /info/fee-estimate failed: HTTP {}",
                resp.status()
            );
        }
        Ok(resp.json().await?)
    }

    /// Base URL for display.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

// --- REST response deserialization ---

/// Raw UTXO as returned by the REST API.
/// The REST format uses `scriptPublicKey: { scriptPublicKey: "hex" }` (no version).
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
    #[serde(deserialize_with = "deser_u64_or_string")]
    amount: u64,
    #[serde(rename = "scriptPublicKey")]
    script_public_key: serde_json::Value, // can be string or object
    #[serde(rename = "blockDaaScore", default, deserialize_with = "deser_u64_or_string_default")]
    block_daa_score: u64,
    #[serde(rename = "isCoinbase", default)]
    is_coinbase: bool,
}

/// Deserialize a value that may be either a JSON number or a string-encoded number.
fn deser_u64_or_string<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct U64OrString;
    impl<'de> de::Visitor<'de> for U64OrString {
        type Value = u64;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a u64 or a string-encoded u64")
        }

        fn visit_u64<E: de::Error>(self, v: u64) -> Result<u64, E> {
            Ok(v)
        }

        fn visit_i64<E: de::Error>(self, v: i64) -> Result<u64, E> {
            u64::try_from(v).map_err(|_| E::custom(format!("negative value: {}", v)))
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<u64, E> {
            v.parse::<u64>().map_err(|_| E::custom(format!("invalid u64 string: {}", v)))
        }
    }

    deserializer.deserialize_any(U64OrString)
}

/// Like `deser_u64_or_string` but returns 0 for missing/null fields.
fn deser_u64_or_string_default<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct U64OrStringOrNull;
    impl<'de> de::Visitor<'de> for U64OrStringOrNull {
        type Value = u64;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a u64, string-encoded u64, or null")
        }

        fn visit_u64<E: de::Error>(self, v: u64) -> Result<u64, E> {
            Ok(v)
        }

        fn visit_i64<E: de::Error>(self, v: i64) -> Result<u64, E> {
            u64::try_from(v).map_err(|_| E::custom(format!("negative value: {}", v)))
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<u64, E> {
            v.parse::<u64>().map_err(|_| E::custom(format!("invalid u64 string: {}", v)))
        }

        fn visit_none<E: de::Error>(self) -> Result<u64, E> {
            Ok(0)
        }

        fn visit_unit<E: de::Error>(self) -> Result<u64, E> {
            Ok(0)
        }
    }

    deserializer.deserialize_any(U64OrStringOrNull)
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
            },
        }
    }
}

// --- TX format translation: wRPC -> REST ---

/// Translate a wRPC-format transaction payload to REST API format.
///
/// Key differences:
/// - wRPC: `value` (string) -> REST: `amount` (number)
/// - wRPC: `script` -> REST: `scriptPublicKey` (inside scriptPublicKey obj)
/// - wRPC: string numbers -> REST: actual numbers
/// - REST wraps in `{"transaction": {...}, "allowOrphan": false}`
fn translate_wrpc_tx_to_rest(
    wrpc_payload: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    // The wRPC submitTransaction payload has the TX at the top level
    // or nested under "transaction"
    let tx = if let Some(t) = wrpc_payload.get("transaction") {
        t.clone()
    } else {
        wrpc_payload.clone()
    };

    // Translate inputs
    let inputs = tx
        .get("inputs")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|inp| {
                    let mut out = inp.clone();
                    if let Some(obj) = out.as_object_mut() {
                        // sequence: string -> number
                        if let Some(seq) = obj.get("sequence").cloned() {
                            if let Some(s) = seq.as_str() {
                                if let Ok(n) = s.parse::<u64>() {
                                    obj.insert("sequence".to_string(), serde_json::json!(n));
                                }
                            }
                        }
                        // sigOpCount: string -> number
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

    // Translate outputs
    let outputs = tx
        .get("outputs")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|out_val| {
                    let mut obj = serde_json::Map::new();

                    // value (string) -> amount (number)
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

                    // scriptPublicKey: translate "script" -> "scriptPublicKey"
                    if let Some(spk) = out_val.get("scriptPublicKey") {
                        let mut spk_obj = serde_json::Map::new();
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
                        spk_obj.insert(
                            "scriptPublicKey".to_string(),
                            serde_json::json!(script),
                        );
                        obj.insert(
                            "scriptPublicKey".to_string(),
                            serde_json::Value::Object(spk_obj),
                        );
                    }

                    // Pass through covenant binding if present
                    if let Some(cov) = out_val.get("covenant") {
                        obj.insert("covenant".to_string(), cov.clone());
                    }

                    serde_json::Value::Object(obj)
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    // Build REST TX
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

    let rest_tx = serde_json::json!({
        "transaction": {
            "version": version,
            "inputs": inputs,
            "outputs": outputs,
            "lockTime": lock_time,
            "subnetworkId": subnetwork_id,
        },
        "allowOrphan": false,
    });

    Ok(rest_tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    // parse_rest_spk tests are in kob_core::rpc_types::tests

    #[test]
    fn test_translate_wrpc_tx_basic() {
        let wrpc = serde_json::json!({
            "transaction": {
                "version": "0",
                "inputs": [{
                    "previousOutpoint": {
                        "transactionId": "abc123",
                        "index": 0
                    },
                    "signatureScript": "deadbeef",
                    "sequence": "0",
                    "sigOpCount": "1"
                }],
                "outputs": [{
                    "value": "4980000",
                    "scriptPublicKey": {
                        "version": "0",
                        "script": "aa20abcdef87"
                    }
                }],
                "lockTime": "0",
                "subnetworkId": "0000000000000000000000000000000000000000",
                "gas": "0",
                "payload": ""
            }
        });

        let rest = translate_wrpc_tx_to_rest(&wrpc).unwrap();
        let tx = rest.get("transaction").unwrap();

        // version should be number
        assert_eq!(tx["version"], 0);

        // outputs: value -> amount (number)
        let out0 = &tx["outputs"][0];
        assert_eq!(out0["amount"], 4980000);

        // scriptPublicKey: script -> scriptPublicKey
        let spk = &out0["scriptPublicKey"];
        assert_eq!(spk["version"], 0);
        assert_eq!(spk["scriptPublicKey"], "aa20abcdef87");

        // inputs: sequence/sigOpCount should be numbers
        let inp0 = &tx["inputs"][0];
        assert_eq!(inp0["sequence"], 0);
        assert_eq!(inp0["sigOpCount"], 1);

        // gas/payload should NOT be in rest output
        assert!(tx.get("gas").is_none());
        assert!(tx.get("payload").is_none());

        // allowOrphan
        assert_eq!(rest["allowOrphan"], false);
    }

    #[test]
    fn test_translate_wrpc_tx_already_numeric() {
        let wrpc = serde_json::json!({
            "version": 0,
            "inputs": [{
                "previousOutpoint": {"transactionId": "abc", "index": 0},
                "signatureScript": "ff",
                "sequence": 0,
                "sigOpCount": 1
            }],
            "outputs": [{
                "amount": 1000,
                "scriptPublicKey": {"version": 0, "scriptPublicKey": "2020abcd"}
            }],
            "lockTime": 0,
            "subnetworkId": "0000000000000000000000000000000000000000"
        });

        let rest = translate_wrpc_tx_to_rest(&wrpc).unwrap();
        let tx = rest.get("transaction").unwrap();
        assert_eq!(tx["outputs"][0]["amount"], 1000);
        assert_eq!(
            tx["outputs"][0]["scriptPublicKey"]["scriptPublicKey"],
            "2020abcd"
        );
    }

    #[test]
    fn test_rest_utxo_raw_conversion() {
        let json = serde_json::json!({
            "address": "kaspatest:abc",
            "outpoint": {
                "transactionId": "deadbeef",
                "index": 0
            },
            "utxoEntry": {
                "amount": 5000000,
                "scriptPublicKey": {"scriptPublicKey": "aa20abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab87"},
                "blockDaaScore": 12345,
                "isCoinbase": false
            }
        });

        let raw: RestUtxoRaw = serde_json::from_value(json).unwrap();
        let utxo = raw.into_rpc_utxo();
        assert_eq!(utxo.outpoint.transaction_id, "deadbeef");
        assert_eq!(utxo.outpoint.index, 0);
        assert_eq!(utxo.utxo_entry.amount, 5000000);
        assert_eq!(
            utxo.utxo_entry.script_public_key.script,
            "aa20abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab87"
        );
        assert_eq!(utxo.utxo_entry.block_daa_score, 12345);
        assert!(!utxo.utxo_entry.is_coinbase);
    }

    #[test]
    fn test_translate_wrpc_tx_with_payload_stripped() {
        let wrpc = serde_json::json!({
            "transaction": {
                "version": 0,
                "inputs": [],
                "outputs": [],
                "lockTime": 0,
                "subnetworkId": "0000000000000000000000000000000000000000",
                "gas": "0",
                "payload": "4b4f423a313a00",
                "mass": "1234"
            }
        });

        let rest = translate_wrpc_tx_to_rest(&wrpc).unwrap();
        let tx = rest.get("transaction").unwrap();
        // gas, payload, mass should not appear
        assert!(tx.get("gas").is_none());
        assert!(tx.get("payload").is_none());
        assert!(tx.get("mass").is_none());
    }

    #[test]
    fn test_rest_utxo_string_encoded_amounts() {
        // Real REST API returns amounts and blockDaaScore as strings, not numbers.
        // This was causing "invalid type: string, expected u64" errors.
        let json = serde_json::json!({
            "address": "kaspatest:abc",
            "outpoint": {
                "transactionId": "508ce7d10b5ae7a61361372458982a57b6209bac636dc027d494f95d9ee3e87f",
                "index": 0
            },
            "utxoEntry": {
                "amount": "4990000",
                "scriptPublicKey": {"scriptPublicKey": "20385d824a2a88043659cc213e4bba950a50fd6be9a10861e3ab568d762a83825cac"},
                "blockDaaScore": "44461699",
                "isCoinbase": false
            }
        });

        let raw: RestUtxoRaw = serde_json::from_value(json).unwrap();
        let utxo = raw.into_rpc_utxo();
        assert_eq!(utxo.utxo_entry.amount, 4990000);
        assert_eq!(utxo.utxo_entry.block_daa_score, 44461699);
        assert_eq!(
            utxo.outpoint.transaction_id,
            "508ce7d10b5ae7a61361372458982a57b6209bac636dc027d494f95d9ee3e87f"
        );
    }

    #[test]
    fn test_rest_utxo_with_version_in_spk() {
        let json = serde_json::json!({
            "outpoint": {"transactionId": "aabb", "index": 1},
            "utxoEntry": {
                "amount": 100,
                "scriptPublicKey": {"version": 1, "scriptPublicKey": "ff00"},
                "blockDaaScore": 999,
                "isCoinbase": true
            }
        });

        let raw: RestUtxoRaw = serde_json::from_value(json).unwrap();
        let utxo = raw.into_rpc_utxo();
        assert_eq!(utxo.utxo_entry.script_public_key.version, 1);
        assert_eq!(utxo.utxo_entry.script_public_key.script, "ff00");
        assert!(utxo.utxo_entry.is_coinbase);
    }
}
