//! Shared RPC response types for Kaspad JSON-RPC WebSocket and REST APIs.
//!
//! These types deserialize Kaspad's camelCase JSON format (e.g., `transactionId`,
//! `utxoEntry`, `scriptPublicKey`). They are used by both kob-cli and kob-engine
//! RPC clients to avoid duplication.

use serde::Deserialize;

/// A UTXO from getUtxosByAddresses response.
#[derive(Debug, Clone, Deserialize)]
pub struct RpcUtxo {
    pub outpoint: RpcOutpoint,
    #[serde(rename = "utxoEntry")]
    pub utxo_entry: RpcUtxoEntry,
}

/// Transaction outpoint reference.
#[derive(Debug, Clone, Deserialize)]
pub struct RpcOutpoint {
    #[serde(rename = "transactionId")]
    pub transaction_id: String,
    pub index: u32,
}

/// UTXO entry with amount, script, DAA score, and coinbase flag.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct RpcUtxoEntry {
    pub amount: u64,
    #[serde(rename = "scriptPublicKey")]
    pub script_public_key: RpcSpk,
    #[serde(rename = "blockDaaScore", default)]
    pub block_daa_score: u64,
    #[serde(rename = "isCoinbase", default)]
    pub is_coinbase: bool,
    /// Covenant id of the UTXO, if any (covenant-bound UTXOs only).
    /// Kaspad serializes this field as `covenantId` (camelCase) in JSON-RPC
    /// responses, or omits/nulls it for covenant-free UTXOs. The filter in
    /// `kob-cli deploy sell` auto-select uses this to distinguish fresh token
    /// UTXOs (carrying the token's covenant id) from incompatible ones.
    #[serde(rename = "covenantId", default)]
    pub covenant_id: Option<String>,
}

/// Split a flat hex `scriptPublicKey` string into `(version_hex, script_hex)`.
///
/// The field is always ASCII hex on the wire, but the string arrives from
/// untrusted sources (client JSON, node RPC data) and is not guaranteed to
/// be. `str::len()` counts BYTES, while `&s[..4]` / `&s[4..]` slice at a BYTE
/// index — Rust panics if that index doesn't land on a UTF-8 char boundary,
/// which a multibyte character straddling offset 4 can trigger even when
/// `s.len() >= 4` holds. `str::get` is the checked, non-panicking
/// equivalent: it returns `None` on an out-of-bounds OR non-boundary index,
/// so this never panics regardless of input.
pub fn split_flat_spk_hex(s: &str) -> Option<(&str, &str)> {
    Some((s.get(..4)?, s.get(4..)?))
}

/// scriptPublicKey — handles both flat hex string and `{version, script}` object.
///
/// TN12 nodes return scriptPublicKey as a flat hex string; mainnet/newer nodes
/// return `{"version": u16, "script": "hex"}`. This custom deserializer accepts both.
#[derive(Debug, Clone)]
pub struct RpcSpk {
    pub version: u16,
    pub script: String,
}

impl<'de> serde::Deserialize<'de> for RpcSpk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de;

        struct RpcSpkVisitor;

        impl<'de> de::Visitor<'de> for RpcSpkVisitor {
            type Value = RpcSpk;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a string or {version, script} object for scriptPublicKey")
            }

            /// Plain hex string: first 4 hex chars = version (u16 LE), rest = script hex.
            fn visit_str<E: de::Error>(self, v: &str) -> Result<RpcSpk, E> {
                let (ver_hex, script_hex) = split_flat_spk_hex(v).ok_or_else(|| {
                    E::custom(format!(
                        "scriptPublicKey string too short or malformed: '{}'", v
                    ))
                })?;
                let version = u16::from_str_radix(ver_hex, 16).map_err(E::custom)?;
                Ok(RpcSpk {
                    version,
                    script: script_hex.to_string(),
                })
            }

            /// Object form: {"version": u16, "script": "hex"} or {"version": u16, "scriptPublicKey": "hex"}
            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<RpcSpk, A::Error> {
                let mut version: Option<u16> = None;
                let mut script: Option<String> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "version" => version = Some(map.next_value()?),
                        "script" | "scriptPublicKey" => script = Some(map.next_value()?),
                        _ => { let _ = map.next_value::<serde_json::Value>(); }
                    }
                }
                Ok(RpcSpk {
                    version: version.unwrap_or(0),
                    script: script.unwrap_or_default(),
                })
            }
        }

        deserializer.deserialize_any(RpcSpkVisitor)
    }
}

impl RpcUtxoEntry {
    /// Extract script bytes from the hex script field.
    pub fn script_bytes(&self) -> Vec<u8> {
        hex::decode(&self.script_public_key.script).unwrap_or_default()
    }

    /// Extract version from script_public_key.
    pub fn script_version(&self) -> u16 {
        self.script_public_key.version
    }

    /// Check if this is a P2SH script (starts with 0xaa, ends with 0x87).
    pub fn is_p2sh(&self) -> bool {
        let bytes = self.script_bytes();
        bytes.len() == 35 && bytes[0] == 0xaa && bytes[34] == 0x87
    }
}

impl RpcUtxo {
    /// Parse the scriptPublicKey into (version, script_bytes).
    pub fn parse_spk(&self) -> (u16, Vec<u8>) {
        let bytes = match hex::decode(&self.utxo_entry.script_public_key.script) {
            Ok(b) => b,
            Err(_) => return (0, vec![]),
        };
        (self.utxo_entry.script_public_key.version, bytes)
    }

    /// Script bytes (decoded from hex).
    pub fn script_bytes(&self) -> Vec<u8> {
        self.utxo_entry.script_bytes()
    }

    /// Check if this is a P2SH UTXO (script starts with aa20).
    pub fn is_p2sh(&self) -> bool {
        self.utxo_entry.script_public_key.script.starts_with("aa20")
    }

    /// Outpoint key string "txid:index".
    pub fn outpoint_key(&self) -> String {
        format!("{}:{}", self.outpoint.transaction_id, self.outpoint.index)
    }
}

/// Parse a REST API scriptPublicKey value (string or object) into RpcSpk.
pub fn parse_rest_spk(v: &serde_json::Value) -> RpcSpk {
    match v {
        serde_json::Value::String(s) => match split_flat_spk_hex(s) {
            Some((ver_hex, script_hex)) => RpcSpk {
                version: u16::from_str_radix(ver_hex, 16).unwrap_or(0),
                script: script_hex.to_string(),
            },
            None => RpcSpk {
                version: 0,
                script: s.clone(),
            },
        },
        serde_json::Value::Object(obj) => {
            let version = obj
                .get("version")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u16;
            let script = obj
                .get("scriptPublicKey")
                .or_else(|| obj.get("script"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            RpcSpk { version, script }
        }
        _ => RpcSpk {
            version: 0,
            script: String::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_spk_deserialize_flat_string() {
        let json = r#""0000aa20bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb87""#;
        let spk: RpcSpk = serde_json::from_str(json).unwrap();
        assert_eq!(spk.version, 0);
        assert!(spk.script.starts_with("aa20"));
        assert!(spk.script.ends_with("87"));
    }

    #[test]
    fn rpc_spk_deserialize_object() {
        let json = r#"{"version": 0, "scriptPublicKey": "aa20bbbb87"}"#;
        let spk: RpcSpk = serde_json::from_str(json).unwrap();
        assert_eq!(spk.version, 0);
        assert_eq!(spk.script, "aa20bbbb87");
    }

    #[test]
    fn rpc_spk_deserialize_object_script_key() {
        let json = r#"{"version": 1, "script": "deadbeef"}"#;
        let spk: RpcSpk = serde_json::from_str(json).unwrap();
        assert_eq!(spk.version, 1);
        assert_eq!(spk.script, "deadbeef");
    }

    #[test]
    fn rpc_utxo_outpoint_key() {
        let utxo = RpcUtxo {
            outpoint: RpcOutpoint {
                transaction_id: "abc123".to_string(),
                index: 2,
            },
            utxo_entry: RpcUtxoEntry {
                amount: 1000,
                script_public_key: RpcSpk { version: 0, script: String::new() },
                block_daa_score: 0,
                is_coinbase: false,
                covenant_id: None,
            },
        };
        assert_eq!(utxo.outpoint_key(), "abc123:2");
    }

    #[test]
    fn rpc_utxo_parse_spk_valid() {
        let mut script_hex = String::from("20");
        script_hex.push_str(&"aa".repeat(32));
        script_hex.push_str("ac");
        let utxo = RpcUtxo {
            outpoint: RpcOutpoint {
                transaction_id: "def".to_string(),
                index: 1,
            },
            utxo_entry: RpcUtxoEntry {
                amount: 5_000_000,
                script_public_key: RpcSpk { version: 0, script: script_hex },
                block_daa_score: 100,
                is_coinbase: false,
                covenant_id: None,
            },
        };
        let (version, script) = utxo.parse_spk();
        assert_eq!(version, 0);
        assert_eq!(script.len(), 34);
        assert_eq!(script[0], 0x20);
        assert_eq!(script[33], 0xac);
    }

    #[test]
    fn rpc_utxo_entry_is_p2sh() {
        // 35-byte P2SH: aa + 20 bytes hash + 87
        let mut script_hex = String::from("aa");
        script_hex.push_str(&"bb".repeat(33));
        script_hex.push_str("87");
        let entry = RpcUtxoEntry {
            amount: 100,
            script_public_key: RpcSpk { version: 0, script: script_hex },
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        };
        assert!(entry.is_p2sh());
    }

    #[test]
    fn parse_rest_spk_object() {
        let v = serde_json::json!({"scriptPublicKey": "aa20abcd87"});
        let spk = parse_rest_spk(&v);
        assert_eq!(spk.version, 0);
        assert_eq!(spk.script, "aa20abcd87");
    }

    #[test]
    fn parse_rest_spk_with_version() {
        let v = serde_json::json!({"version": 1, "scriptPublicKey": "ff00"});
        let spk = parse_rest_spk(&v);
        assert_eq!(spk.version, 1);
        assert_eq!(spk.script, "ff00");
    }

    #[test]
    fn parse_rest_spk_string() {
        let v = serde_json::json!("0000aa20abcd87");
        let spk = parse_rest_spk(&v);
        assert_eq!(spk.version, 0);
        assert_eq!(spk.script, "aa20abcd87");
    }

    // --- DoS regression: a multibyte UTF-8 char straddling byte offset 4 used
    // to panic `&s[..4]`/`&s[4..]` (byte-index string slicing) even though
    // `s.len() >= 4` (byte count) looked safe, because that byte offset lands
    // mid-character. Reachable from untrusted client JSON / node RPC data.

    /// "a", "b", then a 3-byte '€' spanning byte offsets 2..5 — offset 4 is
    /// the LAST byte of '€', not a char boundary.
    const NON_BOUNDARY_AT_4: &str = "ab\u{20AC}cd";

    #[test]
    fn split_flat_spk_hex_rejects_non_boundary_multibyte() {
        assert_eq!(split_flat_spk_hex(NON_BOUNDARY_AT_4), None);
        // Sanity: this used to be exactly the panic trigger (len counts
        // bytes, so this passed the old `len() >= 4` guard).
        assert!(NON_BOUNDARY_AT_4.len() >= 4);
    }

    #[test]
    fn rpc_spk_deserialize_rejects_non_boundary_multibyte_cleanly() {
        // Previously: panic ("byte index 4 is not a char boundary"). Now: a
        // clean deserialize error, no panic.
        let json = serde_json::to_string(NON_BOUNDARY_AT_4).unwrap();
        let res: Result<RpcSpk, _> = serde_json::from_str(&json);
        assert!(res.is_err());
    }

    #[test]
    fn parse_rest_spk_handles_non_boundary_multibyte_cleanly() {
        // Previously: panic. Now: falls back to version 0 / whole string as
        // script (same degrade path as an under-length string), no panic.
        let v = serde_json::json!(NON_BOUNDARY_AT_4);
        let spk = parse_rest_spk(&v);
        assert_eq!(spk.version, 0);
        assert_eq!(spk.script, NON_BOUNDARY_AT_4);
    }
}
