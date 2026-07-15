//! Generic payment-watch seam.
//!
//! `PaymentObserver` watches one or more Kaspa addresses and emits a generic
//! [`ScanEvent`] whenever a UTXO or transaction output paying a watched
//! address appears. It is deliberately decoupled from KOB's covenant-order
//! parsing: it matches purely on the output's script-public-key, and carries
//! any covenant id it sees through *opaquely* (raw hex, never parsed). This
//! is the "watch address -> payment observed -> confirm finality" path that
//! the DEX scanner never had (it only discovered UTXOs by covenant
//! redeem-script length matching).
//!
//! The matching logic is pure (no RPC, no node) so it unit-tests trivially;
//! finality confirmation is a separate async step behind the
//! [`FinalityChecker`] trait, which `RpcClient` implements and tests can mock
//! — the same seam pattern used by `MempoolProbe` in `chain::cache`.

pub mod replay;

pub use replay::{PaymentRecord, PaymentStatus, ReplayCheck, ReplayStore};

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use crate::rpc::{ConfirmConfig, ConfirmResult, RpcClient, RpcUtxo};

/// A generic "payment observed" event: some watched address received value in
/// output `output_index` of transaction `txid`.
///
/// This is intentionally product-agnostic. `covenant_id` is passed through as
/// opaque hex if the output carried a covenant binding, so a downstream
/// consumer (e.g. the x402 KCC20 scheme) can act on it — but the observer
/// itself neither parses nor depends on covenant semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanEvent {
    /// Transaction ID that produced the output.
    pub txid: String,
    /// Index of the paying output within the transaction.
    pub output_index: u32,
    /// The watched address that was paid.
    pub address: String,
    /// Value paid, in sompi.
    pub value: u64,
    /// Opaque covenant id (hex) if the output carried a covenant binding.
    /// NOT parsed by the observer.
    pub covenant_id: Option<String>,
    /// scriptPublicKey version of the paying output.
    pub spk_version: u16,
    /// scriptPublicKey script bytes of the paying output.
    pub spk_script: Vec<u8>,
}

impl ScanEvent {
    /// True if this event paid at least `min` sompi. Amount-policy (exact vs
    /// at-least) is the caller's decision; this is just a convenience.
    pub fn pays_at_least(&self, min: u64) -> bool {
        self.value >= min
    }
}

/// A minimal generic transaction output, decoupled from any engine type.
///
/// Construct directly, or from a node's RPC JSON via [`ObservedOutput::from_rpc_json`].
#[derive(Debug, Clone)]
pub struct ObservedOutput {
    /// Value in sompi.
    pub value: u64,
    /// scriptPublicKey version.
    pub spk_version: u16,
    /// scriptPublicKey script bytes.
    pub spk_script: Vec<u8>,
    /// Opaque covenant id (hex) if this output carries a covenant binding.
    pub covenant_id: Option<String>,
}

impl ObservedOutput {
    /// Parse a single output object from a Kaspa RPC transaction JSON.
    ///
    /// Handles both the TN12 flat-hex scriptPublicKey form
    /// (`"<version4hex><scripthex>"`) and the `{version, script|scriptPublicKey}`
    /// object form, and both the `value` (newer) and `amount` (older) keys —
    /// mirroring the engine scanner's output parsing so the same node
    /// responses work here.
    pub fn from_rpc_json(out: &serde_json::Value) -> Option<Self> {
        let value = out
            .get("value")
            .and_then(|v| v.as_u64())
            .or_else(|| out.get("amount").and_then(|v| v.as_u64()))?;

        let spk = out.get("scriptPublicKey")?;
        let (spk_version, spk_script) = if let Some(flat) = spk.as_str() {
            match crate::rpc_types::split_flat_spk_hex(flat) {
                Some((ver_hex, script_hex)) => {
                    let ver = u16::from_str_radix(ver_hex, 16).unwrap_or(0);
                    let scr = hex::decode(script_hex).unwrap_or_default();
                    (ver, scr)
                }
                None => (0u16, hex::decode(flat).unwrap_or_default()),
            }
        } else {
            let ver = spk.get("version").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            let scr = spk
                .get("script")
                .or_else(|| spk.get("scriptPublicKey"))
                .and_then(|v| v.as_str())
                .and_then(|s| hex::decode(s).ok())
                .unwrap_or_default();
            (ver, scr)
        };

        let covenant_id = out
            .get("covenant")
            .and_then(|c| c.get("covenantId"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Some(ObservedOutput { value, spk_version, spk_script, covenant_id })
    }
}

/// Watches a set of addresses and matches paying outputs against them.
///
/// Cheap to clone-free reuse: register addresses once, then feed it UTXO
/// snapshots or transaction outputs as they arrive.
#[derive(Debug, Default, Clone)]
pub struct PaymentObserver {
    /// Watched addresses keyed by their scriptPublicKey script bytes. Kaspa
    /// native P2PK and P2SH addresses are both spk-version 0, so we key on
    /// the script bytes and additionally verify version 0 at match time.
    by_spk: HashMap<Vec<u8>, String>,
}

impl PaymentObserver {
    /// A new observer watching nothing.
    pub fn new() -> Self {
        PaymentObserver { by_spk: HashMap::new() }
    }

    /// Register an address to watch. Returns an error if the address does not
    /// decode to a supported (P2PK / P2SH) script-public-key.
    pub fn watch(&mut self, address: &str) -> crate::Result<()> {
        let spk = crate::bech32::address_to_spk(address)?;
        self.by_spk.insert(spk, address.to_string());
        Ok(())
    }

    /// Register several addresses at once. Fails on the first undecodable one.
    pub fn watch_many<I, S>(&mut self, addresses: I) -> crate::Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for a in addresses {
            self.watch(a.as_ref())?;
        }
        Ok(())
    }

    /// Number of watched addresses.
    pub fn watched_count(&self) -> usize {
        self.by_spk.len()
    }

    /// Whether `address` is being watched.
    pub fn is_watched(&self, address: &str) -> bool {
        match crate::bech32::address_to_spk(address) {
            Ok(spk) => self.by_spk.contains_key(&spk),
            Err(_) => false,
        }
    }

    /// Match a single output's script against the watched set, returning the
    /// watched address it pays (if any). Native SPKs are version 0.
    fn address_for_spk(&self, spk_version: u16, spk_script: &[u8]) -> Option<&String> {
        if spk_version != 0 {
            return None;
        }
        self.by_spk.get(spk_script)
    }

    /// Scan a snapshot of UTXOs (e.g. from `RpcClient::get_utxos`) and emit an
    /// event for every UTXO that pays a watched address. This is the
    /// polling-based discovery path.
    pub fn scan_utxos(&self, utxos: &[RpcUtxo]) -> Vec<ScanEvent> {
        let mut events = Vec::new();
        for u in utxos {
            let (version, script) = u.parse_spk();
            if let Some(addr) = self.address_for_spk(version, &script) {
                events.push(ScanEvent {
                    txid: u.outpoint.transaction_id.clone(),
                    output_index: u.outpoint.index,
                    address: addr.clone(),
                    value: u.utxo_entry.amount,
                    covenant_id: u.utxo_entry.covenant_id.clone(),
                    spk_version: version,
                    spk_script: script,
                });
            }
        }
        events
    }

    /// Scan a transaction's outputs (already parsed into [`ObservedOutput`]s)
    /// and emit an event for each output paying a watched address. This is the
    /// block-notification / self-broadcast observation path.
    pub fn scan_tx_outputs(&self, txid: &str, outputs: &[ObservedOutput]) -> Vec<ScanEvent> {
        let mut events = Vec::new();
        for (idx, out) in outputs.iter().enumerate() {
            if let Some(addr) = self.address_for_spk(out.spk_version, &out.spk_script) {
                events.push(ScanEvent {
                    txid: txid.to_string(),
                    output_index: idx as u32,
                    address: addr.clone(),
                    value: out.value,
                    covenant_id: out.covenant_id.clone(),
                    spk_version: out.spk_version,
                    spk_script: out.spk_script.clone(),
                });
            }
        }
        events
    }

    /// Parse a raw Kaspa RPC transaction JSON and scan its outputs. Convenience
    /// wrapper that reads `transactionId`/`verboseData.transactionId` and the
    /// `outputs` array, then delegates to [`scan_tx_outputs`](Self::scan_tx_outputs).
    pub fn observe_tx_json(&self, tx_json: &serde_json::Value) -> Vec<ScanEvent> {
        let txid = tx_json
            .get("verboseData")
            .and_then(|v| v.get("transactionId"))
            .and_then(|v| v.as_str())
            .or_else(|| tx_json.get("transactionId").and_then(|v| v.as_str()));
        let Some(txid) = txid else { return Vec::new() };

        let outputs: Vec<ObservedOutput> = tx_json
            .get("outputs")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(ObservedOutput::from_rpc_json).collect())
            .unwrap_or_default();

        self.scan_tx_outputs(txid, &outputs)
    }

    /// Confirm on-chain finality for an observed payment.
    ///
    /// Thin wrapper over the [`FinalityChecker`] (production: `RpcClient`'s
    /// `confirm_tx_output`, which polls the UTXO set for the specific
    /// output). Kept generic so tests can inject a deterministic checker
    /// without a live node.
    pub async fn confirm_finality<C: FinalityChecker>(
        &self,
        checker: &C,
        event: &ScanEvent,
        config: Option<ConfirmConfig>,
    ) -> ConfirmResult {
        checker
            .confirm_output(&event.txid, event.output_index, &event.address, config)
            .await
    }
}

/// Abstraction over "confirm a specific transaction output reached finality".
///
/// `RpcClient` implements this via `confirm_tx_output`; unit tests supply a
/// deterministic fake. Mirrors the `MempoolProbe` seam in `chain::cache`.
pub trait FinalityChecker {
    fn confirm_output<'a>(
        &'a self,
        tx_id: &'a str,
        output_idx: u32,
        address: &'a str,
        config: Option<ConfirmConfig>,
    ) -> Pin<Box<dyn Future<Output = ConfirmResult> + Send + 'a>>;
}

impl FinalityChecker for RpcClient {
    fn confirm_output<'a>(
        &'a self,
        tx_id: &'a str,
        output_idx: u32,
        address: &'a str,
        config: Option<ConfirmConfig>,
    ) -> Pin<Box<dyn Future<Output = ConfirmResult> + Send + 'a>> {
        Box::pin(async move { self.confirm_tx_output(tx_id, output_idx, address, config).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc_types::{RpcOutpoint, RpcSpk, RpcUtxo, RpcUtxoEntry};

    // A real testnet-10 P2PK address and its matching SPK (built the same way
    // the node builds output scripts). This is the "construct real bytecode /
    // SPK and run it through the real matcher off-chain" harness style used by
    // toccata_fill_repro.rs — here we build a real address<->SPK pair and feed
    // it through the observer as a node would.
    fn watched_p2pk() -> (String, Vec<u8>) {
        let pubkey = [0x11u8; 32];
        let addr = crate::wallet::pubkey_to_address(&pubkey, crate::types::Network::Testnet);
        let spk = crate::bech32::address_to_spk(&addr).unwrap();
        (addr, spk)
    }

    fn other_p2pk_spk() -> Vec<u8> {
        let pubkey = [0x22u8; 32];
        let addr = crate::wallet::pubkey_to_address(&pubkey, crate::types::Network::Testnet);
        crate::bech32::address_to_spk(&addr).unwrap()
    }

    fn utxo(txid: &str, index: u32, amount: u64, spk_script: &[u8], covenant: Option<&str>) -> RpcUtxo {
        RpcUtxo {
            outpoint: RpcOutpoint { transaction_id: txid.to_string(), index },
            utxo_entry: RpcUtxoEntry {
                amount,
                script_public_key: RpcSpk { version: 0, script: hex::encode(spk_script) },
                block_daa_score: 0,
                is_coinbase: false,
                covenant_id: covenant.map(|s| s.to_string()),
            },
        }
    }

    #[test]
    fn watch_and_match_utxo_to_watched_address() {
        let (addr, spk) = watched_p2pk();
        let mut obs = PaymentObserver::new();
        obs.watch(&addr).unwrap();
        assert_eq!(obs.watched_count(), 1);
        assert!(obs.is_watched(&addr));

        let utxos = vec![
            utxo(&"aa".repeat(32), 0, 100_000_000, &spk, None),
            utxo(&"bb".repeat(32), 1, 50_000_000, &other_p2pk_spk(), None),
        ];
        let events = obs.scan_utxos(&utxos);
        assert_eq!(events.len(), 1, "only the watched-address UTXO should match");
        assert_eq!(events[0].address, addr);
        assert_eq!(events[0].value, 100_000_000);
        assert_eq!(events[0].output_index, 0);
        assert!(events[0].pays_at_least(100_000_000));
        assert!(!events[0].pays_at_least(100_000_001));
    }

    #[test]
    fn covenant_id_passed_through_opaquely() {
        let (addr, spk) = watched_p2pk();
        let mut obs = PaymentObserver::new();
        obs.watch(&addr).unwrap();
        let cov = "cc".repeat(32);
        let utxos = vec![utxo(&"dd".repeat(32), 2, 7_000_000, &spk, Some(&cov))];
        let events = obs.scan_utxos(&utxos);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].covenant_id.as_deref(), Some(cov.as_str()));
    }

    #[test]
    fn unwatched_address_yields_no_event() {
        let (addr, _spk) = watched_p2pk();
        let mut obs = PaymentObserver::new();
        obs.watch(&addr).unwrap();
        let utxos = vec![utxo(&"ee".repeat(32), 0, 9, &other_p2pk_spk(), None)];
        assert!(obs.scan_utxos(&utxos).is_empty());
    }

    #[test]
    fn observe_tx_json_flat_spk_form() {
        let (addr, spk) = watched_p2pk();
        let mut obs = PaymentObserver::new();
        obs.watch(&addr).unwrap();

        // Flat scriptPublicKey form: "<version4hex><scripthex>".
        let flat = format!("0000{}", hex::encode(&spk));
        let tx = serde_json::json!({
            "transactionId": "ff".repeat(32),
            "outputs": [
                { "value": 123_456u64, "scriptPublicKey": flat },
                { "value": 1u64, "scriptPublicKey": format!("0000{}", hex::encode(other_p2pk_spk())) },
            ],
        });
        let events = obs.observe_tx_json(&tx);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].value, 123_456);
        assert_eq!(events[0].output_index, 0);
        assert_eq!(events[0].address, addr);
    }

    #[test]
    fn observe_tx_json_object_spk_form_with_covenant() {
        let (addr, spk) = watched_p2pk();
        let mut obs = PaymentObserver::new();
        obs.watch(&addr).unwrap();
        let cov = "1a".repeat(32);
        let tx = serde_json::json!({
            "verboseData": { "transactionId": "12".repeat(32) },
            "outputs": [
                {
                    "amount": 999u64,
                    "scriptPublicKey": { "version": 0, "script": hex::encode(&spk) },
                    "covenant": { "authorizingInput": 0, "covenantId": cov }
                }
            ],
        });
        let events = obs.observe_tx_json(&tx);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].value, 999);
        assert_eq!(events[0].covenant_id.as_deref(), Some(cov.as_str()));
    }

    #[test]
    fn watch_rejects_undecodable_address() {
        let mut obs = PaymentObserver::new();
        assert!(obs.watch("not-a-valid-address").is_err());
        assert_eq!(obs.watched_count(), 0);
    }

    // --- finality confirmation via a mock checker (no live node) ---

    struct FakeFinality {
        confirmed: bool,
    }

    impl FinalityChecker for FakeFinality {
        fn confirm_output<'a>(
            &'a self,
            _tx_id: &'a str,
            _output_idx: u32,
            _address: &'a str,
            _config: Option<ConfirmConfig>,
        ) -> Pin<Box<dyn Future<Output = ConfirmResult> + Send + 'a>> {
            let confirmed = self.confirmed;
            Box::pin(async move {
                ConfirmResult { confirmed, polls: 1, amount: if confirmed { Some(100) } else { None } }
            })
        }
    }

    #[tokio::test]
    async fn confirm_finality_delegates_to_checker() {
        let (addr, spk) = watched_p2pk();
        let mut obs = PaymentObserver::new();
        obs.watch(&addr).unwrap();
        let event = obs.scan_utxos(&[utxo(&"77".repeat(32), 0, 100, &spk, None)])[0].clone();

        let ok = obs.confirm_finality(&FakeFinality { confirmed: true }, &event, None).await;
        assert!(ok.confirmed);
        let no = obs.confirm_finality(&FakeFinality { confirmed: false }, &event, None).await;
        assert!(!no.confirmed);
    }

    #[test]
    fn from_rpc_json_rejects_non_boundary_multibyte_spk_cleanly() {
        // DoS regression: a flat scriptPublicKey string with a multibyte
        // UTF-8 char straddling byte offset 4 used to panic ("byte index 4 is
        // not a char boundary") even though its byte length is >= 4. Reachable
        // from untrusted node RPC data (mempool/UTXO scans feed this path).
        // Now: degrades to an empty (non-matching) script, no panic.
        let json = serde_json::json!({
            "value": 100_000_000u64,
            "scriptPublicKey": "ab\u{20AC}cd",
        });
        let out = ObservedOutput::from_rpc_json(&json).expect("value present -> Some");
        assert_eq!(out.spk_version, 0);
        assert!(out.spk_script.is_empty(), "malformed spk decodes to no bytes, not a panic");
    }
}
