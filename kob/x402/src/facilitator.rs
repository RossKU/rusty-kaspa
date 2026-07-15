//! The facilitator: turns a signed payment artifact into a settled on-chain
//! payment, with replay protection and idempotent settlement.
//!
//! Chain access is behind the [`ChainBackend`] trait so the verify/settle
//! logic unit-tests without a live node (production impl is `RpcClient`). This
//! is the same seam style as `MempoolProbe`/`FinalityChecker` in `kob-settle`.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use tokio::sync::Mutex;

use kob_settle::observe::{ObservedOutput, PaymentObserver, PaymentRecord, ReplayCheck, ReplayStore};
use kob_settle::rpc::{ConfirmConfig, RpcClient, RpcUtxo};

use crate::scheme_kcc20;
use crate::scheme_native;
use crate::fingerprint;
use crate::wire::{
    ASSET_NATIVE_KAS, AwaitRequest, FacilitatorRequest, SCHEME_EXACT, SettleResponse, VerifyResponse,
};

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// An incoming transaction discovered at a watched address (pull mode). Carries
/// enough to match it to `PaymentRequirements`: the outputs (for recipient +
/// amount) and the tx payload (for the request-fingerprint memo).
#[derive(Debug, Clone)]
pub struct DiscoveredTx {
    pub txid: String,
    pub outputs: Vec<ObservedOutput>,
    /// TX payload bytes (may carry an `X402:<fingerprint>` memo).
    pub payload: Vec<u8>,
}

/// Minimal chain operations the facilitator needs.
pub trait ChainBackend: Send + Sync {
    /// UTXOs currently owned (unspent) by `address`.
    fn get_address_utxos<'a>(&'a self, address: &'a str) -> BoxFuture<'a, Result<Vec<RpcUtxo>, String>>;
    /// Broadcast a `submitTransaction` envelope; returns the on-chain txid.
    fn submit<'a>(&'a self, tx_json: serde_json::Value) -> BoxFuture<'a, Result<String, String>>;
    /// Poll until `output_idx` of `txid` (paying `address`) is in the UTXO set.
    fn confirm<'a>(
        &'a self,
        txid: &'a str,
        output_idx: u32,
        address: &'a str,
        cfg: Option<ConfirmConfig>,
    ) -> BoxFuture<'a, bool>;
    /// Discover incoming transactions paying `address` — from the mempool
    /// (`getMempoolEntriesByAddresses` `receiving`), which carries each tx's
    /// full payload for fingerprint binding. Used by pull-mode discovery, so a
    /// payment's memo can be read before it is confirmed. Default: none.
    fn discover_incoming<'a>(&'a self, _address: &'a str) -> BoxFuture<'a, Result<Vec<DiscoveredTx>, String>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

impl ChainBackend for RpcClient {
    fn get_address_utxos<'a>(&'a self, address: &'a str) -> BoxFuture<'a, Result<Vec<RpcUtxo>, String>> {
        Box::pin(async move { self.get_utxos(address, None).await })
    }

    fn submit<'a>(&'a self, tx_json: serde_json::Value) -> BoxFuture<'a, Result<String, String>> {
        Box::pin(async move {
            let res = self.submit_transaction(tx_json).await?;
            if res.ok {
                res.tx_id.ok_or_else(|| "submit ok but no transactionId returned".to_string())
            } else {
                Err(res.error.unwrap_or_else(|| "submit failed".to_string()))
            }
        })
    }

    fn confirm<'a>(
        &'a self,
        txid: &'a str,
        output_idx: u32,
        address: &'a str,
        cfg: Option<ConfirmConfig>,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move { self.confirm_tx_output(txid, output_idx, address, cfg).await.confirmed })
    }

    fn discover_incoming<'a>(&'a self, address: &'a str) -> BoxFuture<'a, Result<Vec<DiscoveredTx>, String>> {
        Box::pin(async move {
            let resp = self
                .call(
                    "getMempoolEntriesByAddresses",
                    serde_json::json!({
                        "addresses": [address],
                        "includeOrphanPool": true,
                        "filterTransactionPool": false,
                    }),
                )
                .await?;
            let mut out = Vec::new();
            if let Some(entries) = resp.get("entries").and_then(|v| v.as_array()) {
                for entry in entries {
                    // `receiving`: txs that create outputs paying `address`.
                    if let Some(recv) = entry.get("receiving").and_then(|v| v.as_array()) {
                        for e in recv {
                            let Some(tx) = e.get("transaction") else { continue };
                            let txid = tx
                                .get("verboseData")
                                .and_then(|v| v.get("transactionId"))
                                .and_then(|v| v.as_str())
                                .or_else(|| tx.get("transactionId").and_then(|v| v.as_str()));
                            let Some(txid) = txid else { continue };
                            let outputs: Vec<ObservedOutput> = tx
                                .get("outputs")
                                .and_then(|v| v.as_array())
                                .map(|arr| arr.iter().filter_map(ObservedOutput::from_rpc_json).collect())
                                .unwrap_or_default();
                            let payload = tx
                                .get("payload")
                                .and_then(|v| v.as_str())
                                .and_then(|s| if s.is_empty() { Some(vec![]) } else { hex::decode(s).ok() })
                                .unwrap_or_default();
                            out.push(DiscoveredTx { txid: txid.to_string(), outputs, payload });
                        }
                    }
                }
            }
            Ok(out)
        })
    }
}

/// Facilitator configuration.
#[derive(Debug, Clone)]
pub struct FacilitatorConfig {
    /// Network this facilitator settles on (e.g. `kaspa:testnet-10`).
    pub network: String,
    /// Finality-confirmation polling parameters.
    pub confirm: ConfirmConfig,
}

/// The facilitator. Generic over the chain backend for testability.
pub struct Facilitator<B: ChainBackend> {
    backend: B,
    replay: Mutex<ReplayStore>,
    config: FacilitatorConfig,
}

/// Internal: a fully pure+on-chain-validated payment (either scheme), ready to
/// settle.
struct Validated {
    artifact_id: String,
    payer: String,
    pay_output_index: u32,
    input_outpoints: Vec<String>,
    tx: serde_json::Value,
    pay_to: String,
    /// Address that owns the payment output on-chain — what finality
    /// confirmation polls. For native this is `pay_to` (a P2PK output); for
    /// KCC20 it is the recipient's token_unit P2SH address (the P2PK identity
    /// in `pay_to` never receives the output directly).
    confirm_address: String,
    amount: u64,
}

impl<B: ChainBackend> Facilitator<B> {
    pub fn new(backend: B, replay: ReplayStore, config: FacilitatorConfig) -> Self {
        Facilitator { backend, replay: Mutex::new(replay), config }
    }

    /// The network this facilitator settles on.
    pub fn network(&self) -> &str {
        &self.config.network
    }

    /// Shared envelope/scheme/network validation + pure scheme verification +
    /// on-chain input-existence check. Does NOT touch the replay store.
    async fn validate(&self, req: &FacilitatorRequest) -> Result<Validated, String> {
        let pp = &req.payment_payload;
        let requirements = &req.payment_requirements;

        if pp.scheme != SCHEME_EXACT || requirements.scheme != SCHEME_EXACT {
            return Err(format!("unsupported scheme (only '{}')", SCHEME_EXACT));
        }
        if pp.network != self.config.network || requirements.network != self.config.network {
            return Err(format!(
                "network mismatch: facilitator settles '{}'",
                self.config.network
            ));
        }

        // Common payload fields.
        let from = pp
            .payload
            .get("from")
            .and_then(|v| v.as_str())
            .ok_or("payload missing 'from'")?
            .to_string();
        let payload_pay_to = pp
            .payload
            .get("payTo")
            .and_then(|v| v.as_str())
            .ok_or("payload missing 'payTo'")?;
        if payload_pay_to != requirements.pay_to {
            return Err("payload payTo does not match requirements payTo".to_string());
        }
        let transaction = pp
            .payload
            .get("transaction")
            .ok_or("payload missing 'transaction'")?
            .clone();

        // Route by asset: native-KAS (scheme A) vs KCC20 token_unit (scheme B).
        let is_native = requirements.asset.is_empty() || requirements.asset == ASSET_NATIVE_KAS;

        // `owner_addresses`: the address(es) whose unspent UTXO sets must cover
        // every spent input. `require_covenant`: for KCC20, at least one spent
        // input must be an on-chain UTXO carrying this token covenant id.
        let (validated, owner_addresses, require_covenant): (Validated, Vec<String>, Option<String>) =
            if is_native {
                let v = scheme_native::verify_native_exact(&transaction, &from, requirements)
                    .map_err(|r| r.to_string())?;
                let owners = vec![from.clone()];
                (
                    Validated {
                        artifact_id: v.artifact_id,
                        payer: v.payer,
                        pay_output_index: v.pay_output_index,
                        input_outpoints: v.input_outpoints,
                        tx: v.tx,
                        pay_to: requirements.pay_to.clone(),
                        // Native: the payment output is a P2PK output to pay_to.
                        confirm_address: requirements.pay_to.clone(),
                        amount: requirements.max_amount_sompi()?,
                    },
                    owners,
                    None,
                )
            } else {
                let v = scheme_kcc20::verify_kcc20_exact(&transaction, &from, requirements)
                    .map_err(|r| r.to_string())?;
                // Inputs may include the token covenant UTXO (at the payer's
                // token_unit P2SH address) AND a KAS fee UTXO (at the payer's
                // P2PK address) — union both.
                let owners = vec![v.payer_token_address.clone(), from.clone()];
                let asset = v.asset.clone();
                let confirm_address = v.recipient_token_address.clone();
                (
                    Validated {
                        artifact_id: v.artifact_id,
                        payer: v.payer,
                        pay_output_index: v.pay_output_index,
                        input_outpoints: v.input_outpoints,
                        tx: v.tx,
                        pay_to: requirements.pay_to.clone(),
                        // KCC20: the payment output lives at the recipient's
                        // token_unit P2SH address, not their P2PK identity.
                        confirm_address,
                        amount: requirements.max_amount_sompi()?,
                    },
                    owners,
                    Some(asset),
                )
            };

        // On-chain: every spent input must be an unspent UTXO owned by one of
        // `owner_addresses` (proves inputs are real, unspent, owned by the
        // declared payer). For KCC20, at least one such input must carry the
        // required token covenant id (proves the token being spent is genuine —
        // the generic on-chain-existence idea from kob-settle's CovenantCache,
        // applied directly per-settle here).
        let mut unspent: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut covenant_seen = require_covenant.is_none();
        for owner in &owner_addresses {
            let utxos = self
                .backend
                .get_address_utxos(owner)
                .await
                .map_err(|e| format!("could not fetch UTXOs for {}: {}", owner, e))?;
            for u in &utxos {
                let key = u.outpoint_key();
                if let Some(req_cov) = &require_covenant {
                    if u.utxo_entry.covenant_id.as_deref() == Some(req_cov.as_str())
                        && validated.input_outpoints.contains(&key)
                    {
                        covenant_seen = true;
                    }
                }
                unspent.insert(key);
            }
        }
        for op in &validated.input_outpoints {
            if !unspent.contains(op) {
                return Err(format!("input {} is not an unspent UTXO of the payer", op));
            }
        }
        if !covenant_seen {
            return Err(format!(
                "no spent input carries the required token covenant {}",
                require_covenant.unwrap_or_default()
            ));
        }

        Ok(validated)
    }

    /// `/verify`: validate without broadcasting.
    pub async fn verify(&self, req: &FacilitatorRequest) -> VerifyResponse {
        let validated = match self.validate(req).await {
            Ok(v) => v,
            Err(e) => return VerifyResponse::invalid(e),
        };

        // Replay: a *different* artifact re-spending a consumed outpoint is
        // invalid; the same artifact again is fine (idempotent).
        let store = self.replay.lock().await;
        match store.check_replay(&validated.artifact_id, &validated.input_outpoints) {
            ReplayCheck::OutpointReused { outpoint, existing_txid } => {
                return VerifyResponse::invalid(format!(
                    "input {} already consumed by payment {}",
                    outpoint, existing_txid
                ));
            }
            ReplayCheck::Fresh | ReplayCheck::DuplicateTxid(_) => {}
        }

        VerifyResponse::valid(validated.payer)
    }

    /// `/settle`: re-verify, broadcast, confirm finality, authorize.
    ///
    /// Idempotent: a retry of an already-settled artifact returns the
    /// previously-recorded on-chain txid instead of re-broadcasting.
    pub async fn settle(&self, req: &FacilitatorRequest) -> SettleResponse {
        let net = self.config.network.clone();
        let validated = match self.validate(req).await {
            Ok(v) => v,
            Err(e) => return SettleResponse::failed(net, e),
        };
        let Validated {
            artifact_id, payer, pay_output_index, input_outpoints, tx, pay_to, confirm_address, amount,
        } = validated;

        // Replay / idempotency decision under the store lock.
        {
            let mut store = self.replay.lock().await;
            match store.check_replay(&artifact_id, &input_outpoints) {
                ReplayCheck::OutpointReused { outpoint, existing_txid } => {
                    return SettleResponse::failed(
                        net,
                        format!("input {} already consumed by payment {}", outpoint, existing_txid),
                    );
                }
                ReplayCheck::DuplicateTxid(_) => {
                    // Same artifact seen before. If it already has an on-chain
                    // txid, re-confirm and return idempotently rather than
                    // re-broadcasting.
                    if let Some(rec) = store.get(&artifact_id) {
                        if let Some(chain_txid) = rec.chain_txid.clone() {
                            drop(store);
                            return self
                                .finalize(net, &artifact_id, &chain_txid, pay_output_index, &confirm_address, Some(payer))
                                .await;
                        }
                    }
                    // No on-chain txid recorded (prior attempt crashed before
                    // broadcast completed) — fall through and (re-)broadcast;
                    // the node dedupes by txid.
                }
                ReplayCheck::Fresh => {}
            }

            // Reserve: record Submitted (with outpoints) BEFORE broadcast so a
            // crash immediately after submit can't lose the replay guard.
            let record = PaymentRecord::submitted(artifact_id.clone(), input_outpoints.clone())
                .with_parties(Some(payer.clone()), Some(pay_to.clone()), amount);
            let record = match req.payment_requirements.fingerprint() {
                Some(fp) => record.with_fingerprint(fp),
                None => record,
            };
            if let Err(e) = store.record(record) {
                return SettleResponse::failed(net, format!("failed to persist payment record: {}", e));
            }
        }

        // Broadcast.
        let envelope = serde_json::json!({ "transaction": tx, "allowOrphan": false });
        let chain_txid = match self.backend.submit(envelope).await {
            Ok(txid) => txid,
            Err(e) => {
                let mut store = self.replay.lock().await;
                let _ = store.mark_failed(&artifact_id);
                return SettleResponse::failed(net, format!("broadcast failed: {}", e));
            }
        };

        // Persist the on-chain txid (idempotent retries reuse it).
        {
            let mut store = self.replay.lock().await;
            let base = store
                .get(&artifact_id)
                .cloned()
                .unwrap_or_else(|| PaymentRecord::submitted(artifact_id.clone(), input_outpoints.clone()));
            let _ = store.record(base.with_chain_txid(chain_txid.clone()));
        }

        self.finalize(net, &artifact_id, &chain_txid, pay_output_index, &confirm_address, Some(payer)).await
    }

    /// `/await` (PULL mode): the client broadcasts the payment ITSELF; the
    /// facilitator does NOT broadcast. It watches `payTo`, DISCOVERS the
    /// arriving payment by scanning (mempool for the payload/memo + the UTXO
    /// set for confirmed finality) — never by a known txid — binds the
    /// request fingerprint from the tx payload, and authorizes.
    ///
    /// - happy: a payment >= required with a matching fingerprint appears and
    ///   confirms -> authorized (returns the discovered on-chain txid).
    /// - underpayment: a fingerprint-matched payment < required is discovered
    ///   -> rejected.
    /// - timeout: nothing matching appears -> not authorized.
    /// - replay/double-credit: a payment already credited is not credited
    ///   again (deduped by its payTo-output outpoint in the replay store).
    pub async fn await_payment(&self, req: &AwaitRequest) -> SettleResponse {
        let net = self.config.network.clone();
        let requirements = &req.payment_requirements;

        if requirements.scheme != SCHEME_EXACT {
            return SettleResponse::failed(net, format!("unsupported scheme (only '{}')", SCHEME_EXACT));
        }
        if requirements.network != self.config.network {
            return SettleResponse::failed(net, format!("network mismatch: facilitator settles '{}'", self.config.network));
        }
        if !requirements.asset.is_empty() && requirements.asset != ASSET_NATIVE_KAS {
            return SettleResponse::failed(net, "pull mode currently supports native-KAS only".to_string());
        }
        let required = match requirements.max_amount_sompi() {
            Ok(r) => r,
            Err(e) => return SettleResponse::failed(net, e),
        };
        let pay_to = requirements.pay_to.clone();
        let expected_fp = requirements.fingerprint().map(|s| s.to_string());
        let timeout_secs = if requirements.max_timeout_seconds == 0 { 30 } else { requirements.max_timeout_seconds };

        let mut observer = PaymentObserver::new();
        if let Err(e) = observer.watch(&pay_to) {
            return SettleResponse::failed(net, format!("bad payTo address: {}", e));
        }

        let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
        // txid -> tx payload, cached from the mempool so the fingerprint memo is
        // available even after the tx leaves the mempool (confirmed).
        let mut payloads: HashMap<String, Vec<u8>> = HashMap::new();
        let mut saw_already_credited = false;

        loop {
            // (1) Cache incoming-tx payloads from the mempool (carries the memo).
            if let Ok(dtxs) = self.backend.discover_incoming(&pay_to).await {
                for d in dtxs {
                    payloads.entry(d.txid).or_insert(d.payload);
                }
            }

            // (2) Scan payTo's UTXO set (confirmed => final) to DISCOVER an
            //     arriving payment — by address, not by a known txid.
            let utxos = self.backend.get_address_utxos(&pay_to).await.unwrap_or_default();
            let events = observer.scan_utxos(&utxos);
            for ev in &events {
                let outpoint = format!("{}:{}", ev.txid, ev.output_index);

                // Already credited? Never re-credit. It only counts as "OUR
                // request's payment, already credited" (vs. an unrelated prior
                // payment sitting at this merchant address) when it was
                // credited for THIS request's fingerprint — so a fresh request
                // for a NEW payment is not fooled into "already credited" by
                // some other credited UTXO at the same address.
                {
                    let store = self.replay.lock().await;
                    if let Some(rec) = store.get(&ev.txid) {
                        if rec.fingerprint == expected_fp {
                            saw_already_credited = true;
                        }
                        continue;
                    }
                }

                // Fingerprint binding: read the memo from the mempool-cached
                // payload. If the request carries a fingerprint, only a payment
                // whose payload carries the matching memo is "this" payment.
                if let Some(exp) = &expected_fp {
                    match payloads.get(&ev.txid).and_then(|p| fingerprint::extract_fingerprint(p)) {
                        Some(got) if &got == exp => {}
                        _ => continue, // not our payment yet (or payload not seen) — keep watching
                    }
                }

                // Amount check. (Only reached for our request's payment.)
                if ev.value < required {
                    return SettleResponse::failed(net, format!(
                        "underpayment discovered at {}: paid {} < required {} (txid {})",
                        pay_to, ev.value, required, ev.txid
                    ));
                }

                // Discovered + confirmed (present in the UTXO set) +
                // fingerprint-bound => authorize and record for dedupe.
                let mut record = PaymentRecord::submitted(ev.txid.clone(), vec![outpoint.clone()])
                    .with_chain_txid(ev.txid.clone())
                    .with_parties(None, Some(pay_to.clone()), ev.value);
                if let Some(fp) = &expected_fp {
                    record = record.with_fingerprint(fp.clone());
                }
                {
                    let mut store = self.replay.lock().await;
                    let _ = store.record(record);
                    let _ = store.mark_confirmed(&ev.txid);
                }
                return SettleResponse::ok(net, ev.txid.clone(), None);
            }

            if std::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(700)).await;
        }

        if saw_already_credited {
            SettleResponse::failed(net, "matching payment already credited (not double-crediting)".to_string())
        } else {
            SettleResponse::failed(net, format!("no matching payment discovered at {} within {}s", pay_to, timeout_secs))
        }
    }

    /// Confirm finality for a broadcast payment and record the outcome.
    async fn finalize(
        &self,
        net: String,
        artifact_id: &str,
        chain_txid: &str,
        pay_output_index: u32,
        confirm_address: &str,
        payer: Option<String>,
    ) -> SettleResponse {
        let confirmed = self
            .backend
            .confirm(chain_txid, pay_output_index, confirm_address, Some(self.config.confirm.clone()))
            .await;

        let mut store = self.replay.lock().await;
        if confirmed {
            let _ = store.mark_confirmed(artifact_id);
            SettleResponse::ok(net, chain_txid.to_string(), payer)
        } else {
            // Broadcast accepted but not yet observed on-chain. Leave the
            // record as Submitted (with its chain_txid) so an idempotent
            // retry can re-confirm and flip to success.
            SettleResponse::failed(
                net,
                format!("broadcast accepted ({}) but not confirmed within timeout", chain_txid),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    use kob_settle::rpc::{RpcOutpoint, RpcUtxo};
    use kob_settle::rpc_types::{RpcSpk, RpcUtxoEntry};

    // `fingerprint` comes from `super::*` (the parent module imports it).
    use crate::wire::{
        NativeExactPayload, PaymentPayload, PaymentRequirements, NETWORK_TESTNET10, X402_VERSION,
    };

    fn addr(seed: u8) -> String {
        kob_settle::wallet::pubkey_to_address(&[seed; 32], kob_settle::types::Network::Testnet)
    }
    fn spk_hex(a: &str) -> String {
        hex::encode(kob_settle::bech32::address_to_spk(a).unwrap())
    }

    /// A mock chain: fixed UTXO sets per address, records submissions, and a
    /// configurable confirm outcome.
    struct MockChain {
        utxos: HashMap<String, Vec<RpcUtxo>>,
        submitted: StdMutex<Vec<serde_json::Value>>,
        confirm_ok: bool,
        next_txid: StdMutex<u64>,
        incoming: Vec<DiscoveredTx>,
    }

    impl MockChain {
        fn new(confirm_ok: bool) -> Self {
            MockChain {
                utxos: HashMap::new(),
                submitted: StdMutex::new(Vec::new()),
                confirm_ok,
                next_txid: StdMutex::new(1),
                incoming: Vec::new(),
            }
        }
        /// Seed a discovered incoming payment (mempool) + its confirmed UTXO at
        /// `address`, with `payload` carrying the memo. Models a client-broadcast
        /// pull payment that the facilitator must discover.
        fn with_incoming(mut self, address: &str, txid: &str, out_idx: u32, amount: u64, payload: Vec<u8>) -> Self {
            self.incoming.push(DiscoveredTx {
                txid: txid.to_string(),
                outputs: vec![ObservedOutput {
                    value: amount,
                    spk_version: 0,
                    spk_script: kob_settle::bech32::address_to_spk(address).unwrap(),
                    covenant_id: None,
                }],
                payload,
            });
            self.with_utxo(address, txid, out_idx, amount)
        }
        fn with_utxo(mut self, address: &str, txid: &str, index: u32, amount: u64) -> Self {
            let u = RpcUtxo {
                outpoint: RpcOutpoint { transaction_id: txid.to_string(), index },
                utxo_entry: RpcUtxoEntry {
                    amount,
                    script_public_key: RpcSpk { version: 0, script: spk_hex(address) },
                    block_daa_score: 0,
                    is_coinbase: false,
                    covenant_id: None,
                },
            };
            self.utxos.entry(address.to_string()).or_default().push(u);
            self
        }
        /// Seed a covenant-bound UTXO (the SPK is stored raw so it need not be a
        /// P2PK of `address` — for KCC20 it's a token_unit P2SH).
        fn with_covenant_utxo(
            mut self,
            address: &str,
            spk_script_hex: &str,
            txid: &str,
            index: u32,
            amount: u64,
            covenant_id: &str,
        ) -> Self {
            let u = RpcUtxo {
                outpoint: RpcOutpoint { transaction_id: txid.to_string(), index },
                utxo_entry: RpcUtxoEntry {
                    amount,
                    script_public_key: RpcSpk { version: 0, script: spk_script_hex.to_string() },
                    block_daa_score: 0,
                    is_coinbase: false,
                    covenant_id: Some(covenant_id.to_string()),
                },
            };
            self.utxos.entry(address.to_string()).or_default().push(u);
            self
        }
        fn submit_count(&self) -> usize {
            self.submitted.lock().unwrap().len()
        }
    }

    impl ChainBackend for MockChain {
        fn get_address_utxos<'a>(&'a self, address: &'a str) -> BoxFuture<'a, Result<Vec<RpcUtxo>, String>> {
            let v = self.utxos.get(address).cloned().unwrap_or_default();
            Box::pin(async move { Ok(v) })
        }
        fn submit<'a>(&'a self, tx_json: serde_json::Value) -> BoxFuture<'a, Result<String, String>> {
            let mut n = self.next_txid.lock().unwrap();
            let txid = format!("{:064x}", *n);
            *n += 1;
            self.submitted.lock().unwrap().push(tx_json);
            Box::pin(async move { Ok(txid) })
        }
        fn confirm<'a>(
            &'a self,
            _txid: &'a str,
            _idx: u32,
            _addr: &'a str,
            _cfg: Option<ConfirmConfig>,
        ) -> BoxFuture<'a, bool> {
            let ok = self.confirm_ok;
            Box::pin(async move { ok })
        }
        fn discover_incoming<'a>(&'a self, address: &'a str) -> BoxFuture<'a, Result<Vec<DiscoveredTx>, String>> {
            // Return incoming txs that pay `address` (match by output SPK).
            let want = kob_settle::bech32::address_to_spk(address).ok();
            let v: Vec<DiscoveredTx> = self
                .incoming
                .iter()
                .filter(|d| want.as_ref().is_some_and(|w| d.outputs.iter().any(|o| &o.spk_script == w)))
                .cloned()
                .collect();
            Box::pin(async move { Ok(v) })
        }
    }

    fn tmp_store(tag: &str) -> ReplayStore {
        let mut p = std::env::temp_dir();
        p.push(format!("kob_x402_fac_{}_{}.jsonl", tag, std::process::id()));
        let _ = std::fs::remove_file(&p);
        ReplayStore::open(&p).unwrap()
    }

    fn config() -> FacilitatorConfig {
        FacilitatorConfig {
            network: NETWORK_TESTNET10.to_string(),
            confirm: ConfirmConfig {
                initial_delay: std::time::Duration::from_millis(0),
                max_polls: 1,
                poll_interval: std::time::Duration::from_millis(0),
            },
        }
    }

    fn requirements(pay_to: &str, amount: u64, fp: Option<&str>) -> PaymentRequirements {
        PaymentRequirements {
            scheme: SCHEME_EXACT.to_string(),
            network: NETWORK_TESTNET10.to_string(),
            max_amount_required: amount.to_string(),
            resource: "https://ex/r".to_string(),
            description: String::new(),
            mime_type: String::new(),
            pay_to: pay_to.to_string(),
            max_timeout_seconds: 60,
            asset: ASSET_NATIVE_KAS.to_string(),
            extra: match fp {
                Some(f) => serde_json::json!({ "fingerprint": f }),
                None => serde_json::Value::Null,
            },
        }
    }

    /// Build a request spending `in_txid:in_index` (owned by `from`) paying
    /// `amount` to `pay_to`.
    fn request(
        from: &str,
        pay_to: &str,
        amount: u64,
        in_txid: &str,
        in_index: u32,
        fp: Option<&str>,
        req_amount: u64,
    ) -> FacilitatorRequest {
        let payload_hex = match fp {
            Some(f) => hex::encode(fingerprint::embed_fingerprint(f)),
            None => String::new(),
        };
        let tx = serde_json::json!({
            "version": 0,
            "inputs": [{
                "previousOutpoint": { "transactionId": in_txid, "index": in_index },
                "signatureScript": "41".to_string() + &"cd".repeat(65),
                "sequence": 0,
                "sigOpCount": 1
            }],
            "outputs": [
                { "value": amount, "scriptPublicKey": { "version": 0, "script": spk_hex(pay_to) } },
                { "value": 1_000_000u64, "scriptPublicKey": { "version": 0, "script": spk_hex(from) } }
            ],
            "lockTime": 0,
            "subnetworkId": "0000000000000000000000000000000000000000",
            "payload": payload_hex,
        });
        FacilitatorRequest {
            x402_version: X402_VERSION,
            payment_payload: PaymentPayload {
                x402_version: X402_VERSION,
                scheme: SCHEME_EXACT.to_string(),
                network: NETWORK_TESTNET10.to_string(),
                payload: serde_json::to_value(NativeExactPayload {
                    transaction: tx,
                    from: from.to_string(),
                    pay_to: pay_to.to_string(),
                    amount: amount.to_string(),
                })
                .unwrap(),
            },
            payment_requirements: requirements(pay_to, req_amount, fp),
        }
    }

    #[tokio::test]
    async fn verify_and_settle_happy_path() {
        let from = addr(1);
        let pay_to = addr(2);
        let in_txid = "aa".repeat(32);
        let chain = MockChain::new(true).with_utxo(&from, &in_txid, 0, 200_000_000);
        let fac = Facilitator::new(chain, tmp_store("happy"), config());
        let req = request(&from, &pay_to, 100_000_000, &in_txid, 0, None, 100_000_000);

        let v = fac.verify(&req).await;
        assert!(v.is_valid, "verify: {:?}", v.invalid_reason);
        assert_eq!(v.payer.as_deref(), Some(from.as_str()));

        let s = fac.settle(&req).await;
        assert!(s.success, "settle: {:?}", s.error_reason);
        assert!(s.transaction.is_some());
        assert_eq!(fac.backend.submit_count(), 1);
    }

    #[tokio::test]
    async fn rejects_underpayment_and_does_not_broadcast() {
        let from = addr(1);
        let pay_to = addr(2);
        let in_txid = "bb".repeat(32);
        let chain = MockChain::new(true).with_utxo(&from, &in_txid, 0, 200_000_000);
        let fac = Facilitator::new(chain, tmp_store("under"), config());
        // pays 99_999_999 but requires 100_000_000
        let req = request(&from, &pay_to, 99_999_999, &in_txid, 0, None, 100_000_000);

        let v = fac.verify(&req).await;
        assert!(!v.is_valid);
        let s = fac.settle(&req).await;
        assert!(!s.success);
        assert_eq!(fac.backend.submit_count(), 0, "must not broadcast an underpayment");
    }

    #[tokio::test]
    async fn rejects_wrong_recipient() {
        let from = addr(1);
        let pay_to = addr(2);
        let wrong = addr(9);
        let in_txid = "cc".repeat(32);
        let chain = MockChain::new(true).with_utxo(&from, &in_txid, 0, 200_000_000);
        let fac = Facilitator::new(chain, tmp_store("wrong"), config());
        // Pays `wrong`, requirements demand `pay_to`.
        let mut req = request(&from, &wrong, 100_000_000, &in_txid, 0, None, 100_000_000);
        req.payment_requirements = requirements(&pay_to, 100_000_000, None);
        // Keep payload.payTo consistent with requirements so we exercise the
        // recipient-in-tx check, not the payTo-consistency check.
        req.payment_payload.payload["payTo"] = serde_json::json!(pay_to);

        let v = fac.verify(&req).await;
        assert!(!v.is_valid);
        let s = fac.settle(&req).await;
        assert!(!s.success);
        assert_eq!(fac.backend.submit_count(), 0);
    }

    #[tokio::test]
    async fn rejects_input_not_owned_or_spent() {
        let from = addr(1);
        let pay_to = addr(2);
        let in_txid = "dd".repeat(32);
        // MockChain has NO utxo for `from` -> input existence check fails.
        let chain = MockChain::new(true);
        let fac = Facilitator::new(chain, tmp_store("noinput"), config());
        let req = request(&from, &pay_to, 100_000_000, &in_txid, 0, None, 100_000_000);

        let v = fac.verify(&req).await;
        assert!(!v.is_valid);
        assert!(v.invalid_reason.unwrap().contains("unspent UTXO"));
        assert_eq!(fac.backend.submit_count(), 0);
    }

    #[tokio::test]
    async fn idempotent_settle_does_not_double_broadcast() {
        let from = addr(1);
        let pay_to = addr(2);
        let in_txid = "ee".repeat(32);
        let chain = MockChain::new(true).with_utxo(&from, &in_txid, 0, 200_000_000);
        let fac = Facilitator::new(chain, tmp_store("idem"), config());
        let req = request(&from, &pay_to, 100_000_000, &in_txid, 0, None, 100_000_000);

        let s1 = fac.settle(&req).await;
        assert!(s1.success);
        let s2 = fac.settle(&req).await; // same artifact again
        assert!(s2.success);
        assert_eq!(s1.transaction, s2.transaction, "idempotent: same on-chain txid");
        assert_eq!(fac.backend.submit_count(), 1, "must broadcast only once");
    }

    #[tokio::test]
    async fn rejects_replay_of_consumed_outpoint_by_different_artifact() {
        let from = addr(1);
        let pay_to = addr(2);
        let in_txid = "ff".repeat(32);
        // Same input available; two DIFFERENT payments both try to spend it.
        let chain = MockChain::new(true).with_utxo(&from, &in_txid, 0, 300_000_000);
        let fac = Facilitator::new(chain, tmp_store("replay"), config());

        let req1 = request(&from, &pay_to, 100_000_000, &in_txid, 0, None, 100_000_000);
        let s1 = fac.settle(&req1).await;
        assert!(s1.success);

        // A different artifact (different amount => different tx => different
        // artifact_id) reusing the same input outpoint.
        let req2 = request(&from, &pay_to, 120_000_000, &in_txid, 0, None, 100_000_000);
        let v2 = fac.verify(&req2).await;
        assert!(!v2.is_valid, "replayed outpoint must be rejected at verify");
        let s2 = fac.settle(&req2).await;
        assert!(!s2.success);
        assert_eq!(fac.backend.submit_count(), 1, "replay must not broadcast");
    }

    #[tokio::test]
    async fn broadcast_accepted_but_unconfirmed_is_recoverable() {
        let from = addr(1);
        let pay_to = addr(2);
        let in_txid = "12".repeat(32);
        // First facilitator: confirm fails -> settle returns not-confirmed but
        // the tx is broadcast and recorded with its chain txid.
        let chain = MockChain::new(false).with_utxo(&from, &in_txid, 0, 200_000_000);
        let store = tmp_store("recover");
        let path = store.path().to_path_buf();
        let fac = Facilitator::new(chain, store, config());
        let req = request(&from, &pay_to, 100_000_000, &in_txid, 0, None, 100_000_000);
        let s1 = fac.settle(&req).await;
        assert!(!s1.success);
        assert_eq!(fac.backend.submit_count(), 1);

        // Recovery: a new facilitator (confirm now succeeds) reloads the store
        // and an idempotent retry flips it to success WITHOUT re-broadcasting.
        let chain2 = MockChain::new(true).with_utxo(&from, &in_txid, 0, 200_000_000);
        let store2 = ReplayStore::open(&path).unwrap();
        let fac2 = Facilitator::new(chain2, store2, config());
        let s2 = fac2.settle(&req).await;
        assert!(s2.success, "retry should confirm: {:?}", s2.error_reason);
        assert!(s2.transaction.is_some());
        assert_eq!(fac2.backend.submit_count(), 0, "recovery must not re-broadcast");
        std::fs::remove_file(&path).ok();
    }

    // --- scheme (B): KCC20 token payment, end to end through the facilitator ---

    fn token_addr_and_spk(pubkey: &[u8; 32]) -> (String, String) {
        let rs = kob_core::build_token_unit_redeem_script(pubkey);
        let spk = kob_settle::build_p2sh(&rs);
        let spk_bytes = spk.script().to_vec();
        let addr = kob_settle::bech32::spk_to_address(&spk_bytes, "kaspatest").unwrap();
        (addr, hex::encode(&spk_bytes))
    }

    /// Build a KCC20 token payment request: spends the payer's token_unit UTXO
    /// (`in_txid:0`) and creates a recipient token_unit output of `amount`
    /// bound to `asset`.
    fn kcc20_request(
        payer_pk: &[u8; 32],
        recipient_pk: &[u8; 32],
        asset: &str,
        amount: u64,
        in_txid: &str,
        req_amount: u64,
    ) -> (FacilitatorRequest, String) {
        let payer_addr = kob_settle::wallet::pubkey_to_address(payer_pk, kob_settle::types::Network::Testnet);
        let recipient_addr =
            kob_settle::wallet::pubkey_to_address(recipient_pk, kob_settle::types::Network::Testnet);
        let (_recip_token_addr, recip_token_spk) = token_addr_and_spk(recipient_pk);

        let tx = serde_json::json!({
            "version": 1,
            "inputs": [{
                "previousOutpoint": { "transactionId": in_txid, "index": 0 },
                "signatureScript": "cd".repeat(70),
                "sequence": 0,
                "sigOpCount": 1
            }],
            "outputs": [{
                "value": amount,
                "scriptPublicKey": { "version": 0, "script": recip_token_spk },
                "covenant": { "authorizingInput": 0, "covenantId": asset }
            }],
            "lockTime": 0,
            "subnetworkId": "0000000000000000000000000000000000000000",
            "payload": "",
        });
        let req = FacilitatorRequest {
            x402_version: X402_VERSION,
            payment_payload: PaymentPayload {
                x402_version: X402_VERSION,
                scheme: SCHEME_EXACT.to_string(),
                network: NETWORK_TESTNET10.to_string(),
                payload: serde_json::json!({
                    "transaction": tx,
                    "from": payer_addr,
                    "payTo": recipient_addr,
                    "asset": asset,
                    "amount": amount.to_string(),
                }),
            },
            payment_requirements: PaymentRequirements {
                scheme: SCHEME_EXACT.to_string(),
                network: NETWORK_TESTNET10.to_string(),
                max_amount_required: req_amount.to_string(),
                resource: "https://ex/token".to_string(),
                description: String::new(),
                mime_type: String::new(),
                pay_to: recipient_addr,
                max_timeout_seconds: 60,
                asset: asset.to_string(),
                extra: serde_json::Value::Null,
            },
        };
        (req, payer_addr)
    }

    #[tokio::test]
    async fn kcc20_verify_and_settle_happy_path() {
        let payer_pk = [1u8; 32];
        let recipient_pk = [2u8; 32];
        let asset = "ab".repeat(32);
        let in_txid = "a7".repeat(32);
        let (payer_token_addr, payer_token_spk) = token_addr_and_spk(&payer_pk);

        // The payer owns a token_unit covenant UTXO for `asset` at their token
        // P2SH address, holding 100 token units.
        let chain = MockChain::new(true).with_covenant_utxo(
            &payer_token_addr,
            &payer_token_spk,
            &in_txid,
            0,
            100_000_000,
            &asset,
        );
        let fac = Facilitator::new(chain, tmp_store("kcc20_happy"), config());
        let (req, _payer) = kcc20_request(&payer_pk, &recipient_pk, &asset, 50_000_000, &in_txid, 50_000_000);

        let v = fac.verify(&req).await;
        assert!(v.is_valid, "kcc20 verify: {:?}", v.invalid_reason);

        let s = fac.settle(&req).await;
        assert!(s.success, "kcc20 settle: {:?}", s.error_reason);
        assert!(s.transaction.is_some());
        assert_eq!(fac.backend.submit_count(), 1);
    }

    #[tokio::test]
    async fn kcc20_rejects_when_token_input_covenant_absent() {
        let payer_pk = [1u8; 32];
        let recipient_pk = [2u8; 32];
        let asset = "ab".repeat(32);
        let in_txid = "a8".repeat(32);
        let (payer_token_addr, payer_token_spk) = token_addr_and_spk(&payer_pk);

        // The spent input exists but carries a DIFFERENT covenant id.
        let chain = MockChain::new(true).with_covenant_utxo(
            &payer_token_addr,
            &payer_token_spk,
            &in_txid,
            0,
            100_000_000,
            &"cd".repeat(32),
        );
        let fac = Facilitator::new(chain, tmp_store("kcc20_nocov"), config());
        let (req, _payer) = kcc20_request(&payer_pk, &recipient_pk, &asset, 50_000_000, &in_txid, 50_000_000);

        let v = fac.verify(&req).await;
        assert!(!v.is_valid, "must reject: token input covenant does not match asset");
        let s = fac.settle(&req).await;
        assert!(!s.success);
        assert_eq!(fac.backend.submit_count(), 0);
    }

    #[tokio::test]
    async fn kcc20_rejects_underpayment() {
        let payer_pk = [1u8; 32];
        let recipient_pk = [2u8; 32];
        let asset = "ab".repeat(32);
        let in_txid = "a9".repeat(32);
        let (payer_token_addr, payer_token_spk) = token_addr_and_spk(&payer_pk);
        let chain = MockChain::new(true).with_covenant_utxo(
            &payer_token_addr,
            &payer_token_spk,
            &in_txid,
            0,
            100_000_000,
            &asset,
        );
        let fac = Facilitator::new(chain, tmp_store("kcc20_under"), config());
        // Pays 49_999_999 token units but requires 50_000_000.
        let (req, _payer) = kcc20_request(&payer_pk, &recipient_pk, &asset, 49_999_999, &in_txid, 50_000_000);

        let v = fac.verify(&req).await;
        assert!(!v.is_valid);
        assert_eq!(fac.backend.submit_count(), 0);
    }

    // --- PULL mode (/await): client broadcasts, facilitator DISCOVERS ---

    fn await_req(pay_to: &str, required: u64, fp: Option<&str>, timeout: u64) -> AwaitRequest {
        AwaitRequest {
            x402_version: X402_VERSION,
            payment_requirements: PaymentRequirements {
                scheme: SCHEME_EXACT.to_string(),
                network: NETWORK_TESTNET10.to_string(),
                max_amount_required: required.to_string(),
                resource: "https://ex/pull".to_string(),
                description: String::new(),
                mime_type: String::new(),
                pay_to: pay_to.to_string(),
                max_timeout_seconds: timeout,
                asset: crate::wire::ASSET_NATIVE_KAS.to_string(),
                extra: match fp {
                    Some(f) => serde_json::json!({ "fingerprint": f }),
                    None => serde_json::Value::Null,
                },
            },
        }
    }

    #[tokio::test]
    async fn await_discovers_payment_and_authorizes() {
        let merchant = addr(5);
        let fp = fingerprint::compute_fingerprint("GET", "/r", &merchant, "40000000", "n");
        let pay_txid = "5a".repeat(32);
        // A confirmed payment paying the merchant 40M, with the fingerprint memo.
        let chain = MockChain::new(true).with_incoming(
            &merchant, &pay_txid, 0, 40_000_000, fingerprint::embed_fingerprint(&fp),
        );
        let fac = Facilitator::new(chain, tmp_store("pull_happy"), config());
        let s = fac.await_payment(&await_req(&merchant, 40_000_000, Some(&fp), 5)).await;
        assert!(s.success, "await should authorize: {:?}", s.error_reason);
        assert_eq!(s.transaction.as_deref(), Some(pay_txid.as_str()), "returns the discovered txid");
        // The facilitator never broadcast anything (pull mode).
        assert_eq!(fac.backend.submit_count(), 0);
    }

    #[tokio::test]
    async fn await_rejects_underpayment() {
        let merchant = addr(5);
        let fp = fingerprint::compute_fingerprint("GET", "/r", &merchant, "40000000", "n");
        let pay_txid = "5b".repeat(32);
        // Discovered payment carries the right memo but pays too little.
        let chain = MockChain::new(true).with_incoming(
            &merchant, &pay_txid, 0, 20_000_000, fingerprint::embed_fingerprint(&fp),
        );
        let fac = Facilitator::new(chain, tmp_store("pull_under"), config());
        let s = fac.await_payment(&await_req(&merchant, 40_000_000, Some(&fp), 5)).await;
        assert!(!s.success);
        assert!(s.error_reason.unwrap().contains("underpayment"));
    }

    #[tokio::test]
    async fn await_times_out_with_no_payment() {
        let merchant = addr(5);
        let fp = fingerprint::compute_fingerprint("GET", "/r", &merchant, "40000000", "n");
        // No incoming payment at all.
        let chain = MockChain::new(true);
        let fac = Facilitator::new(chain, tmp_store("pull_timeout"), config());
        let s = fac.await_payment(&await_req(&merchant, 40_000_000, Some(&fp), 1)).await;
        assert!(!s.success);
        assert!(s.error_reason.unwrap().contains("no matching payment"));
    }

    #[tokio::test]
    async fn await_does_not_double_credit() {
        let merchant = addr(5);
        let fp = fingerprint::compute_fingerprint("GET", "/r", &merchant, "40000000", "n");
        let pay_txid = "5c".repeat(32);
        let chain = MockChain::new(true).with_incoming(
            &merchant, &pay_txid, 0, 40_000_000, fingerprint::embed_fingerprint(&fp),
        );
        let fac = Facilitator::new(chain, tmp_store("pull_replay"), config());
        // First: credited.
        let s1 = fac.await_payment(&await_req(&merchant, 40_000_000, Some(&fp), 5)).await;
        assert!(s1.success);
        // Second: same payment still in the UTXO set, already credited -> refused.
        let s2 = fac.await_payment(&await_req(&merchant, 40_000_000, Some(&fp), 1)).await;
        assert!(!s2.success);
        assert!(s2.error_reason.unwrap().contains("already credited"));
    }
}
