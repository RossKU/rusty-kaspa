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

use crate::reservation::ReservationProvider;
use crate::scheme_exact;
use crate::scheme_kcc20;
use crate::scheme_native;
use crate::fingerprint;
use crate::wire_v2::{
    errors, AwaitRequest, FacilitatorRequest, KaspaSettleExt, PaymentRequired, PaymentRequirements,
    Resource, SettlementResponse, VerifyResponse, ASSET_KAS, BINDING_EXACT, BINDING_KCC20,
    BINDING_NATIVE, NETWORK_TESTNET10, SCHEME_EXACT, X402_VERSION,
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
    reservations: Mutex<ReservationProvider>,
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
    /// Request-binding fingerprint: `extra.fingerprint` for native/KCC20, the
    /// bound `requestHash` for exact/KIP-10. MANDATORY across all schemes —
    /// every payment must be scoped to exactly one request, otherwise a
    /// settled artifact could be presented again as authorization for a
    /// DIFFERENT resource/request. Re-checked against the stored
    /// `PaymentRecord` on a `DuplicateTxid` replay-store hit (see
    /// `duplicate_binding_matches`).
    binding_fingerprint: String,
}

// Wire-error mapping is aligned across schemes for the same logical failure:
//   payment doesn't satisfy the offer  -> invalid_payment_requirements
//   request binding missing/mismatched -> invalid_payload  (identifier payload)
//   spent/stale on-chain outpoint       -> invalid_transaction_state
//   otherwise malformed                 -> invalid_payload
// Arms are exhaustive (no wildcard) so a new reject variant can't be silently
// miscategorised.

/// Map a native-scheme reject to a closed wire error code.
fn native_reject_code(r: scheme_native::NativeReject) -> &'static str {
    use scheme_native::NativeReject::*;
    match r {
        WrongRecipient | Underpayment { .. } => errors::INVALID_PAYMENT_REQUIREMENTS,
        FingerprintMissing | FingerprintMismatch { .. } => errors::INVALID_PAYLOAD,
        Malformed(_) | CovenantNotAllowed | NoInputs => errors::INVALID_PAYLOAD,
    }
}

/// Map a KCC20-scheme reject to a closed wire error code.
fn kcc20_reject_code(r: scheme_kcc20::Kcc20Reject) -> &'static str {
    use scheme_kcc20::Kcc20Reject::*;
    match r {
        WrongRecipient | Underpayment { .. } => errors::INVALID_PAYMENT_REQUIREMENTS,
        FingerprintMissing | FingerprintMismatch { .. } => errors::INVALID_PAYLOAD,
        Malformed(_) | BadAsset(_) | BadRecipient(_) | BadPayer(_) | MissingCovenantBinding
        | NoInputs => errors::INVALID_PAYLOAD,
    }
}

fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Map a KIP-10 exact reject to a closed wire error code.
fn exact_reject_code(r: scheme_exact::ExactReject) -> &'static str {
    use scheme_exact::ExactReject::*;
    match r {
        WrongRecipient | Underpayment | UnderThreshold | WrongPaymentOutputIndex => {
            errors::INVALID_PAYMENT_REQUIREMENTS
        }
        // Aligned with native/kcc20: a bad request binding is a payload issue.
        FingerprintMismatch => errors::INVALID_PAYLOAD,
        // Spending a wrong/stale outpoint is an on-chain state conflict.
        WrongBorrowOutpoint => errors::INVALID_TRANSACTION_STATE,
        Malformed | BadEncoding | NoInputs => errors::INVALID_PAYLOAD,
    }
}

/// Whether a `DuplicateTxid` hit at `artifact_id` is a legitimate idempotent
/// retry of the SAME request (its stored binding fingerprint matches this
/// one) rather than a different request presenting an already-settled
/// artifact as its own authorization. `check_replay` proves the ARTIFACT is
/// self-consistent (same signed bytes); this additionally proves THIS
/// request is the one that artifact was actually settled for.
fn duplicate_binding_matches(store: &ReplayStore, artifact_id: &str, binding_fingerprint: &str) -> bool {
    match store.get(artifact_id) {
        Some(rec) => rec.fingerprint.as_deref() == Some(binding_fingerprint),
        None => true, // unreachable in practice: DuplicateTxid implies a record exists
    }
}

impl<B: ChainBackend> Facilitator<B> {
    pub fn new(backend: B, replay: ReplayStore, config: FacilitatorConfig) -> Self {
        Facilitator {
            backend,
            replay: Mutex::new(replay),
            config,
            reservations: Mutex::new(ReservationProvider::new()),
        }
    }

    /// Reserve a KIP-10 additive borrow outpoint and return the v2
    /// PaymentRequired the merchant serves in its 402. The merchant must have
    /// already funded `borrow_txid:borrow_index` (holding `borrow_amount`) to
    /// the covenant P2SH given by `ReservationProvider::borrow_covenant`.
    #[allow(clippy::too_many_arguments)]
    pub async fn reserve(
        &self,
        pay_to: &str,
        amount: u64,
        borrow_txid: &str,
        borrow_index: u32,
        borrow_amount: u64,
        additive_threshold: u64,
        payment_output_index: u32,
        resource_url: &str,
        request_hash: Option<String>,
    ) -> Result<PaymentRequired, String> {
        let seed = format!("{}:{}:{}", borrow_txid, borrow_index, now_nanos());
        let reservation_id = hex::encode(kob_settle::blake2b_256(seed.as_bytes()));
        let terms = {
            let mut store = self.reservations.lock().await;
            store.reserve(
                reservation_id, pay_to, amount, borrow_txid, borrow_index, borrow_amount,
                additive_threshold, payment_output_index, request_hash,
            )?
        };
        Ok(PaymentRequired {
            x402_version: X402_VERSION,
            resource: Resource { url: resource_url.to_string(), description: None, mime_type: None },
            accepts: vec![PaymentRequirements {
                scheme: SCHEME_EXACT.to_string(),
                network: self.config.network.clone(),
                amount: amount.to_string(),
                asset: ASSET_KAS.to_string(),
                pay_to: pay_to.to_string(),
                max_timeout_seconds: 60,
                extra: terms.requirements_extra(),
            }],
            error: None,
            extensions: None,
        })
    }

    /// The network this facilitator settles on.
    pub fn network(&self) -> &str {
        &self.config.network
    }

    /// Shared envelope/scheme/network validation + pure scheme verification +
    /// on-chain input-existence check. Does NOT touch the replay store.
    async fn validate(&self, req: &FacilitatorRequest) -> Result<Validated, &'static str> {
        let pp = &req.payment_payload;
        let requirements = &req.payment_requirements;

        if req.x402_version != X402_VERSION || pp.x402_version != X402_VERSION {
            return Err(errors::INVALID_X402_VERSION);
        }
        if requirements.scheme != SCHEME_EXACT {
            return Err(errors::INVALID_SCHEME);
        }
        if requirements.network != self.config.network {
            return Err(errors::INVALID_NETWORK);
        }

        // Common payload fields (v2 envelope: payerAddress + transaction).
        let from = pp.payer_address().ok_or(errors::INVALID_PAYLOAD)?.to_string();
        let transaction = pp.transaction().ok_or(errors::INVALID_PAYLOAD)?.clone();

        // Route by extra.binding under the v2 envelope.
        let binding = requirements.binding().unwrap_or_default();
        let is_native = binding == BINDING_NATIVE;

        // KIP-10 additive exact (strict interop) — handled here (string-encoded
        // transaction + reservation lookup).
        if binding == BINDING_EXACT {
            let enc = transaction.as_str().ok_or(errors::INVALID_PAYLOAD)?;
            let encoding = pp.payload.get("transactionEncoding").and_then(|v| v.as_str()).unwrap_or("");
            let poi = pp
                .payload
                .get("paymentOutputIndex")
                .and_then(|v| v.as_u64())
                .ok_or(errors::INVALID_PAYLOAD)? as u32;
            let req_hash = pp.request_hash().map(|s| s.to_string());
            let rid = requirements.reservation_id().ok_or(errors::INVALID_PAYMENT_REQUIREMENTS)?;
            // Only settle a reservation we issued and that is not yet consumed.
            // ALL economic terms come from the stored reservation, never the
            // caller-supplied requirements.
            let (t, borrow_owner) = {
                let store = self.reservations.lock().await;
                let t = store.get(rid).ok_or(errors::INVALID_PAYMENT_REQUIREMENTS)?.clone();
                if t.consumed {
                    return Err(errors::INVALID_TRANSACTION_STATE);
                }
                let prefix = if requirements.network == NETWORK_TESTNET10 { "kaspatest" } else { "kaspa" };
                let owner = kob_settle::bech32::spk_to_address(&t.p2sh_script, prefix)
                    .map_err(|_| errors::UNEXPECTED_SETTLE_ERROR)?;
                (t, owner)
            };
            // Caller-supplied requirements must agree with the stored terms.
            let req_matches_terms = requirements.amount_sompi().map(|a| a == t.amount).unwrap_or(false)
                && requirements.pay_to == t.pay_to
                && requirements
                    .borrow_outpoint()
                    .map(|o| o.txid.eq_ignore_ascii_case(&t.borrow_txid) && o.index == t.borrow_index)
                    .unwrap_or(false)
                && requirements.borrow_amount_sompi() == Some(t.borrow_amount)
                && requirements.additive_threshold_sompi() == Some(t.additive_threshold)
                && requirements.payment_output_index() == Some(t.payment_output_index);
            if !req_matches_terms {
                return Err(errors::INVALID_PAYMENT_REQUIREMENTS);
            }
            // Request-binding is MANDATORY: a reservation with no bound
            // requestHash can never settle. Without this, the same signed
            // artifact could be replayed against a different reservation/
            // resource (requestHash lives in the wire payload, not in the
            // hashed transaction bytes, so it is not otherwise pinned to one
            // artifact_id).
            let bound_hash = t.request_hash.clone().ok_or(errors::INVALID_PAYLOAD)?;
            let v = scheme_exact::verify_exact_kip10(
                enc, encoding, poi, req_hash.as_deref(), &from, Some(bound_hash.as_str()), &t,
            )
            .map_err(exact_reject_code)?;
            let validated = Validated {
                artifact_id: v.artifact_id,
                payer: v.payer,
                pay_output_index: v.payment_output_index,
                input_outpoints: v.input_outpoints,
                tx: v.tx,
                pay_to: t.pay_to.clone(),
                confirm_address: v.confirm_address,
                amount: t.amount,
                binding_fingerprint: bound_hash,
            };
            // On-chain: every input unspent across [borrow P2SH, payer].
            self.check_inputs_on_chain(&validated.input_outpoints, &[borrow_owner, from.clone()], None).await?;
            return Ok(validated);
        }

        if binding != BINDING_NATIVE && binding != BINDING_KCC20 {
            return Err(errors::UNSUPPORTED_SCHEME);
        }

        // Request-binding is MANDATORY: without it, an artifact settled for
        // one resource could be replayed (via a fresh /verify or /settle
        // call presenting the SAME signed artifact) as authorization for a
        // different one. The scheme-level check below additionally requires
        // this to match what the transaction payload actually embeds.
        let binding_fingerprint = requirements.fingerprint().map(|s| s.to_string()).ok_or(errors::INVALID_PAYLOAD)?;

        // `owner_addresses`: the address(es) whose unspent UTXO sets must cover
        // every spent input. `require_covenant`: for KCC20, at least one spent
        // input must be an on-chain UTXO carrying this token covenant id.
        let (validated, owner_addresses, require_covenant): (Validated, Vec<String>, Option<String>) =
            if is_native {
                let v = scheme_native::verify_native_exact(&transaction, &from, requirements)
                    .map_err(native_reject_code)?;
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
                        amount: requirements.amount_sompi().map_err(|_| errors::INVALID_PAYMENT_REQUIREMENTS)?,
                        binding_fingerprint,
                    },
                    owners,
                    None,
                )
            } else {
                let v = scheme_kcc20::verify_kcc20_exact(&transaction, &from, requirements)
                    .map_err(kcc20_reject_code)?;
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
                        amount: requirements.amount_sompi().map_err(|_| errors::INVALID_PAYMENT_REQUIREMENTS)?,
                        binding_fingerprint,
                    },
                    owners,
                    Some(asset),
                )
            };

        self.check_inputs_on_chain(&validated.input_outpoints, &owner_addresses, require_covenant.as_deref()).await?;
        Ok(validated)
    }

    /// On-chain check: every input outpoint must be an unspent UTXO owned by one
    /// of `owner_addresses`. If `require_covenant` is set, at least one spent
    /// input must carry that covenant id (KCC20 token genuineness).
    async fn check_inputs_on_chain(
        &self,
        input_outpoints: &[String],
        owner_addresses: &[String],
        require_covenant: Option<&str>,
    ) -> Result<(), &'static str> {
        let mut unspent: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut covenant_seen = require_covenant.is_none();
        for owner in owner_addresses {
            let utxos = self
                .backend
                .get_address_utxos(owner)
                .await
                .map_err(|_| errors::UNEXPECTED_SETTLE_ERROR)?;
            for u in &utxos {
                let key = u.outpoint_key();
                if let Some(req_cov) = require_covenant {
                    if u.utxo_entry.covenant_id.as_deref() == Some(req_cov)
                        && input_outpoints.contains(&key)
                    {
                        covenant_seen = true;
                    }
                }
                unspent.insert(key);
            }
        }
        for op in input_outpoints {
            if !unspent.contains(op) {
                return Err(errors::INVALID_TRANSACTION_STATE);
            }
        }
        if !covenant_seen {
            return Err(errors::INVALID_TRANSACTION_STATE);
        }
        Ok(())
    }

    /// `/verify`: validate without broadcasting.
    pub async fn verify(&self, req: &FacilitatorRequest) -> VerifyResponse {
        let validated = match self.validate(req).await {
            Ok(v) => v,
            Err(e) => return VerifyResponse::invalid(e),
        };

        // Replay: a *different* artifact re-spending a consumed outpoint is
        // invalid; the same artifact again is fine (idempotent) ONLY if it is
        // still bound to the SAME request (see `duplicate_binding_matches`).
        let store = self.replay.lock().await;
        match store.check_replay(&validated.artifact_id, &validated.input_outpoints) {
            ReplayCheck::OutpointReused { .. } => {
                return VerifyResponse::invalid(errors::INVALID_TRANSACTION_STATE);
            }
            ReplayCheck::DuplicateTxid(_) => {
                if !duplicate_binding_matches(&store, &validated.artifact_id, &validated.binding_fingerprint) {
                    return VerifyResponse::invalid(errors::INVALID_TRANSACTION_STATE);
                }
            }
            ReplayCheck::Fresh => {}
        }

        VerifyResponse::valid(validated.payer)
    }

    /// `/settle`: re-verify, broadcast, confirm finality, authorize.
    ///
    /// Idempotent: a retry of an already-settled artifact returns the
    /// previously-recorded on-chain txid instead of re-broadcasting.
    pub async fn settle(&self, req: &FacilitatorRequest) -> SettlementResponse {
        let net = self.config.network.clone();
        let validated = match self.validate(req).await {
            Ok(v) => v,
            Err(e) => return SettlementResponse::failed(e),
        };
        let Validated {
            artifact_id, payer, pay_output_index, input_outpoints, tx, pay_to, confirm_address, amount,
            binding_fingerprint,
        } = validated;
        let request_hash = req.payment_payload.request_hash().map(|s| s.to_string());

        // Replay / idempotency decision under the store lock.
        {
            let mut store = self.replay.lock().await;
            match store.check_replay(&artifact_id, &input_outpoints) {
                ReplayCheck::OutpointReused { .. } => {
                    return SettlementResponse::failed(errors::INVALID_TRANSACTION_STATE);
                }
                ReplayCheck::DuplicateTxid(_) => {
                    // Same artifact seen before. It is only authorized as
                    // THIS request's payment if it is still bound to the same
                    // request — otherwise a settled artifact could be
                    // presented again to authorize a DIFFERENT resource. A
                    // mismatch here refuses even a not-yet-broadcast retry
                    // (below) so it can't silently steal/overwrite the
                    // original record's binding.
                    if !duplicate_binding_matches(&store, &artifact_id, &binding_fingerprint) {
                        return SettlementResponse::failed(errors::INVALID_TRANSACTION_STATE);
                    }
                    // If it already has an on-chain txid, re-confirm and
                    // return idempotently rather than re-broadcasting.
                    if let Some(rec) = store.get(&artifact_id) {
                        if let Some(chain_txid) = rec.chain_txid.clone() {
                            drop(store);
                            return self
                                .finalize(net, &artifact_id, &chain_txid, pay_output_index, &confirm_address, amount, Some(payer), request_hash)
                                .await;
                        }
                    }
                }
                ReplayCheck::Fresh => {}
            }

            // Reserve: record Submitted (with outpoints) BEFORE broadcast so a
            // crash immediately after submit can't lose the replay guard.
            let record = PaymentRecord::submitted(artifact_id.clone(), input_outpoints.clone())
                .with_parties(Some(payer.clone()), Some(pay_to.clone()), amount)
                .with_fingerprint(binding_fingerprint.clone());
            if store.record(record).is_err() {
                return SettlementResponse::failed(errors::UNEXPECTED_SETTLE_ERROR);
            }
        }

        // Broadcast.
        let envelope = serde_json::json!({ "transaction": tx, "allowOrphan": false });
        let chain_txid = match self.backend.submit(envelope).await {
            Ok(txid) => txid,
            Err(_) => {
                let mut store = self.replay.lock().await;
                let _ = store.mark_failed(&artifact_id);
                return SettlementResponse::failed(errors::INVALID_TRANSACTION_STATE);
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

        self.finalize(net, &artifact_id, &chain_txid, pay_output_index, &confirm_address, amount, Some(payer), request_hash).await
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
    pub async fn await_payment(&self, req: &AwaitRequest) -> SettlementResponse {
        let net = self.config.network.clone();
        let requirements = &req.payment_requirements;

        if requirements.scheme != SCHEME_EXACT {
            return SettlementResponse::failed(errors::INVALID_SCHEME);
        }
        if requirements.network != self.config.network {
            return SettlementResponse::failed(errors::INVALID_NETWORK);
        }
        if requirements.binding().unwrap_or_default() != BINDING_NATIVE {
            // Pull discovery is implemented for the KOB-native binding only.
            return SettlementResponse::failed(errors::UNSUPPORTED_SCHEME);
        }
        let required = match requirements.amount_sompi() {
            Ok(r) => r,
            Err(_) => return SettlementResponse::failed(errors::INVALID_PAYMENT_REQUIREMENTS),
        };
        let pay_to = requirements.pay_to.clone();
        let expected_fp = requirements.fingerprint().map(|s| s.to_string());
        let timeout_secs = if requirements.max_timeout_seconds == 0 { 30 } else { requirements.max_timeout_seconds };

        let mut observer = PaymentObserver::new();
        if observer.watch(&pay_to).is_err() {
            return SettlementResponse::failed(errors::INVALID_PAYMENT_REQUIREMENTS);
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
                let _ = timeout_secs;
                if ev.value < required {
                    return SettlementResponse::failed(errors::INVALID_PAYMENT_REQUIREMENTS);
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
                let ext = KaspaSettleExt {
                    payment_output_index: Some(ev.output_index),
                    finality: Some("accepted".to_string()),
                    request_hash: None,
                    ..Default::default()
                };
                return SettlementResponse::ok(&net, &ev.txid, ev.value, None, ext);
            }

            if std::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(700)).await;
        }

        // No matching payment (or only an already-credited one) within timeout.
        let _ = saw_already_credited;
        SettlementResponse::failed(errors::INVALID_TRANSACTION_STATE)
    }

    /// Confirm finality for a broadcast payment and record the outcome.
    #[allow(clippy::too_many_arguments)]
    async fn finalize(
        &self,
        net: String,
        artifact_id: &str,
        chain_txid: &str,
        pay_output_index: u32,
        confirm_address: &str,
        amount: u64,
        payer: Option<String>,
        request_hash: Option<String>,
    ) -> SettlementResponse {
        let confirmed = self
            .backend
            .confirm(chain_txid, pay_output_index, confirm_address, Some(self.config.confirm.clone()))
            .await;

        let mut store = self.replay.lock().await;
        if confirmed {
            let _ = store.mark_confirmed(artifact_id);
            let ext = KaspaSettleExt {
                payment_output_index: Some(pay_output_index),
                finality: Some("accepted".to_string()),
                request_hash,
                ..Default::default()
            };
            SettlementResponse::ok(&net, chain_txid, amount, payer, ext)
        } else {
            // Broadcast accepted but not yet observed on-chain. Leave the
            // record as Submitted (with its chain_txid) so an idempotent
            // retry can re-confirm and flip to success.
            let _ = net;
            SettlementResponse::failed(errors::INVALID_TRANSACTION_STATE)
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
    use crate::wire_v2::{PaymentPayload, PaymentRequirements, ASSET_KAS, NETWORK_TESTNET10};

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

    /// A fixed valid test binding fingerprint. Fingerprint binding is
    /// mandatory (Fix 2), so happy-path/unrelated-failure tests need SOME
    /// valid value here; tests specifically about the binding itself build
    /// their own.
    fn test_fp() -> String {
        "ab".repeat(32)
    }

    fn requirements(pay_to: &str, amount: u64, fp: Option<&str>) -> PaymentRequirements {
        let mut extra = serde_json::json!({ "binding": BINDING_NATIVE });
        if let Some(f) = fp {
            extra["fingerprint"] = serde_json::json!(f);
        }
        PaymentRequirements {
            scheme: SCHEME_EXACT.to_string(),
            network: NETWORK_TESTNET10.to_string(),
            amount: amount.to_string(),
            asset: ASSET_KAS.to_string(),
            pay_to: pay_to.to_string(),
            max_timeout_seconds: 60,
            extra,
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
        let req = requirements(pay_to, req_amount, fp);
        FacilitatorRequest {
            x402_version: X402_VERSION,
            payment_payload: PaymentPayload {
                x402_version: X402_VERSION,
                accepted: req.clone(),
                payload: serde_json::json!({
                    "type": "kob-native-transfer",
                    "payerAddress": from,
                    "transaction": tx,
                }),
                extensions: None,
            },
            payment_requirements: req,
        }
    }

    #[tokio::test]
    async fn verify_and_settle_happy_path() {
        let from = addr(1);
        let pay_to = addr(2);
        let in_txid = "aa".repeat(32);
        let chain = MockChain::new(true).with_utxo(&from, &in_txid, 0, 200_000_000);
        let fac = Facilitator::new(chain, tmp_store("happy"), config());
        let req = request(&from, &pay_to, 100_000_000, &in_txid, 0, Some(&test_fp()), 100_000_000);

        let v = fac.verify(&req).await;
        assert!(v.is_valid, "verify: {:?}", v.invalid_reason);
        assert_eq!(v.payer.as_deref(), Some(from.as_str()));

        let s = fac.settle(&req).await;
        assert!(s.success, "settle: {:?}", s.error_reason);
        assert!(!s.transaction.is_empty());
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
        let req = request(&from, &pay_to, 99_999_999, &in_txid, 0, Some(&test_fp()), 100_000_000);

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
        let mut req = request(&from, &wrong, 100_000_000, &in_txid, 0, Some(&test_fp()), 100_000_000);
        req.payment_requirements = requirements(&pay_to, 100_000_000, Some(&test_fp()));

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
        let req = request(&from, &pay_to, 100_000_000, &in_txid, 0, Some(&test_fp()), 100_000_000);

        let v = fac.verify(&req).await;
        assert!(!v.is_valid);
        assert_eq!(v.invalid_reason.as_deref(), Some(errors::INVALID_TRANSACTION_STATE));
        assert_eq!(fac.backend.submit_count(), 0);
    }

    #[tokio::test]
    async fn idempotent_settle_does_not_double_broadcast() {
        let from = addr(1);
        let pay_to = addr(2);
        let in_txid = "ee".repeat(32);
        let chain = MockChain::new(true).with_utxo(&from, &in_txid, 0, 200_000_000);
        let fac = Facilitator::new(chain, tmp_store("idem"), config());
        let req = request(&from, &pay_to, 100_000_000, &in_txid, 0, Some(&test_fp()), 100_000_000);

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

        let req1 = request(&from, &pay_to, 100_000_000, &in_txid, 0, Some(&test_fp()), 100_000_000);
        let s1 = fac.settle(&req1).await;
        assert!(s1.success);

        // A different artifact (different amount => different tx => different
        // artifact_id) reusing the same input outpoint.
        let req2 = request(&from, &pay_to, 120_000_000, &in_txid, 0, Some(&test_fp()), 100_000_000);
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
        let req = request(&from, &pay_to, 100_000_000, &in_txid, 0, Some(&test_fp()), 100_000_000);
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
        assert!(!s2.transaction.is_empty());
        assert_eq!(fac2.backend.submit_count(), 0, "recovery must not re-broadcast");
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn rejects_missing_fingerprint_binding() {
        // Fix 2: request-binding is mandatory. Requirements with no
        // `extra.fingerprint` at all must be refused, even for an otherwise
        // perfectly valid payment.
        let from = addr(1);
        let pay_to = addr(2);
        let in_txid = "14".repeat(32);
        let chain = MockChain::new(true).with_utxo(&from, &in_txid, 0, 200_000_000);
        let fac = Facilitator::new(chain, tmp_store("fp_missing"), config());
        let req = request(&from, &pay_to, 100_000_000, &in_txid, 0, None, 100_000_000);

        let v = fac.verify(&req).await;
        assert!(!v.is_valid);
        assert_eq!(v.invalid_reason.as_deref(), Some(errors::INVALID_PAYLOAD));
        let s = fac.settle(&req).await;
        assert!(!s.success);
        assert_eq!(fac.backend.submit_count(), 0);
    }

    #[tokio::test]
    async fn settle_refuses_duplicate_artifact_bound_to_a_different_request() {
        // Fix 2 (cross-resource replay). A DuplicateTxid hit is only an
        // authorized idempotent retry if the stored record's binding
        // fingerprint matches THIS request's. Here we settle an artifact,
        // then simulate the stored record having been bound to a DIFFERENT
        // request (e.g. as if this facilitator's history shows the artifact
        // was actually settled for some other resource/request) by tampering
        // the replay record directly — this isolates and proves the new
        // DuplicateTxid guard itself, independent of how any particular
        // caller might arrive at a binding mismatch.
        let from = addr(1);
        let pay_to = addr(2);
        let in_txid = "15".repeat(32);
        let chain = MockChain::new(true).with_utxo(&from, &in_txid, 0, 200_000_000);
        let fac = Facilitator::new(chain, tmp_store("fp_cross"), config());
        let fp = test_fp();
        let req = request(&from, &pay_to, 100_000_000, &in_txid, 0, Some(&fp), 100_000_000);

        let s1 = fac.settle(&req).await;
        assert!(s1.success, "first settle: {:?}", s1.error_reason);

        let artifact_id = fac.validate(&req).await.unwrap().artifact_id;
        {
            let mut store = fac.replay.lock().await;
            let rec = store.get(&artifact_id).unwrap().clone();
            assert_eq!(rec.fingerprint.as_deref(), Some(fp.as_str()));
            store.record(rec.with_fingerprint("cc".repeat(32))).unwrap();
        }

        // Re-presenting the SAME artifact, still bound to `fp` in THIS
        // request, must now be refused: the DuplicateTxid hit's stored
        // fingerprint no longer matches.
        let v2 = fac.verify(&req).await;
        assert!(!v2.is_valid, "verify must also refuse the cross-request replay");
        assert_eq!(v2.invalid_reason.as_deref(), Some(errors::INVALID_TRANSACTION_STATE));
        let s2 = fac.settle(&req).await;
        assert!(!s2.success, "cross-request replay of a settled artifact must be refused");
        assert_eq!(s2.error_reason.as_deref(), Some(errors::INVALID_TRANSACTION_STATE));
        assert_eq!(fac.backend.submit_count(), 1, "must not re-broadcast");
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
        let fp = test_fp();
        let payload_hex = hex::encode(fingerprint::embed_fingerprint(&fp));

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
            "payload": payload_hex,
        });
        let requirements = PaymentRequirements {
            scheme: SCHEME_EXACT.to_string(),
            network: NETWORK_TESTNET10.to_string(),
            amount: req_amount.to_string(),
            asset: ASSET_KAS.to_string(),
            pay_to: recipient_addr,
            max_timeout_seconds: 60,
            extra: serde_json::json!({ "binding": BINDING_KCC20, "assetId": asset, "fingerprint": fp }),
        };
        let req = FacilitatorRequest {
            x402_version: X402_VERSION,
            payment_payload: PaymentPayload {
                x402_version: X402_VERSION,
                accepted: requirements.clone(),
                payload: serde_json::json!({
                    "type": "kob-kcc20-transfer",
                    "payerAddress": payer_addr.clone(),
                    "transaction": tx,
                }),
                extensions: None,
            },
            payment_requirements: requirements,
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
        assert!(!s.transaction.is_empty());
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

    #[tokio::test]
    async fn kcc20_rejects_missing_fingerprint_binding() {
        // Fix 2: mandatory for KCC20 too.
        let payer_pk = [1u8; 32];
        let recipient_pk = [2u8; 32];
        let asset = "ab".repeat(32);
        let in_txid = "b0".repeat(32);
        let (payer_token_addr, payer_token_spk) = token_addr_and_spk(&payer_pk);
        let chain = MockChain::new(true).with_covenant_utxo(
            &payer_token_addr,
            &payer_token_spk,
            &in_txid,
            0,
            100_000_000,
            &asset,
        );
        let fac = Facilitator::new(chain, tmp_store("kcc20_fp_missing"), config());
        let (mut req, _payer) = kcc20_request(&payer_pk, &recipient_pk, &asset, 50_000_000, &in_txid, 50_000_000);
        // Strip the fingerprint the helper embeds.
        req.payment_requirements.extra = serde_json::json!({ "binding": BINDING_KCC20, "assetId": asset });
        req.payment_payload.accepted = req.payment_requirements.clone();

        let v = fac.verify(&req).await;
        assert!(!v.is_valid);
        assert_eq!(v.invalid_reason.as_deref(), Some(errors::INVALID_PAYLOAD));
        assert_eq!(fac.backend.submit_count(), 0);
    }

    // --- PULL mode (/await): client broadcasts, facilitator DISCOVERS ---

    fn await_req(pay_to: &str, required: u64, fp: Option<&str>, timeout: u64) -> AwaitRequest {
        let mut extra = serde_json::json!({ "binding": BINDING_NATIVE });
        if let Some(f) = fp {
            extra["fingerprint"] = serde_json::json!(f);
        }
        AwaitRequest {
            x402_version: X402_VERSION,
            payment_requirements: PaymentRequirements {
                scheme: SCHEME_EXACT.to_string(),
                network: NETWORK_TESTNET10.to_string(),
                amount: required.to_string(),
                asset: ASSET_KAS.to_string(),
                pay_to: pay_to.to_string(),
                max_timeout_seconds: timeout,
                extra,
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
        assert_eq!(s.transaction, pay_txid, "returns the discovered txid");
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
        assert_eq!(s.error_reason.as_deref(), Some(errors::INVALID_PAYMENT_REQUIREMENTS));
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
        assert_eq!(s.error_reason.as_deref(), Some(errors::INVALID_TRANSACTION_STATE));
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
        assert_eq!(s2.error_reason.as_deref(), Some(errors::INVALID_TRANSACTION_STATE));
    }

    // --- KIP-10 additive "exact" (strict interop) through the facilitator ---

    fn exact_encoded_tx(merchant: &str, borrow_txid: &str, pay: u64, cont: u64) -> String {
        let tx = serde_json::json!({
            "transaction": {
                "version": 0,
                "inputs": [
                    { "previousOutpoint": { "transactionId": borrow_txid, "index": 0 }, "signatureScript": "00", "sequence": 0, "sigOpCount": 0 },
                    { "previousOutpoint": { "transactionId": "ff".repeat(32), "index": 0 }, "signatureScript": "41".to_string()+&"cd".repeat(65), "sequence": 0, "sigOpCount": 1 }
                ],
                "outputs": [
                    { "value": pay, "scriptPublicKey": { "version": 0, "script": spk_hex(merchant) } },
                    { "value": cont, "scriptPublicKey": { "version": 0, "script": spk_hex(merchant) } }
                ],
                "lockTime": 0, "subnetworkId": "0000000000000000000000000000000000000000", "payload": ""
            }
        });
        serde_json::to_string(&tx).unwrap()
    }

    /// requestHash binding is mandatory (Fix 2), so the default builder binds
    /// and supplies a fixed, matching hash. Tests specifically about the
    /// requestHash binding itself use `exact_request_rh` directly.
    async fn exact_request<B: ChainBackend>(fac: &Facilitator<B>, merchant: &str, payer: &str, borrow_txid: &str, pay: u64, cont: u64) -> FacilitatorRequest {
        let h = test_fp();
        exact_request_rh(fac, merchant, payer, borrow_txid, pay, cont, Some(h.clone()), Some(&h)).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn exact_request_rh<B: ChainBackend>(
        fac: &Facilitator<B>, merchant: &str, payer: &str, borrow_txid: &str, pay: u64, cont: u64,
        reserve_rh: Option<String>, payload_rh: Option<&str>,
    ) -> FacilitatorRequest {
        let borrow_amount = 100_000_000u64;
        let threshold = 3000u64;
        let pr = fac.reserve(merchant, 250, borrow_txid, 0, borrow_amount, threshold, 0, "https://ex/r", reserve_rh).await.unwrap();
        let requirements = pr.accepts[0].clone();
        let enc = exact_encoded_tx(merchant, borrow_txid, pay, cont);
        let mut payload = serde_json::json!({
            "type": "exact-transaction",
            "payerAddress": payer,
            "transaction": enc,
            "transactionEncoding": crate::wire_v2::TX_ENCODING_SAFE_JSON,
            "paymentOutputIndex": 0
        });
        if let Some(rh) = payload_rh {
            payload["requestHash"] = serde_json::json!(rh);
        }
        FacilitatorRequest {
            x402_version: X402_VERSION,
            payment_payload: PaymentPayload { x402_version: X402_VERSION, accepted: requirements.clone(), payload, extensions: None },
            payment_requirements: requirements,
        }
    }

    #[tokio::test]
    async fn exact_kip10_verify_and_settle_happy() {
        let merchant = addr(2);
        let payer = addr(1);
        let borrow_txid = "a1".repeat(32);
        let (_rs, borrow_spk, borrow_addr) =
            crate::reservation::borrow_covenant(&merchant, 100_000_000, 3000).unwrap();
        let chain = MockChain::new(true)
            .with_covenant_utxo(&borrow_addr, &hex::encode(&borrow_spk), &borrow_txid, 0, 100_000_000, &"00".repeat(32))
            .with_utxo(&payer, &"ff".repeat(32), 0, 200_000_000);
        let fac = Facilitator::new(chain, tmp_store("exact_happy"), config());
        // pays 250 to merchant, continuation 100_003_000 (>= 100M+3000).
        let req = exact_request(&fac, &merchant, &payer, &borrow_txid, 250, 100_003_000).await;

        let v = fac.verify(&req).await;
        assert!(v.is_valid, "exact verify: {:?}", v.invalid_reason);
        let s = fac.settle(&req).await;
        assert!(s.success, "exact settle: {:?}", s.error_reason);
        assert_eq!(s.amount.as_deref(), Some("250"));
        assert_eq!(fac.backend.submit_count(), 1);
    }

    #[tokio::test]
    async fn exact_kip10_rejects_under_threshold() {
        let merchant = addr(2);
        let payer = addr(1);
        let borrow_txid = "a2".repeat(32);
        let (_rs, borrow_spk, borrow_addr) =
            crate::reservation::borrow_covenant(&merchant, 100_000_000, 3000).unwrap();
        let chain = MockChain::new(true)
            .with_covenant_utxo(&borrow_addr, &hex::encode(&borrow_spk), &borrow_txid, 0, 100_000_000, &"00".repeat(32))
            .with_utxo(&payer, &"ff".repeat(32), 0, 200_000_000);
        let fac = Facilitator::new(chain, tmp_store("exact_under"), config());
        // continuation only 100_000_000 (< 100M + 3000) -> refused, no broadcast.
        let req = exact_request(&fac, &merchant, &payer, &borrow_txid, 250, 100_000_000).await;
        let v = fac.verify(&req).await;
        assert!(!v.is_valid);
        assert_eq!(v.invalid_reason.as_deref(), Some(errors::INVALID_PAYMENT_REQUIREMENTS));
        let s = fac.settle(&req).await;
        assert!(!s.success);
        assert_eq!(fac.backend.submit_count(), 0);
    }

    #[tokio::test]
    async fn exact_kip10_rejects_caller_amount_mismatch() {
        let merchant = addr(2);
        let payer = addr(1);
        let borrow_txid = "a3".repeat(32);
        let (_rs, borrow_spk, borrow_addr) =
            crate::reservation::borrow_covenant(&merchant, 100_000_000, 3000).unwrap();
        let chain = MockChain::new(true)
            .with_covenant_utxo(&borrow_addr, &hex::encode(&borrow_spk), &borrow_txid, 0, 100_000_000, &"00".repeat(32))
            .with_utxo(&payer, &"ff".repeat(32), 0, 200_000_000);
        let fac = Facilitator::new(chain, tmp_store("exact_amt_tamper"), config());
        // Reservation quoted at 250; caller rewrites requirements to amount "1"
        // (pay-what-you-want attempt). Must be refused, never settle at "1".
        let mut req = exact_request(&fac, &merchant, &payer, &borrow_txid, 250, 100_003_000).await;
        req.payment_requirements.amount = "1".to_string();
        req.payment_payload.accepted.amount = "1".to_string();

        let v = fac.verify(&req).await;
        assert!(!v.is_valid);
        assert_eq!(v.invalid_reason.as_deref(), Some(errors::INVALID_PAYMENT_REQUIREMENTS));
        let s = fac.settle(&req).await;
        assert!(!s.success);
        assert_ne!(s.amount.as_deref(), Some("1"));
        assert_eq!(fac.backend.submit_count(), 0);
    }

    async fn exact_fac_with_borrow(borrow_txid: &str, tag: &str) -> (Facilitator<MockChain>, String, String) {
        let merchant = addr(2);
        let payer = addr(1);
        let (_rs, borrow_spk, borrow_addr) =
            crate::reservation::borrow_covenant(&merchant, 100_000_000, 3000).unwrap();
        let chain = MockChain::new(true)
            .with_covenant_utxo(&borrow_addr, &hex::encode(&borrow_spk), borrow_txid, 0, 100_000_000, &"00".repeat(32))
            .with_utxo(&payer, &"ff".repeat(32), 0, 200_000_000);
        (Facilitator::new(chain, tmp_store(tag), config()), merchant, payer)
    }

    #[tokio::test]
    async fn exact_kip10_request_hash_binding_enforced() {
        let bt = "a4".repeat(32);
        let (fac, merchant, payer) = exact_fac_with_borrow(&bt, "exact_rh_ok").await;
        let h = "ab".repeat(32);
        // Reservation binds request hash h; payload carries h -> accepted.
        let req = exact_request_rh(&fac, &merchant, &payer, &bt, 250, 100_003_000, Some(h.clone()), Some(&h)).await;
        let v = fac.verify(&req).await;
        assert!(v.is_valid, "matching request hash must pass: {:?}", v.invalid_reason);
    }

    #[tokio::test]
    async fn exact_kip10_rejects_request_hash_mismatch() {
        let bt = "a5".repeat(32);
        let (fac, merchant, payer) = exact_fac_with_borrow(&bt, "exact_rh_bad").await;
        // Reservation binds "ab...", payload carries "cd..." -> refused (dead code before).
        let req = exact_request_rh(&fac, &merchant, &payer, &bt, 250, 100_003_000, Some("ab".repeat(32)), Some(&"cd".repeat(32))).await;
        let v = fac.verify(&req).await;
        assert!(!v.is_valid);
        let s = fac.settle(&req).await;
        assert!(!s.success);
        assert_eq!(fac.backend.submit_count(), 0);
    }

    #[tokio::test]
    async fn exact_kip10_rejects_missing_request_hash_when_bound() {
        let bt = "a6".repeat(32);
        let (fac, merchant, payer) = exact_fac_with_borrow(&bt, "exact_rh_missing").await;
        // Reservation binds a hash; payload omits it -> refused.
        let req = exact_request_rh(&fac, &merchant, &payer, &bt, 250, 100_003_000, Some("ab".repeat(32)), None).await;
        let v = fac.verify(&req).await;
        assert!(!v.is_valid);
        assert_eq!(fac.backend.submit_count(), 0);
    }

    #[tokio::test]
    async fn exact_kip10_rejects_reservation_with_no_bound_request_hash() {
        // Fix 2: request-binding is mandatory. A reservation issued with NO
        // requestHash at all can never settle, even with a perfectly valid
        // payment — otherwise the artifact it produces would carry no
        // per-request binding at all (requestHash lives outside the hashed
        // tx bytes for this scheme) and could be replayed against a
        // different reservation/resource.
        let bt = "a9".repeat(32);
        let (fac, merchant, payer) = exact_fac_with_borrow(&bt, "exact_rh_unbound").await;
        let req = exact_request_rh(&fac, &merchant, &payer, &bt, 250, 100_003_000, None, None).await;
        let v = fac.verify(&req).await;
        assert!(!v.is_valid);
        assert_eq!(v.invalid_reason.as_deref(), Some(errors::INVALID_PAYLOAD));
        let s = fac.settle(&req).await;
        assert!(!s.success);
        assert_eq!(fac.backend.submit_count(), 0);
    }

    #[test]
    fn reject_codes_align_request_binding_across_schemes() {
        // The same logical failure (request-binding mismatch/missing) maps to
        // ONE wire code across all three schemes.
        let n = native_reject_code(scheme_native::NativeReject::FingerprintMismatch { expected: "a".into(), got: None });
        let k = kcc20_reject_code(scheme_kcc20::Kcc20Reject::FingerprintMismatch { expected: "a".into(), got: None });
        let e = exact_reject_code(scheme_exact::ExactReject::FingerprintMismatch);
        assert_eq!(n, errors::INVALID_PAYLOAD);
        assert_eq!(n, k);
        assert_eq!(n, e);
        assert_eq!(native_reject_code(scheme_native::NativeReject::FingerprintMissing), errors::INVALID_PAYLOAD);
        assert_eq!(kcc20_reject_code(scheme_kcc20::Kcc20Reject::FingerprintMissing), errors::INVALID_PAYLOAD);
    }
}
