//! Scheme (C): robust KCC-0020 stablecoin covenant TRANSFER as an x402
//! payment (the pure, node-independent part).
//!
//! §7.4(B) of `kob/STABLECOIN_FOUR_AXIS_AUDIT_2026-07-20.md` (audit finding
//! G-x1): `scheme_kcc20.rs` can only ever recognize its OWN compile-time
//! `P2SH(build_token_unit_redeem_script(pk))` template, so it structurally
//! cannot recognize a stablecoin covenant's P2SH -- a completely different,
//! much larger redeem-script template (role pubkeys, `role_registry_root`,
//! `frozen_flag`, `epoch`; see `kob_core::contract::stablecoin`). This is
//! **Design (B)** from the audit's two options: a dedicated verifier, rather
//! than generalizing `scheme_kcc20.rs`'s SPK derivation in place. Chosen
//! because the stablecoin covenant's TRANSFER shape needs its OWN vocabulary
//! (role pubkeys, mutable state fields, a mandatory issuer OPS attestation)
//! that has nothing to do with `token_unit`'s single-owner-pubkey template;
//! bolting that onto `scheme_kcc20.rs` would either overload `assetId`'s
//! established KCC20 semantics or require a caller-declared-template
//! parameter threaded through a call path that is not built for it. A
//! separate file keeps both schemes' pure-verification logic simple and
//! keeps this change from touching (or risking regressing) `scheme_kcc20.rs`
//! at all. This mirrors how `scheme_native.rs`/`scheme_exact.rs`/
//! `scheme_kcc20.rs` are already three separate modules despite sharing
//! helper patterns (`input_outpoints`, `ObservedOutput` usage, etc).
//!
//! # How the recipient's covenant is recognized (solves G-x1 without an
//! opaque caller-supplied blob)
//!
//! Unlike `token_unit`'s address (a pure function of one pubkey), a
//! stablecoin covenant's redeem script also bakes in the ISSUER's fixed role
//! keys and the coin's current mutable state. `PaymentRequirements.extra`
//! must therefore declare every one of those fields (`identifierType`,
//! `roleRegistryRoot`, `frozenFlag`, `epoch`, `opsPubkey`, `freezePubkey`,
//! `seizePubkeys`, `recoveryPubkeys`, `mintPubkey` -- [`StablecoinTemplate`]),
//! and this module reconstructs the EXACT redeem-script bytes via the SAME
//! real builder that deployed the on-chain covenant
//! (`kob_core::contract::stablecoin::build_stablecoin_redeem_script`) rather
//! than trusting an opaque caller-supplied script blob. A merchant who
//! declares the wrong fields simply derives the wrong P2SH address (a
//! self-defeating lie, same trust model `payTo` already has in every other
//! scheme here) -- there is no new attack surface from taking these fields
//! as input.
//!
//! # OPS attestation: what is, and is not, cryptographically re-verified here
//!
//! A TRANSFER is only valid on-chain with a fresh issuer (OPS role) Schnorr
//! signature over a message binding the covenant id, spent outpoint,
//! successor SPK and amount (`kob_core::contract::stablecoin::attestation`).
//! This module DOES reconstruct that message and Schnorr-verify it against
//! the declared `opsPubkey` -- genuinely, not just a shape check -- which is
//! possible from the artifact + requirements ALONE (no RPC) under Plan A's
//! stated 1:1-transfer invariant (`stablecoin/mod.rs`'s ISSUE-15 note: "one
//! gated input funds one attested successor... binds the input's full native
//! amount"): the spent covenant input's own amount therefore equals the
//! successor output's value, which the artifact already tells us.
//!
//! What is NOT verified here (by design, matching every other scheme in this
//! crate): the OWNER's SIGHASH_ALL transaction signature. No scheme in this
//! crate cryptographically re-verifies the payer's own spending signature at
//! this layer -- that is the consensus node's job at broadcast time. Only
//! the exact-v2 scheme's SEPARATE payer request-authorization digest gets
//! Schnorr-verified in `facilitator.rs`, which is a different, additional
//! signed statement, not the raw tx-spending signature.
//!
//! # The OPS co-sign seam
//!
//! A stablecoin TRANSFER cannot be assembled by the payer alone: the
//! issuer's OPS role must co-sign every spend (the freeze gate). This module
//! provides that seam explicitly as [`OpsAttestationOracle`] (the interface
//! a live client would call out to a deployed issuer-oracle service through)
//! plus [`TestOpsOracle`], an in-process stand-in that signs locally with a
//! known key -- used by this module's own tests and by
//! [`build_stablecoin_transfer_artifact`] (the client tx builder) to produce
//! a genuinely-signed artifact. Wiring a LIVE network round trip to a real
//! deployed issuer-oracle service is explicitly NOT done here (there is no
//! such service in this repo yet); that is the one piece of §7.4(B) left as
//! an interface, per the task's own scoping.

use kob_settle::observe::ObservedOutput;

use kob_core::contract::stablecoin::attestation::op_type;
use kob_core::contract::stablecoin::{
    build_attestation_message, build_stablecoin_redeem_script, build_stablecoin_transfer_sigscript,
    StablecoinStateHeader, STATE_HEADER_LEN,
};

use crate::fingerprint;
use crate::wire_v2::PaymentRequirements;

/// The merchant/issuer-declared robust-stablecoin covenant parameters needed
/// to independently reconstruct the *exact* redeem-script bytes of a given
/// owner's covenant state, via the SAME real `kob_core` builder that
/// deployed the on-chain covenant. See module doc for why this solves G-x1
/// without accepting an opaque caller-supplied script blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StablecoinTemplate {
    pub identifier_type: u8,
    pub role_registry_root: [u8; 32],
    pub frozen_flag: u8,
    pub epoch: u32,
    pub ops_pubkey: [u8; 32],
    pub freeze_pubkey: [u8; 32],
    pub seize_pubkeys: [[u8; 32]; 3],
    pub recovery_pubkeys: [[u8; 32]; 3],
    pub mint_pubkey: [u8; 32],
}

impl StablecoinTemplate {
    /// Encode as the `PaymentRequirements.extra` fields a merchant's 402
    /// offer must carry under [`crate::wire_v2::BINDING_STABLECOIN`] (merged
    /// into `extra` alongside `binding`/`assetId`/`fingerprint`).
    pub fn to_extra_fields(&self) -> serde_json::Value {
        serde_json::json!({
            "identifierType": self.identifier_type as u64,
            "roleRegistryRoot": hex::encode(self.role_registry_root),
            "frozenFlag": self.frozen_flag as u64,
            "epoch": self.epoch,
            "opsPubkey": hex::encode(self.ops_pubkey),
            "freezePubkey": hex::encode(self.freeze_pubkey),
            "seizePubkeys": self.seize_pubkeys.iter().map(hex::encode).collect::<Vec<_>>(),
            "recoveryPubkeys": self.recovery_pubkeys.iter().map(hex::encode).collect::<Vec<_>>(),
            "mintPubkey": hex::encode(self.mint_pubkey),
        })
    }
}

/// Successful pure-verification result for a stablecoin TRANSFER payment.
#[derive(Debug, Clone)]
pub struct StablecoinVerified {
    pub artifact_id: String,
    /// Payer identity address (P2PK), echoed from payload `from`.
    pub payer: String,
    /// Index of BOTH the spent covenant input and the paying output (Plan
    /// A's TRANSFER positional 1:1 convention -- see module doc).
    pub pay_output_index: u32,
    /// Amount paid (== the successor output's native sompi value).
    pub amount_paid: u64,
    /// Consumed input outpoints.
    pub input_outpoints: Vec<String>,
    /// Stablecoin covenant lineage id (hex) this payment is denominated in.
    pub asset: String,
    /// The payer's own stablecoin covenant P2SH address for this lineage --
    /// the address whose UTXO set must contain the spent covenant input
    /// on-chain.
    pub payer_stablecoin_address: String,
    /// The recipient's stablecoin covenant P2SH address -- where the payment
    /// output lives on-chain (what finality confirmation must poll).
    pub recipient_stablecoin_address: String,
    /// Normalized inner transaction object, ready to broadcast.
    pub tx: serde_json::Value,
}

/// Reason a stablecoin TRANSFER payment failed pure verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StablecoinReject {
    Malformed(String),
    BadAsset(String),
    BadRecipient(String),
    BadPayer(String),
    /// `extra`'s declared covenant-template fields are missing/malformed, or
    /// would produce a degenerate covenant (owner key reused as a role key).
    BadTemplate(String),
    WrongRecipient,
    Underpayment { required: u64, paid: u64 },
    MissingCovenantBinding,
    /// The sigscript's OWN successor claim (`new_rs`) disagrees with the
    /// redeem script independently derived for the recipient, even though
    /// the actual output's SPK matched -- a self-consistency failure that
    /// should never be trusted as "correct covenant continuity".
    SuccessorTemplateMismatch,
    /// No input in the transaction structurally looks like a TRANSFER spend
    /// of this covenant lineage (the OPS attestation field, among others, is
    /// simply absent) -- i.e. the mandatory issuer attestation is missing.
    NoCovenantInput,
    /// More than one input structurally looks like a TRANSFER spend of this
    /// SAME lineage -- violates the on-chain single-input-per-lineage guard
    /// (`OpCovInputCount == 1`) this x402 path assumes (1:1 TRANSFER only;
    /// N:M split/merge, op 0x07, is out of scope here).
    MultipleCovenantInputs,
    /// The issuer (OPS role) attestation signature does not verify against
    /// the declared `opsPubkey` for the reconstructed message -- forged,
    /// stale, or bound to different transfer parameters.
    ForgedOpsAttestation,
    FingerprintMissing,
    FingerprintMismatch { expected: String, got: Option<String> },
    NoInputs,
}

impl std::fmt::Display for StablecoinReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StablecoinReject::Malformed(m) => write!(f, "malformed payment: {}", m),
            StablecoinReject::BadAsset(m) => write!(f, "bad stablecoin asset: {}", m),
            StablecoinReject::BadRecipient(m) => write!(f, "bad recipient: {}", m),
            StablecoinReject::BadPayer(m) => write!(f, "bad payer: {}", m),
            StablecoinReject::BadTemplate(m) => write!(f, "bad stablecoin covenant template: {}", m),
            StablecoinReject::WrongRecipient => {
                write!(f, "no stablecoin covenant output pays the required recipient for this asset")
            }
            StablecoinReject::Underpayment { required, paid } => {
                write!(f, "underpayment: required {} token units, paid {}", required, paid)
            }
            StablecoinReject::MissingCovenantBinding => {
                write!(f, "recipient output is missing the stablecoin covenant binding")
            }
            StablecoinReject::SuccessorTemplateMismatch => {
                write!(f, "sigscript's own successor redeem script disagrees with the actual paying output")
            }
            StablecoinReject::NoCovenantInput => {
                write!(f, "no input carries a TRANSFER-shaped spend of this stablecoin covenant lineage (missing OPS attestation)")
            }
            StablecoinReject::MultipleCovenantInputs => {
                write!(f, "more than one input spends this stablecoin covenant lineage (not a 1:1 TRANSFER)")
            }
            StablecoinReject::ForgedOpsAttestation => {
                write!(f, "issuer OPS attestation signature does not verify")
            }
            StablecoinReject::FingerprintMissing => {
                write!(f, "transaction payload is missing the X402 request fingerprint")
            }
            StablecoinReject::FingerprintMismatch { expected, got } => write!(
                f,
                "fingerprint mismatch: expected {}, got {}",
                expected,
                got.as_deref().unwrap_or("<none>")
            ),
            StablecoinReject::NoInputs => write!(f, "transaction has no inputs"),
        }
    }
}

/// Extract the 32-byte Schnorr pubkey from a Kaspa P2PK address.
fn pubkey_from_p2pk(addr: &str) -> Result<[u8; 32], String> {
    let spk = kob_settle::bech32::address_to_spk(addr).map_err(|e| e.to_string())?;
    if spk.len() == 34 && spk[0] == 0x20 && spk[33] == 0xac {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&spk[1..33]);
        Ok(pk)
    } else {
        Err(format!("address {} is not a P2PK identity address", addr))
    }
}

/// Detect the network from an address prefix.
fn network_of(addr: &str) -> kob_settle::types::Network {
    if addr.starts_with("kaspatest") || addr.starts_with("kaspadev") || addr.starts_with("kaspasim") {
        kob_settle::types::Network::Testnet
    } else {
        kob_settle::types::Network::Mainnet
    }
}

fn input_outpoints(tx: &serde_json::Value) -> Vec<String> {
    tx.get("inputs")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|inp| {
                    let op = inp.get("previousOutpoint")?;
                    let txid = op.get("transactionId").and_then(|v| v.as_str())?;
                    let idx = op.get("index").and_then(|v| v.as_u64()).unwrap_or(0);
                    Some(format!("{}:{}", txid, idx))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn hex_field_32(extra: &serde_json::Value, key: &str) -> Result<[u8; 32], String> {
    let s = extra.get(key).and_then(|v| v.as_str()).ok_or_else(|| format!("extra.{} missing", key))?;
    let b = hex::decode(s).map_err(|e| format!("extra.{} invalid hex: {}", key, e))?;
    <[u8; 32]>::try_from(b.as_slice()).map_err(|_| format!("extra.{} must be 32 bytes", key))
}

fn hex_field_32x3(extra: &serde_json::Value, key: &str) -> Result<[[u8; 32]; 3], String> {
    let arr = extra.get(key).and_then(|v| v.as_array()).ok_or_else(|| format!("extra.{} missing", key))?;
    if arr.len() != 3 {
        return Err(format!("extra.{} must have exactly 3 entries", key));
    }
    let mut out = [[0u8; 32]; 3];
    for (i, v) in arr.iter().enumerate() {
        let s = v.as_str().ok_or_else(|| format!("extra.{}[{}] not a string", key, i))?;
        let b = hex::decode(s).map_err(|e| format!("extra.{}[{}] invalid hex: {}", key, i, e))?;
        out[i] = <[u8; 32]>::try_from(b.as_slice()).map_err(|_| format!("extra.{}[{}] must be 32 bytes", key, i))?;
    }
    Ok(out)
}

fn u8_field(extra: &serde_json::Value, key: &str) -> Result<u8, String> {
    let n = extra.get(key).and_then(|v| v.as_u64()).ok_or_else(|| format!("extra.{} missing/invalid", key))?;
    u8::try_from(n).map_err(|_| format!("extra.{} out of u8 range", key))
}

fn u32_field(extra: &serde_json::Value, key: &str) -> Result<u32, String> {
    let n = extra.get(key).and_then(|v| v.as_u64()).ok_or_else(|| format!("extra.{} missing/invalid", key))?;
    u32::try_from(n).map_err(|_| format!("extra.{} out of u32 range", key))
}

fn parse_template(extra: &serde_json::Value) -> Result<StablecoinTemplate, String> {
    Ok(StablecoinTemplate {
        identifier_type: u8_field(extra, "identifierType")?,
        role_registry_root: hex_field_32(extra, "roleRegistryRoot")?,
        frozen_flag: u8_field(extra, "frozenFlag")?,
        epoch: u32_field(extra, "epoch")?,
        ops_pubkey: hex_field_32(extra, "opsPubkey")?,
        freeze_pubkey: hex_field_32(extra, "freezePubkey")?,
        seize_pubkeys: hex_field_32x3(extra, "seizePubkeys")?,
        recovery_pubkeys: hex_field_32x3(extra, "recoveryPubkeys")?,
        mint_pubkey: hex_field_32(extra, "mintPubkey")?,
    })
}

/// Guard against the panic `build_stablecoin_redeem_script` itself asserts
/// on (owner key reused as a role key) -- checked here BEFORE calling the
/// real builder so a malformed/adversarial requirements payload produces a
/// clean [`StablecoinReject::BadTemplate`] instead of taking down the
/// facilitator process.
fn owner_distinct_from_roles(owner: &[u8; 32], t: &StablecoinTemplate) -> Result<(), String> {
    let roles: [&[u8; 32]; 9] = [
        &t.ops_pubkey,
        &t.freeze_pubkey,
        &t.seize_pubkeys[0],
        &t.seize_pubkeys[1],
        &t.seize_pubkeys[2],
        &t.recovery_pubkeys[0],
        &t.recovery_pubkeys[1],
        &t.recovery_pubkeys[2],
        &t.mint_pubkey,
    ];
    if roles.iter().any(|r| *r == owner) {
        return Err("owner pubkey must differ from every declared role pubkey".to_string());
    }
    Ok(())
}

/// Reconstruct the exact redeem-script bytes for `owner_pubkey` under `t`,
/// via the SAME real builder that deploys the on-chain covenant.
fn reconstruct_redeem_script(owner_pubkey: &[u8; 32], t: &StablecoinTemplate) -> Vec<u8> {
    build_stablecoin_redeem_script(
        owner_pubkey,
        t.identifier_type,
        &t.role_registry_root,
        t.frozen_flag,
        t.epoch,
        &t.ops_pubkey,
        &t.freeze_pubkey,
        &t.seize_pubkeys,
        &t.recovery_pubkeys,
        &t.mint_pubkey,
    )
}

/// One input's decoded TRANSFER (`op_type == 0x00`) sigscript fields, per
/// `build_stablecoin_transfer_sigscript`'s documented field order.
struct DecodedTransferInput {
    self_rs: Vec<u8>,
    issuer_sig: [u8; 64],
    new_rs: Vec<u8>,
    op_type: u8,
}

/// Decode a signature script as a TRANSFER-shaped stablecoin spend (six
/// `PushExplicit`-encoded fields: `self_rs, issuer_sig, new_rs,
/// owner_sig||0x01, op_type_selector, redeem_script`), matching exactly what
/// `build_stablecoin_transfer_sigscript` emits. Returns `None` for anything
/// that doesn't decode as EXACTLY this shape -- which is how a spend
/// carrying no OPS attestation at all (or a different op_type's shape, e.g.
/// FREEZE/SEIZE/BURN/MIGRATE) is told apart from a genuine TRANSFER: the
/// owner-signature field's strict 65-byte-ending-in-0x01 check and the
/// trailing-bytes-must-be-empty check reject every other branch's shape (see
/// module doc / this fn's test coverage).
fn decode_transfer_sigscript(ss: &[u8]) -> Option<DecodedTransferInput> {
    let mut rest = ss;
    let (self_rs, n) = kob_core::contract::kcc20::decode_push_explicit(rest)?;
    rest = &rest[n..];
    let (issuer_sig_v, n) = kob_core::contract::kcc20::decode_push_explicit(rest)?;
    rest = &rest[n..];
    let issuer_sig: [u8; 64] = issuer_sig_v.as_slice().try_into().ok()?;
    let (new_rs, n) = kob_core::contract::kcc20::decode_push_explicit(rest)?;
    rest = &rest[n..];
    let (owner_sig_v, n) = kob_core::contract::kcc20::decode_push_explicit(rest)?;
    rest = &rest[n..];
    if owner_sig_v.len() != 65 || owner_sig_v[64] != 0x01 {
        return None;
    }
    let (op_type_v, n) = kob_core::contract::kcc20::decode_push_explicit(rest)?;
    rest = &rest[n..];
    if op_type_v.len() != 1 {
        return None;
    }
    let op_type = op_type_v[0];
    let (trailing_rs, n) = kob_core::contract::kcc20::decode_push_explicit(rest)?;
    rest = &rest[n..];
    if !rest.is_empty() {
        return None;
    }
    if self_rs != trailing_rs {
        return None;
    }
    Some(DecodedTransferInput { self_rs, issuer_sig, new_rs, op_type })
}

/// Verify a robust-stablecoin TRANSFER "exact" payment against the
/// requirements (pure checks). `payer` is the payload `from`; `transaction`
/// is the payload `transaction` (envelope or bare). See module doc for what
/// is and is not cryptographically verified here.
pub fn verify_stablecoin_transfer(
    transaction: &serde_json::Value,
    payer: &str,
    requirements: &PaymentRequirements,
) -> Result<StablecoinVerified, StablecoinReject> {
    let required = requirements.amount_sompi().map_err(StablecoinReject::Malformed)?;

    // Stablecoin covenant lineage id (KOB binding) lives in extra.assetId --
    // same JSON field/semantics KCC20 uses, reused here deliberately.
    let asset = requirements.kcc20_covenant_id().unwrap_or_default().to_lowercase();
    if asset.len() != 64 || hex::decode(&asset).map(|b| b.len() != 32).unwrap_or(true) {
        return Err(StablecoinReject::BadAsset(format!(
            "extra.assetId must be a 32-byte covenant id (hex), got '{}'",
            asset
        )));
    }
    let asset_bytes: [u8; 32] =
        hex::decode(&asset).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| {
            StablecoinReject::BadAsset("extra.assetId failed to decode".to_string())
        })?;

    let template = parse_template(&requirements.extra).map_err(StablecoinReject::BadTemplate)?;

    let recipient_pk = pubkey_from_p2pk(&requirements.pay_to).map_err(StablecoinReject::BadRecipient)?;
    let payer_pk = pubkey_from_p2pk(payer).map_err(StablecoinReject::BadPayer)?;
    owner_distinct_from_roles(&recipient_pk, &template).map_err(StablecoinReject::BadTemplate)?;
    owner_distinct_from_roles(&payer_pk, &template).map_err(StablecoinReject::BadTemplate)?;

    let expected_rs = reconstruct_redeem_script(&recipient_pk, &template);
    if expected_rs.len() < STATE_HEADER_LEN {
        return Err(StablecoinReject::BadTemplate("reconstructed redeem script shorter than the state header".into()));
    }
    let expected_spk = kob_settle::build_p2sh(&expected_rs).script().to_vec();
    let expected_body_suffix = expected_rs[STATE_HEADER_LEN..].to_vec();

    let tx = crate::scheme_native::normalize_tx(transaction);
    if !tx.is_object() {
        return Err(StablecoinReject::Malformed("transaction is not an object".into()));
    }
    let raw_inputs = tx
        .get("inputs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| StablecoinReject::Malformed("transaction has no inputs array".into()))?;
    if raw_inputs.is_empty() {
        return Err(StablecoinReject::NoInputs);
    }
    let raw_outputs = tx
        .get("outputs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| StablecoinReject::Malformed("transaction has no outputs array".into()))?;

    // Identify the (at most one) TRANSFER-shaped covenant input of THIS
    // lineage -- the off-chain, artifact-only mirror of the on-chain
    // `emit_single_input_covenant_guard` (`OpCovInputCount == 1`).
    let mut found: Option<(usize, DecodedTransferInput)> = None;
    let mut count = 0usize;
    for (i, inp) in raw_inputs.iter().enumerate() {
        let Some(ss_hex) = inp.get("signatureScript").and_then(|v| v.as_str()) else { continue };
        let Ok(ss) = hex::decode(ss_hex) else { continue };
        let Some(decoded) = decode_transfer_sigscript(&ss) else { continue };
        if decoded.op_type != op_type::TRANSFER {
            continue;
        }
        if decoded.self_rs.len() < STATE_HEADER_LEN {
            continue;
        }
        if decoded.self_rs[STATE_HEADER_LEN..] != expected_body_suffix[..] {
            continue; // different issuer/role-set: not this lineage
        }
        let Some(hdr) = StablecoinStateHeader::decode(&decoded.self_rs, 0) else { continue };
        if hdr.role_registry_root != template.role_registry_root {
            continue;
        }
        count += 1;
        found = Some((i, decoded));
    }
    match count {
        0 => return Err(StablecoinReject::NoCovenantInput),
        1 => {}
        _ => return Err(StablecoinReject::MultipleCovenantInputs),
    }
    let (idx, decoded) = found.expect("count == 1 implies found is Some");

    // Sanity: the spent coin's own owner must be the claimed payer.
    let self_header = StablecoinStateHeader::decode(&decoded.self_rs, 0).ok_or_else(|| {
        StablecoinReject::Malformed("covenant input's own redeem script failed to decode".into())
    })?;
    if self_header.owner_pubkey != payer_pk {
        return Err(StablecoinReject::BadPayer(
            "spent covenant coin's owner does not match the claimed payer".into(),
        ));
    }

    // Positional 1:1 convention (`body.rs`'s TRANSFER branch reuses
    // `TXINPUTINDEX` as the successor output index): the paying output MUST
    // be at the SAME index as the covenant input.
    let raw_out = raw_outputs
        .get(idx)
        .ok_or(StablecoinReject::WrongRecipient)?;
    let out = ObservedOutput::from_rpc_json(raw_out)
        .ok_or_else(|| StablecoinReject::Malformed(format!("output {} failed to parse", idx)))?;
    if out.spk_version != 0 || out.spk_script != expected_spk {
        return Err(StablecoinReject::WrongRecipient);
    }
    if out.covenant_id.as_deref() != Some(asset.as_str()) {
        return Err(StablecoinReject::MissingCovenantBinding);
    }
    if out.value < required {
        return Err(StablecoinReject::Underpayment { required, paid: out.value });
    }

    // Covenant continuity: the sigscript's OWN successor claim (`new_rs`)
    // must be the redeem script independently derived for the recipient.
    if decoded.new_rs != expected_rs {
        return Err(StablecoinReject::SuccessorTemplateMismatch);
    }

    // Fingerprint binding (identical convention to native/KCC20).
    if let Some(expected_fp) = requirements.fingerprint() {
        let payload_bytes = tx
            .get("payload")
            .and_then(|v| v.as_str())
            .and_then(|s| if s.is_empty() { Some(vec![]) } else { hex::decode(s).ok() })
            .unwrap_or_default();
        match fingerprint::extract_fingerprint(&payload_bytes) {
            None => return Err(StablecoinReject::FingerprintMissing),
            Some(got) if got != expected_fp => {
                return Err(StablecoinReject::FingerprintMismatch {
                    expected: expected_fp.to_string(),
                    got: Some(got),
                })
            }
            Some(_) => {}
        }
    }

    // ---- Full cryptographic OPS-attestation verification (module doc) ----
    let outpoint = raw_inputs[idx]
        .get("previousOutpoint")
        .ok_or_else(|| StablecoinReject::Malformed("input missing previousOutpoint".into()))?;
    let txid_hex = outpoint
        .get("transactionId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| StablecoinReject::Malformed("previousOutpoint missing transactionId".into()))?;
    let outpoint_txid: [u8; 32] = hex::decode(txid_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| StablecoinReject::Malformed("previousOutpoint.transactionId must be 32-byte hex".into()))?;
    let outpoint_index = outpoint
        .get("index")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| StablecoinReject::Malformed("previousOutpoint missing index".into()))?
        as u32;

    // Successor SPK bytes == ScriptPublicKey::to_bytes() form (version(2B
    // BE) || script); P2SH is always version 0.
    let mut successor_spk_bytes = vec![0u8, 0u8];
    successor_spk_bytes.extend_from_slice(&out.spk_script);

    let message = build_attestation_message(
        &asset_bytes,
        op_type::TRANSFER,
        template.epoch,
        &outpoint_txid,
        outpoint_index,
        &successor_spk_bytes,
        out.value,
    );
    let verified = kob_core::schnorr_verify(&message, &decoded.issuer_sig, &template.ops_pubkey).unwrap_or(false);
    if !verified {
        return Err(StablecoinReject::ForgedOpsAttestation);
    }

    let outpoints = input_outpoints(&tx);

    let payer_rs = reconstruct_redeem_script(&payer_pk, &template);
    let payer_spk = kob_settle::build_p2sh(&payer_rs).script().to_vec();
    let payer_stablecoin_address =
        kob_settle::bech32::spk_to_address(&payer_spk, network_of(payer).address_prefix())
            .map_err(|e| StablecoinReject::BadPayer(e.to_string()))?;
    let recipient_stablecoin_address =
        kob_settle::bech32::spk_to_address(&expected_spk, network_of(&requirements.pay_to).address_prefix())
            .map_err(|e| StablecoinReject::BadRecipient(e.to_string()))?;

    Ok(StablecoinVerified {
        artifact_id: crate::scheme_native::artifact_id(&tx),
        payer: payer.to_string(),
        pay_output_index: idx as u32,
        amount_paid: out.value,
        input_outpoints: outpoints,
        asset,
        payer_stablecoin_address,
        recipient_stablecoin_address,
        tx,
    })
}

// ---------------------------------------------------------------------------
// The OPS co-sign seam (module doc "The OPS co-sign seam").
// ---------------------------------------------------------------------------

/// The OPS-attestation co-sign hook. A stablecoin TRANSFER cannot be built
/// by the payer alone -- the issuer's OPS role must sign a fresh attestation
/// for EVERY spend (the freeze gate), so any client tx builder needs a live
/// round trip to the issuer's online co-signer. This trait is that seam: a
/// production implementation is an HTTP client hitting a deployed
/// issuer-oracle service (NOT implemented in this crate -- see module doc);
/// [`TestOpsOracle`] is the in-process stand-in this module's own tests use.
pub trait OpsAttestationOracle {
    /// Produce the OPS role's raw 64-byte Schnorr signature over the
    /// TRANSFER attestation message for the given spend. Implementations
    /// MUST refuse (return `Err`) rather than sign for a frozen coin, an
    /// exhausted budget, etc. -- the freeze/compliance policy lives entirely
    /// on the oracle side, which is the point of the gate.
    fn attest_transfer(
        &self,
        covenant_id: &[u8; 32],
        epoch: u32,
        outpoint_txid: &[u8; 32],
        outpoint_index: u32,
        successor_spk: &[u8],
        amount: u64,
    ) -> Result<[u8; 64], String>;
}

/// In-process test/demo double for [`OpsAttestationOracle`]: holds the OPS
/// role's raw private key and signs locally. Stands in for the network round
/// trip to a deployed issuer-oracle service -- see the module doc's "OPS
/// co-sign seam" note for what remains to wire a live one.
pub struct TestOpsOracle {
    pub ops_privkey: [u8; 32],
}

impl OpsAttestationOracle for TestOpsOracle {
    fn attest_transfer(
        &self,
        covenant_id: &[u8; 32],
        epoch: u32,
        outpoint_txid: &[u8; 32],
        outpoint_index: u32,
        successor_spk: &[u8],
        amount: u64,
    ) -> Result<[u8; 64], String> {
        let message =
            build_attestation_message(covenant_id, op_type::TRANSFER, epoch, outpoint_txid, outpoint_index, successor_spk, amount);
        kob_core::schnorr_sign(&message, &self.ops_privkey).map_err(|e| e.to_string())
    }
}

/// Assemble a stablecoin TRANSFER payment artifact (client-side tx builder,
/// §7.4(B) task item 2): a single covenant input (the payer's stablecoin
/// UTXO) producing a single covenant output (the recipient's successor
/// state) -- Plan A's 1:1 shape. The sigscript carries BOTH the owner's
/// authorization and the issuer's OPS attestation (obtained from `oracle`),
/// via the REAL `build_stablecoin_transfer_sigscript` builder -- the exact
/// bytes a live wallet would submit.
///
/// `owner_sig` is a placeholder 64-byte value here (SIGHASH_ALL byte
/// appended by the builder): this module's verifier -- like every other
/// x402 scheme in this crate -- does not itself re-verify the owner's
/// transaction signature (see module doc). Only the OPS attestation is
/// cryptographically re-verified by [`verify_stablecoin_transfer`], because
/// that is the piece this task is about.
#[allow(clippy::too_many_arguments)]
pub fn build_stablecoin_transfer_artifact(
    payer_pubkey: &[u8; 32],
    recipient_pubkey: &[u8; 32],
    template: &StablecoinTemplate,
    asset: &[u8; 32],
    spent_outpoint_txid: &[u8; 32],
    spent_outpoint_index: u32,
    amount: u64,
    oracle: &dyn OpsAttestationOracle,
    fingerprint_tag: Option<&str>,
) -> Result<serde_json::Value, String> {
    owner_distinct_from_roles(payer_pubkey, template)?;
    owner_distinct_from_roles(recipient_pubkey, template)?;

    let self_rs = reconstruct_redeem_script(payer_pubkey, template);
    let new_rs = reconstruct_redeem_script(recipient_pubkey, template);
    let recipient_spk = kob_settle::build_p2sh(&new_rs).script().to_vec();

    let mut successor_spk_bytes = vec![0u8, 0u8];
    successor_spk_bytes.extend_from_slice(&recipient_spk);

    let issuer_sig = oracle.attest_transfer(
        asset,
        template.epoch,
        spent_outpoint_txid,
        spent_outpoint_index,
        &successor_spk_bytes,
        amount,
    )?;

    let owner_sig = [0x11u8; 64]; // placeholder -- see fn doc.
    let sigscript = build_stablecoin_transfer_sigscript(&owner_sig, &issuer_sig, &new_rs, &self_rs);

    let payload_hex = match fingerprint_tag {
        Some(f) => hex::encode(fingerprint::embed_fingerprint(f)),
        None => String::new(),
    };

    Ok(serde_json::json!({
        "transaction": {
            "version": 1,
            "inputs": [{
                "previousOutpoint": { "transactionId": hex::encode(spent_outpoint_txid), "index": spent_outpoint_index },
                "signatureScript": hex::encode(&sigscript),
                "sequence": 0,
                "sigOpCount": 2
            }],
            "outputs": [{
                "value": amount,
                "scriptPublicKey": { "version": 0, "script": hex::encode(&recipient_spk) },
                "covenant": { "authorizingInput": 0, "covenantId": hex::encode(asset) }
            }],
            "lockTime": 0,
            "subnetworkId": "0000000000000000000000000000000000000000",
            "payload": payload_hex,
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire_v2::{ASSET_KAS, BINDING_STABLECOIN, NETWORK_TESTNET10, SCHEME_EXACT};

    fn privkey(seed: u8) -> [u8; 32] {
        [seed; 32]
    }
    fn pubkey(seed: u8) -> [u8; 32] {
        kob_core::get_public_key(&privkey(seed)).unwrap()
    }
    fn testnet_addr_pk(pk: &[u8; 32]) -> String {
        kob_settle::wallet::pubkey_to_address(pk, kob_settle::types::Network::Testnet)
    }

    fn test_template() -> StablecoinTemplate {
        StablecoinTemplate {
            identifier_type: kob_core::contract::token::identifier_type::PUBKEY,
            role_registry_root: [0x77; 32],
            frozen_flag: kob_core::contract::stablecoin::state::frozen_flag::CLEAR,
            epoch: 3,
            ops_pubkey: pubkey(99),
            freeze_pubkey: [0xDD; 32],
            seize_pubkeys: [[0x91; 32], [0x92; 32], [0x93; 32]],
            recovery_pubkeys: [[0xA1; 32], [0xA2; 32], [0xA3; 32]],
            mint_pubkey: [0xFA; 32],
        }
    }

    fn requirements(pay_to: &str, asset: &str, amount: u64, t: &StablecoinTemplate, fp: Option<&str>) -> PaymentRequirements {
        let mut extra = t.to_extra_fields();
        extra["binding"] = serde_json::json!(BINDING_STABLECOIN);
        extra["assetId"] = serde_json::json!(asset);
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
            additional: Default::default(),
        }
    }

    /// A genuinely-signed 1:1 TRANSFER artifact: payer seed 1 -> recipient
    /// seed 2, using the real client builder + `TestOpsOracle`.
    fn genuine_artifact(
        payer_seed: u8,
        recipient_seed: u8,
        template: &StablecoinTemplate,
        asset_hex: &str,
        amount: u64,
        fp: Option<&str>,
    ) -> serde_json::Value {
        let asset_bytes: [u8; 32] = hex::decode(asset_hex).unwrap().try_into().unwrap();
        let oracle = TestOpsOracle { ops_privkey: privkey(99) };
        build_stablecoin_transfer_artifact(
            &pubkey(payer_seed),
            &pubkey(recipient_seed),
            template,
            &asset_bytes,
            &[0xcc; 32],
            0,
            amount,
            &oracle,
            fp,
        )
        .unwrap()
    }

    #[test]
    fn accepts_valid_transfer_with_genuine_ops_attestation() {
        let template = test_template();
        let asset = "ab".repeat(32);
        let payer = testnet_addr_pk(&pubkey(1));
        let recipient = testnet_addr_pk(&pubkey(2));
        let art = genuine_artifact(1, 2, &template, &asset, 50_000_000, None);
        let req = requirements(&recipient, &asset, 50_000_000, &template, None);

        let v = verify_stablecoin_transfer(&art["transaction"], &payer, &req).unwrap();
        assert_eq!(v.amount_paid, 50_000_000);
        assert_eq!(v.pay_output_index, 0);
        assert_eq!(v.asset, asset);
        assert!(v.payer_stablecoin_address.starts_with("kaspatest:"));
        assert!(v.recipient_stablecoin_address.starts_with("kaspatest:"));
        assert_ne!(v.payer_stablecoin_address, v.recipient_stablecoin_address);
    }

    #[test]
    fn rejects_wrong_recipient_spk() {
        let template = test_template();
        let asset = "ab".repeat(32);
        let payer = testnet_addr_pk(&pubkey(1));
        let recipient = testnet_addr_pk(&pubkey(2));
        // Artifact actually pays owner seed 7's covenant, not seed 2's.
        let art = genuine_artifact(1, 7, &template, &asset, 50_000_000, None);
        let req = requirements(&recipient, &asset, 50_000_000, &template, None);
        let err = verify_stablecoin_transfer(&art["transaction"], &payer, &req).unwrap_err();
        assert_eq!(err, StablecoinReject::WrongRecipient);
    }

    #[test]
    fn rejects_underpayment() {
        let template = test_template();
        let asset = "ab".repeat(32);
        let payer = testnet_addr_pk(&pubkey(1));
        let recipient = testnet_addr_pk(&pubkey(2));
        let art = genuine_artifact(1, 2, &template, &asset, 49_999_999, None);
        let req = requirements(&recipient, &asset, 50_000_000, &template, None);
        let err = verify_stablecoin_transfer(&art["transaction"], &payer, &req).unwrap_err();
        assert_eq!(err, StablecoinReject::Underpayment { required: 50_000_000, paid: 49_999_999 });
    }

    #[test]
    fn rejects_missing_covenant_binding() {
        let template = test_template();
        let asset = "ab".repeat(32);
        let payer = testnet_addr_pk(&pubkey(1));
        let recipient = testnet_addr_pk(&pubkey(2));
        let mut art = genuine_artifact(1, 2, &template, &asset, 50_000_000, None);
        art["transaction"]["outputs"][0].as_object_mut().unwrap().remove("covenant");
        let req = requirements(&recipient, &asset, 50_000_000, &template, None);
        let err = verify_stablecoin_transfer(&art["transaction"], &payer, &req).unwrap_err();
        assert_eq!(err, StablecoinReject::MissingCovenantBinding);
    }

    #[test]
    fn rejects_missing_ops_attestation() {
        // The input's sigscript is a plain placeholder (no covenant shape at
        // all -- as if someone tried to spend the stablecoin UTXO with a bare
        // signature and no OPS attestation).
        let template = test_template();
        let asset = "ab".repeat(32);
        let payer = testnet_addr_pk(&pubkey(1));
        let recipient = testnet_addr_pk(&pubkey(2));
        let mut art = genuine_artifact(1, 2, &template, &asset, 50_000_000, None);
        art["transaction"]["inputs"][0]["signatureScript"] = serde_json::json!("cd".repeat(70));
        let req = requirements(&recipient, &asset, 50_000_000, &template, None);
        let err = verify_stablecoin_transfer(&art["transaction"], &payer, &req).unwrap_err();
        assert_eq!(err, StablecoinReject::NoCovenantInput);
    }

    #[test]
    fn rejects_forged_ops_attestation() {
        let template = test_template();
        let asset = "ab".repeat(32);
        let payer = testnet_addr_pk(&pubkey(1));
        let recipient = testnet_addr_pk(&pubkey(2));
        let mut art = genuine_artifact(1, 2, &template, &asset, 50_000_000, None);

        // Bit-flip one byte inside the (64-byte) issuer_sig field of the
        // sigscript, keeping every length/shape the same -- this can only be
        // caught by the genuine Schnorr re-verification, not a shape check.
        let ss_hex = art["transaction"]["inputs"][0]["signatureScript"].as_str().unwrap().to_string();
        let mut ss = hex::decode(&ss_hex).unwrap();
        // self_rs is pushed first; find where issuer_sig's 64-byte payload
        // starts by re-decoding structurally.
        let (self_rs, n1) = kob_core::contract::kcc20::decode_push_explicit(&ss).unwrap();
        let _ = self_rs;
        // issuer_sig push header is 3 bytes (PUSHDATA2, since the redeem
        // script pushed just before it is well over 255 bytes making the
        // WHOLE script long, but issuer_sig itself is 64 bytes -> OP_DATA_64
        // single-byte header). Flip the first payload byte.
        let issuer_sig_payload_start = n1 + 1; // 1-byte OP_DATA_64 header
        ss[issuer_sig_payload_start] ^= 0xff;
        art["transaction"]["inputs"][0]["signatureScript"] = serde_json::json!(hex::encode(&ss));

        let req = requirements(&recipient, &asset, 50_000_000, &template, None);
        let err = verify_stablecoin_transfer(&art["transaction"], &payer, &req).unwrap_err();
        assert_eq!(err, StablecoinReject::ForgedOpsAttestation);
    }

    #[test]
    fn rejects_multiple_covenant_inputs_of_the_same_lineage() {
        let template = test_template();
        let asset = "ab".repeat(32);
        let payer = testnet_addr_pk(&pubkey(1));
        let recipient = testnet_addr_pk(&pubkey(2));
        let art1 = genuine_artifact(1, 2, &template, &asset, 50_000_000, None);
        // A second, independent TRANSFER-shaped input of the SAME lineage
        // (different payer/owner seed 3, still under the same role-key
        // template), appended as input 1 -- with only ONE output, so it does
        // not satisfy the positional index==1 successor requirement, but the
        // point here is the INPUT-side multiplicity rejection fires first.
        let art3 = genuine_artifact(3, 2, &template, &asset, 50_000_000, None);
        let mut art = art1;
        art["transaction"]["inputs"]
            .as_array_mut()
            .unwrap()
            .push(art3["transaction"]["inputs"][0].clone());

        let req = requirements(&recipient, &asset, 50_000_000, &template, None);
        let err = verify_stablecoin_transfer(&art["transaction"], &payer, &req).unwrap_err();
        assert_eq!(err, StablecoinReject::MultipleCovenantInputs);
    }

    #[test]
    fn rejects_bad_asset() {
        let template = test_template();
        let payer = testnet_addr_pk(&pubkey(1));
        let recipient = testnet_addr_pk(&pubkey(2));
        let art = genuine_artifact(1, 2, &template, &"ab".repeat(32), 50_000_000, None);
        let req = requirements(&recipient, "not-hex", 50_000_000, &template, None);
        let err = verify_stablecoin_transfer(&art["transaction"], &payer, &req).unwrap_err();
        assert!(matches!(err, StablecoinReject::BadAsset(_)));
    }

    #[test]
    fn rejects_missing_template_fields() {
        let template = test_template();
        let payer = testnet_addr_pk(&pubkey(1));
        let recipient = testnet_addr_pk(&pubkey(2));
        let asset = "ab".repeat(32);
        let art = genuine_artifact(1, 2, &template, &asset, 50_000_000, None);
        let mut req = requirements(&recipient, &asset, 50_000_000, &template, None);
        req.extra.as_object_mut().unwrap().remove("opsPubkey");
        let err = verify_stablecoin_transfer(&art["transaction"], &payer, &req).unwrap_err();
        assert!(matches!(err, StablecoinReject::BadTemplate(_)));
    }

    #[test]
    fn enforces_fingerprint_binding() {
        let template = test_template();
        let asset = "ab".repeat(32);
        let payer = testnet_addr_pk(&pubkey(1));
        let recipient = testnet_addr_pk(&pubkey(2));
        let fp = fingerprint::compute_fingerprint("GET", "/r", &recipient, "50000000", "n");
        let art = genuine_artifact(1, 2, &template, &asset, 50_000_000, Some(&fp));
        let req = requirements(&recipient, &asset, 50_000_000, &template, Some(&fp));
        assert!(verify_stablecoin_transfer(&art["transaction"], &payer, &req).is_ok());

        // Missing fingerprint when required -> reject.
        let art2 = genuine_artifact(1, 2, &template, &asset, 50_000_000, None);
        let err = verify_stablecoin_transfer(&art2["transaction"], &payer, &req).unwrap_err();
        assert_eq!(err, StablecoinReject::FingerprintMissing);
    }

    #[test]
    fn rejects_successor_template_mismatch() {
        // The sigscript's own `new_rs` claim is swapped for a DIFFERENT
        // (still validly-shaped) redeem script than the one whose P2SH the
        // actual output pays -- a self-consistency failure that must be
        // caught even though the output's SPK still matches the requirement.
        let template = test_template();
        let asset = "ab".repeat(32);
        let payer = testnet_addr_pk(&pubkey(1));
        let recipient = testnet_addr_pk(&pubkey(2));
        let mut art = genuine_artifact(1, 2, &template, &asset, 50_000_000, None);

        let ss_hex = art["transaction"]["inputs"][0]["signatureScript"].as_str().unwrap().to_string();
        let ss = hex::decode(&ss_hex).unwrap();
        let (self_rs, n1) = kob_core::contract::kcc20::decode_push_explicit(&ss).unwrap();
        let (_issuer_sig, n2) = kob_core::contract::kcc20::decode_push_explicit(&ss[n1..]).unwrap();
        let (real_new_rs, n3) = kob_core::contract::kcc20::decode_push_explicit(&ss[n1 + n2..]).unwrap();
        let _ = real_new_rs;

        // Build a decoy new_rs for a DIFFERENT recipient (seed 8) and splice
        // it in place of the real one, re-emitting the sigscript by hand
        // (push-only, same encoding `push_data` uses).
        let decoy_new_rs = reconstruct_redeem_script(&pubkey(8), &template);
        let issuer_sig_bytes = &ss[n1 + 1..n1 + 65]; // OP_DATA_64 header + 64B payload
        let mut new_ss = Vec::new();
        new_ss.extend_from_slice(&kob_core::push_data(&self_rs));
        new_ss.extend_from_slice(&kob_core::push_data(issuer_sig_bytes));
        new_ss.extend_from_slice(&kob_core::push_data(&decoy_new_rs));
        new_ss.extend_from_slice(&ss[n1 + n2 + n3..]); // owner_sig, op_type, trailing redeem_script unchanged

        art["transaction"]["inputs"][0]["signatureScript"] = serde_json::json!(hex::encode(&new_ss));
        let req = requirements(&recipient, &asset, 50_000_000, &template, None);
        let err = verify_stablecoin_transfer(&art["transaction"], &payer, &req).unwrap_err();
        assert_eq!(err, StablecoinReject::SuccessorTemplateMismatch);
    }
}
