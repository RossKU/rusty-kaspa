//! x402 v2 wire types — conformant with elldeeone/kaspa-x402 at the
//! v0.1.0-alpha.8 profile split (schemas/vectors vendored under
//! `kob/x402/interop/`, synced from upstream commit
//! `0345cbd7b8d26520b4dffe0fcc94d127acd1fcb0`). These are the interoperable
//! shapes; the KOB v1 `wire` module stays for the native/pull + KCC20
//! KOB-native path.
//!
//! alpha.7 -> alpha.8 wire diffs handled here:
//! - `extra.binding` const: `kaspa-exact-v1` -> `kaspa-exact-v2`.
//! - exact split into two profiles: `standard-native` (default; plain v0
//!   transfer, exact merchant amount) and `additive` (optional; KIP-10 head).
//! - requirements extra: `borrowOutpoint`/`borrowAmount`/`borrowScriptPublicKey`/
//!   `borrowRedeemScript`/`reservationId`/`reservationExpiresAt` are FORBIDDEN;
//!   replaced by `headId`/`headVersion`/`expectedHeadOutpoint`/`headAmount`/
//!   `headScriptPublicKey`/`headRedeemScript`/`challengeId`/`challengeExpiresAt`
//!   (+ mandatory `profile` and `payToScriptPublicKey` for every exact offer).
//! - exact-transaction payload: `requestHash` and `authorization` (signed
//!   payer request authorization) are now REQUIRED; `profile` selects the
//!   profile and `challengeId` is required for additive / forbidden for
//!   standard-native.
//! - settlement extensions: `borrowOutpoint`/`reservationId` dropped;
//!   `exactProfile`/`headId`/`headVersion`/`headOutpoint` added.
//! - closed public error enum: UNCHANGED in alpha.8.

use serde::{Deserialize, Serialize};

pub const X402_VERSION: u32 = 2;
pub const SCHEME_EXACT: &str = "exact";
pub const SCHEME_BATCH: &str = "batch-settlement";
pub const ASSET_KAS: &str = "KAS";
pub const NETWORK_MAINNET: &str = "kaspa:mainnet";
pub const NETWORK_TESTNET10: &str = "kaspa:testnet-10";

/// Strict-interop exact binding (alpha.8: v2 supersedes kaspa-exact-v1).
pub const BINDING_EXACT: &str = "kaspa-exact-v2";
/// KOB-native binding under the v2 envelope (not strict interop).
pub const BINDING_NATIVE: &str = "kaspa-native-v1";
/// KOB KCC20 token binding under the v2 envelope (not strict interop).
pub const BINDING_KCC20: &str = "kaspa-kcc20-v1";
/// KOB robust-stablecoin covenant binding under the v2 envelope (not strict
/// interop; §7.4(B) of `STABLECOIN_FOUR_AXIS_AUDIT_2026-07-20.md`, G-x1).
/// A payment under this binding is a single 1:1 TRANSFER of the KCC-0020
/// "Plan A" robust stablecoin covenant (`kob-core`'s
/// `contract::stablecoin`), NOT the generic `token_unit` covenant `kcc20`
/// verifies -- the redeem-script template differs (role pubkeys,
/// `role_registry_root`, `frozen_flag`, `epoch`) and every spend requires an
/// issuer OPS attestation, so it needs its own scheme (`scheme_stablecoin`).
pub const BINDING_STABLECOIN: &str = "kaspa-stablecoin-v1";

/// alpha.8 exact profiles. `standard-native` is the default/baseline profile
/// (plain native transfer — the "standard-transfer exact" baseline);
/// `additive` is the optional KIP-10 head profile.
pub const PROFILE_STANDARD_NATIVE: &str = "standard-native";
pub const PROFILE_ADDITIVE: &str = "additive";

pub const TEMPLATE_KIP10_ADDITIVE: &str = "kaspa-x402-kip10-additive-v1";
pub const TX_ENCODING_SAFE_JSON: &str = "kaspa-sdk-safe-json-v2.0.0";
pub const PAYLOAD_TYPE_EXACT_TX: &str = "exact-transaction";
/// Version const of the mandatory signed payer request authorization.
pub const AUTHORIZATION_VERSION: &str = "kaspa-x402-exact-request-authorization-v1";

pub const HEADER_PAYMENT_REQUIRED: &str = "PAYMENT-REQUIRED";
pub const HEADER_PAYMENT_SIGNATURE: &str = "PAYMENT-SIGNATURE";
pub const HEADER_PAYMENT_RESPONSE: &str = "PAYMENT-RESPONSE";

/// Closed public error enum (goes on the wire in `error` / `invalidReason` /
/// `errorReason`). Unchanged between alpha.7 and alpha.8 (spec/errors.md).
pub mod errors {
    pub const INVALID_X402_VERSION: &str = "invalid_x402_version";
    pub const INVALID_SCHEME: &str = "invalid_scheme";
    pub const INVALID_NETWORK: &str = "invalid_network";
    pub const INVALID_PAYMENT_REQUIREMENTS: &str = "invalid_payment_requirements";
    pub const INVALID_PAYLOAD: &str = "invalid_payload";
    pub const INVALID_TRANSACTION_STATE: &str = "invalid_transaction_state";
    pub const UNSUPPORTED_SCHEME: &str = "unsupported_scheme";
    pub const UNEXPECTED_SETTLE_ERROR: &str = "unexpected_settle_error";
}

pub fn is_valid_network(n: &str) -> bool {
    n == NETWORK_MAINNET || n == NETWORK_TESTNET10
}

pub fn is_valid_profile(p: &str) -> bool {
    p == PROFILE_STANDARD_NATIVE || p == PROFILE_ADDITIVE
}

/// Resource descriptor at the PaymentRequired top level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "mimeType", default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// An outpoint reference (`expectedHeadOutpoint`, `headOutpoint`, ...).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Outpoint {
    pub txid: String,
    pub index: u32,
}

/// One acceptable way to pay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRequirements {
    pub scheme: String,
    pub network: String,
    /// Decimal sompi string.
    pub amount: String,
    pub asset: String,
    #[serde(rename = "payTo")]
    pub pay_to: String,
    #[serde(rename = "maxTimeoutSeconds")]
    pub max_timeout_seconds: u64,
    /// Scheme-specific; for exact it carries the profile + (for additive) the
    /// KIP-10 head fields.
    pub extra: serde_json::Value,
    /// Any further top-level fields, preserved verbatim.
    ///
    /// `paymentRequirementsHash` is SHA-256 over the canonical JSON of the
    /// COMPLETE selected requirements object, and the spec is explicit that
    /// "implementations accepting additional fields MUST still include them in
    /// this canonical object and hash". Without this catch-all, an offer
    /// carrying a field we do not model would round-trip lossily and every
    /// authorization digest computed from it would disagree with the payer's.
    #[serde(flatten)]
    pub additional: serde_json::Map<String, serde_json::Value>,
}

impl PaymentRequirements {
    pub fn amount_sompi(&self) -> Result<u64, String> {
        self.amount.parse::<u64>().map_err(|_| errors::INVALID_PAYMENT_REQUIREMENTS.to_string())
    }
    pub fn binding(&self) -> Option<&str> {
        self.extra.get("binding").and_then(|v| v.as_str())
    }
    /// alpha.8 exact profile (`standard-native` | `additive`).
    pub fn profile(&self) -> Option<&str> {
        self.extra.get("profile").and_then(|v| v.as_str())
    }
    /// Serialized SPK (uint16_be version || script, hex) the server derived
    /// from `payTo`. Mandatory for every exact v2 offer; the verifier
    /// re-derives it from `payTo` and rejects disagreement.
    pub fn pay_to_script_public_key(&self) -> Option<&str> {
        self.extra.get("payToScriptPublicKey").and_then(|v| v.as_str())
    }
    pub fn template_id(&self) -> Option<&str> {
        self.extra.get("templateId").and_then(|v| v.as_str())
    }
    pub fn head_id(&self) -> Option<&str> {
        self.extra.get("headId").and_then(|v| v.as_str())
    }
    pub fn head_version(&self) -> Option<&str> {
        self.extra.get("headVersion").and_then(|v| v.as_str())
    }
    pub fn expected_head_outpoint(&self) -> Option<Outpoint> {
        serde_json::from_value(self.extra.get("expectedHeadOutpoint")?.clone()).ok()
    }
    pub fn head_amount_sompi(&self) -> Option<u64> {
        self.extra.get("headAmount")?.as_str()?.parse().ok()
    }
    pub fn head_script_public_key(&self) -> Option<&str> {
        self.extra.get("headScriptPublicKey").and_then(|v| v.as_str())
    }
    pub fn head_redeem_script(&self) -> Option<&str> {
        self.extra.get("headRedeemScript").and_then(|v| v.as_str())
    }
    pub fn additive_threshold_sompi(&self) -> Option<u64> {
        self.extra.get("additiveThresholdSompi")?.as_str()?.parse().ok()
    }
    /// Server-issued additive challenge id (alpha.8 successor of the alpha.7
    /// `reservationId` — identifies the issued terms + request binding).
    pub fn challenge_id(&self) -> Option<&str> {
        self.extra.get("challengeId").and_then(|v| v.as_str())
    }
    pub fn challenge_expires_at(&self) -> Option<&str> {
        self.extra.get("challengeExpiresAt").and_then(|v| v.as_str())
    }
    pub fn payment_output_index(&self) -> Option<u32> {
        self.extra.get("paymentOutputIndex")?.as_u64().map(|v| v as u32)
    }
    /// KOB request-fingerprint (native/KCC20 KOB-binding schemes) from
    /// `extra.fingerprint`.
    pub fn fingerprint(&self) -> Option<&str> {
        self.extra.get("fingerprint").and_then(|v| v.as_str())
    }
    /// KCC20 token covenant id (KOB-binding scheme) from `extra.assetId`.
    pub fn kcc20_covenant_id(&self) -> Option<&str> {
        self.extra.get("assetId").and_then(|v| v.as_str())
    }
}

/// 402 body / `PAYMENT-REQUIRED` header payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRequired {
    #[serde(rename = "x402Version")]
    pub x402_version: u32,
    pub resource: Resource,
    pub accepts: Vec<PaymentRequirements>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

/// The mandatory signed payer request authorization (alpha.8). Binds the
/// payment artifact to exactly one request: digest over the canonical txid,
/// profile, payment output index, amount, payTo/recipient script, accepted
/// requirements hash, normalized request hash, additive challenge (when
/// present), authorizing payer input index, and expiry — signed by the payer
/// key proven by the authoritative funding input.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExactAuthorization {
    /// MUST equal [`AUTHORIZATION_VERSION`].
    pub version: String,
    /// Index of the standard P2PK funding input whose key signed the digest
    /// (the additive head input cannot authorize the payer request).
    #[serde(rename = "inputIndex")]
    pub input_index: u32,
    /// ISO-8601 `YYYY-MM-DDTHH:MM:SS(.mmm)Z` expiry.
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    /// 32-byte digest, hex.
    pub digest: String,
    /// 64-byte Schnorr signature, hex.
    pub signature: String,
}

/// exact-transaction payload (both profiles).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExactPayload {
    #[serde(rename = "type")]
    pub kind: String,
    /// alpha.8: selected exact profile; MUST match `accepted.extra.profile`.
    pub profile: String,
    #[serde(rename = "payerAddress", default, skip_serializing_if = "Option::is_none")]
    pub payer_address: Option<String>,
    /// Encoded transaction string (per `transactionEncoding`).
    pub transaction: String,
    #[serde(rename = "transactionEncoding")]
    pub transaction_encoding: String,
    #[serde(rename = "paymentOutputIndex")]
    pub payment_output_index: u32,
    /// alpha.8: mandatory normalized request hash.
    #[serde(rename = "requestHash")]
    pub request_hash: String,
    /// Required for `additive` (must echo `accepted.extra.challengeId`);
    /// forbidden for `standard-native`.
    #[serde(rename = "challengeId", default, skip_serializing_if = "Option::is_none")]
    pub challenge_id: Option<String>,
    /// alpha.8: mandatory signed payer request authorization.
    pub authorization: ExactAuthorization,
}

/// `PAYMENT-SIGNATURE` header payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentPayload {
    #[serde(rename = "x402Version")]
    pub x402_version: u32,
    pub accepted: PaymentRequirements,
    pub payload: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

impl PaymentPayload {
    /// The scheme payload's transaction field (object for native/KCC20; encoded
    /// string for exact v2).
    pub fn transaction(&self) -> Option<&serde_json::Value> {
        self.payload.get("transaction")
    }
    /// The payer address (`payerAddress` or legacy `from`).
    pub fn payer_address(&self) -> Option<&str> {
        self.payload.get("payerAddress").or_else(|| self.payload.get("from")).and_then(|v| v.as_str())
    }
    pub fn payload_type(&self) -> Option<&str> {
        self.payload.get("type").and_then(|v| v.as_str())
    }
    pub fn profile(&self) -> Option<&str> {
        self.payload.get("profile").and_then(|v| v.as_str())
    }
    pub fn request_hash(&self) -> Option<&str> {
        self.payload.get("requestHash").and_then(|v| v.as_str())
    }
    pub fn challenge_id(&self) -> Option<&str> {
        self.payload.get("challengeId").and_then(|v| v.as_str())
    }
    pub fn authorization(&self) -> Option<ExactAuthorization> {
        serde_json::from_value(self.payload.get("authorization")?.clone()).ok()
    }
}

/// Facilitator `/verify` and `/settle` request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FacilitatorRequest {
    #[serde(rename = "x402Version", default)]
    pub x402_version: u32,
    #[serde(rename = "paymentPayload")]
    pub payment_payload: PaymentPayload,
    #[serde(rename = "paymentRequirements")]
    pub payment_requirements: PaymentRequirements,
    /// alpha.8 facilitator profile: the RESOURCE SERVER's independently
    /// computed request hash. For exact, `payload.requestHash` is evidence to
    /// compare against this, never an independent statement of the request.
    #[serde(rename = "requestHash", default, skip_serializing_if = "Option::is_none")]
    pub request_hash: Option<String>,
    /// Optional resource identifier (alpha.8 facilitator profile).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

/// Pull-mode `/await` request body (no payment payload — the client broadcasts
/// itself; the facilitator discovers).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwaitRequest {
    #[serde(rename = "x402Version", default)]
    pub x402_version: u32,
    #[serde(rename = "paymentRequirements")]
    pub payment_requirements: PaymentRequirements,
}

/// `/reserve` request (KOB-internal provisioning API, not upstream interop):
/// register a KIP-10 additive borrow/head reservation for an already-funded
/// outpoint and get back the v2 `PaymentRequired` (additive-profile offer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReserveRequest {
    #[serde(rename = "payTo")]
    pub pay_to: String,
    /// Payment price (sompi string).
    pub amount: String,
    #[serde(rename = "borrowTxid")]
    pub borrow_txid: String,
    #[serde(rename = "borrowIndex")]
    pub borrow_index: u32,
    #[serde(rename = "borrowAmount")]
    pub borrow_amount: String,
    #[serde(rename = "additiveThresholdSompi")]
    pub additive_threshold: String,
    #[serde(rename = "paymentOutputIndex", default)]
    pub payment_output_index: u32,
    #[serde(rename = "resourceUrl", default)]
    pub resource_url: String,
    /// Optional expected request hash to bind the payment to (64-hex).
    #[serde(rename = "requestHash", default, skip_serializing_if = "Option::is_none")]
    pub request_hash: Option<String>,
}

/// `/verify` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    #[serde(rename = "isValid")]
    pub is_valid: bool,
    #[serde(rename = "invalidReason", default, skip_serializing_if = "Option::is_none")]
    pub invalid_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
}

impl VerifyResponse {
    pub fn valid(payer: impl Into<String>) -> Self {
        Self { is_valid: true, invalid_reason: None, payer: Some(payer.into()) }
    }
    pub fn invalid(code: &str) -> Self {
        Self { is_valid: false, invalid_reason: Some(code.to_string()), payer: None }
    }
}

/// Kaspa settlement extension block (alpha.8: `borrowOutpoint`/`reservationId`
/// dropped from the schema; `exactProfile` + head lineage fields added).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KaspaSettleExt {
    #[serde(rename = "exactProfile", default, skip_serializing_if = "Option::is_none")]
    pub exact_profile: Option<String>,
    #[serde(rename = "paymentOutputIndex", default, skip_serializing_if = "Option::is_none")]
    pub payment_output_index: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finality: Option<String>,
    #[serde(rename = "requestHash", default, skip_serializing_if = "Option::is_none")]
    pub request_hash: Option<String>,
    #[serde(rename = "transactionEncoding", default, skip_serializing_if = "Option::is_none")]
    pub transaction_encoding: Option<String>,
    #[serde(rename = "templateId", default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    #[serde(rename = "headId", default, skip_serializing_if = "Option::is_none")]
    pub head_id: Option<String>,
    #[serde(rename = "headVersion", default, skip_serializing_if = "Option::is_none")]
    pub head_version: Option<String>,
    /// The consumed (previous) head outpoint.
    #[serde(rename = "headOutpoint", default, skip_serializing_if = "Option::is_none")]
    pub head_outpoint: Option<Outpoint>,
    #[serde(rename = "continuationOutpoint", default, skip_serializing_if = "Option::is_none")]
    pub continuation_outpoint: Option<Outpoint>,
    /// Additive challenge id (schema-open extension field; in the spec's
    /// additive success example).
    #[serde(rename = "challengeId", default, skip_serializing_if = "Option::is_none")]
    pub challenge_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementExtensions {
    pub kaspa: KaspaSettleExt,
}

/// `/settle` response / `PAYMENT-RESPONSE` header payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementResponse {
    pub success: bool,
    /// 64-hex on success; empty string on failure.
    pub transaction: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    #[serde(rename = "errorReason", default, skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<SettlementExtensions>,
}

impl SettlementResponse {
    pub fn ok(network: &str, txid: &str, amount: u64, payer: Option<String>, ext: KaspaSettleExt) -> Self {
        Self {
            success: true,
            transaction: txid.to_string(),
            network: Some(network.to_string()),
            payer,
            amount: Some(amount.to_string()),
            error_reason: None,
            extensions: Some(SettlementExtensions { kaspa: ext }),
        }
    }
    pub fn failed(code: &str) -> Self {
        Self {
            success: false,
            transaction: String::new(),
            network: None,
            payer: None,
            amount: None,
            error_reason: Some(code.to_string()),
            extensions: None,
        }
    }
}

/// `/supported` kind + response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedKind {
    #[serde(rename = "x402Version")]
    pub x402_version: u32,
    pub scheme: String,
    pub network: String,
    pub extra: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedResponse {
    pub kinds: Vec<SupportedKind>,
    pub extensions: Vec<serde_json::Value>,
    pub signers: serde_json::Value,
}

impl SupportedResponse {
    /// The exact scheme only (no batch-settlement), advertising both alpha.8
    /// profiles. `standard-native` is the default profile; `extra.profiles`
    /// is authoritative for this facilitator instance.
    pub fn exact_only(network: &str) -> Self {
        Self {
            kinds: vec![SupportedKind {
                x402_version: X402_VERSION,
                scheme: SCHEME_EXACT.to_string(),
                network: network.to_string(),
                extra: serde_json::json!({
                    "asset": ASSET_KAS,
                    "binding": BINDING_EXACT,
                    "defaultProfile": PROFILE_STANDARD_NATIVE,
                    "profiles": [PROFILE_STANDARD_NATIVE, PROFILE_ADDITIVE],
                    "modes": ["verify", "settle"],
                }),
            }],
            extensions: vec![],
            signers: serde_json::json!({}),
        }
    }
}

/// Base64(JSON) header codec for the PAYMENT-* headers.
pub fn encode_header<T: Serialize>(v: &T) -> Result<String, String> {
    use base64::Engine;
    let json = serde_json::to_vec(v).map_err(|e| e.to_string())?;
    Ok(base64::engine::general_purpose::STANDARD.encode(json))
}

pub fn decode_header<T: for<'de> Deserialize<'de>>(header: &str) -> Result<T, String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(header.trim())
        .map_err(|_| errors::INVALID_PAYLOAD.to_string())?;
    serde_json::from_slice(&bytes).map_err(|_| errors::INVALID_PAYLOAD.to_string())
}

// ---------------------------------------------------------------------------
// ISO-8601 helpers (challengeExpiresAt / authorization.expiresAt) — the wire
// format is `YYYY-MM-DDTHH:MM:SS(.mmm)Z` (UTC only). No chrono dependency:
// civil-from-days / days-from-civil (Howard Hinnant's algorithms).
// ---------------------------------------------------------------------------

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe as i64 - 719_468
}

/// Format unix seconds as `YYYY-MM-DDTHH:MM:SS.000Z`.
pub fn iso8601_from_unix_secs(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.000Z",
        y, m, d, rem / 3600, (rem % 3600) / 60, rem % 60
    )
}

/// Parse `YYYY-MM-DDTHH:MM:SS(.mmm)?Z` (UTC, per the vendored schema pattern)
/// to unix seconds (milliseconds truncated). `None` on anything else.
pub fn unix_secs_from_iso8601(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() != 20 && b.len() != 24 {
        return None;
    }
    if b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || b[b.len() - 1] != b'Z' {
        return None;
    }
    if b.len() == 24 && b[19] != b'.' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u64> { s.get(r)?.parse().ok() };
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hh, mm, ss) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if b.len() == 24 {
        num(20..23)?; // millis must be digits (value truncated)
    }
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 59 {
        return None;
    }
    let days = days_from_civil(y as i64, m as u32, d as u32);
    if days < 0 {
        return None;
    }
    Some(days as u64 * 86_400 + hh * 3600 + mm * 60 + ss)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vendored alpha.8 schemas (upstream commit 0345cbd7b8d26520b4dffe0fcc94d127acd1fcb0).
    const SCHEMA_PAYMENT_REQUIRED: &str =
        include_str!("../interop/schemas/payment-required.schema.json");
    const SCHEMA_PAYMENT_PAYLOAD: &str =
        include_str!("../interop/schemas/payment-payload.schema.json");
    const SCHEMA_KASPA_PAYMENT_PAYLOAD: &str =
        include_str!("../interop/schemas/kaspa-payment-payload.schema.json");
    const SCHEMA_REQUIREMENTS_EXTRA: &str =
        include_str!("../interop/schemas/kaspa-requirements-extra.schema.json");
    const SCHEMA_SETTLEMENT_RESPONSE: &str =
        include_str!("../interop/schemas/settlement-response.schema.json");

    fn schema(s: &str) -> serde_json::Value {
        serde_json::from_str(s).unwrap()
    }

    /// Recursively collect every `"key": {"const": <string>}` pair in a schema.
    fn collect_consts(v: &serde_json::Value, out: &mut Vec<(String, String)>) {
        if let Some(map) = v.as_object() {
            for (k, val) in map {
                if let Some(c) = val.get("const").and_then(|c| c.as_str()) {
                    out.push((k.clone(), c.to_string()));
                }
                collect_consts(val, out);
            }
        } else if let Some(arr) = v.as_array() {
            for val in arr {
                collect_consts(val, out);
            }
        }
    }

    fn binding_consts(v: &serde_json::Value) -> Vec<String> {
        let mut all = Vec::new();
        collect_consts(v, &mut all);
        all.into_iter().filter(|(k, _)| k == "binding").map(|(_, c)| c).collect()
    }

    fn sample_additive_requirements() -> PaymentRequirements {
        PaymentRequirements {
            scheme: SCHEME_EXACT.to_string(),
            network: NETWORK_TESTNET10.to_string(),
            amount: "20000000".to_string(),
            asset: ASSET_KAS.to_string(),
            pay_to: "kaspatest:payout".to_string(),
            max_timeout_seconds: 60,
            extra: serde_json::json!({
                "binding": BINDING_EXACT,
                "profile": PROFILE_ADDITIVE,
                "finality": "accepted",
                "transactionEncoding": TX_ENCODING_SAFE_JSON,
                "payToScriptPublicKey": format!("0000{}", "cd".repeat(34)),
                "templateId": TEMPLATE_KIP10_ADDITIVE,
                "headId": "90".repeat(32),
                "headVersion": "0",
                "expectedHeadOutpoint": { "txid": "ab".repeat(32), "index": 0 },
                "headAmount": "100000000",
                "headScriptPublicKey": format!("0000{}", "aa".repeat(35)),
                "headRedeemScript": "ef".repeat(40),
                "additiveThresholdSompi": "10000000",
                "challengeId": "12".repeat(32),
                "challengeExpiresAt": "2099-01-01T00:00:00.000Z",
                "paymentOutputIndex": 0,
                "assetKind": "native",
                "assetDecimals": 8
            }),
            additional: Default::default(),
        }
    }

    fn sample_standard_native_requirements() -> PaymentRequirements {
        PaymentRequirements {
            scheme: SCHEME_EXACT.to_string(),
            network: NETWORK_TESTNET10.to_string(),
            amount: "20000000".to_string(),
            asset: ASSET_KAS.to_string(),
            pay_to: "kaspatest:payout".to_string(),
            max_timeout_seconds: 60,
            extra: serde_json::json!({
                "binding": BINDING_EXACT,
                "profile": PROFILE_STANDARD_NATIVE,
                "finality": "accepted",
                "transactionEncoding": TX_ENCODING_SAFE_JSON,
                "payToScriptPublicKey": format!("0000{}", "cd".repeat(34)),
                "assetKind": "native",
                "assetDecimals": 8
            }),
            additional: Default::default(),
        }
    }

    fn sample_authorization() -> ExactAuthorization {
        ExactAuthorization {
            version: AUTHORIZATION_VERSION.to_string(),
            input_index: 1,
            expires_at: "2099-01-01T00:00:00.000Z".to_string(),
            digest: "ce".repeat(32),
            signature: "ab".repeat(64),
        }
    }

    // Schema invariants (checked against the vendored alpha.8 schema files).
    fn assert_amount_pattern(s: &str) {
        assert!(s.parse::<u64>().is_ok() && (s == "0" || !s.starts_with('0')), "amount not a canonical sompi string: {}", s);
    }
    fn assert_hash32(s: &str) {
        assert!(s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn schema_binding_const_is_exact_v2() {
        // alpha.8: the exact binding const flipped kaspa-exact-v1 -> v2 in
        // payment-required + requirements-extra; kaspa-exact-v1 is gone.
        for s in [SCHEMA_PAYMENT_REQUIRED, SCHEMA_REQUIREMENTS_EXTRA, SCHEMA_PAYMENT_PAYLOAD] {
            let consts = binding_consts(&schema(s));
            assert!(consts.iter().any(|c| c == BINDING_EXACT), "kaspa-exact-v2 missing in schema");
            assert!(!consts.iter().any(|c| c == "kaspa-exact-v1"), "stale kaspa-exact-v1 in schema");
        }
    }

    #[test]
    fn schema_profile_enum_matches_constants() {
        let s = schema(SCHEMA_REQUIREMENTS_EXTRA);
        let e = &s["oneOf"][0]["properties"]["profile"]["enum"];
        assert_eq!(e[0], PROFILE_STANDARD_NATIVE);
        assert_eq!(e[1], PROFILE_ADDITIVE);
        assert_eq!(e.as_array().unwrap().len(), 2);
    }

    #[test]
    fn additive_requirements_conform_to_vendored_schema() {
        let pr = PaymentRequired {
            x402_version: X402_VERSION,
            resource: Resource {
                url: "https://api.example.test/file".to_string(),
                description: Some("Fixed price download".to_string()),
                mime_type: Some("application/octet-stream".to_string()),
            },
            accepts: vec![sample_additive_requirements()],
            error: None,
            extensions: None,
        };
        let v = serde_json::to_value(&pr).unwrap();
        // payment-required.schema.json: required x402Version(const 2), resource(url), accepts(minItems 1)
        assert_eq!(v["x402Version"], 2);
        assert!(v["resource"]["url"].is_string());
        assert!(v["accepts"].as_array().unwrap().len() >= 1);
        let req = &v["accepts"][0];
        assert_eq!(req["scheme"], "exact");
        assert_eq!(req["asset"], "KAS");
        assert_amount_pattern(req["amount"].as_str().unwrap());
        assert!(is_valid_network(req["network"].as_str().unwrap()));
        let extra = &req["extra"];

        // Common required set from the vendored kaspa-requirements-extra schema.
        let s = schema(SCHEMA_REQUIREMENTS_EXTRA);
        for k in s["oneOf"][0]["required"].as_array().unwrap() {
            assert!(extra.get(k.as_str().unwrap()).is_some(), "extra missing required {}", k);
        }
        // Additive branch (else): full head/challenge set, paymentOutputIndex const 0.
        let else_req = &s["oneOf"][0]["allOf"][0]["else"]["required"];
        for k in else_req.as_array().unwrap() {
            assert!(extra.get(k.as_str().unwrap()).is_some(), "additive extra missing {}", k);
        }
        assert_eq!(extra["paymentOutputIndex"], 0, "additive requires paymentOutputIndex const 0");
        // alpha.7 borrow*/reservation* fields are forbidden by the schema.
        let forbidden = &s["oneOf"][0]["allOf"][1]["not"]["anyOf"];
        for f in forbidden.as_array().unwrap() {
            let k = f["required"][0].as_str().unwrap();
            assert!(extra.get(k).is_none(), "forbidden alpha.7 field {} present", k);
        }
        assert_eq!(extra["binding"], BINDING_EXACT);
        assert_eq!(extra["templateId"], TEMPLATE_KIP10_ADDITIVE);
        assert_hash32(extra["expectedHeadOutpoint"]["txid"].as_str().unwrap());
        assert_hash32(extra["challengeId"].as_str().unwrap());
        assert!(extra["headScriptPublicKey"].as_str().unwrap().starts_with("0000"));
    }

    #[test]
    fn standard_native_requirements_conform_to_vendored_schema() {
        let req = sample_standard_native_requirements();
        let v = serde_json::to_value(&req).unwrap();
        let extra = &v["extra"];
        let s = schema(SCHEMA_REQUIREMENTS_EXTRA);
        for k in s["oneOf"][0]["required"].as_array().unwrap() {
            assert!(extra.get(k.as_str().unwrap()).is_some(), "extra missing required {}", k);
        }
        // standard-native (then): head/challenge/template fields MUST be absent.
        let banned = &s["oneOf"][0]["allOf"][0]["then"]["not"]["anyOf"];
        for f in banned.as_array().unwrap() {
            let k = f["required"][0].as_str().unwrap();
            assert!(extra.get(k).is_none(), "standard-native must not carry {}", k);
        }
        assert_eq!(extra["profile"], PROFILE_STANDARD_NATIVE);
        // Accessors.
        assert_eq!(req.profile(), Some(PROFILE_STANDARD_NATIVE));
        assert!(req.pay_to_script_public_key().unwrap().starts_with("0000"));
        assert!(req.challenge_id().is_none());
    }

    #[test]
    fn payment_payload_conforms_to_vendored_schema() {
        let payload = ExactPayload {
            kind: PAYLOAD_TYPE_EXACT_TX.to_string(),
            profile: PROFILE_ADDITIVE.to_string(),
            payer_address: Some("kaspatest:refund".to_string()),
            transaction: "{}".to_string(),
            transaction_encoding: TX_ENCODING_SAFE_JSON.to_string(),
            payment_output_index: 0,
            request_hash: "99".repeat(32),
            challenge_id: Some("12".repeat(32)),
            authorization: sample_authorization(),
        };
        let pp = PaymentPayload {
            x402_version: X402_VERSION,
            accepted: sample_additive_requirements(),
            payload: serde_json::to_value(&payload).unwrap(),
            extensions: None,
        };
        let v = serde_json::to_value(&pp).unwrap();
        assert_eq!(v["x402Version"], 2);
        assert!(v["accepted"].is_object());

        // kaspa-payment-payload.schema.json exact-transaction branch: alpha.8
        // added requestHash + authorization to the required set.
        let s = schema(SCHEMA_KASPA_PAYMENT_PAYLOAD);
        let branch = s["allOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|b| b["if"]["properties"]["type"]["const"] == PAYLOAD_TYPE_EXACT_TX)
            .unwrap();
        let required: Vec<&str> =
            branch["then"]["required"].as_array().unwrap().iter().map(|k| k.as_str().unwrap()).collect();
        assert!(required.contains(&"requestHash"), "alpha.8 requires requestHash");
        assert!(required.contains(&"authorization"), "alpha.8 requires authorization");
        for k in &required {
            assert!(v["payload"].get(*k).is_some(), "payload missing required {}", k);
        }
        assert!(v["payload"].get("transactionId").is_none(), "transactionId forbidden for exact-transaction");

        // authorization shape: version const from the schema == our constant.
        assert_eq!(
            s["properties"]["authorization"]["properties"]["version"]["const"],
            AUTHORIZATION_VERSION
        );
        assert_eq!(v["payload"]["authorization"]["version"], AUTHORIZATION_VERSION);
        assert_hash32(v["payload"]["authorization"]["digest"].as_str().unwrap());
        assert_eq!(v["payload"]["authorization"]["signature"].as_str().unwrap().len(), 128);

        // payment-payload.schema.json conditionals: additive payload requires
        // profile + challengeId; standard-native forbids challengeId.
        assert_eq!(v["payload"]["profile"], PROFILE_ADDITIVE);
        assert_hash32(v["payload"]["challengeId"].as_str().unwrap());

        // Accessor coverage.
        assert_eq!(pp.profile(), Some(PROFILE_ADDITIVE));
        assert_eq!(pp.challenge_id().unwrap(), "12".repeat(32));
        assert_eq!(pp.authorization().unwrap(), sample_authorization());
    }

    #[test]
    fn settlement_response_conforms_success_and_failure() {
        let ok = SettlementResponse::ok(
            NETWORK_TESTNET10,
            &"77".repeat(32),
            20_000_000,
            Some("kaspatest:refund".to_string()),
            KaspaSettleExt {
                exact_profile: Some(PROFILE_ADDITIVE.to_string()),
                payment_output_index: Some(0),
                finality: Some("accepted".to_string()),
                transaction_encoding: Some(TX_ENCODING_SAFE_JSON.to_string()),
                template_id: Some(TEMPLATE_KIP10_ADDITIVE.to_string()),
                head_id: Some("90".repeat(32)),
                head_version: Some("0".to_string()),
                head_outpoint: Some(Outpoint { txid: "ab".repeat(32), index: 0 }),
                ..Default::default()
            },
        );
        let v = serde_json::to_value(&ok).unwrap();
        // settlement-response.schema.json success branch: network + amount
        // required, transaction 64-hex, no top-level extra.
        assert_eq!(v["success"], true);
        assert_hash32(v["transaction"].as_str().unwrap());
        assert!(is_valid_network(v["network"].as_str().unwrap()));
        assert_amount_pattern(v["amount"].as_str().unwrap());
        assert!(v.get("extra").is_none(), "top-level extra forbidden");
        let ext = &v["extensions"]["kaspa"];
        assert_eq!(ext["exactProfile"], PROFILE_ADDITIVE);

        // The vendored alpha.8 extension schema dropped borrowOutpoint /
        // reservationId and added exactProfile/headId/headVersion/headOutpoint.
        let s = schema(SCHEMA_SETTLEMENT_RESPONSE);
        let props = s["$defs"]["kaspaSettlementExtension"]["properties"].as_object().unwrap();
        for k in ["exactProfile", "headId", "headVersion", "headOutpoint", "continuationOutpoint"] {
            assert!(props.contains_key(k), "schema missing alpha.8 field {}", k);
        }
        for k in ["borrowOutpoint", "reservationId"] {
            assert!(!props.contains_key(k), "stale alpha.7 field {} in schema", k);
            assert!(ext.get(k).is_none(), "we must not emit alpha.7 field {}", k);
        }
        assert_eq!(props["exactProfile"]["enum"][0], PROFILE_STANDARD_NATIVE);
        assert_eq!(props["exactProfile"]["enum"][1], PROFILE_ADDITIVE);

        let fail = SettlementResponse::failed(errors::INVALID_TRANSACTION_STATE);
        let fv = serde_json::to_value(&fail).unwrap();
        // failure branch: errorReason required.
        assert_eq!(fv["success"], false);
        assert_eq!(fv["errorReason"], errors::INVALID_TRANSACTION_STATE);
    }

    #[test]
    fn supported_advertises_profile_split() {
        let s = SupportedResponse::exact_only(NETWORK_TESTNET10);
        let v = serde_json::to_value(&s).unwrap();
        let k = &v["kinds"][0];
        assert_eq!(k["x402Version"], 2);
        assert_eq!(k["scheme"], "exact");
        assert_eq!(k["extra"]["asset"], "KAS");
        assert_eq!(k["extra"]["binding"], BINDING_EXACT);
        // alpha.8 facilitator profile: defaultProfile + authoritative profiles list.
        assert_eq!(k["extra"]["defaultProfile"], PROFILE_STANDARD_NATIVE);
        assert_eq!(k["extra"]["profiles"][0], PROFILE_STANDARD_NATIVE);
        assert_eq!(k["extra"]["profiles"][1], PROFILE_ADDITIVE);
        assert_eq!(k["extra"]["modes"][0], "verify");
        assert!(v["extensions"].is_array());
        assert!(v["signers"].is_object());
    }

    #[test]
    fn header_codec_roundtrips() {
        let s = SupportedResponse::exact_only(NETWORK_TESTNET10);
        let h = encode_header(&s).unwrap();
        let back: SupportedResponse = decode_header(&h).unwrap();
        assert_eq!(back.kinds.len(), 1);
    }

    #[test]
    fn error_codes_are_the_closed_enum() {
        for c in [
            errors::INVALID_X402_VERSION, errors::INVALID_SCHEME, errors::INVALID_NETWORK,
            errors::INVALID_PAYMENT_REQUIREMENTS, errors::INVALID_PAYLOAD,
            errors::INVALID_TRANSACTION_STATE, errors::UNSUPPORTED_SCHEME,
            errors::UNEXPECTED_SETTLE_ERROR,
        ] {
            assert!(c.starts_with("invalid_") || c.starts_with("unsupported_") || c.starts_with("unexpected_"));
        }
    }

    #[test]
    fn iso8601_helpers_roundtrip_and_validate() {
        // Round-trip at a known instant.
        assert_eq!(iso8601_from_unix_secs(0), "1970-01-01T00:00:00.000Z");
        let t = 1_763_000_000u64;
        assert_eq!(unix_secs_from_iso8601(&iso8601_from_unix_secs(t)), Some(t));
        // Upstream vector expiry parses and is far in the future.
        let v = unix_secs_from_iso8601("2099-01-01T00:00:00.000Z").unwrap();
        assert!(v > 4_000_000_000);
        // Without millis (schema allows both).
        assert_eq!(unix_secs_from_iso8601("2099-01-01T00:00:00Z"), Some(v));
        // Garbage is refused.
        for bad in ["", "2099-01-01", "2099-01-01T00:00:00", "2099-13-01T00:00:00Z", "2099-01-01 00:00:00Z"] {
            assert!(unix_secs_from_iso8601(bad).is_none(), "{} must not parse", bad);
        }
    }
}
