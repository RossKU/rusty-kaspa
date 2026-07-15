//! x402 v2 wire types — conformant with elldeeone/kaspa-x402 (schemas vendored
//! under `kob/x402/interop/`). These are the interoperable shapes; the KOB v1
//! `wire` module stays for the native/pull + KCC20 KOB-native path.

use serde::{Deserialize, Serialize};

pub const X402_VERSION: u32 = 2;
pub const SCHEME_EXACT: &str = "exact";
pub const SCHEME_BATCH: &str = "batch-settlement";
pub const ASSET_KAS: &str = "KAS";
pub const NETWORK_MAINNET: &str = "kaspa:mainnet";
pub const NETWORK_TESTNET10: &str = "kaspa:testnet-10";

pub const BINDING_EXACT: &str = "kaspa-exact-v1";
/// KOB-native binding under the v2 envelope (not strict interop).
pub const BINDING_NATIVE: &str = "kaspa-native-v1";
/// KOB KCC20 token binding under the v2 envelope (not strict interop).
pub const BINDING_KCC20: &str = "kaspa-kcc20-v1";
pub const TEMPLATE_KIP10_ADDITIVE: &str = "kaspa-x402-kip10-additive-v1";
pub const TX_ENCODING_SAFE_JSON: &str = "kaspa-sdk-safe-json-v2.0.0";
pub const PAYLOAD_TYPE_EXACT_TX: &str = "exact-transaction";

pub const HEADER_PAYMENT_REQUIRED: &str = "PAYMENT-REQUIRED";
pub const HEADER_PAYMENT_SIGNATURE: &str = "PAYMENT-SIGNATURE";
pub const HEADER_PAYMENT_RESPONSE: &str = "PAYMENT-RESPONSE";

/// Closed public error enum (goes on the wire in `error` / `invalidReason` /
/// `errorReason`).
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

/// Resource descriptor at the PaymentRequired top level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "mimeType", default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// A KIP-10 additive outpoint reference.
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
    /// Scheme-specific; for exact it carries the KIP-10 additive fields.
    pub extra: serde_json::Value,
}

impl PaymentRequirements {
    pub fn amount_sompi(&self) -> Result<u64, String> {
        self.amount.parse::<u64>().map_err(|_| errors::INVALID_PAYMENT_REQUIREMENTS.to_string())
    }
    pub fn binding(&self) -> Option<&str> {
        self.extra.get("binding").and_then(|v| v.as_str())
    }
    pub fn template_id(&self) -> Option<&str> {
        self.extra.get("templateId").and_then(|v| v.as_str())
    }
    pub fn borrow_outpoint(&self) -> Option<Outpoint> {
        serde_json::from_value(self.extra.get("borrowOutpoint")?.clone()).ok()
    }
    pub fn borrow_amount_sompi(&self) -> Option<u64> {
        self.extra.get("borrowAmount")?.as_str()?.parse().ok()
    }
    pub fn additive_threshold_sompi(&self) -> Option<u64> {
        self.extra.get("additiveThresholdSompi")?.as_str()?.parse().ok()
    }
    pub fn payment_output_index(&self) -> Option<u32> {
        self.extra.get("paymentOutputIndex")?.as_u64().map(|v| v as u32)
    }
    pub fn reservation_id(&self) -> Option<&str> {
        self.extra.get("reservationId").and_then(|v| v.as_str())
    }
    pub fn borrow_redeem_script(&self) -> Option<&str> {
        self.extra.get("borrowRedeemScript").and_then(|v| v.as_str())
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

/// exact-transaction payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExactPayload {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(rename = "payerAddress", default, skip_serializing_if = "Option::is_none")]
    pub payer_address: Option<String>,
    /// Encoded transaction string (per `transactionEncoding`).
    pub transaction: String,
    #[serde(rename = "transactionEncoding")]
    pub transaction_encoding: String,
    #[serde(rename = "paymentOutputIndex")]
    pub payment_output_index: u32,
    #[serde(rename = "requestHash", default, skip_serializing_if = "Option::is_none")]
    pub request_hash: Option<String>,
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
    /// string for KIP-10 exact).
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
    pub fn request_hash(&self) -> Option<&str> {
        self.payload.get("requestHash").and_then(|v| v.as_str())
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

/// `/reserve` request: register a KIP-10 additive borrow reservation for an
/// already-funded borrow outpoint and get back the v2 `PaymentRequired`.
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

/// Kaspa settlement extension block.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KaspaSettleExt {
    #[serde(rename = "paymentOutputIndex", default, skip_serializing_if = "Option::is_none")]
    pub payment_output_index: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finality: Option<String>,
    #[serde(rename = "requestHash", default, skip_serializing_if = "Option::is_none")]
    pub request_hash: Option<String>,
    #[serde(rename = "templateId", default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    #[serde(rename = "reservationId", default, skip_serializing_if = "Option::is_none")]
    pub reservation_id: Option<String>,
    #[serde(rename = "borrowOutpoint", default, skip_serializing_if = "Option::is_none")]
    pub borrow_outpoint: Option<Outpoint>,
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
    pub fn exact_only(network: &str) -> Self {
        Self {
            kinds: vec![SupportedKind {
                x402_version: X402_VERSION,
                scheme: SCHEME_EXACT.to_string(),
                network: network.to_string(),
                extra: serde_json::json!({
                    "asset": ASSET_KAS,
                    "binding": BINDING_EXACT,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_exact_requirements() -> PaymentRequirements {
        PaymentRequirements {
            scheme: SCHEME_EXACT.to_string(),
            network: NETWORK_TESTNET10.to_string(),
            amount: "250".to_string(),
            asset: ASSET_KAS.to_string(),
            pay_to: "kaspatest:payout".to_string(),
            max_timeout_seconds: 60,
            extra: serde_json::json!({
                "binding": BINDING_EXACT,
                "finality": "accepted",
                "templateId": TEMPLATE_KIP10_ADDITIVE,
                "transactionEncoding": TX_ENCODING_SAFE_JSON,
                "borrowOutpoint": { "txid": "ab".repeat(32), "index": 0 },
                "borrowAmount": "100000000",
                "borrowScriptPublicKey": format!("0000{}", "cd".repeat(35)),
                "borrowRedeemScript": "ef".repeat(40),
                "additiveThresholdSompi": "1000",
                "paymentOutputIndex": 0,
                "reservationId": "12".repeat(32),
                "assetKind": "native",
                "assetDecimals": 8
            }),
        }
    }

    // Schema invariants extracted from kob/x402/interop/schemas/*.json.
    fn assert_amount_pattern(s: &str) {
        assert!(s.parse::<u64>().is_ok() && (s == "0" || !s.starts_with('0')), "amount not a canonical sompi string: {}", s);
    }
    fn assert_hash32(s: &str) {
        assert!(s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn payment_required_conforms() {
        let pr = PaymentRequired {
            x402_version: X402_VERSION,
            resource: Resource {
                url: "https://api.example.test/file".to_string(),
                description: Some("Fixed price download".to_string()),
                mime_type: Some("application/octet-stream".to_string()),
            },
            accepts: vec![sample_exact_requirements()],
            error: None,
            extensions: None,
        };
        let v = serde_json::to_value(&pr).unwrap();
        // payment-required.schema.json: required x402Version(const 2), resource(url), accepts(minItems 1)
        assert_eq!(v["x402Version"], 2);
        assert!(v["resource"]["url"].is_string());
        assert!(v["accepts"].as_array().unwrap().len() >= 1);
        let req = &v["accepts"][0];
        // basePaymentRequirements: scheme in {exact,batch}, asset const KAS, extra.binding const
        assert_eq!(req["scheme"], "exact");
        assert_eq!(req["asset"], "KAS");
        assert_amount_pattern(req["amount"].as_str().unwrap());
        assert!(is_valid_network(req["network"].as_str().unwrap()));
        assert_eq!(req["extra"]["binding"], BINDING_EXACT);
        // dependentRequired: templateId => all borrow fields present
        assert_eq!(req["extra"]["templateId"], TEMPLATE_KIP10_ADDITIVE);
        assert_eq!(req["extra"]["transactionEncoding"], TX_ENCODING_SAFE_JSON);
        assert_hash32(req["extra"]["borrowOutpoint"]["txid"].as_str().unwrap());
        assert!(req["extra"]["borrowScriptPublicKey"].as_str().unwrap().starts_with("0000"));
        assert_hash32(req["extra"]["reservationId"].as_str().unwrap());
    }

    #[test]
    fn payment_payload_conforms() {
        let payload = ExactPayload {
            kind: PAYLOAD_TYPE_EXACT_TX.to_string(),
            payer_address: Some("kaspatest:refund".to_string()),
            transaction: "aa".to_string(),
            transaction_encoding: TX_ENCODING_SAFE_JSON.to_string(),
            payment_output_index: 0,
            request_hash: Some("99".repeat(32)),
        };
        let pp = PaymentPayload {
            x402_version: X402_VERSION,
            accepted: sample_exact_requirements(),
            payload: serde_json::to_value(&payload).unwrap(),
            extensions: None,
        };
        let v = serde_json::to_value(&pp).unwrap();
        // payment-payload.schema.json: required x402Version(2), accepted, payload
        assert_eq!(v["x402Version"], 2);
        assert!(v["accepted"].is_object());
        // kaspa-payment-payload: exact-transaction requires type, transaction, transactionEncoding, paymentOutputIndex; forbids transactionId
        assert_eq!(v["payload"]["type"], PAYLOAD_TYPE_EXACT_TX);
        assert!(v["payload"]["transaction"].as_str().unwrap().len() >= 1);
        assert_eq!(v["payload"]["transactionEncoding"], TX_ENCODING_SAFE_JSON);
        assert!(v["payload"]["paymentOutputIndex"].is_number());
        assert!(v["payload"].get("transactionId").is_none(), "transactionId forbidden for exact-transaction");
    }

    #[test]
    fn settlement_response_conforms_success_and_failure() {
        let ok = SettlementResponse::ok(
            NETWORK_TESTNET10,
            &"77".repeat(32),
            250,
            Some("kaspatest:refund".to_string()),
            KaspaSettleExt { payment_output_index: Some(0), finality: Some("accepted".to_string()), ..Default::default() },
        );
        let v = serde_json::to_value(&ok).unwrap();
        // settlement-response.schema.json success branch: network + amount required, transaction 64-hex, no top-level extra
        assert_eq!(v["success"], true);
        assert_hash32(v["transaction"].as_str().unwrap());
        assert!(is_valid_network(v["network"].as_str().unwrap()));
        assert_amount_pattern(v["amount"].as_str().unwrap());
        assert!(v.get("extra").is_none(), "top-level extra forbidden");
        assert!(v["extensions"]["kaspa"].is_object());

        let fail = SettlementResponse::failed(errors::INVALID_TRANSACTION_STATE);
        let fv = serde_json::to_value(&fail).unwrap();
        // failure branch: errorReason required
        assert_eq!(fv["success"], false);
        assert_eq!(fv["errorReason"], errors::INVALID_TRANSACTION_STATE);
    }

    #[test]
    fn supported_conforms() {
        let s = SupportedResponse::exact_only(NETWORK_TESTNET10);
        let v = serde_json::to_value(&s).unwrap();
        let k = &v["kinds"][0];
        assert_eq!(k["x402Version"], 2);
        assert_eq!(k["scheme"], "exact");
        assert_eq!(k["extra"]["asset"], "KAS");
        assert_eq!(k["extra"]["binding"], BINDING_EXACT);
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
}
