//! x402 wire-format types.
//!
//! Kept aligned with the upstream x402 protocol (coinbase/x402) so a generic
//! x402 client library can pay a Kaspa-priced resource the same way it pays an
//! EVM one: HTTP 402 with an `accepts` array of `PaymentRequirements`, a
//! base64 `X-PAYMENT` header carrying a `PaymentPayload`, and a facilitator
//! that answers `/verify` and `/settle`. Kaspa-specific bits live in the
//! `network` identifier (`kaspa:mainnet` / `kaspa:testnet-10`), the `asset`
//! (`kas` for native, a covenant id for KCC20), and the scheme payload shape.

use serde::{Deserialize, Serialize};

/// x402 protocol version this facilitator speaks.
pub const X402_VERSION: u32 = 1;

/// The only payment scheme implemented: pay exactly the required amount.
pub const SCHEME_EXACT: &str = "exact";

/// Network identifiers (CAIP-2-flavored, matching the x402 convention).
pub const NETWORK_MAINNET: &str = "kaspa:mainnet";
pub const NETWORK_TESTNET10: &str = "kaspa:testnet-10";

/// `asset` value for a native-KAS payment (analogous to the ERC-20 contract
/// address slot in the upstream EVM schemes, but there is no contract).
pub const ASSET_NATIVE_KAS: &str = "kas";

/// A single acceptable way to pay, advertised in the 402 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRequirements {
    pub scheme: String,
    pub network: String,
    /// Required amount in sompi, string-encoded (x402 encodes atomic amounts
    /// as strings to avoid JS number precision loss).
    #[serde(rename = "maxAmountRequired")]
    pub max_amount_required: String,
    /// The resource URL being paid for.
    pub resource: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "mimeType", default)]
    pub mime_type: String,
    /// Recipient address.
    #[serde(rename = "payTo")]
    pub pay_to: String,
    #[serde(rename = "maxTimeoutSeconds", default)]
    pub max_timeout_seconds: u64,
    /// `kas` for native, or a token covenant id (hex) for KCC20.
    #[serde(default)]
    pub asset: String,
    /// Scheme-specific extra data. For KOB's schemes this carries
    /// `{ "fingerprint": "<hex>" }` — the request-fingerprint the client must
    /// embed in the transaction payload to bind the payment to this request.
    #[serde(default)]
    pub extra: serde_json::Value,
}

impl PaymentRequirements {
    /// Parse `max_amount_required` into sompi.
    pub fn max_amount_sompi(&self) -> Result<u64, String> {
        self.max_amount_required
            .parse::<u64>()
            .map_err(|e| format!("invalid maxAmountRequired '{}': {}", self.max_amount_required, e))
    }

    /// The request-fingerprint the client is expected to bind to, if the
    /// resource server issued one in `extra.fingerprint`.
    pub fn fingerprint(&self) -> Option<&str> {
        self.extra.get("fingerprint").and_then(|v| v.as_str())
    }
}

/// The `X-PAYMENT` header payload (before base64 encoding).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentPayload {
    #[serde(rename = "x402Version")]
    pub x402_version: u32,
    pub scheme: String,
    pub network: String,
    /// Scheme-specific payment payload (see [`NativeExactPayload`] /
    /// `Kcc20ExactPayload`).
    pub payload: serde_json::Value,
}

/// Scheme (A) native-KAS "exact" payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeExactPayload {
    /// The fully-signed transaction, as the kaspad wRPC `submitTransaction`
    /// JSON. Accepts either the full `{ "transaction": {...}, "allowOrphan": _ }`
    /// envelope or a bare transaction object.
    pub transaction: serde_json::Value,
    /// Payer address (whose UTXOs fund the payment). Verified on-chain by
    /// requiring the spent inputs to belong to this address's unspent set.
    pub from: String,
    /// Recipient address (must equal `PaymentRequirements.payTo`).
    #[serde(rename = "payTo")]
    pub pay_to: String,
    /// Amount paid to `payTo`, in sompi (string-encoded).
    pub amount: String,
}

/// 402 Payment Required response body (what a resource server built on this
/// facilitator emits when payment is missing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRequiredResponse {
    #[serde(rename = "x402Version")]
    pub x402_version: u32,
    pub accepts: Vec<PaymentRequirements>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
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

/// Facilitator `/verify` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    #[serde(rename = "isValid")]
    pub is_valid: bool,
    #[serde(rename = "invalidReason", skip_serializing_if = "Option::is_none")]
    pub invalid_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
}

impl VerifyResponse {
    pub fn valid(payer: impl Into<String>) -> Self {
        VerifyResponse { is_valid: true, invalid_reason: None, payer: Some(payer.into()) }
    }
    pub fn invalid(reason: impl Into<String>) -> Self {
        VerifyResponse { is_valid: false, invalid_reason: Some(reason.into()), payer: None }
    }
}

/// Facilitator `/settle` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettleResponse {
    pub success: bool,
    #[serde(rename = "errorReason", skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,
    /// On-chain transaction id on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction: Option<String>,
    pub network: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
}

impl SettleResponse {
    pub fn ok(network: impl Into<String>, txid: impl Into<String>, payer: Option<String>) -> Self {
        SettleResponse {
            success: true,
            error_reason: None,
            transaction: Some(txid.into()),
            network: network.into(),
            payer,
        }
    }
    pub fn failed(network: impl Into<String>, reason: impl Into<String>) -> Self {
        SettleResponse {
            success: false,
            error_reason: Some(reason.into()),
            transaction: None,
            network: network.into(),
            payer: None,
        }
    }
}

/// One `(scheme, network)` the facilitator supports, for `/supported`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedKind {
    #[serde(rename = "x402Version")]
    pub x402_version: u32,
    pub scheme: String,
    pub network: String,
}

/// `/supported` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedResponse {
    pub kinds: Vec<SupportedKind>,
}

/// Encode a `PaymentPayload` as an `X-PAYMENT` header value (base64 of JSON).
pub fn encode_x_payment(p: &PaymentPayload) -> Result<String, String> {
    use base64::Engine;
    let json = serde_json::to_vec(p).map_err(|e| e.to_string())?;
    Ok(base64::engine::general_purpose::STANDARD.encode(json))
}

/// Decode an `X-PAYMENT` header value into a `PaymentPayload`.
pub fn decode_x_payment(header: &str) -> Result<PaymentPayload, String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(header.trim())
        .map_err(|e| format!("X-PAYMENT base64 decode failed: {}", e))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("X-PAYMENT JSON parse failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x_payment_roundtrip() {
        let p = PaymentPayload {
            x402_version: X402_VERSION,
            scheme: SCHEME_EXACT.to_string(),
            network: NETWORK_TESTNET10.to_string(),
            payload: serde_json::json!({ "amount": "100" }),
        };
        let hdr = encode_x_payment(&p).unwrap();
        let back = decode_x_payment(&hdr).unwrap();
        assert_eq!(back.scheme, SCHEME_EXACT);
        assert_eq!(back.network, NETWORK_TESTNET10);
        assert_eq!(back.payload["amount"], "100");
    }

    #[test]
    fn requirements_amount_and_fingerprint() {
        let req = PaymentRequirements {
            scheme: SCHEME_EXACT.to_string(),
            network: NETWORK_TESTNET10.to_string(),
            max_amount_required: "12345".to_string(),
            resource: "https://x/y".to_string(),
            description: String::new(),
            mime_type: String::new(),
            pay_to: "kaspatest:qz".to_string(),
            max_timeout_seconds: 60,
            asset: ASSET_NATIVE_KAS.to_string(),
            extra: serde_json::json!({ "fingerprint": "abcd" }),
        };
        assert_eq!(req.max_amount_sompi().unwrap(), 12345);
        assert_eq!(req.fingerprint(), Some("abcd"));
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(decode_x_payment("!!!not-base64!!!").is_err());
    }
}
