//! axum HTTP server exposing the x402 facilitator endpoints.
//!
//! Routes (aligned with the upstream x402 facilitator contract):
//! - `POST /verify`    -> `VerifyResponse`
//! - `POST /settle`    -> `SettlementResponse` (sets the `PAYMENT-RESPONSE` header)
//! - `POST /await`     -> `SettlementResponse` (pull mode)
//! - `GET  /supported` -> `SupportedResponse`
//! - `GET  /health`    -> `"ok"`
//!
//! `/verify` and `/settle` accept the `FacilitatorRequest` either as a JSON body
//! or base64-encoded in a `PAYMENT-SIGNATURE` header.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use tower_http::cors::{Any, CorsLayer};

use crate::facilitator::{ChainBackend, Facilitator};
use crate::wire_v2::{
    decode_header, encode_header, errors, AwaitRequest, FacilitatorRequest, ReserveRequest,
    SettlementResponse, SupportedResponse, VerifyResponse, HEADER_PAYMENT_RESPONSE,
    HEADER_PAYMENT_SIGNATURE,
};

/// Build the router for a facilitator over any chain backend.
pub fn router<B: ChainBackend + 'static>(fac: Arc<Facilitator<B>>) -> Router {
    Router::new()
        .route("/verify", post(verify_handler::<B>))
        .route("/settle", post(settle_handler::<B>))
        .route("/await", post(await_handler::<B>))
        .route("/reserve", post(reserve_handler::<B>))
        .route("/supported", get(supported_handler::<B>))
        .route("/health", get(|| async { "ok" }))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .with_state(fac)
}

/// Read a `FacilitatorRequest` from the `PAYMENT-SIGNATURE` header (base64 JSON)
/// if present, otherwise from the JSON body.
fn read_request(headers: &HeaderMap, body: &Bytes) -> Result<FacilitatorRequest, &'static str> {
    if let Some(h) = headers.get(HEADER_PAYMENT_SIGNATURE) {
        let s = h.to_str().map_err(|_| errors::INVALID_PAYLOAD)?;
        return decode_header::<FacilitatorRequest>(s).map_err(|_| errors::INVALID_PAYLOAD);
    }
    serde_json::from_slice(body).map_err(|_| errors::INVALID_PAYLOAD)
}

async fn verify_handler<B: ChainBackend + 'static>(
    State(fac): State<Arc<Facilitator<B>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match read_request(&headers, &body) {
        Ok(req) => Json(fac.verify(&req).await).into_response(),
        Err(code) => Json(VerifyResponse::invalid(code)).into_response(),
    }
}

async fn settle_handler<B: ChainBackend + 'static>(
    State(fac): State<Arc<Facilitator<B>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let resp = match read_request(&headers, &body) {
        Ok(req) => fac.settle(&req).await,
        Err(code) => SettlementResponse::failed(code),
    };
    let encoded = encode_header(&resp).ok();
    let mut out = Json(resp).into_response();
    if let Some(enc) = encoded {
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(HEADER_PAYMENT_RESPONSE.as_bytes()),
            HeaderValue::from_str(&enc),
        ) {
            out.headers_mut().insert(name, val);
        }
    }
    out
}

/// Pull mode: discover a client-broadcast payment and authorize it.
async fn await_handler<B: ChainBackend + 'static>(
    State(fac): State<Arc<Facilitator<B>>>,
    Json(req): Json<AwaitRequest>,
) -> Json<SettlementResponse> {
    Json(fac.await_payment(&req).await)
}

async fn supported_handler<B: ChainBackend + 'static>(
    State(fac): State<Arc<Facilitator<B>>>,
) -> Json<SupportedResponse> {
    Json(SupportedResponse::exact_only(fac.network()))
}

/// Reserve a KIP-10 additive borrow outpoint; returns the v2 PaymentRequired.
async fn reserve_handler<B: ChainBackend + 'static>(
    State(fac): State<Arc<Facilitator<B>>>,
    Json(r): Json<ReserveRequest>,
) -> Response {
    let err = || Json(serde_json::json!({ "error": errors::INVALID_PAYMENT_REQUIREMENTS })).into_response();
    let (amount, borrow_amount, threshold) = match (
        r.amount.parse::<u64>(),
        r.borrow_amount.parse::<u64>(),
        r.additive_threshold.parse::<u64>(),
    ) {
        (Ok(a), Ok(b), Ok(t)) => (a, b, t),
        _ => return err(),
    };
    let url = if r.resource_url.is_empty() { "https://kob-x402/resource" } else { &r.resource_url };
    let request_hash = r.request_hash.clone().filter(|s| !s.is_empty());
    match fac
        .reserve(&r.pay_to, amount, &r.borrow_txid, r.borrow_index, borrow_amount, threshold, r.payment_output_index, url, request_hash)
        .await
    {
        Ok(pr) => Json(pr).into_response(),
        Err(_) => err(),
    }
}

/// Bind and serve the facilitator on `bind` (e.g. `0.0.0.0:8402`).
pub async fn serve<B: ChainBackend + 'static>(
    fac: Arc<Facilitator<B>>,
    bind: &str,
) -> anyhow::Result<()> {
    let app = router(fac);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!("[x402] facilitator listening on {}", bind);
    axum::serve(listener, app).await?;
    Ok(())
}
