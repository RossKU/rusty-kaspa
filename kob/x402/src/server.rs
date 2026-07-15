//! axum HTTP server exposing the x402 facilitator endpoints.
//!
//! Routes (aligned with the upstream x402 facilitator contract):
//! - `POST /verify`    -> `VerifyResponse`
//! - `POST /settle`    -> `SettleResponse`
//! - `GET  /supported` -> `SupportedResponse`
//! - `GET  /health`    -> `"ok"`

use std::sync::Arc;

use axum::{
    extract::State,
    response::Json,
    routing::{get, post},
    Router,
};
use tower_http::cors::{Any, CorsLayer};

use crate::facilitator::{ChainBackend, Facilitator};
use crate::wire::{
    AwaitRequest, FacilitatorRequest, SettleResponse, SupportedKind, SupportedResponse,
    VerifyResponse, SCHEME_EXACT, X402_VERSION,
};

/// Build the router for a facilitator over any chain backend.
pub fn router<B: ChainBackend + 'static>(fac: Arc<Facilitator<B>>) -> Router {
    Router::new()
        .route("/verify", post(verify_handler::<B>))
        .route("/settle", post(settle_handler::<B>))
        .route("/await", post(await_handler::<B>))
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

async fn verify_handler<B: ChainBackend + 'static>(
    State(fac): State<Arc<Facilitator<B>>>,
    Json(req): Json<FacilitatorRequest>,
) -> Json<VerifyResponse> {
    Json(fac.verify(&req).await)
}

async fn settle_handler<B: ChainBackend + 'static>(
    State(fac): State<Arc<Facilitator<B>>>,
    Json(req): Json<FacilitatorRequest>,
) -> Json<SettleResponse> {
    Json(fac.settle(&req).await)
}

/// Pull mode: discover a client-broadcast payment and authorize it.
async fn await_handler<B: ChainBackend + 'static>(
    State(fac): State<Arc<Facilitator<B>>>,
    Json(req): Json<AwaitRequest>,
) -> Json<SettleResponse> {
    Json(fac.await_payment(&req).await)
}

async fn supported_handler<B: ChainBackend + 'static>(
    State(fac): State<Arc<Facilitator<B>>>,
) -> Json<SupportedResponse> {
    Json(SupportedResponse {
        kinds: vec![SupportedKind {
            x402_version: X402_VERSION,
            scheme: SCHEME_EXACT.to_string(),
            network: fac.network().to_string(),
        }],
    })
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
