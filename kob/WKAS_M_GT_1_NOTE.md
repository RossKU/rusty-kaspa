# WKAS M>1 LEVER — design note (recorded lever only)

Status: recorded lever only, unscheduled; no design round yet.

Current batch matching is M=1 — one buy per settle tx (see
`BatchError::MultiBuyUnsupported` in `kob/domain/src/spot/batch.rs`).

M=1 is a consequence of KAS not being a covenant token: buys escrow raw
KAS, so multiple buys share no covenant id and no aggregate conservation
law can be composed across them.

Wrapping KAS as a covenant token (WKAS) would give buys a shared cid,
making an aggregate fair_sum-style conservation law composable and M>1
provable.
