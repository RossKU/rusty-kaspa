# KOB Engine — Production API Surface (Design)

Status: **DESIGN ONLY**. No implementation in this pass. This document specs
the API surface the long-running `kob-engine` daemon (block-listen +
auto-match, 24/7) needs to expose once it moves from an E2E test harness to a
production server. It is grounded in the current code (`kob/engine/src/api/mod.rs`,
`kob/engine/src/reporting/*`, `kob/domain/src/spot/order_book.rs`,
`kob/engine/src/chain/{scanner,executor}.rs`, `kob/engine/src/storage/*`) and
in the operational findings recorded in `kob/E2E_LIVE_RESULTS.md` and
`kob/NM_BUY_DESIGN.md`. Every section states what already exists (reuse),
what's new, and why.

**(Update 2026-07-18): this document predates the v18 consolidation.** It was
drafted while v17 was the shipping buy-sweep generation (`MAX_N=8`); v17 was
deleted the next day (commit `23eb1edc`) and v18 became the sole spot
generation, which later raised the sweep ceiling to `MAX_N=32` (commit
`317f163c`). Every "v17"/"MAX_N=8" reference below (§0, §4, §6.2, §7.6)
describes that superseded generation — the underlying API-surface arguments (per-leg
trade records, `leg_index` disambiguation, etc.) are unaffected by the rename
and still apply to v18 sweeps unchanged. See `kob/RELEASE_STATUS.md` for
current status; this file otherwise remains design-only and unimplemented.

## 0. Non-goals

- No Rust code, no route handlers, no migrations. Field names below are the
  proposed contract; wire them up in a follow-up implementation pass.
- Does not re-litigate the v17 N:M covenant design (`kob/NM_BUY_DESIGN.md`) or
  the settlement bug root-caused in `E2E_LIVE_RESULTS.md` — it only specs how
  the API surface must account for their downstream effects on trade/volume
  reporting (§7.6).

## 1. What exists today (grounding)

`kob/engine/src/api/mod.rs` already runs an axum router with a real (if
partial) surface: `/api/v1/pairs`, `/depth`, `/trades`, `/klines`, `/ticker`,
`/spread`, `/order`, `/cross-pair-trades`, `/status`, `/wallet/utxos`, plus
per-instrument routes (stop/trailing-stop/ifd/ifo/perp/lending/prediction) and
a single `/ws` upgrade with a `{"method":"subscribe"|"unsubscribe","params":[...]}`
protocol keyed on `depth:<pair>`, `trades:<pair>`, `kline:<pair>:<interval>`,
`user_orders:<owner_hash>`, and bare `perp`/`lending`/`prediction`. There's a
per-IP sliding-window rate limiter (100 req/min) and WS connection caps
(global 1000, 10/IP, 50 subs/client). This is a solid base — §3–§6 extend it,
not replace it.

Underlying data:
- **Order book** (`kob/domain/src/spot/order_book.rs`): `OrderBook` is an
  in-process `HashMap<token_cov_id, PairBook>` of `BTreeMap`s keyed by
  price/DAA/value. It is **not a database** — it is rebuilt by the block
  scanner (`kob/engine/src/chain/scanner.rs`) on a forward pass, with a JSON
  snapshot (`kob/engine/src/storage/persistence.rs`) cached purely to avoid a
  full rescan on restart. `token_cov_id` (64-hex covenant ID) is the only pair
  identifier that exists — there is no symbol registry.
- **Trades** (`kob/engine/src/reporting/trades.rs`, `TradeLog`): an in-memory
  bounded ring buffer (`DEFAULT_MAX_TRADES`) with an optional best-effort
  JSONL append file that is replayed on restart. No index beyond linear
  per-pair scans; no reorg-awareness.
- **Candles** (`kob/engine/src/reporting/candle.rs` +
  `kob/engine/src/storage/history.rs`): only **M1** is durably persisted to
  SQLite (MT5-style); 5m/15m/1h/4h/1d/1w are aggregated on read via `GROUP BY`.
  This part is already durable and a reasonable foundation.
- **Sync/cursor**: `kob/engine/src/chain/executor.rs` persists a scan cursor
  ("H1: prefer persisted cursor; fall back to current sink") and calls
  `rpc.get_daa_score()` (`get_current_daa`) to read the node's current
  sink/virtual DAA. The gap between persisted cursor and sink DAA is exactly
  the number the daemon needs to expose — see §3.

## 2. Price model decision — KAS is the hub, USD is derived

**Decision**: every tradable pair in KOB is `TOKEN/KAS`. KAS is the sole
settlement asset (every covenant order is funded in, or pays out, KAS or a
KAS-denominated leg) and the sole **base/hub currency** for the whole market
graph — a star topology, exactly like Forex treats USD as the hub currency
that every pair quotes through, and through which cross-rates (EUR/GBP via
EUR/USD and GBP/USD) are derived rather than directly quoted.

Consequences for the API:

1. **All native prices are KAS-per-TOKEN rational fractions** (`num/den`,
   sompi-precision integers), exactly the convention `/api/v1/depth`,
   `/ticker`, `/spread` already use. This is the ground truth: exact, no
   float rounding, and it is what matching/settlement actually uses on L1.
2. **USD is never a settlement unit.** It is a **derived, display-only**
   field computed as `kas_price * kas_usd_reference_rate`. It must never
   appear in covenant logic, matching, or order state — only in REST/WS
   response sugar for human consumers.
3. **KAS/USD reference rate is a pluggable, explicitly-trusted input**, not
   an oracle KOB can vouch for on-chain today. New config surface (mirrors
   the existing `HistoryConfig` pattern in `kob/engine/src/config.rs`):

   ```rust
   pub struct ReferenceRateConfig {
       pub provider: ReferenceRateProvider, // CoinGeckoSimplePrice | CexQuoteMedian(Vec<String>) | StaticManual(String) | OnChainOracle(String) [future]
       pub refresh_interval_secs: u64,      // default 60
       pub stale_after_secs: u64,           // default 300; past this, USD fields are omitted, not stale-served
   }
   ```

   Trust model, stated plainly: this rate is **not consensus data**. It is
   whatever the operator configures, with a fallback chain and a hard
   staleness cutoff (no silently-serving-old-data). Every response carrying
   a `_usd` field is accompanied by `usd_source` and `usd_age_secs` at the
   top level of that response so a consumer can judge trust for themselves.
   New introspection endpoint:

   `GET /api/v1/reference-rate` →
   ```json
   {
     "kas_usd": "0.0842",
     "source": "coingecko:kaspa",
     "as_of": 1752600000,
     "age_secs": 12,
     "stale": false,
     "stale_threshold_secs": 300
   }
   ```

4. **Cross-pair (TOKEN_A/TOKEN_B) is synthesized through the KAS hub**,
   Forex-cross-rate style, in two distinct forms that must not be confused:
   - **Actually-settled cross-pair trades** — already implemented
     (`match_swap_routes`/`execute_swap_fill`, exposed today via
     `GET /api/v1/cross-pair-trades`, which already returns a
     `CrossPairRoutingResponse` with `sellPair`/`buyPair`/`intermediateToken`/
     `kasThrough`/`effectiveRate`). This is a **real on-chain 2-hop or
     3-hop route** with real slippage/surplus. Keep as-is.
   - **Synthetic mid cross-rate** — a new, clearly-labeled convenience
     endpoint for display/charting, not an order book:
     `GET /api/v1/cross-rate?base=<token_a>&quote=<token_b>` →
     ```json
     {
       "pair": "TOKEN_A/TOKEN_B",
       "rate": "1234/1000",
       "rate_decimal": "1.234",
       "synthetic": true,
       "route": ["TOKEN_A/KAS", "TOKEN_B/KAS"],
       "as_of": 1752600000
     }
     ```
     computed as `mid(A/KAS) / mid(B/KAS)`. This is exactly how a Forex data
     vendor derives EUR/GBP from EUR/USD and GBP/USD without EUR/GBP ever
     being a separately-matched book.
5. **The public aggregator feed (§6) carries no USD field at all.** CoinGecko
   and GeckoTerminal compute USD themselves globally once KOB publishes
   KAS-native `TOKEN_KAS` tickers — this mirrors how Forex vendors don't
   republish USD-converted majors (USD *is* the base). Publishing a second,
   KOB-sourced USD number that can drift from CoinGecko's own would trip
   CoinGecko's explicit data-integrity rule (§6.5) that displayed data must
   match the API. USD stays a user-facing/internal convenience only (§4, §5).

## 3. Engine status / sync API

Ground truth: the operationally critical fact the daemon must expose is the
gap between the **persisted scan cursor** and the **node's sink DAA** — this
is precisely the number that would have flagged the catch-up-hangs-at-0%-CPU
failure mode documented in `E2E_LIVE_RESULTS.md` (§"Why the N:N-in-one-TX
success path is not live-settled") before it silently stalled discovery for
hours.

### `GET /api/v1/health`
Cheap liveness/readiness probe for process supervisors / load balancers.
Must not block on the order-book mutex (best-effort `try_lock` or a
lock-free health flag updated by the scan loop).

```json
{ "status": "ok", "node_connected": true, "uptime_secs": 431200 }
```
`status` ∈ `ok | degraded | down`. Returns HTTP 503 when `down`.

### `GET /api/v1/sync`
```json
{
  "cursor_daa": 91234500,
  "sink_daa": 91234512,
  "lag_blocks": 12,
  "caught_up": true,
  "caught_up_threshold": 10,
  "scanning_state": "steady" ,
  "last_block_hash": "8f3a...",
  "node_connected": true,
  "scan_interval_ms": 800,
  "mode": "continuous"
}
```
- `cursor_daa` — DAA score of the last block the scanner fully processed
  (the persisted H1 cursor in `executor.rs`).
- `sink_daa` — current node virtual/sink DAA (`rpc.get_daa_score()`, same
  call as `get_current_daa`).
- `lag_blocks` = `sink_daa - cursor_daa` (saturating).
- `caught_up` = `lag_blocks <= caught_up_threshold` (config knob, default 10).
- `scanning_state` ∈ `steady | catching_up | stalled`. `stalled` = lag not
  decreasing across N consecutive polls — this is the exact signal that
  would have caught the observed multi-thousand-block `getBlocks` hangs.
- This endpoint is the wiring point for external alerting/auto-restart; it
  does not itself take remedial action.

### `GET /api/v1/status` (extend, backward-compatible)
Existing `StatusResponse{uptime_secs,pairs,total_orders,total_trades}` stays;
add:
```json
{
  "uptime_secs": 431200,
  "pairs": 14,
  "total_orders": 812,
  "total_trades": 40213,
  "node_connected": true,
  "version": "kob-engine/0.17.0 (rev b6c1d59)",
  "sync": { "lag_blocks": 12, "caught_up": true }
}
```
`sync` is a summary only — clients needing detail poll `/sync`.

## 4. Market-data REST (KAS-native, USD derived)

Mostly a formalization of what exists, plus explicit KAS/USD field rules and
the fixes required before this can back a public feed (see §7 for the
blocking gaps).

| Endpoint | Status | Notes |
|---|---|---|
| `GET /api/v1/pairs` | exists, extend | add `base_symbol`/`quote_symbol` (nullable until §7.2 lands) |
| `GET /api/v1/depth?pair=&limit=` | exists, keep | L2 snapshot, `lastUpdateId`; document WS-resync contract (below) |
| `GET /api/v1/spread?pair=` | exists, keep | BBO |
| `GET /api/v1/ticker?pair=` | exists, extend | add optional `*_usd` fields + `usd_source`/`usd_age_secs` |
| `GET /api/v1/trades?pair=&limit=&start_time=&end_time=&from_daa=` | exists, extend | add per-leg disambiguator (§7.6) |
| `GET /api/v1/klines?pair=&interval=&limit=` | exists, keep | M1 durable (SQLite), higher TFs computed on read |

**`/api/v1/pairs` (extended)**
```json
[
  { "pair_id": "<64-hex token_cov_id>", "base_symbol": "NACHO", "quote_symbol": "KAS", "bids": 41, "asks": 37 }
]
```
`base_symbol: null` when the token metadata registry (§7.2) has no entry —
document the fallback as the first 8 hex chars of `pair_id`, never silently
substitute a guessed symbol.

**`/api/v1/depth`** — unchanged shape. Document explicitly (it isn't today)
that `lastUpdateId` is a resync anchor: clients take a REST snapshot, then
apply only WS `depth` deltas with `updateId` strictly greater than the
snapshot's, exactly the Binance-style contract already implied by the field
name — this needs to actually hold once `update_id` is wired to increment
per book mutation (currently `SharedState::update_id` is initialized to `0`
and its increment path should be audited before this contract is documented
as load-bearing).

**`/api/v1/ticker` (extended)**
```json
{
  "last": "499/500", "high": "500/500", "low": "495/500",
  "volume": 812000000, "count": 37,
  "bid": "498/500", "ask": "500/500", "spread": "2/500",
  "last_price_usd": "0.0839", "bid_usd": "0.0837", "ask_usd": "0.0840",
  "usd_source": "coingecko:kaspa", "usd_age_secs": 12
}
```
All `_usd` fields and the two `usd_*` metadata fields are omitted (not
null-filled) when the reference rate is stale or unconfigured — a consumer
must be able to tell "no USD available" apart from "USD is zero".

**`/api/v1/trades` (extended)**
Add a stable per-fill disambiguator, currently missing (see §7.6):
```json
{ "txid": "...", "leg_index": 2, "pair": "...", "price": "499/500", "qty": 200000000, "side": "sell", "daaScore": 91234500, "timestamp": 1752600000 }
```
`leg_index` distinguishes multiple trade legs that share one settlement
`txid` (already the case for cross-pair swaps today, and for v17 N:1 buy
sweeps — §7.6; v17 is since superseded by v18, same shape unchanged, see the
top-of-file note). `(txid, leg_index)` becomes the stable trade key.

## 5. User-facing WS distribution

Keep the existing `{"method":"subscribe","params":[...]}` protocol and topic
grammar (`depth:<pair>`, `trades:<pair>`, `kline:<pair>:<interval>`,
`user_orders:<owner_hash>`) — it already works and is a reasonable minimal
protocol. Additions:

1. **New stream: `ticker:<pair>`** — there is currently no push-ticker
   `WsEvent` variant (only `DepthUpdate`, `Trade`, `Kline`, plus the
   order/perp/lending/prediction events); clients must poll REST for 24h
   ticker today. Add:
   ```json
   { "stream": "ticker", "pair": "...", "last": "499/500", "bid": "498/500", "ask": "500/500", "high": "500/500", "low": "495/500", "volume": 812000000, "updateId": 44201 }
   ```
   Emitted on trade and on BBO change, rate-limited server-side (e.g. max
   1/sec/pair) to avoid flooding subscribers on hot pairs.
2. **Snapshot-then-delta on subscribe**: when a client subscribes to
   `depth:<pair>`, immediately push one synthetic `depth` snapshot event
   (not just future deltas) so the client doesn't need a second REST round
   trip to bootstrap. Same for `ticker:<pair>` (push current ticker once on
   subscribe).
3. **Heartbeat**: server-initiated `{"stream":"ping","t":...}` every 30s;
   treat 2 missed client pongs (or one dead-socket write failure, already
   handled) as a disconnect. Needed for load balancers / long-lived
   connections behind idle-timeout proxies.
4. **`user_orders:<owner_hash>` — document the trust boundary, don't
   over-promise.** `owner_hash` is a Blake2b-256 of the owner's
   scriptPublicKey; subscribing to it today requires no proof of ownership
   (`should_forward` matches purely on the string). Given every order is a
   public L1 UTXO already, this isn't a confidentiality leak beyond what a
   block explorer shows — but it should be **documented as a filtering
   convenience, not an authenticated private channel**, so nobody designs a
   trust boundary on top of it later without noticing. If a real private
   channel is wanted later (e.g. to push fee-sensitive fill details), gate
   it behind a signature-challenge subscribe handshake — out of scope here.
5. Reuse the existing WS connection/subscription caps (§1) as-is for these
   new topics; no new cap categories needed.

## 6. Aggregator feed (CoinGecko / GeckoTerminal)

### 6.1 Spec source

Researched directly rather than assumed: the CoinGecko exchange-integration
contract (`/pairs`, `/tickers`, `/orderbook`, `/historical_trades`) is
documented in CoinGecko's public "Integration Ideal API Endpoints" reference
and is the same ticker-API contract real order-book DEXes already use to
feed both CoinGecko's exchange listing *and* GeckoTerminal's on-chain pages —
concretely, **Rubicon Markets** (an order-book, non-AMM DEX) runs exactly
this contract at `coingecko.rubicon.finance/{chainId}/{tickers,orderbook,historical_trades}`.
GeckoTerminal's own support docs confirm non-EVM / non-subgraph chains and
DEXes onboard via "adapters" conforming to GeckoTerminal's API endpoint
requirements rather than requiring a subgraph — Kaspa has neither an EVM
subgraph tool nor an existing GeckoTerminal indexer, so this ticker-API
adapter path is the only realistic route for KOB, and it is a **first-class,
spec-sanctioned path for order-book DEXes**, not a workaround: the spec
explicitly marks `liquidity_in_usd` as "Not applicable to orderbook DEXes"
and notes AMM DEXes may substitute a depth formula for `/orderbook` — the
implication being that order-book DEXes are expected to serve the real thing.

### 6.2 Endpoint group

Serve these under a dedicated, unauthenticated, aggressively-cached route
group — deliberately **not** behind the general 100 req/min per-IP limiter
(§1), since CoinGecko/GeckoTerminal poll from a small, allow-listable set of
IPs at up to once-per-minute across every pair and must not be throttled:

`GET /api/v1/gecko/pairs`
```json
{
  "time": 1752600000,
  "data": [ { "ticker_id": "NACHO_KAS", "base": "NACHO", "target": "KAS" } ]
}
```

`GET /api/v1/gecko/tickers`
```json
{
  "time": 1752600000,
  "data": [
    {
      "ticker_id": "NACHO_KAS",
      "base_currency": "NACHO",
      "target_currency": "KAS",
      "last_price": "0.998",
      "base_volume": "812000000",
      "target_volume": "810376000",
      "bid": "0.996", "ask": "1.000", "high": "1.000", "low": "0.990",
      "pool_id": "<64-hex token_cov_id>"
    }
  ]
}
```
`liquidity_in_usd` is intentionally **omitted** — the spec marks it N/A for
order-book DEXes, and KOB has no pooled reserve to report (every "level" is
discrete resting UTXOs, not an AMM curve). `pool_id` reuses the token
covenant ID as the closest analog to a pool/pair address.

`GET /api/v1/gecko/orderbook?ticker_id=NACHO_KAS&depth=100`
```json
{
  "ticker_id": "NACHO_KAS",
  "timestamp": 1752600000123,
  "bids": [["0.996", "40000000"], ["0.995", "120000000"]],
  "asks": [["1.000", "30000000"], ["1.002", "90000000"]]
}
```
This is a direct re-projection of `/api/v1/depth` with price/size as decimal
strings instead of rationals (aggregators expect decimal, not `num/den`) and
`depth` semantics matching the spec (`0` = full depth, else N total levels
split bid/ask).

`GET /api/v1/gecko/historical_trades?ticker_id=NACHO_KAS&type=buy&limit=500&start_time=&end_time=`
```json
{
  "ticker_id": "NACHO_KAS",
  "timestamp": 1752600000,
  "buy": [ { "trade_id": "6cf08c27...:0", "price": "0.998", "base_volume": "800000000", "target_volume": "798400000", "trade_timestamp": "1752599990", "type": "buy" } ],
  "sell": [ ]
}
```
`trade_id` = `(txid, leg_index)` (§4, §7.6) — a plain `txid` is **not**
sufficient once one settlement TX carries multiple fills (already true
today for cross-pair swaps and v17 buy sweeps — v17 is since superseded by
v18, same shape unchanged, see the top-of-file note; the spec explicitly requires
trade_id uniqueness and calls out that "Unix timestamp does not qualify").

### 6.3 GeckoTerminal specifics

Same four endpoints double as the GeckoTerminal adapter feed. GeckoTerminal
additionally wants, at **onboarding/application** time (not as response
fields): a fixed DEX slug (e.g. `kob`), the Kaspa network id(s) it should be
scoped to (mainnet vs testnet-10 are presumably separate listings), and
confirmation the adapter is publicly reachable without auth/IP restriction
for their crawler. The exact onboarding "adapter" document was not fetchable
during this research pass (CoinGecko's support article on non-EVM chain/DEX
integration 403'd); treat the endpoint shapes above as the confirmed-by-precedent
contract and the onboarding mechanics as to-be-confirmed at application time.

### 6.4 Cross-pair presentation to aggregators

Per §2.4: **do not publish synthetic `TOKEN_A_TOKEN_B` tickers.** Publish
only the `TOKEN_KAS` spokes; CoinGecko derives crosses globally the same way
Forex data vendors derive EUR/GBP from EUR/USD + GBP/USD. Only genuinely
on-chain-settled cross-pair fills (via `/api/v1/cross-pair-trades`, §2.4)
are KOB-specific data the aggregators can't derive themselves, and those are
already a distinct existing endpoint, not part of the `/gecko/*` group.

### 6.5 Data-integrity constraint

CoinGecko's stated policy: displayed website/UI data must match the API
data, or the integration is rejected. This means whatever public trading UI
KOB eventually ships must read the *same* `/api/v1/*` numbers the `/gecko/*`
feed re-projects — no separate "marketing" price path.

## 7. Dependencies, gaps, and rollout order

Ranked by what blocks what. Everything in §7.1–§7.2 blocks §6 (aggregator
feed) outright; §7.3–§7.6 are correctness/trust issues to close before
treating any of this as production-grade for *any* external consumer.

### 7.1 Persistent Spot indexer — the primary blocker (P0)

Today: the order book is a memory-resident structure rebuilt by block-scan,
cached as a JSON snapshot purely to skip a full rescan on restart
(`kob/engine/src/storage/persistence.rs`) — **not** a queryable history.
Candles are durably persisted (SQLite, M1 + on-read rollups) and are a fine
foundation. What is **not** durable or queryable:
- **Raw trade ledger**: `TradeLog` is a bounded in-memory ring buffer with a
  best-effort JSONL file that's fully replayed into memory on restart (no
  index, no time-range query beyond linear scan over what's currently
  resident). `historical_trades` pagination for aggregators, and any
  multi-day trade audit, needs a real append-only, indexed, queryable store.
- **Order lifecycle history**: there is no persistence of past orders at
  all — deploy → partial-fill → fill/cancel/expire transitions are visible
  only as WS events at the moment they happen, or reconstructable from raw
  L1 blocks. A real indexer needs an outpoint-keyed lifecycle table.
- **Trades are recorded at submission time, not confirmation time**:
  `record_trade` (`kob/engine/src/chain/executor.rs`) is called immediately
  after the node accepts the settlement TX, before any confirmation depth.
  A later reorg or mempool eviction is not retracted from `TradeLog` today.
  A persistent indexer must consume confirmed blocks (the scanner's own
  source of truth) rather than mirror the executor's optimistic path, or
  must add explicit retraction handling.

**Recommendation**: a separate indexer process/service, consuming the same
block stream the scanner already parses, writing an append-only trade
ledger + order-lifecycle table + (reusing the existing SQLite M1 candle
approach, which needs no change). It should be the actual data source
behind `/api/v1/trades` (deep history), `/api/v1/gecko/historical_trades`,
and eventually order-lifecycle query endpoints — not the in-memory
`TradeLog`, which stays as the low-latency hot path for recent data + WS.

### 7.2 Pair-id / symbol inconsistency — must fix before any of §4/§6 ship (P0)

A real inconsistency exists **today** between two conventions for
identifying a pair:
- `/api/v1/pairs`, `/depth`, `/spread`, `/order` key by the **full 64-hex
  `token_cov_id`** (`ob.pair_books` `HashMap` key, `handle_pairs` in
  `kob/engine/src/api/mod.rs`).
- `record_trade` (`kob/engine/src/chain/executor.rs`) constructs
  `pair_id = format!("{}/KAS", &token_cov_id[..16])` — a **truncated
  16-hex-char prefix** plus a literal `/KAS` suffix — and that's the key
  `TradeLog`/`CandleAggregator` actually store trades under.

Since `/api/v1/ticker` and `/api/v1/trades` take a single `pair` query param
and use it for *both* the book lookup (`ob.pair_books.get`, needs the full
hex) *and* the trade-log lookup (`trade_log.since`/`recent`, needs the
truncated `"xxxxxxxxxxxxxxxx/KAS"` form), there is no single value of `pair`
that satisfies both today. This must be reconciled — pick one canonical
`pair_id` (the recommendation is the full `token_cov_id` everywhere, with
`TOKEN_KAS`-style display symbols layered on top for humans/aggregators via
the symbol registry below) before a public ticker_id scheme can be
considered stable.

Related, smaller: also add a **token symbol/metadata registry**
(KRC-20/KCC-20 name+ticker lookup) — there is none today, and aggregator
`ticker_id`s need a human `BASE` symbol, not a 64-hex ID.

### 7.3 KAS/USD reference-rate provider (P1)

Nothing like `ReferenceRateConfig` (§2) exists yet. Needs an actual pluggable
provider implementation, a trust-model decision (which source is
authoritative for launch — likely a CEX-quote median or CoinGecko's own
`simple/price` for `kaspa` as a bootstrap, revisited once/if an on-chain
oracle exists), and the staleness/omission behavior specified in §2.3.

### 7.4 Auth / rate-limiting split for public endpoints (P1)

The current limiter (100 req/min/IP, applied uniformly via
`rate_limit_middleware`) is the wrong shape for the `/gecko/*` group, which
must tolerate CoinGecko/GeckoTerminal's poll cadence "on a minutely basis"
across every pair from a small set of IPs CoinGecko asks integrators to
allow-list. Needs: (a) the `/gecko/*` group split out of the general limiter
onto its own generous/allow-listed policy, (b) tolerance for CoinGecko's
required headers (`X-Requested-With: com.coingecko`, a `CoinGecko` UA) —
current CORS (`Any`) already doesn't block these, just don't add UA
filtering later without accounting for them. User-facing endpoints keep the
existing limiter as-is.

### 7.5 Covenant-UTXO reality — already mostly handled, keep it that way (P2)

Every order is a live P2SH covenant UTXO; every book entry already carries
`tx_id`/`index`/`outpoint_key()`, and WS order events already carry
`outpoint`. No new plumbing needed here — the design constraint is just
**discipline**: every new response type in §4/§6 that represents a
book/trade entry must keep surfacing `txid`/`outpoint` so on-chain data
stays independently auditable (useful both for CoinGecko's data-match rule,
§6.5, and for a future public UI to link out to a Kaspa explorer).

### 7.6 v17 N:M sweep effect on trade-tape/volume accounting (P0, feeds §7.1/§4/§6)

> **Stale premise (noted, not rewritten — this doc is design-only):** v17
> was deleted the next day (commit `23eb1edc`, `V18_DESIGN.md` Stage E2).
> v18 is now the sole spot generation (`SPOT_GENERATION=18`,
> `kob/core/src/contract/spot/mod.rs:8`) with `BUY_ORDER_MAX_N=32`
> (`kob/core/src/contract/spot/order.rs:16`, commit `317f163c`), not 8. The
> per-leg trade-recording argument below (one `record_trade` per order-leg
> sharing one `txid`, needing a `leg_index` disambiguator) still applies
> unchanged to v18 sweeps — only the contract name and MAX_N are stale. See
> `kob/RELEASE_STATUS.md` for current status.

Grounded in `kob/NM_BUY_DESIGN.md` and `kob/E2E_LIVE_RESULTS.md`:
- ~~**v17 is live** and is now the sole creatable buy contract. A v17 buy
  sweep settles **1 buy against up to `MAX_N=8` sells in one transaction**~~
  (historical — see the stale-premise note above; today it's v18,
  `MAX_N=32`), emitting one buyer-token output per sell, each bound to its own sell
  input.
- The executor **already does the right thing at the reporting layer**:
  `execute_batch_match`'s caller loops `for sell in &group.sells { record_trade(...) }`
  and `for buy in &group.buys { record_trade(...) }` — i.e. one trade record
  per order-leg, not one blended record per TX. Good foundation.
- **But those per-leg records share one `txid` with no disambiguator** — the
  `Trade` struct (`kob/engine/src/reporting/trades.rs`) has no `leg_index`/
  `input_idx` field. For a live 8-sell sweep this produces up to 9 trade
  records under one `txid`, indistinguishable from each other except by
  price/qty, which can coincide. This is exactly the gap §4/§6.2 close with
  `leg_index` / `(txid, leg_index)` as the trade key — needed **now**, not
  hypothetically, since ~~v17~~ (v18, per the note above) sweeps are already live.
- The **N:N same-token-in-one-TX fix is designed but not committed** (breaks
  5 unit tests on the partial-fill/merge boundary, and the full-fill success
  path was never live-verified — see `E2E_LIVE_RESULTS.md`). The
  `BuySweep`/`GtcBuyMultiFill` shape (N sells : 1 buy, merged buyer output)
  is **contract-limited and currently unsettleable** — sell-side F4 wants
  per-sell outputs, buy-side F6 wants one aggregated output, and token
  conservation forbids both. **Trade-tape design implication**: the
  per-leg-record approach above must be scoped to "one record per
  authorized-output-to-input binding" so that whichever multi-fill shape
  eventually lands (at the time of writing: v17 N:1, now v18 N:1 per the note
  above; later, possibly N:N), the indexer (§7.1)
  can derive trades from the settlement TX's actual covenant-authorization
  structure rather than a TX-level aggregate delta — that scoping is a
  design property to hold now, before the indexer is built, not a rewrite to
  do later.
- **`daa_score` on trade records is currently a wall-clock timestamp
  stand-in**, not a real block DAA score (`record_trade`'s own comment:
  "best-effort; exact DAA score not available in executor"). This should be
  threaded from the actual confirmed block's DAA once trades are sourced
  from the confirmed-block indexer (§7.1) rather than the submission-time
  executor path, so trades get a canonical, reorg-safe chain-order key
  instead of a wall-clock proxy.

### 7.7 Suggested rollout order

1. Fix pair-id inconsistency (§7.2) — cheap, unblocks everything else being
   *correct*, not just present.
2. Add `leg_index` to `Trade` (§7.6) — cheap, prevents the aggregator feed
   from shipping with silently-colliding trade IDs on day one.
3. Ship §3 (`/health`, `/sync`, extended `/status`) — pure read-side
   addition over data that already exists (cursor, sink DAA).
4. Build the persistent indexer (§7.1) — the real lift; blocks a
   production-grade `/api/v1/trades` deep history and all of §6.
5. Symbol registry + reference-rate provider (§7.2 tail, §7.3) — needed for
   human-readable `base_symbol`/`base_currency` and any `_usd` fields.
6. Ship `/gecko/*` (§6) once 1–5 are in place, with its own rate-limit/auth
   carve-out (§7.4).
7. WS additions (`ticker:<pair>`, snapshot-on-subscribe, heartbeat — §5) can
   land in parallel with 3–6; they don't depend on the indexer.
