//! SQLite-backed historical data persistence — MT5 style.
//!
//! Only M1 (1-minute) candles are stored. Higher timeframes (5m, 15m, 1h, 4h,
//! 1d, 1w) are aggregated on-the-fly from M1 rows via GROUP BY.
//! Tick (raw trade) data is kept in-memory only (TradeLog ring buffer);
//! clients hold their own tick history.

use rusqlite::{params, Connection};
use std::sync::{Arc, Mutex};
use tracing::info;

use crate::reporting::candle::{Candle, Interval};
use crate::reporting::trades::{RoutingInfo, Side, Trade};
use crate::config::HistoryConfig;

/// SQLite history store — M1 candles only.
pub struct HistoryStore {
    conn: Arc<Mutex<Connection>>,
    config: HistoryConfig,
}

const CREATE_TABLES_SQL: &str = "
CREATE TABLE IF NOT EXISTS candles_1m (
    pair_id     TEXT    NOT NULL,
    open_time   INTEGER NOT NULL,
    open_num    INTEGER NOT NULL,
    open_den    INTEGER NOT NULL,
    high_num    INTEGER NOT NULL,
    high_den    INTEGER NOT NULL,
    low_num     INTEGER NOT NULL,
    low_den     INTEGER NOT NULL,
    close_num   INTEGER NOT NULL,
    close_den   INTEGER NOT NULL,
    volume      INTEGER NOT NULL,
    trade_count INTEGER NOT NULL,
    PRIMARY KEY (pair_id, open_time)
);
CREATE INDEX IF NOT EXISTS idx_candles_1m_time ON candles_1m(pair_id, open_time);

-- H3-TRADES: durable, query-indexed trade ledger. Rows are written only at
-- CONFIRMATION time (the trade's settlement txid observed in a scanned
-- block, via PendingTrades::take_confirmed), never at submission time --
-- see executor.rs's block-scan loop. `block_hash` records which confirmed
-- block a row was committed under, so a later reorg can retract exactly
-- those rows (retract_trades_by_block). This is the data source
-- /api/v1/trades (deep history) and /api/v1/gecko/historical_trades need;
-- the in-memory TradeLog stays the low-latency hot path for recent/WS data.
-- P1 fix: leg_index disambiguates multiple trade rows sharing one txid
-- (cross-pair swaps, v17 N:M sweeps). (txid, leg_index) is the trade key.
CREATE TABLE IF NOT EXISTS trades (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    txid         TEXT    NOT NULL,
    leg_index    INTEGER NOT NULL DEFAULT 0,
    pair_id      TEXT    NOT NULL,
    price_num    INTEGER NOT NULL,
    price_den    INTEGER NOT NULL,
    quantity     INTEGER NOT NULL,
    side         TEXT    NOT NULL,
    daa_score    INTEGER NOT NULL,
    timestamp    INTEGER NOT NULL,
    block_hash   TEXT    NOT NULL,
    routing_json TEXT,
    confirmed_at INTEGER NOT NULL,
    UNIQUE(txid, leg_index)
);
CREATE INDEX IF NOT EXISTS idx_trades_pair_time ON trades(pair_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_trades_pair_daa ON trades(pair_id, daa_score);
CREATE INDEX IF NOT EXISTS idx_trades_txid ON trades(txid);
CREATE INDEX IF NOT EXISTS idx_trades_block_hash ON trades(block_hash);
";

impl HistoryStore {
    /// Open or create the SQLite database.
    pub fn open(config: &HistoryConfig) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(&config.db_path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA cache_size=-8000;
             PRAGMA temp_store=MEMORY;",
        )?;
        conn.execute_batch(CREATE_TABLES_SQL)?;
        info!("History DB opened: {}", config.db_path);
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            config: config.clone(),
        })
    }

    /// Open an in-memory database (for testing).
    pub fn open_memory(config: &HistoryConfig) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(CREATE_TABLES_SQL)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            config: config.clone(),
        })
    }

    /// Upsert a 1-minute candle (the only interval we persist).
    pub fn upsert_m1(&self, pair_id: &str, candle: &Candle) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT INTO candles_1m (pair_id, open_time, open_num, open_den, high_num, high_den, low_num, low_den, close_num, close_den, volume, trade_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(pair_id, open_time) DO UPDATE SET
                high_num = ?5, high_den = ?6,
                low_num = ?7, low_den = ?8,
                close_num = ?9, close_den = ?10,
                volume = ?11,
                trade_count = ?12",
            params![
                pair_id,
                candle.open_time as i64,
                candle.open.0 as i64, candle.open.1 as i64,
                candle.high.0 as i64, candle.high.1 as i64,
                candle.low.0 as i64, candle.low.1 as i64,
                candle.close.0 as i64, candle.close.1 as i64,
                candle.volume as i64,
                candle.trade_count as i32,
            ],
        )?;
        Ok(())
    }

    /// Query M1 candles directly.
    pub fn query_m1(
        &self,
        pair_id: &str,
        start_time: u64,
        end_time: u64,
        limit: usize,
    ) -> Result<Vec<Candle>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT open_time, open_num, open_den, high_num, high_den, low_num, low_den, close_num, close_den, volume, trade_count
             FROM candles_1m
             WHERE pair_id = ?1 AND open_time >= ?2 AND open_time <= ?3
             ORDER BY open_time ASC
             LIMIT ?4",
        )?;
        let candles = stmt
            .query_map(params![pair_id, start_time as i64, end_time as i64, limit as i64], |row| {
                Ok(Candle {
                    open_time: row.get::<_, i64>(0)? as u64,
                    open: (row.get::<_, i64>(1)? as u64, row.get::<_, i64>(2)? as u64),
                    high: (row.get::<_, i64>(3)? as u64, row.get::<_, i64>(4)? as u64),
                    low: (row.get::<_, i64>(5)? as u64, row.get::<_, i64>(6)? as u64),
                    close: (row.get::<_, i64>(7)? as u64, row.get::<_, i64>(8)? as u64),
                    volume: row.get::<_, i64>(9)? as u64,
                    trade_count: row.get::<_, i64>(10)? as u32,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(candles)
    }

    /// Query candles at any interval by aggregating M1 rows.
    ///
    /// For M1 requests, reads directly. For higher TFs (5m, 1h, 1d, etc.),
    /// groups M1 rows into buckets of `interval.seconds()` and computes OHLCV.
    ///
    /// Rational OHLC: open = first M1's open, close = last M1's close.
    /// High/low use MAX/MIN on `num * cross_den` cross-multiplication to
    /// compare rationals without float conversion.
    pub fn query_candles(
        &self,
        pair_id: &str,
        interval: Interval,
        start_time: u64,
        end_time: u64,
        limit: usize,
    ) -> Result<Vec<Candle>, rusqlite::Error> {
        if interval == Interval::M1 {
            return self.query_m1(pair_id, start_time, end_time, limit);
        }

        let bucket_secs = interval.seconds() as i64;
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());

        // Aggregate M1 rows into buckets.
        // For rational OHLC we need first/last row per bucket + max/min.
        // SQLite doesn't have FIRST_VALUE aggregate, so we use a subquery approach.
        //
        // Strategy: fetch all M1 rows in range, aggregate in Rust.
        // This is simpler and correct for rational price comparison.
        // Cap source M1 rows to prevent loading millions of rows into memory (M-4).
        // 43,200 = 30 days of M1 candles (60 * 24 * 30). For higher timeframes
        // this is more than enough to produce `limit` output candles.
        const MAX_M1_ROWS: i64 = 43_200;

        let mut stmt = conn.prepare(
            "SELECT open_time, open_num, open_den, high_num, high_den, low_num, low_den, close_num, close_den, volume, trade_count
             FROM candles_1m
             WHERE pair_id = ?1 AND open_time >= ?2 AND open_time <= ?3
             ORDER BY open_time ASC
             LIMIT ?4",
        )?;

        let m1_rows: Vec<Candle> = stmt
            .query_map(params![pair_id, start_time as i64, end_time as i64, MAX_M1_ROWS], |row| {
                Ok(Candle {
                    open_time: row.get::<_, i64>(0)? as u64,
                    open: (row.get::<_, i64>(1)? as u64, row.get::<_, i64>(2)? as u64),
                    high: (row.get::<_, i64>(3)? as u64, row.get::<_, i64>(4)? as u64),
                    low: (row.get::<_, i64>(5)? as u64, row.get::<_, i64>(6)? as u64),
                    close: (row.get::<_, i64>(7)? as u64, row.get::<_, i64>(8)? as u64),
                    volume: row.get::<_, i64>(9)? as u64,
                    trade_count: row.get::<_, i64>(10)? as u32,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        // Group into buckets and aggregate
        let mut result: Vec<Candle> = Vec::new();
        let mut current_bucket: Option<Candle> = None;
        let bucket_secs_u64 = bucket_secs as u64;

        for m1 in &m1_rows {
            let bucket_start = (m1.open_time / bucket_secs_u64) * bucket_secs_u64;

            if let Some(ref mut bucket) = current_bucket {
                if bucket.open_time == bucket_start {
                    // Same bucket — update high, low, close, volume, count
                    // High: cross-multiply to compare rationals
                    let m1_high_cross = m1.high.0 as u128 * bucket.high.1 as u128;
                    let bucket_high_cross = bucket.high.0 as u128 * m1.high.1 as u128;
                    if m1_high_cross > bucket_high_cross {
                        bucket.high = m1.high;
                    }
                    // Low
                    let m1_low_cross = m1.low.0 as u128 * bucket.low.1 as u128;
                    let bucket_low_cross = bucket.low.0 as u128 * m1.low.1 as u128;
                    if m1_low_cross < bucket_low_cross {
                        bucket.low = m1.low;
                    }
                    bucket.close = m1.close;
                    bucket.volume = bucket.volume.saturating_add(m1.volume);
                    bucket.trade_count = bucket.trade_count.saturating_add(m1.trade_count);
                } else {
                    // New bucket — push previous
                    result.push(bucket.clone());
                    if result.len() >= limit {
                        return Ok(result);
                    }
                    *bucket = Candle {
                        open_time: bucket_start,
                        open: m1.open,
                        high: m1.high,
                        low: m1.low,
                        close: m1.close,
                        volume: m1.volume,
                        trade_count: m1.trade_count,
                    };
                }
            } else {
                current_bucket = Some(Candle {
                    open_time: bucket_start,
                    open: m1.open,
                    high: m1.high,
                    low: m1.low,
                    close: m1.close,
                    volume: m1.volume,
                    trade_count: m1.trade_count,
                });
            }
        }

        // Push last bucket
        if let Some(bucket) = current_bucket {
            if result.len() < limit {
                result.push(bucket);
            }
        }

        Ok(result)
    }

    /// Get the latest M1 candle for a pair.
    pub fn latest_m1(&self, pair_id: &str) -> Result<Option<Candle>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT open_time, open_num, open_den, high_num, high_den, low_num, low_den, close_num, close_den, volume, trade_count
             FROM candles_1m WHERE pair_id = ?1 ORDER BY open_time DESC LIMIT 1",
        )?;
        let mut rows = stmt.query(params![pair_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(Candle {
                open_time: row.get::<_, i64>(0)? as u64,
                open: (row.get::<_, i64>(1)? as u64, row.get::<_, i64>(2)? as u64),
                high: (row.get::<_, i64>(3)? as u64, row.get::<_, i64>(4)? as u64),
                low: (row.get::<_, i64>(5)? as u64, row.get::<_, i64>(6)? as u64),
                close: (row.get::<_, i64>(7)? as u64, row.get::<_, i64>(8)? as u64),
                volume: row.get::<_, i64>(9)? as u64,
                trade_count: row.get::<_, i64>(10)? as u32,
            }))
        } else {
            Ok(None)
        }
    }

    /// Count M1 candles for a pair.
    pub fn m1_count(&self, pair_id: &str) -> Result<u64, rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            "SELECT COUNT(*) FROM candles_1m WHERE pair_id = ?1",
            params![pair_id],
            |row| row.get::<_, i64>(0),
        )
        .map(|c| c as u64)
    }

    /// Total M1 candle count across all pairs.
    pub fn total_m1_count(&self) -> Result<u64, rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row("SELECT COUNT(*) FROM candles_1m", [], |row| {
            row.get::<_, i64>(0)
        })
        .map(|c| c as u64)
    }

    /// Purge old M1 candles based on retention config.
    /// Returns number of rows deleted.
    pub fn purge_expired(&self) -> Result<usize, rusqlite::Error> {
        // retention_secs == 0 means forever
        if self.config.m1_retention_secs == 0 {
            return self.purge_by_size();
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs();
        let cutoff = now.saturating_sub(self.config.m1_retention_secs);

        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let deleted = conn.execute(
            "DELETE FROM candles_1m WHERE open_time < ?1",
            params![cutoff as i64],
        )?;

        if deleted > 0 {
            info!("History purge: {} M1 candles deleted (time-based)", deleted);
        }

        drop(conn);
        let size_deleted = self.purge_by_size()?;
        Ok(deleted + size_deleted)
    }

    /// Size-based pruning: delete oldest M1 candles when DB exceeds cap.
    fn purge_by_size(&self) -> Result<usize, rusqlite::Error> {
        if self.config.max_db_size_mb == 0 {
            return Ok(0);
        }

        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let db_size_bytes: i64 = conn
            .query_row(
                "SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        let db_size_mb = db_size_bytes as u64 / (1024 * 1024);

        if db_size_mb <= self.config.max_db_size_mb {
            return Ok(0);
        }

        info!(
            "History DB {}MB exceeds cap {}MB — pruning oldest M1",
            db_size_mb, self.config.max_db_size_mb
        );

        let count: i64 = conn.query_row("SELECT COUNT(*) FROM candles_1m", [], |row| row.get(0))?;
        if count <= 100 {
            return Ok(0);
        }
        let to_delete = count / 10; // delete oldest 10%
        let deleted = conn.execute(
            "DELETE FROM candles_1m WHERE rowid IN (
                SELECT rowid FROM candles_1m ORDER BY open_time ASC LIMIT ?1
            )",
            params![to_delete],
        )?;
        if deleted > 0 {
            info!("History purge: {} M1 candles deleted (size-based)", deleted);
        }
        Ok(deleted)
    }

    // Durable trade ledger (H3-TRADES)

    /// Persist a CONFIRMED trade, tagged with the block it was confirmed
    /// under. Returns the new row id.
    ///
    /// Callers must only call this once a trade's txid has actually been
    /// observed in a scanned block (see `PendingTrades::take_confirmed` in
    /// `reporting::trades`) -- never at submission time.
    pub fn insert_confirmed_trade(
        &self,
        trade: &Trade,
        block_hash: &str,
    ) -> Result<i64, rusqlite::Error> {
        let side_str = match trade.side {
            Side::Buy => "buy",
            Side::Sell => "sell",
        };
        let routing_json = trade
            .routing
            .as_ref()
            .map(|r| serde_json::to_string(r).unwrap_or_default());
        let confirmed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT INTO trades (txid, leg_index, pair_id, price_num, price_den, quantity, side, daa_score, timestamp, block_hash, routing_json, confirmed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                trade.txid,
                trade.leg_index,
                trade.pair_id,
                trade.price_num as i64,
                trade.price_den as i64,
                trade.quantity as i64,
                side_str,
                trade.daa_score as i64,
                trade.timestamp as i64,
                block_hash,
                routing_json,
                confirmed_at as i64,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Retract (delete) every durably-persisted trade recorded under
    /// `block_hash`. Called when a chain reorg removes that block, so a
    /// trade whose confirming block no longer exists on-chain doesn't stay
    /// in the ledger. Returns the number of rows deleted (0 if none, e.g.
    /// the reorged block never had a confirmed trade).
    pub fn retract_trades_by_block(&self, block_hash: &str) -> Result<usize, rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute("DELETE FROM trades WHERE block_hash = ?1", params![block_hash])
    }

    fn row_to_trade(row: &rusqlite::Row) -> rusqlite::Result<Trade> {
        let side_str: String = row.get(6)?;
        let side = if side_str == "sell" { Side::Sell } else { Side::Buy };
        let routing_json: Option<String> = row.get(10)?;
        let routing: Option<RoutingInfo> = routing_json
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok());
        Ok(Trade {
            txid: row.get(0)?,
            leg_index: row.get::<_, i64>(1)? as u32,
            pair_id: row.get(2)?,
            price_num: row.get::<_, i64>(3)? as u64,
            price_den: row.get::<_, i64>(4)? as u64,
            quantity: row.get::<_, i64>(5)? as u64,
            side,
            daa_score: row.get::<_, i64>(7)? as u64,
            timestamp: row.get::<_, i64>(8)? as u64,
            routing,
        })
    }

    const TRADE_SELECT_COLS: &'static str =
        "txid, leg_index, pair_id, price_num, price_den, quantity, side, daa_score, timestamp, block_hash, routing_json";

    /// Most recent `limit` durably-confirmed trades for a pair, newest first.
    pub fn recent_trades(&self, pair_id: &str, limit: usize) -> Result<Vec<Trade>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let sql = format!(
            "SELECT {} FROM trades WHERE pair_id = ?1 ORDER BY id DESC LIMIT ?2",
            Self::TRADE_SELECT_COLS
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt
            .query_map(params![pair_id, limit as i64], |row| Self::row_to_trade(row))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Durably-confirmed trades for a pair with `daa_score >= daa_score`, oldest first.
    pub fn trades_since(&self, pair_id: &str, daa_score: u64) -> Result<Vec<Trade>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let sql = format!(
            "SELECT {} FROM trades WHERE pair_id = ?1 AND daa_score >= ?2 ORDER BY id ASC",
            Self::TRADE_SELECT_COLS
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt
            .query_map(params![pair_id, daa_score as i64], |row| Self::row_to_trade(row))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Durably-confirmed trades for a pair in `[start_time, end_time]`
    /// (inclusive, either bound optional), newest first, capped at `limit`.
    /// Mirrors `TradeLog::range`'s contract for the durable store.
    pub fn trades_range(
        &self,
        pair_id: &str,
        start_time: Option<u64>,
        end_time: Option<u64>,
        limit: usize,
    ) -> Result<Vec<Trade>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let sql = format!(
            "SELECT {} FROM trades WHERE pair_id = ?1
             AND (?2 IS NULL OR timestamp >= ?2)
             AND (?3 IS NULL OR timestamp <= ?3)
             ORDER BY id DESC LIMIT ?4",
            Self::TRADE_SELECT_COLS
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt
            .query_map(
                params![
                    pair_id,
                    start_time.map(|v| v as i64),
                    end_time.map(|v| v as i64),
                    limit as i64
                ],
                |row| Self::row_to_trade(row),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Total durably-confirmed trade count for a pair.
    pub fn trade_count(&self, pair_id: &str) -> Result<u64, rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            "SELECT COUNT(*) FROM trades WHERE pair_id = ?1",
            params![pair_id],
            |row| row.get::<_, i64>(0),
        )
        .map(|c| c as u64)
    }

    /// Total durably-confirmed trade count across all pairs.
    pub fn total_trade_count(&self) -> Result<u64, rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row("SELECT COUNT(*) FROM trades", [], |row| row.get::<_, i64>(0))
            .map(|c| c as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> HistoryConfig {
        HistoryConfig {
            db_path: ":memory:".to_string(),
            m1_retention_secs: 0,  // forever for tests
            purge_interval_secs: 3600,
            max_db_size_mb: 0,     // no size limit for tests
        }
    }

    fn make_m1(open_time: u64, price_num: u64, price_den: u64) -> Candle {
        Candle {
            open_time,
            open: (price_num, price_den),
            high: (price_num + 10, price_den),
            low: (price_num.saturating_sub(5), price_den),
            close: (price_num + 3, price_den),
            volume: 50000,
            trade_count: 5,
        }
    }

    #[test]
    fn test_open_memory() {
        let store = HistoryStore::open_memory(&test_config()).unwrap();
        assert_eq!(store.total_m1_count().unwrap(), 0);
    }

    #[test]
    fn test_upsert_and_query_m1() {
        let store = HistoryStore::open_memory(&test_config()).unwrap();
        let candle = make_m1(60, 100, 1);
        store.upsert_m1("T/KAS", &candle).unwrap();

        let result = store.query_m1("T/KAS", 0, 120, 100).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].open_time, 60);
        assert_eq!(result[0].open, (100, 1));
    }

    #[test]
    fn test_upsert_updates_existing() {
        let store = HistoryStore::open_memory(&test_config()).unwrap();
        store.upsert_m1("T/KAS", &make_m1(60, 100, 1)).unwrap();

        let mut updated = make_m1(60, 100, 1);
        updated.high = (200, 1);
        updated.trade_count = 12;
        store.upsert_m1("T/KAS", &updated).unwrap();

        let result = store.query_m1("T/KAS", 0, 120, 100).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].high, (200, 1));
        assert_eq!(result[0].trade_count, 12);
    }

    #[test]
    fn test_aggregate_5m_from_m1() {
        let store = HistoryStore::open_memory(&test_config()).unwrap();
        // Insert 10 M1 candles (0, 60, 120, 180, 240, 300, 360, 420, 480, 540)
        for i in 0..10 {
            let ts = i * 60;
            store.upsert_m1("T/KAS", &make_m1(ts, 100 + i, 1)).unwrap();
        }

        // Query as 5m — should get 2 buckets: [0..299] and [300..599]
        let candles = store
            .query_candles("T/KAS", Interval::M5, 0, 600, 100)
            .unwrap();
        assert_eq!(candles.len(), 2);

        // First bucket: open_time=0, open from first M1, close from 5th M1
        assert_eq!(candles[0].open_time, 0);
        assert_eq!(candles[0].open, (100, 1)); // first M1
        assert_eq!(candles[0].close, (107, 1)); // close of M1 at ts=240 (i=4)

        // Second bucket: open_time=300
        assert_eq!(candles[1].open_time, 300);
        assert_eq!(candles[1].open, (105, 1)); // M1 at ts=300 (i=5)
    }

    #[test]
    fn test_aggregate_1h_from_m1() {
        let store = HistoryStore::open_memory(&test_config()).unwrap();
        // Insert 120 M1 candles (2 hours)
        for i in 0..120 {
            store
                .upsert_m1("T/KAS", &make_m1(i * 60, 100 + i % 20, 1))
                .unwrap();
        }

        let candles = store
            .query_candles("T/KAS", Interval::H1, 0, 7200, 100)
            .unwrap();
        assert_eq!(candles.len(), 2);
        assert_eq!(candles[0].open_time, 0);
        assert_eq!(candles[1].open_time, 3600);
        // Volume: 60 M1s × 50000 each
        assert_eq!(candles[0].volume, 60 * 50000);
    }

    #[test]
    fn test_aggregate_1d_from_m1() {
        let store = HistoryStore::open_memory(&test_config()).unwrap();
        // Insert M1 at start of 2 days
        store.upsert_m1("T/KAS", &make_m1(0, 100, 1)).unwrap();
        store.upsert_m1("T/KAS", &make_m1(60, 110, 1)).unwrap();
        store.upsert_m1("T/KAS", &make_m1(86400, 200, 1)).unwrap();

        let candles = store
            .query_candles("T/KAS", Interval::D1, 0, 90000, 100)
            .unwrap();
        assert_eq!(candles.len(), 2);
        assert_eq!(candles[0].open_time, 0);
        assert_eq!(candles[0].volume, 100000); // 2 M1s
        assert_eq!(candles[1].open_time, 86400);
    }

    #[test]
    fn test_aggregate_1w_from_m1() {
        let store = HistoryStore::open_memory(&test_config()).unwrap();
        store.upsert_m1("T/KAS", &make_m1(0, 100, 1)).unwrap();
        store.upsert_m1("T/KAS", &make_m1(604800, 200, 1)).unwrap(); // week 2

        let candles = store
            .query_candles("T/KAS", Interval::W1, 0, 700000, 100)
            .unwrap();
        assert_eq!(candles.len(), 2);
        assert_eq!(candles[0].open, (100, 1));
        assert_eq!(candles[1].open, (200, 1));
    }

    #[test]
    fn test_aggregate_high_low_rational() {
        let store = HistoryStore::open_memory(&test_config()).unwrap();
        // M1 candles with different rational prices
        let mut c1 = make_m1(0, 3, 2);   // price = 1.5
        c1.high = (3, 2);
        c1.low = (3, 2);
        store.upsert_m1("T/KAS", &c1).unwrap();

        let mut c2 = make_m1(60, 5, 3);  // price = 1.667 (higher)
        c2.high = (5, 3);
        c2.low = (1, 1);   // price = 1.0 (lowest)
        store.upsert_m1("T/KAS", &c2).unwrap();

        let candles = store
            .query_candles("T/KAS", Interval::M5, 0, 300, 100)
            .unwrap();
        assert_eq!(candles.len(), 1);
        // High should be (5,3) because 5/3 > 3/2 (5*2=10 > 3*3=9)
        assert_eq!(candles[0].high, (5, 3));
        // Low should be (1,1) because 1/1 < 3/2
        assert_eq!(candles[0].low, (1, 1));
    }

    #[test]
    fn test_query_limit() {
        let store = HistoryStore::open_memory(&test_config()).unwrap();
        for i in 0..100 {
            store.upsert_m1("T/KAS", &make_m1(i * 60, 100, 1)).unwrap();
        }
        let candles = store.query_m1("T/KAS", 0, 99999, 5).unwrap();
        assert_eq!(candles.len(), 5);
    }

    #[test]
    fn test_multiple_pairs() {
        let store = HistoryStore::open_memory(&test_config()).unwrap();
        store.upsert_m1("USDC/KAS", &make_m1(60, 100, 1)).unwrap();
        store.upsert_m1("NACHO/KAS", &make_m1(60, 200, 1)).unwrap();
        store.upsert_m1("USDC/KAS", &make_m1(120, 101, 1)).unwrap();

        assert_eq!(store.m1_count("USDC/KAS").unwrap(), 2);
        assert_eq!(store.m1_count("NACHO/KAS").unwrap(), 1);
    }

    #[test]
    fn test_latest_m1() {
        let store = HistoryStore::open_memory(&test_config()).unwrap();
        store.upsert_m1("T/KAS", &make_m1(60, 100, 1)).unwrap();
        store.upsert_m1("T/KAS", &make_m1(300, 110, 1)).unwrap();
        store.upsert_m1("T/KAS", &make_m1(180, 105, 1)).unwrap();

        let latest = store.latest_m1("T/KAS").unwrap().unwrap();
        assert_eq!(latest.open_time, 300);
    }

    #[test]
    fn test_purge_by_retention() {
        let mut cfg = test_config();
        cfg.m1_retention_secs = 3600; // 1 hour
        let store = HistoryStore::open_memory(&cfg).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs();
        let now_aligned = (now / 60) * 60;

        // Old candle (2 hours ago)
        store.upsert_m1("T/KAS", &make_m1(now_aligned - 7200, 100, 1)).unwrap();
        // Recent candle
        store.upsert_m1("T/KAS", &make_m1(now_aligned - 60, 110, 1)).unwrap();

        let deleted = store.purge_expired().unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(store.m1_count("T/KAS").unwrap(), 1);
    }

    #[test]
    fn test_purge_keeps_all_when_forever() {
        let store = HistoryStore::open_memory(&test_config()).unwrap(); // m1_retention_secs=0
        store.upsert_m1("T/KAS", &make_m1(60, 100, 1)).unwrap();

        let deleted = store.purge_expired().unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(store.m1_count("T/KAS").unwrap(), 1);
    }

    #[test]
    fn test_m1_passthrough_for_query_candles() {
        let store = HistoryStore::open_memory(&test_config()).unwrap();
        store.upsert_m1("T/KAS", &make_m1(60, 100, 1)).unwrap();
        store.upsert_m1("T/KAS", &make_m1(120, 105, 1)).unwrap();

        // query_candles with M1 interval should return raw M1s
        let candles = store
            .query_candles("T/KAS", Interval::M1, 0, 200, 100)
            .unwrap();
        assert_eq!(candles.len(), 2);
        assert_eq!(candles[0].open_time, 60);
        assert_eq!(candles[1].open_time, 120);
    }

    // Durable trade ledger (H3-TRADES)

    fn make_trade(txid: &str, pair: &str, price_num: u64, daa: u64) -> Trade {
        make_trade_leg(txid, 0, pair, price_num, daa)
    }

    fn make_trade_leg(txid: &str, leg_index: u32, pair: &str, price_num: u64, daa: u64) -> Trade {
        Trade {
            txid: txid.to_string(),
            leg_index,
            pair_id: pair.to_string(),
            price_num,
            price_den: 1,
            quantity: 100,
            side: Side::Buy,
            daa_score: daa,
            timestamp: daa,
            routing: None,
        }
    }

    #[test]
    fn test_insert_and_recent_trades() {
        let store = HistoryStore::open_memory(&test_config()).unwrap();
        store.insert_confirmed_trade(&make_trade("tx1", "T/KAS", 10, 100), "blockA").unwrap();
        store.insert_confirmed_trade(&make_trade("tx2", "T/KAS", 20, 200), "blockA").unwrap();

        let recent = store.recent_trades("T/KAS", 10).unwrap();
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].txid, "tx2", "newest first");
        assert_eq!(recent[1].txid, "tx1");
        assert_eq!(store.trade_count("T/KAS").unwrap(), 2);
        assert_eq!(store.total_trade_count().unwrap(), 2);
    }

    /// P1 fix: multiple legs of a v17 N:M sweep sharing one txid must
    /// persist as distinct durable rows, keyed by (txid, leg_index).
    #[test]
    fn test_insert_multiple_legs_same_txid_are_distinct_durable_rows() {
        let store = HistoryStore::open_memory(&test_config()).unwrap();
        for leg in 0..4u32 {
            store
                .insert_confirmed_trade(&make_trade_leg("sweep_tx", leg, "T/KAS", 10 + leg as u64, 100), "blockA")
                .unwrap();
        }

        let recent = store.recent_trades("T/KAS", 10).unwrap();
        assert_eq!(recent.len(), 4, "all 4 legs must persist as distinct rows");
        let mut legs: Vec<u32> = recent.iter().map(|t| t.leg_index).collect();
        legs.sort();
        assert_eq!(legs, vec![0, 1, 2, 3]);
        assert!(recent.iter().all(|t| t.txid == "sweep_tx"));

        let ids: std::collections::HashSet<String> = recent.iter().map(|t| t.trade_id()).collect();
        assert_eq!(ids.len(), 4, "(txid, leg_index) must be unique per row");
    }

    /// The UNIQUE(txid, leg_index) constraint rejects a duplicate leg for
    /// the same txid (defends against double-confirmation re-inserting the
    /// same leg).
    #[test]
    fn test_duplicate_leg_index_for_same_txid_is_rejected() {
        let store = HistoryStore::open_memory(&test_config()).unwrap();
        store.insert_confirmed_trade(&make_trade_leg("tx1", 0, "T/KAS", 10, 100), "blockA").unwrap();
        let result = store.insert_confirmed_trade(&make_trade_leg("tx1", 0, "T/KAS", 10, 100), "blockA");
        assert!(result.is_err(), "inserting the same (txid, leg_index) twice must fail the UNIQUE constraint");
        assert_eq!(store.trade_count("T/KAS").unwrap(), 1, "only the first insert must have landed");
    }

    #[test]
    fn test_trade_persistence_survives_reopen() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("test_trade_persist_{}.sqlite", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut cfg = test_config();
        cfg.db_path = path.to_string_lossy().to_string();

        {
            let store = HistoryStore::open(&cfg).unwrap();
            store.insert_confirmed_trade(&make_trade("tx1", "T/KAS", 10, 100), "blockA").unwrap();
        }

        {
            // Reopen — durable trade must still be there.
            let store = HistoryStore::open(&cfg).unwrap();
            let recent = store.recent_trades("T/KAS", 10).unwrap();
            assert_eq!(recent.len(), 1, "confirmed trade must survive a process restart");
            assert_eq!(recent[0].txid, "tx1");
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn test_retract_trades_by_block_removes_only_that_block() {
        let store = HistoryStore::open_memory(&test_config()).unwrap();
        store.insert_confirmed_trade(&make_trade("tx1", "T/KAS", 10, 100), "blockA").unwrap();
        store.insert_confirmed_trade(&make_trade("tx2", "T/KAS", 20, 200), "blockB").unwrap();
        store.insert_confirmed_trade(&make_trade("tx3", "T/KAS", 30, 300), "blockA").unwrap();
        assert_eq!(store.trade_count("T/KAS").unwrap(), 3);

        // Reorg retracts blockA: tx1 and tx3 (both under blockA) must be
        // deleted; tx2 (blockB) must survive untouched.
        let retracted = store.retract_trades_by_block("blockA").unwrap();
        assert_eq!(retracted, 2, "both blockA trades must be retracted");

        let remaining = store.recent_trades("T/KAS", 10).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].txid, "tx2", "blockB's trade must survive the blockA reorg-retract");
        assert_eq!(store.trade_count("T/KAS").unwrap(), 1);
    }

    #[test]
    fn test_retract_trades_by_block_no_match_is_noop() {
        let store = HistoryStore::open_memory(&test_config()).unwrap();
        store.insert_confirmed_trade(&make_trade("tx1", "T/KAS", 10, 100), "blockA").unwrap();

        let retracted = store.retract_trades_by_block("nonexistent_block").unwrap();
        assert_eq!(retracted, 0);
        assert_eq!(store.trade_count("T/KAS").unwrap(), 1, "unrelated block retraction must not touch other rows");
    }

    #[test]
    fn test_trades_since_daa_filter() {
        let store = HistoryStore::open_memory(&test_config()).unwrap();
        store.insert_confirmed_trade(&make_trade("tx1", "T/KAS", 10, 100), "b1").unwrap();
        store.insert_confirmed_trade(&make_trade("tx2", "T/KAS", 20, 200), "b2").unwrap();
        store.insert_confirmed_trade(&make_trade("tx3", "T/KAS", 30, 300), "b3").unwrap();

        let since_200 = store.trades_since("T/KAS", 200).unwrap();
        assert_eq!(since_200.len(), 2, "oldest-first, daa_score >= 200");
        assert_eq!(since_200[0].txid, "tx2");
        assert_eq!(since_200[1].txid, "tx3");
    }

    #[test]
    fn test_trades_range_time_bounds() {
        let store = HistoryStore::open_memory(&test_config()).unwrap();
        store.insert_confirmed_trade(&make_trade("tx1", "T/KAS", 10, 100), "b1").unwrap();
        store.insert_confirmed_trade(&make_trade("tx2", "T/KAS", 20, 200), "b2").unwrap();
        store.insert_confirmed_trade(&make_trade("tx3", "T/KAS", 30, 300), "b3").unwrap();

        let result = store.trades_range("T/KAS", Some(200), Some(300), 10).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].txid, "tx3", "newest first");
        assert_eq!(result[1].txid, "tx2");

        let no_bounds = store.trades_range("T/KAS", None, None, 10).unwrap();
        assert_eq!(no_bounds.len(), 3);
    }

    #[test]
    fn test_trades_isolated_per_pair() {
        let store = HistoryStore::open_memory(&test_config()).unwrap();
        store.insert_confirmed_trade(&make_trade("tx1", "A/KAS", 10, 100), "b1").unwrap();
        store.insert_confirmed_trade(&make_trade("tx2", "B/KAS", 20, 200), "b1").unwrap();

        assert_eq!(store.trade_count("A/KAS").unwrap(), 1);
        assert_eq!(store.trade_count("B/KAS").unwrap(), 1);
        assert_eq!(store.total_trade_count().unwrap(), 2);
    }

    #[test]
    fn test_trade_routing_info_roundtrip() {
        let store = HistoryStore::open_memory(&test_config()).unwrap();
        let mut trade = make_trade("tx_cp", "cross:A->B", 1, 100);
        trade.routing = Some(RoutingInfo {
            sell_pair: "A/KAS".to_string(),
            buy_pair: "B/KAS".to_string(),
            intermediate_token: "KAS".to_string(),
            kas_through: 5_000_000,
            sell_price_num: 1,
            sell_price_den: 2,
            buy_price_num: 1,
            buy_price_den: 3,
            surplus: 2_000_000,
        });
        store.insert_confirmed_trade(&trade, "blockA").unwrap();

        let recent = store.recent_trades("cross:A->B", 10).unwrap();
        assert_eq!(recent.len(), 1);
        let routing = recent[0].routing.as_ref().expect("routing must survive SQLite roundtrip");
        assert_eq!(routing.sell_pair, "A/KAS");
        assert_eq!(routing.kas_through, 5_000_000);
    }

    #[test]
    fn test_trade_without_routing_deserializes_none() {
        let store = HistoryStore::open_memory(&test_config()).unwrap();
        store.insert_confirmed_trade(&make_trade("tx1", "T/KAS", 10, 100), "b1").unwrap();
        let recent = store.recent_trades("T/KAS", 10).unwrap();
        assert!(recent[0].routing.is_none());
    }
}
