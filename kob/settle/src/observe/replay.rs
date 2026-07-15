//! Durable submitted-payment / replay log.
//!
//! A minimal, dependency-light durable store for the settlement layer: it
//! records every payment transaction the facilitator has submitted (or is
//! about to submit) so that (a) a repeated `/settle` on the same artifact
//! after a crash is idempotent instead of re-broadcasting, and (b) a
//! *different* artifact that tries to re-spend an already-consumed input
//! outpoint is caught before broadcast.
//!
//! Storage is an append-only JSON-lines file (one `PaymentRecord` per line).
//! No SQLite/RocksDB dependency — the settlement core stays leaf-light. On
//! open, the file is replayed in order with last-write-wins per txid, so a
//! status update is just another appended line. Each write is flushed +
//! `sync_all`'d so a crash immediately after a successful broadcast still
//! leaves the record on disk.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Lifecycle status of a recorded payment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaymentStatus {
    /// Recorded, broadcast attempted — not yet observed on-chain.
    Submitted,
    /// Observed and finality-confirmed on-chain.
    Confirmed,
    /// Broadcast or confirmation failed permanently.
    Failed,
}

/// A single recorded payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRecord {
    /// Replay key for the payment. The facilitator uses a deterministic
    /// artifact id (a hash of the signed transaction) here, so the key is
    /// known before broadcast; the canonical on-chain transaction id is
    /// stored separately in `chain_txid` once the node accepts the tx.
    pub txid: String,
    /// The canonical on-chain transaction id, learned from the node's
    /// `submitTransaction` response. `None` until broadcast succeeds. Used so
    /// an idempotent `/settle` retry returns the same on-chain txid it
    /// returned the first time.
    #[serde(default)]
    pub chain_txid: Option<String>,
    /// Consumed input outpoints ("txid:index"). These are what a *different*
    /// artifact must not re-spend.
    pub outpoints: Vec<String>,
    /// x402 request-fingerprint this payment was bound to (if any). Lets the
    /// facilitator tell "same artifact, same request" (idempotent retry)
    /// apart from "same artifact, different request" (replay attempt).
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// Payer address (derived from the spent input SPK), if known.
    #[serde(default)]
    pub payer: Option<String>,
    /// Recipient address the payment was verified against, if known.
    #[serde(default)]
    pub pay_to: Option<String>,
    /// Amount paid to `pay_to`, in sompi.
    #[serde(default)]
    pub amount: u64,
    /// Lifecycle status.
    pub status: PaymentStatus,
    /// Unix seconds when this record (line) was written.
    pub recorded_at_secs: u64,
}

impl PaymentRecord {
    /// Construct a fresh `Submitted` record with the current timestamp.
    pub fn submitted(txid: impl Into<String>, outpoints: Vec<String>) -> Self {
        PaymentRecord {
            txid: txid.into(),
            chain_txid: None,
            outpoints,
            fingerprint: None,
            payer: None,
            pay_to: None,
            amount: 0,
            status: PaymentStatus::Submitted,
            recorded_at_secs: now_secs(),
        }
    }

    /// Builder: set the canonical on-chain transaction id.
    pub fn with_chain_txid(mut self, chain_txid: impl Into<String>) -> Self {
        self.chain_txid = Some(chain_txid.into());
        self
    }

    /// Builder: bind an x402 request fingerprint.
    pub fn with_fingerprint(mut self, fp: impl Into<String>) -> Self {
        self.fingerprint = Some(fp.into());
        self
    }

    /// Builder: set payer / recipient / amount context.
    pub fn with_parties(mut self, payer: Option<String>, pay_to: Option<String>, amount: u64) -> Self {
        self.payer = payer;
        self.pay_to = pay_to;
        self.amount = amount;
        self
    }
}

/// Outcome of a replay check against the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayCheck {
    /// Neither the txid nor any of its outpoints has been seen — safe to
    /// record and broadcast.
    Fresh,
    /// This exact txid is already recorded (idempotent retry of the same
    /// artifact). Carries the stored status so the caller can short-circuit
    /// `/settle` to the previously-recorded outcome.
    DuplicateTxid(PaymentStatus),
    /// A *different* txid already consumed one of these input outpoints — a
    /// double-spend / replay attempt. Carries the offending outpoint and the
    /// txid that first consumed it.
    OutpointReused { outpoint: String, existing_txid: String },
}

/// Durable append-only payment / replay store.
pub struct ReplayStore {
    path: PathBuf,
    file: File,
    by_txid: HashMap<String, PaymentRecord>,
    /// outpoint_key -> txid that consumed it.
    by_outpoint: HashMap<String, String>,
}

impl ReplayStore {
    /// Open (creating if absent) a replay store at `path`, replaying any
    /// existing records into the in-memory index.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut by_txid: HashMap<String, PaymentRecord> = HashMap::new();
        let mut by_outpoint: HashMap<String, String> = HashMap::new();

        if path.exists() {
            let f = File::open(&path)?;
            for line in BufReader::new(f).lines() {
                let line = line?;
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                // Tolerate a corrupt/truncated trailing line (e.g. a crash
                // mid-write) by skipping it rather than failing to open.
                if let Ok(rec) = serde_json::from_str::<PaymentRecord>(line) {
                    Self::index_record(&mut by_txid, &mut by_outpoint, rec);
                }
            }
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;

        Ok(ReplayStore { path, file, by_txid, by_outpoint })
    }

    fn index_record(
        by_txid: &mut HashMap<String, PaymentRecord>,
        by_outpoint: &mut HashMap<String, String>,
        rec: PaymentRecord,
    ) {
        for op in &rec.outpoints {
            // First writer of an outpoint wins the association; a later
            // record for the *same* txid may repeat its own outpoints (status
            // update) — keep pointing at that same txid.
            by_outpoint.entry(op.clone()).or_insert_with(|| rec.txid.clone());
        }
        by_txid.insert(rec.txid.clone(), rec);
    }

    /// Path this store is backed by.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Number of distinct payments recorded.
    pub fn len(&self) -> usize {
        self.by_txid.len()
    }

    /// Whether the store has no records.
    pub fn is_empty(&self) -> bool {
        self.by_txid.is_empty()
    }

    /// Look up a recorded payment by txid.
    pub fn get(&self, txid: &str) -> Option<&PaymentRecord> {
        self.by_txid.get(txid)
    }

    /// Whether this txid is already recorded.
    pub fn contains_txid(&self, txid: &str) -> bool {
        self.by_txid.contains_key(txid)
    }

    /// The txid that consumed `outpoint_key`, if any.
    pub fn outpoint_consumer(&self, outpoint_key: &str) -> Option<&str> {
        self.by_outpoint.get(outpoint_key).map(|s| s.as_str())
    }

    /// Decide whether a candidate (txid, outpoints) is safe to settle.
    ///
    /// - Same txid already present -> `DuplicateTxid` (idempotent retry).
    /// - Any outpoint already consumed by a *different* txid -> `OutpointReused`.
    /// - Otherwise -> `Fresh`.
    pub fn check_replay(&self, txid: &str, outpoints: &[String]) -> ReplayCheck {
        if let Some(rec) = self.by_txid.get(txid) {
            return ReplayCheck::DuplicateTxid(rec.status);
        }
        for op in outpoints {
            if let Some(existing) = self.by_outpoint.get(op) {
                if existing != txid {
                    return ReplayCheck::OutpointReused {
                        outpoint: op.clone(),
                        existing_txid: existing.clone(),
                    };
                }
            }
        }
        ReplayCheck::Fresh
    }

    /// Append a record (durably) and update the in-memory index.
    ///
    /// Idempotent status updates: re-recording an existing txid overwrites its
    /// in-memory record and appends a fresh line; on reload the last line
    /// wins. The outpoint->txid association is not moved (first writer wins),
    /// which is correct — a status update repeats the same txid's outpoints.
    pub fn record(&mut self, rec: PaymentRecord) -> std::io::Result<()> {
        let line = serde_json::to_string(&rec)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        self.file.write_all(line.as_bytes())?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;
        // Durability: force the record to disk so a crash right after a
        // successful broadcast cannot lose it (which would allow a re-settle
        // to double-broadcast).
        self.file.sync_all()?;
        Self::index_record(&mut self.by_txid, &mut self.by_outpoint, rec);
        Ok(())
    }

    /// Convenience: mark an already-recorded txid as `Confirmed` (or insert a
    /// fresh confirmed record if unseen). Preserves the existing outpoints /
    /// parties / fingerprint when updating.
    pub fn mark_confirmed(&mut self, txid: &str) -> std::io::Result<()> {
        self.update_status(txid, PaymentStatus::Confirmed)
    }

    /// Convenience: mark an already-recorded txid as `Failed`.
    pub fn mark_failed(&mut self, txid: &str) -> std::io::Result<()> {
        self.update_status(txid, PaymentStatus::Failed)
    }

    fn update_status(&mut self, txid: &str, status: PaymentStatus) -> std::io::Result<()> {
        let mut rec = match self.by_txid.get(txid) {
            Some(existing) => existing.clone(),
            None => PaymentRecord::submitted(txid.to_string(), Vec::new()),
        };
        rec.status = status;
        rec.recorded_at_secs = now_secs();
        self.record(rec)
    }
}

/// Current unix time in seconds (saturating to 0 if the clock is before the
/// epoch, which should never happen).
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("kob_settle_replay_test_{}_{}.jsonl", name, std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn fresh_then_record_then_duplicate() {
        let path = tmp_path("dup");
        let mut store = ReplayStore::open(&path).unwrap();
        let txid = "aa".repeat(32);
        let ops = vec![format!("{}:0", "bb".repeat(32))];

        assert_eq!(store.check_replay(&txid, &ops), ReplayCheck::Fresh);
        store.record(PaymentRecord::submitted(txid.clone(), ops.clone())).unwrap();

        match store.check_replay(&txid, &ops) {
            ReplayCheck::DuplicateTxid(PaymentStatus::Submitted) => {}
            other => panic!("expected DuplicateTxid(Submitted), got {:?}", other),
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn outpoint_reuse_by_different_txid_is_rejected() {
        let path = tmp_path("reuse");
        let mut store = ReplayStore::open(&path).unwrap();
        let op = format!("{}:1", "cc".repeat(32));
        let txid_a = "a1".repeat(32);
        let txid_b = "b2".repeat(32);

        store.record(PaymentRecord::submitted(txid_a.clone(), vec![op.clone()])).unwrap();

        // A different artifact re-spending the same outpoint must be rejected.
        match store.check_replay(&txid_b, &[op.clone()]) {
            ReplayCheck::OutpointReused { outpoint, existing_txid } => {
                assert_eq!(outpoint, op);
                assert_eq!(existing_txid, txid_a);
            }
            other => panic!("expected OutpointReused, got {:?}", other),
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn durable_reload_from_disk() {
        let path = tmp_path("reload");
        let txid = "de".repeat(32);
        let ops = vec![format!("{}:3", "ef".repeat(32))];
        {
            let mut store = ReplayStore::open(&path).unwrap();
            store
                .record(
                    PaymentRecord::submitted(txid.clone(), ops.clone())
                        .with_fingerprint("fp-123")
                        .with_parties(Some("payer".into()), Some("recipient".into()), 100_000_000),
                )
                .unwrap();
        }
        // Reopen: record must survive process/handle restart.
        let store2 = ReplayStore::open(&path).unwrap();
        assert!(store2.contains_txid(&txid));
        let rec = store2.get(&txid).unwrap();
        assert_eq!(rec.fingerprint.as_deref(), Some("fp-123"));
        assert_eq!(rec.amount, 100_000_000);
        assert_eq!(store2.outpoint_consumer(&ops[0]), Some(txid.as_str()));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn status_update_is_last_write_wins_on_reload() {
        let path = tmp_path("status");
        let txid = "07".repeat(32);
        let ops = vec![format!("{}:0", "08".repeat(32))];
        {
            let mut store = ReplayStore::open(&path).unwrap();
            store.record(PaymentRecord::submitted(txid.clone(), ops.clone())).unwrap();
            store.mark_confirmed(&txid).unwrap();
            assert_eq!(store.get(&txid).unwrap().status, PaymentStatus::Confirmed);
        }
        let store2 = ReplayStore::open(&path).unwrap();
        assert_eq!(store2.get(&txid).unwrap().status, PaymentStatus::Confirmed);
        // Outpoint association preserved across the status-update line.
        assert_eq!(store2.outpoint_consumer(&ops[0]), Some(txid.as_str()));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn same_txid_repeating_its_own_outpoint_is_duplicate_not_reuse() {
        let path = tmp_path("selfsame");
        let mut store = ReplayStore::open(&path).unwrap();
        let txid = "11".repeat(32);
        let ops = vec![format!("{}:2", "22".repeat(32))];
        store.record(PaymentRecord::submitted(txid.clone(), ops.clone())).unwrap();
        // Re-checking the SAME txid with the SAME outpoints -> idempotent dup,
        // never OutpointReused.
        assert!(matches!(
            store.check_replay(&txid, &ops),
            ReplayCheck::DuplicateTxid(_)
        ));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn corrupt_trailing_line_is_tolerated_on_open() {
        let path = tmp_path("corrupt");
        {
            let mut store = ReplayStore::open(&path).unwrap();
            store.record(PaymentRecord::submitted("33".repeat(32), vec![])).unwrap();
        }
        // Simulate a crash mid-write: append a half-written line.
        {
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(b"{\"txid\":\"truncated").unwrap();
        }
        // Must still open and see the one good record.
        let store = ReplayStore::open(&path).unwrap();
        assert_eq!(store.len(), 1);
        assert!(store.contains_txid(&"33".repeat(32)));
        std::fs::remove_file(&path).ok();
    }
}
