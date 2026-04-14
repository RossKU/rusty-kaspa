//! Active loan position tracker with interest, liquidation, and default detection.

use std::collections::HashMap;



/// An active loan position tracked by the engine.
///
/// Created when a LendingOffer and BorrowRequest are matched and the
/// active_loan_v3 covenant UTXO is confirmed on L1.
#[derive(Debug, Clone)]
pub struct LoanPosition {
    /// Outpoint key "txId:index".
    pub outpoint: String,
    /// Loan principal in sompi.
    pub principal: u64,
    /// Collateral value in sompi (UTXO value).
    pub collateral: u64,
    /// Annual rate numerator.
    pub rate_num: u64,
    /// Annual rate denominator.
    pub rate_den: u64,
    /// Loan start DAA score.
    pub start_daa: u64,
    /// Repayment deadline DAA score.
    pub expiry_daa: u64,
    /// Grace period after expiry for default claim (DAA).
    pub grace_daa: u64,
    /// Blake2b-256 hash of the lender's SPK.
    pub lender_spk_hash: [u8; 32],
    /// Blake2b-256 hash of the borrower's SPK.
    pub borrower_spk_hash: [u8; 32],
    /// Rate mode: 0=fixed, 1=variable.
    pub rate_mode: u64,
    /// Variable rate floor numerator (lender protection).
    pub rate_floor: u64,
    /// Variable rate cap numerator (borrower protection).
    pub rate_cap: u64,
    /// Collateral covenant ID (32 bytes, all-zero = KAS).
    pub collateral_cov_id: [u8; 32],
    /// Liquidation threshold (e.g. 15000 = 150%). Liquidation allowed when
    /// collateral * 10000 < principal * liq_threshold. Set at match time from
    /// the lender's loan offer min_collateral_ratio.
    pub liq_threshold: u64,
    /// Cached redeemScript bytes.
    pub redeem_script: Vec<u8>,
}

/// Result of checking a loan's health at a given price and DAA.
#[derive(Debug, Clone, Copy)]
pub struct LoanHealthResult {
    /// Accrued interest in sompi.
    pub accrued_interest: u64,
    /// Total debt: principal + accrued interest.
    pub total_debt: u64,
    /// Current LTV numerator.
    pub ltv_num: u128,
    /// Current LTV denominator.
    pub ltv_den: u128,
    /// True if liquidatable (collateral * 10000 < principal * liq_threshold).
    /// Matches the covenant's on-chain LTV check in sel=1 and sel=9.
    pub is_liquidatable: bool,
    /// True if expired + grace period passed (defaulted).
    pub is_defaulted: bool,
}

/// A loan eligible for liquidation.
#[derive(Debug, Clone)]
pub struct LiquidatableLoan {
    /// Loan outpoint key.
    pub outpoint: String,
    /// Health check result.
    pub health: LoanHealthResult,
}

/// A loan that has defaulted (expired + grace passed).
#[derive(Debug, Clone)]
pub struct DefaultedLoan {
    /// Loan outpoint key.
    pub outpoint: String,
    /// DAA score at which default is confirmed.
    pub default_daa: u64,
}

/// Statistics about tracked loans.
#[derive(Debug, Clone, Copy, Default)]
pub struct LoanStats {
    /// Total number of active loans.
    pub total_loans: usize,
    /// Total principal across all loans (sompi).
    pub total_principal: u64,
    /// Total collateral across all loans (sompi).
    pub total_collateral: u64,
    /// Largest single loan principal (sompi).
    pub largest_principal: u64,
}

/// Liquidation event record.
#[derive(Debug, Clone)]
pub struct LoanLiquidationEvent {
    /// Outpoint of the liquidated loan.
    pub loan_outpoint: String,
    /// Principal at time of liquidation.
    pub principal: u64,
    /// Collateral seized.
    pub collateral: u64,
    /// Accrued interest at liquidation.
    pub accrued_interest: u64,
    /// DAA score at liquidation.
    pub timestamp_daa: u64,
}

/// Maximum number of liquidation events retained in the feed.
const LIQUIDATION_FEED_CAP: usize = 256;

/// Tracks all active loan positions.
///
/// Loans are indexed by outpoint key for O(1) lookup.
pub struct LoanTracker {
    loans: HashMap<String, LoanPosition>,
    recent_liquidations: Vec<LoanLiquidationEvent>,
}

impl Default for LoanTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl LoanTracker {
    pub fn new() -> Self {
        Self {
            loans: HashMap::new(),
            recent_liquidations: Vec::new(),
        }
    }

    // CRUD

    /// Add a new loan to the tracker.
    pub fn add_loan(&mut self, loan: LoanPosition) {
        let key = loan.outpoint.clone();
        self.loans.insert(key, loan);
    }

    /// Remove a loan by outpoint key. Returns the removed loan if found.
    pub fn remove_loan(&mut self, outpoint: &str) -> Option<LoanPosition> {
        self.loans.remove(outpoint)
    }

    /// Look up a loan by outpoint key.
    pub fn get(&self, outpoint: &str) -> Option<&LoanPosition> {
        self.loans.get(outpoint)
    }

    /// Mutable lookup by outpoint key.
    pub fn get_mut(&mut self, outpoint: &str) -> Option<&mut LoanPosition> {
        self.loans.get_mut(outpoint)
    }

    /// Check if a loan exists.
    pub fn contains(&self, outpoint: &str) -> bool {
        self.loans.contains_key(outpoint)
    }

    /// Number of tracked loans.
    pub fn count(&self) -> usize {
        self.loans.len()
    }

    /// Iterate all loans.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &LoanPosition)> {
        self.loans.iter()
    }

    // Interest Calculation

    /// Calculate accrued interest for a loan at a given DAA score.
    ///
    /// `interest = principal * rate_num * elapsed_daa / (rate_den * DAA_PER_YEAR)`
    ///
    /// Returns 0 if current_daa <= start_daa.
    /// Returns None on overflow.
    pub fn accrued_interest(loan: &LoanPosition, current_daa: u64) -> Option<u64> {
        if current_daa <= loan.start_daa {
            return Some(0);
        }
        let elapsed = current_daa - loan.start_daa;
        kob_core::lending::calculate_interest(
            loan.principal,
            loan.rate_num,
            loan.rate_den,
            elapsed,
        )
    }

    // LTV Calculation

    /// Compute current LTV (Loan-to-Value) ratio.
    ///
    /// LTV = total_debt / collateral_value_in_kas
    ///
    /// For KAS collateral (cov_id all-zero), collateral_value = collateral sompi.
    /// For token collateral, you need a price feed:
    ///   collateral_value = collateral * price_num / price_den
    ///
    /// Returns (ltv_num, ltv_den) where LTV = ltv_num / ltv_den.
    /// Returns None on zero collateral or overflow.
    pub fn current_ltv(
        loan: &LoanPosition,
        current_daa: u64,
        collateral_price_num: u64,
        collateral_price_den: u64,
    ) -> Option<(u128, u128)> {
        if collateral_price_den == 0 {
            return None;
        }

        let interest = Self::accrued_interest(loan, current_daa)?;
        let total_debt = (loan.principal as u128).checked_add(interest as u128)?;

        // collateral_value = collateral * price_num / price_den
        // LTV = total_debt / collateral_value
        //     = total_debt * price_den / (collateral * price_num)
        let ltv_num = total_debt.checked_mul(collateral_price_den as u128)?;
        let ltv_den = (loan.collateral as u128).checked_mul(collateral_price_num as u128)?;

        if ltv_den == 0 {
            return None;
        }

        Some((ltv_num, ltv_den))
    }

    // Liquidation Check

    /// Check if a loan is liquidatable.
    ///
    /// The covenant's liquidation path (sel=1) now enforces on-chain:
    ///   collateral * 10000 < principal * liq_threshold
    ///
    /// The engine mirrors this check. For KAS collateral (cov_id all-zero),
    /// collateral = UTXO value in sompi, principal in sompi, liq_threshold
    /// e.g. 15000 = 150%.
    ///
    /// For token collateral with a price feed, use price_num/price_den to
    /// convert collateral to KAS-equivalent, then apply the same formula.
    ///
    /// For KAS collateral, use price_num=1, price_den=1.
    pub fn is_liquidatable(
        loan: &LoanPosition,
        _current_daa: u64,
        collateral_price_num: u64,
        collateral_price_den: u64,
    ) -> bool {
        if collateral_price_den == 0 || collateral_price_num == 0 {
            return false;
        }
        if loan.liq_threshold == 0 {
            return false;
        }

        // Collateral value in KAS terms
        // collateral_kas = collateral * price_num / price_den
        // LTV check: collateral_kas * 10000 < principal * liq_threshold
        // Cross-multiply to avoid division:
        //   collateral * price_num * 10000 < principal * liq_threshold * price_den
        let lhs = (loan.collateral as u128)
            .checked_mul(collateral_price_num as u128)
            .and_then(|v| v.checked_mul(10000));
        let rhs = (loan.principal as u128)
            .checked_mul(loan.liq_threshold as u128)
            .and_then(|v| v.checked_mul(collateral_price_den as u128));

        match (lhs, rhs) {
            (Some(l), Some(r)) => l < r,
            _ => false,
        }
    }

    /// Check if a loan has defaulted (expired + grace period passed).
    pub fn is_defaulted(loan: &LoanPosition, current_daa: u64) -> bool {
        let deadline = loan.expiry_daa.saturating_add(loan.grace_daa);
        current_daa >= deadline
    }

    /// Full health check for a loan.
    pub fn check_health(
        loan: &LoanPosition,
        current_daa: u64,
        collateral_price_num: u64,
        collateral_price_den: u64,
    ) -> Option<LoanHealthResult> {
        let interest = Self::accrued_interest(loan, current_daa)?;
        let total_debt = loan.principal.checked_add(interest)?;
        let (ltv_num, ltv_den) = Self::current_ltv(
            loan,
            current_daa,
            collateral_price_num,
            collateral_price_den,
        )?;

        let is_liquidatable = Self::is_liquidatable(
            loan,
            current_daa,
            collateral_price_num,
            collateral_price_den,
        );
        let is_defaulted = Self::is_defaulted(loan, current_daa);

        Some(LoanHealthResult {
            accrued_interest: interest,
            total_debt,
            ltv_num,
            ltv_den,
            is_liquidatable,
            is_defaulted,
        })
    }

    // Batch Queries

    /// Find all loans by a specific lender.
    pub fn loans_by_lender(&self, spk_hash: &[u8; 32]) -> Vec<&LoanPosition> {
        self.loans
            .values()
            .filter(|l| &l.lender_spk_hash == spk_hash)
            .collect()
    }

    /// Find all loans by a specific borrower.
    pub fn loans_by_borrower(&self, spk_hash: &[u8; 32]) -> Vec<&LoanPosition> {
        self.loans
            .values()
            .filter(|l| &l.borrower_spk_hash == spk_hash)
            .collect()
    }

    /// Find all liquidatable loans at the given price and DAA score.
    ///
    /// For KAS collateral, use price_num=1, price_den=1.
    pub fn liquidatable_loans(
        &self,
        current_daa: u64,
        collateral_price_num: u64,
        collateral_price_den: u64,
    ) -> Vec<LiquidatableLoan> {
        let mut result = Vec::new();
        for (outpoint, loan) in &self.loans {
            if let Some(health) = Self::check_health(
                loan,
                current_daa,
                collateral_price_num,
                collateral_price_den,
            ) {
                if health.is_liquidatable {
                    result.push(LiquidatableLoan {
                        outpoint: outpoint.clone(),
                        health,
                    });
                }
            }
        }
        result
    }

    /// Find all defaulted loans at the given DAA score.
    pub fn defaulted_loans(&self, current_daa: u64) -> Vec<DefaultedLoan> {
        let mut result = Vec::new();
        for (outpoint, loan) in &self.loans {
            if Self::is_defaulted(loan, current_daa) {
                let deadline = loan.expiry_daa.saturating_add(loan.grace_daa);
                result.push(DefaultedLoan {
                    outpoint: outpoint.clone(),
                    default_daa: deadline,
                });
            }
        }
        result
    }

    // Mutation (state updates after TX confirmation)

    /// Update collateral after top-up (Path 5).
    pub fn update_collateral(&mut self, outpoint: &str, new_collateral: u64) -> bool {
        if let Some(loan) = self.loans.get_mut(outpoint) {
            loan.collateral = new_collateral;
            true
        } else {
            false
        }
    }

    /// Update after partial repay (Path 4): new outpoint, reduced principal.
    ///
    /// Note: start_daa is NOT reset. The covenant's sel=4 uses self-continuation
    /// (`output[0].spk == input.spk`), preserving the entire RS including start_daa.
    /// Interest continues to accrue from the original start_daa on the remaining
    /// principal.
    pub fn partial_repay(
        &mut self,
        old_outpoint: &str,
        new_outpoint: &str,
        new_principal: u64,
        new_collateral: u64,
    ) -> bool {
        if let Some(mut loan) = self.loans.remove(old_outpoint) {
            loan.outpoint = new_outpoint.to_string();
            loan.principal = new_principal;
            loan.collateral = new_collateral;
            // start_daa intentionally NOT reset — matches covenant sel=4 self-continuation
            self.loans.insert(new_outpoint.to_string(), loan);
            true
        } else {
            false
        }
    }

    /// Update after extend (Path 6): new outpoint, new expiry, reset start.
    pub fn extend_loan(
        &mut self,
        old_outpoint: &str,
        new_outpoint: &str,
        new_start_daa: u64,
        new_expiry_daa: u64,
        new_collateral: u64,
    ) -> bool {
        if let Some(mut loan) = self.loans.remove(old_outpoint) {
            loan.outpoint = new_outpoint.to_string();
            loan.start_daa = new_start_daa;
            loan.expiry_daa = new_expiry_daa;
            loan.collateral = new_collateral;
            self.loans.insert(new_outpoint.to_string(), loan);
            true
        } else {
            false
        }
    }

    /// Update after loan transfer (Path 10): new outpoint, new lender.
    pub fn transfer_loan(
        &mut self,
        old_outpoint: &str,
        new_outpoint: &str,
        new_lender_hash: [u8; 32],
    ) -> bool {
        if let Some(mut loan) = self.loans.remove(old_outpoint) {
            loan.outpoint = new_outpoint.to_string();
            loan.lender_spk_hash = new_lender_hash;
            self.loans.insert(new_outpoint.to_string(), loan);
            true
        } else {
            false
        }
    }

    /// Update after rebalance (Path 7): new outpoint, reset start, new rate, reduced collateral.
    ///
    /// The covenant's sel=7 uses self-continuation so the RS doesn't change.
    /// Rate updates are tracked off-chain by the engine. Both rate_num and
    /// rate_den must be updated together to maintain a consistent rate ratio.
    pub fn rebalance_loan(
        &mut self,
        old_outpoint: &str,
        new_outpoint: &str,
        new_rate_num: u64,
        new_rate_den: u64,
        new_start_daa: u64,
        new_collateral: u64,
    ) -> bool {
        if let Some(mut loan) = self.loans.remove(old_outpoint) {
            loan.outpoint = new_outpoint.to_string();
            loan.rate_num = new_rate_num;
            loan.rate_den = new_rate_den;
            loan.start_daa = new_start_daa;
            loan.collateral = new_collateral;
            self.loans.insert(new_outpoint.to_string(), loan);
            true
        } else {
            false
        }
    }

    // Statistics

    /// Compute aggregate statistics.
    pub fn stats(&self) -> LoanStats {
        let mut stats = LoanStats {
            total_loans: self.loans.len(),
            ..Default::default()
        };
        for loan in self.loans.values() {
            stats.total_principal = stats.total_principal.saturating_add(loan.principal);
            stats.total_collateral = stats.total_collateral.saturating_add(loan.collateral);
            if loan.principal > stats.largest_principal {
                stats.largest_principal = loan.principal;
            }
        }
        stats
    }

    // Liquidation Feed

    /// Record a liquidation event.
    pub fn record_liquidation(&mut self, event: LoanLiquidationEvent) {
        if self.recent_liquidations.len() >= LIQUIDATION_FEED_CAP {
            self.recent_liquidations.remove(0);
        }
        self.recent_liquidations.push(event);
    }

    /// Return the most recent liquidation events, up to `limit` entries.
    pub fn liquidation_feed(&self, limit: usize) -> &[LoanLiquidationEvent] {
        let all = self.recent_liquidations.as_slice();
        let start = all.len().saturating_sub(limit);
        &all[start..]
    }

    // Serialization (JSON)

    /// Serialize all loans to JSON.
    pub fn to_json(&self) -> serde_json::Value {
        let loans: Vec<serde_json::Value> = self
            .loans
            .values()
            .map(|l| {
                serde_json::json!({
                    "outpoint": l.outpoint,
                    "principal": l.principal,
                    "collateral": l.collateral,
                    "rate_num": l.rate_num,
                    "rate_den": l.rate_den,
                    "start_daa": l.start_daa,
                    "expiry_daa": l.expiry_daa,
                    "grace_daa": l.grace_daa,
                    "lender_spk_hash": hex::encode(l.lender_spk_hash),
                    "borrower_spk_hash": hex::encode(l.borrower_spk_hash),
                    "rate_mode": l.rate_mode,
                    "rate_floor": l.rate_floor,
                    "rate_cap": l.rate_cap,
                    "collateral_cov_id": hex::encode(l.collateral_cov_id),
                    "liq_threshold": l.liq_threshold,
                    "redeem_script": hex::encode(&l.redeem_script),
                })
            })
            .collect();

        serde_json::json!({ "loans": loans })
    }

    /// Deserialize loans from JSON.
    pub fn from_json(json: &serde_json::Value) -> Option<Self> {
        let mut tracker = Self::new();
        let loans = json.get("loans")?.as_array()?;

        for l in loans {
            let outpoint = l.get("outpoint")?.as_str()?.to_string();
            let principal = l.get("principal")?.as_u64()?;
            let collateral = l.get("collateral")?.as_u64()?;
            let rate_num = l.get("rate_num")?.as_u64()?;
            let rate_den = l.get("rate_den")?.as_u64()?;
            let start_daa = l.get("start_daa")?.as_u64()?;
            let expiry_daa = l.get("expiry_daa")?.as_u64()?;
            let grace_daa = l.get("grace_daa")?.as_u64()?;

            let lender_hex = l.get("lender_spk_hash")?.as_str()?;
            let lender_bytes = hex::decode(lender_hex).ok()?;
            if lender_bytes.len() != 32 {
                return None;
            }
            let mut lender_spk_hash = [0u8; 32];
            lender_spk_hash.copy_from_slice(&lender_bytes);

            let borrower_hex = l.get("borrower_spk_hash")?.as_str()?;
            let borrower_bytes = hex::decode(borrower_hex).ok()?;
            if borrower_bytes.len() != 32 {
                return None;
            }
            let mut borrower_spk_hash = [0u8; 32];
            borrower_spk_hash.copy_from_slice(&borrower_bytes);

            let rate_mode = l.get("rate_mode")?.as_u64()?;
            let rate_floor = l.get("rate_floor")?.as_u64()?;
            let rate_cap = l.get("rate_cap")?.as_u64()?;

            let cov_id_hex = l.get("collateral_cov_id")?.as_str()?;
            let cov_id_bytes = hex::decode(cov_id_hex).ok()?;
            if cov_id_bytes.len() != 32 { return None; }
            let mut collateral_cov_id = [0u8; 32];
            collateral_cov_id.copy_from_slice(&cov_id_bytes);

            let liq_threshold = l.get("liq_threshold").and_then(|v| v.as_u64()).unwrap_or(15000);

            let rs_hex = l.get("redeem_script")?.as_str()?;
            let redeem_script = hex::decode(rs_hex).ok()?;

            tracker.add_loan(LoanPosition {
                outpoint,
                principal,
                collateral,
                rate_num,
                rate_den,
                start_daa,
                expiry_daa,
                grace_daa,
                lender_spk_hash,
                borrower_spk_hash,
                rate_mode,
                rate_floor,
                rate_cap,
                collateral_cov_id,
                liq_threshold,
                redeem_script,
            });
        }

        Some(tracker)
    }

    /// Clear all tracked loans.
    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.loans.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kob_core::lending::DAA_PER_YEAR;

    fn make_loan(
        outpoint: &str,
        principal: u64,
        collateral: u64,
    ) -> LoanPosition {
        LoanPosition {
            outpoint: outpoint.to_string(),
            principal,
            collateral,
            rate_num: 500,         // 5% annual
            rate_den: 10000,
            start_daa: 1_000_000,
            expiry_daa: 32_000_000,
            grace_daa: 1_000_000,
            lender_spk_hash: [1; 32],
            borrower_spk_hash: [2; 32],
            rate_mode: 0,
            rate_floor: 0,
            rate_cap: 0,
            collateral_cov_id: [0u8; 32],
            liq_threshold: 15000, // 150%
            redeem_script: Vec::new(),
        }
    }

    fn make_loan_with_rate(
        outpoint: &str,
        principal: u64,
        collateral: u64,
        rate_num: u64,
        rate_den: u64,
    ) -> LoanPosition {
        let mut loan = make_loan(outpoint, principal, collateral);
        loan.rate_num = rate_num;
        loan.rate_den = rate_den;
        loan
    }

    // Basic CRUD

    #[test]
    fn add_and_count() {
        let mut tracker = LoanTracker::new();
        tracker.add_loan(make_loan("tx1:0", 10_000_000, 20_000_000));
        assert_eq!(tracker.count(), 1);
        assert!(tracker.contains("tx1:0"));
    }

    #[test]
    fn remove_loan() {
        let mut tracker = LoanTracker::new();
        tracker.add_loan(make_loan("tx1:0", 10_000_000, 20_000_000));
        let removed = tracker.remove_loan("tx1:0");
        assert!(removed.is_some());
        assert_eq!(tracker.count(), 0);
    }

    #[test]
    fn remove_nonexistent() {
        let mut tracker = LoanTracker::new();
        assert!(tracker.remove_loan("tx99:0").is_none());
    }

    #[test]
    fn get_loan() {
        let mut tracker = LoanTracker::new();
        tracker.add_loan(make_loan("tx1:0", 10_000_000, 20_000_000));
        let loan = tracker.get("tx1:0").unwrap();
        assert_eq!(loan.principal, 10_000_000);
    }

    #[test]
    fn get_mut_loan() {
        let mut tracker = LoanTracker::new();
        tracker.add_loan(make_loan("tx1:0", 10_000_000, 20_000_000));
        let loan = tracker.get_mut("tx1:0").unwrap();
        loan.collateral = 25_000_000;
        assert_eq!(tracker.get("tx1:0").unwrap().collateral, 25_000_000);
    }

    #[test]
    fn get_nonexistent() {
        let tracker = LoanTracker::new();
        assert!(tracker.get("tx99:0").is_none());
    }

    // Interest Calculation

    #[test]
    fn interest_zero_elapsed() {
        let loan = make_loan("tx1:0", 10_000_000, 20_000_000);
        // current_daa == start_daa
        let interest = LoanTracker::accrued_interest(&loan, 1_000_000).unwrap();
        assert_eq!(interest, 0);
    }

    #[test]
    fn interest_before_start() {
        let loan = make_loan("tx1:0", 10_000_000, 20_000_000);
        // current_daa < start_daa
        let interest = LoanTracker::accrued_interest(&loan, 500_000).unwrap();
        assert_eq!(interest, 0);
    }

    #[test]
    fn interest_one_year() {
        let loan = make_loan("tx1:0", 10_000_000, 20_000_000);
        // 1 year elapsed: 315_360_000 DAA
        let current_daa = 1_000_000 + DAA_PER_YEAR;
        let interest = LoanTracker::accrued_interest(&loan, current_daa).unwrap();
        // interest = 10M * 500 / 10000 = 500_000 (5% of 10M)
        assert_eq!(interest, 500_000);
    }

    #[test]
    fn interest_half_year() {
        let loan = make_loan("tx1:0", 10_000_000, 20_000_000);
        let current_daa = 1_000_000 + DAA_PER_YEAR / 2;
        let interest = LoanTracker::accrued_interest(&loan, current_daa).unwrap();
        // 5% * 10M * 0.5 = 250_000
        assert_eq!(interest, 250_000);
    }

    #[test]
    fn interest_tenth_year() {
        let loan = make_loan("tx1:0", 10_000_000, 20_000_000);
        let elapsed = 31_536_000; // DAA_PER_YEAR / 10
        let current_daa = 1_000_000 + elapsed;
        let interest = LoanTracker::accrued_interest(&loan, current_daa).unwrap();
        // 5% * 10M * 0.1 = 50_000
        assert_eq!(interest, 50_000);
    }

    #[test]
    fn interest_zero_rate() {
        let loan = make_loan_with_rate("tx1:0", 10_000_000, 20_000_000, 0, 10000);
        let interest = LoanTracker::accrued_interest(&loan, 100_000_000).unwrap();
        assert_eq!(interest, 0);
    }

    #[test]
    fn interest_high_rate() {
        // 100% annual rate: rate_num=10000, rate_den=10000
        let loan = make_loan_with_rate("tx1:0", 10_000_000, 20_000_000, 10000, 10000);
        let current_daa = 1_000_000 + DAA_PER_YEAR;
        let interest = LoanTracker::accrued_interest(&loan, current_daa).unwrap();
        assert_eq!(interest, 10_000_000); // 100% of principal
    }

    // LTV Calculation

    #[test]
    fn ltv_kas_collateral_no_interest() {
        let loan = make_loan("tx1:0", 10_000_000, 20_000_000);
        // KAS collateral: price = 1/1
        // LTV = debt / collateral = 10M / 20M = 0.5
        let (num, den) = LoanTracker::current_ltv(&loan, 1_000_000, 1, 1).unwrap();
        // num/den should equal 1/2 (or equivalent)
        // num = 10M * 1 = 10M, den = 20M * 1 = 20M
        assert_eq!(num, 10_000_000);
        assert_eq!(den, 20_000_000);
    }

    #[test]
    fn ltv_with_interest() {
        let loan = make_loan("tx1:0", 10_000_000, 20_000_000);
        let current_daa = 1_000_000 + DAA_PER_YEAR; // 1 year
        // debt = 10M + 500k = 10.5M
        // LTV = 10.5M / 20M = 0.525
        let (num, den) = LoanTracker::current_ltv(&loan, current_daa, 1, 1).unwrap();
        assert_eq!(num, 10_500_000);
        assert_eq!(den, 20_000_000);
    }

    #[test]
    fn ltv_zero_collateral() {
        let loan = make_loan("tx1:0", 10_000_000, 0);
        assert!(LoanTracker::current_ltv(&loan, 1_000_000, 1, 1).is_none());
    }

    #[test]
    fn ltv_zero_price() {
        let loan = make_loan("tx1:0", 10_000_000, 20_000_000);
        assert!(LoanTracker::current_ltv(&loan, 1_000_000, 0, 1).is_none());
    }

    // Liquidation Check

    #[test]
    fn not_liquidatable_healthy() {
        let loan = make_loan("tx1:0", 10_000_000, 20_000_000);
        // Underwater check: debt > collateral_value
        // debt = 10M, collateral = 20M, price = 1/1
        // 10M * 1 = 10M <= 20M * 1 = 20M -> NOT liquidatable
        assert!(!LoanTracker::is_liquidatable(&loan, 1_000_000, 1, 1));
    }

    #[test]
    fn liquidatable_undercollateralized() {
        // Collateral is lower than debt -> underwater
        let loan = make_loan("tx1:0", 10_000_000, 5_000_000);
        // debt = 10M, collateral = 5M
        // 10M * 1 > 5M * 1 -> liquidatable
        assert!(LoanTracker::is_liquidatable(&loan, 1_000_000, 1, 1));
    }

    #[test]
    fn not_liquidatable_at_boundary() {
        // Exactly at 150% threshold: collateral=15M, principal=10M
        // 15M * 10000 = 150B, 10M * 15000 = 150B → NOT liquidatable (not strict less than)
        let loan = make_loan("tx1:0", 10_000_000, 15_000_000);
        assert!(!LoanTracker::is_liquidatable(&loan, 1_000_000, 1, 1));
    }

    #[test]
    fn liquidatable_just_below() {
        // Collateral just below debt -> underwater
        let loan = make_loan("tx1:0", 10_000_000, 9_999_999);
        // 10M > 9_999_999 -> liquidatable
        assert!(LoanTracker::is_liquidatable(&loan, 1_000_000, 1, 1));
    }

    #[test]
    fn liquidatable_below_threshold() {
        // collateral=10.4M, principal=10M, threshold=150%
        // 10.4M is only 104% of 10M — below 150% threshold -> liquidatable
        let loan = make_loan("tx1:0", 10_000_000, 10_400_000);
        assert!(LoanTracker::is_liquidatable(&loan, 1_000_000, 1, 1));
    }

    #[test]
    fn not_liquidatable_above_threshold() {
        // collateral=16M, principal=10M, threshold=150%
        // 16M is 160% of 10M — above 150% threshold -> NOT liquidatable
        let loan = make_loan("tx1:0", 10_000_000, 16_000_000);
        assert!(!LoanTracker::is_liquidatable(&loan, 1_000_000, 1, 1));
    }

    // Default Check

    #[test]
    fn not_defaulted_before_expiry() {
        let loan = make_loan("tx1:0", 10_000_000, 20_000_000);
        // expiry = 32M, grace = 1M, deadline = 33M
        assert!(!LoanTracker::is_defaulted(&loan, 31_000_000));
    }

    #[test]
    fn not_defaulted_in_grace_period() {
        let loan = make_loan("tx1:0", 10_000_000, 20_000_000);
        // After expiry but before grace ends
        assert!(!LoanTracker::is_defaulted(&loan, 32_500_000));
    }

    #[test]
    fn defaulted_after_grace() {
        let loan = make_loan("tx1:0", 10_000_000, 20_000_000);
        // deadline = 32M + 1M = 33M
        assert!(LoanTracker::is_defaulted(&loan, 33_000_000));
    }

    #[test]
    fn defaulted_well_after_grace() {
        let loan = make_loan("tx1:0", 10_000_000, 20_000_000);
        assert!(LoanTracker::is_defaulted(&loan, 100_000_000));
    }

    // Health Check

    #[test]
    fn health_check_healthy() {
        let loan = make_loan("tx1:0", 10_000_000, 20_000_000);
        let health = LoanTracker::check_health(&loan, 1_000_000, 1, 1).unwrap();
        assert_eq!(health.accrued_interest, 0);
        assert_eq!(health.total_debt, 10_000_000);
        assert!(!health.is_liquidatable);
        assert!(!health.is_defaulted);
    }

    #[test]
    fn health_check_with_interest() {
        let loan = make_loan("tx1:0", 10_000_000, 20_000_000);
        let current = 1_000_000 + DAA_PER_YEAR;
        let health = LoanTracker::check_health(&loan, current, 1, 1).unwrap();
        assert_eq!(health.accrued_interest, 500_000);
        assert_eq!(health.total_debt, 10_500_000);
    }

    #[test]
    fn health_check_defaulted() {
        let loan = make_loan("tx1:0", 10_000_000, 20_000_000);
        let health = LoanTracker::check_health(&loan, 33_000_000, 1, 1).unwrap();
        assert!(health.is_defaulted);
    }

    // Batch Queries

    #[test]
    fn loans_by_lender_filters() {
        let mut tracker = LoanTracker::new();
        tracker.add_loan(make_loan("tx1:0", 10_000_000, 20_000_000));
        let mut loan2 = make_loan("tx2:0", 5_000_000, 10_000_000);
        loan2.lender_spk_hash = [3; 32];
        tracker.add_loan(loan2);

        let lender1_loans = tracker.loans_by_lender(&[1; 32]);
        assert_eq!(lender1_loans.len(), 1);
        assert_eq!(lender1_loans[0].outpoint, "tx1:0");

        let lender3_loans = tracker.loans_by_lender(&[3; 32]);
        assert_eq!(lender3_loans.len(), 1);
        assert_eq!(lender3_loans[0].outpoint, "tx2:0");
    }

    #[test]
    fn loans_by_borrower_filters() {
        let mut tracker = LoanTracker::new();
        tracker.add_loan(make_loan("tx1:0", 10_000_000, 20_000_000));
        let mut loan2 = make_loan("tx2:0", 5_000_000, 10_000_000);
        loan2.borrower_spk_hash = [3; 32];
        tracker.add_loan(loan2);

        let borr2_loans = tracker.loans_by_borrower(&[2; 32]);
        assert_eq!(borr2_loans.len(), 1);

        let borr3_loans = tracker.loans_by_borrower(&[3; 32]);
        assert_eq!(borr3_loans.len(), 1);
    }

    #[test]
    fn liquidatable_loans_batch() {
        let mut tracker = LoanTracker::new();
        // Healthy loan
        tracker.add_loan(make_loan("tx1:0", 10_000_000, 20_000_000));
        // Undercollateralized loan
        tracker.add_loan(make_loan("tx2:0", 10_000_000, 5_000_000));

        let liq = tracker.liquidatable_loans(1_000_000, 1, 1);
        assert_eq!(liq.len(), 1);
        assert_eq!(liq[0].outpoint, "tx2:0");
    }

    #[test]
    fn defaulted_loans_batch() {
        let mut tracker = LoanTracker::new();
        tracker.add_loan(make_loan("tx1:0", 10_000_000, 20_000_000));
        let mut loan2 = make_loan("tx2:0", 5_000_000, 10_000_000);
        loan2.expiry_daa = 10_000_000;
        loan2.grace_daa = 1_000_000;
        tracker.add_loan(loan2);

        // At DAA 12M: tx2 has deadline 11M -> defaulted. tx1 deadline 33M -> not.
        let defaults = tracker.defaulted_loans(12_000_000);
        assert_eq!(defaults.len(), 1);
        assert_eq!(defaults[0].outpoint, "tx2:0");
    }

    #[test]
    fn liquidatable_loans_empty_tracker() {
        let tracker = LoanTracker::new();
        assert!(tracker.liquidatable_loans(1_000_000, 1, 1).is_empty());
    }

    #[test]
    fn defaulted_loans_empty_tracker() {
        let tracker = LoanTracker::new();
        assert!(tracker.defaulted_loans(100_000_000).is_empty());
    }

    // Mutation Methods

    #[test]
    fn update_collateral_basic() {
        let mut tracker = LoanTracker::new();
        tracker.add_loan(make_loan("tx1:0", 10_000_000, 20_000_000));
        assert!(tracker.update_collateral("tx1:0", 25_000_000));
        assert_eq!(tracker.get("tx1:0").unwrap().collateral, 25_000_000);
    }

    #[test]
    fn update_collateral_nonexistent() {
        let mut tracker = LoanTracker::new();
        assert!(!tracker.update_collateral("tx99:0", 25_000_000));
    }

    #[test]
    fn partial_repay_basic() {
        let mut tracker = LoanTracker::new();
        tracker.add_loan(make_loan("tx1:0", 10_000_000, 20_000_000));
        assert!(tracker.partial_repay("tx1:0", "tx2:0", 7_000_000, 15_000_000));
        assert!(!tracker.contains("tx1:0"));
        assert!(tracker.contains("tx2:0"));
        let loan = tracker.get("tx2:0").unwrap();
        assert_eq!(loan.principal, 7_000_000);
        assert_eq!(loan.collateral, 15_000_000);
    }

    #[test]
    fn partial_repay_nonexistent() {
        let mut tracker = LoanTracker::new();
        assert!(!tracker.partial_repay("tx99:0", "tx100:0", 5_000_000, 10_000_000));
    }

    #[test]
    fn extend_loan_basic() {
        let mut tracker = LoanTracker::new();
        tracker.add_loan(make_loan("tx1:0", 10_000_000, 20_000_000));
        assert!(tracker.extend_loan(
            "tx1:0",
            "tx2:0",
            2_000_000,   // new start
            64_000_000,  // new expiry
            18_000_000,  // reduced collateral (interest paid out)
        ));
        assert!(!tracker.contains("tx1:0"));
        let loan = tracker.get("tx2:0").unwrap();
        assert_eq!(loan.start_daa, 2_000_000);
        assert_eq!(loan.expiry_daa, 64_000_000);
        assert_eq!(loan.collateral, 18_000_000);
    }

    #[test]
    fn extend_loan_nonexistent() {
        let mut tracker = LoanTracker::new();
        assert!(!tracker.extend_loan("tx99:0", "tx100:0", 2_000_000, 64_000_000, 18_000_000));
    }

    #[test]
    fn transfer_loan_basic() {
        let mut tracker = LoanTracker::new();
        tracker.add_loan(make_loan("tx1:0", 10_000_000, 20_000_000));
        assert!(tracker.transfer_loan("tx1:0", "tx2:0", [3; 32]));
        assert!(!tracker.contains("tx1:0"));
        let loan = tracker.get("tx2:0").unwrap();
        assert_eq!(loan.lender_spk_hash, [3; 32]);
    }

    #[test]
    fn transfer_loan_nonexistent() {
        let mut tracker = LoanTracker::new();
        assert!(!tracker.transfer_loan("tx99:0", "tx100:0", [3; 32]));
    }

    #[test]
    fn rebalance_loan_basic() {
        let mut tracker = LoanTracker::new();
        let mut loan = make_loan("tx1:0", 10_000_000, 20_000_000);
        loan.rate_mode = 1;
        tracker.add_loan(loan);

        assert!(tracker.rebalance_loan(
            "tx1:0",
            "tx2:0",
            600,         // new rate_num
            10000,       // new rate_den
            5_000_000,   // new start
            18_000_000,  // reduced collateral
        ));
        let loan = tracker.get("tx2:0").unwrap();
        assert_eq!(loan.rate_num, 600);
        assert_eq!(loan.rate_den, 10000);
        assert_eq!(loan.start_daa, 5_000_000);
        assert_eq!(loan.collateral, 18_000_000);
    }

    #[test]
    fn rebalance_loan_nonexistent() {
        let mut tracker = LoanTracker::new();
        assert!(!tracker.rebalance_loan("tx99:0", "tx100:0", 600, 10000, 5_000_000, 18_000_000));
    }

    // Statistics

    #[test]
    fn stats_basic() {
        let mut tracker = LoanTracker::new();
        tracker.add_loan(make_loan("tx1:0", 10_000_000, 20_000_000));
        tracker.add_loan(make_loan("tx2:0", 5_000_000, 15_000_000));

        let stats = tracker.stats();
        assert_eq!(stats.total_loans, 2);
        assert_eq!(stats.total_principal, 15_000_000);
        assert_eq!(stats.total_collateral, 35_000_000);
        assert_eq!(stats.largest_principal, 10_000_000);
    }

    #[test]
    fn stats_empty() {
        let tracker = LoanTracker::new();
        let stats = tracker.stats();
        assert_eq!(stats.total_loans, 0);
        assert_eq!(stats.total_principal, 0);
    }

    // Liquidation Feed

    #[test]
    fn liquidation_feed_basic() {
        let mut tracker = LoanTracker::new();
        tracker.record_liquidation(LoanLiquidationEvent {
            loan_outpoint: "tx1:0".to_string(),
            principal: 10_000_000,
            collateral: 5_000_000,
            accrued_interest: 100_000,
            timestamp_daa: 5_000_000,
        });

        let feed = tracker.liquidation_feed(10);
        assert_eq!(feed.len(), 1);
        assert_eq!(feed[0].loan_outpoint, "tx1:0");
    }

    #[test]
    fn liquidation_feed_cap() {
        let mut tracker = LoanTracker::new();
        for i in 0..300 {
            tracker.record_liquidation(LoanLiquidationEvent {
                loan_outpoint: format!("tx{i}:0"),
                principal: 1_000_000,
                collateral: 500_000,
                accrued_interest: 10_000,
                timestamp_daa: i as u64,
            });
        }

        // Should be capped at LIQUIDATION_FEED_CAP
        let feed = tracker.liquidation_feed(500);
        assert_eq!(feed.len(), LIQUIDATION_FEED_CAP);
    }

    #[test]
    fn liquidation_feed_limit() {
        let mut tracker = LoanTracker::new();
        for i in 0..10 {
            tracker.record_liquidation(LoanLiquidationEvent {
                loan_outpoint: format!("tx{i}:0"),
                principal: 1_000_000,
                collateral: 500_000,
                accrued_interest: 10_000,
                timestamp_daa: i as u64,
            });
        }

        let feed = tracker.liquidation_feed(3);
        assert_eq!(feed.len(), 3);
    }

    // Serialization

    #[test]
    fn json_roundtrip() {
        let mut tracker = LoanTracker::new();
        tracker.add_loan(make_loan("tx1:0", 10_000_000, 20_000_000));
        tracker.add_loan(make_loan("tx2:0", 5_000_000, 15_000_000));

        let json = tracker.to_json();
        let restored = LoanTracker::from_json(&json).unwrap();

        assert_eq!(restored.count(), 2);
        let loan = restored.get("tx1:0").unwrap();
        assert_eq!(loan.principal, 10_000_000);
        assert_eq!(loan.collateral, 20_000_000);
    }

    #[test]
    fn json_empty_roundtrip() {
        let tracker = LoanTracker::new();
        let json = tracker.to_json();
        let restored = LoanTracker::from_json(&json).unwrap();
        assert_eq!(restored.count(), 0);
    }

    #[test]
    fn from_json_invalid() {
        let bad = serde_json::json!({ "not": "loans" });
        assert!(LoanTracker::from_json(&bad).is_none());
    }

    // Default trait

    #[test]
    fn default_creates_empty_tracker() {
        let tracker = LoanTracker::default();
        assert_eq!(tracker.count(), 0);
    }

    // Clear

    #[test]
    fn clear_empties_tracker() {
        let mut tracker = LoanTracker::new();
        tracker.add_loan(make_loan("tx1:0", 10_000_000, 20_000_000));
        tracker.clear();
        assert_eq!(tracker.count(), 0);
    }

    // Edge cases

    #[test]
    fn partial_repay_preserves_other_fields() {
        let mut tracker = LoanTracker::new();
        let loan = make_loan("tx1:0", 10_000_000, 20_000_000);
        tracker.add_loan(loan);

        tracker.partial_repay("tx1:0", "tx2:0", 7_000_000, 15_000_000);
        let new_loan = tracker.get("tx2:0").unwrap();
        assert_eq!(new_loan.rate_num, 500);
        assert_eq!(new_loan.rate_den, 10000);
        assert_eq!(new_loan.lender_spk_hash, [1; 32]);
        assert_eq!(new_loan.borrower_spk_hash, [2; 32]);
    }

    #[test]
    fn extend_preserves_other_fields() {
        let mut tracker = LoanTracker::new();
        tracker.add_loan(make_loan("tx1:0", 10_000_000, 20_000_000));
        tracker.extend_loan("tx1:0", "tx2:0", 2_000_000, 64_000_000, 18_000_000);
        let loan = tracker.get("tx2:0").unwrap();
        assert_eq!(loan.principal, 10_000_000);
        assert_eq!(loan.rate_num, 500);
    }

    #[test]
    fn transfer_preserves_other_fields() {
        let mut tracker = LoanTracker::new();
        tracker.add_loan(make_loan("tx1:0", 10_000_000, 20_000_000));
        tracker.transfer_loan("tx1:0", "tx2:0", [5; 32]);
        let loan = tracker.get("tx2:0").unwrap();
        assert_eq!(loan.principal, 10_000_000);
        assert_eq!(loan.borrower_spk_hash, [2; 32]);
        assert_eq!(loan.lender_spk_hash, [5; 32]);
    }

    #[test]
    fn multiple_loans_same_lender() {
        let mut tracker = LoanTracker::new();
        tracker.add_loan(make_loan("tx1:0", 10_000_000, 20_000_000));
        tracker.add_loan(make_loan("tx2:0", 5_000_000, 15_000_000));

        let loans = tracker.loans_by_lender(&[1; 32]);
        assert_eq!(loans.len(), 2);
    }

    #[test]
    fn interest_large_principal() {
        // Test with large values near u64 max to check overflow handling
        let loan = make_loan_with_rate("tx1:0", 1_000_000_000_000, 2_000_000_000_000, 500, 10000);
        let current = 1_000_000 + DAA_PER_YEAR;
        let interest = LoanTracker::accrued_interest(&loan, current).unwrap();
        // 5% of 1T = 50B
        assert_eq!(interest, 50_000_000_000);
    }

    #[test]
    fn iter_all_loans() {
        let mut tracker = LoanTracker::new();
        tracker.add_loan(make_loan("tx1:0", 10_000_000, 20_000_000));
        tracker.add_loan(make_loan("tx2:0", 5_000_000, 15_000_000));

        let count = tracker.iter().count();
        assert_eq!(count, 2);
    }
}
