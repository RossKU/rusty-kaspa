//! N-to-M batch transaction builder for atomic multi-order matching.
//!
//! Builds a single Kaspa transaction that settles N sell orders against M buy
//! orders atomically.  The spot covenant has no `OpTxInputCount==2` constraint
//! (verified by `tests.rs:2207-2208`), so any number of order inputs is valid.
//!
//! # Input layout
//!
//!   `[sell_0 .. sell_{N-1}] [buy_0 .. buy_{M-1}] [wallet_fee_utxo?]`
//!
//! Sell inputs carry covenant_id (= token_id), which provides covenant lineage
//! for buyer token outputs directly.  No separate token_unit input is needed.
//! Each buy's `tii` sigscript parameter points to a sell input with matching
//! covenant_id.
//!
//! No hard input count limit.  Indices >16 use data-push encoding (2 bytes)
//! instead of OpN (1 byte).  Practical limit: bounded by MAX_TX_MASS (500,000).
//!
//! # Fee model
//!
//! Phase 1: Miner fee is pre-estimated via `kob_core::mass::estimate_compute_mass`
//! (conservative: 152 B/input, 53 B/output, 1000 mass/sig_op).
//!
//! Phase 2: After signing, `BatchPlan::converge_fee_exact()` recomputes exact
//! mass from real sigscripts via `calc_mass_with_sigscripts`, then re-adjusts
//! the matcher fee / first-seller output so that miner_fee == compute_mass.
//!
//! # Compute mass reference (all well below MAX_TX_MASS = 500,000)
//!
//!   | Pattern           | Inputs | Outputs | Mass (gram) |
//!   |-------------------|--------|---------|-------------|
//!   | 1:1 batch         |      3 |       3 |       4,819 |
//!   | 2:1 + fee UTXO    |      4 |       4 |       6,394 |
//!   | 3:2 + fee UTXO    |      6 |       6 |       9,544 |
//!   | 7:7 (max same-tk) |     15 |      15 |      23,719 |

use std::collections::{HashMap, HashSet};

use kob_core::MIN_UTXO_VALUE;
use kob_core::contract::spot::oco::{
    build_oco_sell_sl_fill_sigscript,
    build_oco_sell_tp_fill_sigscript,
};
use kob_core::contract::spot::order::{
    BUY_ORDER_MAX_N,
    BUY_ORDER_RS_EXPECTED_LEN,
    build_buy_fill_sigscript,
    build_buy_partial_fill_sigscript,
    build_sell_fill_sigscript,
    build_sell_ioc_fill_sigscript,
};
use kob_core::contract::spot::swap::{parse_swap_order_rs, build_swap_fill_sigscript, SWAP_RS_SIZE};
use kob_core::contract::spot::bracket::{build_bracket_fill_sigscript, BRACKET_RS_SIZE};

/// Order type (buy or sell) for batch matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderType {
    Buy,
    Sell,
}

/// A single order to include in a batch match.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used in tests
pub struct BatchOrder {
    /// Outpoint (txid, index) of the order UTXO.
    pub outpoint: (String, u32),
    /// Order type (buy or sell).
    pub order_type: OrderType,
    /// Contract version (sell: 6/8, buy: 8/10/11).
    pub version: u8,
    /// Token covenant ID (32 bytes).
    pub token_cov_id: [u8; 32],
    /// Price numerator (rational price = price_num / price_den).
    pub price_num: u64,
    /// Price denominator.
    pub price_den: u64,
    /// Order amount:
    ///   Sell: token amount (UTXO value in tokens)
    ///   Buy: KAS amount (UTXO value in KAS)
    pub amount: u64,
    /// Full redeemScript bytes.
    pub redeem_script: Vec<u8>,
    /// UTXO value in sompi.
    pub utxo_value: u64,
    /// Counterparty scriptPublicKey bytes (the destination for this order's output).
    ///
    /// For sell orders: seller's SPK (KAS payment destination).
    /// For buy orders: buyer's SPK (token payment destination).
    pub counterparty_spk: Vec<u8>,
    /// Counterparty SPK version.
    pub counterparty_spk_version: u16,
    /// Minimum fill amount (KAS) enforced by the contract bytecode.
    /// IOC partial fills must produce `fill_kas >= min_fill` or the
    /// script will reject.
    pub min_fill: u64,
    /// OCO path: when set, this sell order is part of a single-UTXO OCO
    /// and must use the TP (Op1) or SL (Op2) selector instead of the
    /// standard sell fill selector (Op1).
    pub oco_path: Option<kob_core::OcoPath>,
    /// Bracket entry metadata (v16 only).
    ///
    /// Contains the receipt and OCO data extracted from the bracket RS state.
    /// The batch matcher uses this to construct the bracket-specific TX layout:
    ///   - input[2] = receipt UTXO (must have matching covenant_id)
    ///   - output[2] = OCO sell P2SH output
    pub bracket_meta: Option<BracketMeta>,
}

/// Metadata extracted from a bracket entry redeemScript (v16).
///
/// The bracket contract enforces hardcoded index checks:
///   - input[2].covenant_id == receipt_cov_id
///   - input[2].amount >= min_receipt_val
///   - output[2].spk == oco_spk
///   - output[2].value >= oco_min_val
#[derive(Debug, Clone)]
pub struct BracketMeta {
    /// Receipt covenant ID (32 bytes). input[2] must have this covenant_id.
    pub receipt_cov_id: [u8; 32],
    /// Minimum receipt value (sompi). input[2].amount must be >= this.
    pub min_receipt_val: u64,
    /// OCO sell SPK (37 bytes: version u16LE + 35-byte P2SH script).
    /// output[2] must have this SPK.
    pub oco_spk: Vec<u8>,
    /// OCO sell SPK version.
    pub oco_spk_version: u16,
    /// Minimum OCO output value (sompi). output[2].value must be >= this.
    pub oco_min_val: u64,
    /// Entry type (0 = buy, 1 = sell).
    pub entry_type: u64,
}

/// Purpose of a planned output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Variant not yet constructed; used in match pattern
pub enum OutputPurpose {
    /// KAS payment to a seller.
    SellerKas,
    /// Token payment to a buyer.
    BuyerTokens,
    /// Matcher fee/profit output.
    MatcherFee,
    /// Wallet change (unused KAS back to matcher).
    WalletChange,
    /// Sell value remainder (excess sell input value beyond buyer needs).
    SellRemainder,
    /// Buyer change (surplus exceeding bps cap returned to buyer).
    BuyerChange,
    /// v18 buy Op2 partial: the buy's residual continuation. Same P2SH SPK as
    /// the buy input (byte-exact, enforced on-chain), NO covenant binding —
    /// the unspent KAS becomes a normal v18 buy UTXO again (chainable).
    BuyResidual,
    /// Ring settle: a swap leg's source-token delivery to its receiver.
    /// Must be auth slot 0 of the giver input (covenant binding attached by
    /// the executor per `RingPlan::output_auth_input`).
    RingDelivery,
    /// Ring settle: matcher token skim, capped by the giver's F4 conservation
    /// cap. Sits at auth slots >= 1 of the giver input (after its delivery).
    MatcherSkim,
}

/// A planned output in the batch TX.
#[derive(Debug, Clone)]
pub struct PlannedOutput {
    /// Output value in sompi.
    pub value: u64,
    /// ScriptPublicKey bytes (P2PK or P2SH).
    pub script_public_key: Vec<u8>,
    /// SPK version.
    pub spk_version: u16,
    /// Purpose of this output.
    pub purpose: OutputPurpose,
}

/// Errors that can occur during batch planning.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Variant not yet constructed; used in Display impl
pub enum BatchError {
    /// An order version is not supported for batch matching.
    UnsupportedVersion { outpoint: String, version: u8 },
    /// No orders provided.
    EmptyBatch,
    /// Output value below MIN_UTXO_VALUE.
    OutputBelowMinimum { index: usize, value: u64 },
    /// Amounts do not balance (inputs != outputs + fee).
    AmountMismatch { total_in: u64, total_out: u64, fee: u64 },
    /// Missing token unit for a buy order's token.
    MissingTokenUnit { token_cov_id: String },
    /// Index exceeds u8 range -- used for legacy error compatibility.
    IndexOutOfRange { index: usize },
    /// Insufficient wallet UTXO for fees.
    InsufficientFee { needed: u64, available: u64 },
    /// No sell orders provided.
    NoSellOrders,
    /// No buy orders provided.
    NoBuyOrders,
    /// Duplicate outpoint detected (would cause double-spend rejection).
    DuplicateOutpoint(String),
    /// Price denominator is zero (would cause division by zero).
    ZeroPriceDenominator { index: usize, side: &'static str },
    /// Arithmetic overflow (u128 result does not fit in u64).
    Overflow { index: usize, side: &'static str, detail: &'static str },
    /// Fee bps cap produced no viable matcher fee (all surplus returned to buyers).
    FeeBpsCappedToZero,
    /// A partially-filled sell does not meet its min_fill requirement.
    MinFillViolation { index: usize, fill_kas: u64, min_fill: u64 },
    /// OCO sell in a sweep/batch where the buys would leave a token remainder.
    ///
    /// The OCO v1 covenant dispatch has no IOC (selector=5) path — only
    /// TP (Op1), SL (Op2), cancel (Op0), and expire (Op4). Attempting to
    /// use build_sell_ioc_fill_sigscript with OCO produces a sigscript with
    /// selector=5 which runs the SL-path branch and then fails
    /// `Op2 OpEqual OpVerify`, causing "script ran, but verification failed"
    /// on-chain. The planner must reject such batches rather than emit a
    /// TX that will be rejected by the node.
    ///
    /// The OCO UTXO remains in the book and will be matched in a later scan
    /// cycle when a counterparty that consumes the full 200M-token value is
    /// available, or when OCO gets rewritten with an IOC path (future HF).
    OcoRemainderUnsupported { outpoint: String, utxo_value: u64, filled_tokens: u64 },
    /// An OCO sell was composed into a multi-sell sweep (2+ sells in one tx).
    ///
    /// A v18 sweep was asked to include more sells than the contract's
    /// compile-time `BUY_ORDER_MAX_N` slot count (the sigscript builder
    /// `assert!`s and panics; the planner rejects gracefully well before
    /// that point).
    TooManySells { count: usize, max: usize },
    /// More than one v18 buy in a single settle tx (item D, fail-closed BY
    /// PROOF — see `test_multi_buy_rejected` for the engine-model
    /// argument: delivery outputs can only bind to tcid inputs, never to a
    /// buy, so cross-buy disjointness is unprovable on-chain).
    MultiBuyUnsupported { count: usize },
    /// A v18 sell that would keep a token residual cannot settle against a
    /// v18 buy covenant in the same tx — STRUCTURAL, not a planner policy:
    /// the buy derives its delivery as `OpAuthOutputIdx(tii, 0)` (auth slot 0
    /// of the sell input, buyer-SPK checked) while the sell's IOC/partial F4
    /// requires that same slot 0 to be its self-SPK residual continuation.
    /// Both cannot hold at once, so v18 sweeps are full-fill-only (exactly
    /// the V18_DESIGN.md note). Such books settle when a counterparty fully
    /// consumes the sell (buy-anchored GTC/IOC/partial planners) or via a
    /// matcher-as-counterparty sell-partial settle (no buy input).
    SellResidualUnsupported { outpoint: String, utxo_value: u64, filled_tokens: u64 },
    /// v18 accounting: the buy contract's surplus cap
    /// (`spent - fair_sum <= spent/10000*mmfee_bps`) cannot be satisfied even
    /// at zero matcher surplus (integer-rounding gap exceeds the allowance).
    CapInfeasible { spent: u64, fair_sum: u64, cap: u64 },
    /// A sell's covenant-enforced owner batch cap (`batch_max`) is smaller
    /// than the planned batch size — the planner must exclude that sell.
    BatchCapExceeded { outpoint: String, batch_max: u8, batch_size: usize },
    /// Ring: leg count outside `2..=RING_MAX`.
    RingLegCount { count: usize },
    /// Ring: the legs do not form a closed cycle (leg i's target token must
    /// equal leg (i+1)%n's source token, all source tokens pairwise distinct).
    RingNotClosed { index: usize },
    /// Ring: a leg's `min_target` floor cannot be met by its giver's amount.
    RingInfeasible { leg: usize, needed: u64, available: u64 },
    /// Ring: a leg failed v18 swap-order validation (bad RS, owner SPK
    /// mismatch, etc.).
    RingInvalidLeg { outpoint: String, reason: &'static str },
}

impl std::fmt::Display for BatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BatchError::UnsupportedVersion { outpoint, version } => {
                write!(f, "Order {} is v{}, unsupported (v14/v16 only)", outpoint, version)
            }
            BatchError::EmptyBatch => write!(f, "No orders in batch"),
            BatchError::OutputBelowMinimum { index, value } => {
                write!(f, "Output[{}] value {} below MIN_UTXO_VALUE {}", index, value, MIN_UTXO_VALUE)
            }
            BatchError::AmountMismatch { total_in, total_out, fee } => {
                write!(f, "Amount mismatch: in={} out={} fee={}", total_in, total_out, fee)
            }
            BatchError::MissingTokenUnit { token_cov_id } => {
                write!(f, "No token unit for covenant {}", token_cov_id)
            }
            BatchError::IndexOutOfRange { index } => {
                write!(f, "TX index {} exceeds maximum supported range", index)
            }
            BatchError::InsufficientFee { needed, available } => {
                write!(f, "Insufficient fee UTXO: need {} have {}", needed, available)
            }
            BatchError::NoSellOrders => write!(f, "No sell orders in batch"),
            BatchError::NoBuyOrders => write!(f, "No buy orders in batch"),
            BatchError::DuplicateOutpoint(ref key) => write!(f, "Duplicate outpoint: {}", key),
            BatchError::ZeroPriceDenominator { index, side } => {
                write!(f, "Order[{}] ({}) has price_den=0 (division by zero)", index, side)
            }
            BatchError::Overflow { index, side, detail } => {
                write!(f, "Order[{}] ({}) arithmetic overflow: {}", index, side, detail)
            }
            BatchError::FeeBpsCappedToZero => {
                write!(f, "Fee bps cap reduced matcher fee to zero (no profit)")
            }
            BatchError::MinFillViolation { index, fill_kas, min_fill } => {
                write!(f, "Sell[{}] partial fill {} KAS below min_fill {}", index, fill_kas, min_fill)
            }
            BatchError::OcoRemainderUnsupported { outpoint, utxo_value, filled_tokens } => {
                write!(f, "OCO sell {} cannot be partially filled (utxo_value={} filled_tokens={}); OCO v1 covenant has no IOC path", outpoint, utxo_value, filled_tokens)
            }
            BatchError::TooManySells { count, max } => {
                write!(f, "v18 sweep has {} sells, exceeds BUY_ORDER_MAX_N={}", count, max)
            }
            BatchError::MultiBuyUnsupported { count } => {
                write!(f, "v18 settle has {} buys; only 1 v18 buy per settle tx is provable on-chain (item D fail-closed pin)", count)
            }
            BatchError::SellResidualUnsupported { outpoint, utxo_value, filled_tokens } => {
                write!(f, "v18 sell {} would keep a token residual ({} of {} filled); a v18 partial sell cannot settle against a v18 buy in the same tx (auth-slot-0 conflict: buy delivery vs sell residual)", outpoint, filled_tokens, utxo_value)
            }
            BatchError::CapInfeasible { spent, fair_sum, cap } => {
                write!(f, "v18 surplus cap infeasible: spent={} fair_sum={} allowed cap={}", spent, fair_sum, cap)
            }
            BatchError::BatchCapExceeded { outpoint, batch_max, batch_size } => {
                write!(
                    f,
                    "sell {} carries batch_max={} but the planned batch has {} same-token inputs",
                    outpoint, batch_max, batch_size
                )
            }
            BatchError::RingLegCount { count } => {
                write!(f, "ring has {} legs; supported range is 2..={}", count, RING_MAX)
            }
            BatchError::RingNotClosed { index } => {
                write!(f, "ring does not close at leg {} (target token != next leg's source token, or duplicate source tokens)", index)
            }
            BatchError::RingInfeasible { leg, needed, available } => {
                write!(f, "ring leg {} needs min_target {} but its giver only holds {}", leg, needed, available)
            }
            BatchError::RingInvalidLeg { outpoint, reason } => {
                write!(f, "ring leg {} invalid: {}", outpoint, reason)
            }
        }
    }
}

impl std::error::Error for BatchError {}

/// A fully built batch transaction input.
#[derive(Debug, Clone)]
pub struct BatchTxInput {
    pub tx_id: String,
    pub index: u32,
    pub sigscript: Vec<u8>,
    pub sig_op_count: u8,
}

/// A fully built batch transaction output.
#[derive(Debug, Clone)]
pub struct BatchTxOutput {
    pub value: u64,
    pub script_public_key: Vec<u8>,
    pub spk_version: u16,
    pub purpose: OutputPurpose,
}

/// The fully built batch transaction.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used in tests
pub struct BatchTx {
    pub inputs: Vec<BatchTxInput>,
    pub outputs: Vec<BatchTxOutput>,
    pub fee: u64,
}

/// Complete batch match plan.
///
/// Maps orders to specific input/output indices and computes all sigscripts.
#[derive(Debug, Clone)]
pub struct BatchPlan {
    /// Sell orders with their assigned input indices.
    pub sells: Vec<(BatchOrder, usize)>,
    /// Buy orders with their assigned input indices.
    pub buys: Vec<(BatchOrder, usize)>,
    /// Optional wallet UTXO for fee payment (txid, index, value).
    pub wallet_input: Option<(String, u32, u64)>,
    /// Planned outputs.
    pub outputs: Vec<PlannedOutput>,
    /// Total miner fee.
    pub total_fee: u64,
    /// Matcher surplus (profit from price spread).
    pub matcher_surplus: u64,
    /// Mapping: buy's token_cov_id (hex) -> sell input index (for tii).
    /// Sell inputs carry covenant_id, providing covenant lineage for buyer outputs.
    pub token_input_map: HashMap<String, usize>,
    /// Mapping: buy input index -> seller output index (soi for v11).
    pub buy_seller_map: HashMap<usize, usize>,
    /// Matcher fee cap in basis points (stored for Phase 2 re-application).
    pub fee_bps: Option<u16>,
    /// Total KAS flowing to sellers (trade volume, for bps cap calculation).
    pub total_seller_kas: u64,
    /// IOC mode: None = normal batch, Some(Buy) = buy sweeps sells, Some(Sell) = sell sweeps buys.
    pub ioc_mode: Option<IocSide>,
    /// Per-sell fill token amounts for sell IOC (index matches sells vec).
    /// Only populated when ioc_mode == Some(IocSide::Sell).
    pub sell_fill_amounts: Vec<u64>,
    /// Per-buy partial fill parameters.
    ///
    /// Key: index into the `buys` vec.
    /// Value: `(fill_kas, residual_output_idx, token_output_idx)`.
    ///
    /// When present for a buy, `build_tx()` emits an Op2 (partial fill) sigscript
    /// instead of Op1 (full fill) or Op5 (IOC fill).  The buy contract's D&R path
    /// creates a continuation UTXO at `residual_output_idx` with the residual KAS.
    pub buy_partial_fills: HashMap<usize, (u64, u16, u16)>,
    /// Output index for each sell (koi). Length = sells.len() if populated.
    /// When empty, build_tx falls back to tuple's input_idx (current behavior).
    pub sell_output_idx: Vec<usize>,
    /// Output index for each buy (toi). Length = buys.len() if populated.
    pub buy_output_idx: Vec<usize>,
    /// Covenant output index for each buy (coi). Length = buys.len() if populated.
    pub buy_coi: Vec<u16>,
    /// Bracket receipt input (v16 only).
    ///
    /// When a bracket buy order is in the batch, the bracket contract checks
    /// `input[2].covenant_id == receipt_cov_id` and `input[2].amount >= min_receipt_val`.
    /// This field holds the receipt UTXO info, which `build_tx()` inserts at index 2
    /// (after sells and buys, before the wallet input).
    ///
    /// The receipt input requires `sig_op_count = 1` (receipt v4 always needs
    /// a recipient signature). The executor must sign this input and build
    /// `build_receipt_consume_sigscript(sig, pk, receipt_rs)`.
    pub bracket_receipt: Option<BracketReceiptInput>,
    /// Bracket OCO sell output (v16 only).
    ///
    /// When a bracket buy order is in the batch, the bracket contract checks
    /// `output[2].spk == oco_spk` and `output[2].value >= oco_min_val`.
    /// This output is inserted at index 2 in `build_tx()`.
    pub bracket_oco_output: Option<PlannedOutput>,
    /// v17 N:M sweep: per-buy sorted list of the sell INPUT indices this buy
    /// sweeps. When non-empty for a buy, `build_tx()` emits the v17 fill
    /// sigscript (`build_buy_v17_fill_sigscript`) instead of the v14/v16 form.
    /// Empty vec for a buy = legacy (non-v17) path.
    pub buy_sweep_sells: Vec<Vec<u16>>,
    /// v17 N:M sweep: OUTPUT index -> authorizing sell input index. The executor
    /// binds each such BuyerTokens output to the named sell input (per-input F4),
    /// instead of the single `token_input_map` tii. Empty = legacy behavior.
    pub output_auth_input: std::collections::HashMap<usize, u16>,
}

/// Receipt input for bracket fill (v16).
///
/// The bracket contract hardcodes `input[2]` as the receipt input.
/// The receipt is a trade_receipt covenant UTXO that proves a prior trade
/// was executed. The matcher signs the receipt to consume it.
#[derive(Debug, Clone)]
pub struct BracketReceiptInput {
    /// Receipt UTXO outpoint (txid, index).
    pub outpoint: (String, u32),
    /// Receipt UTXO value in sompi.
    pub value: u64,
    /// Receipt P2SH scriptPublicKey bytes.
    pub script_public_key: Vec<u8>,
    /// Receipt SPK version.
    pub spk_version: u16,
    /// Receipt redeemScript bytes (needed to build consume sigscript).
    pub redeem_script: Vec<u8>,
}

/// Which side of the IOC is the sweeper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IocSide {
    /// 1 buy sweeps N sells.
    Buy,
    /// 1 sell sweeps N buys.
    Sell,
}

impl BatchPlan {
    /// Build the actual TX inputs/outputs/sigscripts from the plan.
    pub fn build_tx(&self) -> Result<BatchTx, BatchError> {
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();

        // === Build sell inputs (v18 canonical attested sigscripts) ===
        for (i, (sell, input_idx)) in self.sells.iter().enumerate() {
            // Use merged sell_output_idx if populated, else fall back to input_idx (legacy 1:1).
            let koi = if !self.sell_output_idx.is_empty() {
                self.sell_output_idx[i]
            } else {
                *input_idx
            };

            // Detect partial fill: sell_fill_amounts[i] < sell.utxo_value means
            // buyers didn't absorb all tokens — spend via IOC (Op5 + fta) with
            // the self-SPK residual instead of the full-fill path.
            let has_remainder = self.sell_fill_amounts.get(i)
                .map_or(false, |&fta| fta < sell.utxo_value);

            // The attested (pnum, pden) is this sell's OWN price pair — for an
            // OCO term that is the EXECUTING branch's pair (the scanner books
            // each OCO path as its own order carrying that branch's price),
            // which is what the OCO v18 body verifies and what unlocked OCO
            // sweep eligibility on both branches.
            let ss = if let Some(oco_path) = sell.oco_path {
                match oco_path {
                    kob_core::OcoPath::TakeProfit => build_oco_sell_tp_fill_sigscript(
                        koi as u16, sell.price_num, sell.price_den, &sell.redeem_script,
                    ),
                    kob_core::OcoPath::StopLoss => build_oco_sell_sl_fill_sigscript(
                        koi as u16, sell.price_num, sell.price_den, &sell.redeem_script,
                    ),
                }
            } else if has_remainder && !self.sell_fill_amounts.is_empty() {
                // v18 sell keeping a residual (Op5 IOC + fta). NOTE: this
                // shape is structurally incompatible with being a term of
                // a v18 buy in the same tx (the buy reads this input's
                // auth slot 0 as its delivery; the sell's F4 requires that
                // same slot to be the self-SPK residual). The v18 planners
                // never compose it — see
                // `BatchError::SellResidualUnsupported`.
                let fta = self.sell_fill_amounts.get(i).copied().unwrap_or(sell.amount);
                build_sell_ioc_fill_sigscript(
                    koi as u16, sell.price_num, sell.price_den, fta, &sell.redeem_script,
                )
            } else {
                build_sell_fill_sigscript(
                    koi as u16, sell.price_num, sell.price_den, &sell.redeem_script,
                )
            };
            inputs.push(BatchTxInput {
                tx_id: sell.outpoint.0.clone(),
                index: sell.outpoint.1,
                sigscript: ss,
                sig_op_count: 0,
            });
        }

        // === Build buy inputs ===
        for (buy_idx, (buy, _input_idx)) in self.buys.iter().enumerate() {
            // Bracket entries are keyed off RS length (their version u8 is an
            // engine-layer label, not a contract identifier).
            let is_bracket = buy.redeem_script.len() == BRACKET_RS_SIZE;

            // v18 buys are ALWAYS spent via the tii-list sigscript forms
            // (fill/IOC/partial); the v18 planners populate buy_sweep_sells
            // for them, so a v18 buy without a sweep list is a planner bug.
            let ss = if is_bracket {
                // Bracket entry: sigscript = [Op1][pushData(RS)]. No tii list —
                // the bracket contract uses hardcoded output indices.
                build_bracket_fill_sigscript(&buy.redeem_script)
            } else {
                let sell_indices = match self.buy_sweep_sells.get(buy_idx).filter(|v| !v.is_empty()) {
                    Some(s) => s,
                    None => {
                        return Err(BatchError::UnsupportedVersion {
                            outpoint: format!("{}:{}", buy.outpoint.0, buy.outpoint.1),
                            version: buy.version,
                        });
                    }
                };
                if let Some(&(_spent, residual_idx, _)) = self.buy_partial_fills.get(&buy_idx) {
                    // Op2 partial: [tii_1..tii_MAX_N][N][ri][Op2][RS]. The
                    // second tuple field carries the residual OUTPUT index.
                    build_buy_partial_fill_sigscript(
                        sell_indices, residual_idx, &buy.redeem_script,
                    )
                } else {
                    let ioc = self.ioc_mode == Some(IocSide::Buy);
                    build_buy_fill_sigscript(sell_indices, ioc, &buy.redeem_script)
                }
            };
            inputs.push(BatchTxInput {
                tx_id: buy.outpoint.0.clone(),
                index: buy.outpoint.1,
                sigscript: ss,
                // LIMITS re-freeze: the 32-slot buy body exceeds the
                // 9,999-unit free script allowance at every N, so the buy
                // input declares a compute budget (sig_op_count = 1 ->
                // computeBudget 10 = 109,999-unit capacity, the mapping the
                // live N=32 run used). Bracket entries keep 0 (unchanged
                // small body).
                sig_op_count: if is_bracket { 0 } else { 1 },
            });
        }

        // === Build bracket receipt input (v16, index 2) ===
        // Must come BEFORE the wallet input so it lands at input[2].
        // The bracket contract hardcodes `Op2 OpTxInputAmount` / `Op2 OpInputCovenantId`.
        if let Some(ref receipt) = self.bracket_receipt {
            inputs.push(BatchTxInput {
                tx_id: receipt.outpoint.0.clone(),
                index: receipt.outpoint.1,
                sigscript: Vec::new(), // Needs receipt signing externally (sig_op_count=1)
                sig_op_count: 1,
            });
        }

        // === Build wallet input (for fee) ===
        if let Some((ref tx_id, index, _value)) = self.wallet_input {
            inputs.push(BatchTxInput {
                tx_id: tx_id.clone(),
                index,
                sigscript: Vec::new(), // Needs P2PK signing externally
                sig_op_count: 1,
            });
        }

        // === Build outputs ===
        for planned in &self.outputs {
            outputs.push(BatchTxOutput {
                value: planned.value,
                script_public_key: planned.script_public_key.clone(),
                spk_version: planned.spk_version,
                purpose: planned.purpose,
            });
        }

        // === Insert bracket OCO output at index 2 (v16) ===
        // The bracket contract hardcodes `Op2 OpTxOutputSpk` / `Op2 OpTxOutputAmount`
        // to check output[2]. Insert AFTER the first two outputs (seller KAS at 0,
        // buyer tokens at 1) so the OCO lands at index 2.
        if let Some(ref oco) = self.bracket_oco_output {
            let oco_out = BatchTxOutput {
                value: oco.value,
                script_public_key: oco.script_public_key.clone(),
                spk_version: oco.spk_version,
                purpose: oco.purpose,
            };
            if outputs.len() >= 2 {
                outputs.insert(2, oco_out);
            } else {
                outputs.push(oco_out);
            }
        }

        Ok(BatchTx {
            inputs,
            outputs,
            fee: self.total_fee,
        })
    }

    /// Validate the plan: all contracts satisfied, fees covered, amounts balanced.
    pub fn validate(&self) -> Result<(), BatchError> {
        // Check: order versions (v14 for buys/sells, v16 (F6-fix) or v17 (N:M
        // sweep) for buy, or bracket entry). This mirrors plan_batch_match's
        // own version check -- kept here too as a post-hoc sanity check on
        // the built plan, so it must stay in sync with that check (it was
        // missed when v17 landed, silently rejecting an otherwise-correctly
        // planned v17 sweep at this late stage).
        for (sell, _) in &self.sells {
            if sell.version != 14 && sell.version != 18 {
                return Err(BatchError::UnsupportedVersion {
                    outpoint: format!("{}:{}", sell.outpoint.0, sell.outpoint.1),
                    version: sell.version,
                });
            }
        }
        for (buy, _) in &self.buys {
            if buy.version != 14 && buy.version != 16 && buy.version != 17 && buy.version != 18 {
                return Err(BatchError::UnsupportedVersion {
                    outpoint: format!("{}:{}", buy.outpoint.0, buy.outpoint.1),
                    version: buy.version,
                });
            }
        }

        // Check: non-empty
        if self.sells.is_empty() {
            return Err(BatchError::NoSellOrders);
        }
        if self.buys.is_empty() {
            return Err(BatchError::NoBuyOrders);
        }

        // Check: all output values >= MIN_UTXO_VALUE
        for (i, out) in self.outputs.iter().enumerate() {
            if out.value < MIN_UTXO_VALUE {
                return Err(BatchError::OutputBelowMinimum {
                    index: i,
                    value: out.value,
                });
            }
        }

        // Check: every buy's token has a matching sell (for covenant lineage)
        for (buy, _) in &self.buys {
            let token_hex = hex::encode(buy.token_cov_id);
            if !self.token_input_map.contains_key(&token_hex) {
                return Err(BatchError::MissingTokenUnit {
                    token_cov_id: token_hex,
                });
            }
        }

        // No index range cap: push_index() handles indices >16 via data-push
        // encoding.  The practical limit is MAX_TX_MASS (500,000).

        // Check: total sompi balance (all inputs == all outputs + miner fee).
        let total_in: u64 = self.sells.iter().map(|(s, _)| s.utxo_value).sum::<u64>()
            + self.buys.iter().map(|(b, _)| b.utxo_value).sum::<u64>()
            + self.wallet_input.as_ref().map_or(0, |w| w.2);
        let total_out: u64 = self.outputs.iter().map(|o| o.value).sum();
        let expected_out = total_out + self.total_fee;
        if total_in != expected_out {
            return Err(BatchError::AmountMismatch {
                total_in,
                total_out,
                fee: self.total_fee,
            });
        }

        Ok(())
    }

    /// Phase 2 fee convergence: recompute exact mass from real sigscripts and
    /// return the exact fee.  The caller must re-adjust outputs (matcher-fee or
    /// first-seller) by the delta `est_fee - exact_fee` and re-sign the wallet
    /// input if the output set changed.
    ///
    /// # Arguments
    /// * `tx`         - The `kob_core::tx::Transaction` built from this plan.
    /// * `sigscripts` - Actual sigscript bytes for every input (post-signing).
    ///
    /// # Returns
    /// `(exact_fee, delta)` where `delta = est_fee - exact_fee` (always >= 0
    /// because `estimate_compute_mass` is conservative).
    pub fn converge_fee_exact(
        &self,
        tx: &kob_core::tx::Transaction,
        sigscripts: &[Vec<u8>],
    ) -> (u64, u64) {
        // The exact fee is the post-Toccata minimum relay fee for the tx's
        // exact compute mass (`mass * MIN_RELAY_FEE_PER_GRAM`), NOT the raw
        // mass. `self.total_fee` (the Phase-1 estimate) is set with the same
        // rate in `plan_batch_match`, so `delta = est - exact >= 0` and the
        // recovery invariant holds.
        let exact_fee = kob_core::mass::min_relay_fee(
            kob_core::mass::calc_mass_with_sigscripts(tx, sigscripts),
        );
        let delta = self.total_fee.saturating_sub(exact_fee);
        (exact_fee, delta)
    }

    /// Convert this plan into a `kob_core::tx::Transaction` suitable for
    /// sighash computation and `calc_mass_with_sigscripts`.
    ///
    /// The returned transaction has correct input/output structure but
    /// placeholder (empty) sigscripts -- callers fill those via signing.
    ///
    /// Each sell/buy input uses the order's P2SH SPK (derived from its
    /// redeemScript) as `script_bytes` and `sig_op_count = 0`.
    /// Token unit inputs use `sig_op_count = 0`.
    /// The wallet input (if any) uses `sig_op_count = 1`.
    pub fn to_transaction(&self) -> kob_core::tx::Transaction {
        use kob_core::p2sh::build_p2sh;
        use kob_core::tx::{Transaction, TxInput, TxOutput};

        // Version 1 required when outputs have covenant binding
        let has_covenant = self.outputs.iter().any(|o| o.purpose == OutputPurpose::BuyerTokens);
        let mut tx = Transaction::new(if has_covenant { 1 } else { 0 });

        // Sell inputs
        for (sell, _idx) in &self.sells {
            let p2sh = build_p2sh(&sell.redeem_script);
            tx.inputs.push(TxInput {
                prev_tx_id: sell.outpoint.0.clone(),
                prev_index: sell.outpoint.1,
                sequence: 50,
                sig_op_count: 0,
                script_version: p2sh.version(),
                script_bytes: p2sh.script().to_vec(),
                value: sell.utxo_value,
            });
        }

        // Buy inputs
        for (buy, _idx) in &self.buys {
            let p2sh = build_p2sh(&buy.redeem_script);
            tx.inputs.push(TxInput {
                prev_tx_id: buy.outpoint.0.clone(),
                prev_index: buy.outpoint.1,
                sequence: 50,
                // Compute-budget declaration for the 32-slot buy body (see
                // build_tx): sig_op_count = 1 on non-bracket buy inputs.
                sig_op_count: if buy.redeem_script.len() == BRACKET_RS_SIZE { 0 } else { 1 },
                script_version: p2sh.version(),
                script_bytes: p2sh.script().to_vec(),
                value: buy.utxo_value,
            });
        }

        // Wallet input (fee)
        if let Some((ref tx_id, index, value)) = self.wallet_input {
            tx.inputs.push(TxInput {
                prev_tx_id: tx_id.clone(),
                prev_index: index,
                sequence: 0,
                sig_op_count: 1,
                // Wallet UTXO is P2PK; SPK will be set by CLI after lookup.
                // Use dummy 34-byte P2PK SPK for mass estimation (correct size).
                script_version: 0,
                script_bytes: vec![0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xac],
                value,
            });
        }

        // Outputs. Covenant bindings are left None here and set by the caller
        // (CLI match_batch / engine executor) which owns the token covenant
        // hashes; both set the real binding on BuyerTokens/SellRemainder
        // outputs BEFORE computing sighash or calling `converge_fee_exact`, so
        // the post-Toccata covenant-byte mass (counted by
        // `calc_mass_with_sigscripts` when `covenant.is_some()`) is accounted
        // for with the real bindings, not a placeholder.
        for planned in &self.outputs {
            tx.outputs.push(TxOutput::new(
                planned.value,
                planned.spk_version,
                planned.script_public_key.clone(),
                None,
            ));
        }

        tx
    }

    /// Re-adjust plan outputs after Phase 2 fee convergence.
    ///
    /// Recovers the over-estimated fee (`delta = estimated_fee - exact_fee`)
    /// back to the matcher fee output, up to the bps cap. Any portion that the
    /// matcher cannot absorb (no MatcherFee output, or the output is already at
    /// the cap) is NOT folded into the seller output — it is left as miner fee.
    ///
    /// Folding the recovered delta (or a dust matcher surplus) into the seller
    /// made SellerKas exceed the buyer's KAS input, which the covenant rejects
    /// at settlement. Leaving it as miner fee only ever reduces the matcher
    /// take, so F6's surplus cap is untouched and settlement stays valid.
    /// `self.total_fee` is reduced only by what was actually recovered to the
    /// matcher. See V16_STATUS.md Phase 8/9.
    ///
    /// # Arguments
    /// * `exact_fee` - The exact miner fee computed from `converge_fee_exact`.
    pub fn apply_exact_fee(&mut self, exact_fee: u64) {
        let delta = self.total_fee.saturating_sub(exact_fee);
        if delta == 0 {
            return;
        }

        // Compute bps cap (if set)
        let max_matcher = if let Some(bps) = self.fee_bps {
            let cap_128 = self.total_seller_kas as u128 * bps as u128 / 10000;
            if cap_128 > u64::MAX as u128 { u64::MAX } else { cap_128 as u64 }
        } else {
            u64::MAX // no cap
        };

        // Recover to the matcher fee output only, up to the bps cap. Never the
        // seller — the un-recoverable remainder is kept as miner fee.
        let recovered = if let Some(idx) = self.outputs.iter()
            .position(|o| o.purpose == OutputPurpose::MatcherFee)
        {
            let room = max_matcher.saturating_sub(self.outputs[idx].value);
            let to_matcher = delta.min(room);
            if to_matcher > 0 {
                self.outputs[idx].value += to_matcher;
                self.matcher_surplus += to_matcher;
            }
            to_matcher
        } else {
            0
        };

        self.total_fee = self.total_fee.saturating_sub(recovered);
    }
}

// ── Shared helpers for plan_batch_match / plan_ioc_match / plan_sell_ioc_match ──

/// Build a token_cov_id (hex) -> sell input index map from a list of token covenant IDs.
///
/// First occurrence of each token wins (the buy's tii just needs any matching sell).
fn build_token_input_map(token_cov_ids: &[[u8; 32]]) -> HashMap<String, usize> {
    let mut map: HashMap<String, usize> = HashMap::new();
    for (i, id) in token_cov_ids.iter().enumerate() {
        let token_hex = hex::encode(id);
        map.entry(token_hex).or_insert(i);
    }
    map
}

/// Apply a basis-point cap to the matcher's KAS surplus.
///
/// Returns `(capped_matcher_kas, refund_amount)`.
/// If `fee_bps` is `None`, returns the original `matcher_kas` with zero refund.
fn apply_bps_cap(matcher_kas: u64, total_seller_kas: u64, fee_bps: Option<u16>) -> (u64, u64) {
    if let Some(bps) = fee_bps {
        let max_fee_128 = total_seller_kas as u128 * bps as u128 / 10000;
        let max_fee = if max_fee_128 > u64::MAX as u128 { u64::MAX } else { max_fee_128 as u64 };
        if matcher_kas > max_fee {
            (max_fee, matcher_kas - max_fee)
        } else {
            (matcher_kas, 0u64)
        }
    } else {
        (matcher_kas, 0u64)
    }
}

/// Emit a MatcherFee output if `capped_kas` >= MIN_UTXO_VALUE, otherwise drop
/// the dust to the miner fee.
///
/// Returns `(matcher_surplus, dropped_to_fee)`:
/// - `matcher_surplus`: value emitted as a separate MatcherFee output (0 when
///   the surplus was dust and dropped).
/// - `dropped_to_fee`: the dust amount that was NOT emitted as an output; the
///   caller MUST add this to `total_fee` so the plan's amount check stays
///   balanced (`inputs == outputs + total_fee`) — the dropped value becomes
///   the on-chain miner fee.
fn emit_matcher_fee(
    outputs: &mut Vec<PlannedOutput>,
    capped_kas: u64,
    matcher_spk: &[u8],
    matcher_spk_version: u16,
) -> (u64, u64) {
    if capped_kas >= MIN_UTXO_VALUE {
        outputs.push(PlannedOutput {
            value: capped_kas,
            script_public_key: matcher_spk.to_vec(),
            spk_version: matcher_spk_version,
            purpose: OutputPurpose::MatcherFee,
        });
        (capped_kas, 0)
    } else {
        // A sub-MIN_UTXO_VALUE surplus cannot be its own spendable UTXO. It is
        // DROPPED to the miner fee (not emitted as an output; the caller folds
        // it into `total_fee`), rather than folded into the seller (outputs[0])
        // as before.
        //
        // Folding it into the seller made SellerKas exceed the buyer's KAS
        // input, which the buy/sell covenant correctly rejects at settlement
        // ("script ran, but verification failed"). Dropping to the miner fee
        // only ever REDUCES the matcher take, so F6's surplus cap is untouched
        // and settlement stays valid. See V16_STATUS.md Phase 8/9.
        (0, capped_kas)
    }
}

/// Distribute a BPS-cap refund to buyers pro-rata by KAS input value.
///
/// * `buyer_token_output_offset` — index into `outputs` where buyer j's token
///   output lives (= `buyer_token_output_offset + j`).  Dust shares are added
///   to that token output instead of creating a new BuyerChange output.
///   When buy outputs are merged (multiple buys -> 1 output), pass
///   `buy_output_idx` to override the j-based mapping.
fn distribute_buyer_refund(
    outputs: &mut Vec<PlannedOutput>,
    refund: u64,
    buys: &[&BatchOrder],
    total_buy_kas: u64,
    buyer_token_output_offset: usize,
    buy_output_idx: Option<&[usize]>,
) {
    let mut refunded = 0u64;
    for (j, buy) in buys.iter().enumerate() {
        let share = if j == buys.len() - 1 {
            // Last buyer gets remainder to avoid rounding loss
            refund - refunded
        } else {
            // u128 intermediate to avoid precision loss above 2^53 sompi (~9,007 KAS)
            ((refund as u128 * buy.utxo_value as u128 / total_buy_kas as u128) as u64)
                .min(refund - refunded)
        };
        if share >= MIN_UTXO_VALUE {
            outputs.push(PlannedOutput {
                value: share,
                script_public_key: buy.counterparty_spk.clone(),
                spk_version: buy.counterparty_spk_version,
                purpose: OutputPurpose::BuyerChange,
            });
            refunded += share;
        } else if share > 0 {
            // Dust: add to this buyer's token output (use merged idx if provided)
            let idx = match buy_output_idx {
                Some(map) => map[j],
                None => buyer_token_output_offset + j,
            };
            outputs[idx].value += share;
            refunded += share;
        }
    }
}

// Plan Builder






// ═════════════════════════════════════════════════════════════════════════
// v18 planners (Stage B, kob/V18_DESIGN.md) — ADDITIVE; pre-v18 planners
// above are untouched and die with Stage E.
// ═════════════════════════════════════════════════════════════════════════

/// Owner batch cap of a v18 buy (n_max, LIMITS re-freeze): parsed from the
/// RS; unparseable RSs fall back to MAX_N (validation elsewhere rejects).
fn buy_n_max(buy: &BatchOrder) -> usize {
    kob_core::contract::spot::parse::parse_redeem_script(&buy.redeem_script)
        .and_then(|p| p.n_max)
        .map(|v| v as usize)
        .unwrap_or(BUY_ORDER_MAX_N)
}

/// Owner batch cap of a v18 sell (batch_max, LIMITS re-freeze). Covers the
/// plain sell + OCO/twap/decay variants via their parse arms; contracts
/// without the field (e.g. the plain v18 OCO) default to 255.
fn sell_batch_max(sell: &BatchOrder) -> u8 {
    let rs = &sell.redeem_script;
    if let Some(p) = kob_core::contract::spot::parse::parse_redeem_script(rs) {
        if let Some(bm) = p.batch_max {
            return bm;
        }
    }
    if let Some(p) = kob_core::contract::spot::parse::parse_ratchet_oco_redeem_script(rs) {
        if let Some(bm) = p.oco.batch_max {
            return bm;
        }
    }
    255
}

/// Parse `mmfee_bps` out of a v18 buy redeemScript (state offset [162..170)).
///
/// State layout (180B): `[0x01 n_max][0x20 okspkh]` then `[0x20 tcid]`
/// `[0x08 pnum][0x08 pden][0x08 mfill][0x20 ohash][0x20 bspkh][0x08 mmfee]`
/// `[cpend][0x08 expiry]` — mmfee bytes start after 2 + 33 + 127 = 162.
fn parse_buy_mmfee_bps(rs: &[u8]) -> Option<u64> {
    if rs.len() != BUY_ORDER_RS_EXPECTED_LEN {
        return None;
    }
    Some(u64::from_le_bytes(rs[162..170].try_into().ok()?))
}

/// Contract-order fair value of a full-filled sell term, exactly as the v18
/// buy's PASS 2 computes it: `floor(tokens / pden) * pnum` (read from the
/// canonical attestation, which equals the sell's own state pair).
fn fair_kas(tokens: u64, pnum: u64, pden: u64) -> u128 {
    (tokens as u128 / pden as u128) * pnum as u128
}

/// Shared v18 sweep validation: exactly one v18 buy, `<= BUY_ORDER_MAX_N`
/// v18 sells of the buy's token (plain and/or OCO — v18 OCO sells are
/// sweep-eligible on both branches), no duplicate outpoints.
fn validate_sweep(sells: &[BatchOrder], buys: &[BatchOrder]) -> Result<(), BatchError> {
    if sells.is_empty() {
        return Err(BatchError::NoSellOrders);
    }
    if buys.is_empty() {
        return Err(BatchError::NoBuyOrders);
    }
    // Item D pin: never more than ONE v18 buy per settle (fail-closed by
    // proof — see `test_multi_buy_rejected`). M=1 because cross-buy delivery
    // disjointness is unprovable on-chain (buys carry no covenant id; the
    // delivery outputs' single binding slot belongs to the token), so one
    // buy per settle — M buys = M parallel txs.
    if buys.len() > 1 {
        return Err(BatchError::MultiBuyUnsupported { count: buys.len() });
    }
    let buy = &buys[0];
    if buy.version != 18 {
        return Err(BatchError::UnsupportedVersion {
            outpoint: format!("{}:{}", buy.outpoint.0, buy.outpoint.1),
            version: buy.version,
        });
    }
    if sells.len() > BUY_ORDER_MAX_N {
        return Err(BatchError::TooManySells {
            count: sells.len(),
            max: BUY_ORDER_MAX_N,
        });
    }
    // Owner batch caps (LIMITS re-freeze): the covenants enforce these
    // on-chain; reject at plan time so a doomed tx is never built.
    if sells.len() > buy_n_max(buy) {
        return Err(BatchError::TooManySells {
            count: sells.len(),
            max: buy_n_max(buy),
        });
    }
    for s in sells {
        if (sell_batch_max(s) as usize) < sells.len() {
            return Err(BatchError::BatchCapExceeded {
                outpoint: format!("{}:{}", s.outpoint.0, s.outpoint.1),
                batch_max: sell_batch_max(s),
                batch_size: sells.len(),
            });
        }
    }
    let mut seen = HashSet::new();
    for o in sells.iter().chain(buys.iter()) {
        let key = format!("{}:{}", o.outpoint.0, o.outpoint.1);
        if !seen.insert(key.clone()) {
            return Err(BatchError::DuplicateOutpoint(key));
        }
    }
    for (i, s) in sells.iter().enumerate() {
        if s.version != 18 {
            return Err(BatchError::UnsupportedVersion {
                outpoint: format!("{}:{}", s.outpoint.0, s.outpoint.1),
                version: s.version,
            });
        }
        if s.token_cov_id != buy.token_cov_id {
            return Err(BatchError::MissingTokenUnit {
                token_cov_id: hex::encode(s.token_cov_id),
            });
        }
        if s.price_den == 0 {
            return Err(BatchError::ZeroPriceDenominator { index: i, side: "sell" });
        }
    }
    if buy.price_den == 0 {
        return Err(BatchError::ZeroPriceDenominator { index: sells.len(), side: "buy" });
    }
    Ok(())
}

/// v18 GTC N:1 sweep planner: one v18 buy consumes N (`<= BUY_ORDER_MAX_N`)
/// fully-filled v18 sells of the same token in ONE tx. Each sell delivers its
/// full token amount to a SEPARATE BuyerTokens output bound to that sell input
/// (auth slot 0, per-input Fix-3), and the buy contract SUMS those outputs for
/// its aggregate limit-price floor and surplus cap.
///
/// v18 news vs the v17 sibling:
///   - OCO sells are sweep-eligible on BOTH branches (canonical branch
///     attestation; `build_tx` emits the TP/SL v18 sigscript with the
///     executing branch's price pair).
///   - `sell_output_idx` is populated so each sell's `koi` points at its
///     (possibly merged) SellerKas output.
///   - The buy's on-chain surplus cap is pre-checked exactly
///     (`kas_in - fair_sum <= kas_in/10000*mmfee_bps`, contract integer
///     order), so a doomed tx is rejected at plan time.
///
/// Layout:
///   inputs:  [sell_0 .. sell_{N-1}, buy, (wallet?)]
///   outputs: [SellerKas.. (merged by spk), BuyerTokens_0 .. BuyerTokens_{N-1},
///            MatcherFee?]
pub fn plan_batch_match(
    sells: &[BatchOrder],
    buys: &[BatchOrder],
    wallet_utxo: Option<(String, u32, u64)>,
    matcher_spk: &[u8],
    matcher_spk_version: u16,
    fee_bps: Option<u16>,
) -> Result<BatchPlan, BatchError> {
    validate_sweep(sells, buys)?;
    let buy = &buys[0];
    let n = sells.len();

    let token_input_map = build_token_input_map(
        &sells.iter().map(|s| s.token_cov_id).collect::<Vec<_>>(),
    );
    let plan_sells: Vec<(BatchOrder, usize)> =
        sells.iter().enumerate().map(|(i, s)| (s.clone(), i)).collect();
    let plan_buys: Vec<(BatchOrder, usize)> = vec![(buy.clone(), n)];

    let mut outputs: Vec<PlannedOutput> = Vec::new();

    // SellerKas per sell, merged by (spk, version); koi map populated.
    let mut total_seller_kas: u64 = 0;
    let mut fair_sum: u128 = 0;
    let mut seller_group_idx: HashMap<(Vec<u8>, u16), usize> = HashMap::new();
    let mut sell_output_idx: Vec<usize> = Vec::with_capacity(n);
    for (i, sell) in sells.iter().enumerate() {
        let expected_kas_128 = sell.amount as u128 * sell.price_num as u128 / sell.price_den as u128;
        if expected_kas_128 > u64::MAX as u128 {
            return Err(BatchError::Overflow { index: i, side: "sell", detail: "expected_kas" });
        }
        let expected_kas = expected_kas_128 as u64;
        if expected_kas < MIN_UTXO_VALUE {
            return Err(BatchError::OutputBelowMinimum { index: i, value: expected_kas });
        }
        if expected_kas < sell.min_fill {
            return Err(BatchError::MinFillViolation { index: i, fill_kas: expected_kas, min_fill: sell.min_fill });
        }
        total_seller_kas += expected_kas;
        fair_sum += fair_kas(sell.amount, sell.price_num, sell.price_den);
        let key = (sell.counterparty_spk.clone(), sell.counterparty_spk_version);
        if let Some(&existing) = seller_group_idx.get(&key) {
            outputs[existing].value += expected_kas;
            sell_output_idx.push(existing);
        } else {
            let new_idx = outputs.len();
            outputs.push(PlannedOutput {
                value: expected_kas,
                script_public_key: sell.counterparty_spk.clone(),
                spk_version: sell.counterparty_spk_version,
                purpose: OutputPurpose::SellerKas,
            });
            seller_group_idx.insert(key, new_idx);
            sell_output_idx.push(new_idx);
        }
    }

    // BuyerTokens per sell (NOT merged) — each auth-bound to its own sell input.
    let mut total_buyer_tokens: u64 = 0;
    let mut output_auth_input: HashMap<usize, u16> = HashMap::new();
    for (i, sell) in sells.iter().enumerate() {
        let tokens = sell.amount; // full fill
        if tokens < MIN_UTXO_VALUE {
            return Err(BatchError::OutputBelowMinimum { index: n + i, value: tokens });
        }
        total_buyer_tokens += tokens;
        let out_idx = outputs.len();
        outputs.push(PlannedOutput {
            value: tokens,
            script_public_key: buy.counterparty_spk.clone(),
            spk_version: buy.counterparty_spk_version,
            purpose: OutputPurpose::BuyerTokens,
        });
        output_auth_input.insert(out_idx, i as u16);
    }

    // Aggregate GTC limit-price floor (contract enforces on-chain; reject
    // early so the buy covenant never aborts a submitted tx).
    let expected_tokens = buy.utxo_value as u128 * buy.price_num as u128 / buy.price_den as u128;
    if (total_buyer_tokens as u128) < expected_tokens {
        return Err(BatchError::MinFillViolation {
            index: n,
            fill_kas: total_buyer_tokens,
            min_fill: expected_tokens.min(u64::MAX as u128) as u64,
        });
    }

    // Aggregate surplus-cap feasibility, contract integer order:
    // kas_in - fair_sum <= kas_in/10000 * mmfee_bps.
    let mmfee_bps = parse_buy_mmfee_bps(&buy.redeem_script)
        .ok_or_else(|| BatchError::UnsupportedVersion {
            outpoint: format!("{}:{}", buy.outpoint.0, buy.outpoint.1),
            version: buy.version,
        })?;
    let cap = (buy.utxo_value as u128 / 10000) * mmfee_bps as u128;
    let surplus_onchain = (buy.utxo_value as u128).saturating_sub(fair_sum);
    if surplus_onchain > cap {
        return Err(BatchError::CapInfeasible {
            spent: buy.utxo_value,
            fair_sum: fair_sum.min(u64::MAX as u128) as u64,
            cap: cap.min(u64::MAX as u128) as u64,
        });
    }

    // KAS accounting (token sompi cancels: buyer-token outflow == sell inflow).
    let total_sell_value: u64 = sells.iter().map(|s| s.utxo_value).sum();
    let wallet_value = wallet_utxo.as_ref().map_or(0, |w| w.2);
    let total_kas_in = total_sell_value + buy.utxo_value + wallet_value;
    let total_planned_out = total_seller_kas + total_buyer_tokens;

    let num_inputs = 1 + n + if wallet_utxo.is_some() { 1 } else { 0 };
    let num_outputs = outputs.len() + 1; // + matcher fee
    let mut total_fee = kob_core::mass::min_relay_fee(
        kob_core::mass::estimate_compute_mass(num_inputs, num_outputs, 0),
    );
    if total_kas_in < total_planned_out + total_fee {
        return Err(BatchError::InsufficientFee {
            needed: total_planned_out + total_fee,
            available: total_kas_in,
        });
    }
    let raw_surplus = total_kas_in - total_planned_out - total_fee;
    let (capped_matcher_kas, _refund) = apply_bps_cap(raw_surplus, total_seller_kas, fee_bps);
    let (matcher_surplus, dropped_to_fee) =
        emit_matcher_fee(&mut outputs, capped_matcher_kas, matcher_spk, matcher_spk_version);
    total_fee += dropped_to_fee;
    // Surplus beyond the matcher's bps cap is left to the miner fee (same
    // policy as the v17 sibling: only ever reduces the matcher take).
    total_fee += raw_surplus.saturating_sub(matcher_surplus + dropped_to_fee);

    let sell_indices: Vec<u16> = (0..n as u16).collect();

    Ok(BatchPlan {
        sells: plan_sells,
        buys: plan_buys,
        wallet_input: wallet_utxo,
        outputs,
        total_fee,
        matcher_surplus,
        token_input_map,
        buy_seller_map: HashMap::new(),
        fee_bps,
        total_seller_kas,
        ioc_mode: None,
        sell_fill_amounts: Vec::new(),
        buy_partial_fills: HashMap::new(),
        sell_output_idx,
        buy_output_idx: Vec::new(),
        buy_coi: Vec::new(),
        bracket_receipt: None,
        bracket_oco_output: None,
        buy_sweep_sells: vec![sell_indices],
        output_auth_input,
    })
}

/// v18 IOC N:1 sweep planner: one v18 buy (Op5 selector) sweeps up to
/// `BUY_ORDER_MAX_N` fully-filled v18 sells (plain and/or OCO),
/// immediately-or-cancel, with a buyer-change output for leftover KAS.
///
/// Floor semantics mirror the v17 sibling: the contract relaxes the
/// aggregate limit-price floor to the buy's own `min_fill` on the IOC
/// selector, so the planner checks `total_tokens >= buy.min_fill`.
///
/// The contract's surplus cap reads the buy's FULL `kas_in` unconditionally
/// (surplus = kas_in - fair_sum, independent of where the change lands), so
/// leftover KAS is only recoverable within `mmfee_bps` — the planner
/// pre-checks that inequality exactly and rejects doomed sweeps.
pub fn plan_ioc_match(
    sells: &[BatchOrder],
    buy: &BatchOrder,
    wallet_utxo: Option<(String, u32, u64)>,
    matcher_spk: &[u8],
    matcher_spk_version: u16,
    fee_bps: Option<u16>,
) -> Result<BatchPlan, BatchError> {
    if sells.is_empty() {
        return Err(BatchError::NoSellOrders);
    }
    if buy.order_type != OrderType::Buy {
        return Err(BatchError::NoBuyOrders);
    }
    if buy.version != 18 {
        return Err(BatchError::UnsupportedVersion {
            outpoint: format!("{}:{}", buy.outpoint.0, buy.outpoint.1),
            version: buy.version,
        });
    }

    // Greedy affordability sweep: full-fill v18 sells only (a v18 buy is
    // structurally unable to consume a partial/IOC sell — its delivery is the
    // sell's auth slot 0, which a partial sell needs for its own residual).
    // v18 OCO sells are INCLUDED (both branches; full-fill terms).
    let buy_kas = buy.utxo_value;
    let mut kas_remaining = buy_kas;
    let mut filled: Vec<&BatchOrder> = Vec::new();
    // Owner batch caps (LIMITS re-freeze): cap the sweep at the buy's n_max
    // and track the included sells' minimum batch_max — a sell may only join
    // while the resulting batch size respects every member's cap.
    let n_cap = BUY_ORDER_MAX_N.min(buy_n_max(buy));
    let mut min_cap: usize = usize::MAX;
    for sell in sells {
        if filled.len() >= n_cap {
            break;
        }
        if sell.version != 18 {
            continue;
        }
        if sell.token_cov_id != buy.token_cov_id {
            continue;
        }
        if sell.price_den == 0 {
            continue;
        }
        let bm = sell_batch_max(sell) as usize;
        if filled.len() + 1 > bm.min(min_cap) {
            continue; // its (or a member's) batch_max would be exceeded
        }
        let sell_kas_128 = sell.amount as u128 * sell.price_num as u128 / sell.price_den as u128;
        if sell_kas_128 > u64::MAX as u128 {
            continue;
        }
        let sell_kas = sell_kas_128 as u64;
        if sell_kas < MIN_UTXO_VALUE || sell_kas < sell.min_fill {
            continue;
        }
        if kas_remaining >= sell_kas {
            filled.push(sell);
            kas_remaining -= sell_kas;
            min_cap = min_cap.min(bm);
        } else {
            break;
        }
    }

    if filled.is_empty() {
        return Err(BatchError::MinFillViolation {
            index: 0,
            fill_kas: 0,
            min_fill: buy.min_fill,
        });
    }

    let n = filled.len();
    let total_tokens: u64 = filled.iter().map(|s| s.amount).sum();

    // IOC floor: aggregate delivered tokens must meet the buy's OWN min_fill.
    if total_tokens < buy.min_fill {
        return Err(BatchError::MinFillViolation {
            index: n,
            fill_kas: total_tokens,
            min_fill: buy.min_fill,
        });
    }

    // Surplus-cap feasibility (exact contract arithmetic): the cap reads the
    // full kas_in, so unswept `kas_remaining` counts against it.
    let mmfee_bps = parse_buy_mmfee_bps(&buy.redeem_script)
        .ok_or_else(|| BatchError::UnsupportedVersion {
            outpoint: format!("{}:{}", buy.outpoint.0, buy.outpoint.1),
            version: buy.version,
        })?;
    let fair_sum: u128 = filled
        .iter()
        .map(|s| fair_kas(s.amount, s.price_num, s.price_den))
        .sum();
    let cap = (buy_kas as u128 / 10000) * mmfee_bps as u128;
    let surplus_onchain = (buy_kas as u128).saturating_sub(fair_sum);
    if surplus_onchain > cap {
        return Err(BatchError::CapInfeasible {
            spent: buy_kas,
            fair_sum: fair_sum.min(u64::MAX as u128) as u64,
            cap: cap.min(u64::MAX as u128) as u64,
        });
    }

    let token_input_map = build_token_input_map(
        &filled.iter().map(|s| s.token_cov_id).collect::<Vec<_>>(),
    );
    let plan_sells: Vec<(BatchOrder, usize)> =
        filled.iter().enumerate().map(|(i, s)| ((*s).clone(), i)).collect();
    let plan_buys: Vec<(BatchOrder, usize)> = vec![(buy.clone(), n)];

    let mut outputs: Vec<PlannedOutput> = Vec::new();

    // SellerKas per sell, merged by (spk, version); koi map populated.
    let mut total_seller_kas: u64 = 0;
    let mut seller_group_idx: HashMap<(Vec<u8>, u16), usize> = HashMap::new();
    let mut sell_output_idx: Vec<usize> = Vec::with_capacity(n);
    for sell in &filled {
        let sell_kas = (sell.amount as u128 * sell.price_num as u128
            / sell.price_den as u128) as u64;
        total_seller_kas += sell_kas;
        let key = (sell.counterparty_spk.clone(), sell.counterparty_spk_version);
        if let Some(&existing) = seller_group_idx.get(&key) {
            outputs[existing].value += sell_kas;
            sell_output_idx.push(existing);
        } else {
            let new_idx = outputs.len();
            outputs.push(PlannedOutput {
                value: sell_kas,
                script_public_key: sell.counterparty_spk.clone(),
                spk_version: sell.counterparty_spk_version,
                purpose: OutputPurpose::SellerKas,
            });
            seller_group_idx.insert(key, new_idx);
            sell_output_idx.push(new_idx);
        }
    }

    // BuyerTokens per sell (NOT merged) — auth-bound to its own sell input.
    let mut output_auth_input: HashMap<usize, u16> = HashMap::new();
    for (i, sell) in filled.iter().enumerate() {
        let out_idx = outputs.len();
        outputs.push(PlannedOutput {
            value: sell.amount,
            script_public_key: buy.counterparty_spk.clone(),
            spk_version: buy.counterparty_spk_version,
            purpose: OutputPurpose::BuyerTokens,
        });
        output_auth_input.insert(out_idx, i as u16);
    }

    let total_sell_value: u64 = filled.iter().map(|s| s.utxo_value).sum();
    let wallet_value = wallet_utxo.as_ref().map_or(0, |w| w.2);
    let total_kas_in = total_sell_value + buy_kas + wallet_value;
    let total_planned_out = total_seller_kas + total_tokens;

    let num_inputs = 1 + n + if wallet_utxo.is_some() { 1 } else { 0 };
    let num_outputs = outputs.len() + 2; // + buyer change + matcher fee
    let mut total_fee = kob_core::mass::min_relay_fee(
        kob_core::mass::estimate_compute_mass(num_inputs, num_outputs, 0),
    );
    if total_kas_in < total_planned_out + total_fee {
        return Err(BatchError::InsufficientFee {
            needed: total_planned_out + total_fee,
            available: total_kas_in,
        });
    }
    let raw_surplus = total_kas_in - total_planned_out - total_fee;

    // Buyer keeps the unswept KAS; matcher takes the rest, bps-capped.
    let matcher_kas = raw_surplus.saturating_sub(kas_remaining);
    let (capped_matcher_kas, buyer_refund_from_bps) =
        apply_bps_cap(matcher_kas, total_seller_kas, fee_bps);

    let total_buyer_change = kas_remaining + buyer_refund_from_bps;
    if total_buyer_change >= MIN_UTXO_VALUE {
        outputs.push(PlannedOutput {
            value: total_buyer_change,
            script_public_key: buy.counterparty_spk.clone(),
            spk_version: buy.counterparty_spk_version,
            purpose: OutputPurpose::BuyerChange,
        });
    } else if total_buyer_change > 0 {
        if let Some(tok_out) = outputs.iter_mut().find(|o| o.purpose == OutputPurpose::BuyerTokens) {
            tok_out.value += total_buyer_change;
        }
    }

    let (matcher_surplus, dropped_to_fee) =
        emit_matcher_fee(&mut outputs, capped_matcher_kas, matcher_spk, matcher_spk_version);
    total_fee += dropped_to_fee;
    total_fee += raw_surplus
        .saturating_sub(matcher_surplus + dropped_to_fee + kas_remaining + buyer_refund_from_bps);

    let sell_indices: Vec<u16> = (0..n as u16).collect();

    Ok(BatchPlan {
        sells: plan_sells,
        buys: plan_buys,
        wallet_input: wallet_utxo,
        outputs,
        total_fee,
        matcher_surplus,
        token_input_map,
        buy_seller_map: HashMap::new(),
        fee_bps,
        total_seller_kas,
        ioc_mode: Some(IocSide::Buy),
        sell_fill_amounts: Vec::new(),
        buy_partial_fills: HashMap::new(),
        sell_output_idx,
        buy_output_idx: Vec::new(),
        buy_coi: Vec::new(),
        bracket_receipt: None,
        bracket_oco_output: None,
        buy_sweep_sells: vec![sell_indices],
        output_auth_input,
    })
}

/// v18 PARTIAL (Op2) planner — item C, NEW capability: the buy spends only
/// part of its KAS against a subset of fully-filled v18 sells and keeps the
/// rest in a byte-exact self-SPK residual output, which is a normal v18 buy
/// UTXO again (chainable across txs).
///
/// On-chain semantics being planned for (see `emit_partial_body`):
///   - `spent = kas_in - residual`, `residual >= 1`;
///   - floors: `token_sum >= spent/pden*pnum` AND `token_sum >= mfill`
///     (per-event, blocks dust-grind);
///   - cap: `(spent - fair_sum) <= spent/10000*mmfee_bps` (proportional, so
///     splitting one fill into k partials cannot increase total extraction);
///   - residual output SPK == buy input SPK byte-exact, NO covenant binding.
///
/// The planner picks the sell subset greedily (caller pre-sorts best-first),
/// chooses the matcher surplus as the largest value satisfying BOTH the
/// contract cap and the `fee_bps` policy cap (clamped so the spent-based
/// limit floor still holds), and emits the residual at `kas_in - spent`.
pub fn plan_partial_match(
    sells: &[BatchOrder],
    buy: &BatchOrder,
    wallet_utxo: Option<(String, u32, u64)>,
    matcher_spk: &[u8],
    matcher_spk_version: u16,
    fee_bps: Option<u16>,
) -> Result<BatchPlan, BatchError> {
    if sells.is_empty() {
        return Err(BatchError::NoSellOrders);
    }
    if buy.order_type != OrderType::Buy {
        return Err(BatchError::NoBuyOrders);
    }
    if buy.version != 18 {
        return Err(BatchError::UnsupportedVersion {
            outpoint: format!("{}:{}", buy.outpoint.0, buy.outpoint.1),
            version: buy.version,
        });
    }
    if buy.price_den == 0 {
        return Err(BatchError::ZeroPriceDenominator { index: 0, side: "buy" });
    }
    let mmfee_bps = parse_buy_mmfee_bps(&buy.redeem_script)
        .ok_or_else(|| BatchError::UnsupportedVersion {
            outpoint: format!("{}:{}", buy.outpoint.0, buy.outpoint.1),
            version: buy.version,
        })?;

    // Greedy subset: full-fill v18 sells (plain/OCO) the buy can pay for
    // while still keeping a residual.
    let buy_kas = buy.utxo_value;
    let mut filled: Vec<&BatchOrder> = Vec::new();
    let mut base_spent: u64 = 0; // Σ seller_kas
    // Owner batch caps (LIMITS re-freeze): same rule as the GTC/IOC sweep.
    let n_cap = BUY_ORDER_MAX_N.min(buy_n_max(buy));
    let mut min_cap: usize = usize::MAX;
    for sell in sells {
        if filled.len() >= n_cap {
            break;
        }
        if sell.version != 18 || sell.token_cov_id != buy.token_cov_id || sell.price_den == 0 {
            continue;
        }
        let bm = sell_batch_max(sell) as usize;
        if filled.len() + 1 > bm.min(min_cap) {
            continue; // its (or a member's) batch_max would be exceeded
        }
        let sell_kas_128 = sell.amount as u128 * sell.price_num as u128 / sell.price_den as u128;
        if sell_kas_128 > u64::MAX as u128 {
            continue;
        }
        let sell_kas = sell_kas_128 as u64;
        if sell_kas < MIN_UTXO_VALUE || sell_kas < sell.min_fill {
            continue;
        }
        if base_spent + sell_kas <= buy_kas {
            filled.push(sell);
            base_spent += sell_kas;
            min_cap = min_cap.min(bm);
        } else {
            break;
        }
    }

    if filled.is_empty() {
        return Err(BatchError::MinFillViolation {
            index: 0,
            fill_kas: 0,
            min_fill: buy.min_fill,
        });
    }

    let n = filled.len();
    let token_sum: u64 = filled.iter().map(|s| s.amount).sum();

    // Per-event mfill floor (blocks dust-grind partial events on-chain).
    if token_sum < buy.min_fill {
        return Err(BatchError::MinFillViolation {
            index: n,
            fill_kas: token_sum,
            min_fill: buy.min_fill,
        });
    }

    // Contract-order fair value and cap feasibility at zero surplus.
    let fair_sum: u128 = filled
        .iter()
        .map(|s| fair_kas(s.amount, s.price_num, s.price_den))
        .sum();
    let gap = (base_spent as u128).saturating_sub(fair_sum); // integer-rounding gap >= 0
    let zero_allow = (base_spent as u128 / 10000) * mmfee_bps as u128;
    if gap > zero_allow {
        return Err(BatchError::CapInfeasible {
            spent: base_spent,
            fair_sum: fair_sum.min(u64::MAX as u128) as u64,
            cap: zero_allow.min(u64::MAX as u128) as u64,
        });
    }

    // Matcher surplus: largest value that stays within BOTH the contract cap
    // (computed at base_spent — conservative, since the allowance only grows
    // with spent) and the fee_bps policy cap, then clamped so the spent-based
    // limit floor `token_sum >= floor(spent/pden)*pnum` still holds and the
    // residual stays a real UTXO.
    let policy_cap: u128 = match fee_bps {
        Some(bps) => base_spent as u128 * bps as u128 / 10000,
        None => u128::MAX,
    };
    let mut surplus = (zero_allow - gap).min(policy_cap);
    // Floor clamp: max spent with floor(spent/pden) <= floor(token_sum/pnum).
    let max_spent_floor = (token_sum as u128 / buy.price_num as u128) * buy.price_den as u128
        + buy.price_den as u128
        - 1;
    let max_surplus_floor = max_spent_floor.saturating_sub(base_spent as u128);
    surplus = surplus.min(max_surplus_floor);
    // Residual clamp: keep residual >= MIN_UTXO_VALUE.
    let max_surplus_residual =
        (buy_kas as u128).saturating_sub(base_spent as u128 + MIN_UTXO_VALUE as u128);
    surplus = surplus.min(max_surplus_residual);
    let surplus = surplus.min(u64::MAX as u128) as u64;

    let spent = base_spent + surplus;
    let residual = buy_kas.saturating_sub(spent);

    // Final exact verification of the three contract inequalities.
    let spent_128 = spent as u128;
    if (spent_128 - fair_sum) > (spent_128 / 10000) * mmfee_bps as u128 {
        return Err(BatchError::CapInfeasible {
            spent,
            fair_sum: fair_sum.min(u64::MAX as u128) as u64,
            cap: ((spent_128 / 10000) * mmfee_bps as u128).min(u64::MAX as u128) as u64,
        });
    }
    let floor_tokens = (spent_128 / buy.price_den as u128) * buy.price_num as u128;
    if (token_sum as u128) < floor_tokens {
        return Err(BatchError::MinFillViolation {
            index: n,
            fill_kas: token_sum,
            min_fill: floor_tokens.min(u64::MAX as u128) as u64,
        });
    }
    if residual < MIN_UTXO_VALUE {
        // A partial that leaves no (relayable) residual must use the full
        // fill / IOC planners instead — Op2 requires residual >= 1 and a
        // dust residual is an unspendable book entry.
        return Err(BatchError::OutputBelowMinimum { index: usize::MAX, value: residual });
    }

    let token_input_map = build_token_input_map(
        &filled.iter().map(|s| s.token_cov_id).collect::<Vec<_>>(),
    );
    let plan_sells: Vec<(BatchOrder, usize)> =
        filled.iter().enumerate().map(|(i, s)| ((*s).clone(), i)).collect();
    let plan_buys: Vec<(BatchOrder, usize)> = vec![(buy.clone(), n)];

    let mut outputs: Vec<PlannedOutput> = Vec::new();

    // SellerKas per sell, merged by (spk, version); koi map populated.
    let mut total_seller_kas: u64 = 0;
    let mut seller_group_idx: HashMap<(Vec<u8>, u16), usize> = HashMap::new();
    let mut sell_output_idx: Vec<usize> = Vec::with_capacity(n);
    for sell in &filled {
        let sell_kas = (sell.amount as u128 * sell.price_num as u128
            / sell.price_den as u128) as u64;
        total_seller_kas += sell_kas;
        let key = (sell.counterparty_spk.clone(), sell.counterparty_spk_version);
        if let Some(&existing) = seller_group_idx.get(&key) {
            outputs[existing].value += sell_kas;
            sell_output_idx.push(existing);
        } else {
            let new_idx = outputs.len();
            outputs.push(PlannedOutput {
                value: sell_kas,
                script_public_key: sell.counterparty_spk.clone(),
                spk_version: sell.counterparty_spk_version,
                purpose: OutputPurpose::SellerKas,
            });
            seller_group_idx.insert(key, new_idx);
            sell_output_idx.push(new_idx);
        }
    }

    // BuyerTokens per sell (NOT merged) — auth-bound to its own sell input.
    let mut output_auth_input: HashMap<usize, u16> = HashMap::new();
    for (i, sell) in filled.iter().enumerate() {
        let out_idx = outputs.len();
        outputs.push(PlannedOutput {
            value: sell.amount,
            script_public_key: buy.counterparty_spk.clone(),
            spk_version: buy.counterparty_spk_version,
            purpose: OutputPurpose::BuyerTokens,
        });
        output_auth_input.insert(out_idx, i as u16);
    }

    // Residual continuation: SAME P2SH as the buy input (byte-exact SPK =>
    // same 145B state carried; the remaining size lives in the UTXO amount).
    // NO covenant binding — it is plain KAS under the buy's P2SH, i.e. a
    // normal v18 buy UTXO again.
    let buy_p2sh = kob_core::p2sh::build_p2sh(&buy.redeem_script);
    let residual_idx = outputs.len();
    outputs.push(PlannedOutput {
        value: residual,
        script_public_key: buy_p2sh.script().to_vec(),
        spk_version: buy_p2sh.version(),
        purpose: OutputPurpose::BuyResidual,
    });

    let total_sell_value: u64 = filled.iter().map(|s| s.utxo_value).sum();
    let wallet_value = wallet_utxo.as_ref().map_or(0, |w| w.2);
    let total_kas_in = total_sell_value + buy_kas + wallet_value;
    let total_planned_out = total_seller_kas + token_sum + residual;

    let num_inputs = 1 + n + if wallet_utxo.is_some() { 1 } else { 0 };
    let num_outputs = outputs.len() + 1; // + matcher fee
    let mut total_fee = kob_core::mass::min_relay_fee(
        kob_core::mass::estimate_compute_mass(num_inputs, num_outputs, 0),
    );
    if total_kas_in < total_planned_out + total_fee {
        return Err(BatchError::InsufficientFee {
            needed: total_planned_out + total_fee,
            available: total_kas_in,
        });
    }
    let raw_surplus = total_kas_in - total_planned_out - total_fee;
    let (capped_matcher_kas, _refund) = apply_bps_cap(raw_surplus, total_seller_kas, fee_bps);
    let (matcher_surplus, dropped_to_fee) =
        emit_matcher_fee(&mut outputs, capped_matcher_kas, matcher_spk, matcher_spk_version);
    total_fee += dropped_to_fee;
    total_fee += raw_surplus.saturating_sub(matcher_surplus + dropped_to_fee);

    let sell_indices: Vec<u16> = (0..n as u16).collect();
    let mut buy_partial_fills: HashMap<usize, (u64, u16, u16)> = HashMap::new();
    // (spent, residual OUTPUT index, unused) — build_tx's v18 arm reads the
    // residual index; `spent` is informational for the executor/logs.
    buy_partial_fills.insert(0, (spent, residual_idx as u16, 0));

    Ok(BatchPlan {
        sells: plan_sells,
        buys: plan_buys,
        wallet_input: wallet_utxo,
        outputs,
        total_fee,
        matcher_surplus,
        token_input_map,
        buy_seller_map: HashMap::new(),
        fee_bps,
        total_seller_kas,
        ioc_mode: None,
        sell_fill_amounts: Vec::new(),
        buy_partial_fills,
        sell_output_idx,
        buy_output_idx: Vec::new(),
        buy_coi: Vec::new(),
        bracket_receipt: None,
        bracket_oco_output: None,
        buy_sweep_sells: vec![sell_indices],
        output_auth_input,
    })
}

/// v18 sell-initiated IOC planner — parity entry point for the sell-anchored
/// flow (`plan_sell_ioc_match` sibling), adapted to the v18 structural rule
/// that sweeps are FULL-FILL-ONLY on the sell side:
///
///   - The v14 shape "sell keeps a token residual, N buys fully consumed" is
///     NOT expressible in v18: the buy derives its delivery as the sell
///     input's auth slot 0 (buyer-SPK checked) while the sell's IOC/partial
///     F4 requires that same slot to be its self-SPK residual. See
///     `BatchError::SellResidualUnsupported`.
///   - At most ONE v18 buy per settle (item D pin), so the "sweep" selects
///     the first candidate buy that FULLY absorbs the sell: exact match
///     settles GTC (Op1/Op1); a larger buy settles via its IOC selector
///     (Op5) with the sell's full delivery meeting the buy's `min_fill`
///     floor and the leftover KAS returned as buyer change (recoverable only
///     within the buy's `mmfee_bps` cap, which is pre-checked exactly).
pub fn plan_sell_ioc_match(
    sell: &BatchOrder,
    buys: &[BatchOrder],
    wallet_utxo: Option<(String, u32, u64)>,
    matcher_spk: &[u8],
    matcher_spk_version: u16,
    fee_bps: Option<u16>,
) -> Result<BatchPlan, BatchError> {
    if buys.is_empty() {
        return Err(BatchError::NoBuyOrders);
    }
    if sell.order_type != OrderType::Sell {
        return Err(BatchError::NoSellOrders);
    }
    if sell.version != 18 {
        return Err(BatchError::UnsupportedVersion {
            outpoint: format!("{}:{}", sell.outpoint.0, sell.outpoint.1),
            version: sell.version,
        });
    }
    if sell.price_den == 0 {
        return Err(BatchError::ZeroPriceDenominator { index: 0, side: "sell" });
    }

    let seller_kas_128 = sell.amount as u128 * sell.price_num as u128 / sell.price_den as u128;
    if seller_kas_128 > u64::MAX as u128 {
        return Err(BatchError::Overflow { index: 0, side: "sell", detail: "seller_kas" });
    }
    let seller_kas = seller_kas_128 as u64;
    if seller_kas < MIN_UTXO_VALUE {
        return Err(BatchError::OutputBelowMinimum { index: 0, value: seller_kas });
    }
    if seller_kas < sell.min_fill {
        return Err(BatchError::MinFillViolation {
            index: 0,
            fill_kas: seller_kas,
            min_fill: sell.min_fill,
        });
    }
    let fair = fair_kas(sell.amount, sell.price_num, sell.price_den);

    // Select the first v18 buy that fully absorbs the sell.
    let mut selected: Option<(&BatchOrder, bool /* ioc */)> = None;
    let mut best_smaller_demand: u64 = 0;
    let mut saw_smaller = false;
    let mut cap_infeasible: Option<BatchError> = None;
    for buy in buys {
        if buy.order_type != OrderType::Buy || buy.version != 18 {
            continue;
        }
        if buy.token_cov_id != sell.token_cov_id || buy.price_den == 0 {
            continue;
        }
        let buy_expected = buy.utxo_value as u128 * buy.price_num as u128 / buy.price_den as u128;
        if buy_expected < sell.amount as u128 {
            // Would leave a sell residual — structurally unsupported in v18.
            saw_smaller = true;
            best_smaller_demand =
                best_smaller_demand.max(buy_expected.min(u64::MAX as u128) as u64);
            continue;
        }
        let exact = buy_expected == sell.amount as u128;
        if !exact && sell.amount < buy.min_fill {
            continue; // IOC floor unreachable with this sell alone
        }
        // Exact contract cap: kas_in - fair <= kas_in/10000*mmfee_bps.
        let Some(mmfee_bps) = parse_buy_mmfee_bps(&buy.redeem_script) else {
            continue;
        };
        let cap = (buy.utxo_value as u128 / 10000) * mmfee_bps as u128;
        let surplus_onchain = (buy.utxo_value as u128).saturating_sub(fair);
        if surplus_onchain > cap {
            cap_infeasible = Some(BatchError::CapInfeasible {
                spent: buy.utxo_value,
                fair_sum: fair.min(u64::MAX as u128) as u64,
                cap: cap.min(u64::MAX as u128) as u64,
            });
            continue;
        }
        selected = Some((buy, !exact));
        break;
    }

    let Some((buy, ioc)) = selected else {
        if saw_smaller {
            return Err(BatchError::SellResidualUnsupported {
                outpoint: format!("{}:{}", sell.outpoint.0, sell.outpoint.1),
                utxo_value: sell.utxo_value,
                filled_tokens: best_smaller_demand,
            });
        }
        if let Some(e) = cap_infeasible {
            return Err(e);
        }
        return Err(BatchError::MinFillViolation {
            index: 0,
            fill_kas: 0,
            min_fill: sell.min_fill,
        });
    };

    // Layout: inputs [sell(0), buy(1), wallet?];
    // outputs [SellerKas(0), BuyerTokens(1, auth->sell 0), BuyerChange?, MatcherFee?].
    let token_input_map = build_token_input_map(&[sell.token_cov_id]);
    let plan_sells: Vec<(BatchOrder, usize)> = vec![(sell.clone(), 0)];
    let plan_buys: Vec<(BatchOrder, usize)> = vec![(buy.clone(), 1)];

    let mut outputs: Vec<PlannedOutput> = Vec::new();
    outputs.push(PlannedOutput {
        value: seller_kas,
        script_public_key: sell.counterparty_spk.clone(),
        spk_version: sell.counterparty_spk_version,
        purpose: OutputPurpose::SellerKas,
    });
    let mut output_auth_input: HashMap<usize, u16> = HashMap::new();
    output_auth_input.insert(outputs.len(), 0);
    outputs.push(PlannedOutput {
        value: sell.amount,
        script_public_key: buy.counterparty_spk.clone(),
        spk_version: buy.counterparty_spk_version,
        purpose: OutputPurpose::BuyerTokens,
    });

    let wallet_value = wallet_utxo.as_ref().map_or(0, |w| w.2);
    let total_kas_in = sell.utxo_value + buy.utxo_value + wallet_value;
    let total_planned_out = seller_kas + sell.amount;

    let num_inputs = 2 + if wallet_utxo.is_some() { 1 } else { 0 };
    let num_outputs = outputs.len() + 2; // + buyer change + matcher fee
    let mut total_fee = kob_core::mass::min_relay_fee(
        kob_core::mass::estimate_compute_mass(num_inputs, num_outputs, 0),
    );
    if total_kas_in < total_planned_out + total_fee {
        return Err(BatchError::InsufficientFee {
            needed: total_planned_out + total_fee,
            available: total_kas_in,
        });
    }
    let raw_surplus = total_kas_in - total_planned_out - total_fee;
    let (capped_matcher_kas, buyer_refund_from_bps) =
        apply_bps_cap(raw_surplus, seller_kas, fee_bps);

    if buyer_refund_from_bps >= MIN_UTXO_VALUE {
        outputs.push(PlannedOutput {
            value: buyer_refund_from_bps,
            script_public_key: buy.counterparty_spk.clone(),
            spk_version: buy.counterparty_spk_version,
            purpose: OutputPurpose::BuyerChange,
        });
    } else if buyer_refund_from_bps > 0 {
        outputs[1].value += buyer_refund_from_bps; // dust: fold into BuyerTokens
    }

    let (matcher_surplus, dropped_to_fee) =
        emit_matcher_fee(&mut outputs, capped_matcher_kas, matcher_spk, matcher_spk_version);
    total_fee += dropped_to_fee;

    Ok(BatchPlan {
        sells: plan_sells,
        buys: plan_buys,
        wallet_input: wallet_utxo,
        outputs,
        total_fee,
        matcher_surplus,
        token_input_map,
        buy_seller_map: HashMap::new(),
        fee_bps,
        total_seller_kas: seller_kas,
        ioc_mode: if ioc { Some(IocSide::Buy) } else { None },
        sell_fill_amounts: Vec::new(),
        buy_partial_fills: HashMap::new(),
        sell_output_idx: vec![0],
        buy_output_idx: Vec::new(),
        buy_coi: Vec::new(),
        bracket_receipt: None,
        bracket_oco_output: None,
        buy_sweep_sells: vec![vec![0u16]],
        output_auth_input,
    })
}

// ═════════════════════════════════════════════════════════════════════════
// v18 ring planner (item F): 2..=RING_MAX swap-v18 legs, all-or-nothing
// ═════════════════════════════════════════════════════════════════════════

/// Maximum ring legs (2-cycle = token<->token, 3-cycle = triangle, ...).
///
/// Planner-only cap: the swap covenant's checks are purely local and the VM
/// is proven to 128 legs (kob/BATCH_LIMITS.md); 8 is matcher-optimizable
/// headroom in the same spirit as MAX_N.
pub const RING_MAX: usize = 8;

/// One leg of a v18 swap ring: a resting swap-v18 order UTXO. Source/target
/// tokens, `min_target` and `mmfee_bps` are parsed from the redeemScript
/// (single source of truth); the caller supplies the owner's actual SPK
/// bytes, validated against the RS's `owner_spk_hash`.
#[derive(Debug, Clone)]
pub struct RingLegOrder {
    /// Outpoint (txid, index) of the swap order UTXO.
    pub outpoint: (String, u32),
    /// v18 swap redeemScript (183B state + body).
    pub redeem_script: Vec<u8>,
    /// UTXO value = source tokens this leg gives.
    pub utxo_value: u64,
    /// Owner SPK script bytes (target-token delivery destination).
    pub owner_spk: Vec<u8>,
    /// Owner SPK version.
    pub owner_spk_version: u16,
}

/// Planned v18 ring settle.
///
/// Layout:
///   inputs:  `[leg_0 .. leg_{n-1}, wallet(fee)]`
///   outputs: `[delivery_0 .. delivery_{n-1}, skim.. , WalletChange?]`
/// where `delivery_j` carries leg j's source token to the RECEIVING leg's
/// owner and is auth slot 0 of input j (skims sit at higher output indices,
/// so they land at auth slots >= 1). Leg i's sigscript names giver input
/// `(i+1) % n` and target output `(i+1) % n`.
#[derive(Debug, Clone)]
pub struct RingPlan {
    /// Legs with their assigned input indices (0..n).
    pub legs: Vec<(RingLegOrder, usize)>,
    /// Wallet UTXO paying the miner fee (txid, index, value).
    pub wallet_input: Option<(String, u32, u64)>,
    /// Planned outputs (RingDelivery / MatcherSkim / WalletChange).
    pub outputs: Vec<PlannedOutput>,
    /// OUTPUT index -> authorizing leg INPUT index. The executor attaches
    /// `CovenantBinding(authorizing_input, leg_source_tokens[input])` on
    /// each of these outputs (both deliveries and skims).
    pub output_auth_input: HashMap<usize, u16>,
    /// Source token covenant id per leg (parsed from each RS).
    pub leg_source_tokens: Vec<[u8; 32]>,
    /// Total miner fee.
    pub total_fee: u64,
    /// Total matcher token skim (token-valued sompi, across all legs).
    pub matcher_surplus: u64,
}

impl RingPlan {
    /// Build TX inputs/outputs/sigscripts from the plan.
    pub fn build_tx(&self) -> Result<BatchTx, BatchError> {
        let n = self.legs.len();
        let mut inputs = Vec::new();
        for (i, (leg, _idx)) in self.legs.iter().enumerate() {
            let giver = ((i + 1) % n) as u16;
            let toi = ((i + 1) % n) as u16;
            let ss = build_swap_fill_sigscript(giver, toi, &leg.redeem_script);
            inputs.push(BatchTxInput {
                tx_id: leg.outpoint.0.clone(),
                index: leg.outpoint.1,
                sigscript: ss,
                sig_op_count: 0,
            });
        }
        if let Some((ref tx_id, index, _value)) = self.wallet_input {
            inputs.push(BatchTxInput {
                tx_id: tx_id.clone(),
                index,
                sigscript: Vec::new(), // P2PK; signed externally
                sig_op_count: 1,
            });
        }
        let outputs = self
            .outputs
            .iter()
            .map(|planned| BatchTxOutput {
                value: planned.value,
                script_public_key: planned.script_public_key.clone(),
                spk_version: planned.spk_version,
                purpose: planned.purpose,
            })
            .collect();
        Ok(BatchTx { inputs, outputs, fee: self.total_fee })
    }

    /// Sanity: inputs == outputs + fee.
    pub fn validate(&self) -> Result<(), BatchError> {
        let total_in: u64 = self.legs.iter().map(|(l, _)| l.utxo_value).sum::<u64>()
            + self.wallet_input.as_ref().map_or(0, |w| w.2);
        let total_out: u64 = self.outputs.iter().map(|o| o.value).sum();
        if total_in != total_out + self.total_fee {
            return Err(BatchError::AmountMismatch {
                total_in,
                total_out,
                fee: self.total_fee,
            });
        }
        Ok(())
    }
}

/// v18 ring planner (item F): plan an all-or-nothing settle of 2..=RING_MAX
/// swap-v18 legs where leg i gives its source token and receives leg
/// `(i+1) % n`'s source token (which must equal leg i's target — closed
/// cycle). No ring partial (documented v18 limitation).
///
/// Per-leg feasibility enforced at plan time (mirrors the covenant):
///   - F2 target floor: `delivery >= receiver.min_target`;
///   - F4 conservation cap: the matcher skim on leg j is at most
///     `floor(utxo/10000) * mmfee_bps` (contract integer order); the
///     delivery is `max(receiver.min_target, utxo - cap)` and the skim is
///     the rest (folded back into the delivery when it would be dust);
///   - F3: the supplied owner SPK must blake2b-match the RS's
///     `owner_spk_hash` (checked here so the tx cannot fail on-chain).
pub fn plan_ring_match(
    legs: &[RingLegOrder],
    wallet_utxo: Option<(String, u32, u64)>,
    matcher_spk: &[u8],
    matcher_spk_version: u16,
) -> Result<RingPlan, BatchError> {
    let n = legs.len();
    if n < 2 || n > RING_MAX {
        return Err(BatchError::RingLegCount { count: n });
    }
    {
        let mut seen = HashSet::new();
        for leg in legs {
            let key = format!("{}:{}", leg.outpoint.0, leg.outpoint.1);
            if !seen.insert(key.clone()) {
                return Err(BatchError::DuplicateOutpoint(key));
            }
        }
    }

    // Parse + validate every leg RS.
    let mut parsed = Vec::with_capacity(n);
    for leg in legs {
        if leg.redeem_script.len() != SWAP_RS_SIZE {
            return Err(BatchError::RingInvalidLeg {
                outpoint: format!("{}:{}", leg.outpoint.0, leg.outpoint.1),
                reason: "redeem script is not a v18 swap order (wrong length)",
            });
        }
        let p = parse_swap_order_rs(&leg.redeem_script).ok_or(BatchError::RingInvalidLeg {
            outpoint: format!("{}:{}", leg.outpoint.0, leg.outpoint.1),
            reason: "redeem script failed v18 swap parse",
        })?;
        let spk_hash =
            kob_core::p2sh::compute_spk_hash(leg.owner_spk_version, &leg.owner_spk);
        if spk_hash != p.owner_spk_hash {
            return Err(BatchError::RingInvalidLeg {
                outpoint: format!("{}:{}", leg.outpoint.0, leg.outpoint.1),
                reason: "owner SPK does not hash to the RS owner_spk_hash (F3 would fail)",
            });
        }
        parsed.push(p);
    }

    // Closed cycle: leg i's target == leg (i+1)%n's source; sources distinct.
    for i in 0..n {
        if parsed[i].target_token_cov_id != parsed[(i + 1) % n].source_token_cov_id {
            return Err(BatchError::RingNotClosed { index: i });
        }
        for j in (i + 1)..n {
            if parsed[i].source_token_cov_id == parsed[j].source_token_cov_id {
                return Err(BatchError::RingNotClosed { index: i });
            }
        }
    }

    // Per-leg delivery/skim (giver j delivers its source token to receiver
    // r = (j+n-1)%n, whose target is token j).
    let mut outputs: Vec<PlannedOutput> = Vec::new();
    let mut output_auth_input: HashMap<usize, u16> = HashMap::new();
    let mut skims: Vec<(usize, u64)> = Vec::new(); // (giver leg, skim value)
    let mut matcher_surplus: u64 = 0;
    for j in 0..n {
        let giver = &legs[j];
        let receiver_idx = (j + n - 1) % n;
        let min_target = parsed[receiver_idx].min_target_amount;
        let amount = giver.utxo_value;
        if min_target > amount {
            return Err(BatchError::RingInfeasible {
                leg: receiver_idx,
                needed: min_target,
                available: amount,
            });
        }
        // F4 cap, contract integer order: floor(amount/10000) * mmfee_bps.
        let cap = ((amount as u128 / 10000) * parsed[j].mmfee_bps as u128)
            .min(u64::MAX as u128) as u64;
        let mut delivery = std::cmp::max(min_target, amount.saturating_sub(cap));
        let mut skim = amount - delivery;
        if skim > 0 && skim < MIN_UTXO_VALUE {
            // Dust skim cannot be its own token UTXO — fold back to the
            // receiver's delivery (only ever increases it; F2/F4 stay GTE).
            delivery = amount;
            skim = 0;
        }
        if delivery < MIN_UTXO_VALUE {
            return Err(BatchError::OutputBelowMinimum { index: j, value: delivery });
        }
        let out_idx = outputs.len();
        outputs.push(PlannedOutput {
            value: delivery,
            script_public_key: legs[receiver_idx].owner_spk.clone(),
            spk_version: legs[receiver_idx].owner_spk_version,
            purpose: OutputPurpose::RingDelivery,
        });
        output_auth_input.insert(out_idx, j as u16);
        if skim > 0 {
            skims.push((j, skim));
            matcher_surplus += skim;
        }
    }
    // Skims AFTER all deliveries so each delivery stays auth slot 0.
    for (giver, skim) in &skims {
        let out_idx = outputs.len();
        outputs.push(PlannedOutput {
            value: *skim,
            script_public_key: matcher_spk.to_vec(),
            spk_version: matcher_spk_version,
            purpose: OutputPurpose::MatcherSkim,
        });
        output_auth_input.insert(out_idx, *giver as u16);
    }

    // Fee: token legs are value-conserving, so the miner fee comes from the
    // wallet input; change back to the matcher when it isn't dust.
    let num_inputs = n + if wallet_utxo.is_some() { 1 } else { 0 };
    let num_outputs = outputs.len() + 1; // + change
    let mut total_fee = kob_core::mass::min_relay_fee(
        kob_core::mass::estimate_compute_mass(num_inputs, num_outputs, 0),
    );
    let wallet_value = wallet_utxo.as_ref().map_or(0, |w| w.2);
    if wallet_value < total_fee {
        return Err(BatchError::InsufficientFee {
            needed: total_fee,
            available: wallet_value,
        });
    }
    let change = wallet_value - total_fee;
    if change >= MIN_UTXO_VALUE {
        outputs.push(PlannedOutput {
            value: change,
            script_public_key: matcher_spk.to_vec(),
            spk_version: matcher_spk_version,
            purpose: OutputPurpose::WalletChange,
        });
    } else {
        total_fee += change; // dust change -> miner fee
    }

    Ok(RingPlan {
        legs: legs.iter().enumerate().map(|(i, l)| (l.clone(), i)).collect(),
        wallet_input: wallet_utxo,
        outputs,
        output_auth_input,
        leg_source_tokens: parsed.iter().map(|p| p.source_token_cov_id).collect(),
        total_fee,
        matcher_surplus,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kob_core::contract::helpers::push_index;

    // Test token covenant IDs
    const TOKEN_A: [u8; 32] = [0x01; 32];
    const TOKEN_B: [u8; 32] = [0x02; 32];
    const TOKEN_C: [u8; 32] = [0x03; 32];

    /// Matcher SPK for tests (fake P2PK: 0xCC repeated).
    fn matcher_spk() -> Vec<u8> {
        vec![0xCC; 34]
    }

    // ═════════════════════════════════════════════════════════════════════
    // v18 planner tests (Stage B)
    // ═════════════════════════════════════════════════════════════════════

    /// Stage E gates: the generic planner entrypoints reject any pre-v18
    /// generation outright (the legacy planners were deleted with Stage E).
    #[test]
    fn test_pre_versions_rejected() {
        let token = [0x5B; 32];
        for legacy_version in [14u8, 16, 17] {
            let mut sell = make_sell(0x10, 30_000_000, 1, 1, token);
            let buy = make_buy(0x20, 30_000_000, 1, 1, token, 2000);
            sell.version = legacy_version;
            let r = plan_batch_match(&[sell.clone()], &[buy.clone()], None, &matcher_spk(), 0, None);
            assert!(
                matches!(r, Err(BatchError::UnsupportedVersion { .. })),
                "plan_batch_match must reject v{legacy_version}: {r:?}"
            );
            // plan_ioc_match skips non-v18 sells during sweep collection, so
            // a legacy-only book yields an empty-sweep error rather than
            // UnsupportedVersion — either way the plan MUST fail.
            let r = plan_ioc_match(&[sell.clone()], &buy, None, &matcher_spk(), 0, None);
            assert!(r.is_err(), "plan_ioc_match must reject v{legacy_version}: {r:?}");
            let r = plan_sell_ioc_match(&sell, &[buy.clone()], None, &matcher_spk(), 0, None);
            assert!(
                matches!(r, Err(BatchError::UnsupportedVersion { .. })),
                "plan_sell_ioc_match must reject v{legacy_version}: {r:?}"
            );
        }
    }

    /// Create a v18 sell order for testing.
    fn make_sell(id_byte: u8, amount: u64, price_num: u64, price_den: u64, token: [u8; 32]) -> BatchOrder {
        let tx_id = hex::encode([id_byte; 32]);
        let owner = [0xBB; 32];
        let sspkh = [0xCC; 32];
        let rs = kob_core::contract::spot::order::build_sell_redeem_script(
            price_num, price_den, 1_000_000, &owner, &sspkh, &[0xDD; 32], 30, 0, 0,
        ).unwrap();
        BatchOrder {
            outpoint: (tx_id, 0),
            order_type: OrderType::Sell,
            version: 18,
            token_cov_id: token,
            price_num,
            price_den,
            amount,
            redeem_script: rs,
            utxo_value: amount,
            counterparty_spk: vec![0xDD; 34],
            counterparty_spk_version: 0,
            min_fill: 1_000_000,
            oco_path: None,
            bracket_meta: None,
        }
    }

    /// Create a v18 buy order for testing (mmfee_bps lives in the RS state).
    fn make_buy(id_byte: u8, amount: u64, price_num: u64, price_den: u64, token: [u8; 32], mmfee_bps: u64) -> BatchOrder {
        let tx_id = hex::encode([id_byte; 32]);
        let owner = [0xBB; 32];
        let bspkh = [0xCC; 32];
        let rs = kob_core::contract::spot::order::build_buy_redeem_script(
            &token, price_num, price_den, 1_000_000, &owner, &bspkh, &[0xDD; 32], mmfee_bps, 0, 0,
        ).unwrap();
        BatchOrder {
            outpoint: (tx_id, 0),
            order_type: OrderType::Buy,
            version: 18,
            token_cov_id: token,
            price_num,
            price_den,
            amount,
            redeem_script: rs,
            utxo_value: amount,
            counterparty_spk: vec![0xEE; 34],
            counterparty_spk_version: 0,
            min_fill: 1_000_000,
            oco_path: None,
            bracket_meta: None,
        }
    }

    /// Create a v18 OCO sell order for testing. The BatchOrder carries the
    /// EXECUTING branch's price pair (the scanner books each OCO path as its
    /// own order), which is exactly what the attested sigscript must carry.
    fn make_oco_sell(
        id_byte: u8,
        amount: u64,
        tp: (u64, u64),
        sl: (u64, u64),
        path: kob_core::OcoPath,
        token: [u8; 32],
    ) -> BatchOrder {
        let tx_id = hex::encode([id_byte; 32]);
        let owner = [0xBB; 32];
        let sspkh = [0xCC; 32];
        let rs = kob_core::contract::spot::oco::build_oco_sell_redeem_script(
            tp.0, tp.1, 1, sl.0, sl.1, 1, &owner, &sspkh, &[0xDD; 32], 30, 0, 0,
        ).unwrap();
        let (pn, pd) = match path {
            kob_core::OcoPath::TakeProfit => tp,
            kob_core::OcoPath::StopLoss => sl,
        };
        BatchOrder {
            outpoint: (tx_id, 0),
            order_type: OrderType::Sell,
            version: 18,
            token_cov_id: token,
            price_num: pn,
            price_den: pd,
            amount,
            redeem_script: rs,
            utxo_value: amount,
            counterparty_spk: vec![0xDD; 34],
            counterparty_spk_version: 0,
            min_fill: 1,
            oco_path: Some(path),
            bracket_meta: None,
        }
    }

    /// v18 GTC N:1 sweep via the plan_batch_match dispatch: per-sell
    /// BuyerTokens outputs auth-bound to their sell inputs, populated koi
    /// map, canonical v18 sigscripts from build_tx, and a balanced plan.
    #[test]
    fn test_nm_sweep_emits_per_sell_outputs() {
        let token = [0x51; 32];
        let sells = vec![
            make_sell(0x10, 10_000_000, 99, 100, token),
            make_sell(0x11, 20_000_000, 99, 100, token),
        ];
        let buys = vec![make_buy(0x20, 30_000_000, 1, 1, token, 2000)];
        let wallet = Some((hex::encode([0x99u8; 32]), 0u32, 5_000_000u64));
        let plan = plan_batch_match(&sells, &buys, wallet, &matcher_spk(), 0, Some(2000))
            .expect("v18 sweep must plan");

        // One BuyerTokens output per sell, each bound to a distinct sell input.
        let bt: Vec<usize> = plan.outputs.iter().enumerate()
            .filter(|(_, o)| o.purpose == OutputPurpose::BuyerTokens)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(bt.len(), 2, "must emit 2 per-sell BuyerTokens outputs");
        let mut auths: Vec<u16> = bt.iter().map(|i| plan.output_auth_input[i]).collect();
        auths.sort();
        assert_eq!(auths, vec![0, 1]);
        assert_eq!(plan.buy_sweep_sells, vec![vec![0u16, 1u16]]);

        // koi map: both sells share one counterparty SPK -> merged SellerKas
        // output 0, and BOTH koi entries point at it (the v18 planners fix
        // the fallback-koi hazard the v17 planner left open).
        assert_eq!(plan.sell_output_idx, vec![0, 0]);
        assert_eq!(plan.outputs[0].value, 9_900_000 + 19_800_000);

        // Plan balances (validate also checks versions incl. 18).
        plan.validate().expect("v18 plan must validate");

        // build_tx: canonical v18 sigscripts, byte-exact.
        let tx = plan.build_tx().expect("build_tx");
        assert_eq!(tx.inputs.len(), 4, "2 sells + buy + wallet");
        let sell_rs0 = &plan.sells[0].0.redeem_script;
        let sell_rs1 = &plan.sells[1].0.redeem_script;
        assert_eq!(
            tx.inputs[0].sigscript,
            kob_core::contract::spot::order::build_sell_fill_sigscript(0, 99, 100, sell_rs0),
            "sell 0 must use the v18 attested fill sigscript with koi=0"
        );
        assert_eq!(
            tx.inputs[1].sigscript,
            kob_core::contract::spot::order::build_sell_fill_sigscript(0, 99, 100, sell_rs1),
            "sell 1 must use the v18 attested fill sigscript with the MERGED koi=0"
        );
        assert_eq!(
            tx.inputs[2].sigscript,
            build_buy_fill_sigscript(&[0, 1], false, &plan.buys[0].0.redeem_script),
            "buy must use the v18 GTC fill sigscript over sells [0, 1]"
        );
        // Canonical attestation offsets: pnum at [3..11), pden at [12..20).
        assert_eq!(&tx.inputs[0].sigscript[3..11], &99u64.to_le_bytes());
        assert_eq!(&tx.inputs[0].sigscript[12..20], &100u64.to_le_bytes());
    }

    /// Item D pin: >1 v18 buy per settle tx is rejected FAIL-CLOSED, BY PROOF
    /// (not as a temporary planner limitation).
    ///
    /// Engine-model proof (kaspa-txscript covenants.rs model): every token
    /// delivery output must carry the token's `CovenantBinding`, and a
    /// binding's `authorizing_input` must be an input whose covenant id
    /// equals the token's tcid. A buy UTXO is plain KAS P2SH — it carries NO
    /// covenant id — so no delivery output can ever be bound to a buy input.
    /// Per-buy delivery attribution therefore has to route through the tcid
    /// (sell) inputs' auth slots, and the v18 buy hardwires slot 0 of each
    /// tii term (`OpAuthOutputIdx(tii, 0)`). Two buys listing the same sell
    /// would both read (and both count) that same slot-0 output into their
    /// own token_sum/fair_sum, while each buy's floor and surplus cap are
    /// checked against its own kas_in only — nothing on-chain can prove the
    /// buys consumed DISJOINT sell subsets. Cross-buy disjointness being
    /// unprovable, multi-buy settles stay rejected at plan time.
    #[test]
    fn test_multi_buy_rejected() {
        let token = [0x52; 32];
        let sells = vec![
            make_sell(0x10, 10_000_000, 1, 1, token),
            make_sell(0x11, 10_000_000, 1, 1, token),
        ];
        let buys = vec![
            make_buy(0x20, 10_000_000, 1, 1, token, 2000),
            make_buy(0x21, 10_000_000, 1, 1, token, 2000),
        ];
        let r = plan_batch_match(&sells, &buys, None, &matcher_spk(), 0, Some(2000));
        assert!(
            matches!(r, Err(BatchError::MultiBuyUnsupported { count: 2 })),
            "2 v18 buys in one settle must be rejected, got {:?}", r
        );
        // Direct planner call must enforce the same pin.
        let sells2 = vec![make_sell(0x12, 10_000_000, 1, 1, token)];
        let buys2 = vec![
            make_buy(0x22, 10_000_000, 1, 1, token, 2000),
            make_buy(0x23, 10_000_000, 1, 1, token, 2000),
        ];
        let r2 = plan_batch_match(&sells2, &buys2, None, &matcher_spk(), 0, Some(2000));
        assert!(matches!(r2, Err(BatchError::MultiBuyUnsupported { .. })));
    }

    /// N > MAX_N rejects gracefully; N == MAX_N plans fine.
    #[test]
    fn test_sweep_max_n_bounds() {
        let token = [0x53; 32];
        let over = BUY_ORDER_MAX_N + 1;
        let sells: Vec<BatchOrder> = (0..over as u8)
            .map(|i| make_sell(0x60 + i, 5_000_000, 1, 1, token))
            .collect();
        let buys = vec![make_buy(0x20, over as u64 * 5_000_000, 1, 1, token, 2000)];
        let wallet = Some((hex::encode([0x99u8; 32]), 0u32, 5_000_000u64));
        let r = plan_batch_match(&sells, &buys, wallet.clone(), &matcher_spk(), 0, Some(2000));
        assert!(
            matches!(r, Err(BatchError::TooManySells { .. })),
            "N > MAX_N must reject gracefully, got {:?}", r
        );

        // N == MAX_N plans fine (per-sell values sized for the KIP-9
        // storage floor at N=32, wallet sized for the ~5.4M-sompi min fee).
        let n = BUY_ORDER_MAX_N;
        let sells: Vec<BatchOrder> = (0..n as u8)
            .map(|i| make_sell(0x70 + i, 400_000_000, 1, 1, token))
            .collect();
        let buys = vec![make_buy(0x21, n as u64 * 400_000_000, 1, 1, token, 2000)];
        let wallet = Some((hex::encode([0x99u8; 32]), 0u32, 50_000_000u64));
        let r = plan_batch_match(&sells, &buys, wallet, &matcher_spk(), 0, Some(2000));
        assert!(r.is_ok(), "N == MAX_N must plan fine: {:?}", r.err());
    }

    /// OCO sweep enablement: a v18 OCO sell composes into a MULTI-sell v18
    /// sweep (the pre-v18 OcoMultiSellSweepUnsupported guard does not apply),
    /// and build_tx emits the executing branch's attested TP sigscript.
    #[test]
    fn test_oco_multi_sell_sweep_allowed() {
        let token = [0x55; 32];
        let sells = vec![
            make_sell(0x10, 10_000_000, 99, 100, token),
            // TP is the cheap (crossing) branch here; SL parked at 1/2.
            make_oco_sell(0x11, 10_000_000, (99, 100), (1, 2), kob_core::OcoPath::TakeProfit, token),
        ];
        let buys = vec![make_buy(0x20, 20_000_000, 1, 1, token, 2000)];
        let wallet = Some((hex::encode([0x99u8; 32]), 0u32, 5_000_000u64));
        let plan = plan_batch_match(&sells, &buys, wallet, &matcher_spk(), 0, Some(2000))
            .expect("v18 multi-sell sweep with an OCO term must plan");
        let tx = plan.build_tx().expect("build_tx");
        let oco_rs = &plan.sells[1].0.redeem_script;
        assert_eq!(
            tx.inputs[1].sigscript,
            kob_core::contract::spot::oco::build_oco_sell_tp_fill_sigscript(
                plan.sell_output_idx[1] as u16, 99, 100, oco_rs,
            ),
            "OCO TP term must use the v18 attested TP fill sigscript"
        );
    }

    /// OCO branch attestation correctness: an SL-path OCO order attests the
    /// SL pair at the canonical offsets (and NOT the TP pair).
    #[test]
    fn test_oco_sl_branch_attests_sl_price() {
        let token = [0x56; 32];
        let oco = make_oco_sell(0x10, 10_000_000, (3, 1), (99, 100), kob_core::OcoPath::StopLoss, token);
        let oco_rs = oco.redeem_script.clone();
        let sells = vec![oco];
        // Buy limit at the SL rate (1:1 on the delivered 10M tokens for 9.9M KAS).
        let buys = vec![make_buy(0x20, 9_900_000, 100, 99, token, 2000)];
        let wallet = Some((hex::encode([0x99u8; 32]), 0u32, 5_000_000u64));
        let plan = plan_batch_match(&sells, &buys, wallet, &matcher_spk(), 0, Some(2000))
            .expect("solo v18 OCO SL sweep must plan");
        let tx = plan.build_tx().expect("build_tx");
        let ss = &tx.inputs[0].sigscript;
        assert_eq!(
            ss,
            &kob_core::contract::spot::oco::build_oco_sell_sl_fill_sigscript(0, 99, 100, &oco_rs),
            "SL fill must be the v18 attested SL sigscript"
        );
        // The attested pair at the canonical offsets is the SL pair...
        assert_eq!(&ss[3..11], &99u64.to_le_bytes(), "pnum_sl attested at [3..11)");
        assert_eq!(&ss[12..20], &100u64.to_le_bytes(), "pden_sl attested at [12..20)");
        // ...and the selector is Op2 (SL fill), not Op1 (TP).
        assert_eq!(ss[20], 0x52, "selector byte must be Op2 = SL fill");
        assert_ne!(
            ss,
            &kob_core::contract::spot::oco::build_oco_sell_tp_fill_sigscript(0, 3, 1, &oco_rs),
            "must not attest the TP pair"
        );
    }

    /// v18 IOC sweep: 3 crossing sells, buy affords 2; leftover KAS is
    /// accounted (buyer change and/or capped matcher surplus).
    #[test]
    fn test_ioc_sweep_with_change() {
        let token = [0x57; 32];
        let sell1 = make_sell(0x10, 3_000_000, 1, 1, token);
        let sell2 = make_sell(0x11, 3_000_000, 1, 1, token);
        let sell3 = make_sell(0x12, 5_000_000, 1, 1, token);
        let buy = make_buy(0x20, 7_000_000, 1, 1, token, 2000);
        let wallet = Some((hex::encode([0x99u8; 32]), 0u32, 5_000_000u64));

        let plan = plan_ioc_match(&[sell1, sell2, sell3], &buy, wallet, &matcher_spk(), 0, Some(2000))
            .expect("v18 IOC sweep must plan");
        assert_eq!(plan.sells.len(), 2, "only the 2 affordable sells are filled");
        assert_eq!(plan.ioc_mode, Some(IocSide::Buy));
        assert_eq!(plan.buy_sweep_sells, vec![vec![0u16, 1u16]]);
        let bt = plan.outputs.iter().filter(|o| o.purpose == OutputPurpose::BuyerTokens).count();
        assert_eq!(bt, 2, "per-sell BuyerTokens outputs (not merged)");
        let buyer_change_exists = plan.outputs.iter().any(|o| o.purpose == OutputPurpose::BuyerChange);
        assert!(buyer_change_exists || plan.matcher_surplus > 0, "leftover KAS must go somewhere");

        // build_tx emits the IOC (Op5) v18 sigscript.
        let tx = plan.build_tx().expect("build_tx");
        assert_eq!(
            tx.inputs[2].sigscript,
            build_buy_fill_sigscript(&[0, 1], true, &plan.buys[0].0.redeem_script),
        );
    }

    /// v18 IOC floor: total delivered tokens below the buy's own min_fill
    /// rejects (mirrors the contract's ioc_flag ? mfill : expected floor).
    #[test]
    fn test_ioc_below_min_fill_rejected() {
        let token = [0x58; 32];
        let sell1 = make_sell(0x10, 3_000_000, 1, 1, token);
        let mut buy = make_buy(0x20, 3_000_000, 1, 1, token, 2000);
        buy.min_fill = 50_000_000;
        let r = plan_ioc_match(&[sell1], &buy, None, &matcher_spk(), 0, Some(2000));
        assert!(matches!(r, Err(BatchError::MinFillViolation { .. })), "below-min_fill IOC must reject, got {:?}", r);
    }

    /// v18 IOC sweep caps at MAX_N even when more sells cross and are
    /// affordable.
    #[test]
    fn test_ioc_sweep_capped_at_max_n() {
        let token = [0x5a; 32];
        let n_max = BUY_ORDER_MAX_N;
        let sells: Vec<BatchOrder> = (0..(n_max as u8 + 2))
            .map(|i| make_sell(0x50 + i, 5_000_000, 1, 1, token))
            .collect();
        // Affords more than MAX_N sells (32*5M + 1M) but must cap; the
        // 1M leftover stays within the 2000bps on-chain cap (32.2M).
        let buy = make_buy(0x20, n_max as u64 * 5_000_000 + 1_000_000, 1, 1, token, 2000);
        let wallet = Some((hex::encode([0x99u8; 32]), 0u32, 5_000_000u64));
        let plan = plan_ioc_match(&sells, &buy, wallet, &matcher_spk(), 0, Some(2000))
            .expect("must plan (capped, not error)");
        assert_eq!(plan.sells.len(), n_max, "sweep must cap at MAX_N");
    }

    /// v18 IOC cap feasibility: the contract's surplus cap reads the FULL
    /// kas_in, so a sweep leaving more unswept KAS than mmfee_bps allows is
    /// rejected at plan time instead of failing on-chain.
    #[test]
    fn test_ioc_cap_infeasible_rejected() {
        let token = [0x5b; 32];
        let sell1 = make_sell(0x10, 3_000_000, 1, 1, token);
        // mmfee 30bps: allowance = 30M/10000*30 = 90k << 27M leftover.
        let buy = make_buy(0x20, 30_000_000, 1, 1, token, 30);
        let wallet = Some((hex::encode([0x99u8; 32]), 0u32, 5_000_000u64));
        let r = plan_ioc_match(&[sell1], &buy, wallet, &matcher_spk(), 0, Some(2000));
        assert!(matches!(r, Err(BatchError::CapInfeasible { .. })), "over-cap IOC sweep must reject, got {:?}", r);
    }

    /// Item C: v18 partial residual accounting. spent = kas_in - residual;
    /// the residual output is the buy's own P2SH with NO covenant binding;
    /// build_tx emits the Op2 sigscript with the residual output index.
    #[test]
    fn test_partial_residual_accounting() {
        let token = [0x5c; 32];
        let sells = vec![make_sell(0x10, 10_000_000, 99, 100, token)];
        let buy = make_buy(0x20, 30_000_000, 1, 1, token, 2000);
        let buy_p2sh = kob_core::p2sh::build_p2sh(&buy.redeem_script);
        let wallet = Some((hex::encode([0x99u8; 32]), 0u32, 5_000_000u64));
        let plan = plan_partial_match(&sells, &buy, wallet, &matcher_spk(), 0, None)
            .expect("v18 partial must plan");

        let &(spent, residual_idx, _) = plan.buy_partial_fills.get(&0).expect("partial entry");
        // Floor clamp pins spent to exactly the token_sum at the buy's 1/1
        // limit: base 9.9M + 100k matcher surplus = 10M.
        assert_eq!(spent, 10_000_000, "spent = seller kas + clamped surplus");
        let residual_out = &plan.outputs[residual_idx as usize];
        assert_eq!(residual_out.purpose, OutputPurpose::BuyResidual);
        assert_eq!(residual_out.value, buy.utxo_value - spent, "residual = kas_in - spent");
        assert_eq!(residual_out.value, 20_000_000);
        assert_eq!(
            residual_out.script_public_key,
            buy_p2sh.script().to_vec(),
            "residual SPK must be the buy's own P2SH byte-exact"
        );
        plan.validate().expect("partial plan must balance");

        let tx = plan.build_tx().expect("build_tx");
        assert_eq!(
            tx.inputs[1].sigscript,
            build_buy_partial_fill_sigscript(&[0], residual_idx, &plan.buys[0].0.redeem_script),
            "buy must use the v18 Op2 partial sigscript"
        );
    }

    /// Item C chaining: the residual UTXO is a normal v18 buy again (same
    /// RS, same P2SH). Plan a second partial event on it.
    #[test]
    fn test_partial_chaining_two_events() {
        let token = [0x5d; 32];
        let wallet = Some((hex::encode([0x99u8; 32]), 0u32, 5_000_000u64));

        // Event 1: 30M buy spends 10M against a 10M-token sell, keeps 20M.
        let buy1 = make_buy(0x20, 30_000_000, 1, 1, token, 2000);
        let plan1 = plan_partial_match(
            &[make_sell(0x10, 10_000_000, 99, 100, token)],
            &buy1, wallet.clone(), &matcher_spk(), 0, None,
        ).expect("event 1 must plan");
        let &(spent1, ri1, _) = plan1.buy_partial_fills.get(&0).unwrap();
        let residual1 = plan1.outputs[ri1 as usize].value;
        assert_eq!(residual1, buy1.utxo_value - spent1);
        assert_eq!(residual1, 20_000_000);

        // Event 2: the residual (same RS => same P2SH continuation) is the
        // new buy UTXO, spends 15M against a 15M-token sell, keeps 5M.
        let mut buy2 = make_buy(0x21, residual1, 1, 1, token, 2000);
        buy2.redeem_script = buy1.redeem_script.clone(); // byte-exact continuation
        let plan2 = plan_partial_match(
            &[make_sell(0x11, 15_000_000, 99, 100, token)],
            &buy2, wallet, &matcher_spk(), 0, None,
        ).expect("event 2 must plan on the residual");
        let &(spent2, ri2, _) = plan2.buy_partial_fills.get(&0).unwrap();
        let residual2 = plan2.outputs[ri2 as usize].value;
        assert_eq!(spent2, 15_000_000);
        assert_eq!(residual2, residual1 - spent2);
        assert_eq!(residual2, 5_000_000);
        // The chained residual continues the SAME P2SH.
        assert_eq!(
            plan2.outputs[ri2 as usize].script_public_key,
            plan1.outputs[ri1 as usize].script_public_key,
        );
    }

    /// Per-event mfill floor (dust-grind block) on the partial planner.
    #[test]
    fn test_partial_mfill_floor_rejected() {
        let token = [0x5e; 32];
        let sells = vec![make_sell(0x10, 10_000_000, 99, 100, token)];
        let mut buy = make_buy(0x20, 30_000_000, 1, 1, token, 2000);
        buy.min_fill = 50_000_000; // event delivers only 10M tokens
        let r = plan_partial_match(&sells, &buy, None, &matcher_spk(), 0, None);
        assert!(matches!(r, Err(BatchError::MinFillViolation { .. })), "sub-mfill partial event must reject, got {:?}", r);
    }

    /// Cap feasibility: with mmfee_bps = 0 and a sell whose integer-rounding
    /// gap (seller_kas - contract fair_sum) is positive, even a zero-surplus
    /// partial cannot satisfy the contract cap -> reject at plan time.
    #[test]
    fn test_partial_cap_infeasible_rejected() {
        let token = [0x5f; 32];
        // amount=10_000_005 @ 3/10: seller_kas = floor(30_000_015/10) = 3_000_001,
        // fair_sum = floor(10_000_005/10)*3 = 3_000_000 -> gap = 1 > allowance 0.
        let sells = vec![make_sell(0x10, 10_000_005, 3, 10, token)];
        let buy = make_buy(0x20, 30_000_000, 1, 1, token, 0);
        let r = plan_partial_match(&sells, &buy, None, &matcher_spk(), 0, None);
        assert!(matches!(r, Err(BatchError::CapInfeasible { .. })), "rounding gap > 0bps allowance must reject, got {:?}", r);
    }

    /// A "partial" that would leave no relayable residual must use the full
    /// fill planners instead (Op2 demands residual >= 1; dust is unbookable).
    #[test]
    fn test_partial_no_residual_room_rejected() {
        let token = [0x60; 32];
        let sells = vec![make_sell(0x10, 10_000_000, 1, 1, token)];
        let buy = make_buy(0x20, 11_000_000, 1, 1, token, 2000);
        let r = plan_partial_match(&sells, &buy, None, &matcher_spk(), 0, None);
        assert!(matches!(r, Err(BatchError::OutputBelowMinimum { .. })), "sub-MIN_UTXO residual must reject, got {:?}", r);
    }

    /// v18 sell-IOC parity: exact-consume settles GTC (Op1 both sides).
    #[test]
    fn test_sell_ioc_exact_full_fill_plans() {
        let token = [0x61; 32];
        let sell = make_sell(0x10, 10_000_000, 1, 1, token);
        let buys = vec![make_buy(0x20, 10_000_000, 1, 1, token, 2000)];
        let wallet = Some((hex::encode([0x99u8; 32]), 0u32, 5_000_000u64));
        let plan = plan_sell_ioc_match(&sell, &buys, wallet, &matcher_spk(), 0, Some(2000))
            .expect("exact-consume sell IOC must plan");
        assert_eq!(plan.ioc_mode, None, "exact match settles GTC");
        assert_eq!(plan.buy_sweep_sells, vec![vec![0u16]]);
        plan.validate().expect("plan must balance");
        let tx = plan.build_tx().expect("build_tx");
        assert_eq!(
            tx.inputs[0].sigscript,
            kob_core::contract::spot::order::build_sell_fill_sigscript(0, 1, 1, &plan.sells[0].0.redeem_script),
        );
        assert_eq!(
            tx.inputs[1].sigscript,
            build_buy_fill_sigscript(&[0], false, &plan.buys[0].0.redeem_script),
        );
    }

    /// v18 sell-IOC parity: a larger buy absorbs the sell via its IOC
    /// selector; leftover recoverable only within the buy's mmfee cap.
    #[test]
    fn test_sell_ioc_larger_buy_settles_ioc() {
        let token = [0x62; 32];
        let sell = make_sell(0x10, 10_000_000, 1, 1, token);
        // 12M buy: leftover 2M <= floor(12M/10000)*2000 = 2.4M -> feasible.
        let buys = vec![make_buy(0x20, 12_000_000, 1, 1, token, 2000)];
        let wallet = Some((hex::encode([0x99u8; 32]), 0u32, 5_000_000u64));
        let plan = plan_sell_ioc_match(&sell, &buys, wallet, &matcher_spk(), 0, Some(2000))
            .expect("larger-buy sell IOC must plan");
        assert_eq!(plan.ioc_mode, Some(IocSide::Buy));
        let tx = plan.build_tx().expect("build_tx");
        assert_eq!(
            tx.inputs[1].sigscript,
            build_buy_fill_sigscript(&[0], true, &plan.buys[0].0.redeem_script),
            "buy must use the Op5 IOC selector"
        );
    }

    /// v18 sell-IOC structural rejection: a smaller buy would leave a sell
    /// residual, which cannot coexist with a v18 buy in one tx (the buy
    /// reads the sell's auth slot 0 as its delivery; the sell's IOC F4
    /// demands the same slot for its self-SPK residual).
    #[test]
    fn test_sell_ioc_residual_rejected() {
        let token = [0x63; 32];
        let sell = make_sell(0x10, 20_000_000, 1, 1, token);
        let buys = vec![make_buy(0x20, 10_000_000, 1, 1, token, 2000)];
        let r = plan_sell_ioc_match(&sell, &buys, None, &matcher_spk(), 0, Some(2000));
        assert!(
            matches!(r, Err(BatchError::SellResidualUnsupported { .. })),
            "sell-residual composition must reject, got {:?}", r
        );
    }

    // ── Ring planner (item F) ──

    /// Fake P2PK owner SPK for ring tests.
    fn ring_owner_spk(seed: u8) -> Vec<u8> {
        let mut s = Vec::with_capacity(34);
        s.push(0x20);
        s.extend_from_slice(&[seed; 32]);
        s.push(0xac);
        s
    }

    /// Build a ring leg: source -> target with parsed-from-RS parameters.
    fn make_ring_leg(
        id_byte: u8,
        source: [u8; 32],
        target: [u8; 32],
        amount: u64,
        min_target: u64,
        mmfee_bps: u64,
        owner_seed: u8,
    ) -> RingLegOrder {
        let owner_spk = ring_owner_spk(owner_seed);
        let owner_spk_hash = kob_core::p2sh::compute_spk_hash(0, &owner_spk);
        let rs = kob_core::contract::spot::swap::build_swap_redeem_script(
            &source, &target, min_target, &[0xBB; 32], &owner_spk_hash, &[0xEE; 32], mmfee_bps,
        ).unwrap();
        RingLegOrder {
            outpoint: (hex::encode([id_byte; 32]), 0),
            redeem_script: rs,
            utxo_value: amount,
            owner_spk,
            owner_spk_version: 0,
        }
    }

    const RING_A: [u8; 32] = [0xA1; 32];
    const RING_B: [u8; 32] = [0xA2; 32];
    const RING_C: [u8; 32] = [0xA3; 32];

    /// 2-cycle ring with matcher skim exactly at the per-leg F4 cap.
    #[test]
    fn test_ring_2cycle_plans_with_capped_skim() {
        let (a0, a1) = (1_000_000_000u64, 2_000_000_000u64);
        let fee = |a: u64| a / 10000 * 100; // 100bps caps: 10M / 20M
        let legs = vec![
            // leg0 gives A (1e9), wants B with floor = a1 - cap1.
            make_ring_leg(0x10, RING_A, RING_B, a0, a1 - fee(a1), 100, 0xF0),
            // leg1 gives B (2e9), wants A with floor = a0 - cap0.
            make_ring_leg(0x11, RING_B, RING_A, a1, a0 - fee(a0), 100, 0xF1),
        ];
        let wallet = Some((hex::encode([0x99u8; 32]), 0u32, 5_000_000u64));
        let plan = plan_ring_match(&legs, wallet, &matcher_spk(), 0)
            .expect("2-cycle ring must plan");
        plan.validate().expect("ring plan must balance");

        // Deliveries at outputs 0..2, skimmed exactly to the F4 floor.
        assert_eq!(plan.outputs[0].purpose, OutputPurpose::RingDelivery);
        assert_eq!(plan.outputs[0].value, a0 - fee(a0), "leg0 delivery skimmed to its F4 floor");
        assert_eq!(plan.outputs[1].value, a1 - fee(a1));
        // Delivery j is auth slot 0 of giver input j (skims come after).
        assert_eq!(plan.output_auth_input[&0], 0);
        assert_eq!(plan.output_auth_input[&1], 1);
        // Skims to the matcher at outputs >= n, auth-bound to their givers.
        let skims: Vec<usize> = plan.outputs.iter().enumerate()
            .filter(|(_, o)| o.purpose == OutputPurpose::MatcherSkim)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(skims.len(), 2);
        assert!(skims.iter().all(|&i| i >= 2), "skims must sit after all deliveries");
        assert_eq!(plan.matcher_surplus, fee(a0) + fee(a1));

        // build_tx: leg i names giver/toi (i+1) % n.
        let tx = plan.build_tx().expect("build_tx");
        assert_eq!(
            tx.inputs[0].sigscript,
            kob_core::contract::spot::swap::build_swap_fill_sigscript(1, 1, &legs[0].redeem_script),
        );
        assert_eq!(
            tx.inputs[1].sigscript,
            kob_core::contract::spot::swap::build_swap_fill_sigscript(0, 0, &legs[1].redeem_script),
        );
    }

    /// 3-cycle (triangle) ring plans; dust skims fold back into deliveries.
    #[test]
    fn test_ring_3cycle_plans() {
        let amounts = [10_000_000u64, 20_000_000, 30_000_000];
        let legs = vec![
            // min_target = full amount of the target -> no skim room; the
            // 100bps caps (100k..300k) are all dust (< MIN_UTXO) anyway.
            make_ring_leg(0x10, RING_A, RING_B, amounts[0], amounts[1], 100, 0xF0),
            make_ring_leg(0x11, RING_B, RING_C, amounts[1], amounts[2], 100, 0xF1),
            make_ring_leg(0x12, RING_C, RING_A, amounts[2], amounts[0], 100, 0xF2),
        ];
        let wallet = Some((hex::encode([0x99u8; 32]), 0u32, 5_000_000u64));
        let plan = plan_ring_match(&legs, wallet, &matcher_spk(), 0)
            .expect("3-cycle ring must plan");
        plan.validate().expect("ring plan must balance");
        let deliveries: Vec<u64> = plan.outputs.iter()
            .filter(|o| o.purpose == OutputPurpose::RingDelivery)
            .map(|o| o.value)
            .collect();
        assert_eq!(deliveries, amounts.to_vec(), "full deliveries, dust skims folded back");
        assert_eq!(plan.matcher_surplus, 0);
        assert_eq!(plan.leg_source_tokens, vec![RING_A, RING_B, RING_C]);
    }

    /// Ring feasibility: a receiver's min_target above its giver's amount
    /// rejects (F2 could never pass).
    #[test]
    fn test_ring_infeasible_min_target_rejected() {
        let legs = vec![
            // leg0 wants at least 2e9 + 1 of B, but leg1 only holds 2e9.
            make_ring_leg(0x10, RING_A, RING_B, 1_000_000_000, 2_000_000_001, 100, 0xF0),
            make_ring_leg(0x11, RING_B, RING_A, 2_000_000_000, 900_000_000, 100, 0xF1),
        ];
        let wallet = Some((hex::encode([0x99u8; 32]), 0u32, 5_000_000u64));
        let r = plan_ring_match(&legs, wallet, &matcher_spk(), 0);
        assert!(
            matches!(r, Err(BatchError::RingInfeasible { leg: 0, needed: 2_000_000_001, available: 2_000_000_000 })),
            "unmeetable min_target must reject, got {:?}", r
        );
    }

    /// Ring leg-count bounds: 1 and RING_MAX+1 legs reject.
    #[test]
    fn test_ring_leg_count_bounds() {
        let leg = make_ring_leg(0x10, RING_A, RING_B, 10_000_000, 10_000_000, 100, 0xF0);
        let wallet = Some((hex::encode([0x99u8; 32]), 0u32, 5_000_000u64));
        let r = plan_ring_match(&[leg.clone()], wallet.clone(), &matcher_spk(), 0);
        assert!(matches!(r, Err(BatchError::RingLegCount { count: 1 })), "1 leg must reject, got {:?}", r);

        // RING_MAX + 1 legs (closure is checked after the count bound).
        let over = (RING_MAX + 1) as u8;
        let legs: Vec<RingLegOrder> = (0..over)
            .map(|i| make_ring_leg(0x20 + i, [i; 32], [i + 1; 32], 10_000_000, 10_000_000, 100, 0xF0 + i))
            .collect();
        let r = plan_ring_match(&legs, wallet, &matcher_spk(), 0);
        assert!(
            matches!(r, Err(BatchError::RingLegCount { count }) if count == RING_MAX + 1),
            "RING_MAX+1 legs must reject, got {:?}", r
        );
    }

    /// Ring closure: target/source chain must close into a cycle.
    #[test]
    fn test_ring_not_closed_rejected() {
        let legs = vec![
            make_ring_leg(0x10, RING_A, RING_B, 10_000_000, 10_000_000, 100, 0xF0),
            // leg1 gives C (not B) -> leg0's giver has the wrong token.
            make_ring_leg(0x11, RING_C, RING_A, 20_000_000, 10_000_000, 100, 0xF1),
        ];
        let wallet = Some((hex::encode([0x99u8; 32]), 0u32, 5_000_000u64));
        let r = plan_ring_match(&legs, wallet, &matcher_spk(), 0);
        assert!(matches!(r, Err(BatchError::RingNotClosed { .. })), "open chain must reject, got {:?}", r);
    }

    /// Ring leg validation: supplied owner SPK must hash to the RS's
    /// owner_spk_hash (F3 would fail on-chain otherwise).
    #[test]
    fn test_ring_owner_spk_mismatch_rejected() {
        let mut legs = vec![
            make_ring_leg(0x10, RING_A, RING_B, 10_000_000, 10_000_000, 100, 0xF0),
            make_ring_leg(0x11, RING_B, RING_A, 20_000_000, 10_000_000, 100, 0xF1),
        ];
        legs[0].owner_spk = ring_owner_spk(0x00); // wrong SPK for the RS hash
        let wallet = Some((hex::encode([0x99u8; 32]), 0u32, 5_000_000u64));
        let r = plan_ring_match(&legs, wallet, &matcher_spk(), 0);
        assert!(matches!(r, Err(BatchError::RingInvalidLeg { .. })), "owner SPK mismatch must reject, got {:?}", r);
    }

    #[test]
    fn emit_matcher_fee_drops_dust_instead_of_folding_into_seller() {
        // Regression for the engine match settlement failure (V16_STATUS Phase
        // 8): a sub-MIN_UTXO matcher surplus must NOT be added to outputs[0]
        // (the seller) — that inflated SellerKas past the buyer's KAS input and
        // the covenant rejected settlement ("script ran, but verification
        // failed"). It is dropped to the miner fee (no output emitted).
        let mk_seller = || vec![PlannedOutput {
            value: 29_940_000, // seller fair KAS
            script_public_key: vec![0u8; 34],
            spk_version: 0,
            purpose: OutputPurpose::SellerKas,
        }];

        let mut outputs = mk_seller();
        let dust = MIN_UTXO_VALUE - 1;
        let (surplus, dropped) = emit_matcher_fee(&mut outputs, dust, &[0u8; 34], 0);
        assert_eq!(surplus, 0, "dust surplus reported as 0 matcher take");
        assert_eq!(dropped, dust, "dust amount reported as dropped-to-fee so the caller balances total_fee");
        assert_eq!(outputs.len(), 1, "no MatcherFee output emitted for dust");
        assert_eq!(outputs[0].value, 29_940_000, "seller output must NOT be inflated by dust");

        // At/above the threshold it IS a clean MatcherFee output; seller stays.
        let mut outputs2 = mk_seller();
        let (clean, dropped2) = emit_matcher_fee(&mut outputs2, MIN_UTXO_VALUE, &[9u8; 34], 0);
        assert_eq!(clean, MIN_UTXO_VALUE);
        assert_eq!(dropped2, 0, "nothing dropped when the matcher fee is a real UTXO");
        assert_eq!(outputs2.len(), 2);
        assert_eq!(outputs2[1].purpose, OutputPurpose::MatcherFee);
        assert_eq!(outputs2[0].value, 29_940_000, "seller unchanged when matcher fee is its own output");
    }

    #[test]
    fn push_index_encoding() {
        // Op0
        let mut buf = Vec::new();
        push_index(&mut buf, 0);
        assert_eq!(buf, vec![0x00], "index 0 -> Op0");

        // Op1..Op16
        for n in 1..=16u16 {
            let mut buf = Vec::new();
            push_index(&mut buf, n);
            assert_eq!(buf, vec![0x50 + n as u8], "index {} -> Op{}", n, n);
        }

        // 17..127 uses data-push [0x01, n]
        for n in [17u16, 20, 50, 100, 127] {
            let mut buf = Vec::new();
            push_index(&mut buf, n);
            assert_eq!(buf, vec![0x01, n as u8], "index {} -> data-push [0x01, {}]", n, n);
        }

        // 128..255 uses sign-extended data-push [0x02, n, 0x00]
        for n in [128u16, 200, 255] {
            let mut buf = Vec::new();
            push_index(&mut buf, n);
            assert_eq!(buf, vec![0x02, n as u8, 0x00],
                "index {} -> data-push [0x02, {}, 0x00] (sign-extended)", n, n);
        }

        // 256+ uses 2-byte little-endian [0x02, lo, hi]
        for n in [256u16, 300, 512] {
            let mut buf = Vec::new();
            push_index(&mut buf, n);
            assert_eq!(buf, vec![0x02, n as u8, (n >> 8) as u8],
                "index {} -> data-push [0x02, {}, {}]", n, n as u8, (n >> 8) as u8);
        }
    }

    // Test: push_index sign-extension for index 128 (regression for >127 batches)
    #[test]
    fn test_push_index_128_sign_extension() {
        let mut buf = Vec::new();
        push_index(&mut buf, 128);
        // 128 must use [0x02, 0x80, 0x00] to avoid being read as -0 or negative
        assert_eq!(buf, vec![0x02, 0x80, 0x00],
            "index 128 needs sign-extension: [0x02, 0x80, 0x00]");

        let mut buf2 = Vec::new();
        push_index(&mut buf2, 255);
        assert_eq!(buf2, vec![0x02, 0xFF, 0x00],
            "index 255 needs sign-extension: [0x02, 0xFF, 0x00]");

        let mut buf3 = Vec::new();
        push_index(&mut buf3, 256);
        assert_eq!(buf3, vec![0x02, 0x00, 0x01],
            "index 256: [0x02, 0x00, 0x01] little-endian");
    }

    // ---- bps cap tests ----

    // ---- IOC tests ----

    // =========================================================
    //  Sell IOC tests (1 sell sweeps N buys)
    // =========================================================

    // =========================================================
    //  IOC build_tx sigscript tests
    // =========================================================

    // ── V16 tests ──────────────────────────────────────────────────────
    //
    // Regression coverage for the Phase-0 "version 16 is already taken"
    // collision: BatchOrder.version == 16 means EITHER a bracket entry
    // (365B RS) or a v16 buy order (476B RS, the F6-fix contract). Dispatch
    // in build_tx() must key off RS length, not the bare version number.

}
