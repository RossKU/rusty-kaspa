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
    build_oco_sell_sl_fill_sigscript_fixed_offset,
    build_oco_sell_tp_fill_sigscript,
    build_oco_sell_tp_fill_sigscript_fixed_offset,
    build_oco_sell_v18_sl_fill_sigscript,
    build_oco_sell_v18_tp_fill_sigscript,
};
use kob_core::contract::spot::order::{
    BUY_ORDER_V16_RS_EXPECTED_LEN,
    BUY_ORDER_V17_MAX_N,
    BUY_ORDER_V17_RS_EXPECTED_LEN,
    BUY_ORDER_V18_MAX_N,
    BUY_ORDER_V18_RS_EXPECTED_LEN,
    build_buy_fill_sigscript,
    build_buy_ioc_fill_sigscript,
    build_buy_v16_fill_sigscript,
    build_buy_v16_ioc_fill_sigscript,
    build_buy_v16_partial_fill_sigscript,
    build_buy_v17_fill_sigscript,
    build_buy_v18_fill_sigscript,
    build_buy_v18_partial_fill_sigscript,
    build_sell_fill_sigscript,
    build_sell_fill_sigscript_fixed_offset,
    build_sell_ioc_fill_sigscript,
    build_sell_ioc_fill_sigscript_fixed_offset,
    build_sell_v18_fill_sigscript,
    build_sell_v18_ioc_fill_sigscript,
};
use kob_core::contract::spot::swap::{parse_swap_order_v18_rs, build_swap_v18_fill_sigscript, SWAP_V18_RS_SIZE};
use kob_core::contract::spot::bracket::build_bracket_fill_sigscript;
use kob_core::contract::spot::parse::BRACKET_RS_SIZE;

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
    /// History: `OCO_SELL_BODY`'s fill F4 originally used the pre-Fix-3
    /// transaction-wide shared index (`OpCovOutputIdx(T,0)`), so a matcher
    /// could satisfy an OCO sell's F4 with a DIFFERENT same-token sell's
    /// authorized output and drain the OCO seller's tokens out as KAS. That
    /// L1 drain is now CLOSED: `OCO_SELL_BODY`'s F4 was rewritten to the
    /// per-input `OpAuthOutputIdx` binding (Item A, engine-proven by
    /// `oco_f4_shared_output_drain_rejected` / `oco_f4_honest_per_input_outputs_pass`
    /// in `core/tests/toccata_fill_repro.rs`).
    ///
    /// This composition-layer exclusion is KEPT for PRE-v18 generations only.
    /// The real remaining blocker there is the OCO-SL fixed-offset price-read
    /// mismatch -- a v16/v17 buy reads the swept sell's price via
    /// `OpTxInputScriptSigSubstr` at fixed offsets `[7..15)`/`[16..24)`, which
    /// land on the OCO RS's `pnum_tp`/`pden_tp` (correct for a TP fill, WRONG
    /// for an SL fill, which executes at `pnum_sl`/`pden_sl`). Composing an
    /// OCO-SL sell would let the buy fair-price the term at the TP price while
    /// the seller delivers at the SL price, weakening the buyer's surplus cap.
    ///
    /// v18 SOLVES this with the canonical price attestation: every fill-family
    /// sigscript carries `(pnum, pden)` at fixed offsets [3..11)/[12..20) and
    /// the OCO body verifies the attested pair equals the *executing branch's*
    /// state pair (TP: pnum_tp/pden_tp; SL: pnum_sl/pden_sl). v18 OCO sells are
    /// therefore sweep-eligible on BOTH branches (`plan_batch_match_v18` /
    /// `plan_ioc_match_v18` / `plan_partial_match_v18`) and this error is never
    /// returned for them. A solo (1-sell) OCO fill is unaffected in any
    /// generation.
    OcoMultiSellSweepUnsupported { outpoint: String },
    /// A v18 sweep was asked to include more sells than the contract's
    /// compile-time `BUY_ORDER_V18_MAX_N` slot count (same failure mode as
    /// `V17TooManySells`: the sigscript builder `assert!`s and panics; the
    /// planner rejects gracefully well before that point).
    V18TooManySells { count: usize, max: usize },
    /// More than one v18 buy in a single settle tx (item D, fail-closed BY
    /// PROOF — see `test_v18_multi_buy_rejected` for the engine-model
    /// argument: delivery outputs can only bind to tcid inputs, never to a
    /// buy, so cross-buy disjointness is unprovable on-chain).
    V18MultiBuyUnsupported { count: usize },
    /// A v18 sell that would keep a token residual cannot settle against a
    /// v18 buy covenant in the same tx — STRUCTURAL, not a planner policy:
    /// the buy derives its delivery as `OpAuthOutputIdx(tii, 0)` (auth slot 0
    /// of the sell input, buyer-SPK checked) while the sell's IOC/partial F4
    /// requires that same slot 0 to be its self-SPK residual continuation.
    /// Both cannot hold at once, so v18 sweeps are full-fill-only (exactly
    /// the V18_DESIGN.md note). Such books settle when a counterparty fully
    /// consumes the sell (buy-anchored GTC/IOC/partial planners) or via a
    /// matcher-as-counterparty sell-partial settle (no buy input).
    V18SellResidualUnsupported { outpoint: String, utxo_value: u64, filled_tokens: u64 },
    /// v18 accounting: the buy contract's surplus cap
    /// (`spent - fair_sum <= spent/10000*mmfee_bps`) cannot be satisfied even
    /// at zero matcher surplus (integer-rounding gap exceeds the allowance).
    V18CapInfeasible { spent: u64, fair_sum: u64, cap: u64 },
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
    /// A v17 sweep was asked to include more sells than the contract's
    /// compile-time `BUY_ORDER_V17_MAX_N` slot count.
    ///
    /// `build_buy_v17_fill_sigscript` (core/src/contract/spot/order.rs)
    /// `assert!`s on this and panics; this variant lets the planner reject
    /// gracefully with an `Err` well before that point is ever reached.
    V17TooManySells { count: usize, max: usize },
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
            BatchError::OcoMultiSellSweepUnsupported { outpoint } => {
                write!(f, "OCO sell {} cannot be composed into a pre-v18 multi-sell sweep (2+ sells in one tx); the pre-v18 fixed-offset price read lands on the TP pair even for an SL fill (the F4 drain itself was closed by the per-input Fix-3 rewrite). v18 OCO sells attest the executing branch's price and ARE sweep-eligible", outpoint)
            }
            BatchError::V17TooManySells { count, max } => {
                write!(f, "v17 sweep has {} sells, exceeds BUY_ORDER_V17_MAX_N={}", count, max)
            }
            BatchError::V18TooManySells { count, max } => {
                write!(f, "v18 sweep has {} sells, exceeds BUY_ORDER_V18_MAX_N={}", count, max)
            }
            BatchError::V18MultiBuyUnsupported { count } => {
                write!(f, "v18 settle has {} buys; only 1 v18 buy per settle tx is provable on-chain (item D fail-closed pin)", count)
            }
            BatchError::V18SellResidualUnsupported { outpoint, utxo_value, filled_tokens } => {
                write!(f, "v18 sell {} would keep a token residual ({} of {} filled); a v18 partial sell cannot settle against a v18 buy in the same tx (auth-slot-0 conflict: buy delivery vs sell residual)", outpoint, filled_tokens, utxo_value)
            }
            BatchError::V18CapInfeasible { spent, fair_sum, cap } => {
                write!(f, "v18 surplus cap infeasible: spent={} fair_sum={} allowed cap={}", spent, fair_sum, cap)
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

        // Fixed-offset detection: if any buy in the batch reads the
        // counterparty sell's pnum/pden via OpTxInputScriptSigSubstr at fixed
        // sigscript offsets [7..15)/[16..24), all sells must use the
        // fixed-offset sigscript format (fixed 2-byte koi push) so those
        // offsets land where the buy expects them (see order.rs). BOTH v16
        // (F6 cross-input surplus) AND v17 (per-sell fair_kas summation) use
        // this exact convention, so a v17 buy needs it too -- omitting v17
        // here left the swept sells on the 1-byte-OpN koi push, shifting the
        // RS (and thus pnum/pden) one byte and making v17's price read decode
        // garbage -> "script ran, but verification failed" on-chain.
        let has_fixed_offset_buy = self.buys.iter().any(|(b, _)| {
            b.redeem_script.len() == BUY_ORDER_V16_RS_EXPECTED_LEN
                || b.redeem_script.len() == BUY_ORDER_V17_RS_EXPECTED_LEN
        });

        // v18 detection: a v18 buy reads each swept sell's price at the
        // CANONICAL attestation offsets (pnum at sigscript [3..11), pden at
        // [12..20)) on the covenant-authenticated tii, so every sell in a v18
        // settle must use the v18 attested sigscript builders (which also make
        // the sell body itself verify the attested pair against the executing
        // branch's state pair).
        let has_v18_buy = self.buys.iter().any(|(b, _)| {
            b.redeem_script.len() == BUY_ORDER_V18_RS_EXPECTED_LEN
        });

        // === Build sell inputs ===
        for (i, (sell, input_idx)) in self.sells.iter().enumerate() {
            // Use merged sell_output_idx if populated, else fall back to input_idx (legacy 1:1).
            let koi = if !self.sell_output_idx.is_empty() {
                self.sell_output_idx[i]
            } else {
                *input_idx
            };

            // Detect partial fill: sell_fill_amounts[i] < sell.utxo_value means
            // buyers didn't absorb all tokens.  The full-fill path (Op1) F4 check
            // requires covenant_output[0].value >= input_value, which fails when
            // there's a remainder.  Use IOC fill (Op5 + fta) instead — its F4
            // only checks covenant_output_count >= 1 (existence).
            let has_remainder = self.sell_fill_amounts.get(i)
                .map_or(false, |&fta| fta < sell.utxo_value);

            let ss = if has_v18_buy {
                // v18 canonical attested sigscripts. The attested (pnum, pden)
                // is this sell's OWN price pair — for an OCO term that is the
                // EXECUTING branch's pair (the scanner books each OCO path as
                // its own order carrying that branch's price), which is what
                // the OCO v18 body verifies and what unlocked OCO sweep
                // eligibility on both branches.
                if let Some(oco_path) = sell.oco_path {
                    match oco_path {
                        kob_core::OcoPath::TakeProfit => build_oco_sell_v18_tp_fill_sigscript(
                            koi as u16, sell.price_num, sell.price_den, &sell.redeem_script,
                        ),
                        kob_core::OcoPath::StopLoss => build_oco_sell_v18_sl_fill_sigscript(
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
                    // `BatchError::V18SellResidualUnsupported`.
                    let fta = self.sell_fill_amounts.get(i).copied().unwrap_or(sell.amount);
                    build_sell_v18_ioc_fill_sigscript(
                        koi as u16, sell.price_num, sell.price_den, fta, &sell.redeem_script,
                    )
                } else {
                    build_sell_v18_fill_sigscript(
                        koi as u16, sell.price_num, sell.price_den, &sell.redeem_script,
                    )
                }
            } else if let Some(oco_path) = sell.oco_path {
                if has_remainder {
                    // OCO sell with remainder: use IOC fill (Op5 + fta) instead
                    // of TP/SL full-fill path to avoid F4 value check failure.
                    let fta = self.sell_fill_amounts.get(i).copied().unwrap_or(sell.amount);
                    if has_fixed_offset_buy {
                        build_sell_ioc_fill_sigscript_fixed_offset(koi as u16, fta, &sell.redeem_script)
                    } else {
                        build_sell_ioc_fill_sigscript(koi as u16, fta, &sell.redeem_script)
                    }
                } else {
                    // OCO sell fully filled: use TP (Op1) or SL (Op2) path
                    // selector. MED #4: gate on has_fixed_offset_buy, same as
                    // the sibling sell branches -- a v16/v17 buy in this tx
                    // reads this sell's pnum/pden at fixed sigscript offsets,
                    // which only line up with the 2-byte koi push.
                    match (oco_path, has_fixed_offset_buy) {
                        (kob_core::OcoPath::TakeProfit, true) => {
                            build_oco_sell_tp_fill_sigscript_fixed_offset(koi as u16, &sell.redeem_script)
                        }
                        (kob_core::OcoPath::TakeProfit, false) => {
                            build_oco_sell_tp_fill_sigscript(koi as u16, &sell.redeem_script)
                        }
                        (kob_core::OcoPath::StopLoss, true) => {
                            build_oco_sell_sl_fill_sigscript_fixed_offset(koi as u16, &sell.redeem_script)
                        }
                        (kob_core::OcoPath::StopLoss, false) => {
                            build_oco_sell_sl_fill_sigscript(koi as u16, &sell.redeem_script)
                        }
                    }
                }
            } else if (self.ioc_mode == Some(IocSide::Sell) || has_remainder) && !self.sell_fill_amounts.is_empty() {
                // Sell IOC or sell with remainder: use fta-based sigscript
                let fta = self.sell_fill_amounts.get(i).copied().unwrap_or(sell.amount);
                if has_fixed_offset_buy {
                    build_sell_ioc_fill_sigscript_fixed_offset(koi as u16, fta, &sell.redeem_script)
                } else {
                    build_sell_ioc_fill_sigscript(koi as u16, fta, &sell.redeem_script)
                }
            } else if has_fixed_offset_buy {
                build_sell_fill_sigscript_fixed_offset(koi as u16, &sell.redeem_script)
            } else {
                build_sell_fill_sigscript(koi as u16, &sell.redeem_script)
            };
            inputs.push(BatchTxInput {
                tx_id: sell.outpoint.0.clone(),
                index: sell.outpoint.1,
                sigscript: ss,
                sig_op_count: 0,
            });
        }

        // === Build buy inputs ===
        // Track covenant output count per token_cov_id for coi computation
        let mut cov_out_counter: HashMap<String, u16> = HashMap::new();
        for (buy_idx, (buy, _input_idx)) in self.buys.iter().enumerate() {
            let token_hex = hex::encode(buy.token_cov_id);
            let tii = self.token_input_map.get(&token_hex)
                .ok_or_else(|| BatchError::MissingTokenUnit {
                    token_cov_id: token_hex.clone(),
                })?;

            // Buy's output index = N + j where j is position in buys vec
            // (or merged buy_output_idx[buy_idx] if populated).
            let toi = if !self.buy_output_idx.is_empty() {
                self.buy_output_idx[buy_idx]
            } else {
                self.sells.len() + buy_idx
            };

            // coi = index of this buy's output among all covenant outputs for this token.
            // When buy_coi is populated (merged path), use the precomputed value;
            // otherwise count covenant outputs sequentially per token.
            let coi = if !self.buy_coi.is_empty() {
                self.buy_coi[buy_idx]
            } else {
                let c = *cov_out_counter.get(&token_hex).unwrap_or(&0);
                *cov_out_counter.entry(token_hex).or_insert(0) += 1;
                c
            };

            // Indices >16 are handled by data-push encoding (no OpN limit).
            //
            // NOTE on `is_bracket`: this MUST be keyed off RS length, not the
            // bare `buy.version` number. Bracket entries and v16 buy orders
            // (this file's F6-fix contract) both report `version == 16` --
            // that number is an engine-layer convenience label, not a unique
            // contract identifier (see V16_STATUS.md Phase 0, "version number
            // 16 is already taken"). RS length is the only thing that
            // actually distinguishes them, and it already does everywhere
            // else in this codebase (`is_v16` below uses the same pattern).
            let is_v16 = buy.redeem_script.len() == BUY_ORDER_V16_RS_EXPECTED_LEN;
            let is_bracket = buy.redeem_script.len() == BRACKET_RS_SIZE;

            // v17 N:M sweep: the buy's sell-input list is in buy_sweep_sells.
            // The sigscript lists those sell inputs; the contract derives each
            // token output via OpAuthOutputIdx (no toi/coi needed here).
            let v17_sells = self.buy_sweep_sells.get(buy_idx).filter(|v| !v.is_empty());

            // v18 buys are ALWAYS spent via the tii-list sigscript forms
            // (fill/IOC/partial); the v18 planners populate buy_sweep_sells
            // for them, so a v18 buy without a sweep list is a planner bug.
            let is_v18 = buy.redeem_script.len() == BUY_ORDER_V18_RS_EXPECTED_LEN;

            let ss = if is_v18 {
                let sell_indices = match v17_sells {
                    Some(s) => s,
                    None => {
                        return Err(BatchError::UnsupportedVersion {
                            outpoint: format!("{}:{}", buy.outpoint.0, buy.outpoint.1),
                            version: 18,
                        });
                    }
                };
                if let Some(&(_spent, residual_idx, _)) = self.buy_partial_fills.get(&buy_idx) {
                    // Op2 partial: [tii_1..tii_MAX_N][N][ri][Op2][RS]. The
                    // second tuple field carries the residual OUTPUT index
                    // (v14/v16 partials use the same slot for their ri).
                    build_buy_v18_partial_fill_sigscript(
                        sell_indices, residual_idx, &buy.redeem_script,
                    )
                } else {
                    let ioc = self.ioc_mode == Some(IocSide::Buy);
                    build_buy_v18_fill_sigscript(sell_indices, ioc, &buy.redeem_script)
                }
            } else if let Some(sell_indices) = v17_sells {
                let ioc = self.ioc_mode == Some(IocSide::Buy);
                build_buy_v17_fill_sigscript(sell_indices, ioc, &buy.redeem_script)
            } else if is_bracket {
                // Bracket entry: sigscript = [Op1][pushData(RS)] (365B RS).
                // No toi/tii/coi — bracket contract uses hardcoded output indices
                // (output[1] for buy entry token dest, output[0] for sell entry KAS dest).
                build_bracket_fill_sigscript(&buy.redeem_script)
            } else if let Some(&(fill_kas, residual_idx, token_idx)) = self.buy_partial_fills.get(&buy_idx) {
                // Partial fill (Op2 selector): buy D&R with residual continuation.
                if is_v16 {
                    // V16: [ri] [ti] [pushData(fk 8B)] [Op2] [pushData(RS)]
                    // No sii (Phase-0 fix): F6 authenticates against the
                    // hardcoded literal token-input index (see order.rs).
                    build_buy_v16_partial_fill_sigscript(
                        &buy.redeem_script,
                        fill_kas,
                        residual_idx,
                        token_idx,
                    )
                } else {
                    // V14: [ri] [ti] [pushData(fk 8B)] [Op2] [pushData(RS)]
                    kob_core::build_buy_partial_fill_sigscript(
                        &buy.redeem_script,
                        fill_kas,
                        residual_idx,
                        token_idx,
                    )
                }
            } else if self.ioc_mode == Some(IocSide::Buy) {
                if is_v16 {
                    // V16 buy IOC: [toi] [tii] [coi] [Op5] [pushData(RS)]
                    // No sii: F6 reads tii directly (already authenticated).
                    build_buy_v16_ioc_fill_sigscript(
                        toi as u16,
                        *tii as u16,
                        coi,
                        &buy.redeem_script,
                    )
                } else {
                    // V14 buy IOC: use Op5 selector
                    build_buy_ioc_fill_sigscript(
                        toi as u16,
                        *tii as u16,
                        coi,
                        &buy.redeem_script,
                    )
                }
            } else if is_v16 {
                // V16 buy fill: [toi] [tii] [coi] [Op1] [pushData(RS)]
                // No sii (Phase-0 fix): F6 reads tii directly instead of a
                // free, unauthenticated sigscript index.
                build_buy_v16_fill_sigscript(
                    toi as u16,
                    *tii as u16,
                    coi,
                    &buy.redeem_script,
                )
            } else {
                build_buy_fill_sigscript(
                    toi as u16,
                    *tii as u16,
                    coi,
                    &buy.redeem_script,
                )
            };
            inputs.push(BatchTxInput {
                tx_id: buy.outpoint.0.clone(),
                index: buy.outpoint.1,
                sigscript: ss,
                sig_op_count: 0,
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
                sig_op_count: 0,
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

/// Build a batch plan from a set of matchable orders.
///
/// Sell inputs provide covenant lineage for buyer token outputs directly.
/// Each buy's `tii` sigscript parameter is set to the index of a sell input
/// with matching `token_cov_id`.
///
/// # Arguments
/// * `sells` - Sell orders to include.
/// * `buys` - Buy orders to include.
/// * `wallet_utxo` - Optional wallet UTXO for fee payment (txid, index, value).
/// * `matcher_spk` - Matcher's scriptPublicKey bytes for receiving KAS outputs.
/// * `matcher_spk_version` - SPK version.
/// * `fee_bps` - Optional matcher fee cap in basis points (e.g. 50 = 0.5%).
///   When set, matcher surplus is capped at `(total_trade_value * fee_bps) / 10000`.
///   Excess surplus is returned to buyers as change outputs pro-rata.
///   `None` means no cap (matcher takes all surplus).
///
/// # Returns
/// A `BatchPlan` with all indices assigned and outputs computed.
pub fn plan_batch_match(
    sells: &[BatchOrder],
    buys: &[BatchOrder],
    wallet_utxo: Option<(String, u32, u64)>,
    matcher_spk: &[u8],
    matcher_spk_version: u16,
    fee_bps: Option<u16>,
) -> Result<BatchPlan, BatchError> {
    if sells.is_empty() {
        return Err(BatchError::NoSellOrders);
    }
    if buys.is_empty() {
        return Err(BatchError::NoBuyOrders);
    }

    // Reject duplicate outpoints (would cause double-spend rejection on-chain)
    {
        let mut seen = HashSet::new();
        for sell in sells {
            let key = format!("{}:{}", sell.outpoint.0, sell.outpoint.1);
            if !seen.insert(key.clone()) {
                return Err(BatchError::DuplicateOutpoint(key));
            }
        }
        for buy in buys {
            let key = format!("{}:{}", buy.outpoint.0, buy.outpoint.1);
            if !seen.insert(key.clone()) {
                return Err(BatchError::DuplicateOutpoint(key));
            }
        }
    }

    // v18 (unified spot) is handled by its own planner: ONE v18 buy sweeping
    // up to BUY_ORDER_V18_MAX_N v18 sells — plain and/or OCO; v18 OCO sells
    // are sweep-eligible on BOTH branches thanks to the canonical branch
    // attestation. Dispatch BEFORE the v14 sell-version gate and the pre-v18
    // OCO exclusion below, which do not apply to v18.
    if buys.iter().any(|b| b.version == 18) || sells.iter().any(|s| s.version == 18) {
        return plan_batch_match_v18(
            sells, buys, wallet_utxo, matcher_spk, matcher_spk_version, fee_bps,
        );
    }

    // Validate order versions (v14 for buys/sells, v16 for buy (F6-fix) or bracket entry)
    for sell in sells {
        if sell.version != 14 {
            return Err(BatchError::UnsupportedVersion {
                outpoint: format!("{}:{}", sell.outpoint.0, sell.outpoint.1),
                version: sell.version,
            });
        }
    }
    // RELEASE-BLOCKER #1 (pre-v18 generations only; v18 dispatched above):
    // exclude OCO sells from any multi-sell composition.
    // See BatchError::OcoMultiSellSweepUnsupported for the fund-drain this
    // guards against. A solo OCO sell (sells.len() == 1) is unaffected.
    if sells.len() > 1 {
        for sell in sells {
            if sell.oco_path.is_some() {
                return Err(BatchError::OcoMultiSellSweepUnsupported {
                    outpoint: format!("{}:{}", sell.outpoint.0, sell.outpoint.1),
                });
            }
        }
    }
    for buy in buys {
        if buy.version != 14 && buy.version != 16 && buy.version != 17 {
            return Err(BatchError::UnsupportedVersion {
                outpoint: format!("{}:{}", buy.outpoint.0, buy.outpoint.1),
                version: buy.version,
            });
        }
    }

    // v17 (N:M sweep) is handled by a dedicated, isolated planner so the
    // v14/v16 merge path below is untouched. A v17 buy delivers one token
    // output PER SELL (each bound to its own sell input, per-input F4), summed
    // and surplus-capped by the buy contract. Batches mixing v17 with other
    // buy versions are not supported (the matcher groups by contract kind).
    let any_v17 = buys.iter().any(|b| b.version == 17);
    if any_v17 {
        if !buys.iter().all(|b| b.version == 17) {
            return Err(BatchError::UnsupportedVersion {
                outpoint: "mixed-v17-batch".into(),
                version: 17,
            });
        }
        return plan_batch_match_v17(
            sells, buys, wallet_utxo, matcher_spk, matcher_spk_version, fee_bps,
        );
    }

    let n = sells.len();
    let _m = buys.len();

    // Build token_input_map: token_cov_id (hex) -> sell input index.
    // Sell inputs carry covenant_id, providing covenant lineage for buyer
    // token outputs.  Each buy's tii points to a sell with matching token.
    let token_input_map = build_token_input_map(
        &sells.iter().map(|s| s.token_cov_id).collect::<Vec<_>>(),
    );

    // Verify every buy's token has a matching sell
    for buy in buys {
        let token_hex = hex::encode(buy.token_cov_id);
        if !token_input_map.contains_key(&token_hex) {
            return Err(BatchError::MissingTokenUnit {
                token_cov_id: token_hex,
            });
        }
    }

    // Assign sell orders to input[0..N-1]
    let plan_sells: Vec<(BatchOrder, usize)> = sells.iter()
        .enumerate()
        .map(|(i, s)| (s.clone(), i))
        .collect();

    // Assign buy orders to input[N..N+M-1]
    let plan_buys: Vec<(BatchOrder, usize)> = buys.iter()
        .enumerate()
        .map(|(j, b)| (b.clone(), n + j))
        .collect();

    // Compute output amounts
    //
    // For each sell[i]:
    //   expected_kas = (sell.amount * sell.price_num) / sell.price_den
    //   output[i] = expected_kas (KAS to seller)
    //
    // For each buy[j]:
    //   expected_tokens = (buy.amount * buy.price_num) / buy.price_den
    //   output[N+j] = expected_tokens (tokens to buyer)
    let mut outputs: Vec<PlannedOutput> = Vec::new();

    // Seller KAS outputs — MERGED by (spk, spk_version) to reduce storage mass.
    // Each merged output sums all sell KAS for the same counterparty.
    // Covenant safety: order.rs:326 OpSwap OpGTE OpVerify checks
    // output[koi].value >= expected_kas (GTE), and order.rs:330 SPK hash check
    // is bytewise == — but all merged sells share the same counterparty_spk so
    // the same hash holds.  See task brief.
    let mut total_seller_kas: u64 = 0;
    // (spk_bytes, spk_version) -> outputs index
    let mut seller_group_idx: HashMap<(Vec<u8>, u16), usize> = HashMap::new();
    let mut sell_output_idx: Vec<usize> = Vec::with_capacity(sells.len());
    let mut sell_expected_kas: Vec<u64> = Vec::with_capacity(sells.len());
    for (i, sell) in sells.iter().enumerate() {
        if sell.price_den == 0 {
            return Err(BatchError::ZeroPriceDenominator { index: i, side: "sell" });
        }
        let expected_kas_128 = sell.amount as u128 * sell.price_num as u128
            / sell.price_den as u128;
        if expected_kas_128 > u64::MAX as u128 {
            return Err(BatchError::Overflow {
                index: i,
                side: "sell",
                detail: "u128 to u64 truncation in expected_kas",
            });
        }
        let expected_kas = expected_kas_128 as u64;
        if expected_kas < MIN_UTXO_VALUE {
            return Err(BatchError::OutputBelowMinimum {
                index: i,
                value: expected_kas,
            });
        }
        // Min-fill guard: sell contract Op1 path checks expected_kas >= mfill.
        if expected_kas < sell.min_fill {
            return Err(BatchError::MinFillViolation {
                index: i,
                fill_kas: expected_kas,
                min_fill: sell.min_fill,
            });
        }
        total_seller_kas += expected_kas;
        sell_expected_kas.push(expected_kas);

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

    // Buyer token outputs — MERGED by (token_cov_id, spk, spk_version).
    // Covenant safety: order.rs:337 F4 token conservation is also GTE, so
    // summing buyer token outputs that share the same covenant + counterparty
    // satisfies the per-buy >= constraint.
    //
    // coi assignment: per token_cov_id, in order of first appearance among
    // merged outputs.  Buys sharing the same merged output share the same coi.
    let mut total_buyer_tokens_by_cov: HashMap<String, u64> = HashMap::new();
    // (token_cov_id_hex, spk_bytes, spk_version) -> outputs index
    let mut buyer_group_idx: HashMap<(String, Vec<u8>, u16), usize> = HashMap::new();
    // token_cov_id_hex -> next coi to assign
    let mut next_coi_per_token: HashMap<String, u16> = HashMap::new();
    // outputs idx -> coi (so buys merging into same group reuse the coi)
    let mut output_idx_to_coi: HashMap<usize, u16> = HashMap::new();
    let mut buy_output_idx: Vec<usize> = Vec::with_capacity(buys.len());
    let mut buy_coi: Vec<u16> = Vec::with_capacity(buys.len());
    for (j, buy) in buys.iter().enumerate() {
        if buy.price_den == 0 {
            return Err(BatchError::ZeroPriceDenominator { index: n + j, side: "buy" });
        }
        let expected_tokens_128 = buy.amount as u128 * buy.price_num as u128
            / buy.price_den as u128;
        if expected_tokens_128 > u64::MAX as u128 {
            return Err(BatchError::Overflow {
                index: n + j,
                side: "buy",
                detail: "u128 to u64 truncation in expected_tokens",
            });
        }
        let expected_tokens = expected_tokens_128 as u64;
        if expected_tokens < MIN_UTXO_VALUE {
            return Err(BatchError::OutputBelowMinimum {
                index: n + j,
                value: expected_tokens,
            });
        }
        let token_hex = hex::encode(buy.token_cov_id);
        *total_buyer_tokens_by_cov.entry(token_hex.clone()).or_insert(0) += expected_tokens;

        let key = (token_hex.clone(), buy.counterparty_spk.clone(), buy.counterparty_spk_version);
        if let Some(&existing) = buyer_group_idx.get(&key) {
            outputs[existing].value += expected_tokens;
            buy_output_idx.push(existing);
            buy_coi.push(*output_idx_to_coi.get(&existing).expect("coi tracked for existing group"));
        } else {
            let new_idx = outputs.len();
            outputs.push(PlannedOutput {
                value: expected_tokens,
                script_public_key: buy.counterparty_spk.clone(),
                spk_version: buy.counterparty_spk_version,
                purpose: OutputPurpose::BuyerTokens,
            });
            buyer_group_idx.insert(key, new_idx);
            // Assign next coi for this token covenant
            let coi = *next_coi_per_token.entry(token_hex.clone()).or_insert(0);
            *next_coi_per_token.entry(token_hex).or_insert(0) += 1;
            output_idx_to_coi.insert(new_idx, coi);
            buy_output_idx.push(new_idx);
            buy_coi.push(coi);
        }
    }

    // Compute KAS surplus
    //
    // Inputs: sell + buy + wallet.  Outputs: seller_kas + buyer_tokens + matcher_fee.
    // Sell input values flow to buyer token outputs (covenant conservation).
    // Buy input values flow to seller KAS outputs.
    // Surplus = buy_kas - seller_kas - fee (price spread profit).
    let total_sell_value: u64 = sells.iter().map(|s| s.utxo_value).sum();
    let total_buy_kas: u64 = buys.iter().map(|b| b.utxo_value).sum();
    let wallet_value = wallet_utxo.as_ref().map_or(0, |w| w.2);
    let total_kas_in = total_sell_value + total_buy_kas + wallet_value;

    let total_buyer_tokens: u64 = total_buyer_tokens_by_cov.values().sum();
    let total_planned_out: u64 = total_seller_kas + total_buyer_tokens;

    // Estimate miner fee. Post-Toccata the network requires
    // `mass * MIN_RELAY_FEE_PER_GRAM` (100 sompi/gram); the exact fee at
    // convergence uses the same rate, keeping `delta = est - exact >= 0`.
    let num_inputs = buys.len() + sells.len()
        + if wallet_utxo.is_some() { 1 } else { 0 };
    // +1 for matcher fee, +1 for potential sell remainder
    let num_outputs = sells.len() + buys.len() + 2;
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

    // Sell remainder: if sell input value > buyer token output value for a
    // covenant, the excess sell value needs a non-covenant output.
    // Compute per-sell fill amounts: fills are assigned in order within each
    // covenant.  The last sell for a covenant absorbs any partial remainder.
    let sell_excess = total_sell_value.saturating_sub(total_buyer_tokens);
    let per_sell_fill: Vec<u64> = {
        // Track remaining buyer demand per covenant
        let mut remaining_by_cov: HashMap<String, u64> = total_buyer_tokens_by_cov.clone();
        sells.iter().map(|sell| {
            let token_hex = hex::encode(sell.token_cov_id);
            let remaining = remaining_by_cov.get(&token_hex).copied().unwrap_or(0);
            let fill = remaining.min(sell.utxo_value);
            *remaining_by_cov.entry(token_hex).or_insert(0) = remaining.saturating_sub(fill);
            fill
        }).collect()
    };
    // IOC min_fill pre-check: when a sell is partially consumed (has remainder),
    // the IOC fill path computes fill_kas = fta * pnum / pden and checks
    // fill_kas >= min_fill.  Reject here to avoid submitting a TX that will fail.
    if sell_excess > 0 {
        for (i, sell) in sells.iter().enumerate() {
            let fta = per_sell_fill[i];
            if fta < sell.utxo_value && fta > 0 && sell.price_den > 0 {
                // Bug-A guard: OCO v1 covenant has no IOC (selector=5) path.
                // If this OCO sell has a remainder, the resulting sigscript
                // would be `[koi][fta][Op5][RS]`, and OCO's dispatch would
                // route sel=5 into the SL-branch's `Op2 OpEqual OpVerify`
                // which fails on-chain. Reject before submit. See
                // core/src/contract/spot/oco.rs OCO_SELL_BODY.
                if sell.oco_path.is_some() {
                    return Err(BatchError::OcoRemainderUnsupported {
                        outpoint: format!("{}:{}", sell.outpoint.0, sell.outpoint.1),
                        utxo_value: sell.utxo_value,
                        filled_tokens: fta,
                    });
                }

                let fill_kas = fta as u128 * sell.price_num as u128 / sell.price_den as u128;
                if (fill_kas as u64) < sell.min_fill {
                    return Err(BatchError::MinFillViolation {
                        index: i,
                        fill_kas: fill_kas as u64,
                        min_fill: sell.min_fill,
                    });
                }
            }
        }
    }
    if sell_excess > 0 {
        // Merge SellRemainder outputs by (spk, spk_version) too.
        let mut remainder_group_idx: HashMap<(Vec<u8>, u16), usize> = HashMap::new();
        for (i, sell) in sells.iter().enumerate() {
            let this_excess = sell.utxo_value.saturating_sub(per_sell_fill[i]);
            if this_excess >= MIN_UTXO_VALUE {
                let key = (sell.counterparty_spk.clone(), sell.counterparty_spk_version);
                if let Some(&existing) = remainder_group_idx.get(&key) {
                    outputs[existing].value += this_excess;
                } else {
                    let new_idx = outputs.len();
                    outputs.push(PlannedOutput {
                        value: this_excess,
                        script_public_key: sell.counterparty_spk.clone(),
                        spk_version: sell.counterparty_spk_version,
                        purpose: OutputPurpose::SellRemainder,
                    });
                    remainder_group_idx.insert(key, new_idx);
                }
            }
        }
    }

    // Matcher KAS surplus = raw_surplus minus sell excess
    let matcher_kas = raw_surplus.saturating_sub(sell_excess);

    // Apply bps cap: matcher fee <= (total_trade_value * fee_bps) / 10000
    // total_trade_value = sum of KAS flowing to sellers (the traded volume)
    let (capped_matcher_kas, buyer_refund) = apply_bps_cap(matcher_kas, total_seller_kas, fee_bps);

    // Refund excess surplus to buyers pro-rata by KAS input
    if buyer_refund > 0 {
        let buy_refs: Vec<&BatchOrder> = buys.iter().collect();
        distribute_buyer_refund(&mut outputs, buyer_refund, &buy_refs, total_buy_kas, n, Some(&buy_output_idx));
    }

    let (matcher_surplus, dropped_to_fee) = emit_matcher_fee(&mut outputs, capped_matcher_kas, matcher_spk, matcher_spk_version);
    // A dust matcher surplus is dropped to the miner fee; keep the plan's
    // amount check balanced (inputs == outputs + total_fee).
    total_fee += dropped_to_fee;

    // Build buy-to-sell mapping for soi (round-robin across matching sells)
    let mut buy_seller_map: HashMap<usize, usize> = HashMap::new();
    let mut sell_usage_count: HashMap<usize, usize> = HashMap::new();
    for (j, buy) in buys.iter().enumerate() {
        // Find sells matching this buy's token, pick the least-used one
        let matching_sells: Vec<usize> = sells.iter()
            .enumerate()
            .filter(|(_, s)| s.token_cov_id == buy.token_cov_id)
            .map(|(i, _)| i)
            .collect();

        let seller_idx = if matching_sells.is_empty() {
            0 // fallback
        } else {
            // Pick the sell with lowest usage count
            *matching_sells.iter()
                .min_by_key(|&&idx| sell_usage_count.get(&idx).unwrap_or(&0))
                .unwrap()
        };

        *sell_usage_count.entry(seller_idx).or_insert(0) += 1;
        buy_seller_map.insert(n + j, seller_idx);
    }

    // Always store per-sell fill amounts so build_tx() can detect partial
    // fills per-sell via has_remainder (fill < utxo_value).
    // When sell_excess > 0, also switch to IOC sell mode globally.
    let ioc_mode = if sell_excess > 0 {
        Some(IocSide::Sell)
    } else {
        None
    };
    let sell_fill_amounts = per_sell_fill.clone();

    Ok(BatchPlan {
        sells: plan_sells,
        buys: plan_buys,
        wallet_input: wallet_utxo,
        outputs,
        total_fee,
        matcher_surplus,
        token_input_map,
        buy_seller_map,
        fee_bps,
        total_seller_kas,
        ioc_mode,
        sell_fill_amounts,
        buy_partial_fills: HashMap::new(),
        sell_output_idx,
        buy_output_idx,
        buy_coi,
        bracket_receipt: None,
        bracket_oco_output: None,
        buy_sweep_sells: Vec::new(),
        output_auth_input: std::collections::HashMap::new(),
    })
}

/// v17 N:M sweep planner: 1 v17 buy consumes N (fully-filled) sells of the same
/// token, in ONE tx. Each sell delivers its full token amount to a SEPARATE
/// BuyerTokens output bound to that sell input (per-input F4), and the v17 buy
/// contract SUMS those outputs to enforce its aggregate limit-price floor and
/// surplus cap. This is the settleable form of the N-sells:1-buy sweep that the
/// merged (v14/v16) path cannot express.
///
/// Layout:
///   inputs:  [sell_0 .. sell_{N-1}, buy, (wallet?)]
///   outputs: [SellerKas.. (merged by spk), BuyerTokens_0 .. BuyerTokens_{N-1}
///            (one per sell, auth'd to sell i), MatcherFee?]
///
/// Scope: exactly one v17 buy; all sells fully filled and same token as the buy.
fn plan_batch_match_v17(
    sells: &[BatchOrder],
    buys: &[BatchOrder],
    wallet_utxo: Option<(String, u32, u64)>,
    matcher_spk: &[u8],
    matcher_spk_version: u16,
    fee_bps: Option<u16>,
) -> Result<BatchPlan, BatchError> {
    if buys.len() != 1 {
        // Multiple v17 buys in one tx (allocation across buys) is a follow-on.
        return Err(BatchError::UnsupportedVersion {
            outpoint: "v17-multi-buy".into(),
            version: 17,
        });
    }
    let buy = &buys[0];
    let n = sells.len();

    // HIGH DoS #3: the v17 contract has exactly BUY_ORDER_V17_MAX_N term
    // slots; build_buy_v17_fill_sigscript `assert!`s on this and PANICS if
    // handed more. Reject gracefully here, well before that call, so a
    // crossing book with more sells than the contract can express never
    // reaches the panic.
    if n > BUY_ORDER_V17_MAX_N {
        return Err(BatchError::V17TooManySells { count: n, max: BUY_ORDER_V17_MAX_N });
    }

    // RELEASE-BLOCKER #1: exclude OCO sells from a multi-sell v17 sweep (see
    // BatchError::OcoMultiSellSweepUnsupported). Checked here too (not just
    // in plan_batch_match's dispatch gate) so the invariant holds for any
    // future direct caller of this planner.
    if n > 1 {
        for s in sells {
            if s.oco_path.is_some() {
                return Err(BatchError::OcoMultiSellSweepUnsupported {
                    outpoint: format!("{}:{}", s.outpoint.0, s.outpoint.1),
                });
            }
        }
    }

    // All sells must be the same token as the buy (same-token sweep).
    for (i, s) in sells.iter().enumerate() {
        if s.version != 14 {
            return Err(BatchError::UnsupportedVersion {
                outpoint: format!("{}:{}", s.outpoint.0, s.outpoint.1),
                version: s.version,
            });
        }
        if s.token_cov_id != buy.token_cov_id {
            return Err(BatchError::MissingTokenUnit { token_cov_id: hex::encode(s.token_cov_id) });
        }
        if s.price_den == 0 {
            return Err(BatchError::ZeroPriceDenominator { index: i, side: "sell" });
        }
    }
    if buy.price_den == 0 {
        return Err(BatchError::ZeroPriceDenominator { index: n, side: "buy" });
    }

    let token_input_map = build_token_input_map(
        &sells.iter().map(|s| s.token_cov_id).collect::<Vec<_>>(),
    );

    let plan_sells: Vec<(BatchOrder, usize)> =
        sells.iter().enumerate().map(|(i, s)| (s.clone(), i)).collect();
    let plan_buys: Vec<(BatchOrder, usize)> = vec![(buy.clone(), n)];

    let mut outputs: Vec<PlannedOutput> = Vec::new();

    // SellerKas per sell, merged by (spk, version).
    let mut total_seller_kas: u64 = 0;
    let mut seller_group_idx: HashMap<(Vec<u8>, u16), usize> = HashMap::new();
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
        let key = (sell.counterparty_spk.clone(), sell.counterparty_spk_version);
        if let Some(&existing) = seller_group_idx.get(&key) {
            outputs[existing].value += expected_kas;
        } else {
            let new_idx = outputs.len();
            outputs.push(PlannedOutput {
                value: expected_kas,
                script_public_key: sell.counterparty_spk.clone(),
                spk_version: sell.counterparty_spk_version,
                purpose: OutputPurpose::SellerKas,
            });
            seller_group_idx.insert(key, new_idx);
        }
    }

    // BuyerTokens per sell (NOT merged) — each authorized by its own sell input.
    let mut total_buyer_tokens: u64 = 0;
    let mut output_auth_input: std::collections::HashMap<usize, u16> = std::collections::HashMap::new();
    for (i, sell) in sells.iter().enumerate() {
        let tokens = sell.amount; // full fill: this sell delivers its whole balance
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

    // Aggregate limit-price floor (contract enforces on-chain; reject early to
    // avoid submitting a tx the buy covenant will abort): the buyer must receive
    // at least kas_in/buy_price tokens.
    let expected_tokens = buy.utxo_value as u128 * buy.price_num as u128 / buy.price_den as u128;
    if (total_buyer_tokens as u128) < expected_tokens {
        return Err(BatchError::MinFillViolation {
            index: n,
            fill_kas: total_buyer_tokens,
            min_fill: expected_tokens.min(u64::MAX as u128) as u64,
        });
    }

    // KAS accounting (tokens are sompi-valued; buyer-token outflow is matched by
    // the sell token inflow, so they cancel in the surplus, same as the general
    // planner). Surplus = buy KAS + wallet - seller KAS - fee.
    let total_sell_value: u64 = sells.iter().map(|s| s.utxo_value).sum();
    let total_buy_kas: u64 = buy.utxo_value;
    let wallet_value = wallet_utxo.as_ref().map_or(0, |w| w.2);
    let total_kas_in = total_sell_value + total_buy_kas + wallet_value;
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
    // Any surplus beyond the matcher's bps cap is left to the miner fee (only
    // reduces the matcher take; the buy covenant's own cap is on the intrinsic
    // kas_in - fair spread, unaffected by where surplus KAS lands).
    total_fee += raw_surplus.saturating_sub(matcher_surplus + dropped_to_fee);

    let buy_seller_map: HashMap<usize, usize> = HashMap::new();
    let sell_indices: Vec<u16> = (0..n as u16).collect();

    Ok(BatchPlan {
        sells: plan_sells,
        buys: plan_buys,
        wallet_input: wallet_utxo,
        outputs,
        total_fee,
        matcher_surplus,
        token_input_map,
        buy_seller_map,
        fee_bps,
        total_seller_kas,
        ioc_mode: None,
        sell_fill_amounts: Vec::new(),
        buy_partial_fills: HashMap::new(),
        sell_output_idx: Vec::new(),
        buy_output_idx: Vec::new(),
        buy_coi: Vec::new(),
        bracket_receipt: None,
        bracket_oco_output: None,
        buy_sweep_sells: vec![sell_indices],
        output_auth_input,
    })
}

/// IOC (Immediate-Or-Cancel) batch match: one buy sweeps multiple sells.
///
/// Sells are consumed in order (caller should pre-sort by price, best first).
/// The buy provides KAS; sells provide tokens. The buy sweeps sells until
/// its KAS is exhausted or all sells are filled.
///
/// Unlike `plan_batch_match` (which assumes pre-matched full-fill pairs),
/// this function computes how many sells the buy can afford and returns
/// change to the buyer for any unspent KAS.
///
/// # Arguments
/// * `sells` - Sell orders sorted by price (best first).
/// * `buy` - The single IOC buy order.
/// * `wallet_utxo` - Optional wallet UTXO for miner fee.
/// * `matcher_spk` / `matcher_spk_version` - Matcher's SPK for fee output.
/// * `fee_bps` - Optional bps cap on matcher fee.
///
/// # Returns
/// A `BatchPlan` containing only the sells that were filled (full fill).
/// Buyer change output is added if buy KAS exceeds what was needed.
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

    // Sweep sells with the buy's KAS
    let buy_kas = buy.utxo_value;
    let mut filled_sells: Vec<&BatchOrder> = Vec::new();
    let mut kas_remaining = buy_kas;

    for sell in sells {
        if sell.price_den == 0 {
            continue; // skip broken orders
        }
        // Min-fill guard: sell contract Op1 checks expected_kas >= mfill.
        let sell_kas_128 = sell.amount as u128 * sell.price_num as u128
            / sell.price_den as u128;
        if sell_kas_128 > u64::MAX as u128 {
            continue; // overflow, skip
        }
        let sell_kas = sell_kas_128 as u64;
        if sell_kas < MIN_UTXO_VALUE {
            continue; // too small
        }
        if sell_kas < sell.min_fill {
            continue; // unmatchable: on-chain F1 check would fail
        }

        if kas_remaining >= sell_kas {
            // Full fill this sell
            filled_sells.push(sell);
            kas_remaining -= sell_kas;
        } else {
            // Can't afford this sell — stop (IOC: no partial fill for now)
            break;
        }
    }

    if filled_sells.is_empty() {
        return Err(BatchError::MinFillViolation {
            index: 0,
            fill_kas: 0,
            min_fill: sells.first().map_or(0, |s| s.min_fill),
        });
    }

    // Compute totals from the filtered filled_sells
    let mut total_seller_kas: u64 = 0;
    let mut total_tokens_bought: u64 = 0;
    for sell in &filled_sells {
        let sell_kas = (sell.amount as u128 * sell.price_num as u128
            / sell.price_den as u128) as u64;
        total_seller_kas += sell_kas;
        total_tokens_bought += sell.amount;
    }

    let n = filled_sells.len();

    // Build token_input_map: sell provides covenant lineage
    let token_input_map = build_token_input_map(
        &filled_sells.iter().map(|s| s.token_cov_id).collect::<Vec<_>>(),
    );

    // Input layout: [sell_0..sell_{n-1}] [buy] [wallet?]
    let plan_sells: Vec<(BatchOrder, usize)> = filled_sells.iter()
        .enumerate()
        .map(|(i, s)| ((*s).clone(), i))
        .collect();
    let buy_input_idx = n;
    let plan_buys: Vec<(BatchOrder, usize)> = vec![(buy.clone(), buy_input_idx)];

    // Build outputs
    let mut outputs: Vec<PlannedOutput> = Vec::new();

    // Seller KAS outputs
    for sell in &filled_sells {
        let sell_kas_128 = sell.amount as u128 * sell.price_num as u128
            / sell.price_den as u128;
        let sell_kas = sell_kas_128 as u64;
        outputs.push(PlannedOutput {
            value: sell_kas,
            script_public_key: sell.counterparty_spk.clone(),
            spk_version: sell.counterparty_spk_version,
            purpose: OutputPurpose::SellerKas,
        });
    }

    // Buyer token output (all tokens from filled sells)
    if total_tokens_bought >= MIN_UTXO_VALUE {
        outputs.push(PlannedOutput {
            value: total_tokens_bought,
            script_public_key: buy.counterparty_spk.clone(),
            spk_version: buy.counterparty_spk_version,
            purpose: OutputPurpose::BuyerTokens,
        });
    }

    // Estimate miner fee (post-Toccata min relay rate; see the 1:1 path above).
    let num_inputs = n + 1 + if wallet_utxo.is_some() { 1 } else { 0 };
    let num_outputs = n + 3; // sellers + buyer_tokens + buyer_change + matcher_fee
    let mut total_fee = kob_core::mass::min_relay_fee(
        kob_core::mass::estimate_compute_mass(num_inputs, num_outputs, 0),
    );

    // Total KAS in
    let wallet_value = wallet_utxo.as_ref().map_or(0, |w| w.2);
    let total_sell_value: u64 = filled_sells.iter().map(|s| s.utxo_value).sum();
    let total_kas_in = total_sell_value + buy_kas + wallet_value;
    let total_planned_out: u64 = total_seller_kas + total_tokens_bought;

    if total_kas_in < total_planned_out + total_fee {
        return Err(BatchError::InsufficientFee {
            needed: total_planned_out + total_fee,
            available: total_kas_in,
        });
    }

    let raw_surplus = total_kas_in - total_planned_out - total_fee;

    // Sell remainder (excess sell input value beyond token outputs).
    // All fills are full-fill (amount == tokens consumed), so per-sell
    // excess = utxo_value - amount.  Distribute individually.
    let sell_excess = total_sell_value.saturating_sub(total_tokens_bought);
    if sell_excess > 0 {
        for sell in &filled_sells {
            let this_excess = sell.utxo_value.saturating_sub(sell.amount);
            if this_excess >= MIN_UTXO_VALUE {
                outputs.push(PlannedOutput {
                    value: this_excess,
                    script_public_key: sell.counterparty_spk.clone(),
                    spk_version: sell.counterparty_spk_version,
                    purpose: OutputPurpose::SellRemainder,
                });
            }
        }
    }

    // raw_surplus includes kas_remaining (unspent buy KAS) + wallet excess.
    // Matcher gets: wallet excess + spread profit (not the buyer's unspent KAS).
    // Buyer gets back: kas_remaining (unspent KAS from sweep).
    let matcher_kas = raw_surplus
        .saturating_sub(sell_excess)
        .saturating_sub(kas_remaining);

    // Apply bps cap
    let (capped_matcher_kas, buyer_refund_from_bps) = apply_bps_cap(matcher_kas, total_seller_kas, fee_bps);

    // Buyer change = unspent KAS from sweep + any bps refund
    let total_buyer_change = kas_remaining + buyer_refund_from_bps;
    if total_buyer_change >= MIN_UTXO_VALUE {
        outputs.push(PlannedOutput {
            value: total_buyer_change,
            script_public_key: buy.counterparty_spk.clone(),
            spk_version: buy.counterparty_spk_version,
            purpose: OutputPurpose::BuyerChange,
        });
    } else if total_buyer_change > 0 {
        // Dust: add to buyer token output
        if let Some(tok_out) = outputs.iter_mut()
            .find(|o| o.purpose == OutputPurpose::BuyerTokens)
        {
            tok_out.value += total_buyer_change;
        }
    }

    // Matcher fee output
    let (matcher_surplus, dropped_to_fee) = emit_matcher_fee(&mut outputs, capped_matcher_kas, matcher_spk, matcher_spk_version);
    total_fee += dropped_to_fee;

    // Buy-to-sell mapping (buy maps to first sell with matching token)
    let mut buy_seller_map: HashMap<usize, usize> = HashMap::new();
    buy_seller_map.insert(buy_input_idx, 0);

    Ok(BatchPlan {
        sells: plan_sells,
        buys: plan_buys,
        wallet_input: wallet_utxo,
        outputs,
        total_fee,
        matcher_surplus,
        token_input_map,
        buy_seller_map,
        fee_bps,
        total_seller_kas,
        ioc_mode: Some(IocSide::Buy),
        sell_fill_amounts: Vec::new(),
        buy_partial_fills: HashMap::new(),
        sell_output_idx: Vec::new(),
        buy_output_idx: Vec::new(),
        buy_coi: Vec::new(),
        bracket_receipt: None,
        bracket_oco_output: None,
        buy_sweep_sells: Vec::new(),
        output_auth_input: std::collections::HashMap::new(),
    })
}

/// v17 IOC N:M sweep planner: 1 v17 buy (IOC selector) sweeps up to
/// `BUY_ORDER_V17_MAX_N` sells of the same token, immediately-or-cancel.
///
/// Mirrors `plan_batch_match_v17`'s per-sell BuyerTokens output mechanism
/// (each output bound to its own sell input via `output_auth_input`, exactly
/// the shape the v17 contract's per-term `OpAuthOutputIdx` binding expects),
/// combined with `plan_ioc_match`'s greedy affordability sweep (full-fill
/// sells only, stop when the buy's remaining KAS can't afford the next
/// sell) and buyer-change output for any leftover KAS.
///
/// IOC floor: the v17 contract relaxes its aggregate limit-price floor from
/// the full expected-token amount to the buy's own `min_fill` when the IOC
/// selector (Op5) is used -- mirrored here by checking `total_tokens >=
/// buy.min_fill` instead of the GTC full amount.
///
/// The contract's aggregate surplus cap (`kas_in - fair_sum <= cap`) reads
/// the buy's FULL `kas_in` unconditionally, exactly like v16's existing F6
/// (see `order.rs`) -- so, like the pre-existing `plan_ioc_match`, a large
/// buyer-change amount is only obtainable within `mmfee_bps`; this mirrors
/// that already-shipped design, not a new risk. The v17 covenant bytecode
/// itself is unchanged and already adversarially proven (`v17_nm_buy.rs`
/// `m15_ioc_within_cap_passes` / `m15b_ioc_underdelivery_theft_rejected`);
/// this planner only has to compose the HONEST tx shape those tests assume.
pub fn plan_ioc_match_v17(
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
    if buy.version != 17 {
        return Err(BatchError::UnsupportedVersion {
            outpoint: format!("{}:{}", buy.outpoint.0, buy.outpoint.1),
            version: buy.version,
        });
    }

    // Greedy affordability sweep: full-fill sells only, capped at MAX_N.
    // RELEASE-BLOCKER #1 (defense-in-depth): an OCO sell must never enter a
    // multi-sell v17 composition even here, in case a caller bypasses the
    // find_sweep_groups/plan_batch_match gates.
    let buy_kas = buy.utxo_value;
    let mut kas_remaining = buy_kas;
    let mut filled: Vec<&BatchOrder> = Vec::new();
    for sell in sells {
        if filled.len() >= BUY_ORDER_V17_MAX_N {
            break;
        }
        if sell.oco_path.is_some() {
            continue;
        }
        if sell.token_cov_id != buy.token_cov_id {
            continue;
        }
        if sell.price_den == 0 {
            continue;
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

    // IOC floor: aggregate delivered tokens must meet the buy's OWN min_fill
    // (relaxed from the full expected-amount GTC floor), mirroring the
    // contract's ioc_flag ? mfill : expected relaxation.
    if total_tokens < buy.min_fill {
        return Err(BatchError::MinFillViolation {
            index: n,
            fill_kas: total_tokens,
            min_fill: buy.min_fill,
        });
    }

    let token_input_map = build_token_input_map(
        &filled.iter().map(|s| s.token_cov_id).collect::<Vec<_>>(),
    );
    let plan_sells: Vec<(BatchOrder, usize)> =
        filled.iter().enumerate().map(|(i, s)| ((*s).clone(), i)).collect();
    let plan_buys: Vec<(BatchOrder, usize)> = vec![(buy.clone(), n)];

    let mut outputs: Vec<PlannedOutput> = Vec::new();

    // SellerKas per sell, merged by (spk, version).
    let mut total_seller_kas: u64 = 0;
    let mut seller_group_idx: HashMap<(Vec<u8>, u16), usize> = HashMap::new();
    for sell in &filled {
        let sell_kas = (sell.amount as u128 * sell.price_num as u128
            / sell.price_den as u128) as u64;
        total_seller_kas += sell_kas;
        let key = (sell.counterparty_spk.clone(), sell.counterparty_spk_version);
        if let Some(&existing) = seller_group_idx.get(&key) {
            outputs[existing].value += sell_kas;
        } else {
            let new_idx = outputs.len();
            outputs.push(PlannedOutput {
                value: sell_kas,
                script_public_key: sell.counterparty_spk.clone(),
                spk_version: sell.counterparty_spk_version,
                purpose: OutputPurpose::SellerKas,
            });
            seller_group_idx.insert(key, new_idx);
        }
    }

    // BuyerTokens per sell (NOT merged) -- each authorized by its own sell
    // input, exactly like the GTC v17 planner.
    let mut output_auth_input: std::collections::HashMap<usize, u16> = std::collections::HashMap::new();
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
    let total_buy_kas = buy.utxo_value;
    let wallet_value = wallet_utxo.as_ref().map_or(0, |w| w.2);
    let total_kas_in = total_sell_value + total_buy_kas + wallet_value;
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

    // matcher_kas excludes kas_remaining (unspent buy KAS, returned to the
    // buyer as change) from the matcher's take, same split as plan_ioc_match.
    let matcher_kas = raw_surplus.saturating_sub(kas_remaining);
    let (capped_matcher_kas, buyer_refund_from_bps) = apply_bps_cap(matcher_kas, total_seller_kas, fee_bps);

    let total_buyer_change = kas_remaining + buyer_refund_from_bps;
    if total_buyer_change >= MIN_UTXO_VALUE {
        outputs.push(PlannedOutput {
            value: total_buyer_change,
            script_public_key: buy.counterparty_spk.clone(),
            spk_version: buy.counterparty_spk_version,
            purpose: OutputPurpose::BuyerChange,
        });
    } else if total_buyer_change > 0 {
        // Dust: fold into the first BuyerTokens output.
        if let Some(tok_out) = outputs.iter_mut().find(|o| o.purpose == OutputPurpose::BuyerTokens) {
            tok_out.value += total_buyer_change;
        }
    }

    let (matcher_surplus, dropped_to_fee) =
        emit_matcher_fee(&mut outputs, capped_matcher_kas, matcher_spk, matcher_spk_version);
    total_fee += dropped_to_fee;
    total_fee += raw_surplus.saturating_sub(matcher_surplus + dropped_to_fee + kas_remaining + buyer_refund_from_bps);

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
        sell_output_idx: Vec::new(),
        buy_output_idx: Vec::new(),
        buy_coi: Vec::new(),
        bracket_receipt: None,
        bracket_oco_output: None,
        buy_sweep_sells: vec![sell_indices],
        output_auth_input,
    })
}

/// IOC (Immediate-Or-Cancel) batch match: one sell sweeps multiple buys.
///
/// Buys are consumed in order (caller should pre-sort by price, best first).
/// The sell provides tokens; buys provide KAS. The sell sweeps buys until
/// its tokens are exhausted or all buys are filled.
///
/// # Returns
/// A `BatchPlan` containing only the buys that were filled (full fill).
/// Seller token change output is added if sell tokens exceed what was needed.
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

    // Sweep buys with the sell's tokens
    let sell_tokens = sell.amount; // = sell.utxo_value for token UTXOs
    let mut filled_buys: Vec<&BatchOrder> = Vec::new();
    let mut total_tokens_sold: u64 = 0;
    let mut total_seller_kas: u64 = 0;
    let mut tokens_remaining = sell_tokens;

    for buy in buys {
        if buy.price_den == 0 {
            continue;
        }
        // How many tokens does this buy want?
        let buy_tokens_128 = buy.utxo_value as u128 * buy.price_num as u128
            / buy.price_den as u128;
        if buy_tokens_128 > u64::MAX as u128 {
            continue;
        }
        let buy_tokens = buy_tokens_128 as u64;
        if buy_tokens < MIN_UTXO_VALUE {
            continue;
        }

        // How much KAS does the buyer pay? = buy.utxo_value
        // How many tokens does the seller give? = buy_tokens
        // Seller gets: buy.utxo_value KAS (the buyer's full UTXO)

        if tokens_remaining >= buy_tokens {
            filled_buys.push(buy);
            total_tokens_sold += buy_tokens;
            total_seller_kas += buy.utxo_value; // buyer pays full UTXO value
            tokens_remaining -= buy_tokens;
        } else {
            break;
        }
    }

    if filled_buys.is_empty() {
        return Err(BatchError::InsufficientFee {
            needed: buys[0].amount as u64,
            available: sell_tokens,
        });
    }

    // Bug-A guard: OCO v1 covenant has no IOC path (no selector=5 dispatch).
    // If the sell is OCO and buys leave a token remainder, the resulting
    // sigscript would be `[koi][fta][Op5][RS]`, and OCO's script would run
    // the SL-branch `Op2 OpEqual OpVerify` which fails for selector=5.
    // See core/src/contract/spot/oco.rs OCO_SELL_BODY dispatch table.
    //
    // Reject here so the executor can skip the group without mark_failed
    // (which would drag any co-grouped orders into cooldown — see Bug B).
    if sell.oco_path.is_some() && total_tokens_sold < sell.utxo_value {
        return Err(BatchError::OcoRemainderUnsupported {
            outpoint: format!("{}:{}", sell.outpoint.0, sell.outpoint.1),
            utxo_value: sell.utxo_value,
            filled_tokens: total_tokens_sold,
        });
    }

    // Min-fill guard: the sell contract's IOC path checks fill_kas >= mfill.
    // fill_kas = total_tokens_sold * pnum / pden. If this is below min_fill,
    // the on-chain script will reject the TX.
    if sell.price_den > 0 {
        let fill_kas = total_tokens_sold as u128 * sell.price_num as u128
            / sell.price_den as u128;
        if (fill_kas as u64) < sell.min_fill {
            return Err(BatchError::MinFillViolation {
                index: 0,
                fill_kas: fill_kas as u64,
                min_fill: sell.min_fill,
            });
        }
    }

    let m = filled_buys.len();

    // Token input map: sell provides covenant lineage
    let token_input_map = build_token_input_map(&[sell.token_cov_id]);

    // Input layout: [sell] [buy_0..buy_{m-1}] [wallet?]
    let plan_sells: Vec<(BatchOrder, usize)> = vec![(sell.clone(), 0)];
    let plan_buys: Vec<(BatchOrder, usize)> = filled_buys.iter()
        .enumerate()
        .map(|(j, b)| ((*b).clone(), 1 + j))
        .collect();

    // Build outputs.
    //
    // Output layout (partial IOC-sell, i.e. token_change present):
    //   [0] SellerKas           (KAS to the seller's wallet; non-covenant)
    //   [1] SellRemainder       (unsold tokens re-locked under the sell order's
    //                            OWN P2SH -- the residual self-continuation)
    //   [2..] BuyerTokens       (tokens delivered to each buyer)
    //
    // The residual MUST be the sell input's 0th AUTHORIZED covenant output:
    // the deployed sell IOC F4 reads `OpTxInputIndex Op0 OpAuthOutputIdx` and
    // requires that output's SPK == the sell input's own SPK (the order P2SH,
    // a self-continuation) with value >= token_in - fta. BuyerTokens are ALSO
    // covenant continuations authorized by the (single) sell input, so the
    // residual has to sit at a LOWER output index than any BuyerTokens.
    // SellerKas at [0] is non-covenant (not in the sell input's auth list), so
    // putting the residual at [1] makes it the sell input's auth-index 0 while
    // keeping koi=0. Previously this output used the seller's *wallet* SPK and
    // sat AFTER the BuyerTokens, so auth[0] resolved to a BuyerTokens output
    // and the F4 self-continuation check failed closed (SECURITY_FIXES Fix 1
    // residual). The residual's covenant binding (authorizing_input = 0 = the
    // sell input, covenant_id = the token) is attached by the CLI/engine
    // caller (match_batch.rs / matching.rs SellRemainder arm).
    let mut outputs: Vec<PlannedOutput> = Vec::new();

    // Output[0] = seller's KAS (aggregated from all filled buys).
    // total_seller_kas is the sum of the filled buys' UTXO values (each
    // >= MIN_UTXO_VALUE), so it is always emitted here and koi = 0 holds.
    outputs.push(PlannedOutput {
        value: total_seller_kas,
        script_public_key: sell.counterparty_spk.clone(),
        spk_version: sell.counterparty_spk_version,
        purpose: OutputPurpose::SellerKas,
    });

    // Output[1] = residual self-continuation (unsold tokens -> sell order P2SH).
    let token_change = sell_tokens.saturating_sub(total_tokens_sold);
    let has_residual = token_change >= MIN_UTXO_VALUE;
    if has_residual {
        let sell_p2sh = kob_core::p2sh::build_p2sh(&sell.redeem_script);
        outputs.push(PlannedOutput {
            value: token_change,
            script_public_key: sell_p2sh.script().to_vec(),
            spk_version: sell_p2sh.version(),
            purpose: OutputPurpose::SellRemainder,
        });
    }

    // Output[buyer_base + j] = buyer token outputs (each buyer gets their tokens).
    let buyer_base = if has_residual { 2 } else { 1 };
    for buy in &filled_buys {
        let buy_tokens_128 = buy.utxo_value as u128 * buy.price_num as u128
            / buy.price_den as u128;
        let buy_tokens = buy_tokens_128 as u64;
        outputs.push(PlannedOutput {
            value: buy_tokens,
            script_public_key: buy.counterparty_spk.clone(),
            spk_version: buy.counterparty_spk_version,
            purpose: OutputPurpose::BuyerTokens,
        });
    }

    // Estimate miner fee
    let num_inputs = 1 + m + if wallet_utxo.is_some() { 1 } else { 0 };
    let num_outputs = outputs.len() + 1; // + matcher fee
    let mut total_fee = kob_core::mass::estimate_compute_mass(num_inputs, num_outputs, 0);

    // Total value in
    let wallet_value = wallet_utxo.as_ref().map_or(0, |w| w.2);
    let total_buy_value: u64 = filled_buys.iter().map(|b| b.utxo_value).sum();
    let total_kas_in = sell.utxo_value + total_buy_value + wallet_value;
    let total_planned_out: u64 = outputs.iter().map(|o| o.value).sum();

    if total_kas_in < total_planned_out + total_fee {
        return Err(BatchError::InsufficientFee {
            needed: total_planned_out + total_fee,
            available: total_kas_in,
        });
    }

    let raw_surplus = total_kas_in - total_planned_out - total_fee;

    // Matcher gets surplus (wallet excess + any spread)
    let matcher_kas = raw_surplus;

    // Apply bps cap
    let (capped_matcher_kas, buyer_refund_from_bps) = apply_bps_cap(matcher_kas, total_seller_kas, fee_bps);

    // Refund BPS cap excess to buyers pro-rata by KAS input. BuyerTokens
    // start at `buyer_base` (2 when a residual self-continuation occupies
    // output[1], else 1), so dust-folding must target that offset.
    if buyer_refund_from_bps > 0 {
        distribute_buyer_refund(&mut outputs, buyer_refund_from_bps, &filled_buys, total_buy_value, buyer_base, None);
    }

    // Matcher fee output: a dust surplus is dropped to the miner fee (added to
    // total_fee) rather than folded into an output; matcher_surplus reflects
    // only what was actually emitted as a MatcherFee output.
    let (matcher_surplus, dropped_to_fee) = emit_matcher_fee(&mut outputs, capped_matcher_kas, matcher_spk, matcher_spk_version);
    total_fee += dropped_to_fee;

    // Explicit output-index maps (the residual, when present, shifts the
    // BuyerTokens outputs and the token covenant-output ordering):
    //   koi (seller KAS)  = output 0
    //   toi (buyer j)     = buyer_base + j
    //   coi (buyer j)     = (has_residual ? 1 : 0) + j  -- the residual is
    //                       token covenant-output 0 when present.
    // Buy-to-sell mapping keys are the BuyerTokens OUTPUT indices, all
    // authorized by the single sell input (0).
    let sell_output_idx = vec![0usize];
    let buy_output_idx: Vec<usize> = (0..m).map(|j| buyer_base + j).collect();
    let coi_base: u16 = if has_residual { 1 } else { 0 };
    let buy_coi: Vec<u16> = (0..m).map(|j| coi_base + j as u16).collect();
    let mut buy_seller_map: HashMap<usize, usize> = HashMap::new();
    for j in 0..m {
        buy_seller_map.insert(buyer_base + j, 0);
    }

    // sell_fill_amounts: the sell is the sweeper, so we track how much of its
    // tokens go to each buyer (used for sell IOC sigscript fta parameter).
    // But there's only 1 sell, so fill_amount = total_tokens_sold.
    let sell_fill_amounts = vec![total_tokens_sold];

    Ok(BatchPlan {
        sells: plan_sells,
        buys: plan_buys,
        wallet_input: wallet_utxo,
        outputs,
        total_fee,
        matcher_surplus,
        token_input_map,
        buy_seller_map,
        fee_bps,
        total_seller_kas,
        ioc_mode: Some(IocSide::Sell),
        sell_fill_amounts,
        buy_partial_fills: HashMap::new(),
        sell_output_idx,
        buy_output_idx,
        buy_coi,
        bracket_receipt: None,
        bracket_oco_output: None,
        buy_sweep_sells: Vec::new(),
        output_auth_input: std::collections::HashMap::new(),
    })
}

// ═════════════════════════════════════════════════════════════════════════
// v18 planners (Stage B, kob/V18_DESIGN.md) — ADDITIVE; pre-v18 planners
// above are untouched and die with Stage E.
// ═════════════════════════════════════════════════════════════════════════

/// Parse `mmfee_bps` out of a v18 buy redeemScript (state offset [160..168)).
///
/// State layout (178B): `[0x20 okspkh]` then `[0x20 tcid][0x08 pnum]`
/// `[0x08 pden][0x08 mfill][0x20 ohash][0x20 bspkh][0x08 mmfee][cpend]`
/// `[0x08 expiry]` — mmfee bytes start after 33 + 127 = 160.
fn parse_v18_buy_mmfee_bps(rs: &[u8]) -> Option<u64> {
    if rs.len() != BUY_ORDER_V18_RS_EXPECTED_LEN {
        return None;
    }
    Some(u64::from_le_bytes(rs[160..168].try_into().ok()?))
}

/// Contract-order fair value of a full-filled sell term, exactly as the v18
/// buy's PASS 2 computes it: `floor(tokens / pden) * pnum` (read from the
/// canonical attestation, which equals the sell's own state pair).
fn v18_fair_kas(tokens: u64, pnum: u64, pden: u64) -> u128 {
    (tokens as u128 / pden as u128) * pnum as u128
}

/// Shared v18 sweep validation: exactly one v18 buy, `<= BUY_ORDER_V18_MAX_N`
/// v18 sells of the buy's token (plain and/or OCO — v18 OCO sells are
/// sweep-eligible on both branches), no duplicate outpoints.
fn validate_v18_sweep(sells: &[BatchOrder], buys: &[BatchOrder]) -> Result<(), BatchError> {
    if sells.is_empty() {
        return Err(BatchError::NoSellOrders);
    }
    if buys.is_empty() {
        return Err(BatchError::NoBuyOrders);
    }
    // Item D pin: never more than ONE v18 buy per settle (fail-closed by
    // proof — see `test_v18_multi_buy_rejected`).
    if buys.len() > 1 {
        return Err(BatchError::V18MultiBuyUnsupported { count: buys.len() });
    }
    let buy = &buys[0];
    if buy.version != 18 {
        return Err(BatchError::UnsupportedVersion {
            outpoint: format!("{}:{}", buy.outpoint.0, buy.outpoint.1),
            version: buy.version,
        });
    }
    if sells.len() > BUY_ORDER_V18_MAX_N {
        return Err(BatchError::V18TooManySells {
            count: sells.len(),
            max: BUY_ORDER_V18_MAX_N,
        });
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

/// v18 GTC N:1 sweep planner: one v18 buy consumes N (`<= BUY_ORDER_V18_MAX_N`)
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
pub fn plan_batch_match_v18(
    sells: &[BatchOrder],
    buys: &[BatchOrder],
    wallet_utxo: Option<(String, u32, u64)>,
    matcher_spk: &[u8],
    matcher_spk_version: u16,
    fee_bps: Option<u16>,
) -> Result<BatchPlan, BatchError> {
    validate_v18_sweep(sells, buys)?;
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
        fair_sum += v18_fair_kas(sell.amount, sell.price_num, sell.price_den);
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
    let mmfee_bps = parse_v18_buy_mmfee_bps(&buy.redeem_script)
        .ok_or_else(|| BatchError::UnsupportedVersion {
            outpoint: format!("{}:{}", buy.outpoint.0, buy.outpoint.1),
            version: buy.version,
        })?;
    let cap = (buy.utxo_value as u128 / 10000) * mmfee_bps as u128;
    let surplus_onchain = (buy.utxo_value as u128).saturating_sub(fair_sum);
    if surplus_onchain > cap {
        return Err(BatchError::V18CapInfeasible {
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
/// `BUY_ORDER_V18_MAX_N` fully-filled v18 sells (plain and/or OCO),
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
pub fn plan_ioc_match_v18(
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
    for sell in sells {
        if filled.len() >= BUY_ORDER_V18_MAX_N {
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
    let mmfee_bps = parse_v18_buy_mmfee_bps(&buy.redeem_script)
        .ok_or_else(|| BatchError::UnsupportedVersion {
            outpoint: format!("{}:{}", buy.outpoint.0, buy.outpoint.1),
            version: buy.version,
        })?;
    let fair_sum: u128 = filled
        .iter()
        .map(|s| v18_fair_kas(s.amount, s.price_num, s.price_den))
        .sum();
    let cap = (buy_kas as u128 / 10000) * mmfee_bps as u128;
    let surplus_onchain = (buy_kas as u128).saturating_sub(fair_sum);
    if surplus_onchain > cap {
        return Err(BatchError::V18CapInfeasible {
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
/// On-chain semantics being planned for (see `emit_partial_body_v18`):
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
pub fn plan_partial_match_v18(
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
    let mmfee_bps = parse_v18_buy_mmfee_bps(&buy.redeem_script)
        .ok_or_else(|| BatchError::UnsupportedVersion {
            outpoint: format!("{}:{}", buy.outpoint.0, buy.outpoint.1),
            version: buy.version,
        })?;

    // Greedy subset: full-fill v18 sells (plain/OCO) the buy can pay for
    // while still keeping a residual.
    let buy_kas = buy.utxo_value;
    let mut filled: Vec<&BatchOrder> = Vec::new();
    let mut base_spent: u64 = 0; // Σ seller_kas
    for sell in sells {
        if filled.len() >= BUY_ORDER_V18_MAX_N {
            break;
        }
        if sell.version != 18 || sell.token_cov_id != buy.token_cov_id || sell.price_den == 0 {
            continue;
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
        .map(|s| v18_fair_kas(s.amount, s.price_num, s.price_den))
        .sum();
    let gap = (base_spent as u128).saturating_sub(fair_sum); // integer-rounding gap >= 0
    let zero_allow = (base_spent as u128 / 10000) * mmfee_bps as u128;
    if gap > zero_allow {
        return Err(BatchError::V18CapInfeasible {
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
        return Err(BatchError::V18CapInfeasible {
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
///     `BatchError::V18SellResidualUnsupported`.
///   - At most ONE v18 buy per settle (item D pin), so the "sweep" selects
///     the first candidate buy that FULLY absorbs the sell: exact match
///     settles GTC (Op1/Op1); a larger buy settles via its IOC selector
///     (Op5) with the sell's full delivery meeting the buy's `min_fill`
///     floor and the leftover KAS returned as buyer change (recoverable only
///     within the buy's `mmfee_bps` cap, which is pre-checked exactly).
pub fn plan_sell_ioc_match_v18(
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
    let fair = v18_fair_kas(sell.amount, sell.price_num, sell.price_den);

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
        let Some(mmfee_bps) = parse_v18_buy_mmfee_bps(&buy.redeem_script) else {
            continue;
        };
        let cap = (buy.utxo_value as u128 / 10000) * mmfee_bps as u128;
        let surplus_onchain = (buy.utxo_value as u128).saturating_sub(fair);
        if surplus_onchain > cap {
            cap_infeasible = Some(BatchError::V18CapInfeasible {
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
            return Err(BatchError::V18SellResidualUnsupported {
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

/// Maximum ring legs (2-cycle = token<->token, 3-cycle = triangle).
pub const RING_MAX: usize = 3;

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
            let ss = build_swap_v18_fill_sigscript(giver, toi, &leg.redeem_script);
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
        if leg.redeem_script.len() != SWAP_V18_RS_SIZE {
            return Err(BatchError::RingInvalidLeg {
                outpoint: format!("{}:{}", leg.outpoint.0, leg.outpoint.1),
                reason: "redeem script is not a v18 swap order (wrong length)",
            });
        }
        let p = parse_swap_order_v18_rs(&leg.redeem_script).ok_or(BatchError::RingInvalidLeg {
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

    /// Create a fake sell order for testing.
    fn make_sell(id_byte: u8, amount: u64, price_num: u64, price_den: u64, token: [u8; 32]) -> BatchOrder {
        let tx_id = hex::encode(&[id_byte; 32]);
        // Build a real v14 sell RS for correct sigscript sizing
        let owner = [0xBB; 32];
        let sspkh = [0xCC; 32];
        let rs = kob_core::contract::build_sell_redeem_script(
            price_num, price_den, 1_000_000, &owner, &sspkh, 0, 0, 0,).unwrap();
        BatchOrder {
            outpoint: (tx_id, 0),
            order_type: OrderType::Sell,
            version: 14,
            token_cov_id: token,
            price_num,
            price_den,
            amount,
            redeem_script: rs,
            utxo_value: amount,
            counterparty_spk: vec![0xDD; 34], // fake seller SPK
            counterparty_spk_version: 0,
            min_fill: 1_000_000,
            oco_path: None,
            bracket_meta: None,
        }
    }

    /// Create a fake buy order for testing.
    fn make_buy(id_byte: u8, amount: u64, price_num: u64, price_den: u64, token: [u8; 32]) -> BatchOrder {
        let tx_id = hex::encode(&[id_byte; 32]);
        let owner = [0xBB; 32];
        let bspkh = [0xCC; 32];
        let rs = kob_core::contract::build_buy_redeem_script(
            &token, price_num, price_den, 1_000_000, &owner, &bspkh, 0, 0, 0,).unwrap();
        BatchOrder {
            outpoint: (tx_id, 0),
            order_type: OrderType::Buy,
            version: 14,
            token_cov_id: token,
            price_num,
            price_den,
            amount,
            redeem_script: rs,
            utxo_value: amount,
            counterparty_spk: vec![0xEE; 34], // fake buyer SPK
            counterparty_spk_version: 0,
            min_fill: 1_000_000,
            oco_path: None,
            bracket_meta: None,
        }
    }

    /// Create a v17 (N:M sweep) buy order for testing.
    fn make_buy_v17(id_byte: u8, amount: u64, price_num: u64, price_den: u64, token: [u8; 32], mmfee_bps: u64) -> BatchOrder {
        let tx_id = hex::encode(&[id_byte; 32]);
        let owner = [0xBB; 32];
        let bspkh = [0xCC; 32];
        let rs = kob_core::contract::spot::order::build_buy_v17_redeem_script(
            &token, price_num, price_den, 1_000_000, &owner, &bspkh, mmfee_bps, 0, 0,
        ).unwrap();
        BatchOrder {
            outpoint: (tx_id, 0),
            order_type: OrderType::Buy,
            version: 17,
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

    /// Matcher SPK for tests (fake P2PK: 0xCC repeated).
    fn matcher_spk() -> Vec<u8> {
        vec![0xCC; 34]
    }

    /// v17 N:M sweep: 2 sells (99/100) + 1 v17 buy (1/1) -> the plan emits ONE
    /// BuyerTokens output PER SELL, each authorized by its own sell input, and
    /// build_tx emits the v17 fill sigscript.
    #[test]
    fn test_v17_nm_sweep_emits_per_sell_outputs() {
        let token = [0x42; 32];
        let sells = vec![
            make_sell(0x10, 10_000_000, 99, 100, token),
            make_sell(0x11, 20_000_000, 99, 100, token),
        ];
        // Buy pays 30M KAS at 1/1, sells supply 30M tokens total.
        let buys = vec![make_buy_v17(0x20, 30_000_000, 1, 1, token, 2000)];
        // Matcher wallet UTXO funds the miner fee.
        let wallet = Some((hex::encode(&[0x99u8; 32]), 0u32, 100_000_000u64));
        let plan = plan_batch_match(&sells, &buys, wallet, &matcher_spk(), 0, Some(2000))
            .expect("v17 sweep must plan");

        // One BuyerTokens output per sell, each bound to its own sell input.
        let bt: Vec<usize> = plan.outputs.iter().enumerate()
            .filter(|(_, o)| o.purpose == OutputPurpose::BuyerTokens)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(bt.len(), 2, "must emit 2 per-sell BuyerTokens outputs");
        // auth inputs map to sell inputs 0 and 1 (distinct).
        let mut auths: Vec<u16> = bt.iter().map(|i| plan.output_auth_input[i]).collect();
        auths.sort();
        assert_eq!(auths, vec![0, 1], "each BuyerTokens output bound to a distinct sell input");
        // Per-sell values = each sell's full amount.
        let vals: Vec<u64> = bt.iter().map(|i| plan.outputs[*i].value).collect();
        assert!(vals.contains(&10_000_000) && vals.contains(&20_000_000));
        // Sweep sell list.
        assert_eq!(plan.buy_sweep_sells, vec![vec![0u16, 1u16]]);

        // Economic consistency with the v17 contract (the exact shape+values are
        // engine-proven in kob-core's v17_nm_buy.rs honest(2) case):
        //  - aggregate limit-price floor: total tokens >= kas_in/buy_price.
        let total_tokens: u64 = vals.iter().sum();
        let buy_kas = 30_000_000u64;
        assert!(total_tokens >= buy_kas /* 1/1 */, "limit-price floor holds");
        //  - aggregate surplus cap: (kas_in - sum fair_kas) <= kas_in*bps/10000.
        //    sum(fair_kas) == total_seller_kas (each output priced at its sell).
        let surplus = buy_kas - plan.total_seller_kas;
        let cap = buy_kas / 10000 * 2000;
        assert!(surplus <= cap, "intrinsic surplus {surplus} within cap {cap}");

        // build_tx emits the v17 fill sigscript (selector Op1 = 0x51; the last
        // pushData is the v17 RS, which starts with the 145B state then Op9 0x7a).
        let tx = plan.build_tx().expect("build_tx");
        assert_eq!(tx.inputs.len(), 4, "2 sells + 1 buy + wallet fee input");
        let buy_ss = &tx.inputs[2].sigscript; // input[2] is the buy (after 2 sells)
        // The v17 fill sigscript ends with pushData(RS); RS body starts at
        // offset 145 with 0x59 0x7a. Confirm the RS is the v17 contract.
        assert!(
            buy_ss.windows(2).any(|w| w == [0x59, 0x7a]),
            "buy sigscript must embed the v17 selector-dispatch RS"
        );
    }

    /// A v17 batch mixing a non-v17 buy is rejected (matcher groups by kind).
    #[test]
    fn test_v17_mixed_batch_rejected() {
        let token = [0x43; 32];
        let sells = vec![make_sell(0x10, 10_000_000, 99, 100, token)];
        let buys = vec![
            make_buy_v17(0x20, 10_000_000, 1, 1, token, 2000),
            make_buy(0x21, 5_000_000, 1, 1, token),
        ];
        let r = plan_batch_match(&sells, &buys, None, &matcher_spk(), 0, Some(2000));
        assert!(matches!(r, Err(BatchError::UnsupportedVersion { .. })), "mixed v17 batch must be rejected");
    }

    /// Create a fake OCO sell order (TP path) for testing.
    fn make_oco_sell(id_byte: u8, amount: u64, price_num: u64, price_den: u64, token: [u8; 32]) -> BatchOrder {
        let tx_id = hex::encode(&[id_byte; 32]);
        let owner = [0xBB; 32];
        let sspkh = [0xCC; 32];
        let rs = kob_core::build_oco_sell_redeem_script(
            price_num, price_den, 1_000_000,
            price_num, price_den, 1_000_000,
            &owner, &sspkh, 0, 0, 0,
        ).unwrap();
        BatchOrder {
            outpoint: (tx_id, 0),
            order_type: OrderType::Sell,
            version: 14,
            token_cov_id: token,
            price_num,
            price_den,
            amount,
            redeem_script: rs,
            utxo_value: amount,
            counterparty_spk: vec![0xDD; 34],
            counterparty_spk_version: 0,
            min_fill: 1_000_000,
            oco_path: Some(kob_core::OcoPath::TakeProfit),
            bracket_meta: None,
        }
    }

    /// RELEASE-BLOCKER #1: an OCO sell composed alongside another sell of the
    /// same token into one v17 sweep must be rejected, not silently planned.
    /// OCO_SELL_BODY's F4 still uses the pre-Fix-3 transaction-wide shared
    /// output index, so a matcher could otherwise satisfy the OCO sell's F4
    /// via the OTHER sell's authorized output, without ever delivering the
    /// OCO seller's own tokens anywhere a buyer paid for.
    #[test]
    fn test_v17_oco_multi_sell_sweep_rejected() {
        let token = [0x44; 32];
        let sells = vec![
            make_sell(0x10, 10_000_000, 99, 100, token),
            make_oco_sell(0x11, 20_000_000, 99, 100, token),
        ];
        let buys = vec![make_buy_v17(0x20, 30_000_000, 1, 1, token, 2000)];
        let r = plan_batch_match(&sells, &buys, None, &matcher_spk(), 0, Some(2000));
        assert!(
            matches!(r, Err(BatchError::OcoMultiSellSweepUnsupported { .. })),
            "plain sell + OCO sell swept by a v17 buy must be rejected, got {:?}", r
        );
    }

    /// Same exclusion must hold for the legacy (non-v17) merge planner too --
    /// the composition-layer guard is not v17-specific.
    #[test]
    fn test_legacy_batch_oco_multi_sell_sweep_rejected() {
        let token = [0x45; 32];
        let sells = vec![
            make_sell(0x10, 10_000_000, 99, 100, token),
            make_oco_sell(0x11, 10_000_000, 99, 100, token),
        ];
        let buys = vec![make_buy(0x20, 20_000_000, 1, 1, token)];
        let r = plan_batch_match(&sells, &buys, None, &matcher_spk(), 0, Some(2000));
        assert!(
            matches!(r, Err(BatchError::OcoMultiSellSweepUnsupported { .. })),
            "plain sell + OCO sell in a legacy batch must be rejected, got {:?}", r
        );
    }

    /// A SOLO OCO sell (no other same-token sell in the tx) is unaffected --
    /// there's no shared output index to collide with, so 1:1 fills keep
    /// working through the v17 planner exactly as before this fix.
    #[test]
    fn test_v17_solo_oco_sell_still_plans() {
        let token = [0x46; 32];
        let sells = vec![make_oco_sell(0x10, 10_000_000, 99, 100, token)];
        let buys = vec![make_buy_v17(0x20, 10_000_000, 1, 1, token, 2000)];
        let wallet = Some((hex::encode(&[0x99u8; 32]), 0u32, 100_000_000u64));
        let r = plan_batch_match(&sells, &buys, wallet, &matcher_spk(), 0, Some(2000));
        assert!(r.is_ok(), "solo OCO sell must still plan fine: {:?}", r.err());

        // MED #4: build_tx must pick the FIXED-OFFSET OCO TP builder (2-byte
        // koi push), matching the sibling sell branches, because the v17 buy
        // in this tx reads pnum/pden at fixed sigscript offsets.
        let plan = r.unwrap();
        let tx = plan.build_tx().expect("build_tx");
        let expected = kob_core::build_oco_sell_tp_fill_sigscript_fixed_offset(0, &plan.sells[0].0.redeem_script);
        assert_eq!(
            tx.inputs[0].sigscript, expected,
            "OCO sell paired with a v17 buy must use the fixed-offset TP fill sigscript"
        );
    }

    /// HIGH DoS #3: more sells than BUY_ORDER_V17_MAX_N must reject gracefully
    /// (Err), never reaching build_buy_v17_fill_sigscript's internal
    /// `assert!(sell_input_indices.len() <= BUY_ORDER_V17_MAX_N)` panic.
    #[test]
    fn test_v17_too_many_sells_rejects_not_panics() {
        let token = [0x47; 32];
        let n = kob_core::contract::spot::order::BUY_ORDER_V17_MAX_N + 1;
        let sells: Vec<BatchOrder> = (0..n as u8)
            .map(|i| make_sell(0x50 + i, 5_000_000, 1, 1, token))
            .collect();
        let buys = vec![make_buy_v17(0x20, n as u64 * 5_000_000, 1, 1, token, 2000)];
        let wallet = Some((hex::encode(&[0x99u8; 32]), 0u32, 100_000_000u64));
        let r = plan_batch_match(&sells, &buys, wallet, &matcher_spk(), 0, Some(2000));
        assert!(
            matches!(r, Err(BatchError::V17TooManySells { .. })),
            "N > MAX_N must reject gracefully, got {:?}", r
        );
    }

    /// N == MAX_N (the boundary) must still plan fine (positive control for
    /// the DoS #3 guard, proving it doesn't over-restrict the honest case).
    #[test]
    fn test_v17_exactly_max_n_sells_plans_ok() {
        let token = [0x48; 32];
        let n = kob_core::contract::spot::order::BUY_ORDER_V17_MAX_N;
        let sells: Vec<BatchOrder> = (0..n as u8)
            .map(|i| make_sell(0x60 + i, 5_000_000, 1, 1, token))
            .collect();
        let buys = vec![make_buy_v17(0x20, n as u64 * 5_000_000, 1, 1, token, 2000)];
        let wallet = Some((hex::encode(&[0x99u8; 32]), 0u32, 100_000_000u64));
        let r = plan_batch_match(&sells, &buys, wallet, &matcher_spk(), 0, Some(2000));
        assert!(r.is_ok(), "N == MAX_N must plan fine: {:?}", r.err());
    }

    /// HIGH #2: v17 IOC N:M sweep -- honest case. 3 sells cross, buy can only
    /// afford 2, so IOC stops there (unlike GTC, no min-total-tokens floor
    /// beyond the buy's own min_fill) and returns change for the unspent KAS.
    #[test]
    fn test_v17_ioc_sweep_with_change() {
        let token = [0x4a; 32];
        let sell1 = make_sell(0x10, 3_000_000, 1, 1, token);
        let sell2 = make_sell(0x11, 3_000_000, 1, 1, token);
        let sell3 = make_sell(0x12, 5_000_000, 1, 1, token); // too expensive to also afford
        let buy = make_buy_v17(0x20, 7_000_000, 1, 1, token, 2000);
        let wallet = Some((hex::encode(&[0x99u8; 32]), 0u32, 5_000_000u64));

        let plan = plan_ioc_match_v17(&[sell1, sell2, sell3], &buy, wallet, &matcher_spk(), 0, Some(2000))
            .expect("v17 IOC sweep must plan");

        assert_eq!(plan.sells.len(), 2, "only the 2 affordable sells should be filled");
        let bt: Vec<&PlannedOutput> = plan.outputs.iter()
            .filter(|o| o.purpose == OutputPurpose::BuyerTokens)
            .collect();
        assert_eq!(bt.len(), 2, "one per-sell BuyerTokens output (not merged)");
        let auths: std::collections::HashSet<u16> = plan.output_auth_input.values().copied().collect();
        assert_eq!(auths.len(), 2, "each BuyerTokens output bound to a distinct sell input");
        assert_eq!(plan.buy_sweep_sells, vec![vec![0u16, 1u16]]);

        // Some form of leftover accounting exists (change or matcher surplus).
        let buyer_change_exists = plan.outputs.iter().any(|o| o.purpose == OutputPurpose::BuyerChange);
        assert!(buyer_change_exists || plan.matcher_surplus > 0, "leftover KAS must go somewhere");
    }

    /// A v17 IOC sweep whose total delivered tokens fall below the buy's own
    /// min_fill must be rejected (the IOC floor, mirroring the contract's
    /// ioc_flag ? mfill : expected relaxation).
    #[test]
    fn test_v17_ioc_sweep_below_min_fill_rejected() {
        let token = [0x4b; 32];
        let sell1 = make_sell(0x10, 3_000_000, 1, 1, token);
        let mut buy = make_buy_v17(0x20, 3_000_000, 1, 1, token, 2000);
        buy.min_fill = 50_000_000; // far above what a single 3M sell can deliver
        let wallet = Some((hex::encode(&[0x99u8; 32]), 0u32, 5_000_000u64));

        let r = plan_ioc_match_v17(&[sell1], &buy, wallet, &matcher_spk(), 0, Some(2000));
        assert!(matches!(r, Err(BatchError::MinFillViolation { .. })), "below-min_fill IOC sweep must reject, got {:?}", r);
    }

    /// A non-v17 buy passed to plan_ioc_match_v17 must be rejected explicitly
    /// (this planner is v17-only; v14/v16 IOC sweeps keep using plan_ioc_match).
    #[test]
    fn test_v17_ioc_rejects_non_v17_buy() {
        let token = [0x4c; 32];
        let sell1 = make_sell(0x10, 3_000_000, 1, 1, token);
        let buy = make_buy(0x20, 3_000_000, 1, 1, token); // version 14
        let r = plan_ioc_match_v17(&[sell1], &buy, None, &matcher_spk(), 0, Some(2000));
        assert!(matches!(r, Err(BatchError::UnsupportedVersion { .. })), "non-v17 buy must reject, got {:?}", r);
    }

    /// HIGH DoS #3 (IOC variant): more crossing sells than MAX_N must cap the
    /// sweep at MAX_N, not attempt to include them all.
    #[test]
    fn test_v17_ioc_sweep_capped_at_max_n() {
        let token = [0x4d; 32];
        let n_max = kob_core::contract::spot::order::BUY_ORDER_V17_MAX_N;
        let sells: Vec<BatchOrder> = (0..(n_max as u8 + 2))
            .map(|i| make_sell(0x50 + i, 5_000_000, 1, 1, token))
            .collect();
        // Buy affords far more than n_max sells' worth of KAS.
        let buy = make_buy_v17(0x20, 100_000_000, 1, 1, token, 2000);
        let wallet = Some((hex::encode(&[0x99u8; 32]), 0u32, 5_000_000u64));

        let plan = plan_ioc_match_v17(&sells, &buy, wallet, &matcher_spk(), 0, Some(2000))
            .expect("must plan (capped, not error)");
        assert_eq!(plan.sells.len(), n_max, "sweep must cap at MAX_N even though more sells crossed and were affordable");
    }

    /// Item D: multi-v17-buy allocation is NOT supported and must reject.
    ///
    /// A v17 buy's per-term OpAuthOutputIdx binding + aggregate surplus cap is
    /// designed for exactly ONE buy summing N sells. Allocating N sells across
    /// M>1 v17 buys in one tx would require each buy to sum a DISJOINT subset of
    /// sells, but nothing in the v17 covenant prevents two buys from both
    /// referencing (and both counting) the same sell's authorized output -- a
    /// cross-buy double-count. Each buy's cap is checked independently against
    /// its own kas_in, so a matcher could over-allocate one sell's tokens across
    /// two buys' fair-value sums without any single covenant catching it. Since
    /// that disjointness is not covenant-provable, the planner rejects >1 v17
    /// buy (fail-closed) rather than ship an unverifiable allocation.
    #[test]
    fn test_v17_multi_buy_rejected() {
        let token = [0x4e; 32];
        let sells = vec![
            make_sell(0x10, 10_000_000, 1, 1, token),
            make_sell(0x11, 10_000_000, 1, 1, token),
        ];
        let buys = vec![
            make_buy_v17(0x20, 10_000_000, 1, 1, token, 2000),
            make_buy_v17(0x21, 10_000_000, 1, 1, token, 2000),
        ];
        let r = plan_batch_match(&sells, &buys, None, &matcher_spk(), 0, Some(2000));
        assert!(
            matches!(r, Err(BatchError::UnsupportedVersion { .. })),
            "2 v17 buys in one tx must be rejected (no covenant-provable cross-buy disjointness), got {:?}", r
        );
    }

    /// Item C: v17 has NO partial-fill (Op2 D&R residual continuation) path --
    /// its covenant dispatches only expire(4)/cancel(0)/cancel-mark(3)/
    /// fill(1)/IOC(5). A v17 buy therefore NEVER gets a partial-fill sigscript:
    /// both v17 planners populate `buy_sweep_sells` (so build_tx takes the v17
    /// fill branch) and leave `buy_partial_fills` empty. This test pins that
    /// invariant so no future change silently emits a broken v17 partial-fill.
    /// (Incremental buy-order consumption across txs for v17 would need a
    /// covenant redesign -- out of scope per NM_BUY_DESIGN.md Sec 5.)
    #[test]
    fn test_v17_never_emits_partial_fill() {
        let token = [0x4f; 32];
        let sells = vec![make_sell(0x10, 10_000_000, 1, 1, token)];
        let buys = vec![make_buy_v17(0x20, 10_000_000, 1, 1, token, 2000)];
        let wallet = Some((hex::encode(&[0x99u8; 32]), 0u32, 100_000_000u64));
        let plan = plan_batch_match(&sells, &buys, wallet, &matcher_spk(), 0, Some(2000)).unwrap();
        assert!(plan.buy_partial_fills.is_empty(), "v17 plan must carry no partial-fill entries");
        assert!(!plan.buy_sweep_sells.is_empty() && !plan.buy_sweep_sells[0].is_empty(),
            "v17 plan must carry the sweep-sells list so build_tx uses the v17 fill sigscript");
        // build_tx's buy sigscript is the v17 fill form (selector Op1=0x51 with
        // the v17 RS embedded), never a partial-fill (Op2) sigscript.
        let tx = plan.build_tx().unwrap();
        let buy_ss = &tx.inputs[1].sigscript; // input[1] = the single buy (after 1 sell)
        assert!(buy_ss.windows(2).any(|w| w == [0x59, 0x7a]),
            "buy sigscript must embed the v17 selector-dispatch RS (fill path), not a partial-fill");
    }

    // ═════════════════════════════════════════════════════════════════════
    // v18 planner tests (Stage B)
    // ═════════════════════════════════════════════════════════════════════

    /// Create a v18 sell order for testing.
    fn make_sell_v18(id_byte: u8, amount: u64, price_num: u64, price_den: u64, token: [u8; 32]) -> BatchOrder {
        let tx_id = hex::encode([id_byte; 32]);
        let owner = [0xBB; 32];
        let sspkh = [0xCC; 32];
        let rs = kob_core::contract::spot::order::build_sell_v18_redeem_script(
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
    fn make_buy_v18(id_byte: u8, amount: u64, price_num: u64, price_den: u64, token: [u8; 32], mmfee_bps: u64) -> BatchOrder {
        let tx_id = hex::encode([id_byte; 32]);
        let owner = [0xBB; 32];
        let bspkh = [0xCC; 32];
        let rs = kob_core::contract::spot::order::build_buy_v18_redeem_script(
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
    fn make_oco_sell_v18(
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
        let rs = kob_core::contract::spot::oco::build_oco_sell_v18_redeem_script(
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
    fn test_v18_nm_sweep_emits_per_sell_outputs() {
        let token = [0x51; 32];
        let sells = vec![
            make_sell_v18(0x10, 10_000_000, 99, 100, token),
            make_sell_v18(0x11, 20_000_000, 99, 100, token),
        ];
        let buys = vec![make_buy_v18(0x20, 30_000_000, 1, 1, token, 2000)];
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
            kob_core::contract::spot::order::build_sell_v18_fill_sigscript(0, 99, 100, sell_rs0),
            "sell 0 must use the v18 attested fill sigscript with koi=0"
        );
        assert_eq!(
            tx.inputs[1].sigscript,
            kob_core::contract::spot::order::build_sell_v18_fill_sigscript(0, 99, 100, sell_rs1),
            "sell 1 must use the v18 attested fill sigscript with the MERGED koi=0"
        );
        assert_eq!(
            tx.inputs[2].sigscript,
            build_buy_v18_fill_sigscript(&[0, 1], false, &plan.buys[0].0.redeem_script),
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
    fn test_v18_multi_buy_rejected() {
        let token = [0x52; 32];
        let sells = vec![
            make_sell_v18(0x10, 10_000_000, 1, 1, token),
            make_sell_v18(0x11, 10_000_000, 1, 1, token),
        ];
        let buys = vec![
            make_buy_v18(0x20, 10_000_000, 1, 1, token, 2000),
            make_buy_v18(0x21, 10_000_000, 1, 1, token, 2000),
        ];
        let r = plan_batch_match(&sells, &buys, None, &matcher_spk(), 0, Some(2000));
        assert!(
            matches!(r, Err(BatchError::V18MultiBuyUnsupported { count: 2 })),
            "2 v18 buys in one settle must be rejected, got {:?}", r
        );
        // Direct planner call must enforce the same pin.
        let sells2 = vec![make_sell_v18(0x12, 10_000_000, 1, 1, token)];
        let buys2 = vec![
            make_buy_v18(0x22, 10_000_000, 1, 1, token, 2000),
            make_buy_v18(0x23, 10_000_000, 1, 1, token, 2000),
        ];
        let r2 = plan_batch_match_v18(&sells2, &buys2, None, &matcher_spk(), 0, Some(2000));
        assert!(matches!(r2, Err(BatchError::V18MultiBuyUnsupported { .. })));
    }

    /// N > MAX_N rejects gracefully; N == MAX_N plans fine.
    #[test]
    fn test_v18_sweep_max_n_bounds() {
        let token = [0x53; 32];
        let over = BUY_ORDER_V18_MAX_N + 1;
        let sells: Vec<BatchOrder> = (0..over as u8)
            .map(|i| make_sell_v18(0x60 + i, 5_000_000, 1, 1, token))
            .collect();
        let buys = vec![make_buy_v18(0x20, over as u64 * 5_000_000, 1, 1, token, 2000)];
        let wallet = Some((hex::encode([0x99u8; 32]), 0u32, 5_000_000u64));
        let r = plan_batch_match(&sells, &buys, wallet.clone(), &matcher_spk(), 0, Some(2000));
        assert!(
            matches!(r, Err(BatchError::V18TooManySells { .. })),
            "N > MAX_N must reject gracefully, got {:?}", r
        );

        let n = BUY_ORDER_V18_MAX_N;
        let sells: Vec<BatchOrder> = (0..n as u8)
            .map(|i| make_sell_v18(0x70 + i, 5_000_000, 1, 1, token))
            .collect();
        let buys = vec![make_buy_v18(0x21, n as u64 * 5_000_000, 1, 1, token, 2000)];
        let r = plan_batch_match(&sells, &buys, wallet, &matcher_spk(), 0, Some(2000));
        assert!(r.is_ok(), "N == MAX_N must plan fine: {:?}", r.err());
    }

    /// Mixed generations in a v18 settle are rejected in both directions.
    #[test]
    fn test_v18_mixed_generation_rejected() {
        let token = [0x54; 32];
        // v18 buy + v14 sell.
        let r = plan_batch_match(
            &[make_sell(0x10, 10_000_000, 1, 1, token)],
            &[make_buy_v18(0x20, 10_000_000, 1, 1, token, 2000)],
            None, &matcher_spk(), 0, Some(2000),
        );
        assert!(matches!(r, Err(BatchError::UnsupportedVersion { .. })), "v14 sell under v18 buy must reject, got {:?}", r);
        // v18 sell + v14 buy.
        let r = plan_batch_match(
            &[make_sell_v18(0x11, 10_000_000, 1, 1, token)],
            &[make_buy(0x21, 10_000_000, 1, 1, token)],
            None, &matcher_spk(), 0, Some(2000),
        );
        assert!(matches!(r, Err(BatchError::UnsupportedVersion { .. })), "v14 buy over v18 sell must reject, got {:?}", r);
    }

    /// OCO sweep enablement: a v18 OCO sell composes into a MULTI-sell v18
    /// sweep (the pre-v18 OcoMultiSellSweepUnsupported guard does not apply),
    /// and build_tx emits the executing branch's attested TP sigscript.
    #[test]
    fn test_v18_oco_multi_sell_sweep_allowed() {
        let token = [0x55; 32];
        let sells = vec![
            make_sell_v18(0x10, 10_000_000, 99, 100, token),
            // TP is the cheap (crossing) branch here; SL parked at 1/2.
            make_oco_sell_v18(0x11, 10_000_000, (99, 100), (1, 2), kob_core::OcoPath::TakeProfit, token),
        ];
        let buys = vec![make_buy_v18(0x20, 20_000_000, 1, 1, token, 2000)];
        let wallet = Some((hex::encode([0x99u8; 32]), 0u32, 5_000_000u64));
        let plan = plan_batch_match(&sells, &buys, wallet, &matcher_spk(), 0, Some(2000))
            .expect("v18 multi-sell sweep with an OCO term must plan");
        let tx = plan.build_tx().expect("build_tx");
        let oco_rs = &plan.sells[1].0.redeem_script;
        assert_eq!(
            tx.inputs[1].sigscript,
            kob_core::contract::spot::oco::build_oco_sell_v18_tp_fill_sigscript(
                plan.sell_output_idx[1] as u16, 99, 100, oco_rs,
            ),
            "OCO TP term must use the v18 attested TP fill sigscript"
        );
    }

    /// OCO branch attestation correctness: an SL-path OCO order attests the
    /// SL pair at the canonical offsets (and NOT the TP pair).
    #[test]
    fn test_v18_oco_sl_branch_attests_sl_price() {
        let token = [0x56; 32];
        let oco = make_oco_sell_v18(0x10, 10_000_000, (3, 1), (99, 100), kob_core::OcoPath::StopLoss, token);
        let oco_rs = oco.redeem_script.clone();
        let sells = vec![oco];
        // Buy limit at the SL rate (1:1 on the delivered 10M tokens for 9.9M KAS).
        let buys = vec![make_buy_v18(0x20, 9_900_000, 100, 99, token, 2000)];
        let wallet = Some((hex::encode([0x99u8; 32]), 0u32, 5_000_000u64));
        let plan = plan_batch_match(&sells, &buys, wallet, &matcher_spk(), 0, Some(2000))
            .expect("solo v18 OCO SL sweep must plan");
        let tx = plan.build_tx().expect("build_tx");
        let ss = &tx.inputs[0].sigscript;
        assert_eq!(
            ss,
            &kob_core::contract::spot::oco::build_oco_sell_v18_sl_fill_sigscript(0, 99, 100, &oco_rs),
            "SL fill must be the v18 attested SL sigscript"
        );
        // The attested pair at the canonical offsets is the SL pair...
        assert_eq!(&ss[3..11], &99u64.to_le_bytes(), "pnum_sl attested at [3..11)");
        assert_eq!(&ss[12..20], &100u64.to_le_bytes(), "pden_sl attested at [12..20)");
        // ...and the selector is Op2 (SL fill), not Op1 (TP).
        assert_eq!(ss[20], 0x52, "selector byte must be Op2 = SL fill");
        assert_ne!(
            ss,
            &kob_core::contract::spot::oco::build_oco_sell_v18_tp_fill_sigscript(0, 3, 1, &oco_rs),
            "must not attest the TP pair"
        );
    }

    /// v18 IOC sweep: 3 crossing sells, buy affords 2; leftover KAS is
    /// accounted (buyer change and/or capped matcher surplus).
    #[test]
    fn test_v18_ioc_sweep_with_change() {
        let token = [0x57; 32];
        let sell1 = make_sell_v18(0x10, 3_000_000, 1, 1, token);
        let sell2 = make_sell_v18(0x11, 3_000_000, 1, 1, token);
        let sell3 = make_sell_v18(0x12, 5_000_000, 1, 1, token);
        let buy = make_buy_v18(0x20, 7_000_000, 1, 1, token, 2000);
        let wallet = Some((hex::encode([0x99u8; 32]), 0u32, 5_000_000u64));

        let plan = plan_ioc_match_v18(&[sell1, sell2, sell3], &buy, wallet, &matcher_spk(), 0, Some(2000))
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
            build_buy_v18_fill_sigscript(&[0, 1], true, &plan.buys[0].0.redeem_script),
        );
    }

    /// v18 IOC floor: total delivered tokens below the buy's own min_fill
    /// rejects (mirrors the contract's ioc_flag ? mfill : expected floor).
    #[test]
    fn test_v18_ioc_below_min_fill_rejected() {
        let token = [0x58; 32];
        let sell1 = make_sell_v18(0x10, 3_000_000, 1, 1, token);
        let mut buy = make_buy_v18(0x20, 3_000_000, 1, 1, token, 2000);
        buy.min_fill = 50_000_000;
        let r = plan_ioc_match_v18(&[sell1], &buy, None, &matcher_spk(), 0, Some(2000));
        assert!(matches!(r, Err(BatchError::MinFillViolation { .. })), "below-min_fill IOC must reject, got {:?}", r);
    }

    /// Non-v18 buy handed to the v18 IOC planner rejects explicitly.
    #[test]
    fn test_v18_ioc_rejects_non_v18_buy() {
        let token = [0x59; 32];
        let sell1 = make_sell_v18(0x10, 3_000_000, 1, 1, token);
        let buy = make_buy(0x20, 3_000_000, 1, 1, token); // v14
        let r = plan_ioc_match_v18(&[sell1], &buy, None, &matcher_spk(), 0, Some(2000));
        assert!(matches!(r, Err(BatchError::UnsupportedVersion { .. })), "non-v18 buy must reject, got {:?}", r);
    }

    /// v18 IOC sweep caps at MAX_N even when more sells cross and are
    /// affordable.
    #[test]
    fn test_v18_ioc_sweep_capped_at_max_n() {
        let token = [0x5a; 32];
        let n_max = BUY_ORDER_V18_MAX_N;
        let sells: Vec<BatchOrder> = (0..(n_max as u8 + 2))
            .map(|i| make_sell_v18(0x50 + i, 5_000_000, 1, 1, token))
            .collect();
        // Affords more than MAX_N sells (41M vs 8*5M) but must cap; the
        // 1M leftover stays within the 2000bps on-chain cap (8.2M).
        let buy = make_buy_v18(0x20, 41_000_000, 1, 1, token, 2000);
        let wallet = Some((hex::encode([0x99u8; 32]), 0u32, 5_000_000u64));
        let plan = plan_ioc_match_v18(&sells, &buy, wallet, &matcher_spk(), 0, Some(2000))
            .expect("must plan (capped, not error)");
        assert_eq!(plan.sells.len(), n_max, "sweep must cap at MAX_N");
    }

    /// v18 IOC cap feasibility: the contract's surplus cap reads the FULL
    /// kas_in, so a sweep leaving more unswept KAS than mmfee_bps allows is
    /// rejected at plan time instead of failing on-chain.
    #[test]
    fn test_v18_ioc_cap_infeasible_rejected() {
        let token = [0x5b; 32];
        let sell1 = make_sell_v18(0x10, 3_000_000, 1, 1, token);
        // mmfee 30bps: allowance = 30M/10000*30 = 90k << 27M leftover.
        let buy = make_buy_v18(0x20, 30_000_000, 1, 1, token, 30);
        let wallet = Some((hex::encode([0x99u8; 32]), 0u32, 5_000_000u64));
        let r = plan_ioc_match_v18(&[sell1], &buy, wallet, &matcher_spk(), 0, Some(2000));
        assert!(matches!(r, Err(BatchError::V18CapInfeasible { .. })), "over-cap IOC sweep must reject, got {:?}", r);
    }

    /// Item C: v18 partial residual accounting. spent = kas_in - residual;
    /// the residual output is the buy's own P2SH with NO covenant binding;
    /// build_tx emits the Op2 sigscript with the residual output index.
    #[test]
    fn test_v18_partial_residual_accounting() {
        let token = [0x5c; 32];
        let sells = vec![make_sell_v18(0x10, 10_000_000, 99, 100, token)];
        let buy = make_buy_v18(0x20, 30_000_000, 1, 1, token, 2000);
        let buy_p2sh = kob_core::p2sh::build_p2sh(&buy.redeem_script);
        let wallet = Some((hex::encode([0x99u8; 32]), 0u32, 5_000_000u64));
        let plan = plan_partial_match_v18(&sells, &buy, wallet, &matcher_spk(), 0, None)
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
            build_buy_v18_partial_fill_sigscript(&[0], residual_idx, &plan.buys[0].0.redeem_script),
            "buy must use the v18 Op2 partial sigscript"
        );
    }

    /// Item C chaining: the residual UTXO is a normal v18 buy again (same
    /// RS, same P2SH). Plan a second partial event on it.
    #[test]
    fn test_v18_partial_chaining_two_events() {
        let token = [0x5d; 32];
        let wallet = Some((hex::encode([0x99u8; 32]), 0u32, 5_000_000u64));

        // Event 1: 30M buy spends 10M against a 10M-token sell, keeps 20M.
        let buy1 = make_buy_v18(0x20, 30_000_000, 1, 1, token, 2000);
        let plan1 = plan_partial_match_v18(
            &[make_sell_v18(0x10, 10_000_000, 99, 100, token)],
            &buy1, wallet.clone(), &matcher_spk(), 0, None,
        ).expect("event 1 must plan");
        let &(spent1, ri1, _) = plan1.buy_partial_fills.get(&0).unwrap();
        let residual1 = plan1.outputs[ri1 as usize].value;
        assert_eq!(residual1, buy1.utxo_value - spent1);
        assert_eq!(residual1, 20_000_000);

        // Event 2: the residual (same RS => same P2SH continuation) is the
        // new buy UTXO, spends 15M against a 15M-token sell, keeps 5M.
        let mut buy2 = make_buy_v18(0x21, residual1, 1, 1, token, 2000);
        buy2.redeem_script = buy1.redeem_script.clone(); // byte-exact continuation
        let plan2 = plan_partial_match_v18(
            &[make_sell_v18(0x11, 15_000_000, 99, 100, token)],
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
    fn test_v18_partial_mfill_floor_rejected() {
        let token = [0x5e; 32];
        let sells = vec![make_sell_v18(0x10, 10_000_000, 99, 100, token)];
        let mut buy = make_buy_v18(0x20, 30_000_000, 1, 1, token, 2000);
        buy.min_fill = 50_000_000; // event delivers only 10M tokens
        let r = plan_partial_match_v18(&sells, &buy, None, &matcher_spk(), 0, None);
        assert!(matches!(r, Err(BatchError::MinFillViolation { .. })), "sub-mfill partial event must reject, got {:?}", r);
    }

    /// Cap feasibility: with mmfee_bps = 0 and a sell whose integer-rounding
    /// gap (seller_kas - contract fair_sum) is positive, even a zero-surplus
    /// partial cannot satisfy the contract cap -> reject at plan time.
    #[test]
    fn test_v18_partial_cap_infeasible_rejected() {
        let token = [0x5f; 32];
        // amount=10_000_005 @ 3/10: seller_kas = floor(30_000_015/10) = 3_000_001,
        // fair_sum = floor(10_000_005/10)*3 = 3_000_000 -> gap = 1 > allowance 0.
        let sells = vec![make_sell_v18(0x10, 10_000_005, 3, 10, token)];
        let buy = make_buy_v18(0x20, 30_000_000, 1, 1, token, 0);
        let r = plan_partial_match_v18(&sells, &buy, None, &matcher_spk(), 0, None);
        assert!(matches!(r, Err(BatchError::V18CapInfeasible { .. })), "rounding gap > 0bps allowance must reject, got {:?}", r);
    }

    /// A "partial" that would leave no relayable residual must use the full
    /// fill planners instead (Op2 demands residual >= 1; dust is unbookable).
    #[test]
    fn test_v18_partial_no_residual_room_rejected() {
        let token = [0x60; 32];
        let sells = vec![make_sell_v18(0x10, 10_000_000, 1, 1, token)];
        let buy = make_buy_v18(0x20, 11_000_000, 1, 1, token, 2000);
        let r = plan_partial_match_v18(&sells, &buy, None, &matcher_spk(), 0, None);
        assert!(matches!(r, Err(BatchError::OutputBelowMinimum { .. })), "sub-MIN_UTXO residual must reject, got {:?}", r);
    }

    /// v18 sell-IOC parity: exact-consume settles GTC (Op1 both sides).
    #[test]
    fn test_v18_sell_ioc_exact_full_fill_plans() {
        let token = [0x61; 32];
        let sell = make_sell_v18(0x10, 10_000_000, 1, 1, token);
        let buys = vec![make_buy_v18(0x20, 10_000_000, 1, 1, token, 2000)];
        let wallet = Some((hex::encode([0x99u8; 32]), 0u32, 5_000_000u64));
        let plan = plan_sell_ioc_match_v18(&sell, &buys, wallet, &matcher_spk(), 0, Some(2000))
            .expect("exact-consume sell IOC must plan");
        assert_eq!(plan.ioc_mode, None, "exact match settles GTC");
        assert_eq!(plan.buy_sweep_sells, vec![vec![0u16]]);
        plan.validate().expect("plan must balance");
        let tx = plan.build_tx().expect("build_tx");
        assert_eq!(
            tx.inputs[0].sigscript,
            kob_core::contract::spot::order::build_sell_v18_fill_sigscript(0, 1, 1, &plan.sells[0].0.redeem_script),
        );
        assert_eq!(
            tx.inputs[1].sigscript,
            build_buy_v18_fill_sigscript(&[0], false, &plan.buys[0].0.redeem_script),
        );
    }

    /// v18 sell-IOC parity: a larger buy absorbs the sell via its IOC
    /// selector; leftover recoverable only within the buy's mmfee cap.
    #[test]
    fn test_v18_sell_ioc_larger_buy_settles_ioc() {
        let token = [0x62; 32];
        let sell = make_sell_v18(0x10, 10_000_000, 1, 1, token);
        // 12M buy: leftover 2M <= floor(12M/10000)*2000 = 2.4M -> feasible.
        let buys = vec![make_buy_v18(0x20, 12_000_000, 1, 1, token, 2000)];
        let wallet = Some((hex::encode([0x99u8; 32]), 0u32, 5_000_000u64));
        let plan = plan_sell_ioc_match_v18(&sell, &buys, wallet, &matcher_spk(), 0, Some(2000))
            .expect("larger-buy sell IOC must plan");
        assert_eq!(plan.ioc_mode, Some(IocSide::Buy));
        let tx = plan.build_tx().expect("build_tx");
        assert_eq!(
            tx.inputs[1].sigscript,
            build_buy_v18_fill_sigscript(&[0], true, &plan.buys[0].0.redeem_script),
            "buy must use the Op5 IOC selector"
        );
    }

    /// v18 sell-IOC structural rejection: a smaller buy would leave a sell
    /// residual, which cannot coexist with a v18 buy in one tx (the buy
    /// reads the sell's auth slot 0 as its delivery; the sell's IOC F4
    /// demands the same slot for its self-SPK residual).
    #[test]
    fn test_v18_sell_ioc_residual_rejected() {
        let token = [0x63; 32];
        let sell = make_sell_v18(0x10, 20_000_000, 1, 1, token);
        let buys = vec![make_buy_v18(0x20, 10_000_000, 1, 1, token, 2000)];
        let r = plan_sell_ioc_match_v18(&sell, &buys, None, &matcher_spk(), 0, Some(2000));
        assert!(
            matches!(r, Err(BatchError::V18SellResidualUnsupported { .. })),
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
        let rs = kob_core::contract::spot::swap::build_swap_v18_redeem_script(
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
            kob_core::contract::spot::swap::build_swap_v18_fill_sigscript(1, 1, &legs[0].redeem_script),
        );
        assert_eq!(
            tx.inputs[1].sigscript,
            kob_core::contract::spot::swap::build_swap_v18_fill_sigscript(0, 0, &legs[1].redeem_script),
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

        let legs: Vec<RingLegOrder> = (0..4u8)
            .map(|i| make_ring_leg(0x20 + i, [i; 32], [i + 1; 32], 10_000_000, 10_000_000, 100, 0xF0 + i))
            .collect();
        let r = plan_ring_match(&legs, wallet, &matcher_spk(), 0);
        assert!(matches!(r, Err(BatchError::RingLegCount { count: 4 })), "4 legs must reject, got {:?}", r);
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

    // Test 1: Simple same-pair batch (2 sells + 2 buys of same token)
    #[test]
    fn test_simple_same_pair_batch() {
        // Sell 10M Token A at price 1/2 => expects 5M KAS each
        let sell1 = make_sell(0x10, 10_000_000, 1, 2, TOKEN_A);
        let sell2 = make_sell(0x11, 10_000_000, 1, 2, TOKEN_A);

        // Buy 10M KAS for Token A at price 1/3 => expects ~3.33M tokens each
        // Buy utxo_value = 10M KAS, seller expects 5M KAS per sell
        // Surplus per sell-buy pair: 10M - 5M = 5M
        let buy1 = make_buy(0x20, 10_000_000, 1, 3, TOKEN_A);
        let buy2 = make_buy(0x21, 10_000_000, 1, 3, TOKEN_A);

        let plan = plan_batch_match(
            &[sell1, sell2],
            &[buy1, buy2],
            None,
            &matcher_spk(),
            0,
            None,
        ).expect("plan should succeed");

        // 2 sells + 2 buys = 4 orders
        assert_eq!(plan.sells.len(), 2, "should have 2 sells");
        assert_eq!(plan.buys.len(), 2, "should have 2 buys");
        // Input indices: sell[0]=0, sell[1]=1, buy[0]=2, buy[1]=3
        assert_eq!(plan.sells[0].1, 0);
        assert_eq!(plan.sells[1].1, 1);
        assert_eq!(plan.buys[0].1, 2);
        assert_eq!(plan.buys[1].1, 3);

        // Outputs are MERGED by (spk, spk_version) — both sells share the same
        // counterparty_spk (0xDD), and both buys share (0xEE) + TOKEN_A, so:
        //   outputs[0] = merged SellerKas = 5M + 5M = 10M
        //   outputs[1] = merged BuyerTokens = 3_333_333 + 3_333_333 = 6_666_666
        //   (+ sell_remainder / matcher_fee as appropriate)
        assert!(plan.outputs.len() >= 2, "at least 2 merged order outputs");
        assert_eq!(plan.outputs[0].purpose, OutputPurpose::SellerKas);
        assert_eq!(plan.outputs[1].purpose, OutputPurpose::BuyerTokens);

        // Merged seller KAS: 5M + 5M = 10M (same counterparty SPK)
        assert_eq!(plan.outputs[0].value, 10_000_000);

        // Merged buyer tokens: 3_333_333 * 2 = 6_666_666 (same token, same SPK)
        assert_eq!(plan.outputs[1].value, 6_666_666);

        // Verify merge-index mapping: both sells -> output 0, both buys -> output 1, coi=0
        assert_eq!(plan.sell_output_idx, vec![0, 0]);
        assert_eq!(plan.buy_output_idx, vec![1, 1]);
        assert_eq!(plan.buy_coi, vec![0, 0]);

        // Build TX and verify
        let tx = plan.build_tx().expect("build_tx should succeed");
        assert_eq!(tx.inputs.len(), 4, "2 sells + 2 buys (no token_unit)");
    }

    // Test 2: Cross-pair batch requires matching sell for each buy's token.
    // sell A + buy B (different tokens) should FAIL (no sell provides token B).
    #[test]
    fn test_cross_pair_fails_without_matching_sell() {
        let sell = make_sell(0x10, 20_000_000, 1, 2, TOKEN_A);
        let buy = make_buy(0x20, 15_000_000, 1, 3, TOKEN_B);

        let result = plan_batch_match(
            &[sell],
            &[buy],
            None,
            &matcher_spk(),
            0,
            None,
        );
        assert!(result.is_err(), "cross-pair without matching sell should fail");
    }

    // Test 3: Multi-pair batch (sell A + sell B + buy B + buy A + tokens)
    #[test]
    fn test_multi_pair_batch() {
        // Sell 20M Token A at price 1/2 => expects 10M KAS
        let sell_a = make_sell(0x10, 20_000_000, 1, 2, TOKEN_A);
        // Sell 30M Token B at price 1/3 => expects 10M KAS
        let sell_b = make_sell(0x11, 30_000_000, 1, 3, TOKEN_B);

        // Buy Token B with 15M KAS at price 1/3 => expects 5M Token B
        let buy_b = make_buy(0x20, 15_000_000, 1, 3, TOKEN_B);
        // Buy Token A with 15M KAS at price 1/3 => expects 5M Token A
        let buy_a = make_buy(0x21, 15_000_000, 1, 3, TOKEN_A);

        let plan = plan_batch_match(
            &[sell_a, sell_b],
            &[buy_b, buy_a],
            None,
            &matcher_spk(),
            0,
            None,
        ).expect("plan should succeed");

        // 2 sells + 2 buys
        assert_eq!(plan.sells.len(), 2);
        assert_eq!(plan.buys.len(), 2);
        

        // Input layout: sell_a=0, sell_b=1, buy_b=2, buy_a=3
        assert_eq!(plan.sells[0].1, 0);
        assert_eq!(plan.sells[1].1, 1);
        assert_eq!(plan.buys[0].1, 2);
        assert_eq!(plan.buys[1].1, 3);

        // Outputs are MERGED by (spk, spk_version). Both sells share 0xDD SPK
        // so they merge to a single SellerKas output. Buyers share 0xEE SPK but
        // have different token_cov_id (TOKEN_A vs TOKEN_B) so they stay separate.
        //   outputs[0] = merged SellerKas (sell_a + sell_b = 10M + 10M = 20M)
        //   outputs[1] = BuyerTokens (buy_b, TOKEN_B, 5M)
        //   outputs[2] = BuyerTokens (buy_a, TOKEN_A, 5M)
        assert!(plan.outputs.len() >= 3, "at least 3 merged outputs");
        assert_eq!(plan.outputs[0].purpose, OutputPurpose::SellerKas);
        assert_eq!(plan.outputs[1].purpose, OutputPurpose::BuyerTokens);
        assert_eq!(plan.outputs[2].purpose, OutputPurpose::BuyerTokens);

        // Both sells merged into output 0
        assert_eq!(plan.sell_output_idx, vec![0, 0]);
        // Buys keep separate outputs because of distinct token_cov_id
        assert_eq!(plan.buy_output_idx, vec![1, 2]);

        // Build TX
        let tx = plan.build_tx().expect("build should succeed");
        assert_eq!(tx.inputs.len(), 4, "2 sells + 2 buys (no token_unit)");
    }

    // Test 4: Batch plan validation
    #[test]
    fn test_batch_plan_validation() {
        let sell = make_sell(0x10, 10_000_000, 1, 2, TOKEN_A);
        let buy = make_buy(0x20, 10_000_000, 1, 3, TOKEN_A);

        let plan = plan_batch_match(
            &[sell],
            &[buy],
            None,
            &matcher_spk(),
            0,
            None,
        ).expect("plan should succeed");

        // Validate should pass
        let result = plan.validate();
        assert!(result.is_ok(), "valid plan should pass validation: {:?}", result.err());
    }

    // Test 5: Sigscript indices verification
    #[test]
    fn test_sigscript_indices() {
        // Build a small batch to verify sigscript byte encoding
        let sell = make_sell(0x10, 10_000_000, 1, 2, TOKEN_A);
        let buy = make_buy(0x20, 10_000_000, 1, 3, TOKEN_A);

        let plan = plan_batch_match(
            &[sell],
            &[buy],
            None,
            &matcher_spk(),
            0,
            None,
        ).expect("plan should succeed");

        let tx = plan.build_tx().expect("build should succeed");

        // Sell at input[0]: koi=0, sigscript starts with Op0=0x00
        let sell_ss = &tx.inputs[0].sigscript;
        assert_eq!(sell_ss[0], 0x00, "sell koi=0 -> Op0 (0x00)");
        assert_eq!(sell_ss[1], 0x08, "sell IOC: fta push opcode (0x08)");

        // Buy v13 at input[1]: toi=1, tii=0 (sell input), coi=0, selector=Op1
        let buy_ss = &tx.inputs[1].sigscript;
        assert_eq!(buy_ss[0], 0x51, "buy toi=1 -> Op1 (0x51)");
        assert_eq!(buy_ss[1], 0x00, "buy tii=0 -> Op0 (sell input provides covenant)");
        assert_eq!(buy_ss[2], 0x00, "buy coi=0 -> Op0 (0x00)");
        assert_eq!(buy_ss[3], 0x51, "buy selector=1 -> Op1 (0x51)");
    }

    // Test 6: Large batch (10 sells + 10 buys -> no longer limited by OpN)
    #[test]
    fn test_large_batch() {
        // With 10 sells + 10 buys = 20 orders, indices >16 use data-push encoding.
        // This should now succeed (no OpN limit).
        let sells: Vec<BatchOrder> = (0..10)
            .map(|i| make_sell(0x10 + i, 10_000_000, 1, 2, TOKEN_A))
            .collect();
        let buys: Vec<BatchOrder> = (0..10)
            .map(|i| make_buy(0x20 + i, 10_000_000, 1, 3, TOKEN_A))
            .collect();

        let plan = plan_batch_match(
            &sells,
            &buys,
            None,
            &matcher_spk(),
            0,
            None,
        ).expect("10+10 batch should succeed (no OpN limit)");

        assert_eq!(plan.sells.len(), 10);
        assert_eq!(plan.buys.len(), 10);

        let tx = plan.build_tx().expect("build should succeed");
        // 10 sells + 10 buys = 20 inputs (no token_unit)
        assert_eq!(tx.inputs.len(), 20);

        // Verify indices >16 use data-push encoding (2 bytes: [0x01, n])
        // Buy at input[20] (index 20) has toi = 10 + 10_pos = some index >= 10
        // Sell at input[0] has koi=0 (Op0=0x00, 1 byte)
        let sell0_ss = &tx.inputs[0].sigscript;
        assert_eq!(sell0_ss[0], 0x00, "sell koi=0 -> Op0 (0x00)");

        // 7+7 should still work
        let sells7: Vec<BatchOrder> = (0..7)
            .map(|i| make_sell(0x10 + i, 10_000_000, 1, 2, TOKEN_A))
            .collect();
        let buys7: Vec<BatchOrder> = (0..7)
            .map(|i| make_buy(0x20 + i, 10_000_000, 1, 3, TOKEN_A))
            .collect();

        let plan = plan_batch_match(
            &sells7,
            &buys7,
            None,
            &matcher_spk(),
            0,
            None,
        ).expect("7+7 batch should succeed");

        assert_eq!(plan.sells.len(), 7);
        assert_eq!(plan.buys.len(), 7);

        let tx = plan.build_tx().expect("build should succeed");
        // 7 sells + 7 buys = 14 inputs (no token_unit)
        assert_eq!(tx.inputs.len(), 14);
    }

    // Test 7: Fee calculation
    #[test]
    fn test_fee_calculation() {
        // Sell 10M Token A at 1/2 => expects 5M KAS
        let sell = make_sell(0x10, 10_000_000, 1, 2, TOKEN_A);
        // Buy 10M KAS for Token A at 1/3 => expects 3.33M tokens
        let buy = make_buy(0x20, 10_000_000, 1, 3, TOKEN_A);

        let plan = plan_batch_match(
            &[sell],
            &[buy],
            None,
            &matcher_spk(),
            0,
            None,
        ).expect("plan should succeed");

        // Fee is computed from mass: 1 sell + 1 buy = 2 inputs,
        // 1 seller + 1 buyer + potential sell_remainder + matcher_fee = 4 outputs,
        // scaled by the post-Toccata min relay rate (100 sompi/gram).
        let expected_fee = kob_core::mass::min_relay_fee(
            kob_core::mass::estimate_compute_mass(2, 4, 0),
        );
        assert_eq!(plan.total_fee, expected_fee, "fee should match mass-based estimate");

        // KAS surplus = buy(10M) - seller_kas(5M) - fee
        
        let expected_surplus = 10_000_000 - 5_000_000 - expected_fee;
        assert_eq!(plan.matcher_surplus, expected_surplus);

        // Verify matcher fee output exists
        let matcher_out = plan.outputs.iter()
            .find(|o| o.purpose == OutputPurpose::MatcherFee);
        assert!(matcher_out.is_some(), "should have matcher fee output");
        assert_eq!(matcher_out.unwrap().value, expected_surplus);
    }

    // Test 8: version validation (v14 only)
    #[test]
    fn test_version_validation() {
        // v14 sell + v14 buy should be accepted (default from make_sell/make_buy)
        let sell = make_sell(0x10, 10_000_000, 1, 2, TOKEN_A);
        let buy = make_buy(0x20, 10_000_000, 1, 3, TOKEN_A);

        let result = plan_batch_match(
            &[sell],
            &[buy],
            None,
            &matcher_spk(),
            0,
            None,
        );
        assert!(result.is_ok(), "v14 sell+buy should be accepted: {:?}", result.err());

        // non-v14 sell should be rejected
        let mut sell_old = make_sell(0x10, 10_000_000, 1, 2, TOKEN_A);
        sell_old.version = 13;

        let result2 = plan_batch_match(
            &[sell_old],
            &[make_buy(0x20, 10_000_000, 1, 3, TOKEN_A)],
            None,
            &matcher_spk(),
            0,
            None,
        );
        assert!(result2.is_err(), "v13 sell should be rejected");
        match result2.unwrap_err() {
            BatchError::UnsupportedVersion { version, .. } => assert_eq!(version, 13),
            e => panic!("expected UnsupportedVersion, got: {:?}", e),
        }

        // non-v14 buy should be rejected
        let mut buy_old = make_buy(0x20, 10_000_000, 1, 3, TOKEN_A);
        buy_old.version = 13;

        let result3 = plan_batch_match(
            &[make_sell(0x10, 10_000_000, 1, 2, TOKEN_A)],
            &[buy_old],
            None,
            &matcher_spk(),
            0,
            None,
        );
        assert!(result3.is_err(), "v13 buy should be rejected");
        match result3.unwrap_err() {
            BatchError::UnsupportedVersion { version, .. } => assert_eq!(version, 13),
            e => panic!("expected UnsupportedVersion, got: {:?}", e),
        }
    }

    // Test 9: Outputs below MIN_UTXO_VALUE are rejected
    #[test]
    fn test_min_utxo_filter() {
        // Sell 3M tokens at price 1/10 => expects 300K KAS (below MIN_UTXO_VALUE=3M)
        let sell = make_sell(0x10, 3_000_000, 1, 10, TOKEN_A);
        let buy = make_buy(0x20, 10_000_000, 1, 3, TOKEN_A);

        let result = plan_batch_match(
            &[sell],
            &[buy],
            None,
            &matcher_spk(),
            0,
            None,
        );

        assert!(result.is_err(), "output below MIN_UTXO_VALUE should be rejected");
        match result.unwrap_err() {
            BatchError::OutputBelowMinimum { value, .. } => {
                assert!(value < MIN_UTXO_VALUE, "value {} should be below {}", value, MIN_UTXO_VALUE);
            }
            e => panic!("expected OutputBelowMinimum, got: {:?}", e),
        }

        // Also test buy side: buy 3M KAS at price 1/10 => expects 300K tokens
        let sell2 = make_sell(0x10, 10_000_000, 1, 2, TOKEN_A);
        let buy2 = make_buy(0x20, 3_000_000, 1, 10, TOKEN_A);

        let result2 = plan_batch_match(
            &[sell2],
            &[buy2],
            None,
            &matcher_spk(),
            0,
            None,
        );

        assert!(result2.is_err(), "buyer token output below MIN_UTXO_VALUE should be rejected");
    }

    // Additional: wallet input for fee coverage
    #[test]
    fn test_wallet_input_for_fees() {
        // Sell 10M Token A at 1/1 => expects 10M KAS
        let sell = make_sell(0x10, 10_000_000, 1, 1, TOKEN_A);
        // Buy 10M KAS for Token A at 1/1 => expects 10M tokens
        let buy = make_buy(0x20, 10_000_000, 1, 1, TOKEN_A);

        // Without wallet: sell(10M) + buy(10M) at 1/1.
        // seller_kas=10M, buyer_tokens=10M. total_in=20M, total_out=20M.
        // No surplus for fee -> needs wallet. Skip no-wallet test for 1:1 price.

        // With wallet UTXO: should succeed

        // With wallet UTXO: should also succeed, with wallet as extra input
        let wallet = ("ff".repeat(32), 0, 5_000_000);
        let plan = plan_batch_match(
            &[sell],
            &[buy],
            Some(wallet),
            &matcher_spk(),
            0,
            None,
        ).expect("should succeed with wallet UTXO");

        assert!(plan.wallet_input.is_some());
        let tx = plan.build_tx().expect("build should succeed");
        // 1 sell + 1 buy + 1 wallet = 3 inputs (no token_unit)
        assert_eq!(tx.inputs.len(), 3);
        // Wallet input has sig_op_count=1
        assert_eq!(tx.inputs[2].sig_op_count, 1);
    }

    // Additional: missing token unit
    #[test]
    fn test_missing_token_unit() {
        let sell = make_sell(0x10, 10_000_000, 1, 2, TOKEN_A);
        let buy = make_buy(0x20, 10_000_000, 1, 3, TOKEN_B); // needs Token B
        // Only provide Token A unit, not Token B

        let result = plan_batch_match(
            &[sell],
            &[buy],
            None,
            &matcher_spk(),
            0,
            None,
        );

        assert!(result.is_err(), "missing token unit should fail");
        match result.unwrap_err() {
            BatchError::MissingTokenUnit { .. } => {}
            e => panic!("expected MissingTokenUnit, got: {:?}", e),
        }
    }

    // H-2: coi > 16 now handled by data-push encoding (no error)
    #[test]
    fn test_large_coi_succeeds() {
        // With data-push encoding, coi > 16 is no longer an error.
        // 7 sells + 7 buys = 14 inputs, coi stays 0..6.
        let sells: Vec<BatchOrder> = (0..7)
            .map(|i| make_sell(0x10 + i, 10_000_000, 1, 2, TOKEN_A))
            .collect();
        let buys: Vec<BatchOrder> = (0..7)
            .map(|i| make_buy(0x20 + i, 10_000_000, 1, 3, TOKEN_A))
            .collect();

        let plan = plan_batch_match(
            &sells,
            &buys,
            None,
            &matcher_spk(),
            0,
            None,
        ).expect("7+7 batch should succeed");

        let tx = plan.build_tx().expect("build_tx should succeed");
        assert_eq!(tx.inputs.len(), 14);
    }

    // Additional: verify build_tx sigscript sizes match v8 expectations
    #[test]
    fn test_sigscript_sizes() {
        let sell = make_sell(0x10, 10_000_000, 1, 2, TOKEN_A);
        let buy = make_buy(0x20, 10_000_000, 1, 3, TOKEN_A);

        let plan = plan_batch_match(
            &[sell],
            &[buy],
            None,
            &matcher_spk(),
            0,
            None,
        ).expect("plan should succeed");

        let tx = plan.build_tx().expect("build should succeed");

        // Sell v14 IOC fill SS: [Op(koi)] [push8(fta)] [Op5] [PUSHDATA2(2)] [427B RS]
        // = 1 + 9 + 1 + 3 + 427 = 441 bytes (IOC mode: sell excess > 0)
        let sell_ss_len = tx.inputs[0].sigscript.len();
        assert_eq!(sell_ss_len, 441, "sell_v14 IOC fill SS = 441B");

        // Buy v14 fill SS: [Op(toi)] [Op(tii)] [Op(coi)] [Op1] [PUSHDATA2(2)] [396B RS]
        // = 1 + 1 + 1 + 1 + 3 + 396 = 403 bytes
        let buy_ss_len = tx.inputs[1].sigscript.len();
        assert_eq!(buy_ss_len, 403, "buy_v14 fill SS = 403B");
    }

    // Test: zero price denominator is rejected
    #[test]
    fn batch_zero_price_denominator_sell() {
        // Construct a sell order with price_den = 0 directly (bypassing make_sell
        // which asserts price_den > 0 in the RS builder).
        let sell = BatchOrder {
            outpoint: (hex::encode([0x10u8; 32]), 0),
            order_type: OrderType::Sell,
            version: 14,
            token_cov_id: TOKEN_A,
            price_num: 1,
            price_den: 0, // <-- zero denominator
            amount: 10_000_000,
            redeem_script: vec![0x00; 10], // dummy RS (won't reach sigscript build)
            utxo_value: 10_000_000,
            counterparty_spk: vec![0xDD; 34],
            counterparty_spk_version: 0,
            min_fill: 1_000_000,
            oco_path: None,
            bracket_meta: None,
        };
        let buy = make_buy(0x20, 10_000_000, 1, 3, TOKEN_A);

        let result = plan_batch_match(
            &[sell],
            &[buy],
            None,
            &matcher_spk(),
            0,
            None,
        );
        match result {
            Err(BatchError::ZeroPriceDenominator { index: 0, side: "sell" }) => {} // expected
            other => panic!("expected ZeroPriceDenominator for sell, got: {:?}", other),
        }
    }

    #[test]
    fn batch_zero_price_denominator_buy() {
        // Construct a buy order with price_den = 0 directly.
        let sell = make_sell(0x10, 10_000_000, 1, 2, TOKEN_A);
        let buy = BatchOrder {
            outpoint: (hex::encode([0x20u8; 32]), 0),
            order_type: OrderType::Buy,
            version: 14,
            token_cov_id: TOKEN_A,
            price_num: 1,
            price_den: 0, // <-- zero denominator
            amount: 10_000_000,
            redeem_script: vec![0x00; 10], // dummy RS
            utxo_value: 10_000_000,
            counterparty_spk: vec![0xEE; 34],
            counterparty_spk_version: 0,
            min_fill: 1_000_000,
            oco_path: None,
            bracket_meta: None,
        };

        let result = plan_batch_match(
            &[sell],
            &[buy],
            None,
            &matcher_spk(),
            0,
            None,
        );
        match result {
            Err(BatchError::ZeroPriceDenominator { index: 1, side: "buy" }) => {} // expected (index = n + j = 1 + 0)
            other => panic!("expected ZeroPriceDenominator for buy, got: {:?}", other),
        }
    }

    #[test]
    fn converge_fee_exact_reduces_overestimate() {
        // 1:1 batch with wallet fee UTXO
        let sell = make_sell(0x10, 50_000_000, 1, 1, TOKEN_A);
        let buy = make_buy(0x20, 50_000_000, 1, 1, TOKEN_A);
        let wallet = (hex::encode([0x40u8; 32]), 0u32, 100_000_000u64);

        let mut plan = plan_batch_match(
            &[sell],
            &[buy],
            Some(wallet),
            &matcher_spk(),
            0,
            None,
        ).unwrap();
        plan.validate().unwrap();

        let est_fee = plan.total_fee;
        assert!(est_fee > 0, "estimated fee must be positive");

        // Build Transaction and sigscripts from the plan
        let tx = plan.to_transaction();
        let batch_tx = plan.build_tx().unwrap();
        let mut sigscripts: Vec<Vec<u8>> = batch_tx.inputs.iter()
            .map(|i| i.sigscript.clone())
            .collect();

        // The wallet input (last) gets a fake 64-byte P2PK sigscript
        // (real Schnorr sig = 64 bytes + push opcode = 66 bytes total)
        let fake_wallet_ss = vec![0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0xac];
        *sigscripts.last_mut().unwrap() = fake_wallet_ss;

        // Phase 2: exact mass
        let (exact_fee, delta) = plan.converge_fee_exact(&tx, &sigscripts);
        assert!(exact_fee <= est_fee, "exact fee must be <= estimated fee");
        // delta is u64, always non-negative by type.
        assert_eq!(exact_fee + delta, est_fee, "exact + delta = estimated");

        // Apply and verify (no bps cap — delta goes to matcher)
        let old_surplus = plan.matcher_surplus;
        plan.apply_exact_fee(exact_fee);
        assert_eq!(plan.total_fee, exact_fee);
        // Surplus should increase by delta
        assert_eq!(plan.matcher_surplus, old_surplus + delta);
    }

    /// Isolates the Phase-1 estimate vs the real mass directly (bypassing
    /// `total_fee`, which for a generously-funded wallet input also absorbs
    /// uncapped matcher surplus and would otherwise mask an under-estimate).
    /// Checked at both N=1 (tightest margin: only 2 sig-op-bearing... inputs
    /// assumed vs 1 real) and N=MAX_N (largest buy sigscript).
    fn v17_fee_estimate_vs_real_mass_at_n(n: usize) -> (u64, u64) {
        let token = [0x49; 32];
        let sells: Vec<BatchOrder> = (0..n as u8)
            .map(|i| make_sell(0x70 + i, 5_000_000, 1, 1, token))
            .collect();
        let buys = vec![make_buy_v17(0x20, n as u64 * 5_000_000, 1, 1, token, 2000)];
        let wallet = (hex::encode(&[0x99u8; 32]), 0u32, 3_000_000u64);
        let plan = plan_batch_match(&sells, &buys, Some(wallet), &matcher_spk(), 0, Some(2000)).unwrap();

        let num_inputs = 1 + n + 1; // buy + n sells + wallet
        let num_outputs = plan.outputs.len();
        let est_mass = kob_core::mass::estimate_compute_mass(num_inputs, num_outputs, 0);

        let tx = plan.to_transaction();
        let batch_tx = plan.build_tx().unwrap();
        let mut sigscripts: Vec<Vec<u8>> = batch_tx.inputs.iter().map(|i| i.sigscript.clone()).collect();
        let fake_wallet_ss = vec![0x41u8; 66];
        *sigscripts.last_mut().unwrap() = fake_wallet_ss;
        let real_mass = kob_core::mass::calc_mass_with_sigscripts(&tx, &sigscripts);
        (est_mass, real_mass)
    }

    #[test]
    fn test_v17_max_n_fee_estimate_vs_real_mass() {
        let n = kob_core::contract::spot::order::BUY_ORDER_V17_MAX_N;
        let (est_mass, real_mass) = v17_fee_estimate_vs_real_mass_at_n(n);
        eprintln!("PROBE v17 N={n}: est_mass={est_mass} real_mass={real_mass}");
        assert!(
            real_mass <= est_mass,
            "v17 N={n}: real mass {real_mass} exceeds the Phase-1 estimate {est_mass} \
             -- estimate_compute_mass's ~100B/input sigscript assumption is blown by \
             the v17 buy's real (RS 838B + N tii pushes) sigscript -- Fix 5 under-pay"
        );
    }

    #[test]
    fn test_v17_n1_fee_estimate_vs_real_mass() {
        // N=1 has the tightest safety margin (fewest inputs to over-count
        // sig-ops on, relative to the buy's fixed ~850B sigscript cost).
        let (est_mass, real_mass) = v17_fee_estimate_vs_real_mass_at_n(1);
        eprintln!("PROBE v17 N=1: est_mass={est_mass} real_mass={real_mass}");
        assert!(
            real_mass <= est_mass,
            "v17 N=1: real mass {real_mass} exceeds the Phase-1 estimate {est_mass} -- Fix 5 under-pay"
        );
    }

    // Test: Phase 2 convergence respects bps cap
    #[test]
    fn converge_fee_exact_respects_bps_cap() {
        let sell = make_sell(0x10, 50_000_000, 1, 1, TOKEN_A);
        let buy = make_buy(0x20, 50_000_000, 1, 1, TOKEN_A);
        let wallet = (hex::encode([0x40u8; 32]), 0u32, 100_000_000u64);

        // bps = 7000 (70%) — cap matcher at 70% of trade value
        let mut plan = plan_batch_match(
            &[sell], &[buy], Some(wallet),
            &matcher_spk(), 0, Some(7000),
        ).unwrap();
        plan.validate().unwrap();

        let max_fee_bps = 50_000_000u64 * 7000 / 10000; // 35_000_000
        assert_eq!(plan.matcher_surplus, max_fee_bps,
            "Phase 1 surplus should be exactly bps cap");

        let _est_fee = plan.total_fee;
        let tx = plan.to_transaction();
        let batch_tx = plan.build_tx().unwrap();
        let mut sigscripts: Vec<Vec<u8>> = batch_tx.inputs.iter()
            .map(|i| i.sigscript.clone()).collect();
        let fake_wallet_ss = vec![0x41; 66];
        let _ = fake_wallet_ss.last(); // suppress unused warning
        *sigscripts.last_mut().unwrap() = vec![0x41; 66];

        let (exact_fee, delta) = plan.converge_fee_exact(&tx, &sigscripts);
        assert!(delta > 0, "Phase 2 should recover some fee");

        // Apply — matcher surplus must NOT exceed bps cap.
        plan.apply_exact_fee(exact_fee);
        assert_eq!(plan.matcher_surplus, max_fee_bps,
            "Phase 2 must not push surplus above bps cap");

        // With the matcher output already at its bps cap, the recovered delta
        // has nowhere to go on the matcher side. It must NOT be folded into the
        // seller (that made SellerKas exceed the buyer input and the covenant
        // rejected settlement) — it stays as miner fee instead.
        let seller_out = &plan.outputs[0];
        assert_eq!(seller_out.purpose, OutputPurpose::SellerKas);
        assert_eq!(seller_out.value, 50_000_000,
            "seller output must stay at its fair value (delta not folded in): {}", seller_out.value);
        // total_fee is unchanged (nothing recovered) — the delta is miner fee.
        assert_eq!(plan.total_fee, _est_fee,
            "un-recoverable delta stays as miner fee, so total_fee is unchanged");
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

    #[test]
    fn to_transaction_correct_input_output_count() {
        let sell = make_sell(0x10, 50_000_000, 1, 1, TOKEN_A);
        let buy = make_buy(0x20, 50_000_000, 1, 1, TOKEN_A);
        let wallet = (hex::encode([0x40u8; 32]), 0u32, 100_000_000u64);

        let plan = plan_batch_match(
            &[sell],
            &[buy],
            Some(wallet),
            &matcher_spk(),
            0,
            None,
        ).unwrap();

        let tx = plan.to_transaction();
        // 1 sell + 1 buy + 1 wallet = 3 inputs (no token_unit)
        assert_eq!(tx.inputs.len(), 3);
        // outputs = plan.outputs.len()
        assert_eq!(tx.outputs.len(), plan.outputs.len());
    }

    // Test: 20+20 batch (indices reach 39, well past old u8/OpN limits)
    #[test]
    fn test_20x20_large_batch() {
        let sells: Vec<BatchOrder> = (0..20u8)
            .map(|i| make_sell(i + 1, 10_000_000, 1, 2, TOKEN_A))
            .collect();
        let buys: Vec<BatchOrder> = (0..20u8)
            .map(|i| make_buy(0x80 + i, 10_000_000, 1, 3, TOKEN_A))
            .collect();

        let plan = plan_batch_match(
            &sells,
            &buys,
            None,
            &matcher_spk(),
            0,
            None,
        ).expect("20+20 batch should succeed");

        assert_eq!(plan.sells.len(), 20);
        assert_eq!(plan.buys.len(), 20);

        // Validate should pass (no index range cap)
        plan.validate().expect("20+20 plan should validate");

        let tx = plan.build_tx().expect("20+20 build_tx should succeed");
        // 20 sells + 20 buys = 40 inputs (no token_unit)
        assert_eq!(tx.inputs.len(), 40);
        // Merge: all 20 sells share counterparty 0xDD => 1 SellerKas output.
        // All 20 buys share TOKEN_A + counterparty 0xEE => 1 BuyerTokens output.
        // Plus sell_remainder (merged, 1) + matcher_fee (1) at most.
        let output_count = tx.outputs.len();
        assert!(output_count >= 2, "at least 2 merged outputs");
        assert!(output_count <= 4, "merge should collapse 40 outputs down to <=4");

        // All 20 sells point at the single merged seller output 0
        assert_eq!(plan.sell_output_idx, vec![0usize; 20]);
        // All 20 buys point at the single merged buyer output 1
        assert_eq!(plan.buy_output_idx, vec![1usize; 20]);
        // All share the same coi=0 for TOKEN_A
        assert_eq!(plan.buy_coi, vec![0u16; 20]);

        // Verify sell koi=0 uses Op0 (merged target)
        let sell19_ss = &tx.inputs[19].sigscript;
        assert_eq!(sell19_ss[0], 0x00, "sell koi=0 (merged target): Op0");

        // Buy[0] at input[20]: toi=1 (merged), tii=0, coi=0
        let buy0_ss = &tx.inputs[20].sigscript;
        // toi=1 -> Op1 (0x51)
        assert_eq!(buy0_ss[0], 0x51, "buy0 toi=1 (merged): Op1");
        // tii=0 -> Op0 (0x00)
        assert_eq!(buy0_ss[1], 0x00, "buy0 tii=0: Op0 (sell provides covenant)");
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

    // Test: bps cap limits matcher surplus
    #[test]
    fn test_bps_cap_limits_surplus() {
        // sell 5M at 1/1, buy 10M at 1/1
        // surplus (no cap) = buy_kas(10M) - seller_kas(5M) - fee ≈ 5M - fee
        let sell = make_sell(0x01, 5_000_000, 1, 1, TOKEN_A);
        let buy = make_buy(0x02, 10_000_000, 1, 1, TOKEN_A);
        let wallet = ("wallet".to_string(), 0, 5_000_000u64);

        // Without bps cap: matcher takes all surplus
        let plan_no_cap = plan_batch_match(
            &[sell.clone()], &[buy.clone()],
            Some(wallet.clone()), &matcher_spk(), 0, None,
        ).unwrap();
        assert!(plan_no_cap.matcher_surplus > 0, "without cap, surplus > 0");
        let no_cap_surplus = plan_no_cap.matcher_surplus;

        // With bps cap = 7000 (70%): max_fee = seller_kas(5M) * 7000 / 10000 = 3_500_000
        // Since surplus ≈ 5M > 3.5M, cap should take effect
        let plan_capped = plan_batch_match(
            &[sell.clone()], &[buy.clone()],
            Some(wallet.clone()), &matcher_spk(), 0, Some(7000),
        ).unwrap();
        let max_fee = 5_000_000u64 * 7000 / 10000; // 3_500_000
        assert_eq!(plan_capped.matcher_surplus, max_fee,
            "capped surplus should be exactly max_fee={}", max_fee);
        assert!(plan_capped.matcher_surplus < no_cap_surplus,
            "capped surplus {} < uncapped {}", plan_capped.matcher_surplus, no_cap_surplus);

        // Refund goes to buyer. It might be < MIN_UTXO_VALUE and get added to
        // buyer's token output as dust. Check that total output value is conserved.
        let total_out: u64 = plan_capped.outputs.iter().map(|o| o.value).sum();
        let total_out_no_cap: u64 = plan_no_cap.outputs.iter().map(|o| o.value).sum();
        // Both plans should have same total_out (value conservation), only
        // distribution differs (matcher gets less, buyer gets more).
        assert_eq!(total_out, total_out_no_cap,
            "total output value should be conserved regardless of bps cap");
    }

    // Test: bps cap with zero bps means matcher gets nothing
    #[test]
    fn test_bps_zero_returns_all_to_buyer() {
        let sell = make_sell(0x01, 5_000_000, 1, 1, TOKEN_A);
        let buy = make_buy(0x02, 10_000_000, 1, 1, TOKEN_A);
        let wallet = ("wallet".to_string(), 0, 5_000_000u64);

        let plan = plan_batch_match(
            &[sell], &[buy],
            Some(wallet), &matcher_spk(), 0, Some(0),
        ).unwrap();
        assert_eq!(plan.matcher_surplus, 0, "bps=0 means no matcher fee");
        let matcher_fee_out: Vec<&PlannedOutput> = plan.outputs.iter()
            .filter(|o| matches!(o.purpose, OutputPurpose::MatcherFee))
            .collect();
        assert!(matcher_fee_out.is_empty(), "no MatcherFee output with bps=0");
    }

    // Test: bps cap with high bps doesn't exceed actual surplus
    #[test]
    fn test_bps_high_value_no_excess() {
        let sell = make_sell(0x01, 5_000_000, 1, 1, TOKEN_A);
        let buy = make_buy(0x02, 10_000_000, 1, 1, TOKEN_A);
        let wallet = ("wallet".to_string(), 0, 5_000_000u64);

        // bps=10000 (100%) -> cap = total_seller_kas = 5M, which is >= surplus
        let plan_full = plan_batch_match(
            &[sell.clone()], &[buy.clone()],
            Some(wallet.clone()), &matcher_spk(), 0, Some(10000),
        ).unwrap();
        let plan_none = plan_batch_match(
            &[sell], &[buy],
            Some(wallet), &matcher_spk(), 0, None,
        ).unwrap();
        assert_eq!(plan_full.matcher_surplus, plan_none.matcher_surplus,
            "bps=100% should not reduce surplus below actual");
    }

    // Test: bps cap pro-rata across multiple buyers
    #[test]
    fn test_bps_cap_prorata_multi_buyer() {
        let sell1 = make_sell(0x01, 5_000_000, 1, 1, TOKEN_A);
        let sell2 = make_sell(0x02, 5_000_000, 1, 1, TOKEN_A);
        // buyer1: 7M KAS, buyer2: 3M KAS (7:3 ratio)
        let buy1 = make_buy(0x03, 7_000_000, 1, 1, TOKEN_A);
        let buy2 = make_buy(0x04, 3_000_000, 1, 1, TOKEN_A);
        let wallet = ("wallet".to_string(), 0, 5_000_000u64);

        // No cap first to get baseline
        let sell1b = make_sell(0x01, 5_000_000, 1, 1, TOKEN_A);
        let sell2b = make_sell(0x02, 5_000_000, 1, 1, TOKEN_A);
        let buy1b = make_buy(0x03, 7_000_000, 1, 1, TOKEN_A);
        let buy2b = make_buy(0x04, 3_000_000, 1, 1, TOKEN_A);
        let wallet2 = ("wallet".to_string(), 0, 5_000_000u64);
        let plan_no_cap = plan_batch_match(
            &[sell1b, sell2b], &[buy1b, buy2b],
            Some(wallet2), &matcher_spk(), 0, None,
        ).unwrap();

        let plan = plan_batch_match(
            &[sell1, sell2], &[buy1, buy2],
            Some(wallet), &matcher_spk(), 0, Some(5000), // 50%
        ).unwrap();

        // total_seller_kas = 5M + 5M = 10M, max_fee = 10M * 5000 / 10000 = 5_000_000
        // But actual surplus = total_kas_in - planned_out - miner_fee, which is < 5M
        // So matcher_surplus = min(actual_surplus, max_fee)
        let max_fee_bps = 10_000_000u64 * 5000 / 10000;
        assert!(plan.matcher_surplus <= max_fee_bps,
            "matcher surplus {} should be <= bps cap {}", plan.matcher_surplus, max_fee_bps);
        assert!(plan.matcher_surplus < plan_no_cap.matcher_surplus ||
                plan.matcher_surplus == plan_no_cap.matcher_surplus,
            "capped surplus should be <= uncapped");
    }

    // ---- IOC tests ----

    // Test: IOC buy sweeps 2 sells, KAS left over → buyer change
    #[test]
    fn test_ioc_buy_sweeps_with_change() {
        // sell1: 3M tokens @ 1/1 (costs 3M KAS)
        // sell2: 2M tokens @ 1/1 (costs 2M KAS)
        // buy: 10M KAS → can fill both (5M total), 5M - fee left over
        let sell1 = make_sell(0x01, 3_000_000, 1, 1, TOKEN_A);
        let sell2 = make_sell(0x02, 3_000_000, 1, 1, TOKEN_A);
        let buy = make_buy(0x10, 10_000_000, 1, 1, TOKEN_A);
        let wallet = ("wallet".to_string(), 0, 5_000_000u64);

        let plan = plan_ioc_match(
            &[sell1, sell2], &buy, Some(wallet),
            &matcher_spk(), 0, None,
        ).unwrap();

        // Both sells filled
        assert_eq!(plan.sells.len(), 2, "both sells should be filled");
        assert_eq!(plan.buys.len(), 1, "one buy");

        // Buyer gets tokens
        let buyer_tokens: Vec<&PlannedOutput> = plan.outputs.iter()
            .filter(|o| matches!(o.purpose, OutputPurpose::BuyerTokens))
            .collect();
        assert_eq!(buyer_tokens.len(), 1);
        assert_eq!(buyer_tokens[0].value, 6_000_000, "buyer gets 3M + 3M tokens");

        // Check buyer change exists (unspent KAS)
        let buyer_change: Vec<&PlannedOutput> = plan.outputs.iter()
            .filter(|o| matches!(o.purpose, OutputPurpose::BuyerChange))
            .collect();
        // buy has 10M, sells cost 6M, so ~4M left (minus absorbed into surplus/fee)
        assert!(!buyer_change.is_empty() || plan.matcher_surplus > 0,
            "excess KAS should go somewhere");
    }

    // Test: IOC buy can't afford all sells → only fills what it can
    #[test]
    fn test_ioc_partial_sweep() {
        // sell1: 3M tokens @ 1/1 (costs 3M KAS)
        // sell2: 5M tokens @ 1/1 (costs 5M KAS)
        // sell3: 4M tokens @ 1/1 (costs 4M KAS)
        // buy: 7M KAS → fills sell1 (3M) + can't afford sell2 (5M), stops
        let sell1 = make_sell(0x01, 3_000_000, 1, 1, TOKEN_A);
        let sell2 = make_sell(0x02, 5_000_000, 1, 1, TOKEN_A);
        let sell3 = make_sell(0x03, 4_000_000, 1, 1, TOKEN_A);
        let buy = make_buy(0x10, 7_000_000, 1, 1, TOKEN_A);
        let wallet = ("wallet".to_string(), 0, 5_000_000u64);

        let plan = plan_ioc_match(
            &[sell1, sell2, sell3], &buy, Some(wallet),
            &matcher_spk(), 0, None,
        ).unwrap();

        // Only sell1 filled (sell2 costs 5M, buy only has 4M left)
        assert_eq!(plan.sells.len(), 1, "only sell1 should be filled");

        let buyer_tokens: Vec<&PlannedOutput> = plan.outputs.iter()
            .filter(|o| matches!(o.purpose, OutputPurpose::BuyerTokens))
            .collect();
        assert_eq!(buyer_tokens[0].value, 3_000_000, "buyer gets only sell1 tokens");
    }

    // Test: IOC with bps cap
    #[test]
    fn test_ioc_with_bps_cap() {
        let sell1 = make_sell(0x01, 5_000_000, 1, 1, TOKEN_A);
        let buy = make_buy(0x10, 10_000_000, 1, 1, TOKEN_A);
        let wallet = ("wallet".to_string(), 0, 5_000_000u64);

        // bps = 5000 (50%): cap = 5M * 50% = 2.5M (< MIN_UTXO 3M, so dust)
        // Use higher bps: 8000 (80%): cap = 5M * 80% = 4M
        let plan = plan_ioc_match(
            &[sell1], &buy, Some(wallet),
            &matcher_spk(), 0, Some(8000),
        ).unwrap();

        let max_fee = 5_000_000u64 * 8000 / 10000; // 4M
        assert!(plan.matcher_surplus <= max_fee,
            "matcher surplus {} should be <= bps cap {}", plan.matcher_surplus, max_fee);
    }

    // Test: IOC with no affordable sells → error
    #[test]
    fn test_ioc_no_affordable_sells() {
        let sell1 = make_sell(0x01, 10_000_000, 1, 1, TOKEN_A);
        let buy = make_buy(0x10, 3_000_000, 1, 1, TOKEN_A); // can't afford
        let wallet = ("wallet".to_string(), 0, 5_000_000u64);

        let result = plan_ioc_match(
            &[sell1], &buy, Some(wallet),
            &matcher_spk(), 0, None,
        );
        assert!(result.is_err(), "should fail when buy can't afford any sell");
    }

    // =========================================================
    //  Sell IOC tests (1 sell sweeps N buys)
    // =========================================================

    #[test]
    fn test_sell_ioc_sweeps_all_buys() {
        // sell: 10M tokens @ 1/1
        // buy1: 3M KAS → wants 3M tokens
        // buy2: 4M KAS → wants 4M tokens
        // Total tokens needed: 7M, sell has 10M → 3M token change
        let sell = make_sell(0x01, 10_000_000, 1, 1, TOKEN_A);
        let buy1 = make_buy(0x10, 3_000_000, 1, 1, TOKEN_A);
        let buy2 = make_buy(0x11, 4_000_000, 1, 1, TOKEN_A);
        let wallet = ("wallet".to_string(), 0, 5_000_000u64);

        let plan = plan_sell_ioc_match(
            &sell, &[buy1, buy2], Some(wallet),
            &matcher_spk(), 0, None,
        ).unwrap();

        assert_eq!(plan.sells.len(), 1, "one sell");
        assert_eq!(plan.buys.len(), 2, "both buys filled");
        assert_eq!(plan.ioc_mode, Some(IocSide::Sell));

        // Seller gets KAS from both buys
        let seller_kas: Vec<&PlannedOutput> = plan.outputs.iter()
            .filter(|o| matches!(o.purpose, OutputPurpose::SellerKas))
            .collect();
        assert_eq!(seller_kas.len(), 1);
        assert_eq!(seller_kas[0].value, 7_000_000, "seller gets 3M + 4M KAS");

        // Each buyer gets tokens
        let buyer_tokens: Vec<&PlannedOutput> = plan.outputs.iter()
            .filter(|o| matches!(o.purpose, OutputPurpose::BuyerTokens))
            .collect();
        assert_eq!(buyer_tokens.len(), 2);
        assert_eq!(buyer_tokens[0].value, 3_000_000, "buyer1 gets 3M tokens");
        assert_eq!(buyer_tokens[1].value, 4_000_000, "buyer2 gets 4M tokens");

        // Seller gets token change (unfilled 3M)
        let token_change: Vec<&PlannedOutput> = plan.outputs.iter()
            .filter(|o| matches!(o.purpose, OutputPurpose::SellRemainder))
            .collect();
        assert_eq!(token_change.len(), 1);
        assert_eq!(token_change[0].value, 3_000_000, "seller gets 3M unfilled tokens back");

        // sell_fill_amounts for sigscript
        assert_eq!(plan.sell_fill_amounts, vec![7_000_000], "fta = total tokens sold");
    }

    #[test]
    fn test_sell_ioc_partial_sweep() {
        // sell: 10M tokens @ 1/1
        // buy1: 3M KAS → wants 3M tokens
        // buy2: 9M KAS → wants 9M tokens (sell only has 7M left, can't fill)
        // Only buy1 filled, token change = 7M (>= MIN_UTXO 3M)
        let sell = make_sell(0x01, 10_000_000, 1, 1, TOKEN_A);
        let buy1 = make_buy(0x10, 3_000_000, 1, 1, TOKEN_A);
        let buy2 = make_buy(0x11, 9_000_000, 1, 1, TOKEN_A);
        let wallet = ("wallet".to_string(), 0, 5_000_000u64);

        let plan = plan_sell_ioc_match(
            &sell, &[buy1, buy2], Some(wallet),
            &matcher_spk(), 0, None,
        ).unwrap();

        assert_eq!(plan.buys.len(), 1, "only buy1 filled");
        assert_eq!(plan.sell_fill_amounts, vec![3_000_000]);

        let seller_kas: Vec<&PlannedOutput> = plan.outputs.iter()
            .filter(|o| matches!(o.purpose, OutputPurpose::SellerKas))
            .collect();
        assert_eq!(seller_kas[0].value, 3_000_000);

        let token_change: Vec<&PlannedOutput> = plan.outputs.iter()
            .filter(|o| matches!(o.purpose, OutputPurpose::SellRemainder))
            .collect();
        assert_eq!(token_change[0].value, 7_000_000, "10M - 3M = 7M tokens remaining");
    }

    #[test]
    fn test_sell_ioc_residual_is_self_continuation_at_auth0() {
        // Partial IOC-sell (SECURITY_FIXES Fix 1 residual wiring): the unsold
        // tokens must return via a self-continuation output that is the sell
        // input's 0th AUTHORIZED covenant output.
        let sell = make_sell(0x01, 10_000_000, 1, 1, TOKEN_A);
        let buy1 = make_buy(0x10, 3_000_000, 1, 1, TOKEN_A);
        let wallet = ("wallet".to_string(), 0, 5_000_000u64);

        let plan = plan_sell_ioc_match(&sell, &[buy1], Some(wallet), &matcher_spk(), 0, None).unwrap();

        // Layout: SellerKas[0] (non-covenant), residual[1], BuyerTokens[2].
        assert_eq!(plan.outputs[0].purpose, OutputPurpose::SellerKas);
        assert_eq!(plan.outputs[1].purpose, OutputPurpose::SellRemainder);
        assert_eq!(plan.outputs[2].purpose, OutputPurpose::BuyerTokens);

        // Residual SPK == the sell order's OWN P2SH (self-continuation), NOT the
        // seller's wallet SPK (the pre-fix bug), and value == token_in - fta.
        let sell_p2sh = kob_core::p2sh::build_p2sh(&sell.redeem_script);
        assert_eq!(plan.outputs[1].script_public_key, sell_p2sh.script().to_vec());
        assert_eq!(plan.outputs[1].spk_version, sell_p2sh.version());
        assert_ne!(plan.outputs[1].script_public_key, sell.counterparty_spk);
        assert_eq!(plan.outputs[1].value, 7_000_000);

        // Index maps: koi=0, buyer toi=2, buyer coi=1 (residual is covOut 0);
        // buy_seller_map keys are BuyerTokens OUTPUT indices -> sell input 0.
        assert_eq!(plan.sell_output_idx, vec![0]);
        assert_eq!(plan.buy_output_idx, vec![2]);
        assert_eq!(plan.buy_coi, vec![1]);
        assert_eq!(plan.buy_seller_map.get(&2), Some(&0));

        // No-residual (exact fill): layout unchanged -- BuyerTokens at [1], coi 0.
        let sell2 = make_sell(0x02, 3_000_000, 1, 1, TOKEN_A);
        let buy2 = make_buy(0x20, 3_000_000, 1, 1, TOKEN_A);
        let plan2 = plan_sell_ioc_match(
            &sell2, &[buy2], Some(("w".into(), 0, 5_000_000)), &matcher_spk(), 0, None,
        ).unwrap();
        assert!(plan2.outputs.iter().all(|o| o.purpose != OutputPurpose::SellRemainder));
        assert_eq!(plan2.buy_output_idx, vec![1]);
        assert_eq!(plan2.buy_coi, vec![0]);
    }

    #[test]
    fn test_sell_ioc_no_token_change_when_exact() {
        // sell: 7M tokens @ 1/1
        // buy1: 3M, buy2: 4M → exactly 7M tokens needed
        let sell = make_sell(0x01, 7_000_000, 1, 1, TOKEN_A);
        let buy1 = make_buy(0x10, 3_000_000, 1, 1, TOKEN_A);
        let buy2 = make_buy(0x11, 4_000_000, 1, 1, TOKEN_A);
        let wallet = ("wallet".to_string(), 0, 5_000_000u64);

        let plan = plan_sell_ioc_match(
            &sell, &[buy1, buy2], Some(wallet),
            &matcher_spk(), 0, None,
        ).unwrap();

        let token_change: Vec<&PlannedOutput> = plan.outputs.iter()
            .filter(|o| matches!(o.purpose, OutputPurpose::SellRemainder))
            .collect();
        assert!(token_change.is_empty(), "no token change when exact fill");
    }

    #[test]
    fn test_sell_ioc_with_bps_cap() {
        let sell = make_sell(0x01, 10_000_000, 1, 1, TOKEN_A);
        let buy1 = make_buy(0x10, 5_000_000, 1, 1, TOKEN_A);
        let wallet = ("wallet".to_string(), 0, 5_000_000u64);

        let plan = plan_sell_ioc_match(
            &sell, &[buy1], Some(wallet),
            &matcher_spk(), 0, Some(5000), // 50%
        ).unwrap();

        let max_fee = 5_000_000u64 * 5000 / 10000; // 2.5M
        assert!(plan.matcher_surplus <= max_fee,
            "matcher surplus {} should be <= bps cap {}", plan.matcher_surplus, max_fee);
    }

    #[test]
    fn test_sell_ioc_no_affordable_buys() {
        // sell: 1M tokens @ 2/1 (needs 2M KAS per token)
        // buy: has only 500K KAS → buy_tokens = 500K * 2/1 = 1M tokens but
        //   actually: buy_tokens = utxo_value * price_num / price_den
        //   = 500_000 * 2 / 1 = 1_000_000 tokens → can fill
        // Use different scenario: sell with very few tokens
        let sell = make_sell(0x01, 500_000, 1, 1, TOKEN_A); // only 500K tokens
        // buy wants 3M tokens but sell can fill (500K < 3M tokens the buy wants)
        // Actually, plan_sell_ioc_match checks tokens_remaining >= buy_tokens
        // buy_tokens = 3M * 1/1 = 3M. 500K < 3M → can't fill → error
        let buy1 = make_buy(0x10, 3_000_000, 1, 1, TOKEN_A);
        let wallet = ("wallet".to_string(), 0, 5_000_000u64);

        let result = plan_sell_ioc_match(
            &sell, &[buy1], Some(wallet),
            &matcher_spk(), 0, None,
        );
        assert!(result.is_err(), "should fail when sell can't fill any buy");
    }

    #[test]
    fn test_sell_ioc_with_price_ratio() {
        // sell: 20M tokens @ 3/2 (seller wants 1.5 KAS per token)
        // buy1: 6M KAS @ 3/2 → wants 6M * 3/2 = 9M tokens
        // sell has 20M, 20M >= 9M → fills
        // seller gets 6M KAS, token change = 20M - 9M = 11M (>= MIN_UTXO 3M)
        let sell = make_sell(0x01, 20_000_000, 3, 2, TOKEN_A);
        let buy1 = make_buy(0x10, 6_000_000, 3, 2, TOKEN_A);
        let wallet = ("wallet".to_string(), 0, 5_000_000u64);

        let plan = plan_sell_ioc_match(
            &sell, &[buy1], Some(wallet),
            &matcher_spk(), 0, None,
        ).unwrap();

        let seller_kas: Vec<&PlannedOutput> = plan.outputs.iter()
            .filter(|o| matches!(o.purpose, OutputPurpose::SellerKas))
            .collect();
        assert_eq!(seller_kas[0].value, 6_000_000, "seller gets buyer's 6M KAS");

        let buyer_tokens: Vec<&PlannedOutput> = plan.outputs.iter()
            .filter(|o| matches!(o.purpose, OutputPurpose::BuyerTokens))
            .collect();
        assert_eq!(buyer_tokens[0].value, 9_000_000, "buyer gets 9M tokens");

        let token_change: Vec<&PlannedOutput> = plan.outputs.iter()
            .filter(|o| matches!(o.purpose, OutputPurpose::SellRemainder))
            .collect();
        assert_eq!(token_change[0].value, 11_000_000, "20M - 9M = 11M tokens returned");
    }

    // =========================================================
    //  IOC build_tx sigscript tests
    // =========================================================

    #[test]
    fn test_ioc_buy_build_tx_sigscript() {
        // Buy IOC: 1 buy sweeps 2 sells
        let sell1 = make_sell(0x01, 3_000_000, 1, 1, TOKEN_A);
        let sell2 = make_sell(0x02, 4_000_000, 1, 1, TOKEN_A);
        let buy = make_buy(0x10, 10_000_000, 1, 1, TOKEN_A);
        let wallet = ("wallet".to_string(), 0, 5_000_000u64);

        let plan = plan_ioc_match(
            &[sell1, sell2], &buy, Some(wallet),
            &matcher_spk(), 0, None,
        ).unwrap();

        assert_eq!(plan.ioc_mode, Some(IocSide::Buy));

        let batch_tx = plan.build_tx().unwrap();

        // Sell inputs use normal fill sigscript (Op1 selector)
        for i in 0..plan.sells.len() {
            let ss = &batch_tx.inputs[i].sigscript;
            assert!(!ss.is_empty(), "sell sigscript should not be empty");
            // Sell fill sigscript has Op1 (0x51) as selector before RS push
            // Find the selector byte: it's right before the pushdata for RS
            // In sell fill: [koi] [Op1] [pushData(RS)]
            // koi is 1-2 bytes, then selector Op1
        }

        // Buy input uses IOC fill sigscript (Op5 selector = 0x55)
        let buy_ss = &batch_tx.inputs[plan.sells.len()].sigscript;
        assert!(!buy_ss.is_empty(), "buy IOC sigscript should not be empty");
        // The IOC buy sigscript should contain Op5 (0x55) as selector
        // Sigscript layout: [toi] [tii] [coi] [Op5] [pushData(RS)]
        // The Op5 byte should be present before the RS pushdata
        let rs_len = plan.buys[0].0.redeem_script.len();
        // pushData: 0x4c + 1B len (for 256..=396B RS) or 0x4d + 2B len
        let pushdata_offset = if rs_len <= 255 { 2 } else { 3 };
        let op5_pos = buy_ss.len() - rs_len - pushdata_offset - 1;
        assert_eq!(buy_ss[op5_pos], 0x55, "buy IOC selector should be Op5 (0x55)");
    }

    #[test]
    fn test_ioc_sell_build_tx_sigscript() {
        // Sell IOC: 1 sell sweeps 2 buys
        let sell = make_sell(0x01, 10_000_000, 1, 1, TOKEN_A);
        let buy1 = make_buy(0x10, 3_000_000, 1, 1, TOKEN_A);
        let buy2 = make_buy(0x11, 4_000_000, 1, 1, TOKEN_A);
        let wallet = ("wallet".to_string(), 0, 5_000_000u64);

        let plan = plan_sell_ioc_match(
            &sell, &[buy1, buy2], Some(wallet),
            &matcher_spk(), 0, None,
        ).unwrap();

        assert_eq!(plan.ioc_mode, Some(IocSide::Sell));

        let batch_tx = plan.build_tx().unwrap();

        // Sell input uses IOC fill sigscript (Op5 selector = 0x55)
        let sell_ss = &batch_tx.inputs[0].sigscript;
        assert!(!sell_ss.is_empty(), "sell IOC sigscript should not be empty");
        // Sell IOC sigscript layout: [koi] [pushData(fta 8B)] [Op5] [pushData(RS)]
        let rs_len = plan.sells[0].0.redeem_script.len();
        let pushdata_offset = if rs_len <= 255 { 2 } else { 3 };
        let op5_pos = sell_ss.len() - rs_len - pushdata_offset - 1;
        assert_eq!(sell_ss[op5_pos], 0x55, "sell IOC selector should be Op5 (0x55)");

        // fta should be encoded in the sigscript
        let fta = plan.sell_fill_amounts[0];
        assert_eq!(fta, 7_000_000, "fta = 3M + 4M tokens");
        // fta is pushed as 8-byte LE data: [0x08] [fta 8B]
        let fta_bytes = fta.to_le_bytes();
        // Search for the fta bytes in sigscript
        let mut found_fta = false;
        for i in 0..sell_ss.len().saturating_sub(9) {
            if sell_ss[i] == 0x08 && sell_ss[i+1..i+9] == fta_bytes {
                found_fta = true;
                break;
            }
        }
        assert!(found_fta, "sell IOC sigscript should contain fta push (0x08 + 8B LE)");

        // Buy inputs use normal fill sigscript (Op1 selector)
        for j in 0..plan.buys.len() {
            let buy_ss = &batch_tx.inputs[1 + j].sigscript;
            assert!(!buy_ss.is_empty(), "buy sigscript should not be empty");
        }
    }

    #[test]
    fn test_ioc_buy_build_tx_output_count() {
        // Buy IOC: 1 buy sweeps 2 sells, with wallet
        let sell1 = make_sell(0x01, 3_000_000, 1, 1, TOKEN_A);
        let sell2 = make_sell(0x02, 4_000_000, 1, 1, TOKEN_A);
        let buy = make_buy(0x10, 10_000_000, 1, 1, TOKEN_A);
        let wallet = ("wallet".to_string(), 0, 5_000_000u64);

        let plan = plan_ioc_match(
            &[sell1, sell2], &buy, Some(wallet),
            &matcher_spk(), 0, None,
        ).unwrap();

        let batch_tx = plan.build_tx().unwrap();

        // Inputs: 2 sells + 1 buy + 1 wallet = 4
        assert_eq!(batch_tx.inputs.len(), 4);

        // Outputs: seller_kas_0, seller_kas_1, buyer_tokens, buyer_change?, matcher_fee?
        assert!(batch_tx.outputs.len() >= 3, "at least 2 seller KAS + 1 buyer tokens");
    }

    #[test]
    fn test_ioc_sell_build_tx_output_count() {
        // Sell IOC: 1 sell sweeps 2 buys, with wallet
        let sell = make_sell(0x01, 10_000_000, 1, 1, TOKEN_A);
        let buy1 = make_buy(0x10, 3_000_000, 1, 1, TOKEN_A);
        let buy2 = make_buy(0x11, 4_000_000, 1, 1, TOKEN_A);
        let wallet = ("wallet".to_string(), 0, 5_000_000u64);

        let plan = plan_sell_ioc_match(
            &sell, &[buy1, buy2], Some(wallet),
            &matcher_spk(), 0, None,
        ).unwrap();

        let batch_tx = plan.build_tx().unwrap();

        // Inputs: 1 sell + 2 buys + 1 wallet = 4
        assert_eq!(batch_tx.inputs.len(), 4);

        // Outputs: seller_kas, buyer_tokens_0, buyer_tokens_1, seller_token_change, matcher_fee?
        assert!(batch_tx.outputs.len() >= 4,
            "at least 1 seller KAS + 2 buyer tokens + 1 token change, got {}", batch_tx.outputs.len());
    }

    #[test]
    fn test_ioc_sell_3_buys() {
        // Sell IOC: 1 sell sweeps 3 buys with remainder
        let sell = make_sell(0x01, 20_000_000, 1, 1, TOKEN_A);
        let buy1 = make_buy(0x10, 3_000_000, 1, 1, TOKEN_A);
        let buy2 = make_buy(0x11, 4_000_000, 1, 1, TOKEN_A);
        let buy3 = make_buy(0x12, 5_000_000, 1, 1, TOKEN_A);
        let wallet = ("wallet".to_string(), 0, 5_000_000u64);

        let plan = plan_sell_ioc_match(
            &sell, &[buy1, buy2, buy3], Some(wallet),
            &matcher_spk(), 0, None,
        ).unwrap();

        assert_eq!(plan.buys.len(), 3, "all 3 buys filled");
        assert_eq!(plan.sell_fill_amounts, vec![12_000_000], "3M+4M+5M = 12M tokens sold");

        let seller_kas: Vec<&PlannedOutput> = plan.outputs.iter()
            .filter(|o| matches!(o.purpose, OutputPurpose::SellerKas))
            .collect();
        assert_eq!(seller_kas[0].value, 12_000_000, "seller gets 12M KAS");

        let token_change: Vec<&PlannedOutput> = plan.outputs.iter()
            .filter(|o| matches!(o.purpose, OutputPurpose::SellRemainder))
            .collect();
        assert_eq!(token_change[0].value, 8_000_000, "20M - 12M = 8M tokens remaining");

        // build_tx should succeed
        let batch_tx = plan.build_tx().unwrap();
        // 1 sell + 3 buys + 1 wallet = 5 inputs
        assert_eq!(batch_tx.inputs.len(), 5);
    }

    /// Find theoretical max buyers per seller by scaling N and measuring mass.
    #[test]
    fn test_max_buyers_per_seller() {
        // 1 sell with huge token supply, N buys each wanting 10 KAS worth of tokens.
        // Price 1/1 => each buy wants buy.utxo_value tokens.
        let token = TOKEN_A;
        let per_buy = 10_000_000_000u64; // 100 KAS per buy
        let _max_n = 800; // upper bound to search

        let mut last_ok_n = 0u64;
        let mut results: Vec<(usize, u64, u64, u64)> = Vec::new(); // (n, compute, storage, sigscript_total)

        for n in [1, 2, 3, 5, 10, 20, 50, 100, 150, 200, 250, 300, 400, 500, 600, 700, 800] {
            let sell_amount = per_buy * n as u64 * 2; // enough tokens for all
            let sell = make_sell(0x10, sell_amount, 1, 1, token);

            let buys: Vec<BatchOrder> = (0..n).map(|j| {
                let id_byte = (j % 256) as u8;
                let mut b = make_buy(id_byte, per_buy, 1, 1, token);
                // unique outpoint
                b.outpoint.0 = format!("{:064x}", j + 0x20);
                b
            }).collect();

            let wallet = Some(("ff".repeat(32), 0u32, 100_000_000_000u64));

            let result = plan_sell_ioc_match(
                &sell,
                &buys,
                wallet,
                &matcher_spk(),
                0,
                None,
            );

            match result {
                Ok(plan) => {
                    let tx = plan.build_tx().unwrap();
                    // Compute mass from sigscript sizes
                    let num_inputs = tx.inputs.len();
                    let num_outputs = tx.outputs.len();
                    let ss_total: usize = tx.inputs.iter().map(|i| i.sigscript.len()).sum();
                    let compute = kob_core::mass::estimate_compute_mass(num_inputs, num_outputs, 0);

                    // Storage mass: need input/output values
                    let mut in_vals = vec![sell.utxo_value];
                    for b in &buys {
                        in_vals.push(b.utxo_value);
                    }
                    in_vals.push(100_000_000_000); // wallet
                    let out_vals: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
                    let storage = kob_core::mass::compute_storage_mass(&in_vals, &out_vals);

                    results.push((n, compute, storage, ss_total as u64));
                    if compute <= 500_000 && storage <= 500_000 {
                        last_ok_n = n as u64;
                    }
                }
                Err(e) => {
                    eprintln!("n={}: plan failed: {}", n, e);
                    break;
                }
            }
        }

        eprintln!("\n=== SELL IOC: Max Buyers per Seller ===");
        eprintln!("{:>5} {:>10} {:>10} {:>10} {:>8}", "N", "compute", "storage", "ss_bytes", "ok?");
        for (n, compute, storage, ss) in &results {
            let effective = std::cmp::max(*compute, *storage);
            let ok = if effective <= 500_000 { "OK" } else { "OVER" };
            eprintln!("{:>5} {:>10} {:>10} {:>10} {:>8}", n, compute, storage, ss, ok);
        }
        eprintln!("\nMax buyers (mass <= 500K): {}", last_ok_n);
        assert!(last_ok_n >= 3, "should support at least 3 buyers (E2E proved)");
    }

    // ── V16 tests ──────────────────────────────────────────────────────
    //
    // Regression coverage for the Phase-0 "version 16 is already taken"
    // collision: BatchOrder.version == 16 means EITHER a bracket entry
    // (365B RS) or a v16 buy order (476B RS, the F6-fix contract). Dispatch
    // in build_tx() must key off RS length, not the bare version number.

    /// Create a fake v16 buy order for testing (mirrors `make_buy`, but uses
    /// the v16 F6-fix contract and carries a BPS matcher-fee cap).
    fn make_buy_v16(id_byte: u8, amount: u64, price_num: u64, price_den: u64, token: [u8; 32], mmfee_bps: u64) -> BatchOrder {
        let tx_id = hex::encode(&[id_byte; 32]);
        let owner = [0xBB; 32];
        let bspkh = [0xCC; 32];
        let rs = kob_core::contract::spot::order::build_buy_v16_redeem_script(
            &token, price_num, price_den, 1_000_000, &owner, &bspkh, mmfee_bps, 0, 0,).unwrap();
        BatchOrder {
            outpoint: (tx_id, 0),
            order_type: OrderType::Buy,
            version: 16,
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

    #[test]
    fn v16_buy_rs_len_distinct_from_bracket_and_v14() {
        // The whole collision-fix relies on these lengths being pairwise
        // distinct. If a future edit ever makes two of them equal again,
        // RS-length-based dispatch silently breaks -- catch it here before
        // it becomes a build_tx() misrouting bug.
        use kob_core::contract::spot::order::BUY_ORDER_V16_RS_EXPECTED_LEN;
        use kob_core::contract::spot::parse::BUY_RS_SIZE as BUY_RS_SIZE_V14;
        assert_ne!(BUY_ORDER_V16_RS_EXPECTED_LEN, BRACKET_RS_SIZE);
        assert_ne!(BUY_ORDER_V16_RS_EXPECTED_LEN, BUY_RS_SIZE_V14);
    }

    #[test]
    fn v16_buy_dispatches_to_v16_fill_not_bracket_shape() {
        // A v16 buy order in a batch must produce the v16 fill sigscript
        // ([toi][tii][coi][Op1][pushData(RS)]), never the bracket shape
        // ([Op1][pushData(RS)], no toi/tii/coi) that a version==16 bare-number
        // check would have wrongly selected pre-fix.
        let sell = make_sell(0x10, 10_000_000, 1, 2, TOKEN_A);
        let buy = make_buy_v16(0x20, 10_000_000, 1, 3, TOKEN_A, 30);

        let plan = plan_batch_match(&[sell], &[buy], None, &matcher_spk(), 0, None)
            .expect("plan should succeed");
        let tx = plan.build_tx().expect("build_tx should succeed");

        assert_eq!(tx.inputs.len(), 2, "1 sell + 1 buy");
        let buy_ss = &tx.inputs[1].sigscript;

        // Recompute the exact expected sigscript from the plan's own
        // resolved indices and compare byte-for-byte -- this is stronger
        // than checking a length/shape heuristic.
        let tii = *plan.token_input_map.get(&hex::encode(TOKEN_A)).unwrap() as u16;
        let toi = plan.buy_output_idx[0] as u16;
        let coi = plan.buy_coi[0];
        let buy_rs = &plan.buys[0].0.redeem_script;
        let expected = kob_core::contract::spot::order::build_buy_v16_fill_sigscript(toi, tii, coi, buy_rs);
        assert_eq!(buy_ss, &expected, "v16 buy input must carry the v16 (no-sii) fill sigscript");

        // And make sure it's definitely not bracket-shaped: bracket's
        // sigscript is exactly [Op1][pushData(RS)] with a 365B RS, which
        // can never equal a sigscript carrying a 476B RS.
        let bracket_shaped = kob_core::contract::spot::bracket::build_bracket_fill_sigscript(buy_rs);
        assert_ne!(buy_ss, &bracket_shaped);
    }

    #[test]
    fn bracket_entry_still_dispatches_to_bracket_shape_after_v16_fix() {
        // Regression guard: fixing the v16/bracket collision must not break
        // genuine bracket entries, which also report version==16.
        let oco_spk = [0x07u8; 37];
        let receipt_cov = [0x09u8; 32];
        let trade_spk_hash = [0x0Au8; 32];
        let owner_hash = [0x0Bu8; 32];
        let bracket_rs = kob_core::contract::spot::bracket::build_bracket_redeem_script(
            0, &TOKEN_A, 1, 2, &oco_spk, 1_000_000, 1_000_000, 1_000_000,
            &receipt_cov, &trade_spk_hash, &owner_hash,
        ).unwrap();
        assert_eq!(bracket_rs.len(), BRACKET_RS_SIZE);

        let sell = make_sell(0x10, 10_000_000, 1, 2, TOKEN_A);
        let bracket_buy = BatchOrder {
            outpoint: (hex::encode(&[0x30u8; 32]), 0),
            order_type: OrderType::Buy,
            version: 16,
            token_cov_id: TOKEN_A,
            price_num: 1,
            price_den: 2,
            amount: 10_000_000,
            redeem_script: bracket_rs.clone(),
            utxo_value: 10_000_000,
            counterparty_spk: vec![0xEE; 34],
            counterparty_spk_version: 0,
            min_fill: 1_000_000,
            oco_path: None,
            bracket_meta: None,
        };

        let plan = plan_batch_match(&[sell], &[bracket_buy], None, &matcher_spk(), 0, None)
            .expect("plan should succeed");
        let tx = plan.build_tx().expect("build_tx should succeed");
        let buy_ss = &tx.inputs[1].sigscript;

        let expected = kob_core::contract::spot::bracket::build_bracket_fill_sigscript(&bracket_rs);
        assert_eq!(buy_ss, &expected, "bracket entry must still get the bracket sigscript shape");
    }
}
