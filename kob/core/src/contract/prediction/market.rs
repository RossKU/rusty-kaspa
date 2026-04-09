use super::{VOTE_COUNTER_UNIT, DISPUTE_THRESHOLD};
use super::ballot_box::*;
use super::redemption::*;
use super::split_merge::*;

// 5. Market Deployment Orchestrator
//
// Cross-covenant timeline validation. Enforces:
//   SplitMerge.expiry_daa < BallotBox.start_daa < BallotBox.end_daa < BallotBox.expiry_daa
//   Redemption.expiry_daa == BallotBox.expiry_daa
//
// This is the ONLY correct way to deploy a prediction market.
// Individual builders accept raw parameters — this function validates relationships.

/// BallotBox redeemScript (shared across all collateral pools).
/// With v6, both YES and NO BallotBoxes use the SAME redeemScript (same CID).
/// They are distinguished by UTXO value at settlement.
pub struct PredictionMarketBallots {
    /// Single BallotBox redeemScript (deploy two UTXOs with different initial values)
    pub ballot_rs: Vec<u8>,
}

/// Per-collateral pool scripts.
pub struct CollateralPoolScripts {
    /// SplitMerge redeemScript
    pub split_merge_rs: Vec<u8>,
}

/// Collateral asset for prediction market.
/// BallotBox voting is always KAS (PoW incentive). This only affects
/// SplitMerge (token issuance) and Redemption (payout).
#[derive(Clone, Debug, PartialEq)]
pub enum Collateral {
    /// Native KAS. Available now.
    Kas,
    /// Covenant token (e.g. USDC). Requires HF covenant token support.
    /// The [u8; 32] is the covenant ID of the collateral token.
    CovenantToken([u8; 32]),
}

/// Core market parameters (shared across all collateral pools).
/// BallotBox voting is always KAS.
///
/// `reward_per_vote` is fixed at [`VOTE_COUNTER_UNIT`] (2 sompi) — a
/// counting mechanism, not a miner incentive. Creator revenue comes from
/// the spread between `unit_value` and `payout_per_token` in the collateral pool.
pub struct PredictionMarketParams {
    pub market_id: [u8; 32],
    pub creator_pkh: [u8; 32],
    /// Initial value of YES BallotBox (must be even).
    /// NO BallotBox gets initial_ballot_value + 1 (odd).
    /// Must be >= 3_000_000 (dust floor) + DISPUTE_THRESHOLD * VOTE_COUNTER_UNIT.
    pub initial_ballot_value: u64,
    /// DAA score after which SplitMerge creator can reclaim (token sales end)
    pub split_merge_expiry_daa: u64,
    /// DAA score when voting begins (must be > split_merge_expiry_daa)
    pub ballot_start_daa: u64,
    /// DAA score when voting ends
    pub ballot_end_daa: u64,
    /// DAA score after which BallotBox/Redemption creator can reclaim (market void)
    pub market_expiry_daa: u64,
}

/// Per-collateral pool parameters. One market can have multiple pools
/// (KAS, USDC, etc.) sharing the same BallotBoxes.
pub struct CollateralPoolParams {
    pub collateral: Collateral,
    pub yes_token_cid: [u8; 32],
    pub no_token_cid: [u8; 32],
    pub unit_value: u64,
    pub payout_per_token: u64,
}

/// Stage 1a: Build BallotBox redeemScripts (shared, always KAS).
///
/// Timeline enforced:
/// ```text
/// |-- token sales --|-- voting window --|-- cooling --|-- expiry -->
/// 0          SM.expiry  BB.start  BB.end_daa   BB.expiry / R.expiry
/// ```
pub fn build_prediction_market(params: &PredictionMarketParams) -> crate::Result<PredictionMarketBallots> {
    // Cross-covenant timeline validation (C1 fix: on-chain enforcement at builder level)
    if params.split_merge_expiry_daa >= params.ballot_start_daa {
        return Err(crate::KobError::Contract(
            "split_merge_expiry_daa must be < ballot_start_daa (C1: token sales must end before voting begins)".into(),
        ));
    }
    if params.ballot_start_daa >= params.ballot_end_daa {
        return Err(crate::KobError::Contract(
            "ballot_start_daa must be < ballot_end_daa".into(),
        ));
    }
    if params.ballot_end_daa >= params.market_expiry_daa {
        return Err(crate::KobError::Contract(
            "ballot_end_daa must be < market_expiry_daa".into(),
        ));
    }

    // Validate initial_ballot_value
    if params.initial_ballot_value % 2 != 0 {
        return Err(crate::KobError::Contract(
            "initial_ballot_value must be even (YES box parity)".into(),
        ));
    }
    let min_ballot_value = 3_000_000 + DISPUTE_THRESHOLD * VOTE_COUNTER_UNIT;
    if params.initial_ballot_value < min_ballot_value {
        return Err(crate::KobError::Contract(
            format!(
                "initial_ballot_value must be >= {} (dust floor 3M + {} votes * {} sompi/vote)",
                min_ballot_value, DISPUTE_THRESHOLD, VOTE_COUNTER_UNIT,
            ),
        ));
    }

    let ballot_rs = build_ballot_box_redeem_script(
        &params.market_id,
        VOTE_COUNTER_UNIT,
        params.ballot_start_daa,
        params.ballot_end_daa,
        params.market_expiry_daa,
    )?;

    Ok(PredictionMarketBallots {
        ballot_rs,
    })
}

/// Stage 1b: Build SplitMerge for a collateral pool.
/// Call once per collateral type (KAS, USDC, etc.) for the same market.
pub fn build_collateral_pool(
    params: &PredictionMarketParams,
    pool: &CollateralPoolParams,
) -> crate::Result<CollateralPoolScripts> {
    if let Collateral::CovenantToken(_) = &pool.collateral {
        return Err(crate::KobError::Contract(
            "CovenantToken collateral not yet supported — requires HF covenant token opcodes".into(),
        ));
    }

    let split_merge_rs = build_split_merge_redeem_script(
        &params.market_id,
        &pool.yes_token_cid,
        &pool.no_token_cid,
        &params.creator_pkh,
        pool.unit_value,
        params.split_merge_expiry_daa,
    )?;

    Ok(CollateralPoolScripts { split_merge_rs })
}

/// Stage 2: Build Redemption v6 redeemScript after BallotBox deployment.
/// One Redemption per collateral pool, all sharing the same BallotBox CID.
///
/// With v8, both YES and NO BallotBoxes use the SAME redeemScript (same CID).
/// Redemption v6 uses a single `ballot_cid` and OP_MOD parity to identify
/// YES (even value) vs NO (odd value). Settlement gated by dispute threshold.
///
/// `threshold_value` is computed: 2 * initial_ballot_value + 1 - DISPUTE_THRESHOLD * VOTE_COUNTER_UNIT
///
/// # Arguments
/// * `params` - Same `PredictionMarketParams` used in Stage 1
/// * `pool` - Collateral pool parameters
/// * `ballot_cid` - Covenant ID of the deployed BallotBox (same for both YES and NO)
/// * `reward_per_receipt` - Sompi reward per vote receipt redemption
/// * `yes_receipt_cid` - Covenant ID of YES vote receipt tokens
/// * `no_receipt_cid` - Covenant ID of NO vote receipt tokens
pub fn build_prediction_market_redemption(
    params: &PredictionMarketParams,
    pool: &CollateralPoolParams,
    ballot_cid: &[u8; 32],
    reward_per_receipt: u64,
    yes_receipt_cid: &[u8; 32],
    no_receipt_cid: &[u8; 32],
) -> crate::Result<Vec<u8>> {
    if let Collateral::CovenantToken(_) = &pool.collateral {
        return Err(crate::KobError::Contract(
            "CovenantToken collateral not yet supported — requires HF covenant token opcodes".into(),
        ));
    }

    // threshold_value = 2 * V + 1 - DISPUTE_THRESHOLD * VOTE_COUNTER_UNIT
    // YES starts at V (even), NO starts at V+1 (odd).
    // Initial sum = V + (V+1) = 2V+1.
    // Each vote decreases one box by VOTE_COUNTER_UNIT, so after N total votes
    // sum = 2V+1 - N*VOTE_COUNTER_UNIT. We want N >= DISPUTE_THRESHOLD.
    let threshold_value = 2 * params.initial_ballot_value + 1
        - DISPUTE_THRESHOLD * VOTE_COUNTER_UNIT;

    build_redemption_redeem_script(
        &params.market_id,
        ballot_cid,
        &pool.yes_token_cid,
        &pool.no_token_cid,
        pool.payout_per_token,
        threshold_value,
        &params.creator_pkh,
        params.market_expiry_daa,
        reward_per_receipt,
        yes_receipt_cid,
        no_receipt_cid,
    )
}

// 7. Vote Receipt — Atomic Miner Reward Proof
//
// # Kaspa Covenant Opcode Reference (Complete)
//
// ## TX Introspection (available with covenants_enabled):
//   0xb2 OpTxVersion           — push tx.version
//   0xb3 OpTxInputCount        — push tx.inputs.len()
//   0xb4 OpTxOutputCount       — push tx.outputs.len()
//   0xb5 OpTxLockTime          — push tx.lockTime
//   0xb6 OpTxSubnetId          — push tx.subnetworkId
//   0xb7 OpTxGas               — push tx.gas
//   0xb8 OpTxPayloadSubstr     — pop(start,end) -> push tx.payload[start..end]
//   0xb9 OpTxInputIndex        — push current input index
//   0xba OpOutpointTxId        — pop(idx) -> push input[idx].outpoint.txId
//   0xbb OpOutpointIndex       — pop(idx) -> push input[idx].outpoint.index
//   0xbc OpTxInputScriptSigSubstr — pop(idx,start,end) -> push input[idx].sig[start..end]
//   0xbd OpTxInputSeq          — pop(idx) -> push input[idx].sequence (raw LE bytes)
//   0xbe OpTxInputAmount       — pop(idx) -> push utxo(idx).amount
//   0xbf OpTxInputSpk          — pop(idx) -> push utxo(idx).spk (version_be ++ script)
//   0xc0 OpTxInputDaaScore     — pop(idx) -> push utxo(idx).blockDaaScore
//   0xc1 OpTxInputIsCoinbase   — pop(idx) -> push utxo(idx).isCoinbase (0 or 1)
//   0xc2 OpTxOutputAmount      — pop(idx) -> push output[idx].value
//   0xc3 OpTxOutputSpk         — pop(idx) -> push output[idx].spk (version_be ++ script)
//   0xc4 OpTxPayloadLen        — push tx.payload.len()
//   0xc5 OpTxInputSpkLen       — pop(idx) -> push len(utxo(idx).spk.to_bytes())
//   0xc6 OpTxInputSpkSubstr    — pop(idx,start,end) -> push utxo(idx).spk[start..end]
//   0xc7 OpTxOutputSpkLen      — pop(idx) -> push len(output[idx].spk.to_bytes())
//   0xc8 OpTxOutputSpkSubstr   — pop(idx,start,end) -> push output[idx].spk[start..end]
//   0xc9 OpTxInputScriptSigLen — pop(idx) -> push len(input[idx].sig)
//
// ## Covenant-specific:
//   0xcb OpAuthOutputCount     — pop(input_idx) -> push #outputs authorized by input_idx
//   0xcc OpAuthOutputIdx       — pop(input_idx,k) -> push the k-th auth output index
//   0xcd OpNum2Bin             — pop(size,num) -> push num as size-byte LE (max 8)
//   0xce OpBin2Num             — pop(raw) -> push as minimally-encoded i64
//   0xcf OpInputCovenantId     — pop(idx) -> push utxo(idx).covenantId (ZERO_HASH if none)
//   0xd0 OpCovInputCount       — pop(cid) -> push #inputs with that covenant id
//   0xd1 OpCovInputIdx         — pop(cid,k) -> push the k-th input index for cid
//   0xd2 OpCovOutputCount      — pop(cid) -> push #outputs with that covenant id
//   0xd3 OpCovOutputIdx        — pop(cid,k) -> push the k-th output index for cid
//   0xd4 OpChainblockSeqCommit — pop(block_hash) -> push seq commitment (chain ancestor check)
//   0xd5 OpOutputCovenantId    — pop(idx) -> push output[idx].covenantId (ZERO_HASH if none)
//   0xd6 OpOutputAuthorizingInput — pop(idx) -> push output[idx].authorizingInput (-1 if none)
//
// ## Re-enabled under covenants:
//   0x7e OpCat    — pop(a,b) -> push a||b
//   0x7f OpSubstr — pop(data,start,end) -> push data[start..end]
//   0x83 OpInvert — pop(data) -> push bitwise NOT
//   0x84 OpAnd    — pop(a,b) -> push a & b (same length required)
//   0x85 OpOr     — pop(a,b) -> push a | b (same length required)
//   0x86 OpXor    — pop(a,b) -> push a ^ b (same length required)
//   0x95 OpMul    — pop(a,b) -> push a*b (checked i64)
//   0x96 OpDiv    — pop(a,b) -> push a/b (checked i64)
//   0x97 OpMod    — pop(a,b) -> push a%b (checked i64)
//   0xb0 OpCLTV   — verify locktime >= top (already in pre-covenant Kaspa)
//   0xb1 OpCSV    — verify sequence (already in pre-covenant Kaspa)
//
// ## SPK encoding (what OpTxOutputSpk pushes):
//   version (2 bytes, big-endian) ++ script (variable length)
//   For P2SH: version=0x0000, script = OP_BLAKE2B <32-byte-hash> OP_EQUAL (34 bytes)
//   Total P2SH SPK bytes: 2 + 34 = 36 bytes
//
// ## Covenant ID computation (genesis):
//   CovenantID = Blake2b(outpoint.txId, outpoint.index, len(outputs),
//                        for each: (outputIndex, value, spk.version, spk.script))
//   Continuation: covenant_id inherited from UTXO entry (same CID if same SPK)
//
// # Alternative Approaches Analysis
//
// ## (a) Receipt as separate covenant UTXO (4th output)
//
// Feasibility: HIGH. BallotBox can enforce Output[3] properties using:
//   - OP_TXOUTPUTSPK(3) to read Output[3]'s full SPK
//   - OP_TXOUTPUTAMOUNT(3) to read Output[3]'s value
//   - OP_OUTPUTCOVENANTID(3) to read Output[3]'s covenant_id
//   - OP_CAT to build expected SPK from vote_side + ballot_cid
//
// The receipt covenant's redeemScript must encode which side was voted for.
// BallotBox can verify that Output[3] has the correct SPK by building the
// expected P2SH hash on-stack using OP_CAT + OP_BLAKE2B.
//
// Bytecode cost: ~30-40B added to vote path. Receipt RS: ~100B.
// Problem: This creates a NEW covenant (genesis) with a CID that depends on
// the outpoint of the authorizing input — which changes every TX. The receipt
// CID is therefore different for every vote TX. This makes batch redemption
// impossible because each receipt has a unique covenant ID.
//
// Workaround: Make the receipt a plain P2SH (not covenant), where the
// redeemScript encodes vote_side + ballot_cid. But then redemption requires
// knowing the receipt's redeemScript, which is fine since it is deterministic.
//
// Verdict: FEASIBLE but expensive in mass/complexity. ~30B added to BallotBox
// body per vote path. 4 outputs = higher storage mass.
//
// ## (b) Receipt encoded in BallotBox value (value bits encode voter info)
//
// The BallotBox value already encodes vote count through the decrease. There
// is no way to encode per-voter identity in a single scalar value — all 1024
// miners would need to be distinguishable. Value is a single u64.
//
// Verdict: INFEASIBLE. A single integer cannot encode N unique voter identities.
//
// ## (c) OP_CAT to build receipt data on-chain
//
// OP_CAT is available (0x7e, enabled under covenants). Can concatenate:
//   - ballot_cid (32B) + vote_side (1B) + miner_data (variable)
// This is a building block for approach (a), not a standalone approach.
//
// Verdict: TOOL, not approach. Used within (a) or (g).
//
// ## (d) Commit-reveal scheme
//
// Miner commits to vote in TX1, reveals in TX2. This is NOT atomic — requires
// 2 TXs. Also introduces a timing window where the miner can see others' votes
// before revealing.
//
// Verdict: INFEASIBLE — violates the atomic (single TX) constraint.
//
// ## (e) Miner's Input[2] UTXO becomes the receipt (UTXO ID as proof)
//
// The miner's Input[2] UTXO is consumed. Its outpoint (txId + index) is a
// unique identifier for this specific vote TX. An off-chain indexer can track:
//   "outpoint X was consumed in vote TX Y which voted for side Z"
//
// However, the consumed UTXO is gone — it cannot be "presented" later.
// The miner's Output[2] (change) is the new UTXO, but it has no on-chain
// proof of which side was voted for. Any P2PKH output looks the same.
//
// To make this work, Output[2] would need to be a covenant that encodes
// the vote side. But then Output[2] is no longer freely spendable change —
// it is locked in a receipt covenant. This becomes approach (a) with the
// receipt at position [2] instead of [3].
//
// Verdict: INFEASIBLE as described. Degenerates to (a) if receipt is covenant.
//
// ## (f) No receipt — BallotBox tracks cumulative reward per side
//
// BallotBox value decreases by reward_per_vote per vote. The total reward
// pool for the winning side = (initial_value - final_value) / reward_per_vote
// = number_of_votes * reward_per_vote. But there is no on-chain record of
// WHICH miners voted. Settlement would pay to... whom?
//
// Without per-voter records, the reward pool can only go to:
//   1. The market creator (defeats purpose)
//   2. Be burned (wasteful)
//   3. ALL miners proportionally (no mechanism to track)
//
// Verdict: INFEASIBLE. No individual voter attribution without receipts.
//
// ## (g) VoteToken covenant minted alongside each vote (LP-token pattern)
//
// Instead of a generic "receipt", mint a specific VoteToken covenant during
// each vote TX. The VoteToken:
//   - Has a known CID (same redeemScript for all tokens of one side)
//   - Contains vote_side as state
//   - Is spendable only by presenting a winning BallotBox
//
// KEY INSIGHT: If all YES VoteTokens have the SAME redeemScript (and thus
// the same CID), then the Redemption covenant can use OpCovInputCount to
// verify "at least 1 VoteToken with this CID is present as co-input".
//
// BUT: All tokens from the same genesis group share a CID. Tokens minted
// in DIFFERENT vote TXs have DIFFERENT genesis outpoints, hence DIFFERENT
// CIDs. This makes batch redemption impossible (each vote TX produces
// VoteTokens with unique CIDs).
//
// FIX: Use a continuation pattern. Deploy a VoteToken "factory" covenant
// that has a fixed CID. Each vote TX includes the factory as a co-input,
// and the factory mints a new VoteToken as a continuation output. But this
// requires the factory UTXO to be consumed and recreated every vote — it
// becomes a sequential bottleneck (only 1 vote per factory per TX).
//
// Verdict: INFEASIBLE at scale due to UTXO contention. The factory
// approach serializes all votes through a single UTXO chain.
//
// ## (h) Creative use of OpCovInputIdx / OpCovOutputCount
//
// These opcodes count inputs/outputs by covenant ID. They cannot create
// new data or mint tokens. They are verification tools, not minting tools.
//
// Verdict: TOOL, not approach. Useful within other approaches.
//
// # RECOMMENDED APPROACH: (a) with P2SH receipt + off-chain RewardPool
//
// After analyzing all alternatives, approach (a) with a key simplification
// is optimal: the Vote Receipt is a small P2SH covenant UTXO whose
// redeemScript deterministically encodes the vote side and ballot CID.
//
// ## Design: VoteReceipt Covenant
//
// The receipt's redeemScript is deterministic from (ballot_cid, vote_side):
//
//   State (34B): [0x20][ballot_cid 32B][0x01][vote_side 1B]
//   Body (~60B): verify winning side matches, allow spend
//
// P2SH SPK = version(2B) ++ OP_BLAKE2B(1B) ++ BLAKE2B(RS)(32B) ++ OP_EQUAL(1B)
//          = 36 bytes total
//
// Since the RS is deterministic, the P2SH hash is deterministic. The
// BallotBox can verify that Output[3] has the exact correct SPK by
// building it on-stack.
//
// ## BallotBox v9 Vote Path Modifications
//
// New TX template:
//   Input[0]: BallotBox A (voted side)
//   Input[1]: BallotBox B (pass-through)
//   Input[2]: Miner UTXO
//   Output[0]: BallotBox A continuation
//   Output[1]: BallotBox B continuation
//   Output[2]: Miner change + 2 sompi (reduced to cover receipt)
//   Output[3]: VoteReceipt UTXO (minimum value, covenant)
//
// The BallotBox must now enforce:
//   - INPUTCOUNT == 3 (unchanged)
//   - OUTPUTCOUNT == 4 (was 3 — BallotBox doesn't currently check this!)
//   - Output[3] SPK matches expected receipt P2SH hash
//   - Output[3] value >= RECEIPT_DUST_FLOOR
//   - fee == 0 (sum of 4 outputs == sum of 3 inputs)
//
// ## VoteReceipt Redemption
//
// After settlement, the receipt holder redeems by presenting:
//   Input[0]: VoteReceipt UTXO
//   Input[1]: RewardPool UTXO (separate covenant, funded by creator)
//   Input[2]: Winning BallotBox (read-only witness, settle path)
//   Output[0]: Reward payout to miner
//   Output[1]: RewardPool continuation
//   Output[2]: BallotBox continuation
//
// VoteReceipt script checks:
//   1. Read BallotBox values to determine winner (same parity logic)
//   2. Verify vote_side matches winner
//   3. Allow spend (miner gets receipt value + reward from pool)
//
// ## Mass/Size Impact
//
// Adding Output[3] at minimum value (e.g., 3M sompi = 0.03 KAS):
//   Storage mass contribution: C / 3M = 1T / 3M = 333,333
//   Current 3-output TX: 3 * 333,333 = 1M (at limit with 3M each)
//   4-output TX: 4 * 333,333 = 1,333,333 > MAX_TX_MASS (1M)
//
// PROBLEM: 4 outputs at 3M sompi each exceeds MAX_TX_MASS!
//
// Solutions:
//   1. Receipt at higher value (10M sompi = 100K mass per output)
//      4 * 100K (outputs) vs 3 inputs absorbing: viable if inputs are large
//   2. Miner provides a larger Input[2] to absorb storage mass
//   3. BallotBox values are large (100M+ sompi), their outputs contribute
//      only 10K mass each. Receipt at 3M = 333K. Total output mass ~353K.
//      Input absorption depends on UTXO sizes.
//
// With realistic BallotBox values (100M sompi each):
//   Output mass: 2*10K + 10K (miner change ~100M) + 333K (receipt 3M) = 363K
//   Input mass absorbed by 3 inputs of ~100M each: 3*10K = 30K
//   Net storage mass: 363K - 30K = 333K < 1M. OK!
//
// RECEIPT_DUST_FLOOR = 3,000,000 sompi (same as BallotBox dust floor).
// This is feasible as long as BallotBox values are >> 3M sompi.
//
// ## Bytecode Cost Analysis (BallotBox v9 vote path additions)
//
// The BallotBox needs to build the receipt SPK on-stack and compare:
//
// Step 1: Build receipt RS on stack using OP_CAT
//   push 0x20 (1B) | ballot_cid from state | OP_CAT (1B)    ~3B
//   push vote_side byte | OP_CAT (1B)                       ~3B
//   push receipt_body | OP_CAT (1B)                          ~62B (body push)
//
// PROBLEM: The receipt body is ~60B. Embedding the entire receipt body bytecode
// as a constant inside BallotBox's redeemScript bloats BallotBox by 60+ bytes.
// BallotBox RS is already 187B (v8). Adding 60+B would make it ~250B.
//
// SIMPLER: Don't verify the receipt's internal logic from BallotBox.
// Instead, BallotBox just verifies that Output[3] exists and has a specific
// known SPK. The receipt SPK hash is embedded in BallotBox state as a
// constant (32 bytes, set at deploy time).
//
// Even simpler: Don't pre-embed the receipt hash. Instead, the receipt
// RS is derived from (ballot_cid + vote_side). The ballot_cid is already
// known to BallotBox (it IS the BallotBox's own CID). The vote_side can
// be determined from which BallotBox's value decreased.
//
// SIMPLEST VIABLE APPROACH:
// BallotBox verifies Output[3] has a covenant_id == ZERO_HASH
// (i.e., Output[3] is a genesis covenant or non-covenant output).
// Combined with OP_TXOUTPUTSPK, verify the SPK matches a hash built
// from the ballot CID and vote side.
//
// Actually, the simplest approach that maintains full atomicity:
//
// ## FINAL DESIGN: BallotBox v9 + VoteReceipt v1
//
// BallotBox v9 adds to the vote path:
//   1. OP_TXOUTPUTCOUNT == 4 (verify 4 outputs)               [4B]
//   2. Build expected receipt P2SH SPK on stack                [~45B]
//   3. Compare with actual Output[3] SPK                       [3B]
//   4. Verify Output[3] amount >= RECEIPT_DUST_FLOOR           [6B]
//   5. Update fee==0 sum to include 4th output                 [2B]
//
// Building expected receipt P2SH SPK on stack:
//   - receipt_rs = [0x20, ballot_cid, 0x01, vote_side, body_bytes...]
//   - P2SH script = [OP_BLAKE2B, blake2b(receipt_rs), OP_EQUAL]
//   - SPK bytes = [0x00, 0x00, OP_BLAKE2B, blake2b_hash, OP_EQUAL]
//
// We cannot compute blake2b(receipt_rs) on-stack because OP_BLAKE2B
// only hashes a single stack element — and we would need to build the
// entire receipt RS on-stack first, which requires pushing the ~60B
// receipt body as BallotBox state data.
//
// REVISION: Embed the pre-computed receipt P2SH hash directly in
// BallotBox state. Two hashes needed (YES receipt, NO receipt):
//
//   receipt_yes_rs = [state(ballot_cid, vote_side=0), body]
//   receipt_no_rs  = [state(ballot_cid, vote_side=1), body]
//   receipt_yes_spk_hash = blake2b(receipt_yes_rs)
//   receipt_no_spk_hash  = blake2b(receipt_no_rs)
//
// But this is circular: ballot_cid depends on the BallotBox redeemScript,
// which would contain the receipt hashes, which depend on ballot_cid...
//
// SOLUTION: Use a 2-stage deploy (already used for Redemption):
//   Stage 1: Deploy BallotBox (get ballot_cid)
//   Stage 2: Compute receipt hashes from ballot_cid, embed in... wait,
//            BallotBox is already deployed. Cannot change its RS.
//
// FUNDAMENTAL PROBLEM: BallotBox CID is determined by its RS. The receipt
// RS contains ballot_cid. The BallotBox RS must contain the receipt hash.
// This creates a circular dependency.
//
// BREAKING THE CYCLE: The BallotBox does NOT embed the receipt hash.
// Instead, BallotBox builds the receipt SPK on-stack at execution time.
//
// ## REVISED FINAL DESIGN: On-Stack Receipt SPK Construction
//
// BallotBox v9 knows its own CID via OP_INPUTCOVENANTID. At vote time:
//
//   1. Push vote_side byte (determined by which box's value decreased)
//   2. Get own CID: OP_TXINPUTINDEX OP_INPUTCOVENANTID
//   3. Build receipt RS: push_receipt_body OP_CAT cid OP_CAT [0x20] OP_CAT
//      Actually: RS = [0x20][cid 32B][0x01][side 1B][body N bytes]
//      Build: push(0x20) | push(cid) | OP_CAT | push(0x01) | OP_CAT |
//             push(side) | OP_CAT | push(body) | OP_CAT
//   4. OP_BLAKE2B to get RS hash
//   5. Build P2SH SPK: push([0x00,0x00,0xaa]) | OP_CAT | push(0x87) | OP_CAT
//   6. OP_3 OP_TXOUTPUTSPK to get Output[3] SPK
//   7. OP_EQUAL OP_VERIFY
//
// PROBLEM: The receipt body must be pushed as data within BallotBox.
// VoteReceipt body is ~50-60B. This is pushed via OP_PUSHDATA1 (2B overhead)
// plus the body itself. Total: ~62B added to BallotBox state/body.
//
// COST ANALYSIS FOR ON-STACK APPROACH:
//   - Push receipt body constant:      ~62B
//   - OP_CAT chain to build RS:        ~20B
//   - OP_BLAKE2B:                       1B
//   - Build and compare SPK:           ~10B
//   - Output count check:               4B
//   - Output[3] amount check:           6B
//   - Fee recalculation (4 outputs):    4B
//   Total addition: ~107B to BallotBox
//
// This nearly DOUBLES the BallotBox body (currently 119B).
// BallotBox RS: 187B + 107B = 294B. Still under 520B OP_PUSHDATA2 limit.
//
// ALTERNATIVE: Embed receipt body hash in BallotBox state (not the body
// itself). Then BallotBox cannot verify receipt internals — but can still
// verify Output[3] has some known SPK. The receipt body hash is:
//   h = blake2b(VOTE_RECEIPT_BODY)
// This is a constant! Same for all markets. Embed as 32B state.
//
// Then: RS = [0x20, my_cid, 0x01, vote_side, receipt_body]
// But we need blake2b(RS), not blake2b of individual pieces.
// blake2b is not homomorphic — we cannot compute blake2b(a||b) from
// blake2b(a) and blake2b(b).
//
// So we MUST build the full RS on stack to hash it.
//
// ## PRAGMATIC FINAL DESIGN: VoteReceipt with minimal receipt body
//
// Minimize the receipt body to reduce BallotBox bloat.
//
// VoteReceipt v1 — Minimal receipt covenant:
//
//   State (35B with push opcodes):
//     [0x20] ballot_cid  (32B) — identifies which prediction market
//     [0x01] vote_side   (1B)  — 0x01=YES, 0x00=NO
//
//   Body: Just OP_1 (always spendable, 1B)
//     The receipt is a PROOF OF PARTICIPATION, not a payout mechanism.
//     It proves: "I voted for side X in market with ballot_cid Y"
//     Redemption logic lives in the RewardPool covenant, not the receipt.
//
//   Total RS: 35 + 1 = 36B
//   P2SH SPK: [0x00, 0x00, 0xAA, blake2b(RS), 0x87] = 36B
//
// With OP_1 body, the receipt is freely spendable by anyone who knows the
// redeemScript. But the RS is deterministic — anyone can compute it from
// (ballot_cid, vote_side). This is fine because:
//   1. The receipt UTXO is locked to whoever holds it
//   2. The receipt's VALUE is the miner's stake (dust floor)
//   3. Reward comes from RewardPool, which checks receipt co-input
//
// WAIT — OP_1 means anyone can spend! The receipt needs to be locked to
// the miner. But BallotBox cannot know the miner's public key (it is not
// in BallotBox state, and Input[2]'s SPK is a P2PKH which BallotBox can
// read but cannot embed into the receipt RS).
//
// SOLUTION: Receipt body = OP_1 (unlocked), but the UTXO value IS the
// receipt. Once spent, it cannot be re-presented. The RewardPool only
// needs to see "a UTXO with this specific RS exists as co-input" — it
// does not care who holds it. The miner naturally holds it because it
// was created as Output[3] of their vote TX.
//
// If someone steals the receipt UTXO (front-runs the redemption), the
// miner loses only the dust value. The reward from RewardPool goes to
// whoever presents the receipt. This is acceptable because:
//   - Receipt value is dust (3M sompi = 0.03 KAS)
//   - Front-running requires monitoring all receipt UTXOs and racing
//   - The reward per vote is also small (a few sompi from RewardPool)
//
// For stronger security, make receipt body check a miner-provided key:
//   Body (2B): OP_CHECKSIGVERIFY OP_1
//   The miner signs the redemption TX with the key from their Input[2]
//
// BUT: BallotBox cannot embed the miner's key into the receipt RS
// (it doesn't know it at script compile time). The miner's key varies.
//
// ACTUAL SOLUTION: The receipt RS does NOT contain the miner's key.
// The receipt is an OP_1 "bearer token". Miners must redeem promptly.
// For the amounts involved (dust + small reward), this is acceptable.
//
// ## BallotBox v9 Receipt Verification (Vote Path Addition)
//
// Added after existing V6 (fee==0) check. Receipt verification:
//
// ```
// V7: Output count == 4 (4B)
//   OP_TXOUTPUTCOUNT                // push output count           [1B]
//   OP_4 OP_EQUAL OP_VERIFY        // exactly 4                   [3B]
//
// V8: Build expected receipt P2SH SPK and verify Output[3] (35B)
//   // Build receipt RS on stack: [0x20, ballot_cid, 0x01, vote_side, OP_1]
//   OP_TXINPUTINDEX                 // my input index              [1B]
//   OP_INPUTCOVENANTID              // my ballot_cid (32B hash)    [1B]
//   OP_1 OP_NUM2BIN                 // 0x01 as 1 byte             [2B] (*)
//   OP_CAT                          // [cid || 0x01]              [1B]
//   //(*) Actually: push_data([0x20]) for the RS push opcode prefix
//   //... This approach requires careful byte-level construction.
//
// SIMPLIFIED: Push the known receipt RS hash directly.
// ```
//
// The on-stack construction is complex. Let me provide a concrete
// implementation that works.
//
// ## CONCRETE IMPLEMENTATION
//
// VoteReceipt v1 redeemScript (36B):
//   [0x20][ballot_cid 32B][OP_DROP][OP_1]  — 36B total
//   (Push 32B CID, drop it, leave TRUE)
//   Wait — this is 35B. And vote_side is not encoded.
//
// VoteReceipt v1 with vote_side (37B):
//   [0x20][ballot_cid 32B][0x01][vote_side 1B][OP_2DROP][OP_1]
//   Total: 1+32 + 1+1 + 1+1 = 37B
//   P2SH hash = blake2b(this RS)
//
// Two receipt variants exist (different RS, different P2SH hash):
//   YES receipt: vote_side = 0x01 (OP_1 encoding)
//   NO receipt:  vote_side = 0x00 (OP_0 encoding)
//   Actually use raw bytes: vote_side = 0x01 for YES, 0x00 for NO.
//
// Correction: vote_side in push data, not as opcode.
//   [0x20][ballot_cid 32B][0x01][vote_side_byte][OP_DROP][OP_DROP][OP_1]
//   = 1+32+1+1+1+1+1 = 38B
//
// Even simpler — since the RS only needs to be DIFFERENT for YES vs NO
// and contain the ballot_cid for binding:
//
// VoteReceipt YES RS: [0x20][ballot_cid 32B][OP_DROP][OP_1][OP_1]  = 36B
// VoteReceipt NO  RS: [0x20][ballot_cid 32B][OP_DROP][OP_1]        = 35B
//
// These have different lengths → different hashes. But the semantic meaning
// is unclear. Better to use explicit vote_side:
//
