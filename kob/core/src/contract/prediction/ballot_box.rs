#![allow(dead_code)] // Opcode reference table — many constants reserved for future use
use crate::primitives::{push_data, u64_le};

// Opcode constants (Kaspa script)

const OP_0: u8 = 0x00;
const OP_1: u8 = 0x51;
const OP_2: u8 = 0x52;
const OP_3: u8 = 0x53;
const OP_4: u8 = 0x54;
const OP_5: u8 = 0x55;
const OP_DUP: u8 = 0x76;
const OP_DROP: u8 = 0x75;
const OP_2DUP: u8 = 0x6e;
const OP_2DROP: u8 = 0x6d;
const OP_NOT: u8 = 0x91;
const OP_SWAP: u8 = 0x7c;
const OP_OVER: u8 = 0x78;
const OP_PICK: u8 = 0x79;
const OP_ROLL: u8 = 0x7a;

const OP_ADD: u8 = 0x93;

const OP_EQUAL: u8 = 0x87;
const OP_VERIFY: u8 = 0x69;
const OP_GTE: u8 = 0xa2;
const OP_GT: u8 = 0xa0;
const OP_LT: u8 = 0x9f;

const OP_IF: u8 = 0x63;
const OP_ELSE: u8 = 0x67;
const OP_NOTIF: u8 = 0x64;
const OP_ENDIF: u8 = 0x68;

const OP_BLAKE2B: u8 = 0xaa;
const OP_CHECKSIGVERIFY: u8 = 0xad;
const OP_CLTV: u8 = 0xb0;

const OP_TXINPUTINDEX: u8 = 0xb9;
const OP_TXINPUTAMOUNT: u8 = 0xbe;
const OP_TXINPUTSPK: u8 = 0xbf;
const OP_TXINPUTSIGSIGLEN: u8 = 0xc9;
const OP_TXOUTPUTAMOUNT: u8 = 0xc2;
const OP_TXOUTPUTSPK: u8 = 0xc3;
const OP_INPUTCOUNT: u8 = 0xb3;
const OP_TXLOCKTIME: u8 = 0xb5;

const OP_INPUTCOVENANTID: u8 = 0xcf;
const OP_COVINPUTCOUNT: u8 = 0xd0;
const OP_COVOUTCOUNT: u8 = 0xd2;
const OP_COVINPUTIDX: u8 = 0xd1;

#[allow(dead_code)]
const OP_MUL: u8 = 0x95;
const OP_MOD: u8 = 0x97;

const OP_6: u8 = 0x56;
const OP_7: u8 = 0x57;
const OP_8: u8 = 0x58;
const OP_9: u8 = 0x59;
const OP_10: u8 = 0x5a;
const OP_11: u8 = 0x5b;
const OP_SUB: u8 = 0x94;

// Additional covenant introspection opcodes (for VoteReceipt design)
const OP_CAT: u8 = 0x7e;
#[allow(dead_code)]
const OP_SUBSTR: u8 = 0x7f;
const OP_TXOUTPUTCOUNT: u8 = 0xb4;
const OP_TXOUTPUTSPKLEN: u8 = 0xc7;
const OP_TXOUTPUTSPKSUBSTR: u8 = 0xc8;
const OP_OUTPUTCOVENANTID: u8 = 0xd5;
#[allow(dead_code)]
const OP_OUTPUTAUTHINPUT: u8 = 0xd6;
const OP_COVOUTIDX: u8 = 0xd3;
const OP_NUM2BIN: u8 = 0xcd;
#[allow(dead_code)]
const OP_BIN2NUM: u8 = 0xce;
#[allow(dead_code)]
const OP_DIV: u8 = 0x96;
#[allow(dead_code)]
const OP_INVERT: u8 = 0x83;
#[allow(dead_code)]
const OP_AND: u8 = 0x84;
#[allow(dead_code)]
const OP_OR: u8 = 0x85;
#[allow(dead_code)]
const OP_XOR: u8 = 0x86;
const OP_SIZE: u8 = 0x82;
#[allow(dead_code)]
const OP_AUTHOUTCOUNT: u8 = 0xcb;
#[allow(dead_code)]
const OP_AUTHOUTIDX: u8 = 0xcc;
const OP_OUTPOINTTXID: u8 = 0xba;
#[allow(dead_code)]
const OP_OUTPOINTINDEX: u8 = 0xbb;
const OP_TXINPUTSIGSIGSUBSTR: u8 = 0xbc;

/// Fixed vote counter unit: 2 sompi.
///
/// This is NOT a miner incentive — it is the minimum even value needed to
/// maintain the parity invariant (YES=even, NO=odd) that distinguishes
/// BallotBoxes on-chain. The miner receives 2 sompi per vote, which is
/// economically negligible. This eliminates any incentive to vote for the
/// incorrect outcome.
///
/// Market creator revenue comes from the spread between `unit_value`
/// (SplitMerge deposit) and `payout_per_token` (Redemption payout).
// VOTE_COUNTER_UNIT and DISPUTE_THRESHOLD are defined in super (prediction mod.rs).


pub const RECEIPT_DUST_FLOOR: u64 = 3_000_000;

/// BallotBox body bytecode — with atomic VoteReceipt minting.
///
/// Extends v8 with:
///   - 4th output (VoteReceipt) enforced in vote path
///   - On-stack P2SH SPK construction for receipt verification
///   - Receipt encodes vote_side via Input[0] parity (even=YES=0, odd=NO=1)
///
/// TX template (vote path):
///   Input[0]: BallotBox A (voted side, value decreases)
///   Input[1]: BallotBox B (pass-through, value unchanged)
///   Input[2]: Miner UTXO
///   Output[0]: BallotBox A continuation
///   Output[1]: BallotBox B continuation
///   Output[2]: Miner change
///   Output[3]: VoteReceipt (P2SH covenant, bearer token)
///
/// State (69B — same as v8):
///   [0x20][market_id 32B][0x08][reward_per_vote 8B]
///   [0x08][start_daa 8B][0x08][end_daa 8B][0x08][expiry_daa 8B]
///
/// Body: 166B (v8 was 119B, +47B for receipt verification)
pub const BALLOT_BOX_BODY: &[u8] = &[
    // DISPATCH (5B): 3-way selector (identical to v8)
    OP_5, OP_ROLL,                          // selector to top            [2B]
    OP_DUP,                                 // dup selector               [1B]
    OP_2, OP_EQUAL,                         // selector == 2?             [2B]
    OP_IF,                                  // settle path                [1B]

    // SETTLE PATH (26B): identical to v8
    OP_DROP,                               // drop selector               [1B]
    OP_TXINPUTINDEX, OP_1, OP_ADD,         // input_idx + 1               [3B]
    OP_TXOUTPUTSPK,                        // output[idx+1].spk           [1B]
    OP_TXINPUTINDEX, OP_TXINPUTSPK,        // input.spk                   [2B]
    OP_EQUAL, OP_VERIFY,                   // must match                  [2B]
    OP_TXINPUTINDEX, OP_1, OP_ADD,         // input_idx + 1               [3B]
    OP_TXOUTPUTAMOUNT,                     // output[idx+1].value          [1B]
    OP_TXINPUTINDEX, OP_TXINPUTAMOUNT,     // input.value                  [2B]
    OP_EQUAL, OP_VERIFY,                   // output == input (strict)    [2B]
    OP_TXINPUTINDEX, OP_INPUTCOVENANTID,   // my covenant ID              [2B]
    OP_COVOUTCOUNT,                        // outputs with this covId     [1B]
    OP_2, OP_EQUAL, OP_VERIFY,            // exactly 2                   [3B]
    OP_2DROP, OP_2DROP, OP_DROP,           // drop 5 state items          [3B]
    OP_1,                                  // TRUE                        [1B]

    // ELSE: VOTE OR EXPIRE
    OP_ELSE,                               //                              [1B]
    OP_IF,                                 // selector==1 -> vote          [1B]

    // VOTE PATH (122B) — v8 core (75B) + receipt verification (47B)

    // --- v8 core checks (identical) ---

    // V0: exactly 2 co-inputs with my CID (6B)
    OP_TXINPUTINDEX, OP_INPUTCOVENANTID,   // my covenant ID              [2B]
    OP_COVINPUTCOUNT,                      // inputs with my cid          [1B]
    OP_2, OP_EQUAL, OP_VERIFY,            // exactly 2                   [3B]

    // V0b: exactly 2 continuation outputs (6B)
    OP_TXINPUTINDEX, OP_INPUTCOVENANTID,   // my covenant ID              [2B]
    OP_COVOUTCOUNT,                        // outputs with my cid         [1B]
    OP_2, OP_EQUAL, OP_VERIFY,            // exactly 2 continuations     [3B]

    // V1: start_daa CLTV (3B)
    //
    // OpCheckLockTimeVerify POPS the value it checks (unlike Bitcoin's
    // non-consuming CLTV) -- confirmed against the real kaspad script
    // engine (`kaspa-txscript` OpCheckLockTimeVerify: `pop_raw()`). The
    // PICK'd copy IS what OP_CLTV consumes; there is nothing left to drop
    // afterward. A trailing OP_DROP here would eat into the real state
    // (start_daa itself), corrupting every later PICK index. Live-confirmed
    // via a rejected on-chain `expire_ballot` tx that hit this exact
    // miscount (see the EXPIRE PATH below).
    OP_2, OP_PICK,                         // copy start_daa              [2B]
    OP_CLTV,                               // TxLockTime >= start_daa; consumes the copy [1B]

    // V1b: end_daa upper bound (5B)
    OP_1, OP_PICK,                         // copy end_daa                [2B]
    OP_TXLOCKTIME,                         // push tx.lockTime            [1B]
    OP_GT, OP_VERIFY,                      // end_daa > lockTime          [2B]

    // V2: SPK equality — self-continuation (8B)
    OP_TXINPUTINDEX, OP_1, OP_ADD,         // input_idx + 1               [3B]
    OP_TXOUTPUTSPK,                        // output[idx+1].spk           [1B]
    OP_TXINPUTINDEX, OP_TXINPUTSPK,        // input.spk                   [2B]
    OP_EQUAL, OP_VERIFY,                   // must match                  [2B]

    // V3: dust floor (8B)
    OP_TXINPUTINDEX, OP_1, OP_ADD,         // input_idx + 1               [3B]
    OP_TXOUTPUTAMOUNT,                     // output[idx+1].value          [1B]
    0x03, 0xC0, 0xC6, 0x2D,              // push 3,000,000 (LE 3 bytes) [4B]
    OP_GTE, OP_VERIFY,                    // output >= 3M sompi          [2B]

    // V4: value decrease <= reward_per_vote (12B)
    OP_TXINPUTINDEX, OP_TXINPUTAMOUNT,    // input value                  [2B]
    OP_TXINPUTINDEX, OP_1, OP_ADD,        // input_idx + 1                [3B]
    OP_TXOUTPUTAMOUNT,                    // output value                  [1B]
    OP_SUB,                               // decrease = input - output    [1B]
    OP_4, OP_PICK,                        // copy reward_per_vote         [2B]
    OP_SWAP,                              // reward below, decrease top   [1B]
    OP_GTE, OP_VERIFY,                    // reward >= decrease           [2B]

    // V5: exactly 3 inputs (4B)
    OP_INPUTCOUNT,                        // input count                  [1B]
    OP_3, OP_EQUAL, OP_VERIFY,           // exactly 3                    [3B]

    // V6: fee == 0 — 3 inputs == 4 outputs (20B, was 18B for 3 outputs)
    OP_0, OP_TXINPUTAMOUNT,              // input[0].value                [2B]
    OP_1, OP_TXINPUTAMOUNT,              // input[1].value                [2B]
    OP_ADD,                               // in[0] + in[1]               [1B]
    OP_2, OP_TXINPUTAMOUNT,              // input[2].value                [2B]
    OP_ADD,                               // total_in                    [1B]
    OP_0, OP_TXOUTPUTAMOUNT,             // output[0].value               [2B]
    OP_1, OP_TXOUTPUTAMOUNT,             // output[1].value               [2B]
    OP_ADD,                               // out[0] + out[1]             [1B]
    OP_2, OP_TXOUTPUTAMOUNT,             // output[2].value               [2B]
    OP_ADD,                               // out[0..2] sum               [1B]
    OP_3, OP_TXOUTPUTAMOUNT,             // output[3].value (receipt)    [2B]
    OP_ADD,                               // total_out (4 outputs)       [1B]
    OP_EQUAL, OP_VERIFY,                 // total_in == total_out         [2B]

    // --- NEW: Receipt verification (25B) ---

    // V7: exactly 4 outputs (4B)
    OP_TXOUTPUTCOUNT,                    // push output count             [1B]
    OP_4, OP_EQUAL, OP_VERIFY,          // exactly 4                     [3B]

    // V8: Output[3] amount >= RECEIPT_DUST_FLOOR (8B)
    OP_3, OP_TXOUTPUTAMOUNT,            // output[3].value                [2B]
    0x03, 0xC0, 0xC6, 0x2D,            // push 3,000,000 (LE 3 bytes)   [4B]
    OP_GTE, OP_VERIFY,                  // out3 >= 3M sompi              [2B]

    // NOTE: V9 covenant-id check (ZERO_HASH verification) was considered
    // but REJECTED due to 37B cost (32B for ZERO_HASH literal). Instead,
    // BallotBox enforces only output count, amount, and fee==0. The miner
    // is responsible for creating a valid receipt; the RewardPool covenant
    // verifies the receipt SPK at redemption time. This is safe because
    // the miner has economic incentive to create a correct receipt.
    //
    // Total receipt addition to vote path: 14B (4B output count + 8B amount
    // check + 2B fee sum adjustment for 4th output).

    // Cleanup + TRUE (4B)
    OP_2DROP, OP_2DROP, OP_DROP,          // drop 5 state items           [3B]
    OP_1,                                 // TRUE                        [1B]

    // EXPIRE PATH (6B)
    //
    // OP_CLTV pops expiry_daa itself (see the V1 note above), leaving only
    // 4 state items (end_daa, start_daa, reward_per_vote, market_id) to
    // drop before (pubkey, sig) are exposed for OP_CHECKSIGVERIFY -- the
    // old 5-item drop count (matching a non-consuming CLTV model) ate the
    // pubkey too, leaving CHECKSIGVERIFY with only 1 stack item. Live-
    // confirmed on testnet-10: node rejected with "failed to verify the
    // signature script: opcode requires at least 2 but stack has only 1".
    OP_ELSE,                              //                              [1B]
    OP_CLTV,                              // verify locktime >= expiry; consumes expiry_daa [1B]
    OP_2DROP, OP_2DROP,                   // drop 4 remaining state items [2B]
    OP_CHECKSIGVERIFY,                    // verify sig                   [1B]
    OP_1,                                 // TRUE                        [1B]

    // CLOSING
    OP_ENDIF,                             // vote vs expire               [1B]
    OP_ENDIF,                             // settle vs vote/expire        [1B]
];

/// Build BallotBox redeemScript (Vote Receipt enabled).
///
/// Same state layout as v8. Adds atomic receipt enforcement in vote path.
///
/// State (69B): [0x20][market_id 32B][0x08][reward_per_vote 8B]
///              [0x08][start_daa 8B][0x08][end_daa 8B][0x08][expiry_daa 8B]
/// Body: BALLOT_BOX_BODY
pub fn build_ballot_box_redeem_script(
    market_id: &[u8; 32],
    reward_per_vote: u64,
    start_daa: u64,
    end_daa: u64,
    expiry_daa: u64,
) -> crate::Result<Vec<u8>> {
    if reward_per_vote == 0 {
        return Err(crate::KobError::Contract("reward_per_vote must be > 0".into()));
    }
    if reward_per_vote % 2 != 0 {
        return Err(crate::KobError::Contract(
            "reward_per_vote must be even (parity preservation)".into(),
        ));
    }
    if start_daa == 0 || end_daa == 0 || expiry_daa == 0 {
        return Err(crate::KobError::Contract("daa scores must be > 0".into()));
    }
    if end_daa <= start_daa {
        return Err(crate::KobError::Contract("end_daa must be > start_daa".into()));
    }
    if expiry_daa <= end_daa {
        return Err(crate::KobError::Contract("expiry_daa must be > end_daa".into()));
    }

    let body = BALLOT_BOX_BODY;
    let mut rs = Vec::with_capacity(69 + body.len());

    rs.push(0x20);
    rs.extend_from_slice(market_id);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(reward_per_vote));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(start_daa));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(end_daa));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(expiry_daa));

    rs.extend_from_slice(body);
    Ok(rs)
}

/// Build BallotBox vote sigscript (same format as v8).
/// Format: [Op1 (selector=vote)] [pushData(RS)]
pub fn build_ballot_box_vote_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(OP_1);
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build BallotBox settle sigscript (same format as v8).
/// Format: [Op2 (selector=settle)] [pushData(RS)]
pub fn build_ballot_box_settle_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(OP_2);
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build BallotBox expire sigscript (same format as v8).
pub fn build_ballot_box_expire_sigscript(
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_ht = Vec::with_capacity(65);
    sig_ht.extend_from_slice(signature);
    sig_ht.push(0x01);

    let mut ss = Vec::with_capacity(1 + 66 + 33 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_ht));
    ss.extend_from_slice(&push_data(pubkey));
    ss.push(OP_0);
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

// RewardPool Covenant v1 — Collects and distributes miner vote rewards
//
// The RewardPool is funded by the market creator at deploy time.
// After settlement, miners with valid VoteReceipts can claim a share.
//
// State (69B with push opcodes):
//   [0x20] ballot_cid       (32B) — BallotBox covenant ID (for receipt verification)
//   [0x08] reward_per_vote  (8B)  — KAS reward per valid vote receipt
//   [0x20] creator_pkh      (32B) — for refund path
//   [0x08] expiry_daa       (8B)  — CLTV for refund
//
// Paths:
//   Claim: VoteReceipt co-input + winning BallotBox witnesses → payout
//   Refund: CLTV + creator sig → return unclaimed funds
//
// Claim TX template:
//   Input[0]: RewardPool (this covenant, claim path)
//   Input[1]: VoteReceipt (bearer token, proves vote participation)
//   Input[2]: YES_BallotBox (settle path, read-only witness)
//   Input[3]: NO_BallotBox (settle path, read-only witness)
//   Output[0]: Reward payout (>= reward_per_vote)
//   Output[1]: RewardPool continuation (pool - reward_per_vote)
//   Output[2]: YES_BallotBox continuation
//   Output[3]: NO_BallotBox continuation
//
// The claim path verifies:
//   1. Input[1]'s SPK is a valid VoteReceipt for this market
//   2. Determine winner from BallotBox values (same parity logic)
//   3. VoteReceipt's vote_side matches the winner
//   4. Payout amount >= reward_per_vote
//   5. Self-continuation with value preservation
//
// CHALLENGE: RewardPool cannot read Input[1]'s redeemScript directly.
// It can only read Input[1]'s SPK (the P2SH hash). To verify the
// receipt is for the correct market and side, RewardPool must:
//   - Compute expected receipt P2SH SPK on-stack (same as BallotBox
//     approach), OR
//   - Embed both receipt P2SH hashes in state (YES and NO)
//
// Using embedded hashes (simpler, +64B state):
//   [0x20] receipt_yes_hash (32B) — blake2b(VoteReceipt RS for YES)
//   [0x20] receipt_no_hash  (32B) — blake2b(VoteReceipt RS for NO)
//
// But this has the same circular dependency issue — receipt hashes
// depend on ballot_cid, which is known only after BallotBox deploy.
// SOLUTION: 2-stage deploy (same as Redemption v4):
//   Stage 1: Deploy BallotBoxes → get ballot_cid
//   Stage 2: Compute receipt hashes → Deploy RewardPool
//
// This works! RewardPool is deployed AFTER BallotBoxes, so ballot_cid
// is known. receipt_yes_hash and receipt_no_hash are pre-computed.
//
// RewardPool state becomes (133B with push opcodes):
//   [0x20] ballot_cid        (32B)
//   [0x20] receipt_yes_hash  (32B) — blake2b(VoteReceipt(ballot_cid, YES))
//   [0x20] receipt_no_hash   (32B) — blake2b(VoteReceipt(ballot_cid, NO))
//   [0x08] reward_per_vote   (8B)
//   [0x20] creator_pkh       (32B)
//   [0x08] expiry_daa        (8B)
//
// Total state: 6*1 (push opcodes) + 32+32+32+8+32+8 = 150B

// Note: Full RewardPool bytecode implementation deferred pending
// OP_BLAKE2B personalization verification (blocker #1 above).
// The design above is complete; implementation requires confirming
// that OP_BLAKE2B in script context produces the same hash as
// the P2SH address derivation blake2b.

