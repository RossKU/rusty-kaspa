use crate::primitives::push_data;

const OP_1: u8 = 0x51;
const OP_2DROP: u8 = 0x6d;

pub const VOTE_RECEIPT_BODY: &[u8] = &[
    OP_2DROP,   // drop vote_side and ballot_cid    [1B]
    OP_1,       // TRUE (always spendable)          [1B]
    // Padding byte to avoid ambiguity with other 2-byte scripts:
    // Actually, no padding needed. 2B body is fine.
];

// VoteReceipt total RS size: 1 + 32 + 1 + 1 + 2 = 37B
// P2SH SPK: [version 2B][OP_BLAKE2B 1B][hash 32B][OP_EQUAL 1B] = 36B

/// Build VoteReceipt redeemScript.
///
/// State (34B): [0x20][ballot_cid 32B][0x01][vote_side 1B]
/// Body (2B):   [OP_2DROP][OP_1]
/// Total: 37B
///
/// vote_side: 0 = NO, 1 = YES
pub fn build_vote_receipt_redeem_script(
    ballot_cid: &[u8; 32],
    vote_side: u8,
) -> Vec<u8> {
    assert!(vote_side <= 1, "vote_side must be 0 (NO) or 1 (YES)");

    let body = VOTE_RECEIPT_BODY;
    let mut rs = Vec::with_capacity(37);

    // State
    rs.push(0x20);                          // push 32 bytes
    rs.extend_from_slice(ballot_cid);       // ballot_cid
    rs.push(0x01);                          // push 1 byte
    rs.push(vote_side);                     // 0x00=NO, 0x01=YES

    // Body
    rs.extend_from_slice(body);
    rs
}

/// Build VoteReceipt spend sigscript (bearer token — just the RS).
/// Format: [pushData(RS)]
pub fn build_vote_receipt_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    push_data(redeem_script)
}

/// Get VoteReceipt redeemScript for external P2SH hash computation.
///
/// The caller hashes this with UNKEYED blake2b-256 to get the P2SH hash:
///   hash = blake2b_256(redeem_script)  // NO key, NO personalization
///
/// This matches both OP_BLAKE2B (0xaa) and Kaspa's P2SH address derivation.
/// Source: rusty-kaspa Params::new().hash_length(32).to_state().update(&rs).finalize()
///
/// Used at deploy time to pre-compute receipt SPK hashes for RewardPool state.
pub fn vote_receipt_redeem_script_for_hash(
    ballot_cid: &[u8; 32],
    vote_side: u8,
) -> Vec<u8> {
    build_vote_receipt_redeem_script(ballot_cid, vote_side)
}

// BallotBox — Vote Receipt Enabled
//
// v9 extends v8 with atomic vote receipt minting.
//
// APPROACH: On-stack construction of expected receipt P2SH SPK.
//
// The BallotBox builds the receipt redeemScript on-stack at vote time,
// hashes it to get the P2SH SPK, and compares with Output[3]'s actual SPK.
//
// On-stack RS construction sequence:
//   1. Push [0x20] (1B literal for RS push opcode)
//   2. Get my CID: OP_TXINPUTINDEX OP_INPUTCOVENANTID
//   3. OP_CAT → [0x20 || cid]
//   4. Push [0x01] (RS push opcode for vote_side)
//   5. Determine vote_side from which box's value decreased:
//      If MY value decreased → I am the voted side → side=1 if I'm YES
//      Actually, both BallotBoxes run the same script. The voted side is
//      the one whose value decreases. The parity (even/odd) identifies YES/NO.
//
//      PROBLEM: BallotBox does not know its own parity at script level.
//      The RS is identical for YES and NO. Parity comes from the UTXO value.
//      The receipt must encode whether the vote was for YES or NO.
//      But the BallotBox cannot read its own value's parity in the script
//      (OP_MOD requires knowledge of which box I am).
//
//      WAIT — the BallotBox CAN read its own value:
//        OP_TXINPUTINDEX OP_TXINPUTAMOUNT — my value
//        OP_2 OP_MOD — 0 if even (YES), 1 if odd (NO)
//
//      And it knows whether it is the voted side (value decreased vs not).
//      The voted side's value decreases by reward_per_vote.
//      The non-voted side's value is unchanged.
//
//      So: the receipt should encode "voted for the side whose parity is X".
//      The voted BallotBox (Input[0]) has value decrease. Its parity tells
//      which side was voted for.
//
//      From the MINER's perspective: they arrange Input[0] to be the side
//      they vote for. The receipt encodes Input[0]'s parity as vote_side.
//
//      From BallotBox's perspective: BOTH BallotBoxes run their scripts.
//      Each BallotBox at input index I sees:
//        - My value vs my output value → did I decrease?
//        - If I decreased, I am the voted side
//        - Receipt should encode MY parity as vote_side
//        - If I did NOT decrease, receipt should still encode Input[0]'s parity
//
//      This is getting complex. Both BallotBox scripts run, and both must
//      agree on what Output[3] looks like. Since they share a CID, they
//      have the same RS, so they produce the same verification result.
//
//      The receipt SPK must be THE SAME regardless of which BallotBox is
//      checking it. So both scripts must derive the same expected receipt SPK.
//
//      SOLUTION: receipt vote_side = parity of Input[0]'s value.
//      Both BallotBoxes can read Input[0]'s value:
//        OP_0 OP_TXINPUTAMOUNT OP_2 OP_MOD → 0 if Input[0] is YES, 1 if NO
//
//      Actually: the voted side is whichever Input has value decrease.
//      By convention Input[0] is always the voted side (its value decreases).
//      So vote_side = parity of Input[0]'s original value:
//        OP_0 OP_TXINPUTAMOUNT OP_2 OP_MOD → parity of Input[0]'s UTXO
//
//      Wait: Input[0]'s UTXO amount is the PREVIOUS value (before this TX).
//      We want to know which side Input[0] IS (YES or NO), which is
//      determined by its parity. This works regardless of which BallotBox
//      position we are at.
//
//   5 (revised): Push vote_side byte:
//      OP_0 OP_TXINPUTAMOUNT     // Input[0]'s value (previous UTXO)
//      OP_2 OP_MOD               // 0=YES(even), 1=NO(odd)
//      OP_1 OP_NUM2BIN           // convert to 1-byte encoding
//      OP_CAT                    // append to [0x20 || cid || 0x01]
//
//   6. Push receipt body [OP_2DROP, OP_1]:
//      push_data([0x6d, 0x51])   // 2B body
//      OP_CAT                    // full RS on stack
//
//   7. Hash and build SPK:
//      OP_BLAKE2B                // blake2b(RS) → 32B hash
//      push([0x00, 0x00, 0xAA]) // SPK prefix: version(0)+OP_BLAKE2B
//      OP_SWAP OP_CAT            // prefix || hash
//      push([0x87])              // OP_EQUAL
//      OP_CAT                    // full SPK
//
//   8. Compare with Output[3]:
//      OP_3 OP_TXOUTPUTSPK       // Output[3] SPK
//      OP_EQUAL OP_VERIFY
//
// BYTE COUNT for on-stack construction:
//   Step 1: push [0x20] = 2B (0x01, 0x20)
//   Step 2: OP_TXINPUTINDEX OP_INPUTCOVENANTID = 2B
//   Step 3: OP_CAT = 1B
//   Step 4: push [0x01] = 2B (0x01, 0x01)
//   Step 5: OP_CAT = 1B
//   Step 5: OP_0 OP_TXINPUTAMOUNT OP_2 OP_MOD OP_1 OP_NUM2BIN = 6B
//   Step 5: OP_CAT = 1B
//   Step 6: push_data([0x6d, 0x51]) = 3B (0x02, 0x6d, 0x51)
//   Step 6: OP_CAT = 1B
//   Step 7: OP_BLAKE2B = 1B
//   Step 7: push([0x00, 0x00, 0xAA]) = 4B (0x03, 0x00, 0x00, 0xAA)
//   Step 7: OP_SWAP OP_CAT = 2B
//   Step 7: push([0x87]) = 2B (0x01, 0x87)
//   Step 7: OP_CAT = 1B
//   Step 8: OP_3 OP_TXOUTPUTSPK = 2B
//   Step 8: OP_EQUAL OP_VERIFY = 2B
//
//   Subtotal receipt SPK verification: 33B
//
//   Plus:
//   Output count check: OP_TXOUTPUTCOUNT OP_4 OP_EQUAL OP_VERIFY = 4B
//   Output[3] amount >= dust: OP_3 OP_TXOUTPUTAMOUNT push(3M) OP_GTE OP_VERIFY = 8B
//   Fee==0 now sums 4 outputs instead of 3: +2B (OP_3 OP_TXOUTPUTAMOUNT OP_ADD)
//
//   TOTAL ADDITION TO VOTE PATH: 33 + 4 + 8 + 2 = 47B
//
// BallotBox body: 118 + 47 = 165B (body only)
// BallotBox RS: 69 + 165 = 234B (state + body)
//
// This is within Kaspa's P2SH limits.
//
// ## Blockers and Unknowns
//
// 1. OP_BLAKE2B personalization: The P2SH hash uses blake2b with the
//    key "TransactionScriptPublicKeyBlake2" (from Kaspa source).
//    OP_BLAKE2B in script uses a DIFFERENT personalization
//    ("BlockHashBlake2bHash" per kaspa-hashes, or possibly none).
//    If OP_BLAKE2B uses a different personalization than the P2SH
//    address derivation, the on-stack hash will NOT match.
//    THIS MUST BE VERIFIED AGAINST THE ACTUAL OP_BLAKE2B IMPLEMENTATION.
//
// 2. SPK format: OpTxOutputSpk pushes version(2B BE) ++ script.
//    The P2SH script is [OP_BLAKE2B, hash, OP_EQUAL].
//    SPK bytes: [0x00, 0x00, 0xAA, <32B>, 0x87] = 36 bytes.
//    Need to verify this matches what OP_TXOUTPUTSPK pushes.
//
// 3. OP_NUM2BIN size limit: Max 8 bytes. We use size=1, which is fine.
//    But OP_0 OP_TXINPUTAMOUNT might push a number that OP_MOD returns
//    as 0 or 1 (i64). OP_1 OP_NUM2BIN converts to [0x00] or [0x01].
//    Need to verify this matches [0x00] and [0x01] byte values.
//
// 4. OP_MOD behavior with signed numbers: Input amounts are always
//    positive, so OP_MOD result is always 0 or 1. No sign issues.
//
// 5. HF dependency: All covenant opcodes require the Covenants++ HF
//    (~June 2026). This includes OP_CAT, OP_NUM2BIN, OP_BLAKE2B in
//    script context, and all OpCov* opcodes.

// OP_BLAKE2B personalization: VERIFIED COMPATIBLE
// Both OP_BLAKE2B (0xaa) and P2SH address derivation use UNKEYED blake2b-256:
//   Script:  Params::new().hash_length(32).to_state().update(&data).finalize()
//   P2SH:    Params::new().hash_length(32).to_state().update(redeem_script).finalize()
// Source: rusty-kaspa/crypto/txscript/src/opcodes/mod.rs line 872
//         rusty-kaspa/crypto/txscript/src/standard.rs line 51
//
// This means BallotBox CAN build the receipt P2SH SPK on-stack using OP_BLAKE2B
// and the result WILL match the actual P2SH address. Blocker #1 is RESOLVED.
//
// Additionally, OpBlake2bWithKey (0xa7) is available for keyed hashes if needed.

// RECEIPT_DUST_FLOOR is defined in ballot_box.rs
