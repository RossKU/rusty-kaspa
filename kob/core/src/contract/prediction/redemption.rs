#![allow(dead_code)] // Opcode reference table — many constants reserved for future use
use crate::primitives::{push_data, u64_le};

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
const OP_SUB: u8 = 0x94;
const OP_MOD: u8 = 0x97;
const OP_EQUAL: u8 = 0x87;
const OP_VERIFY: u8 = 0x69;
const OP_GTE: u8 = 0xa2;
#[allow(dead_code)]
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
#[allow(dead_code)]
const OP_TXINPUTSPK: u8 = 0xbf;
const OP_TXOUTPUTAMOUNT: u8 = 0xc2;
const OP_TXOUTPUTSPK: u8 = 0xc3;
const OP_INPUTCOVENANTID: u8 = 0xcf;
const OP_COVINPUTCOUNT: u8 = 0xd0;
const OP_COVINPUTIDX: u8 = 0xd1;
const OP_COVOUTCOUNT: u8 = 0xd2;
const OP_6: u8 = 0x56;
const OP_7: u8 = 0x57;
const OP_8: u8 = 0x58;
const OP_9: u8 = 0x59;
const OP_10: u8 = 0x5a;
const OP_11: u8 = 0x5b;

// Redemption Covenant — Receipt Redeem Path
//
// Correct voters can claim rewards from the Redemption pool using their
// VoteReceipt bearer tokens.
//
// 3-way dispatch via selector:
//   selector=2: Receipt Redeem (NEW) — VoteReceipt holder claims reward
//   selector=1: Token Redeem   (from v6) — Winning token holder claims payout
//   selector=0: Refund         (from v6) — Creator reclaims after expiry
//
// State (267B with push opcodes):
//   [0x20][market_id 32B]
//   [0x20][ballot_cid 32B]
//   [0x20][yes_token_cid 32B]
//   [0x20][no_token_cid 32B]
//   [0x08][payout_per_token 8B]
//   [0x08][threshold_value 8B]
//   [0x20][creator_pkh 32B]
//   [0x08][expiry_daa 8B]
//   --- NEW (75B) ---
//   [0x08][reward_per_receipt 8B]
//   [0x20][yes_receipt_cid 32B]
//   [0x20][no_receipt_cid 32B]
//
// Stack after state push (11 items, top=0):
//   no_receipt_cid(0), yes_receipt_cid(1), reward_per_receipt(2),
//   expiry_daa(3), creator_pkh(4), threshold(5), payout(6),
//   no_tok(7), yes_tok(8), ballot_cid(9), market_id(10)
//
// Selector at depth 11 → OP_11 OP_ROLL for dispatch.
//
// Receipt Redeem TX template:
//   Input[0]: Redemption UTXO (pool)
//   Input[1]: BallotBox YES (witness, settle path)
//   Input[2]: BallotBox NO (witness, settle path)
//   Input[3]: VoteReceipt (winning side)
//   Output[0]: Reward payout to receipt holder
//   Output[1]: Redemption continuation
//   Output[2]: BallotBox YES continuation
//   Output[3]: BallotBox NO continuation
//
// Token Redeem TX template (same as v6):
//   Input[0]: Redemption UTXO (pool)
//   Input[1]: BallotBox YES (witness, settle path)
//   Input[2]: BallotBox NO (witness, settle path)
//   Input[3]: Winning token (co-input)
//   Output[0]: Payout to token holder
//   Output[1]: Redemption continuation
//
// Sigscript formats:
//   Receipt Redeem: [Op2(selector)] [pushData(RS)]                         sigOpCount=0
//   Token Redeem:   [Op1(selector)] [pushData(RS)]                         sigOpCount=0
//   Refund:         [push(sig+0x01)] [push(pk)] [Op0(selector)] [pushData(RS)] sigOpCount=1

/// Redemption body bytecode.
///
/// 3-way dispatch: receipt redeem (2) / token redeem (1) / refund (0).
/// Receipt path reuses BallotBox parity + winner logic from v6, but checks
/// VoteReceipt CID instead of token CID and pays reward_per_receipt.
pub const REDEMPTION_BODY: &[u8] = &[
    // DISPATCH (6B)
    OP_11, OP_ROLL,                        // selector to top              [2B]
    OP_DUP, OP_2, OP_EQUAL,               // selector == 2?               [3B]
    OP_IF,                                 // receipt redeem path           [1B]

    // RECEIPT REDEEM PATH (selector=2) — 75B
    // Stack: selector(0), no_receipt_cid(1), yes_receipt_cid(2),
    //        reward_per_receipt(3), expiry_daa(4), creator_pkh(5),
    //        threshold(6), payout(7), no_tok(8), yes_tok(9),
    //        ballot_cid(10), market_id(11)
    OP_DROP,                               // drop selector                [1B]
    // Stack (11 items):
    //   no_receipt_cid(0), yes_receipt_cid(1), reward_per_receipt(2),
    //   expiry_daa(3), creator_pkh(4), threshold(5), payout(6),
    //   no_tok(7), yes_tok(8), ballot_cid(9), market_id(10)

    // RR1: Get both BallotBox input indices via OP_COVINPUTIDX (8B)
    OP_9, OP_PICK,                         // copy ballot_cid (idx 9)      [2B]
    OP_0, OP_COVINPUTIDX,                  // idx_first (1st instance)     [2B]
    OP_10, OP_PICK,                        // copy ballot_cid (idx 10)     [2B]
    OP_1, OP_COVINPUTIDX,                  // idx_second (2nd instance)    [2B]
    // Stack: idx_second(0), idx_first(1), + 11 state items

    // RR2: Read both values (4B)
    OP_SWAP,                               // idx_first on top             [1B]
    OP_TXINPUTAMOUNT,                      // val_first                    [1B]
    OP_SWAP,                               // idx_second on top            [1B]
    OP_TXINPUTAMOUNT,                      // val_second                   [1B]
    // Stack: val_second(0), val_first(1), + 11 state items
    //   threshold is at idx 5+2=7

    // RR2.5: Total vote count check — dispute threshold (7B)
    OP_2DUP,                               // copy val_second, val_first   [1B]
    OP_ADD,                                // sum                          [1B]
    OP_8, OP_PICK,                         // threshold (idx 8)            [2B]
    OP_SWAP,                               // sum on top, threshold below  [1B]
    OP_GTE, OP_VERIFY,                     // threshold >= sum             [2B]
    // Stack unchanged: val_second(0), val_first(1), + 11 state items

    // RR3: Normalize to YES_val(0), NO_val(1) using parity (6B)
    OP_OVER,                               // copy val_first               [1B]
    OP_2, OP_MOD,                          // val_first MOD 2              [2B]
    OP_NOTIF,                              // if even (val_first=YES)      [1B]
      OP_SWAP,                             // swap to get YES(0), NO(1)    [1B]
    OP_ENDIF,                              //                              [1B]

    // RR4: Tie rejection (4B)
    OP_2DUP,                               // copy YES_val, NO_val         [1B]
    OP_EQUAL, OP_NOT, OP_VERIFY,           // reject tie                   [3B]

    // RR5: Winner determination + receipt co-input check (16B)
    // After OP_SWAP+OP_LT consumes both vals:
    //   no_receipt(0), yes_receipt(1), reward(2), expiry(3), creator(4),
    //   threshold(5), payout(6), no_tok(7), yes_tok(8), ballot_cid(9), market_id(10)
    OP_SWAP,                               // NO_val(0), YES_val(1)        [1B]
    OP_LT,                                 // YES_val < NO_val?            [1B]
    OP_IF,                                 // YES wins (lower value)       [1B]
      OP_1, OP_PICK,                       // yes_receipt_cid (idx 1)      [2B]
      OP_COVINPUTCOUNT,                    // count inputs with yes CID    [1B]
      OP_1, OP_GTE, OP_VERIFY,            // >= 1 receipt present         [3B]
    OP_ELSE,                               // NO wins                      [1B]
      OP_DUP,                              // no_receipt_cid (idx 0)       [1B]
      OP_COVINPUTCOUNT,                    // count inputs with no CID     [1B]
      OP_1, OP_GTE, OP_VERIFY,            // >= 1 receipt present         [3B]
    OP_ENDIF,                              //                              [1B]

    // RR6: Payout check — output[0] >= reward_per_receipt (6B)
    OP_0, OP_TXOUTPUTAMOUNT,               // output[0].value              [2B]
    OP_3, OP_PICK,                         // reward_per_receipt (idx 3)   [2B]
    OP_GTE, OP_VERIFY,                     // out0 >= reward               [2B]

    // RR7: Self-continuation — exactly 1 output with my covenant ID (6B)
    OP_TXINPUTINDEX, OP_INPUTCOVENANTID,   // my covenant ID               [2B]
    OP_COVOUTCOUNT,                        // count of outputs with covId  [1B]
    OP_1, OP_EQUAL, OP_VERIFY,            // exactly 1 continuation       [3B]

    // RR8: Pool conservation — out[1] >= in[0] - reward (10B)
    OP_0, OP_TXINPUTAMOUNT,                // input[0].value (pool)        [2B]
    OP_3, OP_PICK,                         // reward_per_receipt (idx 3)   [2B]
    OP_SUB,                                // pool - reward                [1B]
    OP_1, OP_TXOUTPUTAMOUNT,               // output[1].value (cont.)     [2B]
    OP_SWAP,                               // expected(0), out1(1)         [1B]
    OP_GTE, OP_VERIFY,                     // out1 >= expected             [2B]

    // RR9: Cleanup 11 state items + TRUE (7B)
    OP_2DROP, OP_2DROP, OP_2DROP,          // drop 6 items                 [3B]
    OP_2DROP, OP_2DROP,                    // drop 4 items                 [2B]
    OP_DROP,                               // drop 11th item               [1B]
    OP_1,                                  // TRUE                         [1B]

    // SELECTOR 0 or 1 — token redeem or refund
    OP_ELSE,                               //                              [1B]
    // Stack: selector(0), no_receipt_cid(1), yes_receipt_cid(2),
    //        reward_per_receipt(3), expiry_daa(4), creator_pkh(5),
    //        threshold(6), payout(7), no_tok(8), yes_tok(9),
    //        ballot_cid(10), market_id(11)
    //
    // Inner OP_IF consumes selector: 1=token, 0=refund
    OP_IF,                                 // selector=1 → token redeem    [1B]

    // TOKEN REDEEM PATH (selector=1) — 76B
    // Stack: no_receipt_cid(0), yes_receipt_cid(1), reward_per_receipt(2),
    //        expiry_daa(3), creator_pkh(4), threshold(5), payout(6),
    //        no_tok(7), yes_tok(8), ballot_cid(9), market_id(10)

    // TR0: Drop 5 items not needed: 3 receipt items + expiry + creator (5B)
    OP_2DROP, OP_DROP,                     // drop no_receipt, yes_receipt, reward  [3B]
    OP_DROP, OP_DROP,                      // drop expiry_daa, creator_pkh          [2B]
    // Stack: threshold(0), payout(1), no_tok(2), yes_tok(3),
    //        ballot_cid(4), market_id(5) — identical to v6 after R0

    // TR1 (= v6 R1): Get both BallotBox input indices (8B)
    OP_4, OP_PICK,                         // copy ballot_cid              [2B]
    OP_0, OP_COVINPUTIDX,                  // idx_first                    [2B]
    OP_5, OP_PICK,                         // copy ballot_cid (depth+1)    [2B]
    OP_1, OP_COVINPUTIDX,                  // idx_second                   [2B]

    // TR2 (= v6 R2): Read both values (4B)
    OP_SWAP, OP_TXINPUTAMOUNT,             // val_first                    [2B]
    OP_SWAP, OP_TXINPUTAMOUNT,             // val_second                   [2B]

    // TR2.5 (= v6 R2.5): Vote count check (7B)
    OP_2DUP, OP_ADD,                       // sum                          [2B]
    OP_3, OP_PICK,                         // threshold_value (idx 3)      [2B]
    OP_SWAP, OP_GTE, OP_VERIFY,            // threshold >= sum             [3B]

    // TR3 (= v6 R3): Normalize parity (6B)
    OP_OVER,                               // copy val_first               [1B]
    OP_2, OP_MOD,                          // val_first MOD 2              [2B]
    OP_NOTIF,                              // if even (YES)                [1B]
      OP_SWAP,                             // YES(0), NO(1)                [1B]
    OP_ENDIF,                              //                              [1B]

    // TR4 (= v6 R4): Tie rejection (4B)
    OP_2DUP, OP_EQUAL, OP_NOT, OP_VERIFY, // reject tie                   [4B]

    // TR5 (= v6 R5): Winner + token co-input check (16B)
    OP_SWAP,                               // NO_val(0), YES_val(1)        [1B]
    OP_LT,                                 // YES_val < NO_val?            [1B]
    OP_IF,                                 // YES wins                     [1B]
      OP_3, OP_PICK,                       // yes_token_cid (idx 3)        [2B]
      OP_COVINPUTCOUNT,                    // count YES token inputs       [1B]
      OP_1, OP_GTE, OP_VERIFY,            // >= 1                         [3B]
    OP_ELSE,                               // NO wins                      [1B]
      OP_2, OP_PICK,                       // no_token_cid (idx 2)         [2B]
      OP_COVINPUTCOUNT,                    // count NO token inputs        [1B]
      OP_1, OP_GTE, OP_VERIFY,            // >= 1                         [3B]
    OP_ENDIF,                              //                              [1B]

    // TR6 (= v6 R6): Payout check (6B)
    OP_0, OP_TXOUTPUTAMOUNT,               // output[0].value              [2B]
    OP_2, OP_PICK,                         // payout_per_token (idx 2)     [2B]
    OP_GTE, OP_VERIFY,                     // out0 >= payout               [2B]

    // TR7 (= v6 R7): Self-continuation (6B)
    OP_TXINPUTINDEX, OP_INPUTCOVENANTID,   // my covenant ID               [2B]
    OP_COVOUTCOUNT,                        //                              [1B]
    OP_1, OP_EQUAL, OP_VERIFY,            // exactly 1                    [3B]

    // TR8 (= v6 R8): Pool conservation (10B)
    OP_0, OP_TXINPUTAMOUNT,                // input[0].value (pool)        [2B]
    OP_2, OP_PICK,                         // payout_per_token (idx 2)     [2B]
    OP_SUB,                                // pool - payout                [1B]
    OP_1, OP_TXOUTPUTAMOUNT,               // output[1].value              [2B]
    OP_SWAP,                               // expected, out1               [1B]
    OP_GTE, OP_VERIFY,                     // out1 >= expected             [2B]

    // TR9 (= v6 R9): Cleanup 6 state items + TRUE (4B)
    OP_2DROP, OP_2DROP, OP_2DROP,          // drop 6 items                 [3B]
    OP_1,                                  // TRUE                         [1B]

    // REFUND PATH (selector=0) — 16B
    OP_ELSE,                               //                              [1B]
    // Stack: no_receipt_cid(0), yes_receipt_cid(1), reward_per_receipt(2),
    //        expiry_daa(3), creator_pkh(4), threshold(5), payout(6),
    //        no_tok(7), yes_tok(8), ballot_cid(9), market_id(10),
    //        pk(11), sig(12)

    // RF0: Drop 3 receipt items (3B)
    OP_2DROP, OP_DROP,                     // drop no_receipt, yes_receipt, reward  [3B]
    // Stack: expiry_daa(0), creator_pkh(1), threshold(2), payout(3),
    //        no_tok(4), yes_tok(5), ballot_cid(6), market_id(7),
    //        pk(8), sig(9) — identical to v6 refund stack

    // RF1 (= v6 RF0): CLTV (1B)
    //
    // OpCheckLockTimeVerify pops the value it checks (confirmed against the
    // real kaspad `kaspa-txscript` engine: OpCheckLockTimeVerify uses
    // `pop_raw()`) -- unlike Bitcoin's non-consuming CLTV. There is nothing
    // left on the stack to explicitly drop afterward, so the removed
    // trailing OP_DROP was the only thing wrong here -- RF2's `pk (idx 7)`
    // PICK depth below already assumed this exact (correct) consuming
    // behavior. See the identical, live-confirmed bug in ballot_box.rs's
    // EXPIRE PATH (that one over-drops and starves OP_CHECKSIGVERIFY down
    // to 1 stack item).
    OP_CLTV,                               // verify locktime >= expiry; consumes expiry_daa [1B]

    // RF2 (= v6 RF1): verify Blake2b(pk) == creator_pkh (5B)
    OP_7, OP_PICK,                         // pk (idx 7 after drop)        [2B]
    OP_BLAKE2B,                            // Blake2b(pk)                  [1B]
    OP_EQUAL, OP_VERIFY,                   // hash == creator_pkh          [2B]

    // RF3 (= v6 RF2): cleanup 6 state items + checksig + TRUE (5B)
    OP_2DROP, OP_2DROP, OP_2DROP,          // drop 6 state items           [3B]
    OP_CHECKSIGVERIFY,                     // verify creator sig            [1B]
    OP_1,                                  // TRUE                          [1B]

    // CLOSING
    OP_ENDIF,                              // inner (token/refund)          [1B]
    OP_ENDIF,                              // outer (receipt/other)         [1B]
];

/// Build Redemption redeemScript.
///
/// **Receipt-enabled settlement**: extends v6 with receipt redeem path.
/// State layout adds 3 fields (75B) for receipt reward distribution.
///
/// State (267B):
///   [0x20][market_id 32B][0x20][ballot_cid 32B]
///   [0x20][yes_token_cid 32B][0x20][no_token_cid 32B]
///   [0x08][payout_per_token 8B][0x08][threshold_value 8B]
///   [0x20][creator_pkh 32B][0x08][expiry_daa 8B]
///   [0x08][reward_per_receipt 8B]
///   [0x20][yes_receipt_cid 32B][0x20][no_receipt_cid 32B]
///
/// Body: REDEMPTION_BODY
pub fn build_redemption_redeem_script(
    market_id: &[u8; 32],
    ballot_cid: &[u8; 32],
    yes_token_cid: &[u8; 32],
    no_token_cid: &[u8; 32],
    payout_per_token: u64,
    threshold_value: u64,
    creator_pkh: &[u8; 32],
    expiry_daa: u64,
    reward_per_receipt: u64,
    yes_receipt_cid: &[u8; 32],
    no_receipt_cid: &[u8; 32],
) -> crate::Result<Vec<u8>> {
    if payout_per_token == 0 {
        return Err(crate::KobError::Contract("payout_per_token must be > 0".into()));
    }
    if threshold_value == 0 {
        return Err(crate::KobError::Contract("threshold_value must be > 0".into()));
    }
    if expiry_daa == 0 {
        return Err(crate::KobError::Contract("expiry_daa must be > 0".into()));
    }
    if reward_per_receipt == 0 {
        return Err(crate::KobError::Contract("reward_per_receipt must be > 0".into()));
    }

    let body = REDEMPTION_BODY;
    let state_size = 267;
    let mut rs = Vec::with_capacity(state_size + body.len());

    // v6 state (192B)
    rs.push(0x20);
    rs.extend_from_slice(market_id);
    rs.push(0x20);
    rs.extend_from_slice(ballot_cid);
    rs.push(0x20);
    rs.extend_from_slice(yes_token_cid);
    rs.push(0x20);
    rs.extend_from_slice(no_token_cid);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(payout_per_token));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(threshold_value));
    rs.push(0x20);
    rs.extend_from_slice(creator_pkh);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(expiry_daa));

    // New receipt fields (75B)
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(reward_per_receipt));
    rs.push(0x20);
    rs.extend_from_slice(yes_receipt_cid);
    rs.push(0x20);
    rs.extend_from_slice(no_receipt_cid);

    rs.extend_from_slice(body);
    Ok(rs)
}

/// Build Redemption receipt redeem sigscript.
/// Format: [Op2 (selector=receipt)] [pushData(RS)]
/// sigOpCount = 0
pub fn build_redemption_receipt_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(OP_2); // selector = receipt redeem
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build Redemption token redeem sigscript.
/// Format: [Op1 (selector=token)] [pushData(RS)]
/// sigOpCount = 0
pub fn build_redemption_token_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(OP_1); // selector = token redeem
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build Redemption refund sigscript.
/// Format: [push(sig+0x01)] [push(pk)] [Op0 (selector=refund)] [pushData(RS)]
/// sigOpCount = 1
pub fn build_redemption_refund_sigscript(
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_ht = Vec::with_capacity(65);
    sig_ht.extend_from_slice(signature);
    sig_ht.push(0x01);

    let mut ss = Vec::with_capacity(66 + 33 + 1 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_ht));  // sig+hashtype
    ss.extend_from_slice(&push_data(pubkey));    // pk
    ss.push(OP_0);                               // selector = refund
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}


