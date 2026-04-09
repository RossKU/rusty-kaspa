use crate::primitives::{push_data, u64_le};

const OP_0: u8 = 0x00;
const OP_1: u8 = 0x51;
const OP_2: u8 = 0x52;
const OP_3: u8 = 0x53;
const OP_6: u8 = 0x56;
const OP_DUP: u8 = 0x76;
const OP_DROP: u8 = 0x75;
const OP_2DROP: u8 = 0x6d;
const OP_SWAP: u8 = 0x7c;
const OP_PICK: u8 = 0x79;
const OP_ROLL: u8 = 0x7a;
const OP_SUB: u8 = 0x94;
const OP_EQUAL: u8 = 0x87;
const OP_VERIFY: u8 = 0x69;
const OP_GTE: u8 = 0xa2;
const OP_GT: u8 = 0xa0;
const OP_IF: u8 = 0x63;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
const OP_BLAKE2B: u8 = 0xaa;
const OP_CHECKSIGVERIFY: u8 = 0xad;
const OP_CLTV: u8 = 0xb0;
const OP_TXINPUTINDEX: u8 = 0xb9;
const OP_TXINPUTAMOUNT: u8 = 0xbe;
const OP_TXOUTPUTAMOUNT: u8 = 0xc2;
const OP_INPUTCOUNT: u8 = 0xb3;
const OP_INPUTCOVENANTID: u8 = 0xcf;
const OP_COVINPUTCOUNT: u8 = 0xd0;
const OP_COVOUTCOUNT: u8 = 0xd2;

// 4. SplitMerge Covenant v2
//
// Conditional token minting: enables Polymarket-style split/merge.
//
// Split: User deposits unit_value KAS → receives 1 YES token + 1 NO token
// Merge: User returns 1 YES token + 1 NO token → receives unit_value KAS back
//
// This ensures YES + NO always sums to unit_value KAS (tight market, no arb).
//
// v2 fixes:
//   C4:  refund path requires creator signature (prevents unauthorized drain)
//   H3:  split path verifies YES/NO token outputs via OpCovOutCount
//   H5:  merge path enforces exact amount conservation using unit_value
//
// State (150B with push opcodes):
//   [0x20] market_id      (32B) — market identifier
//   [0x20] yes_token_cid  (32B) — covenant ID of YES token
//   [0x20] no_token_cid   (32B) — covenant ID of NO token
//   [0x20] creator_pkh    (32B) — Blake2b hash of creator's pubkey
//   [0x08] unit_value     (8B)  — KAS per token pair (e.g. 100_000_000 = 1 KAS)
//   [0x08] expiry_daa     (8B)  — DAA score after which creator can reclaim (CLTV)
//
// Paths:
//   Split: KAS in → self-continuation + YES token out + NO token out
//   Merge: YES token + NO token in → KAS out + self-continuation
//   Refund: CLTV + creator sig → creator reclaims pool (market expired)
//
// TX templates:
//
// Split TX:
//   Inputs:  [0] SplitMerge UTXO, [1] user KAS UTXO (deposit)
//   Outputs: [0] YES token UTXO, [1] NO token UTXO,
//            [2] SplitMerge continuation (pool + deposit), [3] change
//
// Merge TX:
//   Inputs:  [0] SplitMerge UTXO, [1] YES token UTXO, [2] NO token UTXO
//   Outputs: [0] KAS to user (unit_value), [1] SplitMerge continuation (pool - unit_value)

/// SplitMerge v2 body bytecode.
///
/// Stack after state (top to bottom):
///   expiry_daa(0), unit_value(1), creator_pkh(2), no_token_cid(3),
///   yes_token_cid(4), market_id(5)
///
/// Dispatch: sigscript selector.
///   Op2 = split, Op1 = merge, Op0 = refund
///
/// Split sigscript:  [Op2] [pushData(RS)]
/// Merge sigscript:  [Op1] [pushData(RS)]
/// Refund sigscript: [push(sig+0x01)] [push(pk)] [Op0] [pushData(RS)]
pub const SPLIT_MERGE_BODY: &[u8] = &[
    // DISPATCH (5B)
    OP_6, OP_ROLL,                          // selector to top            [2B]
    OP_DUP,                                 // dup selector               [1B]
    OP_2, OP_EQUAL,                         // selector == 2?             [2B]
    OP_IF,                                  // split path                 [1B]

    // SPLIT PATH
    // Stack: selector(0), expiry_daa(1), unit_value(2), creator_pkh(3),
    //        no_cid(4), yes_cid(5), market_id(6)
    OP_DROP,                               // drop selector               [1B]
    OP_DROP,                               // drop expiry_daa             [1B]
    // Stack: unit_value(0), creator_pkh(1), no_cid(2), yes_cid(3), market_id(4)

    // SP1: input count >= 2 (pool + user deposit)
    OP_INPUTCOUNT, OP_2, OP_GTE, OP_VERIFY, //                           [4B]

    // SP2: YES token output exists (H3 fix)
    OP_3, OP_PICK,                          // yes_token_cid              [2B]
    OP_COVOUTCOUNT,                         // count of YES token outputs [1B]
    OP_1, OP_GTE, OP_VERIFY,               // >= 1 YES token output      [3B]

    // SP3: NO token output exists (H3 fix)
    OP_2, OP_PICK,                          // no_token_cid               [2B]
    OP_COVOUTCOUNT,                         // count of NO token outputs  [1B]
    OP_1, OP_GTE, OP_VERIFY,               // >= 1 NO token output       [3B]

    // SP4: self-continuation — exactly 1 output with my covenant ID (anti-split)
    OP_TXINPUTINDEX, OP_INPUTCOVENANTID,    // my covenant ID             [2B]
    OP_COVOUTCOUNT,                         // count of outputs with covId [1B]
    OP_1, OP_EQUAL, OP_VERIFY,             // exactly 1                  [3B]

    // SP5: pool value increases (user deposited KAS)
    OP_2, OP_TXOUTPUTAMOUNT,               // output[2].amount (cont.)   [2B]
    OP_TXINPUTINDEX, OP_TXINPUTAMOUNT,     // input.amount (pool)        [2B]
    OP_GT, OP_VERIFY,                      // output > input (grew)      [2B]

    // Cleanup: unit_value, creator_pkh, no_cid, yes_cid, market_id = 5 items
    OP_2DROP, OP_2DROP, OP_DROP,           // drop 5                     [3B]
    OP_1,                                  // TRUE                       [1B]

    // ELSE: MERGE OR REFUND
    OP_ELSE,                               //                             [1B]
    // Stack: selector(0), expiry_daa(1), unit_value(2), creator_pkh(3),
    //        no_cid(4), yes_cid(5), market_id(6)
    OP_IF,                                 // selector==1 → merge         [1B]
    // selector consumed by OP_IF. Stack:
    // expiry_daa(0), unit_value(1), creator_pkh(2), no_cid(3), yes_cid(4), market_id(5)

    // MERGE PATH
    OP_DROP,                               // drop expiry_daa             [1B]
    // Stack: unit_value(0), creator_pkh(1), no_cid(2), yes_cid(3), market_id(4)

    // MG1: YES token must be a co-input
    OP_3, OP_PICK,                          // yes_cid                    [2B]
    OP_COVINPUTCOUNT,                       // YES tokens in inputs       [1B]
    OP_1, OP_GTE, OP_VERIFY,               // >= 1                       [3B]

    // MG2: NO token must be a co-input
    OP_2, OP_PICK,                          // no_cid                     [2B]
    OP_COVINPUTCOUNT,                       // NO tokens in inputs        [1B]
    OP_1, OP_GTE, OP_VERIFY,               // >= 1                       [3B]

    // MG3: self-continuation — exactly 1 output with my covenant ID
    OP_TXINPUTINDEX, OP_INPUTCOVENANTID,    // my covenant ID             [2B]
    OP_COVOUTCOUNT,                         // count of outputs with covId [1B]
    OP_1, OP_EQUAL, OP_VERIFY,             // exactly 1                  [3B]

    // MG4: output[0].value == unit_value (exact payout, H5 fix)
    OP_0, OP_TXOUTPUTAMOUNT,               // output[0].amount           [2B]
    OP_1, OP_PICK,                         // unit_value                  [2B]
    OP_EQUAL, OP_VERIFY,                   // must be exact               [2B]

    // MG5: pool conservation — continuation value = input - unit_value
    OP_TXINPUTINDEX, OP_TXINPUTAMOUNT,     // input amount                [2B]
    OP_1, OP_PICK,                         // unit_value                  [2B]
    OP_SUB,                                // input - unit_value          [1B]
    OP_1, OP_TXOUTPUTAMOUNT,               // output[1].amount (cont.)   [2B]
    OP_SWAP,                               // expected, output[1]         [1B]
    OP_GTE, OP_VERIFY,                     // output[1] >= expected       [2B]

    // Cleanup: unit_value, creator_pkh, no_cid, yes_cid, market_id = 5 items
    OP_2DROP, OP_2DROP, OP_DROP,           // drop 5                     [3B]
    OP_1,                                  // TRUE                       [1B]

    // REFUND PATH — CLTV + creator sig required (C4 fix + CLTV fix)
    OP_ELSE,                               //                             [1B]
    // selector=0 consumed by OP_IF (falsy). Stack:
    // expiry_daa(0), unit_value(1), creator_pkh(2), no_cid(3), yes_cid(4),
    // market_id(5), pk(6), sig(7)

    // RF0: CLTV — expiry_daa is on top (2B)
    OP_CLTV,                               // verify locktime >= expiry   [1B]
    OP_DROP,                               // drop expiry_daa             [1B]
    // Stack: unit_value(0), creator_pkh(1), no_cid(2), yes_cid(3),
    //        market_id(4), pk(5), sig(6)

    // RF1: verify Blake2b(pk) == creator_pkh
    OP_6, OP_PICK,                         // pk                          [2B]
    OP_BLAKE2B,                            // Blake2b(pk)                 [1B]
    OP_6, OP_PICK,                         // creator_pkh                 [2B]
    OP_EQUAL, OP_VERIFY,                   // must match                  [2B]

    // RF2: cleanup state + verify sig
    OP_2DROP, OP_2DROP, OP_DROP,           // drop 5 state items          [3B]
    OP_SWAP,                               // pk, sig                     [1B]
    OP_CHECKSIGVERIFY,                     // verify creator sig          [1B]
    OP_1,                                  // TRUE                        [1B]

    // CLOSING
    OP_ENDIF,                              // merge vs refund             [1B]
    OP_ENDIF,                              // split vs merge/refund       [1B]
];

/// Build SplitMerge v2 redeemScript.
///
/// **IMPORTANT**: Set `expiry_daa` BEFORE `BallotBox.start_daa` to prevent
/// post-settlement token minting. Token sales must end before voting begins.
/// Failing to do so allows infinite token mint → Redemption pool drain (C1 vulnerability).
///
/// State (150B): [0x20][market_id 32B][0x20][yes_token_cid 32B]
///               [0x20][no_token_cid 32B][0x20][creator_pkh 32B]
///               [0x08][unit_value 8B][0x08][expiry_daa 8B]
/// Body: SPLIT_MERGE_BODY
pub fn build_split_merge_redeem_script(
    market_id: &[u8; 32],
    yes_token_cid: &[u8; 32],
    no_token_cid: &[u8; 32],
    creator_pkh: &[u8; 32],
    unit_value: u64,
    expiry_daa: u64,
) -> crate::Result<Vec<u8>> {
    if unit_value == 0 {
        return Err(crate::KobError::Contract("unit_value must be > 0".into()));
    }
    if expiry_daa == 0 {
        return Err(crate::KobError::Contract("expiry_daa must be > 0".into()));
    }

    let body = SPLIT_MERGE_BODY;
    let mut rs = Vec::with_capacity(150 + body.len());

    rs.push(0x20);
    rs.extend_from_slice(market_id);
    rs.push(0x20);
    rs.extend_from_slice(yes_token_cid);
    rs.push(0x20);
    rs.extend_from_slice(no_token_cid);
    rs.push(0x20);
    rs.extend_from_slice(creator_pkh);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(unit_value));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(expiry_daa));

    rs.extend_from_slice(body);
    Ok(rs)
}

/// Build SplitMerge v2 split sigscript.
/// Format: [Op2 (selector=split)] [pushData(RS)]
pub fn build_split_merge_split_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(OP_2);
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build SplitMerge v2 merge sigscript.
/// Format: [Op1 (selector=merge)] [pushData(RS)]
pub fn build_split_merge_merge_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(OP_1);
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build SplitMerge v2 refund sigscript (creator sig required).
/// Format: [push(sig+0x01)] [push(pk)] [Op0 (selector=refund)] [pushData(RS)]
pub fn build_split_merge_refund_sigscript(
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

