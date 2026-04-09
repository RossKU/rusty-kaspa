use crate::primitives::{push_data, u64_le};
use crate::contract::helpers::{gcd, opn};

/// buy_order body bytecode (264 bytes, +4B output count limit).
///
/// Features:
/// - Max matcher fee (mmfee) cap: (kas_in - out[0].value) <= mmfee
/// - Output count limit: max 4 outputs (prevents receipt multiplication attack)
/// - On-chain expiry via CLTV
/// - OP_CSV exposure delay (50 DAA) on fill/partial paths
///
/// State (145B): [tcid 32B][pnum 8B][pden 8B][mfill 8B][ohash 32B][bspkh 32B][mmfee 8B][cpend 1B][expiry_daa 8B]
///
/// Stack after state push:
///   expiry(0), cpend(1), mmfee(2), bspkh(3), ohash(4), mfill(5), pden(6), pnum(7), tcid(8)
///
/// Dispatch thresholds (RS=409B):
///   T0 = 414 (expire < 414 < fill)
///   T1 = 417 (fill < 417 < partial)
///   T2 = 425 (partial < 425 < cancel)
pub const BUY_ORDER_BODY: &[u8] = &[
    // DISPATCH PREAMBLE (15B)
    0xb9, 0xc9, 0x76,             // OpTxInputIndex, OpTxInputScriptSigLen, OpDup  [3B]
    0x02, 0xa9, 0x01,             // push T2=425                                   [3B]
    0x9f,                         // OpLessThan (sigLen < T2?)                      [1B]
    0x63,                         // OpIf (expire/fill/partial)                     [1B]
    0x76,                         // OpDup (keep sigLen for T0 check)               [1B]
    0x02, 0x9e, 0x01,             // push T0=414                                   [3B]
    0x9f,                         // OpLessThan (sigLen < T0?)                      [1B]
    0x63,                         // OpIf (EXPIRE)                                  [1B]
    0x75,                         // OpDrop (sigLen, not needed in expire)           [1B]

    // EXPIRE PATH (21B)
    // Stack: expiry(0), cpend(1), mmfee(2), bspkh(3), ohash(4), mfill(5),
    //        pden(6), pnum(7), tcid(8), 4(9)
    //
    // E0: GTC guard — reject expire when expiry_daa == 0
    0x76, 0x69,                   // OpDup OpVerify (expiry != 0 or FAIL)            [2B]
    // E1: CLTV — enforces expiry_daa <= tx.lockTime (i.e., expired)
    0xb0,                         // OpCheckLockTimeVerify (pops expiry)             [1B]
    // Stack: cpend(0), mmfee(1), bspkh(2), ohash(3), mfill(4), pden(5),
    //        pnum(6), tcid(7), 4(8)
    //
    // E2: output[0].spk.blake2b == bspkh (funds go to owner)
    // After hash push: hash(0), cpend(1), mmfee(2), bspkh(3), ...
    0x00, 0xc3, 0xaa,             // Op0 OpTxOutputSpk OpBlake2b                    [3B]
    0x53, 0x79,                   // Op3 OpPick(bspkh at d3)                        [2B]
    0x87, 0x69,                   // OpEqual OpVerify                               [2B]
    // hash consumed by OpEqual, stack back to: cpend(0), mmfee(1), bspkh(2), ...
    //
    // E3: output[0].value >= input.value (full refund)
    0x00, 0xc2,                   // Op0 OpTxOutputAmount                           [2B]
    0xb9, 0xbe,                   // OpTxInputIndex OpTxInputAmount                 [2B]
    0xa2, 0x69,                   // OpGTE OpVerify (output >= input)                [2B]
    //
    // Cleanup: cpend(0)..4(8) = 9 items
    0x6d, 0x6d, 0x6d, 0x6d, 0x75, // Op2Drop x4 + OpDrop                           [5B]

    // ELSE: FILL OR PARTIAL (time-gated)
    0x67,                         // OpElse (sigLen >= T0: fill or partial)          [1B]

    // --- TIME GATE (12B) ---
    // Stack: sigLen(0), expiry(1), cpend(2), mmfee(3), bspkh(4), ...
    0x51, 0x7a,                   // Op1 OpRoll(expiry) -> expiry to top             [2B]
    0x76, 0x00, 0x9c,             // OpDup Op0 OpNumEqual -> expiry, (expiry==0?)    [3B]
    0x64,                         // OpNotIf (has expiry)                            [1B]
    0x76, 0xb5,                   // OpDup OpTxLockTime -> expiry, lockTime          [2B]
    0xa0, 0x69,                   // OpGreaterThan OpVerify (expiry > lockTime)      [2B]
    0x68,                         // OpEndIf                                         [1B]
    0x75,                         // OpDrop (remove expiry)                          [1B]
    // Stack now: sigLen(0), cpend(1), mmfee(2), bspkh(3), ohash(4), mfill(5),
    //            pden(6), pnum(7), tcid(8), sigscript_items...

    // --- EXPOSURE DELAY (3B) ---
    0x01, 0x32,                   // push(50) MIN_EXPOSURE = 50 DAA                  [2B]
    0xb1,                         // OpCheckSequenceVerify (UTXO age >= 50)          [1B]

    // --- T1 DISPATCH (5B) ---
    0x02, 0xa1, 0x01,             // push T1=417                                    [3B]
    0x9f,                         // OpLessThan (sigLen < T1?)                       [1B]
    0x63,                         // OpIf (fill)                                    [1B]

    // FILL PATH (67B)
    // Stack: cpend(0), mmfee(1), bspkh(2), ohash(3), mfill(4), pden(5),
    //        pnum(6), tcid(7), 1(8), coi(9), tii(10), toi(11)
    // F5: cancel_pending must be 0
    0x00, 0x87, 0x69,             // Op0 OpEqual OpVerify (cpend==0)                 [3B]
    // Stack: mmfee(0), bspkh(1), ohash(2), mfill(3), pden(4),
    //        pnum(5), tcid(6), 1(7), coi(8), tii(9), toi(10)
    // Price calc
    0xb9, 0xbe,                   // OpTxInputIndex, OpTxInputAmount -> kas          [2B]
    0x76,                         // OpDup                                           [1B]
    // kas_c(0), kas(1), mmfee(2), bspkh(3), ..., pnum(7)
    0x57, 0x79, 0x95,             // Op7 OpPick(pnum) OpMul                          [3B]
    // product(0), kas(1), mmfee(2), bspkh(3), ..., pden(6)
    0x56, 0x79, 0x96,             // Op6 OpPick(pden) OpDiv -> expected_tokens       [3B]
    0x76,                         // OpDup                                           [1B]
    // exp_tok_c(0), exp_tok(1), kas(2), mmfee(3), ..., mfill(6)
    0x56, 0x79, 0xa2, 0x69,       // Op6 OpPick(mfill) OpGTE OpVerify               [4B]
    // exp_tok(0), kas(1), mmfee(2), ..., toi(12)
    // Token output amount (PARAMETERIZED: toi)
    0x5c, 0x79, 0xc2,             // Op12 OpPick(toi) OpTxOutputAmount               [3B]
    0x7c, 0xa2, 0x69,             // OpSwap OpGTE OpVerify                           [3B]
    // kas(0), mmfee(1), ..., toi(11)
    // Token input covenant check (PARAMETERIZED: tii)
    0x5a, 0x79, 0xcf,             // Op10 OpPick(tii) OpTxInputCovId                 [3B]
    // covId(0), kas(1), mmfee(2), ..., tcid(8)
    0x58, 0x79, 0x87, 0x69,       // Op8 OpPick(tcid) OpEqual OpVerify               [4B]
    // kas(0), mmfee(1), ..., toi(11)
    // F2: buyer SPK hash check (PARAMETERIZED: toi)
    0x5b, 0x79, 0xc3, 0xaa,       // Op11 OpPick(toi) OpTxOutputSpk OpBlake2b        [4B]
    // hash(0), kas(1), mmfee(2), bspkh(3)
    0x53, 0x79, 0x87, 0x69,       // Op3 OpPick(bspkh) OpEqual OpVerify              [4B]
    // kas(0), mmfee(1), ..., toi(11)
    // F4: token output covenant check (PARAMETERIZED: coi)
    0x57, 0x79, 0x76,             // Op7 OpPick(tcid) OpDup                          [3B]
    // tcid_c2(0), tcid_c(1), kas(2), mmfee(3), ..., coi(10)
    0xd2, 0x51, 0xa2, 0x69,       // OpCovOutCount(T) Op1 OpGTE OpVerify             [4B]
    // tcid_c(0), kas(1), mmfee(2), ..., coi(10), tii(11), toi(12)
    0x5a, 0x79, 0xd3,             // Op10 OpPick(coi) OpCovOutputIdx(T,coi)          [3B]
    // outIdx(0), kas(1), mmfee(2), ..., toi(12)
    0x5c, 0x79,                   // Op12 OpPick(toi)                                [2B]
    0x87, 0x69,                   // OpEqual OpVerify                                [2B]
    // kas(0), mmfee(1), bspkh(2), ..., toi(11) = 12 items
    // F6: matcher fee cap — (kas_in - out[0].value) <= mmfee
    0xb9, 0xbe,                   // OpTxInputIndex OpTxInputAmount -> kas_in         [2B]
    0x00, 0xc2,                   // Op0 OpTxOutputAmount -> out[0].value             [2B]
    0x94,                         // OpSub -> fee = (kas_in - out[0].value)           [1B]
    0x52, 0x79,                   // Op2 OpPick(mmfee at d2)                         [2B]
    0xa1, 0x69,                   // OpLTE OpVerify (fee <= mmfee)                   [2B]
    // Cleanup: 12 items = Op2Drop x6
    0x6d, 0x6d, 0x6d, 0x6d, 0x6d, 0x6d, // Op2Drop x6                              [6B]

    // PARTIAL FILL PATH (103B)
    0x67,                         // OpElse (sigLen >= T1: partial)                  [1B]
    // Stack: cpend(0), mmfee(1), bspkh(2), ohash(3), mfill(4), pden(5),
    //        pnum(6), tcid(7), 2(8), fk(9), ti(10), ri(11)
    // F5
    0x00, 0x87, 0x69,             // cpend==0                                       [3B]
    // Stack: mmfee(0), bspkh(1), ohash(2), mfill(3), pden(4),
    //        pnum(5), tcid(6), 2(7), fk(8), ti(9), ri(10)
    // Price calc: fill_tokens = fk * pnum / pden
    0x58, 0x79,                   // Op8 OpPick(fk)                                  [2B]
    0x76,                         // OpDup                                           [1B]
    // fk_c2(0), fk_c(1), mmfee(2), ..., pnum(7)
    0x57, 0x79, 0x95,             // Op7 OpPick(pnum) OpMul                          [3B]
    0x56, 0x79, 0x96,             // Op6 OpPick(pden) OpDiv                          [3B]
    0x76,                         // OpDup                                           [1B]
    // fill_tok_c(0), fill_tok(1), fk_c(2), mmfee(3), ..., mfill(6)
    0x56, 0x79, 0xa2, 0x69,       // Op6 OpPick(mfill) OpGTE OpVerify               [4B]
    // fill_tok(0), fk_c(1), mmfee(2), ..., ti(11), ri(12)
    0x5b, 0x79, 0xc2,             // Op11 OpPick(ti) OpTxOutputAmount                [3B]
    0x7c, 0xa2, 0x69,             // OpSwap OpGTE OpVerify                           [3B]
    // fk_c(0), mmfee(1), ..., ri(11)
    0xb9, 0xbe,                   // kas_in                                          [2B]
    // kas(0), fk_c(1), mmfee(2), ..., ri(12)
    0x51, 0x79, 0xa0, 0x69,       // Op1 OpPick(fk_c) OpGreaterThan OpVerify         [4B]
    // fk_c(0), mmfee(1), ..., ri(11)
    0x5b, 0x79, 0xc3,             // Op11 OpPick(ri) OpTxOutputSpk                   [3B]
    0xb9, 0xbf,                   // OpTxInputIndex OpTxInputSpk                     [2B]
    0x87, 0x69,                   // OpEqual OpVerify                                [2B]
    // fk_c(0), mmfee(1), ..., ri(11)
    0xb9, 0xbe,                   // kas_in                                          [2B]
    // kas(0), fk_c(1), mmfee(2), ..., ri(12)
    0x51, 0x7a, 0x94,             // Op1 OpRoll(fk_c) OpSub                          [3B]
    // residual(0), mmfee(1), ..., ri(11)
    0x5b, 0x79, 0xc2,             // Op11 OpPick(ri) OpTxOutputAmount                [3B]
    0x7c, 0xa2, 0x69,             // OpSwap OpGTE OpVerify                           [3B]
    // mmfee(0), bspkh(1), ..., 2(7), fk(8), ti(9), ri(10) = 11 items
    // Residual fill check
    0xb9, 0xbe,                   // kas_in                                          [2B]
    // kas(0), mmfee(1), ..., fk(9)
    0x59, 0x79, 0x94,             // Op9 OpPick(fk) OpSub                            [3B]
    // res_kas(0), mmfee(1), ..., pden(5)
    0x55, 0x79, 0x96,             // Op5 OpPick(pden) OpDiv                          [3B]
    // quotient(0), mmfee(1), ..., pnum(6)
    0x56, 0x79, 0x95,             // Op6 OpPick(pnum) OpMul                          [3B]
    // result(0), mmfee(1), ..., mfill(4)
    0x54, 0x79, 0xa2, 0x69,       // Op4 OpPick(mfill) OpGTE OpVerify               [4B]
    // mmfee(0), bspkh(1), ..., ri(10)
    // Token input check
    0x51, 0xcf,                   // Op1 OpTxInputCovId                              [2B]
    // covId(0), mmfee(1), ..., tcid(7)
    0x57, 0x79, 0x87, 0x69,       // Op7 OpPick(tcid) OpEqual OpVerify               [4B]
    // mmfee(0), bspkh(1), ..., ri(10)
    // F2: buyer SPK hash
    0x59, 0x79, 0xc3,             // Op9 OpPick(ti) OpTxOutputSpk                    [3B]
    0xaa,                         // OpBlake2b                                       [1B]
    // hash(0), mmfee(1), bspkh(2)
    0x52, 0x79, 0x87, 0x69,       // Op2 OpPick(bspkh) OpEqual OpVerify              [4B]
    // mmfee(0), bspkh(1), ..., ri(10)
    // F4: token output covenant
    0x56, 0x79, 0x76,             // Op6 OpPick(tcid) OpDup                          [3B]
    0xd2, 0x51, 0xa2, 0x69,       // OpCovOutCount(T) Op1 OpGTE OpVerify             [4B]
    0x00, 0xd3,                   // Op0 OpCovOutputIdx(T,0)                         [2B]
    0x51,                         // Op1                                             [1B]
    0x87, 0x69,                   // OpEqual OpVerify                                [2B]
    // mmfee(0), bspkh(1), ..., ri(10) = 11 items
    // F6 PARTIAL: matcher fee cap — (kas_in - out[0].value) <= mmfee
    0xb9, 0xbe,                   // OpTxInputIndex OpTxInputAmount -> kas_in         [2B]
    0x00, 0xc2,                   // Op0 OpTxOutputAmount -> out[0].value             [2B]
    0x94,                         // OpSub -> fee = (kas_in - out[0].value)           [1B]
    0x51, 0x79,                   // Op1 OpPick(mmfee at d1)                         [2B]
    0xa1, 0x69,                   // OpLTE OpVerify (fee <= mmfee)                   [2B]
    // Cleanup: 11 items = Op2Drop x5 + OpDrop
    0x6d, 0x6d, 0x6d, 0x6d, 0x6d, 0x75, // Op2Drop x5 + OpDrop                     [6B]

    // --- FILL/PARTIAL END ---
    0x68,                         // OpEndIf (fill vs partial)                       [1B]

    // --- OUTPUT COUNT LIMIT (4B) ---
    // Prevents receipt output multiplication attack: a malicious matcher could
    // duplicate receipt outputs to amplify a single off-market fill into
    // multiple price-proof UTXOs for attacking lending/perp positions.
    // Max 4 outputs: seller_kas + buyer_tokens + receipt + matcher_change.
    0xb4,                         // OpTxOutputCount                                 [1B]
    0x54,                         // Op4 (= 4)                                       [1B]
    0xa1, 0x69,                   // OpLTE OpVerify (output_count <= 4)              [2B]

    0x68,                         // OpEndIf (expire vs fill/partial)                [1B]

    // CANCEL / CANCEL-MARK PATH (28B)
    0x67,                         // OpElse (sigLen >= T2: cancel)                   [1B]
    0x75,                         // OpDrop (sigLen)                                 [1B]
    0x75,                         // OpDrop (expiry)                                 [1B]
    // Stack: cpend(0), mmfee(1), bspkh(2), ohash(3), mfill(4), pden(5),
    //        pnum(6), tcid(7), pk(8), sig(9), selector(10)
    0x5a, 0x7a,                   // Op10 OpRoll(selector) -> selector on top        [2B]
    0x63,                         // OpIf (selector>0 = cancel-mark)                 [1B]
    0x00, 0x87, 0x69,             // cpend==0 verify                                [3B]
    0x67,                         // OpElse (cancel-complete: selector=0)            [1B]
    0x75,                         // OpDrop cpend                                    [1B]
    0x68,                         // OpEndIf                                         [1B]
    // Stack: mmfee(0), bspkh(1), ohash(2), mfill(3), pden(4), pnum(5),
    //        tcid(6), pk(7), sig(8)
    0x57, 0x79, 0xaa,             // Op7 OpPick(pk) OpBlake2b                        [3B]
    0x53, 0x79, 0x87, 0x69,       // Op3 OpPick(ohash) OpEqual OpVerify              [4B]
    0x58, 0x7a,                   // Op8 OpRoll(sig)                                 [2B]
    0x58, 0x7a,                   // Op8 OpRoll(pk)                                  [2B]
    0xad,                         // OpCheckSigVerify                                [1B]
    // mmfee(0), bspkh(1)..tcid(6) = 7 items
    0x6d, 0x6d, 0x6d, 0x75,       // Op2Drop x3 + OpDrop                             [4B]

    // CLOSING (2B)
    0x68,                         // OpEndIf (outer)                                 [1B]
    0x51,                         // Op1 (TRUE)                                      [1B]
];

/// Expected length of BUY_ORDER_BODY bytecode.
pub const BUY_ORDER_BODY_EXPECTED_LEN: usize = 264;

/// Expected length of buy_order redeemScript (145B state + 264B body).
pub const BUY_ORDER_RS_EXPECTED_LEN: usize = 409;

/// Sell order body bytecode (266B, +4B output count limit).
///
/// Features:
/// - Max matcher fee (mmfee) cap: (token_in - out[0].value) <= mmfee
/// - Output count limit: max 4 outputs (prevents receipt multiplication attack)
/// - On-chain expiry via CLTV
/// - OP_CSV exposure delay (50 DAA) on fill/partial paths
///
/// State layout (112B):
///   `[pnum 8B][pden 8B][mfill 8B][ohash 32B][sspkh 32B][mmfee 8B][cpend 1B][expiry_daa 8B]`
///   Stack after state push: expiry(0), cpend(1), mmfee(2), sspkh(3), ohash(4), mfill(5), pden(6), pnum(7)
///   + sigscript items below pnum
pub const SELL_ORDER_BODY: &[u8] = &[
    // DISPATCH (12B)
    // Stack: expiry(0), cpend(1), mmfee(2), sspkh(3), ohash(4), mfill(5), pden(6), pnum(7), sigscript_items(8+)
    0x58, 0x7a,                   // Op8 OpRoll -> selector                           [2B]
    0x76,                         // OpDup                                           [1B]
    0x54, 0x87,                   // Op4 OpEqual (selector == 4?)                    [2B]
    0x63,                         // OpIf (EXPIRE, selector=4)                       [1B]

    // EXPIRE PATH (30B)
    0x75,                         // OpDrop (remove selector duplicate)               [1B]
    0x76, 0x69,                   // OpDup OpVerify (expiry != 0 or FAIL)             [2B]
    0xb0,                         // OpCheckLockTimeVerify (pops expiry)              [1B]
    // Stack: cpend(0), mmfee(1), sspkh(2), ohash(3), mfill(4), pden(5), pnum(6)
    0x00, 0xc3, 0xaa,             // Op0 OpTxOutputSpk OpBlake2b                     [3B]
    0x53, 0x79,                   // Op3 OpPick(sspkh at d3)                         [2B]
    0x87, 0x69,                   // OpEqual OpVerify                                [2B]
    0x00, 0xc2,                   // Op0 OpTxOutputAmount                            [2B]
    0xb9, 0xbe,                   // OpTxInputIndex OpTxInputAmount                  [2B]
    0xa2, 0x69,                   // OpGTE OpVerify                                  [2B]
    0xb9, 0xcf,                   // OpTxInputIndex OpInputCovenantId -> T           [2B]
    0xd2, 0x51, 0xa2, 0x69,       // OpCovOutCount(T) Op1 OpGTE OpVerify             [4B]
    // Cleanup: cpend(0)..pnum(6) = 7 items
    0x6d, 0x6d, 0x6d, 0x75,       // Op2Drop x3 + OpDrop                             [4B]

    // ELSE: NON-EXPIRE PATHS
    0x67,                         // OpElse (selector != 4)                          [1B]

    0x76,                         // OpDup                                           [1B]
    0x52, 0x9f,                   // Op2 OpLessThan (selector < 2?)                  [2B]
    0x63,                         // OpIf (fill or cancel)                           [1B]
    0x51, 0x87,                   // Op1 OpEqual (selector == 1?)                    [2B]
    0x63,                         // OpIf (FILL)                                     [1B]

    // FILL PATH (74B)
    // TIME GATE (10B)
    0x76, 0x00, 0x9c,             // OpDup Op0 OpNumEqual                             [3B]
    0x64,                         // OpNotIf (has expiry)                            [1B]
    0x76, 0xb5,                   // OpDup OpTxLockTime                              [2B]
    0xa0, 0x69,                   // OpGreaterThan OpVerify (expiry > lockTime)      [2B]
    0x68,                         // OpEndIf                                         [1B]
    0x75,                         // OpDrop (remove expiry)                          [1B]

    // --- EXPOSURE DELAY (3B) ---
    0x01, 0x32,                   // push(50) MIN_EXPOSURE = 50 DAA                  [2B]
    0xb1,                         // OpCheckSequenceVerify (UTXO age >= 50)          [1B]

    // F5: cpend==0
    0x00, 0x87, 0x69,             // Op0 OpEqual OpVerify                            [3B]
    // Stack: mmfee(0), sspkh(1), ohash(2), mfill(3), pden(4), pnum(5), koi(6)
    // Price calculation
    0xb9, 0xbe,                   // OpTxInputIndex OpTxInputAmount -> token_amount  [2B]
    0x56, 0x79, 0x95,             // Op6 OpPick(pnum) OpMul                          [3B]
    0x55, 0x79, 0x96,             // Op5 OpPick(pden) OpDiv -> expected_kas          [3B]
    0x76,                         // OpDup                                           [1B]
    0x55, 0x79, 0xa2, 0x69,       // Op5 OpPick(mfill) OpGTE OpVerify               [4B]
    // KAS output (PARAMETERIZED: koi)
    0x57, 0x79, 0xc2,             // Op7 OpPick(koi) OpTxOutputAmount                [3B]
    0x7c, 0xa2, 0x69,             // OpSwap OpGTE OpVerify                           [3B]
    // F2: seller SPK hash
    0x56, 0x79, 0xc3,             // Op6 OpPick(koi) OpTxOutputSpk                   [3B]
    0xaa,                         // OpBlake2b                                       [1B]
    0x52, 0x79, 0x87, 0x69,       // Op2 OpPick(sspkh) OpEqual OpVerify              [4B]
    // F4: token conservation full fill
    0xb9, 0xcf, 0x76,             // OpTxInputIndex OpInputCovenantId OpDup          [3B]
    0xd2, 0x51, 0xa2, 0x69,       // OpCovOutCount(T) Op1 OpGTE OpVerify             [4B]
    0x00, 0xd3,                   // Op0 OpCovOutputIdx(T,0)                         [2B]
    0xc2,                         // OpTxOutputAmount(idx)                           [1B]
    0xb9, 0xbe,                   // OpTxInputIndex OpTxInputAmount                  [2B]
    0xa2, 0x69,                   // OpGTE OpVerify                                  [2B]

    // F6: matcher fee cap — (token_in - out[0].value) <= mmfee
    0xb9, 0xbe,                   // OpTxInputIndex OpTxInputAmount -> token_in       [2B]
    0x00, 0xc2,                   // Op0 OpTxOutputAmount -> out[0].value             [2B]
    0x94,                         // OpSub -> fee = (token_in - out[0].value)         [1B]
    0x51, 0x79,                   // Op1 OpPick(mmfee at d1)                         [2B]
    0xa1, 0x69,                   // OpLTE OpVerify (fee <= mmfee)                   [2B]

    // Cleanup: 7 items = Op2Drop x3 + OpDrop
    0x6d, 0x6d, 0x6d, 0x75,       // Op2Drop x3 + OpDrop                             [4B]

    // CANCEL PATH (selector=0, 17B)
    0x67,                         // OpElse (cancel)                                 [1B]
    0x6d,                         // Op2Drop (expiry + cpend)                        [1B]
    // Stack: mmfee(0), sspkh(1), ohash(2), mfill(3), pden(4), pnum(5), pk(6), sig(7)
    0x56, 0x79, 0xaa,             // Op6 OpPick(pk) OpBlake2b                        [3B]
    0x53, 0x79, 0x87, 0x69,       // Op3 OpPick(ohash) OpEqual OpVerify              [4B]
    0x57, 0x7a,                   // Op7 OpRoll(sig)                                 [2B]
    0x57, 0x7a,                   // Op7 OpRoll(pk)                                  [2B]
    0xac, 0x69,                   // OpCheckSig OpVerify                             [2B]
    // mmfee(0)..pnum(5) = 6 items
    0x6d, 0x6d, 0x6d,             // Op2Drop x3                                      [3B]

    // --- INNER END ---
    0x68,                         // OpEndIf (fill vs cancel)                        [1B]

    // ELSE: selector >= 2 (partial, cancel-mark)
    0x67,                         // OpElse (selector >= 2)                          [1B]
    0x52, 0x87,                   // Op2 OpEqual (selector == 2?)                    [2B]
    0x63,                         // OpIf (PARTIAL FILL)                             [1B]

    // PARTIAL FILL PATH (108B)
    // TIME GATE (10B)
    0x76, 0x00, 0x9c,             // OpDup Op0 OpNumEqual                             [3B]
    0x64,                         // OpNotIf                                         [1B]
    0x76, 0xb5,                   // OpDup OpTxLockTime                              [2B]
    0xa0, 0x69,                   // OpGreaterThan OpVerify                          [2B]
    0x68,                         // OpEndIf                                         [1B]
    0x75,                         // OpDrop (expiry)                                 [1B]

    // --- EXPOSURE DELAY (3B) ---
    0x01, 0x32,                   // push(50) MIN_EXPOSURE = 50 DAA                  [2B]
    0xb1,                         // OpCheckSequenceVerify (UTXO age >= 50)          [1B]

    // F5
    0x00, 0x87, 0x69,             // cpend==0                                       [3B]
    // Stack: mmfee(0), sspkh(1), ohash(2), mfill(3), pden(4), pnum(5), fta(6), ri(7), ki(8)
    0x56, 0x79,                   // Op6 OpPick(fta)                                 [2B]
    0x76,                         // OpDup                                           [1B]
    0x57, 0x79, 0x95,             // Op7 OpPick(pnum) OpMul                          [3B]
    0x56, 0x79, 0x96,             // Op6 OpPick(pden) OpDiv -> fill_kas              [3B]
    0x76,                         // OpDup                                           [1B]
    0x56, 0x79, 0xa2, 0x69,       // Op6 OpPick(mfill) OpGTE OpVerify               [4B]
    0x5a, 0x79, 0xc2,             // Op10 OpPick(ki) OpTxOutputAmount                [3B]
    0x7c, 0xa2, 0x69,             // OpSwap OpGTE OpVerify                           [3B]
    0xb9, 0xbe,                   // token_in                                        [2B]
    0x51, 0x79, 0xa0, 0x69,       // Op1 OpPick(fta_c) OpGreaterThan OpVerify        [4B]
    0x58, 0x79, 0xc3,             // Op8 OpPick(ri) OpTxOutputSpk                    [3B]
    0xb9, 0xbf,                   // OpTxInputIndex OpTxInputSpk                     [2B]
    0x87, 0x69,                   // OpEqual OpVerify                                [2B]
    0xb9, 0xbe,                   // token_in                                        [2B]
    0x51, 0x7a, 0x94,             // Op1 OpRoll(fta_c) OpSub -> residual             [3B]
    0x58, 0x79, 0xc2,             // Op8 OpPick(ri) OpTxOutputAmount                 [3B]
    0x7c, 0xa2, 0x69,             // OpSwap OpGTE OpVerify                           [3B]
    0xb9, 0xbe,                   // token_in                                        [2B]
    0x57, 0x79, 0x94,             // Op7 OpPick(fta) OpSub                           [3B]
    0x56, 0x79, 0x95,             // Op6 OpPick(pnum) OpMul                          [3B]
    0x55, 0x79, 0x96,             // Op5 OpPick(pden) OpDiv                          [3B]
    0x54, 0x79, 0xa2, 0x69,       // Op4 OpPick(mfill) OpGTE OpVerify               [4B]
    // F2: seller SPK
    0x58, 0x79, 0xc3,             // Op8 OpPick(ki) OpTxOutputSpk                    [3B]
    0xaa,                         // OpBlake2b                                       [1B]
    0x52, 0x79, 0x87, 0x69,       // Op2 OpPick(sspkh) OpEqual OpVerify              [4B]
    // F4: token conservation partial
    0xb9, 0xcf,                   // OpTxInputIndex OpInputCovenantId -> T           [2B]
    0xd2, 0x52, 0xa2, 0x69,       // OpCovOutCount(T) Op2 OpGTE OpVerify             [4B]

    // F6 PARTIAL: matcher fee cap — (token_in - out[0].value) <= mmfee
    0xb9, 0xbe,                   // OpTxInputIndex OpTxInputAmount -> token_in       [2B]
    0x00, 0xc2,                   // Op0 OpTxOutputAmount -> out[0].value             [2B]
    0x94,                         // OpSub -> fee = (token_in - out[0].value)         [1B]
    0x51, 0x79,                   // Op1 OpPick(mmfee at d1)                         [2B]
    0xa1, 0x69,                   // OpLTE OpVerify (fee <= mmfee)                   [2B]

    // Cleanup: 9 items = Op2Drop x4 + OpDrop
    0x6d, 0x6d, 0x6d, 0x6d, 0x75, // Op2Drop x4 + OpDrop                            [5B]

    // CANCEL-MARK PATH (selector=3, 20B)
    0x67,                         // OpElse (cancel-mark)                            [1B]
    0x75,                         // OpDrop expiry                                   [1B]
    0x00, 0x87, 0x69,             // cpend==0 verify                                [3B]
    // Stack: mmfee(0), sspkh(1), ohash(2), mfill(3), pden(4), pnum(5), pk(6), sig(7)
    0x56, 0x79, 0xaa,             // Op6 OpPick(pk) OpBlake2b                        [3B]
    0x53, 0x79, 0x87, 0x69,       // Op3 OpPick(ohash) OpEqual OpVerify              [4B]
    0x57, 0x7a,                   // Op7 OpRoll(sig)                                 [2B]
    0x57, 0x7a,                   // Op7 OpRoll(pk)                                  [2B]
    0xac, 0x69,                   // OpCheckSig OpVerify                             [2B]
    // mmfee(0)..pnum(5) = 6 items
    0x6d, 0x6d, 0x6d,             // Op2Drop x3                                      [3B]

    // CLOSING (8B = 4B + output count limit 4B)
    0x68,                         // OpEndIf (partial vs cancel-mark)                [1B]
    0x68,                         // OpEndIf (sel<2 vs sel>=2)                       [1B]

    // --- OUTPUT COUNT LIMIT (4B) ---
    // Prevents receipt output multiplication attack (see BUY_ORDER_BODY).
    // Max 4 outputs: seller_kas + buyer_tokens + receipt + matcher_change.
    // Applied to all non-expire paths (fill, partial, cancel, cancel-mark).
    // Cancel/cancel-mark always produce <= 4 outputs, so this is non-binding for them.
    0xb4,                         // OpTxOutputCount                                 [1B]
    0x54,                         // Op4 (= 4)                                       [1B]
    0xa1, 0x69,                   // OpLTE OpVerify (output_count <= 4)              [2B]

    0x68,                         // OpEndIf (expire vs rest)                        [1B]
    0x51,                         // Op1 (TRUE)                                      [1B]
];

/// Expected body length for sell order.
pub const SELL_ORDER_BODY_EXPECTED_LEN: usize = 266;

/// Expected redeemScript length for sell order (112B state + 266B body).
pub const SELL_ORDER_RS_EXPECTED_LEN: usize = 112 + SELL_ORDER_BODY_EXPECTED_LEN;

/// Build buy_order redeemScript (145B state + 264B body = 409B).
///
/// State (145B):
///   `[0x20][tcid 32B][0x08][pnum 8B][0x08][pden 8B][0x08][mfill 8B]`
///   `[0x20][ohash 32B][0x20][bspkh 32B][0x08][mmfee 8B][cpend 1B][0x08][expiry_daa 8B]`
///
/// Max matcher fee cap: (kas_in - out[0].value) <= mmfee.
/// Includes output count limit (max 4) to prevent receipt multiplication.
pub fn build_buy_redeem_script(
    token_covenant_id: &[u8; 32],
    price_num: u64,
    price_den: u64,
    min_fill: u64,
    owner_hash: &[u8; 32],
    buyer_spk_hash: &[u8; 32],
    max_matcher_fee: u64,
    cancel_pending: u8,
    expiry_daa: u64,
) -> crate::Result<Vec<u8>> {
    if price_num <= 0 {
        return Err(crate::KobError::Contract("price_num must be > 0".into()));
    }
    if price_den <= 0 {
        return Err(crate::KobError::Contract("price_den must be > 0".into()));
    }
    if min_fill <= 0 {
        return Err(crate::KobError::Contract("min_fill must be > 0 (zero min_fill allows free extraction attack)".into()));
    }
    if cancel_pending > 1 {
        return Err(crate::KobError::Contract("cancel_pending must be 0 or 1".into()));
    }
    let g = gcd(price_num, price_den);
    let price_num = if g > 0 { price_num / g } else { price_num };
    let price_den = if g > 0 { price_den / g } else { price_den };
    let mut rs = Vec::with_capacity(145 + BUY_ORDER_BODY.len());
    // State header (145B)
    rs.push(0x20);
    rs.extend_from_slice(token_covenant_id);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(price_num));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(price_den));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_fill));
    rs.push(0x20);
    rs.extend_from_slice(owner_hash);
    rs.push(0x20);
    rs.extend_from_slice(buyer_spk_hash);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(max_matcher_fee));
    if cancel_pending == 0 {
        rs.push(0x00);
    } else {
        rs.push(0x51);
    }
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(expiry_daa));
    // Body
    rs.extend_from_slice(BUY_ORDER_BODY);
    Ok(rs)
}

/// Build buy_order fill sigscript.
///
/// Layout: `[toi_opN] [tii_opN] [coi_opN] [Op1] [pushData(RS)]`
pub fn build_buy_fill_sigscript(
    token_output_idx: u8,
    token_input_idx: u8,
    cov_output_idx: u8,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(4 + redeem_script.len() + 3);
    ss.push(opn(token_output_idx));
    ss.push(opn(token_input_idx));
    ss.push(opn(cov_output_idx));
    ss.push(0x51); // Op1 (selector = fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build buy_order partial fill sigscript.
///
/// Layout: `[ri_opN] [ti_opN] [pushData(fk 8B)] [Op2] [pushData(RS)]`
pub fn build_buy_partial_fill_sigscript(
    redeem_script: &[u8],
    fill_kas: u64,
    residual_idx: u8,
    token_idx: u8,
) -> Vec<u8> {
    let fk = u64_le(fill_kas);
    let mut ss = Vec::with_capacity(14 + redeem_script.len() + 3);
    ss.push(opn(residual_idx));
    ss.push(opn(token_idx));
    ss.extend_from_slice(&push_data(&fk));
    ss.push(0x52); // Op2 (selector = partial fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build sell_order redeemScript (112B state + 266B body = 378B).
///
/// State (112B):
///   `[0x08][pnum 8B][0x08][pden 8B][0x08][mfill 8B]`
///   `[0x20][ohash 32B][0x20][sspkh 32B][0x08][mmfee 8B][cpend 1B]`
///   `[0x08][expiry_daa 8B]`
///
/// Max matcher fee cap: (token_in - out[0].value) <= mmfee.
/// Includes output count limit (max 4 outputs) on fill/partial paths.
pub fn build_sell_redeem_script(
    price_num: u64,
    price_den: u64,
    min_fill: u64,
    owner_hash: &[u8; 32],
    seller_spk_hash: &[u8; 32],
    max_matcher_fee: u64,
    cancel_pending: u8,
    expiry_daa: u64,
) -> crate::Result<Vec<u8>> {
    if price_num <= 0 {
        return Err(crate::KobError::Contract("price_num must be > 0".into()));
    }
    if price_den <= 0 {
        return Err(crate::KobError::Contract("price_den must be > 0".into()));
    }
    if min_fill <= 0 {
        return Err(crate::KobError::Contract("min_fill must be > 0 (zero min_fill allows free extraction attack)".into()));
    }
    if cancel_pending > 1 {
        return Err(crate::KobError::Contract("cancel_pending must be 0 or 1".into()));
    }
    let g = gcd(price_num, price_den);
    let price_num = if g > 0 { price_num / g } else { price_num };
    let price_den = if g > 0 { price_den / g } else { price_den };
    let mut rs = Vec::with_capacity(112 + SELL_ORDER_BODY.len());
    // State header (112B)
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(price_num));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(price_den));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_fill));
    rs.push(0x20);
    rs.extend_from_slice(owner_hash);
    rs.push(0x20);
    rs.extend_from_slice(seller_spk_hash);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(max_matcher_fee));
    if cancel_pending == 0 {
        rs.push(0x00);
    } else {
        rs.push(0x51);
    }
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(expiry_daa));
    // Body
    rs.extend_from_slice(SELL_ORDER_BODY);
    Ok(rs)
}

/// Build sell_order fill sigscript.
///
/// Layout: `[kas_output_idx_opN] [Op1] [pushData(RS)]`
pub fn build_sell_fill_sigscript(
    kas_output_idx: u8,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(2 + redeem_script.len() + 3);
    ss.push(opn(kas_output_idx));
    ss.push(0x51); // Op1 (selector = fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build sell_order partial fill sigscript.
///
/// Layout: `[kas_idx_opN] [residual_idx_opN] [pushData(fill_ta 8B)] [Op2] [pushData(RS)]`
pub fn build_sell_partial_fill_sigscript(
    redeem_script: &[u8],
    fill_token_amount: u64,
    kas_idx: u8,
    residual_idx: u8,
) -> Vec<u8> {
    let fta = u64_le(fill_token_amount);
    let mut ss = Vec::with_capacity(14 + redeem_script.len() + 3);
    ss.push(opn(kas_idx));
    ss.push(opn(residual_idx));
    ss.extend_from_slice(&push_data(&fta));
    ss.push(0x52); // Op2 (selector = partial fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

pub fn build_buy_expire_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(0x54); // Op4 (selector = expire)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build sell_order expire sigscript.
///
/// Layout: `[Op4] [pushData(RS)]`
pub fn build_sell_expire_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(0x54); // Op4 (selector = expire)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}
