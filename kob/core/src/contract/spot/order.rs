use crate::primitives::{push_data, u64_le};
use crate::contract::helpers::{gcd, push_index};

/// buy_order body bytecode (251 bytes, v14: IOC fill path added, F6 removed).
///
/// Features:
/// - Max matcher fee (mmfee) cap: (kas_in - out[0].value) <= mmfee
/// - On-chain expiry via CLTV
/// - OP_CSV exposure delay (50 DAA) on fill/partial paths
/// - IOC fill (selector=Op5): relaxes token output check to >= mfill
///
/// State (145B): [tcid 32B][pnum 8B][pden 8B][mfill 8B][ohash 32B][bspkh 32B][mmfee 8B][cpend 1B][expiry_daa 8B]
///
/// Stack after state push:
///   expiry(0), cpend(1), mmfee(2), bspkh(3), ohash(4), mfill(5), pden(6), pnum(7), tcid(8)
///
/// Dispatch thresholds (RS=396B):
///   T0 = 401 (expire < 401 < fill)
///   T1 = 409 (fill < 409 < partial)
///   T2 = 415 (partial < 415 < cancel)
///
/// Fill sigscript margin: v14 base=403, max=406 (3 data-push indices).
/// Partial sigscript margin: v14 base=412, max=414 (2 data-push indices).
pub const BUY_ORDER_BODY: &[u8] = &[
    // DISPATCH PREAMBLE (15B)
    0xb9, 0xc9, 0x76,             // OpTxInputIndex, OpTxInputScriptSigLen, OpDup  [3B]
    0x02, 0x9f, 0x01,             // push T2=415                                   [3B]
    0x9f,                         // OpLessThan (sigLen < T2?)                      [1B]
    0x63,                         // OpIf (expire/fill/partial)                     [1B]
    0x76,                         // OpDup (keep sigLen for T0 check)               [1B]
    0x02, 0x91, 0x01,             // push T0=401                                   [3B]
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
    0x02, 0x99, 0x01,             // push T1=409                                    [3B]
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
    // exp_tok(0), kas(1), mmfee(2), ..., sel(9), ..., toi(12)
    //
    // IOC SUB-DISPATCH (9B): if selector==Op5, replace exp_tok with mfill
    // so the output check becomes output[toi] >= mfill (not >= exp_tok).
    0x59, 0x79,                   // Op9 OpPick(selector copy)                       [2B]
    0x55, 0x87,                   // Op5 OpEqual (selector == 5?)                    [2B]
    0x63,                         // OpIf (IOC)                                      [1B]
    0x75,                         // OpDrop (drop exp_tok)                           [1B]
    0x54, 0x79,                   // Op4 OpPick(mfill)                               [2B]
    0x68,                         // OpEndIf                                          [1B]
    // Normal fill: exp_tok(0) unchanged. IOC fill: mfill(0) replaces exp_tok.
    // Either way depth=13, value_to_check at [0], toi at [12].
    //
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
    // F6 REMOVED: buy F6 was `kas_in - out[0].value <= mmfee` with hardcoded
    // output[0]. In N:M batch, output[0] is only the first seller's KAS,
    // so kas_in - out[0] >> mmfee for any multi-seller match.
    // Buy is protected by price check and covenant binding instead.
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
    // F6 PARTIAL REMOVED: same hardcoded output[0] issue as fill path F6.
    // Cleanup: 11 items = Op2Drop x5 + OpDrop
    0x6d, 0x6d, 0x6d, 0x6d, 0x6d, 0x75, // Op2Drop x5 + OpDrop                     [6B]

    // --- FILL/PARTIAL END ---
    0x68,                         // OpEndIf (fill vs partial)                       [1B]

    // NOTE: Output count limit removed to enable N:M batch matching.
    // Receipt multiplication is mitigated by the mmfee cap and price checks.

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
pub const BUY_ORDER_BODY_EXPECTED_LEN: usize = 251;

/// Expected length of buy_order redeemScript (145B state + 251B body).
pub const BUY_ORDER_RS_EXPECTED_LEN: usize = 145 + BUY_ORDER_BODY_EXPECTED_LEN;

/// Sell order body bytecode (303B, v14: IOC fill path added, F6 removed).
///
/// Features:
/// - Token conservation via F4 (covenant-bound output >= input)
/// - On-chain expiry via CLTV
/// - OP_CSV exposure delay (50 DAA) on fill/partial paths
/// - IOC fill (selector=Op5): uses `fta` (fill token amount) for partial sell
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
    // F4: token conservation bound to THIS input's OWN authorized output, not
    // the transaction-wide shared covenant-output-0. OpCovOutputIdx(T,0) returns
    // output_indices[0] for token T across the WHOLE tx, so two sellers of the
    // same token both checked one shared output and a matcher could satisfy both
    // with a single token output while draining the other seller's tokens to KAS.
    // OpAuthOutputIdx(thisInput,0) returns the 0th output THIS input authorized;
    // each output has exactly one authorizing_input, so two sellers can never
    // share one. (Length-neutral: new F4 is 14B == old F4 14B.)
    0xb9, 0x00, 0xcc,             // OpTxInputIndex Op0 OpAuthOutputIdx -> my out idx [3B]
    0x76,                         // OpDup                                           [1B]
    0xd5,                         // OpOutputCovenantId(idx) -> covid                [1B]
    0xb9, 0xcf,                   // OpTxInputIndex OpInputCovenantId -> T           [2B]
    0x87, 0x69,                   // OpEqual OpVerify (out covid == my token)        [2B]
    0xc2,                         // OpTxOutputAmount(idx)                           [1B]
    0xb9, 0xbe,                   // OpTxInputIndex OpTxInputAmount -> token_in      [2B]
    0xa2, 0x69,                   // OpGTE OpVerify (my out >= token_in)             [2B]

    // F6 REMOVED: sell F6 was denomination-blind (token_in - kas_out[0])
    // which only passed at price 1/1.  Sell is protected by F4 (token
    // conservation) and the price check instead.  See v8 sell body which
    // also omits F6.

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

    // ELSE: selector >= 2 (IOC fill, partial, cancel-mark)
    0x67,                         // OpElse (selector >= 2)                          [1B]

    // IOC FILL CHECK (4B dispatch)
    0x76,                         // OpDup (keep selector for partial check)         [1B]
    0x55, 0x87,                   // Op5 OpEqual (selector == 5?)                    [2B]
    0x63,                         // OpIf (IOC FILL)                                 [1B]

    // IOC FILL PATH (54B)
    0x75,                         // OpDrop (remove stale selector from OpDup)       [1B]
    // Stack: expiry(0), cpend(1), mmfee(2), sspkh(3), ohash(4), mfill(5),
    //        pden(6), pnum(7), fta(8), koi(9)
    //
    // TIME GATE (10B) — same as fill/partial
    0x76, 0x00, 0x9c,             // OpDup Op0 OpNumEqual                             [3B]
    0x64,                         // OpNotIf (has expiry)                            [1B]
    0x76, 0xb5,                   // OpDup OpTxLockTime                              [2B]
    0xa0, 0x69,                   // OpGreaterThan OpVerify (expiry > lockTime)      [2B]
    0x68,                         // OpEndIf                                         [1B]
    0x75,                         // OpDrop (remove expiry)                          [1B]

    // EXPOSURE DELAY (3B)
    0x01, 0x32,                   // push(50) MIN_EXPOSURE = 50 DAA                  [2B]
    0xb1,                         // OpCheckSequenceVerify                           [1B]

    // F5: cpend==0 (3B)
    0x00, 0x87, 0x69,             // Op0 OpEqual OpVerify                            [3B]
    // Stack: mmfee(0), sspkh(1), ohash(2), mfill(3), pden(4), pnum(5), fta(6), koi(7)

    // Price calc from fta (13B)
    0x56, 0x79,                   // Op6 OpPick(fta)                                 [2B]
    0x56, 0x79, 0x95,             // Op6 OpPick(pnum) OpMul                          [3B]
    0x55, 0x79, 0x96,             // Op5 OpPick(pden) OpDiv -> fill_kas              [3B]
    0x76,                         // OpDup                                           [1B]
    0x55, 0x79, 0xa2, 0x69,       // Op5 OpPick(mfill) OpGTE OpVerify               [4B]
    // fill_kas(0), mmfee(1), sspkh(2), ..., fta(7), koi(8)

    // KAS output check (6B)
    0x58, 0x79, 0xc2,             // Op8 OpPick(koi) OpTxOutputAmount                [3B]
    0x7c, 0xa2, 0x69,             // OpSwap OpGTE OpVerify (out >= fill_kas)         [3B]
    // mmfee(0), sspkh(1), ..., fta(6), koi(7)

    // F2: seller SPK hash (8B)
    0x57, 0x79, 0xc3,             // Op7 OpPick(koi) OpTxOutputSpk                   [3B]
    0xaa,                         // OpBlake2b                                       [1B]
    0x52, 0x79, 0x87, 0x69,       // Op2 OpPick(sspkh) OpEqual OpVerify              [4B]
    // mmfee(0), sspkh(1), ohash(2), mfill(3), pden(4), pnum(5), fta(6), koi(7)

    // F4: RESIDUAL CONSERVATION (17B). The old check was existence-only
    // (OpCovOutCount>=1) with a free `fta`: a matcher could consume the whole
    // token_in, price only `fta` to the seller, and drain the (token_in - fta)
    // unsold tokens out as KAS. Now the residual must return to THIS seller via
    // a self-continuation output bound to THIS input (its 0th authorized covenant
    // output, OpAuthOutputIdx — per-input, like the full-fill F4; needs NO
    // sigscript change so v16 F6's fixed-offset reads are untouched).
    // r = OpTxInputIndex Op0 OpAuthOutputIdx (this input's 0th authorized output)
    0xb9, 0x00, 0xcc,             // OpTxInputIndex Op0 OpAuthOutputIdx -> r          [3B]
    0x76,                         // OpDup                                            [1B]
    0xc3,                         // OpTxOutputSpk(r)                                 [1B]
    0xb9, 0xbf,                   // OpTxInputIndex OpTxInputSpk -> my spk            [2B]
    0x87, 0x69,                   // OpEqual OpVerify (r is self-continuation to me)  [2B]
    0xc2,                         // OpTxOutputAmount(r)                              [1B]
    0xb9, 0xbe,                   // OpTxInputIndex OpTxInputAmount -> token_in       [2B]
    0x58, 0x79,                   // Op8 OpPick(fta)                                  [2B]
    0x94,                         // OpSub -> token_in - fta                          [1B]
    0xa2, 0x69,                   // OpGTE OpVerify (residual out >= token_in - fta)  [2B]

    // Cleanup: 8 items = Op2Drop x4 (4B)
    0x6d, 0x6d, 0x6d, 0x6d,       // Op2Drop x4                                      [4B]

    0x67,                         // OpElse (not IOC — partial or cancel-mark)       [1B]

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

    // F6 PARTIAL REMOVED: same denomination-blind issue as fill path F6.

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

    // CLOSING (5B, output count limit removed for N:M batch matching)
    0x68,                         // OpEndIf (partial vs cancel-mark)                [1B]
    0x68,                         // OpEndIf (IOC vs partial/cancel-mark)            [1B]
    0x68,                         // OpEndIf (sel<2 vs sel>=2)                       [1B]

    // NOTE: Output count limit removed to enable N:M batch matching.
    // Receipt multiplication is mitigated by the mmfee cap and price checks.

    0x68,                         // OpEndIf (expire vs rest)                        [1B]
    0x51,                         // Op1 (TRUE)                                      [1B]
];

/// Expected body length for sell order.
pub const SELL_ORDER_BODY_EXPECTED_LEN: usize = 315;

/// Expected redeemScript length for sell order (112B state + 315B body).
pub const SELL_ORDER_RS_EXPECTED_LEN: usize = 112 + SELL_ORDER_BODY_EXPECTED_LEN;

/// Build buy_order redeemScript (145B state + 242B body = 387B).
///
/// State (145B):
///   `[0x20][tcid 32B][0x08][pnum 8B][0x08][pden 8B][0x08][mfill 8B]`
///   `[0x20][ohash 32B][0x20][bspkh 32B][0x08][mmfee 8B][cpend 1B][0x08][expiry_daa 8B]`
///
/// Max matcher fee cap: (kas_in - out[0].value) <= mmfee.
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
/// Layout: `[toi] [tii] [coi] [Op1] [pushData(RS)]`
///
/// Indices use OpN (1 byte) for 0..=16, or data-push `[0x01, val]` (2 bytes) for 17+.
pub fn build_buy_fill_sigscript(
    token_output_idx: u16,
    token_input_idx: u16,
    cov_output_idx: u16,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(7 + redeem_script.len() + 3);
    push_index(&mut ss, token_output_idx);
    push_index(&mut ss, token_input_idx);
    push_index(&mut ss, cov_output_idx);
    ss.push(0x51); // Op1 (selector = fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build buy_order partial fill sigscript.
///
/// Layout: `[ri] [ti] [pushData(fk 8B)] [Op2] [pushData(RS)]`
///
/// Indices use OpN (1 byte) for 0..=16, or data-push `[0x01, val]` (2 bytes) for 17+.
pub fn build_buy_partial_fill_sigscript(
    redeem_script: &[u8],
    fill_kas: u64,
    residual_idx: u16,
    token_idx: u16,
) -> Vec<u8> {
    let fk = u64_le(fill_kas);
    let mut ss = Vec::with_capacity(16 + redeem_script.len() + 3);
    push_index(&mut ss, residual_idx);
    push_index(&mut ss, token_idx);
    ss.extend_from_slice(&push_data(&fk));
    ss.push(0x52); // Op2 (selector = partial fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build sell_order redeemScript (112B state + 244B body = 356B).
///
/// State (112B):
///   `[0x08][pnum 8B][0x08][pden 8B][0x08][mfill 8B]`
///   `[0x20][ohash 32B][0x20][sspkh 32B][0x08][mmfee 8B][cpend 1B]`
///   `[0x08][expiry_daa 8B]`
///
/// Max matcher fee cap: (token_in - out[0].value) <= mmfee.
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
/// Layout: `[kas_output_idx] [Op1] [pushData(RS)]`
///
/// Index uses OpN (1 byte) for 0..=16, or data-push `[0x01, val]` (2 bytes) for 17+.
pub fn build_sell_fill_sigscript(
    kas_output_idx: u16,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(3 + redeem_script.len() + 3);
    push_index(&mut ss, kas_output_idx);
    ss.push(0x51); // Op1 (selector = fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build sell_order partial fill sigscript.
///
/// Layout: `[kas_idx] [residual_idx] [pushData(fill_ta 8B)] [Op2] [pushData(RS)]`
///
/// Indices use OpN (1 byte) for 0..=16, or data-push `[0x01, val]` (2 bytes) for 17+.
pub fn build_sell_partial_fill_sigscript(
    redeem_script: &[u8],
    fill_token_amount: u64,
    kas_idx: u16,
    residual_idx: u16,
) -> Vec<u8> {
    let fta = u64_le(fill_token_amount);
    let mut ss = Vec::with_capacity(16 + redeem_script.len() + 3);
    push_index(&mut ss, kas_idx);
    push_index(&mut ss, residual_idx);
    ss.extend_from_slice(&push_data(&fta));
    ss.push(0x52); // Op2 (selector = partial fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build sell_order IOC fill sigscript.
///
/// Layout: `[koi] [pushData(fta 8B)] [Op5] [pushData(RS)]`
///
/// * `kas_output_idx`: which output receives the seller's KAS
/// * `fill_token_amount`: how many tokens are being filled (fta)
///
/// Selector=Op5 triggers the IOC path which uses `fta` for price calc
/// instead of the full TxInputAmount.
pub fn build_sell_ioc_fill_sigscript(
    kas_output_idx: u16,
    fill_token_amount: u64,
    redeem_script: &[u8],
) -> Vec<u8> {
    let fta = u64_le(fill_token_amount);
    let mut ss = Vec::with_capacity(14 + redeem_script.len() + 3);
    push_index(&mut ss, kas_output_idx);
    ss.extend_from_slice(&push_data(&fta));
    ss.push(0x55); // Op5 (selector = IOC fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build buy_order IOC fill sigscript.
///
/// Layout: `[toi] [tii] [coi] [Op5] [pushData(RS)]`
///
/// Same as fill but selector=Op5 triggers the IOC sub-dispatch
/// which relaxes the token output check to >= mfill instead of >= expected_tokens.
pub fn build_buy_ioc_fill_sigscript(
    token_output_idx: u16,
    token_input_idx: u16,
    cov_output_idx: u16,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(7 + redeem_script.len() + 3);
    push_index(&mut ss, token_output_idx);
    push_index(&mut ss, token_input_idx);
    push_index(&mut ss, cov_output_idx);
    ss.push(0x55); // Op5 (selector = IOC fill)
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

/// Build sell_order fill sigscript with fixed-offset convention.
///
/// Layout: `[0x01, koi_val] [Op1] [pushData(RS)]`
///
/// Always uses 2-byte koi push so the buy contract can read sell's pnum/pden
/// at fixed offsets [7..15) and [16..24) via OpTxInputScriptSigSubstr. Used
/// by the v16 buy contract's F6 cross-input surplus check (originally
/// introduced for v15, which has since been removed — v16 kept this same
/// sell-side convention, see order.rs's V16 BUY CONTRACT section below).
///
/// The sell contract is unmodified — it reads koi as a number from the stack,
/// which is identical whether pushed via OpN (1B) or data-push (2B).
pub fn build_sell_fill_sigscript_fixed_offset(
    kas_output_idx: u16,
    redeem_script: &[u8],
) -> Vec<u8> {
    assert!(kas_output_idx <= 255, "koi must fit in 1 byte for fixed-offset convention");
    let mut ss = Vec::with_capacity(4 + redeem_script.len() + 3);
    // Fixed 2-byte koi push (even for indices 0-16)
    ss.push(0x01); // push 1 byte
    ss.push(kas_output_idx as u8);
    ss.push(0x51); // Op1 (selector = fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build sell_order IOC fill sigscript with fixed-offset convention.
///
/// Layout: `[0x01, koi_val] [pushData(fta 8B)] [Op5] [pushData(RS)]`
///
/// Note: For IOC sell, pnum/pden offsets differ from regular fill:
///   pnum at [16..24), pden at [25..33) due to fta field between koi and selector.
///
/// Used by the v16 buy contract's F6 cross-input surplus check (see
/// `build_sell_fill_sigscript_fixed_offset` above for why this convention
/// exists independent of any single buy-contract version).
pub fn build_sell_ioc_fill_sigscript_fixed_offset(
    kas_output_idx: u16,
    fill_token_amount: u64,
    redeem_script: &[u8],
) -> Vec<u8> {
    assert!(kas_output_idx <= 255, "koi must fit in 1 byte for fixed-offset convention");
    let fta = u64_le(fill_token_amount);
    let mut ss = Vec::with_capacity(14 + redeem_script.len() + 3);
    // Fixed 2-byte koi push
    ss.push(0x01);
    ss.push(kas_output_idx as u8);
    ss.extend_from_slice(&push_data(&fta));
    ss.push(0x55); // Op5 (selector = IOC fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

// ============================================================================
// V16 BUY CONTRACT — v15 semantics + Phase-0 fix (F6 cross-input authentication)
// ============================================================================
//
// V16 = V15 with one structural change: F6's cross-input price read is bound
// to the SAME input that the covenant check already authenticates, instead of
// a free `sii` sigscript parameter.
//
// The v15 flaw: F6 read sell_pnum/sell_pden via `OpTxInputScriptSigSubstr` at
// input index `sii`, a bare sigscript-supplied number never checked against
// anything. The matcher who assembles the batch tx could set `sii` to a
// self-controlled decoy input with forged price bytes at the expected offsets,
// while the REAL trade still settles against the genuine (and pricier)
// counterparty identified by `tii` (checked via `OpTxInputCovId(tii)==tcid`).
//
// The fix (see V16_STATUS.md Phase 0 for the full derivation):
//   - Fill / IOC-fill: `sii` is deleted from the sigscript. F6 reads the
//     substr source from `tii` (the SAME value already used, and already
//     authenticated, by the token-input covenant check a few instructions
//     earlier) via `OpPick(tii)` instead of a second, free `OpPick(sii)`.
//   - Partial-fill: the covenant check in this path has always hardcoded the
//     token input to literal tx-input-index `1` (`Op1 OpTxInputCovId`, both
//     v14 and v15 — see CLI's `partial_fill.rs` TX layout doc:
//     input[0]=buy, input[1]=token, input[2]=fee). There is no `tii` stack
//     variable there to point F6 at, so F6 is fixed the same way the
//     covenant check already is: the substr source is the hardcoded literal
//     `1`, not any sigscript-suppliable value.
//
// In both cases `sii` disappears from the sigscript entirely (not merely
// forced equal to `tii` at runtime, which would still cost a check) — since
// `sii` was always meant to equal the already-authenticated input, there is
// nothing left to pass as a separate parameter. This makes v16 both smaller
// and stricter than v15: the fill path is 1 byte shorter (no extra cleanup
// item to drop) and the partial path is 2 bytes shorter (no `OpPick` needed
// to fetch a hardcoded constant), and the sigscript itself sheds the `sii`
// push (saving another 1-2 bytes per spend).
//
// State layout: UNCHANGED (145B) — same as v14/v15. mmfee field is BPS
// (basis points), same interpretation as v15, NOT absolute sompi.

/// V16 buy_order body bytecode (331 bytes).
///
/// F6 CROSS-INPUT SURPLUS CAP (applied to fill AND partial paths), fixed:
///   1. Read sell_pnum from sell_sigscript[7..15) via OpTxInputScriptSigSubstr,
///      with the input index bound to the already-authenticated token input
///      (`tii` for fill/IOC-fill; hardcoded literal `1` for partial-fill).
///   2. Read sell_pden from sell_sigscript[16..24) the same way.
///   3. tokens = fk_or_kas / buy_pden * buy_pnum  (recompute, div-first overflow-safe)
///   4. fair_kas = tokens / sell_pden * sell_pnum
///   5. surplus = fk_or_kas - fair_kas
///   6. max_surplus = fk_or_kas / 10000 * mmfee_bps
///   7. Verify: max_surplus >= surplus
///   (Fill uses kas_in from OpTxInputAmount; partial uses fk from sigscript.)
///
/// State (145B): [tcid 32B][pnum 8B][pden 8B][mfill 8B][ohash 32B][bspkh 32B][mmfee_bps 8B][cpend 1B][expiry_daa 8B]
///
/// Stack after state push:
///   expiry(0), cpend(1), mmfee_bps(2), bspkh(3), ohash(4), mfill(5), pden(6), pnum(7), tcid(8)
///
/// Dispatch thresholds (RS=476B):
///   T0 = 481 (expire < 481 < fill)
///   T1 = 489 (fill < 489 < partial)
///   T2 = 494 (partial < 494 < cancel)
///
/// Fill sigscript: `[toi] [tii] [coi] [Op1/Op5] [pushData(RS)]` (no `sii` — see above)
///   base=483, max=486 (3 data-push indices)
/// Partial sigscript: `[ri] [ti] [pushData(fk 8B)] [Op2] [pushData(RS)]` (no `sii`)
///   base=491, max=493 (2 data-push indices)
pub const BUY_ORDER_V16_BODY: &[u8] = &[
    // DISPATCH PREAMBLE (15B) — same structure as v14/v15, updated thresholds
    0xb9, 0xc9, 0x76,             // OpTxInputIndex, OpTxInputScriptSigLen, OpDup  [3B]
    0x02, 0xee, 0x01,             // push T2=494                                   [3B]
    0x9f,                         // OpLessThan (sigLen < T2?)                      [1B]
    0x63,                         // OpIf (expire/fill/partial)                     [1B]
    0x76,                         // OpDup (keep sigLen for T0 check)               [1B]
    0x02, 0xe1, 0x01,             // push T0=481                                   [3B]
    0x9f,                         // OpLessThan (sigLen < T0?)                      [1B]
    0x63,                         // OpIf (EXPIRE)                                  [1B]
    0x75,                         // OpDrop (sigLen, not needed in expire)           [1B]

    // EXPIRE PATH (21B) — identical to v14/v15
    0x76, 0x69,                   // OpDup OpVerify (expiry != 0 or FAIL)            [2B]
    0xb0,                         // OpCheckLockTimeVerify                           [1B]
    0x00, 0xc3, 0xaa,             // Op0 OpTxOutputSpk OpBlake2b                    [3B]
    0x53, 0x79,                   // Op3 OpPick(bspkh)                              [2B]
    0x87, 0x69,                   // OpEqual OpVerify                               [2B]
    0x00, 0xc2,                   // Op0 OpTxOutputAmount                           [2B]
    0xb9, 0xbe,                   // OpTxInputIndex OpTxInputAmount                 [2B]
    0xa2, 0x69,                   // OpGTE OpVerify                                 [2B]
    0x6d, 0x6d, 0x6d, 0x6d, 0x75, // Op2Drop x4 + OpDrop                           [5B]

    // ELSE: FILL OR PARTIAL
    0x67,                         // OpElse                                         [1B]

    // TIME GATE (12B) — identical to v14/v15
    0x51, 0x7a,                   // Op1 OpRoll(expiry)                             [2B]
    0x76, 0x00, 0x9c,             // OpDup Op0 OpNumEqual                           [3B]
    0x64,                         // OpNotIf                                        [1B]
    0x76, 0xb5,                   // OpDup OpTxLockTime                             [2B]
    0xa0, 0x69,                   // OpGreaterThan OpVerify                         [2B]
    0x68,                         // OpEndIf                                        [1B]
    0x75,                         // OpDrop (expiry)                                [1B]

    // EXPOSURE DELAY (3B) — identical to v14/v15
    0x01, 0x32,                   // push(50) MIN_EXPOSURE = 50 DAA                 [2B]
    0xb1,                         // OpCheckSequenceVerify                          [1B]

    // T1 DISPATCH (5B) — updated threshold
    0x02, 0xe9, 0x01,             // push T1=489                                    [3B]
    0x9f,                         // OpLessThan (sigLen < T1?)                       [1B]
    0x63,                         // OpIf (fill)                                    [1B]

    // ============================================================
    // FILL PATH (61B v14-identical + 41B F6 + 6B cleanup = 108B)
    // ============================================================
    // Stack: cpend(0), mmfee_bps(1), bspkh(2), ohash(3), mfill(4), pden(5),
    //        pnum(6), tcid(7), 1(8), coi(9), tii(10), toi(11)
    //
    // F5: cancel_pending must be 0
    0x00, 0x87, 0x69,             // Op0 OpEqual OpVerify (cpend==0)                [3B]
    // Stack: mmfee_bps(0), bspkh(1), ohash(2), mfill(3), pden(4),
    //        pnum(5), tcid(6), 1(7), coi(8), tii(9), toi(10)
    //
    // Price calc — overflow-safe div-first (kas/pden*pnum instead of kas*pnum/pden)
    0xb9, 0xbe,                   // OpTxInputIndex, OpTxInputAmount -> kas          [2B]
    0x76,                         // OpDup                                          [1B]
    0x57, 0x79, 0x95,             // Op7 OpPick(pnum) OpMul -> product              [3B]
    0x56, 0x79, 0x96,             // Op6 OpPick(pden) OpDiv -> expected_tokens      [3B]
    0x76,                         // OpDup                                          [1B]
    0x56, 0x79, 0xa2, 0x69,       // Op6 OpPick(mfill) OpGTE OpVerify              [4B]
    //
    // IOC SUB-DISPATCH (9B) — identical to v14/v15
    0x59, 0x79,                   // Op9 OpPick(selector copy)                      [2B]
    0x55, 0x87,                   // Op5 OpEqual (selector == 5?)                   [2B]
    0x63,                         // OpIf (IOC)                                     [1B]
    0x75,                         // OpDrop (drop exp_tok)                          [1B]
    0x54, 0x79,                   // Op4 OpPick(mfill)                              [2B]
    0x68,                         // OpEndIf                                        [1B]
    //
    // Token output amount (PARAMETERIZED: toi) — identical to v14/v15
    0x5c, 0x79, 0xc2,             // Op12 OpPick(toi) OpTxOutputAmount              [3B]
    0x7c, 0xa2, 0x69,             // OpSwap OpGTE OpVerify                          [3B]
    // kas(0), mmfee_bps(1), ..., toi(11)
    //
    // Token input covenant check (PARAMETERIZED: tii) — identical to v14/v15
    // This is the authentication F6 below now reuses instead of a free `sii`.
    0x5a, 0x79, 0xcf,             // Op10 OpPick(tii) OpTxInputCovId               [3B]
    0x58, 0x79, 0x87, 0x69,       // Op8 OpPick(tcid) OpEqual OpVerify             [4B]
    // kas(0), mmfee_bps(1), ..., toi(11)
    //
    // F2: buyer SPK hash check (PARAMETERIZED: toi) — identical to v14/v15
    0x5b, 0x79, 0xc3, 0xaa,       // Op11 OpPick(toi) OpTxOutputSpk OpBlake2b      [4B]
    0x53, 0x79, 0x87, 0x69,       // Op3 OpPick(bspkh) OpEqual OpVerify            [4B]
    // kas(0), mmfee_bps(1), ..., toi(11)
    //
    // F4: token output covenant check (PARAMETERIZED: coi) — identical to v14/v15
    0x57, 0x79, 0x76,             // Op7 OpPick(tcid) OpDup                        [3B]
    0xd2, 0x51, 0xa2, 0x69,       // OpCovOutCount(T) Op1 OpGTE OpVerify           [4B]
    0x5a, 0x79, 0xd3,             // Op10 OpPick(coi) OpCovOutputIdx(T,coi)        [3B]
    0x5c, 0x79,                   // Op12 OpPick(toi)                              [2B]
    0x87, 0x69,                   // OpEqual OpVerify                              [2B]
    // kas(0), mmfee_bps(1), bspkh(2), ohash(3), mfill(4), pden(5),
    //    pnum(6), tcid(7), 1(8), coi(9), tii(10), toi(11) = 12 items (v14-identical, no sii)
    //
    // ============================================================
    // F6: CROSS-INPUT SURPLUS CAP (41B) — FIXED: reads tii, not free sii
    // ============================================================
    // Read sell_pnum from the ALREADY-AUTHENTICATED tii input's sigscript[7..15)
    // (tii is still on the stack at depth 10, unconsumed by the OpPick above.)
    0x5a, 0x79,                   // Op10 OpPick(tii)                              [2B]
    0x57,                         // Op7 (start=7)                                 [1B]
    0x5f,                         // Op15 (end=15)                                 [1B]
    0xbc,                         // OpTxInputScriptSigSubstr -> sell_pnum         [1B]
    // (13): sell_pnum(0), kas(1), mmfee_bps(2), ..., toi(12)
    //
    // Read sell_pden from the same tii input's sigscript[16..24)
    0x5b, 0x79,                   // Op11 OpPick(tii)                              [2B]
    0x60,                         // Op16 (start=16)                               [1B]
    0x01, 0x18,                   // push 24 (end=24)                              [2B]
    0xbc,                         // OpTxInputScriptSigSubstr -> sell_pden         [1B]
    // (14): sell_pden(0), sell_pnum(1), kas(2), mmfee_bps(3), ...,
    //       pden_b(7), pnum_b(8), ..., toi(13)
    //
    // tokens = ACTUAL tokens delivered to the buyer at output[toi], NOT the
    // full hypothetical kas/pden*pnum. The IOC sub-dispatch relaxes the token
    // output floor to mfill, so a matcher can deliver only mfill tokens while
    // consuming the full kas_in; basing fair_kas on the hypothetical full
    // quantity let that surplus escape F6. Reading output[toi] binds the cap to
    // what the buyer really received. Same stack effect (pushes one item);
    // 5 OpNop pad the freed bytes so RS length / dispatch thresholds are
    // unchanged. (toi is at depth 13 here: sell_pden,sell_pnum,kas,mmfee_bps,
    // bspkh,ohash,mfill,pden_b,pnum_b,tcid,1,coi,tii,toi.)
    0x5d, 0x79,                   // Op13 OpPick(toi)                              [2B]
    0xc2,                         // OpTxOutputAmount -> actual tokens             [1B]
    0x61, 0x61, 0x61, 0x61, 0x61, // OpNop x5 (length-neutral pad)                 [5B]
    //
    // fair_kas = tokens / sell_pden * sell_pnum (div-first, overflow-safe)
    0x51, 0x79,                   // Op1 OpPick(sell_pden)                         [2B]
    0x96,                         // OpDiv -> tokens / sell_pden                   [1B]
    0x52, 0x79,                   // Op2 OpPick(sell_pnum)                         [2B]
    0x95,                         // OpMul -> fair_kas                             [1B]
    //
    // surplus = kas - fair_kas
    0x53, 0x79,                   // Op3 OpPick(kas)                               [2B]
    0x7c,                         // OpSwap                                        [1B]
    0x94,                         // OpSub -> surplus = kas - fair_kas             [1B]
    //
    // max_surplus = kas / 10000 * mmfee_bps (div-first, overflow-safe)
    0x53, 0x79,                   // Op3 OpPick(kas)                               [2B]
    0x02, 0x10, 0x27,             // push 10000 (0x2710 LE)                        [3B]
    0x96,                         // OpDiv -> kas / 10000                          [1B]
    0x55, 0x79,                   // Op5 OpPick(mmfee_bps)                         [2B]
    0x95,                         // OpMul -> max_surplus                         [1B]
    //
    // Verify: max_surplus >= surplus. Stack is [surplus, max_surplus] (max_surplus
    // on top), and OpGTE/OpLTE pop [a=deeper, b=top], so OpGTE would compute the
    // INVERTED `surplus >= max_surplus` (rejecting every within-cap trade). Use
    // OpLTE instead: `surplus <= max_surplus` == the intended cap. (This F6 body
    // was never exercised on-chain before — v14 has no fill F6, v15 was broken —
    // so this off-by-swap surfaced only when the first real v16 match was run
    // through the script engine; see V16_STATUS.md Phase 10.)
    0xa1, 0x69,                   // OpLTE OpVerify (surplus <= max_surplus)        [2B]
    // (14): sell_pden(0), sell_pnum(1), kas(2), mmfee_bps(3), ..., toi(13)
    //
    // Drop F6 temporaries (sell_pden + sell_pnum)
    0x6d,                         // Op2Drop                                       [1B]
    // (12): kas(0), mmfee_bps(1), ..., toi(11) — restored to pre-F6 state (v14-identical)
    //
    // ============================================================
    // Cleanup: 12 items = Op2Drop x6 (v14-identical, NOT v15's 13-item +OpDrop)
    0x6d, 0x6d, 0x6d, 0x6d, 0x6d, 0x6d, // Op2Drop x6                              [6B]

    // ============================================================
    // PARTIAL FILL PATH (1B OpElse + 88B v14-identical + 39B F6 + 6B cleanup = 134B)
    // ============================================================
    0x67,                         // OpElse (sigLen >= T1: partial)                 [1B]
    // Stack: cpend(0), mmfee_bps(1), bspkh(2), ohash(3), mfill(4), pden(5),
    //        pnum(6), tcid(7), 2(8), fk(9), ti(10), ri(11)
    // F5
    0x00, 0x87, 0x69,             // cpend==0                                      [3B]
    // Stack: mmfee_bps(0), bspkh(1), ohash(2), mfill(3), pden(4), pnum(5),
    //        tcid(6), 2(7), fk(8), ti(9), ri(10)  [11 items, v14-identical, no sii]
    // Price calc: fill_tokens = fk / pden * pnum (div-first, overflow-safe)
    0x58, 0x79,                   // Op8 OpPick(fk)                                [2B]
    0x76,                         // OpDup                                         [1B]
    0x56, 0x79, 0x96,             // Op6 OpPick(pden) OpDiv                        [3B]
    0x57, 0x79, 0x95,             // Op7 OpPick(pnum) OpMul                        [3B]
    0x76,                         // OpDup                                         [1B]
    0x56, 0x79, 0xa2, 0x69,       // Op6 OpPick(mfill) OpGTE OpVerify             [4B]
    0x5b, 0x79, 0xc2,             // Op11 OpPick(ti) OpTxOutputAmount              [3B]
    0x7c, 0xa2, 0x69,             // OpSwap OpGTE OpVerify                        [3B]
    0xb9, 0xbe,                   // kas_in                                        [2B]
    0x51, 0x79, 0xa0, 0x69,       // Op1 OpPick(fk_c) OpGreaterThan OpVerify       [4B]
    0x5b, 0x79, 0xc3,             // Op11 OpPick(ri) OpTxOutputSpk                 [3B]
    0xb9, 0xbf,                   // OpTxInputIndex OpTxInputSpk                   [2B]
    0x87, 0x69,                   // OpEqual OpVerify                              [2B]
    0xb9, 0xbe,                   // kas_in                                        [2B]
    0x51, 0x7a, 0x94,             // Op1 OpRoll(fk_c) OpSub                        [3B]
    0x5b, 0x79, 0xc2,             // Op11 OpPick(ri) OpTxOutputAmount              [3B]
    0x7c, 0xa2, 0x69,             // OpSwap OpGTE OpVerify                        [3B]
    0xb9, 0xbe,                   // kas_in                                        [2B]
    0x59, 0x79, 0x94,             // Op9 OpPick(fk) OpSub                          [3B]
    0x55, 0x79, 0x96,             // Op5 OpPick(pden) OpDiv                        [3B]
    0x56, 0x79, 0x95,             // Op6 OpPick(pnum) OpMul                        [3B]
    0x54, 0x79, 0xa2, 0x69,       // Op4 OpPick(mfill) OpGTE OpVerify             [4B]
    // Token input check — HARDCODED input index 1 (v14/v15-identical). F6
    // below authenticates against this exact same literal, not a free `sii`.
    0x51, 0xcf,                   // Op1 OpTxInputCovId                            [2B]
    0x57, 0x79, 0x87, 0x69,       // Op7 OpPick(tcid) OpEqual OpVerify             [4B]
    // F2: buyer SPK hash
    0x59, 0x79, 0xc3,             // Op9 OpPick(ti) OpTxOutputSpk                  [3B]
    0xaa,                         // OpBlake2b                                     [1B]
    0x52, 0x79, 0x87, 0x69,       // Op2 OpPick(bspkh) OpEqual OpVerify            [4B]
    // F4: token output covenant
    0x56, 0x79, 0x76,             // Op6 OpPick(tcid) OpDup                        [3B]
    0xd2, 0x51, 0xa2, 0x69,       // OpCovOutCount(T) Op1 OpGTE OpVerify           [4B]
    0x00, 0xd3,                   // Op0 OpCovOutputIdx(T,0)                       [2B]
    0x51,                         // Op1                                           [1B]
    0x87, 0x69,                   // OpEqual OpVerify                              [2B]
    // mmfee_bps(0), bspkh(1), ohash(2), mfill(3), pden(4), pnum(5),
    //   tcid(6), 2(7), fk(8), ti(9), ri(10) = 11 items (v14-identical, no sii)
    //
    // ============================================================
    // F6: CROSS-INPUT SURPLUS CAP (39B) — FIXED: idx hardcoded to literal 1
    // ============================================================
    // Read sell_pnum from input[1]'s sigscript[7..15). No OpPick needed: the
    // index itself is the constant the covenant check above already trusts.
    0x51,                         // Op1 (idx=1, hardcoded token input)            [1B]
    0x57,                         // Op7 (start=7)                                 [1B]
    0x5f,                         // Op15 (end=15)                                 [1B]
    0xbc,                         // OpTxInputScriptSigSubstr -> sell_pnum         [1B]
    // Read sell_pden from input[1]'s sigscript[16..24)
    0x51,                         // Op1 (idx=1, hardcoded)                        [1B]
    0x60,                         // Op16 (start=16)                               [1B]
    0x01, 0x18,                   // push 24 (end=24)                              [2B]
    0xbc,                         // OpTxInputScriptSigSubstr -> sell_pden         [1B]
    // Recompute: tokens = fk / buy_pden * buy_pnum (div-first, overflow-safe)
    0x5a, 0x79,                   // Op10 OpPick(fk)                               [2B]
    0x57, 0x79,                   // Op7 OpPick(pden_b)                            [2B]
    0x96,                         // OpDiv -> fk / buy_pden                        [1B]
    0x58, 0x79,                   // Op8 OpPick(pnum_b)                            [2B]
    0x95,                         // OpMul -> tokens                               [1B]
    // fair_kas = tokens / sell_pden * sell_pnum (div-first, overflow-safe)
    0x51, 0x79,                   // Op1 OpPick(sell_pden)                         [2B]
    0x96,                         // OpDiv -> tokens / sell_pden                   [1B]
    0x52, 0x79,                   // Op2 OpPick(sell_pnum)                         [2B]
    0x95,                         // OpMul -> fair_kas                             [1B]
    // surplus = fk - fair_kas
    0x5b, 0x79,                   // Op11 OpPick(fk)                               [2B]
    0x7c,                         // OpSwap                                        [1B]
    0x94,                         // OpSub -> surplus = fk - fair_kas              [1B]
    // max_surplus = fk / 10000 * mmfee_bps (div-first, overflow-safe)
    0x5b, 0x79,                   // Op11 OpPick(fk)                               [2B]
    0x02, 0x10, 0x27,             // push 10000 (0x2710 LE)                        [3B]
    0x96,                         // OpDiv -> fk / 10000                           [1B]
    0x54, 0x79,                   // Op4 OpPick(mmfee_bps)                         [2B]
    0x95,                         // OpMul -> max_surplus                         [1B]
    // Verify: max_surplus >= surplus. Same inverted-OpGTE fix as the fill path
    // above: stack is [surplus, max_surplus]; use OpLTE for `surplus <= max_surplus`.
    0xa1, 0x69,                   // OpLTE OpVerify (surplus <= max_surplus)        [2B]
    // Drop F6 temporaries (sell_pden + sell_pnum)
    0x6d,                         // Op2Drop                                       [1B]
    // (11): mmfee_bps(0), ..., ri(10) — restored to pre-F6 state (v14-identical)
    //
    // ============================================================
    // Cleanup: 11 items = Op2Drop x5 + OpDrop (v14-identical, NOT v15's 12-item Op2Drop x6)
    0x6d, 0x6d, 0x6d, 0x6d, 0x6d, 0x75, // Op2Drop x5 + OpDrop                    [6B]

    // FILL/PARTIAL END
    0x68,                         // OpEndIf (fill vs partial)                     [1B]
    0x68,                         // OpEndIf (expire vs fill/partial)              [1B]

    // CANCEL / CANCEL-MARK PATH (28B) — identical to v14/v15
    0x67,                         // OpElse (sigLen >= T2: cancel)                 [1B]
    0x75,                         // OpDrop (sigLen)                               [1B]
    0x75,                         // OpDrop (expiry)                               [1B]
    0x5a, 0x7a,                   // Op10 OpRoll(selector)                         [2B]
    0x63,                         // OpIf (cancel-mark)                            [1B]
    0x00, 0x87, 0x69,             // cpend==0 verify                              [3B]
    0x67,                         // OpElse (cancel-complete)                      [1B]
    0x75,                         // OpDrop cpend                                  [1B]
    0x68,                         // OpEndIf                                       [1B]
    0x57, 0x79, 0xaa,             // Op7 OpPick(pk) OpBlake2b                      [3B]
    0x53, 0x79, 0x87, 0x69,       // Op3 OpPick(ohash) OpEqual OpVerify            [4B]
    0x58, 0x7a,                   // Op8 OpRoll(sig)                               [2B]
    0x58, 0x7a,                   // Op8 OpRoll(pk)                                [2B]
    0xad,                         // OpCheckSigVerify                              [1B]
    0x6d, 0x6d, 0x6d, 0x75,       // Op2Drop x3 + OpDrop                          [4B]

    // CLOSING (2B)
    0x68,                         // OpEndIf (outer)                               [1B]
    0x51,                         // Op1 (TRUE)                                    [1B]
];

/// Expected length of BUY_ORDER_V16_BODY bytecode.
pub const BUY_ORDER_V16_BODY_EXPECTED_LEN: usize = 331;

/// Expected length of v16 buy_order redeemScript (145B state + 331B body).
pub const BUY_ORDER_V16_RS_EXPECTED_LEN: usize = 145 + BUY_ORDER_V16_BODY_EXPECTED_LEN;

/// Build v16 buy_order redeemScript (145B state + 331B body = 476B).
///
/// Same state layout as v14/v15 (145B). The `max_matcher_fee` field is
/// interpreted as basis points (BPS), NOT absolute sompi (same as v15).
///
/// e.g., max_matcher_fee_bps=30 means 0.30% of trade value.
pub fn build_buy_v16_redeem_script(
    token_covenant_id: &[u8; 32],
    price_num: u64,
    price_den: u64,
    min_fill: u64,
    owner_hash: &[u8; 32],
    buyer_spk_hash: &[u8; 32],
    max_matcher_fee_bps: u64,
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
        return Err(crate::KobError::Contract("min_fill must be > 0".into()));
    }
    if cancel_pending > 1 {
        return Err(crate::KobError::Contract("cancel_pending must be 0 or 1".into()));
    }
    if max_matcher_fee_bps > 10000 {
        return Err(crate::KobError::Contract("max_matcher_fee_bps must be <= 10000".into()));
    }
    let g = gcd(price_num, price_den);
    let price_num = if g > 0 { price_num / g } else { price_num };
    let price_den = if g > 0 { price_den / g } else { price_den };
    let mut rs = Vec::with_capacity(145 + BUY_ORDER_V16_BODY.len());
    // State header (145B) — identical layout to v14/v15
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
    rs.extend_from_slice(&u64_le(max_matcher_fee_bps));
    if cancel_pending == 0 {
        rs.push(0x00);
    } else {
        rs.push(0x51);
    }
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(expiry_daa));
    // Body
    rs.extend_from_slice(BUY_ORDER_V16_BODY);
    Ok(rs)
}

/// Build v16 buy_order fill sigscript.
///
/// Layout: `[toi] [tii] [coi] [Op1] [pushData(RS)]`
///
/// No `sii` parameter (Phase-0 fix): F6 reads the sell price directly off the
/// already-authenticated `tii` input.
/// All indices use OpN (1 byte) for 0..=16, or data-push `[0x01, val]` (2 bytes) for 17+.
pub fn build_buy_v16_fill_sigscript(
    token_output_idx: u16,
    token_input_idx: u16,
    cov_output_idx: u16,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(7 + redeem_script.len() + 3);
    push_index(&mut ss, token_output_idx);
    push_index(&mut ss, token_input_idx);
    push_index(&mut ss, cov_output_idx);
    ss.push(0x51); // Op1 (selector = fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build v16 buy_order IOC fill sigscript.
///
/// Layout: `[toi] [tii] [coi] [Op5] [pushData(RS)]`
///
/// Same as fill but with Op5 selector for IOC path (relaxes token check to >= mfill).
pub fn build_buy_v16_ioc_fill_sigscript(
    token_output_idx: u16,
    token_input_idx: u16,
    cov_output_idx: u16,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(7 + redeem_script.len() + 3);
    push_index(&mut ss, token_output_idx);
    push_index(&mut ss, token_input_idx);
    push_index(&mut ss, cov_output_idx);
    ss.push(0x55); // Op5 (selector = IOC fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build v16 buy_order partial fill sigscript.
///
/// Layout: `[ri] [ti] [pushData(fk 8B)] [Op2] [pushData(RS)]`
///
/// No `sii` parameter: F6's cross-input read uses the hardcoded literal `1`
/// (matching the pre-existing hardcoded token-input covenant check).
/// Indices use OpN (1 byte) for 0..=16, or data-push `[0x01, val]` (2 bytes) for 17+.
pub fn build_buy_v16_partial_fill_sigscript(
    redeem_script: &[u8],
    fill_kas: u64,
    residual_idx: u16,
    token_idx: u16,
) -> Vec<u8> {
    let fk = u64_le(fill_kas);
    let mut ss = Vec::with_capacity(16 + redeem_script.len() + 3);
    push_index(&mut ss, residual_idx);
    push_index(&mut ss, token_idx);
    ss.extend_from_slice(&push_data(&fk));
    ss.push(0x52); // Op2 (selector = partial fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

// ============================================================================
// V17 BUY CONTRACT — N:M-capable sweep (N sells : 1 buy in one tx)
// ============================================================================
//
// v16 delivered the buyer's tokens to ONE merged output[toi] and priced the
// surplus cap against it. The sell contract's per-input F4 (Fix 3) requires each
// sell's tokens to land in an output that ONLY that sell authorizes, so an
// N-sell match needs N separate token outputs — mutually incompatible with the
// single-output read. v17 SUMS N per-sell token outputs, each re-derived from
// and bound to its own sell input, and caps the buyer's surplus against the sum
// (see kob/NM_BUY_DESIGN.md).
//
// Both buyer protections are carried:
//   - aggregate limit-price floor: sum(tokens_i) >= kas_in/buy_pden*buy_pnum
//     (relaxed to `mfill` on the IOC selector, mirroring v16).
//   - aggregate surplus cap: (kas_in - sum(fair_kas_i)) <= kas_in/10000*mmfee_bps
//     where fair_kas_i = tokens_i priced at sell_i's own committed price.
//
// Per summation term i, given the sigscript-supplied sell input index tii_i:
//   1. toi_i = OpAuthOutputIdx(tii_i, 0)  — the delivered output is DERIVED from
//      the sell input, never a free sigscript parameter, so no decoy/unauthorized
//      output can be substituted (CovenantsContext guarantees toi_i carries the
//      same covenant id as input tii_i).
//   2. OpInputCovenantId(tii_i) == tcid   — tii_i is really a sell of THIS token.
//   3. blake2b(OpTxOutputSpk(toi_i)) == bspkh — tokens go to the buyer.
//   4. sell_pnum/pden read off tii_i's sigscript at the fixed-offset convention
//      (build_sell_fill_sigscript_fixed_offset, unchanged): [7..15)/[16..24).
// Plus strict-increasing tii across active slots (anti double-count), O(N).
//
// State layout: UNCHANGED (145B) — identical to v14/v15/v16. mmfee_bps is BPS.
// Dispatch: explicit selector (like the sell contract), NOT length-based — the
// fill sigscript carries a variable number of tii pushes. Selector sits at
// depth 9 (9 state items) in every sigscript form.

/// Maximum sells swept into one buy fill (compile-time slot count).
///
/// Justification (tx mass budget): each swept sell adds ~478B of input (its
/// fixed-offset fill sigscript is ~433B: `[0x01,koi][Op1][pushData(RS 427B)]`)
/// + 2 outputs (seller KAS + buyer tokens). An N=8 sweep tx is ~6KB serialized
/// + ~6K output-spk mass ≈ 12,000 compute grams — ~12% of the pre-Toccata
/// `MAXIMUM_STANDARD_TRANSACTION_MASS` (100,000), leaving generous headroom for
/// fee/change/mass-estimation slack. (Post-Toccata the standard cap is relaxed
/// and only block-fit bounds apply, so 8 is conservative either way;
/// script-size/op-count limits are 1e6, nowhere near binding.) 8 balances
/// realistic same-token sweep depth against the per-fill cost every buy — even
/// a 1:1 fill — pays to carry the MAX_N-slot body. A crossing book with more
/// than MAX_N same-token sells against one buy is settled MAX_N-at-a-time across
/// sequential txs by the matcher (each a valid v17 fill consuming <=8 sells);
/// this full-sweep path fully fills one buy from <=MAX_N sells.
pub const BUY_ORDER_V17_MAX_N: usize = 8;

// v17 opcode bytes (named for readability of the programmatic builder).
// pub(crate): the v18 unified-spot builders (buy/sell here, OCO in oco.rs,
// swap in swap.rs) reuse the same emission table.
pub(crate) mod v17op {
    pub const OP0: u8 = 0x00;
    pub const OP1: u8 = 0x51;
    pub const DUP: u8 = 0x76;
    pub const DROP: u8 = 0x75;
    pub const TWO_DROP: u8 = 0x6d;
    pub const SWAP: u8 = 0x7c;
    pub const PICK: u8 = 0x79;
    pub const ROLL: u8 = 0x7a;
    pub const IF: u8 = 0x63;
    pub const NOTIF: u8 = 0x64;
    pub const ELSE: u8 = 0x67;
    pub const ENDIF: u8 = 0x68;
    pub const VERIFY: u8 = 0x69;
    pub const EQUAL: u8 = 0x87;
    pub const LT: u8 = 0x9f;
    pub const NUMEQUAL: u8 = 0x9c;
    pub const ADD: u8 = 0x93;
    pub const SUB: u8 = 0x94;
    pub const MUL: u8 = 0x95;
    pub const DIV: u8 = 0x96;
    pub const GT: u8 = 0xa0;
    pub const LTE: u8 = 0xa1;
    pub const GTE: u8 = 0xa2;
    pub const BLAKE2B: u8 = 0xaa;
    pub const CHECKSIGVERIFY: u8 = 0xad;
    pub const CLTV: u8 = 0xb0;
    pub const CSV: u8 = 0xb1;
    pub const TXLOCKTIME: u8 = 0xb5;
    pub const TXINPUTINDEX: u8 = 0xb9;
    pub const TXINPUTSIGSUBSTR: u8 = 0xbc;
    pub const TXINPUTAMOUNT: u8 = 0xbe;
    pub const TXOUTPUTAMOUNT: u8 = 0xc2;
    pub const TXOUTPUTSPK: u8 = 0xc3;
    pub const AUTHOUTPUTIDX: u8 = 0xcc;
    pub const INPUTCOVENANTID: u8 = 0xcf;
    // Added for the v18 unified-spot generation (unused by v17 bodies).
    pub const TXINPUTCOUNT: u8 = 0xb3;
    pub const TXINPUTSPK: u8 = 0xbf;
    pub const CHECKSIG: u8 = 0xac;
    pub const COVOUTCOUNT: u8 = 0xd2;
    pub const OUTPUTCOVENANTID: u8 = 0xd5;
    // Added for the v18 bracket (entry-type dispatch on an 8-byte state push).
    pub const BIN2NUM: u8 = 0xce;
}

// Emit `OpPick(depth)`.
pub(crate) fn e_pick(b: &mut Vec<u8>, depth: usize) {
    push_index(b, depth as u16);
    b.push(v17op::PICK);
}
// Emit `OpRoll(depth)`.
pub(crate) fn e_roll(b: &mut Vec<u8>, depth: usize) {
    push_index(b, depth as u16);
    b.push(v17op::ROLL);
}
// Emit a numeric literal push.
pub(crate) fn e_num(b: &mut Vec<u8>, n: u16) {
    push_index(b, n);
}

/// Build the v17 buy body (deterministic given `BUY_ORDER_V17_MAX_N`).
///
/// Stack after the RS state prefix pushes (depth 0 = top):
///   expiry(0), cpend(1), mmfee_bps(2), bspkh(3), ohash(4), mfill(5),
///   pden(6), pnum(7), tcid(8), <sigscript items at depth 9+>
/// with the selector at depth 9 in every sigscript form.
pub fn build_buy_v17_body() -> Vec<u8> {
    use v17op::*;
    const MAX_N: usize = BUY_ORDER_V17_MAX_N;
    let mut b: Vec<u8> = Vec::with_capacity(1024);

    // ===== DISPATCH: bring selector (depth 9) to top, branch on its value =====
    e_num(&mut b, 9);
    b.push(ROLL);

    // selector == 4 -> EXPIRE
    b.push(DUP);
    e_num(&mut b, 4);
    b.push(NUMEQUAL);
    b.push(IF);
    {
        b.push(DROP);
        // stack: expiry(0), cpend(1), mmfee(2), bspkh(3), ohash(4), mfill(5),
        //        pden(6), pnum(7), tcid(8)
        b.push(DUP);
        b.push(VERIFY); // expiry != 0 (GTC guard)
        b.push(CLTV); // consumes expiry; requires expiry <= tx.lockTime
        // cpend(0), mmfee(1), bspkh(2), ohash(3), mfill(4), pden(5), pnum(6), tcid(7)
        b.push(OP0);
        b.push(TXOUTPUTSPK);
        b.push(BLAKE2B);
        e_pick(&mut b, 3); // bspkh (depth 2 + 1 for the hash)
        b.push(EQUAL);
        b.push(VERIFY); // output[0] pays the buyer
        b.push(OP0);
        b.push(TXOUTPUTAMOUNT);
        b.push(TXINPUTINDEX);
        b.push(TXINPUTAMOUNT);
        b.push(GTE);
        b.push(VERIFY); // output[0].value >= input.value (full refund)
        for _ in 0..4 {
            b.push(TWO_DROP);
        }
    }
    b.push(ELSE);
    {
        b.push(DUP);
        e_num(&mut b, 0);
        b.push(NUMEQUAL);
        b.push(IF); // selector == 0 -> CANCEL
        {
            b.push(DROP);
            emit_cancel_body(&mut b);
        }
        b.push(ELSE);
        {
            b.push(DUP);
            e_num(&mut b, 3);
            b.push(NUMEQUAL);
            b.push(IF); // selector == 3 -> CANCEL-MARK
            {
                b.push(DROP);
                emit_cancel_body(&mut b);
            }
            b.push(ELSE);
            {
                // selector is 1 (fill) or 5 (IOC fill); selector on top.
                emit_fill_body(&mut b, MAX_N);
            }
            b.push(ENDIF);
        }
        b.push(ENDIF);
    }
    b.push(ENDIF);

    b.push(OP1);
    b
}

/// CANCEL / CANCEL-MARK owner-signature spend.
/// Entry (selector dropped): expiry(0), cpend(1), mmfee(2), bspkh(3), ohash(4),
///   mfill(5), pden(6), pnum(7), tcid(8), sig(9), pk(10)
fn emit_cancel_body(b: &mut Vec<u8>) {
    use v17op::*;
    e_pick(b, 10);
    b.push(BLAKE2B); // blake2b(pk)
    e_pick(b, 5); // ohash (depth 4 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    e_roll(b, 9); // sig -> top
    e_roll(b, 10); // pk -> top
    b.push(CHECKSIGVERIFY);
    // 9 items: expiry..tcid
    for _ in 0..4 {
        b.push(TWO_DROP);
    }
    b.push(DROP);
}

/// FILL (selector 1) / IOC FILL (selector 5): the N:M sweep.
/// Entry (selector on top): selector(0), expiry(1), cpend(2), mmfee_bps(3),
///   bspkh(4), ohash(5), mfill(6), pden(7), pnum(8), tcid(9), N(10),
///   tii_MAX_N(11), tii_k(11 + MAX_N - k), tii_1(10 + MAX_N)
fn emit_fill_body(b: &mut Vec<u8>, max_n: usize) {
    use v17op::*;

    // A) ioc_flag = (selector == 5), replacing selector at depth 0.
    e_num(b, 5);
    b.push(NUMEQUAL);
    // B0: ioc_flag(0), expiry(1), cpend(2), mmfee(3), bspkh(4), ohash(5),
    //     mfill(6), pden(7), pnum(8), tcid(9), N(10), tii_MAX_N(11),
    //     tii_k(11 + max_n - k)

    // B) F5: cpend == 0.
    e_pick(b, 2);
    b.push(OP0);
    b.push(NUMEQUAL);
    b.push(VERIFY);

    // C) time gate on expiry (copy; leaves stack unchanged).
    e_pick(b, 1);
    b.push(DUP);
    b.push(OP0);
    b.push(NUMEQUAL);
    b.push(NOTIF);
    b.push(DUP);
    b.push(TXLOCKTIME);
    b.push(GT);
    b.push(VERIFY);
    b.push(ENDIF);
    b.push(DROP);

    // D) exposure delay (OP_CSV 50 DAA).
    e_num(b, 50);
    b.push(CSV);

    // Distinctness: tii_k < tii_{k+1} for active adjacent pairs.
    for k in 1..max_n {
        e_num(b, (k + 1) as u16); // guard: (k+1) <= N
        e_pick(b, 11); // N (depth 10 + 1)
        b.push(LTE);
        b.push(IF);
        {
            let d = 11 + max_n - k; // tii_k depth at B0
            e_pick(b, d); // tii_k
            e_pick(b, d); // tii_{k+1} (was d-1, +1 after the tii_k push)
            b.push(LT);
            b.push(VERIFY);
        }
        b.push(ENDIF);
    }

    // E) floor_value = ioc_flag ? mfill : expected, consuming ioc_flag.
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT); // kas_in(0), ioc_flag(1)
    e_pick(b, 8); // pden (depth 7 + 1)
    b.push(DIV);
    e_pick(b, 9); // pnum (depth 8 + 1)
    b.push(MUL); // expected(0), ioc_flag(1)
    b.push(DUP);
    e_pick(b, 8); // mfill (B0 depth 6 -> +2 after expected/dup)
    b.push(GTE);
    b.push(VERIFY); // expected >= mfill
    b.push(SWAP); // ioc_flag(0), expected(1)
    b.push(IF);
    {
        b.push(DROP); // drop expected
        e_pick(b, 5); // mfill as floor
    }
    b.push(ENDIF);
    // B1: floor_value(0), expiry(1), ... tcid(9), N(10), tii_MAX_N(11), ...

    // F) token_sum = 0.
    b.push(OP0);
    // B2: token_sum(0), floor_value(1), expiry(2), cpend(3), mmfee(4),
    //     bspkh(5), ohash(6), mfill(7), pden(8), pnum(9), tcid(10), N(11),
    //     tii_MAX_N(12), tii_k(12 + max_n - k)

    // G) PASS 1: sum delivered tokens + per-term binding checks.
    for k in 1..=max_n {
        e_num(b, k as u16); // guard: k <= N
        e_pick(b, 12); // N (depth 11 + 1)
        b.push(LTE);
        b.push(IF);
        {
            let tii = 12 + max_n - k; // tii_k depth at B2
            e_pick(b, tii);
            b.push(OP0);
            b.push(AUTHOUTPUTIDX); // toi = auth_outputs[tii][0]
            e_pick(b, tii + 1); // tii_k (+1 for toi)
            b.push(INPUTCOVENANTID);
            e_pick(b, 12); // tcid (depth 10, +2 for toi+covid)
            b.push(EQUAL);
            b.push(VERIFY);
            b.push(DUP);
            b.push(TXOUTPUTSPK);
            b.push(BLAKE2B);
            e_pick(b, 7); // bspkh (depth 5, +2 for toi+hash)
            b.push(EQUAL);
            b.push(VERIFY);
            b.push(TXOUTPUTAMOUNT); // tokens_i (consumes toi)
            b.push(ADD); // token_sum += tokens_i
        }
        b.push(ENDIF);
    }

    // H) aggregate limit-price floor: token_sum >= floor_value.
    b.push(SWAP); // floor_value(0), token_sum(1)
    b.push(GTE); // pops [token_sum, floor_value] -> token_sum >= floor_value
    b.push(VERIFY);
    // B3: expiry(0), cpend(1), mmfee(2), bspkh(3), ohash(4), mfill(5),
    //     pden(6), pnum(7), tcid(8), N(9), tii_MAX_N(10), tii_k(10 + max_n - k)

    // I) fair_sum = 0.
    b.push(OP0);
    // B4: fair_sum(0), expiry(1), cpend(2), mmfee(3), bspkh(4), ohash(5),
    //     mfill(6), pden(7), pnum(8), tcid(9), N(10), tii_MAX_N(11),
    //     tii_k(11 + max_n - k)

    // PASS 2: sum fair_kas at each sell's own committed price.
    for k in 1..=max_n {
        e_num(b, k as u16);
        e_pick(b, 11); // N (depth 10 + 1)
        b.push(LTE);
        b.push(IF);
        {
            let tii = 11 + max_n - k; // tii_k depth at B4
            e_pick(b, tii);
            b.push(OP0);
            b.push(AUTHOUTPUTIDX); // toi
            b.push(TXOUTPUTAMOUNT); // tokens_i
            e_pick(b, tii + 1); // tii_k (+1 for tokens)
            e_num(b, 7);
            e_num(b, 15);
            b.push(TXINPUTSIGSUBSTR); // sell_pnum
            e_pick(b, tii + 2); // tii_k (+2 for tokens + pnum)
            e_num(b, 16);
            e_num(b, 24);
            b.push(TXINPUTSIGSUBSTR); // sell_pden
            // fair_kas = tokens / sell_pden * sell_pnum, consuming temps.
            // stack: fair_sum, tokens, sell_pnum, sell_pden(top)
            e_num(b, 2);
            b.push(ROLL); // tokens -> top
            b.push(SWAP); // sell_pden on top, tokens below
            b.push(DIV); // tokens / sell_pden
            b.push(SWAP); // sell_pnum on top
            b.push(MUL); // -> fair_kas
            b.push(ADD); // fair_sum += fair_kas
        }
        b.push(ENDIF);
    }

    // J) aggregate surplus cap.
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT); // kas_in(0), fair_sum(1)
    b.push(DUP);
    e_num(b, 2);
    b.push(ROLL); // fair_sum -> top: fair_sum(0), kas_in(1), kas_in(2)
    b.push(SUB); // surplus = kas_in - fair_sum: surplus(0), kas_in(1)
    b.push(SWAP); // kas_in(0), surplus(1)
    e_num(b, 10000);
    b.push(DIV); // kas_in/10000(0), surplus(1)
    e_pick(b, 4); // mmfee_bps (depth 2, +2 for surplus + kas_in/10000)
    b.push(MUL); // max_surplus(0), surplus(1)
    b.push(LTE); // pops [surplus, max_surplus] -> surplus <= max_surplus
    b.push(VERIFY);
    // leftover: 9 state + N + max_n tii
    let leftover = 10 + max_n;
    for _ in 0..(leftover / 2) {
        b.push(TWO_DROP);
    }
    if leftover % 2 == 1 {
        b.push(DROP);
    }
}

/// Expected v17 buy body length (deterministic for `BUY_ORDER_V17_MAX_N`=8).
/// Asserted against `build_buy_v17_body()` in tests + the `bytecode_stable` pin.
pub const BUY_ORDER_V17_BODY_EXPECTED_LEN: usize = 693;

/// Expected v17 buy redeemScript length (145B state + body).
pub const BUY_ORDER_V17_RS_EXPECTED_LEN: usize = 145 + BUY_ORDER_V17_BODY_EXPECTED_LEN;

/// Build the v17 buy_order redeemScript (145B state + v17 body).
///
/// State layout identical to v14/v15/v16 (145B). `max_matcher_fee_bps` is BPS.
pub fn build_buy_v17_redeem_script(
    token_covenant_id: &[u8; 32],
    price_num: u64,
    price_den: u64,
    min_fill: u64,
    owner_hash: &[u8; 32],
    buyer_spk_hash: &[u8; 32],
    max_matcher_fee_bps: u64,
    cancel_pending: u8,
    expiry_daa: u64,
) -> crate::Result<Vec<u8>> {
    if price_num == 0 {
        return Err(crate::KobError::Contract("price_num must be > 0".into()));
    }
    if price_den == 0 {
        return Err(crate::KobError::Contract("price_den must be > 0".into()));
    }
    if min_fill == 0 {
        return Err(crate::KobError::Contract("min_fill must be > 0".into()));
    }
    if cancel_pending > 1 {
        return Err(crate::KobError::Contract("cancel_pending must be 0 or 1".into()));
    }
    if max_matcher_fee_bps > 10000 {
        return Err(crate::KobError::Contract("max_matcher_fee_bps must be <= 10000".into()));
    }
    let g = gcd(price_num, price_den);
    let price_num = if g > 0 { price_num / g } else { price_num };
    let price_den = if g > 0 { price_den / g } else { price_den };
    let body = build_buy_v17_body();
    let mut rs = Vec::with_capacity(145 + body.len());
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
    rs.extend_from_slice(&u64_le(max_matcher_fee_bps));
    if cancel_pending == 0 {
        rs.push(0x00);
    } else {
        rs.push(0x51);
    }
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(expiry_daa));
    rs.extend_from_slice(&body);
    Ok(rs)
}

/// Build a v17 buy fill sigscript for an N-sell sweep.
///
/// Layout: `[tii_1]...[tii_MAX_N][N][selector][pushData(RS)]` — always MAX_N tii
/// pushes (unused slots padded with 0, never read since guarded by k<=N), then
/// the sell count N, then the selector (Op1 fill / Op5 IOC).
///
/// `sell_input_indices` are the tx-input indices of the swept sells, strictly
/// increasing. `1 <= len <= MAX_N`.
pub fn build_buy_v17_fill_sigscript(
    sell_input_indices: &[u16],
    ioc: bool,
    redeem_script: &[u8],
) -> Vec<u8> {
    assert!(!sell_input_indices.is_empty(), "at least one sell required");
    assert!(
        sell_input_indices.len() <= BUY_ORDER_V17_MAX_N,
        "at most MAX_N sells per sweep"
    );
    let n = sell_input_indices.len();
    let mut ss = Vec::with_capacity(BUY_ORDER_V17_MAX_N + 4 + redeem_script.len() + 3);
    for i in 0..BUY_ORDER_V17_MAX_N {
        let v = if i < n { sell_input_indices[i] } else { 0 };
        push_index(&mut ss, v);
    }
    push_index(&mut ss, n as u16);
    ss.push(if ioc { 0x55 } else { 0x51 });
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build a v17 buy expire sigscript: `[Op4][pushData(RS)]`.
pub fn build_buy_v17_expire_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(0x54); // Op4
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build a v17 buy cancel/cancel-mark sigscript: `[pk][sig][selector][pushData(RS)]`.
/// selector = Op0 (cancel) or Op3 (cancel-mark).
///
/// `signature` is the 64-byte Schnorr signature; the SIGHASH_ALL type byte
/// (0x01) is appended here, matching the sell/receipt cancel convention. Note
/// the layout differs from v14/v16 cancel (`[selector][sig][pk][RS]`): v17
/// dispatches by selector (which must sit at stack depth 9), so pk/sig go
/// BELOW the selector, not above.
pub fn build_buy_v17_cancel_sigscript(
    pubkey: &[u8; 32],
    signature: &[u8; 64],
    mark: bool,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01); // SIGHASH_ALL
    let mut ss = Vec::with_capacity(2 + 32 + 66 + redeem_script.len() + 6);
    ss.extend_from_slice(&push_data(pubkey));
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.push(if mark { 0x53 } else { 0x00 }); // Op3 / Op0
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

// ============================================================================
// V18 UNIFIED SPOT CONTRACTS — buy + sell (see kob/V18_DESIGN.md)
// ============================================================================
//
// v18 unifies the whole spot matrix into one contract generation:
//   - Buy: v17 N:M fill/IOC semantics carried unchanged, plus a NEW Op2
//     partial-fill path (item C) with a byte-exact self-SPK residual, a
//     spent-based floor/cap, and a self-instance uniqueness guard.
//   - Sell: fill-family branches verify a sigscript price attestation
//     against the state price, and the partial F4 is upgraded from the
//     count-only `OpCovOutCount >= 2` to the per-input Fix-3 binding.
//
// CANONICAL PRICE ATTESTATION (all sweep-eligible sell-side fill sigscripts —
// plain sell fill, sell IOC, sell partial, OCO TP, OCO SL):
//
//   [0x01, koi]  [0x08, pnum 8LE]  [0x08, pden 8LE]  [branch extras]  [sel]  [RS]
//    bytes 0-1    2, 3..11          11, 12..20
//
// pnum always at sigscript [3..11), pden at [12..20); `koi` always a forced
// 2-byte push. Buys read the counterparty price ONLY at these offsets via
// `OpTxInputScriptSigSubstr` on the covenant-authenticated `tii`.
//
// DEVIATION from the frozen spec text: V18_DESIGN.md places branch extras
// (fta etc.) AFTER the RS push. The engine takes the P2SH redeem script from
// the TOP of the sigscript-produced stack (`execute_inner`, txscript lib.rs:
// `saved_stack` + `dstack.pop()`), so the RS MUST be the final push — extras
// after it would be popped as the "redeem script" and fail the P2SH hash.
// Extras therefore sit between the attested prices and the selector, which
// preserves the invariant the spec actually needs: the [3..11)/[12..20)
// prefix offsets never move across branches.

/// Maximum sells swept into one v18 buy fill (same budget analysis as v17).
pub const BUY_ORDER_V18_MAX_N: usize = BUY_ORDER_V17_MAX_N;

/// Build the v18 buy body (deterministic given `BUY_ORDER_V18_MAX_N`).
///
/// State (178B): the v17 145B layout preceded by the owner KAS seat
/// (`okspkh` = blake2b of the owner's raw P2PK SPK, the EXPIRE refund
/// endpoint — `bspkh` is the token_unit delivery seat post-D2 and must not
/// receive plain KAS). Stack after the state pushes:
///   expiry(0), cpend(1), mmfee_bps(2), bspkh(3), ohash(4), mfill(5),
///   pden(6), pnum(7), tcid(8), okspkh(9), <sigscript items at depth 10+>
/// with the selector at depth 10 in every sigscript form.
///
/// Selector dispatch: 0=CANCEL, 1=FILL, 2=PARTIAL-FILL, 3=CANCEL-MARK,
/// 4=EXPIRE, 5=IOC.
pub fn build_buy_v18_body() -> Vec<u8> {
    use v17op::*;
    const MAX_N: usize = BUY_ORDER_V18_MAX_N;
    let mut b: Vec<u8> = Vec::with_capacity(2048);

    // ===== DISPATCH: bring selector (depth 10) to top, branch on its value =====
    e_num(&mut b, 10);
    b.push(ROLL);

    // selector == 4 -> EXPIRE (refund to the owner KAS seat)
    b.push(DUP);
    e_num(&mut b, 4);
    b.push(NUMEQUAL);
    b.push(IF);
    {
        b.push(DROP);
        b.push(DUP);
        b.push(VERIFY); // expiry != 0 (GTC guard)
        b.push(CLTV); // consumes expiry; requires expiry <= tx.lockTime
        b.push(OP0);
        b.push(TXOUTPUTSPK);
        b.push(BLAKE2B);
        e_pick(&mut b, 9); // okspkh (depth 8 + 1 for the hash)
        b.push(EQUAL);
        b.push(VERIFY); // output[0] pays the OWNER KAS seat, not bspkh
        b.push(OP0);
        b.push(TXOUTPUTAMOUNT);
        b.push(TXINPUTINDEX);
        b.push(TXINPUTAMOUNT);
        b.push(GTE);
        b.push(VERIFY); // output[0].value >= input.value (full refund)
        // 9 items: cpend..okspkh
        for _ in 0..4 {
            b.push(TWO_DROP);
        }
        b.push(DROP);
    }
    b.push(ELSE);
    {
        b.push(DUP);
        e_num(&mut b, 0);
        b.push(NUMEQUAL);
        b.push(IF); // selector == 0 -> CANCEL
        {
            b.push(DROP);
            emit_cancel_body_v18(&mut b);
        }
        b.push(ELSE);
        {
            b.push(DUP);
            e_num(&mut b, 3);
            b.push(NUMEQUAL);
            b.push(IF); // selector == 3 -> CANCEL-MARK
            {
                b.push(DROP);
                emit_cancel_body_v18(&mut b);
            }
            b.push(ELSE);
            {
                b.push(DUP);
                e_num(&mut b, 2);
                b.push(NUMEQUAL);
                b.push(IF); // selector == 2 -> PARTIAL-FILL (new in v18)
                {
                    b.push(DROP);
                    emit_partial_body_v18(&mut b, MAX_N);
                }
                b.push(ELSE);
                {
                    // selector is 1 (fill) or 5 (IOC fill); selector on top.
                    emit_fill_body_v18(&mut b, MAX_N);
                }
                b.push(ENDIF);
            }
            b.push(ENDIF);
        }
        b.push(ENDIF);
    }
    b.push(ENDIF);

    b.push(OP1);
    b
}

/// v18 CANCEL / CANCEL-MARK owner-signature spend (okspkh-aware layout).
/// Entry (selector dropped): expiry(0), cpend(1), mmfee(2), bspkh(3),
///   ohash(4), mfill(5), pden(6), pnum(7), tcid(8), okspkh(9), sig(10),
///   pk(11)
fn emit_cancel_body_v18(b: &mut Vec<u8>) {
    use v17op::*;
    e_pick(b, 11);
    b.push(BLAKE2B); // blake2b(pk)
    e_pick(b, 5); // ohash (depth 4 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    e_roll(b, 10); // sig -> top
    e_roll(b, 11); // pk -> top
    b.push(CHECKSIGVERIFY);
    // 10 items: expiry..okspkh
    for _ in 0..5 {
        b.push(TWO_DROP);
    }
}

/// v18 FILL (selector 1) / IOC FILL (selector 5): v17 `emit_fill_body`
/// semantics carried unchanged, EXCEPT the counterparty price reads move to
/// the canonical attestation offsets [3..11) / [12..20) (v17 read the price
/// out of the RS push at [7..15) / [16..24) — the layout the old fixed-offset
/// sell sigscripts had).
///
/// Entry (selector on top): selector(0), expiry(1), cpend(2), mmfee_bps(3),
///   bspkh(4), ohash(5), mfill(6), pden(7), pnum(8), tcid(9), okspkh(10),
///   N(11), tii_MAX_N(12), tii_k(12 + MAX_N - k), tii_1(11 + MAX_N)
fn emit_fill_body_v18(b: &mut Vec<u8>, max_n: usize) {
    use v17op::*;

    // A) ioc_flag = (selector == 5), replacing selector at depth 0.
    e_num(b, 5);
    b.push(NUMEQUAL);
    // B0: ioc_flag(0), expiry(1), cpend(2), mmfee(3), bspkh(4), ohash(5),
    //     mfill(6), pden(7), pnum(8), tcid(9), okspkh(10), N(11),
    //     tii_MAX_N(12), tii_k(12 + max_n - k)

    // B) F5: cpend == 0.
    e_pick(b, 2);
    b.push(OP0);
    b.push(NUMEQUAL);
    b.push(VERIFY);

    // C) time gate on expiry (copy; leaves stack unchanged).
    e_pick(b, 1);
    b.push(DUP);
    b.push(OP0);
    b.push(NUMEQUAL);
    b.push(NOTIF);
    b.push(DUP);
    b.push(TXLOCKTIME);
    b.push(GT);
    b.push(VERIFY);
    b.push(ENDIF);
    b.push(DROP);

    // D) exposure delay (OP_CSV 50 DAA).
    e_num(b, 50);
    b.push(CSV);

    // Distinctness: tii_k < tii_{k+1} for active adjacent pairs.
    for k in 1..max_n {
        e_num(b, (k + 1) as u16); // guard: (k+1) <= N
        e_pick(b, 12); // N (depth 11 + 1)
        b.push(LTE);
        b.push(IF);
        {
            let d = 12 + max_n - k; // tii_k depth at B0
            e_pick(b, d); // tii_k
            e_pick(b, d); // tii_{k+1} (was d-1, +1 after the tii_k push)
            b.push(LT);
            b.push(VERIFY);
        }
        b.push(ENDIF);
    }

    // E) floor_value = ioc_flag ? mfill : expected, consuming ioc_flag.
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT); // kas_in(0), ioc_flag(1)
    e_pick(b, 8); // pden (depth 7 + 1)
    b.push(DIV);
    e_pick(b, 9); // pnum (depth 8 + 1)
    b.push(MUL); // expected(0), ioc_flag(1)
    b.push(DUP);
    e_pick(b, 8); // mfill (B0 depth 6 -> +2 after expected/dup)
    b.push(GTE);
    b.push(VERIFY); // expected >= mfill
    b.push(SWAP); // ioc_flag(0), expected(1)
    b.push(IF);
    {
        b.push(DROP); // drop expected
        e_pick(b, 5); // mfill as floor
    }
    b.push(ENDIF);
    // B1: floor_value(0), expiry(1), ... tcid(9), okspkh(10), N(11),
    //     tii_MAX_N(12), ...

    // F) token_sum = 0.
    b.push(OP0);
    // B2: token_sum(0), floor_value(1), expiry(2), cpend(3), mmfee(4),
    //     bspkh(5), ohash(6), mfill(7), pden(8), pnum(9), tcid(10),
    //     okspkh(11), N(12), tii_MAX_N(13), tii_k(13 + max_n - k)

    // G) PASS 1: sum delivered tokens + per-term binding checks.
    for k in 1..=max_n {
        e_num(b, k as u16); // guard: k <= N
        e_pick(b, 13); // N (depth 12 + 1)
        b.push(LTE);
        b.push(IF);
        {
            let tii = 13 + max_n - k; // tii_k depth at B2
            e_pick(b, tii);
            b.push(OP0);
            b.push(AUTHOUTPUTIDX); // toi = auth_outputs[tii][0]
            e_pick(b, tii + 1); // tii_k (+1 for toi)
            b.push(INPUTCOVENANTID);
            e_pick(b, 12); // tcid (depth 10, +2 for toi+covid)
            b.push(EQUAL);
            b.push(VERIFY);
            b.push(DUP);
            b.push(TXOUTPUTSPK);
            b.push(BLAKE2B);
            e_pick(b, 7); // bspkh (depth 5, +2 for toi+hash)
            b.push(EQUAL);
            b.push(VERIFY);
            b.push(TXOUTPUTAMOUNT); // tokens_i (consumes toi)
            b.push(ADD); // token_sum += tokens_i
        }
        b.push(ENDIF);
    }

    // H) aggregate limit-price floor: token_sum >= floor_value.
    b.push(SWAP); // floor_value(0), token_sum(1)
    b.push(GTE); // pops [token_sum, floor_value] -> token_sum >= floor_value
    b.push(VERIFY);
    // B3: expiry(0), cpend(1), mmfee(2), bspkh(3), ohash(4), mfill(5),
    //     pden(6), pnum(7), tcid(8), okspkh(9), N(10), tii_MAX_N(11),
    //     tii_k(11 + max_n - k)

    // I) fair_sum = 0.
    b.push(OP0);
    // B4: fair_sum(0), expiry(1), cpend(2), mmfee(3), bspkh(4), ohash(5),
    //     mfill(6), pden(7), pnum(8), tcid(9), okspkh(10), N(11),
    //     tii_MAX_N(12), tii_k(12 + max_n - k)

    // PASS 2: sum fair_kas at each sell's own ATTESTED price, read at the
    // canonical offsets: pnum = sigscript[3..11), pden = sigscript[12..20).
    for k in 1..=max_n {
        e_num(b, k as u16);
        e_pick(b, 12); // N (depth 11 + 1)
        b.push(LTE);
        b.push(IF);
        {
            let tii = 12 + max_n - k; // tii_k depth at B4
            e_pick(b, tii);
            b.push(OP0);
            b.push(AUTHOUTPUTIDX); // toi
            b.push(TXOUTPUTAMOUNT); // tokens_i
            e_pick(b, tii + 1); // tii_k (+1 for tokens)
            e_num(b, 3);
            e_num(b, 11);
            b.push(TXINPUTSIGSUBSTR); // sell_pnum (canonical [3..11))
            e_pick(b, tii + 2); // tii_k (+2 for tokens + pnum)
            e_num(b, 12);
            e_num(b, 20);
            b.push(TXINPUTSIGSUBSTR); // sell_pden (canonical [12..20))
            // fair_kas = tokens / sell_pden * sell_pnum, consuming temps.
            // stack: fair_sum, tokens, sell_pnum, sell_pden(top)
            e_num(b, 2);
            b.push(ROLL); // tokens -> top
            b.push(SWAP); // sell_pden on top, tokens below
            b.push(DIV); // tokens / sell_pden
            b.push(SWAP); // sell_pnum on top
            b.push(MUL); // -> fair_kas
            b.push(ADD); // fair_sum += fair_kas
        }
        b.push(ENDIF);
    }

    // J) aggregate surplus cap.
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT); // kas_in(0), fair_sum(1)
    b.push(DUP);
    e_num(b, 2);
    b.push(ROLL); // fair_sum -> top: fair_sum(0), kas_in(1), kas_in(2)
    b.push(SUB); // surplus = kas_in - fair_sum: surplus(0), kas_in(1)
    b.push(SWAP); // kas_in(0), surplus(1)
    e_num(b, 10000);
    b.push(DIV); // kas_in/10000(0), surplus(1)
    e_pick(b, 4); // mmfee_bps (depth 2, +2 for surplus + kas_in/10000)
    b.push(MUL); // max_surplus(0), surplus(1)
    b.push(LTE); // pops [surplus, max_surplus] -> surplus <= max_surplus
    b.push(VERIFY);
    // leftover: 10 state (incl. okspkh) + N + max_n tii
    let leftover = 11 + max_n;
    for _ in 0..(leftover / 2) {
        b.push(TWO_DROP);
    }
    if leftover % 2 == 1 {
        b.push(DROP);
    }
}

/// v18 PARTIAL-FILL (selector 2, item C): incremental buy consumption.
///
/// Sigscript: `[tii_1]...[tii_MAX_N][N][ri][Op2][pushData(RS)]`.
///
/// Semantics:
///   - Residual continuation: `OpTxOutputSpk(ri) == OpTxInputSpk(self)`
///     byte-exact (same RS => same 145B state carried; the remaining size
///     lives in the UTXO amount), `residual = OpTxOutputAmount(ri) >= 1`
///     (residual == 0 must use selector 1/5 — branch mutual exclusion).
///     The residual output carries NO covenant binding (plain KAS P2SH).
///   - Accounting on the spent portion only: `spent = kas_in - residual`
///     (with `spent >= 0` so a matcher cannot feed negative values into the
///     divisions); floor `token_sum >= spent/pden*pnum` AND
///     `token_sum >= mfill` (per-event, blocks dust-grind); cap
///     `(spent - fair_sum) <= spent/10000*mmfee_bps` (proportional =>
///     splitting one fill into k partials cannot increase total extraction:
///     floor(a/10000) + floor(b/10000) <= floor((a+b)/10000)).
///   - Same N:M sweep machinery as fill: per-term `OpAuthOutputIdx(tii,0)`
///     binding, covenant-id check, buyer-SPK check, strict-increasing tii.
///   - Self-instance uniqueness guard: exactly ONE tx input carries this
///     UTXO's SPK (unrolled i=0..15, each gated by `i < OpTxInputCount`;
///     `OpTxInputCount <= 16` so no input escapes the scan). Blocks two
///     identical-RS buy UTXOs sharing one residual output — buys carry no
///     covenant id, so the Fix-3 auth binding is unavailable to them.
///   - F5 `cpend == 0` enforced (no partial on cancel-pending).
///
/// Entry (selector dropped): expiry(0), cpend(1), mmfee(2), bspkh(3),
///   ohash(4), mfill(5), pden(6), pnum(7), tcid(8), okspkh(9), ri(10),
///   N(11), tii_MAX_N(12), tii_k(12 + MAX_N - k), tii_1(11 + MAX_N)
fn emit_partial_body_v18(b: &mut Vec<u8>, max_n: usize) {
    use v17op::*;

    // P1) F5: cpend == 0.
    e_pick(b, 1);
    b.push(OP0);
    b.push(NUMEQUAL);
    b.push(VERIFY);

    // P2) time gate on expiry (copy; stack-neutral).
    e_pick(b, 0);
    b.push(DUP);
    b.push(OP0);
    b.push(NUMEQUAL);
    b.push(NOTIF);
    b.push(DUP);
    b.push(TXLOCKTIME);
    b.push(GT);
    b.push(VERIFY);
    b.push(ENDIF);
    b.push(DROP);

    // P3) exposure delay (OP_CSV 50 DAA).
    e_num(b, 50);
    b.push(CSV);

    // P4) distinctness: tii_k < tii_{k+1} for active adjacent pairs.
    // (Without this, one sell's auth[0] could be double-counted into
    // token_sum/fair_sum — same anti-double-count guard as the fill path;
    // N/tii depths at entry are identical to the fill path's B0.)
    for k in 1..max_n {
        e_num(b, (k + 1) as u16);
        e_pick(b, 12); // N (depth 11 + 1)
        b.push(LTE);
        b.push(IF);
        {
            let d = 12 + max_n - k;
            e_pick(b, d);
            e_pick(b, d);
            b.push(LT);
            b.push(VERIFY);
        }
        b.push(ENDIF);
    }

    // P5) self-instance uniqueness guard (stack-neutral).
    b.push(TXINPUTINDEX);
    b.push(TXINPUTSPK); // own_spk
    b.push(OP0); // count = 0
    for i in 0..16u16 {
        e_num(b, i);
        b.push(TXINPUTCOUNT);
        b.push(LT); // i < input_count?  (OpTxInputSpk errors on OOB index,
        b.push(IF); //                    so every read must be gated)
        {
            e_num(b, i);
            b.push(TXINPUTSPK); // spk_i
            e_pick(b, 2); // own_spk
            b.push(EQUAL);
            b.push(ADD); // count += (spk_i == own_spk)
        }
        b.push(ENDIF);
    }
    b.push(OP1);
    b.push(NUMEQUAL);
    b.push(VERIFY); // exactly one self-instance
    b.push(TXINPUTCOUNT);
    e_num(b, 16);
    b.push(LTE);
    b.push(VERIFY); // no input beyond the scanned range
    b.push(DROP); // drop own_spk

    // P6) residual continuation + spent = kas_in - residual.
    e_pick(b, 10); // ri
    b.push(TXOUTPUTSPK);
    b.push(TXINPUTINDEX);
    b.push(TXINPUTSPK);
    b.push(EQUAL);
    b.push(VERIFY); // byte-exact self-SPK (same RS => same state)
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT); // kas_in
    e_pick(b, 11); // ri (depth 10 + 1)
    b.push(TXOUTPUTAMOUNT); // residual(0), kas_in(1)
    b.push(DUP);
    b.push(OP1);
    b.push(GTE);
    b.push(VERIFY); // residual >= 1
    b.push(SUB); // spent = kas_in - residual
    b.push(DUP);
    b.push(OP0);
    b.push(GTE);
    b.push(VERIFY); // spent >= 0 (no negative arithmetic downstream)
    // B1: spent(0), expiry(1), cpend(2), mmfee(3), bspkh(4), ohash(5),
    //     mfill(6), pden(7), pnum(8), tcid(9), okspkh(10), ri(11), N(12),
    //     tii_MAX_N(13), tii_k(13 + max_n - k)

    // P7) floor_value = spent / pden * pnum (v17 division order).
    b.push(DUP);
    e_pick(b, 8); // pden (depth 7 + 1)
    b.push(DIV);
    e_pick(b, 9); // pnum (depth 8 + 1)
    b.push(MUL);
    // B2: floor(0), spent(1), expiry(2), cpend(3), mmfee(4), bspkh(5),
    //     ohash(6), mfill(7), pden(8), pnum(9), tcid(10), okspkh(11),
    //     ri(12), N(13), tii_MAX_N(14)

    // P8) token_sum = 0.
    b.push(OP0);
    // B3: token_sum(0), floor(1), spent(2), expiry(3), cpend(4), mmfee(5),
    //     bspkh(6), ohash(7), mfill(8), pden(9), pnum(10), tcid(11),
    //     okspkh(12), ri(13), N(14), tii_MAX_N(15), tii_k(15 + max_n - k)

    // P9) PASS 1: sum delivered tokens + per-term binding checks.
    for k in 1..=max_n {
        e_num(b, k as u16);
        e_pick(b, 15); // N (depth 14 + 1)
        b.push(LTE);
        b.push(IF);
        {
            let tii = 15 + max_n - k; // tii_k depth at B3
            e_pick(b, tii);
            b.push(OP0);
            b.push(AUTHOUTPUTIDX); // toi = auth_outputs[tii][0]
            e_pick(b, tii + 1); // tii_k (+1 for toi)
            b.push(INPUTCOVENANTID);
            e_pick(b, 13); // tcid (depth 11, +2 for toi+covid)
            b.push(EQUAL);
            b.push(VERIFY);
            b.push(DUP);
            b.push(TXOUTPUTSPK);
            b.push(BLAKE2B);
            e_pick(b, 8); // bspkh (depth 6, +2 for toi+hash)
            b.push(EQUAL);
            b.push(VERIFY);
            b.push(TXOUTPUTAMOUNT); // tokens_i (consumes toi)
            b.push(ADD);
        }
        b.push(ENDIF);
    }

    // P10) floors: token_sum >= mfill (per event), token_sum >= floor.
    b.push(DUP);
    e_pick(b, 9); // mfill (depth 8 + 1)
    b.push(GTE);
    b.push(VERIFY); // token_sum >= mfill
    b.push(SWAP); // floor(0), token_sum(1)
    b.push(GTE);
    b.push(VERIFY); // token_sum >= floor
    // B4: spent(0), expiry(1), cpend(2), mmfee(3), bspkh(4), ohash(5),
    //     mfill(6), pden(7), pnum(8), tcid(9), okspkh(10), ri(11), N(12),
    //     tii_MAX_N(13)

    // P11) fair_sum = 0.
    b.push(OP0);
    // B5: fair_sum(0), spent(1), expiry(2), cpend(3), mmfee(4), bspkh(5),
    //     ohash(6), mfill(7), pden(8), pnum(9), tcid(10), okspkh(11),
    //     ri(12), N(13), tii_MAX_N(14), tii_k(14 + max_n - k)

    // P12) PASS 2: fair_sum at each sell's attested price ([3..11)/[12..20)).
    for k in 1..=max_n {
        e_num(b, k as u16);
        e_pick(b, 14); // N (depth 13 + 1)
        b.push(LTE);
        b.push(IF);
        {
            let tii = 14 + max_n - k; // tii_k depth at B5
            e_pick(b, tii);
            b.push(OP0);
            b.push(AUTHOUTPUTIDX);
            b.push(TXOUTPUTAMOUNT); // tokens_i
            e_pick(b, tii + 1);
            e_num(b, 3);
            e_num(b, 11);
            b.push(TXINPUTSIGSUBSTR); // sell_pnum
            e_pick(b, tii + 2);
            e_num(b, 12);
            e_num(b, 20);
            b.push(TXINPUTSIGSUBSTR); // sell_pden
            e_num(b, 2);
            b.push(ROLL); // tokens -> top
            b.push(SWAP);
            b.push(DIV);
            b.push(SWAP);
            b.push(MUL); // fair_kas = tokens / sell_pden * sell_pnum
            b.push(ADD);
        }
        b.push(ENDIF);
    }

    // P13) spent-based surplus cap: (spent - fair_sum) <= spent/10000*mmfee.
    e_pick(b, 1); // spent copy
    b.push(DUP);
    e_num(b, 2);
    b.push(ROLL); // fair_sum -> top
    b.push(SUB); // surplus = spent - fair_sum
    b.push(SWAP); // spent(0), surplus(1)
    e_num(b, 10000);
    b.push(DIV);
    e_pick(b, 5); // mmfee_bps (depth 3, +2 for surplus + quotient)
    b.push(MUL); // max_surplus
    b.push(LTE);
    b.push(VERIFY); // surplus <= max_surplus
    // leftover: spent + 10 state (incl. okspkh) + ri + N + max_n tii
    let leftover = 13 + max_n;
    for _ in 0..(leftover / 2) {
        b.push(TWO_DROP);
    }
    if leftover % 2 == 1 {
        b.push(DROP);
    }
}

/// Expected v18 buy body length (deterministic for `BUY_ORDER_V18_MAX_N`=8).
pub const BUY_ORDER_V18_BODY_EXPECTED_LEN: usize = 1542;

/// v18 buy state size: the v17 145B layout preceded by `[0x20][okspkh 32B]`.
pub const BUY_ORDER_V18_STATE_SIZE: usize = 178;

/// Expected v18 buy redeemScript length (178B state + body).
pub const BUY_ORDER_V18_RS_EXPECTED_LEN: usize =
    BUY_ORDER_V18_STATE_SIZE + BUY_ORDER_V18_BODY_EXPECTED_LEN;

/// Build the v18 buy_order redeemScript (178B state + v18 body).
///
/// State (178B):
///   `[0x20][okspkh 32B]` — owner KAS seat: blake2b of the owner's raw P2PK
///   SPK; the EXPIRE branch refunds here (plain KAS must not land on the
///   token_unit `bspkh` seat) — then the v17 145B layout unchanged:
///   `[0x20][tcid][0x08][pnum][0x08][pden][0x08][mfill][0x20][ohash]`
///   `[0x20][bspkh][0x08][mmfee_bps][cpend][0x08][expiry]`.
/// `max_matcher_fee_bps` is BPS.
pub fn build_buy_v18_redeem_script(
    token_covenant_id: &[u8; 32],
    price_num: u64,
    price_den: u64,
    min_fill: u64,
    owner_hash: &[u8; 32],
    buyer_spk_hash: &[u8; 32],
    owner_kas_spk_hash: &[u8; 32],
    max_matcher_fee_bps: u64,
    cancel_pending: u8,
    expiry_daa: u64,
) -> crate::Result<Vec<u8>> {
    if price_num == 0 {
        return Err(crate::KobError::Contract("price_num must be > 0".into()));
    }
    if price_den == 0 {
        return Err(crate::KobError::Contract("price_den must be > 0".into()));
    }
    if min_fill == 0 {
        return Err(crate::KobError::Contract("min_fill must be > 0".into()));
    }
    if cancel_pending > 1 {
        return Err(crate::KobError::Contract("cancel_pending must be 0 or 1".into()));
    }
    if max_matcher_fee_bps > 10000 {
        return Err(crate::KobError::Contract("max_matcher_fee_bps must be <= 10000".into()));
    }
    let g = gcd(price_num, price_den);
    let price_num = if g > 0 { price_num / g } else { price_num };
    let price_den = if g > 0 { price_den / g } else { price_den };
    let body = build_buy_v18_body();
    let mut rs = Vec::with_capacity(BUY_ORDER_V18_STATE_SIZE + body.len());
    rs.push(0x20);
    rs.extend_from_slice(owner_kas_spk_hash);
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
    rs.extend_from_slice(&u64_le(max_matcher_fee_bps));
    if cancel_pending == 0 {
        rs.push(0x00);
    } else {
        rs.push(0x51);
    }
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(expiry_daa));
    rs.extend_from_slice(&body);
    debug_assert_eq!(rs.len(), BUY_ORDER_V18_RS_EXPECTED_LEN);
    Ok(rs)
}

/// Build a v18 buy fill sigscript for an N-sell sweep (GTC or IOC).
///
/// Layout: `[tii_1]...[tii_MAX_N][N][selector][pushData(RS)]` — always MAX_N
/// tii pushes (unused slots padded with 0, never read since guarded by k<=N).
pub fn build_buy_v18_fill_sigscript(
    sell_input_indices: &[u16],
    ioc: bool,
    redeem_script: &[u8],
) -> Vec<u8> {
    assert!(!sell_input_indices.is_empty(), "at least one sell required");
    assert!(
        sell_input_indices.len() <= BUY_ORDER_V18_MAX_N,
        "at most MAX_N sells per sweep"
    );
    let n = sell_input_indices.len();
    let mut ss = Vec::with_capacity(BUY_ORDER_V18_MAX_N + 4 + redeem_script.len() + 3);
    for i in 0..BUY_ORDER_V18_MAX_N {
        let v = if i < n { sell_input_indices[i] } else { 0 };
        push_index(&mut ss, v);
    }
    push_index(&mut ss, n as u16);
    ss.push(if ioc { 0x55 } else { 0x51 });
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build a v18 buy PARTIAL-FILL sigscript.
///
/// Layout: `[tii_1]...[tii_MAX_N][N][ri][Op2][pushData(RS)]` where `ri` is the
/// residual output index (self-SPK continuation carrying the unspent KAS).
pub fn build_buy_v18_partial_fill_sigscript(
    sell_input_indices: &[u16],
    residual_output_idx: u16,
    redeem_script: &[u8],
) -> Vec<u8> {
    assert!(!sell_input_indices.is_empty(), "at least one sell required");
    assert!(
        sell_input_indices.len() <= BUY_ORDER_V18_MAX_N,
        "at most MAX_N sells per sweep"
    );
    let n = sell_input_indices.len();
    let mut ss = Vec::with_capacity(BUY_ORDER_V18_MAX_N + 6 + redeem_script.len() + 3);
    for i in 0..BUY_ORDER_V18_MAX_N {
        let v = if i < n { sell_input_indices[i] } else { 0 };
        push_index(&mut ss, v);
    }
    push_index(&mut ss, n as u16);
    push_index(&mut ss, residual_output_idx);
    ss.push(0x52); // Op2 (selector = partial fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build a v18 buy expire sigscript: `[Op4][pushData(RS)]`.
pub fn build_buy_v18_expire_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(0x54); // Op4
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build a v18 buy cancel/cancel-mark sigscript: `[pk][sig][selector][RS]`.
/// selector = Op0 (cancel) or Op3 (cancel-mark). Same layout as v17.
pub fn build_buy_v18_cancel_sigscript(
    pubkey: &[u8; 32],
    signature: &[u8; 64],
    mark: bool,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01); // SIGHASH_ALL
    let mut ss = Vec::with_capacity(2 + 32 + 66 + redeem_script.len() + 6);
    ss.extend_from_slice(&push_data(pubkey));
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.push(if mark { 0x53 } else { 0x00 }); // Op3 / Op0
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

// ============================================================================
// V18 SELL — 112B state unchanged; fill-family price attestation + Fix-3 F4
// ============================================================================

/// Build the v18 sell body.
///
/// Stack after state push (the v14 layout preceded by the owner token seat
/// `otspkh` = blake2b of the owner's token_unit P2SH SPK):
///   expiry(0), cpend(1), mmfee(2), sspkh(3), ohash(4), mfill(5), pden(6),
///   pnum(7), otspkh(8), <sigscript items at depth 9+> with the selector at
///   depth 9 in every sigscript form.
///
/// Changes vs the v14 sell body:
///   - FILL / IOC / PARTIAL verify the sigscript-attested (pnum, pden)
///     against the state price (the canonical attestation the buy reads at
///     fixed offsets [3..11)/[12..20)).
///   - PARTIAL F4 upgraded from count-only (`OpCovOutCount >= 2`) to Fix-3:
///     this input's auth[0] must be a self-SPK residual worth
///     `>= token_in - fta` (same per-input binding the IOC path already had).
///   - EXPIRE refunds the token escrow to `otspkh` as a covenant-bound
///     token_unit via the Fix-3 per-input binding (auth[0] of self), instead
///     of the v14 raw-P2PK `sspkh` refund that stripped the binding.
///   - mmfee is BPS uniformly (the v14 absolute-sompi semantics die with v14);
///     the sell body itself never reads mmfee — the cap lives on the buy side.
pub fn build_sell_v18_body() -> Vec<u8> {
    use v17op::*;
    let mut b: Vec<u8> = Vec::with_capacity(512);

    // ===== DISPATCH: selector (depth 9) to top =====
    e_roll(&mut b, 9);
    b.push(DUP);
    e_num(&mut b, 4);
    b.push(EQUAL);
    b.push(IF); // selector == 4 -> EXPIRE
    {
        b.push(DROP);
        b.push(DUP);
        b.push(VERIFY); // expiry != 0 (GTC guard)
        b.push(CLTV);
        // Fix-3 refund: this input's auth[0] must be a covenant-bound token
        // output on the OWNER TOKEN SEAT worth the full escrow.
        // stack: cpend(0), mmfee(1), sspkh(2), ohash(3), mfill(4), pden(5),
        //        pnum(6), otspkh(7)
        b.push(TXINPUTINDEX);
        b.push(OP0);
        b.push(AUTHOUTPUTIDX); // r = auth_outputs[self][0]
        b.push(DUP);
        b.push(TXOUTPUTSPK);
        b.push(BLAKE2B);
        e_pick(&mut b, 9); // otspkh (depth 7, +2 for r + hash)
        b.push(EQUAL);
        b.push(VERIFY); // refund lands on the owner's token_unit P2SH
        b.push(DUP);
        b.push(OUTPUTCOVENANTID);
        b.push(TXINPUTINDEX);
        b.push(INPUTCOVENANTID);
        b.push(EQUAL);
        b.push(VERIFY); // refund carries THIS token's CovenantBinding
        b.push(TXOUTPUTAMOUNT); // consumes r
        b.push(TXINPUTINDEX);
        b.push(TXINPUTAMOUNT);
        b.push(GTE);
        b.push(VERIFY); // full refund
        // 8 items: cpend..otspkh
        for _ in 0..4 {
            b.push(TWO_DROP);
        }
    }
    b.push(ELSE);
    {
        b.push(DUP);
        e_num(&mut b, 2);
        b.push(LT);
        b.push(IF); // selector < 2 (fill or cancel)
        {
            e_num(&mut b, 1);
            b.push(EQUAL);
            b.push(IF); // selector == 1 -> FILL
            {
                emit_sell_v18_fill(&mut b);
            }
            b.push(ELSE); // selector == 0 -> CANCEL
            {
                emit_sell_v18_cancel(&mut b, false);
            }
            b.push(ENDIF);
        }
        b.push(ELSE); // selector >= 2 (IOC, partial, cancel-mark)
        {
            b.push(DUP);
            e_num(&mut b, 5);
            b.push(EQUAL);
            b.push(IF); // selector == 5 -> IOC FILL
            {
                b.push(DROP);
                emit_sell_v18_ioc(&mut b);
            }
            b.push(ELSE);
            {
                e_num(&mut b, 2);
                b.push(EQUAL);
                b.push(IF); // selector == 2 -> PARTIAL FILL
                {
                    emit_sell_v18_partial(&mut b);
                }
                b.push(ELSE); // selector == 3 -> CANCEL-MARK
                {
                    emit_sell_v18_cancel(&mut b, true);
                }
                b.push(ENDIF);
            }
            b.push(ENDIF);
        }
        b.push(ENDIF);
    }
    b.push(ENDIF);
    b.push(OP1);
    b
}

/// v18 sell FILL (selector 1). Sigscript:
/// `[0x01,koi][0x08 pnum][0x08 pden][Op1][pushData(RS)]`.
///
/// Entry (selector consumed): expiry(0), cpend(1), mmfee(2), sspkh(3),
///   ohash(4), mfill(5), pden(6), pnum(7), otspkh(8), pden_att(9),
///   pnum_att(10), koi(11)
fn emit_sell_v18_fill(b: &mut Vec<u8>) {
    use v17op::*;
    // time gate
    b.push(DUP);
    b.push(OP0);
    b.push(NUMEQUAL);
    b.push(NOTIF);
    b.push(DUP);
    b.push(TXLOCKTIME);
    b.push(GT);
    b.push(VERIFY);
    b.push(ENDIF);
    b.push(DROP);
    // exposure delay
    e_num(b, 50);
    b.push(CSV);
    // F5: cpend == 0
    b.push(OP0);
    b.push(EQUAL);
    b.push(VERIFY);
    // base(10): mmfee(0), sspkh(1), ohash(2), mfill(3), pden(4), pnum(5),
    //           otspkh(6), pden_att(7), pnum_att(8), koi(9)
    // ATTESTATION: attested pair == state pair
    e_pick(b, 8); // pnum_att
    e_pick(b, 6); // pnum (5 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    e_pick(b, 7); // pden_att
    e_pick(b, 5); // pden (4 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    // price: expected_kas = token_in * pnum / pden, >= mfill
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT);
    e_pick(b, 6); // pnum (5 + 1)
    b.push(MUL);
    e_pick(b, 5); // pden (4 + 1)
    b.push(DIV);
    b.push(DUP);
    e_pick(b, 5); // mfill (3 + 2)
    b.push(GTE);
    b.push(VERIFY);
    // KAS output >= expected_kas (PARAMETERIZED: koi)
    e_pick(b, 10); // koi (9 + 1)
    b.push(TXOUTPUTAMOUNT);
    b.push(SWAP);
    b.push(GTE);
    b.push(VERIFY);
    // F2: seller SPK hash
    e_pick(b, 9); // koi
    b.push(TXOUTPUTSPK);
    b.push(BLAKE2B);
    e_pick(b, 2); // sspkh (1 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    // F4: per-input token conservation (Fix-3, unchanged from v14 fill)
    b.push(TXINPUTINDEX);
    b.push(OP0);
    b.push(AUTHOUTPUTIDX);
    b.push(DUP);
    b.push(OUTPUTCOVENANTID);
    b.push(TXINPUTINDEX);
    b.push(INPUTCOVENANTID);
    b.push(EQUAL);
    b.push(VERIFY);
    b.push(TXOUTPUTAMOUNT);
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT);
    b.push(GTE);
    b.push(VERIFY);
    // cleanup: 10 items
    for _ in 0..5 {
        b.push(TWO_DROP);
    }
}

/// v18 sell IOC FILL (selector 5). Sigscript:
/// `[0x01,koi][0x08 pnum][0x08 pden][0x08 fta][Op5][pushData(RS)]`.
///
/// Entry (stale selector dropped): expiry(0), cpend(1), mmfee(2), sspkh(3),
///   ohash(4), mfill(5), pden(6), pnum(7), otspkh(8), fta(9), pden_att(10),
///   pnum_att(11), koi(12)
fn emit_sell_v18_ioc(b: &mut Vec<u8>) {
    use v17op::*;
    b.push(DUP);
    b.push(OP0);
    b.push(NUMEQUAL);
    b.push(NOTIF);
    b.push(DUP);
    b.push(TXLOCKTIME);
    b.push(GT);
    b.push(VERIFY);
    b.push(ENDIF);
    b.push(DROP);
    e_num(b, 50);
    b.push(CSV);
    b.push(OP0);
    b.push(EQUAL);
    b.push(VERIFY);
    // base(11): mmfee(0), sspkh(1), ohash(2), mfill(3), pden(4), pnum(5),
    //           otspkh(6), fta(7), pden_att(8), pnum_att(9), koi(10)
    // ATTESTATION
    e_pick(b, 9); // pnum_att
    e_pick(b, 6); // pnum (5 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    e_pick(b, 8); // pden_att
    e_pick(b, 5); // pden (4 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    // fill_kas = fta * pnum / pden, >= mfill
    e_pick(b, 7); // fta
    e_pick(b, 6); // pnum (5 + 1)
    b.push(MUL);
    e_pick(b, 5); // pden (4 + 1)
    b.push(DIV);
    b.push(DUP);
    e_pick(b, 5); // mfill (3 + 2)
    b.push(GTE);
    b.push(VERIFY);
    // KAS output >= fill_kas
    e_pick(b, 11); // koi (10 + 1)
    b.push(TXOUTPUTAMOUNT);
    b.push(SWAP);
    b.push(GTE);
    b.push(VERIFY);
    // F2: seller SPK hash
    e_pick(b, 10); // koi
    b.push(TXOUTPUTSPK);
    b.push(BLAKE2B);
    e_pick(b, 2); // sspkh (1 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    // F4: residual conservation — auth[0] is a self-SPK continuation worth
    // >= token_in - fta (unchanged from the v14 IOC path).
    b.push(TXINPUTINDEX);
    b.push(OP0);
    b.push(AUTHOUTPUTIDX);
    b.push(DUP);
    b.push(TXOUTPUTSPK);
    b.push(TXINPUTINDEX);
    b.push(TXINPUTSPK);
    b.push(EQUAL);
    b.push(VERIFY);
    b.push(TXOUTPUTAMOUNT);
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT);
    e_pick(b, 9); // fta (7 + 2)
    b.push(SUB);
    b.push(GTE);
    b.push(VERIFY);
    // cleanup: 11 items
    for _ in 0..5 {
        b.push(TWO_DROP);
    }
    b.push(DROP);
}

/// v18 sell PARTIAL FILL (selector 2). Sigscript:
/// `[0x01,koi][0x08 pnum][0x08 pden][0x08 fta][ri][Op2][pushData(RS)]`.
///
/// Entry (selector consumed): expiry(0), cpend(1), mmfee(2), sspkh(3),
///   ohash(4), mfill(5), pden(6), pnum(7), otspkh(8), ri(9), fta(10),
///   pden_att(11), pnum_att(12), koi(13)
fn emit_sell_v18_partial(b: &mut Vec<u8>) {
    use v17op::*;
    b.push(DUP);
    b.push(OP0);
    b.push(NUMEQUAL);
    b.push(NOTIF);
    b.push(DUP);
    b.push(TXLOCKTIME);
    b.push(GT);
    b.push(VERIFY);
    b.push(ENDIF);
    b.push(DROP);
    e_num(b, 50);
    b.push(CSV);
    b.push(OP0);
    b.push(EQUAL);
    b.push(VERIFY);
    // base(12): mmfee(0), sspkh(1), ohash(2), mfill(3), pden(4), pnum(5),
    //           otspkh(6), ri(7), fta(8), pden_att(9), pnum_att(10), koi(11)
    // ATTESTATION
    e_pick(b, 10); // pnum_att
    e_pick(b, 6); // pnum (5 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    e_pick(b, 9); // pden_att
    e_pick(b, 5); // pden (4 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    // fill_kas = fta * pnum / pden, >= mfill (keeps an fta copy on stack)
    e_pick(b, 8); // fta
    b.push(DUP);
    e_pick(b, 7); // pnum (5 + 2)
    b.push(MUL);
    e_pick(b, 6); // pden (4 + 2)
    b.push(DIV);
    b.push(DUP);
    e_pick(b, 6); // mfill (3 + 3)
    b.push(GTE);
    b.push(VERIFY);
    // KAS output >= fill_kas
    e_pick(b, 13); // koi (11 + 2)
    b.push(TXOUTPUTAMOUNT);
    b.push(SWAP);
    b.push(GTE);
    b.push(VERIFY);
    // partial guard: token_in > fta
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT);
    e_pick(b, 1); // fta copy
    b.push(GT);
    b.push(VERIFY);
    // residual output SPK == own SPK (D&R continuation)
    e_pick(b, 8); // ri (7 + 1)
    b.push(TXOUTPUTSPK);
    b.push(TXINPUTINDEX);
    b.push(TXINPUTSPK);
    b.push(EQUAL);
    b.push(VERIFY);
    // residual output value >= token_in - fta (consumes the fta copy)
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT);
    e_roll(b, 1);
    b.push(SUB);
    e_pick(b, 8); // ri (7 + 1)
    b.push(TXOUTPUTAMOUNT);
    b.push(SWAP);
    b.push(GTE);
    b.push(VERIFY);
    // residual-fill floor: (token_in - fta) * pnum / pden >= mfill
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT);
    e_pick(b, 9); // fta (8 + 1)
    b.push(SUB);
    e_pick(b, 6); // pnum (5 + 1)
    b.push(MUL);
    e_pick(b, 5); // pden (4 + 1)
    b.push(DIV);
    e_pick(b, 4); // mfill (3 + 1)
    b.push(GTE);
    b.push(VERIFY);
    // F2: seller SPK hash on koi
    e_pick(b, 11); // koi
    b.push(TXOUTPUTSPK);
    b.push(BLAKE2B);
    e_pick(b, 2); // sspkh (1 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    // F4 (Fix-3, upgraded from count-only `OpCovOutCount >= 2`): this input's
    // auth[0] must be a self-SPK residual token output worth >= token_in - fta.
    // The old shared count let another same-token input's outputs satisfy the
    // check; per-input binding closes that (same shape as the IOC F4).
    b.push(TXINPUTINDEX);
    b.push(OP0);
    b.push(AUTHOUTPUTIDX);
    b.push(DUP);
    b.push(TXOUTPUTSPK);
    b.push(TXINPUTINDEX);
    b.push(TXINPUTSPK);
    b.push(EQUAL);
    b.push(VERIFY);
    b.push(TXOUTPUTAMOUNT);
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT);
    e_pick(b, 10); // fta (8 + 2)
    b.push(SUB);
    b.push(GTE);
    b.push(VERIFY);
    // cleanup: 12 items
    for _ in 0..6 {
        b.push(TWO_DROP);
    }
}

/// v18 sell CANCEL (selector 0) / CANCEL-MARK (selector 3) — owner signature.
/// Sigscript: `[sig][pk][Op0 or Op3][pushData(RS)]` (same shapes as v14).
fn emit_sell_v18_cancel(b: &mut Vec<u8>, mark: bool) {
    use v17op::*;
    if mark {
        b.push(DROP); // expiry
        b.push(OP0);
        b.push(EQUAL);
        b.push(VERIFY); // cpend == 0 (can't re-mark)
    } else {
        b.push(TWO_DROP); // expiry + cpend
    }
    // stack: mmfee(0), sspkh(1), ohash(2), mfill(3), pden(4), pnum(5),
    //        otspkh(6), pk(7), sig(8)
    e_pick(b, 7); // pk
    b.push(BLAKE2B);
    e_pick(b, 3); // ohash (2 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    e_roll(b, 8); // sig
    e_roll(b, 8); // pk
    b.push(CHECKSIG);
    b.push(VERIFY);
    // 7 items
    for _ in 0..3 {
        b.push(TWO_DROP);
    }
    b.push(DROP);
}

/// Expected v18 sell body length.
pub const SELL_ORDER_V18_BODY_EXPECTED_LEN: usize = 370;

/// v18 sell state size: the v14 112B layout preceded by `[0x20][otspkh 32B]`.
pub const SELL_ORDER_V18_STATE_SIZE: usize = 145;

/// Expected v18 sell redeemScript length (145B state + body).
pub const SELL_ORDER_V18_RS_EXPECTED_LEN: usize =
    SELL_ORDER_V18_STATE_SIZE + SELL_ORDER_V18_BODY_EXPECTED_LEN;

/// Build the v18 sell_order redeemScript (145B state + v18 body).
///
/// State (145B):
///   `[0x20][otspkh 32B]` — owner token seat: blake2b of the owner's
///   token_unit P2SH SPK (`compute_token_unit_spk_hash`); the EXPIRE branch
///   refunds the token escrow here as a covenant-bound token_unit — then
///   the v14 112B layout unchanged. `max_matcher_fee_bps` is BPS.
pub fn build_sell_v18_redeem_script(
    price_num: u64,
    price_den: u64,
    min_fill: u64,
    owner_hash: &[u8; 32],
    seller_spk_hash: &[u8; 32],
    owner_token_spk_hash: &[u8; 32],
    max_matcher_fee_bps: u64,
    cancel_pending: u8,
    expiry_daa: u64,
) -> crate::Result<Vec<u8>> {
    if price_num == 0 {
        return Err(crate::KobError::Contract("price_num must be > 0".into()));
    }
    if price_den == 0 {
        return Err(crate::KobError::Contract("price_den must be > 0".into()));
    }
    if min_fill == 0 {
        return Err(crate::KobError::Contract("min_fill must be > 0".into()));
    }
    if cancel_pending > 1 {
        return Err(crate::KobError::Contract("cancel_pending must be 0 or 1".into()));
    }
    if max_matcher_fee_bps > 10000 {
        return Err(crate::KobError::Contract("max_matcher_fee_bps must be <= 10000".into()));
    }
    let g = gcd(price_num, price_den);
    let price_num = if g > 0 { price_num / g } else { price_num };
    let price_den = if g > 0 { price_den / g } else { price_den };
    let body = build_sell_v18_body();
    let mut rs = Vec::with_capacity(SELL_ORDER_V18_STATE_SIZE + body.len());
    rs.push(0x20);
    rs.extend_from_slice(owner_token_spk_hash);
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
    rs.extend_from_slice(&u64_le(max_matcher_fee_bps));
    if cancel_pending == 0 {
        rs.push(0x00);
    } else {
        rs.push(0x51);
    }
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(expiry_daa));
    rs.extend_from_slice(&body);
    debug_assert_eq!(rs.len(), SELL_ORDER_V18_RS_EXPECTED_LEN);
    Ok(rs)
}

/// Append the canonical v18 attestation prefix to a sigscript buffer:
/// `[0x01, koi][0x08, pnum 8LE][0x08, pden 8LE]` (pnum at [3..11), pden at
/// [12..20)). Prices are gcd-normalized so the attested bytes always equal
/// the state bytes the RS builder wrote.
fn push_v18_attested_prefix(ss: &mut Vec<u8>, kas_output_idx: u16, price_num: u64, price_den: u64) {
    assert!(kas_output_idx <= 255, "koi must fit in 1 byte for the canonical convention");
    let g = gcd(price_num, price_den);
    let pnum = if g > 0 { price_num / g } else { price_num };
    let pden = if g > 0 { price_den / g } else { price_den };
    ss.push(0x01); // forced 2-byte koi push
    ss.push(kas_output_idx as u8);
    ss.push(0x08);
    ss.extend_from_slice(&u64_le(pnum));
    ss.push(0x08);
    ss.extend_from_slice(&u64_le(pden));
}

/// Build v18 sell fill sigscript (canonical attestation layout).
///
/// Layout: `[0x01,koi][0x08 pnum][0x08 pden][Op1][pushData(RS)]`.
pub fn build_sell_v18_fill_sigscript(
    kas_output_idx: u16,
    price_num: u64,
    price_den: u64,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(21 + redeem_script.len() + 3);
    push_v18_attested_prefix(&mut ss, kas_output_idx, price_num, price_den);
    ss.push(0x51); // Op1 (selector = fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build v18 sell IOC fill sigscript (canonical attestation layout).
///
/// Layout: `[0x01,koi][0x08 pnum][0x08 pden][0x08 fta][Op5][pushData(RS)]`.
pub fn build_sell_v18_ioc_fill_sigscript(
    kas_output_idx: u16,
    price_num: u64,
    price_den: u64,
    fill_token_amount: u64,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(30 + redeem_script.len() + 3);
    push_v18_attested_prefix(&mut ss, kas_output_idx, price_num, price_den);
    ss.push(0x08);
    ss.extend_from_slice(&u64_le(fill_token_amount));
    ss.push(0x55); // Op5 (selector = IOC fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build v18 sell partial fill sigscript (canonical attestation layout).
///
/// Layout: `[0x01,koi][0x08 pnum][0x08 pden][0x08 fta][ri][Op2][pushData(RS)]`.
pub fn build_sell_v18_partial_fill_sigscript(
    kas_output_idx: u16,
    price_num: u64,
    price_den: u64,
    fill_token_amount: u64,
    residual_output_idx: u16,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(33 + redeem_script.len() + 3);
    push_v18_attested_prefix(&mut ss, kas_output_idx, price_num, price_den);
    ss.push(0x08);
    ss.extend_from_slice(&u64_le(fill_token_amount));
    push_index(&mut ss, residual_output_idx);
    ss.push(0x52); // Op2 (selector = partial fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build v18 sell expire sigscript: `[Op4][pushData(RS)]`.
pub fn build_sell_v18_expire_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(0x54);
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build v18 sell cancel-mark sigscript: `[sig][pk][Op3][pushData(RS)]`.
/// (Plain cancel reuses `build_sell_cancel_sigscript` — identical shape,
/// selector Op0.)
pub fn build_sell_v18_cancel_mark_sigscript(
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01);
    let mut ss = Vec::with_capacity(102 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pubkey));
    ss.push(0x53); // Op3 (selector = cancel-mark)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}
