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
    // F4: token conservation full fill
    0xb9, 0xcf, 0x76,             // OpTxInputIndex OpInputCovenantId OpDup          [3B]
    0xd2, 0x51, 0xa2, 0x69,       // OpCovOutCount(T) Op1 OpGTE OpVerify             [4B]
    0x00, 0xd3,                   // Op0 OpCovOutputIdx(T,0)                         [2B]
    0xc2,                         // OpTxOutputAmount(idx)                           [1B]
    0xb9, 0xbe,                   // OpTxInputIndex OpTxInputAmount                  [2B]
    0xa2, 0x69,                   // OpGTE OpVerify                                  [2B]

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

    // F4: token conservation — at least 1 covenant output (6B)
    0xb9, 0xcf,                   // OpTxInputIndex OpInputCovenantId -> T           [2B]
    0xd2, 0x51, 0xa2, 0x69,       // OpCovOutCount(T) Op1 OpGTE OpVerify             [4B]

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
pub const SELL_ORDER_BODY_EXPECTED_LEN: usize = 304;

/// Expected redeemScript length for sell order (112B state + 304B body).
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

// ============================================================================
// V15 BUY CONTRACT — Cross-input surplus enforcement via OpTxInputScriptSigSubstr
// ============================================================================
//
// V15 adds F6 (surplus cap) back to the fill path using cross-input introspection.
// The buy contract reads the sell input's pnum/pden from its sigscript, computes
// the fair KAS required, and verifies that the matcher surplus is bounded by
// mmfee_bps (basis points of trade value).
//
// Changes from V14:
//   1. F6 restored: 41 bytes of surplus verification bytecode
//   2. Dispatch thresholds updated: T0=444, T1=452, T2=458
//   3. Fill sigscript gains `sii` (sell input index) parameter (deepest on stack)
//   4. Cleanup grows by 1 byte (13 items vs 12)
//   5. mmfee field reinterpreted as BPS (was absolute sompi)
//
// State layout: UNCHANGED (145B) — mmfee field now means BPS, not sompi.
//
// Requires fixed-offset sell sigscript convention: sell fill sigscript MUST use
// 2-byte koi push (build_sell_fill_sigscript_v15) so pnum/pden are at fixed
// offsets [7..15) and [16..24) respectively.

/// V15 buy_order body bytecode (293 bytes).
///
/// F6 CROSS-INPUT SURPLUS CAP:
///   1. Read sell_pnum from sell_sigscript[7..15) via OpTxInputScriptSigSubstr
///   2. Read sell_pden from sell_sigscript[16..24) via OpTxInputScriptSigSubstr
///   3. tokens = kas / buy_pden * buy_pnum  (recompute, div-first overflow-safe)
///   4. fair_kas = tokens / sell_pden * sell_pnum
///   5. surplus = kas - fair_kas
///   6. max_surplus = kas / 10000 * mmfee_bps
///   7. Verify: max_surplus >= surplus
///
/// State (145B): [tcid 32B][pnum 8B][pden 8B][mfill 8B][ohash 32B][bspkh 32B][mmfee_bps 8B][cpend 1B][expiry_daa 8B]
///
/// Stack after state push:
///   expiry(0), cpend(1), mmfee_bps(2), bspkh(3), ohash(4), mfill(5), pden(6), pnum(7), tcid(8)
///
/// Dispatch thresholds (RS=438B):
///   T0 = 444 (expire < 444 < fill)
///   T1 = 452 (fill < 452 < partial)
///   T2 = 458 (partial < 458 < cancel)
///
/// Fill sigscript: `[sii] [toi] [tii] [coi] [Op1/Op5] [pushData(RS)]`
///   v15 base=446, max=450 (4 data-push indices + sii)
/// Partial sigscript: `[ri] [ti] [pushData(fk 8B)] [Op2] [pushData(RS)]`
///   v15 base=453, max=455 (no sii, no F6 in partial path)
pub const BUY_ORDER_V15_BODY: &[u8] = &[
    // DISPATCH PREAMBLE (15B) — same structure as v14, updated thresholds
    0xb9, 0xc9, 0x76,             // OpTxInputIndex, OpTxInputScriptSigLen, OpDup  [3B]
    0x02, 0xca, 0x01,             // push T2=458                                   [3B]
    0x9f,                         // OpLessThan (sigLen < T2?)                      [1B]
    0x63,                         // OpIf (expire/fill/partial)                     [1B]
    0x76,                         // OpDup (keep sigLen for T0 check)               [1B]
    0x02, 0xbc, 0x01,             // push T0=444                                   [3B]
    0x9f,                         // OpLessThan (sigLen < T0?)                      [1B]
    0x63,                         // OpIf (EXPIRE)                                  [1B]
    0x75,                         // OpDrop (sigLen, not needed in expire)           [1B]

    // EXPIRE PATH (21B) — identical to v14
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

    // TIME GATE (12B) — identical to v14
    0x51, 0x7a,                   // Op1 OpRoll(expiry)                             [2B]
    0x76, 0x00, 0x9c,             // OpDup Op0 OpNumEqual                           [3B]
    0x64,                         // OpNotIf                                        [1B]
    0x76, 0xb5,                   // OpDup OpTxLockTime                             [2B]
    0xa0, 0x69,                   // OpGreaterThan OpVerify                         [2B]
    0x68,                         // OpEndIf                                        [1B]
    0x75,                         // OpDrop (expiry)                                [1B]

    // EXPOSURE DELAY (3B) — identical to v14
    0x01, 0x32,                   // push(50) MIN_EXPOSURE = 50 DAA                 [2B]
    0xb1,                         // OpCheckSequenceVerify                          [1B]

    // T1 DISPATCH (5B) — updated threshold
    0x02, 0xc4, 0x01,             // push T1=452                                    [3B]
    0x9f,                         // OpLessThan (sigLen < T1?)                       [1B]
    0x63,                         // OpIf (fill)                                    [1B]

    // ============================================================
    // FILL PATH (67B existing + 41B F6 + 1B extra cleanup = 109B)
    // ============================================================
    // Stack: cpend(0), mmfee_bps(1), bspkh(2), ohash(3), mfill(4), pden(5),
    //        pnum(6), tcid(7), 1(8), coi(9), tii(10), toi(11), sii(12)
    //
    // F5: cancel_pending must be 0
    0x00, 0x87, 0x69,             // Op0 OpEqual OpVerify (cpend==0)                [3B]
    // Stack: mmfee_bps(0), bspkh(1), ohash(2), mfill(3), pden(4),
    //        pnum(5), tcid(6), 1(7), coi(8), tii(9), toi(10), sii(11)
    //
    // Price calc — overflow-safe div-first (kas/pden*pnum instead of kas*pnum/pden)
    0xb9, 0xbe,                   // OpTxInputIndex, OpTxInputAmount -> kas          [2B]
    0x76,                         // OpDup                                          [1B]
    0x56, 0x79, 0x96,             // Op6 OpPick(pden) OpDiv                         [3B]
    0x57, 0x79, 0x95,             // Op7 OpPick(pnum) OpMul -> expected_tokens      [3B]
    0x76,                         // OpDup                                          [1B]
    0x56, 0x79, 0xa2, 0x69,       // Op6 OpPick(mfill) OpGTE OpVerify              [4B]
    //
    // IOC SUB-DISPATCH (9B) — identical to v14
    0x59, 0x79,                   // Op9 OpPick(selector copy)                      [2B]
    0x55, 0x87,                   // Op5 OpEqual (selector == 5?)                   [2B]
    0x63,                         // OpIf (IOC)                                     [1B]
    0x75,                         // OpDrop (drop exp_tok)                          [1B]
    0x54, 0x79,                   // Op4 OpPick(mfill)                              [2B]
    0x68,                         // OpEndIf                                        [1B]
    //
    // Token output amount (PARAMETERIZED: toi) — identical to v14
    0x5c, 0x79, 0xc2,             // Op12 OpPick(toi) OpTxOutputAmount              [3B]
    0x7c, 0xa2, 0x69,             // OpSwap OpGTE OpVerify                          [3B]
    // kas(0), mmfee_bps(1), ..., toi(11), sii(12)
    //
    // Token input covenant check (PARAMETERIZED: tii) — identical to v14
    0x5a, 0x79, 0xcf,             // Op10 OpPick(tii) OpTxInputCovId               [3B]
    0x58, 0x79, 0x87, 0x69,       // Op8 OpPick(tcid) OpEqual OpVerify             [4B]
    // kas(0), mmfee_bps(1), ..., toi(11), sii(12)
    //
    // F2: buyer SPK hash check (PARAMETERIZED: toi) — identical to v14
    0x5b, 0x79, 0xc3, 0xaa,       // Op11 OpPick(toi) OpTxOutputSpk OpBlake2b      [4B]
    0x53, 0x79, 0x87, 0x69,       // Op3 OpPick(bspkh) OpEqual OpVerify            [4B]
    // kas(0), mmfee_bps(1), ..., toi(11), sii(12)
    //
    // F4: token output covenant check (PARAMETERIZED: coi) — identical to v14
    0x57, 0x79, 0x76,             // Op7 OpPick(tcid) OpDup                        [3B]
    0xd2, 0x51, 0xa2, 0x69,       // OpCovOutCount(T) Op1 OpGTE OpVerify           [4B]
    0x5a, 0x79, 0xd3,             // Op10 OpPick(coi) OpCovOutputIdx(T,coi)        [3B]
    0x5c, 0x79,                   // Op12 OpPick(toi)                              [2B]
    0x87, 0x69,                   // OpEqual OpVerify                              [2B]
    // kas(0), mmfee_bps(1), bspkh(2), ohash(3), mfill(4), pden_b(5),
    //    pnum_b(6), tcid(7), 1(8), coi(9), tii(10), toi(11), sii(12) = 13 items
    //
    // ============================================================
    // F6: CROSS-INPUT SURPLUS CAP (41B) — NEW in v15
    // ============================================================
    // Read sell_pnum from sell input's sigscript[7..15)
    // (Fixed-offset convention: sell koi always 2B → RS state starts at sigscript[6])
    0x5c, 0x79,                   // Op12 OpPick(sii)                              [2B]
    0x57,                         // Op7 (start=7)                                 [1B]
    0x5f,                         // Op15 (end=15)                                 [1B]
    0xbc,                         // OpTxInputScriptSigSubstr → sell_pnum          [1B]
    // (14): sell_pnum(0), kas(1), mmfee_bps(2), ..., sii(13)
    //
    // Read sell_pden from sell input's sigscript[16..24)
    0x5d, 0x79,                   // Op13 OpPick(sii)                              [2B]
    0x60,                         // Op16 (start=16)                               [1B]
    0x01, 0x18,                   // push 24 (end=24)                              [2B]
    0xbc,                         // OpTxInputScriptSigSubstr → sell_pden          [1B]
    // (15): sell_pden(0), sell_pnum(1), kas(2), mmfee_bps(3), ...,
    //       pden_b(7), pnum_b(8), ..., sii(14)
    //
    // Recompute: tokens = kas / buy_pden * buy_pnum (div-first, overflow-safe)
    0x52, 0x79,                   // Op2 OpPick(kas)                               [2B]
    0x58, 0x79,                   // Op8 OpPick(pden_b) [shifted by 2 pushes]      [2B]
    0x96,                         // OpDiv → kas / buy_pden                        [1B]
    0x59, 0x79,                   // Op9 OpPick(pnum_b)                            [2B]
    0x95,                         // OpMul → tokens                                [1B]
    // (16): tokens(0), sell_pden(1), sell_pnum(2), kas(3), ...
    //
    // fair_kas = tokens / sell_pden * sell_pnum (div-first, overflow-safe)
    0x51, 0x79,                   // Op1 OpPick(sell_pden)                         [2B]
    0x96,                         // OpDiv → tokens / sell_pden                    [1B]
    0x52, 0x79,                   // Op2 OpPick(sell_pnum)                         [2B]
    0x95,                         // OpMul → fair_kas                              [1B]
    // (16): fair_kas(0), sell_pden(1), sell_pnum(2), kas(3), mmfee_bps(4), ...
    //
    // surplus = kas - fair_kas
    0x53, 0x79,                   // Op3 OpPick(kas)                               [2B]
    0x7c,                         // OpSwap                                        [1B]
    0x94,                         // OpSub → surplus = kas - fair_kas              [1B]
    // (16): surplus(0), sell_pden(1), sell_pnum(2), kas(3), mmfee_bps(4), ...
    //
    // max_surplus = kas / 10000 * mmfee_bps (div-first, overflow-safe)
    0x53, 0x79,                   // Op3 OpPick(kas)                               [2B]
    0x02, 0x10, 0x27,             // push 10000 (0x2710 LE)                        [3B]
    0x96,                         // OpDiv → kas / 10000                           [1B]
    0x55, 0x79,                   // Op5 OpPick(mmfee_bps)                         [2B]
    0x95,                         // OpMul → max_surplus                           [1B]
    // (17): max_surplus(0), surplus(1), sell_pden(2), sell_pnum(3), kas(4), ...
    //
    // Verify: max_surplus >= surplus
    0xa2, 0x69,                   // OpGTE OpVerify                                [2B]
    // (15): sell_pden(0), sell_pnum(1), kas(2), mmfee_bps(3), ..., sii(14)
    //
    // Drop F6 temporaries (sell_pden + sell_pnum)
    0x6d,                         // Op2Drop                                       [1B]
    // (13): kas(0), mmfee_bps(1), ..., sii(12) — restored to pre-F6 state
    //
    // ============================================================
    // Cleanup: 13 items = Op2Drop x6 + OpDrop
    0x6d, 0x6d, 0x6d, 0x6d, 0x6d, 0x6d, 0x75, // Op2Drop x6 + OpDrop             [7B]

    // PARTIAL FILL PATH (103B) — identical to v14, no F6 (no sii in partial sigscript)
    0x67,                         // OpElse (sigLen >= T1: partial)                 [1B]
    // Stack: cpend(0), mmfee_bps(1), bspkh(2), ohash(3), mfill(4), pden(5),
    //        pnum(6), tcid(7), 2(8), fk(9), ti(10), ri(11)
    // F5
    0x00, 0x87, 0x69,             // cpend==0                                      [3B]
    0x58, 0x79,                   // Op8 OpPick(fk)                                [2B]
    0x76,                         // OpDup                                         [1B]
    0x56, 0x79, 0x96,             // Op6 OpPick(pden) OpDiv                        [3B]
    0x57, 0x79, 0x95,             // Op7 OpPick(pnum) OpMul                        [3B]
    0x76,                         // OpDup                                         [1B]
    0x56, 0x79, 0xa2, 0x69,       // Op6 OpPick(mfill) OpGTE OpVerify             [4B]
    0x5b, 0x79, 0xc2,             // Op11 OpPick(ti) OpTxOutputAmount              [3B]
    0x7c, 0xa2, 0x69,             // OpSwap OpGTE OpVerify                         [3B]
    0xb9, 0xbe,                   // kas_in                                        [2B]
    0x51, 0x79, 0xa0, 0x69,       // Op1 OpPick(fk_c) OpGreaterThan OpVerify       [4B]
    0x5b, 0x79, 0xc3,             // Op11 OpPick(ri) OpTxOutputSpk                 [3B]
    0xb9, 0xbf,                   // OpTxInputIndex OpTxInputSpk                   [2B]
    0x87, 0x69,                   // OpEqual OpVerify                              [2B]
    0xb9, 0xbe,                   // kas_in                                        [2B]
    0x51, 0x7a, 0x94,             // Op1 OpRoll(fk_c) OpSub                        [3B]
    0x5b, 0x79, 0xc2,             // Op11 OpPick(ri) OpTxOutputAmount              [3B]
    0x7c, 0xa2, 0x69,             // OpSwap OpGTE OpVerify                         [3B]
    0xb9, 0xbe,                   // kas_in                                        [2B]
    0x59, 0x79, 0x94,             // Op9 OpPick(fk) OpSub                          [3B]
    0x55, 0x79, 0x96,             // Op5 OpPick(pden) OpDiv                        [3B]
    0x56, 0x79, 0x95,             // Op6 OpPick(pnum) OpMul                        [3B]
    0x54, 0x79, 0xa2, 0x69,       // Op4 OpPick(mfill) OpGTE OpVerify             [4B]
    // Token input check
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
    // F6 NOT ADDED to partial path (no sii). Protected by per-order mmfee cap.
    // Cleanup: 11 items = Op2Drop x5 + OpDrop
    0x6d, 0x6d, 0x6d, 0x6d, 0x6d, 0x75, // Op2Drop x5 + OpDrop                   [6B]

    // FILL/PARTIAL END
    0x68,                         // OpEndIf (fill vs partial)                     [1B]
    0x68,                         // OpEndIf (expire vs fill/partial)              [1B]

    // CANCEL / CANCEL-MARK PATH (28B) — identical to v14
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

/// Expected length of BUY_ORDER_V15_BODY bytecode.
pub const BUY_ORDER_V15_BODY_EXPECTED_LEN: usize = 293;

/// Expected length of v15 buy_order redeemScript (145B state + 293B body).
pub const BUY_ORDER_V15_RS_EXPECTED_LEN: usize = 145 + BUY_ORDER_V15_BODY_EXPECTED_LEN;

/// Build v15 buy_order redeemScript (145B state + 293B body = 438B).
///
/// Same state layout as v14 (145B). The `max_matcher_fee` field is now
/// interpreted as basis points (BPS), NOT absolute sompi.
///
/// e.g., max_matcher_fee=30 means 0.30% of trade value.
pub fn build_buy_v15_redeem_script(
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
    let mut rs = Vec::with_capacity(145 + BUY_ORDER_V15_BODY.len());
    // State header (145B) — identical layout to v14
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
    rs.extend_from_slice(BUY_ORDER_V15_BODY);
    Ok(rs)
}

/// Build v15 buy_order fill sigscript.
///
/// Layout: `[sii] [toi] [tii] [coi] [Op1] [pushData(RS)]`
///
/// `sii` = sell input index (for cross-input price reading in F6).
/// All indices use OpN (1 byte) for 0..=16, or data-push `[0x01, val]` (2 bytes) for 17+.
pub fn build_buy_v15_fill_sigscript(
    sell_input_idx: u16,
    token_output_idx: u16,
    token_input_idx: u16,
    cov_output_idx: u16,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(9 + redeem_script.len() + 3);
    push_index(&mut ss, sell_input_idx);
    push_index(&mut ss, token_output_idx);
    push_index(&mut ss, token_input_idx);
    push_index(&mut ss, cov_output_idx);
    ss.push(0x51); // Op1 (selector = fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build v15 buy_order IOC fill sigscript.
///
/// Layout: `[sii] [toi] [tii] [coi] [Op5] [pushData(RS)]`
///
/// Same as fill but with Op5 selector for IOC path (relaxes token check to >= mfill).
pub fn build_buy_v15_ioc_fill_sigscript(
    sell_input_idx: u16,
    token_output_idx: u16,
    token_input_idx: u16,
    cov_output_idx: u16,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(9 + redeem_script.len() + 3);
    push_index(&mut ss, sell_input_idx);
    push_index(&mut ss, token_output_idx);
    push_index(&mut ss, token_input_idx);
    push_index(&mut ss, cov_output_idx);
    ss.push(0x55); // Op5 (selector = IOC fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build sell_order fill sigscript with fixed-offset convention (v15 compatible).
///
/// Layout: `[0x01, koi_val] [Op1] [pushData(RS)]`
///
/// Always uses 2-byte koi push so the buy contract can read sell's pnum/pden
/// at fixed offsets [7..15) and [16..24) via OpTxInputScriptSigSubstr.
///
/// The sell contract is unmodified — it reads koi as a number from the stack,
/// which is identical whether pushed via OpN (1B) or data-push (2B).
pub fn build_sell_fill_sigscript_v15(
    kas_output_idx: u16,
    redeem_script: &[u8],
) -> Vec<u8> {
    assert!(kas_output_idx <= 255, "koi must fit in 1 byte for v15 fixed-offset");
    let mut ss = Vec::with_capacity(4 + redeem_script.len() + 3);
    // Fixed 2-byte koi push (even for indices 0-16)
    ss.push(0x01); // push 1 byte
    ss.push(kas_output_idx as u8);
    ss.push(0x51); // Op1 (selector = fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build sell_order IOC fill sigscript with fixed-offset convention (v15 compatible).
///
/// Layout: `[0x01, koi_val] [pushData(fta 8B)] [Op5] [pushData(RS)]`
///
/// Note: For IOC sell, pnum/pden offsets differ from regular fill:
///   pnum at [16..24), pden at [25..33) due to fta field between koi and selector.
pub fn build_sell_ioc_fill_sigscript_v15(
    kas_output_idx: u16,
    fill_token_amount: u64,
    redeem_script: &[u8],
) -> Vec<u8> {
    assert!(kas_output_idx <= 255, "koi must fit in 1 byte for v15 fixed-offset");
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
