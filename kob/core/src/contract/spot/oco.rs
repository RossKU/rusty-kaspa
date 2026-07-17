use crate::primitives::{push_data, u64_le};
use crate::contract::helpers::gcd;

// ============================================================================
// Single-UTXO OCO Sell covenant (v18)
// ============================================================================
//
// One UTXO holds both take-profit and stop-loss sell orders.
// Spending the UTXO for either path naturally cancels the other (UTXO model).
// No nonce linking, no cancel-by-partner.
//
// The generation-agnostic cancel/expire sigscript builders live below; the
// v18 body + RS builder follow (canonical price attestation on both fill
// branches, otspkh expire seat).

/// Core OCO sell state layout size (the v18 state = `[0x20][otspkh]` + this).
pub const OCO_SELL_STATE_SIZE: usize = 139;

/// Build OCO sell cancel sigscript.
///
/// Layout: `[pushData(sig+type 65B)] [pushData(pubkey 32B)] [Op0] [pushData(RS)]`
///
/// sigOpCount = 1.
pub fn build_oco_sell_cancel_sigscript(
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01);

    let mut ss = Vec::with_capacity(101 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pubkey));
    ss.push(0x00); // Op0 (selector = cancel)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build OCO sell expire sigscript.
///
/// Layout: `[Op4] [pushData(RS)]`
///
/// sigOpCount = 0.
pub fn build_oco_sell_expire_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(0x54); // Op4 (selector = expire)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// OCO path selector for batch engine integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OcoPath {
    /// Take-profit path (selector = Op1).
    TakeProfit,
    /// Stop-loss path (selector = Op2).
    StopLoss,
}

// ============================================================================
// V18 OCO SELL — 139B state unchanged; TP/SL canonical price attestation
// ============================================================================
//
// v18 (see kob/V18_DESIGN.md) makes the OCO sell sweep-eligible on BOTH
// branches: every fill sigscript carries the canonical attestation prefix
// `[0x01,koi][0x08 pnum][0x08 pden]` (pnum at [3..11), pden at [12..20)) and
// the body verifies the attested pair equals the *executing branch's* state
// pair (TP: pnum_tp/pden_tp; SL: pnum_sl/pden_sl). A v18 buy reading the
// fixed offsets therefore always sees the price the branch actually executes
// at — this removes the old OCO-SL fixed-offset mismatch (the historic sweep
// blocker) at L1.

use crate::contract::spot::order::{e_num, e_pick, e_roll, v17op};

/// Build the v18 OCO sell body.
///
/// Stack after state push (v1 layout preceded by the owner token seat
/// `otspkh` = blake2b of the owner's token_unit P2SH SPK, 12 items):
///   expiry(0), cpend(1), mmfee(2), sspkh(3), ohash(4),
///   mfill_sl(5), pden_sl(6), pnum_sl(7),
///   mfill_tp(8), pden_tp(9), pnum_tp(10), otspkh(11)
/// with the selector at depth 12 in every sigscript form.
///
/// Selectors: 0=CANCEL, 1=TP FILL, 2=SL FILL, 4=EXPIRE. The EXPIRE branch
/// refunds the token escrow to `otspkh` as a covenant-bound token_unit via
/// the Fix-3 per-input binding (auth[0] of self) — same form as the v18
/// plain sell.
pub fn build_oco_sell_v18_body() -> Vec<u8> {
    use v17op::*;
    let mut b: Vec<u8> = Vec::with_capacity(512);

    e_roll(&mut b, 12);
    b.push(DUP);
    e_num(&mut b, 4);
    b.push(EQUAL);
    b.push(IF); // selector == 4 -> EXPIRE
    {
        b.push(DROP);
        b.push(DUP);
        b.push(VERIFY); // expiry != 0
        b.push(CLTV);
        // Fix-3 refund: auth[0] of self -> owner token seat, binding kept.
        // stack: cpend(0), mmfee(1), sspkh(2), ohash(3), mfill_sl(4),
        //        pden_sl(5), pnum_sl(6), mfill_tp(7), pden_tp(8),
        //        pnum_tp(9), otspkh(10)
        b.push(TXINPUTINDEX);
        b.push(OP0);
        b.push(AUTHOUTPUTIDX); // r = auth_outputs[self][0]
        b.push(DUP);
        b.push(TXOUTPUTSPK);
        b.push(BLAKE2B);
        e_pick(&mut b, 12); // otspkh (depth 10, +2 for r + hash)
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
        // 11 items: cpend..otspkh
        for _ in 0..5 {
            b.push(TWO_DROP);
        }
        b.push(DROP);
    }
    b.push(ELSE);
    {
        b.push(DUP);
        e_num(&mut b, 2);
        b.push(LT);
        b.push(IF); // selector < 2 (TP fill or cancel)
        {
            e_num(&mut b, 1);
            b.push(EQUAL);
            b.push(IF); // selector == 1 -> TP FILL
            {
                emit_oco_v18_fill(&mut b, true);
            }
            b.push(ELSE); // selector == 0 -> CANCEL
            {
                emit_oco_v18_cancel(&mut b);
            }
            b.push(ENDIF);
        }
        b.push(ELSE); // selector >= 2 -> SL FILL (must be exactly 2)
        {
            e_num(&mut b, 2);
            b.push(EQUAL);
            b.push(VERIFY);
            emit_oco_v18_fill(&mut b, false);
        }
        b.push(ENDIF);
    }
    b.push(ENDIF);
    b.push(OP1);
    b
}

/// v18 OCO fill (TP when `tp`, else SL). Sigscript:
/// `[0x01,koi][0x08 pnum][0x08 pden][Op1|Op2][pushData(RS)]`.
///
/// Entry (selector consumed): expiry(0), cpend(1), mmfee(2), sspkh(3),
///   ohash(4), mfill_sl(5), pden_sl(6), pnum_sl(7), mfill_tp(8), pden_tp(9),
///   pnum_tp(10), otspkh(11), pden_att(12), pnum_att(13), koi(14)
fn emit_oco_v18_fill(b: &mut Vec<u8>, tp: bool) {
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
    // base(13): mmfee(0), sspkh(1), ohash(2), mfill_sl(3), pden_sl(4),
    //           pnum_sl(5), mfill_tp(6), pden_tp(7), pnum_tp(8), otspkh(9),
    //           pden_att(10), pnum_att(11), koi(12)
    let (pnum_d, pden_d, mfill_d) = if tp { (8usize, 7usize, 6usize) } else { (5, 4, 3) };
    // ATTESTATION: attested pair == the EXECUTING branch's state pair
    e_pick(b, 11); // pnum_att
    e_pick(b, pnum_d + 1);
    b.push(EQUAL);
    b.push(VERIFY);
    e_pick(b, 10); // pden_att
    e_pick(b, pden_d + 1);
    b.push(EQUAL);
    b.push(VERIFY);
    // price: expected_kas = token_in * pnum / pden, >= mfill
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT);
    e_pick(b, pnum_d + 1);
    b.push(MUL);
    e_pick(b, pden_d + 1);
    b.push(DIV);
    b.push(DUP);
    e_pick(b, mfill_d + 2);
    b.push(GTE);
    b.push(VERIFY);
    // KAS output >= expected_kas
    e_pick(b, 13); // koi (12 + 1)
    b.push(TXOUTPUTAMOUNT);
    b.push(SWAP);
    b.push(GTE);
    b.push(VERIFY);
    // F2: seller SPK hash
    e_pick(b, 12); // koi
    b.push(TXOUTPUTSPK);
    b.push(BLAKE2B);
    e_pick(b, 2); // sspkh (1 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    // F4: per-input token conservation (Fix-3, unchanged from v1's fixed form)
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
    // cleanup: 13 items
    for _ in 0..6 {
        b.push(TWO_DROP);
    }
    b.push(DROP);
}

/// v18 OCO cancel (selector 0) — owner signature.
/// Sigscript: `[sig][pk][Op0][pushData(RS)]` (same shape as v1).
fn emit_oco_v18_cancel(b: &mut Vec<u8>) {
    use v17op::*;
    // entry: expiry(0), cpend(1), mmfee(2), sspkh(3), ohash(4), mfill_sl(5),
    //        pden_sl(6), pnum_sl(7), mfill_tp(8), pden_tp(9), pnum_tp(10),
    //        otspkh(11), pk(12), sig(13)
    b.push(TWO_DROP); // expiry + cpend
    e_pick(b, 10); // pk
    b.push(BLAKE2B);
    e_pick(b, 3); // ohash (2 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    e_roll(b, 11); // sig
    e_roll(b, 11); // pk
    b.push(CHECKSIG);
    b.push(VERIFY);
    // 10 items
    for _ in 0..5 {
        b.push(TWO_DROP);
    }
}

/// Expected v18 OCO sell body length.
pub const OCO_SELL_V18_BODY_EXPECTED_LEN: usize = 225;

/// v18 OCO sell state size: the v1 139B layout preceded by
/// `[0x20][otspkh 32B]` (owner token seat).
pub const OCO_SELL_V18_STATE_SIZE: usize = OCO_SELL_STATE_SIZE + 33;

/// v18 OCO sell redeemScript size (172B state + v18 body).
pub const OCO_SELL_V18_RS_SIZE: usize = OCO_SELL_V18_STATE_SIZE + OCO_SELL_V18_BODY_EXPECTED_LEN;

/// Build the v18 single-UTXO OCO sell redeemScript (172B state + v18 body).
///
/// State: `[0x20][otspkh 32B]` (owner token seat = blake2b of the owner's
/// token_unit P2SH SPK; the EXPIRE refund endpoint, binding preserved) then
/// the v1 139B layout. `max_matcher_fee` is BPS in v18 (uniform).
pub fn build_oco_sell_v18_redeem_script(
    price_num_tp: u64,
    price_den_tp: u64,
    min_fill_tp: u64,
    price_num_sl: u64,
    price_den_sl: u64,
    min_fill_sl: u64,
    owner_hash: &[u8; 32],
    seller_spk_hash: &[u8; 32],
    owner_token_spk_hash: &[u8; 32],
    max_matcher_fee_bps: u64,
    cancel_pending: u8,
    expiry_daa: u64,
) -> crate::Result<Vec<u8>> {
    if price_num_tp == 0 || price_den_tp == 0 {
        return Err(crate::KobError::Contract("TP price must be > 0".into()));
    }
    if price_num_sl == 0 || price_den_sl == 0 {
        return Err(crate::KobError::Contract("SL price must be > 0".into()));
    }
    if min_fill_tp == 0 || min_fill_sl == 0 {
        return Err(crate::KobError::Contract("min_fill must be > 0".into()));
    }
    if cancel_pending > 1 {
        return Err(crate::KobError::Contract("cancel_pending must be 0 or 1".into()));
    }
    if max_matcher_fee_bps > 10000 {
        return Err(crate::KobError::Contract("max_matcher_fee_bps must be <= 10000".into()));
    }
    let g_tp = gcd(price_num_tp, price_den_tp);
    let pnum_tp = if g_tp > 0 { price_num_tp / g_tp } else { price_num_tp };
    let pden_tp = if g_tp > 0 { price_den_tp / g_tp } else { price_den_tp };
    let g_sl = gcd(price_num_sl, price_den_sl);
    let pnum_sl = if g_sl > 0 { price_num_sl / g_sl } else { price_num_sl };
    let pden_sl = if g_sl > 0 { price_den_sl / g_sl } else { price_den_sl };

    let body = build_oco_sell_v18_body();
    let mut rs = Vec::with_capacity(OCO_SELL_V18_STATE_SIZE + body.len());
    rs.push(0x20);
    rs.extend_from_slice(owner_token_spk_hash);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(pnum_tp));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(pden_tp));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_fill_tp));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(pnum_sl));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(pden_sl));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_fill_sl));
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
    debug_assert_eq!(rs.len(), OCO_SELL_V18_RS_SIZE);
    Ok(rs)
}

/// Build v18 OCO TP fill sigscript (canonical attestation layout).
///
/// Layout: `[0x01,koi][0x08 pnum_tp][0x08 pden_tp][Op1][pushData(RS)]`.
pub fn build_oco_sell_v18_tp_fill_sigscript(
    kas_output_idx: u16,
    price_num_tp: u64,
    price_den_tp: u64,
    redeem_script: &[u8],
) -> Vec<u8> {
    assert!(kas_output_idx <= 255, "koi must fit in 1 byte for the canonical convention");
    let g = gcd(price_num_tp, price_den_tp);
    let pnum = if g > 0 { price_num_tp / g } else { price_num_tp };
    let pden = if g > 0 { price_den_tp / g } else { price_den_tp };
    let mut ss = Vec::with_capacity(21 + redeem_script.len() + 3);
    ss.push(0x01);
    ss.push(kas_output_idx as u8);
    ss.push(0x08);
    ss.extend_from_slice(&u64_le(pnum));
    ss.push(0x08);
    ss.extend_from_slice(&u64_le(pden));
    ss.push(0x51); // Op1 (selector = TP fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build v18 OCO SL fill sigscript (canonical attestation layout).
///
/// Layout: `[0x01,koi][0x08 pnum_sl][0x08 pden_sl][Op2][pushData(RS)]`.
pub fn build_oco_sell_v18_sl_fill_sigscript(
    kas_output_idx: u16,
    price_num_sl: u64,
    price_den_sl: u64,
    redeem_script: &[u8],
) -> Vec<u8> {
    assert!(kas_output_idx <= 255, "koi must fit in 1 byte for the canonical convention");
    let g = gcd(price_num_sl, price_den_sl);
    let pnum = if g > 0 { price_num_sl / g } else { price_num_sl };
    let pden = if g > 0 { price_den_sl / g } else { price_den_sl };
    let mut ss = Vec::with_capacity(21 + redeem_script.len() + 3);
    ss.push(0x01);
    ss.push(kas_output_idx as u8);
    ss.push(0x08);
    ss.extend_from_slice(&u64_le(pnum));
    ss.push(0x08);
    ss.extend_from_slice(&u64_le(pden));
    ss.push(0x52); // Op2 (selector = SL fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build v18 OCO expire sigscript: `[Op4][pushData(RS)]` (same shape as v1;
/// provided for naming symmetry).
pub fn build_oco_sell_v18_expire_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    build_oco_sell_expire_sigscript(redeem_script)
}

/// Build v18 OCO cancel sigscript: `[sig][pk][Op0][pushData(RS)]` (same shape
/// as v1; provided for naming symmetry).
pub fn build_oco_sell_v18_cancel_sigscript(
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    build_oco_sell_cancel_sigscript(signature, pubkey, redeem_script)
}
