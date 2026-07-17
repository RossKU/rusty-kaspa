use crate::primitives::{push_data, u64_le};
use crate::contract::spot::order::{e_num, e_pick, e_roll, ops};

// ============================================================================
// V18 BRACKET — receipt-gated IFD/IFO hard path (see kob/V18_DESIGN.md,
// "IFD / IFO — MANDATORY")
// ============================================================================
//
// The v18 bracket keeps the v1 224B state layout byte-for-byte (the embedded
// `oco_spk` is a generation-agnostic 37B SPK, so it pins a v18 OCO P2SH with
// no layout change) and the same receipt-gated fill structure, with these
// v18 changes:
//
//   1. SELECTOR DISPATCH (Op1 = fill, Op0 = cancel) replaces the v1
//      sigLen<400 split. The v18 body is longer than v1's 141B, which pushes
//      the fill sigscript (`[sel][pushData(RS)]` = RS+4) past the fixed 400
//      threshold — a length-based dispatch cannot survive a body-size change,
//      selector dispatch is also the v18 house style throughout.
//   2. CSV(50) exposure delay on the fill path (v18 fill-family parity; the
//      cancel path stays immediate, as everywhere else in the generation).
//   3. TOKEN-BINDING checks (the Fix-3-analog for the bracket's rigid shape;
//      the bracket input itself is the only covenant-capable input it can
//      derive indices from, so fixed output indices + `OpOutputCovenantId`
//      carry the same guarantee the sweep contracts get from
//      `OpAuthOutputIdx`):
//        - BUY entry: `OpOutputCovenantId(1) == tcid` — the delivery output
//          must be GENUINE tokens of the stated covenant. v1 only checked
//          value+SPK, so a matcher could satisfy the entry with plain KAS
//          labeled as tokens (wrong-asset delivery).
//        - BUY entry: `OpOutputCovenantId(2) == tcid` — the spawned OCO must
//          hold genuine tokens, i.e. the done-leg is a LIVE v18 OCO sell
//          (its fill paths need a token-covenant input); v1 allowed a
//          plain-KAS "OCO" that could never execute (dead done-leg trap).
//        - SELL entry: `OpInputCovenantId(self) == tcid` plus the standard
//          v18 Fix-3 F4 (`OpTxInputIndex Op0 OpAuthOutputIdx` → own token
//          output, covenant == own, value >= token_in) — identical to the
//          v18 sell/OCO conservation form.
//
// RIGID TX SHAPE (input[2] = receipt, outputs[0..3) = KAS/token/OCO) is kept
// deliberately: the bracket's counterparty is the receipt-holding matcher,
// not book orders, so the entry fill is its own tx and never a sweep member.
// The v18 sweep-shape machinery (canonical price attestation offsets,
// per-term tii lists) is therefore not applicable — the bracket reads no
// counterparty sigscript at all; its price is its own state (epnum/epden).
//
// No mmfee field: as in v1, the matcher's compensation is the entry spread
// (the entry price fully allocates kas_in/token_in), so there is no fee
// deduction for a BPS cap to bound.
//
// Sigscripts:
//   Fill:   [Op1] [pushData(RS)]                        sigOpCount = 0
//   Cancel: [pushData(sig+type 65B)] [pushData(pk 32B)] [Op0] [pushData(RS)]
//                                                       sigOpCount = 1
//
// Stack after state push (11 items, depth from top):
//   owner_hash(0), trade_spk_hash(1), rcid(2), mrv(3), mfill(4),
//   oco_mv(5), oco_spk(6), epden(7), epnum(8), tcid(9), etype(10)
// with the selector at depth 11 in every sigscript form.

/// Bracket state size (224B, shared by v1 and v18).
pub const BRACKET_STATE_SIZE: usize = 224;

/// Expected v18 bracket body length (deterministic; pinned in tests).
pub const BRACKET_BODY_EXPECTED_LEN: usize = 148;

/// v18 bracket redeemScript size (224B state + v18 body).
pub const BRACKET_RS_SIZE: usize = BRACKET_STATE_SIZE + BRACKET_BODY_EXPECTED_LEN;

/// Build the v18 bracket body.
///
/// Selectors: 1 = FILL (entry execution), 0 = CANCEL (owner signature).
/// Any other selector falls into the cancel branch and dies on the
/// signature check (fail-closed).
pub fn build_bracket_body() -> Vec<u8> {
    use ops::*;
    let mut b: Vec<u8> = Vec::with_capacity(256);

    // ===== DISPATCH: selector (depth 11) == 1 -> fill, else cancel =====
    e_roll(&mut b, 11);
    e_num(&mut b, 1);
    b.push(EQUAL);
    b.push(IF);
    {
        // ===== FILL PATH =====
        // Exposure delay (v18 fill-family parity).
        e_num(&mut b, 50);
        b.push(CSV);
        // Receipt value: input[2].amount >= min_receipt_val.
        e_num(&mut b, 2);
        b.push(TXINPUTAMOUNT);
        e_pick(&mut b, 4); // mrv (3 + 1)
        b.push(GTE);
        b.push(VERIFY);
        // Receipt covenant: OpInputCovenantId(2) == receipt_cov_id (N4).
        e_num(&mut b, 2);
        b.push(INPUTCOVENANTID);
        e_pick(&mut b, 3); // rcid (2 + 1)
        b.push(EQUAL);
        b.push(VERIFY);
        // OCO spawn SPK: output[2].spk == oco_spk (byte-exact 37B).
        e_num(&mut b, 2);
        b.push(TXOUTPUTSPK);
        e_pick(&mut b, 7); // oco_spk (6 + 1)
        b.push(EQUAL);
        b.push(VERIFY);
        // OCO spawn value: output[2].value >= oco_min_val.
        e_num(&mut b, 2);
        b.push(TXOUTPUTAMOUNT);
        e_pick(&mut b, 6); // oco_mv (5 + 1)
        b.push(GTE);
        b.push(VERIFY);
        // Entry-type dispatch (truthy = sell entry).
        e_pick(&mut b, 10); // etype
        b.push(BIN2NUM);
        b.push(IF);
        {
            // ===== SELL ENTRY =====
            // The bracket UTXO must hold the STATED token.
            b.push(TXINPUTINDEX);
            b.push(INPUTCOVENANTID);
            e_pick(&mut b, 10); // tcid (9 + 1)
            b.push(EQUAL);
            b.push(VERIFY);
            // ek = token_in * epnum / epden; ek >= mfill.
            b.push(TXINPUTINDEX);
            b.push(TXINPUTAMOUNT);
            e_pick(&mut b, 9); // epnum (8 + 1)
            b.push(MUL);
            e_pick(&mut b, 8); // epden (7 + 1)
            b.push(DIV);
            b.push(DUP);
            e_pick(&mut b, 6); // mfill (4 + 2)
            b.push(GTE);
            b.push(VERIFY);
            // output[0].value >= ek (seller's KAS proceeds).
            b.push(OP0);
            b.push(TXOUTPUTAMOUNT);
            b.push(SWAP);
            b.push(GTE);
            b.push(VERIFY);
            // blake2b(output[0].spk) == trade_spk_hash (N5).
            b.push(OP0);
            b.push(TXOUTPUTSPK);
            b.push(BLAKE2B);
            e_pick(&mut b, 2); // trade_spk_hash (1 + 1)
            b.push(EQUAL);
            b.push(VERIFY);
            // F4 (Fix-3): own tokens conserved to the own authorized output.
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
        }
        b.push(ELSE);
        {
            // ===== BUY ENTRY =====
            // et = kas_in / epden * epnum; et >= mfill.
            b.push(TXINPUTINDEX);
            b.push(TXINPUTAMOUNT);
            e_pick(&mut b, 8); // epden (7 + 1)
            b.push(DIV);
            e_pick(&mut b, 9); // epnum (8 + 1)
            b.push(MUL);
            b.push(DUP);
            e_pick(&mut b, 6); // mfill (4 + 2)
            b.push(GTE);
            b.push(VERIFY);
            // output[1].value >= et (buyer's token delivery).
            e_num(&mut b, 1);
            b.push(TXOUTPUTAMOUNT);
            b.push(SWAP);
            b.push(GTE);
            b.push(VERIFY);
            // blake2b(output[1].spk) == trade_spk_hash (N5).
            e_num(&mut b, 1);
            b.push(TXOUTPUTSPK);
            b.push(BLAKE2B);
            e_pick(&mut b, 2); // trade_spk_hash (1 + 1)
            b.push(EQUAL);
            b.push(VERIFY);
            // Delivery must be GENUINE tokens of tcid (wrong-asset guard).
            e_num(&mut b, 1);
            b.push(OUTPUTCOVENANTID);
            e_pick(&mut b, 10); // tcid (9 + 1)
            b.push(EQUAL);
            b.push(VERIFY);
            // Spawned OCO must hold genuine tokens (live v18 done-leg).
            e_num(&mut b, 2);
            b.push(OUTPUTCOVENANTID);
            e_pick(&mut b, 10); // tcid (9 + 1)
            b.push(EQUAL);
            b.push(VERIFY);
        }
        b.push(ENDIF);
        // Cleanup: 11 state items.
        for _ in 0..5 {
            b.push(TWO_DROP);
        }
        b.push(DROP);
    }
    b.push(ELSE);
    {
        // ===== CANCEL PATH =====
        // Sigscript [sig][pk][Op0][RS] -> stack: owner_hash(0) .. etype(10),
        // pk(11), sig(12).
        e_pick(&mut b, 11); // pk
        b.push(BLAKE2B);
        e_pick(&mut b, 1); // owner_hash (0 + 1)
        b.push(EQUAL);
        b.push(VERIFY);
        e_roll(&mut b, 12); // sig
        e_roll(&mut b, 12); // pk
        b.push(CHECKSIG);
        b.push(VERIFY);
        // Cleanup: 11 state items.
        for _ in 0..5 {
            b.push(TWO_DROP);
        }
        b.push(DROP);
    }
    b.push(ENDIF);
    b.push(OP1);
    b
}

/// Build the v18 bracket redeemScript (224B state + v18 body).
///
/// State layout identical to v1 (`build_bracket_redeem_script`); `oco_spk`
/// must be the 37B SPK (version u16LE + 35B P2SH script) of a **v18 OCO
/// sell** for a buy-entry IFO (the fill path enforces that the spawned
/// output holds genuine `token_cov_id` tokens, so only a token-selling
/// done-leg is functional), or of a v18 buy for a sell-entry re-buy leg.
///
/// See `build_bracket_redeem_script` for the argument docs; entry price is
/// NOT gcd-normalized (v1 parity — the bracket price is never read through
/// the canonical attestation offsets by other contracts).
pub fn build_bracket_redeem_script(
    entry_type: u64,
    token_cov_id: &[u8; 32],
    entry_price_num: u64,
    entry_price_den: u64,
    oco_spk: &[u8; 37],
    oco_min_value: u64,
    min_fill: u64,
    min_receipt_value: u64,
    receipt_cov_id: &[u8; 32],
    trade_spk_hash: &[u8; 32],
    owner_hash: &[u8; 32],
) -> crate::Result<Vec<u8>> {
    if entry_type > 1 {
        return Err(crate::KobError::Contract("entry_type must be 0 (buy) or 1 (sell)".into()));
    }
    if entry_price_num == 0 {
        return Err(crate::KobError::Contract("entry_price_num must be > 0".into()));
    }
    if entry_price_den == 0 {
        return Err(crate::KobError::Contract("entry_price_den must be > 0".into()));
    }
    if min_fill == 0 {
        return Err(crate::KobError::Contract("min_fill must be > 0 (zero allows dust griefing)".into()));
    }
    let body = build_bracket_body();
    let mut rs = Vec::with_capacity(BRACKET_STATE_SIZE + body.len());
    // State (224 bytes, identical layout to v1)
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(entry_type));
    rs.push(0x20);
    rs.extend_from_slice(token_cov_id);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(entry_price_num));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(entry_price_den));
    rs.push(0x25);
    rs.extend_from_slice(oco_spk);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(oco_min_value));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_fill));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_receipt_value));
    rs.push(0x20);
    rs.extend_from_slice(receipt_cov_id);
    rs.push(0x20);
    rs.extend_from_slice(trade_spk_hash);
    rs.push(0x20);
    rs.extend_from_slice(owner_hash);
    rs.extend_from_slice(&body);
    debug_assert_eq!(rs.len(), BRACKET_RS_SIZE);
    Ok(rs)
}

/// Build the v18 bracket fill sigscript: `[Op1][pushData(RS)]`.
///
/// sigOpCount = 0. The fill input's sequence must be >= 50 (CSV exposure
/// delay, v18 fill-family parity).
pub fn build_bracket_fill_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(0x51); // Op1 (selector = fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build the v18 bracket cancel sigscript:
/// `[pushData(sig+type 65B)][pushData(pk 32B)][Op0][pushData(RS)]`.
///
/// sigOpCount = 1. Note the ordering differs from the v1 bracket cancel
/// (`[Op0][sig][pk][RS]`): the v18 selector must sit directly below the
/// state (depth 11), so sig/pk go BELOW the selector (v17/v18 convention).
pub fn build_bracket_cancel_sigscript(
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01);

    let mut ss = Vec::with_capacity(66 + 33 + 1 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pubkey));
    ss.push(0x00); // Op0 (selector = cancel)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

