use crate::primitives::u64_le;
use crate::contract::helpers::gcd;
use crate::contract::spot::order::{e_num, e_pick, e_roll, ops};

// ============================================================================
// `twap_sell` — rate-limited sell (consensus CSV clock)
// (kob/TIME_CONTRACTS_DESIGN.md §3 — ADDITIVE contract beside frozen v18)
// ============================================================================
//
// FROZEN FIX (§3.2): there is NO stored `last_fill_daa` clock — the
// originally specified `last := L` splice is UNSOUND (clock-lag burst: L may
// lag real time arbitrarily, so a stored clock banks the whole idle allowance
// and dumps it in one burst). Instead the design gates on the REAL age of the
// order UTXO: every fill-family event consumes the order UTXO and (for
// partials/IOC) creates the residual continuation; that residual's
// `block_daa_score` is the true acceptance time of the previous event,
// recorded by consensus itself. `twin CSV` (T3) then proves consecutive
// events on one order lineage are ≥ twin REAL DAA apart — unforgeable,
// burst-free, no splice, no stored field.
//
// Semantics (§3.3): `twin` = DAA window, `mpw` = max tokens per event;
// applied to ALL fill-family branches (full FILL and IOC included — otherwise
// a matcher bypasses the limiter by full-filling; the "last chunk" must also
// obey `token_in ≤ mpw`):
//
//   twin CSV                      // real age of this order UTXO ≥ twin (T3)
//   vol ≤ mpw                     // vol: FILL = token_in ; IOC/PARTIAL = fta
//
// Owner branches (CANCEL/CANCEL-MARK/EXPIRE) are NOT gated — the owner's
// escape is never rate-limited. Rate guarantee: fills on one lineage are
// ≥ twin apart in real acceptance DAA and each moves ≤ mpw ⇒ long-run rate
// ≤ mpw/twin, worst-case burst = mpw. The first fill also waits twin from
// DEPLOY (the deploy UTXO's age gates it) — accepted and documented.
//
// State (163B = 18 + v18 sell 145), new fields PREPENDED:
//   [0x08][twin 8B] [0x08][mpw 8B]  ‖  v18 sell 145B layout unchanged
// stack at body start (11): expiry(0) … otspkh(8) mpw(9) twin(10);
// selector at 11 (v18 sell: 9).
//
// Engine note: fill-family inputs must carry `sequence = max(50, twin)` =
// twin (builder enforces twin ≥ 50, which also covers the exposure delay).
//
// The twap_sell fill/IOC/partial/cancel/expire sigscripts are byte-identical
// in SHAPE to the v18 sell's — reuse `build_sell_fill_sigscript`,
// `build_sell_ioc_fill_sigscript`, `build_sell_partial_fill_sigscript`,
// `build_sell_expire_sigscript`, `build_sell_cancel_sigscript` and
// `build_sell_cancel_mark_sigscript` with the twap RS (the state price IS the
// attested price; gcd normalization stays consistent on both sides).

/// Build the twap_sell body.
///
/// Stack after state push (11 items):
///   expiry(0), cpend(1), mmfee(2), sspkh(3), ohash(4), mfill(5), pden(6),
///   pnum(7), otspkh(8), mpw(9), twin(10); selector at depth 11.
pub fn build_twap_sell_body() -> Vec<u8> {
    use ops::*;
    let mut b: Vec<u8> = Vec::with_capacity(512);

    // ===== DISPATCH: selector (depth 11) to top =====
    e_roll(&mut b, 11);
    b.push(DUP);
    e_num(&mut b, 4);
    b.push(EQUAL);
    b.push(IF); // selector == 4 -> EXPIRE (owner path: NOT rate-gated)
    {
        b.push(DROP);
        b.push(DUP);
        b.push(VERIFY); // expiry != 0 (GTC guard)
        b.push(CLTV);
        // stack: cpend(0), mmfee(1), sspkh(2), ohash(3), mfill(4), pden(5),
        //        pnum(6), otspkh(7), mpw(8), twin(9)
        b.push(TXINPUTINDEX);
        b.push(OP0);
        b.push(AUTHOUTPUTIDX); // r = auth_outputs[self][0]
        b.push(DUP);
        b.push(TXOUTPUTSPK);
        b.push(BLAKE2B);
        e_pick(&mut b, 9); // otspkh (depth 7, +2 for r + hash)
        b.push(EQUAL);
        b.push(VERIFY);
        b.push(DUP);
        b.push(OUTPUTCOVENANTID);
        b.push(TXINPUTINDEX);
        b.push(INPUTCOVENANTID);
        b.push(EQUAL);
        b.push(VERIFY);
        b.push(TXOUTPUTAMOUNT); // consumes r
        b.push(TXINPUTINDEX);
        b.push(TXINPUTAMOUNT);
        b.push(GTE);
        b.push(VERIFY); // full refund
        // 10 items: cpend..twin
        for _ in 0..5 {
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
                emit_twap_sell_fill(&mut b);
            }
            b.push(ELSE); // selector == 0 -> CANCEL
            {
                emit_twap_sell_cancel(&mut b, false);
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
                emit_twap_sell_ioc(&mut b);
            }
            b.push(ELSE);
            {
                e_num(&mut b, 2);
                b.push(EQUAL);
                b.push(IF); // selector == 2 -> PARTIAL FILL
                {
                    emit_twap_sell_partial(&mut b);
                }
                b.push(ELSE); // selector == 3 -> CANCEL-MARK
                {
                    emit_twap_sell_cancel(&mut b, true);
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

/// twap_sell FILL (selector 1). Sigscript = v18 sell fill shape.
///
/// Entry (selector consumed): expiry(0), cpend(1), mmfee(2), sspkh(3),
///   ohash(4), mfill(5), pden(6), pnum(7), otspkh(8), mpw(9), twin(10),
///   pden_att(11), pnum_att(12), koi(13)
fn emit_twap_sell_fill(b: &mut Vec<u8>) {
    use ops::*;
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
    // base(12): mmfee(0), sspkh(1), ohash(2), mfill(3), pden(4), pnum(5),
    //   otspkh(6), mpw(7), twin(8), pden_att(9), pnum_att(10), koi(11)
    // W1: consensus real-age gate (T3): UTXO age >= twin.
    e_pick(b, 8); // twin
    b.push(CSV);
    // W2: per-event volume cap, vol = token_in (FILL form).
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT); // vol
    e_pick(b, 8); // mpw (7 + 1 for vol)
    b.push(SWAP); // [mpw, vol]
    b.push(GTE);
    b.push(VERIFY); // mpw >= vol
    // ATTESTATION: attested pair == state pair (v18-identical, +2 depths)
    e_pick(b, 10); // pnum_att
    e_pick(b, 6); // pnum (5 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    e_pick(b, 9); // pden_att
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
    // KAS output >= expected_kas
    e_pick(b, 12); // koi (11 + 1)
    b.push(TXOUTPUTAMOUNT);
    b.push(SWAP);
    b.push(GTE);
    b.push(VERIFY);
    // F2: seller SPK hash
    e_pick(b, 11); // koi
    b.push(TXOUTPUTSPK);
    b.push(BLAKE2B);
    e_pick(b, 2); // sspkh (1 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    // F4: per-input token conservation (Fix-3)
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
    // cleanup: 12 items
    for _ in 0..6 {
        b.push(TWO_DROP);
    }
}

/// twap_sell IOC FILL (selector 5). Sigscript = v18 sell IOC shape.
///
/// Entry (stale selector dropped): expiry(0)..otspkh(8), mpw(9), twin(10),
///   fta(11), pden_att(12), pnum_att(13), koi(14)
fn emit_twap_sell_ioc(b: &mut Vec<u8>) {
    use ops::*;
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
    // base(13): mmfee(0), sspkh(1), ohash(2), mfill(3), pden(4), pnum(5),
    //   otspkh(6), mpw(7), twin(8), fta(9), pden_att(10), pnum_att(11),
    //   koi(12)
    // W1
    e_pick(b, 8); // twin
    b.push(CSV);
    // W2: vol = fta (IOC form)
    e_pick(b, 9); // fta
    e_pick(b, 8); // mpw (7 + 1 for vol)
    b.push(SWAP); // [mpw, vol]
    b.push(GTE);
    b.push(VERIFY); // mpw >= vol
    // ATTESTATION
    e_pick(b, 11); // pnum_att
    e_pick(b, 6); // pnum (5 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    e_pick(b, 10); // pden_att
    e_pick(b, 5); // pden (4 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    // fill_kas = fta * pnum / pden, >= mfill
    e_pick(b, 9); // fta
    e_pick(b, 6); // pnum (5 + 1)
    b.push(MUL);
    e_pick(b, 5); // pden (4 + 1)
    b.push(DIV);
    b.push(DUP);
    e_pick(b, 5); // mfill (3 + 2)
    b.push(GTE);
    b.push(VERIFY);
    // KAS output >= fill_kas
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
    // F4: residual conservation (self-SPK continuation >= token_in - fta)
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
    e_pick(b, 11); // fta (9 + 2)
    b.push(SUB);
    b.push(GTE);
    b.push(VERIFY);
    // cleanup: 13 items
    for _ in 0..6 {
        b.push(TWO_DROP);
    }
    b.push(DROP);
}

/// twap_sell PARTIAL FILL (selector 2). Sigscript = v18 sell partial shape.
///
/// Entry (selector consumed): expiry(0)..otspkh(8), mpw(9), twin(10), ri(11),
///   fta(12), pden_att(13), pnum_att(14), koi(15)
fn emit_twap_sell_partial(b: &mut Vec<u8>) {
    use ops::*;
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
    // base(14): mmfee(0), sspkh(1), ohash(2), mfill(3), pden(4), pnum(5),
    //   otspkh(6), mpw(7), twin(8), ri(9), fta(10), pden_att(11),
    //   pnum_att(12), koi(13)
    // W1
    e_pick(b, 8); // twin
    b.push(CSV);
    // W2: vol = fta (PARTIAL form)
    e_pick(b, 10); // fta
    e_pick(b, 8); // mpw (7 + 1 for vol)
    b.push(SWAP); // [mpw, vol]
    b.push(GTE);
    b.push(VERIFY); // mpw >= vol
    // ATTESTATION
    e_pick(b, 12); // pnum_att
    e_pick(b, 6); // pnum (5 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    e_pick(b, 11); // pden_att
    e_pick(b, 5); // pden (4 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    // fill_kas = fta * pnum / pden, >= mfill (keeps an fta copy on stack)
    e_pick(b, 10); // fta
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
    e_pick(b, 15); // koi (13 + 2)
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
    e_pick(b, 10); // ri (9 + 1)
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
    e_pick(b, 10); // ri (9 + 1)
    b.push(TXOUTPUTAMOUNT);
    b.push(SWAP);
    b.push(GTE);
    b.push(VERIFY);
    // residual-fill floor: (token_in - fta) * pnum / pden >= mfill
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT);
    e_pick(b, 11); // fta (10 + 1)
    b.push(SUB);
    e_pick(b, 6); // pnum (5 + 1)
    b.push(MUL);
    e_pick(b, 5); // pden (4 + 1)
    b.push(DIV);
    e_pick(b, 4); // mfill (3 + 1)
    b.push(GTE);
    b.push(VERIFY);
    // F2: seller SPK hash on koi
    e_pick(b, 13); // koi
    b.push(TXOUTPUTSPK);
    b.push(BLAKE2B);
    e_pick(b, 2); // sspkh (1 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    // F4 (Fix-3): self-SPK residual worth >= token_in - fta
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
    e_pick(b, 12); // fta (10 + 2)
    b.push(SUB);
    b.push(GTE);
    b.push(VERIFY);
    // cleanup: 14 items
    for _ in 0..7 {
        b.push(TWO_DROP);
    }
}

/// twap_sell CANCEL (0) / CANCEL-MARK (3) — owner signature, NOT rate-gated.
fn emit_twap_sell_cancel(b: &mut Vec<u8>, mark: bool) {
    use ops::*;
    // entry (selector consumed): expiry(0)..otspkh(8), mpw(9), twin(10),
    //   pk(11), sig(12)
    if mark {
        b.push(DROP); // expiry
        b.push(OP0);
        b.push(EQUAL);
        b.push(VERIFY); // cpend == 0 (can't re-mark)
    } else {
        b.push(TWO_DROP); // expiry + cpend
    }
    // stack: mmfee(0), sspkh(1), ohash(2), mfill(3), pden(4), pnum(5),
    //        otspkh(6), mpw(7), twin(8), pk(9), sig(10)
    e_pick(b, 9); // pk
    b.push(BLAKE2B);
    e_pick(b, 3); // ohash (2 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    e_roll(b, 10); // sig
    e_roll(b, 10); // pk
    b.push(CHECKSIG);
    b.push(VERIFY);
    // 9 items
    for _ in 0..4 {
        b.push(TWO_DROP);
    }
    b.push(DROP);
}

/// Expected twap_sell body length (pinned at Stage-A freeze).
pub const TWAP_SELL_BODY_EXPECTED_LEN: usize = 406;

/// twap_sell state size: `[0x08 twin][0x08 mpw]` + v18 sell 145B.
pub const TWAP_SELL_STATE_SIZE: usize = 18 + 145;

/// Expected twap_sell redeemScript length (163B state + body).
pub const TWAP_SELL_RS_EXPECTED_LEN: usize =
    TWAP_SELL_STATE_SIZE + TWAP_SELL_BODY_EXPECTED_LEN;

/// Build the twap_sell redeemScript (163B state + body).
///
/// State: `[0x08][twin][0x08][mpw]` then the v18 sell 145B layout unchanged
/// (gcd-normalized price, exactly like the v18 sell — the attestation is a
/// byte-equality against the same normalized sigscript builders).
///
/// Builder validation (§3.4): `50 ≤ twin ≤ 0xFFFF_FFFF` (CSV 32-bit mask)
/// `∧ mpw ≥ 1 ∧ mpw×pnum/pden ≥ mfill` (else no event can satisfy both
/// floors).
pub fn build_twap_sell_redeem_script(
    twin: u64,
    mpw: u64,
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
    if twin < 50 {
        return Err(crate::KobError::Contract("twin must be >= 50 (covers the exposure delay; plain behavior = deploy the v18 sell)".into()));
    }
    if twin > 0xFFFF_FFFF {
        return Err(crate::KobError::Contract("twin must fit the CSV 32-bit mask".into()));
    }
    if mpw == 0 {
        return Err(crate::KobError::Contract("mpw must be >= 1".into()));
    }
    let g = gcd(price_num, price_den);
    let price_num = if g > 0 { price_num / g } else { price_num };
    let price_den = if g > 0 { price_den / g } else { price_den };
    let event_kas = mpw
        .checked_mul(price_num)
        .ok_or_else(|| crate::KobError::Contract("mpw*pnum overflows".into()))?
        / price_den;
    if event_kas < min_fill {
        return Err(crate::KobError::Contract("mpw*pnum/pden must be >= min_fill (no event could satisfy both floors)".into()));
    }
    let body = build_twap_sell_body();
    let mut rs = Vec::with_capacity(TWAP_SELL_STATE_SIZE + body.len());
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(twin));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(mpw));
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
    debug_assert_eq!(rs.len(), TWAP_SELL_RS_EXPECTED_LEN);
    Ok(rs)
}
