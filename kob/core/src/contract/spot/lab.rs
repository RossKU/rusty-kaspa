//! EXPERIMENTAL batch-limit lab — parameterized buy covenants for the
//! measurement campaign recorded in `kob/BATCH_LIMITS.md`.
//!
//! The SHIPPING buy covenant is `order::build_buy_body()` with the frozen
//! `BUY_ORDER_MAX_N = 32` (LIMITS re-freeze). This module builds EXPERIMENTAL
//! variants whose only difference is the unrolled sweep slot count `max_n`
//! (the same `emit_fill_body` / `emit_partial_body` emitters, so per-term
//! semantics are identical). They exist to measure where one settle
//! transaction hits node limits (mass dimensions, script units, stack) —
//! they are NOT deployable through the product paths: `parse_redeem_script`
//! dispatches on the shipping RS lengths and every deploy path bails on
//! anything else.
//!
//! Invariant pinned by `lab_max_n_32_matches_shipping_bytes`: `max_n == 32`
//! (the shipping `BUY_ORDER_MAX_N` since the LIMITS re-freeze) reproduces
//! the shipping RS byte-for-byte, so measurements at other `max_n` differ
//! from the product only by the slot count (and the derived `max_n + 2`
//! partial-guard scan).

use super::order::{
    emit_cancel_body, emit_fill_body, emit_partial_body, ops, e_num,
    BUY_ORDER_STATE_SIZE,
};
use crate::primitives::{push_data, u64_le};
use crate::contract::helpers::{gcd, push_index};

/// Build an EXPERIMENTAL v18-shaped buy body with `max_n` sweep slots.
/// `max_n = 32` is byte-identical to the shipping `build_buy_body()`.
pub fn build_buy_body_lab(max_n: usize) -> Vec<u8> {
    use ops::*;
    let mut b: Vec<u8> = Vec::with_capacity(8192);

    // ===== DISPATCH (identical to order::build_buy_body) =====
    e_num(&mut b, 11);
    b.push(ROLL);

    b.push(DUP);
    e_num(&mut b, 4);
    b.push(NUMEQUAL);
    b.push(IF);
    {
        b.push(DROP);
        b.push(DUP);
        b.push(VERIFY);
        b.push(CLTV);
        b.push(OP0);
        b.push(TXOUTPUTSPK);
        b.push(BLAKE2B);
        super::order::e_pick(&mut b, 9);
        b.push(EQUAL);
        b.push(VERIFY);
        b.push(OP0);
        b.push(TXOUTPUTAMOUNT);
        b.push(TXINPUTINDEX);
        b.push(TXINPUTAMOUNT);
        b.push(GTE);
        b.push(VERIFY);
        for _ in 0..5 {
            b.push(TWO_DROP);
        }
    }
    b.push(ELSE);
    {
        b.push(DUP);
        e_num(&mut b, 0);
        b.push(NUMEQUAL);
        b.push(IF);
        {
            b.push(DROP);
            emit_cancel_body(&mut b);
        }
        b.push(ELSE);
        {
            b.push(DUP);
            e_num(&mut b, 3);
            b.push(NUMEQUAL);
            b.push(IF);
            {
                b.push(DROP);
                emit_cancel_body(&mut b);
            }
            b.push(ELSE);
            {
                b.push(DUP);
                e_num(&mut b, 2);
                b.push(NUMEQUAL);
                b.push(IF);
                {
                    b.push(DROP);
                    emit_partial_body(&mut b, max_n);
                }
                b.push(ELSE);
                {
                    emit_fill_body(&mut b, max_n);
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

/// Build an EXPERIMENTAL buy redeemScript (shipping state layout with
/// `n_max = max_n` + `build_buy_body_lab(max_n)`). Same argument semantics
/// as `order::build_buy_redeem_script`. For `max_n <= 127` the n_max field
/// is the shipping fixed `[0x01][v]` push; larger lab variants use a 2-byte
/// zero-padded push (the body reads it by STACK depth, not byte offset).
#[allow(clippy::too_many_arguments)]
pub fn build_buy_redeem_script_lab(
    max_n: usize,
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
    if price_num == 0 || price_den == 0 {
        return Err(crate::KobError::Contract("price must be > 0".into()));
    }
    if min_fill == 0 {
        return Err(crate::KobError::Contract("min_fill must be > 0".into()));
    }
    let g = gcd(price_num, price_den);
    let price_num = if g > 0 { price_num / g } else { price_num };
    let price_den = if g > 0 { price_den / g } else { price_den };
    let body = build_buy_body_lab(max_n);
    let mut rs = Vec::with_capacity(BUY_ORDER_STATE_SIZE + body.len());
    if max_n <= 127 {
        rs.push(0x01); // n_max (shipping encoding at max_n = 32)
        rs.push(max_n as u8);
    } else {
        rs.push(0x02); // large lab variants: keep the value positive
        rs.push((max_n & 0xff) as u8);
        rs.push((max_n >> 8) as u8);
    }
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
    Ok(rs)
}

/// EXPERIMENTAL buy fill sigscript for a `max_n`-slot covenant:
/// `[tii_1]...[tii_max_n][N][selector][pushData(RS)]` (unused slots = 0).
pub fn build_buy_fill_sigscript_lab(
    max_n: usize,
    sell_input_indices: &[u16],
    ioc: bool,
    redeem_script: &[u8],
) -> Vec<u8> {
    assert!(!sell_input_indices.is_empty(), "at least one sell required");
    assert!(sell_input_indices.len() <= max_n, "at most max_n sells per sweep");
    let n = sell_input_indices.len();
    let mut ss = Vec::with_capacity(max_n + 4 + redeem_script.len() + 3);
    for i in 0..max_n {
        let v = if i < n { sell_input_indices[i] } else { 0 };
        push_index(&mut ss, v);
    }
    push_index(&mut ss, n as u16);
    ss.push(if ioc { 0x55 } else { 0x51 });
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// EXPERIMENTAL buy PARTIAL sigscript for a `max_n`-slot covenant:
/// `[tii_1]...[tii_max_n][N][ri][Op2][pushData(RS)]`.
pub fn build_buy_partial_fill_sigscript_lab(
    max_n: usize,
    sell_input_indices: &[u16],
    residual_output_idx: u16,
    redeem_script: &[u8],
) -> Vec<u8> {
    assert!(!sell_input_indices.is_empty(), "at least one sell required");
    assert!(sell_input_indices.len() <= max_n, "at most max_n sells per sweep");
    let n = sell_input_indices.len();
    let mut ss = Vec::with_capacity(max_n + 6 + redeem_script.len() + 3);
    for i in 0..max_n {
        let v = if i < n { sell_input_indices[i] } else { 0 };
        push_index(&mut ss, v);
    }
    push_index(&mut ss, n as u16);
    push_index(&mut ss, residual_output_idx);
    ss.push(0x52);
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::spot::order::{
        build_buy_body, build_buy_fill_sigscript, build_buy_redeem_script,
        BUY_ORDER_RS_EXPECTED_LEN,
    };

    /// The lab builder at max_n=32 must reproduce the SHIPPING bytecode
    /// byte-for-byte — the measurement variants differ only in slot count.
    #[test]
    fn lab_max_n_32_matches_shipping_bytes() {
        assert_eq!(build_buy_body_lab(32), build_buy_body());
        let tcid = [0x11u8; 32];
        let h = [0x22u8; 32];
        let ship = build_buy_redeem_script(&tcid, 3, 7, 1000, &h, &h, &h, 30, 0, 0).unwrap();
        let lab =
            build_buy_redeem_script_lab(32, &tcid, 3, 7, 1000, &h, &h, &h, 30, 0, 0).unwrap();
        assert_eq!(ship, lab);
        assert_eq!(ship.len(), BUY_ORDER_RS_EXPECTED_LEN);
        assert_eq!(
            build_buy_fill_sigscript(&[0, 1, 2], false, &ship),
            build_buy_fill_sigscript_lab(32, &[0, 1, 2], false, &lab),
        );
    }
}
