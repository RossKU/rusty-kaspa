//! Parse spot order redeemScripts to extract on-chain state.

use crate::types::OrderSide;
use crate::contract::spot::bracket::{BRACKET_RS_SIZE, BRACKET_STATE_SIZE as BRACKET_STATE_SIZE};
use crate::contract::spot::oco::{
    OCO_SELL_CORE_STATE_SIZE, OCO_SELL_RS_SIZE, OCO_SELL_STATE_SIZE, OcoPath,
};
use crate::contract::spot::order::{
    BUY_ORDER_RS_EXPECTED_LEN, BUY_ORDER_STATE_SIZE,
    SELL_ORDER_RS_EXPECTED_LEN, SELL_ORDER_STATE_SIZE,
};

/// OpZkPrecompile opcode byte (0xa6).
pub const OP_ZK_PRECOMPILE: u8 = 0xa6;

/// Check whether the *body* section of a redeemScript contains the ZK
/// precompile opcode.  The state section (push-data at the front) is
/// skipped because arbitrary data bytes there (e.g. owner_hash) can
/// coincidentally equal `0xa6`, causing false positives.
pub fn has_zk_opcode(redeem_script: &[u8], body_start: usize) -> bool {
    redeem_script.get(body_start..).map_or(false, |body| body.contains(&OP_ZK_PRECOMPILE))
}

/// Parsed order parameters from a redeemScript.
#[derive(Debug, Clone)]
pub struct ParsedOrder {
    pub order_type: OrderSide,
    /// Contract version identifier (for forward-compat, currently unused).
    pub version: u8,
    /// Token covenant ID (32 bytes). For sell orders this is [0;32].
    pub token_cov_id: [u8; 32],
    pub price_num: u64,
    pub price_den: u64,
    pub min_fill: u64,
    pub owner_hash: [u8; 32],
    /// Buyer/Seller SPK hash
    pub spk_hash: [u8; 32],
    /// Max matcher fee
    pub _max_matcher_fee: u64,
    /// Cancel pending flag
    pub cpend: u8,
    /// Full redeemScript bytes
    pub redeem_script: Vec<u8>,
    /// Post-only flag from v2 payload (Matcher-level policy).
    pub post_only: bool,
    /// GTD expiry DAA score from v2 payload. None = GTC (no expiry).
    pub expiry_daa: Option<u64>,
    /// True if the redeemScript contains OpZkPrecompile (0xa6).
    #[allow(dead_code)]
    pub requires_zk: bool,
    /// IFD: order B's redeemScript bytes (from IFD payload flag).
    pub ifd_order_b_rs: Option<Vec<u8>>,
    /// v18 owner refund seat (None for pre-v18 generations):
    /// buy = `okspkh` (blake2b of the owner's raw P2PK SPK, EXPIRE KAS
    /// refund endpoint); sell = `otspkh` (blake2b of the owner's token_unit
    /// P2SH SPK, EXPIRE token refund endpoint).
    pub owner_seat_hash: Option<[u8; 32]>,
}

/// Core buy state layout size (the v18 state = `[0x20][okspkh]` + this).
pub const BUY_STATE_SIZE: usize = 145;
/// Core sell state layout size (the v18 state = `[0x20][otspkh]` + this).
pub const SELL_STATE_SIZE: usize = 112;


/// Parsed OCO sell order (single-UTXO, two price paths).
#[derive(Debug, Clone)]
pub struct ParsedOcoSell {
    pub price_num_tp: u64,
    pub price_den_tp: u64,
    pub min_fill_tp: u64,
    pub price_num_sl: u64,
    pub price_den_sl: u64,
    pub min_fill_sl: u64,
    pub owner_hash: [u8; 32],
    pub spk_hash: [u8; 32],
    pub _max_matcher_fee: u64,
    pub cpend: u8,
    pub expiry_daa: Option<u64>,
    pub redeem_script: Vec<u8>,
    /// v18 owner token seat `otspkh` (None for the v1 OCO).
    pub owner_seat_hash: Option<[u8; 32]>,
}

/// Parse a redeemScript to extract order parameters.
///
/// Identifies the contract type by RS length and body signature bytes,
/// then extracts parameters from the fixed-offset state portion.
pub fn parse_redeem_script(rs: &[u8]) -> Option<ParsedOrder> {
    match rs.len() {
        BUY_ORDER_RS_EXPECTED_LEN => {
            // Buy v18 (unified spot: N:M sweep + Op2 partial): the v17 145B
            // state layout preceded by [0x20][okspkh 32B] (178B state), body
            // dispatch signature Op10 OpRoll = 0x5a 0x7a; the RS length is
            // the version tag.
            if rs[BUY_ORDER_STATE_SIZE] == 0x5a
                && rs[BUY_ORDER_STATE_SIZE + 1] == 0x7a
            {
                return parse_buy_state(rs);
            }
            None
        }
        SELL_ORDER_RS_EXPECTED_LEN => {
            // Sell v18 (canonical price attestation + Fix-3 partial F4 +
            // otspkh expire seat): the v14 112B layout preceded by
            // [0x20][otspkh 32B] (145B state), body dispatch signature Op9
            // OpRoll = 0x59 0x7a; the RS length is the version tag.
            if rs[SELL_ORDER_STATE_SIZE] == 0x59
                && rs[SELL_ORDER_STATE_SIZE + 1] == 0x7a
            {
                return parse_sell_state(rs);
            }
            None
        }
        BRACKET_RS_SIZE => {
            // Bracket v18: SAME 224B state layout as v1 (oco_spk pins a v18
            // OCO P2SH), selector-dispatch body starting with Op11 OpRoll
            // (0x5b 0x7a — same signature bytes as the OCO sell body, which
            // is unambiguous because the RS lengths differ; pinned by the
            // v18_rs_lengths_no_collision test).
            if rs[BRACKET_STATE_SIZE] == 0x5b && rs[BRACKET_STATE_SIZE + 1] == 0x7a {
                return parse_bracket_state(rs).map(|mut o| {
                    o.version = crate::contract::spot::SPOT_GENERATION as u8;
                    o
                });
            }
            None
        }
        _ => None,
    }
}

/// Try to parse a v18 OCO sell redeemScript (the core 139B layout preceded
/// by `[0x20][otspkh 32B]`).
///
/// Returns `None` if the RS is not a v18 OCO sell (wrong size or signature).
pub fn parse_oco_sell_redeem_script(rs: &[u8]) -> Option<ParsedOcoSell> {
    if rs.len() == OCO_SELL_RS_SIZE {
        // v18 body signature: 0x5c 0x7a (Op12 OpRoll) at offset 172
        if rs[OCO_SELL_STATE_SIZE] != 0x5c || rs[OCO_SELL_STATE_SIZE + 1] != 0x7a {
            return None;
        }
        return parse_oco_sell_state(rs, 33);
    }
    None
}

/// Parse buy state (145B v14/v16/v17 layout at offset `base`).
///
/// State layout (relative to `base`):
///   [0x20][tcid 32B]    = bytes 0..33
///   [0x08][pnum 8B]     = bytes 33..42
///   [0x08][pden 8B]     = bytes 42..51
///   [0x08][mfill 8B]    = bytes 51..60
///   [0x20][ohash 32B]   = bytes 60..93
///   [0x20][bspkh 32B]   = bytes 93..126
///   [0x08][mmfee 8B]    = bytes 126..135
///   [cpend 1B]          = byte 135
///   [0x08][expiry 8B]   = bytes 136..145
/// Parse a v18 buy state (178B): `[0x20][okspkh 32B]` + the 145B layout.
fn parse_buy_state(rs: &[u8]) -> Option<ParsedOrder> {
    if rs.len() < BUY_ORDER_STATE_SIZE {
        return None;
    }
    if rs[0] != 0x20 {
        return None;
    }
    let mut seat = [0u8; 32];
    seat.copy_from_slice(&rs[1..33]);
    let mut o = parse_buy_state_at(rs, 33)?;
    o.version = crate::contract::spot::SPOT_GENERATION as u8;
    o.owner_seat_hash = Some(seat);
    Some(o)
}

fn parse_buy_state_at(rs: &[u8], base: usize) -> Option<ParsedOrder> {
    if rs.len() < base + BUY_STATE_SIZE {
        return None;
    }
    let s = &rs[base..];

    if s[0] != 0x20 { return None; }
    if s[33] != 0x08 || s[42] != 0x08 || s[51] != 0x08 { return None; }
    if s[60] != 0x20 || s[93] != 0x20 { return None; }
    if s[126] != 0x08 { return None; }
    if s[136] != 0x08 { return None; }

    let mut tcid = [0u8; 32];
    tcid.copy_from_slice(&s[1..33]);

    let pnum = u64::from_le_bytes(s[34..42].try_into().ok()?);
    let pden = u64::from_le_bytes(s[43..51].try_into().ok()?);
    let mfill = u64::from_le_bytes(s[52..60].try_into().ok()?);

    let mut ohash = [0u8; 32];
    ohash.copy_from_slice(&s[61..93]);

    let mut bspkh = [0u8; 32];
    bspkh.copy_from_slice(&s[94..126]);

    let mmfee = u64::from_le_bytes(s[127..135].try_into().ok()?);

    let cpend = match s[135] {
        0x00 => 0,
        0x51 => 1,
        _ => return None,
    };

    let expiry_daa = u64::from_le_bytes(s[137..145].try_into().ok()?);

    if pnum == 0 || pden == 0 || mfill == 0 {
        return None;
    }

    Some(ParsedOrder {
        order_type: OrderSide::Buy,
        version: 0,
        token_cov_id: tcid,
        price_num: pnum,
        price_den: pden,
        min_fill: mfill,
        owner_hash: ohash,
        spk_hash: bspkh,
        _max_matcher_fee: mmfee,
        cpend,
        requires_zk: has_zk_opcode(rs, base + BUY_STATE_SIZE),
        redeem_script: rs.to_vec(),
        post_only: false,
        expiry_daa: if expiry_daa > 0 { Some(expiry_daa) } else { None },
        ifd_order_b_rs: None,
        owner_seat_hash: None,
    })
}

/// Parse sell state (112B v14 layout at offset `base`).
///
/// State layout (relative to `base`):
///   [0x08][pnum 8B]     = bytes 0..9
///   [0x08][pden 8B]     = bytes 9..18
///   [0x08][mfill 8B]    = bytes 18..27
///   [0x20][ohash 32B]   = bytes 27..60
///   [0x20][sspkh 32B]   = bytes 60..93
///   [0x08][mmfee 8B]    = bytes 93..102
///   [cpend 1B]          = byte 102
///   [0x08][expiry 8B]   = bytes 103..112
/// Parse a v18 sell state (145B): `[0x20][otspkh 32B]` + the 112B layout.
fn parse_sell_state(rs: &[u8]) -> Option<ParsedOrder> {
    if rs.len() < SELL_ORDER_STATE_SIZE {
        return None;
    }
    if rs[0] != 0x20 {
        return None;
    }
    let mut seat = [0u8; 32];
    seat.copy_from_slice(&rs[1..33]);
    let mut o = parse_sell_state_at(rs, 33)?;
    o.version = crate::contract::spot::SPOT_GENERATION as u8;
    o.owner_seat_hash = Some(seat);
    Some(o)
}

fn parse_sell_state_at(rs: &[u8], base: usize) -> Option<ParsedOrder> {
    if rs.len() < base + SELL_STATE_SIZE {
        return None;
    }
    let s = &rs[base..];

    if s[0] != 0x08 || s[9] != 0x08 || s[18] != 0x08 { return None; }
    if s[27] != 0x20 || s[60] != 0x20 { return None; }
    if s[93] != 0x08 { return None; }
    if s[103] != 0x08 { return None; }

    let pnum = u64::from_le_bytes(s[1..9].try_into().ok()?);
    let pden = u64::from_le_bytes(s[10..18].try_into().ok()?);
    let mfill = u64::from_le_bytes(s[19..27].try_into().ok()?);

    let mut ohash = [0u8; 32];
    ohash.copy_from_slice(&s[28..60]);

    let mut sspkh = [0u8; 32];
    sspkh.copy_from_slice(&s[61..93]);

    let mmfee = u64::from_le_bytes(s[94..102].try_into().ok()?);

    let cpend = match s[102] {
        0x00 => 0,
        0x51 => 1,
        _ => return None,
    };

    let expiry_daa = u64::from_le_bytes(s[104..112].try_into().ok()?);

    if pnum == 0 || pden == 0 || mfill == 0 {
        return None;
    }

    Some(ParsedOrder {
        order_type: OrderSide::Sell,
        version: 0,
        token_cov_id: [0u8; 32],
        price_num: pnum,
        price_den: pden,
        min_fill: mfill,
        owner_hash: ohash,
        spk_hash: sspkh,
        _max_matcher_fee: mmfee,
        cpend,
        requires_zk: has_zk_opcode(rs, base + SELL_STATE_SIZE),
        redeem_script: rs.to_vec(),
        post_only: false,
        expiry_daa: if expiry_daa > 0 { Some(expiry_daa) } else { None },
        ifd_order_b_rs: None,
        owner_seat_hash: None,
    })
}

/// Parse bracket order state (224B) into a `ParsedOrder`.
///
/// The bracket entry leg is a buy (entry_type=0) or sell (entry_type=1) order
/// from the matcher's perspective. The exit parameters (oco_spk, receipt_cov_id,
/// etc.) are not needed for order-book matching and are ignored here.
///
/// State layout (224B):
///   [0x08][entry_type 8B]        = bytes 0..9
///   [0x20][token_cov_id 32B]     = bytes 9..42
///   [0x08][epnum 8B]             = bytes 42..51
///   [0x08][epden 8B]             = bytes 51..60
///   [0x25][oco_spk 37B]          = bytes 60..98
///   [0x08][oco_min_val 8B]       = bytes 98..107
///   [0x08][min_fill 8B]          = bytes 107..116
///   [0x08][min_receipt_val 8B]   = bytes 116..125
///   [0x20][receipt_cov_id 32B]   = bytes 125..158
///   [0x20][trade_spk_hash 32B]   = bytes 158..191
///   [0x20][owner_hash 32B]       = bytes 191..224
fn parse_bracket_state(rs: &[u8]) -> Option<ParsedOrder> {
    if rs.len() < BRACKET_STATE_SIZE {
        return None;
    }

    // Verify push-size markers
    if rs[0] != 0x08 { return None; }   // entry_type
    if rs[9] != 0x20 { return None; }   // token_cov_id
    if rs[42] != 0x08 { return None; }  // epnum
    if rs[51] != 0x08 { return None; }  // epden
    if rs[60] != 0x25 { return None; }  // oco_spk (37 bytes)
    if rs[98] != 0x08 { return None; }  // oco_min_val
    if rs[107] != 0x08 { return None; } // min_fill
    if rs[116] != 0x08 { return None; } // min_receipt_val
    if rs[125] != 0x20 { return None; } // receipt_cov_id
    if rs[158] != 0x20 { return None; } // trade_spk_hash
    if rs[191] != 0x20 { return None; } // owner_hash

    let entry_type = u64::from_le_bytes(rs[1..9].try_into().ok()?);

    let mut tcid = [0u8; 32];
    tcid.copy_from_slice(&rs[10..42]);

    let pnum = u64::from_le_bytes(rs[43..51].try_into().ok()?);
    let pden = u64::from_le_bytes(rs[52..60].try_into().ok()?);

    let mfill = u64::from_le_bytes(rs[108..116].try_into().ok()?);

    let mut trade_spk_hash = [0u8; 32];
    trade_spk_hash.copy_from_slice(&rs[159..191]);

    let mut ohash = [0u8; 32];
    ohash.copy_from_slice(&rs[192..224]);

    if pnum == 0 || pden == 0 || mfill == 0 {
        return None;
    }

    // entry_type 0 = buy, 1 = sell
    let side = if entry_type == 0 {
        OrderSide::Buy
    } else {
        OrderSide::Sell
    };

    Some(ParsedOrder {
        order_type: side,
        version: 0,
        // Buy entries carry the token_cov_id; sell entries use [0;32]
        // (same convention as regular orders).
        token_cov_id: if side == OrderSide::Buy { tcid } else { [0u8; 32] },
        price_num: pnum,
        price_den: pden,
        min_fill: mfill,
        owner_hash: ohash,
        spk_hash: trade_spk_hash,
        _max_matcher_fee: 0,
        cpend: 0,
        requires_zk: has_zk_opcode(rs, BRACKET_STATE_SIZE),
        redeem_script: rs.to_vec(),
        post_only: false,
        expiry_daa: None,
        ifd_order_b_rs: None,
        owner_seat_hash: None,
    })
}

/// Parse OCO sell state (139B v1 layout at offset `base`; v18 prefixes it
/// with `[0x20][otspkh 32B]`, `base` = 33).
///
/// State layout (relative to `base`):
///   [0x08][pnum_tp 8B]   = bytes 0..9
///   [0x08][pden_tp 8B]   = bytes 9..18
///   [0x08][mfill_tp 8B]  = bytes 18..27
///   [0x08][pnum_sl 8B]   = bytes 27..36
///   [0x08][pden_sl 8B]   = bytes 36..45
///   [0x08][mfill_sl 8B]  = bytes 45..54
///   [0x20][ohash 32B]    = bytes 54..87
///   [0x20][sspkh 32B]    = bytes 87..120
///   [0x08][mmfee 8B]     = bytes 120..129
///   [cpend 1B]           = byte 129
///   [0x08][expiry 8B]    = bytes 130..139
fn parse_oco_sell_state(rs: &[u8], base: usize) -> Option<ParsedOcoSell> {
    if rs.len() < base + OCO_SELL_CORE_STATE_SIZE {
        return None;
    }
    let seat: Option<[u8; 32]> = if base > 0 {
        if rs[0] != 0x20 {
            return None;
        }
        let mut a = [0u8; 32];
        a.copy_from_slice(&rs[1..33]);
        Some(a)
    } else {
        None
    };
    let s = &rs[base..];
    // Verify push-size markers
    if s[0] != 0x08 || s[9] != 0x08 || s[18] != 0x08 { return None; }
    if s[27] != 0x08 || s[36] != 0x08 || s[45] != 0x08 { return None; }
    if s[54] != 0x20 || s[87] != 0x20 { return None; }
    if s[120] != 0x08 { return None; }
    if s[130] != 0x08 { return None; }

    let pnum_tp = u64::from_le_bytes(s[1..9].try_into().ok()?);
    let pden_tp = u64::from_le_bytes(s[10..18].try_into().ok()?);
    let mfill_tp = u64::from_le_bytes(s[19..27].try_into().ok()?);
    let pnum_sl = u64::from_le_bytes(s[28..36].try_into().ok()?);
    let pden_sl = u64::from_le_bytes(s[37..45].try_into().ok()?);
    let mfill_sl = u64::from_le_bytes(s[46..54].try_into().ok()?);

    let mut ohash = [0u8; 32];
    ohash.copy_from_slice(&s[55..87]);

    let mut sspkh = [0u8; 32];
    sspkh.copy_from_slice(&s[88..120]);

    let mmfee = u64::from_le_bytes(s[121..129].try_into().ok()?);

    let cpend = match s[129] {
        0x00 => 0,
        0x51 => 1,
        _ => return None,
    };

    let expiry_daa_raw = u64::from_le_bytes(s[131..139].try_into().ok()?);

    if pnum_tp == 0 || pden_tp == 0 || mfill_tp == 0 { return None; }
    if pnum_sl == 0 || pden_sl == 0 || mfill_sl == 0 { return None; }

    Some(ParsedOcoSell {
        price_num_tp: pnum_tp,
        price_den_tp: pden_tp,
        min_fill_tp: mfill_tp,
        price_num_sl: pnum_sl,
        price_den_sl: pden_sl,
        min_fill_sl: mfill_sl,
        owner_hash: ohash,
        spk_hash: sspkh,
        _max_matcher_fee: mmfee,
        cpend,
        expiry_daa: if expiry_daa_raw > 0 { Some(expiry_daa_raw) } else { None },
        redeem_script: rs.to_vec(),
        owner_seat_hash: seat,
    })
}

/// Convert a `ParsedOcoSell` into a `ParsedOrder` for a specific path.
///
/// The scanner uses this to register virtual orders in the order book.
impl ParsedOcoSell {
    /// Convert to a ParsedOrder for the given OCO path.
    pub fn to_parsed_order(&self, path: OcoPath) -> ParsedOrder {
        let (pnum, pden, mfill) = match path {
            OcoPath::TakeProfit => (self.price_num_tp, self.price_den_tp, self.min_fill_tp),
            OcoPath::StopLoss => (self.price_num_sl, self.price_den_sl, self.min_fill_sl),
        };
        ParsedOrder {
            order_type: OrderSide::Sell,
            version: 0,
            token_cov_id: [0u8; 32], // sell orders have no tcid in state
            price_num: pnum,
            price_den: pden,
            min_fill: mfill,
            owner_hash: self.owner_hash,
            spk_hash: self.spk_hash,
            _max_matcher_fee: self._max_matcher_fee,
            cpend: self.cpend,
            requires_zk: false,
            redeem_script: self.redeem_script.clone(),
            post_only: false,
            expiry_daa: self.expiry_daa,
            ifd_order_b_rs: None,
            owner_seat_hash: self.owner_seat_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::spot::order::{build_buy_redeem_script, build_sell_redeem_script};

    #[test]
    fn roundtrip_buy() {
        let tcid = [0xAA; 32];
        let ohash = [0xBB; 32];
        let bspkh = [0xCC; 32];
        let okspkh = [0xDD; 32];
        let rs = build_buy_redeem_script(&tcid, 3, 2, 1_000_000, &ohash, &bspkh, &okspkh, 50, 0, 0).unwrap();
        assert_eq!(rs.len(), BUY_ORDER_RS_EXPECTED_LEN);
        let parsed = parse_redeem_script(&rs).expect("should parse buy");
        assert_eq!(parsed.order_type, OrderSide::Buy);
        assert_eq!(parsed.version, 18);
        assert_eq!(parsed.token_cov_id, tcid);
        assert_eq!(parsed.price_num, 3);
        assert_eq!(parsed.price_den, 2);
        assert_eq!(parsed.min_fill, 1_000_000);
        assert_eq!(parsed.owner_hash, ohash);
        assert_eq!(parsed.spk_hash, bspkh);
        assert_eq!(parsed.owner_seat_hash, Some(okspkh));
        assert_eq!(parsed._max_matcher_fee, 50);
        assert_eq!(parsed.cpend, 0);
        assert_eq!(parsed.expiry_daa, None);
    }

    #[test]
    fn roundtrip_sell() {
        let ohash = [0xDD; 32];
        let sspkh = [0xEE; 32];
        let otspkh = [0xAB; 32];
        let rs = build_sell_redeem_script(5, 3, 2_000_000, &ohash, &sspkh, &otspkh, 25, 0, 0).unwrap();
        assert_eq!(rs.len(), SELL_ORDER_RS_EXPECTED_LEN);
        let parsed = parse_redeem_script(&rs).expect("should parse sell");
        assert_eq!(parsed.order_type, OrderSide::Sell);
        assert_eq!(parsed.version, 18);
        assert_eq!(parsed.price_num, 5);
        assert_eq!(parsed.price_den, 3);
        assert_eq!(parsed.min_fill, 2_000_000);
        assert_eq!(parsed.owner_hash, ohash);
        assert_eq!(parsed.spk_hash, sspkh);
        assert_eq!(parsed.owner_seat_hash, Some(otspkh));
        assert_eq!(parsed.cpend, 0);
    }

    #[test]
    fn buy_with_expiry() {
        let t = [0u8; 32];
        let rs = build_buy_redeem_script(&t, 1, 2, 1, &t, &t, &t, 100, 0, 999_999).unwrap();
        let parsed = parse_redeem_script(&rs).expect("should parse");
        assert_eq!(parsed.expiry_daa, Some(999_999));
    }

    #[test]
    fn sell_with_cpend() {
        let t = [0u8; 32];
        let rs = build_sell_redeem_script(1, 2, 1, &t, &t, &t, 0, 1, 0).unwrap();
        let parsed = parse_redeem_script(&rs).expect("should parse");
        assert_eq!(parsed.cpend, 1);
    }

    #[test]
    fn wrong_size_returns_none() {
        // Unknown RS lengths (incl. the retired v14 buy 396 / sell 427 /
        // v16 476 / v17 838 / bracket v1 365 / OCO v1 333 / swap v1 243)
        // must parse to None — clean rejection, no legacy fallback.
        for len in [100usize, 243, 333, 365, 396, 427, 476, 838] {
            assert!(parse_redeem_script(&vec![0x51; len]).is_none(), "len {len}");
        }
    }

    #[test]
    fn has_zk_opcode_positive() {
        assert!(has_zk_opcode(&[0x51, 0xa6, 0x87], 1));
    }

    #[test]
    fn has_zk_opcode_negative() {
        assert!(!has_zk_opcode(&[0x51, 0x52, 0x87], 1));
    }

    #[test]
    fn has_zk_opcode_ignores_state_section() {
        assert!(!has_zk_opcode(&[0x51, 0xa6, 0x52, 0x87, 0x69], 3));
    }

    #[test]
    fn has_zk_opcode_false_for_buy_and_sell() {
        // Worst case: state hashes full of 0xa6 must not leak into the body scan.
        let h = [0xa6; 32];
        let buy = build_buy_redeem_script(&h, 1, 20, 1_000_000, &h, &h, &h, 50, 0, 0).unwrap();
        assert!(!has_zk_opcode(&buy, BUY_ORDER_STATE_SIZE));
        let sell = build_sell_redeem_script(1, 20, 1_000_000, &h, &h, &h, 50, 0, 0).unwrap();
        assert!(!has_zk_opcode(&sell, SELL_ORDER_STATE_SIZE));
    }

    #[test]
    fn roundtrip_oco_sell() {
        use crate::contract::spot::oco::{build_oco_sell_redeem_script, OCO_SELL_RS_SIZE};
        let ohash = [0xAA; 32];
        let sspkh = [0xBB; 32];
        let otspkh = [0xCD; 32];
        let rs = build_oco_sell_redeem_script(
            5, 1, 500_000,   // TP: price 5/1, mfill 500k
            2, 1, 200_000,   // SL: price 2/1, mfill 200k
            &ohash, &sspkh, &otspkh, 30, 0, 0,
        ).unwrap();
        assert_eq!(rs.len(), OCO_SELL_RS_SIZE);

        let parsed = parse_oco_sell_redeem_script(&rs).expect("should parse OCO sell");
        assert_eq!(parsed.price_num_tp, 5);
        assert_eq!(parsed.price_den_tp, 1);
        assert_eq!(parsed.min_fill_tp, 500_000);
        assert_eq!(parsed.price_num_sl, 2);
        assert_eq!(parsed.price_den_sl, 1);
        assert_eq!(parsed.min_fill_sl, 200_000);
        assert_eq!(parsed.owner_hash, ohash);
        assert_eq!(parsed.spk_hash, sspkh);
        assert_eq!(parsed.owner_seat_hash, Some(otspkh));
        assert_eq!(parsed._max_matcher_fee, 30);
        assert_eq!(parsed.cpend, 0);
        assert_eq!(parsed.expiry_daa, None);

        let tp = parsed.to_parsed_order(OcoPath::TakeProfit);
        assert_eq!(tp.order_type, OrderSide::Sell);
        assert_eq!(tp.price_num, 5);
        assert_eq!(tp.price_den, 1);
        assert_eq!(tp.min_fill, 500_000);
        assert_eq!(tp.owner_seat_hash, Some(otspkh));

        let sl = parsed.to_parsed_order(OcoPath::StopLoss);
        assert_eq!(sl.price_num, 2);
        assert_eq!(sl.price_den, 1);
        assert_eq!(sl.min_fill, 200_000);
    }

    #[test]
    fn oco_sell_gcd_normalization() {
        use crate::contract::spot::oco::build_oco_sell_redeem_script;
        let t = [0u8; 32];
        let rs = build_oco_sell_redeem_script(
            10, 4, 100,  // TP: 10/4 -> 5/2
            6, 9, 100,   // SL: 6/9 -> 2/3
            &t, &t, &t, 0, 0, 0,
        ).unwrap();
        let parsed = parse_oco_sell_redeem_script(&rs).expect("should parse");
        assert_eq!(parsed.price_num_tp, 5);
        assert_eq!(parsed.price_den_tp, 2);
        assert_eq!(parsed.price_num_sl, 2);
        assert_eq!(parsed.price_den_sl, 3);
    }

    #[test]
    fn oco_sell_wrong_size_returns_none() {
        // Incl. the retired v1 OCO length (333B).
        assert!(parse_oco_sell_redeem_script(&vec![0x51; 200]).is_none());
        assert!(parse_oco_sell_redeem_script(&vec![0x51; 333]).is_none());
    }

    #[test]
    fn oco_sell_wrong_signature_returns_none() {
        use crate::contract::spot::oco::OCO_SELL_RS_SIZE;
        // Right size but wrong body signature bytes at the v18 offset.
        let mut fake = vec![0x08; OCO_SELL_RS_SIZE];
        fake[OCO_SELL_STATE_SIZE] = 0x58;
        fake[OCO_SELL_STATE_SIZE + 1] = 0x7a;
        assert!(parse_oco_sell_redeem_script(&fake).is_none());
    }

    #[test]
    fn roundtrip_bracket_buy_and_sell() {
        use crate::contract::spot::bracket::build_bracket_redeem_script;
        let tcid = [0xAA; 32];
        let ohash = [0xBB; 32];
        let tspkh = [0xCC; 32];
        let oco_spk = [0xDD; 37];
        let rcid = [0xEE; 32];
        for (etype, side) in [(0u64, OrderSide::Buy), (1u64, OrderSide::Sell)] {
            let rs = build_bracket_redeem_script(
                etype, &tcid, 3, 2, &oco_spk, 500_000, 1_000_000, 100, &rcid, &tspkh, &ohash,
            )
            .unwrap();
            assert_eq!(rs.len(), BRACKET_RS_SIZE);
            let parsed = parse_redeem_script(&rs).expect("should parse v18 bracket");
            assert_eq!(parsed.order_type, side);
            assert_eq!(parsed.version, 18, "v18 bracket must report version 18");
            assert_eq!(
                parsed.token_cov_id,
                if side == OrderSide::Buy { tcid } else { [0u8; 32] }
            );
            assert_eq!(parsed.price_num, 3);
            assert_eq!(parsed.price_den, 2);
            assert_eq!(parsed.min_fill, 1_000_000);
            assert_eq!(parsed.owner_hash, ohash);
            assert_eq!(parsed.spk_hash, tspkh);
        }
    }

    #[test]
    fn bracket_wrong_signature_returns_none() {
        use crate::contract::spot::bracket::build_bracket_redeem_script;
        let t32 = [0x11; 32];
        let mut rs = build_bracket_redeem_script(
            0, &t32, 1, 1, &[0x22; 37], 1, 1, 1, &t32, &t32, &t32,
        )
        .unwrap();
        rs[BRACKET_STATE_SIZE] = 0xb9; // v1-style preamble instead of Op11 OpRoll
        rs[BRACKET_STATE_SIZE + 1] = 0xc9;
        assert!(parse_redeem_script(&rs).is_none());
    }

    #[test]
    fn bracket_rejects_invalid_builder_args() {
        use crate::contract::spot::bracket::build_bracket_redeem_script;
        let t32 = [0x11; 32];
        let spk = [0x22; 37];
        assert!(build_bracket_redeem_script(2, &t32, 1, 1, &spk, 1, 1, 1, &t32, &t32, &t32).is_err());
        assert!(build_bracket_redeem_script(0, &t32, 0, 1, &spk, 1, 1, 1, &t32, &t32, &t32).is_err());
        assert!(build_bracket_redeem_script(0, &t32, 1, 0, &spk, 1, 1, 1, &t32, &t32, &t32).is_err());
        assert!(build_bracket_redeem_script(0, &t32, 1, 1, &spk, 1, 0, 1, &t32, &t32, &t32).is_err());
    }
}
