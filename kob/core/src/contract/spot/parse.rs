//! Parse spot order redeemScripts to extract on-chain state.

use crate::types::OrderSide;

/// OpZkPrecompile opcode byte (0xa6).
pub const OP_ZK_PRECOMPILE: u8 = 0xa6;

/// Check whether a redeemScript contains the ZK precompile opcode.
pub fn has_zk_opcode(redeem_script: &[u8]) -> bool {
    redeem_script.contains(&OP_ZK_PRECOMPILE)
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
}

/// Buy state size: 145B.
const BUY_STATE_SIZE: usize = 145;
/// Sell state size: 112B.
const SELL_STATE_SIZE: usize = 112;

/// Buy body size (v14: IOC path added, +9B).
const BUY_BODY_SIZE: usize = 251;
/// Sell body size (v14: IOC path added, +60B).
const SELL_BODY_SIZE: usize = 304;

/// Buy RS size: 145 + 251 = 396.
pub const BUY_RS_SIZE: usize = BUY_STATE_SIZE + BUY_BODY_SIZE;
/// Sell RS size: 112 + 304 = 416.
pub const SELL_RS_SIZE: usize = SELL_STATE_SIZE + SELL_BODY_SIZE;

/// Parse a redeemScript to extract order parameters.
///
/// Identifies the contract type by RS length and body signature bytes,
/// then extracts parameters from the fixed-offset state portion.
pub fn parse_redeem_script(rs: &[u8]) -> Option<ParsedOrder> {
    match rs.len() {
        BUY_RS_SIZE => {
            // Buy: body starts at offset 145, signature 0xb9 0xc9
            if rs[BUY_STATE_SIZE] == 0xb9 && rs[BUY_STATE_SIZE + 1] == 0xc9
                && rs[BUY_STATE_SIZE + 2] == 0x76
            {
                return parse_buy_state(rs);
            }
            None
        }
        SELL_RS_SIZE => {
            // Sell: body starts at offset 112, signature 0x58 0x7a (Op8 OpRoll)
            if rs[SELL_STATE_SIZE] == 0x58 && rs[SELL_STATE_SIZE + 1] == 0x7a {
                return parse_sell_state(rs);
            }
            None
        }
        _ => None,
    }
}

/// Parse buy state (145B).
///
/// State layout:
///   [0x20][tcid 32B]    = bytes 0..33
///   [0x08][pnum 8B]     = bytes 33..42
///   [0x08][pden 8B]     = bytes 42..51
///   [0x08][mfill 8B]    = bytes 51..60
///   [0x20][ohash 32B]   = bytes 60..93
///   [0x20][bspkh 32B]   = bytes 93..126
///   [0x08][mmfee 8B]    = bytes 126..135
///   [cpend 1B]          = byte 135
///   [0x08][expiry 8B]   = bytes 136..145
fn parse_buy_state(rs: &[u8]) -> Option<ParsedOrder> {
    if rs.len() < BUY_STATE_SIZE {
        return None;
    }

    if rs[0] != 0x20 { return None; }
    if rs[33] != 0x08 || rs[42] != 0x08 || rs[51] != 0x08 { return None; }
    if rs[60] != 0x20 || rs[93] != 0x20 { return None; }
    if rs[126] != 0x08 { return None; }
    if rs[136] != 0x08 { return None; }

    let mut tcid = [0u8; 32];
    tcid.copy_from_slice(&rs[1..33]);

    let pnum = u64::from_le_bytes(rs[34..42].try_into().ok()?);
    let pden = u64::from_le_bytes(rs[43..51].try_into().ok()?);
    let mfill = u64::from_le_bytes(rs[52..60].try_into().ok()?);

    let mut ohash = [0u8; 32];
    ohash.copy_from_slice(&rs[61..93]);

    let mut bspkh = [0u8; 32];
    bspkh.copy_from_slice(&rs[94..126]);

    let mmfee = u64::from_le_bytes(rs[127..135].try_into().ok()?);

    let cpend = match rs[135] {
        0x00 => 0,
        0x51 => 1,
        _ => return None,
    };

    let expiry_daa = u64::from_le_bytes(rs[137..145].try_into().ok()?);

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
        requires_zk: has_zk_opcode(rs),
        redeem_script: rs.to_vec(),
        post_only: false,
        expiry_daa: if expiry_daa > 0 { Some(expiry_daa) } else { None },
        ifd_order_b_rs: None,
    })
}

/// Parse sell state (112B).
///
/// State layout:
///   [0x08][pnum 8B]     = bytes 0..9
///   [0x08][pden 8B]     = bytes 9..18
///   [0x08][mfill 8B]    = bytes 18..27
///   [0x20][ohash 32B]   = bytes 27..60
///   [0x20][sspkh 32B]   = bytes 60..93
///   [0x08][mmfee 8B]    = bytes 93..102
///   [cpend 1B]          = byte 102
///   [0x08][expiry 8B]   = bytes 103..112
fn parse_sell_state(rs: &[u8]) -> Option<ParsedOrder> {
    if rs.len() < SELL_STATE_SIZE {
        return None;
    }

    if rs[0] != 0x08 || rs[9] != 0x08 || rs[18] != 0x08 { return None; }
    if rs[27] != 0x20 || rs[60] != 0x20 { return None; }
    if rs[93] != 0x08 { return None; }
    if rs[103] != 0x08 { return None; }

    let pnum = u64::from_le_bytes(rs[1..9].try_into().ok()?);
    let pden = u64::from_le_bytes(rs[10..18].try_into().ok()?);
    let mfill = u64::from_le_bytes(rs[19..27].try_into().ok()?);

    let mut ohash = [0u8; 32];
    ohash.copy_from_slice(&rs[28..60]);

    let mut sspkh = [0u8; 32];
    sspkh.copy_from_slice(&rs[61..93]);

    let mmfee = u64::from_le_bytes(rs[94..102].try_into().ok()?);

    let cpend = match rs[102] {
        0x00 => 0,
        0x51 => 1,
        _ => return None,
    };

    let expiry_daa = u64::from_le_bytes(rs[104..112].try_into().ok()?);

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
        requires_zk: has_zk_opcode(rs),
        redeem_script: rs.to_vec(),
        post_only: false,
        expiry_daa: if expiry_daa > 0 { Some(expiry_daa) } else { None },
        ifd_order_b_rs: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{build_buy_redeem_script, build_sell_redeem_script};

    #[test]
    fn roundtrip_buy() {
        let tcid = [0xAA; 32];
        let ohash = [0xBB; 32];
        let bspkh = [0xCC; 32];
        let rs = build_buy_redeem_script(&tcid, 3, 2, 1_000_000, &ohash, &bspkh, 50_000, 0, 0).unwrap();
        assert_eq!(rs.len(), BUY_RS_SIZE);
        let parsed = parse_redeem_script(&rs).expect("should parse buy");
        assert_eq!(parsed.order_type, OrderSide::Buy);
        assert_eq!(parsed.token_cov_id, tcid);
        assert_eq!(parsed.price_num, 3);
        assert_eq!(parsed.price_den, 2);
        assert_eq!(parsed.min_fill, 1_000_000);
        assert_eq!(parsed.owner_hash, ohash);
        assert_eq!(parsed.spk_hash, bspkh);
        assert_eq!(parsed._max_matcher_fee, 50_000);
        assert_eq!(parsed.cpend, 0);
        assert_eq!(parsed.expiry_daa, None);
    }

    #[test]
    fn roundtrip_sell() {
        let ohash = [0xDD; 32];
        let sspkh = [0xEE; 32];
        let rs = build_sell_redeem_script(5, 3, 2_000_000, &ohash, &sspkh, 0, 0, 0).unwrap();
        assert_eq!(rs.len(), SELL_RS_SIZE);
        let parsed = parse_redeem_script(&rs).expect("should parse sell");
        assert_eq!(parsed.order_type, OrderSide::Sell);
        assert_eq!(parsed.price_num, 5);
        assert_eq!(parsed.price_den, 3);
        assert_eq!(parsed.min_fill, 2_000_000);
        assert_eq!(parsed.owner_hash, ohash);
        assert_eq!(parsed.spk_hash, sspkh);
        assert_eq!(parsed.cpend, 0);
    }

    #[test]
    fn buy_with_expiry() {
        let t = [0u8; 32];
        let rs = build_buy_redeem_script(&t, 1, 2, 1, &t, &t, 100, 0, 999_999).unwrap();
        let parsed = parse_redeem_script(&rs).expect("should parse");
        assert_eq!(parsed.expiry_daa, Some(999_999));
    }

    #[test]
    fn sell_with_cpend() {
        let t = [0u8; 32];
        let rs = build_sell_redeem_script(1, 2, 1, &t, &t, 0, 1, 0).unwrap();
        let parsed = parse_redeem_script(&rs).expect("should parse");
        assert_eq!(parsed.cpend, 1);
    }

    #[test]
    fn wrong_size_returns_none() {
        assert!(parse_redeem_script(&vec![0x51; 100]).is_none());
    }

    #[test]
    fn has_zk_opcode_positive() {
        assert!(has_zk_opcode(&[0x51, 0xa6, 0x87]));
    }

    #[test]
    fn has_zk_opcode_negative() {
        assert!(!has_zk_opcode(&[0x51, 0x52, 0x87]));
    }
}
