//! Parse perp deploy redeemScripts to extract on-chain state.

/// Side of a perpetual futures deploy order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerpDeploySide {
    Long,
    Short,
}

/// Parsed perp deploy order from redeemScript.
#[derive(Debug, Clone)]
pub struct ParsedPerpOrder {
    pub side: PerpDeploySide,
    pub owner_spk_hash: [u8; 32],
    pub price_num: u64,
    pub price_den: u64,
    pub maint_pct_num: u64,
    pub maint_pct_den: u64,
    pub keeper_fee: u64,
    pub emergency_daa: u64,
    pub min_fill: u64,
    pub max_matcher_fee: u64,
    pub redeem_script: Vec<u8>,
}

/// Perp deploy v1 state size.
pub const PERP_DEPLOY_V1_STATE_SIZE: usize = 105;
/// Perp deploy body size.
const PERP_DEPLOY_BODY_SIZE: usize = 107;
/// Perp deploy total RS size.
pub const PERP_DEPLOY_V1_RS_SIZE: usize = PERP_DEPLOY_V1_STATE_SIZE + PERP_DEPLOY_BODY_SIZE; // 212

/// Parse a perp_deploy_v1 redeemScript to extract order parameters.
///
/// Side defaults to Long; callers should override from payload metadata.
pub fn parse_perp_deploy_rs(rs: &[u8]) -> Option<ParsedPerpOrder> {
    if rs.len() != PERP_DEPLOY_V1_RS_SIZE {
        return None;
    }

    // Body signature check: 0xb9 0xc9 0x76
    let body_start = PERP_DEPLOY_V1_STATE_SIZE;
    if rs[body_start] != 0xb9 || rs[body_start + 1] != 0xc9 || rs[body_start + 2] != 0x76 {
        return None;
    }

    // Validate push prefixes
    if rs[0] != 0x20 { return None; }
    for &offset in &[33, 42, 51, 60, 69, 78, 87, 96] {
        if rs[offset] != 0x08 { return None; }
    }

    let mut owner_spk_hash = [0u8; 32];
    owner_spk_hash.copy_from_slice(&rs[1..33]);

    let price_num = u64::from_le_bytes(rs[34..42].try_into().ok()?);
    let price_den = u64::from_le_bytes(rs[43..51].try_into().ok()?);
    let maint_pct_num = u64::from_le_bytes(rs[52..60].try_into().ok()?);
    let maint_pct_den = u64::from_le_bytes(rs[61..69].try_into().ok()?);
    let keeper_fee = u64::from_le_bytes(rs[70..78].try_into().ok()?);
    let emergency_daa = u64::from_le_bytes(rs[79..87].try_into().ok()?);
    let min_fill = u64::from_le_bytes(rs[88..96].try_into().ok()?);
    let max_matcher_fee = u64::from_le_bytes(rs[97..105].try_into().ok()?);

    if price_den == 0 || maint_pct_den == 0 || min_fill == 0 {
        return None;
    }

    Some(ParsedPerpOrder {
        side: PerpDeploySide::Long,
        owner_spk_hash,
        price_num,
        price_den,
        maint_pct_num,
        maint_pct_den,
        keeper_fee,
        emergency_daa,
        min_fill,
        max_matcher_fee,
        redeem_script: rs.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::perp::build_perp_deploy_redeem_script;

    #[test]
    fn roundtrip_perp_deploy() {
        let owner = [0xAA; 32];
        let rs = build_perp_deploy_redeem_script(
            &owner, 100, 1, 5, 100, 50_000, 100_000, 1_000_000, 10_000,
        );
        assert_eq!(rs.len(), PERP_DEPLOY_V1_RS_SIZE);

        let parsed = parse_perp_deploy_rs(&rs).expect("should parse");
        assert_eq!(parsed.side, PerpDeploySide::Long);
        assert_eq!(parsed.owner_spk_hash, owner);
        assert_eq!(parsed.price_num, 100);
        assert_eq!(parsed.price_den, 1);
        assert_eq!(parsed.maint_pct_num, 5);
        assert_eq!(parsed.maint_pct_den, 100);
        assert_eq!(parsed.keeper_fee, 50_000);
        assert_eq!(parsed.emergency_daa, 100_000);
        assert_eq!(parsed.min_fill, 1_000_000);
        assert_eq!(parsed.max_matcher_fee, 10_000);
    }

    #[test]
    fn wrong_size_returns_none() {
        assert!(parse_perp_deploy_rs(&vec![0u8; 100]).is_none());
    }

    #[test]
    fn bad_body_signature_returns_none() {
        let owner = [0xAA; 32];
        let mut rs = build_perp_deploy_redeem_script(
            &owner, 100, 1, 5, 100, 50_000, 100_000, 1_000_000, 10_000,
        );
        rs[PERP_DEPLOY_V1_STATE_SIZE] = 0xFF;
        assert!(parse_perp_deploy_rs(&rs).is_none());
    }
}
