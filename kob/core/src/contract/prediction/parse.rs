//! Parse prediction market redeemScripts to identify covenant type.

/// Type of prediction market covenant detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredictionItemType {
    /// SplitMerge: token issuer (1 KAS -> 1 YES + 1 NO).
    SplitMerge,
    /// BallotBox: voting chain UTXO.
    BallotBox,
    /// Redemption: holds KAS pool for winner payout.
    Redemption,
}

/// Parsed prediction market covenant from redeemScript.
#[derive(Debug, Clone)]
pub struct ParsedPredictionItem {
    pub item_type: PredictionItemType,
    pub redeem_script: Vec<u8>,
}

/// Parse a prediction market redeemScript.
///
/// Identifies covenant type by state push prefix pattern:
///   - BallotBox:  [0x20][32B][0x08][8B][0x08][8B][0x08][8B][0x08][8B]  (1 hash + 4 u64)
///   - SplitMerge: [0x20][32B][0x20][32B][0x20][32B][0x20][32B][0x08].. (4 hashes + u64s)
///   - Redemption: [0x20][32B][0x20][32B][0x20][32B][0x20][32B][0x20].. (5+ hashes)
pub fn parse_prediction_rs(rs: &[u8]) -> Option<ParsedPredictionItem> {
    if rs.len() < 69 {
        return None;
    }

    if rs[0] != 0x20 {
        return None;
    }

    // Both SplitMerge and Redemption have 4 consecutive 0x20 pushes at offsets 0,33,66,99.
    // Redemption has additional 0x20 pushes and is longer (state=267B vs SplitMerge state=150B).
    // Distinguish by checking for a 0x20 push at offset 150 (creator_pkh in Redemption).
    if rs.len() >= 132 && rs[0] == 0x20 && rs[33] == 0x20 && rs[66] == 0x20
        && rs[99] == 0x20
    {
        // Redemption: has 0x20 at offset 150 (creator_pkh after two u64 fields)
        if rs.len() >= 183 && rs[150] == 0x20 {
            return Some(ParsedPredictionItem {
                item_type: PredictionItemType::Redemption,
                redeem_script: rs.to_vec(),
            });
        }
        // SplitMerge: 4 hashes + 2 u64 fields, no 0x20 at 150
        return Some(ParsedPredictionItem {
            item_type: PredictionItemType::SplitMerge,
            redeem_script: rs.to_vec(),
        });
    }

    // BallotBox: 1 hash then 4 u64 pushes (0x08)
    if rs[33] == 0x08 && rs[42] == 0x08 && rs[51] == 0x08 && rs[60] == 0x08 {
        return Some(ParsedPredictionItem {
            item_type: PredictionItemType::BallotBox,
            redeem_script: rs.to_vec(),
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prediction::{
        build_split_merge_redeem_script,
        build_ballot_box_redeem_script,
        build_redemption_redeem_script,
    };

    #[test]
    fn parse_split_merge() {
        let rs = build_split_merge_redeem_script(
            &[0xDD; 32], &[0x11; 32], &[0x22; 32], &[0xEE; 32], 1_000_000, 2_000_000,
        ).unwrap();
        let parsed = parse_prediction_rs(&rs).expect("should parse SplitMerge");
        assert_eq!(parsed.item_type, PredictionItemType::SplitMerge);
    }

    #[test]
    fn parse_ballot_box() {
        let rs = build_ballot_box_redeem_script(
            &[0xDD; 32], 1_000_000, 100, 500_000, 1_000_000,
        ).unwrap();
        let parsed = parse_prediction_rs(&rs).expect("should parse BallotBox");
        assert_eq!(parsed.item_type, PredictionItemType::BallotBox);
    }

    #[test]
    fn parse_redemption() {
        let rs = build_redemption_redeem_script(
            &[0xDD; 32], &[0x44; 32], &[0x66; 32], &[0x77; 32],
            1_000_000, 1001, &[0x88; 32], 2_000_000, 1, &[0u8; 32], &[0u8; 32],
        ).unwrap();
        let parsed = parse_prediction_rs(&rs).expect("should parse Redemption");
        assert_eq!(parsed.item_type, PredictionItemType::Redemption);
    }

    #[test]
    fn too_short_returns_none() {
        assert!(parse_prediction_rs(&vec![0u8; 10]).is_none());
    }
}
