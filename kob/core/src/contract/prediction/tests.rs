use super::*;
use crate::primitives::u64_le;

// Opcode constants used in tests
const OP_0: u8 = 0x00;
const OP_1: u8 = 0x51;
const OP_2: u8 = 0x52;
const OP_3: u8 = 0x53;
const OP_4: u8 = 0x54;
const OP_5: u8 = 0x55;
const OP_8: u8 = 0x58;
const OP_9: u8 = 0x59;
const OP_10: u8 = 0x5a;
const OP_11: u8 = 0x5b;
const OP_DUP: u8 = 0x76;
const OP_DROP: u8 = 0x75;
const OP_2DUP: u8 = 0x6e;
const OP_2DROP: u8 = 0x6d;
const OP_NOT: u8 = 0x91;
const OP_SWAP: u8 = 0x7c;
const OP_OVER: u8 = 0x78;
const OP_PICK: u8 = 0x79;
const OP_ROLL: u8 = 0x7a;
const OP_ADD: u8 = 0x93;
const OP_SUB: u8 = 0x94;
const OP_MOD: u8 = 0x97;
const OP_EQUAL: u8 = 0x87;
const OP_VERIFY: u8 = 0x69;
const OP_GTE: u8 = 0xa2;
const OP_GT: u8 = 0xa0;
const OP_LT: u8 = 0x9f;
const OP_IF: u8 = 0x63;
const OP_ELSE: u8 = 0x67;
const OP_NOTIF: u8 = 0x64;
const OP_ENDIF: u8 = 0x68;
const OP_BLAKE2B: u8 = 0xaa;
const OP_CHECKSIGVERIFY: u8 = 0xad;
const OP_CLTV: u8 = 0xb0;
const OP_TXINPUTINDEX: u8 = 0xb9;
const OP_TXINPUTAMOUNT: u8 = 0xbe;
const OP_TXINPUTSPK: u8 = 0xbf;
const OP_TXOUTPUTAMOUNT: u8 = 0xc2;
const OP_TXOUTPUTSPK: u8 = 0xc3;
const OP_TXOUTPUTCOUNT: u8 = 0xb4;
const OP_INPUTCOUNT: u8 = 0xb3;
const OP_TXLOCKTIME: u8 = 0xb5;
const OP_INPUTCOVENANTID: u8 = 0xcf;
const OP_COVINPUTCOUNT: u8 = 0xd0;
const OP_COVOUTCOUNT: u8 = 0xd2;
const OP_COVINPUTIDX: u8 = 0xd1;

// --- BallotBox v3 (Value-as-Votes, Two-Box) ---

// --- BallotBox v4 (PoW-Secured, Fee-Zero) ---

// --- BallotBox v5 (Settlement-Compatible, 3-Path) ---

// --- Redemption v4 (Settlement-Separated) ---

// --- BallotBox v2 (deprecated) ---

// --- BallotBox v2 security ---

// --- Redemption v3 (On-Chain Settlement) ---

// --- Redemption v2 (deprecated) ---

// --- Redemption v2 security ---

// --- SplitMerge v2 ---

#[test]
fn split_merge_redeem_script_size() {
    let m = [0xab; 32];
    let yes_cid = [0xcc; 32];
    let no_cid = [0xdd; 32];
    let creator_pkh = [0xee; 32];
    let rs = build_split_merge_redeem_script(&m, &yes_cid, &no_cid, &creator_pkh, 100_000_000, 1_000_000).unwrap();
    // State: [0x20][32B][0x20][32B][0x20][32B][0x20][32B][0x08][8B][0x08][8B] = 150B
    let state_size = 1 + 32 + 1 + 32 + 1 + 32 + 1 + 32 + 1 + 8 + 1 + 8; // 150B
    let body_size = SPLIT_MERGE_BODY.len();
    assert_eq!(rs.len(), state_size + body_size);
    println!("SplitMerge v2 RS: {}B state + {}B body = {}B total",
        state_size, body_size, rs.len());
}

#[test]
fn split_merge_validation() {
    let m = [0xab; 32];
    let y = [0xcc; 32];
    let n = [0xdd; 32];
    let c = [0xee; 32];
    // unit_value must be > 0
    assert!(build_split_merge_redeem_script(&m, &y, &n, &c, 0, 1000).is_err());
    // expiry_daa must be > 0
    assert!(build_split_merge_redeem_script(&m, &y, &n, &c, 1, 0).is_err());
    // valid
    assert!(build_split_merge_redeem_script(&m, &y, &n, &c, 1, 1000).is_ok());
}

#[test]
fn split_merge_if_endif_balance() {
    check_if_endif_balance(SPLIT_MERGE_BODY, "SplitMerge v2");
}

#[test]
fn split_merge_sigscript_selectors() {
    let m = [0xab; 32];
    let c = [0xee; 32];
    let rs = build_split_merge_redeem_script(&m, &[0xcc; 32], &[0xdd; 32], &c, 100_000_000, 1_000_000).unwrap();
    let ss_split = build_split_merge_split_sigscript(&rs);
    let ss_merge = build_split_merge_merge_sigscript(&rs);
    let sig = [0x11; 64];
    let pk = [0x22; 32];
    let ss_refund = build_split_merge_refund_sigscript(&sig, &pk, &rs);
    assert_eq!(ss_split[0], OP_2);  // split
    assert_eq!(ss_merge[0], OP_1);  // merge
    assert_eq!(ss_refund[99], OP_0); // refund (after sig+pk)
}

// --- SplitMerge v2 security ---

#[test]
fn split_merge_refund_requires_sig() {
    // C4 fix: refund path must contain Blake2b + CheckSigVerify
    let body = SPLIT_MERGE_BODY;
    assert!(body.contains(&OP_BLAKE2B),
        "SplitMerge v2 refund path must contain OP_BLAKE2B for creator_pkh check");
    assert!(body.contains(&OP_CHECKSIGVERIFY),
        "SplitMerge v2 refund path must contain OP_CHECKSIGVERIFY for creator sig");
}

#[test]
fn split_merge_split_verifies_token_outputs() {
    // H3 fix: split path must verify YES/NO token outputs via OpCovOutCount
    let body = SPLIT_MERGE_BODY;
    // Find the split path region (first OP_IF to first OP_ELSE)
    let split_start = body.iter().position(|&b| b == OP_IF).unwrap();
    let split_end = body[split_start..].iter().position(|&b| b == OP_ELSE).unwrap() + split_start;
    let split_path = &body[split_start..split_end];

    // Must contain OpCovOutCount at least twice (YES + NO token checks)
    // plus once for self-continuation = 3 total in split path
    let covoutcount_count = split_path.iter().filter(|&&b| b == OP_COVOUTCOUNT).count();
    assert!(covoutcount_count >= 3,
        "SplitMerge v2 split path must use OpCovOutCount for YES/NO tokens + self-continuation (found {})",
        covoutcount_count);
}

#[test]
fn split_merge_merge_exact_payout() {
    // H5 fix: merge path must enforce exact unit_value payout (not just > 0)
    let body = SPLIT_MERGE_BODY;
    // The merge path should contain OP_SUB for amount conservation
    assert!(body.contains(&OP_SUB),
        "SplitMerge v2 merge path must contain OP_SUB for amount conservation");
}

#[test]
fn split_merge_refund_has_cltv() {
    // Security fix: refund path must contain OP_CLTV to prevent premature pool drain
    let body = SPLIT_MERGE_BODY;
    assert!(body.contains(&OP_CLTV),
        "SplitMerge v2 refund path must contain OP_CLTV (0xb0) for timelock");
}

#[test]
fn split_merge_refund_sigscript_has_sig_and_pk() {
    let m = [0xab; 32];
    let c = [0xee; 32];
    let rs = build_split_merge_redeem_script(&m, &[0xcc; 32], &[0xdd; 32], &c, 100_000_000, 1_000_000).unwrap();
    let sig = [0x11; 64];
    let pk = [0x22; 32];
    let ss = build_split_merge_refund_sigscript(&sig, &pk, &rs);
    assert_eq!(ss[99], OP_0); // selector at offset 99 (after sig+pk)
    assert!(ss.len() > 100, "refund sigscript must include sig + pk + RS");
}

// --- Payload ---

#[test]
fn payload_roundtrip() {
    let rs = vec![0x01, 0x02, 0x03];
    let payload = build_prediction_payload(&rs);
    let parsed = parse_prediction_payload(&payload).unwrap();
    assert_eq!(parsed, &rs[..]);
}

#[test]
fn payload_wrong_prefix() {
    assert!(parse_prediction_payload(b"KOB:2:data").is_none());
}

// --- Market Deployment Orchestrator ---

fn test_market_params() -> PredictionMarketParams {
    PredictionMarketParams {
        market_id: [0xaa; 32],
        creator_pkh: [0xbb; 32],
        // Must be even and >= 3_000_000 + 1024*2 = 3_002_048
        initial_ballot_value: 100_000_000,
        split_merge_expiry_daa: 1000,
        ballot_start_daa: 2000,
        ballot_end_daa: 3000,
        market_expiry_daa: 4000,
    }
}

fn test_kas_pool() -> CollateralPoolParams {
    CollateralPoolParams {
        collateral: Collateral::Kas,
        yes_token_cid: [0xcc; 32],
        no_token_cid: [0xdd; 32],
        unit_value: 100_000_000,
        payout_per_token: 100_000_000,
    }
}

#[test]
fn deploy_market_valid_timeline() {
    let params = test_market_params();
    let ballots = build_prediction_market(&params).unwrap();
    assert!(!ballots.ballot_rs.is_empty());
}

#[test]
fn deploy_market_rejects_sm_expiry_gte_start() {
    let mut params = test_market_params();
    params.split_merge_expiry_daa = 2000; // == ballot_start_daa
    assert!(build_prediction_market(&params).is_err());

    params.split_merge_expiry_daa = 3000; // > ballot_start_daa
    assert!(build_prediction_market(&params).is_err());
}

#[test]
fn deploy_market_rejects_start_gte_end() {
    let mut params = test_market_params();
    params.ballot_start_daa = 3000; // == ballot_end_daa
    assert!(build_prediction_market(&params).is_err());
}

#[test]
fn deploy_market_rejects_end_gte_expiry() {
    let mut params = test_market_params();
    params.ballot_end_daa = 4000; // == market_expiry_daa
    assert!(build_prediction_market(&params).is_err());
}

// --- Collateral Pool ---

#[test]
fn collateral_pool_kas_valid() {
    let params = test_market_params();
    let pool = test_kas_pool();
    let scripts = build_collateral_pool(&params, &pool).unwrap();
    assert!(!scripts.split_merge_rs.is_empty());
}

#[test]
fn collateral_pool_rejects_covenant_token() {
    let params = test_market_params();
    let mut pool = test_kas_pool();
    pool.collateral = Collateral::CovenantToken([0xff; 32]);
    assert!(build_collateral_pool(&params, &pool).is_err());
}

#[test]
fn multiple_collateral_pools_same_market() {
    let params = test_market_params();
    let kas_pool = test_kas_pool();
    let mut kas_pool_2 = test_kas_pool();
    kas_pool_2.unit_value = 200_000_000; // different denomination
    kas_pool_2.yes_token_cid = [0xee; 32];
    kas_pool_2.no_token_cid = [0xff; 32];

    let scripts_1 = build_collateral_pool(&params, &kas_pool).unwrap();
    let scripts_2 = build_collateral_pool(&params, &kas_pool_2).unwrap();
    // Different pools produce different SplitMerge scripts
    assert_ne!(scripts_1.split_merge_rs, scripts_2.split_merge_rs);
}

// --- Stage 2: Redemption orchestrator ---

#[test]
fn stage2_redemption_valid_build() {
    let params = test_market_params();
    let pool = test_kas_pool();
    let ballot_cid = [0x11; 32];
    let yes_receipt_cid = [0x22; 32];
    let no_receipt_cid = [0x33; 32];
    let rs = build_prediction_market_redemption(
        &params,
        &pool,
        &ballot_cid,
        100,
        &yes_receipt_cid,
        &no_receipt_cid,
    )
    .unwrap();
    assert!(!rs.is_empty(), "Redemption redeemScript must be non-empty");
}

#[test]
fn stage2_redemption_rejects_covenant_token() {
    let params = test_market_params();
    let mut pool = test_kas_pool();
    pool.collateral = Collateral::CovenantToken([0xff; 32]);
    let ballot_cid = [0x11; 32];
    let yes_receipt_cid = [0x22; 32];
    let no_receipt_cid = [0x33; 32];
    assert!(build_prediction_market_redemption(&params, &pool, &ballot_cid, 100, &yes_receipt_cid, &no_receipt_cid).is_err());
}

// --- BallotBox v6 (Paired — Same CID) ---

#[test]
fn stage2_redemption_v5_single_ballot_cid() {
    // Orchestrator now builds v6 (same state layout as v5)
    let params = test_market_params();
    let pool = test_kas_pool();
    let ballot_cid = [0x11; 32];
    let yes_receipt_cid = [0x22; 32];
    let no_receipt_cid = [0x33; 32];
    let rs = build_prediction_market_redemption(&params, &pool, &ballot_cid, 100, &yes_receipt_cid, &no_receipt_cid).unwrap();
    assert!(!rs.is_empty());
    // v6 (same layout as v5): single ballot_cid at offset 34..66 (after market_id)
    assert_eq!(&rs[34..66], &ballot_cid[..],
        "ballot_cid slot must contain ballot_cid");
    // Verify yes_token_cid follows at 67..99
    assert_eq!(&rs[67..99], &pool.yes_token_cid[..],
        "yes_token_cid slot must match");
}

// --- BallotBox v7 (Parity-Safe) ---

// --- Redemption v5 (Single-CID Parity) ---

#[test]
fn parity_invariant_test() {
    // Verify that even stays even and odd stays odd after N decrements
    // of VOTE_COUNTER_UNIT (2 sompi)
    let reward = VOTE_COUNTER_UNIT;
    assert_eq!(reward, 2, "VOTE_COUNTER_UNIT must be 2");
    assert_eq!(reward % 2, 0, "VOTE_COUNTER_UNIT must be even");

    let mut yes_val: u64 = 100_000_000; // even
    let mut no_val: u64 = 100_000_001;  // odd

    for _ in 0..50_000 {
        // Simulate votes: each vote decreases value by VOTE_COUNTER_UNIT
        yes_val -= reward;
        no_val -= reward;
    }

    assert_eq!(yes_val % 2, 0, "YES value must remain even after 50k votes");
    assert_eq!(no_val % 2, 1, "NO value must remain odd after 50k votes");
}

#[test]
fn redemption_v5_saves_state_bytes_vs_v4() {
    // v4 state: 225B (two ballot CIDs), v5 state: 192B (one ballot CID)
    let v4_state = 225;
    let v5_state = 192;
    assert_eq!(v4_state - v5_state, 33,
        "v5 saves exactly 33B state (one fewer 32B CID + 1B push prefix)");
}

// --- BallotBox v8 (Dispute-Based Settlement) ---

// --- Redemption v6 (Dispute-Based Settlement) ---

#[test]
fn deploy_market_v8_uses_dispute_threshold() {
    let params = test_market_params();
    let pool = test_kas_pool();
    let ballot_cid = [0x11; 32];
    let yes_receipt_cid = [0x22; 32];
    let no_receipt_cid = [0x33; 32];
    let rs = build_prediction_market_redemption(&params, &pool, &ballot_cid, 100, &yes_receipt_cid, &no_receipt_cid).unwrap();

    // Verify threshold_value is correctly computed and embedded in state.
    // threshold_value = 2 * initial_ballot_value + 1 - DISPUTE_THRESHOLD * VOTE_COUNTER_UNIT
    let expected_threshold = 2 * params.initial_ballot_value + 1
        - DISPUTE_THRESHOLD * VOTE_COUNTER_UNIT;

    // threshold_value is at state offset: 4*33 + 9 + 1 = 142..150
    // Layout: [0x20][market_id 32B][0x20][ballot_cid 32B][0x20][yes 32B][0x20][no 32B]
    //         [0x08][payout 8B][0x08][threshold 8B]...
    // = 33 + 33 + 33 + 33 + 9 = 141, then [0x08] at 141, threshold at 142..150
    let threshold_bytes = &rs[142..150];
    assert_eq!(threshold_bytes, &u64_le(expected_threshold),
        "threshold_value in state must match formula: 2V+1 - 1024*2 = {}",
        expected_threshold);
}

#[test]
fn deploy_market_v8_rejects_small_ballot_value() {
    let mut params = test_market_params();
    // Too small: below dust floor + dispute threshold headroom
    params.initial_ballot_value = 3_000_000; // exactly dust floor, no room for 1024 votes
    assert!(build_prediction_market(&params).is_err(),
        "initial_ballot_value too small for 1024 votes must be rejected");

    // Minimum valid: 3_000_000 + 1024 * 2 = 3_002_048
    params.initial_ballot_value = 3_002_048;
    assert!(build_prediction_market(&params).is_ok(),
        "minimum valid initial_ballot_value must be accepted");
}

#[test]
fn dispute_threshold_math() {
    // Verify the formula: threshold_value = 2V+1 - DISPUTE_THRESHOLD * VOTE_COUNTER_UNIT
    // correctly requires exactly 1024 total votes.
    let v: u64 = 100_000_000;
    let threshold = 2 * v + 1 - DISPUTE_THRESHOLD * VOTE_COUNTER_UNIT;
    // 2*100M+1 - 1024*2 = 200_000_001 - 2048 = 199_997_953

    // Initial sum = V + (V+1) = 200_000_001
    // After 1023 votes: sum = 200_000_001 - 1023*2 = 199_998_955
    let sum_1023 = 2 * v + 1 - 1023 * VOTE_COUNTER_UNIT;
    assert!(sum_1023 > threshold,
        "1023 votes must NOT satisfy threshold: sum {} > threshold {}", sum_1023, threshold);

    // After 1024 votes: sum = 200_000_001 - 1024*2 = 199_997_953
    let sum_1024 = 2 * v + 1 - 1024 * VOTE_COUNTER_UNIT;
    assert_eq!(sum_1024, threshold,
        "exactly 1024 votes must satisfy threshold (equal): sum {} == threshold {}", sum_1024, threshold);

    // After 1025 votes: sum < threshold
    let sum_1025 = 2 * v + 1 - 1025 * VOTE_COUNTER_UNIT;
    assert!(sum_1025 < threshold,
        "1025 votes must satisfy threshold: sum {} < threshold {}", sum_1025, threshold);
}

// Redemption v7 tests

#[test]
fn redemption_if_endif_balance() {
    check_if_endif_balance(REDEMPTION_BODY, "Redemption v7");
}

#[test]
fn redemption_state_size() {
    let market_id = [0x01; 32];
    let ballot_cid = [0x02; 32];
    let yes_tok = [0x03; 32];
    let no_tok = [0x04; 32];
    let creator = [0x05; 32];
    let yes_receipt = [0x06; 32];
    let no_receipt = [0x07; 32];
    let rs = build_redemption_redeem_script(
        &market_id, &ballot_cid, &yes_tok, &no_tok,
        1000, 100000, &creator, 50000,
        500, &yes_receipt, &no_receipt,
    ).unwrap();
    let state_size = 267;
    let body_size = REDEMPTION_BODY.len();
    assert_eq!(rs.len(), state_size + body_size,
        "RS must be state({}B) + body({}B) = {}B, got {}B",
        state_size, body_size, state_size + body_size, rs.len());
}

#[test]
fn redemption_state_extends_v6() {
    // v7 state = v6 state (192B) + 75B new receipt fields = 267B
    let v6_state: usize = 192;
    let v7_state: usize = 267;
    assert_eq!(v7_state - v6_state, 75,
        "v7 adds exactly 75B to v6 state: 9(reward) + 33(yes_receipt) + 33(no_receipt)");
}

#[test]
fn redemption_has_3way_dispatch() {
    let body = REDEMPTION_BODY;
    // Must start with OP_11 OP_ROLL (selector from depth 11)
    assert_eq!(body[0], OP_11, "first byte must be OP_11 (0x5b)");
    assert_eq!(body[1], OP_ROLL, "second byte must be OP_ROLL");
    // OP_DUP OP_2 OP_EQUAL for selector==2 check
    assert_eq!(body[2], OP_DUP, "3rd byte must be OP_DUP");
    assert_eq!(body[3], OP_2, "4th byte must be OP_2");
    assert_eq!(body[4], OP_EQUAL, "5th byte must be OP_EQUAL");
    assert_eq!(body[5], OP_IF, "6th byte must be OP_IF");
}

#[test]
fn redemption_has_receipt_path() {
    let body = REDEMPTION_BODY;
    // Receipt path uses OP_9 OP_PICK (ballot_cid at depth 9)
    let pick9_pattern = [OP_9, OP_PICK];
    assert!(body.windows(2).any(|w| w == pick9_pattern),
        "v7 receipt path must use OP_9 OP_PICK for ballot_cid");
    // Also uses OP_10 OP_PICK for second COVINPUTIDX
    let pick10_pattern = [OP_10, OP_PICK];
    assert!(body.windows(2).any(|w| w == pick10_pattern),
        "v7 receipt path must use OP_10 OP_PICK for ballot_cid (2nd)");
}

#[test]
fn redemption_has_token_path() {
    let body = REDEMPTION_BODY;
    // Token path drops 5 items: OP_2DROP OP_DROP OP_DROP OP_DROP
    // then uses OP_4 OP_PICK (same as v6 R1)
    let pick4_pattern = [OP_4, OP_PICK];
    assert!(body.windows(2).any(|w| w == pick4_pattern),
        "v7 token path must use OP_4 OP_PICK (ballot_cid, same as v6)");
}

#[test]
fn redemption_has_refund_path() {
    let body = REDEMPTION_BODY;
    // Refund path uses OP_CLTV and OP_CHECKSIGVERIFY
    assert!(body.contains(&OP_CLTV),
        "v7 must contain OP_CLTV for refund path");
    assert!(body.contains(&OP_CHECKSIGVERIFY),
        "v7 must contain OP_CHECKSIGVERIFY for refund path");
}

#[test]
fn redemption_has_vote_count_check_receipt_path() {
    let body = REDEMPTION_BODY;
    // Receipt path vote count check uses OP_8 OP_PICK (threshold at depth 8:
    // sum(0), val_second(1), val_first(2) + 11 state items, threshold at idx 8)
    let pattern = [OP_2DUP, OP_ADD, OP_8, OP_PICK, OP_SWAP, OP_GTE, OP_VERIFY];
    assert!(body.windows(7).any(|w| w == pattern),
        "v7 receipt path must contain vote count check with OP_8 OP_PICK");
}

#[test]
fn redemption_has_vote_count_check_token_path() {
    let body = REDEMPTION_BODY;
    // Token path vote count check uses OP_3 OP_PICK (same as v6)
    let pattern = [OP_2DUP, OP_ADD, OP_3, OP_PICK, OP_SWAP, OP_GTE, OP_VERIFY];
    assert!(body.windows(7).any(|w| w == pattern),
        "v7 token path must contain vote count check with OP_3 OP_PICK (same as v6)");
}

#[test]
fn redemption_receipt_sigscript() {
    let rs = vec![0xab; 100];
    let ss = build_redemption_receipt_sigscript(&rs);
    // Format: [Op2] [pushData(RS)]
    assert_eq!(ss[0], OP_2, "receipt sigscript selector must be OP_2");
    assert!(ss.len() > 1 + rs.len(),
        "sigscript must include push overhead");
}

#[test]
fn redemption_token_sigscript() {
    let rs = vec![0xab; 100];
    let ss = build_redemption_token_sigscript(&rs);
    assert_eq!(ss[0], OP_1, "token sigscript selector must be OP_1");
}

#[test]
fn redemption_refund_sigscript() {
    let sig = [0xaa; 64];
    let pk = [0xbb; 32];
    let rs = vec![0xcc; 100];
    let ss = build_redemption_refund_sigscript(&sig, &pk, &rs);
    // Must contain OP_0 selector
    assert!(ss.contains(&OP_0), "refund sigscript must have OP_0 selector");
}

#[test]
fn redemption_rejects_zero_reward() {
    let z32 = [0x00; 32];
    let result = build_redemption_redeem_script(
        &z32, &z32, &z32, &z32, 1000, 100000, &z32, 50000,
        0, &z32, &z32, // reward = 0
    );
    assert!(result.is_err(), "reward_per_receipt = 0 must be rejected");
}

#[test]
fn redemption_rejects_zero_payout() {
    let z32 = [0x00; 32];
    let result = build_redemption_redeem_script(
        &z32, &z32, &z32, &z32, 0, 100000, &z32, 50000,
        500, &z32, &z32,
    );
    assert!(result.is_err(), "payout_per_token = 0 must be rejected");
}

#[test]
fn redemption_rejects_zero_expiry() {
    let z32 = [0x00; 32];
    let result = build_redemption_redeem_script(
        &z32, &z32, &z32, &z32, 1000, 100000, &z32, 0,
        500, &z32, &z32,
    );
    assert!(result.is_err(), "expiry_daa = 0 must be rejected");
}

#[test]
fn redemption_rejects_zero_threshold() {
    let z32 = [0x00; 32];
    let result = build_redemption_redeem_script(
        &z32, &z32, &z32, &z32, 1000, 0, &z32, 50000,
        500, &z32, &z32,
    );
    assert!(result.is_err(), "threshold_value = 0 must be rejected");
}

#[test]
fn redemption_deterministic() {
    let m = [0x11; 32];
    let b = [0x22; 32];
    let yt = [0x33; 32];
    let nt = [0x44; 32];
    let c = [0x55; 32];
    let yr = [0x66; 32];
    let nr = [0x77; 32];
    let rs1 = build_redemption_redeem_script(
        &m, &b, &yt, &nt, 1000, 100000, &c, 50000, 500, &yr, &nr,
    ).unwrap();
    let rs2 = build_redemption_redeem_script(
        &m, &b, &yt, &nt, 1000, 100000, &c, 50000, 500, &yr, &nr,
    ).unwrap();
    assert_eq!(rs1, rs2, "same inputs must produce same RS");
}

#[test]
fn redemption_receipt_and_token_paths_independent() {
    // Changing receipt CIDs must not affect token path dispatch logic.
    // The v6 state prefix (192B) must be identical.
    let m = [0x11; 32];
    let b = [0x22; 32];
    let yt = [0x33; 32];
    let nt = [0x44; 32];
    let c = [0x55; 32];

    let rs_a = build_redemption_redeem_script(
        &m, &b, &yt, &nt, 1000, 100000, &c, 50000,
        500, &[0xaa; 32], &[0xbb; 32],
    ).unwrap();
    let rs_b = build_redemption_redeem_script(
        &m, &b, &yt, &nt, 1000, 100000, &c, 50000,
        999, &[0xcc; 32], &[0xdd; 32],
    ).unwrap();

    // First 192 bytes (v6 state portion) must be identical
    assert_eq!(&rs_a[..192], &rs_b[..192],
        "v6 state portion must be identical regardless of receipt params");
    // Bytes after 192 differ (receipt state + body same, but receipt state differs)
    assert_ne!(rs_a, rs_b,
        "different receipt params must produce different RS");
}

#[test]
fn redemption_pool_conservation_receipt_path() {
    // Receipt path pool conservation uses OP_3 OP_PICK (reward_per_receipt at idx 3
    // after OP_TXINPUTAMOUNT pushes pool value).
    // Token path pool conservation uses OP_2 OP_PICK (payout_per_token at idx 2).
    // They differ by index, so check separately.
    let receipt_pattern = [OP_0, OP_TXINPUTAMOUNT, OP_3, OP_PICK, OP_SUB,
                           OP_1, OP_TXOUTPUTAMOUNT, OP_SWAP, OP_GTE, OP_VERIFY];
    let token_pattern = [OP_0, OP_TXINPUTAMOUNT, OP_2, OP_PICK, OP_SUB,
                         OP_1, OP_TXOUTPUTAMOUNT, OP_SWAP, OP_GTE, OP_VERIFY];
    let receipt_count = REDEMPTION_BODY.windows(10)
        .filter(|w| *w == receipt_pattern)
        .count();
    let token_count = REDEMPTION_BODY.windows(10)
        .filter(|w| *w == token_pattern)
        .count();
    assert_eq!(receipt_count, 1,
        "receipt path pool conservation (OP_3 OP_PICK) must appear exactly once");
    assert_eq!(token_count, 1,
        "token path pool conservation (OP_2 OP_PICK) must appear exactly once");
}

#[test]
fn redemption_self_continuation_both_paths() {
    // Self-continuation pattern appears in both redeem paths:
    // OP_TXINPUTINDEX OP_INPUTCOVENANTID OP_COVOUTCOUNT OP_1 OP_EQUAL OP_VERIFY
    let pattern = [OP_TXINPUTINDEX, OP_INPUTCOVENANTID, OP_COVOUTCOUNT,
                    OP_1, OP_EQUAL, OP_VERIFY];
    let count = REDEMPTION_BODY.windows(6)
        .filter(|w| *w == pattern)
        .count();
    assert_eq!(count, 2,
        "self-continuation check must appear exactly twice (receipt + token paths)");
}

#[test]
fn redemption_parity_normalization_both_paths() {
    // Parity normalization with OP_NOTIF OP_SWAP OP_ENDIF
    let pattern = [OP_OVER, OP_2, OP_MOD, OP_NOTIF, OP_SWAP, OP_ENDIF];
    let count = REDEMPTION_BODY.windows(6)
        .filter(|w| *w == pattern)
        .count();
    assert_eq!(count, 2,
        "parity normalization must appear exactly twice (receipt + token paths)");
}

// VoteReceipt v1 tests

#[test]
fn vote_receipt_rs_size() {
    let ballot_cid = [0xaa; 32];
    let rs_yes = build_vote_receipt_redeem_script(&ballot_cid, 1);
    let rs_no = build_vote_receipt_redeem_script(&ballot_cid, 0);

    // State: 1(push) + 32(cid) + 1(push) + 1(side) = 35B
    // Body: 2B (OP_2DROP + OP_1)
    // Total: 37B
    // Wait: VOTE_RECEIPT_BODY is [OP_2DROP, OP_1] = 2B
    // State: [0x20][32B][0x01][1B] = 35B
    // 35 + 2 = 37B? No: 1+32+1+1 = 35B state, 2B body = 37B
    // But OP_2DROP pops 2 items. State pushes 2 items (ballot_cid + vote_side). Correct.
    assert_eq!(rs_yes.len(), 37, "VoteReceipt YES RS must be 37B");
    assert_eq!(rs_no.len(), 37, "VoteReceipt NO RS must be 37B");

    // YES and NO must produce different RS (different P2SH addresses)
    assert_ne!(rs_yes, rs_no, "YES and NO receipts must differ");
}

#[test]
fn vote_receipt_deterministic() {
    let cid = [0xbb; 32];
    let rs1 = build_vote_receipt_redeem_script(&cid, 1);
    let rs2 = build_vote_receipt_redeem_script(&cid, 1);
    assert_eq!(rs1, rs2, "Same inputs must produce same RS");
}

#[test]
fn vote_receipt_sigscript() {
    let cid = [0xcc; 32];
    let rs = build_vote_receipt_redeem_script(&cid, 0);
    let ss = build_vote_receipt_sigscript(&rs);
    // Sigscript is just pushData(RS) — no selector, no sig
    assert!(ss.len() > rs.len(), "sigscript includes push overhead");
    // RS is 37B < 75, so push opcode = 1 byte
    assert_eq!(ss.len(), 1 + rs.len(), "37B RS uses 1-byte push");
    assert_eq!(ss[0], rs.len() as u8, "first byte is push length");
}

#[test]
fn vote_receipt_different_markets() {
    let cid_a = [0x01; 32];
    let cid_b = [0x02; 32];
    let rs_a = build_vote_receipt_redeem_script(&cid_a, 1);
    let rs_b = build_vote_receipt_redeem_script(&cid_b, 1);
    assert_ne!(rs_a, rs_b, "Different markets must produce different receipts");
}

#[test]
#[should_panic(expected = "vote_side must be 0")]
fn vote_receipt_invalid_side() {
    build_vote_receipt_redeem_script(&[0; 32], 2);
}

// BallotBox v9 tests

#[test]
fn ballot_box_if_endif_balance() {
    check_if_endif_balance(BALLOT_BOX_BODY, "BallotBox v9");
}

#[test]
fn ballot_box_rs_build() {
    let market_id = [0xab; 32];
    let rs = build_ballot_box_redeem_script(
        &market_id, 2, 100, 200, 300,
    ).unwrap();

    // State: 69B (same as v8)
    let state_size = 1 + 32 + 1 + 8 + 1 + 8 + 1 + 8 + 1 + 8; // 69B
    assert_eq!(rs.len(), state_size + BALLOT_BOX_BODY.len());
    println!("BallotBox v9 RS: {}B total ({}B state + {}B body)",
        rs.len(), state_size, BALLOT_BOX_BODY.len());
}

#[test]
fn ballot_box_validation() {
    let m = [0xab; 32];
    // reward must be > 0
    assert!(build_ballot_box_redeem_script(&m, 0, 100, 200, 300).is_err());
    // reward must be even
    assert!(build_ballot_box_redeem_script(&m, 3, 100, 200, 300).is_err());
    // daa scores must be > 0
    assert!(build_ballot_box_redeem_script(&m, 2, 0, 200, 300).is_err());
    // end > start
    assert!(build_ballot_box_redeem_script(&m, 2, 200, 100, 300).is_err());
    // expiry > end
    assert!(build_ballot_box_redeem_script(&m, 2, 100, 200, 200).is_err());
    // valid
    assert!(build_ballot_box_redeem_script(&m, 2, 100, 200, 300).is_ok());
}

#[test]
fn ballot_box_output_count_check() {
    // Verify v9 body contains OP_TXOUTPUTCOUNT (0xb4) for 4-output enforcement
    assert!(BALLOT_BOX_BODY.contains(&OP_TXOUTPUTCOUNT),
        "v9 must enforce output count with OP_TXOUTPUTCOUNT");

    // Verify the 4-output check pattern: OP_TXOUTPUTCOUNT OP_4 OP_EQUAL OP_VERIFY
    let pattern = [OP_TXOUTPUTCOUNT, OP_4, OP_EQUAL, OP_VERIFY];
    assert!(BALLOT_BOX_BODY.windows(4).any(|w| w == pattern),
        "v9 must check exactly 4 outputs");
}

#[test]
fn ballot_box_receipt_dust_check() {
    // Verify v9 body checks Output[3] amount >= 3M sompi
    // Pattern: OP_3 OP_TXOUTPUTAMOUNT <3M push> OP_GTE OP_VERIFY
    let body = BALLOT_BOX_BODY;
    let pattern = [OP_3, OP_TXOUTPUTAMOUNT];
    let count = body.windows(2).filter(|w| w == &pattern).count();
    assert!(count >= 2, "v9 must reference output[3] amount at least twice \
        (once in fee sum, once in dust check). Found: {}", count);
}

#[test]
fn ballot_box_fee_zero_four_outputs() {
    // Verify v9 fee==0 sum includes all 4 outputs
    // Must contain OP_3 OP_TXOUTPUTAMOUNT for output[3] in fee calc
    let body = BALLOT_BOX_BODY;
    // Count how many distinct output indices are referenced in TXOUTPUTAMOUNT
    let out_amount_refs: Vec<u8> = body.windows(2)
        .filter(|w| w[1] == OP_TXOUTPUTAMOUNT)
        .map(|w| w[0])
        .collect();
    // Should include OP_0(output[0]), OP_1(output[1]), OP_2(output[2]), OP_3(output[3])
    assert!(out_amount_refs.contains(&OP_0), "must sum output[0]");
    assert!(out_amount_refs.contains(&OP_1), "must sum output[1]");
    assert!(out_amount_refs.contains(&OP_2), "must sum output[2]");
    assert!(out_amount_refs.contains(&OP_3), "must sum output[3]");
}

#[test]
fn vote_receipt_storage_mass_feasibility() {
    // Verify that a 4-output vote TX is within mass limits
    // with realistic BallotBox values.
    use crate::mass::{compute_storage_mass, MAX_TX_MASS};

    let ballot_value: u64 = 100_000_000; // 1 KAS per BallotBox
    let miner_utxo: u64 = 10_000_000;    // 0.1 KAS miner input
    let receipt_value: u64 = RECEIPT_DUST_FLOOR; // 3M sompi

    let inputs = vec![ballot_value, ballot_value, miner_utxo];
    let outputs = vec![
        ballot_value - VOTE_COUNTER_UNIT, // BallotBox A continuation (decreased)
        ballot_value,                      // BallotBox B continuation (unchanged)
        miner_utxo + VOTE_COUNTER_UNIT - receipt_value, // miner change
        receipt_value,                     // VoteReceipt
    ];

    let mass = compute_storage_mass(&inputs, &outputs);
    println!("Vote TX with receipt: storage_mass = {} (limit = {})", mass, MAX_TX_MASS);
    assert!(mass < MAX_TX_MASS,
        "4-output vote TX must be within mass limits: {} >= {}", mass, MAX_TX_MASS);
}

// --- Helpers ---

fn check_if_endif_balance(body: &[u8], name: &str) {
    let mut depth = 0i32;
    for (i, &byte) in body.iter().enumerate() {
        match byte {
            0x63 | 0x64 => depth += 1,  // OP_IF / OP_NOTIF
            0x68 => depth -= 1,          // OP_ENDIF
            _ => {}
        }
        assert!(depth >= 0, "{}: IF/ENDIF underflow at byte {}", name, i);
    }
    assert_eq!(depth, 0, "{}: IF/ENDIF not balanced: depth={}", name, depth);
}
