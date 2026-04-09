use super::*;
use crate::primitives::u64_le;

const FAKE_PK: [u8; 32] = [0xaa; 32];
const FAKE_COV_ID: [u8; 32] = [0xbb; 32];
const FAKE_SIG: [u8; 64] = [0xcc; 64];
const FAKE_CREATOR_SPK_HASH: [u8; 32] = [0xdd; 32];

// --- Body size sanity ---

#[test]
fn english_body_size() {
    assert_eq!(ENGLISH_AUCTION_BODY.len(), 131);
}

#[test]
fn dutch_body_size() {
    assert_eq!(DUTCH_AUCTION_BODY.len(), 107);
}

#[test]
fn escrow_body_size() {
    assert_eq!(AUCTION_ESCROW_BODY.len(), 23);
}

// --- RS builder output size ---

#[test]
fn english_rs_size() {
    let rs = build_english_auction_redeem_script(
        &FAKE_PK, 100_000, &FAKE_COV_ID, 5_000_000, 1000,
        &FAKE_CREATOR_SPK_HASH, 50_000,
    ).unwrap();
    assert_eq!(rs.len(), ENGLISH_AUCTION_STATE_SIZE + ENGLISH_AUCTION_BODY.len());
    assert_eq!(rs.len(), 168 + 131); // 299
}

#[test]
fn dutch_rs_size() {
    let rs = build_dutch_auction_redeem_script(
        &FAKE_PK, 1_000_000, 100_000, 50, 1000, &FAKE_COV_ID,
        &FAKE_CREATOR_SPK_HASH, 50_000,
    ).unwrap();
    assert_eq!(rs.len(), DUTCH_AUCTION_STATE_SIZE + DUTCH_AUCTION_BODY.len());
    assert_eq!(rs.len(), 177 + 107); // 284
}

#[test]
fn escrow_rs_size() {
    let rs = build_auction_escrow_redeem_script(&FAKE_COV_ID, &FAKE_PK);
    assert_eq!(rs.len(), AUCTION_ESCROW_STATE_SIZE + AUCTION_ESCROW_BODY.len());
    assert_eq!(rs.len(), 66 + 23); // 89
}

// --- RS structure: state prefix + body suffix ---

#[test]
fn english_rs_structure() {
    let rs = build_english_auction_redeem_script(
        &FAKE_PK, 500_000, &FAKE_COV_ID, 10_000_000, 2000,
        &FAKE_CREATOR_SPK_HASH, 100_000,
    ).unwrap();
    let mut off = 0;
    assert_eq!(rs[off], 0x20); off += 1;
    assert_eq!(&rs[off..off+32], &FAKE_PK); off += 32;
    assert_eq!(rs[off], 0x08); off += 1;
    assert_eq!(&rs[off..off+8], &u64_le(500_000)); off += 8;
    assert_eq!(rs[off], 0x20); off += 1;
    assert_eq!(&rs[off..off+32], &FAKE_COV_ID); off += 32;
    assert_eq!(rs[off], 0x08); off += 1;
    assert_eq!(&rs[off..off+8], &u64_le(10_000_000)); off += 8;
    assert_eq!(rs[off], 0x08); off += 1;
    assert_eq!(&rs[off..off+8], &u64_le(2000)); off += 8;
    assert_eq!(rs[off], 0x20); off += 1;
    let expected_seller_spk = crate::p2sh::compute_p2pk_spk_hash(&FAKE_PK);
    assert_eq!(&rs[off..off+32], &expected_seller_spk); off += 32;
    assert_eq!(rs[off], 0x20); off += 1;
    assert_eq!(&rs[off..off+32], &FAKE_CREATOR_SPK_HASH); off += 32;
    assert_eq!(rs[off], 0x08); off += 1;
    assert_eq!(&rs[off..off+8], &u64_le(100_000)); off += 8;
    assert_eq!(off, ENGLISH_AUCTION_STATE_SIZE);
    assert_eq!(&rs[off..], ENGLISH_AUCTION_BODY);
}

#[test]
fn dutch_rs_structure() {
    let rs = build_dutch_auction_redeem_script(
        &FAKE_PK, 2_000_000, 100_000, 50, 1000, &FAKE_COV_ID,
        &FAKE_CREATOR_SPK_HASH, 75_000,
    ).unwrap();
    let mut off = 0;
    assert_eq!(rs[off], 0x20); off += 1;
    assert_eq!(&rs[off..off+32], &FAKE_PK); off += 32;
    assert_eq!(rs[off], 0x08); off += 1;
    assert_eq!(&rs[off..off+8], &u64_le(2_000_000)); off += 8; // reserve
    assert_eq!(rs[off], 0x08); off += 1;
    assert_eq!(&rs[off..off+8], &u64_le(100_000)); off += 8; // step
    assert_eq!(rs[off], 0x08); off += 1;
    assert_eq!(&rs[off..off+8], &u64_le(50)); off += 8; // tick_interval
    assert_eq!(rs[off], 0x08); off += 1;
    assert_eq!(&rs[off..off+8], &u64_le(1000)); off += 8; // expiry_daa
    assert_eq!(rs[off], 0x20); off += 1;
    let expected_seller_spk = crate::p2sh::compute_p2pk_spk_hash(&FAKE_PK);
    assert_eq!(&rs[off..off+32], &expected_seller_spk); off += 32;
    assert_eq!(rs[off], 0x20); off += 1;
    assert_eq!(&rs[off..off+32], &FAKE_COV_ID); off += 32; // item_cov_id
    assert_eq!(rs[off], 0x20); off += 1;
    assert_eq!(&rs[off..off+32], &FAKE_CREATOR_SPK_HASH); off += 32;
    assert_eq!(rs[off], 0x08); off += 1;
    assert_eq!(&rs[off..off+8], &u64_le(75_000)); off += 8; // royalty
    assert_eq!(off, DUTCH_AUCTION_STATE_SIZE);
    assert_eq!(&rs[off..], DUTCH_AUCTION_BODY);
}

#[test]
fn escrow_rs_structure() {
    let rs = build_auction_escrow_redeem_script(&FAKE_COV_ID, &FAKE_PK);
    assert_eq!(rs[0], 0x20);
    assert_eq!(&rs[1..33], &FAKE_COV_ID);
    assert_eq!(rs[33], 0x20);
    assert_eq!(&rs[34..66], &FAKE_PK);
    assert_eq!(&rs[66..], AUCTION_ESCROW_BODY);
}

// --- Validation: zero params rejected ---

#[test]
fn english_zero_min_increment_rejected() {
    assert!(build_english_auction_redeem_script(
        &FAKE_PK, 0, &FAKE_COV_ID, 5_000_000, 1000,
        &FAKE_CREATOR_SPK_HASH, 50_000,
    ).is_err());
}

#[test]
fn english_zero_reserve_rejected() {
    assert!(build_english_auction_redeem_script(
        &FAKE_PK, 100_000, &FAKE_COV_ID, 0, 1000,
        &FAKE_CREATOR_SPK_HASH, 50_000,
    ).is_err());
}

#[test]
fn english_zero_expiry_rejected() {
    assert!(build_english_auction_redeem_script(
        &FAKE_PK, 100_000, &FAKE_COV_ID, 5_000_000, 0,
        &FAKE_CREATOR_SPK_HASH, 50_000,
    ).is_err());
}

#[test]
fn english_zero_royalty_allowed() {
    assert!(build_english_auction_redeem_script(
        &FAKE_PK, 100_000, &FAKE_COV_ID, 5_000_000, 1000,
        &FAKE_CREATOR_SPK_HASH, 0,
    ).is_ok());
}

#[test]
fn dutch_zero_reserve_rejected() {
    assert!(build_dutch_auction_redeem_script(
        &FAKE_PK, 0, 100_000, 50, 1000, &FAKE_COV_ID,
        &FAKE_CREATOR_SPK_HASH, 50_000,
    ).is_err());
}

#[test]
fn dutch_zero_step_rejected() {
    assert!(build_dutch_auction_redeem_script(
        &FAKE_PK, 1_000_000, 0, 50, 1000, &FAKE_COV_ID,
        &FAKE_CREATOR_SPK_HASH, 50_000,
    ).is_err());
}

#[test]
fn dutch_zero_tick_interval_rejected() {
    assert!(build_dutch_auction_redeem_script(
        &FAKE_PK, 1_000_000, 100_000, 0, 1000, &FAKE_COV_ID,
        &FAKE_CREATOR_SPK_HASH, 50_000,
    ).is_err());
}

#[test]
fn dutch_expiry_le_tick_interval_rejected() {
    assert!(build_dutch_auction_redeem_script(
        &FAKE_PK, 1_000_000, 100_000, 50, 50, &FAKE_COV_ID,
        &FAKE_CREATOR_SPK_HASH, 50_000,
    ).is_err());
    assert!(build_dutch_auction_redeem_script(
        &FAKE_PK, 1_000_000, 100_000, 50, 30, &FAKE_COV_ID,
        &FAKE_CREATOR_SPK_HASH, 50_000,
    ).is_err());
}

#[test]
fn dutch_zero_royalty_allowed() {
    assert!(build_dutch_auction_redeem_script(
        &FAKE_PK, 1_000_000, 100_000, 50, 1000, &FAKE_COV_ID,
        &FAKE_CREATOR_SPK_HASH, 0,
    ).is_ok());
}

// --- Sigscript format ---

#[test]
fn english_bid_sigscript_format() {
    let rs = build_english_auction_redeem_script(
        &FAKE_PK, 100_000, &FAKE_COV_ID, 5_000_000, 1000,
        &FAKE_CREATOR_SPK_HASH, 50_000,
    ).unwrap();
    let ss = build_english_bid_sigscript(&rs);
    assert_eq!(ss[0], 0x00); // Op0 dummy
    assert_eq!(ss[1], 0x53); // Op3 selector = bid
}

#[test]
fn english_expire_sigscript_format() {
    let rs = build_english_auction_redeem_script(
        &FAKE_PK, 100_000, &FAKE_COV_ID, 5_000_000, 1000,
        &FAKE_CREATOR_SPK_HASH, 50_000,
    ).unwrap();
    let ss = build_english_expire_sigscript(&rs);
    assert_eq!(ss[0], 0x00); // Op0 dummy
    assert_eq!(ss[1], 0x52); // Op2 selector = expire
}

#[test]
fn english_settle_sigscript_format() {
    let rs = build_english_auction_redeem_script(
        &FAKE_PK, 100_000, &FAKE_COV_ID, 5_000_000, 1000,
        &FAKE_CREATOR_SPK_HASH, 50_000,
    ).unwrap();
    let ss = build_english_settle_sigscript(&FAKE_SIG, &rs);
    assert_eq!(ss[0], 0x41); // pushData length 65
    assert_eq!(ss[66], 0x51); // Op1 selector = settle
}

#[test]
fn english_cancel_sigscript_format() {
    let rs = build_english_auction_redeem_script(
        &FAKE_PK, 100_000, &FAKE_COV_ID, 5_000_000, 1000,
        &FAKE_CREATOR_SPK_HASH, 50_000,
    ).unwrap();
    let ss = build_english_cancel_sigscript(&FAKE_SIG, &rs);
    assert_eq!(ss[0], 0x41); // pushData length 65
    assert_eq!(ss[66], 0x00); // Op0 selector = cancel
}

#[test]
fn dutch_buy_sigscript_format() {
    let rs = build_dutch_auction_redeem_script(
        &FAKE_PK, 1_000_000, 100_000, 50, 1000, &FAKE_COV_ID,
        &FAKE_CREATOR_SPK_HASH, 50_000,
    ).unwrap();
    let ss = build_dutch_buy_sigscript(&rs);
    assert_eq!(ss[0], 0x52); // Op2 selector = buy
}

#[test]
fn dutch_tick_sigscript_format() {
    let rs = build_dutch_auction_redeem_script(
        &FAKE_PK, 1_000_000, 100_000, 50, 1000, &FAKE_COV_ID,
        &FAKE_CREATOR_SPK_HASH, 50_000,
    ).unwrap();
    let ss = build_dutch_tick_sigscript(&rs);
    assert_eq!(ss[0], 0x51); // Op1 selector = tick
}

#[test]
fn dutch_cancel_sigscript_format() {
    let rs = build_dutch_auction_redeem_script(
        &FAKE_PK, 1_000_000, 100_000, 50, 1000, &FAKE_COV_ID,
        &FAKE_CREATOR_SPK_HASH, 50_000,
    ).unwrap();
    let ss = build_dutch_cancel_sigscript(&FAKE_SIG, &FAKE_PK, &rs);
    assert_eq!(ss[0], 0x41); // pushData length 65 (sig+type)
    assert_eq!(ss[66], 0x20); // pushData length 32 (pubkey)
    assert_eq!(&ss[67..99], &FAKE_PK);
    assert_eq!(ss[99], 0x00); // Op0 selector = cancel
}

#[test]
fn escrow_release_sigscript_format() {
    let rs = build_auction_escrow_redeem_script(&FAKE_COV_ID, &FAKE_PK);
    let ss = build_auction_escrow_release_sigscript(&FAKE_SIG, &rs);
    assert_eq!(ss[0], 0x41); // pushData 65 = signature present
    assert_eq!(ss[66], 0x51); // Op1 selector = release
}

#[test]
fn escrow_cancel_sigscript_format() {
    let rs = build_auction_escrow_redeem_script(&FAKE_COV_ID, &FAKE_PK);
    let ss = build_auction_escrow_cancel_sigscript(&FAKE_SIG, &rs);
    assert_eq!(ss[0], 0x41); // pushData 65
    assert_eq!(ss[66], 0x00); // Op0 selector = cancel
}

// --- Bytecode contains expected opcodes ---

#[test]
fn english_body_contains_cov_input_count() {
    assert!(
        ENGLISH_AUCTION_BODY.contains(&0xd0),
        "body must contain OpCovInputCount (0xd0) for atomic delivery"
    );
}

#[test]
fn dutch_body_contains_cov_input_count() {
    assert!(
        DUTCH_AUCTION_BODY.contains(&0xd0),
        "body must contain OpCovInputCount (0xd0) for atomic delivery"
    );
}

#[test]
fn escrow_body_contains_cov_input_count() {
    assert!(
        AUCTION_ESCROW_BODY.contains(&0xd0),
        "escrow body must contain OpCovInputCount (0xd0) for auction co-input check"
    );
}

#[test]
fn escrow_body_contains_cov_out_count() {
    assert!(
        AUCTION_ESCROW_BODY.contains(&0xd2),
        "escrow body must contain OpCovOutCount (0xd2) to verify auction is consumed, not self-continued"
    );
}

#[test]
fn english_body_contains_csv() {
    assert!(
        ENGLISH_AUCTION_BODY.contains(&0xb1),
        "body must contain OpCheckSequenceVerify (0xb1) for expiry"
    );
}

#[test]
fn dutch_body_contains_csv() {
    assert!(
        DUTCH_AUCTION_BODY.contains(&0xb1),
        "body must contain OpCheckSequenceVerify (0xb1) for tick rate-limit and expiry"
    );
}

#[test]
fn english_body_has_fee_zero() {
    let count = ENGLISH_AUCTION_BODY
        .windows(4)
        .filter(|w| *w == [0xca, 0x00, 0x87, 0x69])
        .count();
    assert_eq!(count, 2, "must have fee==0 in both bid and expire paths");
}

#[test]
fn dutch_body_has_fee_zero() {
    let count = DUTCH_AUCTION_BODY
        .windows(4)
        .filter(|w| *w == [0xca, 0x00, 0x87, 0x69])
        .count();
    assert_eq!(count, 2, "must have fee==0 in both buy and tick paths");
}

#[test]
fn english_body_contains_blake2b() {
    let count = ENGLISH_AUCTION_BODY.iter().filter(|&&b| b == 0xaa).count();
    assert!(count >= 3, "must have at least 3 OpBlake2b: expire seller_spk + settle seller_spk + settle creator_spk");
}

#[test]
fn dutch_body_contains_blake2b() {
    let count = DUTCH_AUCTION_BODY.iter().filter(|&&b| b == 0xaa).count();
    assert!(count >= 2, "must have at least 2 OpBlake2b: buy seller_spk + buy creator_spk");
}

#[test]
fn escrow_body_no_fee_zero() {
    assert!(
        !AUCTION_ESCROW_BODY.contains(&0xca),
        "escrow must not contain OpTxFee (not a permissionless path)"
    );
}

// --- Dispatch opcode checks ---

#[test]
fn english_dispatch_uses_op8_roll() {
    assert_eq!(ENGLISH_AUCTION_BODY[0], 0x58, "must start with Op8");
    assert_eq!(ENGLISH_AUCTION_BODY[1], 0x7a, "must be OpRoll");
}

#[test]
fn dutch_dispatch_uses_op9_roll() {
    assert_eq!(DUTCH_AUCTION_BODY[0], 0x59, "must start with Op9");
    assert_eq!(DUTCH_AUCTION_BODY[1], 0x7a, "must be OpRoll");
}

#[test]
fn escrow_dispatch_uses_op2_roll() {
    assert_eq!(AUCTION_ESCROW_BODY[0], 0x52, "must start with Op2");
    assert_eq!(AUCTION_ESCROW_BODY[1], 0x7a, "must be OpRoll");
}

// --- Body ends with Op1 (TRUE) ---

#[test]
fn all_bodies_end_with_op1_true() {
    assert_eq!(*ENGLISH_AUCTION_BODY.last().unwrap(), 0x51);
    assert_eq!(*DUTCH_AUCTION_BODY.last().unwrap(), 0x51);
    assert_eq!(*AUCTION_ESCROW_BODY.last().unwrap(), 0x51);
}

// --- Escrow: both paths require signature ---

#[test]
fn escrow_body_contains_checksigverify() {
    let count = AUCTION_ESCROW_BODY.iter().filter(|&&b| b == 0xad).count();
    assert_eq!(count, 2, "escrow must have OpCheckSigVerify in both release and cancel paths");
}

// --- English expire has F13 fix ---

#[test]
fn english_expire_has_seller_spk_check() {
    let body = ENGLISH_AUCTION_BODY;
    let first_else = body.iter().position(|&b| b == 0x67).unwrap();
    let expire_section = &body[first_else..];
    assert!(
        expire_section.contains(&0xaa),
        "expire path must contain OpBlake2b for F13 seller_spk_hash check"
    );
}

// --- Payload round-trip ---

#[test]
fn auction_payload_round_trip() {
    let rs = build_english_auction_redeem_script(
        &FAKE_PK, 100_000, &FAKE_COV_ID, 5_000_000, 1000,
        &FAKE_CREATOR_SPK_HASH, 50_000,
    ).unwrap();
    let payload = build_auction_payload(&rs);
    let parsed = parse_auction_payload(&payload).unwrap();
    assert_eq!(parsed, &rs[..]);
}

#[test]
fn auction_payload_wrong_prefix() {
    assert!(parse_auction_payload(b"KOB:X:stuff").is_none());
}
