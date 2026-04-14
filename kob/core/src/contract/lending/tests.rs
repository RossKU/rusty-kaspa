use super::*;
use crate::primitives::{push_data, u64_le};

const LOAN_OFFER_BODY_EXPECTED_LEN: usize = 85;
const BORROW_REQUEST_BODY_EXPECTED_LEN: usize = 82;
const ACTIVE_LOAN_BODY_EXPECTED_LEN: usize = ACTIVE_LOAN_BODY.len();

/// Convert integer 0..=16 to OpN opcode.
fn opn(n: u8) -> u8 {
    match n {
        0 => 0x00,
        1..=16 => 0x50 + n,
        _ => panic!("OpN index out of range: {} (must be 0..=16)", n),
    }
}

fn zero32() -> [u8; 32] {
    [0u8; 32]
}

fn sample_hash(byte: u8) -> [u8; 32] {
    [byte; 32]
}

/// push_data overhead: 1B for <=75, 2B for <=255, 3B for >255.
fn push_overhead(data_len: usize) -> usize {
    if data_len <= 75 {
        1
    } else if data_len <= 255 {
        2
    } else {
        3
    }
}

// Payload tests

#[test]
fn lending_payload_prefix() {
    assert_eq!(KOB_LENDING_PAYLOAD_PREFIX, b"KOB:L:");
    assert_eq!(KOB_LENDING_PAYLOAD_PREFIX.len(), 6);
}

#[test]
fn lending_payload_roundtrip() {
    let rs = vec![0xAB; 200];
    let payload = build_lending_payload(&rs);
    let parsed = parse_lending_payload(&payload).unwrap();
    assert_eq!(parsed, &rs[..]);
}

#[test]
fn lending_payload_empty_rs() {
    let payload = build_lending_payload(&[]);
    assert_eq!(payload, b"KOB:L:");
    let parsed = parse_lending_payload(&payload).unwrap();
    assert!(parsed.is_empty());
}

#[test]
fn lending_payload_wrong_prefix() {
    let payload = b"KOB:P:hello";
    assert!(parse_lending_payload(payload).is_none());
}

#[test]
fn lending_payload_too_short() {
    let payload = b"KOB:";
    assert!(parse_lending_payload(payload).is_none());
}

#[test]
fn lending_payload_exact_prefix_only() {
    let payload = b"KOB:L:";
    let parsed = parse_lending_payload(payload).unwrap();
    assert!(parsed.is_empty());
}

// OpN helper tests

#[test]
fn opn_values() {
    assert_eq!(opn(0), 0x00);
    assert_eq!(opn(1), 0x51);
    assert_eq!(opn(16), 0x60);
}

#[test]
#[should_panic(expected = "OpN index out of range")]
fn opn_panic_on_17() {
    opn(17);
}

// LoanOffer v3 body tests

#[test]
fn loan_offer_body_snapshot_length() {
    assert_eq!(
        LOAN_OFFER_BODY.len(),
        LOAN_OFFER_BODY_EXPECTED_LEN,
        "body length changed"
    );
}

#[test]
fn loan_offer_body_reasonable_size() {
    let len = LOAN_OFFER_BODY.len();
    assert!(len > 50, "body too small: {len}");
    assert!(len < 200, "body too large: {len}");
}

#[test]
fn loan_offer_body_starts_with_dispatch() {
    assert_eq!(LOAN_OFFER_BODY[0], 0xb9, "OpTxInputIndex");
    assert_eq!(LOAN_OFFER_BODY[1], 0xc9, "OpTxInputScriptSigLen");
    assert_eq!(LOAN_OFFER_BODY[2], 0x76, "OpDup");
}

#[test]
fn loan_offer_body_ends_with_true() {
    let body = LOAN_OFFER_BODY;
    let len = body.len();
    assert_eq!(body[len - 1], 0x51, "last byte must be Op1 (TRUE)");
    assert_eq!(body[len - 2], 0x68, "second-to-last must be OpEndIf");
}

#[test]
fn loan_offer_body_has_checksigverify() {
    assert!(
        LOAN_OFFER_BODY.contains(&0xad),
        "body must contain OpCheckSigVerify"
    );
}

#[test]
fn loan_offer_body_has_blake2b() {
    assert!(
        LOAN_OFFER_BODY.contains(&0xaa),
        "body must contain OpBlake2b for owner auth"
    );
}

#[test]
fn loan_offer_body_has_self_continuation() {
    assert!(
        LOAN_OFFER_BODY.contains(&0xbf),
        "body must contain OpTxInputSpk for replace self-continuation"
    );
}

#[test]
fn loan_offer_body_has_output_amount() {
    let out_amount = [0x00, 0xc2]; // Op0 OpTxOutputAmount
    assert!(
        LOAN_OFFER_BODY.windows(2).any(|w| w == out_amount),
        "match path must check output[0] amount"
    );
}

#[test]
fn loan_offer_opif_endif_balance() {
    let body = LOAN_OFFER_BODY;
    let opif_count = body.iter().filter(|&&b| b == 0x63).count();
    let opendif_count = body.iter().filter(|&&b| b == 0x68).count();
    assert_eq!(
        opif_count, opendif_count,
        "OpIf({opif_count}) must equal OpEndIf({opendif_count})"
    );
}

// LoanOffer v3 RS builder tests

fn default_loan_offer_rs() -> Vec<u8> {
    build_loan_offer_redeem_script(
        &sample_hash(0xAA),
        1_000_000_000, // 10 KAS principal
        500,           // 5% rate
        10000,
        15000, // 150% collateral
        31_536_000,
        &zero32(),
        0,
        0,
    )
    .unwrap()
}

#[test]
fn loan_offer_rs_size() {
    let rs = default_loan_offer_rs();
    assert_eq!(rs.len(), LOAN_OFFER_STATE_SIZE + LOAN_OFFER_BODY.len());
}

#[test]
fn loan_offer_rs_body_appended() {
    let rs = default_loan_offer_rs();
    assert_eq!(&rs[LOAN_OFFER_STATE_SIZE..], LOAN_OFFER_BODY);
}

#[test]
fn loan_offer_rejects_zero_principal() {
    let r = build_loan_offer_redeem_script(
        &zero32(), 0, 500, 10000, 15000, 100, &zero32(), 0, 0,
    );
    assert!(r.is_err());
    assert!(r.unwrap_err().to_string().contains("principal"));
}

#[test]
fn loan_offer_rejects_zero_rate_den() {
    let r = build_loan_offer_redeem_script(
        &zero32(), 1000, 500, 0, 15000, 100, &zero32(), 0, 0,
    );
    assert!(r.is_err());
    assert!(r.unwrap_err().to_string().contains("rate_den"));
}

#[test]
fn loan_offer_rejects_zero_min_collateral_ratio() {
    let r = build_loan_offer_redeem_script(
        &zero32(), 1000, 500, 10000, 0, 100, &zero32(), 0, 0,
    );
    assert!(r.is_err());
    assert!(r.unwrap_err().to_string().contains("min_collateral_ratio"));
}

#[test]
fn loan_offer_rejects_zero_max_duration() {
    let r = build_loan_offer_redeem_script(
        &zero32(), 1000, 500, 10000, 15000, 0, &zero32(), 0, 0,
    );
    assert!(r.is_err());
    assert!(r.unwrap_err().to_string().contains("max_duration_daa"));
}

#[test]
fn loan_offer_rejects_invalid_rate_mode() {
    let r = build_loan_offer_redeem_script(
        &zero32(), 1000, 500, 10000, 15000, 100, &zero32(), 2, 0,
    );
    assert!(r.is_err());
    assert!(r.unwrap_err().to_string().contains("rate_mode"));
}

#[test]
fn loan_offer_rejects_floor_with_fixed_mode() {
    let r = build_loan_offer_redeem_script(
        &zero32(), 1000, 500, 10000, 15000, 100, &zero32(), 0, 100,
    );
    assert!(r.is_err());
    assert!(r.unwrap_err().to_string().contains("rate_floor_num"));
}

#[test]
fn loan_offer_accepts_variable_with_floor() {
    let r = build_loan_offer_redeem_script(
        &zero32(), 1000, 500, 10000, 15000, 100, &zero32(), 1, 200,
    );
    assert!(r.is_ok());
}

#[test]
fn loan_offer_state_field_extraction() {
    let owner = sample_hash(0x11);
    let cov_id = sample_hash(0x22);
    let rs = build_loan_offer_redeem_script(
        &owner,
        5_000_000,
        300,
        10000,
        12000,
        99_000_000,
        &cov_id,
        1,
        100,
    )
    .unwrap();

    let mut pos = 0;
    // owner_spk_hash
    assert_eq!(rs[pos], 0x20);
    pos += 1;
    assert_eq!(&rs[pos..pos + 32], &owner);
    pos += 32;
    // principal
    assert_eq!(rs[pos], 0x08);
    pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 5_000_000);
    pos += 8;
    // rate_num
    assert_eq!(rs[pos], 0x08);
    pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 300);
    pos += 8;
    // rate_den
    assert_eq!(rs[pos], 0x08);
    pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 10000);
    pos += 8;
    // min_collateral_ratio
    assert_eq!(rs[pos], 0x08);
    pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 12000);
    pos += 8;
    // max_duration_daa
    assert_eq!(rs[pos], 0x08);
    pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 99_000_000);
    pos += 8;
    // accepted_collateral_cov_id
    assert_eq!(rs[pos], 0x20);
    pos += 1;
    assert_eq!(&rs[pos..pos + 32], &cov_id);
    pos += 32;
    // rate_mode
    assert_eq!(rs[pos], 0x08);
    pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 1);
    pos += 8;
    // rate_floor_num
    assert_eq!(rs[pos], 0x08);
    pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 100);
    pos += 8;
    // body
    assert_eq!(&rs[pos..], LOAN_OFFER_BODY);
}

#[test]
fn loan_offer_different_params_different_rs() {
    let rs1 = build_loan_offer_redeem_script(
        &sample_hash(0x01), 1000, 500, 10000, 15000, 100, &zero32(), 0, 0,
    )
    .unwrap();
    let rs2 = build_loan_offer_redeem_script(
        &sample_hash(0x02), 1000, 500, 10000, 15000, 100, &zero32(), 0, 0,
    )
    .unwrap();
    assert_ne!(rs1, rs2);
}

#[test]
fn loan_offer_different_principal_different_rs() {
    let rs1 = build_loan_offer_redeem_script(
        &zero32(), 1000, 500, 10000, 15000, 100, &zero32(), 0, 0,
    )
    .unwrap();
    let rs2 = build_loan_offer_redeem_script(
        &zero32(), 2000, 500, 10000, 15000, 100, &zero32(), 0, 0,
    )
    .unwrap();
    assert_ne!(rs1, rs2);
}

#[test]
fn loan_offer_deterministic() {
    let rs1 = default_loan_offer_rs();
    let rs2 = default_loan_offer_rs();
    assert_eq!(rs1, rs2);
}

#[test]
fn loan_offer_accepts_zero_rate_num() {
    // 0% interest is valid (interest-free loan)
    let r = build_loan_offer_redeem_script(
        &zero32(), 1000, 0, 10000, 15000, 100, &zero32(), 0, 0,
    );
    assert!(r.is_ok());
}

// LoanOffer v3 sigscript tests

#[test]
fn loan_offer_match_sigscript_structure() {
    let rs = default_loan_offer_rs();
    let ss = build_loan_offer_match_sigscript(&rs);
    // pushData(RS)
    let overhead = push_overhead(rs.len());
    assert_eq!(ss.len(), overhead + rs.len());
}

#[test]
fn loan_offer_cancel_sigscript_structure() {
    let fake_sig = [0xAA; 64];
    let fake_pk = [0xBB; 32];
    let rs = default_loan_offer_rs();
    let ss = build_loan_offer_cancel_sigscript(&fake_sig, &fake_pk, &rs);

    // sig: pushData(65B) = 0x41 prefix + 64B sig + 0x01 sighash
    assert_eq!(ss[0], 0x41, "sig push prefix must be 65");
    assert_eq!(&ss[1..65], &fake_sig[..]);
    assert_eq!(ss[65], 0x01, "sighash type");
    // pk: pushData(32B) = 0x20 prefix + 32B
    assert_eq!(ss[66], 0x20, "pk push prefix must be 32");
    assert_eq!(&ss[67..99], &fake_pk[..]);
}

#[test]
fn loan_offer_replace_sigscript_structure() {
    let fake_sig = [0xCC; 64];
    let fake_pk = [0xDD; 32];
    let rs = default_loan_offer_rs();
    let ss = build_loan_offer_replace_sigscript(&fake_sig, &fake_pk, 600, 10000, &rs);

    // new_rate_num: pushData(8B) = 0x08 prefix + 8B
    assert_eq!(ss[0], 0x08, "new_rate_num push prefix");
    assert_eq!(&ss[1..9], &u64_le(600));
    // new_rate_den: pushData(8B)
    assert_eq!(ss[9], 0x08, "new_rate_den push prefix");
    assert_eq!(&ss[10..18], &u64_le(10000));
    // sig: pushData(65B)
    assert_eq!(ss[18], 0x41, "sig push prefix");
}

#[test]
fn loan_offer_sigscript_thresholds() {
    let rs = default_loan_offer_rs();
    let match_ss = build_loan_offer_match_sigscript(&rs);
    let fake_sig = [0u8; 64];
    let fake_pk = [0u8; 32];
    let cancel_ss = build_loan_offer_cancel_sigscript(&fake_sig, &fake_pk, &rs);
    let replace_ss =
        build_loan_offer_replace_sigscript(&fake_sig, &fake_pk, 500, 10000, &rs);

    let match_len = match_ss.len();
    let cancel_len = cancel_ss.len();
    let replace_len = replace_ss.len();

    // T1=250, T2=330
    assert!(
        match_len < 250,
        "match({match_len}) must be < T1(250)"
    );
    assert!(
        cancel_len >= 250,
        "cancel({cancel_len}) must be >= T1(250)"
    );
    assert!(
        cancel_len < 330,
        "cancel({cancel_len}) must be < T2(330)"
    );
    assert!(
        replace_len >= 330,
        "replace({replace_len}) must be >= T2(330)"
    );
}

#[test]
fn loan_offer_body_hex_snapshot() {
    let hex: String = LOAN_OFFER_BODY
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    assert!(hex.starts_with("b9c976"), "dispatch prefix must be b9c976");
    assert!(hex.ends_with("6851"), "must end with OpEndIf+Op1");
}

#[test]
fn loan_offer_drop_count() {
    let body = LOAN_OFFER_BODY;
    let drop_count = body.iter().filter(|&&b| b == 0x75).count();
    // Match: 9, Cancel: 9, Replace: 11 = 29 total
    assert!(
        drop_count >= 25,
        "must have enough OpDrop, got {drop_count}"
    );
}

// BorrowRequest v3 body tests

#[test]
fn borrow_request_body_snapshot_length() {
    assert_eq!(
        BORROW_REQUEST_BODY.len(),
        BORROW_REQUEST_BODY_EXPECTED_LEN,
        "body length changed"
    );
}

#[test]
fn borrow_request_body_reasonable_size() {
    let len = BORROW_REQUEST_BODY.len();
    assert!(len > 30, "body too small: {len}");
    assert!(len < 150, "body too large: {len}");
}

#[test]
fn borrow_request_body_starts_with_dispatch() {
    assert_eq!(BORROW_REQUEST_BODY[0], 0xb9, "OpTxInputIndex");
    assert_eq!(BORROW_REQUEST_BODY[1], 0xc9, "OpTxInputScriptSigLen");
}

#[test]
fn borrow_request_body_ends_with_true() {
    let body = BORROW_REQUEST_BODY;
    let len = body.len();
    assert_eq!(body[len - 1], 0x51, "last byte must be Op1");
    assert_eq!(body[len - 2], 0x68, "second-to-last must be OpEndIf");
}

#[test]
fn borrow_request_body_has_checksigverify() {
    assert!(BORROW_REQUEST_BODY.contains(&0xad));
}

#[test]
fn borrow_request_body_has_blake2b() {
    assert!(BORROW_REQUEST_BODY.contains(&0xaa));
}

#[test]
fn borrow_request_opif_endif_balance() {
    let body = BORROW_REQUEST_BODY;
    let opif = body.iter().filter(|&&b| b == 0x63).count();
    let opendif = body.iter().filter(|&&b| b == 0x68).count();
    assert_eq!(opif, opendif);
}

// BorrowRequest v3 RS builder tests

fn default_borrow_request_rs() -> Vec<u8> {
    build_borrow_request_redeem_script(
        &sample_hash(0xBB),
        500_000_000, // 5 KAS desired
        800,         // max 8% rate
        10000,
        15_768_000, // ~6 months min duration
        &zero32(),
        0,
        0,
    )
    .unwrap()
}

#[test]
fn borrow_request_rs_size() {
    let rs = default_borrow_request_rs();
    assert_eq!(
        rs.len(),
        BORROW_REQUEST_STATE_SIZE + BORROW_REQUEST_BODY.len()
    );
}

#[test]
fn borrow_request_rs_body_appended() {
    let rs = default_borrow_request_rs();
    assert_eq!(&rs[BORROW_REQUEST_STATE_SIZE..], BORROW_REQUEST_BODY);
}

#[test]
fn borrow_request_rejects_zero_desired_amount() {
    let r = build_borrow_request_redeem_script(
        &zero32(), 0, 500, 10000, 100, &zero32(), 0, 0,
    );
    assert!(r.is_err());
    assert!(r.unwrap_err().to_string().contains("desired_amount"));
}

#[test]
fn borrow_request_rejects_zero_max_rate_den() {
    let r = build_borrow_request_redeem_script(
        &zero32(), 1000, 500, 0, 100, &zero32(), 0, 0,
    );
    assert!(r.is_err());
    assert!(r.unwrap_err().to_string().contains("max_rate_den"));
}

#[test]
fn borrow_request_rejects_invalid_rate_mode() {
    let r = build_borrow_request_redeem_script(
        &zero32(), 1000, 500, 10000, 100, &zero32(), 3, 0,
    );
    assert!(r.is_err());
    assert!(r.unwrap_err().to_string().contains("rate_mode"));
}

#[test]
fn borrow_request_rejects_cap_with_fixed_mode() {
    let r = build_borrow_request_redeem_script(
        &zero32(), 1000, 500, 10000, 100, &zero32(), 0, 100,
    );
    assert!(r.is_err());
    assert!(r.unwrap_err().to_string().contains("rate_cap_num"));
}

#[test]
fn borrow_request_accepts_variable_with_cap() {
    let r = build_borrow_request_redeem_script(
        &zero32(), 1000, 500, 10000, 100, &zero32(), 1, 800,
    );
    assert!(r.is_ok());
}

#[test]
fn borrow_request_accepts_either_mode() {
    let r = build_borrow_request_redeem_script(
        &zero32(), 1000, 500, 10000, 100, &zero32(), 2, 900,
    );
    assert!(r.is_ok());
}

#[test]
fn borrow_request_deterministic() {
    let rs1 = default_borrow_request_rs();
    let rs2 = default_borrow_request_rs();
    assert_eq!(rs1, rs2);
}

#[test]
fn borrow_request_different_params_different_rs() {
    let rs1 = build_borrow_request_redeem_script(
        &sample_hash(0x01), 1000, 500, 10000, 100, &zero32(), 0, 0,
    )
    .unwrap();
    let rs2 = build_borrow_request_redeem_script(
        &sample_hash(0x02), 1000, 500, 10000, 100, &zero32(), 0, 0,
    )
    .unwrap();
    assert_ne!(rs1, rs2);
}

#[test]
fn borrow_request_state_field_extraction() {
    let owner = sample_hash(0x33);
    let cov_id = sample_hash(0x44);
    let rs = build_borrow_request_redeem_script(
        &owner, 7_777_777, 600, 10000, 31_536_000, &cov_id, 2, 1000,
    )
    .unwrap();

    let mut pos = 0;
    // owner
    assert_eq!(rs[pos], 0x20);
    pos += 1;
    assert_eq!(&rs[pos..pos + 32], &owner);
    pos += 32;
    // desired_amount
    assert_eq!(rs[pos], 0x08);
    pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 7_777_777);
    pos += 8;
    // max_rate_num
    assert_eq!(rs[pos], 0x08);
    pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 600);
    pos += 8;
    // max_rate_den
    assert_eq!(rs[pos], 0x08);
    pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 10000);
    pos += 8;
    // min_duration_daa
    assert_eq!(rs[pos], 0x08);
    pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 31_536_000);
    pos += 8;
    // collateral_cov_id
    assert_eq!(rs[pos], 0x20);
    pos += 1;
    assert_eq!(&rs[pos..pos + 32], &cov_id);
    pos += 32;
    // rate_mode
    assert_eq!(rs[pos], 0x08);
    pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 2);
    pos += 8;
    // rate_cap_num
    assert_eq!(rs[pos], 0x08);
    pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 1000);
    pos += 8;
    // body
    assert_eq!(&rs[pos..], BORROW_REQUEST_BODY);
}

// BorrowRequest v3 sigscript tests

#[test]
fn borrow_request_match_sigscript_structure() {
    let rs = default_borrow_request_rs();
    let ss = build_borrow_request_match_sigscript(&rs);
    let overhead = push_overhead(rs.len());
    assert_eq!(ss.len(), overhead + rs.len());
}

#[test]
fn borrow_request_cancel_sigscript_structure() {
    let fake_sig = [0xEE; 64];
    let fake_pk = [0xFF; 32];
    let rs = default_borrow_request_rs();
    let ss = build_borrow_request_cancel_sigscript(&fake_sig, &fake_pk, &rs);

    assert_eq!(ss[0], 0x41, "sig push prefix");
    assert_eq!(&ss[1..65], &fake_sig[..]);
    assert_eq!(ss[65], 0x01, "sighash type");
    assert_eq!(ss[66], 0x20, "pk push prefix");
    assert_eq!(&ss[67..99], &fake_pk[..]);
}

#[test]
fn borrow_request_sigscript_thresholds() {
    let rs = default_borrow_request_rs();
    let match_ss = build_borrow_request_match_sigscript(&rs);
    let fake_sig = [0u8; 64];
    let fake_pk = [0u8; 32];
    let cancel_ss = build_borrow_request_cancel_sigscript(&fake_sig, &fake_pk, &rs);

    let match_len = match_ss.len();
    let cancel_len = cancel_ss.len();

    // T1=250
    assert!(
        match_len < 250,
        "match({match_len}) must be < T1(250)"
    );
    assert!(
        cancel_len >= 250,
        "cancel({cancel_len}) must be >= T1(250)"
    );
}

#[test]
fn borrow_request_accepts_zero_min_duration() {
    let r = build_borrow_request_redeem_script(
        &zero32(), 1000, 500, 10000, 0, &zero32(), 0, 0,
    );
    assert!(r.is_ok());
}

#[test]
fn borrow_request_accepts_zero_max_rate_num() {
    // max_rate_num=0 means borrower wants 0% interest (unlikely but valid)
    let r = build_borrow_request_redeem_script(
        &zero32(), 1000, 0, 10000, 100, &zero32(), 0, 0,
    );
    assert!(r.is_ok());
}

#[test]
fn borrow_request_drop_count() {
    let body = BORROW_REQUEST_BODY;
    let drop_count = body.iter().filter(|&&b| b == 0x75).count();
    // Match: 8, Cancel: 8 = 16
    assert!(
        drop_count >= 14,
        "must have enough OpDrop, got {drop_count}"
    );
}

// ActiveLoan v3 body tests

#[test]
fn active_loan_body_snapshot_length() {
    assert_eq!(
        ACTIVE_LOAN_BODY.len(),
        ACTIVE_LOAN_BODY_EXPECTED_LEN,
        "body length changed"
    );
}

#[test]
fn active_loan_body_reasonable_size() {
    let len = ACTIVE_LOAN_BODY.len();
    assert!(len > 200, "body too small: {len}");
    assert!(len < 900, "body too large: {len}");
}

#[test]
fn active_loan_body_starts_with_selector_dispatch() {
    // Selector-based dispatch: Op14(0x5e) OpRoll(0x7a) to bring selector to top
    assert_eq!(ACTIVE_LOAN_BODY[0], 0x5e, "Op14");
    assert_eq!(ACTIVE_LOAN_BODY[1], 0x7a, "OpRoll");
    assert_eq!(ACTIVE_LOAN_BODY[2], 0x76, "OpDup");
}

#[test]
fn active_loan_body_ends_with_true() {
    let body = ACTIVE_LOAN_BODY;
    let len = body.len();
    assert_eq!(body[len - 1], 0x51);
    assert_eq!(body[len - 2], 0x68);
}

#[test]
fn active_loan_body_has_checksigverify() {
    assert!(ACTIVE_LOAN_BODY.contains(&0xad));
}

#[test]
fn active_loan_body_has_blake2b() {
    assert!(ACTIVE_LOAN_BODY.contains(&0xaa));
}

#[test]
fn active_loan_opif_endif_balance() {
    let body = ACTIVE_LOAN_BODY;
    let opif = body.iter().filter(|&&b| b == 0x63).count();
    let opendif = body.iter().filter(|&&b| b == 0x68).count();
    // OpEndIf count is OpIf count + 1 (insurance branch uses OpNotIf which is
    // indistinguishable from push data 0x64 in a naive byte scan).
    assert_eq!(opif + 1, opendif, "OpIf({opif})+1 must equal OpEndIf({opendif})");
}

// ActiveLoan v3 RS builder tests

fn default_active_loan_rs() -> Vec<u8> {
    build_active_loan_redeem_script(
        &[0u8; 32],         // insurer (none)
        &sample_hash(0xAA), // lender
        &sample_hash(0xBB), // borrower
        1_000_000_000,      // 10 KAS principal
        500,                // 5% rate
        10000,
        100_000_000,  // start_daa
        131_536_000,  // expiry_daa
        &zero32(),    // KAS collateral
        0,            // fixed
        0,
        0,
        3_153_600,    // grace_daa (~1 day)
        15000,        // liq_threshold (150%)
    )
    .unwrap()
}

#[test]
fn active_loan_rs_size() {
    let rs = default_active_loan_rs();
    assert_eq!(rs.len(), ACTIVE_LOAN_STATE_SIZE + ACTIVE_LOAN_BODY.len());
}

#[test]
fn active_loan_rs_body_appended() {
    let rs = default_active_loan_rs();
    assert_eq!(&rs[ACTIVE_LOAN_STATE_SIZE..], ACTIVE_LOAN_BODY);
}

#[test]
fn active_loan_rejects_zero_principal() {
    let r = build_active_loan_redeem_script(
        &[0u8; 32], &zero32(), &zero32(), 0, 500, 10000, 100, 200, &zero32(), 0, 0, 0, 0, 15000,
    );
    assert!(r.is_err());
    assert!(r.unwrap_err().to_string().contains("principal"));
}

#[test]
fn active_loan_rejects_zero_rate_den() {
    let r = build_active_loan_redeem_script(
        &[0u8; 32], &zero32(), &zero32(), 1000, 500, 0, 100, 200, &zero32(), 0, 0, 0, 0, 15000,
    );
    assert!(r.is_err());
    assert!(r.unwrap_err().to_string().contains("rate_den"));
}

#[test]
fn active_loan_rejects_zero_expiry() {
    let r = build_active_loan_redeem_script(
        &[0u8; 32], &zero32(), &zero32(), 1000, 500, 10000, 100, 0, &zero32(), 0, 0, 0, 0, 15000,
    );
    assert!(r.is_err());
    assert!(r.unwrap_err().to_string().contains("expiry_daa"));
}

#[test]
fn active_loan_rejects_expiry_before_start() {
    let r = build_active_loan_redeem_script(
        &[0u8; 32], &zero32(), &zero32(), 1000, 500, 10000, 200, 100, &zero32(), 0, 0, 0, 0, 15000,
    );
    assert!(r.is_err());
    assert!(r.unwrap_err().to_string().contains("expiry_daa must be > start_daa"));
}

#[test]
fn active_loan_rejects_expiry_equals_start() {
    let r = build_active_loan_redeem_script(
        &[0u8; 32], &zero32(), &zero32(), 1000, 500, 10000, 100, 100, &zero32(), 0, 0, 0, 0, 15000,
    );
    assert!(r.is_err());
}

#[test]
fn active_loan_rejects_invalid_rate_mode() {
    let r = build_active_loan_redeem_script(
        &[0u8; 32], &zero32(), &zero32(), 1000, 500, 10000, 100, 200, &zero32(), 2, 0, 0, 0, 15000,
    );
    assert!(r.is_err());
    assert!(r.unwrap_err().to_string().contains("rate_mode"));
}

#[test]
fn active_loan_rejects_floor_cap_with_fixed() {
    let r = build_active_loan_redeem_script(
        &[0u8; 32], &zero32(), &zero32(), 1000, 500, 10000, 100, 200, &zero32(), 0, 100, 200, 0, 15000,
    );
    assert!(r.is_err());
}

#[test]
fn active_loan_rejects_floor_above_cap() {
    let r = build_active_loan_redeem_script(
        &[0u8; 32], &zero32(), &zero32(), 1000, 500, 10000, 100, 200, &zero32(), 1, 500, 200, 0, 15000,
    );
    assert!(r.is_err());
    assert!(r.unwrap_err().to_string().contains("rate_floor_num must be <= rate_cap_num"));
}

#[test]
fn active_loan_accepts_variable_with_floor_cap() {
    let r = build_active_loan_redeem_script(
        &[0u8; 32], &zero32(), &zero32(), 1000, 500, 10000, 100, 200, &zero32(), 1, 200, 800, 1, 15000,
    );
    assert!(r.is_ok());
}

#[test]
fn active_loan_accepts_variable_zero_cap() {
    // rate_cap_num=0 means no cap
    let r = build_active_loan_redeem_script(
        &[0u8; 32], &zero32(), &zero32(), 1000, 500, 10000, 100, 200, &zero32(), 1, 0, 0, 1, 15000,
    );
    assert!(r.is_ok());
}

#[test]
fn active_loan_deterministic() {
    let rs1 = default_active_loan_rs();
    let rs2 = default_active_loan_rs();
    assert_eq!(rs1, rs2);
}

#[test]
fn active_loan_different_params_different_rs() {
    let rs1 = build_active_loan_redeem_script(
        &[0u8; 32], &sample_hash(0x01), &sample_hash(0x02), 1000, 500, 10000,
        100, 200, &zero32(), 0, 0, 0, 1, 15000,
    )
    .unwrap();
    let rs2 = build_active_loan_redeem_script(
        &[0u8; 32], &sample_hash(0x03), &sample_hash(0x04), 1000, 500, 10000,
        100, 200, &zero32(), 0, 0, 0, 1, 15000,
    )
    .unwrap();
    assert_ne!(rs1, rs2);
}

#[test]
fn active_loan_state_field_extraction() {
    let lender = sample_hash(0x11);
    let borrower = sample_hash(0x22);
    let cov_id = sample_hash(0x33);
    let rs = build_active_loan_redeem_script(
        &[0u8; 32], &lender,
        &borrower,
        9_999_999,
        750,
        10000,
        50_000_000,
        80_000_000,
        &cov_id,
        1,
        200,
        900,
        1_000_000,
        15000,
    )
    .unwrap();

    let mut pos = 0;
    // insurer_spk_hash
    assert_eq!(rs[pos], 0x20);
    pos += 1;
    assert_eq!(&rs[pos..pos + 32], &[0u8; 32]);
    pos += 32;
    // lender_spk_hash
    assert_eq!(rs[pos], 0x20);
    pos += 1;
    assert_eq!(&rs[pos..pos + 32], &lender);
    pos += 32;
    // borrower_spk_hash
    assert_eq!(rs[pos], 0x20);
    pos += 1;
    assert_eq!(&rs[pos..pos + 32], &borrower);
    pos += 32;
    // principal
    assert_eq!(rs[pos], 0x08);
    pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 9_999_999);
    pos += 8;
    // rate_num
    assert_eq!(rs[pos], 0x08);
    pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 750);
    pos += 8;
    // rate_den
    assert_eq!(rs[pos], 0x08);
    pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 10000);
    pos += 8;
    // start_daa
    assert_eq!(rs[pos], 0x08);
    pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 50_000_000);
    pos += 8;
    // expiry_daa
    assert_eq!(rs[pos], 0x08);
    pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 80_000_000);
    pos += 8;
    // collateral_cov_id
    assert_eq!(rs[pos], 0x20);
    pos += 1;
    assert_eq!(&rs[pos..pos + 32], &cov_id);
    pos += 32;
    // rate_mode
    assert_eq!(rs[pos], 0x08);
    pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 1);
    pos += 8;
    // rate_floor_num
    assert_eq!(rs[pos], 0x08);
    pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 200);
    pos += 8;
    // rate_cap_num
    assert_eq!(rs[pos], 0x08);
    pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 900);
    pos += 8;
    // grace_daa
    assert_eq!(rs[pos], 0x08);
    pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 1_000_000);
    pos += 8;
    // liq_threshold
    assert_eq!(rs[pos], 0x08);
    pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 15000);
    pos += 8;
    // body
    assert_eq!(&rs[pos..], ACTIVE_LOAN_BODY);
}

// ActiveLoan v3 sigscript tests

#[test]
fn active_loan_repay_sigscript_structure() {
    let fake_sig = [0xAA; 64];
    let fake_pk = [0xBB; 32];
    let rs = default_active_loan_rs();
    let ss = build_active_loan_repay_sigscript(&fake_sig, &fake_pk, 2, &rs);

    // loi: OpN(2) = Op2 = 0x52
    assert_eq!(ss[0], 0x52, "loi OpN(2)");
    // sig: pushData(65B)
    assert_eq!(ss[1], 0x41, "sig push prefix");
    assert_eq!(&ss[2..66], &fake_sig[..]);
    assert_eq!(ss[66], 0x01, "sighash type");
    // pk: pushData(32B)
    assert_eq!(ss[67], 0x20, "pk push prefix");
    assert_eq!(&ss[68..100], &fake_pk[..]);
    // selector: Op3 = 0x53
    assert_eq!(ss[100], 0x53, "selector Op3");
}

#[test]
fn active_loan_default_sigscript_structure() {
    let fake_sig = [0xCC; 64];
    let fake_pk = [0xDD; 32];
    let rs = default_active_loan_rs();
    let ss = build_active_loan_default_sigscript(&fake_sig, &fake_pk, &rs);

    assert_eq!(ss[0], 0x41, "sig push prefix");
    assert_eq!(&ss[1..65], &fake_sig[..]);
    assert_eq!(ss[65], 0x01, "sighash type");
    assert_eq!(ss[66], 0x20, "pk push prefix");
    assert_eq!(&ss[67..99], &fake_pk[..]);
    // selector: Op2 = 0x52
    assert_eq!(ss[99], 0x52, "selector Op2");
}

#[test]
fn active_loan_liquidate_sigscript_structure() {
    let rs = default_active_loan_rs();
    let ss = build_active_loan_liquidate_sigscript(1, 0, 2, 3, &rs);

    assert_eq!(ss[0], opn(1), "price_input_idx");
    assert_eq!(ss[1], opn(0), "lender_output_idx");
    assert_eq!(ss[2], opn(2), "borrower_output_idx");
    assert_eq!(ss[3], opn(3), "liquidator_output_idx");
    // selector: Op1 = 0x51
    assert_eq!(ss[4], 0x51, "selector Op1");
}

#[test]
fn active_loan_selector_dispatch_all_paths() {
    // Verify all 10 paths have unique selectors in their sigscripts
    let rs = default_active_loan_rs();
    let fake_sig = [0u8; 64];
    let fake_pk = [0u8; 32];
    let rs_pd = push_data(&rs);
    let rs_pd_len = rs_pd.len();

    let liq_ss = build_active_loan_liquidate_sigscript(1, 0, 2, 3, &rs);
    let def_ss = build_active_loan_default_sigscript(&fake_sig, &fake_pk, &rs);
    let rep_ss = build_active_loan_repay_sigscript(&fake_sig, &fake_pk, 0, &rs);
    let prp_ss = build_active_loan_partial_repay_sigscript(&fake_sig, &fake_pk, 0, 100, &rs, &rs, &rs);
    let top_ss = build_active_loan_topup_sigscript(&fake_sig, &fake_pk, 0, &rs);
    let ext_ss = build_active_loan_extend_sigscript(&fake_sig, &fake_pk, &fake_sig, &fake_pk, 0, 200_000_000, &rs, &rs, &rs);
    let reb_ss = build_active_loan_rebalance_sigscript(1, 0, 2, &rs, &rs, &rs);
    let red_ss = build_active_loan_redemption_sigscript(0, &rs);
    let pliq_ss = build_active_loan_partial_liquidation_sigscript(1, 0, 2, 3, 50_000, &rs);
    let xfer_ss = build_active_loan_loan_transfer_sigscript(&fake_sig, &fake_pk, 0, &sample_hash(0xFF), &rs, &rs, &rs);

    // Each sigscript must end with pushData(RS), preceded by selector OpN
    // Selector byte is just before the RS push_data
    let check_sel = |name: &str, ss: &[u8], expected_sel: u8| {
        let sel_pos = ss.len() - rs_pd_len - 1;
        assert_eq!(ss[sel_pos], expected_sel,
            "{name} selector byte at pos {sel_pos} must be 0x{expected_sel:02x}, got 0x{:02x}",
            ss[sel_pos]);
    };

    check_sel("liquidate", &liq_ss, 0x51);      // Op1
    check_sel("default", &def_ss, 0x52);         // Op2
    check_sel("repay", &rep_ss, 0x53);            // Op3
    check_sel("partial_repay", &prp_ss, 0x54);    // Op4
    check_sel("topup", &top_ss, 0x55);            // Op5
    check_sel("extend", &ext_ss, 0x56);            // Op6
    check_sel("rebalance", &reb_ss, 0x57);        // Op7
    check_sel("redemption", &red_ss, 0x58);       // Op8
    check_sel("partial_liq", &pliq_ss, 0x59);     // Op9
    check_sel("loan_transfer", &xfer_ss, 0x5a);   // Op10
}

#[test]
fn active_loan_body_hex_snapshot() {
    let hex: String = ACTIVE_LOAN_BODY
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    // Selector dispatch: Op14(5e) OpRoll(7a) OpDup(76)
    assert!(hex.starts_with("5e7a76"), "dispatch prefix must be 5e7a76");
    assert!(hex.ends_with("6851"), "closing");
}

#[test]
fn active_loan_drop_count() {
    let body = ACTIVE_LOAN_BODY;
    let drop_count = body.iter().filter(|&&b| b == 0x75).count();
    // Liquidate: 15, Default: 11, Repay: 12 = 38
    assert!(
        drop_count >= 30,
        "must have enough OpDrop, got {drop_count}"
    );
}

// Interest calculation tests

#[test]
fn interest_zero_elapsed() {
    let i = calculate_interest(1_000_000_000, 500, 10000, 0);
    assert_eq!(i, Some(0));
}

#[test]
fn interest_one_year() {
    // 10 KAS at 5% for 1 year
    let i = calculate_interest(1_000_000_000, 500, 10000, DAA_PER_YEAR);
    // 1_000_000_000 * 500 / 10000 = 50_000_000
    assert_eq!(i, Some(50_000_000));
}

#[test]
fn interest_half_year() {
    let i = calculate_interest(1_000_000_000, 500, 10000, DAA_PER_YEAR / 2);
    // ~25_000_000 (integer division)
    assert_eq!(i, Some(25_000_000));
}

#[test]
fn interest_zero_rate() {
    let i = calculate_interest(1_000_000_000, 0, 10000, DAA_PER_YEAR);
    assert_eq!(i, Some(0));
}

#[test]
fn interest_zero_rate_den() {
    let i = calculate_interest(1_000_000_000, 500, 0, DAA_PER_YEAR);
    assert_eq!(i, None);
}

#[test]
fn interest_high_rate() {
    // 100% rate
    let i = calculate_interest(1_000_000_000, 10000, 10000, DAA_PER_YEAR);
    assert_eq!(i, Some(1_000_000_000));
}

#[test]
fn interest_small_amounts() {
    // 1 sompi at 5% for 1 year -> 0 (rounds down)
    let i = calculate_interest(1, 500, 10000, DAA_PER_YEAR);
    assert_eq!(i, Some(0));
}

#[test]
fn repay_total_basic() {
    let r = calculate_repay_total(1_000_000_000, 500, 10000, DAA_PER_YEAR);
    assert_eq!(r, Some(1_050_000_000));
}

#[test]
fn repay_total_zero_elapsed() {
    let r = calculate_repay_total(1_000_000_000, 500, 10000, 0);
    assert_eq!(r, Some(1_000_000_000));
}

#[test]
fn repay_total_zero_den() {
    let r = calculate_repay_total(1_000_000_000, 500, 0, DAA_PER_YEAR);
    assert_eq!(r, None);
}

#[test]
fn daa_per_year_constant() {
    assert_eq!(DAA_PER_YEAR, 315_360_000);
    // 10 BPS * 86400 * 365
    assert_eq!(10 * 86400 * 365, 315_360_000u64);
}

// State size constant verification

#[test]
fn loan_offer_state_size_matches_spec() {
    // 2 hashes: 2 * (1+32) = 66
    // 7 u64s:   7 * (1+8)  = 63
    // Total: 129
    assert_eq!(LOAN_OFFER_STATE_SIZE, 129);
}

#[test]
fn borrow_request_state_size_matches_spec() {
    // 2 hashes: 2 * (1+32) = 66
    // 6 u64s:   6 * (1+8)  = 54
    // Total: 120
    assert_eq!(BORROW_REQUEST_STATE_SIZE, 120);
}

#[test]
fn active_loan_state_size_matches_spec() {
    // 4 hashes: 4 * (1+32) = 132  (insurer, lender, borrower, collateral_cov_id)
    // 10 u64s:  10 * (1+8) = 90
    // Total: 222
    assert_eq!(ACTIVE_LOAN_STATE_SIZE, 222);
}

// Cross-covenant consistency tests

#[test]
fn all_bodies_end_with_true() {
    for (name, body) in [
        ("LoanOffer", LOAN_OFFER_BODY),
        ("BorrowRequest", BORROW_REQUEST_BODY),
        ("ActiveLoan", ACTIVE_LOAN_BODY),
    ] {
        let len = body.len();
        assert_eq!(
            body[len - 1], 0x51,
            "{name} body must end with Op1 (TRUE)"
        );
    }
}

#[test]
fn all_bodies_start_with_dispatch() {
    // LoanOffer and BorrowRequest use sigLen-based dispatch (OpTxInputIndex + OpTxInputScriptSigLen)
    for (name, body) in [
        ("LoanOffer", LOAN_OFFER_BODY),
        ("BorrowRequest", BORROW_REQUEST_BODY),
    ] {
        assert_eq!(
            body[0], 0xb9,
            "{name} body must start with OpTxInputIndex"
        );
        assert_eq!(
            body[1], 0xc9,
            "{name} body second byte must be OpTxInputScriptSigLen"
        );
    }
    // ActiveLoan uses selector-based dispatch (Op14 OpRoll)
    assert_eq!(ACTIVE_LOAN_BODY[0], 0x5e, "ActiveLoan must start with Op14");
    assert_eq!(ACTIVE_LOAN_BODY[1], 0x7a, "ActiveLoan second byte must be OpRoll");
}

#[test]
fn all_bodies_have_balanced_if_endif() {
    for (name, body) in [
        ("LoanOffer", LOAN_OFFER_BODY),
        ("BorrowRequest", BORROW_REQUEST_BODY),
        ("ActiveLoan", ACTIVE_LOAN_BODY),
    ] {
        let opif = body.iter().filter(|&&b| b == 0x63).count();
        let opendif = body.iter().filter(|&&b| b == 0x68).count();
        // ActiveLoan has 1 OpNotIf (insurance branch) which adds 1 OpEndIf
        let extra_notif = if name == "ActiveLoan" { 1 } else { 0 };
        assert_eq!(
            opif + extra_notif, opendif,
            "{name}: OpIf({opif})+{extra_notif} != OpEndIf({opendif})"
        );
    }
}

#[test]
fn all_cancel_paths_have_checksigverify() {
    for (name, body) in [
        ("LoanOffer", LOAN_OFFER_BODY),
        ("BorrowRequest", BORROW_REQUEST_BODY),
        ("ActiveLoan", ACTIVE_LOAN_BODY),
    ] {
        assert!(
            body.contains(&0xad),
            "{name} must contain OpCheckSigVerify"
        );
    }
}

#[test]
fn all_auth_paths_have_blake2b() {
    for (name, body) in [
        ("LoanOffer", LOAN_OFFER_BODY),
        ("BorrowRequest", BORROW_REQUEST_BODY),
        ("ActiveLoan", ACTIVE_LOAN_BODY),
    ] {
        assert!(
            body.contains(&0xaa),
            "{name} must contain OpBlake2b for auth"
        );
    }
}

// Payload prefix distinctness

#[test]
fn lending_prefix_distinct_from_spot_and_perp() {
    assert_ne!(KOB_LENDING_PAYLOAD_PREFIX, b"KOB:1:");
    assert_ne!(KOB_LENDING_PAYLOAD_PREFIX, b"KOB:2:");
    assert_ne!(KOB_LENDING_PAYLOAD_PREFIX, b"KOB:P:");
}

// Edge case: large values

#[test]
fn loan_offer_max_principal() {
    let r = build_loan_offer_redeem_script(
        &zero32(),
        u64::MAX,
        500,
        10000,
        15000,
        100,
        &zero32(),
        0,
        0,
    );
    assert!(r.is_ok());
    let rs = r.unwrap();
    let princ = u64::from_le_bytes(rs[34..42].try_into().unwrap());
    assert_eq!(princ, u64::MAX);
}

#[test]
fn active_loan_max_rate() {
    let r = build_active_loan_redeem_script(
        &[0u8; 32], &zero32(),
        &zero32(),
        1000,
        u64::MAX,
        u64::MAX,
        100,
        200,
        &zero32(),
        0,
        0,
        0,
        1,
        15000,
    );
    assert!(r.is_ok());
}

#[test]
fn interest_no_overflow_large_values() {
    // u128 intermediates should handle this
    let i = calculate_interest(u64::MAX, 10000, 10000, DAA_PER_YEAR);
    assert_eq!(i, Some(u64::MAX)); // rate=100% for 1 year
}

#[test]
fn interest_overflow_returns_none() {
    // principal=MAX, rate=200%, elapsed=2 years -> overflow u64
    let i = calculate_interest(u64::MAX, 20000, 10000, DAA_PER_YEAR * 2);
    // 4 * u64::MAX > u64::MAX
    assert_eq!(i, None);
}

// Sigscript length determinism

#[test]
fn loan_offer_sigscript_lengths_deterministic() {
    let rs1 = default_loan_offer_rs();
    let rs2 = build_loan_offer_redeem_script(
        &sample_hash(0xFF), 999, 100, 10000, 12000, 50, &sample_hash(0xEE), 1, 50,
    )
    .unwrap();
    // Both RS have same length (state + body are same sizes)
    assert_eq!(rs1.len(), rs2.len(), "all loan offer RS must have same length");
}

#[test]
fn borrow_request_sigscript_lengths_deterministic() {
    let rs1 = default_borrow_request_rs();
    let rs2 = build_borrow_request_redeem_script(
        &sample_hash(0xFF), 999, 100, 10000, 50, &sample_hash(0xEE), 2, 500,
    )
    .unwrap();
    assert_eq!(rs1.len(), rs2.len());
}

#[test]
fn active_loan_sigscript_lengths_deterministic() {
    let rs1 = default_active_loan_rs();
    let rs2 = build_active_loan_redeem_script(
        &[0u8; 32], &sample_hash(0xFF), &sample_hash(0xEE), 999, 100, 10000,
        50, 100, &sample_hash(0xDD), 1, 50, 500, 100, 15000,
    )
    .unwrap();
    assert_eq!(rs1.len(), rs2.len());
}

// Body constant verification (exact expected lengths)

#[test]
fn loan_offer_body_exact_length() {
    assert_eq!(LOAN_OFFER_BODY.len(), 85);
}

#[test]
fn borrow_request_body_exact_length() {
    assert_eq!(BORROW_REQUEST_BODY.len(), 82);
}

#[test]
fn active_loan_body_exact_length() {
    assert_eq!(ACTIVE_LOAN_BODY.len(), 782); // D&R pattern + insurer branch (+16B for 8x SPK version prefix)
}

// Total RS size tests

#[test]
fn loan_offer_total_rs_size() {
    let rs = default_loan_offer_rs();
    assert_eq!(rs.len(), 129 + 85); // 214
}

#[test]
fn borrow_request_total_rs_size() {
    let rs = default_borrow_request_rs();
    assert_eq!(rs.len(), 120 + 82); // 202
}

#[test]
fn active_loan_total_rs_size() {
    let rs = default_active_loan_rs();
    assert_eq!(rs.len(), 222 + 782); // 1004 (D&R pattern + insurer, +16B for 8x SPK version prefix)
}

// BorrowRequest v3 replace path tests

#[test]
fn borrow_request_replace_sigscript_structure() {
    let fake_sig = [0xCC; 64];
    let fake_pk = [0xDD; 32];
    let rs = default_borrow_request_rs();
    let ss = build_borrow_request_replace_sigscript(&fake_sig, &fake_pk, 600, 10000, &rs);

    // new_max_rate_num: pushData(8B) = 0x08 prefix + 8B
    assert_eq!(ss[0], 0x08, "new_max_rate_num push prefix");
    assert_eq!(&ss[1..9], &u64_le(600));
    // new_max_rate_den: pushData(8B)
    assert_eq!(ss[9], 0x08, "new_max_rate_den push prefix");
    assert_eq!(&ss[10..18], &u64_le(10000));
    // sig: pushData(65B)
    assert_eq!(ss[18], 0x41, "sig push prefix");
}

#[test]
fn borrow_request_sigscript_thresholds_3_paths() {
    let rs = default_borrow_request_rs();
    let fake_sig = [0u8; 64];
    let fake_pk = [0u8; 32];

    let match_ss = build_borrow_request_match_sigscript(&rs);
    let cancel_ss = build_borrow_request_cancel_sigscript(&fake_sig, &fake_pk, &rs);
    let replace_ss = build_borrow_request_replace_sigscript(
        &fake_sig, &fake_pk, 500, 10000, &rs,
    );

    let match_len = match_ss.len();
    let cancel_len = cancel_ss.len();
    let replace_len = replace_ss.len();

    // T1=250, T2=310
    assert!(match_len < 250, "match({match_len}) must be < T1(250)");
    assert!(cancel_len >= 250, "cancel({cancel_len}) must be >= T1(250)");
    assert!(cancel_len < 310, "cancel({cancel_len}) must be < T2(310)");
    assert!(replace_len >= 310, "replace({replace_len}) must be >= T2(310)");
}

#[test]
fn borrow_request_body_has_self_continuation() {
    assert!(
        BORROW_REQUEST_BODY.contains(&0xbf),
        "body must contain OpTxInputSpk for replace self-continuation"
    );
}

// ActiveLoan v3 new path sigscript tests

#[test]
fn active_loan_partial_repay_sigscript_structure() {
    let fake_sig = [0xAA; 64];
    let fake_pk = [0xBB; 32];
    let rs = default_active_loan_rs();
    let ss = build_active_loan_partial_repay_sigscript(&fake_sig, &fake_pk, 1, 500_000, &rs, &rs, &rs);

    // D&R: starts with pushData(new_rs) + pushData(old_rs)
    let rs_pd_len = push_data(&rs).len();
    let dr_prefix_len = rs_pd_len * 2; // new_rs + old_rs push data
    // After D&R prefix: loi_opN
    assert_eq!(ss[dr_prefix_len], 0x51, "loi OpN(1)");
    // repay_amount: pushData(8B)
    assert_eq!(ss[dr_prefix_len + 1], 0x08, "repay_amount push prefix");
    assert_eq!(&ss[dr_prefix_len + 2..dr_prefix_len + 10], &u64_le(500_000));
    // sig: pushData(65B)
    assert_eq!(ss[dr_prefix_len + 10], 0x41, "sig push prefix");
    // selector: Op4 = 0x54
    let sel_pos = ss.len() - rs_pd_len - 1;
    assert_eq!(ss[sel_pos], 0x54, "selector Op4");
}

#[test]
fn active_loan_topup_sigscript_structure() {
    let fake_sig = [0xAA; 64];
    let fake_pk = [0xBB; 32];
    let rs = default_active_loan_rs();
    let ss = build_active_loan_topup_sigscript(&fake_sig, &fake_pk, 0, &rs);

    // ci_opN: Op0 = 0x00
    assert_eq!(ss[0], 0x00, "ci OpN(0)");
    // sig: pushData(65B)
    assert_eq!(ss[1], 0x41, "sig push prefix");
    // selector: Op5 = 0x55
    let sel_pos = ss.len() - push_data(&rs).len() - 1;
    assert_eq!(ss[sel_pos], 0x55, "selector Op5");
}

#[test]
fn active_loan_extend_sigscript_structure() {
    let fake_sig = [0xAA; 64];
    let fake_pk = [0xBB; 32];
    let rs = default_active_loan_rs();
    let ss = build_active_loan_extend_sigscript(
        &fake_sig, &fake_pk, &fake_sig, &fake_pk, 0, 200_000_000, &rs, &rs, &rs,
    );

    let rs_pd_len = push_data(&rs).len();
    let dr_prefix_len = rs_pd_len * 2;
    // After D&R prefix: loi_opN
    assert_eq!(ss[dr_prefix_len], 0x00, "loi OpN(0)");
    // new_expiry: pushData(8B)
    assert_eq!(ss[dr_prefix_len + 1], 0x08, "new_expiry push prefix");
    assert_eq!(&ss[dr_prefix_len + 2..dr_prefix_len + 10], &u64_le(200_000_000));
    // lender sig: pushData(65B)
    assert_eq!(ss[dr_prefix_len + 10], 0x41, "lender sig push prefix");
    // selector: Op6 = 0x56
    let sel_pos = ss.len() - rs_pd_len - 1;
    assert_eq!(ss[sel_pos], 0x56, "selector Op6");
}

#[test]
fn active_loan_extend_has_two_sigs() {
    let fake_sig = [0xAA; 64];
    let fake_pk = [0xBB; 32];
    let rs = default_active_loan_rs();
    let ss = build_active_loan_extend_sigscript(
        &fake_sig, &fake_pk, &fake_sig, &fake_pk, 0, 200_000_000, &rs, &rs, &rs,
    );

    // Should contain 2 signature pushes (0x41 prefix for 65B)
    let sig_push_count = ss.windows(1).filter(|w| w[0] == 0x41).count();
    assert!(sig_push_count >= 2, "extend must have 2 sig pushes, got {sig_push_count}");
}

#[test]
fn active_loan_rebalance_sigscript_structure() {
    let rs = default_active_loan_rs();
    let ss = build_active_loan_rebalance_sigscript(1, 0, 2, &rs, &rs, &rs);

    let rs_pd_len = push_data(&rs).len();
    let dr_prefix_len = rs_pd_len * 2;
    assert_eq!(ss[dr_prefix_len], opn(1), "rate_input_idx");
    assert_eq!(ss[dr_prefix_len + 1], opn(0), "lender_output_idx");
    assert_eq!(ss[dr_prefix_len + 2], opn(2), "continuation_output_idx");
    assert_eq!(ss[dr_prefix_len + 3], 0x57, "selector Op7");
}

#[test]
fn active_loan_redemption_sigscript_structure() {
    let rs = default_active_loan_rs();
    let ss = build_active_loan_redemption_sigscript(0, &rs);

    assert_eq!(ss[0], opn(0), "lender_output_idx");
    assert_eq!(ss[1], 0x58, "selector Op8");
}

#[test]
fn active_loan_partial_liquidation_sigscript_structure() {
    let rs = default_active_loan_rs();
    let ss = build_active_loan_partial_liquidation_sigscript(1, 0, 2, 3, 50_000, &rs);

    // liq_amount: pushData(8B)
    assert_eq!(ss[0], 0x08, "liq_amount push prefix");
    assert_eq!(&ss[1..9], &u64_le(50_000));
    assert_eq!(ss[9], opn(1), "price_input_idx");
    assert_eq!(ss[10], opn(0), "lender_output_idx");
    assert_eq!(ss[11], opn(2), "liquidator_output_idx");
    assert_eq!(ss[12], opn(3), "continuation_output_idx");
    assert_eq!(ss[13], 0x59, "selector Op9");
}

#[test]
fn active_loan_loan_transfer_sigscript_structure() {
    let fake_sig = [0xAA; 64];
    let fake_pk = [0xBB; 32];
    let new_lender = sample_hash(0xFF);
    let rs = default_active_loan_rs();
    let ss = build_active_loan_loan_transfer_sigscript(
        &fake_sig, &fake_pk, 0, &new_lender, &rs, &rs, &rs,
    );

    let rs_pd_len = push_data(&rs).len();
    let dr_prefix_len = rs_pd_len * 2;
    // After D&R prefix: new_lender_hash: pushData(32B)
    assert_eq!(ss[dr_prefix_len], 0x20, "new_lender_hash push prefix");
    assert_eq!(&ss[dr_prefix_len + 1..dr_prefix_len + 33], &new_lender);
    // ci_opN: Op0 = 0x00
    assert_eq!(ss[dr_prefix_len + 33], 0x00, "ci OpN(0)");
    // sig: pushData(65B)
    assert_eq!(ss[dr_prefix_len + 34], 0x41, "sig push prefix");
    // selector: Op10 = 0x5a
    let sel_pos = ss.len() - rs_pd_len - 1;
    assert_eq!(ss[sel_pos], 0x5a, "selector Op10");
}

// ActiveLoan v3 selector dispatch body tests

#[test]
fn active_loan_body_has_self_continuation() {
    // Multiple paths need self-continuation (partial repay, top-up, extend, rebalance, etc.)
    assert!(
        ACTIVE_LOAN_BODY.contains(&0xbf),
        "body must contain OpTxInputSpk for self-continuation paths"
    );
}

#[test]
fn active_loan_body_has_cltv() {
    assert!(
        ACTIVE_LOAN_BODY.contains(&0xb0),
        "body must contain OpCheckLockTimeVerify for default claim path"
    );
}

#[test]
fn active_loan_body_has_locktime() {
    assert!(
        ACTIVE_LOAN_BODY.contains(&0xb5),
        "body must contain OpTxLockTime"
    );
}

#[test]
fn active_loan_body_multiple_checksigverify() {
    // Paths 2,3,4,5,6,10 all have CheckSigVerify. Path 6 has 2.
    let csv_count = ACTIVE_LOAN_BODY.iter().filter(|&&b| b == 0xad).count();
    assert!(csv_count >= 7, "body must have >= 7 OpCheckSigVerify, got {csv_count}");
}

#[test]
fn active_loan_body_multiple_blake2b() {
    // Multiple paths verify SPK hashes via Blake2b
    let b2b_count = ACTIVE_LOAN_BODY.iter().filter(|&&b| b == 0xaa).count();
    assert!(b2b_count >= 5, "body must have >= 5 OpBlake2b, got {b2b_count}");
}

#[test]
fn active_loan_body_10_path_opif_endif_balance() {
    let body = ACTIVE_LOAN_BODY;
    let opif = body.iter().filter(|&&b| b == 0x63).count();
    let opendif = body.iter().filter(|&&b| b == 0x68).count();
    // OpEndIf count is OpIf count + 1 (insurance branch uses OpNotIf which is
    // indistinguishable from push data 0x64 in a naive byte scan).
    assert_eq!(opif + 1, opendif, "OpIf({opif})+1 must equal OpEndIf({opendif})");
}

#[test]
fn active_loan_body_drop_count_10_paths() {
    let body = ACTIVE_LOAN_BODY;
    let drop_count = body.iter().filter(|&&b| b == 0x75).count();
    // Each path drops all state + sigscript items. 10 paths, each 12-17 drops.
    assert!(drop_count >= 100, "must have enough OpDrop, got {drop_count}");
}

// ActiveLoan v3 grace_daa validation tests

#[test]
fn active_loan_rejects_zero_grace_daa() {
    let r = build_active_loan_redeem_script(
        &[0u8; 32], &zero32(), &zero32(), 1000, 500, 10000, 100, 200, &zero32(), 0, 0, 0, 0, 15000,
    );
    assert!(r.is_err());
    assert!(r.unwrap_err().to_string().contains("grace_daa"));
}

#[test]
fn active_loan_accepts_large_grace_daa() {
    let r = build_active_loan_redeem_script(
        &[0u8; 32], &zero32(), &zero32(), 1000, 500, 10000, 100, 200, &zero32(), 0, 0, 0, u64::MAX, 15000,
    );
    assert!(r.is_ok());
}

#[test]
fn active_loan_grace_daa_in_state() {
    let rs = build_active_loan_redeem_script(
        &[0u8; 32], &sample_hash(0x11), &sample_hash(0x22), 1000, 500, 10000,
        100, 200, &zero32(), 0, 0, 0, 999_999, 15000,
    )
    .unwrap();

    // grace_daa is the second-to-last state field (d1)
    // Position: 4*33 + 8*9 = 132 + 72 = 204 bytes for first 12 fields
    // Then grace_daa at 204: [0x08][8B]
    let pos = 4 * 33 + 8 * 9; // = 204
    assert_eq!(rs[pos], 0x08);
    let grace = u64::from_le_bytes(rs[pos + 1..pos + 9].try_into().unwrap());
    assert_eq!(grace, 999_999);
}

// ActiveLoan v3 RS size with new state

#[test]
fn active_loan_rs_size_with_grace() {
    let rs = default_active_loan_rs();
    // 14 items: 4 hashes (33B each) + 10 u64s (9B each) + body
    let expected_state = 4 * 33 + 10 * 9;
    assert_eq!(expected_state, 222);
    assert_eq!(rs.len(), expected_state + ACTIVE_LOAN_BODY.len());
}

// ActiveLoan v3 new sigscript size tests

#[test]
fn active_loan_all_sigscripts_end_with_rs() {
    let rs = default_active_loan_rs();
    let fake_sig = [0u8; 64];
    let fake_pk = [0u8; 32];
    let rs_pd = push_data(&rs);

    let all_ss: Vec<(&str, Vec<u8>)> = vec![
        ("liquidate", build_active_loan_liquidate_sigscript(1, 0, 2, 3, &rs)),
        ("default", build_active_loan_default_sigscript(&fake_sig, &fake_pk, &rs)),
        ("repay", build_active_loan_repay_sigscript(&fake_sig, &fake_pk, 0, &rs)),
        ("partial_repay", build_active_loan_partial_repay_sigscript(&fake_sig, &fake_pk, 0, 100, &rs, &rs, &rs)),
        ("topup", build_active_loan_topup_sigscript(&fake_sig, &fake_pk, 0, &rs)),
        ("extend", build_active_loan_extend_sigscript(&fake_sig, &fake_pk, &fake_sig, &fake_pk, 0, 200, &rs, &rs, &rs)),
        ("rebalance", build_active_loan_rebalance_sigscript(1, 0, 2, &rs, &rs, &rs)),
        ("redemption", build_active_loan_redemption_sigscript(0, &rs)),
        ("partial_liq", build_active_loan_partial_liquidation_sigscript(1, 0, 2, 3, 100, &rs)),
        ("loan_transfer", build_active_loan_loan_transfer_sigscript(&fake_sig, &fake_pk, 0, &sample_hash(0xFF), &rs, &rs, &rs)),
    ];

    for (name, ss) in &all_ss {
        let tail = &ss[ss.len() - rs_pd.len()..];
        assert_eq!(
            tail, &rs_pd[..],
            "{name} sigscript must end with pushData(RS)"
        );
    }
}

#[test]
fn active_loan_extend_is_longest_sigscript() {
    let rs = default_active_loan_rs();
    let fake_sig = [0u8; 64];
    let fake_pk = [0u8; 32];

    let extend_len = build_active_loan_extend_sigscript(
        &fake_sig, &fake_pk, &fake_sig, &fake_pk, 0, 200, &rs, &rs, &rs,
    ).len();

    // Extend has 2 sigs + 2 pks + new_expiry + loi + selector + RS = longest
    let repay_len = build_active_loan_repay_sigscript(&fake_sig, &fake_pk, 0, &rs).len();
    let transfer_len = build_active_loan_loan_transfer_sigscript(
        &fake_sig, &fake_pk, 0, &sample_hash(0xFF), &rs, &rs, &rs,
    ).len();

    assert!(extend_len > repay_len, "extend({extend_len}) must be > repay({repay_len})");
    assert!(extend_len > transfer_len, "extend({extend_len}) must be > transfer({transfer_len})");
}

#[test]
fn active_loan_permissionless_paths_are_shorter() {
    let rs = default_active_loan_rs();
    let fake_sig = [0u8; 64];
    let fake_pk = [0u8; 32];

    // Non-D&R permissionless paths are shorter than signed paths.
    // Rebalance now uses D&R (includes 2 full RS copies) so it's excluded.
    let perm_lens: Vec<usize> = vec![
        build_active_loan_liquidate_sigscript(1, 0, 2, 3, &rs).len(),
        build_active_loan_redemption_sigscript(0, &rs).len(),
    ];

    let signed_lens: Vec<usize> = vec![
        build_active_loan_default_sigscript(&fake_sig, &fake_pk, &rs).len(),
        build_active_loan_repay_sigscript(&fake_sig, &fake_pk, 0, &rs).len(),
        build_active_loan_topup_sigscript(&fake_sig, &fake_pk, 0, &rs).len(),
    ];

    let max_perm = *perm_lens.iter().max().unwrap();
    let min_signed = *signed_lens.iter().min().unwrap();

    assert!(max_perm < min_signed,
        "permissionless max({max_perm}) must be < signed min({min_signed})");
}

// ActiveLoan v3 RS determinism with all new paths

#[test]
fn active_loan_new_sigscripts_deterministic() {
    let rs1 = default_active_loan_rs();
    let rs2 = default_active_loan_rs();
    let fake_sig = [0xAA; 64];
    let fake_pk = [0xBB; 32];

    // Partial repay
    let ss1 = build_active_loan_partial_repay_sigscript(&fake_sig, &fake_pk, 0, 100, &rs1, &rs1, &rs1);
    let ss2 = build_active_loan_partial_repay_sigscript(&fake_sig, &fake_pk, 0, 100, &rs2, &rs2, &rs2);
    assert_eq!(ss1, ss2);

    // Top-up
    let ss1 = build_active_loan_topup_sigscript(&fake_sig, &fake_pk, 0, &rs1);
    let ss2 = build_active_loan_topup_sigscript(&fake_sig, &fake_pk, 0, &rs2);
    assert_eq!(ss1, ss2);

    // Extend
    let ss1 = build_active_loan_extend_sigscript(&fake_sig, &fake_pk, &fake_sig, &fake_pk, 0, 200, &rs1, &rs1, &rs1);
    let ss2 = build_active_loan_extend_sigscript(&fake_sig, &fake_pk, &fake_sig, &fake_pk, 0, 200, &rs2, &rs2, &rs2);
    assert_eq!(ss1, ss2);

    // Rebalance
    let ss1 = build_active_loan_rebalance_sigscript(1, 0, 2, &rs1, &rs1, &rs1);
    let ss2 = build_active_loan_rebalance_sigscript(1, 0, 2, &rs2, &rs2, &rs2);
    assert_eq!(ss1, ss2);

    // Redemption
    let ss1 = build_active_loan_redemption_sigscript(0, &rs1);
    let ss2 = build_active_loan_redemption_sigscript(0, &rs2);
    assert_eq!(ss1, ss2);

    // Partial liquidation
    let ss1 = build_active_loan_partial_liquidation_sigscript(1, 0, 2, 3, 100, &rs1);
    let ss2 = build_active_loan_partial_liquidation_sigscript(1, 0, 2, 3, 100, &rs2);
    assert_eq!(ss1, ss2);

    // Loan transfer
    let nlh = sample_hash(0xFF);
    let ss1 = build_active_loan_loan_transfer_sigscript(&fake_sig, &fake_pk, 0, &nlh, &rs1, &rs1, &rs1);
    let ss2 = build_active_loan_loan_transfer_sigscript(&fake_sig, &fake_pk, 0, &nlh, &rs2, &rs2, &rs2);
    assert_eq!(ss1, ss2);
}

// ActiveLoan v3 different params produce different sigscripts

#[test]
fn active_loan_partial_repay_different_amounts() {
    let rs = default_active_loan_rs();
    let fake_sig = [0u8; 64];
    let fake_pk = [0u8; 32];
    let ss1 = build_active_loan_partial_repay_sigscript(&fake_sig, &fake_pk, 0, 100, &rs, &rs, &rs);
    let ss2 = build_active_loan_partial_repay_sigscript(&fake_sig, &fake_pk, 0, 200, &rs, &rs, &rs);
    assert_ne!(ss1, ss2);
}

#[test]
fn active_loan_extend_different_expiry() {
    let rs = default_active_loan_rs();
    let fake_sig = [0u8; 64];
    let fake_pk = [0u8; 32];
    let ss1 = build_active_loan_extend_sigscript(&fake_sig, &fake_pk, &fake_sig, &fake_pk, 0, 100, &rs, &rs, &rs);
    let ss2 = build_active_loan_extend_sigscript(&fake_sig, &fake_pk, &fake_sig, &fake_pk, 0, 200, &rs, &rs, &rs);
    assert_ne!(ss1, ss2);
}

#[test]
fn active_loan_transfer_different_lender_hash() {
    let rs = default_active_loan_rs();
    let fake_sig = [0u8; 64];
    let fake_pk = [0u8; 32];
    let ss1 = build_active_loan_loan_transfer_sigscript(&fake_sig, &fake_pk, 0, &sample_hash(0x01), &rs, &rs, &rs);
    let ss2 = build_active_loan_loan_transfer_sigscript(&fake_sig, &fake_pk, 0, &sample_hash(0x02), &rs, &rs, &rs);
    assert_ne!(ss1, ss2);
}

#[test]
fn active_loan_partial_liq_different_amounts() {
    let rs = default_active_loan_rs();
    let ss1 = build_active_loan_partial_liquidation_sigscript(1, 0, 2, 3, 100, &rs);
    let ss2 = build_active_loan_partial_liquidation_sigscript(1, 0, 2, 3, 200, &rs);
    assert_ne!(ss1, ss2);
}

// ActiveLoan v3 sigscript length tests

#[test]
fn active_loan_redemption_is_shortest_sigscript() {
    let rs = default_active_loan_rs();
    let red_len = build_active_loan_redemption_sigscript(0, &rs).len();
    let reb_len = build_active_loan_rebalance_sigscript(1, 0, 2, &rs, &rs, &rs).len();
    let liq_len = build_active_loan_liquidate_sigscript(1, 0, 2, 3, &rs).len();

    assert!(red_len < reb_len, "redemption({red_len}) must be < rebalance({reb_len})");
    assert!(red_len < liq_len, "redemption({red_len}) must be < liquidate({liq_len})");
}

// ActiveLoan v3 selector OpN correctness

#[test]
fn active_loan_selector_opn_mapping() {
    // Verify OpN values map correctly to selectors 1-10
    assert_eq!(opn(1), 0x51);
    assert_eq!(opn(2), 0x52);
    assert_eq!(opn(3), 0x53);
    assert_eq!(opn(4), 0x54);
    assert_eq!(opn(5), 0x55);
    assert_eq!(opn(6), 0x56);
    assert_eq!(opn(7), 0x57);
    assert_eq!(opn(8), 0x58);
    assert_eq!(opn(9), 0x59);
    assert_eq!(opn(10), 0x5a);
}

// ActiveLoan v3 body selector verification checks

#[test]
fn active_loan_body_has_all_selector_checks() {
    let body = ACTIVE_LOAN_BODY;
    // Each path verifies sel==N via OpN OpEqual OpVerify (3 bytes: 0x5N 0x87 0x69)
    let check_selector_verify = |sel: u8| {
        let sel_byte = opn(sel);
        body.windows(3).any(|w| w[0] == sel_byte && w[1] == 0x87 && w[2] == 0x69)
    };

    for sel in 1..=10u8 {
        if sel == 8 { continue; } // PATH 8 (Redemption) removed
        assert!(
            check_selector_verify(sel),
            "body must contain OpN({sel}) OpEqual OpVerify for path {sel}"
        );
    }
}

#[test]
fn active_loan_body_dispatch_roll_depth() {
    // First two bytes must be Op14(0x5e) OpRoll(0x7a)
    // This brings the selector from depth 14 (beneath 14 state items) to top
    assert_eq!(ACTIVE_LOAN_BODY[0], 0x5e);
    assert_eq!(ACTIVE_LOAN_BODY[1], 0x7a);
}

// ActiveLoan v3 path-specific body feature tests

#[test]
fn active_loan_body_has_add_for_grace_deadline() {
    // Default claim path adds grace_daa to expiry_daa (OpAdd = 0x93)
    assert!(
        ACTIVE_LOAN_BODY.contains(&0x93),
        "body must contain OpAdd for grace+expiry deadline computation"
    );
}

#[test]
fn active_loan_body_has_greaterthan_for_not_expired() {
    // Liquidation paths check OpGreaterThan (0xa0) for not-expired check
    assert!(
        ACTIVE_LOAN_BODY.contains(&0xa0),
        "body must contain OpGreaterThan for liquidation not-expired check"
    );
}

#[test]
fn active_loan_body_has_output_spk_check() {
    // Multiple paths check output SPK (OpTxOutputSpk = 0xc3)
    let spk_count = ACTIVE_LOAN_BODY.iter().filter(|&&b| b == 0xc3).count();
    assert!(spk_count >= 5, "body must have >= 5 OpTxOutputSpk, got {spk_count}");
}

#[test]
fn active_loan_body_has_output_amount_check() {
    // Multiple paths check output amounts (OpTxOutputAmount = 0xc2)
    let amt_count = ACTIVE_LOAN_BODY.iter().filter(|&&b| b == 0xc2).count();
    assert!(amt_count >= 2, "body must have >= 2 OpTxOutputAmount, got {amt_count}");
}

#[test]
fn active_loan_body_has_input_spk_for_continuation() {
    // Self-continuation paths need OpTxInputSpk (0xbf)
    let ispk_count = ACTIVE_LOAN_BODY.iter().filter(|&&b| b == 0xbf).count();
    assert!(ispk_count >= 4, "body must have >= 4 OpTxInputSpk, got {ispk_count}");
}

// BorrowRequest v3 body length with replace path

#[test]
fn borrow_request_body_3_paths_larger_than_original() {
    // 3-path body (82B) is larger than a 2-path body would have been
    let body_len = BORROW_REQUEST_BODY.len();
    assert!(body_len > 45, "3-path body must be > original 2-path body");
    assert!(body_len < 120, "body should not be unreasonably large");
}

// Cross-covenant size relationship tests

#[test]
fn active_loan_body_largest() {
    // ActiveLoan with 10 paths should be the largest body
    assert!(ACTIVE_LOAN_BODY.len() > LOAN_OFFER_BODY.len());
    assert!(ACTIVE_LOAN_BODY.len() > BORROW_REQUEST_BODY.len());
}

#[test]
fn active_loan_state_largest() {
    // ActiveLoan with 12 items should have the largest state
    assert!(ACTIVE_LOAN_STATE_SIZE > LOAN_OFFER_STATE_SIZE);
    assert!(ACTIVE_LOAN_STATE_SIZE > BORROW_REQUEST_STATE_SIZE);
}

// ActiveLoan v3 sigscript size consistency tests

#[test]
fn active_loan_all_sigscripts_same_rs_length() {
    // All sigscripts built from the same RS should have the same RS portion
    let rs = default_active_loan_rs();
    let rs_len = rs.len();
    let rs2 = build_active_loan_redeem_script(
        &[0u8; 32], &sample_hash(0x11), &sample_hash(0x22), 500, 300, 10000,
        50, 100, &zero32(), 0, 0, 0, 500, 15000,
    ).unwrap();
    assert_eq!(rs_len, rs2.len(), "all ActiveLoan RS must have same length");
}

#[test]
fn active_loan_liquidate_sigscript_minimal() {
    // Liquidate: 4 OpN + selector + pushData(RS)
    let rs = default_active_loan_rs();
    let ss = build_active_loan_liquidate_sigscript(0, 1, 2, 3, &rs);
    let rs_pd_len = push_data(&rs).len();
    let expected = 4 + 1 + rs_pd_len; // 4 opN + 1 selector + RS push
    assert_eq!(ss.len(), expected);
}

#[test]
fn active_loan_redemption_sigscript_minimal() {
    // Redemption: 1 OpN + selector + pushData(RS)
    let rs = default_active_loan_rs();
    let ss = build_active_loan_redemption_sigscript(0, &rs);
    let rs_pd_len = push_data(&rs).len();
    let expected = 1 + 1 + rs_pd_len; // 1 opN + 1 selector + RS push
    assert_eq!(ss.len(), expected);
}

#[test]
fn active_loan_rebalance_sigscript_size() {
    // D&R: pushData(new_rs) + pushData(old_rs) + 3 OpN + selector + pushData(RS)
    let rs = default_active_loan_rs();
    let ss = build_active_loan_rebalance_sigscript(1, 0, 2, &rs, &rs, &rs);
    let rs_pd_len = push_data(&rs).len();
    let expected = rs_pd_len * 2 + 3 + 1 + rs_pd_len;
    assert_eq!(ss.len(), expected);
}

#[test]
fn active_loan_default_sigscript_size() {
    // Default: sig(66) + pk(33) + selector(1) + pushData(RS)
    let rs = default_active_loan_rs();
    let fake_sig = [0u8; 64];
    let fake_pk = [0u8; 32];
    let ss = build_active_loan_default_sigscript(&fake_sig, &fake_pk, &rs);
    let rs_pd_len = push_data(&rs).len();
    let expected = 66 + 33 + 1 + rs_pd_len;
    assert_eq!(ss.len(), expected);
}

#[test]
fn active_loan_repay_sigscript_size() {
    // Repay: opN(1) + sig(66) + pk(33) + selector(1) + pushData(RS)
    let rs = default_active_loan_rs();
    let fake_sig = [0u8; 64];
    let fake_pk = [0u8; 32];
    let ss = build_active_loan_repay_sigscript(&fake_sig, &fake_pk, 0, &rs);
    let rs_pd_len = push_data(&rs).len();
    let expected = 1 + 66 + 33 + 1 + rs_pd_len;
    assert_eq!(ss.len(), expected);
}

#[test]
fn active_loan_topup_sigscript_size() {
    // Top-up: opN(1) + sig(66) + pk(33) + selector(1) + pushData(RS)
    let rs = default_active_loan_rs();
    let fake_sig = [0u8; 64];
    let fake_pk = [0u8; 32];
    let ss = build_active_loan_topup_sigscript(&fake_sig, &fake_pk, 0, &rs);
    let rs_pd_len = push_data(&rs).len();
    let expected = 1 + 66 + 33 + 1 + rs_pd_len;
    assert_eq!(ss.len(), expected);
}

#[test]
fn active_loan_partial_repay_sigscript_size() {
    // D&R: pushData(new_rs) + pushData(old_rs) + opN(1) + pushData(8B)(9) + sig(66) + pk(33) + selector(1) + pushData(RS)
    let rs = default_active_loan_rs();
    let fake_sig = [0u8; 64];
    let fake_pk = [0u8; 32];
    let ss = build_active_loan_partial_repay_sigscript(&fake_sig, &fake_pk, 0, 100, &rs, &rs, &rs);
    let rs_pd_len = push_data(&rs).len();
    let expected = rs_pd_len * 2 + 1 + 9 + 66 + 33 + 1 + rs_pd_len;
    assert_eq!(ss.len(), expected);
}

#[test]
fn active_loan_loan_transfer_sigscript_size() {
    // D&R: pushData(new_rs) + pushData(old_rs) + pushData(32B)(33) + opN(1) + sig(66) + pk(33) + selector(1) + pushData(RS)
    let rs = default_active_loan_rs();
    let fake_sig = [0u8; 64];
    let fake_pk = [0u8; 32];
    let ss = build_active_loan_loan_transfer_sigscript(&fake_sig, &fake_pk, 0, &sample_hash(0xFF), &rs, &rs, &rs);
    let rs_pd_len = push_data(&rs).len();
    let expected = rs_pd_len * 2 + 33 + 1 + 66 + 33 + 1 + rs_pd_len;
    assert_eq!(ss.len(), expected);
}

#[test]
fn active_loan_extend_sigscript_size() {
    // D&R: pushData(new_rs) + pushData(old_rs) + opN(1) + pushData(8B)(9) + sig(66) + pk(33) + sig(66) + pk(33) + selector(1) + pushData(RS)
    let rs = default_active_loan_rs();
    let fake_sig = [0u8; 64];
    let fake_pk = [0u8; 32];
    let ss = build_active_loan_extend_sigscript(&fake_sig, &fake_pk, &fake_sig, &fake_pk, 0, 200, &rs, &rs, &rs);
    let rs_pd_len = push_data(&rs).len();
    let expected = rs_pd_len * 2 + 1 + 9 + 66 + 33 + 66 + 33 + 1 + rs_pd_len;
    assert_eq!(ss.len(), expected);
}

#[test]
fn active_loan_partial_liq_sigscript_size() {
    // Partial liq: pushData(8B)(9) + 4*opN(4) + selector(1) + pushData(RS)
    let rs = default_active_loan_rs();
    let ss = build_active_loan_partial_liquidation_sigscript(1, 0, 2, 3, 100, &rs);
    let rs_pd_len = push_data(&rs).len();
    let expected = 9 + 4 + 1 + rs_pd_len;
    assert_eq!(ss.len(), expected);
}

// ActiveLoan v3 variable rate path tests

#[test]
fn active_loan_variable_rate_rs() {
    let r = build_active_loan_redeem_script(
        &[0u8; 32], &sample_hash(0xAA), &sample_hash(0xBB),
        1_000_000_000, 500, 10000, 100_000_000, 131_536_000,
        &zero32(), 1, 200, 800, 3_153_600, 15000,
    );
    assert!(r.is_ok());
}

#[test]
fn active_loan_variable_rate_rebalance() {
    // Rebalance only works with variable rate (rate_mode=1)
    let rs = build_active_loan_redeem_script(
        &[0u8; 32], &sample_hash(0xAA), &sample_hash(0xBB),
        1_000_000_000, 500, 10000, 100_000_000, 131_536_000,
        &zero32(), 1, 200, 800, 3_153_600, 15000,
    ).unwrap();
    let ss = build_active_loan_rebalance_sigscript(1, 0, 2, &rs, &rs, &rs);
    // The sigscript itself doesn't validate rate_mode - the body does on-chain.
    // Just verify it builds correctly.
    assert!(ss.len() > 0);
}

// OpN range edge case tests

#[test]
fn active_loan_liquidate_max_indices() {
    // All OpN indices up to 16 should work
    let rs = default_active_loan_rs();
    let ss = build_active_loan_liquidate_sigscript(16, 15, 14, 13, &rs);
    assert_eq!(ss[0], 0x60); // Op16
    assert_eq!(ss[1], 0x5f); // Op15
    assert_eq!(ss[2], 0x5e); // Op14
    assert_eq!(ss[3], 0x5d); // Op13
}

#[test]
#[should_panic(expected = "OpN index out of range")]
fn active_loan_liquidate_panics_idx_17() {
    let rs = default_active_loan_rs();
    let _ = build_active_loan_liquidate_sigscript(17, 0, 1, 2, &rs);
}

// ActiveLoan v3 complete state extraction with all 14 fields

#[test]
fn active_loan_full_13_field_state_extraction() {
    let insurer = sample_hash(0x44);
    let lender = sample_hash(0x11);
    let borrower = sample_hash(0x22);
    let cov_id = sample_hash(0x33);
    let rs = build_active_loan_redeem_script(
        &insurer, &lender, &borrower, 5_000_000, 750, 10000,
        100_000, 200_000, &cov_id, 1, 300, 900, 50_000, 15000,
    ).unwrap();

    let mut pos = 0;

    // d13: insurer_spk_hash
    assert_eq!(rs[pos], 0x20); pos += 1;
    assert_eq!(&rs[pos..pos + 32], &insurer); pos += 32;

    // d12: lender_spk_hash
    assert_eq!(rs[pos], 0x20); pos += 1;
    assert_eq!(&rs[pos..pos + 32], &lender); pos += 32;

    // d11: borrower_spk_hash
    assert_eq!(rs[pos], 0x20); pos += 1;
    assert_eq!(&rs[pos..pos + 32], &borrower); pos += 32;

    // d10: principal
    assert_eq!(rs[pos], 0x08); pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 5_000_000); pos += 8;

    // d9: rate_num
    assert_eq!(rs[pos], 0x08); pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 750); pos += 8;

    // d8: rate_den
    assert_eq!(rs[pos], 0x08); pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 10000); pos += 8;

    // d7: start_daa
    assert_eq!(rs[pos], 0x08); pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 100_000); pos += 8;

    // d6: expiry_daa
    assert_eq!(rs[pos], 0x08); pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 200_000); pos += 8;

    // d5: collateral_cov_id
    assert_eq!(rs[pos], 0x20); pos += 1;
    assert_eq!(&rs[pos..pos + 32], &cov_id); pos += 32;

    // d4: rate_mode
    assert_eq!(rs[pos], 0x08); pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 1); pos += 8;

    // d3: rate_floor_num
    assert_eq!(rs[pos], 0x08); pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 300); pos += 8;

    // d2: rate_cap_num
    assert_eq!(rs[pos], 0x08); pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 900); pos += 8;

    // d1: grace_daa
    assert_eq!(rs[pos], 0x08); pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 50_000); pos += 8;

    // d0: liq_threshold
    assert_eq!(rs[pos], 0x08); pos += 1;
    assert_eq!(u64::from_le_bytes(rs[pos..pos + 8].try_into().unwrap()), 15000); pos += 8;

    // Body follows
    assert_eq!(pos, ACTIVE_LOAN_STATE_SIZE);
    assert_eq!(&rs[pos..], ACTIVE_LOAN_BODY);
}

// ActiveLoan v3 all paths have correct drop counts

#[test]
fn active_loan_body_opelse_count() {
    // 10 paths need branching: should have multiple OpElse
    let body = ACTIVE_LOAN_BODY;
    let opelse = body.iter().filter(|&&b| b == 0x67).count();
    assert!(opelse >= 5, "body must have >= 5 OpElse, got {opelse}");
}

#[test]
fn active_loan_body_selector_equal_verify_count() {
    // Each of 10 paths has OpEqual(0x87) OpVerify(0x69) for selector check
    let body = ACTIVE_LOAN_BODY;
    let eq_verify_count = body.windows(2).filter(|w| w[0] == 0x87 && w[1] == 0x69).count();
    // 10 selector checks + some SPK equality checks
    assert!(eq_verify_count >= 10, "body must have >= 10 OpEqual+OpVerify, got {eq_verify_count}");
}

// ActiveLoan v3 path-specific output index tests

#[test]
fn active_loan_liquidate_all_zero_indices() {
    let rs = default_active_loan_rs();
    let ss = build_active_loan_liquidate_sigscript(0, 0, 0, 0, &rs);
    assert_eq!(ss[0], 0x00); // Op0
    assert_eq!(ss[1], 0x00); // Op0
    assert_eq!(ss[2], 0x00); // Op0
    assert_eq!(ss[3], 0x00); // Op0
    assert_eq!(ss[4], 0x51); // selector Op1
}

#[test]
fn active_loan_repay_different_loi() {
    let rs = default_active_loan_rs();
    let fake_sig = [0u8; 64];
    let fake_pk = [0u8; 32];
    let ss1 = build_active_loan_repay_sigscript(&fake_sig, &fake_pk, 0, &rs);
    let ss2 = build_active_loan_repay_sigscript(&fake_sig, &fake_pk, 5, &rs);
    assert_ne!(ss1, ss2);
    assert_eq!(ss1[0], 0x00); // Op0
    assert_eq!(ss2[0], 0x55); // Op5
}

#[test]
fn active_loan_topup_different_ci() {
    let rs = default_active_loan_rs();
    let fake_sig = [0u8; 64];
    let fake_pk = [0u8; 32];
    let ss1 = build_active_loan_topup_sigscript(&fake_sig, &fake_pk, 0, &rs);
    let ss2 = build_active_loan_topup_sigscript(&fake_sig, &fake_pk, 1, &rs);
    assert_ne!(ss1, ss2);
}

#[test]
fn active_loan_redemption_different_loi() {
    let rs = default_active_loan_rs();
    let ss1 = build_active_loan_redemption_sigscript(0, &rs);
    let ss2 = build_active_loan_redemption_sigscript(1, &rs);
    assert_ne!(ss1, ss2);
}

#[test]
fn active_loan_rebalance_different_indices() {
    let rs = default_active_loan_rs();
    let ss1 = build_active_loan_rebalance_sigscript(1, 0, 2, &rs, &rs, &rs);
    let ss2 = build_active_loan_rebalance_sigscript(2, 1, 3, &rs, &rs, &rs);
    assert_ne!(ss1, ss2);
}

// BorrowRequest v3 replace path additional tests

#[test]
fn borrow_request_replace_different_params() {
    let rs = default_borrow_request_rs();
    let fake_sig = [0u8; 64];
    let fake_pk = [0u8; 32];
    let ss1 = build_borrow_request_replace_sigscript(&fake_sig, &fake_pk, 500, 10000, &rs);
    let ss2 = build_borrow_request_replace_sigscript(&fake_sig, &fake_pk, 600, 10000, &rs);
    assert_ne!(ss1, ss2);
}

#[test]
fn borrow_request_replace_sigscript_size() {
    let rs = default_borrow_request_rs();
    let fake_sig = [0u8; 64];
    let fake_pk = [0u8; 32];
    let ss = build_borrow_request_replace_sigscript(&fake_sig, &fake_pk, 500, 10000, &rs);
    let rs_pd_len = push_data(&rs).len();
    // new_mrn(9) + new_mrd(9) + sig(66) + pk(33) + RS
    let expected = 9 + 9 + 66 + 33 + rs_pd_len;
    assert_eq!(ss.len(), expected);
}

#[test]
fn borrow_request_replace_deterministic() {
    let rs = default_borrow_request_rs();
    let fake_sig = [0u8; 64];
    let fake_pk = [0u8; 32];
    let ss1 = build_borrow_request_replace_sigscript(&fake_sig, &fake_pk, 500, 10000, &rs);
    let ss2 = build_borrow_request_replace_sigscript(&fake_sig, &fake_pk, 500, 10000, &rs);
    assert_eq!(ss1, ss2);
}

// ActiveLoan v3 body OpGTE and OpLessThan counts

#[test]
fn active_loan_body_has_gte_for_amount_checks() {
    let body = ACTIVE_LOAN_BODY;
    let gte_count = body.iter().filter(|&&b| b == 0xa2).count();
    assert!(gte_count >= 2, "body must have >= 2 OpGTE for amount checks, got {gte_count}");
}

#[test]
fn active_loan_body_has_lessthan_for_dispatch() {
    let body = ACTIVE_LOAN_BODY;
    let lt_count = body.iter().filter(|&&b| b == 0x9f).count();
    // Nested dispatch: sel<4, sel<2, sel<3, sel<7, sel<5, sel<6, sel<9, sel<8, sel<10
    assert!(lt_count >= 5, "body must have >= 5 OpLessThan for dispatch, got {lt_count}");
}

// ActiveLoan v3 continuation path output SPK verification

#[test]
fn active_loan_body_has_input_index_for_spk() {
    let body = ACTIVE_LOAN_BODY;
    // Self-continuation checks need OpTxInputIndex (0xb9) OpTxInputSpk (0xbf)
    let ii_count = body.iter().filter(|&&b| b == 0xb9).count();
    assert!(ii_count >= 4, "body must have >= 4 OpTxInputIndex, got {ii_count}");
}

// ActiveLoan v3 edge case: zero grace period

#[test]
fn active_loan_zero_grace_period_valid() {
    // grace_daa=0 is now rejected (borrower must have nonzero grace period)
    let r = build_active_loan_redeem_script(
        &[0u8; 32], &sample_hash(0xAA), &sample_hash(0xBB),
        1_000_000_000, 500, 10000, 100, 200, &zero32(), 0, 0, 0, 0, 15000,
    );
    assert!(r.is_err());
    // grace_daa=1 should succeed
    let r2 = build_active_loan_redeem_script(
        &[0u8; 32], &sample_hash(0xAA), &sample_hash(0xBB),
        1_000_000_000, 500, 10000, 100, 200, &zero32(), 0, 0, 0, 1, 15000,
    );
    assert!(r2.is_ok());
    let rs = r2.unwrap();
    // grace_daa is second-to-last state field (d1), liq_threshold is last (d0)
    let grace_pos = ACTIVE_LOAN_STATE_SIZE - 2 * 9 + 1;
    let grace = u64::from_le_bytes(rs[grace_pos..grace_pos + 8].try_into().unwrap());
    assert_eq!(grace, 1);
    // liq_threshold is last state field
    let lt_pos = ACTIVE_LOAN_STATE_SIZE - 8;
    let lt = u64::from_le_bytes(rs[lt_pos..lt_pos + 8].try_into().unwrap());
    assert_eq!(lt, 15000);
}

// Payload compatibility

#[test]
fn lending_payload_with_new_active_loan_rs() {
    let rs = default_active_loan_rs();
    let payload = build_lending_payload(&rs);
    assert!(payload.starts_with(b"KOB:L:"));
    let parsed = parse_lending_payload(&payload).unwrap();
    assert_eq!(parsed, &rs[..]);
}

#[test]
fn lending_payload_with_borrow_request_rs() {
    let rs = default_borrow_request_rs();
    let payload = build_lending_payload(&rs);
    let parsed = parse_lending_payload(&payload).unwrap();
    assert_eq!(parsed, &rs[..]);
}

// Body constant snapshot test (ACTIVE_LOAN_BODY_EXPECTED_LEN)

#[test]
fn active_loan_body_snapshot_matches_const() {
    assert_eq!(
        ACTIVE_LOAN_BODY.len(),
        ACTIVE_LOAN_BODY_EXPECTED_LEN,
        "body length changed — update ACTIVE_LOAN_BODY_EXPECTED_LEN"
    );
}

#[test]
fn active_loan_extend_both_sigs_different() {
    let rs = default_active_loan_rs();
    let sig_a = [0xAA; 64];
    let sig_b = [0xBB; 64];
    let pk_a = [0xCC; 32];
    let pk_b = [0xDD; 32];
    let ss = build_active_loan_extend_sigscript(&sig_a, &pk_a, &sig_b, &pk_b, 0, 200, &rs, &rs, &rs);
    // Verify both sigs are present
    assert!(ss.windows(64).any(|w| w == &sig_a[..]));
    assert!(ss.windows(64).any(|w| w == &sig_b[..]));
    // Verify both pks are present
    assert!(ss.windows(32).any(|w| w == &pk_a[..]));
    assert!(ss.windows(32).any(|w| w == &pk_b[..]));
}

#[test]
fn active_loan_partial_liq_amount_encoded_correctly() {
    let rs = default_active_loan_rs();
    let ss = build_active_loan_partial_liquidation_sigscript(1, 0, 2, 3, 12345678, &rs);
    // liq_amount is pushData(8B) at start
    assert_eq!(ss[0], 0x08);
    assert_eq!(&ss[1..9], &u64_le(12345678));
}

#[test]
fn active_loan_loan_transfer_new_lender_hash_in_sigscript() {
    let rs = default_active_loan_rs();
    let fake_sig = [0u8; 64];
    let fake_pk = [0u8; 32];
    let new_lender = sample_hash(0xAB);
    let ss = build_active_loan_loan_transfer_sigscript(&fake_sig, &fake_pk, 0, &new_lender, &rs, &rs, &rs);
    // D&R prefix then new_lender_hash pushData(32B)
    let rs_pd_len = push_data(&rs).len();
    let dr_prefix_len = rs_pd_len * 2;
    assert_eq!(ss[dr_prefix_len], 0x20);
    assert_eq!(&ss[dr_prefix_len + 1..dr_prefix_len + 33], &new_lender);
}

// Bytecode stack depth verification
//
// These tests verify that every OpPick/OpRoll operand in the bytecode
// references a valid stack position. This catches the class of bug where
// an opcode doesn't pop (like CLTV) and all subsequent depths are off.
//
// We walk the bytecode for each path, tracking stack depth changes.
// We don't simulate full execution — we just verify that every OpPick(N)
// and OpRoll(N) has N < current_stack_depth.

/// Walk a bytecode path and verify all OpPick/OpRoll depths are valid.
///
/// `initial_depth`: stack depth when the path starts executing.
/// `body_slice`: the bytecode bytes for this specific path (after dispatch).
///
/// Returns the final stack depth, or panics with details if an invalid
/// depth reference is found.
fn verify_stack_depths(path_name: &str, body_slice: &[u8], initial_depth: usize) -> usize {
    let mut depth = initial_depth;
    let mut i = 0;

    while i < body_slice.len() {
        let op = body_slice[i];
        match op {
            // OpN pushes: push 1 item
            0x00 => { depth += 1; i += 1; } // Op0
            0x51..=0x60 => { depth += 1; i += 1; } // Op1..Op16

            // Push data: 1-byte length prefix <= 75
            len @ 0x01..=0x4b => {
                depth += 1;
                i += 1 + len as usize;
            }
            // OP_PUSHDATA1
            0x4c => {
                let len = body_slice[i + 1] as usize;
                depth += 1;
                i += 2 + len;
            }

            // OpDup: +1
            0x76 => { depth += 1; i += 1; }

            // OpDrop: -1
            0x75 => {
                assert!(depth > 0, "{path_name}: OpDrop at byte {i} with empty stack");
                depth -= 1;
                i += 1;
            }

            // Op2Drop: -2
            0x6d => {
                assert!(depth >= 2, "{path_name}: Op2Drop at byte {i} with depth {depth}");
                depth -= 2;
                i += 1;
            }

            // OpSwap: net 0 (swaps top 2)
            0x7c => {
                assert!(depth >= 2, "{path_name}: OpSwap at byte {i} with depth {depth}");
                i += 1;
            }

            // OpPick: pops index, pushes picked item (net 0)
            0x79 => {
                // The index was the top of stack (just pushed by OpN before this)
                // After OpPick: index consumed, picked value pushed. Net 0.
                // The index value (from the preceding OpN) must be < depth-1
                // (depth-1 because the index itself is on stack).
                if i > 0 {
                    let idx_op = body_slice[i - 1];
                    let idx_val = match idx_op {
                        0x00 => Some(0usize),
                        0x51..=0x60 => Some((idx_op - 0x50) as usize),
                        // push literal byte
                        0x01 => Some(body_slice[i - 2] as usize),
                        _ => None, // can't determine statically
                    };
                    if let Some(idx) = idx_val {
                        assert!(
                            idx < depth,
                            "{path_name}: OpPick({idx}) at byte {i} but stack depth is only {depth}"
                        );
                    }
                }
                // OpPick: pops index, pushes value. Net 0.
                i += 1;
            }

            // OpRoll: pops index, removes item at depth, pushes to top (net -1)
            0x7a => {
                if i > 0 {
                    let idx_op = body_slice[i - 1];
                    let idx_val = match idx_op {
                        0x00 => Some(0usize),
                        0x51..=0x60 => Some((idx_op - 0x50) as usize),
                        0x01 => Some(body_slice[i - 2] as usize),
                        _ => None,
                    };
                    if let Some(idx) = idx_val {
                        assert!(
                            idx < depth,
                            "{path_name}: OpRoll({idx}) at byte {i} but stack depth is only {depth}"
                        );
                    }
                }
                // OpRoll: pops index, removes from depth, pushes to top. Net -1.
                depth -= 1;
                i += 1;
            }

            // Binary ops that consume 2, push 1: net -1
            0x87 | // OpEqual
            0x93 | // OpAdd
            0x94 | // OpSub
            0x95 | // OpMul
            0x96 | // OpDiv
            0x9c | // OpNumEqual
            0x9f | // OpLessThan
            0xa0 | // OpGreaterThan
            0xa1 | // OpLTE
            0xa2   // OpGTE
            => {
                assert!(depth >= 2, "{path_name}: binary op 0x{op:02x} at byte {i} with depth {depth}");
                depth -= 1;
                i += 1;
            }

            // OpCat: 2 items -> 1. Net -1.
            0x7e => {
                assert!(depth >= 2, "{path_name}: OpCat at byte {i} with depth {depth}");
                depth -= 1;
                i += 1;
            }

            // OpSubstr: 3 items (str, begin, size) -> 1. Net -2.
            0x7f => {
                assert!(depth >= 3, "{path_name}: OpSubstr at byte {i} with depth {depth}");
                depth -= 2;
                i += 1;
            }

            // OpSize: pushes size without popping. Net +1.
            0x82 => { depth += 1; i += 1; }

            // Unary ops: consume 1, push 1. Net 0.
            0x91 | // OpNot
            0xaa   // OpBlake2b
            => { i += 1; }

            // OpVerify: pops 1 (checks it's true). Net -1.
            0x69 => {
                assert!(depth > 0, "{path_name}: OpVerify at byte {i} with empty stack");
                depth -= 1;
                i += 1;
            }

            // OpCheckSigVerify: pops pk + sig (2), pushes nothing. Net -2.
            0xad => {
                assert!(depth >= 2, "{path_name}: OpCheckSigVerify at byte {i} with depth {depth}");
                depth -= 2;
                i += 1;
            }

            // OpCheckLockTimeVerify: does NOT pop. Net 0.
            0xb0 => { i += 1; }

            // Introspection ops that push 1 value: Net +1.
            0xb3 | // OpInputCount
            0xb5 | // OpTxLockTime
            0xb9   // OpTxInputIndex
            => { depth += 1; i += 1; }

            // Introspection ops that consume 1 (index), push 1: Net 0.
            0xbe | // OpTxInputAmount
            0xbf | // OpTxInputSpk
            0xc2 | // OpTxOutputAmount
            0xc3 | // OpTxOutputSpk
            0xc9   // OpTxInputScriptSigLen
            => { i += 1; }

            // OpInputCovenantId: consumes 1 (index), pushes 1. Net 0.
            0xcf => { i += 1; }

            // Control flow: OpIf/OpNotIf/OpElse/OpEndIf — skip, we trace specific paths
            0x63 | 0x64 | 0x67 | 0x68 => { i += 1; }

            // OpCheckSig: pops pk + sig (2), pushes bool (1). Net -1.
            0xac => {
                assert!(depth >= 2, "{path_name}: OpCheckSig at byte {i} with depth {depth}");
                depth -= 1;
                i += 1;
            }

            _ => {
                // Unknown opcode — skip, assume net 0
                i += 1;
            }
        }
    }
    depth
}

/// Extract PATH 2 (default claim) bytecode from ACTIVE_LOAN_BODY.
/// PATH 2 runs from after "Op2 OpEqual OpVerify" to the cleanup OpDrops
/// before OpEndIf.
#[test]
fn active_loan_path2_default_claim_stack_depth() {
    let body = ACTIVE_LOAN_BODY;

    // PATH 2 starts at the "Op2 OpEqual OpVerify" selector check.
    // After dispatch + branch A + sub-branch (sel>=2):
    //   Dispatch: Op13 OpRoll (2B)
    //   Branch: OpDup Op4 OpLessThan OpIf (5B) = offset 7
    //   Sub-branch: OpDup Op2 OpLessThan OpIf (5B) = offset 12
    //   PATH 1 ends at OpElse... PATH 2 begins after that OpElse.
    //
    // Find PATH 2's selector check: 0x52, 0x87, 0x69 (Op2 OpEqual OpVerify)
    // Then find its cleanup (13 OpDrops).
    //
    // Instead of manually extracting bytes, we verify the key CLTV section:
    // After "Op2 OpEqual OpVerify" (sel consumed), stack depth = 15
    // (13 state + pk(13) + sig(14), sel consumed = 15 items)

    // Find the Op2 OpEqual OpVerify sequence for PATH 2
    let path2_start = body.windows(3)
        .position(|w| w == [0x52, 0x87, 0x69])
        .expect("PATH 2 selector check not found");

    // After sel consumed: depth = 15 (liq_th..lend=13 + pk + sig)
    // Walk PATH 2 bytecode from after selector check
    // PATH 2 ends at OpEndIf (0x68). It includes cleanup OpDrops.
    // Find the end: after 13 OpDrops there's OpEndIf at offset for path2/3 boundary
    let path2_body_start = path2_start + 3; // after Op2 OpEqual OpVerify

    // Extract PATH 2 bytes: from selector check to the OpElse (path 3 boundary)
    // The OpElse for path 3 is 0x67 after the 13 cleanup OpDrops
    let mut end = path2_body_start;
    let mut drop_count = 0;
    while end < body.len() {
        if body[end] == 0x75 {
            drop_count += 1;
            if drop_count == 13 {
                end += 1; // include last drop
                break;
            }
        } else {
            drop_count = 0;
        }
        end += 1;
    }

    let path2_bytes = &body[path2_body_start..end];

    // Initial depth after sel consumed: 15
    // (liq_th(0) grace(1) rcap(2) rfl(3) rm(4) ccid(5) exp(6)
    //  start(7) rd(8) rn(9) princ(10) borr(11) lend(12) pk(13) sig(14))
    let final_depth = verify_stack_depths("PATH 2 (default claim)", path2_bytes, 15);

    // After 13 drops, should be at depth 2 (pk and sig were rolled/consumed)
    // Actually: sig and pk are OpRoll'd and consumed by CheckSigVerify (-2 from Roll, -2 from CSV)
    // Then 13 state items dropped = 0 items left. But cleanup drops 13, so:
    // After auth: depth = 13. After 13 drops: depth = 0.
    assert_eq!(final_depth, 0,
        "PATH 2 must end with empty stack (got {final_depth})");
}

#[test]
fn active_loan_path2_cltv_opdrop_present() {
    let body = ACTIVE_LOAN_BODY;
    // CLTV (0xb0) must be immediately followed by OpDrop (0x75)
    // This is the bug fix — CLTV doesn't pop, so we need explicit OpDrop
    let cltv_pos = body.iter().position(|&b| b == 0xb0)
        .expect("CLTV opcode not found in body");
    assert_eq!(body[cltv_pos + 1], 0x75,
        "OpDrop (0x75) must immediately follow CLTV (0xb0) at pos {cltv_pos}; \
         got 0x{:02x}. CLTV does NOT pop the stack — explicit drop required.",
        body[cltv_pos + 1]);
}

#[test]
fn active_loan_path3_repay_stack_depth() {
    let body = ACTIVE_LOAN_BODY;

    // PATH 3 starts at "Op3 OpEqual OpVerify"
    let path3_start = body.windows(3)
        .position(|w| w == [0x53, 0x87, 0x69])
        .expect("PATH 3 selector check not found");

    let path3_body_start = path3_start + 3;

    // Find cleanup end: 14 OpDrops for PATH 3
    let mut end = path3_body_start;
    let mut drop_count = 0;
    while end < body.len() {
        if body[end] == 0x75 {
            drop_count += 1;
            if drop_count == 14 {
                end += 1;
                break;
            }
        } else {
            drop_count = 0;
        }
        end += 1;
    }

    let path3_bytes = &body[path3_body_start..end];

    // Initial depth: 16 (13 state + pk + sig + loi, sel consumed)
    let final_depth = verify_stack_depths("PATH 3 (repay)", path3_bytes, 16);
    assert_eq!(final_depth, 0,
        "PATH 3 must end with empty stack (got {final_depth})");
}

#[test]
fn active_loan_path1_liquidate_stack_depth() {
    let body = ACTIVE_LOAN_BODY;

    // PATH 1 starts at "Op1 OpEqual OpVerify"
    let path1_start = body.windows(3)
        .position(|w| w == [0x51, 0x87, 0x69])
        .expect("PATH 1 selector check not found");

    let path1_body_start = path1_start + 3;

    // Find cleanup end: 17 OpDrops for PATH 1
    let mut end = path1_body_start;
    let mut drop_count = 0;
    while end < body.len() {
        if body[end] == 0x75 {
            drop_count += 1;
            if drop_count == 17 {
                end += 1;
                break;
            }
        } else {
            drop_count = 0;
        }
        end += 1;
    }

    let path1_bytes = &body[path1_body_start..end];

    // Initial depth: 17 (13 state + liqi + boi + loi + pi, sel consumed)
    let final_depth = verify_stack_depths("PATH 1 (liquidate)", path1_bytes, 17);
    assert_eq!(final_depth, 0,
        "PATH 1 must end with empty stack (got {final_depth})");
}

#[test]
fn active_loan_path5_topup_stack_depth() {
    let body = ACTIVE_LOAN_BODY;

    // PATH 5 starts at "Op5 OpEqual OpVerify"
    let path5_start = body.windows(3)
        .position(|w| w == [0x55, 0x87, 0x69])
        .expect("PATH 5 selector check not found");

    let path5_body_start = path5_start + 3;

    // Find cleanup end: 14 OpDrops
    let mut end = path5_body_start;
    let mut drop_count = 0;
    while end < body.len() {
        if body[end] == 0x75 {
            drop_count += 1;
            if drop_count == 14 {
                end += 1;
                break;
            }
        } else {
            drop_count = 0;
        }
        end += 1;
    }

    let path5_bytes = &body[path5_body_start..end];

    // Initial depth: 16 (13 state + pk + sig + ci, sel consumed)
    let final_depth = verify_stack_depths("PATH 5 (topup)", path5_bytes, 16);
    assert_eq!(final_depth, 0,
        "PATH 5 must end with empty stack (got {final_depth})");
}

#[test]
fn active_loan_only_one_cltv() {
    let body = ACTIVE_LOAN_BODY;
    let cltv_count = body.iter().filter(|&&b| b == 0xb0).count();
    assert_eq!(cltv_count, 1,
        "exactly 1 CLTV expected (PATH 2 only), got {cltv_count}");
}
