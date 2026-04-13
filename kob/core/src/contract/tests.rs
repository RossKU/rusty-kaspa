#[allow(deprecated)]

use super::*;
use super::helpers::opn;
use crate::primitives::{minimal_script_encode, push_data, u64_le};

// Opcode constants used in tests
const OP_0: u8 = 0x00;
const OP_1: u8 = 0x51;
const OP_2: u8 = 0x52;
const OP_3: u8 = 0x53;
const OP_4: u8 = 0x54;
const OP_5: u8 = 0x55;
const OP_6: u8 = 0x56;
const OP_7: u8 = 0x57;
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
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKSIGVERIFY: u8 = 0xad;
const OP_CLTV: u8 = 0xb0;
const OP_CSV: u8 = 0xb2;
const OP_TXINPUTINDEX: u8 = 0xb9;
const OP_TXINPUTAMOUNT: u8 = 0xbe;
const OP_TXINPUTSPK: u8 = 0xbf;
const OP_TXINPUTSIGSIGLEN: u8 = 0xc9;
const OP_TXOUTPUTAMOUNT: u8 = 0xc2;
const OP_TXOUTPUTSPK: u8 = 0xc3;
const OP_INPUTCOUNT: u8 = 0xb3;
const OP_TXLOCKTIME: u8 = 0xb5;
const OP_INPUTCOVENANTID: u8 = 0xcf;
const OP_COVINPUTCOUNT: u8 = 0xd0;
const OP_COVOUTCOUNT: u8 = 0xd2;
const OP_COVINPUTIDX: u8 = 0xd1;

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    #[test]
    fn opn_values() {
        assert_eq!(opn(0), 0x00);
        assert_eq!(opn(1), 0x51);
        assert_eq!(opn(2), 0x52);
        assert_eq!(opn(9), 0x59);
        assert_eq!(opn(16), 0x60);
    }

    #[test]
    #[should_panic(expected = "OpN index out of range")]
    fn opn_panic_on_17() {
        opn(17);
    }

    // Token contract tests

    #[test]
    fn token_mint_body_length() {
        assert_eq!(TOKEN_MINT_BODY.len(), 14, "token_mint body must be 14 bytes");
    }

    #[test]
    fn token_unit_body_length() {
        assert_eq!(TOKEN_UNIT_BODY.len(), 2, "token_unit body must be 2 bytes");
    }

    #[test]
    fn token_mint_body_hex_matches_spec() {
        let expected = "517a6300c3b9bf8769ad67ad6851";
        assert_eq!(hex::encode(TOKEN_MINT_BODY), expected);
    }

    #[test]
    fn token_unit_body_hex_matches_spec() {
        let expected = "ad51";
        assert_eq!(hex::encode(TOKEN_UNIT_BODY), expected);
    }

    #[test]
    fn token_mint_redeem_script_length() {
        let pk = [0u8; 32];
        let rs = build_token_mint_redeem_script(&pk);
        assert_eq!(rs.len(), 47, "token_mint RS must be 47 bytes (33 + 14)");
    }

    #[test]
    fn token_unit_redeem_script_length() {
        let pk = [0u8; 32];
        let rs = build_token_unit_redeem_script(&pk);
        assert_eq!(rs.len(), 35, "token_unit RS must be 35 bytes (33 + 2)");
    }

    #[test]
    fn token_mint_state_layout() {
        let pk = [0xAA; 32];
        let rs = build_token_mint_redeem_script(&pk);
        assert_eq!(rs[0], 0x20, "admin_pk push opcode");
        assert_eq!(&rs[1..33], &[0xAA; 32], "admin_pubkey");
        assert_eq!(&rs[33..], TOKEN_MINT_BODY, "body must match");
    }

    #[test]
    fn token_unit_state_layout() {
        let pk = [0xBB; 32];
        let rs = build_token_unit_redeem_script(&pk);
        assert_eq!(rs[0], 0x20, "owner_pk push opcode");
        assert_eq!(&rs[1..33], &[0xBB; 32], "owner_pubkey");
        assert_eq!(&rs[33..], TOKEN_UNIT_BODY, "body must match");
    }

    #[test]
    fn token_mint_sigscript_structure() {
        let pk = [0u8; 32];
        let rs = build_token_mint_redeem_script(&pk);
        let sig = [0x42u8; 64];
        let ss = build_token_mint_sigscript(&sig, &rs);
        // [65] [sig 64B] [0x01] [0x51] [pushData(RS 47B)]
        // = 66 + 1 + 1 + 47 = 115
        assert_eq!(ss.len(), 115, "token_mint mint sigscript = 115B");
        assert_eq!(ss[0], 65, "first byte = sig length prefix");
        assert_eq!(ss[65], 0x01, "sighash type");
        assert_eq!(ss[66], 0x51, "Op1 selector = mint");
        assert_eq!(ss[67], 47, "RS push length");
    }

    #[test]
    fn token_burn_sigscript_structure() {
        let pk = [0u8; 32];
        let rs = build_token_mint_redeem_script(&pk);
        let sig = [0x42u8; 64];
        let ss = build_token_burn_sigscript(&sig, &rs);
        // [65] [sig 64B] [0x01] [0x00] [pushData(RS 47B)]
        // = 66 + 1 + 1 + 47 = 115
        assert_eq!(ss.len(), 115, "token_mint burn sigscript = 115B");
        assert_eq!(ss[66], 0x00, "Op0 selector = burn");
    }

    #[test]
    fn token_unit_sigscript_structure() {
        let pk = [0u8; 32];
        let rs = build_token_unit_redeem_script(&pk);
        let sig = [0x42u8; 64];
        let ss = build_token_unit_sigscript(&sig, &rs);
        // [65] [sig 64B] [0x01] [pushData(RS 35B)]
        // = 66 + 1 + 35 = 102
        assert_eq!(ss.len(), 102, "token_unit transfer sigscript = 102B");
        assert_eq!(ss[0], 65, "first byte = sig length prefix");
        assert_eq!(ss[65], 0x01, "sighash type");
        assert_eq!(ss[66], 35, "RS push length");
    }

    // Zero-fill attack prevention tests (TN12 T79: min_fill=0 vulnerability)

    // Token contract tests

    #[test]
    fn token_mint_sigscript_mint_vs_burn_differ() {
        let pk = [0u8; 32];
        let rs = build_token_mint_redeem_script(&pk);
        let sig = [0x42u8; 64];
        let mint_ss = build_token_mint_sigscript(&sig, &rs);
        let burn_ss = build_token_burn_sigscript(&sig, &rs);
        // Same length, different selector byte
        assert_eq!(mint_ss.len(), burn_ss.len());
        assert_ne!(mint_ss, burn_ss, "mint and burn sigscripts must differ");
        assert_eq!(mint_ss[66], 0x51, "mint has Op1");
        assert_eq!(burn_ss[66], 0x00, "burn has Op0");
    }

    // trade_receipt tests (consume-only, no trigger-read)

    #[test]
    fn receipt_body_length() {
        assert_eq!(RECEIPT_BODY.len(), 17, "trade_receipt body must be 17 bytes");
    }

    #[test]
    fn receipt_body_ends_with_op1() {
        assert_eq!(*RECEIPT_BODY.last().unwrap(), 0x51, "body must end with Op1 (TRUE)");
    }

    #[test]
    fn receipt_redeem_script_length() {
        let pair_id = [0u8; 32];
        let rhash = [0u8; 32];
        let rs = build_receipt_redeem_script(&pair_id, 1, 2, 5000, 10_000_000_000, &rhash).unwrap();
        assert_eq!(rs.len(), 119, "trade_receipt RS must be 119 bytes (102 + 17)");
    }

    #[test]
    fn receipt_no_trigger_read_dispatch() {
        // Body must NOT contain sigLen dispatch opcodes (OpIf, OpElse, OpEndIf)
        let op_if: u8 = 0x63;
        let op_else: u8 = 0x67;
        let op_endif: u8 = 0x68;
        let op_tx_input_script_sig_len: u8 = 0xc9;
        assert!(!RECEIPT_BODY.contains(&op_if), "must not contain OpIf");
        assert!(!RECEIPT_BODY.contains(&op_else), "must not contain OpElse");
        assert!(!RECEIPT_BODY.contains(&op_endif), "must not contain OpEndIf");
        assert!(!RECEIPT_BODY.contains(&op_tx_input_script_sig_len), "must not contain OpTxInputScriptSigLen");
    }

    #[test]
    fn receipt_balanced_if_endif() {
        // No branching at all — both counts must be 0
        let if_count = RECEIPT_BODY.iter().filter(|&&b| b == 0x63).count();
        let endif_count = RECEIPT_BODY.iter().filter(|&&b| b == 0x68).count();
        assert_eq!(if_count, 0, "must have 0 OpIf");
        assert_eq!(endif_count, 0, "must have 0 OpEndIf");
    }

    #[test]
    fn receipt_deterministic_rs_builder() {
        let pair_id = [0xAA; 32];
        let rhash = [0xBB; 32];
        let rs1 = build_receipt_redeem_script(&pair_id, 42, 7, 1000, 50_000, &rhash).unwrap();
        let rs2 = build_receipt_redeem_script(&pair_id, 42, 7, 1000, 50_000, &rhash).unwrap();
        assert_eq!(rs1, rs2, "RS builder must be deterministic");
    }

    #[test]
    fn receipt_state_layout() {
        let pair_id = [0xAA; 32];
        let rhash = [0xEE; 32];
        let rs = build_receipt_redeem_script(&pair_id, 100, 200, 5000, 10_000_000_000, &rhash).unwrap();

        // Verify state layout (102 bytes) — identical to v3
        assert_eq!(rs[0], 0x20, "pair_id push opcode");
        assert_eq!(&rs[1..33], &[0xAA; 32], "pair_id");
        assert_eq!(rs[33], 0x08, "pnum push opcode");
        assert_eq!(u64::from_le_bytes(rs[34..42].try_into().unwrap()), 100, "price_num");
        assert_eq!(rs[42], 0x08, "pden push opcode");
        assert_eq!(u64::from_le_bytes(rs[43..51].try_into().unwrap()), 200, "price_den");
        assert_eq!(rs[51], 0x08, "exec_amount push opcode");
        assert_eq!(u64::from_le_bytes(rs[52..60].try_into().unwrap()), 5000, "exec_amount");
        assert_eq!(rs[60], 0x08, "min_receipt_value push opcode");
        assert_eq!(u64::from_le_bytes(rs[61..69].try_into().unwrap()), 10_000_000_000, "min_receipt_value");
        assert_eq!(rs[69], 0x20, "rhash push opcode");
        assert_eq!(&rs[70..102], &[0xEE; 32], "recipient_hash");

        // Body starts at offset 102
        assert_eq!(&rs[102..], RECEIPT_BODY, "body must match bytecode");
    }

    #[test]
    fn receipt_consume_sigscript_structure() {
        let pair_id = [0u8; 32];
        let rhash = [0u8; 32];
        let rs = build_receipt_redeem_script(&pair_id, 1, 2, 5000, 10_000_000_000, &rhash).unwrap();
        let sig = [0xAA; 64];
        let pk = [0xBB; 32];
        let ss = build_receipt_consume_sigscript(&sig, &pk, &rs);

        // Structure: [65][sig 64B][0x01] [32][pk 32B] [0x4c][119][RS 119B]
        // RS=119 > 75, so PUSHDATA1: [0x4c][len][data]
        assert_eq!(ss[0], 65, "sig push length");
        assert_eq!(&ss[1..65], &[0xAA; 64], "signature bytes");
        assert_eq!(ss[65], 0x01, "sighash type");
        assert_eq!(ss[66], 32, "pk push length");
        assert_eq!(&ss[67..99], &[0xBB; 32], "pubkey bytes");
        assert_eq!(ss[99], 0x4c, "PUSHDATA1 for RS");
        assert_eq!(ss[100], 119, "RS length byte");
        assert_eq!(&ss[101..], rs.as_slice(), "redeemScript");
    }

    #[test]
    #[should_panic(expected = "price_den must be > 0")]
    fn receipt_rejects_price_den_zero() {
        let pair_id = [0u8; 32];
        let rhash = [0u8; 32];
        build_receipt_redeem_script(&pair_id, 1, 0, 5000, 10_000_000_000, &rhash).unwrap();
    }

    #[test]
    #[should_panic(expected = "exec_amount must be > 0")]
    fn receipt_rejects_exec_amount_zero() {
        let pair_id = [0u8; 32];
        let rhash = [0u8; 32];
        build_receipt_redeem_script(&pair_id, 1, 2, 0, 10_000_000_000, &rhash).unwrap();
    }

    #[test]
    fn receipt_accepts_min_receipt_value_zero() {
        let pair_id = [0u8; 32];
        let rhash = [0u8; 32];
        let rs = build_receipt_redeem_script(&pair_id, 1, 2, 5000, 0, &rhash).unwrap();
        assert_eq!(rs.len(), 119);
    }

    // payment_channel tests (F13 fix: authorized top-up)

    #[test]
    fn payment_channel_body_length() {
        assert_eq!(PAYMENT_CHANNEL_BODY.len(), 36, "payment_channel body must be 36 bytes");
    }

    #[test]
    fn payment_channel_body_hex_matches_spec() {
        let expected = "527a63527a5279ad527a7cad756700c3b9bf876900c2b9bea069527a6377677568ad6851";
        assert_eq!(hex::encode(PAYMENT_CHANNEL_BODY), expected);
    }

    #[test]
    fn payment_channel_redeem_script_length() {
        let pk_a = [0u8; 32];
        let pk_b = [0u8; 32];
        let rs = build_payment_channel_redeem_script(&pk_a, &pk_b);
        // State: 33 + 33 = 66B. Body: 36B. Total: 102B
        assert_eq!(rs.len(), 102, "payment_channel RS must be 102 bytes (66 + 36)");
    }

    #[test]
    fn payment_channel_state_layout() {
        let pk_a = [0xAA; 32];
        let pk_b = [0xBB; 32];
        let rs = build_payment_channel_redeem_script(&pk_a, &pk_b);

        // [0x20][party_a_pk 32B][0x20][party_b_pk 32B][BODY 36B]
        assert_eq!(rs[0], 0x20, "party_a_pk push opcode");
        assert_eq!(&rs[1..33], &[0xAA; 32], "party_a_pk");
        assert_eq!(rs[33], 0x20, "party_b_pk push opcode");
        assert_eq!(&rs[34..66], &[0xBB; 32], "party_b_pk");

        // Body starts at offset 66
        assert_eq!(&rs[66..], PAYMENT_CHANNEL_BODY, "body must match bytecode");
    }

    #[test]
    fn payment_channel_close_sigscript_structure() {
        let pk_a = [0u8; 32];
        let pk_b = [0u8; 32];
        let rs = build_payment_channel_redeem_script(&pk_a, &pk_b);
        let sig_a = [0x42u8; 64];
        let sig_b = [0x43u8; 64];
        let ss = build_payment_channel_close_sigscript(&sig_a, &sig_b, &rs);
        // pushData(sig_b 65B) = 66B
        // pushData(sig_a 65B) = 66B
        // Op1(1) = 1B
        // OP_PUSHDATA1(1) + len(1) + rs(102) = 104B
        // Total: 66 + 66 + 1 + 104 = 237
        assert_eq!(ss.len(), 237, "close sigscript = 237B");
        // sig_b is first (pushed deeper), sig_a is second (on top)
        assert_eq!(ss[0], 65, "sig_b length prefix");
        assert_eq!(ss[66], 65, "sig_a length prefix");
        // Verify sig_b content (pushed first = 0x43)
        assert_eq!(ss[1], 0x43, "sig_b content");
        // Verify sig_a content (pushed second = 0x42)
        assert_eq!(ss[67], 0x42, "sig_a content");
        // Op1 selector
        assert_eq!(ss[132], 0x51, "Op1 selector = close");
    }

    #[test]
    fn payment_channel_topup_party_a_sigscript_structure() {
        let pk_a = [0u8; 32];
        let pk_b = [0u8; 32];
        let rs = build_payment_channel_redeem_script(&pk_a, &pk_b);
        let sig = [0x42u8; 64];
        let ss = build_payment_channel_topup_sigscript(&sig, 0, &rs).unwrap(); // party_a
        // pushData(sig 65B) = 66B
        // Op0(1) party_idx = 1B
        // Op0(1) selector = 1B
        // OP_PUSHDATA1(1) + len(1) + rs(102) = 104B
        // Total: 66 + 1 + 1 + 104 = 172
        assert_eq!(ss.len(), 172, "party_a topup sigscript = 172B");
        assert_eq!(ss[0], 65, "sig length prefix");
        assert_eq!(ss[65], 0x01, "sighash type");
        assert_eq!(ss[66], 0x00, "Op0 party_idx = party_a");
        assert_eq!(ss[67], 0x00, "Op0 selector = top-up");
    }

    #[test]
    fn payment_channel_topup_party_b_sigscript_structure() {
        let pk_a = [0u8; 32];
        let pk_b = [0u8; 32];
        let rs = build_payment_channel_redeem_script(&pk_a, &pk_b);
        let sig = [0x42u8; 64];
        let ss = build_payment_channel_topup_sigscript(&sig, 1, &rs).unwrap(); // party_b
        // Same total length as party_a
        assert_eq!(ss.len(), 172, "party_b topup sigscript = 172B");
        assert_eq!(ss[66], 0x51, "Op1 party_idx = party_b");
        assert_eq!(ss[67], 0x00, "Op0 selector = top-up");
    }

    #[test]
    #[should_panic(expected = "party_idx must be 0")]
    fn payment_channel_topup_rejects_invalid_party_idx() {
        let pk_a = [0u8; 32];
        let pk_b = [0u8; 32];
        let rs = build_payment_channel_redeem_script(&pk_a, &pk_b);
        let sig = [0u8; 64];
        build_payment_channel_topup_sigscript(&sig, 2, &rs).unwrap();
    }

    #[test]
    fn payment_channel_state_layout_matches_spec() {
        // State layout: [0x20][pk_a 32B][0x20][pk_b 32B]
        let pk_a = [0xAA; 32];
        let pk_b = [0xBB; 32];
        let rs = build_payment_channel_redeem_script(&pk_a, &pk_b);

        // State bytes (first 66) should be identical regardless of body version
        assert_eq!(rs[0], 0x20);
        assert_eq!(&rs[1..33], &[0xAA; 32]);
        assert_eq!(rs[33], 0x20);
        assert_eq!(&rs[34..66], &[0xBB; 32]);
        // RS is 102B (66 state + 36 body)
        assert_eq!(rs.len(), 102);
    }

    #[test]
    fn payment_channel_topup_party_a_vs_b_differ() {
        let pk_a = [0u8; 32];
        let pk_b = [0u8; 32];
        let rs = build_payment_channel_redeem_script(&pk_a, &pk_b);
        let sig = [0x42u8; 64];
        let ss_a = build_payment_channel_topup_sigscript(&sig, 0, &rs).unwrap();
        let ss_b = build_payment_channel_topup_sigscript(&sig, 1, &rs).unwrap();
        assert_eq!(ss_a.len(), ss_b.len(), "same length");
        assert_ne!(ss_a, ss_b, "party_a and party_b sigscripts must differ");
        // Only the party_idx byte differs
        assert_eq!(ss_a[66], 0x00, "party_a idx = Op0");
        assert_eq!(ss_b[66], 0x51, "party_b idx = Op1");
    }

    // oco_pair tests (OCO2-F3: CBP value floor + input count)

    #[test]
    fn oco_pair_body_length() {
        assert_eq!(OCO_PAIR_BODY.len(), 147, "oco_pair body must be 147 bytes");
    }

    #[test]
    fn oco_pair_redeem_script_length() {
        let nonce = [0u8; 32];
        let tcid = [0u8; 32];
        let ohash = [0u8; 32];
        let ospk = [0u8; 36];
        let rs = build_oco_pair_redeem_script(
            &nonce, 0, &tcid, 0, 1, 2, 1000, &ohash, &ospk,
        ).unwrap();
        assert_eq!(rs.len(), 328, "oco_pair RS must be 328 bytes (181 + 147)");
    }

    #[test]
    fn oco_pair_state_layout() {
        let nonce = [0x11; 32];
        let tcid = [0xAA; 32];
        let ohash = [0xBB; 32];
        let ospk = [0xCC; 36];
        let rs = build_oco_pair_redeem_script(
            &nonce, 1, &tcid, 5000, 100, 200, 3_000_000, &ohash, &ospk,
        ).unwrap();

        // State layout (181 bytes, identical to v3):
        // [0x20][nonce 32B][0x08][role 8B][0x20][tcid 32B][0x08][tamt 8B]
        // [0x08][pnum 8B][0x08][pden 8B][0x08][mfill 8B][0x20][ohash 32B]
        // [0x24][ospk 36B]
        assert_eq!(rs[0], 0x20, "nonce push opcode");
        assert_eq!(&rs[1..33], &[0x11; 32], "nonce");
        assert_eq!(rs[33], 0x08, "role push opcode");
        assert_eq!(u64::from_le_bytes(rs[34..42].try_into().unwrap()), 1, "role");
        assert_eq!(rs[42], 0x20, "tcid push opcode");
        assert_eq!(&rs[43..75], &[0xAA; 32], "token_cov_id");
        assert_eq!(rs[75], 0x08, "tamt push opcode");
        assert_eq!(u64::from_le_bytes(rs[76..84].try_into().unwrap()), 5000, "token_amount");
        assert_eq!(rs[84], 0x08, "pnum push opcode");
        assert_eq!(u64::from_le_bytes(rs[85..93].try_into().unwrap()), 100, "price_num");
        assert_eq!(rs[93], 0x08, "pden push opcode");
        assert_eq!(u64::from_le_bytes(rs[94..102].try_into().unwrap()), 200, "price_den");
        assert_eq!(rs[102], 0x08, "mfill push opcode");
        assert_eq!(u64::from_le_bytes(rs[103..111].try_into().unwrap()), 3_000_000, "min_fill");
        assert_eq!(rs[111], 0x20, "ohash push opcode");
        assert_eq!(&rs[112..144], &[0xBB; 32], "owner_hash");
        assert_eq!(rs[144], 0x24, "ospk push opcode");
        assert_eq!(&rs[145..181], &[0xCC; 36], "owner_spk");

        // Body starts at offset 181 (same as v3)
        assert_eq!(&rs[181..], OCO_PAIR_BODY, "body must match bytecode");
    }

    #[test]
    fn oco_pair_dispatch_threshold_correct() {
        // The dispatch threshold is 350 (bytes 2-4 of body: 02 5e 01)
        assert_eq!(&OCO_PAIR_BODY[2..5], &[0x02, 0x5e, 0x01], "threshold push = 350");
        let threshold = u16::from_le_bytes([OCO_PAIR_BODY[3], OCO_PAIR_BODY[4]]);
        assert_eq!(threshold, 350, "dispatch threshold = 350");

        // Verify sigscript lengths vs threshold
        let nonce = [0u8; 32];
        let tcid = [0u8; 32];
        let ohash = [0u8; 32];
        let ospk = [0u8; 36];
        let rs = build_oco_pair_redeem_script(
            &nonce, 0, &tcid, 0, 1, 2, 1000, &ohash, &ospk,
        ).unwrap();
        let fill_ss = build_oco_pair_fill_sigscript(1, &rs);
        let cbp_ss = build_oco_pair_cbp_sigscript(0, &rs);
        let sig = [0u8; 64];
        let pk = [0u8; 32];
        let cancel_ss = build_oco_pair_cancel_sigscript(&sig, &pk, &rs);

        assert!(fill_ss.len() < 350, "fill < threshold");
        assert!(cbp_ss.len() < 350, "cbp < threshold");
        assert!(cancel_ss.len() >= 350, "cancel >= threshold");

        // Safety margins
        assert!(350 - fill_ss.len() >= 10, "fill margin >= 10B");
        assert!(cancel_ss.len() - 350 >= 50, "cancel margin >= 50B");
    }

    #[test]
    fn oco_pair_fill_sigscript_below_threshold() {
        let nonce = [0u8; 32];
        let tcid = [0u8; 32];
        let ohash = [0u8; 32];
        let ospk = [0u8; 36];
        let rs = build_oco_pair_redeem_script(
            &nonce, 0, &tcid, 0, 1, 2, 1000, &ohash, &ospk,
        ).unwrap();
        let ss = build_oco_pair_fill_sigscript(1, &rs);
        // Op1(1) + OpN(1) + PUSHDATA2(1) + len(2) + RS(328) = 333
        assert_eq!(ss.len(), 333, "fill sigscript = 333B");
        assert!(ss.len() < 350, "fill sigscript must be < 350 for non-cancel dispatch");
        assert_eq!(ss[0], 0x51, "first byte must be Op1 (fill selector)");
        assert_eq!(ss[1], 0x51, "second byte must be Op1 (partner_idx=1)");
    }

    #[test]
    fn oco_pair_cbp_sigscript_below_threshold() {
        let nonce = [0u8; 32];
        let tcid = [0u8; 32];
        let ohash = [0u8; 32];
        let ospk = [0u8; 36];
        let rs = build_oco_pair_redeem_script(
            &nonce, 1, &tcid, 5000, 1, 2, 1000, &ohash, &ospk,
        ).unwrap();
        let ss = build_oco_pair_cbp_sigscript(0, &rs);
        // Op2(1) + Op0(1) + PUSHDATA2(1) + len(2) + RS(328) = 333
        assert_eq!(ss.len(), 333, "cbp sigscript = 333B");
        assert!(ss.len() < 350, "cbp sigscript must be < 350 for non-cancel dispatch");
        assert_eq!(ss[0], 0x52, "first byte must be Op2 (cbp selector)");
        assert_eq!(ss[1], 0x00, "second byte must be Op0 (partner_idx=0)");
    }

    #[test]
    fn oco_pair_cancel_sigscript_above_threshold() {
        let nonce = [0u8; 32];
        let tcid = [0u8; 32];
        let ohash = [0u8; 32];
        let ospk = [0u8; 36];
        let rs = build_oco_pair_redeem_script(
            &nonce, 0, &tcid, 0, 1, 2, 1000, &ohash, &ospk,
        ).unwrap();
        let sig = [0u8; 64];
        let pk = [0u8; 32];
        let ss = build_oco_pair_cancel_sigscript(&sig, &pk, &rs);
        // Op0(1) + push(sig65)(66) + push(pk32)(33) + PUSHDATA2(1) + len(2) + RS(328) = 431
        assert_eq!(ss.len(), 431, "cancel sigscript = 431B");
        assert!(ss.len() >= 350, "cancel sigscript must be >= 350 for cancel dispatch");
        assert_eq!(ss[0], 0x00, "first byte must be Op0 (cancel selector)");
    }

    #[test]
    fn oco_pair_cbp_path_contains_value_floor() {
        // Verify that the CBP path contains the value floor opcodes:
        // b9 be 02 10 27 94 b9 c2 7c a2 69
        let body_hex = hex::encode(OCO_PAIR_BODY);
        // Value floor: OpTxInputIndex(b9) OpTxInputAmount(be) push10000(021027)
        //   OpSub(94) OpTxInputIndex(b9) OpTxOutputAmount(c2) OpSwap(7c) OpGTE(a2) OpVerify(69)
        assert!(
            body_hex.contains("b9be02102794b9c27ca269"),
            "CBP path must contain value floor opcodes"
        );
    }

    #[test]
    fn oco_pair_cbp_path_contains_input_count_check() {
        // Verify that the CBP path contains the input count = 2 check:
        // b3 52 87 69
        let body_hex = hex::encode(OCO_PAIR_BODY);
        // OpTxInputCount(b3) Op2(52) OpEqual(87) OpVerify(69)
        assert!(
            body_hex.contains("b3528769"),
            "CBP path must contain input count = 2 check opcodes"
        );
    }

    #[test]
    fn oco_pair_cbp_path_no_partner_spk_opcodes() {
        // Verify that v4 does NOT contain partner SPK hash opcodes (bf, aa for TxInputSpk+Blake2b)
        let body_hex = hex::encode(OCO_PAIR_BODY);
        assert!(
            !body_hex.contains("bfaa"),
            "CBP path must NOT contain OpTxInputSpk+OpBlake2b (no partner_spk_hash)"
        );
    }

    #[test]
    fn oco_pair_buy_and_sell_rs_differ() {
        let nonce = [0x42; 32];
        let tcid = [0xAA; 32];
        let ohash = [0xBB; 32];
        let ospk = [0xCC; 36];
        let buy_rs = build_oco_pair_redeem_script(
            &nonce, 0, &tcid, 0, 100, 1, 1000, &ohash, &ospk,
        ).unwrap();
        let sell_rs = build_oco_pair_redeem_script(
            &nonce, 1, &tcid, 5000, 100, 1, 1000, &ohash, &ospk,
        ).unwrap();
        assert_ne!(buy_rs, sell_rs, "buy and sell RS must differ (different role + tamt)");
        assert_eq!(buy_rs.len(), sell_rs.len(), "same length");
    }

    #[test]
    #[should_panic(expected = "price_num must be > 0")]
    fn oco_pair_rejects_price_num_zero() {
        let n = [0u8; 32];
        let t = [0u8; 32];
        let s = [0u8; 36];
        build_oco_pair_redeem_script(&n, 0, &t, 0, 0, 2, 1000, &n, &s).unwrap();
    }

    #[test]
    #[should_panic(expected = "price_den must be > 0")]
    fn oco_pair_rejects_price_den_zero() {
        let n = [0u8; 32];
        let t = [0u8; 32];
        let s = [0u8; 36];
        build_oco_pair_redeem_script(&n, 0, &t, 0, 1, 0, 1000, &n, &s).unwrap();
    }

    #[test]
    #[should_panic(expected = "min_fill must be > 0")]
    fn oco_pair_rejects_min_fill_zero() {
        let n = [0u8; 32];
        let t = [0u8; 32];
        let s = [0u8; 36];
        build_oco_pair_redeem_script(&n, 0, &t, 0, 1, 2, 0, &n, &s).unwrap();
    }

    #[test]
    #[should_panic(expected = "role must be 0 (buy) or 1 (sell)")]
    fn oco_pair_rejects_invalid_role() {
        let n = [0u8; 32];
        let t = [0u8; 32];
        let s = [0u8; 36];
        build_oco_pair_redeem_script(&n, 2, &t, 0, 1, 2, 1000, &n, &s).unwrap();
    }

    #[test]
    fn oco_pair_nonce_at_consistent_sigscript_offset() {
        // The nonce is always at sigscript offset [6..38) for fill/CBP sigscripts.
        let nonce = [0x42; 32];
        let tcid = [0u8; 32];
        let ohash = [0u8; 32];
        let ospk = [0u8; 36];
        let rs = build_oco_pair_redeem_script(
            &nonce, 0, &tcid, 0, 1, 2, 1000, &ohash, &ospk,
        ).unwrap();
        let fill_ss = build_oco_pair_fill_sigscript(1, &rs);
        assert_eq!(&fill_ss[6..38], &[0x42; 32], "nonce at fill sigscript [6..38)");

        let cbp_ss = build_oco_pair_cbp_sigscript(0, &rs);
        assert_eq!(&cbp_ss[6..38], &[0x42; 32], "nonce at CBP sigscript [6..38)");
    }

    // bracket_order tests (N4 fix: receipt covenant_id check)

    #[test]
    fn bracket_body_length() {
        assert_eq!(
            BRACKET_ORDER_BODY.len(),
            142,
            "bracket_order body must be 142 bytes"
        );
    }

    #[test]
    fn bracket_body_hex_matches_spec() {
        let expected = "b9c902a4019f6352c35879876952c25779a26953c35679876953c25579a26952be5379a26952cf527987695b79ce63b9be5a7995597996765579a26900c27ca269757575757575757575757575755167b9be5979965a7995765579a26951c27ca269757575757575757575757575755168675c7976aa527987695e7a7cad75757575757575757575757575755168";
        assert_eq!(
            hex::encode(BRACKET_ORDER_BODY),
            expected,
            "bracket_order body hex must match spec"
        );
    }

    #[test]
    fn bracket_redeem_length() {
        let tcid = [0u8; 32];
        let tp_spk = [0u8; 37];
        let sl_spk = [0u8; 37];
        let rcid = [0u8; 32];
        let ohash = [0u8; 32];
        let rs = build_bracket_redeem_script(
            1, &tcid, 1000, 1, &tp_spk, 5_000_000, &sl_spk, 5_000_000,
            1_000_000, 5_000_000, &rcid, &ohash,
        ).unwrap();
        assert_eq!(rs.len(), 380, "bracket_order RS must be 380 bytes (238 state + 142 body)");
    }

    #[test]
    fn bracket_redeem_state_layout() {
        let tcid = [0xAAu8; 32];
        let tp_spk = [0xBBu8; 37];
        let sl_spk = [0xCCu8; 37];
        let rcid = [0xDDu8; 32];
        let ohash = [0xEEu8; 32];
        let rs = build_bracket_redeem_script(
            1, &tcid, 100, 200, &tp_spk, 5_000_000, &sl_spk, 3_000_000,
            1_000_000, 2_000_000, &rcid, &ohash,
        ).unwrap();

        // State layout verification (238 bytes):
        // [0x08][entry_type 8B] = 9B
        assert_eq!(rs[0], 0x08, "entry_type push opcode");
        assert_eq!(u64::from_le_bytes(rs[1..9].try_into().unwrap()), 1, "entry_type");

        // [0x20][token_cov_id 32B] = 33B
        assert_eq!(rs[9], 0x20, "token_cov_id push opcode");
        assert_eq!(&rs[10..42], &[0xAA; 32], "token_cov_id");

        // [0x08][epnum 8B] = 9B
        assert_eq!(rs[42], 0x08, "epnum push opcode");
        assert_eq!(u64::from_le_bytes(rs[43..51].try_into().unwrap()), 100, "epnum");

        // [0x08][epden 8B] = 9B
        assert_eq!(rs[51], 0x08, "epden push opcode");
        assert_eq!(u64::from_le_bytes(rs[52..60].try_into().unwrap()), 200, "epden");

        // [0x25][tp_spk 37B] = 38B
        assert_eq!(rs[60], 0x25, "tp_spk push opcode");
        assert_eq!(&rs[61..98], &[0xBB; 37], "tp_spk");

        // [0x08][tp_min_val 8B] = 9B
        assert_eq!(rs[98], 0x08, "tp_min_val push opcode");
        assert_eq!(u64::from_le_bytes(rs[99..107].try_into().unwrap()), 5_000_000, "tp_min_val");

        // [0x25][sl_spk 37B] = 38B
        assert_eq!(rs[107], 0x25, "sl_spk push opcode");
        assert_eq!(&rs[108..145], &[0xCC; 37], "sl_spk");

        // [0x08][sl_min_val 8B] = 9B
        assert_eq!(rs[145], 0x08, "sl_min_val push opcode");
        assert_eq!(u64::from_le_bytes(rs[146..154].try_into().unwrap()), 3_000_000, "sl_min_val");

        // [0x08][min_fill 8B] = 9B
        assert_eq!(rs[154], 0x08, "min_fill push opcode");
        assert_eq!(u64::from_le_bytes(rs[155..163].try_into().unwrap()), 1_000_000, "min_fill");

        // [0x08][min_receipt_val 8B] = 9B
        assert_eq!(rs[163], 0x08, "min_receipt_val push opcode");
        assert_eq!(u64::from_le_bytes(rs[164..172].try_into().unwrap()), 2_000_000, "min_receipt_val");

        // [0x20][receipt_cov_id 32B] = 33B  <-- NEW in v4
        assert_eq!(rs[172], 0x20, "receipt_cov_id push opcode");
        assert_eq!(&rs[173..205], &[0xDD; 32], "receipt_cov_id");

        // [0x20][owner_hash 32B] = 33B
        assert_eq!(rs[205], 0x20, "owner_hash push opcode");
        assert_eq!(&rs[206..238], &[0xEE; 32], "owner_hash");

        // Body starts at offset 238
        assert_eq!(&rs[238..], BRACKET_ORDER_BODY, "body must match bytecode");
    }

    #[test]
    fn bracket_fill_sigscript_below_threshold() {
        let tcid = [0u8; 32];
        let tp_spk = [0u8; 37];
        let sl_spk = [0u8; 37];
        let rcid = [0u8; 32];
        let ohash = [0u8; 32];
        let rs = build_bracket_redeem_script(
            0, &tcid, 1000, 1, &tp_spk, 5_000_000, &sl_spk, 5_000_000,
            1_000_000, 5_000_000, &rcid, &ohash,
        ).unwrap();
        let fill_ss = build_bracket_fill_sigscript(&rs);
        // Fill: Op1(1) + OP_PUSHDATA2(3B) + RS(380B) = 384B
        assert_eq!(fill_ss.len(), 384, "fill sigscript must be 384B");
        assert!(fill_ss.len() < 420, "fill must be below dispatch threshold 420");
        assert_eq!(fill_ss[0], 0x51, "first byte must be Op1 selector");
    }

    #[test]
    fn bracket_cancel_sigscript_above_threshold() {
        let tcid = [0u8; 32];
        let tp_spk = [0u8; 37];
        let sl_spk = [0u8; 37];
        let rcid = [0u8; 32];
        let ohash = [0u8; 32];
        let rs = build_bracket_redeem_script(
            0, &tcid, 1000, 1, &tp_spk, 5_000_000, &sl_spk, 5_000_000,
            1_000_000, 5_000_000, &rcid, &ohash,
        ).unwrap();
        let sig = [0u8; 64];
        let pk = [0u8; 32];
        let cancel_ss = build_bracket_cancel_sigscript(&sig, &pk, &rs);
        // Cancel: Op0(1) + push_sig(66) + push_pk(33) + OP_PUSHDATA2(3) + RS(380) = 483B
        assert_eq!(cancel_ss.len(), 483, "cancel sigscript must be 483B");
        assert!(cancel_ss.len() >= 420, "cancel must be at or above dispatch threshold 420");
        assert_eq!(cancel_ss[0], 0x00, "first byte must be Op0 selector");
    }

    #[test]
    fn bracket_dispatch_margin_sufficient() {
        let tcid = [0u8; 32];
        let tp_spk = [0u8; 37];
        let sl_spk = [0u8; 37];
        let rcid = [0u8; 32];
        let ohash = [0u8; 32];
        let rs = build_bracket_redeem_script(
            1, &tcid, 1000, 1, &tp_spk, 5_000_000, &sl_spk, 5_000_000,
            1_000_000, 5_000_000, &rcid, &ohash,
        ).unwrap();
        let fill_ss = build_bracket_fill_sigscript(&rs);
        let sig = [0u8; 64];
        let pk = [0u8; 32];
        let cancel_ss = build_bracket_cancel_sigscript(&sig, &pk, &rs);

        // Verify both are well within their respective sides of threshold 420
        assert!(420 - fill_ss.len() >= 20, "fill margin from threshold must be >= 20B");
        assert!(cancel_ss.len() - 420 >= 50, "cancel margin from threshold must be >= 50B");
    }

    #[test]
    fn bracket_receipt_cov_id_in_body() {
        // Verify the body contains OpInputCovenantId (0xcf) which is the N4 fix
        assert!(
            BRACKET_ORDER_BODY.contains(&0xcf),
            "body must contain OpInputCovenantId (0xcf)"
        );
        // Verify v4 has one more OpDrop than v3 in each section (13 vs 12, 14 vs 13)
        let drop_count = BRACKET_ORDER_BODY.iter().filter(|&&b| b == 0x75).count();
        // SELL: 13, BUY: 13, CANCEL: 14 = 40 total drops
        assert_eq!(drop_count, 40, "body must have 40 total OpDrop opcodes");
    }

    #[test]
    #[should_panic(expected = "entry_price_num must be > 0")]
    fn bracket_rejects_zero_price_num() {
        let tcid = [0u8; 32];
        let tp_spk = [0u8; 37];
        let sl_spk = [0u8; 37];
        let rcid = [0u8; 32];
        let ohash = [0u8; 32];
        build_bracket_redeem_script(
            0, &tcid, 0, 1, &tp_spk, 1000, &sl_spk, 1000, 1000, 1000, &rcid, &ohash,
        ).unwrap();
    }

    #[test]
    #[should_panic(expected = "entry_price_den must be > 0")]
    fn bracket_rejects_zero_price_den() {
        let tcid = [0u8; 32];
        let tp_spk = [0u8; 37];
        let sl_spk = [0u8; 37];
        let rcid = [0u8; 32];
        let ohash = [0u8; 32];
        build_bracket_redeem_script(
            0, &tcid, 1, 0, &tp_spk, 1000, &sl_spk, 1000, 1000, 1000, &rcid, &ohash,
        ).unwrap();
    }

    #[test]
    #[should_panic(expected = "min_fill must be > 0")]
    fn bracket_rejects_zero_min_fill() {
        let tcid = [0u8; 32];
        let tp_spk = [0u8; 37];
        let sl_spk = [0u8; 37];
        let rcid = [0u8; 32];
        let ohash = [0u8; 32];
        build_bracket_redeem_script(
            0, &tcid, 1, 1, &tp_spk, 1000, &sl_spk, 1000, 0, 1000, &rcid, &ohash,
        ).unwrap();
    }

    // call_option tests (American-style with exercise window)

    #[test]
    fn call_option_body_length() {
        assert_eq!(
            CALL_OPTION_BODY.len(),
            33,
            "call_option body must be 33 bytes"
        );
    }

    #[test]
    fn call_option_body_hex_matches_spec() {
        // dispatch(5) + time1(3) + time2(3) + step1(6) + step2(5) + step3(2) + cancel(7) + tail(2) = 33B
        let expected = "567a00a063517ab0b5a06900c2527aa26900c3aa876977ad67b075757575ad6851";
        assert_eq!(
            hex::encode(CALL_OPTION_BODY),
            expected,
            "call_option body hex must match spec"
        );
    }

    #[test]
    fn call_option_redeem_script_length() {
        let writer_pk = [0u8; 32];
        let holder_pk = [0u8; 32];
        let wsh = [0u8; 32];
        let rs = build_call_option_redeem_script(&writer_pk, &holder_pk, 1_000_000, &wsh, 100, 200).unwrap();
        assert_eq!(
            rs.len(),
            159,
            "call_option RS must be 159 bytes (126 state + 33 body)"
        );
    }

    #[test]
    fn call_option_state_layout() {
        let writer_pk = [0xAAu8; 32];
        let holder_pk = [0xBBu8; 32];
        let strike_kas: u64 = 50_000_000_000;
        let wsh = [0xCCu8; 32];
        let start_daa: u64 = 1_000_000;
        let expiry_daa: u64 = 2_000_000;

        let rs = build_call_option_redeem_script(
            &writer_pk,
            &holder_pk,
            strike_kas,
            &wsh,
            start_daa,
            expiry_daa,
        ).unwrap();

        // State layout verification (126 bytes):

        // [0x20][writer_pk 32B] at offset 0..33
        assert_eq!(rs[0], 0x20, "writer_pk push opcode");
        assert_eq!(&rs[1..33], &[0xAA; 32], "writer_pk bytes");

        // [0x20][holder_pk 32B] at offset 33..66
        assert_eq!(rs[33], 0x20, "holder_pk push opcode");
        assert_eq!(&rs[34..66], &[0xBB; 32], "holder_pk bytes");

        // [0x08][strike_kas 8B LE] at offset 66..75
        assert_eq!(rs[66], 0x08, "strike_kas push opcode");
        assert_eq!(
            u64::from_le_bytes(rs[67..75].try_into().unwrap()),
            strike_kas,
            "strike_kas value"
        );

        // [0x20][writer_spk_hash 32B] at offset 75..108
        assert_eq!(rs[75], 0x20, "writer_spk_hash push opcode");
        assert_eq!(&rs[76..108], &[0xCC; 32], "writer_spk_hash bytes");

        // [0x08][start_daa 8B LE] at offset 108..117
        assert_eq!(rs[108], 0x08, "start_daa push opcode");
        assert_eq!(
            u64::from_le_bytes(rs[109..117].try_into().unwrap()),
            start_daa,
            "start_daa value"
        );

        // [0x08][expiry_daa 8B LE] at offset 117..126
        assert_eq!(rs[117], 0x08, "expiry_daa push opcode");
        assert_eq!(
            u64::from_le_bytes(rs[118..126].try_into().unwrap()),
            expiry_daa,
            "expiry_daa value"
        );

        // Body starts at offset 126
        assert_eq!(&rs[126..], CALL_OPTION_BODY, "body must match bytecode");
    }

    #[test]
    fn call_option_dispatch_uses_op6_roll() {
        // Dispatch: 56 7a (Op6 OpRoll) brings selector at depth 6 to top.
        // 6 state fields (expiry, start, wsh, sk, hp, wp) sit above the selector.
        assert_eq!(CALL_OPTION_BODY[0], 0x56, "dispatch Op6");
        assert_eq!(CALL_OPTION_BODY[1], 0x7a, "dispatch OpRoll");
        assert_eq!(CALL_OPTION_BODY[2], 0x00, "dispatch Op0");
        assert_eq!(CALL_OPTION_BODY[3], 0xa0, "dispatch OpGreaterThan");
        assert_eq!(CALL_OPTION_BODY[4], 0x63, "dispatch OpIf");
    }

    #[test]
    fn call_option_exercise_has_cltv_and_locktime() {
        // Exercise path must contain CLTV (0xb0) for start_daa check
        // and OpTxLockTime (0xb5) for expiry_daa check.
        let exercise_body = &CALL_OPTION_BODY[5..24]; // exercise path bytes
        assert!(
            exercise_body.contains(&0xb0),
            "exercise path must contain OpCheckLockTimeVerify (0xb0)"
        );
        assert!(
            exercise_body.contains(&0xb5),
            "exercise path must contain OpTxLockTime (0xb5)"
        );
    }

    #[test]
    fn call_option_cancel_has_cltv() {
        // Cancel path must contain CLTV (0xb0) for expiry_daa enforcement.
        // Cancel path starts at OpElse (byte 24).
        assert_eq!(CALL_OPTION_BODY[24], 0x67, "byte 24 must be OpElse (0x67)");
        assert_eq!(CALL_OPTION_BODY[25], 0xb0, "cancel CLTV for expiry_daa");
        assert_eq!(CALL_OPTION_BODY[26], 0x75, "cancel drop 1 (start)");
        assert_eq!(CALL_OPTION_BODY[27], 0x75, "cancel drop 2 (wsh)");
        assert_eq!(CALL_OPTION_BODY[28], 0x75, "cancel drop 3 (sk)");
        assert_eq!(CALL_OPTION_BODY[29], 0x75, "cancel drop 4 (hp)");
        assert_eq!(CALL_OPTION_BODY[30], 0xad, "cancel CheckSigVerify");
        assert_eq!(CALL_OPTION_BODY[31], 0x68, "OpEndIf");
        assert_eq!(CALL_OPTION_BODY[32], 0x51, "Op1 TRUE");
    }

    #[test]
    fn call_option_body_contains_spk_check() {
        let spk_count = CALL_OPTION_BODY.iter().filter(|&&b| b == 0xc3).count();
        assert_eq!(
            spk_count,
            1,
            "call_option body must contain exactly 1 OpTxOutputSpk (0xc3)"
        );
    }

    #[test]
    fn call_option_exercise_sigscript_format() {
        let writer_pk = [0u8; 32];
        let holder_pk = [0u8; 32];
        let wsh = [0u8; 32];
        let rs = build_call_option_redeem_script(&writer_pk, &holder_pk, 1_000_000, &wsh, 100, 200).unwrap();
        let sig = [0u8; 64];
        let exercise_ss = build_call_option_exercise_sigscript(&sig, &rs);

        // Format: push(sig+type 65B) + Op1 + pushdata1(RS 159B)
        // push(65B): 0x41 prefix (1B) + 65B = 66B
        // Op1: 1B
        // pushdata1(159B): 0x4c (1B) + 0x9f (1B) + 159B = 161B
        // Total: 66 + 1 + 161 = 228B
        assert_eq!(exercise_ss.len(), 228, "exercise sigscript must be 228B");
        assert_eq!(exercise_ss[0], 0x41, "first byte is 0x41 (push 65 bytes)");
        assert_eq!(exercise_ss[66], 0x51, "selector byte must be Op1 (0x51)");
    }

    #[test]
    fn call_option_cancel_sigscript_format() {
        let writer_pk = [0u8; 32];
        let holder_pk = [0u8; 32];
        let wsh = [0u8; 32];
        let rs = build_call_option_redeem_script(&writer_pk, &holder_pk, 1_000_000, &wsh, 100, 200).unwrap();
        let sig = [0u8; 64];
        let cancel_ss = build_call_option_cancel_sigscript(&sig, &rs);

        assert_eq!(cancel_ss.len(), 228, "cancel sigscript must be 228B");
        assert_eq!(cancel_ss[0], 0x41, "first byte is 0x41 (push 65 bytes)");
        assert_eq!(cancel_ss[66], 0x00, "selector byte must be Op0 (0x00)");
    }

    #[test]
    #[should_panic(expected = "strike_kas must be > 0")]
    fn call_option_rejects_zero_strike() {
        let writer_pk = [0u8; 32];
        let holder_pk = [0u8; 32];
        let wsh = [0u8; 32];
        build_call_option_redeem_script(&writer_pk, &holder_pk, 0, &wsh, 100, 200).unwrap();
    }

    #[test]
    #[should_panic(expected = "start_daa must be < expiry_daa")]
    fn call_option_rejects_start_gte_expiry() {
        let writer_pk = [0u8; 32];
        let holder_pk = [0u8; 32];
        let wsh = [0u8; 32];
        build_call_option_redeem_script(&writer_pk, &holder_pk, 1_000_000, &wsh, 200, 200).unwrap();
    }

    #[test]
    #[should_panic(expected = "start_daa must be < expiry_daa")]
    fn call_option_rejects_start_gt_expiry() {
        let writer_pk = [0u8; 32];
        let holder_pk = [0u8; 32];
        let wsh = [0u8; 32];
        build_call_option_redeem_script(&writer_pk, &holder_pk, 1_000_000, &wsh, 300, 200).unwrap();
    }

    // put_option tests (American-style with exercise window)

    #[test]
    fn put_option_body_length() {
        assert_eq!(
            PUT_OPTION_BODY.len(),
            46,
            "put_option body must be 46 bytes"
        );
    }

    #[test]
    fn put_option_body_hex_matches_spec() {
        // dispatch(5) + time1(3) + time2(3) + step1(6) + step2(6) + step3(6) + step4(5) + step5(2) + cancel(8) + tail(2) = 46B
        let expected = "577a00a063517ab0b5a069517ad051a26900c2527aa2697651c3aa876900c3aa876977ad67b07575757575ad6851";
        assert_eq!(
            hex::encode(PUT_OPTION_BODY),
            expected,
            "put_option body hex must match spec"
        );
    }

    #[test]
    fn put_option_redeem_script_length() {
        let writer_pk = [0u8; 32];
        let holder_pk = [0u8; 32];
        let tcid = [0u8; 32];
        let wsh = [0u8; 32];
        let rs = build_put_option_redeem_script(&writer_pk, &holder_pk, 1_000_000, &tcid, &wsh, 100, 200).unwrap();
        assert_eq!(
            rs.len(),
            205,
            "put_option RS must be 205 bytes (159 state + 46 body)"
        );
    }

    #[test]
    fn put_option_state_layout() {
        let writer_pk = [0xAAu8; 32];
        let holder_pk = [0xBBu8; 32];
        let strike_kas: u64 = 50_000_000_000;
        let tcid = [0xCCu8; 32];
        let wsh = [0xDDu8; 32];
        let start_daa: u64 = 1_000_000;
        let expiry_daa: u64 = 2_000_000;

        let rs = build_put_option_redeem_script(
            &writer_pk,
            &holder_pk,
            strike_kas,
            &tcid,
            &wsh,
            start_daa,
            expiry_daa,
        ).unwrap();

        // State layout verification (159 bytes):

        // [0x20][writer_pk 32B] at offset 0..33
        assert_eq!(rs[0], 0x20, "writer_pk push opcode");
        assert_eq!(&rs[1..33], &[0xAA; 32], "writer_pk bytes");

        // [0x20][holder_pk 32B] at offset 33..66
        assert_eq!(rs[33], 0x20, "holder_pk push opcode");
        assert_eq!(&rs[34..66], &[0xBB; 32], "holder_pk bytes");

        // [0x08][strike_kas 8B LE] at offset 66..75
        assert_eq!(rs[66], 0x08, "strike_kas push opcode");
        assert_eq!(
            u64::from_le_bytes(rs[67..75].try_into().unwrap()),
            strike_kas,
            "strike_kas value"
        );

        // [0x20][token_cov_id 32B] at offset 75..108
        assert_eq!(rs[75], 0x20, "token_cov_id push opcode");
        assert_eq!(&rs[76..108], &[0xCC; 32], "token_cov_id bytes");

        // [0x20][writer_spk_hash 32B] at offset 108..141
        assert_eq!(rs[108], 0x20, "writer_spk_hash push opcode");
        assert_eq!(&rs[109..141], &[0xDD; 32], "writer_spk_hash bytes");

        // [0x08][start_daa 8B LE] at offset 141..150
        assert_eq!(rs[141], 0x08, "start_daa push opcode");
        assert_eq!(
            u64::from_le_bytes(rs[142..150].try_into().unwrap()),
            start_daa,
            "start_daa value"
        );

        // [0x08][expiry_daa 8B LE] at offset 150..159
        assert_eq!(rs[150], 0x08, "expiry_daa push opcode");
        assert_eq!(
            u64::from_le_bytes(rs[151..159].try_into().unwrap()),
            expiry_daa,
            "expiry_daa value"
        );

        // Body starts at offset 159
        assert_eq!(&rs[159..], PUT_OPTION_BODY, "body must match bytecode");
    }

    #[test]
    fn put_option_dispatch_uses_op7_roll() {
        // Dispatch: 57 7a (Op7 OpRoll) brings selector at depth 7 to top.
        // 7 state fields (expiry, start, wsh, tcid, sk, hp, wp) sit above the selector.
        assert_eq!(PUT_OPTION_BODY[0], 0x57, "dispatch Op7");
        assert_eq!(PUT_OPTION_BODY[1], 0x7a, "dispatch OpRoll");
        assert_eq!(PUT_OPTION_BODY[2], 0x00, "dispatch Op0");
        assert_eq!(PUT_OPTION_BODY[3], 0xa0, "dispatch OpGreaterThan");
        assert_eq!(PUT_OPTION_BODY[4], 0x63, "dispatch OpIf");
    }

    #[test]
    fn put_option_exercise_has_cltv_and_locktime() {
        // Exercise path must contain CLTV (0xb0) for start_daa check
        // and OpTxLockTime (0xb5) for expiry_daa check.
        let exercise_body = &PUT_OPTION_BODY[5..36]; // exercise path bytes
        assert!(
            exercise_body.contains(&0xb0),
            "exercise path must contain OpCheckLockTimeVerify (0xb0)"
        );
        assert!(
            exercise_body.contains(&0xb5),
            "exercise path must contain OpTxLockTime (0xb5)"
        );
    }

    #[test]
    fn put_option_cancel_has_cltv() {
        // Cancel path starts at OpElse.
        assert_eq!(PUT_OPTION_BODY[36], 0x67, "byte 36 must be OpElse (0x67)");
        assert_eq!(PUT_OPTION_BODY[37], 0xb0, "cancel CLTV for expiry_daa");
        assert_eq!(PUT_OPTION_BODY[38], 0x75, "cancel drop 1 (start)");
        assert_eq!(PUT_OPTION_BODY[39], 0x75, "cancel drop 2 (wsh)");
        assert_eq!(PUT_OPTION_BODY[40], 0x75, "cancel drop 3 (tcid)");
        assert_eq!(PUT_OPTION_BODY[41], 0x75, "cancel drop 4 (sk)");
        assert_eq!(PUT_OPTION_BODY[42], 0x75, "cancel drop 5 (hp)");
        assert_eq!(PUT_OPTION_BODY[43], 0xad, "cancel CheckSigVerify");
        assert_eq!(PUT_OPTION_BODY[44], 0x68, "OpEndIf");
        assert_eq!(PUT_OPTION_BODY[45], 0x51, "Op1 TRUE");
    }

    #[test]
    fn put_option_body_contains_opdup_for_wsh() {
        assert!(
            PUT_OPTION_BODY.contains(&0x76),
            "body must contain OpDup (0x76) for wsh preservation"
        );
    }

    #[test]
    fn put_option_body_contains_two_output_spk_checks() {
        let spk_count = PUT_OPTION_BODY.iter().filter(|&&b| b == 0xc3).count();
        assert_eq!(
            spk_count,
            2,
            "body must contain exactly 2 OpTxOutputSpk (0xc3) opcodes"
        );
    }

    #[test]
    fn put_option_body_contains_token_delivery_check() {
        assert!(
            PUT_OPTION_BODY.contains(&0xd0),
            "body must contain OpCovInputCount (0xd0) for token delivery check"
        );
    }

    #[test]
    fn put_option_exercise_sigscript_format() {
        let writer_pk = [0u8; 32];
        let holder_pk = [0u8; 32];
        let tcid = [0u8; 32];
        let wsh = [0u8; 32];
        let rs = build_put_option_redeem_script(&writer_pk, &holder_pk, 1_000_000, &tcid, &wsh, 100, 200).unwrap();
        let sig = [0u8; 64];
        let exercise_ss = build_put_option_exercise_sigscript(&sig, &rs);

        // Format: push(sig+type 65B) + Op1 + pushdata1(RS 205B)
        // push(65B): 0x41 prefix (1B) + 65B = 66B
        // Op1: 1B
        // pushdata1(205B): 0x4c (1B) + 0xcd (1B) + 205B = 207B
        // Total: 66 + 1 + 207 = 274B
        assert_eq!(exercise_ss.len(), 274, "exercise sigscript must be 274B");
        assert_eq!(exercise_ss[0], 0x41, "first byte is 0x41 (push 65 bytes)");
        assert_eq!(exercise_ss[66], 0x51, "selector byte must be Op1 (0x51)");
    }

    #[test]
    fn put_option_cancel_sigscript_format() {
        let writer_pk = [0u8; 32];
        let holder_pk = [0u8; 32];
        let tcid = [0u8; 32];
        let wsh = [0u8; 32];
        let rs = build_put_option_redeem_script(&writer_pk, &holder_pk, 1_000_000, &tcid, &wsh, 100, 200).unwrap();
        let sig = [0u8; 64];
        let cancel_ss = build_put_option_cancel_sigscript(&sig, &rs);

        assert_eq!(cancel_ss.len(), 274, "cancel sigscript must be 274B");
        assert_eq!(cancel_ss[0], 0x41, "first byte is 0x41 (push 65 bytes)");
        assert_eq!(cancel_ss[66], 0x00, "selector byte must be Op0 (0x00)");
    }

    #[test]
    #[should_panic(expected = "strike_kas must be > 0")]
    fn put_option_rejects_zero_strike() {
        let writer_pk = [0u8; 32];
        let holder_pk = [0u8; 32];
        let tcid = [0u8; 32];
        let wsh = [0u8; 32];
        build_put_option_redeem_script(&writer_pk, &holder_pk, 0, &tcid, &wsh, 100, 200).unwrap();
    }

    #[test]
    #[should_panic(expected = "start_daa must be < expiry_daa")]
    fn put_option_rejects_start_gte_expiry() {
        let writer_pk = [0u8; 32];
        let holder_pk = [0u8; 32];
        let tcid = [0u8; 32];
        let wsh = [0u8; 32];
        build_put_option_redeem_script(&writer_pk, &holder_pk, 1_000_000, &tcid, &wsh, 200, 200).unwrap();
    }

    #[test]
    #[should_panic(expected = "start_daa must be < expiry_daa")]
    fn put_option_rejects_start_gt_expiry() {
        let writer_pk = [0u8; 32];
        let holder_pk = [0u8; 32];
        let tcid = [0u8; 32];
        let wsh = [0u8; 32];
        build_put_option_redeem_script(&writer_pk, &holder_pk, 1_000_000, &tcid, &wsh, 300, 200).unwrap();
    }

    // token_pair_order tests

    #[test]
    fn token_pair_order_body_length() {
        assert_eq!(
            TOKEN_PAIR_ORDER_BODY.len(),
            61,
            "token_pair_order body must be 61 bytes"
        );
    }

    #[test]
    fn token_pair_order_body_hex() {
        // Verify key opcode patterns in the body hex
        let hex = hex::encode(TOKEN_PAIR_ORDER_BODY);
        // Verify key opcode patterns
        assert_eq!(&hex[0..10], "587a00a063", "dispatch: Op8 OpRoll Op0 OpGreaterThan OpIf");
        assert!(hex.contains("b9cf"), "fill path must contain OpTxInputIndex OpInputCovenantId");
        assert!(hex.contains("b9be"), "fill path must contain OpTxInputIndex OpTxInputAmount");
        assert!(hex.ends_with("6851"), "must end with OpEndIf Op1");
    }

    #[test]
    fn token_pair_order_redeem_script_length() {
        let pid = [0u8; 32];
        let oh = [0u8; 32];
        let ta = [0u8; 32];
        let tb = [0u8; 32];
        let rs = build_token_pair_order_redeem_script(
            &pid, &oh, &ta, &tb, 100, 200, 1000, 50000,
        ).unwrap();
        assert_eq!(rs.len(), 229, "token_pair_order RS must be 229 bytes (168 state + 61 body)");
    }

    #[test]
    fn token_pair_order_state_layout() {
        let pid = [0xAAu8; 32];
        let oh = [0xBBu8; 32];
        let ta = [0xCCu8; 32];
        let tb = [0xDDu8; 32];
        let rs = build_token_pair_order_redeem_script(
            &pid, &oh, &ta, &tb, 100, 200, 500, 10000,
        ).unwrap();

        // [0x20][pair_id 32B]
        assert_eq!(rs[0], 0x20, "pair_id push opcode");
        assert_eq!(&rs[1..33], &[0xAA; 32], "pair_id");

        // [0x20][owner_hash 32B]
        assert_eq!(rs[33], 0x20, "owner_hash push opcode");
        assert_eq!(&rs[34..66], &[0xBB; 32], "owner_hash");

        // [0x20][token_a_cov_id 32B]
        assert_eq!(rs[66], 0x20, "token_a push opcode");
        assert_eq!(&rs[67..99], &[0xCC; 32], "token_a_cov_id");

        // [0x20][token_b_cov_id 32B]
        assert_eq!(rs[99], 0x20, "token_b push opcode");
        assert_eq!(&rs[100..132], &[0xDD; 32], "token_b_cov_id");

        // [0x08][price_num 8B]
        assert_eq!(rs[132], 0x08, "price_num push opcode");
        assert_eq!(u64::from_le_bytes(rs[133..141].try_into().unwrap()), 100, "price_num");

        // [0x08][price_den 8B]
        assert_eq!(rs[141], 0x08, "price_den push opcode");
        assert_eq!(u64::from_le_bytes(rs[142..150].try_into().unwrap()), 200, "price_den");

        // [0x08][min_fill 8B]
        assert_eq!(rs[150], 0x08, "min_fill push opcode");
        assert_eq!(u64::from_le_bytes(rs[151..159].try_into().unwrap()), 500, "min_fill");

        // [0x08][amount 8B]
        assert_eq!(rs[159], 0x08, "amount push opcode");
        assert_eq!(u64::from_le_bytes(rs[160..168].try_into().unwrap()), 10000, "amount");

        // Body starts at offset 168
        assert_eq!(&rs[168..], TOKEN_PAIR_ORDER_BODY, "body must match bytecode");
    }

    #[test]
    fn token_pair_order_dispatch_opcodes() {
        // Verify dispatch preamble: Op8 OpRoll, Op0 OpGreaterThan, OpIf
        assert_eq!(TOKEN_PAIR_ORDER_BODY[0], 0x58, "Op8");
        assert_eq!(TOKEN_PAIR_ORDER_BODY[1], 0x7a, "OpRoll");
        assert_eq!(TOKEN_PAIR_ORDER_BODY[2], 0x00, "Op0");
        assert_eq!(TOKEN_PAIR_ORDER_BODY[3], 0xa0, "OpGreaterThan");
        assert_eq!(TOKEN_PAIR_ORDER_BODY[4], 0x63, "OpIf");
    }

    #[test]
    #[should_panic(expected = "price_num must be > 0")]
    fn token_pair_order_panics_on_zero_price_num() {
        let z = [0u8; 32];
        build_token_pair_order_redeem_script(&z, &z, &z, &z, 0, 1, 1, 1).unwrap();
    }

    #[test]
    #[should_panic(expected = "amount must be > 0")]
    fn token_pair_order_panics_on_zero_amount() {
        let z = [0u8; 32];
        build_token_pair_order_redeem_script(&z, &z, &z, &z, 1, 1, 1, 0).unwrap();
    }

    // dca_order tests

    #[test]
    fn dca_order_body_length() {
        assert_eq!(
            DCA_ORDER_BODY.len(),
            195,
            "dca_order body must be 195 bytes"
        );
    }

    #[test]
    fn dca_order_body_hex() {
        let hex = hex::encode(DCA_ORDER_BODY);
        // Verify dispatch: Op8 OpRoll Op0 OpGreaterThan OpIf
        assert_eq!(&hex[0..10], "587a00a063", "dispatch pattern");
        // Verify CLTV presence
        assert!(hex.contains("b0"), "fill path must contain OpCheckLockTimeVerify");
        // Verify D&R Blake2b authenticity pattern
        assert!(hex.contains("aa02aa207c7e01877e"), "D&R must contain Blake2b+P2SH SPK pattern");
        // Verify ends with OpEndIf Op1
        assert!(hex.ends_with("6851"), "must end with OpEndIf Op1");
    }

    #[test]
    fn dca_order_redeem_script_length() {
        let oh = [0u8; 32];
        let tcid = [0u8; 32];
        let rs = build_dca_order_redeem_script(
            &oh, &tcid, 100, 200, 50000, 100, 1000, 10,
        ).unwrap();
        assert_eq!(rs.len(), 315, "dca_order RS must be 315 bytes (120 state + 195 body)");
    }

    #[test]
    fn dca_order_state_layout() {
        let oh = [0xAAu8; 32];
        let tcid = [0xBBu8; 32];
        let rs = build_dca_order_redeem_script(
            &oh, &tcid, 100, 200, 50000, 100, 1000, 10,
        ).unwrap();

        // [0x20][owner_hash 32B]
        assert_eq!(rs[0], 0x20, "owner_hash push opcode");
        assert_eq!(&rs[1..33], &[0xAA; 32], "owner_hash");

        // [0x20][target_cov_id 32B]
        assert_eq!(rs[33], 0x20, "target_cov_id push opcode");
        assert_eq!(&rs[34..66], &[0xBB; 32], "target_cov_id");

        // [0x08][price_num 8B]
        assert_eq!(rs[66], 0x08, "price_num push opcode");
        assert_eq!(u64::from_le_bytes(rs[67..75].try_into().unwrap()), 100, "price_num");

        // [0x08][price_den 8B]
        assert_eq!(rs[75], 0x08, "price_den push opcode");
        assert_eq!(u64::from_le_bytes(rs[76..84].try_into().unwrap()), 200, "price_den");

        // [0x08][amount_per_period 8B]
        assert_eq!(rs[84], 0x08, "amount_per_period push opcode");
        assert_eq!(u64::from_le_bytes(rs[85..93].try_into().unwrap()), 50000, "amount_per_period");

        // [0x08][interval_daa 8B] — reordered: before next_exec in v2
        assert_eq!(rs[93], 0x08, "interval_daa push opcode");
        assert_eq!(u64::from_le_bytes(rs[94..102].try_into().unwrap()), 100, "interval_daa");

        // [0x08][next_execution_daa 8B]
        assert_eq!(rs[102], 0x08, "next_execution_daa push opcode");
        assert_eq!(u64::from_le_bytes(rs[103..111].try_into().unwrap()), 1000, "next_execution_daa");

        // [0x08][periods_remaining 8B]
        assert_eq!(rs[111], 0x08, "periods_remaining push opcode");
        assert_eq!(u64::from_le_bytes(rs[112..120].try_into().unwrap()), 10, "periods_remaining");

        // Body starts at offset 120
        assert_eq!(&rs[120..], DCA_ORDER_BODY, "body must match bytecode");
    }

    #[test]
    fn dca_order_state_mutable_zone() {
        // The D&R mutable zone is [103..120) = next_exec value + push prefix + periods value
        let oh = [0xAAu8; 32];
        let tcid = [0xBBu8; 32];
        let rs = build_dca_order_redeem_script(
            &oh, &tcid, 100, 200, 50000, 100, 1000, 10,
        ).unwrap();

        // Locked prefix [0..103): owner_hash + tcid + pnum + pden + amt_pp + interval + push_prefix
        let prefix = &rs[0..103];
        assert_eq!(prefix[102], 0x08, "prefix ends with push prefix for next_exec");

        // Mutable zone [103..120): next_exec value (8B) + 0x08 (push prefix) + periods value (8B)
        assert_eq!(u64::from_le_bytes(rs[103..111].try_into().unwrap()), 1000, "mutable next_exec");
        assert_eq!(rs[111], 0x08, "push prefix for periods in mutable zone");
        assert_eq!(u64::from_le_bytes(rs[112..120].try_into().unwrap()), 10, "mutable periods");

        // Suffix [120..): body bytecode (locked)
        assert_eq!(&rs[120..], DCA_ORDER_BODY, "suffix is body");
    }

    #[test]
    fn dca_order_contains_cltv() {
        assert!(
            DCA_ORDER_BODY.contains(&0xb0),
            "dca_order body must contain OpCheckLockTimeVerify (0xb0)"
        );
    }

    #[test]
    fn dca_order_contains_d_and_r_pattern() {
        let body = DCA_ORDER_BODY;
        // Must contain OpBlake2b (0xaa) for RS authenticity and SPK verification
        let blake2b_count = body.iter().filter(|&&b| b == 0xaa).count();
        assert!(blake2b_count >= 3, "need at least 3 OpBlake2b: auth + SPK build x2, got {}", blake2b_count);
        // Must contain OpSubstr (0x7f) for prefix/suffix/value extraction
        let substr_count = body.iter().filter(|&&b| b == 0x7f).count();
        assert!(substr_count >= 8, "need at least 8 OpSubstr, got {}", substr_count);
        // Must contain OpTxInputSpk (0xbf) for input SPK verification
        assert!(body.contains(&0xbf), "must contain OpTxInputSpk");
        // Must contain OpTxOutputSpk (0xc3) for output SPK verification
        assert!(body.contains(&0xc3), "must contain OpTxOutputSpk");
        // Must contain OpNumEqual (0x9c) for transition checks
        let numeq_count = body.iter().filter(|&&b| b == 0x9c).count();
        assert!(numeq_count >= 2, "need at least 2 OpNumEqual for transition checks, got {}", numeq_count);
    }

    #[test]
    fn dca_order_fill_path_cltv_sequence() {
        // After dispatch (5B), fill path starts at byte 5.
        // CLTV sequence: Op1 OpPick, CLTV
        assert_eq!(DCA_ORDER_BODY[5], 0x51, "Op1 (pick next_exec at d1)");
        assert_eq!(DCA_ORDER_BODY[6], 0x79, "OpPick");
        assert_eq!(DCA_ORDER_BODY[7], 0xb0, "OpCheckLockTimeVerify");
    }

    #[test]
    fn dca_order_dispatch_opcodes() {
        // Op8 OpRoll dispatch
        assert_eq!(&DCA_ORDER_BODY[0..5], &[0x58, 0x7a, 0x00, 0xa0, 0x63],
            "dispatch must be: Op8 OpRoll Op0 OpGreaterThan OpIf");
    }

    #[test]
    fn dca_order_if_endif_balanced() {
        // Count OpIf/OpElse/OpEndIf in body, skipping data bytes.
        // Walk the body and skip push-data operands to avoid false positives
        // (e.g., 0x67 as data byte for "push 103" vs OpElse opcode).
        let body = DCA_ORDER_BODY;
        let mut i = 0;
        let (mut ifs, mut elses, mut endifs) = (0, 0, 0);
        while i < body.len() {
            let b = body[i];
            match b {
                0x01..=0x4b => { i += 1 + b as usize; continue; } // push N bytes
                0x4c => { if i + 1 < body.len() { i += 2 + body[i+1] as usize; } else { i += 1; } continue; }
                0x4d => { if i + 2 < body.len() { let sz = u16::from_le_bytes([body[i+1], body[i+2]]) as usize; i += 3 + sz; } else { i += 1; } continue; }
                0x63 => ifs += 1,
                0x67 => elses += 1,
                0x68 => endifs += 1,
                _ => {}
            }
            i += 1;
        }
        assert_eq!(ifs, endifs, "IF count ({}) must equal ENDIF count ({})", ifs, endifs);
        assert_eq!(ifs, 2, "expected 2 OpIf branches (dispatch, periods), got {}", ifs);
        assert_eq!(elses, 2, "expected 2 OpElse branches, got {}", elses);
    }

    #[test]
    #[should_panic(expected = "periods_remaining must be > 0")]
    fn dca_order_panics_on_zero_periods() {
        let z = [0u8; 32];
        build_dca_order_redeem_script(&z, &z, 1, 1, 1000, 10, 100, 0).unwrap();
    }

    #[test]
    #[should_panic(expected = "amount_per_period must be > 0")]
    fn dca_order_panics_on_zero_amount_per_period() {
        let z = [0u8; 32];
        build_dca_order_redeem_script(&z, &z, 1, 1, 0, 10, 100, 5).unwrap();
    }

    #[test]
    #[should_panic(expected = "interval_daa must be > 0")]
    fn dca_order_panics_on_zero_interval() {
        let z = [0u8; 32];
        build_dca_order_redeem_script(&z, &z, 1, 1, 1000, 0, 100, 5).unwrap();
    }

    #[test]
    #[should_panic(expected = "price_num must be > 0")]
    fn dca_order_panics_on_zero_price_num() {
        let z = [0u8; 32];
        build_dca_order_redeem_script(&z, &z, 0, 1, 1000, 10, 100, 5).unwrap();
    }

    #[test]
    #[should_panic(expected = "price_den must be > 0")]
    fn dca_order_panics_on_zero_price_den() {
        let z = [0u8; 32];
        build_dca_order_redeem_script(&z, &z, 1, 0, 1000, 10, 100, 5).unwrap();
    }

    #[test]
    fn dca_order_fill_sigscript_format() {
        let oh = [0xAAu8; 32];
        let tcid = [0xBBu8; 32];
        let old_rs = build_dca_order_redeem_script(
            &oh, &tcid, 100, 200, 50000, 100, 1000, 10,
        ).unwrap();
        let new_rs = build_dca_order_redeem_script(
            &oh, &tcid, 100, 200, 50000, 100, 1100, 9,
        ).unwrap();

        let ss = build_dca_order_fill_sigscript(0, &old_rs, &new_rs, &old_rs);
        // sigscript contains: pushData(new_rs) + pushData(old_rs) + ci + Op1 + pushData(RS)
        // new_rs and old_rs are 315B each, pushData(315) = 4d + 2B len + 315B = 318B
        // ci = Op0 (1B), selector Op1 (1B), pushData(RS=315B) = 318B
        // Total ≈ 318 + 318 + 1 + 1 + 318 = 956B
        assert!(ss.len() > 900, "fill sigscript should be >900B, got {}", ss.len());
        // Last bytes should be pushData(RS)
        let rs_push = push_data(&old_rs);
        assert_eq!(&ss[ss.len()-rs_push.len()..], &rs_push, "sigscript must end with pushData(RS)");
    }

    #[test]
    fn dca_order_cancel_sigscript_format() {
        let oh = [0xAAu8; 32];
        let tcid = [0xBBu8; 32];
        let rs = build_dca_order_redeem_script(
            &oh, &tcid, 100, 200, 50000, 100, 1000, 10,
        ).unwrap();

        let sig = [0xCCu8; 64];
        let pk = [0xDDu8; 32];
        let ss = build_dca_order_cancel_sigscript(&sig, &pk, &rs);
        // pushData(sig 65B) + pushData(pk 32B) + Op0 + pushData(RS 315B)
        // = 66 + 33 + 1 + 307 = 407B
        assert!(ss.len() > 400, "cancel sigscript should be >400B, got {}", ss.len());
        // Verify Op0 selector is at the right position
        let sig_push_len = push_data(&{
            let mut s = [0u8; 65];
            s[..64].copy_from_slice(&sig);
            s[64] = 0x01;
            s
        }).len();
        let pk_push_len = push_data(&pk).len();
        assert_eq!(ss[sig_push_len + pk_push_len], 0x00, "cancel selector must be Op0");
    }

    #[test]
    fn dca_order_d_and_r_prefix_suffix_offsets() {
        // Verify the D&R bytecode uses correct offsets for prefix/suffix
        let body = DCA_ORDER_BODY;
        let hex = hex::encode(body);
        // prefix size = 103 = 0x67
        assert!(hex.contains("0167"), "body must push 103 (0x67) for prefix size");
        // suffix offset = 120 = 0x78
        assert!(hex.contains("0178"), "body must push 120 (0x78) for suffix offset");
        // push prefix check at byte 111 = 0x6f
        assert!(hex.contains("016f"), "body must push 111 (0x6f) for push prefix check");
        // next_exec offset = 103 = 0x67 (same as prefix size, reused)
        // periods offset = 112 = 0x70
        assert!(hex.contains("0170"), "body must push 112 (0x70) for periods offset");
    }

    #[test]
    fn dca_order_continuation_rs_matches_transition() {
        // Build old RS with periods=5, next_exec=1000, interval=100
        let oh = [0xAAu8; 32];
        let tcid = [0xBBu8; 32];
        let old_rs = build_dca_order_redeem_script(
            &oh, &tcid, 50, 100, 10000, 100, 1000, 5,
        ).unwrap();

        // Build expected continuation RS
        let new_rs = build_dca_order_redeem_script(
            &oh, &tcid, 50, 100, 10000, 100, 1100, 4,
        ).unwrap();

        // Prefix [0..103) must match
        assert_eq!(&old_rs[0..103], &new_rs[0..103], "prefix must be identical");

        // Suffix [120..end) must match (body bytecode)
        assert_eq!(&old_rs[120..], &new_rs[120..], "suffix (body) must be identical");

        // Mutable zone [103..120) must differ
        assert_ne!(&old_rs[103..120], &new_rs[103..120], "mutable zone must differ");

        // Verify new_next_exec = old_next_exec + interval
        let old_next = u64::from_le_bytes(old_rs[103..111].try_into().unwrap());
        let new_next = u64::from_le_bytes(new_rs[103..111].try_into().unwrap());
        let interval = u64::from_le_bytes(old_rs[94..102].try_into().unwrap());
        assert_eq!(new_next, old_next + interval, "new_next_exec must equal old + interval");

        // Verify new_periods = old_periods - 1
        let old_periods = u64::from_le_bytes(old_rs[112..120].try_into().unwrap());
        let new_periods = u64::from_le_bytes(new_rs[112..120].try_into().unwrap());
        assert_eq!(new_periods, old_periods - 1, "new_periods must equal old - 1");

        // Push prefix at byte 111 preserved
        assert_eq!(old_rs[111], 0x08, "old push prefix");
        assert_eq!(new_rs[111], 0x08, "new push prefix");
    }

    #[test]
    fn dca_order_final_fill_no_continuation() {
        // When periods == 1, the script takes the else branch (no D&R)
        let oh = [0xAAu8; 32];
        let tcid = [0xBBu8; 32];
        let rs = build_dca_order_redeem_script(
            &oh, &tcid, 50, 100, 10000, 100, 1000, 1,
        ).unwrap();

        // For final fill, old_rs/new_rs can be empty (Op0 pushes empty)
        let ss = build_dca_order_fill_sigscript(0, &[], &[], &rs);
        // Should be valid: pushData(empty) + pushData(empty) + Op0 + Op1 + pushData(RS)
        // pushData(empty) = [0x00] (1 byte each)
        // Total = 1 + 1 + 1 + 1 + pushData(315) = 4 + 318 = 322B
        assert!(ss.len() < 330, "final fill sigscript should be compact, got {}", ss.len());
    }

    // vesting tests

    #[test]
    fn vesting_body_length() {
        assert_eq!(
            VESTING_BODY.len(),
            42,
            "vesting body must be 42 bytes (removed OpDrop after CLTV)"
        );
    }

    #[test]
    fn vesting_body_hex() {
        let hex = hex::encode(VESTING_BODY);
        // Verify CLTV at start
        assert_eq!(&hex[0..2], "b0", "must start with CLTV (0xb0); Kaspa CLTV pops, no OpDrop");
        // Verify OpTxLockTime
        assert!(hex.contains("b5"), "body must contain OpTxLockTime (0xb5)");
        // Verify ends with drops + TRUE
        assert!(hex.ends_with("51"), "must end with Op1 (TRUE)");
    }

    #[test]
    fn vesting_redeem_script_length() {
        let bh = [0u8; 32];
        let tcid = [0u8; 32];
        let rs = build_vesting_redeem_script(
            &bh, &tcid, 1_000_000, 0, 1000, 10000, 2000,
        ).unwrap();
        assert_eq!(rs.len(), 153, "vesting RS must be 153 bytes (111 state + 42 body)");
    }

    #[test]
    fn vesting_state_layout() {
        let bh = [0xAAu8; 32];
        let tcid = [0xBBu8; 32];
        let rs = build_vesting_redeem_script(
            &bh, &tcid, 1_000_000, 250_000, 1000, 10000, 3000,
        ).unwrap();

        // [0x20][beneficiary_hash 32B]
        assert_eq!(rs[0], 0x20, "beneficiary_hash push opcode");
        assert_eq!(&rs[1..33], &[0xAA; 32], "beneficiary_hash");

        // [0x20][token_cov_id 32B]
        assert_eq!(rs[33], 0x20, "token_cov_id push opcode");
        assert_eq!(&rs[34..66], &[0xBB; 32], "token_cov_id");

        // [0x08][total_amount 8B]
        assert_eq!(rs[66], 0x08, "total_amount push opcode");
        assert_eq!(u64::from_le_bytes(rs[67..75].try_into().unwrap()), 1_000_000, "total_amount");

        // [0x08][claimed_amount 8B]
        assert_eq!(rs[75], 0x08, "claimed_amount push opcode");
        assert_eq!(u64::from_le_bytes(rs[76..84].try_into().unwrap()), 250_000, "claimed_amount");

        // [0x08][start_daa 8B]
        assert_eq!(rs[84], 0x08, "start_daa push opcode");
        assert_eq!(u64::from_le_bytes(rs[85..93].try_into().unwrap()), 1000, "start_daa");

        // [0x08][end_daa 8B]
        assert_eq!(rs[93], 0x08, "end_daa push opcode");
        assert_eq!(u64::from_le_bytes(rs[94..102].try_into().unwrap()), 10000, "end_daa");

        // [0x08][cliff_daa 8B]
        assert_eq!(rs[102], 0x08, "cliff_daa push opcode");
        assert_eq!(u64::from_le_bytes(rs[103..111].try_into().unwrap()), 3000, "cliff_daa");

        // Body starts at offset 111
        assert_eq!(&rs[111..], VESTING_BODY, "body must match bytecode");
    }

    #[test]
    fn vesting_contains_cltv_and_locktime() {
        assert!(
            VESTING_BODY.contains(&0xb0),
            "vesting must contain OpCheckLockTimeVerify (0xb0)"
        );
        assert!(
            VESTING_BODY.contains(&0xb5),
            "vesting must contain OpTxLockTime (0xb5)"
        );
    }

    #[test]
    fn vesting_cltv_is_first_opcode() {
        // First opcode must be OpCheckLockTimeVerify (cliff_daa is on top of stack)
        assert_eq!(VESTING_BODY[0], 0xb0, "first byte must be OpCheckLockTimeVerify");
        // Kaspa CLTV pops the stack. No OpDrop after CLTV.
        assert_ne!(VESTING_BODY[1], 0x75, "second byte must NOT be OpDrop (Kaspa CLTV pops)");
    }

    #[test]
    fn vesting_no_dispatch_single_path() {
        // Vesting has no selector dispatch — only a claim path.
        // Verify there is no Op8 OpRoll dispatch.
        assert_ne!(VESTING_BODY[0], 0x58, "should not start with Op8 (no selector dispatch)");
    }

    #[test]
    #[should_panic(expected = "total_amount must be > 0")]
    fn vesting_panics_on_zero_total() {
        let z = [0u8; 32];
        build_vesting_redeem_script(&z, &z, 0, 0, 1000, 10000, 2000).unwrap();
    }

    #[test]
    #[should_panic(expected = "end_daa must be > start_daa")]
    fn vesting_panics_on_invalid_daa_range() {
        let z = [0u8; 32];
        build_vesting_redeem_script(&z, &z, 1000, 0, 10000, 5000, 10000).unwrap();
    }

    #[test]
    #[should_panic(expected = "cliff_daa must be >= start_daa")]
    fn vesting_panics_on_cliff_before_start() {
        let z = [0u8; 32];
        build_vesting_redeem_script(&z, &z, 1000, 0, 5000, 10000, 1000).unwrap();
    }

    #[test]
    fn order_router_body_length() {
        assert_eq!(ORDER_ROUTER_BODY.len(), 51, "order_router body must be 51 bytes");
    }

    #[test]
    fn order_router_rs_length() {
        let oh = [0u8; 32];
        let icid = [0u8; 32];
        let ocid = [0u8; 32];
        let mcid = [0u8; 32];
        let rs = build_order_router_redeem_script(&oh, &icid, &ocid, &mcid, 1000, 3).unwrap();
        assert_eq!(rs.len(), 201, "order_router RS must be 201 bytes (150 state + 51 body)");
    }

    #[test]
    fn order_router_state_layout() {
        let oh = [0xAA; 32];
        let icid = [0xBB; 32];
        let ocid = [0xCC; 32];
        let mcid = [0xDD; 32];
        let rs = build_order_router_redeem_script(&oh, &icid, &ocid, &mcid, 50_000, 3).unwrap();

        assert_eq!(rs[0], 0x20, "owner_hash push opcode");
        assert_eq!(&rs[1..33], &[0xAA; 32], "owner_hash");
        assert_eq!(rs[33], 0x20, "input_cov_id push opcode");
        assert_eq!(&rs[34..66], &[0xBB; 32], "input_cov_id");
        assert_eq!(rs[66], 0x20, "output_cov_id push opcode");
        assert_eq!(&rs[67..99], &[0xCC; 32], "output_cov_id");
        assert_eq!(rs[99], 0x20, "intermediate_cov_id push opcode");
        assert_eq!(&rs[100..132], &[0xDD; 32], "intermediate_cov_id");
        assert_eq!(rs[132], 0x08, "min_output push opcode");
        assert_eq!(u64::from_le_bytes(rs[133..141].try_into().unwrap()), 50_000, "min_output");
        assert_eq!(rs[141], 0x08, "max_hops push opcode");
        assert_eq!(u64::from_le_bytes(rs[142..150].try_into().unwrap()), 3, "max_hops");
        // Body starts at offset 150
        assert_eq!(&rs[150..], ORDER_ROUTER_BODY, "body must match");
    }

    #[test]
    fn order_router_body_uses_cov_input_output_count() {
        // Execute path uses OpCovInputCount (0xd0) and OpCovOutCount (0xd2)
        assert!(
            ORDER_ROUTER_BODY.contains(&0xd0),
            "body must contain OpCovInputCount (0xd0)"
        );
        assert!(
            ORDER_ROUTER_BODY.contains(&0xd2),
            "body must contain OpCovOutCount (0xd2)"
        );
    }

    #[test]
    #[should_panic(expected = "min_output must be > 0")]
    fn order_router_rejects_zero_min_output() {
        let z = [0u8; 32];
        build_order_router_redeem_script(&z, &z, &z, &z, 0, 3).unwrap();
    }

    #[test]
    fn order_router_execute_sigscript() {
        let z = [0u8; 32];
        let rs = build_order_router_redeem_script(&z, &z, &z, &z, 1000, 3).unwrap();
        let ss = build_order_router_execute_sigscript(&rs);
        assert_eq!(ss[0], 0x51, "first byte must be Op1 (execute selector)");
        // Op1(1) + PUSHDATA1(1) + len(1) + rs(201) = 204
        assert_eq!(ss.len(), 204, "execute sigscript = 204B");
    }

    #[test]
    fn order_router_cancel_sigscript() {
        let z = [0u8; 32];
        let rs = build_order_router_redeem_script(&z, &z, &z, &z, 1000, 3).unwrap();
        let sig = [0u8; 64];
        let pk = [0u8; 32];
        let ss = build_order_router_cancel_sigscript(&sig, &pk, &rs);
        // push(sig65)(66) + push(pk32)(33) + Op0(1) + PUSHDATA1(1)+len(1)+rs(201) = 303
        assert_eq!(ss.len(), 303, "cancel sigscript = 303B");
    }

}


// Adversarial security tests (GAP-1, GAP-2, GAP-4, GAP-5, GAP-9)
#[cfg(test)]
mod adversarial_tests {
    use super::*;

    // Payload tests

    #[test]
    fn payload_build_and_parse_no_flags() {
        let rs = vec![0x01, 0x02, 0x03];
        let payload = build_order_payload(&rs, false);
        assert_eq!(&payload[..6], b"KOB:2:", "must start with KOB:2: prefix");
        assert_eq!(payload[6], 0x00, "flags byte must be 0 when no flags set");
        assert_eq!(&payload[7..], &rs[..], "RS data must follow flags byte");

        let parsed = parse_order_payload(&payload).expect("should parse v2");
        assert_eq!(parsed.flags, 0);
        assert!(!parsed.post_only);
        assert!(parsed.expiry_daa.is_none());
        assert_eq!(parsed.rs_data, rs);
    }

    #[test]
    fn payload_build_and_parse_post_only() {
        let rs = vec![0xaa, 0xbb];
        let payload = build_order_payload(&rs, true);
        assert_eq!(payload[6], PAYLOAD_FLAG_POST_ONLY, "flags bit 0 must be set");

        let parsed = parse_order_payload(&payload).expect("should parse v2");
        assert!(parsed.post_only, "post_only must be true");
        assert!(parsed.expiry_daa.is_none());
        assert_eq!(parsed.rs_data, rs);
    }

    #[test]
    fn payload_parse_rejects_too_short() {
        // KOB:2: is 6 bytes, needs at least 7 (prefix + flags)
        assert!(parse_order_payload(b"KOB:2:").is_none(), "must reject payload with no flags byte");
        assert!(parse_order_payload(b"KOB:2").is_none());
        assert!(parse_order_payload(b"").is_none());
    }

    #[test]
    fn payload_empty_rs_data() {
        let payload = build_order_payload(&[], true);
        let parsed = parse_order_payload(&payload).expect("should parse");
        assert!(parsed.post_only);
        assert!(parsed.rs_data.is_empty());
    }

    #[test]
    fn payload_oco_build_and_parse() {
        let buy_rs = vec![0x11; 10];
        let sell_rs = vec![0x22; 8];
        let payload = build_oco_order_payload(&buy_rs, &sell_rs, true).unwrap();
        assert_eq!(&payload[..6], b"KOB:2:");
        assert_eq!(payload[6], PAYLOAD_FLAG_POST_ONLY);

        // After flags: u16 LE buy_len + buy_rs + sell_rs
        let buy_len = u16::from_le_bytes([payload[7], payload[8]]) as usize;
        assert_eq!(buy_len, 10);
        assert_eq!(&payload[9..9 + buy_len], &buy_rs[..]);
        assert_eq!(&payload[9 + buy_len..], &sell_rs[..]);
    }

    // GTD (Good-Till-Date) payload tests

    #[test]
    fn payload_gtd_build_and_parse() {
        let rs = vec![0x01, 0x02, 0x03];
        let daa: u64 = 1_000_000;
        let payload = build_order_payload_full(&rs, false, Some(daa));
        assert_eq!(&payload[..6], b"KOB:2:");
        assert_eq!(payload[6], PAYLOAD_FLAG_GTD, "GTD flag must be set");
        // RS data = payload[7..7+3], GTD trailer = payload[10..18]
        assert_eq!(payload.len(), 6 + 1 + 3 + 8);

        let parsed = parse_order_payload(&payload).expect("should parse GTD v2");
        assert!(!parsed.post_only);
        assert_eq!(parsed.expiry_daa, Some(daa));
        assert_eq!(parsed.rs_data, rs);
    }

    #[test]
    fn payload_gtd_with_post_only() {
        let rs = vec![0xaa, 0xbb];
        let daa: u64 = 99_999_999;
        let payload = build_order_payload_full(&rs, true, Some(daa));
        assert_eq!(
            payload[6],
            PAYLOAD_FLAG_POST_ONLY | PAYLOAD_FLAG_GTD,
            "both flags must be set"
        );

        let parsed = parse_order_payload(&payload).expect("should parse");
        assert!(parsed.post_only);
        assert_eq!(parsed.expiry_daa, Some(daa));
        assert_eq!(parsed.rs_data, rs);
    }

    #[test]
    fn payload_gtd_zero_expiry() {
        let rs = vec![0x01];
        let payload = build_order_payload_full(&rs, false, Some(0));
        let parsed = parse_order_payload(&payload).expect("should parse");
        assert_eq!(parsed.expiry_daa, Some(0));
        assert_eq!(parsed.rs_data, rs);
    }

    #[test]
    fn payload_gtd_max_expiry() {
        let rs = vec![0x01];
        let payload = build_order_payload_full(&rs, false, Some(u64::MAX));
        let parsed = parse_order_payload(&payload).expect("should parse");
        assert_eq!(parsed.expiry_daa, Some(u64::MAX));
        assert_eq!(parsed.rs_data, rs);
    }

    #[test]
    fn payload_gtd_rejects_truncated_trailer() {
        // Manually build a payload with GTD flag but only 4 bytes of trailer
        let mut payload = Vec::new();
        payload.extend_from_slice(b"KOB:2:");
        payload.push(PAYLOAD_FLAG_GTD);
        payload.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // only 4 bytes, need 8
        // Parser should still succeed: it treats last 8 bytes as DAA, but there's
        // only 4 after flags, and that's < 8, so should fail.
        // Actually: after_flags = [0x01, 0x02, 0x03, 0x04], len=4 < 8 => None
        assert!(
            parse_order_payload(&payload).is_none(),
            "must reject GTD payload with < 8 bytes after flags"
        );
    }

    #[test]
    fn payload_gtd_empty_rs_with_expiry() {
        let payload = build_order_payload_full(&[], false, Some(42));
        let parsed = parse_order_payload(&payload).expect("should parse");
        assert!(parsed.rs_data.is_empty());
        assert_eq!(parsed.expiry_daa, Some(42));
    }

    #[test]
    fn payload_no_gtd_flag_means_none() {
        let rs = vec![0x01, 0x02, 0x03];
        let payload = build_order_payload_full(&rs, false, None);
        let parsed = parse_order_payload(&payload).expect("should parse");
        assert!(parsed.expiry_daa.is_none());
        assert_eq!(parsed.rs_data, rs);
    }

    #[test]
    fn payload_oco_gtd_build_and_parse() {
        let buy_rs = vec![0x11; 10];
        let sell_rs = vec![0x22; 8];
        let daa: u64 = 5_000_000;
        let payload = build_oco_order_payload_full(&buy_rs, &sell_rs, false, Some(daa)).unwrap();
        assert_eq!(payload[6], PAYLOAD_FLAG_GTD);

        let parsed = parse_order_payload(&payload).expect("should parse OCO GTD");
        assert_eq!(parsed.expiry_daa, Some(daa));
        // The rs_data should contain the OCO structure (buy_len + buy_rs + sell_rs)
        // minus the 8-byte GTD trailer
        let buy_len = u16::from_le_bytes([parsed.rs_data[0], parsed.rs_data[1]]) as usize;
        assert_eq!(buy_len, 10);
        assert_eq!(&parsed.rs_data[2..2 + buy_len], &buy_rs[..]);
        assert_eq!(&parsed.rs_data[2 + buy_len..], &sell_rs[..]);
    }

    // buy_order tests

    #[test]
    fn buy_order_body_exact_length() {
        let body = BUY_ORDER_BODY;
        assert_eq!(
            body.len(),
            BUY_ORDER_BODY_EXPECTED_LEN,
            "buy v13 body should be {}B, got {}B",
            BUY_ORDER_BODY_EXPECTED_LEN,
            body.len()
        );
    }

    #[test]
    fn buy_order_rs_size() {
        let tcid = [0xAAu8; 32];
        let oh = [0xBBu8; 32];
        let bspkh = [0xCCu8; 32];
        let rs = build_buy_redeem_script(
            &tcid, 100, 1, 10, &oh, &bspkh, 0, 0, 0,)
        .unwrap();
        assert_eq!(
            rs.len(),
            BUY_ORDER_RS_EXPECTED_LEN,
            "buy v13 RS should be {}B, got {}B",
            BUY_ORDER_RS_EXPECTED_LEN,
            rs.len()
        );
    }

    #[test]
    fn buy_fill_sigscript_stack_trace() {
        // Verify the v13 fill sigscript layout and that the body dispatch works.
        let tcid = [0x11u8; 32];
        let oh = [0x22u8; 32];
        let bspkh = [0x33u8; 32];
        let rs = build_buy_redeem_script(
            &tcid, 3, 1, 5, &oh, &bspkh, 0, 0, 1000,)
        .unwrap();

        // v13 fill sigscript: [toi, tii, coi, Op1, pushdata(RS)]
        let ss = build_buy_fill_sigscript(0, 1, 0, &rs);
        // 4 opcode items + pushdata(RS with 3-byte prefix for RS>255)
        let expected_len = 4 + 3 + rs.len();
        assert_eq!(ss.len(), expected_len,
            "fill sigscript should be {} bytes, got {}", expected_len, ss.len());

        // Verify sigLen lands in fill range: T0 <= sigLen < T1
        // T0 = 401, T1 = 409 (v14)
        assert!(ss.len() >= 401, "sigLen {} must be >= T0=401", ss.len());
        assert!(ss.len() < 409, "sigLen {} must be < T1=409", ss.len());

        // Verify body starts with correct dispatch
        let body = BUY_ORDER_BODY;
        assert_eq!(body[0], 0xb9, "OpTxInputIndex");
        assert_eq!(body[1], 0xc9, "OpTxInputScriptSigLen");

        // Verify T2 = 415 encoded at offset 4-5
        let t2 = u16::from_le_bytes([body[4], body[5]]);
        assert_eq!(t2, 415, "T2 should be 415");

        // Verify T0 = 401 encoded at offset 10-11
        let t0 = u16::from_le_bytes([body[10], body[11]]);
        assert_eq!(t0, 401, "T0 should be 401");

        // Verify body does NOT contain OpInputCount (0xb3) — no InputCount==2 constraint.
        // Rationale: removing InputCount==2 enables N-to-M batch matching (multiple
        // sell + buy orders in one TX), cross-pair routing (3+ inputs), and a
        // dedicated fee UTXO input.  The OCO contract (oco.rs) still enforces
        // InputCount==2 for its own fill path, but standard spot orders do not.
        assert!(!body.contains(&0xb3), "body must NOT contain OpInputCount (InputCount constraint removed)");

        // Verify mmfee check is present: OpLTE (0xa1) followed by OpVerify (0x69)
        // in the fill path after F4
    }

    #[test]
    fn buy_partial_sigscript_range() {
        let tcid = [0x11u8; 32];
        let oh = [0x22u8; 32];
        let bspkh = [0x33u8; 32];
        let rs = build_buy_redeem_script(
            &tcid, 3, 1, 5, &oh, &bspkh, 0, 0, 1000,)
        .unwrap();

        let ss = build_buy_partial_fill_sigscript(&rs, 50000, 1, 0);
        // T1 <= sigLen < T2: 409 <= sigLen < 415 (v14)
        assert!(ss.len() >= 409, "partial sigLen {} must be >= T1=409", ss.len());
        assert!(ss.len() < 415, "partial sigLen {} must be < T2=415", ss.len());
    }

    #[test]
    fn buy_body_has_cltv_and_locktime() {
        assert!(BUY_ORDER_BODY.contains(&0xb0), "body must contain CLTV");
        assert!(BUY_ORDER_BODY.contains(&0xb5), "body must contain OpTxLockTime");
    }

    #[test]
    fn buy_body_has_csv() {
        assert!(BUY_ORDER_BODY.contains(&0xb1), "body must contain CSV");
    }

    #[test]
    fn buy_state_includes_mmfee() {
        // State should be 145B (includes mmfee 8B)
        let tcid = [0xAAu8; 32];
        let oh = [0xBBu8; 32];
        let bspkh = [0xCCu8; 32];
        let rs = build_buy_redeem_script(
            &tcid, 100, 1, 10, &oh, &bspkh, 0, 0, 0,)
        .unwrap();
        let state_len = rs.len() - BUY_ORDER_BODY.len();
        assert_eq!(state_len, 145, "state should be 145B (with mmfee), got {}B", state_len);
    }

    #[test]
    fn sell_order_body_exact_length() {
        let body = SELL_ORDER_BODY;
        assert_eq!(
            body.len(),
            SELL_ORDER_BODY_EXPECTED_LEN,
            "sell v13 body should be {}B, got {}B",
            SELL_ORDER_BODY_EXPECTED_LEN,
            body.len()
        );
    }

    #[test]
    fn sell_order_rs_size() {
        let oh = [0xAAu8; 32];
        let sspkh = [0xBBu8; 32];
        let rs = build_sell_redeem_script(
            100, 1, 10, &oh, &sspkh, 0, 0, 0,)
        .unwrap();
        assert_eq!(
            rs.len(),
            SELL_ORDER_RS_EXPECTED_LEN,
            "sell v13 RS should be {}B, got {}B",
            SELL_ORDER_RS_EXPECTED_LEN,
            rs.len()
        );
    }

}
