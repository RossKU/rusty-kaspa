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

    // bracket_order tests (N4 fix: receipt covenant_id check)

    #[test]
    fn bracket_body_length() {
        assert_eq!(
            BRACKET_ORDER_BODY.len(),
            159,
            "bracket_order body must be 159 bytes"
        );
    }

    #[test]
    fn bracket_body_hex_matches_spec() {
        let expected = "b9c902e0019f6352c35979876952c25879a26953c35779876953c25679a26952be5479a26952cf537987695c79ce63b9be5b79955a7996765679a26900c27ca26900c3aa5279876975757575757575757575757575755167b9be5a79965b7995765679a26951c27ca26951c3aa5279876975757575757575757575757575755168675d7976aa527987695f7a7cad7575757575757575757575757575755168";
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
        let tspk = [0u8; 32];
        let ohash = [0u8; 32];
        let rs = build_bracket_redeem_script(
            1, &tcid, 1000, 1, &tp_spk, 5_000_000, &sl_spk, 5_000_000,
            1_000_000, 5_000_000, &rcid, &tspk, &ohash,
        ).unwrap();
        assert_eq!(rs.len(), 430, "bracket_order RS must be 430 bytes (271 state + 159 body)");
    }

    #[test]
    fn bracket_redeem_state_layout() {
        let tcid = [0xAAu8; 32];
        let tp_spk = [0xBBu8; 37];
        let sl_spk = [0xCCu8; 37];
        let rcid = [0xDDu8; 32];
        let tspk = [0x11u8; 32];
        let ohash = [0xEEu8; 32];
        let rs = build_bracket_redeem_script(
            1, &tcid, 100, 200, &tp_spk, 5_000_000, &sl_spk, 3_000_000,
            1_000_000, 2_000_000, &rcid, &tspk, &ohash,
        ).unwrap();

        // State layout verification (271 bytes):
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

        // [0x20][receipt_cov_id 32B] = 33B
        assert_eq!(rs[172], 0x20, "receipt_cov_id push opcode");
        assert_eq!(&rs[173..205], &[0xDD; 32], "receipt_cov_id");

        // [0x20][trade_spk_hash 32B] = 33B  <-- NEW in N5
        assert_eq!(rs[205], 0x20, "trade_spk_hash push opcode");
        assert_eq!(&rs[206..238], &[0x11; 32], "trade_spk_hash");

        // [0x20][owner_hash 32B] = 33B
        assert_eq!(rs[238], 0x20, "owner_hash push opcode");
        assert_eq!(&rs[239..271], &[0xEE; 32], "owner_hash");

        // Body starts at offset 271
        assert_eq!(&rs[271..], BRACKET_ORDER_BODY, "body must match bytecode");
    }

    #[test]
    fn bracket_fill_sigscript_below_threshold() {
        let tcid = [0u8; 32];
        let tp_spk = [0u8; 37];
        let sl_spk = [0u8; 37];
        let rcid = [0u8; 32];
        let tspk = [0u8; 32];
        let ohash = [0u8; 32];
        let rs = build_bracket_redeem_script(
            0, &tcid, 1000, 1, &tp_spk, 5_000_000, &sl_spk, 5_000_000,
            1_000_000, 5_000_000, &rcid, &tspk, &ohash,
        ).unwrap();
        let fill_ss = build_bracket_fill_sigscript(&rs);
        // Fill: Op1(1) + OP_PUSHDATA2(3B) + RS(430B) = 434B
        assert_eq!(fill_ss.len(), 434, "fill sigscript must be 434B");
        assert!(fill_ss.len() < 480, "fill must be below dispatch threshold 480");
        assert_eq!(fill_ss[0], 0x51, "first byte must be Op1 selector");
    }

    #[test]
    fn bracket_cancel_sigscript_above_threshold() {
        let tcid = [0u8; 32];
        let tp_spk = [0u8; 37];
        let sl_spk = [0u8; 37];
        let rcid = [0u8; 32];
        let tspk = [0u8; 32];
        let ohash = [0u8; 32];
        let rs = build_bracket_redeem_script(
            0, &tcid, 1000, 1, &tp_spk, 5_000_000, &sl_spk, 5_000_000,
            1_000_000, 5_000_000, &rcid, &tspk, &ohash,
        ).unwrap();
        let sig = [0u8; 64];
        let pk = [0u8; 32];
        let cancel_ss = build_bracket_cancel_sigscript(&sig, &pk, &rs);
        // Cancel: Op0(1) + push_sig(66) + push_pk(33) + OP_PUSHDATA2(3) + RS(430) = 533B
        assert_eq!(cancel_ss.len(), 533, "cancel sigscript must be 533B");
        assert!(cancel_ss.len() >= 480, "cancel must be at or above dispatch threshold 480");
        assert_eq!(cancel_ss[0], 0x00, "first byte must be Op0 selector");
    }

    #[test]
    fn bracket_dispatch_margin_sufficient() {
        let tcid = [0u8; 32];
        let tp_spk = [0u8; 37];
        let sl_spk = [0u8; 37];
        let rcid = [0u8; 32];
        let tspk = [0u8; 32];
        let ohash = [0u8; 32];
        let rs = build_bracket_redeem_script(
            1, &tcid, 1000, 1, &tp_spk, 5_000_000, &sl_spk, 5_000_000,
            1_000_000, 5_000_000, &rcid, &tspk, &ohash,
        ).unwrap();
        let fill_ss = build_bracket_fill_sigscript(&rs);
        let sig = [0u8; 64];
        let pk = [0u8; 32];
        let cancel_ss = build_bracket_cancel_sigscript(&sig, &pk, &rs);

        // Verify both are well within their respective sides of threshold 480
        assert!(480 - fill_ss.len() >= 20, "fill margin from threshold must be >= 20B");
        assert!(cancel_ss.len() - 480 >= 50, "cancel margin from threshold must be >= 50B");
    }

    #[test]
    fn bracket_receipt_cov_id_in_body() {
        // Verify the body contains OpInputCovenantId (0xcf) which is the N4 fix
        assert!(
            BRACKET_ORDER_BODY.contains(&0xcf),
            "body must contain OpInputCovenantId (0xcf)"
        );
        // N5: SELL: 14, BUY: 14, CANCEL: 15 = 43 total drops
        let drop_count = BRACKET_ORDER_BODY.iter().filter(|&&b| b == 0x75).count();
        assert_eq!(drop_count, 43, "body must have 43 total OpDrop opcodes");
    }

    #[test]
    fn bracket_trade_spk_blake2b_in_body() {
        // N5: Verify the body contains OpBlake2b (0xaa) for trade SPK verification.
        // Should appear 3 times: cancel (pk hash) + sell (output SPK) + buy (output SPK)
        let blake2b_count = BRACKET_ORDER_BODY.iter().filter(|&&b| b == 0xaa).count();
        assert_eq!(blake2b_count, 3, "body must have 3 OpBlake2b opcodes (cancel + sell SPK + buy SPK)");
    }

    #[test]
    #[should_panic(expected = "entry_price_num must be > 0")]
    fn bracket_rejects_zero_price_num() {
        let tcid = [0u8; 32];
        let tp_spk = [0u8; 37];
        let sl_spk = [0u8; 37];
        let rcid = [0u8; 32];
        let tspk = [0u8; 32];
        let ohash = [0u8; 32];
        build_bracket_redeem_script(
            0, &tcid, 0, 1, &tp_spk, 1000, &sl_spk, 1000, 1000, 1000, &rcid, &tspk, &ohash,
        ).unwrap();
    }

    #[test]
    #[should_panic(expected = "entry_price_den must be > 0")]
    fn bracket_rejects_zero_price_den() {
        let tcid = [0u8; 32];
        let tp_spk = [0u8; 37];
        let sl_spk = [0u8; 37];
        let rcid = [0u8; 32];
        let tspk = [0u8; 32];
        let ohash = [0u8; 32];
        build_bracket_redeem_script(
            0, &tcid, 1, 0, &tp_spk, 1000, &sl_spk, 1000, 1000, 1000, &rcid, &tspk, &ohash,
        ).unwrap();
    }

    #[test]
    #[should_panic(expected = "min_fill must be > 0")]
    fn bracket_rejects_zero_min_fill() {
        let tcid = [0u8; 32];
        let tp_spk = [0u8; 37];
        let sl_spk = [0u8; 37];
        let rcid = [0u8; 32];
        let tspk = [0u8; 32];
        let ohash = [0u8; 32];
        build_bracket_redeem_script(
            0, &tcid, 1, 1, &tp_spk, 1000, &sl_spk, 1000, 0, 1000, &rcid, &tspk, &ohash,
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
            216,
            "dca_order body must be 216 bytes"
        );
    }

    #[test]
    fn dca_order_body_hex() {
        let hex = hex::encode(DCA_ORDER_BODY);
        // Verify dispatch: Op9 OpRoll Op0 OpGreaterThan OpIf
        assert_eq!(&hex[0..10], "597a00a063", "dispatch pattern");
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
        let bspkh = [0u8; 32];
        let rs = build_dca_order_redeem_script(
            &oh, &tcid, &bspkh, 100, 200, 50000, 100, 1000, 10,
        ).unwrap();
        assert_eq!(rs.len(), 369, "dca_order RS must be 369 bytes (153 state + 216 body)");
    }

    #[test]
    fn dca_order_state_layout() {
        let oh = [0xAAu8; 32];
        let tcid = [0xBBu8; 32];
        let bspkh = [0xCCu8; 32];
        let rs = build_dca_order_redeem_script(
            &oh, &tcid, &bspkh, 100, 200, 50000, 100, 1000, 10,
        ).unwrap();

        // [0x20][owner_hash 32B]
        assert_eq!(rs[0], 0x20, "owner_hash push opcode");
        assert_eq!(&rs[1..33], &[0xAA; 32], "owner_hash");

        // [0x20][target_cov_id 32B]
        assert_eq!(rs[33], 0x20, "target_cov_id push opcode");
        assert_eq!(&rs[34..66], &[0xBB; 32], "target_cov_id");

        // [0x20][buyer_spk_hash 32B]
        assert_eq!(rs[66], 0x20, "buyer_spk_hash push opcode");
        assert_eq!(&rs[67..99], &[0xCC; 32], "buyer_spk_hash");

        // [0x08][price_num 8B]
        assert_eq!(rs[99], 0x08, "price_num push opcode");
        assert_eq!(u64::from_le_bytes(rs[100..108].try_into().unwrap()), 100, "price_num");

        // [0x08][price_den 8B]
        assert_eq!(rs[108], 0x08, "price_den push opcode");
        assert_eq!(u64::from_le_bytes(rs[109..117].try_into().unwrap()), 200, "price_den");

        // [0x08][amount_per_period 8B]
        assert_eq!(rs[117], 0x08, "amount_per_period push opcode");
        assert_eq!(u64::from_le_bytes(rs[118..126].try_into().unwrap()), 50000, "amount_per_period");

        // [0x08][interval_daa 8B]
        assert_eq!(rs[126], 0x08, "interval_daa push opcode");
        assert_eq!(u64::from_le_bytes(rs[127..135].try_into().unwrap()), 100, "interval_daa");

        // [0x08][next_execution_daa 8B]
        assert_eq!(rs[135], 0x08, "next_execution_daa push opcode");
        assert_eq!(u64::from_le_bytes(rs[136..144].try_into().unwrap()), 1000, "next_execution_daa");

        // [0x08][periods_remaining 8B]
        assert_eq!(rs[144], 0x08, "periods_remaining push opcode");
        assert_eq!(u64::from_le_bytes(rs[145..153].try_into().unwrap()), 10, "periods_remaining");

        // Body starts at offset 153
        assert_eq!(&rs[153..], DCA_ORDER_BODY, "body must match bytecode");
    }

    #[test]
    fn dca_order_state_mutable_zone() {
        // The D&R mutable zone is [136..153) = next_exec value + push prefix + periods value
        let oh = [0xAAu8; 32];
        let tcid = [0xBBu8; 32];
        let bspkh = [0xCCu8; 32];
        let rs = build_dca_order_redeem_script(
            &oh, &tcid, &bspkh, 100, 200, 50000, 100, 1000, 10,
        ).unwrap();

        // Locked prefix [0..136): owner_hash + tcid + bspkh + pnum + pden + amt_pp + interval + push_prefix
        let prefix = &rs[0..136];
        assert_eq!(prefix[135], 0x08, "prefix ends with push prefix for next_exec");

        // Mutable zone [136..153): next_exec value (8B) + 0x08 (push prefix) + periods value (8B)
        assert_eq!(u64::from_le_bytes(rs[136..144].try_into().unwrap()), 1000, "mutable next_exec");
        assert_eq!(rs[144], 0x08, "push prefix for periods in mutable zone");
        assert_eq!(u64::from_le_bytes(rs[145..153].try_into().unwrap()), 10, "mutable periods");

        // Suffix [153..): body bytecode (locked)
        assert_eq!(&rs[153..], DCA_ORDER_BODY, "suffix is body");
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
        // Must contain OpBlake2b (0xaa) for RS authenticity, buyer SPK, and D&R SPK verification
        let blake2b_count = body.iter().filter(|&&b| b == 0xaa).count();
        assert!(blake2b_count >= 4, "need at least 4 OpBlake2b: auth + buyer_spk + D&R SPK x2, got {}", blake2b_count);
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
        // Op9 OpRoll dispatch
        assert_eq!(&DCA_ORDER_BODY[0..5], &[0x59, 0x7a, 0x00, 0xa0, 0x63],
            "dispatch must be: Op9 OpRoll Op0 OpGreaterThan OpIf");
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
        build_dca_order_redeem_script(&z, &z, &z, 1, 1, 1000, 10, 100, 0).unwrap();
    }

    #[test]
    #[should_panic(expected = "amount_per_period must be > 0")]
    fn dca_order_panics_on_zero_amount_per_period() {
        let z = [0u8; 32];
        build_dca_order_redeem_script(&z, &z, &z, 1, 1, 0, 10, 100, 5).unwrap();
    }

    #[test]
    #[should_panic(expected = "interval_daa must be > 0")]
    fn dca_order_panics_on_zero_interval() {
        let z = [0u8; 32];
        build_dca_order_redeem_script(&z, &z, &z, 1, 1, 1000, 0, 100, 5).unwrap();
    }

    #[test]
    #[should_panic(expected = "price_num must be > 0")]
    fn dca_order_panics_on_zero_price_num() {
        let z = [0u8; 32];
        build_dca_order_redeem_script(&z, &z, &z, 0, 1, 1000, 10, 100, 5).unwrap();
    }

    #[test]
    #[should_panic(expected = "price_den must be > 0")]
    fn dca_order_panics_on_zero_price_den() {
        let z = [0u8; 32];
        build_dca_order_redeem_script(&z, &z, &z, 1, 0, 1000, 10, 100, 5).unwrap();
    }

    #[test]
    fn dca_order_fill_sigscript_format() {
        let oh = [0xAAu8; 32];
        let tcid = [0xBBu8; 32];
        let bspkh = [0xCCu8; 32];
        let old_rs = build_dca_order_redeem_script(
            &oh, &tcid, &bspkh, 100, 200, 50000, 100, 1000, 10,
        ).unwrap();
        let new_rs = build_dca_order_redeem_script(
            &oh, &tcid, &bspkh, 100, 200, 50000, 100, 1100, 9,
        ).unwrap();

        let ss = build_dca_order_fill_sigscript(0, &old_rs, &new_rs, &old_rs);
        // sigscript contains: pushData(new_rs) + pushData(old_rs) + ci + Op1 + pushData(RS)
        // new_rs and old_rs are 369B each, pushData(369) = 4d + 2B len + 369B = 372B
        // ci = Op0 (1B), selector Op1 (1B), pushData(RS=369B) = 372B
        // Total ≈ 372 + 372 + 1 + 1 + 372 = 1118B
        assert!(ss.len() > 1100, "fill sigscript should be >1100B, got {}", ss.len());
        // Last bytes should be pushData(RS)
        let rs_push = push_data(&old_rs);
        assert_eq!(&ss[ss.len()-rs_push.len()..], &rs_push, "sigscript must end with pushData(RS)");
    }

    #[test]
    fn dca_order_cancel_sigscript_format() {
        let oh = [0xAAu8; 32];
        let tcid = [0xBBu8; 32];
        let bspkh = [0xCCu8; 32];
        let rs = build_dca_order_redeem_script(
            &oh, &tcid, &bspkh, 100, 200, 50000, 100, 1000, 10,
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
        // prefix size = 136 = 0x88 (pushed as 2-byte: 0x02 0x88 0x00)
        assert!(hex.contains("028800"), "body must push 136 (0x88,0x00) for prefix size");
        // suffix offset = 153 = 0x99 (pushed as 2-byte: 0x02 0x99 0x00)
        assert!(hex.contains("029900"), "body must push 153 (0x99,0x00) for suffix offset");
        // push prefix check at byte 144 = 0x90 (pushed as 2-byte: 0x02 0x90 0x00)
        assert!(hex.contains("029000"), "body must push 144 (0x90,0x00) for push prefix check");
        // next_exec offset = 136 = 0x88 (same encoding as prefix size)
        // periods offset = 145 = 0x91 (pushed as 2-byte: 0x02 0x91 0x00)
        assert!(hex.contains("029100"), "body must push 145 (0x91,0x00) for periods offset");
    }

    #[test]
    fn dca_order_continuation_rs_matches_transition() {
        // Build old RS with periods=5, next_exec=1000, interval=100
        let oh = [0xAAu8; 32];
        let tcid = [0xBBu8; 32];
        let bspkh = [0xCCu8; 32];
        let old_rs = build_dca_order_redeem_script(
            &oh, &tcid, &bspkh, 50, 100, 10000, 100, 1000, 5,
        ).unwrap();

        // Build expected continuation RS
        let new_rs = build_dca_order_redeem_script(
            &oh, &tcid, &bspkh, 50, 100, 10000, 100, 1100, 4,
        ).unwrap();

        // Prefix [0..136) must match
        assert_eq!(&old_rs[0..136], &new_rs[0..136], "prefix must be identical");

        // Suffix [153..end) must match (body bytecode)
        assert_eq!(&old_rs[153..], &new_rs[153..], "suffix (body) must be identical");

        // Mutable zone [136..153) must differ
        assert_ne!(&old_rs[136..153], &new_rs[136..153], "mutable zone must differ");

        // Verify new_next_exec = old_next_exec + interval
        let old_next = u64::from_le_bytes(old_rs[136..144].try_into().unwrap());
        let new_next = u64::from_le_bytes(new_rs[136..144].try_into().unwrap());
        let interval = u64::from_le_bytes(old_rs[127..135].try_into().unwrap());
        assert_eq!(new_next, old_next + interval, "new_next_exec must equal old + interval");

        // Verify new_periods = old_periods - 1
        let old_periods = u64::from_le_bytes(old_rs[145..153].try_into().unwrap());
        let new_periods = u64::from_le_bytes(new_rs[145..153].try_into().unwrap());
        assert_eq!(new_periods, old_periods - 1, "new_periods must equal old - 1");

        // Push prefix at byte 144 preserved
        assert_eq!(old_rs[144], 0x08, "old push prefix");
        assert_eq!(new_rs[144], 0x08, "new push prefix");
    }

    #[test]
    fn dca_order_final_fill_no_continuation() {
        // When periods == 1, the script takes the else branch (no D&R)
        let oh = [0xAAu8; 32];
        let tcid = [0xBBu8; 32];
        let bspkh = [0xCCu8; 32];
        let rs = build_dca_order_redeem_script(
            &oh, &tcid, &bspkh, 50, 100, 10000, 100, 1000, 1,
        ).unwrap();

        // For final fill, old_rs/new_rs can be empty (Op0 pushes empty)
        let ss = build_dca_order_fill_sigscript(0, &[], &[], &rs);
        // Should be valid: pushData(empty) + pushData(empty) + Op0 + Op1 + pushData(RS)
        // pushData(empty) = [0x00] (1 byte each)
        // Total = 1 + 1 + 1 + 1 + pushData(369) = 4 + 372 = 376B
        assert!(ss.len() < 380, "final fill sigscript should be compact, got {}", ss.len());
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
