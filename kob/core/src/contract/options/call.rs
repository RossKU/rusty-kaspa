use crate::primitives::{push_data, u64_le};

// call_option (American-style with on-chain exercise window)

/// call_option body bytecode (33 bytes).
///
/// On-chain exercise window enforcement via CLTV + OpTxLockTime.
///
/// Exercise window: `[start_daa, expiry_daa)` — holder can exercise only within this range.
/// Cancel after expiry: writer can recover collateral only after `expiry_daa`.
///
/// State layout (126B):
///   [0x20][writer_pk 32B][0x20][holder_pk 32B][0x08][strike_kas 8B]
///   [0x20][writer_spk_hash 32B][0x08][start_daa 8B][0x08][expiry_daa 8B]
///
/// Stack after state push (from top):
///   `expiry_daa(0), start_daa(1), wsh(2), sk(3), hp(4), wp(5)`
///
/// Exercise sigscript: `[pushData(sig_h 65B)][Op1][pushData(RS 159B)]`
/// Cancel sigscript:   `[pushData(sig_w 65B)][Op0][pushData(RS 159B)]`
///
/// Exercise TX layout:
///   input[0]:  call_option UTXO
///   input[1]:  holder's KAS UTXO (provides strike payment)
///   output[0]: writer receives >= strike_kas  -- verified: value + SPK
///   output[1]: holder receives collateral
///   output[2]: (optional) change from input[1]
///
/// Body = 33B, RS = 126 + 33 = 159 bytes.
pub const CALL_OPTION_BODY: &[u8] = &[
    // === Dispatch (5B): Op6 OpRoll brings selector to top ===
    // Initial stack (exercise): expiry(0), start(1), wsh(2), sk(3), hp(4), wp(5), 1(6), sig_h(7)
    0x56, 0x7a,             // Op6 OpRoll -> brings 1 (selector) to top
    0x00, 0xa0,             // Op0 OpGreaterThan -> (1 > 0) = TRUE
    0x63,                   // OpIf (exercise path)
    // Stack at exercise entry: expiry(0), start(1), wsh(2), sk(3), hp(4), wp(5), sig_h(6)

    // === Exercise Path (19B) ===

    // Time check 1: start_daa <= lockTime (3B)
    // Stack: expiry(0), start(1), wsh(2), sk(3), hp(4), wp(5), sig_h(6)
    0x51, 0x7a,             // Op1 OpRoll -> move start(1) to top
    // Stack: start(0), expiry(1), wsh(2), sk(3), hp(4), wp(5), sig_h(6)
    0xb0,                   // OpCheckLockTimeVerify (pops start; verifies start <= tx.lockTime)
    // Stack: expiry(0), wsh(1), sk(2), hp(3), wp(4), sig_h(5)  [6 items]

    // Time check 2: expiry_daa > lockTime — not yet expired (3B)
    // Stack: expiry(0), wsh(1), sk(2), hp(3), wp(4), sig_h(5)
    0xb5,                   // OpTxLockTime -> push tx.lockTime
    // Stack: lockTime(0), expiry(1), wsh(2), sk(3), hp(4), wp(5), sig_h(6)
    0xa0, 0x69,             // OpGreaterThan OpVerify -> expiry > lockTime (pops both)
    // Stack: wsh(0), sk(1), hp(2), wp(3), sig_h(4)  [5 items]

    // Step 1: Verify output[0].value >= strike_kas (6B)
    // Stack: wsh(0), sk(1), hp(2), wp(3), sig_h(4)
    0x00, 0xc2,             // Op0 OpTxOutputAmount -> push output[0].value
    // Stack: val(0), wsh(1), sk(2), hp(3), wp(4), sig_h(5)
    0x52, 0x7a,             // Op2 OpRoll -> move sk(2) to top
    // Stack: sk(0), val(1), wsh(2), hp(3), wp(4), sig_h(5)
    0xa2, 0x69,             // OpGTE OpVerify -> val >= sk; consumes both
    // Stack after: wsh(0), hp(1), wp(2), sig_h(3)  [4 items]

    // Step 2: Verify output[0] destination = writer (5B)
    // Stack: wsh(0), hp(1), wp(2), sig_h(3)
    0x00, 0xc3,             // Op0 OpTxOutputSpk -> push output[0].spk (37B)
    // Stack: spk(0), wsh(1), hp(2), wp(3), sig_h(4)
    0xaa,                   // OpBlake2b -> hash(spk)
    // Stack: hash(0), wsh(1), hp(2), wp(3), sig_h(4)
    0x87, 0x69,             // OpEqual OpVerify -> hash == wsh? pops both
    // Stack after: hp(0), wp(1), sig_h(2)  [3 items]

    // Step 3: Verify holder signature (2B)
    0x77,                   // OpNip -> remove wp (second from top)
    // Stack: hp(0), sig_h(1)
    0xad,                   // OpCheckSigVerify -> pk=hp, sig=sig_h; verify holder
    // Stack after: []  [0 items]

    // === Cancel Path (7B) ===
    // Stack at cancel entry: expiry(0), start(1), wsh(2), sk(3), hp(4), wp(5), sig_w(6)
    0x67,                   // OpElse
    // Time check: CLTV with expiry_daa (already at top)
    0xb0,                   // OpCheckLockTimeVerify (pops expiry; verifies expiry <= tx.lockTime)
    // Stack: start(0), wsh(1), sk(2), hp(3), wp(4), sig_w(5)  [6 items]
    0x75, 0x75, 0x75, 0x75, // OpDrop x4 -> drop start, wsh, sk, hp
    // Stack: wp(0), sig_w(1)
    0xad,                   // OpCheckSigVerify -> pk=wp, sig=sig_w; verify writer
    // Stack after: []  [0 items]

    // === Common Tail (2B) ===
    0x68,                   // OpEndIf
    0x51,                   // Op1 (TRUE) -> clean stack
];

/// Build call_option redeemScript (159 bytes).
///
/// State layout (126B):
///   [0x20][writer_pk][0x20][holder_pk][0x08][strike_kas LE]
///   [0x20][writer_spk_hash][0x08][start_daa LE][0x08][expiry_daa LE]
///
/// Body (33B): CALL_OPTION_BODY
///
/// # Arguments
/// * `writer_pk`       - Writer's 32-byte Schnorr x-only public key
/// * `holder_pk`       - Holder's 32-byte Schnorr x-only public key
/// * `strike_kas`      - Strike price in sompi (KAS amount holder pays on exercise)
/// * `writer_spk_hash` - Blake2b-256 hash of writer's full SPK (version_2B || script)
/// * `start_daa`       - Earliest DAA score at which the holder can exercise
/// * `expiry_daa`      - DAA score at which the exercise window closes and writer can cancel
///
/// # Errors
/// Returns error if `strike_kas` is 0 or `start_daa >= expiry_daa`.
pub fn build_call_option_redeem_script(
    writer_pk: &[u8; 32],
    holder_pk: &[u8; 32],
    strike_kas: u64,
    writer_spk_hash: &[u8; 32],
    start_daa: u64,
    expiry_daa: u64,
) -> crate::Result<Vec<u8>> {
    if strike_kas <= 0 {
        return Err(crate::KobError::Contract("strike_kas must be > 0".into()));
    }
    if start_daa >= expiry_daa {
        return Err(crate::KobError::Contract("start_daa must be < expiry_daa".into()));
    }

    let state_size = 33 + 33 + 9 + 33 + 9 + 9; // 126 bytes
    let mut rs = Vec::with_capacity(state_size + CALL_OPTION_BODY.len());

    // [0x20][writer_pk 32B]
    rs.push(0x20);
    rs.extend_from_slice(writer_pk);

    // [0x20][holder_pk 32B]
    rs.push(0x20);
    rs.extend_from_slice(holder_pk);

    // [0x08][strike_kas 8B LE]
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(strike_kas));

    // [0x20][writer_spk_hash 32B]
    rs.push(0x20);
    rs.extend_from_slice(writer_spk_hash);

    // [0x08][start_daa 8B LE]
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(start_daa));

    // [0x08][expiry_daa 8B LE]
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(expiry_daa));

    rs.extend_from_slice(CALL_OPTION_BODY);
    Ok(rs)
}

/// Build call_option exercise sigscript.
///
/// Format: `[pushData(sig_h + 0x01, 65B)][Op1][pushData(redeemScript)]`
///
/// sigOpCount = 1 (holder signature).
pub fn build_call_option_exercise_sigscript(
    holder_sig: &[u8; 64],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = [0u8; 65];
    sig_with_type[..64].copy_from_slice(holder_sig);
    sig_with_type[64] = 0x01;

    let mut ss = Vec::with_capacity(66 + 1 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.push(0x51); // Op1 (exercise selector)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build call_option cancel sigscript.
///
/// Format: `[pushData(sig_w + 0x01, 65B)][Op0][pushData(redeemScript)]`
///
/// sigOpCount = 1 (writer signature).
pub fn build_call_option_cancel_sigscript(
    writer_sig: &[u8; 64],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = [0u8; 65];
    sig_with_type[..64].copy_from_slice(writer_sig);
    sig_with_type[64] = 0x01;

    let mut ss = Vec::with_capacity(66 + 1 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.push(0x00); // Op0 (cancel selector)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}
