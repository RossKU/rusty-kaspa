use crate::primitives::u64_le;

/// vesting body bytecode (42 bytes).
///
/// Purpose: Linear vesting schedule — tokens unlock proportionally over time.
/// The beneficiary can claim vested tokens after the cliff period.
///
/// State (111B):
///   [0x20][beneficiary_hash 32B][0x20][token_cov_id 32B][0x08][total_amount 8B]
///   [0x08][claimed_amount 8B][0x08][start_daa 8B][0x08][end_daa 8B]
///   [0x08][cliff_daa 8B]
///
/// Stack after state pushes (7 items, depth 0 = top):
///   cliff(0), end(1), start(2), claimed(3), total(4), tcid(5), bhash(6)
///
/// Single path: claim (beneficiary sig required).
///
/// Sigscript: [pushData(sig+type 65B)] [pushData(pk 32B)] [pushData(RS)]
/// sigOpCount = 1.
///
/// Claim path:
///   1. CLTV: cliff_daa <= tx.lockTime
///   2. vested = total * (tx.lockTime - start) / (end - start)
///   3. claimable = vested - claimed
///   4. Verify output[0].value >= claimable
///   5. Verify Blake2b(pubkey) == beneficiary_hash
///   6. CheckSigVerify
///
/// Body = 42B, RS = 111 + 42 = 153 bytes.
pub const VESTING_BODY: &[u8] = &[
    // --- CLTV (2B) ---
    // Stack: cliff(0), end(1), start(2), claimed(3), total(4), tcid(5), bhash(6), pk(7), sig(8)
    0xb0,             // OpCheckLockTimeVerify (pops cliff; 8 items remain)
    // NOTE: Kaspa CLTV pops the top value. No OpDrop needed.
    // Stack: end(0), start(1), claimed(2), total(3), tcid(4), bhash(5), pk(6), sig(7)

    // --- VESTED CALCULATION (15B) ---
    // vested = total * (lockTime - start) / (end - start)
    0xb5,             // OpTxLockTime -> lockTime (9 items)
    0x52, 0x79,       // Op2 OpPick -> start copy (10 items)
    0x94,             // OpSub -> (lockTime - start) (9 items)
    0x54, 0x79,       // Op4 OpPick -> total (10 items)
    0x95,             // OpMul -> total * (lockTime - start) (9 items)
    0x51, 0x79,       // Op1 OpPick -> end copy (10 items)
    0x53, 0x79,       // Op3 OpPick -> start copy (11 items)
    0x94,             // OpSub -> (end - start) (10 items)
    0x96,             // OpDiv -> vested = total*(lt-start)/(end-start) (9 items)
    // Stack: vested(0), end(1), start(2), claimed(3), total(4), tcid(5), bhash(6), pk(7), sig(8)

    // --- CLAIMABLE (3B) ---
    0x53, 0x79,       // Op3 OpPick -> claimed copy (10 items)
    0x94,             // OpSub -> vested - claimed = claimable (9 items)
    // Stack: claimable(0), end(1), start(2), claimed(3), total(4), tcid(5), bhash(6), pk(7), sig(8)

    // --- OUTPUT CHECK (5B) ---
    0x00, 0xc2,       // Op0 OpTxOutputAmount -> output[0].value (10 items)
    0x7c,             // OpSwap
    0xa2, 0x69,       // OpGTE OpVerify (out0 >= claimable) (8 items)
    // Stack: end(0), start(1), claimed(2), total(3), tcid(4), bhash(5), pk(6), sig(7)

    // --- BENEFICIARY SIG CHECK (14B) ---
    0x56, 0x79,       // Op6 OpPick -> pk copy (9 items)
    0x76,             // OpDup (10 items)
    0xaa,             // OpBlake2b -> hash(pk) (10 items)
    0x57, 0x79,       // Op7 OpPick -> bhash (d7 in 10-item stack) (11 items)
    0x87, 0x69,       // OpEqual OpVerify (hash == bhash) (9 items)
    0x58, 0x7a,       // Op8 OpRoll -> sig to top (9 items)
    0x7c,             // OpSwap -> pk, sig
    0xad,             // OpCheckSigVerify (7 items)
    // Stack: end(0), start(1), claimed(2), total(3), tcid(4), bhash(5), pk(6)

    // --- CLEANUP (8B) ---
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x7
    0x51,             // Op1 (TRUE)
];

/// Build vesting redeemScript (153 bytes).
///
/// State (111B):
///   [0x20][beneficiary_hash 32B][0x20][token_cov_id 32B][0x08][total_amount 8B]
///   [0x08][claimed_amount 8B][0x08][start_daa 8B][0x08][end_daa 8B]
///   [0x08][cliff_daa 8B]
/// Body (43B): VESTING_BODY
/// # Arguments
/// * `beneficiary_hash` - Blake2b-256 of the beneficiary's Schnorr public key
/// * `token_cov_id` - 32-byte CovenantID of the vesting token
/// * `total_amount` - Total tokens to vest
/// * `claimed_amount` - Tokens already claimed (0 for initial deployment)
/// * `start_daa` - Vesting start DAA score
/// * `end_daa` - Vesting end DAA score (full unlock)
/// * `cliff_daa` - Cliff period DAA (no claims before this)
///
/// # Panics
/// Panics if `total_amount` is 0, or `end_daa <= start_daa`, or `cliff_daa < start_daa`.
pub fn build_vesting_redeem_script(
    beneficiary_hash: &[u8; 32],
    token_cov_id: &[u8; 32],
    total_amount: u64,
    claimed_amount: u64,
    start_daa: u64,
    end_daa: u64,
    cliff_daa: u64,
) -> crate::Result<Vec<u8>> {
    if total_amount <= 0 {
        return Err(crate::KobError::Contract("total_amount must be > 0".into()));
    }
    if end_daa <= start_daa {
        return Err(crate::KobError::Contract("end_daa must be > start_daa".into()));
    }
    if cliff_daa < start_daa {
        return Err(crate::KobError::Contract("cliff_daa must be >= start_daa".into()));
    }
    let mut rs = Vec::with_capacity(153);
    // State (111 bytes)
    rs.push(0x20);
    rs.extend_from_slice(beneficiary_hash);
    rs.push(0x20);
    rs.extend_from_slice(token_cov_id);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(total_amount));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(claimed_amount));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(start_daa));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(end_daa));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(cliff_daa));
    // Body (43 bytes)
    rs.extend_from_slice(VESTING_BODY);
    Ok(rs)
}
