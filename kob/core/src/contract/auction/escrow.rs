use crate::primitives::push_data;

// Auction Escrow (seller-signed release for English auctions)

/// Auction escrow body bytecode (23 bytes).
///
/// Seller signature required on the release path, fixing the F13
/// attack vector where a miner could expire an English auction and release
/// the escrow in the same TX (stealing both funds and item).
///
/// State (66B):
/// `[0x20][auction_cov_id 32B][0x20][seller_pk 32B]`
///
/// Stack after state push (bottom->top): auction_cov_id(1), seller_pk(0)
///
/// Dispatch: `Op2 OpRoll` selector (2 state items)
/// - selector > 0 -> release (auction consumed + seller sig, sigOpCount=1)
/// - selector == 0 -> cancel (seller sig, sigOpCount=1)
///
/// Release: auction consumed (input >=1, output == 0) + seller Schnorr signature.
///   Only settle (which has seller sig) can trigger release, not expire.
///
/// Cancel: seller Schnorr signature.
pub const AUCTION_ESCROW_BODY: &[u8] = &[
    // --- DISPATCH (5B) ---
    0x52, 0x7a,       // Op2 OpRoll -> selector to top
    0x00, 0xa0,       // Op0 OpGreaterThan (selector > 0?)
    0x63,             // OpIf (true=release)

    // --- RELEASE PATH (11B) ---
    // sigscript: [pushData(sig 65B)][Op1 selector][pushData(RS)], sigOpCount=1
    // Stack: [sig, auction_cov_id, seller_pk]
    0x7c,             // OpSwap -> [sig, seller_pk, auction_cov_id]
    0x76,             // OpDup -> [sig, seller_pk, auction_cov_id, copy]

    // Check 1: auction is input (3B)
    0xd0,             // OpCovInputCount -> pops copy, pushes in_count
    0x51, 0xa2, 0x69, // Op1 OpGTE OpVerify (in_count >= 1)
    // Stack: [sig, seller_pk, auction_cov_id]

    // Check 2: auction is NOT output (3B)
    0xd2,             // OpCovOutCount -> pops auction_cov_id, pushes out_count
    0x00, 0x87, 0x69, // Op0 OpEqual OpVerify (out_count == 0)
    // Stack: [sig, seller_pk]

    0xad,             // OpCheckSigVerify

    // --- CANCEL PATH (4B) ---
    0x67,             // OpElse
    // sigscript: [pushData(sig 65B)][Op0 selector][pushData(RS)], sigOpCount=1
    // Stack: [sig, auction_cov_id, seller_pk]
    0x51, 0x7a,       // Op1 OpRoll -> auction_cov_id to top
    0x75,             // OpDrop (auction_cov_id)
    // Stack: [sig, seller_pk]
    0xad,             // OpCheckSigVerify

    // --- END (2B) ---
    0x68,             // OpEndIf
    0x51,             // Op1 (TRUE)
];

/// Auction escrow state size:
/// [0x20][auction_cov_id 32B][0x20][seller_pk 32B] = 66 bytes.
pub const AUCTION_ESCROW_STATE_SIZE: usize = 66;

/// Build auction escrow redeemScript (89 bytes).
///
/// `auction_cov_id`: 32-byte covenant ID of the auction contract.
/// `seller_pk`: 32-byte x-only Schnorr public key (for release + cancel).
pub fn build_auction_escrow_redeem_script(
    auction_cov_id: &[u8; 32],
    seller_pk: &[u8; 32],
) -> Vec<u8> {
    let mut rs = Vec::with_capacity(AUCTION_ESCROW_STATE_SIZE + AUCTION_ESCROW_BODY.len());
    rs.push(0x20);
    rs.extend_from_slice(auction_cov_id);
    rs.push(0x20);
    rs.extend_from_slice(seller_pk);
    rs.extend_from_slice(AUCTION_ESCROW_BODY);
    rs
}

/// Build auction escrow release sigscript:
/// `[pushData(sig+type 65B)] [Op1 selector] [pushData(RS)]`
///
/// sigOpCount = 1 (seller signature required).
/// The release TX must include the consumed auction covenant as a co-input.
pub fn build_auction_escrow_release_sigscript(
    signature: &[u8; 64],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01); // SIGHASH_ALL

    let mut ss = Vec::with_capacity(66 + 1 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.push(0x51); // Op1 (selector = release)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build auction escrow cancel sigscript:
/// `[pushData(sig+type 65B)] [Op0 selector] [pushData(RS)]`
///
/// sigOpCount = 1 (seller signature required).
pub fn build_auction_escrow_cancel_sigscript(
    signature: &[u8; 64],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01); // SIGHASH_ALL

    let mut ss = Vec::with_capacity(66 + 1 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.push(0x00); // Op0 (selector = cancel)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}
