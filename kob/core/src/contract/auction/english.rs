//! Auction covenants for KOB (Kaspa Order Book).
//!
//! Two auction types on Kaspa L1 covenants, plus an escrow for atomic delivery:
//!
//! # English Auction (ascending bids with royalty enforcement)
//! Seller deploys with reserve price, min_increment, expiry, item covenant ID,
//! and optional creator royalty. Bids are self-continuation TXs. Seller settles
//! (with royalty split) or cancels (if no bids). Expire path returns funds to
//! seller after CSV expiry (F13-safe: enforces seller SPK destination).
//!
//! # Dutch Auction (descending price with royalty enforcement)
//! Seller deploys at starting price with tick rate-limit, expiry, item covenant ID,
//! and optional creator royalty. Buy path splits payment between seller and creator.
//! Tick decrements price with CSV rate-limit. Cancel requires CSV expiry + seller sig.
//!
//! # Auction Escrow (seller-signed release)
//! Holds the auctioned item. Released when the auction covenant is consumed as a
//! co-input AND the seller signs. Prevents F13 attack (miner expire + release).
//! Cancel requires seller signature.

use crate::primitives::{push_data, u64_le};

/// KOB auction payload prefix (6 bytes, ASCII).
pub const KOB_AUCTION_PAYLOAD_PREFIX: &[u8] = b"KOB:A:";

pub fn build_auction_payload(rs: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(KOB_AUCTION_PAYLOAD_PREFIX.len() + rs.len());
    payload.extend_from_slice(KOB_AUCTION_PAYLOAD_PREFIX);
    payload.extend_from_slice(rs);
    payload
}

pub fn parse_auction_payload(payload: &[u8]) -> Option<&[u8]> {
    if payload.starts_with(KOB_AUCTION_PAYLOAD_PREFIX) {
        Some(&payload[KOB_AUCTION_PAYLOAD_PREFIX.len()..])
    } else {
        None
    }
}

// English Auction (F13 fix + royalty enforcement)

/// English auction body bytecode (131 bytes).
///
/// Includes F13 fix (expire path enforces seller SPK destination) and
/// royalty enforcement (settle path splits payment between seller and creator).
///
/// State (168B):
/// ```text
/// [0x20][seller_pk 32B]
/// [0x08][min_increment 8B]
/// [0x20][item_cov_id 32B]
/// [0x08][reserve_price 8B]
/// [0x08][expiry_daa 8B]
/// [0x20][seller_spk_hash 32B]
/// [0x20][creator_spk_hash 32B]
/// [0x08][royalty_amount 8B]
/// ```
///
/// Stack after state push (bottom->top):
///   seller_pk(7), min_inc(6), item_cov_id(5), reserve(4), expiry(3),
///   seller_spk_hash(2), creator_spk_hash(1), royalty_amount(0)
///
/// Dispatch: `Op8 OpRoll` selector, 4-way:
/// - selector > 2 -> bid (Op3)
/// - selector == 2 -> expire (CSV + seller SPK dest)
/// - selector == 1 -> settle (item co-input + royalty split + seller sig)
/// - selector == 0 -> cancel (no bids + seller sig)
///
/// Royalty on settle:
///   output[0].value >= input.value - royalty_amount, Blake2b(output[0].spk) == seller_spk_hash
///   output[1].value >= royalty_amount, Blake2b(output[1].spk) == creator_spk_hash
///
/// Expire: all funds to seller (no royalty -- expired auction, no sale).
/// Cancel: no royalty (no sale).
/// Bid: no royalty (no sale yet).
pub const ENGLISH_AUCTION_BODY: &[u8] = &[
    // --- OUTER DISPATCH (6B) ---
    0x58, 0x7a,       // Op8 OpRoll -> selector to top
    0x76,             // OpDup
    0x51,             // Op1
    0xa0,             // OpGreaterThan (selector > 1?)
    0x63,             // OpIf (true = bid or expire)

    // --- INNER DISPATCH bid/expire (3B) ---
    0x52,             // Op2
    0xa0,             // OpGreaterThan (selector > 2?)
    0x63,             // OpIf (true = bid)

    // --- BID PATH (30B) ---
    // sigscript: [Op0 dummy][Op3 selector][RS], sigOpCount=0
    // After dispatch: selector consumed. Stack (9 items):
    //   dummy(8), seller_pk(7), min_inc(6), item_cov_id(5), reserve(4),
    //   expiry(3), seller_spk_hash(2), creator_spk_hash(1), royalty_amount(0)

    // Self-continuation (6B)
    0x00, 0xc3,       // Op0 OpTxOutputSpk -> output[0].spk
    0xb9, 0xbf,       // OpTxInputIndex OpTxInputSpk -> input.spk
    0x87, 0x69,       // OpEqual OpVerify

    // Min increment: output[0] >= input + min_inc (9B)
    // After pushing out_val and in_val, min_inc is at depth 8
    0x00, 0xc2,       // Op0 OpTxOutputAmount
    0xb9, 0xbe,       // OpTxInputIndex OpTxInputAmount
    0x58, 0x79,       // Op8 OpPick -> min_increment
    0x93,             // OpAdd (input.value + min_increment)
    0xa2, 0x69,       // OpGTE OpVerify

    // Refund: output[1] >= input (6B)
    0x51, 0xc2,       // Op1 OpTxOutputAmount
    0xb9, 0xbe,       // OpTxInputIndex OpTxInputAmount
    0xa2, 0x69,       // OpGTE OpVerify

    // fee=0 (4B)
    0xca,             // OpTxFee
    0x00, 0x87, 0x69, // Op0 OpEqual OpVerify

    // Clean 9 items (5B)
    0x6d, 0x6d, 0x6d, 0x6d, // Op2Drop x4
    0x75,                     // OpDrop

    // --- ELSE: EXPIRE PATH (31B) ---
    0x67,             // OpElse
    // sigscript: [Op0 dummy][Op2 selector][RS], sigOpCount=0
    // Same stack as bid after dispatch.

    // CSV expiry: expiry_daa at depth 3 (3B)
    0x53, 0x79,       // Op3 OpPick -> expiry_daa copy
    0xb1,             // OpCheckSequenceVerify (pops copy)

    // Bids exist: input > reserve. reserve at depth 4 (6B)
    0xb9, 0xbe,       // OpTxInputIndex OpTxInputAmount -> in_val (10 items)
    0x55, 0x79,       // Op5 OpPick -> reserve copy (11 items)
    0xa0, 0x69,       // OpGT OpVerify (in_val > reserve). Back to 9 items.

    // Seller SPK dest check (F13 fix): Blake2b(output[0].spk) == seller_spk_hash (7B)
    // seller_spk_hash at depth 2
    0x00, 0xc3,       // Op0 OpTxOutputSpk
    0xaa,             // OpBlake2b -> hash on top (10 items)
    0x53, 0x79,       // Op3 OpPick -> seller_spk_hash (depth: hash=0, royalty=1, creator=2, seller_spk=3)
    0x87, 0x69,       // OpEqual OpVerify. Back to 9.

    // Output value: output[0] >= input (all funds to seller, no royalty on expire) (6B)
    0x00, 0xc2,       // Op0 OpTxOutputAmount
    0xb9, 0xbe,       // OpTxInputIndex OpTxInputAmount
    0xa2, 0x69,       // OpGTE OpVerify

    // fee=0 (4B)
    0xca,             // OpTxFee
    0x00, 0x87, 0x69, // Op0 OpEqual OpVerify

    // Clean 9 items (5B)
    0x6d, 0x6d, 0x6d, 0x6d, // Op2Drop x4
    0x75,                     // OpDrop

    // --- ENDIF inner bid/expire (1B) ---
    0x68,             // OpEndIf

    // --- ELSE: settle/cancel branch (1B) ---
    0x67,             // OpElse

    // --- INNER DISPATCH settle/cancel (3B) ---
    0x51,             // Op1
    0x87,             // OpEqual (selector == 1?)
    0x63,             // OpIf (true = settle)

    // --- SETTLE PATH (40B) ---
    // sigscript: [sig 65B][Op1 selector][RS], sigOpCount=1
    // After dispatch: selector consumed. Stack (9 items):
    //   sig(8), seller_pk(7), min_inc(6), item_cov_id(5), reserve(4),
    //   expiry(3), seller_spk_hash(2), creator_spk_hash(1), royalty_amount(0)

    // Item co-input (6B) -- item_cov_id at depth 5
    0x55, 0x79,       // Op5 OpPick -> item_cov_id copy (10 items)
    0xd0,             // OpCovInputCount (pops copy, pushes count)
    0x51, 0xa2, 0x69, // Op1 OpGTE OpVerify. Back to 9.

    // Seller payment: output[0] >= input - royalty_amount (9B)
    // royalty_amount at depth 0 after pushing out_val and in_val
    0x00, 0xc2,       // Op0 OpTxOutputAmount -> out0_val (10 items)
    0xb9, 0xbe,       // OpTxInputIndex OpTxInputAmount -> in_val (11 items)
    0x52, 0x79,       // Op2 OpPick -> royalty_amount copy (12 items)
    0x94,             // OpSub (in_val - royalty). 11 items.
    0xa2, 0x69,       // OpGTE OpVerify (out0_val >= in_val - royalty). 9 items.

    // Seller SPK check: Blake2b(output[0].spk) == seller_spk_hash (7B)
    // seller_spk_hash at depth 2
    0x00, 0xc3,       // Op0 OpTxOutputSpk
    0xaa,             // OpBlake2b (10 items). hash=0, royalty=1, creator=2, seller_spk=3
    0x53, 0x79,       // Op3 OpPick -> seller_spk_hash (11 items)
    0x87, 0x69,       // OpEqual OpVerify. 9 items.

    // Creator royalty: output[1] >= royalty_amount (6B)
    0x51, 0xc2,       // Op1 OpTxOutputAmount -> out1_val (10 items). out1=0, royalty=1
    0x51, 0x79,       // Op1 OpPick -> royalty_amount copy (11 items)
    0xa2, 0x69,       // OpGTE OpVerify. 9 items.

    // Creator SPK check: Blake2b(output[1].spk) == creator_spk_hash (7B)
    // creator_spk_hash at depth 1
    0x51, 0xc3,       // Op1 OpTxOutputSpk
    0xaa,             // OpBlake2b (10 items). hash=0, royalty=1, creator=2
    0x52, 0x79,       // Op2 OpPick -> creator_spk_hash (11 items)
    0x87, 0x69,       // OpEqual OpVerify. 9 items.

    // Clean 7 state items + seller sig (5B)
    // Op2Drop x3: drops royalty+creator, seller_spk+expiry, reserve+item_cov = 6 gone. 3 remain: sig, seller_pk, min_inc.
    0x6d, 0x6d, 0x6d, // Op2Drop x3
    0x75,             // OpDrop (min_inc). Stack: sig, seller_pk.
    0xad,             // OpCheckSigVerify

    // --- ELSE: CANCEL PATH (11B) ---
    0x67,             // OpElse
    // sigscript: [sig 65B][Op0 selector][RS], sigOpCount=1
    // Same stack layout as settle.

    // No bids: input == reserve (6B)
    // reserve at depth 4. Push input_val, then pick reserve at depth 5.
    0xb9, 0xbe,       // OpTxInputIndex OpTxInputAmount -> in_val (10 items)
    0x55, 0x79,       // Op5 OpPick -> reserve copy (11 items)
    0x87, 0x69,       // OpEqual OpVerify (in_val == reserve). 9 items.

    // Clean 7 state items + seller sig (5B)
    0x6d, 0x6d, 0x6d, // Op2Drop x3
    0x75,             // OpDrop
    0xad,             // OpCheckSigVerify

    // --- ENDIF + ENDIF + TRUE (3B) ---
    0x68,             // OpEndIf (inner settle/cancel)
    0x68,             // OpEndIf (outer)
    0x51,             // Op1 (TRUE)
];

/// English auction state size:
/// [0x20][seller_pk 32B][0x08][min_inc 8B][0x20][item_cov_id 32B][0x08][reserve 8B][0x08][expiry 8B][0x20][seller_spk_hash 32B][0x20][creator_spk_hash 32B][0x08][royalty 8B]
/// = 1+32 + 1+8 + 1+32 + 1+8 + 1+8 + 1+32 + 1+32 + 1+8 = 168 bytes.
pub const ENGLISH_AUCTION_STATE_SIZE: usize = 168;

/// Build english_auction redeemScript.
///
/// `seller_pk`: 32-byte x-only Schnorr public key.
/// `min_increment`: minimum bid increase in sompi (must be > 0).
/// `item_cov_id`: 32-byte covenant ID of the escrowed item.
/// `reserve_price`: initial price / cancel threshold in sompi (must be > 0).
/// `expiry_daa`: DAA score age required for expire path (must be > 0).
/// `creator_spk_hash`: 32-byte Blake2b hash of creator's SPK (for royalty).
/// `royalty_amount`: absolute royalty in sompi (can be 0 for no royalty).
///
/// `seller_spk_hash` is computed automatically from `seller_pk`.
pub fn build_english_auction_redeem_script(
    seller_pk: &[u8; 32],
    min_increment: u64,
    item_cov_id: &[u8; 32],
    reserve_price: u64,
    expiry_daa: u64,
    creator_spk_hash: &[u8; 32],
    royalty_amount: u64,
) -> crate::Result<Vec<u8>> {
    if min_increment == 0 {
        return Err(crate::KobError::Contract("min_increment must be > 0".into()));
    }
    if reserve_price == 0 {
        return Err(crate::KobError::Contract("reserve_price must be > 0".into()));
    }
    if expiry_daa == 0 {
        return Err(crate::KobError::Contract("expiry_daa must be > 0".into()));
    }
    let seller_spk_hash = crate::p2sh::compute_p2pk_spk_hash(seller_pk);

    let mut rs = Vec::with_capacity(ENGLISH_AUCTION_STATE_SIZE + ENGLISH_AUCTION_BODY.len());
    // State (168B)
    rs.push(0x20);
    rs.extend_from_slice(seller_pk);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_increment));
    rs.push(0x20);
    rs.extend_from_slice(item_cov_id);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(reserve_price));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(expiry_daa));
    rs.push(0x20);
    rs.extend_from_slice(&seller_spk_hash);
    rs.push(0x20);
    rs.extend_from_slice(creator_spk_hash);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(royalty_amount));
    // Body
    rs.extend_from_slice(ENGLISH_AUCTION_BODY);
    Ok(rs)
}

/// Build english_auction bid sigscript:
/// `[Op0 dummy] [Op3 selector] [pushData(RS)]`
///
/// sigOpCount = 0 (permissionless).
pub fn build_english_bid_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(2 + redeem_script.len() + 3);
    ss.push(0x00); // Op0 (dummy)
    ss.push(0x53); // Op3 (selector = bid)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build english_auction expire sigscript:
/// `[Op0 dummy] [Op2 selector] [pushData(RS)]`
///
/// sigOpCount = 0 (permissionless).
pub fn build_english_expire_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(2 + redeem_script.len() + 3);
    ss.push(0x00); // Op0 (dummy)
    ss.push(0x52); // Op2 (selector = expire)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build english_auction settle sigscript:
/// `[pushData(sig+type 65B)] [Op1 selector] [pushData(RS)]`
///
/// sigOpCount = 1 (seller signature required).
/// The settle TX must also include the item covenant UTXO as a co-input.
pub fn build_english_settle_sigscript(
    signature: &[u8; 64],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01); // SIGHASH_ALL

    let mut ss = Vec::with_capacity(66 + 1 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.push(0x51); // Op1 (selector = settle)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build english_auction cancel sigscript:
/// `[pushData(sig+type 65B)] [Op0 selector] [pushData(RS)]`
///
/// sigOpCount = 1 (seller signature required).
pub fn build_english_cancel_sigscript(
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
