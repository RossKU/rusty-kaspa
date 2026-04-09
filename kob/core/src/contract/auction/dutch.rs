use crate::primitives::{push_data, u64_le};

// Dutch Auction (royalty enforcement)

/// Dutch auction body bytecode (107 bytes).
///
/// Includes royalty enforcement on buy path (splits payment between seller and creator),
/// CSV tick rate-limit, and CSV expiry cancel.
///
/// State (177B):
/// ```text
/// [0x20][seller_pk 32B]
/// [0x08][reserve 8B]
/// [0x08][step 8B]
/// [0x08][tick_interval 8B]
/// [0x08][expiry_daa 8B]
/// [0x20][seller_spk_hash 32B]
/// [0x20][item_cov_id 32B]
/// [0x20][creator_spk_hash 32B]
/// [0x08][royalty_amount 8B]
/// ```
///
/// Stack after state push (bottom->top):
///   seller_pk(8), reserve(7), step(6), tick_interval(5), expiry_daa(4),
///   seller_spk_hash(3), item_cov_id(2), creator_spk_hash(1), royalty_amount(0)
///
/// Dispatch: `Op9 OpRoll` selector, 3-way:
/// - selector > 1 -> buy (atomic delivery + royalty split + fee=0)
/// - selector == 1 -> tick (CSV rate-limit + self-continuation + fee=0)
/// - selector == 0 -> cancel (CSV expiry + seller sig)
///
/// Royalty on buy:
///   output[0].value >= input.value - royalty_amount, Blake2b(output[0].spk) == seller_spk_hash
///   output[1].value >= royalty_amount, Blake2b(output[1].spk) == creator_spk_hash
pub const DUTCH_AUCTION_BODY: &[u8] = &[
    // --- DISPATCH (6B) ---
    0x59, 0x7a,       // Op9 OpRoll -> selector to top
    0x76,             // OpDup
    0x51,             // Op1
    0xa0,             // OpGreaterThan (selector > 1?)
    0x63,             // OpIf (true=buy)

    // --- BUY PATH (45B) ---
    // sigscript: [Op2 selector][RS], sigOpCount=0
    // Stack: 9 state items + selector on top = 10 items
    0x75,             // OpDrop (selector). 9 items.
    // seller_pk(8), reserve(7), step(6), tick_int(5), expiry(4),
    // seller_spk_hash(3), item_cov_id(2), creator_spk_hash(1), royalty_amount(0)

    // Atomic delivery: item_cov_id at depth 2 (6B)
    0x52, 0x79,       // Op2 OpPick -> item_cov_id copy (10 items)
    0xd0,             // OpCovInputCount (pops copy, pushes count)
    0x51, 0xa2, 0x69, // Op1 OpGTE OpVerify. 9 items.

    // Seller SPK dest: Blake2b(output[0].spk) == seller_spk_hash (7B)
    // seller_spk_hash at depth 3
    0x00, 0xc3,       // Op0 OpTxOutputSpk
    0xaa,             // OpBlake2b (10 items). hash=0, royalty=1, creator=2, item_cov=3, seller_spk=4
    0x54, 0x79,       // Op4 OpPick -> seller_spk_hash (11 items)
    0x87, 0x69,       // OpEqual OpVerify. 9 items.

    // Seller payment: output[0] >= input - royalty_amount (9B)
    0x00, 0xc2,       // Op0 OpTxOutputAmount (10 items)
    0xb9, 0xbe,       // OpTxInputIndex OpTxInputAmount (11 items)
    0x52, 0x79,       // Op2 OpPick -> royalty_amount (12 items)
    0x94,             // OpSub (in_val - royalty). 11 items.
    0xa2, 0x69,       // OpGTE OpVerify. 9 items.

    // Creator royalty: output[1] >= royalty_amount (6B)
    0x51, 0xc2,       // Op1 OpTxOutputAmount (10 items). out1=0, royalty=1
    0x51, 0x79,       // Op1 OpPick -> royalty_amount (11 items)
    0xa2, 0x69,       // OpGTE OpVerify. 9 items.

    // Creator SPK: Blake2b(output[1].spk) == creator_spk_hash (7B)
    0x51, 0xc3,       // Op1 OpTxOutputSpk
    0xaa,             // OpBlake2b (10 items). hash=0, royalty=1, creator=2
    0x52, 0x79,       // Op2 OpPick -> creator_spk_hash (11 items)
    0x87, 0x69,       // OpEqual OpVerify. 9 items.

    // fee=0 (4B)
    0xca,             // OpTxFee
    0x00, 0x87, 0x69, // Op0 OpEqual OpVerify

    // Clean 9 items (5B)
    0x6d, 0x6d, 0x6d, 0x6d, // Op2Drop x4
    0x75,                     // OpDrop

    // --- ELSE + INNER DISPATCH (4B) ---
    0x67,             // OpElse
    0x51,             // Op1
    0x87,             // OpEqual (selector == 1?)
    0x63,             // OpIf (true=tick)

    // --- TICK PATH (33B) ---
    // sigscript: [Op1 selector][RS], sigOpCount=0
    // Stack: 9 state items (selector consumed by dispatch).

    // Self-continuation (6B)
    0x00, 0xc3,       // Op0 OpTxOutputSpk
    0xb9, 0xbf,       // OpTxInputIndex OpTxInputSpk
    0x87, 0x69,       // OpEqual OpVerify

    // CSV tick rate-limit: tick_interval at depth 5 (3B)
    0x55, 0x79,       // Op5 OpPick -> tick_interval copy (10 items)
    0xb1,             // OpCheckSequenceVerify (pops copy). 9 items.

    // Price decay: output[0] >= input - step (9B)
    // After pushing out_val and in_val (11 items), step at depth 8
    0x00, 0xc2,       // Op0 OpTxOutputAmount
    0xb9, 0xbe,       // OpTxInputIndex OpTxInputAmount
    0x58, 0x79,       // Op8 OpPick -> step (12 items)
    0x94,             // OpSub (input - step). 11 items.
    0xa2, 0x69,       // OpGTE OpVerify. 9 items.

    // Reserve floor: output[0] >= reserve (6B)
    // reserve at depth 7. Push out_val (10 items), reserve at depth 8.
    0x00, 0xc2,       // Op0 OpTxOutputAmount
    0x58, 0x79,       // Op8 OpPick -> reserve (11 items)
    0xa2, 0x69,       // OpGTE OpVerify. 9 items.

    // fee=0 (4B)
    0xca,             // OpTxFee
    0x00, 0x87, 0x69, // Op0 OpEqual OpVerify

    // Clean 9 items (5B)
    0x6d, 0x6d, 0x6d, 0x6d, // Op2Drop x4
    0x75,                     // OpDrop

    // --- ELSE: CANCEL PATH (15B) ---
    0x67,             // OpElse
    // sigscript: [sig 65B][pubkey 32B][Op0 selector][RS], sigOpCount=1
    // Stack: sig(10), pubkey(9), + 9 state items = 11 items

    // CSV expiry: expiry_daa at depth 4 (3B)
    0x54, 0x79,       // Op4 OpPick -> expiry_daa copy (12 items)
    0xb1,             // OpCheckSequenceVerify (pops copy). 11 items.

    // Verify pubkey == seller_pk (6B)
    // seller_pk at depth 8, pubkey at depth 9 (then +1 after pick)
    0x58, 0x79,       // Op8 OpPick -> seller_pk copy (12 items)
    0x5a, 0x79,       // Op10 OpPick -> pubkey copy (13 items)
    0x87, 0x69,       // OpEqual OpVerify. 11 items.

    // Clean 9 state items (5B)
    0x6d, 0x6d, 0x6d, 0x6d, // Op2Drop x4
    0x75,                     // OpDrop. Stack: sig, pubkey.

    // Seller sig (1B)
    0xad,             // OpCheckSigVerify

    // --- ENDIF + ENDIF + TRUE (3B) ---
    0x68,             // OpEndIf (inner)
    0x68,             // OpEndIf (outer)
    0x51,             // Op1 (TRUE)
];

/// Dutch auction state size:
/// [0x20][seller_pk 32B][0x08][reserve 8B][0x08][step 8B][0x08][tick_interval 8B][0x08][expiry_daa 8B]
/// [0x20][seller_spk_hash 32B][0x20][item_cov_id 32B][0x20][creator_spk_hash 32B][0x08][royalty_amount 8B]
/// = 1+32 + 1+8 + 1+8 + 1+8 + 1+8 + 1+32 + 1+32 + 1+32 + 1+8 = 177 bytes.
pub const DUTCH_AUCTION_STATE_SIZE: usize = 177;

/// Build dutch_auction redeemScript.
///
/// `seller_pk`: 32-byte x-only Schnorr public key.
/// `reserve`: minimum price (price floor) in sompi (must be > 0).
/// `step`: price decrement per tick in sompi (must be > 0).
/// `tick_interval`: minimum DAA age between ticks (must be > 0).
/// `expiry_daa`: DAA age required for cancel path (must be > tick_interval).
/// `item_cov_id`: 32-byte covenant ID of the escrowed item.
/// `creator_spk_hash`: 32-byte Blake2b hash of creator's SPK (for royalty).
/// `royalty_amount`: absolute royalty in sompi (can be 0 for no royalty).
///
/// `seller_spk_hash` is computed automatically from `seller_pk`.
pub fn build_dutch_auction_redeem_script(
    seller_pk: &[u8; 32],
    reserve: u64,
    step: u64,
    tick_interval: u64,
    expiry_daa: u64,
    item_cov_id: &[u8; 32],
    creator_spk_hash: &[u8; 32],
    royalty_amount: u64,
) -> crate::Result<Vec<u8>> {
    if reserve == 0 {
        return Err(crate::KobError::Contract("reserve must be > 0".into()));
    }
    if step == 0 {
        return Err(crate::KobError::Contract("step must be > 0".into()));
    }
    if tick_interval == 0 {
        return Err(crate::KobError::Contract("tick_interval must be > 0".into()));
    }
    if expiry_daa <= tick_interval {
        return Err(crate::KobError::Contract("expiry_daa must be > tick_interval".into()));
    }
    let seller_spk_hash = crate::p2sh::compute_p2pk_spk_hash(seller_pk);

    let mut rs = Vec::with_capacity(DUTCH_AUCTION_STATE_SIZE + DUTCH_AUCTION_BODY.len());
    // State (177B)
    rs.push(0x20);
    rs.extend_from_slice(seller_pk);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(reserve));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(step));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(tick_interval));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(expiry_daa));
    rs.push(0x20);
    rs.extend_from_slice(&seller_spk_hash);
    rs.push(0x20);
    rs.extend_from_slice(item_cov_id);
    rs.push(0x20);
    rs.extend_from_slice(creator_spk_hash);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(royalty_amount));
    // Body
    rs.extend_from_slice(DUTCH_AUCTION_BODY);
    Ok(rs)
}

/// Build dutch_auction buy sigscript:
/// `[Op2] [pushData(RS)]`
///
/// sigOpCount = 0 (permissionless).
/// The buy TX must include the item covenant UTXO as a co-input.
pub fn build_dutch_buy_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(0x52); // Op2 (selector = buy)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build dutch_auction tick sigscript:
/// `[Op1] [pushData(RS)]`
///
/// sigOpCount = 0 (permissionless).
pub fn build_dutch_tick_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(0x51); // Op1 (selector = tick)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build dutch_auction cancel sigscript:
/// `[pushData(sig+type 65B)] [pushData(pubkey 32B)] [Op0] [pushData(RS)]`
///
/// sigOpCount = 1 (seller signature required).
pub fn build_dutch_cancel_sigscript(
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01); // SIGHASH_ALL

    let mut ss = Vec::with_capacity(66 + 33 + 1 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pubkey));
    ss.push(0x00); // Op0 (selector = cancel)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}
