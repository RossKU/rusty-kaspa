#![allow(dead_code)] // Opcode reference table — many constants reserved for future use
use crate::primitives::{push_data, u64_le};

const OP_0: u8 = 0x00;
const OP_1: u8 = 0x51;
const OP_2: u8 = 0x52;
const OP_3: u8 = 0x53;
const OP_DROP: u8 = 0x75;
const OP_ROLL: u8 = 0x7a;
const OP_EQUAL: u8 = 0x87;
const OP_VERIFY: u8 = 0x69;
const OP_GTE: u8 = 0xa2;
const OP_IF: u8 = 0x63;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
const OP_CHECKSIGVERIFY: u8 = 0xad;
const OP_CLTV: u8 = 0xb0;
const OP_TXINPUTINDEX: u8 = 0xb9;
const OP_TXINPUTAMOUNT: u8 = 0xbe;
const OP_TXINPUTSPK: u8 = 0xbf;
const OP_TXOUTPUTAMOUNT: u8 = 0xc2;
const OP_TXOUTPUTSPK: u8 = 0xc3;

// 1b. MarketMint Covenant — Bond-Protected — DEPRECATED
//
// DEPRECATED: Bond protection mitigates spam but does NOT fix the core C1
// vulnerability (admin mints unbacked tokens → merge drains pool).
// SplitMerge's 1:1 KAS backing is the correct solution.
//
// Extends v1 with anti-rug-pull protections:
//   1. expiry_daa in state → CLTV on burn path (admin cannot void market early)
//   2. Value conservation on mint path (admin cannot drain bond during minting)
//
// The UTXO value of MarketMint acts as a creation bond:
//   - Creator locks X KAS when deploying MarketMint
//   - Bond is preserved through all mint operations (value conservation)
//   - Bond can only be recovered after expiry_daa via burn path
//   - This prevents spam markets (economic cost) and rug-pulls (time lock)
//
// State (75B with push opcodes):
//   [0x20] admin_pk    (32B)  — market creator's pubkey
//   [0x20] market_id   (32B)  — Blake2b hash of market parameters
//   [0x08] expiry_daa  (8B)   — DAA score after which admin can burn/reclaim
//
// Stack after state (top=0):
//   expiry_daa(0), market_id(1), admin_pk(2)
//
// Paths:
//   Mint:  admin sig → self-continuation + value conservation + token output
//   Burn:  CLTV + admin sig → destroy covenant, reclaim bond (market ended)

/// MarketMint body bytecode (25B).
///
/// Stack after state: expiry_daa(0), market_id(1), admin_pk(2)
/// Sigscript: [sig+hashtype, selector, RS]
///   selector: Op1 = mint, Op0 = burn
///
/// DEPRECATED: Bond protection does not fix C1. Use SplitMerge.
#[deprecated(note = "C1 vulnerability: use SplitMerge as sole token issuer.")]
pub const MARKET_MINT_BODY: &[u8] = &[
    // DISPATCH (3B)
    OP_3, OP_ROLL,                          // selector to top            [2B]
    OP_IF,                                  // mint path                  [1B]

    // MINT PATH (15B): self-continuation + value conservation + admin sig
    // Stack: expiry_daa(0), market_id(1), admin_pk(2)
    OP_DROP,                               // drop expiry_daa            [1B]
    // Stack: market_id(0), admin_pk(1)

    // M1: SPK equality — self-continuation
    OP_0, OP_TXOUTPUTSPK,                  // output[0].spk              [2B]
    OP_TXINPUTINDEX, OP_TXINPUTSPK,        // input.spk                  [2B]
    OP_EQUAL, OP_VERIFY,                   // must match                 [2B]

    // M2: Value conservation — bond cannot be drained during minting
    OP_0, OP_TXOUTPUTAMOUNT,               // output[0].value            [2B]
    OP_TXINPUTINDEX, OP_TXINPUTAMOUNT,     // input.value                [2B]
    OP_GTE, OP_VERIFY,                     // output >= input            [2B]

    // M3: admin sig
    OP_DROP,                               // drop market_id             [1B]
    OP_CHECKSIGVERIFY,                     // admin sig                  [1B]

    // BURN PATH (5B): CLTV + admin sig
    OP_ELSE,                               //                            [1B]
    // Stack: expiry_daa(0), market_id(1), admin_pk(2)

    // B1: CLTV — cannot burn before expiry
    OP_CLTV,                               // verify locktime >= expiry  [1B]
    OP_DROP,                               // drop expiry_daa            [1B]

    // B2: admin sig
    OP_DROP,                               // drop market_id             [1B]
    OP_CHECKSIGVERIFY,                     // admin sig                  [1B]

    // CLOSING (2B)
    OP_ENDIF,                              //                            [1B]
    OP_1,                                  // TRUE                       [1B]
];

/// Build MarketMint mint sigscript.
/// Format: [push(sig+0x01)] [Op1] [pushData(RS)]
#[deprecated(note = "C1 vulnerability: use SplitMerge.")]
pub fn build_market_mint_sigscript(signature: &[u8; 64], redeem_script: &[u8]) -> Vec<u8> {
    let mut sig_ht = Vec::with_capacity(65);
    sig_ht.extend_from_slice(signature);
    sig_ht.push(0x01);

    let mut ss = Vec::with_capacity(66 + 1 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_ht));
    ss.push(OP_1); // selector = mint
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build MarketMint burn sigscript.
/// Format: [push(sig+0x01)] [Op0] [pushData(RS)]
#[deprecated(note = "C1 vulnerability: use SplitMerge.")]
pub fn build_market_burn_sigscript(signature: &[u8; 64], redeem_script: &[u8]) -> Vec<u8> {
    let mut sig_ht = Vec::with_capacity(65);
    sig_ht.extend_from_slice(signature);
    sig_ht.push(0x01);

    let mut ss = Vec::with_capacity(66 + 1 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_ht));
    ss.push(OP_0); // selector = burn
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build MarketMint redeemScript (bond-protected).
///
/// State (75B): [0x20][admin_pk 32B][0x20][market_id 32B][0x08][expiry_daa 8B]
/// Body (25B): MARKET_MINT_BODY
/// Total: 100B
///
/// DEPRECATED: Use SplitMerge as sole token issuer.
#[deprecated(note = "C1 vulnerability: use SplitMerge.")]
pub fn build_market_mint_redeem_script(
    admin_pubkey: &[u8; 32],
    market_id: &[u8; 32],
    expiry_daa: u64,
) -> crate::Result<Vec<u8>> {
    if expiry_daa == 0 {
        return Err(crate::KobError::Contract("expiry_daa must be > 0".into()));
    }

    let mut rs = Vec::with_capacity(100);
    rs.push(0x20);
    rs.extend_from_slice(admin_pubkey);
    rs.push(0x20);
    rs.extend_from_slice(market_id);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(expiry_daa));
    rs.extend_from_slice(MARKET_MINT_BODY);
    Ok(rs)
}

