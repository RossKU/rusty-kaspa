//! Core types and transaction building for KOB (Kaspa Order Book).

#![allow(clippy::too_many_arguments)]

pub mod contract;
pub mod listing;

// Settlement-core modules now live in `kob-settle` (Phase 1 extraction, see
// kob/x402/X402_STATUS.md). Re-exported here so every existing
// `kob_core::{crypto,error,mass,primitives,tx,types,wallet,compat,rpc_types}`
// path in the workspace keeps resolving unchanged.
pub use kob_settle::crypto;
pub use kob_settle::error;
pub use kob_settle::mass;
pub use kob_settle::primitives;
pub use kob_settle::tx;
pub use kob_settle::types;
pub use kob_settle::wallet;
pub use kob_settle::compat;
pub use kob_settle::rpc_types;

// Flat re-exports preserve the original `kob_core::{bech32,p2sh,sighash,signing}`
// paths used throughout the workspace. Relocating into `crypto/` is a storage
// concern only — the public surface stays flat.
pub use crypto::{bech32, p2sh, sighash, signing};

pub use contract::perp;
pub use contract::prediction;
pub use contract::lending;
pub use contract::insurance;
pub use contract::auction;

pub use error::KobError;
pub type Result<T> = std::result::Result<T, KobError>;

pub use contract::{
    build_receipt_redeem_script, build_receipt_consume_sigscript,
    build_buy_cancel_sigscript, build_sell_cancel_sigscript,
    build_token_mint_redeem_script, build_token_unit_redeem_script,
    build_token_mint_sigscript, build_token_burn_sigscript, build_token_unit_sigscript,
    parse_token_unit_state,
    RECEIPT_BODY, TOKEN_RS,
    TOKEN_MINT_BODY, TOKEN_UNIT_BODY,
    // KCC20
    Kcc20StateHeader, StateField, TokenDescriptor,
    TOKEN_UNIT_STATE_LAYOUT, KCC20_TOKEN_UNIT_DESCRIPTOR,
    NONCE_EXT_ID, NONCE_EXT_OFFSET, NONCE_EXT_LEN,
    OCO_SELL_BODY, OCO_SELL_RS_SIZE, OCO_SELL_STATE_SIZE, OcoPath,
    build_oco_sell_redeem_script,
    build_oco_sell_tp_fill_sigscript, build_oco_sell_sl_fill_sigscript,
    build_oco_sell_tp_fill_sigscript_fixed_offset, build_oco_sell_sl_fill_sigscript_fixed_offset,
    build_oco_sell_cancel_sigscript, build_oco_sell_expire_sigscript,
    // DCA
    DCA_V2_RS_SIZE, DCA_V2_STATE_SIZE, DCA_V2_BODY_SIZE,
    ParsedDcaOrder, parse_dca_order_rs,
    build_dca_order_redeem_script, build_dca_order_fill_sigscript,
    // Swap
    SWAP_ORDER_BODY, SWAP_STATE_SIZE, SWAP_BODY_SIZE, SWAP_RS_SIZE,
    ParsedSwapOrder, parse_swap_order_rs,
    build_swap_redeem_script, build_swap_fill_sigscript, build_swap_cancel_sigscript,
    build_buy_redeem_script, build_sell_redeem_script,
    build_buy_fill_sigscript, build_sell_fill_sigscript,
    build_buy_partial_fill_sigscript, build_sell_partial_fill_sigscript,
    build_buy_expire_sigscript, build_sell_expire_sigscript,
    BUY_ORDER_BODY, SELL_ORDER_BODY,
    build_order_payload, build_oco_order_payload, parse_order_payload,
    KOB_PAYLOAD_PREFIX,
    // Spot parse
    ParsedOrder, ParsedOcoSell, parse_redeem_script, parse_oco_sell_redeem_script,
    has_zk_opcode, OP_ZK_PRECOMPILE,
    BUY_RS_SIZE, SELL_RS_SIZE,
};
pub use p2sh::{blake2b_256, build_p2sh, compute_spk_hash, compute_p2pk_spk_hash};
pub use primitives::{push_data, u16_le, u32_le, u64_le};
pub use sighash::{compute_covenant_id, compute_sighash};
pub use signing::{schnorr_sign, schnorr_sign_secure, get_public_key, get_public_key_secure, schnorr_verify};
pub use types::{Network, Order, OrderSide, Outpoint, Price};
pub use tx::{select_utxos, select_utxos_mass_aware, select_utxos_mass_aware_simple, CoinSelection};
pub use compat::{
    parse_tx_id, tx_id_to_hex, parse_hash, hash_to_hex,
    parse_subnetwork_id, subnetwork_id_to_hex,
    parse_outpoint, outpoint_to_hex,
    covenant_binding_from_hex,
    kob_outpoint_to_kaspa, kaspa_outpoint_to_kob,
};
pub use wallet::{SecureKey, WalletContext, LegacyWalletJson};
pub use wallet::{EncryptedWalletFile, encrypt_wallet, save_encrypted, derive_key_public};
pub use wallet::{HdWallet, WalletFileV2, AccountEntry, WatchOnlyExport, pubkey_to_address};
pub use mass::{
    compute_storage_mass, compute_storage_mass_ex,
    check_storage_mass, check_storage_mass_ex, check_tx_storage_mass,
    check_buy_match_mass, check_sell_match_mass, minimum_sell_min_fill,
    min_penalty_free_output, suggest_deploy_amount,
    calc_compute_mass, calc_miner_fee, converge_fee,
    calc_mass_with_sigscripts, estimate_compute_mass,
    estimate_tx_serialized_size,
    MassError, STORAGE_MASS_PARAMETER, MAX_TX_MASS,
    MASS_PER_TX_BYTE, MASS_PER_SCRIPT_PUB_KEY_BYTE, MASS_PER_SIG_OP,
};
pub use lending::{
    KOB_LENDING_PAYLOAD_PREFIX, DAA_PER_YEAR,
    build_lending_payload, parse_lending_payload,
    LOAN_OFFER_BODY, LOAN_OFFER_STATE_SIZE,
    build_loan_offer_redeem_script,
    build_loan_offer_match_sigscript,
    build_loan_offer_cancel_sigscript,
    build_loan_offer_replace_sigscript,
    BORROW_REQUEST_BODY, BORROW_REQUEST_STATE_SIZE,
    build_borrow_request_redeem_script,
    build_borrow_request_match_sigscript,
    build_borrow_request_cancel_sigscript,
    ACTIVE_LOAN_BODY, ACTIVE_LOAN_STATE_SIZE,
    build_active_loan_redeem_script,
    build_active_loan_repay_sigscript,
    build_active_loan_default_sigscript,
    build_active_loan_liquidate_sigscript,
    calculate_interest, calculate_repay_total,
    // Lending parse
    ParsedLendingOrder, LendingOrderType, parse_lending_rs,
    LOAN_OFFER_RS_SIZE, BORROW_REQUEST_RS_SIZE,
};

pub use auction::{
    KOB_AUCTION_PAYLOAD_PREFIX,
    build_auction_payload, parse_auction_payload,

    ENGLISH_AUCTION_BODY, ENGLISH_AUCTION_STATE_SIZE,
    build_english_auction_redeem_script,
    build_english_bid_sigscript, build_english_expire_sigscript,
    build_english_settle_sigscript, build_english_cancel_sigscript,

    DUTCH_AUCTION_BODY, DUTCH_AUCTION_STATE_SIZE,
    build_dutch_auction_redeem_script,
    build_dutch_buy_sigscript, build_dutch_tick_sigscript, build_dutch_cancel_sigscript,

    AUCTION_ESCROW_BODY, AUCTION_ESCROW_STATE_SIZE,
    build_auction_escrow_redeem_script,
    build_auction_escrow_release_sigscript, build_auction_escrow_cancel_sigscript,
};

/// Default matcher fee (10,000 sompi).
///
/// This is the maximum fee a matcher may extract from order surplus when
/// executing a trade. It is NOT the miner fee. Miner fees are calculated
/// from transaction mass via `mass::calc_miner_fee()`.
pub const DEFAULT_MATCHER_FEE: u64 = 10_000;

/// Minimum UTXO value to avoid storage mass rejection (~3M sompi).
///
/// Canonical definition moved to `kob-settle` (Phase 1 extraction) since
/// `kob_settle::tx` depends on it; re-exported here unchanged.
pub use kob_settle::MIN_UTXO_VALUE;

/// Dust value for trade_receipt outputs.
pub const RECEIPT_DUST: u64 = 3_000_000;

/// Receipt output value (1 KAS = 100M sompi).
pub const RECEIPT_VALUE: u64 = 100_000_000;

/// Default subnetwork ID (native, all zeros).
///
/// Canonical definition moved to `kob-settle` (Phase 1 extraction) since
/// `kob_settle::tx` depends on it; re-exported here unchanged.
pub use kob_settle::SUBNETWORK_ID;
