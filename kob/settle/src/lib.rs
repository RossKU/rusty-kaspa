//! Settlement core for KOB and the Kaspa x402 facilitator.
//!
//! Crypto primitives, mass/fee calculation, transaction building, wallet
//! management, the Kaspa RPC client (submit/UTXO/finality), and generic
//! chain-settlement plumbing (on-chain-existence cache, spent-outpoint
//! tracking, RPC payload builders). Zero `kob_domain` references — this
//! crate knows nothing about order books, matching, or any specific
//! covenant product. It is reused by the DEX engine (via re-export from
//! `kob-core`/`kob-engine`, kept for path compatibility) and by `kob-x402`.
//!
//! Extracted from `kob-core` / `kob-engine`; see `kob/x402/X402_STATUS.md`
//! Phase 1 for the extraction notes (in particular: `types.rs` was pulled in
//! too, despite not being on the original clean-file list, because the
//! other clean files hard-depend on it).

#![allow(clippy::too_many_arguments)]

pub mod chain;
pub mod compat;
pub mod config;
pub mod crypto;
pub mod error;
pub mod mass;
pub mod primitives;
pub mod rpc;
pub mod rpc_types;
pub mod tx;
pub mod types;
pub mod utils;
pub mod wallet;

// Flat re-exports preserve the original `kob_core::{bech32,p2sh,sighash,signing}`
// paths used throughout the workspace. Relocating into `crypto/` is a storage
// concern only — the public surface stays flat.
pub use crypto::{bech32, p2sh, sighash, signing};

pub use error::KobError;
pub type Result<T> = std::result::Result<T, KobError>;

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
pub use rpc::RpcClient;

/// Minimum UTXO value to avoid storage mass rejection (~3M sompi).
///
/// Canonical definition (moved from `kob-core`, which now re-exports this).
pub const MIN_UTXO_VALUE: u64 = 3_000_000;

/// Default subnetwork ID (native, all zeros).
///
/// Canonical definition (moved from `kob-core`, which now re-exports this).
pub const SUBNETWORK_ID: &str = "0000000000000000000000000000000000000000";
