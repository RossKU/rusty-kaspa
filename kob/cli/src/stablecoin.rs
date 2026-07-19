//! `kob-cli stablecoin` -- KCC-0020 stablecoin (Plan A, native-value) CLI:
//! deploy / mint / transfer (WU-E).
//!
//! # Role
//!
//! This is the spender-side counterpart to WU-A's covenant
//! (`kob_core::contract::stablecoin`) and WU-D's issuer tool
//! ([`crate::attest`]). It builds the three transactions that make up a
//! stablecoin's lifecycle:
//!
//! - **`deploy`** -- genesis of a token series: a `token_mint`-shaped mint
//!   authority whose ADMIN key is fixed to the stablecoin's ISSUER key. This
//!   is the only place the issuer identity for a series is chosen; every coin
//!   minted under it inherits that same `issuer_pubkey` into its attestation
//!   gate.
//! - **`mint`** -- spends the mint authority (unmodified `token_mint` body:
//!   self-continuation + admin signature only) to create a new stablecoin
//!   coin: `build_stablecoin_redeem_script(recipient_pubkey, issuer_pubkey)`
//!   P2SH, native-value KCC20 `amount` (Plan A's UTXO-value mapping, see
//!   `kob_core::contract::stablecoin` module docs).
//! - **`transfer`** -- the 1:1 issuer-attestation-gated spend: input's full
//!   amount moves to a successor coin at the same output index, authorized by
//!   BOTH the owner's SIGHASH_ALL signature and a pre-computed issuer
//!   attestation (`--issuer-sig`, produced offline by `kob-cli attest sign`).
//!
//! # Successor SPK contract with WU-D (repeated from `attest.rs`)
//!
//! `transfer`'s successor output is built with
//! [`crate::attest::build_successor_spk_for_recipient`] -- the EXACT function
//! `attest sign` uses to compute the SPK it attests over. Calling the same
//! function (rather than re-deriving the bytes independently here) is what
//! makes the byte-for-byte match structural instead of a maintained
//! invariant: there is no second implementation to drift out of sync. Before
//! spending anything, `transfer` also locally recomputes the attestation
//! message from the same on-chain facts the covenant will use and verifies
//! `--issuer-sig` against it, so a parameter mismatch (stale amount, wrong
//! successor, wrong outpoint, ...) fails fast offline instead of burning a
//! real transaction attempt.
//!
//! # sig_op_count = 2 (RT-1 lesson)
//!
//! The stablecoin body performs two signature checks per gated spend: an
//! `OpCheckSigVerify` (owner) and an `OpCheckSigFromStack` (issuer
//! attestation). `TxInput::sig_op_count` for that input MUST be `2` --
//! undercounting it (as `RT-1` found for a different covenant) starves the
//! node's compute budget and the spend is rejected even though the script
//! itself is valid. [`build_transfer_tx`] hardcodes this; a unit test below
//! pins it.
//!
//! # Network-free core
//!
//! Following [`crate::attest`]'s split of I/O (`cmd_sign`) from pure
//! computation (`build_attestation`), [`build_transfer_tx`] is a pure,
//! RPC-free function: given already-resolved on-chain facts (UTXO
//! values/scripts), it assembles the complete transaction and both
//! sigscripts. `stablecoin_transfer` is the thin async wrapper that resolves
//! those facts via RPC and calls it (twice, for the standard
//! estimate-then-exact-mass fee convergence used throughout this crate).
//! This is what the unit tests below exercise directly, with no node
//! connection required.

use crate::node::NodeClient;
use crate::signing;
use clap::Subcommand;
use kob_core::contract;
use kob_core::contract::stablecoin::{
    build_attestation_message, build_stablecoin_redeem_script, build_stablecoin_sigscript, check_numeric_domain,
    validate_x_only_pubkey,
};
use kob_core::mass::{calc_mass_with_sigscripts, converge_fee};
use kob_core::p2sh::build_p2sh;
use kob_core::sighash::{compute_covenant_id, compute_sighash};
use kob_core::tx::{to_rpc_payload, AuthOutput, CovenantBinding, Transaction, TxInput, TxOutput};
use kob_core::types::Network;
use kob_core::wallet::WalletContext;
use kob_core::MIN_UTXO_VALUE;
use std::path::Path;
use tracing::info;

#[derive(Subcommand, Debug)]
pub enum StablecoinCommand {
    /// Deploy a new stablecoin token series (genesis): a `token_mint`-shaped
    /// mint authority whose admin key IS the stablecoin's issuer key. This
    /// fixes WHO can mint and WHO must attest every future transfer; it does
    /// NOT fix who may hold a coin (that's `--recipient-pubkey` at mint time).
    ///
    /// EXAMPLE:
    ///   kob-cli stablecoin deploy --issuer-key issuer.key \
    ///       --ticker KUSD --supply 1000000000 --amount 500000000
    Deploy {
        /// Issuer's 32-byte Schnorr private key: 64 hex chars directly, or a
        /// path to a file whose (trimmed) contents are the 64 hex chars
        /// (same resolution as `attest sign --issuer-key`). This key becomes
        /// BOTH the mint authority's admin key (only it can `stablecoin
        /// mint`) and the attestation key baked into every coin minted under
        /// this series (only it can `attest sign` a transfer of them).
        #[arg(long)]
        issuer_key: String,

        /// Ticker symbol (e.g. "KUSD"). Metadata only, not enforced on-chain.
        #[arg(long)]
        ticker: String,

        /// Total supply in base units. Metadata only, not enforced on-chain.
        #[arg(long)]
        supply: u64,

        /// Decimal places (default: 8). Metadata only.
        #[arg(long, default_value = "8")]
        decimals: u8,

        /// KAS amount to lock in the mint-authority UTXO (sompi).
        #[arg(long)]
        amount: u64,
    },

    /// Mint new stablecoin units from the mint authority. Requires the
    /// issuer's private key (the same key supplied to `deploy`).
    ///
    /// EXAMPLE:
    ///   kob-cli stablecoin mint --issuer-key issuer.key \
    ///       --txid <genesis_txid> --index 0 --token <covenant_id> \
    ///       --amount 500000000 --recipient-pubkey <hex>
    Mint {
        /// Issuer's private key (same resolution as `deploy --issuer-key`).
        /// Signs the mint authority's admin sigscript -- WITHOUT this key,
        /// no new units of this series can ever be minted.
        #[arg(long)]
        issuer_key: String,

        /// Mint authority UTXO transaction ID (hex, 64 chars).
        #[arg(long)]
        txid: String,

        /// Mint authority UTXO output index.
        #[arg(long, default_value = "0")]
        index: u32,

        /// Token covenant ID (hex, 64 chars) -- the value `deploy` printed
        /// as "Token ID".
        #[arg(long)]
        token: String,

        /// Amount of sompi to allocate to the new stablecoin coin. This IS
        /// the KCC-0020 `amount` under Plan A's native-value mapping (see
        /// `kob_core::contract::stablecoin` module docs) -- there is no
        /// separate in-script amount field.
        #[arg(long)]
        amount: u64,

        /// Recipient's x-only public key (hex, 64 chars) for the new coin.
        /// Defaults to the operating wallet's own public key.
        #[arg(long)]
        recipient_pubkey: Option<String>,

        /// Fee UTXO outpoint (txid:index) to use instead of auto-selection.
        #[arg(long)]
        fee_utxo: Option<String>,
    },

    /// Transfer a stablecoin coin under the 1:1 issuer-attestation gate. Run
    /// `kob-cli attest sign` first (same --covenant-id/--txid/--index/
    /// --recipient-pubkey/--amount) to obtain `--issuer-sig` for this exact
    /// spend -- without it the covenant hard-aborts (fail-close freeze).
    ///
    /// EXAMPLE:
    ///   kob-cli stablecoin transfer --txid <txid> --index 1 \
    ///       --token <covenant_id> --issuer-pubkey <hex> \
    ///       --recipient-pubkey <hex> --issuer-sig <hex from `attest sign`>
    Transfer {
        /// Stablecoin UTXO transaction ID (hex, 64 chars) being spent.
        #[arg(long)]
        txid: String,

        /// Stablecoin UTXO output index.
        #[arg(long)]
        index: u32,

        /// Token covenant ID (hex, 64 chars) -- must match the value passed
        /// to `attest sign --covenant-id` (it is also what the on-chain
        /// body reads back via `OpInputCovenantId` for this input).
        #[arg(long)]
        token: String,

        /// The token's issuer x-only public key (hex, 64 chars). Fixes both
        /// the owner's current stablecoin P2SH (`f(owner_pubkey,
        /// issuer_pubkey)`, used for UTXO discovery) and the successor's.
        #[arg(long)]
        issuer_pubkey: String,

        /// Recipient's x-only public key (hex, 64 chars): the new owner of
        /// the successor coin.
        #[arg(long)]
        recipient_pubkey: String,

        /// The issuer's 64-byte attestation signature (hex, 128 chars) from
        /// `kob-cli attest sign` for this exact spend. Verified locally
        /// against the recomputed attestation message before anything is
        /// submitted.
        #[arg(long)]
        issuer_sig: String,

        /// Fee UTXO outpoint (txid:index) to use instead of auto-selection.
        #[arg(long)]
        fee_utxo: Option<String>,
    },
}

/// Resolve `--issuer-key` into a 32-byte private key: either 64 hex chars
/// directly, or a path to a file whose (trimmed) contents are the 64 hex
/// chars. Local copy of `attest::resolve_issuer_key` (private to that
/// module; duplicated here the same way `attest.rs` duplicates
/// `lib.rs`'s private `parse_hash32` rather than exposing it).
fn resolve_issuer_key(arg: &str) -> anyhow::Result<[u8; 32]> {
    let trimmed = arg.trim();
    let looks_like_hex = trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit());
    let hex_str = if looks_like_hex {
        trimmed.to_string()
    } else {
        let contents = std::fs::read_to_string(trimmed)
            .map_err(|e| anyhow::anyhow!("--issuer-key '{trimmed}' is neither 64 hex chars nor a readable key file: {e}"))?;
        contents.trim().to_string()
    };
    let bytes = hex::decode(&hex_str).map_err(|e| anyhow::anyhow!("issuer key is not valid hex: {e}"))?;
    if bytes.len() != 32 {
        anyhow::bail!("issuer private key must be 32 bytes (64 hex chars), got {} bytes", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Derive and validate the issuer's x-only public key from their resolved
/// private key -- re-checked through the same WU-A gate `attest::
/// build_attestation` applies, so a malformed key is rejected here rather
/// than baked into a covenant that can never be spent from.
fn resolve_issuer_pubkey(issuer_privkey: &[u8; 32]) -> anyhow::Result<[u8; 32]> {
    let pk = crate::signing::derive_pubkey(issuer_privkey)?;
    validate_x_only_pubkey(&pk).map_err(|e| anyhow::anyhow!("issuer pubkey invalid: {e}"))
}

/// Deploy a new stablecoin token series (genesis): identical TX shape to
/// `token create`, with the mint authority's admin key parameterized to the
/// stablecoin issuer's key instead of the operating wallet's key.
///
/// TX layout:
/// - Input[0]: wallet P2PK UTXO (funding)
/// - Output[0]: mint-authority P2SH UTXO (CovenantBinding -> new covenant_id;
///   admin key = issuer_pubkey)
/// - Output[1]: change back to wallet (if sufficient)
#[allow(clippy::too_many_arguments)]
pub async fn stablecoin_deploy(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    issuer_key_arg: &str,
    ticker: &str,
    supply: u64,
    decimals: u8,
    amount: u64,
) -> anyhow::Result<()> {
    let wallet = WalletContext::load(wallet_path)?;
    let funding_privkey = *wallet.privkey_bytes();

    let issuer_privkey = resolve_issuer_key(issuer_key_arg)?;
    let issuer_pubkey = resolve_issuer_pubkey(&issuer_privkey)?;

    // Mint authority: identical shape to `token create`'s genesis, admin key
    // = issuer_pubkey (so only the issuer can ever mint under this series).
    let mint_rs = contract::build_token_mint_redeem_script(&issuer_pubkey);
    let p2sh = build_p2sh(&mint_rs);

    println!("KCC-0020 Stablecoin Deploy (Genesis)");
    println!("=====================================");
    println!("Ticker:         {}", ticker);
    println!("Supply:         {} (metadata, not enforced on-chain)", supply);
    println!("Decimals:       {}", decimals);
    println!("Amount:         {} sompi ({:.8} KAS)", amount, amount as f64 / 1e8);
    println!("Issuer pubkey:  {} (x-only)", hex::encode(issuer_pubkey));
    println!("  -> must sign every `stablecoin mint` for this series and");
    println!("     every `attest sign` for coins minted under it.");
    println!("Funding wallet: {}", wallet.pubkey_hex());
    println!();
    println!("Mint-authority RS:       {} bytes", mint_rs.len());
    println!("Mint-authority P2SH SPK: {}", hex::encode(p2sh.script()));
    println!();

    if amount < MIN_UTXO_VALUE {
        anyhow::bail!(
            "Amount {} sompi is below MIN_UTXO_VALUE ({}). Use at least {} sompi.",
            amount,
            MIN_UTXO_VALUE,
            MIN_UTXO_VALUE
        );
    }

    info!(address = %wallet.address, amount = amount, issuer_pubkey = %hex::encode(issuer_pubkey), "deploying stablecoin mint authority");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    let utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let est_fee_pre = kob_core::mass::estimate_compute_mass(1, 2, 0);
    let needed = amount + est_fee_pre + MIN_UTXO_VALUE;

    let mut candidates: Vec<_> = utxos.iter().filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= needed).collect();
    candidates.sort_by(|a, b| a.utxo_entry.amount.cmp(&b.utxo_entry.amount));
    if candidates.is_empty() {
        candidates = utxos.iter().filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= amount + est_fee_pre).collect();
        candidates.sort_by(|a, b| a.utxo_entry.amount.cmp(&b.utxo_entry.amount));
    }
    let funding = candidates
        .first()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("No P2PK UTXO with >= {} sompi found ({} UTXOs available)", needed, utxos.len()))?;

    println!(
        "Funding UTXO: {}:{} ({} sompi)",
        funding.outpoint.transaction_id, funding.outpoint.index, funding.utxo_entry.amount
    );

    let covenant_id = compute_covenant_id(
        &funding.outpoint.transaction_id,
        funding.outpoint.index,
        &[AuthOutput { index: 0, value: amount, spk_version: p2sh.version, spk_script: p2sh.script().to_vec() }],
    )?;
    let covenant_id_hex = hex::encode(covenant_id);
    println!("Token ID:   {}", covenant_id_hex);
    println!();

    let mut tx = Transaction::new(1);
    let spk_bytes = funding.script_bytes();
    tx.inputs.push(TxInput {
        prev_tx_id: funding.outpoint.transaction_id.clone(),
        prev_index: funding.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: funding.utxo_entry.script_public_key.version,
        script_bytes: spk_bytes,
        value: funding.utxo_entry.amount,
    });

    tx.outputs.push(TxOutput::new(
        amount,
        p2sh.version,
        p2sh.script().to_vec(),
        Some(CovenantBinding::new(0, kob_core::compat::parse_hash(&covenant_id_hex)?)),
    ));

    let total_in = funding.utxo_entry.amount;
    let tent_change = total_in.saturating_sub(amount + est_fee_pre);
    let wallet_spk = hex::decode(&funding.utxo_entry.script_public_key.script)?;
    if tent_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(tent_change, funding.utxo_entry.script_public_key.version, wallet_spk.clone(), None));
    }

    let has_change = tx.outputs.len() > 1;
    let change_idx = tx.outputs.len().saturating_sub(1);
    let (est_fee, _) =
        if has_change { converge_fee(&mut tx, total_in, change_idx, 0) } else { (kob_core::mass::calc_miner_fee(&tx), 0) };

    if has_change && tx.outputs.last().unwrap().value < MIN_UTXO_VALUE {
        let change_val = tx.outputs.last().unwrap().value;
        tx.outputs.pop();
        if change_val > 0 {
            println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", change_val);
        }
    }

    let sighash = compute_sighash(&tx, 0)?;
    let signature = signing::schnorr_sign(&funding_privkey, &sighash)?;
    let sigscript = signing::build_p2pk_sigscript(&signature);

    let exact_mass = calc_mass_with_sigscripts(&tx, &[sigscript.clone()]);
    let exact_fee = kob_core::mass::min_relay_fee(exact_mass);
    let sigscript = if exact_fee != est_fee && tx.outputs.len() > 1 {
        let change_idx = tx.outputs.len() - 1;
        let new_change = total_in.saturating_sub(amount + exact_fee);
        if new_change >= MIN_UTXO_VALUE {
            tx.outputs[change_idx].value = new_change;
        } else {
            tx.outputs.pop();
            if new_change > 0 {
                println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", new_change);
            }
        }
        let sighash = compute_sighash(&tx, 0)?;
        let signature = signing::schnorr_sign(&funding_privkey, &sighash)?;
        signing::build_p2pk_sigscript(&signature)
    } else {
        sigscript
    };

    println!("Fee: {} sompi", if exact_fee != est_fee { exact_fee } else { est_fee });
    println!();

    let payload = to_rpc_payload(&tx, &[sigscript]);
    println!("Submitting transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Stablecoin series deployed.");
    println!("TXID:           {}", tx_id);
    println!("Token ID:       {}", covenant_id_hex);
    println!("Mint authority: {}:0", tx_id);
    println!();
    println!("Next steps:");
    println!(
        "  1. Mint:     kob-cli stablecoin mint --issuer-key <key> --txid {} --index 0 --token {} --amount <AMT> --recipient-pubkey <hex>",
        tx_id, covenant_id_hex
    );
    println!(
        "  2. Transfer: kob-cli stablecoin transfer --txid <TXID> --index 1 --token {} --issuer-pubkey {} --recipient-pubkey <hex> --issuer-sig <hex from `attest sign`>",
        covenant_id_hex,
        hex::encode(issuer_pubkey)
    );

    Ok(())
}

/// Mint new stablecoin units from the mint authority. `token_mint`'s
/// covenant body runs UNMODIFIED (self-continuation + admin signature only
/// -- it does not know or care what output[1]'s script is); only the second
/// output's construction is replaced with the stablecoin's
/// issuer-attestation-gated P2SH instead of a plain `token_unit`.
///
/// TX layout:
/// - Input[0]: mint-authority P2SH UTXO (sig_op_count=1, issuer/admin sig)
/// - Input[1]: wallet P2PK UTXO (fee + stablecoin funding)
/// - Output[0]: updated mint authority (same P2SH, reduced value, covenant binding)
/// - Output[1]: new stablecoin coin (stablecoin P2SH for recipient, covenant binding)
/// - Output[2]: change from fee UTXO back to wallet
#[allow(clippy::too_many_arguments)]
pub async fn stablecoin_mint(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    issuer_key_arg: &str,
    mint_txid: &str,
    mint_index: u32,
    token_covenant_id: &str,
    token_amount: u64,
    recipient_pubkey_hex: Option<&str>,
    fee_utxo_override: Option<&str>,
) -> anyhow::Result<()> {
    let wallet = WalletContext::load(wallet_path)?;
    let wallet_pubkey = wallet.pubkey;
    let fee_privkey = *wallet.privkey_bytes();

    let token_cov_bytes = hex::decode(token_covenant_id)?;
    if token_cov_bytes.len() != 32 {
        anyhow::bail!("token covenant ID must be 64 hex characters (32 bytes)");
    }

    let issuer_privkey = resolve_issuer_key(issuer_key_arg)?;
    let issuer_pubkey = resolve_issuer_pubkey(&issuer_privkey)?;

    let recipient_pk: [u8; 32] = if let Some(rp_hex) = recipient_pubkey_hex {
        let rp_bytes = hex::decode(rp_hex)?;
        validate_x_only_pubkey(&rp_bytes).map_err(|e| anyhow::anyhow!("--recipient-pubkey invalid: {e}"))?
    } else {
        wallet_pubkey
    };

    // Mint authority: admin key = issuer_pubkey (must match `deploy`'s).
    let mint_rs = contract::build_token_mint_redeem_script(&issuer_pubkey);
    let mint_p2sh = build_p2sh(&mint_rs);

    // The new coin: stablecoin body instead of token_unit -- the ONLY
    // substitution relative to `token_mint`'s output[1].
    let stable_rs = build_stablecoin_redeem_script(&recipient_pk, &issuer_pubkey);
    let stable_p2sh = build_p2sh(&stable_rs);

    println!("KCC-0020 Stablecoin Mint");
    println!("=========================");
    println!("Token ID:         {}", token_covenant_id);
    println!("Mint Authority:   {}:{}", mint_txid, mint_index);
    println!("Amount:           {} sompi ({:.8} KAS equivalent)", token_amount, token_amount as f64 / 1e8);
    println!("Recipient PK:     {}", hex::encode(recipient_pk));
    println!("Issuer pubkey:    {} (x-only)", hex::encode(issuer_pubkey));
    println!();
    println!("Mint RS:          {} bytes", mint_rs.len());
    println!("Mint P2SH:        {}", hex::encode(mint_p2sh.script()));
    println!("Stablecoin RS:    {} bytes", stable_rs.len());
    println!("Stablecoin P2SH:  {}", hex::encode(stable_p2sh.script()));
    println!();

    if token_amount < MIN_UTXO_VALUE {
        anyhow::bail!("Token amount {} sompi is below MIN_UTXO_VALUE ({})", token_amount, MIN_UTXO_VALUE);
    }

    info!(mint_txid = %mint_txid, mint_index = mint_index, token = %token_covenant_id, "minting stablecoin units");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    let mint_addr = crate::cancel::kaspa_address_encode(network.address_prefix(), 8, &mint_p2sh.script()[2..34]);
    println!("Querying mint authority at {}...", &mint_addr[..40]);
    let mint_utxos = rpc.get_utxos_by_addresses(&[&mint_addr]).await?;
    let mint_utxo = mint_utxos
        .iter()
        .find(|u| u.outpoint.transaction_id == mint_txid && u.outpoint.index == mint_index)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Mint authority UTXO {}:{} not found at {}. Check txid/index and --issuer-key.",
                mint_txid,
                mint_index,
                mint_addr
            )
        })?;

    let mint_value = mint_utxo.utxo_entry.amount;
    println!("Mint UTXO:        {}:{} ({} sompi)", mint_utxo.outpoint.transaction_id, mint_utxo.outpoint.index, mint_value);

    let est_fee_pre = kob_core::mass::estimate_compute_mass(2, 3, 0);
    let mint_continuation_value = mint_value.saturating_sub(est_fee_pre);
    if mint_continuation_value < MIN_UTXO_VALUE {
        anyhow::bail!(
            "Mint continuation value {} sompi would be below MIN_UTXO_VALUE. Mint authority nearly exhausted.",
            mint_continuation_value
        );
    }

    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let needed_from_fee = token_amount + est_fee_pre;
    let fee_utxo = if let Some(fee_op_str) = fee_utxo_override {
        let fee_op = kob_core::types::Outpoint::parse(fee_op_str)?;
        wallet_utxos
            .iter()
            .find(|u| u.outpoint.transaction_id == fee_op.transaction_id && u.outpoint.index == fee_op.index)
            .ok_or_else(|| anyhow::anyhow!("Fee UTXO {} not found in wallet UTXOs.", fee_op_str))?
    } else {
        wallet_utxos
            .iter()
            .filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= needed_from_fee)
            .min_by_key(|u| u.utxo_entry.amount)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No P2PK UTXO with >= {} sompi for stablecoin funding + fee ({} UTXOs available)",
                    needed_from_fee,
                    wallet_utxos.len()
                )
            })?
    };

    println!("Fee UTXO:         {}:{} ({} sompi)", fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount);

    let mut tx = Transaction::new(1);

    tx.inputs.push(TxInput {
        prev_tx_id: mint_utxo.outpoint.transaction_id.clone(),
        prev_index: mint_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: mint_p2sh.version,
        script_bytes: mint_p2sh.script().to_vec(),
        value: mint_value,
    });

    let fee_spk_bytes = fee_utxo.script_bytes();
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_spk_bytes,
        value: fee_utxo.utxo_entry.amount,
    });

    tx.outputs.push(TxOutput::new(
        mint_continuation_value,
        mint_p2sh.version,
        mint_p2sh.script().to_vec(),
        Some(CovenantBinding::new(0, kob_core::compat::parse_hash(token_covenant_id)?)),
    ));
    tx.outputs.push(TxOutput::new(
        token_amount,
        stable_p2sh.version,
        stable_p2sh.script().to_vec(),
        Some(CovenantBinding::new(0, kob_core::compat::parse_hash(token_covenant_id)?)),
    ));

    let total_in = mint_value + fee_utxo.utxo_entry.amount;
    let fixed_sum = mint_continuation_value + token_amount;
    let tent_fee_change = total_in.saturating_sub(fixed_sum + est_fee_pre);
    let wallet_spk = hex::decode(&fee_utxo.utxo_entry.script_public_key.script)?;
    if tent_fee_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(tent_fee_change, fee_utxo.utxo_entry.script_public_key.version, wallet_spk.clone(), None));
    }

    let has_change = tx.outputs.len() > 2;
    let change_idx = tx.outputs.len().saturating_sub(1);
    let (est_fee, _) =
        if has_change { converge_fee(&mut tx, total_in, change_idx, 0) } else { (kob_core::mass::calc_miner_fee(&tx), 0) };

    if has_change && tx.outputs.last().unwrap().value < MIN_UTXO_VALUE {
        let change_val = tx.outputs.last().unwrap().value;
        tx.outputs.pop();
        if change_val > 0 {
            println!("Fee change {} sompi below MIN_UTXO_VALUE, donated as fee.", change_val);
        }
    }

    let sighash_0 = compute_sighash(&tx, 0)?;
    let sig_0 = signing::schnorr_sign(&issuer_privkey, &sighash_0)?;
    let sigscript_0 = contract::build_token_mint_sigscript(&sig_0, &mint_rs);

    let sighash_1 = compute_sighash(&tx, 1)?;
    let sig_1 = signing::schnorr_sign(&fee_privkey, &sighash_1)?;
    let sigscript_1 = signing::build_p2pk_sigscript(&sig_1);

    let exact_mass = calc_mass_with_sigscripts(&tx, &[sigscript_0.clone(), sigscript_1.clone()]);
    let exact_fee = kob_core::mass::min_relay_fee(exact_mass);

    let (sigscript_0, sigscript_1) = if exact_fee != est_fee && tx.outputs.len() > 2 {
        let change_idx = tx.outputs.len() - 1;
        let new_change = total_in.saturating_sub(fixed_sum + exact_fee);
        if new_change >= MIN_UTXO_VALUE {
            tx.outputs[change_idx].value = new_change;
        } else {
            tx.outputs.pop();
            if new_change > 0 {
                println!("Fee change {} sompi below MIN_UTXO_VALUE, donated as fee.", new_change);
            }
        }
        let sighash_0 = compute_sighash(&tx, 0)?;
        let sig_0 = signing::schnorr_sign(&issuer_privkey, &sighash_0)?;
        let sigscript_0 = contract::build_token_mint_sigscript(&sig_0, &mint_rs);
        let sighash_1 = compute_sighash(&tx, 1)?;
        let sig_1 = signing::schnorr_sign(&fee_privkey, &sighash_1)?;
        let sigscript_1 = signing::build_p2pk_sigscript(&sig_1);
        (sigscript_0, sigscript_1)
    } else {
        (sigscript_0, sigscript_1)
    };

    println!("Sighash[0]: {} (mint authority, issuer-signed)", hex::encode(compute_sighash(&tx, 0)?));
    println!("Sighash[1]: {} (fee)", hex::encode(compute_sighash(&tx, 1)?));
    println!();

    let payload = to_rpc_payload(&tx, &[sigscript_0, sigscript_1]);
    println!("Submitting stablecoin mint transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Stablecoin units minted.");
    println!("TXID:            {}", tx_id);
    println!("Mint cont:       {}:0 ({} sompi)", tx_id, mint_continuation_value);
    println!("Stablecoin unit: {}:1 ({} sompi) owner={}", tx_id, token_amount, hex::encode(recipient_pk));
    if tx.outputs.len() > 2 {
        println!("Fee change:      {}:2 ({} sompi)", tx_id, tx.outputs[2].value);
    }
    println!();
    println!(
        "Next: kob-cli stablecoin transfer --txid {} --index 1 --token {} --issuer-pubkey {} --recipient-pubkey <new_owner_hex> --issuer-sig <hex from `attest sign`>",
        tx_id,
        token_covenant_id,
        hex::encode(issuer_pubkey)
    );

    Ok(())
}

/// Pure, network-free assembly of a stablecoin transfer TX: the two inputs
/// (gated stablecoin coin + fee P2PK) and the successor output (recipient's
/// stablecoin coin at the SAME index as the gated input, full amount, +
/// optional fee change), fully signed. No RPC inside this function --
/// callers (the `stablecoin_transfer` CLI entry point below, and the unit
/// tests) supply every on-chain fact already resolved.
///
/// The successor's scriptPublicKey is built with the SAME
/// `build_stablecoin_redeem_script` + `build_p2sh` call
/// [`crate::attest::build_successor_spk_for_recipient`] uses -- there is no
/// independent re-implementation of that byte layout to drift out of sync.
#[allow(clippy::too_many_arguments)]
pub fn build_transfer_tx(
    owner_pubkey: &[u8; 32],
    owner_privkey: &[u8; 32],
    issuer_pubkey: &[u8; 32],
    issuer_sig: &[u8; 64],
    recipient_pubkey: &[u8; 32],
    token_covenant_id_hex: &str,
    stable_txid: &str,
    stable_index: u32,
    stable_value: u64,
    stable_script_version: u16,
    stable_script_bytes: Vec<u8>,
    fee_txid: &str,
    fee_index: u32,
    fee_value: u64,
    fee_script_version: u16,
    fee_script_bytes: Vec<u8>,
    miner_fee: u64,
) -> anyhow::Result<(Transaction, Vec<u8>, Vec<u8>)> {
    let owner_rs = build_stablecoin_redeem_script(owner_pubkey, issuer_pubkey);
    let recipient_rs = build_stablecoin_redeem_script(recipient_pubkey, issuer_pubkey);
    let recipient_p2sh = build_p2sh(&recipient_rs);
    let covenant_id = kob_core::compat::parse_hash(token_covenant_id_hex)?;

    let mut tx = Transaction::new(1);

    // Input 0: the gated stablecoin coin. sig_op_count MUST be 2 -- one
    // OpCheckSigVerify (owner) + one OpCheckSigFromStack (issuer
    // attestation). RT-1's lesson: undercounting this starves the node's
    // compute budget and a script-valid spend still gets rejected.
    tx.inputs.push(TxInput {
        prev_tx_id: stable_txid.to_string(),
        prev_index: stable_index,
        sequence: 0,
        sig_op_count: 2,
        script_version: stable_script_version,
        script_bytes: stable_script_bytes,
        value: stable_value,
    });

    // Input 1: fee P2PK UTXO, unrelated to the gate.
    tx.inputs.push(TxInput {
        prev_tx_id: fee_txid.to_string(),
        prev_index: fee_index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_script_version,
        script_bytes: fee_script_bytes.clone(),
        value: fee_value,
    });

    // Output 0: successor at the SAME index as the gated input (WU-A's 1:1
    // shape), binding the input's FULL amount -- no split/change on the
    // stablecoin side.
    tx.outputs.push(TxOutput::new(
        stable_value,
        recipient_p2sh.version,
        recipient_p2sh.script().to_vec(),
        Some(CovenantBinding::new(0, covenant_id)),
    ));

    // Output 1: fee change, only if it clears the dust floor.
    let total_in = stable_value.saturating_add(fee_value);
    let fee_change = total_in.saturating_sub(stable_value.saturating_add(miner_fee));
    if fee_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(fee_change, fee_script_version, fee_script_bytes, None));
    }

    let sighash_0 = compute_sighash(&tx, 0)?;
    let owner_sig = signing::schnorr_sign(owner_privkey, &sighash_0)?;
    let sigscript_0 = build_stablecoin_sigscript(&owner_sig, issuer_sig, &owner_rs);

    let sighash_1 = compute_sighash(&tx, 1)?;
    let fee_sig = signing::schnorr_sign(owner_privkey, &sighash_1)?;
    let sigscript_1 = signing::build_p2pk_sigscript(&fee_sig);

    Ok((tx, sigscript_0, sigscript_1))
}

/// Transfer a stablecoin coin to a new owner under the 1:1
/// issuer-attestation gate. Fee is paid from a separate wallet P2PK UTXO,
/// exactly as `token transfer` does. See module docs for the pre-submission
/// local verification of `--issuer-sig`.
#[allow(clippy::too_many_arguments)]
pub async fn stablecoin_transfer(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    txid: &str,
    index: u32,
    token_covenant_id: &str,
    issuer_pubkey_hex: &str,
    recipient_pubkey_hex: &str,
    issuer_sig_hex: &str,
    fee_utxo_override: Option<&str>,
) -> anyhow::Result<()> {
    let wallet = WalletContext::load(wallet_path)?;
    let owner_pubkey = wallet.pubkey;
    let owner_privkey = *wallet.privkey_bytes();

    let token_cov_bytes = hex::decode(token_covenant_id)?;
    if token_cov_bytes.len() != 32 {
        anyhow::bail!("token covenant ID must be 64 hex characters (32 bytes)");
    }
    let mut covenant_id_arr = [0u8; 32];
    covenant_id_arr.copy_from_slice(&token_cov_bytes);

    let issuer_pubkey =
        validate_x_only_pubkey(&hex::decode(issuer_pubkey_hex)?).map_err(|e| anyhow::anyhow!("--issuer-pubkey invalid: {e}"))?;
    let recipient_pubkey = validate_x_only_pubkey(&hex::decode(recipient_pubkey_hex)?)
        .map_err(|e| anyhow::anyhow!("--recipient-pubkey invalid: {e}"))?;

    let issuer_sig_bytes = hex::decode(issuer_sig_hex)?;
    if issuer_sig_bytes.len() != 64 {
        anyhow::bail!("--issuer-sig must be 128 hex characters (64 bytes), got {} bytes", issuer_sig_bytes.len());
    }
    let mut issuer_sig = [0u8; 64];
    issuer_sig.copy_from_slice(&issuer_sig_bytes);

    let txid_bytes = hex::decode(txid)?;
    if txid_bytes.len() != 32 {
        anyhow::bail!("--txid must be 64 hex characters (32 bytes)");
    }
    let mut txid_arr = [0u8; 32];
    txid_arr.copy_from_slice(&txid_bytes);

    let owner_rs = build_stablecoin_redeem_script(&owner_pubkey, &issuer_pubkey);
    let owner_p2sh = build_p2sh(&owner_rs);

    println!("KCC-0020 Stablecoin Transfer");
    println!("=============================");
    println!("Token ID:      {}", token_covenant_id);
    println!("Source:        {}:{}", txid, index);
    println!("Owner:         {} (x-only)", wallet.pubkey_hex());
    println!("Recipient:     {}", hex::encode(recipient_pubkey));
    println!("Issuer pubkey: {}", hex::encode(issuer_pubkey));
    println!();
    println!("Owner stablecoin P2SH: {}", hex::encode(owner_p2sh.script()));
    println!();

    info!(txid = %txid, index = index, token = %token_covenant_id, "transferring stablecoin");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    let p2sh_address = crate::cancel::p2sh_to_address(&owner_p2sh.script(), network.address_prefix());
    println!("Owner P2SH Address: {}", p2sh_address);
    let p2sh_utxos = rpc.get_utxos_by_addresses(&[&p2sh_address]).await?;

    let stable_utxo = p2sh_utxos.iter().find(|u| u.outpoint.transaction_id == txid && u.outpoint.index == index).ok_or_else(|| {
        anyhow::anyhow!(
            "Stablecoin UTXO {}:{} not found at P2SH address {}. It may have been spent, or \
             --issuer-pubkey doesn't match this coin's actual issuer.",
            txid,
            index,
            p2sh_address
        )
    })?;

    let amount = stable_utxo.utxo_entry.amount;
    println!("Stablecoin UTXO: {}:{} ({} sompi)", stable_utxo.outpoint.transaction_id, stable_utxo.outpoint.index, amount);

    check_numeric_domain(index, amount).map_err(|e| anyhow::anyhow!("{e}"))?;

    // Recompute the successor SPK and attestation message the SAME way WU-D
    // did, then verify --issuer-sig locally BEFORE spending anything -- a
    // mismatch here means the on-chain OpCheckSigFromStack would reject too.
    let successor_spk = crate::attest::build_successor_spk_for_recipient(&recipient_pubkey, &issuer_pubkey);
    let attestation_message = build_attestation_message(&covenant_id_arr, &txid_arr, index, &successor_spk, amount);

    let sig_valid = kob_core::signing::schnorr_verify(&attestation_message, &issuer_sig, &issuer_pubkey)?;
    if !sig_valid {
        anyhow::bail!(
            "--issuer-sig does not verify against the locally recomputed attestation message \
             (covenant_id={}, txid={}, index={}, amount={}, successor_spk={}). This spend would \
             be rejected on-chain -- re-run `kob-cli attest sign` with these exact parameters.",
            token_covenant_id,
            txid,
            index,
            amount,
            hex::encode(&successor_spk)
        );
    }
    println!("issuer_sig verified locally against the recomputed attestation message.");
    println!();

    let all_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let est_fee_pre = kob_core::mass::estimate_compute_mass(2, 2, 0);

    let fee_utxo = if let Some(fee_op_str) = fee_utxo_override {
        let fee_op = kob_core::types::Outpoint::parse(fee_op_str)?;
        all_utxos
            .iter()
            .find(|u| u.outpoint.transaction_id == fee_op.transaction_id && u.outpoint.index == fee_op.index)
            .ok_or_else(|| anyhow::anyhow!("Fee UTXO {} not found in wallet UTXOs.", fee_op_str))?
    } else {
        all_utxos
            .iter()
            .filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= est_fee_pre + MIN_UTXO_VALUE)
            .min_by_key(|u| u.utxo_entry.amount)
            .or_else(|| all_utxos.iter().filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= est_fee_pre).min_by_key(|u| u.utxo_entry.amount))
            .ok_or_else(|| anyhow::anyhow!("No P2PK UTXO with >= {} sompi for fees ({} UTXOs available)", est_fee_pre, all_utxos.len()))?
    };

    println!("Fee UTXO: {}:{} ({} sompi)", fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount);

    let (mut tx, mut sigscript_0, mut sigscript_1) = build_transfer_tx(
        &owner_pubkey,
        &owner_privkey,
        &issuer_pubkey,
        &issuer_sig,
        &recipient_pubkey,
        token_covenant_id,
        txid,
        index,
        amount,
        stable_utxo.utxo_entry.script_public_key.version,
        stable_utxo.script_bytes(),
        &fee_utxo.outpoint.transaction_id,
        fee_utxo.outpoint.index,
        fee_utxo.utxo_entry.amount,
        fee_utxo.utxo_entry.script_public_key.version,
        fee_utxo.script_bytes(),
        est_fee_pre,
    )?;

    let exact_mass = calc_mass_with_sigscripts(&tx, &[sigscript_0.clone(), sigscript_1.clone()]);
    let exact_fee = kob_core::mass::min_relay_fee(exact_mass);
    if exact_fee != est_fee_pre {
        let (tx2, s0, s1) = build_transfer_tx(
            &owner_pubkey,
            &owner_privkey,
            &issuer_pubkey,
            &issuer_sig,
            &recipient_pubkey,
            token_covenant_id,
            txid,
            index,
            amount,
            stable_utxo.utxo_entry.script_public_key.version,
            stable_utxo.script_bytes(),
            &fee_utxo.outpoint.transaction_id,
            fee_utxo.outpoint.index,
            fee_utxo.utxo_entry.amount,
            fee_utxo.utxo_entry.script_public_key.version,
            fee_utxo.script_bytes(),
            exact_fee,
        )?;
        tx = tx2;
        sigscript_0 = s0;
        sigscript_1 = s1;
    }

    println!("Sighash[0]: {} (stablecoin, owner-signed)", hex::encode(compute_sighash(&tx, 0)?));
    println!("Sighash[1]: {} (fee)", hex::encode(compute_sighash(&tx, 1)?));
    println!();

    let payload = to_rpc_payload(&tx, &[sigscript_0, sigscript_1]);
    println!("Submitting transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Stablecoin transferred.");
    println!("TXID: {}", tx_id);
    println!("To:   {} ({}:0, {} sompi)", hex::encode(recipient_pubkey), tx_id, amount);
    if tx.outputs.len() > 1 {
        println!("Fee change: {}:1 ({} sompi, back to sender)", tx_id, tx.outputs[1].value);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same fixed test key `signing.rs`/`attest.rs` use for their own tests.
    fn owner_privkey() -> [u8; 32] {
        let hex = "ae4ef0f30537c81653c2213b4b1ad84053fec52c547cb590277a7015850359a4";
        let bytes = hex::decode(hex).unwrap();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    fn dummy_p2pk_spk(byte: u8) -> Vec<u8> {
        let mut spk = vec![0x20];
        spk.extend_from_slice(&[byte; 32]);
        spk.push(0xac);
        spk
    }

    /// Build a transfer tx with fixed, deterministic dummy on-chain facts.
    /// `issuer_sig` need not verify for these structural tests -- only
    /// `build_stablecoin_sigscript`'s exact bytes and the tx shape matter.
    fn sample_transfer(
        owner_pubkey: [u8; 32],
        issuer_pubkey: [u8; 32],
        recipient_pubkey: [u8; 32],
    ) -> (Transaction, Vec<u8>, Vec<u8>, [u8; 64]) {
        let owner_privkey = owner_privkey();
        let issuer_sig = [0x77u8; 64];
        let token_covenant_id = "11".repeat(32);
        let stable_txid = "22".repeat(32);
        let fee_txid = "33".repeat(32);
        let owner_rs = build_stablecoin_redeem_script(&owner_pubkey, &issuer_pubkey);
        let owner_p2sh = build_p2sh(&owner_rs);

        let (tx, s0, s1) = build_transfer_tx(
            &owner_pubkey,
            &owner_privkey,
            &issuer_pubkey,
            &issuer_sig,
            &recipient_pubkey,
            &token_covenant_id,
            &stable_txid,
            0,
            500_000_000,
            owner_p2sh.version,
            owner_p2sh.script().to_vec(),
            &fee_txid,
            0,
            10_000_000,
            0,
            dummy_p2pk_spk(0x99),
            2_000_000,
        )
        .unwrap();
        (tx, s0, s1, issuer_sig)
    }

    #[test]
    fn resolve_issuer_key_accepts_hex() {
        let hex_key = "11".repeat(32);
        let resolved = resolve_issuer_key(&hex_key).unwrap();
        assert_eq!(resolved, [0x11u8; 32]);
    }

    #[test]
    fn resolve_issuer_key_accepts_file() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("kob_stablecoin_test_key_{}.txt", std::process::id()));
        std::fs::write(&path, format!("{}\n", "22".repeat(32))).unwrap();
        let resolved = resolve_issuer_key(path.to_str().unwrap()).unwrap();
        assert_eq!(resolved, [0x22u8; 32]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn resolve_issuer_key_rejects_garbage() {
        assert!(resolve_issuer_key("not-a-key-and-not-a-file-path").is_err());
    }

    #[test]
    fn resolve_issuer_pubkey_matches_derive_pubkey() {
        let privkey = owner_privkey();
        let expected = crate::signing::derive_pubkey(&privkey).unwrap();
        assert_eq!(resolve_issuer_pubkey(&privkey).unwrap(), expected);
    }

    /// Deploy/mint's mint authority MUST be keyed to the issuer's pubkey,
    /// not some other admin -- this is the "genesis fixes the issuer"
    /// contract the CLI spec calls for.
    #[test]
    fn mint_authority_is_keyed_to_issuer_pubkey() {
        let issuer_pubkey = [0x5cu8; 32];
        let mint_rs = contract::build_token_mint_redeem_script(&issuer_pubkey);
        // token_mint's redeemScript layout: push32, pubkey, then TOKEN_MINT_BODY.
        assert_eq!(&mint_rs[1..33], &issuer_pubkey);
        // A different admin key yields a different mint authority (and thus a
        // different P2SH address) -- deploy's issuer_pubkey parameterization
        // is load-bearing, not cosmetic.
        let other_rs = contract::build_token_mint_redeem_script(&[0x5du8; 32]);
        assert_ne!(mint_rs, other_rs);
    }

    /// The stablecoin output `mint` constructs must be byte-identical to
    /// calling WU-A's builder directly with (recipient_pubkey, issuer_pubkey).
    #[test]
    fn mint_output_matches_core_stablecoin_builder() {
        let recipient_pubkey = [0xa1u8; 32];
        let issuer_pubkey = [0xa2u8; 32];
        let stable_rs = build_stablecoin_redeem_script(&recipient_pubkey, &issuer_pubkey);
        let stable_p2sh = build_p2sh(&stable_rs);
        let expected_rs = kob_core::contract::stablecoin::build_stablecoin_redeem_script(&recipient_pubkey, &issuer_pubkey);
        assert_eq!(stable_rs, expected_rs);
        assert_eq!(stable_p2sh.script(), build_p2sh(&expected_rs).script());
    }

    /// The gated input's sig_op_count MUST be 2 (owner CheckSigVerify +
    /// issuer CheckSigFromStack); the fee input stays at the ordinary 1.
    #[test]
    fn transfer_gated_input_has_sig_op_count_two() {
        let (tx, _, _, _) = sample_transfer([0xAAu8; 32], [0xBBu8; 32], [0xCCu8; 32]);
        assert_eq!(tx.inputs.len(), 2);
        assert_eq!(tx.inputs[0].sig_op_count, 2, "gated stablecoin input must carry sig_op_count=2 (RT-1 lesson)");
        assert_eq!(tx.inputs[1].sig_op_count, 1, "fee P2PK input is an ordinary single-sig spend");
    }

    /// 1:1 shape: the successor output at index 0 must bind the input's
    /// FULL value -- no split, no partial transfer on the stablecoin side.
    #[test]
    fn transfer_binds_full_input_amount_no_split() {
        let (tx, _, _, _) = sample_transfer([0xAAu8; 32], [0xBBu8; 32], [0xCCu8; 32]);
        assert_eq!(tx.outputs[0].value, tx.inputs[0].value);
        assert_eq!(tx.outputs[0].value, 500_000_000);
    }

    /// The successor's scriptPublicKey bytes (2B BE version + script) must
    /// be byte-for-byte identical to what WU-D's `attest sign` computes and
    /// signs over -- this IS the successor_spk contract between WU-D/WU-E.
    #[test]
    fn transfer_successor_spk_matches_attest_module() {
        let owner_pubkey = [0xAAu8; 32];
        let issuer_pubkey = [0xBBu8; 32];
        let recipient_pubkey = [0xCCu8; 32];
        let (tx, _, _, _) = sample_transfer(owner_pubkey, issuer_pubkey, recipient_pubkey);

        let expected_successor_spk = crate::attest::build_successor_spk_for_recipient(&recipient_pubkey, &issuer_pubkey);

        let out0 = &tx.outputs[0];
        let mut actual_spk = Vec::with_capacity(2 + out0.script_bytes().len());
        actual_spk.extend_from_slice(&out0.script_version().to_be_bytes());
        actual_spk.extend_from_slice(out0.script_bytes());

        assert_eq!(actual_spk, expected_successor_spk);
    }

    /// The sigscript for input 0 must be byte-identical to independently
    /// calling `build_stablecoin_sigscript` with the same owner signature,
    /// issuer signature, and owner redeemScript.
    #[test]
    fn transfer_sigscript_matches_build_stablecoin_sigscript() {
        let owner_pubkey = [0xAAu8; 32];
        let issuer_pubkey = [0xBBu8; 32];
        let recipient_pubkey = [0xCCu8; 32];
        let (tx, sigscript_0, _, issuer_sig) = sample_transfer(owner_pubkey, issuer_pubkey, recipient_pubkey);

        let owner_rs = build_stablecoin_redeem_script(&owner_pubkey, &issuer_pubkey);
        let sighash_0 = compute_sighash(&tx, 0).unwrap();
        let expected_owner_sig = signing::schnorr_sign(&owner_privkey(), &sighash_0).unwrap();
        let expected_sigscript = build_stablecoin_sigscript(&expected_owner_sig, &issuer_sig, &owner_rs);

        assert_eq!(sigscript_0, expected_sigscript);
    }

    /// The successor output must carry a CovenantBinding continuing the
    /// SAME covenant_id the transfer was invoked with (authorizing_input=0,
    /// matching every other `CovenantBinding::new(0, ...)` call in this
    /// codebase for a single-authorized-output continuation).
    #[test]
    fn transfer_covenant_binding_carries_token_id() {
        let (tx, _, _, _) = sample_transfer([0xAAu8; 32], [0xBBu8; 32], [0xCCu8; 32]);
        let covenant = tx.outputs[0].covenant.as_ref().expect("successor output must carry a CovenantBinding");
        assert_eq!(covenant.authorizing_input, 0);
        let expected = kob_core::compat::parse_hash(&"11".repeat(32)).unwrap();
        assert_eq!(covenant.covenant_id, expected);
    }

    /// Fee change (when present) is a plain P2PK output with no covenant --
    /// it must not be mistaken for a continuation of the token lineage.
    #[test]
    fn transfer_fee_change_output_has_no_covenant() {
        let (tx, _, _, _) = sample_transfer([0xAAu8; 32], [0xBBu8; 32], [0xCCu8; 32]);
        // total_in = 500_000_000 + 10_000_000, fixed_out = 500_000_000 + miner_fee(2_000_000)
        // change = 10_000_000 - 2_000_000 = 8_000_000 >= MIN_UTXO_VALUE, so a change output exists.
        assert_eq!(tx.outputs.len(), 2, "fee change should clear the dust floor for this fixture");
        assert!(tx.outputs[1].covenant.is_none());
        assert_eq!(tx.outputs[1].value, 8_000_000);
    }

    /// Distinct recipients must yield distinct successor outputs (and thus
    /// distinct sigscripts, since the owner_sig's sighash depends on the
    /// output set) -- sanity that recipient_pubkey is load-bearing.
    #[test]
    fn transfer_distinct_recipients_yield_distinct_successor_outputs() {
        let owner_pubkey = [0xAAu8; 32];
        let issuer_pubkey = [0xBBu8; 32];
        let (tx_a, _, _, _) = sample_transfer(owner_pubkey, issuer_pubkey, [0x01u8; 32]);
        let (tx_b, _, _, _) = sample_transfer(owner_pubkey, issuer_pubkey, [0x02u8; 32]);
        assert_ne!(tx_a.outputs[0].script_bytes(), tx_b.outputs[0].script_bytes());
    }
}
