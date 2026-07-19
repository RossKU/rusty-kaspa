//! `kob-cli attest` -- KCC-0020 stablecoin (Plan A, native-value) issuer
//! attestation signing tool (WU-D).
//!
//! # Role
//!
//! Every spend of a `kob_core::contract::stablecoin` UTXO is gated behind a
//! fresh, per-spend Schnorr attestation from the token issuer (see
//! `kob_core::contract::stablecoin` module docs: owner authorization is
//! necessary but not sufficient -- the on-chain body also
//! `OpCheckSigFromStack`-verifies an issuer signature over a message it
//! reconstructs from transaction introspection). This tool is the issuer-side
//! (oracle) half of that gate: given the exact spend parameters (which
//! outpoint, which successor output, how much), it reproduces the same
//! 32-byte message the covenant body will recompute on-chain
//! (`kob_core::contract::stablecoin::build_attestation_message`) and signs it
//! with the issuer's private key using the same raw-message-hash Schnorr
//! signer the rest of this CLI uses ([`crate::signing::schnorr_sign`]).
//!
//! If the issuer declines to run this tool for a given transfer, no valid
//! `issuer_sig` exists and the covenant's `OpVerify` hard-aborts any attempt
//! to spend that UTXO -- this is the freeze control. There is no seize path;
//! withholding attestation is the entire mechanism.
//!
//! # Successor SPK contract with WU-E (the transfer CLI)
//!
//! WU-A's covenant body binds the *successor output at the same index as the
//! spent input* (the 1:1 shape; see `kob_core::contract::stablecoin::body`
//! module docs, "ISSUE-15" note) and hashes that output's
//! `ScriptPublicKey::to_bytes()` form -- 2 big-endian version bytes followed
//! by the raw script bytes (`crypto/txscript`'s `SpkEncoding::to_bytes`,
//! mirrored here since it is not a public API). For the common case, that
//! successor is another stablecoin UTXO for a (possibly new) owner, built the
//! same way WU-A's `build_stablecoin_redeem_script` + `build_p2sh` build any
//! stablecoin P2SH: `owner_pubkey = recipient_pubkey`, `issuer_pubkey` = this
//! tool's signing key's own x-only pubkey (the SAME issuer key must remain
//! baked into every successor, or the transferred coin exits the covenant and
//! is no longer attestation-gated). `--recipient-pubkey` drives that
//! reconstruction so the byte-for-byte match with what WU-E independently
//! builds (and what the chain will actually see at that output index) is
//! guaranteed by both sides calling the identical WU-A builders. `--successor-spk`
//! is an escape hatch for a non-standard successor shape -- whoever uses it is
//! responsible for making sure WU-E puts EXACTLY those bytes at the gated
//! output index, or the attestation this tool produces will be valid for a
//! message the real transaction never presents and the spend will fail
//! on-chain.
//!
//! # Output
//!
//! `attest sign` prints the resolved `issuer_pubkey` (so the caller can
//! diff it against the `issuer_pubkey` baked into the covenant body at
//! deploy time -- a mismatch there means this key can never produce a valid
//! attestation for that token), the recomputed successor SPK and attestation
//! message, and the 64-byte `issuer_sig` (hex). That `issuer_sig` is exactly
//! the 64-byte push WU-E's transfer sigscript places beneath `owner_sig` (see
//! `kob_core::contract::stablecoin::body` module docs, "Sigscript the body
//! consumes"). `--json` emits the same fields as a single JSON object for
//! scripted consumption.

use clap::Subcommand;
use kob_core::contract::stablecoin::{
    build_attestation_message, build_stablecoin_redeem_script, check_numeric_domain, validate_x_only_pubkey,
};
use kob_core::p2sh::build_p2sh;

#[derive(Subcommand, Debug)]
pub enum AttestCommand {
    /// Sign an issuer attestation authorizing a transfer of a gated
    /// stablecoin UTXO to a successor output.
    ///
    /// EXAMPLES:
    ///   kob-cli attest sign --issuer-key issuer.key \
    ///       --covenant-id <64hex> --txid <64hex> --index 0 \
    ///       --recipient-pubkey <64hex> --amount 500000000
    ///
    ///   kob-cli attest sign --issuer-key <64hex-privkey> \
    ///       --covenant-id <64hex> --txid <64hex> --index 0 \
    ///       --successor-spk <hex: 2B version + script> --amount 500000000
    Sign {
        /// Issuer's 32-byte Schnorr private key: either 64 hex chars
        /// directly, or a path to a file whose (trimmed) contents are the
        /// 64 hex chars. Never logged; only the derived public key is
        /// printed.
        #[arg(long)]
        issuer_key: String,

        /// The stablecoin's covenant id (hex, 64 chars) -- the same value
        /// baked into every token_unit/stablecoin UTXO of this token via
        /// CovenantBinding.
        #[arg(long)]
        covenant_id: String,

        /// Transaction id of the outpoint being spent (hex, 64 chars).
        #[arg(long)]
        txid: String,

        /// Output index of the outpoint being spent.
        #[arg(long)]
        index: u32,

        /// Recipient's x-only public key (hex, 64 chars): the new owner of
        /// the successor stablecoin UTXO. The successor SPK is derived as
        /// `build_p2sh(build_stablecoin_redeem_script(recipient_pubkey,
        /// issuer_pubkey))` -- the same issuer key stays baked into the
        /// successor so it remains attestation-gated. Mutually exclusive
        /// with `--successor-spk`.
        #[arg(long, conflicts_with = "successor_spk")]
        recipient_pubkey: Option<String>,

        /// Raw successor scriptPublicKey (hex): 2-byte big-endian version
        /// followed by the script bytes -- exactly
        /// `ScriptPublicKey::to_bytes()`'s form, i.e. what `OpTxOutputSpk`
        /// pushes on-chain for the output at this input's index. Advanced
        /// override for a non-standard successor shape; the caller is
        /// responsible for WU-E placing exactly these bytes at the gated
        /// output index. Mutually exclusive with `--recipient-pubkey`.
        #[arg(long)]
        successor_spk: Option<String>,

        /// Amount (sompi) being attested. Must equal the spent UTXO's full
        /// native value -- WU-A's 1:1 shape binds the input's complete
        /// amount, no split/change on the token side.
        #[arg(long)]
        amount: u64,

        /// Emit the result as a single JSON object instead of the default
        /// human-readable report.
        #[arg(long)]
        json: bool,
    },
}

/// Entry point for `kob-cli attest`. Fully offline -- no node/wallet
/// connection is made or needed.
pub fn run(cmd: &AttestCommand) -> anyhow::Result<()> {
    match cmd {
        AttestCommand::Sign { issuer_key, covenant_id, txid, index, recipient_pubkey, successor_spk, amount, json } => {
            cmd_sign(
                issuer_key,
                covenant_id,
                txid,
                *index,
                recipient_pubkey.as_deref(),
                successor_spk.as_deref(),
                *amount,
                *json,
            )
        }
    }
}

/// The fully computed attestation result: everything `attest sign` prints,
/// and everything WU-E needs to place the `issuer_sig` push correctly. Kept
/// separate from CLI arg parsing so it can be unit-tested directly.
#[derive(Debug, Clone)]
pub struct AttestationResult {
    pub issuer_pubkey: [u8; 32],
    pub covenant_id: [u8; 32],
    pub outpoint_txid: [u8; 32],
    pub outpoint_index: u32,
    pub amount: u64,
    /// Raw successor `ScriptPublicKey::to_bytes()` form (2B BE version + script).
    pub successor_spk: Vec<u8>,
    pub attestation_message: [u8; 32],
    pub issuer_sig: [u8; 64],
}

/// Build the successor's raw SPK bytes (`ScriptPublicKey::to_bytes()` form:
/// 2-byte big-endian version + script) for a standard stablecoin P2SH owned
/// by `recipient_pubkey` and still gated by `issuer_pubkey`. This mirrors
/// `crypto/txscript`'s private `SpkEncoding::to_bytes` exactly (`build_p2sh`
/// always mints version 0, so the 2-byte prefix is `[0x00, 0x00]` either way
/// endianness is read).
pub fn build_successor_spk_for_recipient(recipient_pubkey: &[u8; 32], issuer_pubkey: &[u8; 32]) -> Vec<u8> {
    let redeem_script = build_stablecoin_redeem_script(recipient_pubkey, issuer_pubkey);
    let p2sh = build_p2sh(&redeem_script);
    let mut spk_bytes = Vec::with_capacity(2 + p2sh.script().len());
    spk_bytes.extend_from_slice(&p2sh.version().to_be_bytes());
    spk_bytes.extend_from_slice(p2sh.script());
    spk_bytes
}

/// Pure computation: build the attestation message and sign it. No I/O.
pub fn build_attestation(
    issuer_privkey: &[u8; 32],
    covenant_id: [u8; 32],
    outpoint_txid: [u8; 32],
    outpoint_index: u32,
    successor_spk: Vec<u8>,
    amount: u64,
) -> anyhow::Result<AttestationResult> {
    check_numeric_domain(outpoint_index, amount).map_err(|e| anyhow::anyhow!("{e}"))?;

    let issuer_pubkey = crate::signing::derive_pubkey(issuer_privkey)?;
    // Re-validate through the WU-A gate itself: derive_pubkey already returns
    // exactly 32 bytes, but running the shared validator keeps this tool in
    // lock-step with the on-chain acceptance check rather than re-deriving
    // its own notion of "valid issuer key".
    let issuer_pubkey = validate_x_only_pubkey(&issuer_pubkey).map_err(|e| anyhow::anyhow!("issuer pubkey invalid: {e}"))?;

    let attestation_message =
        build_attestation_message(&covenant_id, &outpoint_txid, outpoint_index, &successor_spk, amount);

    let issuer_sig = crate::signing::schnorr_sign(issuer_privkey, &attestation_message)?;

    Ok(AttestationResult {
        issuer_pubkey,
        covenant_id,
        outpoint_txid,
        outpoint_index,
        amount,
        successor_spk,
        attestation_message,
        issuer_sig,
    })
}

#[allow(clippy::too_many_arguments)]
fn cmd_sign(
    issuer_key_arg: &str,
    covenant_id_hex: &str,
    txid_hex: &str,
    index: u32,
    recipient_pubkey_hex: Option<&str>,
    successor_spk_hex: Option<&str>,
    amount: u64,
    json: bool,
) -> anyhow::Result<()> {
    let issuer_privkey = resolve_issuer_key(issuer_key_arg)?;
    let covenant_id = parse_hash32(covenant_id_hex, "--covenant-id")?;
    let outpoint_txid = parse_hash32(txid_hex, "--txid")?;

    let (successor_spk, successor_source) = match (recipient_pubkey_hex, successor_spk_hex) {
        (Some(rp_hex), None) => {
            let rp_bytes = hex::decode(rp_hex).map_err(|e| anyhow::anyhow!("--recipient-pubkey is not valid hex: {e}"))?;
            let recipient_pubkey =
                validate_x_only_pubkey(&rp_bytes).map_err(|e| anyhow::anyhow!("--recipient-pubkey invalid: {e}"))?;
            // issuer_pubkey is needed here too, before the shared
            // build_attestation() derives it again -- cheap and keeps this
            // branch self-contained.
            let issuer_pubkey = crate::signing::derive_pubkey(&issuer_privkey)?;
            let spk = build_successor_spk_for_recipient(&recipient_pubkey, &issuer_pubkey);
            (spk, format!("stablecoin P2SH for recipient {rp_hex} (issuer-gated, same issuer key)"))
        }
        (None, Some(spk_hex)) => {
            let spk = hex::decode(spk_hex).map_err(|e| anyhow::anyhow!("--successor-spk is not valid hex: {e}"))?;
            (spk, "explicit --successor-spk override".to_string())
        }
        (None, None) => anyhow::bail!("one of --recipient-pubkey or --successor-spk is required"),
        (Some(_), Some(_)) => unreachable!("clap conflicts_with enforces --recipient-pubkey/--successor-spk mutual exclusion"),
    };

    let result = build_attestation(&issuer_privkey, covenant_id, outpoint_txid, index, successor_spk, amount)?;

    if json {
        let out = serde_json::json!({
            "issuer_pubkey": hex::encode(result.issuer_pubkey),
            "covenant_id": hex::encode(result.covenant_id),
            "outpoint_txid": hex::encode(result.outpoint_txid),
            "outpoint_index": result.outpoint_index,
            "amount": result.amount,
            "successor_spk": hex::encode(&result.successor_spk),
            "successor_source": successor_source,
            "attestation_message": hex::encode(result.attestation_message),
            "issuer_sig": hex::encode(result.issuer_sig),
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    println!("KCC-0020 Stablecoin Issuer Attestation");
    println!("=======================================");
    println!("Issuer pubkey (x-only): {}", hex::encode(result.issuer_pubkey));
    println!("  -> must equal the issuer_pubkey baked into this token's covenant body at deploy time.");
    println!();
    println!("Covenant id:    {}", hex::encode(result.covenant_id));
    println!("Spent outpoint: {}:{}", hex::encode(result.outpoint_txid), result.outpoint_index);
    println!("Amount:         {} sompi ({:.8} KAS)", result.amount, result.amount as f64 / 1e8);
    println!();
    println!("Successor SPK:  {}", hex::encode(&result.successor_spk));
    println!("  source: {successor_source}");
    println!();
    println!("Attestation message (Blake3 of 116B pre-image): {}", hex::encode(result.attestation_message));
    println!();
    println!("issuer_sig (64B, hex): {}", hex::encode(result.issuer_sig));
    println!();
    println!("Pass issuer_sig as the 64-byte push directly beneath owner_sig in the");
    println!("transfer sigscript (kob_core::contract::stablecoin::body: [owner_sig][issuer_sig][redeemScript]).");

    Ok(())
}

/// Resolve `--issuer-key` into a 32-byte private key. Accepts either a raw
/// 64-char hex string, or a path to a file whose trimmed contents are that
/// hex string (so the key need not be typed on the command line / land in
/// shell history).
fn resolve_issuer_key(arg: &str) -> anyhow::Result<[u8; 32]> {
    let trimmed = arg.trim();
    let looks_like_hex = trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit());
    let hex_str = if looks_like_hex {
        trimmed.to_string()
    } else {
        let contents = std::fs::read_to_string(trimmed).map_err(|e| {
            anyhow::anyhow!("--issuer-key '{trimmed}' is neither 64 hex chars nor a readable key file: {e}")
        })?;
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

/// Parse a 64-char hex string into a 32-byte array, tagging errors with
/// which flag they came from (local copy -- `crate::parse_hash32` is
/// private to `lib.rs`).
fn parse_hash32(hex_str: &str, flag: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).map_err(|e| anyhow::anyhow!("{flag} is not valid hex: {e}"))?;
    if bytes.len() != 32 {
        anyhow::bail!("{flag} must be 64 hex chars (32 bytes), got {} chars", hex_str.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_issuer_privkey() -> [u8; 32] {
        // Same fixed test key `signing.rs` uses for its own round-trip test
        // (64 hex chars = 32 bytes).
        let hex = "ae4ef0f30537c81653c2213b4b1ad84053fec52c547cb590277a7015850359a4";
        let bytes = hex::decode(hex).unwrap();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    fn sample_recipient_pubkey() -> [u8; 32] {
        [0x42u8; 32]
    }

    /// attest sign's issuer_sig must verify against the exact message
    /// `build_attestation_message` produces for the same inputs -- the
    /// round-trip the WU-D spec requires.
    #[test]
    fn issuer_sig_round_trips_through_schnorr_verify() {
        let issuer_privkey = sample_issuer_privkey();
        let issuer_pubkey = crate::signing::derive_pubkey(&issuer_privkey).unwrap();
        let recipient_pubkey = sample_recipient_pubkey();

        let covenant_id = [0x11u8; 32];
        let outpoint_txid = [0x22u8; 32];
        let index = 0u32;
        let amount = 500_000_000u64;

        let successor_spk = build_successor_spk_for_recipient(&recipient_pubkey, &issuer_pubkey);
        let result =
            build_attestation(&issuer_privkey, covenant_id, outpoint_txid, index, successor_spk.clone(), amount).unwrap();

        // The message this tool signed must be byte-identical to what the
        // on-chain body will recompute from the same inputs.
        let expected_msg = build_attestation_message(&covenant_id, &outpoint_txid, index, &successor_spk, amount);
        assert_eq!(result.attestation_message, expected_msg);

        // The signature must verify against that message under the issuer's
        // pubkey -- this is the round-trip the covenant's
        // OpCheckSigFromStack performs on-chain.
        let valid = kob_core::signing::schnorr_verify(&result.attestation_message, &result.issuer_sig, &issuer_pubkey)
            .expect("schnorr_verify should not error on well-formed inputs");
        assert!(valid, "issuer_sig must verify against the attestation message under the issuer pubkey");

        assert_eq!(result.issuer_pubkey, issuer_pubkey);
    }

    /// A signature must NOT verify against a mismatched pubkey.
    #[test]
    fn issuer_sig_does_not_verify_under_wrong_pubkey() {
        let issuer_privkey = sample_issuer_privkey();
        let issuer_pubkey = crate::signing::derive_pubkey(&issuer_privkey).unwrap();
        let recipient_pubkey = sample_recipient_pubkey();
        let successor_spk = build_successor_spk_for_recipient(&recipient_pubkey, &issuer_pubkey);

        let result =
            build_attestation(&issuer_privkey, [0x33u8; 32], [0x44u8; 32], 1, successor_spk, 1_000).unwrap();

        let wrong_pubkey = [0x99u8; 32];
        let valid = kob_core::signing::schnorr_verify(&result.attestation_message, &result.issuer_sig, &wrong_pubkey)
            .unwrap_or(false);
        assert!(!valid, "issuer_sig must not verify under an unrelated pubkey");
    }

    /// Distinct outpoints (txid or index) must produce distinct signatures
    /// (they sign distinct messages -- replay-binding sanity from the
    /// tool's side).
    #[test]
    fn different_outpoint_yields_different_signature() {
        let issuer_privkey = sample_issuer_privkey();
        let issuer_pubkey = crate::signing::derive_pubkey(&issuer_privkey).unwrap();
        let recipient_pubkey = sample_recipient_pubkey();
        let successor_spk = build_successor_spk_for_recipient(&recipient_pubkey, &issuer_pubkey);
        let covenant_id = [0xa1u8; 32];
        let amount = 42_000_000u64;

        let base = build_attestation(&issuer_privkey, covenant_id, [0x01u8; 32], 0, successor_spk.clone(), amount).unwrap();

        let diff_txid = build_attestation(&issuer_privkey, covenant_id, [0x02u8; 32], 0, successor_spk.clone(), amount).unwrap();
        assert_ne!(base.attestation_message, diff_txid.attestation_message);
        assert_ne!(base.issuer_sig, diff_txid.issuer_sig);

        let diff_index = build_attestation(&issuer_privkey, covenant_id, [0x01u8; 32], 1, successor_spk.clone(), amount).unwrap();
        assert_ne!(base.attestation_message, diff_index.attestation_message);
        assert_ne!(base.issuer_sig, diff_index.issuer_sig);
    }

    /// Distinct recipients (successor SPKs) must produce distinct signatures.
    #[test]
    fn different_recipient_yields_different_signature() {
        let issuer_privkey = sample_issuer_privkey();
        let issuer_pubkey = crate::signing::derive_pubkey(&issuer_privkey).unwrap();
        let covenant_id = [0xb2u8; 32];
        let outpoint_txid = [0xc3u8; 32];
        let amount = 7_000_000u64;

        let spk_a = build_successor_spk_for_recipient(&[0x01u8; 32], &issuer_pubkey);
        let spk_b = build_successor_spk_for_recipient(&[0x02u8; 32], &issuer_pubkey);
        assert_ne!(spk_a, spk_b, "distinct recipients must yield distinct successor SPKs");

        let a = build_attestation(&issuer_privkey, covenant_id, outpoint_txid, 0, spk_a, amount).unwrap();
        let b = build_attestation(&issuer_privkey, covenant_id, outpoint_txid, 0, spk_b, amount).unwrap();
        assert_ne!(a.attestation_message, b.attestation_message);
        assert_ne!(a.issuer_sig, b.issuer_sig);
    }

    /// Distinct amounts must produce distinct signatures.
    #[test]
    fn different_amount_yields_different_signature() {
        let issuer_privkey = sample_issuer_privkey();
        let issuer_pubkey = crate::signing::derive_pubkey(&issuer_privkey).unwrap();
        let recipient_pubkey = sample_recipient_pubkey();
        let successor_spk = build_successor_spk_for_recipient(&recipient_pubkey, &issuer_pubkey);
        let covenant_id = [0xd4u8; 32];
        let outpoint_txid = [0xe5u8; 32];

        let a = build_attestation(&issuer_privkey, covenant_id, outpoint_txid, 0, successor_spk.clone(), 1_000).unwrap();
        let b = build_attestation(&issuer_privkey, covenant_id, outpoint_txid, 0, successor_spk, 1_001).unwrap();
        assert_ne!(a.attestation_message, b.attestation_message);
        assert_ne!(a.issuer_sig, b.issuer_sig);
    }

    /// The successor SPK built from a recipient pubkey is exactly the raw
    /// `ScriptPublicKey::to_bytes()` form: 2-byte version prefix + the P2SH
    /// script produced by `build_p2sh`. This is the byte layout WU-E must
    /// reproduce for the actual output at the gated index.
    #[test]
    fn successor_spk_layout_matches_spk_to_bytes_form() {
        let issuer_pubkey = [0x07u8; 32];
        let recipient_pubkey = [0x08u8; 32];
        let redeem_script = build_stablecoin_redeem_script(&recipient_pubkey, &issuer_pubkey);
        let expected_p2sh = build_p2sh(&redeem_script);

        let spk = build_successor_spk_for_recipient(&recipient_pubkey, &issuer_pubkey);
        assert_eq!(spk.len(), 2 + expected_p2sh.script().len());
        assert_eq!(&spk[0..2], &expected_p2sh.version().to_be_bytes());
        assert_eq!(&spk[2..], expected_p2sh.script());
    }

    /// `resolve_issuer_key` accepts raw hex directly.
    #[test]
    fn resolve_issuer_key_accepts_hex() {
        let hex_key = "11".repeat(32);
        let resolved = resolve_issuer_key(&hex_key).unwrap();
        assert_eq!(resolved, [0x11u8; 32]);
    }

    /// `resolve_issuer_key` accepts a file path containing the hex key.
    #[test]
    fn resolve_issuer_key_accepts_file() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("kob_attest_test_key_{}.txt", std::process::id()));
        std::fs::write(&path, format!("{}\n", "22".repeat(32))).unwrap();
        let resolved = resolve_issuer_key(path.to_str().unwrap()).unwrap();
        assert_eq!(resolved, [0x22u8; 32]);
        std::fs::remove_file(&path).ok();
    }

    /// A key that is neither valid inline hex nor an existing file path
    /// must fail loudly rather than silently misinterpreting garbage.
    #[test]
    fn resolve_issuer_key_rejects_garbage() {
        assert!(resolve_issuer_key("not-a-key-and-not-a-file-path").is_err());
    }

    /// Requiring exactly one of --recipient-pubkey / --successor-spk is
    /// enforced by clap's `conflicts_with` at the CLI layer; this test
    /// documents (and pins) that `cmd_sign` itself also refuses to proceed
    /// with neither present.
    #[test]
    fn cmd_sign_requires_a_successor_target() {
        let issuer_hex = "33".repeat(32);
        let covenant_hex = "44".repeat(32);
        let txid_hex = "55".repeat(32);
        let err = cmd_sign(&issuer_hex, &covenant_hex, &txid_hex, 0, None, None, 1_000, false).unwrap_err();
        assert!(err.to_string().contains("recipient-pubkey") || err.to_string().contains("successor-spk"));
    }
}
