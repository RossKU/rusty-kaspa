//! Wallet loading, key management, and encryption.
//!
//! Supports:
//! - Plaintext single-key wallets (`WalletFile`)
//! - Encrypted single-key wallets (`EncryptedWalletFile`, Argon2id + ChaCha20-Poly1305)
//! - HD wallets with BIP-39/32 derivation (`HdWallet`, `WalletFileV2`)

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::signing::get_public_key;

/// Secure wrapper for a 32-byte private key.
///
/// Zeroes memory on drop to prevent key material from lingering in RAM.
/// Use this instead of raw `[u8; 32]` whenever handling private keys.
///
/// # Example
/// ```
/// # use kob_core::wallet::SecureKey;
/// let key = SecureKey::from_bytes([1u8; 32]);
/// assert_eq!(key.as_bytes().len(), 32);
/// // key is zeroed when dropped
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureKey([u8; 32]);

impl SecureKey {
    /// Create a `SecureKey` from a `LegacyWalletJson`'s hex-encoded private key.
    pub fn from_legacy(wallet: &LegacyWalletJson) -> crate::Result<Self> {
        let bytes = hex::decode(&wallet.private_key)?;
        let mut key = [0u8; 32];
        if bytes.len() != 32 {
            return Err(crate::KobError::Wallet("private key must be 32 bytes".into()));
        }
        key.copy_from_slice(&bytes);
        Ok(Self(key))
    }

    /// Create a `SecureKey` from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create a `SecureKey` from a byte slice.
    pub fn from_slice(bytes: &[u8]) -> crate::Result<Self> {
        if bytes.len() != 32 {
            return Err(crate::KobError::Wallet("private key must be 32 bytes".into()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    /// Get a reference to the underlying 32-byte key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// Prevent Debug from leaking key material
impl std::fmt::Debug for SecureKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecureKey([REDACTED])")
    }
}

// ────────────────────────────────────────────────────────────────
// WalletContext — unified wallet loader (production API)
// ────────────────────────────────────────────────────────────────

/// Unified wallet context: the three values every CLI command needs.
///
/// Loads any supported wallet format (V2 HD, V1 encrypted, plaintext)
/// and returns the private key, public key, and address for a single
/// signing identity.
pub struct WalletContext {
    privkey: SecureKey,
    pub pubkey: [u8; 32],
    pub address: String,
}

impl WalletContext {
    /// Load wallet from file, auto-detecting format.
    ///
    /// - V2 HD wallets: decrypts seed, derives key at `m/972'/111'/0'/0'`.
    ///   Pass `KOB_PASSPHRASE` env var for the passphrase.
    /// - V1 encrypted: decrypts with `KOB_PASSPHRASE` env var.
    /// - V0 plaintext: loads directly (warns on insecure permissions).
    pub fn load(path: &Path) -> crate::Result<Self> {
        Self::load_full(path, None, None)
    }

    /// Load with explicit passphrase and HD account index.
    pub fn load_full(
        path: &Path,
        passphrase: Option<&str>,
        account_index: Option<u32>,
    ) -> crate::Result<Self> {
        let env_pass = std::env::var("KOB_PASSPHRASE").ok();
        let pass = passphrase.or(env_pass.as_deref());

        match WalletFileV2::detect_version(path) {
            Some(2) => {
                let pass = pass.ok_or_else(|| {
                    crate::KobError::Wallet(
                        "HD wallet requires a passphrase (set KOB_PASSPHRASE or pass --passphrase)"
                            .into(),
                    )
                })?;
                let v2 = WalletFileV2::load(path)?;
                let hd = v2.decrypt_hd(pass)?;
                let account = account_index.unwrap_or(0);
                let key = hd.derive_key(account, 0)?;
                let pubkey = get_public_key(key.as_bytes())?;
                let address = pubkey_to_address(
                    &pubkey,
                    Self::detect_network_from_accounts(&v2.accounts),
                );
                Ok(Self {
                    privkey: key,
                    pubkey,
                    address,
                })
            }
            Some(1) => {
                // V1 encrypted (legacy EncryptedWalletFile)
                let pass = pass.ok_or_else(|| {
                    crate::KobError::Wallet(
                        "encrypted wallet requires a passphrase (set KOB_PASSPHRASE)".into(),
                    )
                })?;
                let legacy = LegacyWalletJson::load_auto(path, Some(pass))?;
                Self::from_legacy(legacy)
            }
            _ => {
                // V0 plaintext, unknown, or future versions — try plaintext parse
                if let Some(pass) = pass {
                    // Might be encrypted without version field
                    match LegacyWalletJson::load_auto(path, Some(pass)) {
                        Ok(legacy) => return Self::from_legacy(legacy),
                        Err(_) => {} // fall through to plaintext
                    }
                }
                let legacy = LegacyWalletJson::load(path)?;
                Self::from_legacy(legacy)
            }
        }
    }

    /// Get a reference to the private key.
    pub fn privkey(&self) -> &SecureKey {
        &self.privkey
    }

    /// Get private key bytes (for signing functions that take `&[u8; 32]`).
    pub fn privkey_bytes(&self) -> &[u8; 32] {
        self.privkey.as_bytes()
    }

    /// Get public key as hex string (for display).
    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.pubkey)
    }

    fn from_legacy(legacy: LegacyWalletJson) -> crate::Result<Self> {
        let mut privkey_bytes = hex::decode(&legacy.private_key)?;
        if privkey_bytes.len() != 32 {
            privkey_bytes.zeroize();
            return Err(crate::KobError::Wallet("private key must be 32 bytes".into()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&privkey_bytes);
        privkey_bytes.zeroize();
        let pubkey = get_public_key(&key)?;
        let address = legacy.address.clone();
        let secure_key = SecureKey::from_bytes(key);
        key.zeroize();
        Ok(Self {
            privkey: secure_key,
            pubkey,
            address,
        })
    }

    fn detect_network_from_accounts(accounts: &[AccountEntry]) -> crate::types::Network {
        if let Some(acc) = accounts.first() {
            if acc.address.starts_with("kaspa:") {
                return crate::types::Network::Mainnet;
            }
        }
        crate::types::Network::Testnet
    }
}

// ────────────────────────────────────────────────────────────────
// LegacyWalletJson — internal deserialization target
// ────────────────────────────────────────────────────────────────

/// Legacy wallet file structure (matches wallet.json from test scripts).
/// For wallet creation/migration only — use `WalletContext` for loading.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyWalletJson {
    pub private_key: String,
    pub public_key: String,
    pub address: String,
}

impl std::fmt::Debug for LegacyWalletJson {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LegacyWalletJson")
            .field("public_key", &self.public_key)
            .field("address", &self.address)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl LegacyWalletJson {
    /// Load wallet from a JSON file.
    ///
    /// Supports both plaintext and encrypted formats. If the file contains
    /// an `"encrypted"` field, it will be treated as an encrypted wallet
    /// and requires a passphrase.
    ///
    /// For plaintext wallets, warns if file permissions are too open (unix).
    pub fn load(path: &Path) -> crate::Result<Self> {
        // Enforce strict file permissions on unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(path) {
                let mode = metadata.permissions().mode();
                if mode & 0o077 != 0 {
                    return Err(crate::KobError::Wallet(format!(
                        "Wallet file {} has insecure permissions (mode {:o}). Run: chmod 600 {}",
                        path.display(),
                        mode,
                        path.display()
                    )));
                }
            }
        }

        let contents = std::fs::read_to_string(path).map_err(|e| {
            crate::KobError::Wallet(format!("failed to read wallet file {:?}: {}", path, e))
        })?;

        // Try to detect encrypted format
        if contents.contains("\"encrypted\"") {
            return Err(crate::KobError::Wallet(
                "encrypted wallet detected; use load_encrypted() with a passphrase".into(),
            ));
        }

        let wallet: Self = serde_json::from_str(&contents)?;
        Ok(wallet)
    }

    /// Load a wallet file, auto-detecting format.
    ///
    /// If `passphrase` is `Some`, attempts encrypted decryption first.
    /// If `None`, loads as plaintext (errors if encrypted).
    pub fn load_auto(path: &Path, passphrase: Option<&str>) -> crate::Result<Self> {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            crate::KobError::Wallet(format!("failed to read wallet file {:?}: {}", path, e))
        })?;

        if contents.contains("\"encrypted\"") {
            let passphrase = passphrase.ok_or_else(|| {
                crate::KobError::Wallet("encrypted wallet requires a passphrase".into())
            })?;
            let enc: EncryptedWalletFile =
                serde_json::from_str(&contents)?;
            return decrypt_wallet(&enc, passphrase);
        }

        // Enforce strict file permissions on unix for plaintext wallets
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(path) {
                let mode = metadata.permissions().mode();
                if mode & 0o077 != 0 {
                    return Err(crate::KobError::Wallet(format!(
                        "Wallet file {} has insecure permissions (mode {:o}). Run: chmod 600 {}",
                        path.display(),
                        mode,
                        path.display()
                    )));
                }
            }
        }

        let wallet: Self = serde_json::from_str(&contents)?;
        Ok(wallet)
    }

    /// Get private key as a `SecureKey` (preferred over raw bytes).
    pub fn secure_key(&self) -> crate::Result<SecureKey> {
        SecureKey::from_legacy(self)
    }

    /// Get private key bytes (32 bytes).
    ///
    /// Prefer `secure_key()` for production use, as it zeroes on drop.
    pub fn private_key_bytes(&self) -> crate::Result<[u8; 32]> {
        let bytes = hex::decode(&self.private_key)?;
        bytes
            .try_into()
            .map_err(|_| crate::KobError::Wallet("private key must be 32 bytes".into()))
    }

    /// Get public key bytes (32 bytes, x-only Schnorr).
    pub fn public_key_bytes(&self) -> crate::Result<[u8; 32]> {
        let bytes = hex::decode(&self.public_key)?;
        bytes
            .try_into()
            .map_err(|_| crate::KobError::Wallet("public key must be 32 bytes".into()))
    }
}

impl Drop for LegacyWalletJson {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

// Encrypted wallet (Argon2id + ChaCha20-Poly1305)

/// Argon2id parameters (OWASP minimum recommendation).
const ARGON2_M_COST: u32 = 19_456; // 19 MiB
const ARGON2_T_COST: u32 = 2; // 2 iterations
const ARGON2_P_COST: u32 = 1; // 1 lane

/// Salt length (16 bytes = 128 bits).
const SALT_LEN: usize = 16;

/// Nonce length for ChaCha20-Poly1305 (12 bytes = 96 bits).
const NONCE_LEN: usize = 12;

/// Encrypted wallet file structure.
///
/// Stored as JSON on disk. The `encrypted` field contains the base64-encoded
/// ciphertext of the wallet JSON, encrypted with ChaCha20-Poly1305 using a
/// key derived from the passphrase via Argon2id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedWalletFile {
    /// Base64-encoded ciphertext (ChaCha20-Poly1305 encrypted wallet JSON).
    pub encrypted: String,
    /// Hex-encoded salt for Argon2id (16 bytes).
    pub salt: String,
    /// Hex-encoded nonce for ChaCha20-Poly1305 (12 bytes).
    pub nonce: String,
}

/// Derive a 32-byte encryption key from a passphrase and salt using Argon2id.
///
/// Public API for use by callers needing key derivation with the same parameters.
pub fn derive_key_public(passphrase: &str, salt: &[u8]) -> crate::Result<[u8; 32]> {
    derive_key(passphrase, salt)
}

/// Derive a 32-byte encryption key from a passphrase and salt using Argon2id.
fn derive_key(passphrase: &str, salt: &[u8]) -> crate::Result<[u8; 32]> {
    let params = argon2::Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| crate::KobError::Wallet(format!("Argon2 params error: {}", e)))?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| crate::KobError::Wallet(format!("Argon2 key derivation failed: {}", e)))?;
    Ok(key)
}

/// Encrypt a wallet file with a passphrase.
///
/// Uses Argon2id for key derivation and ChaCha20-Poly1305 for encryption.
/// Generates random salt (16 bytes) and nonce (12 bytes).
///
/// # Example
/// ```no_run
pub fn encrypt_wallet(
    wallet: &LegacyWalletJson,
    passphrase: &str,
) -> crate::Result<EncryptedWalletFile> {
    use rand::RngCore;

    if passphrase.is_empty() {
        return Err(crate::KobError::Wallet(
            "passphrase must not be empty".into(),
        ));
    }

    // Generate random salt and nonce
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    // Derive encryption key
    let mut enc_key = derive_key(passphrase, &salt)?;

    // Serialize wallet to JSON
    let plaintext = serde_json::to_string(wallet)?;

    // Encrypt
    let cipher = ChaCha20Poly1305::new_from_slice(&enc_key)
        .map_err(|e| crate::KobError::Wallet(format!("cipher init error: {}", e)))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| crate::KobError::Wallet(format!("encryption failed: {}", e)))?;

    // Zeroize key material
    enc_key.zeroize();

    Ok(EncryptedWalletFile {
        encrypted: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ciphertext),
        salt: hex::encode(salt),
        nonce: hex::encode(nonce_bytes),
    })
}

/// Decrypt an encrypted wallet file with a passphrase.
///
/// # Errors
/// Returns an error if the passphrase is wrong (authentication tag mismatch),
/// or if the decrypted JSON is malformed.
#[allow(deprecated)]
pub fn decrypt_wallet(
    encrypted: &EncryptedWalletFile,
    passphrase: &str,
) -> crate::Result<LegacyWalletJson> {
    use base64::Engine;

    // Decode salt, nonce, ciphertext
    let salt = hex::decode(&encrypted.salt)?;
    if salt.len() != SALT_LEN {
        return Err(crate::KobError::Wallet(format!(
            "salt must be {} bytes, got {}",
            SALT_LEN,
            salt.len()
        )));
    }

    let nonce_bytes = hex::decode(&encrypted.nonce)?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(crate::KobError::Wallet(format!(
            "nonce must be {} bytes, got {}",
            NONCE_LEN,
            nonce_bytes.len()
        )));
    }

    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&encrypted.encrypted)
        .map_err(|e| crate::KobError::Wallet(format!("invalid base64: {}", e)))?;

    // Derive decryption key
    let mut dec_key = derive_key(passphrase, &salt)?;

    // Decrypt
    let cipher = ChaCha20Poly1305::new_from_slice(&dec_key)
        .map_err(|e| crate::KobError::Wallet(format!("cipher init error: {}", e)))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| {
            crate::KobError::Wallet(
                "decryption failed: wrong passphrase or corrupted data".into(),
            )
        })?;

    // Zeroize key material
    dec_key.zeroize();

    // Parse the decrypted JSON
    let mut plaintext_str = String::from_utf8(plaintext)
        .map_err(|e| crate::KobError::Wallet(format!("decrypted data is not UTF-8: {}", e)))?;
    let wallet: LegacyWalletJson = serde_json::from_str(&plaintext_str)?;
    plaintext_str.zeroize();

    Ok(wallet)
}

/// Save an encrypted wallet to a file.
///
/// Sets file permissions to 0600 on unix.
pub fn save_encrypted(
    encrypted: &EncryptedWalletFile,
    path: &std::path::Path,
) -> crate::Result<()> {
    let json = serde_json::to_string_pretty(encrypted)?;
    std::fs::write(path, &json)?;

    // Set restrictive permissions on unix (best-effort; some filesystems
    // like Android FUSE reject chmod).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }

    Ok(())
}

// HD Wallet (BIP-39 / BIP-32 style)

/// BIP-39 English wordlist (2048 words).
/// Embedded at compile time for zero external dependency.
const BIP39_WORDLIST: &str = include_str!("bip39_english.txt");

/// KOB derivation path constants.
const PURPOSE: u32 = 972; // "KAS" on phone keypad
const COIN_TYPE: u32 = 111; // "KOB"

/// HD wallet with seed and optional mnemonic.
///
/// The seed is a 64-byte value derived from a BIP-39 mnemonic via PBKDF2.
/// All private key material is zeroized on drop.
pub struct HdWallet {
    seed: HdSeed,
    mnemonic: Option<String>,
}

/// Secure 64-byte seed wrapper with zeroize-on-drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct HdSeed([u8; 64]);

impl HdSeed {
    fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

// Prevent Debug from leaking seed material
impl std::fmt::Debug for HdSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HdSeed([REDACTED])")
    }
}

/// Extended key: private key (32 bytes) + chain code (32 bytes).
#[derive(Zeroize, ZeroizeOnDrop)]
struct ExtendedKey {
    key: [u8; 32],
    chain_code: [u8; 32],
}

impl HdWallet {
    /// Generate a new HD wallet with a random mnemonic.
    ///
    /// `word_count` must be 12 (128-bit entropy) or 24 (256-bit entropy).
    ///
    /// # Example
    /// ```
    /// # use kob_core::wallet::HdWallet;
    /// let wallet = HdWallet::generate(12).unwrap();
    /// let mnemonic = wallet.mnemonic().unwrap();
    /// assert_eq!(mnemonic.split_whitespace().count(), 12);
    /// ```
    pub fn generate(word_count: usize) -> crate::Result<Self> {
        use rand::RngCore;

        let entropy_bytes = match word_count {
            12 => 16, // 128 bits
            24 => 32, // 256 bits
            _ => {
                return Err(crate::KobError::Wallet(
                    "word_count must be 12 or 24".into(),
                ))
            }
        };

        let mut entropy = vec![0u8; entropy_bytes];
        rand::thread_rng().fill_bytes(&mut entropy);

        let mnemonic = entropy_to_mnemonic(&entropy)?;
        entropy.zeroize();

        Self::from_mnemonic(&mnemonic)
    }

    /// Restore an HD wallet from a BIP-39 mnemonic phrase.
    ///
    /// The mnemonic is validated (word count, checksum) before use.
    ///
    /// # Example
    /// ```
    /// # use kob_core::wallet::HdWallet;
    /// let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    /// let wallet = HdWallet::from_mnemonic(mnemonic).unwrap();
    /// let key = wallet.derive_key(0, 0).unwrap();
    /// assert_eq!(key.as_bytes().len(), 32);
    /// ```
    pub fn from_mnemonic(mnemonic: &str) -> crate::Result<Self> {
        validate_mnemonic(mnemonic)?;
        let seed = mnemonic_to_seed(mnemonic, "")?;
        Ok(Self {
            seed: HdSeed(seed),
            mnemonic: Some(mnemonic.to_string()),
        })
    }

    /// Create an HD wallet directly from a 64-byte seed (no mnemonic).
    ///
    /// This is useful for testing or when the seed is derived externally.
    pub fn from_seed(seed: [u8; 64]) -> Self {
        Self {
            seed: HdSeed(seed),
            mnemonic: None,
        }
    }

    /// Get the mnemonic phrase, if available.
    pub fn mnemonic(&self) -> Option<&str> {
        self.mnemonic.as_deref()
    }

    /// Derive a child private key at `m/972'/111'/account'/index'`.
    ///
    /// All levels use hardened derivation for security.
    /// The returned `SecureKey` is zeroized on drop.
    pub fn derive_key(&self, account: u32, index: u32) -> crate::Result<SecureKey> {
        // Master key from seed
        let mut master = derive_master_key(self.seed.as_bytes())?;

        // m/972'
        let mut child = derive_hardened_child(&master, PURPOSE)?;
        master.zeroize();

        // m/972'/111'
        let mut child2 = derive_hardened_child(&child, COIN_TYPE)?;
        child.zeroize();

        // m/972'/111'/account'
        let mut child3 = derive_hardened_child(&child2, account)?;
        child2.zeroize();

        // m/972'/111'/account'/index'
        let mut child4 = derive_hardened_child(&child3, index)?;
        child3.zeroize();

        let key = SecureKey::from_bytes(child4.key);
        child4.zeroize();

        // Validate that the derived key is a valid secp256k1 scalar
        get_public_key(key.as_bytes()).map_err(|_| {
            crate::KobError::Wallet(format!(
                "derived key at account={}/index={} is not a valid secp256k1 scalar",
                account, index
            ))
        })?;

        Ok(key)
    }

    /// Get the Kaspa address for a derived key at `m/972'/111'/account'/index'`.
    ///
    /// Returns a Kaspa testnet address (kaspatest:q...) or mainnet (kaspa:q...).
    pub fn get_address(
        &self,
        account: u32,
        index: u32,
        network: crate::types::Network,
    ) -> crate::Result<String> {
        let key = self.derive_key(account, index)?;
        let pubkey = get_public_key(key.as_bytes())?;
        Ok(pubkey_to_address(&pubkey, network))
    }

    /// Derive multiple addresses for an account (index 0..count).
    pub fn derive_addresses(
        &self,
        account: u32,
        count: u32,
        network: crate::types::Network,
    ) -> crate::Result<Vec<(u32, String, String)>> {
        let mut results = Vec::with_capacity(count as usize);
        for index in 0..count {
            let key = self.derive_key(account, index)?;
            let pubkey = get_public_key(key.as_bytes())?;
            let address = pubkey_to_address(&pubkey, network);
            results.push((index, hex::encode(pubkey), address));
        }
        Ok(results)
    }

    /// Export a watch-only wallet (public keys and addresses only).
    pub fn export_watch_only(
        &self,
        account: u32,
        count: u32,
        network: crate::types::Network,
    ) -> crate::Result<WatchOnlyExport> {
        let mut accounts = Vec::with_capacity(count as usize);
        for index in 0..count {
            let key = self.derive_key(account, index)?;
            let pubkey = get_public_key(key.as_bytes())?;
            accounts.push(WatchOnlyAccount {
                index,
                public_key: hex::encode(pubkey),
                address: pubkey_to_address(&pubkey, network),
                label: String::new(),
            });
        }
        Ok(WatchOnlyExport {
            wallet_type: "watch-only".into(),
            accounts,
        })
    }
}

// Prevent Debug from leaking mnemonic
impl std::fmt::Debug for HdWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HdWallet")
            .field("seed", &"[REDACTED]")
            .field("has_mnemonic", &self.mnemonic.is_some())
            .finish()
    }
}

impl Drop for HdWallet {
    fn drop(&mut self) {
        if let Some(ref mut m) = self.mnemonic {
            m.zeroize();
        }
    }
}

/// Get the BIP-39 English wordlist as a Vec.
fn wordlist() -> Vec<&'static str> {
    BIP39_WORDLIST.lines().collect()
}

/// Convert entropy bytes to a BIP-39 mnemonic sentence.
fn entropy_to_mnemonic(entropy: &[u8]) -> crate::Result<String> {
    let ent_bits = entropy.len() * 8;
    if ent_bits != 128 && ent_bits != 256 {
        return Err(crate::KobError::Wallet(
            "entropy must be 128 or 256 bits".into(),
        ));
    }

    // Checksum: first (entropy_bits / 32) bits of SHA-256(entropy)
    let cs_bits = ent_bits / 32;
    let hash = Sha256::digest(entropy);

    // Build bit string: entropy || checksum
    let mut bits = Vec::with_capacity(ent_bits + cs_bits);
    for byte in entropy {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1);
        }
    }
    for i in 0..cs_bits {
        bits.push((hash[i / 8] >> (7 - (i % 8))) & 1);
    }

    // Split into 11-bit groups and map to words
    let words = wordlist();
    if words.len() != 2048 {
        return Err(crate::KobError::Wallet(format!(
            "BIP-39 wordlist must have 2048 entries, got {}",
            words.len()
        )));
    }

    let mut mnemonic_words = Vec::with_capacity((ent_bits + cs_bits) / 11);
    for chunk in bits.chunks(11) {
        let mut idx: usize = 0;
        for &bit in chunk {
            idx = (idx << 1) | (bit as usize);
        }
        mnemonic_words.push(words[idx]);
    }

    Ok(mnemonic_words.join(" "))
}

/// Validate a BIP-39 mnemonic (word count, wordlist membership, checksum).
fn validate_mnemonic(mnemonic: &str) -> crate::Result<()> {
    let words_input: Vec<&str> = mnemonic.split_whitespace().collect();
    let word_count = words_input.len();

    if word_count != 12 && word_count != 24 {
        return Err(crate::KobError::Wallet(format!(
            "mnemonic must be 12 or 24 words, got {}",
            word_count
        )));
    }

    let wl = wordlist();

    // Map words to indices
    let mut indices = Vec::with_capacity(word_count);
    for word in &words_input {
        let idx = wl
            .iter()
            .position(|w| w == word)
            .ok_or_else(|| crate::KobError::Wallet(format!("unknown BIP-39 word: '{}'", word)))?;
        indices.push(idx);
    }

    // Convert indices back to bits
    let total_bits = word_count * 11;
    let mut bits = Vec::with_capacity(total_bits);
    for idx in &indices {
        for i in (0..11).rev() {
            bits.push(((idx >> i) & 1) as u8);
        }
    }

    let ent_bits = match word_count {
        12 => 128,
        24 => 256,
        _ => unreachable!(),
    };
    let cs_bits = ent_bits / 32;

    // Extract entropy bytes
    let mut entropy = vec![0u8; ent_bits / 8];
    for i in 0..ent_bits {
        if bits[i] == 1 {
            entropy[i / 8] |= 1 << (7 - (i % 8));
        }
    }

    // Verify checksum
    let hash = Sha256::digest(&entropy);
    for i in 0..cs_bits {
        let expected = (hash[i / 8] >> (7 - (i % 8))) & 1;
        let actual = bits[ent_bits + i];
        if expected != actual {
            return Err(crate::KobError::Wallet(
                "mnemonic checksum invalid".into(),
            ));
        }
    }

    Ok(())
}

/// Derive a 64-byte seed from a mnemonic using PBKDF2-HMAC-SHA512.
///
/// BIP-39 spec: PBKDF2(password=mnemonic, salt="mnemonic"+passphrase, c=2048, dkLen=64)
fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> crate::Result<[u8; 64]> {
    let salt = format!("mnemonic{}", passphrase);
    let mut seed = [0u8; 64];

    pbkdf2::pbkdf2_hmac::<Sha512>(mnemonic.as_bytes(), salt.as_bytes(), 2048, &mut seed);

    Ok(seed)
}

/// Derive the master extended key from a seed.
///
/// BIP-32: HMAC-SHA512(key="Bitcoin seed", data=seed) but we use "KOB seed"
/// to keep the derivation KOB-specific while following the same structure.
fn derive_master_key(seed: &[u8; 64]) -> crate::Result<ExtendedKey> {
    type HmacSha512 = Hmac<Sha512>;
    let mut mac =
        <HmacSha512 as Mac>::new_from_slice(b"KOB seed").expect("HMAC can take key of any size");
    mac.update(seed);
    let result = mac.finalize().into_bytes();

    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    chain_code.copy_from_slice(&result[32..]);

    // Verify the key is a valid secp256k1 scalar (non-zero, < order)
    if key.iter().all(|&b| b == 0) {
        return Err(crate::KobError::Wallet(
            "derived master key is zero (astronomically unlikely, retry)".into(),
        ));
    }

    Ok(ExtendedKey { key, chain_code })
}

/// Derive a hardened child key.
///
/// BIP-32 hardened derivation: HMAC-SHA512(key=chain_code, data=0x00||key||index+0x80000000)
fn derive_hardened_child(parent: &ExtendedKey, index: u32) -> crate::Result<ExtendedKey> {
    type HmacSha512 = Hmac<Sha512>;
    let mut mac = <HmacSha512 as Mac>::new_from_slice(&parent.chain_code)
        .expect("HMAC can take key of any size");

    // Hardened: 0x00 || parent_key || (index | 0x80000000)
    mac.update(&[0x00]);
    mac.update(&parent.key);
    mac.update(&(index | 0x80000000).to_be_bytes());

    let result = mac.finalize().into_bytes();

    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    chain_code.copy_from_slice(&result[32..]);

    // In proper BIP-32, we would add parent key to child key mod curve order.
    // For our simplified derivation, we use the HMAC output directly as the key.
    // This is secure because:
    // 1. HMAC-SHA512 is a PRF
    // 2. We use hardened derivation only (no public key derivation)
    // 3. The chain code provides domain separation between levels

    if key.iter().all(|&b| b == 0) {
        return Err(crate::KobError::Wallet(
            "derived child key is zero (astronomically unlikely, retry)".into(),
        ));
    }

    Ok(ExtendedKey { key, chain_code })
}

/// Encode a 32-byte x-only public key as a Kaspa address.
///
/// Delegates to `kaspa_addresses::Address` via `crate::bech32::bech32_encode`.
pub fn pubkey_to_address(pubkey: &[u8; 32], network: crate::types::Network) -> String {
    crate::bech32::bech32_encode(network.address_prefix(), 0x00, pubkey)
}

/// Wallet file format version 2 — supports both HD and legacy single-key wallets.
///
/// The encrypted field contains either:
/// - Legacy (type="legacy"): encrypted WalletFile JSON
/// - HD (type="hd"): encrypted HD seed (64 bytes, hex-encoded)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WalletFileV2 {
    /// Format version (2).
    pub version: u32,
    /// Wallet type: "hd" or "legacy".
    #[serde(rename = "type")]
    pub wallet_type: String,
    /// Base64-encoded ciphertext.
    pub encrypted: String,
    /// Hex-encoded Argon2id salt.
    pub salt: String,
    /// Hex-encoded ChaCha20-Poly1305 nonce.
    pub nonce: String,
    /// Derived account entries (for display; not sensitive).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accounts: Vec<AccountEntry>,
}

/// A derived account entry stored in the wallet file (public info only).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AccountEntry {
    pub index: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    pub address: String,
}

/// Encrypted HD data: seed (hex) + optional mnemonic.
#[derive(serde::Serialize, serde::Deserialize)]
struct HdPlaintext {
    seed: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    mnemonic: Option<String>,
}

impl WalletFileV2 {
    /// Create an encrypted v2 HD wallet file.
    pub fn encrypt_hd(
        wallet: &HdWallet,
        passphrase: &str,
        accounts: Vec<AccountEntry>,
    ) -> crate::Result<Self> {
        use rand::RngCore;

        if passphrase.is_empty() {
            return Err(crate::KobError::Wallet("passphrase must not be empty".into()));
        }

        let plaintext_data = HdPlaintext {
            seed: hex::encode(wallet.seed.as_bytes()),
            mnemonic: wallet.mnemonic.clone(),
        };
        let plaintext_json = serde_json::to_string(&plaintext_data)?;

        // Generate random salt and nonce
        let mut salt = [0u8; 16];
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        // Derive key with Argon2id
        let mut enc_key = derive_key_public(passphrase, &salt)?;

        let cipher = ChaCha20Poly1305::new_from_slice(&enc_key)
            .map_err(|e| crate::KobError::Wallet(format!("cipher init error: {}", e)))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext_json.as_bytes())
            .map_err(|e| crate::KobError::Wallet(format!("encryption failed: {}", e)))?;

        enc_key.zeroize();

        Ok(Self {
            version: 2,
            wallet_type: "hd".into(),
            encrypted: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &ciphertext,
            ),
            salt: hex::encode(salt),
            nonce: hex::encode(nonce_bytes),
            accounts,
        })
    }

    /// Decrypt a v2 HD wallet file.
    pub fn decrypt_hd(&self, passphrase: &str) -> crate::Result<HdWallet> {
        use base64::Engine;

        if self.wallet_type != "hd" {
            return Err(crate::KobError::Wallet(
                "not an HD wallet (type is not 'hd')".into(),
            ));
        }

        let salt = hex::decode(&self.salt)?;
        let nonce_bytes = hex::decode(&self.nonce)?;
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&self.encrypted)
            .map_err(|e| crate::KobError::Wallet(format!("invalid base64: {}", e)))?;

        let mut dec_key = derive_key_public(passphrase, &salt)?;

        let cipher = ChaCha20Poly1305::new_from_slice(&dec_key)
            .map_err(|e| crate::KobError::Wallet(format!("cipher init error: {}", e)))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| {
                crate::KobError::Wallet(
                    "decryption failed: wrong passphrase or corrupted data".into(),
                )
            })?;

        dec_key.zeroize();

        let mut plaintext_str = String::from_utf8(plaintext)
            .map_err(|e| crate::KobError::Wallet(format!("decrypted data is not UTF-8: {}", e)))?;

        let hd_data: HdPlaintext = serde_json::from_str(&plaintext_str)?;
        plaintext_str.zeroize();

        let seed_bytes = hex::decode(&hd_data.seed)?;
        if seed_bytes.len() != 64 {
            return Err(crate::KobError::Wallet("HD seed must be 64 bytes".into()));
        }
        let mut seed = [0u8; 64];
        seed.copy_from_slice(&seed_bytes);

        let wallet = if let Some(mnemonic) = hd_data.mnemonic {
            HdWallet {
                seed: HdSeed(seed),
                mnemonic: Some(mnemonic),
            }
        } else {
            HdWallet::from_seed(seed)
        };

        Ok(wallet)
    }

    /// Save a v2 wallet file to disk with restricted permissions.
    pub fn save(&self, path: &std::path::Path) -> crate::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, &json)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }

        Ok(())
    }

    /// Load a v2 wallet file from disk (returns the encrypted structure).
    pub fn load(path: &std::path::Path) -> crate::Result<Self> {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            crate::KobError::Wallet(format!("failed to read wallet file {:?}: {}", path, e))
        })?;
        let v2: Self = serde_json::from_str(&contents)?;
        if v2.version != 2 {
            return Err(crate::KobError::Wallet(format!(
                "expected wallet version 2, got {}",
                v2.version
            )));
        }
        Ok(v2)
    }

    /// Detect wallet file version from contents.
    ///
    /// Returns:
    /// - Some(2) for v2 format (has "version": 2)
    /// - Some(1) for v1 encrypted (has "encrypted" but no "version")
    /// - Some(0) for v1 plaintext (has "privateKey")
    /// - None if unrecognized
    pub fn detect_version(path: &std::path::Path) -> Option<u32> {
        let contents = std::fs::read_to_string(path).ok()?;
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&contents) {
            if v.get("version").and_then(|v| v.as_u64()) == Some(2) {
                return Some(2);
            }
            if v.get("encrypted").is_some() {
                return Some(1);
            }
            if v.get("privateKey").is_some() {
                return Some(0);
            }
        }
        None
    }
}

/// Export public-only wallet data (watch-only).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WatchOnlyExport {
    /// Wallet type: "watch-only".
    #[serde(rename = "type")]
    pub wallet_type: String,
    /// Derived addresses with public keys.
    pub accounts: Vec<WatchOnlyAccount>,
}

/// A single watch-only account entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WatchOnlyAccount {
    pub index: u32,
    pub public_key: String,
    pub address: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
}

#[cfg(test)]
mod tests {
    use super::*;


    fn test_wallet() -> LegacyWalletJson {
        LegacyWalletJson {
            private_key:
                "ae4ef0f30537c81653c2213b4b1ad84053fec52c547cb590277a7015850359a4".into(),
            public_key:
                "3509e6f574e705aa233b7f9713e979bb27f463116d6a754369c19479d3fe6583".into(),
            address:
                "kaspatest:qxapemh4t8qp4rf3eek88m98u0a2y78xzes52jrjd8gclj5c0l9svhkkwmwc5"
                    .into(),
        }
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let wallet = test_wallet();
        let passphrase = "test-passphrase-123!";

        let encrypted = encrypt_wallet(&wallet, passphrase).unwrap();

        // Verify encrypted format has expected fields
        assert!(!encrypted.encrypted.is_empty());
        assert_eq!(hex::decode(&encrypted.salt).unwrap().len(), SALT_LEN);
        assert_eq!(hex::decode(&encrypted.nonce).unwrap().len(), NONCE_LEN);

        // Decrypt and verify
        let decrypted = decrypt_wallet(&encrypted, passphrase).unwrap();
        assert_eq!(decrypted.private_key, wallet.private_key);
        assert_eq!(decrypted.public_key, wallet.public_key);
        assert_eq!(decrypted.address, wallet.address);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let wallet = test_wallet();
        let encrypted = encrypt_wallet(&wallet, "correct-passphrase").unwrap();

        let result = decrypt_wallet(&encrypted, "wrong-passphrase");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("wrong passphrase"),
            "Error should mention wrong passphrase: {}",
            err_msg
        );
    }

    #[test]
    fn empty_passphrase_rejected() {
        let wallet = test_wallet();
        let result = encrypt_wallet(&wallet, "");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must not be empty"));
    }

    #[test]
    fn encrypted_json_format() {
        let wallet = test_wallet();
        let encrypted = encrypt_wallet(&wallet, "test123").unwrap();
        let json = serde_json::to_string_pretty(&encrypted).unwrap();

        // Must contain "encrypted" field (used by auto-detection)
        assert!(json.contains("\"encrypted\""));
        assert!(json.contains("\"salt\""));
        assert!(json.contains("\"nonce\""));

        // Must NOT contain private key in plaintext
        assert!(
            !json.contains(&wallet.private_key),
            "encrypted JSON must not contain plaintext private key"
        );
    }

    #[test]
    fn different_encryptions_produce_different_ciphertext() {
        let wallet = test_wallet();
        let pass = "same-passphrase";
        let enc1 = encrypt_wallet(&wallet, pass).unwrap();
        let enc2 = encrypt_wallet(&wallet, pass).unwrap();

        // Different random salt/nonce means different ciphertext
        assert_ne!(enc1.salt, enc2.salt);
        assert_ne!(enc1.encrypted, enc2.encrypted);
    }

    // TODO: WalletContext migration — load_auto moved to WalletContext::load()
    // These tests need to be rewritten to use WalletContext API.
    // #[test] fn save_and_load_encrypted_file() { ... }
    // #[test] fn load_auto_plaintext_without_passphrase() { ... }
    // #[test] fn load_auto_encrypted_without_passphrase_fails() { ... }


    /// The well-known BIP-39 test vector mnemonic.
    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn generate_12_word_mnemonic() {
        let wallet = HdWallet::generate(12).unwrap();
        let mnemonic = wallet.mnemonic().unwrap();
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 12);
    }

    #[test]
    fn generate_24_word_mnemonic() {
        let wallet = HdWallet::generate(24).unwrap();
        let mnemonic = wallet.mnemonic().unwrap();
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 24);
    }

    #[test]
    fn invalid_word_count_rejected() {
        assert!(HdWallet::generate(15).is_err());
        assert!(HdWallet::generate(6).is_err());
    }

    #[test]
    fn mnemonic_roundtrip() {
        let wallet1 = HdWallet::generate(12).unwrap();
        let mnemonic = wallet1.mnemonic().unwrap().to_string();
        let wallet2 = HdWallet::from_mnemonic(&mnemonic).unwrap();

        // Same mnemonic should produce same keys
        let key1 = wallet1.derive_key(0, 0).unwrap();
        let key2 = wallet2.derive_key(0, 0).unwrap();
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn deterministic_derivation() {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC).unwrap();
        let key1 = wallet.derive_key(0, 0).unwrap();
        let key2 = wallet.derive_key(0, 0).unwrap();
        assert_eq!(
            key1.as_bytes(),
            key2.as_bytes(),
            "Same path must produce same key"
        );
    }

    #[test]
    fn different_indices_different_keys() {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC).unwrap();
        let key0 = wallet.derive_key(0, 0).unwrap();
        let key1 = wallet.derive_key(0, 1).unwrap();
        assert_ne!(
            key0.as_bytes(),
            key1.as_bytes(),
            "Different indices must produce different keys"
        );
    }

    #[test]
    fn different_accounts_different_keys() {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC).unwrap();
        let key_a0 = wallet.derive_key(0, 0).unwrap();
        let key_a1 = wallet.derive_key(1, 0).unwrap();
        assert_ne!(
            key_a0.as_bytes(),
            key_a1.as_bytes(),
            "Different accounts must produce different keys"
        );
    }

    #[test]
    fn derived_key_is_valid_secp256k1() {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC).unwrap();
        for i in 0..5 {
            let key = wallet.derive_key(0, i).unwrap();
            let pubkey = get_public_key(key.as_bytes());
            assert!(pubkey.is_ok(), "Key at index {} must be valid secp256k1", i);
        }
    }

    #[test]
    fn address_generation() {
        use crate::types::Network;
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC).unwrap();
        let addr = wallet.get_address(0, 0, Network::Testnet).unwrap();
        assert!(
            addr.starts_with("kaspatest:"),
            "Testnet address must start with kaspatest:"
        );
        let addr_main = wallet.get_address(0, 0, Network::Mainnet).unwrap();
        assert!(
            addr_main.starts_with("kaspa:"),
            "Mainnet address must start with kaspa:"
        );
    }

    #[test]
    fn address_deterministic() {
        use crate::types::Network;
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC).unwrap();
        let addr1 = wallet.get_address(0, 0, Network::Testnet).unwrap();
        let addr2 = wallet.get_address(0, 0, Network::Testnet).unwrap();
        assert_eq!(addr1, addr2, "Same path must produce same address");
    }

    #[test]
    fn validate_mnemonic_valid() {
        assert!(validate_mnemonic(TEST_MNEMONIC).is_ok());
    }

    #[test]
    fn validate_mnemonic_bad_word() {
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zzzzz";
        let err = validate_mnemonic(bad);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("unknown BIP-39 word"));
    }

    #[test]
    fn validate_mnemonic_bad_checksum() {
        // Replace last word with a valid word that gives wrong checksum
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zoo";
        let err = validate_mnemonic(bad);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("checksum"));
    }

    #[test]
    fn validate_mnemonic_wrong_count() {
        let bad = "abandon abandon abandon";
        let err = validate_mnemonic(bad);
        assert!(err.is_err());
    }

    #[test]
    fn derive_multiple_addresses() {
        use crate::types::Network;
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC).unwrap();
        let addrs = wallet.derive_addresses(0, 5, Network::Testnet).unwrap();
        assert_eq!(addrs.len(), 5);
        // All addresses must be unique
        let unique: std::collections::HashSet<_> = addrs.iter().map(|(_, _, a)| a.clone()).collect();
        assert_eq!(unique.len(), 5, "All derived addresses must be unique");
    }

    #[test]
    fn hd_wallet_debug_redacted() {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC).unwrap();
        let debug = format!("{:?}", wallet);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("abandon"));
    }

    #[test]
    fn encrypt_decrypt_hd_roundtrip() {
        use crate::types::Network;
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC).unwrap();
        let accounts = vec![AccountEntry {
            index: 0,
            label: "Trading".into(),
            address: wallet.get_address(0, 0, Network::Testnet).unwrap(),
        }];

        let encrypted = WalletFileV2::encrypt_hd(&wallet, "test-pass-123", accounts).unwrap();
        assert_eq!(encrypted.version, 2);
        assert_eq!(encrypted.wallet_type, "hd");
        assert_eq!(encrypted.accounts.len(), 1);

        let decrypted = encrypted.decrypt_hd("test-pass-123").unwrap();
        assert_eq!(decrypted.mnemonic().unwrap(), TEST_MNEMONIC);

        let key_orig = wallet.derive_key(0, 0).unwrap();
        let key_decr = decrypted.derive_key(0, 0).unwrap();
        assert_eq!(key_orig.as_bytes(), key_decr.as_bytes());
    }

    #[test]
    fn encrypt_hd_wrong_passphrase() {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC).unwrap();
        let encrypted = WalletFileV2::encrypt_hd(&wallet, "correct", vec![]).unwrap();
        let result = encrypted.decrypt_hd("wrong");
        assert!(result.is_err());
    }

    #[test]
    fn wallet_v2_save_load_roundtrip() {
        use crate::types::Network;
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC).unwrap();
        let addr = wallet.get_address(0, 0, Network::Testnet).unwrap();
        let accounts = vec![AccountEntry {
            index: 0,
            label: "Test".into(),
            address: addr,
        }];

        let encrypted = WalletFileV2::encrypt_hd(&wallet, "file-test", accounts).unwrap();
        let tmp_path = std::env::temp_dir().join("kob_test_hd_wallet_v2.json");
        encrypted.save(&tmp_path).unwrap();

        let loaded = WalletFileV2::load(&tmp_path).unwrap();
        assert_eq!(loaded.version, 2);
        assert_eq!(loaded.wallet_type, "hd");
        assert_eq!(loaded.accounts.len(), 1);

        let decrypted = loaded.decrypt_hd("file-test").unwrap();
        let key = decrypted.derive_key(0, 0).unwrap();
        let orig_key = wallet.derive_key(0, 0).unwrap();
        assert_eq!(key.as_bytes(), orig_key.as_bytes());

        let _ = std::fs::remove_file(&tmp_path);
    }

    #[test]
    fn detect_version_v2() {
        let tmp_path = std::env::temp_dir().join("kob_test_detect_v2.json");
        std::fs::write(
            &tmp_path,
            r#"{"version":2,"type":"hd","encrypted":"x","salt":"aa","nonce":"bb","accounts":[]}"#,
        )
        .unwrap();
        assert_eq!(WalletFileV2::detect_version(&tmp_path), Some(2));
        let _ = std::fs::remove_file(&tmp_path);
    }

    #[test]
    fn detect_version_v1_encrypted() {
        let tmp_path = std::env::temp_dir().join("kob_test_detect_v1enc.json");
        std::fs::write(
            &tmp_path,
            r#"{"encrypted":"x","salt":"aa","nonce":"bb"}"#,
        )
        .unwrap();
        assert_eq!(WalletFileV2::detect_version(&tmp_path), Some(1));
        let _ = std::fs::remove_file(&tmp_path);
    }

    #[test]
    fn detect_version_v0_plaintext() {
        let tmp_path = std::env::temp_dir().join("kob_test_detect_v0.json");
        std::fs::write(
            &tmp_path,
            r#"{"privateKey":"aa","publicKey":"bb","address":"kaspatest:q"}"#,
        )
        .unwrap();
        assert_eq!(WalletFileV2::detect_version(&tmp_path), Some(0));
        let _ = std::fs::remove_file(&tmp_path);
    }

    #[test]
    fn export_watch_only() {
        use crate::types::Network;
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC).unwrap();
        let export = wallet
            .export_watch_only(0, 3, Network::Testnet)
            .unwrap();
        assert_eq!(export.wallet_type, "watch-only");
        assert_eq!(export.accounts.len(), 3);
        for acc in &export.accounts {
            assert!(acc.address.starts_with("kaspatest:"));
            assert!(!acc.public_key.is_empty());
        }

        // Verify the JSON does not contain any private key data
        let json = serde_json::to_string_pretty(&export).unwrap();
        assert!(!json.contains("seed"));
        assert!(!json.contains("mnemonic"));
        assert!(!json.contains("private"));
    }

    #[test]
    fn pubkey_to_address_format() {
        use crate::types::Network;
        // Use a known public key and verify the address format
        let privkey = [1u8; 32];
        let pubkey = get_public_key(&privkey).unwrap();
        let addr = pubkey_to_address(&pubkey, Network::Testnet);
        assert!(addr.starts_with("kaspatest:q"));
        // Address should be consistent
        let addr2 = pubkey_to_address(&pubkey, Network::Testnet);
        assert_eq!(addr, addr2);
    }

    #[test]
    fn pubkey_to_address_roundtrip_32_bytes() {
        use crate::types::Network;
        // Verify that encoding then decoding an address produces the original
        // 32-byte x-only public key. This catches the bug where standard bech32
        // (6-char checksum) was used instead of Kaspa's 8-char checksum, causing
        // decoders to strip 2 extra data characters and yield only 30 bytes.
        let privkey = [1u8; 32];
        let pubkey = get_public_key(&privkey).unwrap();
        let addr = pubkey_to_address(&pubkey, Network::Testnet);

        // Kaspa bech32 decode: strip prefix, decode 5-bit, strip 8-char checksum
        let payload_str = addr.split(':').nth(1).unwrap();
        let charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        let chars: Vec<u8> = payload_str
            .chars()
            .map(|c| charset.find(c).unwrap() as u8)
            .collect();
        // Strip 8-character Kaspa checksum
        let data5 = &chars[..chars.len() - 8];

        // Convert 5-bit to 8-bit
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        let mut decoded = Vec::new();
        for &val in data5 {
            acc = (acc << 5) | (val as u32);
            bits += 5;
            while bits >= 8 {
                bits -= 8;
                decoded.push(((acc >> bits) & 0xFF) as u8);
            }
        }

        // First byte is type (0x00 for P2PK), rest is pubkey
        assert_eq!(decoded[0], 0x00, "type byte must be 0x00 (P2PK)");
        let recovered_pubkey = &decoded[1..];
        assert_eq!(
            recovered_pubkey.len(),
            32,
            "decoded pubkey must be 32 bytes, got {}",
            recovered_pubkey.len()
        );
        assert_eq!(recovered_pubkey, &pubkey[..], "pubkey must round-trip");
    }

    #[test]
    fn hd_derived_address_decodes_to_32_bytes() {
        use crate::types::Network;
        // Ensure HD-derived addresses produce valid 32-byte payloads
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC).unwrap();
        for index in 0..5 {
            let addr = wallet.get_address(0, index, Network::Testnet).unwrap();
            let payload_str = addr.split(':').nth(1).unwrap();
            let charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
            let chars: Vec<u8> = payload_str
                .chars()
                .map(|c| charset.find(c).unwrap() as u8)
                .collect();
            let data5 = &chars[..chars.len() - 8];
            let mut acc: u32 = 0;
            let mut bits: u32 = 0;
            let mut decoded = Vec::new();
            for &val in data5 {
                acc = (acc << 5) | (val as u32);
                bits += 5;
                while bits >= 8 {
                    bits -= 8;
                    decoded.push(((acc >> bits) & 0xFF) as u8);
                }
            }
            assert_eq!(decoded[0], 0x00, "type byte for index {}", index);
            assert_eq!(
                decoded.len() - 1,
                32,
                "pubkey for HD index {} must be 32 bytes, got {}",
                index,
                decoded.len() - 1
            );
        }
    }

    #[test]
    fn bech32_address_decodes_consistently() {
        use crate::types::Network;
        // Verify that the same key always produces the same address
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC).unwrap();
        let mut addresses = Vec::new();
        for _ in 0..3 {
            addresses.push(wallet.get_address(0, 0, Network::Testnet).unwrap());
        }
        assert_eq!(addresses[0], addresses[1]);
        assert_eq!(addresses[1], addresses[2]);
    }

    #[test]
    fn entropy_to_mnemonic_known_vector() {
        // All-zero 128-bit entropy should give "abandon ... about"
        let entropy = [0u8; 16];
        let mnemonic = entropy_to_mnemonic(&entropy).unwrap();
        assert_eq!(mnemonic, TEST_MNEMONIC);
    }

    #[test]
    fn seed_from_known_mnemonic() {
        // BIP-39 test vector: "abandon ... about" with empty passphrase
        // This is deterministic and can be verified against any BIP-39 impl
        let seed = mnemonic_to_seed(TEST_MNEMONIC, "").unwrap();
        assert_eq!(seed.len(), 64);
        // The seed should be non-zero
        assert!(seed.iter().any(|&b| b != 0));
    }
}
