//! `kob-cli wallet` -- Show wallet info, balance, UTXOs, and HD wallet management.
//!
//! Provides subcommands:
//!   wallet create              -- Create new HD wallet (shows mnemonic)
//!   wallet create --legacy     -- Create single-key wallet (current behavior)
//!   wallet import --mnemonic   -- Import HD wallet from mnemonic
//!   wallet import --private-key -- Import single-key wallet
//!   wallet list                -- Show all derived addresses
//!   wallet derive --index N    -- Derive address at index N
//!   wallet export --public     -- Export watch-only wallet
//!   wallet balance             -- Show balance for all derived addresses
//!   wallet info                -- Show wallet info (legacy behavior)
//!   wallet utxos               -- List all UTXOs with detailed metadata
//!   wallet consolidate         -- Merge many small UTXOs into fewer larger ones

use crate::node::NodeClient;
use kob_core::wallet::{AccountEntry, HdWallet, WalletFileV2};
use kob_core::types::Network;
use kob_core::wallet::WalletFile;
use std::path::Path;

pub async fn run(wallet_path: &Path, node_url: &str, network: Network) -> anyhow::Result<()> {
    let wallet = WalletFile::load(wallet_path)?;

    println!("Wallet Information");
    println!("==================");
    println!("Address:    {}", wallet.address);
    println!("Public Key: {}", wallet.public_key);
    println!("Network:    {:?}", network);
    println!("Node:       {}", node_url);

    let pk_bytes = wallet.public_key_bytes()?;
    let owner_hash = kob_core::blake2b_256(&pk_bytes);
    println!("Owner Hash: {}", hex::encode(owner_hash));
    println!();

    // Connect to node and query UTXOs
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    let utxos = rpc.get_spendable_utxos(&wallet.address).await?;

    let total: u64 = utxos.iter().map(|u| u.utxo_entry.amount).sum();
    let p2sh_count = utxos.iter().filter(|u| u.is_p2sh()).count();
    let p2pk_count = utxos.len() - p2sh_count;

    println!("Balance:    {} sompi ({:.8} KAS)", total, total as f64 / 1e8);
    println!("UTXOs:      {} total ({} P2PK, {} P2SH)", utxos.len(), p2pk_count, p2sh_count);
    println!();

    if utxos.is_empty() {
        println!("(no UTXOs found)");
        return Ok(());
    }

    // Show top UTXOs (up to 10)
    let show_count = utxos.len().min(10);
    println!("Top {} UTXOs (sorted by amount descending):", show_count);
    println!("{:<66}  {:>4}  {:>14}  {:>6}  {:>10}", "TXID", "IDX", "AMOUNT", "TYPE", "DAA");
    println!("{}", "-".repeat(108));

    for u in utxos.iter().take(show_count) {
        let kind = if u.is_p2sh() { "P2SH" } else { "P2PK" };
        println!(
            "{}  {:>4}  {:>14}  {:>6}  {:>10}",
            u.outpoint.transaction_id,
            u.outpoint.index,
            u.utxo_entry.amount,
            kind,
            u.utxo_entry.block_daa_score,
        );
    }

    if utxos.len() > show_count {
        println!("... and {} more UTXOs", utxos.len() - show_count);
    }

    Ok(())
}

/// Wallet subcommands.
#[derive(clap::Subcommand, Debug)]
pub enum WalletCommand {
    /// Create a new wallet.
    Create {
        /// Create a legacy single-key wallet instead of HD.
        #[arg(long)]
        legacy: bool,

        /// Word count for mnemonic (12 or 24). Default: 12.
        #[arg(long, default_value = "12")]
        words: usize,

        /// Passphrase for encrypting the wallet file.
        #[arg(long)]
        passphrase: Option<String>,

        /// Store wallet without encryption (NOT RECOMMENDED).
        /// Requires explicit opt-in because plaintext wallets are insecure.
        #[arg(long)]
        force_plaintext: bool,
    },

    /// Import a wallet from mnemonic or private key.
    Import {
        /// BIP-39 mnemonic phrase (12 or 24 words, quoted).
        #[arg(long)]
        mnemonic: Option<String>,

        /// Hex-encoded private key (64 hex chars).
        #[arg(long)]
        private_key: Option<String>,

        /// Passphrase for encrypting the wallet file.
        #[arg(long)]
        passphrase: Option<String>,

        /// Store wallet without encryption (NOT RECOMMENDED).
        /// Requires explicit opt-in because plaintext wallets are insecure.
        #[arg(long)]
        force_plaintext: bool,
    },

    /// List all derived addresses for the HD wallet.
    List {
        /// Number of addresses to derive and show. Default: 5.
        #[arg(long, default_value = "5")]
        count: u32,

        /// Account index. Default: 0.
        #[arg(long, default_value = "0")]
        account: u32,
    },

    /// Derive a specific address at the given index.
    Derive {
        /// Address index to derive.
        #[arg(long)]
        index: u32,

        /// Account index. Default: 0.
        #[arg(long, default_value = "0")]
        account: u32,
    },

    /// Export a watch-only wallet (public keys and addresses).
    Export {
        /// Export public-only (watch-only) data.
        #[arg(long)]
        public: bool,

        /// Number of addresses to export. Default: 5.
        #[arg(long, default_value = "5")]
        count: u32,

        /// Account index. Default: 0.
        #[arg(long, default_value = "0")]
        account: u32,

        /// Output file path (defaults to stdout).
        #[arg(long)]
        output: Option<String>,
    },

    /// Show balance for all derived addresses.
    Balance {
        /// Number of addresses to check. Default: 5.
        #[arg(long, default_value = "5")]
        count: u32,

        /// Account index. Default: 0.
        #[arg(long, default_value = "0")]
        account: u32,
    },

    /// Show wallet info (address, public key, owner hash).
    Info,

    /// List all UTXOs with detailed metadata.
    ///
    /// Shows outpoint, value, type (P2PK/P2SH), age (DAA score delta), and
    /// storage mass estimate for each UTXO.
    Utxos {
        /// Filter by specific address (default: wallet address).
        #[arg(long)]
        address: Option<String>,

        /// Only show UTXOs with value >= this amount (sompi).
        #[arg(long)]
        min_value: Option<u64>,

        /// Sort order: value (default) or age.
        #[arg(long, default_value = "value")]
        sort: String,

        /// Output as JSON for scripting.
        #[arg(long)]
        json: bool,
    },

    /// Send KAS to an address.
    Send {
        /// Recipient Kaspa address.
        #[arg(long)]
        to: String,

        /// Amount to send in sompi.
        #[arg(long)]
        amount: Option<u64>,

        /// Amount to send in KAS (float, converted to sompi).
        #[arg(long)]
        amount_kas: Option<f64>,

        /// Fee override in sompi (default: 10000).
        #[arg(long)]
        fee: Option<u64>,
    },

    /// Encrypt an existing plaintext wallet file.
    ///
    /// Reads a plaintext wallet.json and writes an encrypted version using
    /// Argon2id + ChaCha20-Poly1305. The original file is overwritten unless
    /// --output is specified.
    Encrypt {
        /// Passphrase for encryption.
        #[arg(long)]
        passphrase: Option<String>,

        /// Write encrypted wallet to a different file instead of overwriting.
        #[arg(long)]
        output: Option<String>,
    },

    /// Decrypt an encrypted wallet file to plaintext.
    ///
    /// Reads an encrypted wallet and writes the plaintext JSON. Useful for
    /// backup or migration. WARNING: the output contains the private key
    /// in cleartext.
    Decrypt {
        /// Passphrase for decryption.
        #[arg(long)]
        passphrase: Option<String>,

        /// Write plaintext wallet to a different file instead of overwriting.
        #[arg(long)]
        output: Option<String>,
    },

    /// Consolidate many small UTXOs into fewer larger ones.
    ///
    /// Reduces storage mass costs by merging dust UTXOs. Groups eligible P2PK
    /// UTXOs into batches and creates a self-send TX per batch.
    Consolidate {
        /// Number of outputs per consolidation TX (default: 1).
        #[arg(long, default_value = "1")]
        target_count: usize,

        /// Only consolidate UTXOs at or below this value (sompi).
        /// If omitted, all P2PK UTXOs are eligible.
        #[arg(long)]
        min_value: Option<u64>,

        /// Maximum inputs per consolidation TX (default: 84, Kaspa limit).
        #[arg(long, default_value = "84")]
        max_inputs: usize,

        /// Show consolidation plan without submitting transactions.
        #[arg(long)]
        dry_run: bool,

        /// Exclude UTXOs from these transaction IDs (stale-avoidance).
        /// Can be specified multiple times: --exclude-txid <txid1> --exclude-txid <txid2>
        #[arg(long = "exclude-txid")]
        exclude_txids: Vec<String>,
    },
}

/// Execute a wallet subcommand.
pub async fn run_command(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    command: &WalletCommand,
) -> anyhow::Result<()> {
    match command {
        WalletCommand::Create {
            legacy,
            words,
            passphrase,
            force_plaintext,
        } => {
            cmd_create(wallet_path, network, *legacy, *words, passphrase.as_deref(), *force_plaintext).await
        }
        WalletCommand::Import {
            mnemonic,
            private_key,
            passphrase,
            force_plaintext,
        } => {
            cmd_import(
                wallet_path,
                network,
                mnemonic.as_deref(),
                private_key.as_deref(),
                passphrase.as_deref(),
                *force_plaintext,
            )
            .await
        }
        WalletCommand::List { count, account } => {
            cmd_list(wallet_path, network, *account, *count).await
        }
        WalletCommand::Derive { index, account } => {
            cmd_derive(wallet_path, network, *account, *index).await
        }
        WalletCommand::Export {
            public,
            count,
            account,
            output,
        } => {
            cmd_export(
                wallet_path,
                network,
                *public,
                *account,
                *count,
                output.as_deref(),
            )
            .await
        }
        WalletCommand::Balance { count, account } => {
            cmd_balance(wallet_path, node_url, network, *account, *count).await
        }
        WalletCommand::Info => cmd_info(wallet_path, node_url, network).await,
        WalletCommand::Utxos {
            address,
            min_value,
            sort,
            json,
        } => {
            let sort_order = crate::consolidate::UtxoSortOrder::parse_order(sort)?;
            crate::consolidate::cmd_utxos(
                wallet_path,
                node_url,
                network,
                address.as_deref(),
                *min_value,
                sort_order,
                *json,
            )
            .await
        }
        WalletCommand::Send {
            to,
            amount,
            amount_kas,
            fee,
        } => {
            let sompi = match (amount, amount_kas) {
                (Some(s), None) => *s,
                (None, Some(kas)) => (*kas * 1e8) as u64,
                (Some(_), Some(_)) => anyhow::bail!("Specify --amount or --amount-kas, not both"),
                (None, None) => anyhow::bail!("Specify --amount (sompi) or --amount-kas (KAS)"),
            };
            crate::wallet_send::run(wallet_path, node_url, network, to, sompi, *fee).await
        }
        WalletCommand::Encrypt { passphrase, output } => {
            cmd_encrypt(wallet_path, passphrase.as_deref(), output.as_deref()).await
        }
        WalletCommand::Decrypt { passphrase, output } => {
            cmd_decrypt(wallet_path, passphrase.as_deref(), output.as_deref()).await
        }
        WalletCommand::Consolidate {
            target_count,
            min_value,
            max_inputs,
            dry_run,
            exclude_txids,
        } => {
            crate::consolidate::cmd_consolidate(
                wallet_path,
                node_url,
                network,
                *target_count,
                *min_value,
                *max_inputs,
                *dry_run,
                exclude_txids,
            )
            .await
        }
    }
}

/// Create a new wallet.
async fn cmd_create(
    wallet_path: &Path,
    network: Network,
    legacy: bool,
    words: usize,
    passphrase: Option<&str>,
    force_plaintext: bool,
) -> anyhow::Result<()> {
    if wallet_path.exists() {
        anyhow::bail!(
            "Wallet file already exists at {}. Use a different --wallet path or remove the existing file",
            wallet_path.display()
        );
    }

    if legacy {
        // Create a single-key wallet (legacy)
        return cmd_create_legacy(wallet_path, network, passphrase, force_plaintext).await;
    }

    // Require passphrase or explicit opt-out
    let pass = resolve_passphrase(passphrase, force_plaintext)?;

    // Create HD wallet
    let hd = HdWallet::generate(words)?;
    let mnemonic = hd
        .mnemonic()
        .expect("generated wallet always has mnemonic")
        .to_string();

    // Derive first address for display
    let addr = hd.get_address(0, 0, network)?;
    let key = hd.derive_key(0, 0)?;
    let pubkey = kob_core::get_public_key(key.as_bytes())?;

    println!("HD Wallet Created");
    println!("==================");
    println!();
    println!("IMPORTANT: Write down your mnemonic phrase and store it safely.");
    println!("This is the ONLY way to recover your wallet if the file is lost.");
    println!();
    println!("Mnemonic ({} words):", words);
    println!("  {}", mnemonic);
    println!();
    println!("Derivation Path: m/972'/111'/0'/0'");
    println!("Address[0]:      {}", addr);
    println!("Public Key[0]:   {}", hex::encode(pubkey));
    println!("Network:         {:?}", network);

    let accounts = vec![AccountEntry {
        index: 0,
        label: "Default".into(),
        address: addr,
    }];

    let encrypted = WalletFileV2::encrypt_hd(&hd, &pass, accounts)?;
    encrypted.save(wallet_path)?;

    println!();
    println!("Saved to: {}", wallet_path.display());
    println!("Format:   v2 HD (encrypted)");

    Ok(())
}

/// Create a legacy single-key wallet.
async fn cmd_create_legacy(
    wallet_path: &Path,
    network: Network,
    passphrase: Option<&str>,
    force_plaintext: bool,
) -> anyhow::Result<()> {
    use rand::RngCore;

    // Generate random private key
    let mut privkey = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut privkey);

    let pubkey = kob_core::get_public_key(&privkey)?;
    let address = kob_core::wallet::pubkey_to_address(&pubkey, network);

    let wallet = WalletFile {
        private_key: hex::encode(privkey),
        public_key: hex::encode(pubkey),
        address: address.clone(),
    };

    // Zero the raw key
    privkey.iter_mut().for_each(|b| *b = 0);

    if force_plaintext {
        // User explicitly opted out of encryption
        eprintln!("WARNING: Storing wallet WITHOUT encryption. Private key is in plaintext on disk.");
        eprintln!("         Anyone with file access can steal your funds.");
        save_plaintext_wallet(&wallet, wallet_path)?;
        println!("Legacy Wallet Created (plaintext -- NOT RECOMMENDED)");
    } else if let Some(pass) = passphrase {
        if pass.is_empty() {
            anyhow::bail!(
                "Passphrase cannot be empty. Use --force-plaintext to store without encryption."
            );
        }
        let encrypted = kob_core::encrypt_wallet(&wallet, pass)?;
        kob_core::wallet::save_encrypted(&encrypted, wallet_path)?;
        println!("Legacy Wallet Created (encrypted)");
    } else {
        anyhow::bail!(
            "Passphrase required. Use --passphrase <PASS> to encrypt, or --force-plaintext to store unencrypted."
        );
    }

    println!("==================");
    println!("Address:    {}", wallet.address);
    println!("Public Key: {}", wallet.public_key);
    println!("Network:    {:?}", network);
    println!("Saved to:   {}", wallet_path.display());

    Ok(())
}

/// Import a wallet from mnemonic or private key.
async fn cmd_import(
    wallet_path: &Path,
    network: Network,
    mnemonic: Option<&str>,
    private_key: Option<&str>,
    passphrase: Option<&str>,
    force_plaintext: bool,
) -> anyhow::Result<()> {
    if wallet_path.exists() {
        anyhow::bail!(
            "Wallet file already exists at {}. Use a different --wallet path or remove the existing file",
            wallet_path.display()
        );
    }

    match (mnemonic, private_key) {
        (Some(m), None) => {
            // Import HD wallet from mnemonic -- always encrypted
            let pass = resolve_passphrase(passphrase, force_plaintext)?;

            let hd = HdWallet::from_mnemonic(m)?;
            let addr = hd.get_address(0, 0, network)?;
            let key = hd.derive_key(0, 0)?;
            let pubkey = kob_core::get_public_key(key.as_bytes())?;

            let accounts = vec![AccountEntry {
                index: 0,
                label: "Default".into(),
                address: addr.clone(),
            }];

            let encrypted = WalletFileV2::encrypt_hd(&hd, &pass, accounts)?;
            encrypted.save(wallet_path)?;

            println!("HD Wallet Imported");
            println!("==================");
            println!("Address[0]:  {}", addr);
            println!("Public Key:  {}", hex::encode(pubkey));
            println!("Network:     {:?}", network);
            println!("Saved to:    {}", wallet_path.display());
        }
        (None, Some(pk_hex)) => {
            // Import single-key wallet
            let privkey_bytes = hex::decode(pk_hex)?;
            if privkey_bytes.len() != 32 {
                anyhow::bail!("Private key must be 64 hex characters (32 bytes), got {}", privkey_bytes.len());
            }
            let mut privkey = [0u8; 32];
            privkey.copy_from_slice(&privkey_bytes);

            let pubkey = kob_core::get_public_key(&privkey)?;
            let address = kob_core::wallet::pubkey_to_address(&pubkey, network);

            let wallet = WalletFile {
                private_key: hex::encode(privkey),
                public_key: hex::encode(pubkey),
                address: address.clone(),
            };

            privkey.iter_mut().for_each(|b| *b = 0);

            if force_plaintext {
                eprintln!("WARNING: Storing wallet WITHOUT encryption. Private key is in plaintext on disk.");
                save_plaintext_wallet(&wallet, wallet_path)?;
            } else if let Some(pass) = passphrase {
                if pass.is_empty() {
                    anyhow::bail!(
                        "Passphrase cannot be empty. Use --force-plaintext to store without encryption."
                    );
                }
                let encrypted = kob_core::encrypt_wallet(&wallet, pass)?;
                kob_core::wallet::save_encrypted(&encrypted, wallet_path)?;
            } else {
                anyhow::bail!(
                    "Passphrase required. Use --passphrase <PASS> to encrypt, or --force-plaintext to store unencrypted."
                );
            }

            println!("Legacy Wallet Imported");
            println!("==================");
            println!("Address:    {}", wallet.address);
            println!("Public Key: {}", wallet.public_key);
            println!("Saved to:   {}", wallet_path.display());
        }
        (Some(_), Some(_)) => {
            anyhow::bail!("Specify either --mnemonic or --private-key, not both");
        }
        (None, None) => {
            anyhow::bail!("Specify --mnemonic or --private-key to import");
        }
    }

    Ok(())
}

/// List derived addresses for an HD wallet.
async fn cmd_list(
    wallet_path: &Path,
    network: Network,
    account: u32,
    count: u32,
) -> anyhow::Result<()> {
    let hd = load_hd_wallet(wallet_path)?;

    let addrs = hd.derive_addresses(account, count, network)?;

    println!("HD Wallet Addresses (account={})", account);
    println!("==================");
    println!(
        "{:>5}  {:<66}  PUBLIC_KEY",
        "INDEX", "ADDRESS"
    );
    println!("{}", "-".repeat(140));

    for (index, pubkey_hex, address) in &addrs {
        println!("{:>5}  {:<66}  {}", index, address, pubkey_hex);
    }

    Ok(())
}

/// Derive a specific address.
async fn cmd_derive(
    wallet_path: &Path,
    network: Network,
    account: u32,
    index: u32,
) -> anyhow::Result<()> {
    let hd = load_hd_wallet(wallet_path)?;

    let key = hd.derive_key(account, index)?;
    let pubkey = kob_core::get_public_key(key.as_bytes())?;
    let address = kob_core::wallet::pubkey_to_address(&pubkey, network);
    let owner_hash = kob_core::blake2b_256(&pubkey);

    println!("Derived Key at m/972'/111'/{}'/{}' ", account, index);
    println!("==================");
    println!("Address:    {}", address);
    println!("Public Key: {}", hex::encode(pubkey));
    println!("Owner Hash: {}", hex::encode(owner_hash));
    println!("Network:    {:?}", network);

    Ok(())
}

/// Export watch-only wallet data.
async fn cmd_export(
    wallet_path: &Path,
    network: Network,
    public_only: bool,
    account: u32,
    count: u32,
    output_path: Option<&str>,
) -> anyhow::Result<()> {
    if !public_only {
        anyhow::bail!("Currently only --public export is supported (watch-only)");
    }

    let hd = load_hd_wallet(wallet_path)?;
    let export = hd.export_watch_only(account, count, network)?;
    let json = serde_json::to_string_pretty(&export)?;

    if let Some(path) = output_path {
        std::fs::write(path, &json)?;
        println!("Watch-only wallet exported to: {}", path);
    } else {
        println!("{}", json);
    }

    Ok(())
}

/// Show balance for all derived addresses (HD) or the single address (legacy).
async fn cmd_balance(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    account: u32,
    count: u32,
) -> anyhow::Result<()> {
    let version = WalletFileV2::detect_version(wallet_path);

    match version {
        Some(2) => {
            // HD wallet -- derive and show balance for each address
            let hd = load_hd_wallet(wallet_path)?;
            let addrs = hd.derive_addresses(account, count, network)?;

            println!("HD Wallet Balance (account={})", account);
            println!("==================");
            println!("Connecting to {}...", node_url);

            let rpc = NodeClient::connect(node_url).await?;

            let mut grand_total: u64 = 0;
            let mut grand_utxos: usize = 0;

            println!(
                "{:>5}  {:>14}  {:>5}  ADDRESS",
                "INDEX", "BALANCE (KAS)", "UTXOs"
            );
            println!("{}", "-".repeat(100));

            for (index, _pubkey_hex, address) in &addrs {
                let utxos = rpc.get_utxos_by_addresses(&[address.as_str()]).await?;
                let total: u64 = utxos.iter().map(|u| u.utxo_entry.amount).sum();
                let utxo_count = utxos.len();

                grand_total += total;
                grand_utxos += utxo_count;

                // Only show addresses with balance, or first address always
                if total > 0 || *index == 0 {
                    println!(
                        "{:>5}  {:>14.8}  {:>5}  {}",
                        index,
                        total as f64 / 1e8,
                        utxo_count,
                        address,
                    );
                }
            }

            println!("{}", "-".repeat(100));
            println!(
                "{:>5}  {:>14.8}  {:>5}",
                "TOTAL",
                grand_total as f64 / 1e8,
                grand_utxos,
            );
        }
        Some(0) | Some(1) => {
            // Legacy single-key wallet
            let wallet = if version == Some(1) {
                load_legacy_encrypted(wallet_path)?
            } else {
                WalletFile::load(wallet_path)?
            };

            println!("Legacy Wallet Balance");
            println!("==================");
            println!("Address:    {}", wallet.address);
            println!("Connecting to {}...", node_url);

            let rpc = NodeClient::connect(node_url).await?;
            let utxos = rpc.get_spendable_utxos(&wallet.address).await?;
            let total: u64 = utxos.iter().map(|u| u.utxo_entry.amount).sum();
            println!("Balance:    {:.8} KAS ({} UTXOs)", total as f64 / 1e8, utxos.len());
        }
        _ => {
            anyhow::bail!(
                "Wallet file not found or unrecognized format: {}",
                wallet_path.display()
            );
        }
    }

    Ok(())
}

/// Show wallet info (legacy behavior, works with both HD and single-key).
async fn cmd_info(wallet_path: &Path, node_url: &str, network: Network) -> anyhow::Result<()> {
    // Detect wallet version
    let version = WalletFileV2::detect_version(wallet_path);

    match version {
        Some(2) => {
            // HD wallet -- show first address info
            let hd = load_hd_wallet(wallet_path)?;
            let key = hd.derive_key(0, 0)?;
            let pubkey = kob_core::get_public_key(key.as_bytes())?;
            let address = kob_core::wallet::pubkey_to_address(&pubkey, network);
            let owner_hash = kob_core::blake2b_256(&pubkey);

            println!("HD Wallet Information");
            println!("==================");
            println!("Type:       HD (v2)");
            println!("Address[0]: {}", address);
            println!("PubKey[0]:  {}", hex::encode(pubkey));
            println!("OwnerHash:  {}", hex::encode(owner_hash));
            println!("Network:    {:?}", network);

            if let Some(mnemonic) = hd.mnemonic() {
                let word_count = mnemonic.split_whitespace().count();
                println!("Mnemonic:   {} words (stored)", word_count);
            }

            // Show account entries from the wallet file
            if let Ok(v2) = WalletFileV2::load(wallet_path) {
                if !v2.accounts.is_empty() {
                    println!();
                    println!("Stored Accounts:");
                    for acc in &v2.accounts {
                        let label = if acc.label.is_empty() {
                            "(unlabeled)".to_string()
                        } else {
                            acc.label.clone()
                        };
                        println!("  [{}] {} - {}", acc.index, label, acc.address);
                    }
                }
            }

            println!();
            println!("Connecting to {}...", node_url);
            let rpc = NodeClient::connect(node_url).await?;
            let utxos = rpc.get_utxos_by_addresses(&[address.as_str()]).await?;
            let total: u64 = utxos.iter().map(|u| u.utxo_entry.amount).sum();
            println!("Balance[0]: {:.8} KAS ({} UTXOs)", total as f64 / 1e8, utxos.len());
        }
        Some(0) | Some(1) => {
            // Legacy wallet
            let wallet = if version == Some(1) {
                // Encrypted v1 -- try KOB_PASSPHRASE env var, then prompt
                load_legacy_encrypted(wallet_path)?
            } else {
                WalletFile::load(wallet_path)?
            };

            println!("Legacy Wallet Information");
            println!("==================");
            println!("Type:       Legacy (single-key)");
            println!("Address:    {}", wallet.address);
            println!("Public Key: {}", wallet.public_key);
            println!("Network:    {:?}", network);

            let pk_bytes = wallet.public_key_bytes()?;
            let owner_hash = kob_core::blake2b_256(&pk_bytes);
            println!("Owner Hash: {}", hex::encode(owner_hash));

            println!();
            println!("Connecting to {}...", node_url);
            let rpc = NodeClient::connect(node_url).await?;
            let utxos = rpc.get_spendable_utxos(&wallet.address).await?;
            let total: u64 = utxos.iter().map(|u| u.utxo_entry.amount).sum();
            println!("Balance:    {:.8} KAS ({} UTXOs)", total as f64 / 1e8, utxos.len());
        }
        _ => {
            anyhow::bail!(
                "Wallet file not found or unrecognized format: {}",
                wallet_path.display()
            );
        }
    }

    Ok(())
}

/// Load an encrypted v1 legacy wallet, trying env var then prompting.
fn load_legacy_encrypted(wallet_path: &Path) -> anyhow::Result<WalletFile> {
    // 1. Try KOB_PASSPHRASE env var
    if let Ok(env_pass) = std::env::var("KOB_PASSPHRASE") {
        if let Ok(w) = WalletFile::load_auto(wallet_path, Some(&env_pass)) {
            return Ok(w);
        }
        eprintln!("WARNING: KOB_PASSPHRASE env var did not decrypt wallet.");
    }

    // 2. Prompt interactively
    eprint!("Enter wallet passphrase: ");
    let mut passphrase = String::new();
    std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut passphrase)?;
    let passphrase = passphrase.trim_end();

    if passphrase.is_empty() {
        anyhow::bail!(
            "Encrypted v1 wallet requires a passphrase. Set KOB_PASSPHRASE env var or provide one."
        );
    }

    WalletFile::load_auto(wallet_path, Some(passphrase))
        .map_err(|e| anyhow::anyhow!("Failed to decrypt wallet: {}", e))
}

/// Load an HD wallet from a v2 wallet file.
///
/// Tries passphrase from KOB_PASSPHRASE env var first. If not set,
/// prompts for passphrase interactively (stderr, so stdout stays clean for piping).
fn load_hd_wallet(wallet_path: &Path) -> anyhow::Result<HdWallet> {
    let v2 = WalletFileV2::load(wallet_path)?;

    // 1. Try KOB_PASSPHRASE env var
    if let Ok(env_pass) = std::env::var("KOB_PASSPHRASE") {
        if let Ok(hd) = v2.decrypt_hd(&env_pass) {
            return Ok(hd);
        }
        // Wrong passphrase from env -- fall through to prompt
        eprintln!("WARNING: KOB_PASSPHRASE env var did not decrypt wallet.");
    }

    // 2. Try legacy default passphrase for backward compatibility with existing wallet files
    if let Ok(hd) = v2.decrypt_hd("kob-default-passphrase") {
        eprintln!("WARNING: Wallet encrypted with legacy default passphrase.");
        eprintln!("         Re-create with --passphrase for better security.");
        return Ok(hd);
    }

    // 3. Prompt interactively
    eprint!("Enter wallet passphrase: ");
    let mut passphrase = String::new();
    std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut passphrase)?;
    let passphrase = passphrase.trim_end();

    v2.decrypt_hd(passphrase)
        .map_err(|e| anyhow::anyhow!("Failed to decrypt HD wallet: {}", e))
}

/// Resolve passphrase for wallet creation/import.
///
/// Rules:
/// - If `--force-plaintext`: not allowed for HD wallets (always encrypted), error
/// - If `--passphrase <PASS>`: use it (must be non-empty)
/// - If neither: check `KOB_PASSPHRASE` env var
/// - If nothing: prompt interactively
///
/// For HD wallets, `force_plaintext` should trigger an error at the call site
/// since WalletFileV2 requires a non-empty passphrase.
fn resolve_passphrase(
    passphrase: Option<&str>,
    force_plaintext: bool,
) -> anyhow::Result<String> {
    if force_plaintext {
        anyhow::bail!(
            "HD wallets are always encrypted. --force-plaintext is only for legacy wallets.\n\
             Use --passphrase <PASS> to set your encryption passphrase."
        );
    }

    if let Some(pass) = passphrase {
        if pass.is_empty() {
            anyhow::bail!("Passphrase cannot be empty. Use a strong passphrase to protect your wallet");
        }
        return Ok(pass.to_string());
    }

    // Try env var
    if let Ok(env_pass) = std::env::var("KOB_PASSPHRASE") {
        if !env_pass.is_empty() {
            return Ok(env_pass);
        }
    }

    // Prompt interactively
    eprint!("Enter passphrase for wallet encryption: ");
    let mut passphrase = String::new();
    std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut passphrase)?;
    let passphrase = passphrase.trim_end().to_string();

    if passphrase.is_empty() {
        anyhow::bail!(
            "Passphrase is required for HD wallets. Use --passphrase <PASS> or set KOB_PASSPHRASE env var."
        );
    }

    Ok(passphrase)
}

/// Save a plaintext wallet file with restricted permissions.
///
/// On Unix, creates the file with mode 0o600 atomically to prevent a TOCTOU
/// window where private key material could be world-readable.
fn save_plaintext_wallet(wallet: &WalletFile, path: &Path) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(wallet)?;

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(json.as_bytes())?;
        file.flush()?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, &json)?;
    }

    Ok(())
}

/// Encrypt a plaintext wallet file.
///
/// Reads a v0 plaintext wallet, encrypts it, and writes the encrypted version.
/// If `--output` is specified, writes to a new file; otherwise overwrites in place.
async fn cmd_encrypt(
    wallet_path: &Path,
    passphrase: Option<&str>,
    output: Option<&str>,
) -> anyhow::Result<()> {
    use kob_core::wallet::WalletFileV2;

    // Detect version first
    let version = WalletFileV2::detect_version(wallet_path);
    match version {
        Some(1) => anyhow::bail!("Wallet is already encrypted (legacy v1 format). Decrypt first with 'kob wallet decrypt', then re-encrypt"),
        Some(2) => anyhow::bail!("Wallet is already encrypted (v2 HD format). Decrypt first with 'kob wallet decrypt', then re-encrypt"),
        Some(0) => {} // plaintext -- proceed
        None => anyhow::bail!(
            "Wallet file not found or unrecognized format: {}",
            wallet_path.display()
        ),
        Some(v) => anyhow::bail!("Unknown wallet version: {}", v),
    }

    // Load plaintext wallet
    let wallet = WalletFile::load(wallet_path)?;

    // Resolve passphrase
    let pass = match passphrase {
        Some(p) if !p.is_empty() => p.to_string(),
        Some(_) => anyhow::bail!("Empty passphrase is not allowed."),
        None => {
            // Try env var
            if let Ok(env_pass) = std::env::var("KOB_PASSPHRASE") {
                if !env_pass.is_empty() {
                    env_pass
                } else {
                    anyhow::bail!(
                        "Passphrase required. Use --passphrase <PASS> or set KOB_PASSPHRASE env var."
                    );
                }
            } else {
                // Prompt interactively
                eprint!("Enter passphrase for encryption: ");
                let mut input = String::new();
                std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut input)?;
                let input = input.trim_end().to_string();
                if input.is_empty() {
                    anyhow::bail!("Passphrase required.");
                }
                input
            }
        }
    };

    let encrypted = kob_core::encrypt_wallet(&wallet, &pass)?;
    let dest = if let Some(out) = output {
        std::path::PathBuf::from(out)
    } else {
        wallet_path.to_path_buf()
    };
    kob_core::wallet::save_encrypted(&encrypted, &dest)?;

    println!("Wallet encrypted successfully.");
    println!("Output: {}", dest.display());
    if output.is_none() {
        println!("(Original plaintext file overwritten.)");
    }

    Ok(())
}

/// Decrypt an encrypted wallet file to plaintext.
///
/// Reads an encrypted v1 wallet, decrypts it, and writes plaintext JSON.
/// If `--output` is specified, writes to a new file; otherwise overwrites in place.
async fn cmd_decrypt(
    wallet_path: &Path,
    passphrase: Option<&str>,
    output: Option<&str>,
) -> anyhow::Result<()> {
    use kob_core::wallet::WalletFileV2;

    let version = WalletFileV2::detect_version(wallet_path);
    match version {
        Some(0) => anyhow::bail!("Wallet is already in plaintext format."),
        Some(2) => anyhow::bail!(
            "v2 HD wallets cannot be decrypted to plaintext. Use `wallet export --public` for watch-only export."
        ),
        Some(1) => {} // encrypted v1 -- proceed
        None => anyhow::bail!(
            "Wallet file not found or unrecognized format: {}",
            wallet_path.display()
        ),
        Some(v) => anyhow::bail!("Unknown wallet version: {}", v),
    }

    // Resolve passphrase
    let pass = match passphrase {
        Some(p) if !p.is_empty() => p.to_string(),
        Some(_) => anyhow::bail!("Empty passphrase is not allowed."),
        None => {
            if let Ok(env_pass) = std::env::var("KOB_PASSPHRASE") {
                if !env_pass.is_empty() {
                    env_pass
                } else {
                    anyhow::bail!(
                        "Passphrase required. Use --passphrase <PASS> or set KOB_PASSPHRASE env var."
                    );
                }
            } else {
                eprint!("Enter wallet passphrase: ");
                let mut input = String::new();
                std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut input)?;
                let input = input.trim_end().to_string();
                if input.is_empty() {
                    anyhow::bail!("Passphrase required.");
                }
                input
            }
        }
    };

    let wallet = WalletFile::load_auto(wallet_path, Some(&pass))?;

    let dest = if let Some(out) = output {
        std::path::PathBuf::from(out)
    } else {
        wallet_path.to_path_buf()
    };

    eprintln!("WARNING: Writing private key in PLAINTEXT to {}.", dest.display());
    eprintln!("         Anyone with file access can steal your funds.");
    save_plaintext_wallet(&wallet, &dest)?;

    println!("Wallet decrypted successfully.");
    println!("Output: {}", dest.display());

    Ok(())
}
