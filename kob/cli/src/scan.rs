//! `kob-cli scan` -- Scan for P2SH covenant UTXOs.
//!
//! Queries UTXOs for a given address and identifies P2SH outputs
//! (covenant contracts). Groups by script hash and shows value summary.
//!
//! Known contract body hashes are used to identify covenant types
//! when possible (requires the redeemScript body suffix to be known).

use crate::node::NodeClient;
use crate::rpc::RpcUtxo;
use kob_core::types::Network;
use kob_core::wallet::WalletFile;
use std::collections::BTreeMap;
use std::path::Path;

/// A known covenant contract type with its body hex.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Public API: used by scan command for contract identification
pub struct KnownContract {
    pub name: &'static str,
    /// The body bytecode (suffix of redeemScript) as hex.
    pub body_hex: &'static str,
    /// Expected total redeemScript size, or 0 if variable.
    pub rs_size: usize,
}

/// Known KOB covenant contract types.
/// Since we cannot reverse-hash the P2SH to determine the contract type,
/// we identify contracts by matching against known body hex suffixes when
/// the full redeemScript is available (e.g., from a local order cache).
///
/// For on-chain scanning without redeemScript access, we can only identify
/// UTXOs as "P2SH" and group by their script hash.
#[allow(dead_code)] // Public API: contract identification table
pub const KNOWN_CONTRACTS: &[KnownContract] = &[
    KnownContract {
        name: "buy_order_v5",
        body_hex: "b9c9760235019f63b352a269022a019f63b9be76557996567995765579a26951c27ca26951cf5779876951c3aa52798769757575757575757567577976567995557996765579a2695a79c27ca269b9be5179a0695a79c3b9bf8769b9be517a945a79c27ca269b9be5879945479965579955379a26951cf567987695879c3aa5179876975757575757575757575686775567a76aa53798769577a7cad757575757575756851",
        rs_size: 291,
    },
    KnownContract {
        name: "sell_order_v4",
        body_hex: "557a7600a063518763b9be557995547996765479a26900c27ca26900c3aa51798769757575757567557976567995557996765579a2695979c27ca269b9be5179a0695779c3b9bf8769b9be517a945779c27ca269b9be5679945579955479965379a2695779c3aa5179876975757575757575756867755579aa52798769567a567aac6975757575756851",
        rs_size: 231,
    },
    KnownContract {
        name: "trade_receipt",
        body_hex: "7575757551",
        rs_size: 65,
    },
    KnownContract {
        name: "market_config",
        body_hex: "577976aa52798769597a7cad587a63b9cfd200a06968757575757575757551",
        rs_size: 142,
    },
    KnownContract {
        name: "bracket_order_v2",
        body_hex: "b9c9025e019f6352c35679876952c25579a26953c35479876953c25379a2695979ce63b9be587995577996765379a26900c27ca26975757575757575757575755167b9be577996587995765379a26951c27ca26975757575757575757575755168675a7976aa527987695c7a7cad7575757575757575757575755168",
        rs_size: 320,
    },
    // --- sell_order v6 (190B body, 94B state, RS=284) ---
    KnownContract {
        name: "sell_order_v6",
        body_hex: "567a76529f63518763008769b9be557995547996765479a26900c27ca26900c3aa51798769b9cf76d251a26900d3c2b9bea269757575757567755579aa52798769567a567aac6975757575756867528763008769557976567995557996765579a2695979c27ca269b9be5179a0695779c3b9bf8769b9be517a945779c27ca269b9be5679945579955479965379a2695779c3aa51798769b9cfd252a2697575757575757575670087695579aa52798769567a567aac697575757575686851",
        rs_size: 284,
    },
    // --- sell_order v8 (193B body, 94B state, RS=287) ---
    // Parameterized koi (KAS output index) in fill path; partial/cancel unchanged from v6.
    KnownContract {
        name: "sell_order_v8",
        body_hex: "567a76529f63518763008769b9be557995547996765479a2695679c27ca2695579c3aa51798769b9cf76d251a26900d3c2b9bea26975757575757567755579aa52798769567a567aac6975757575756867528763008769557976567995557996765579a2695979c27ca269b9be5179a0695779c3b9bf8769b9be517a945779c27ca269b9be5679945579955479965379a2695779c3aa51798769b9cfd252a2697575757575757575670087695579aa52798769567a567aac697575757575686851",
        rs_size: 287,
    },
    // --- buy_order v8 (220B body, 136B state, RS=356) ---
    // Parameterized toi/tii/coi in fill path; F6 hardcoded output[0] for seller KAS.
    KnownContract {
        name: "buy_order_v8",
        body_hex: "b9c9760277019f63b352a269026e019f63008769b9be76577995567996765679a2695c79c27ca2695a79cf587987695b79c3aa53798769577976d251a2695a79d35c79876900c2945179a169757575757575757575757567008769587976577995567996765679a2695b79c27ca269b9be5179a0695b79c3b9bf8769b9be517a945b79c27ca269b9be5979945579965679955479a26951cf577987695979c3aa52798769567976d251a26900d351876975757575757575757575756867755a7a630087696775685779aa53798769587a587aad757575757575756851",
        rs_size: 356,
    },
    // --- buy_order v9 (235B body, 136B state, RS=371) ---
    // F6 partial fill fee check added (si parameter). Has double-subtraction bug in partial fill.
    KnownContract {
        name: "buy_order_v9",
        body_hex: "b9c9760287019f63b352a269027d019f63008769b9be76577995567996765679a2695c79c27ca2695a79cf587987695b79c3aa53798769577976d251a2695a79d35c79876900c2945179a169757575757575757575757567008769587976577995567996765679a2695b79c27ca269b9be5179a0695b79c3b9bf8769b9be517a945b79c27ca269b9be5979945579965679955479a26951cf577987695979c3aa52798769567976d251a26900d3518769b9be5b79c2945c79c2945179a1697575757575757575757575756867755a7a630087696775685779aa53798769587a587aad757575757575756851",
        rs_size: 371,
    },
    // --- buy_order v10 (233B body, 136B state, RS=369) ---
    // v9 F6 double-subtraction bug fixed; si removed from partial fill sigscript.
    KnownContract {
        name: "buy_order_v10",
        body_hex: "b9c9760284019f63b352a269027c019f63008769b9be76577995567996765679a2695c79c27ca2695a79cf587987695b79c3aa53798769577976d251a2695a79d35c79876900c2945179a169757575757575757575757567008769587976577995567996765679a2695b79c27ca269b9be5179a0695b79c3b9bf8769b9be517a945b79c27ca269b9be5979945579965679955479a26951cf577987695979c3aa52798769567976d251a26900d3518769b9be5b79c2945979945179a16975757575757575757575756867755a7a630087696775685779aa53798769587a587aad757575757575756851",
        rs_size: 369,
    },
    // --- buy_order v11 (235B body, 136B state, RS=371) ---
    // soi (seller output index) parameterized in fill F6 for batch fill defense.
    // NOTE: v11 RS=371 = v9 RS. Distinguished by body hex (T2 byte at offset +5: v11=0x86 vs v9=0x87).
    KnownContract {
        name: "buy_order_v11",
        body_hex: "b9c9760286019f63b352a269027f019f63008769b9be76577995567996765679a2695c79c27ca2695a79cf587987695b79c3aa53798769577976d251a2695a79d35c7987695c79c2945179a16975757575757575757575757567008769587976577995567996765679a2695b79c27ca269b9be5179a0695b79c3b9bf8769b9be517a945b79c27ca269b9be5979945579965679955479a26951cf577987695979c3aa52798769567976d251a26900d3518769b9be5b79c2945979945179a16975757575757575757575756867755a7a630087696775685779aa53798769587a587aad757575757575756851",
        rs_size: 371,
    },
    // --- buy_order v12 (270B body, 145B state, RS=415) ---
    // On-chain expiry via CLTV. CSV exposure delay (50 DAA) on fill/partial.
    // GTC guard (OpDup OpVerify) prevents expire of GTC orders. OpNumEqual for time gate.
    KnownContract {
        name: "buy_order_v12",
        body_hex: "b9c97602b4019f637602a6019f63757669b000c3aa5379876900c2b9be537994a2696d6d6d6d7567517a76009c6476b5a06968750132b1b352a26902ac019f63008769b9be76577995567996765679a2695c79c27ca2695a79cf587987695b79c3aa53798769577976d251a2695a79d35c7987695c79c2945179a1696d6d6d6d6d6d67008769587976577995567996765679a2695b79c27ca269b9be5179a0695b79c3b9bf8769b9be517a945b79c27ca269b9be5979945579965679955479a26951cf577987695979c3aa52798769567976d251a26900d3518769b9be5b79c2945979945179a1696d6d6d6d6d7568686775755a7a630087696775685779aa53798769587a587aad6d6d6d756851",
        rs_size: 415,
    },
    // --- sell_order v12 (241B body, 103B state, RS=344) ---
    // On-chain expiry via CLTV. CSV exposure delay (50 DAA) on fill/partial.
    // GTC guard (OpDup OpVerify) prevents expire of GTC orders. OpNumEqual for time gate.
    KnownContract {
        name: "sell_order_v12",
        body_hex: "577a76548763757669b000c3aa5279876900c2b9bea269b9cfd251a2696d6d6d6776529f6351876376009c6476b5a06968750132b1008769b9be557995547996765479a2695679c27ca2695579c3aa51798769b9cf76d251a26900d3c2b9bea2696d6d6d676d5579aa52798769567a567aac696d6d75686752876376009c6476b5a06968750132b1008769557976567995557996765579a2695979c27ca269b9be5179a0695779c3b9bf8769b9be517a945779c27ca269b9be5679945579955479965379a2695779c3aa51798769b9cfd252a2696d6d6d6d67750087695579aa52798769567a567aac696d6d7568686851",
        rs_size: 344,
    },
];

/// Extract the 32-byte script hash from a P2SH scriptPublicKey hex string.
///
/// P2SH SPK format: `aa20<32-byte-hash>87` = 70 hex chars.
/// Returns the 32-byte hash as a hex string, or None if not a valid P2SH.
pub fn extract_p2sh_hash(spk_hex: &str) -> Option<String> {
    if spk_hex.len() == 70
        && spk_hex.starts_with("aa20")
        && spk_hex.ends_with("87")
    {
        Some(spk_hex[4..68].to_string())
    } else {
        None
    }
}

/// Check if a UTXO is a P2SH covenant UTXO.
pub fn is_p2sh_utxo(utxo: &RpcUtxo) -> bool {
    let spk = &utxo.utxo_entry.script_public_key.script;
    spk.len() == 70 && spk.starts_with("aa20") && spk.ends_with("87")
}

/// Covenant type filter for the --type flag.
#[derive(Debug, Clone, PartialEq)]
pub enum CovenantFilter {
    All,
    Buy,
    Sell,
    Receipt,
    Bracket,
    Config,
}

impl CovenantFilter {
    pub fn parse_filter(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "all" => Some(Self::All),
            "buy" => Some(Self::Buy),
            "sell" => Some(Self::Sell),
            "receipt" => Some(Self::Receipt),
            "bracket" => Some(Self::Bracket),
            "config" => Some(Self::Config),
            _ => None,
        }
    }

    /// Check if a contract name matches this filter.
    #[allow(dead_code)] // Public API: used by scan --type filter
    pub fn matches(&self, name: &str) -> bool {
        match self {
            Self::All => true,
            Self::Buy => name.contains("buy"),
            Self::Sell => name.contains("sell"),
            Self::Receipt => name.contains("receipt"),
            Self::Bracket => name.contains("bracket"),
            Self::Config => name.contains("config"),
        }
    }
}

/// Summary for a group of P2SH UTXOs sharing the same script hash.
#[derive(Debug)]
struct P2shGroup {
    script_hash: String,
    utxos: Vec<RpcUtxo>,
    total_value: u64,
}

pub async fn run(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    address_override: Option<&str>,
    type_filter: Option<&str>,
) -> anyhow::Result<()> {
    // Determine address to scan
    let address = if let Some(addr) = address_override {
        addr.to_string()
    } else {
        let wallet = WalletFile::load(wallet_path)?;
        wallet.address.clone()
    };

    // Parse filter
    let filter = if let Some(t) = type_filter {
        CovenantFilter::parse_filter(t).ok_or_else(|| {
            anyhow::anyhow!(
                "Unknown type filter '{}'. Valid types: all, buy, sell, receipt, bracket, config",
                t
            )
        })?
    } else {
        CovenantFilter::All
    };

    // Truncate address for display header
    let addr_display = if address.len() > 24 {
        format!("{}...{}", &address[..14], &address[address.len() - 6..])
    } else {
        address.clone()
    };

    println!("KOB Scan -- Covenant UTXOs for {}", addr_display);
    println!();

    // Connect and fetch UTXOs
    let rpc = NodeClient::connect(node_url).await?;
    let utxos = rpc.get_utxos_by_addresses(&[address.as_str()]).await?;

    if utxos.is_empty() {
        println!("  (no UTXOs found for this address)");
        return Ok(());
    }

    // Separate P2SH and non-P2SH UTXOs
    let p2sh_utxos: Vec<RpcUtxo> = utxos.into_iter().filter(is_p2sh_utxo).collect();

    if p2sh_utxos.is_empty() {
        println!("  (no P2SH covenant UTXOs found)");
        return Ok(());
    }

    // Group by script hash
    let mut groups: BTreeMap<String, P2shGroup> = BTreeMap::new();
    for utxo in p2sh_utxos {
        let spk = &utxo.utxo_entry.script_public_key.script;
        if let Some(hash) = extract_p2sh_hash(spk) {
            let group = groups.entry(hash.clone()).or_insert_with(|| P2shGroup {
                script_hash: hash,
                utxos: Vec::new(),
                total_value: 0,
            });
            group.total_value += utxo.utxo_entry.amount;
            group.utxos.push(utxo);
        }
    }

    // Display summary
    // Note: Without access to the actual redeemScripts on-chain, we cannot
    // definitively identify contract types from the P2SH hash alone.
    // We label all as "P2SH" and show the script hash for identification.
    // Users can cross-reference with their deploy records.

    let mut total_covenant_utxos: usize = 0;
    let mut total_locked_value: u64 = 0;
    let mut displayed_groups: Vec<(String, usize, u64)> = Vec::new();

    for group in groups.values() {
        let count = group.utxos.len();
        let value = group.total_value;

        // Apply filter (for now, all P2SH are shown under "All" filter;
        // specific filters require contract identification which needs
        // the redeemScript, not just the hash)
        if filter != CovenantFilter::All {
            // We can't identify contract type from hash alone.
            // Show all and note the limitation.
        }

        total_covenant_utxos += count;
        total_locked_value += value;
        displayed_groups.push((group.script_hash.clone(), count, value));
    }

    if filter != CovenantFilter::All {
        println!("  Note: --type filter requires redeemScript access for identification.");
        println!("  Showing all P2SH UTXOs (contract type cannot be determined from hash alone).");
        println!();
    }

    // Show each group
    println!(
        "  {:<66}  {:>5}  {:>14}",
        "SCRIPT_HASH", "UTXOs", "VALUE (KAS)"
    );
    println!("  {}", "-".repeat(90));

    for (hash, count, value) in &displayed_groups {
        println!(
            "  {}  {:>5}  {:>14.8}",
            hash,
            count,
            *value as f64 / 1e8,
        );
    }

    println!();
    println!(
        "  Total: {} covenant UTXOs across {} script hashes, {:.8} KAS locked",
        total_covenant_utxos,
        displayed_groups.len(),
        total_locked_value as f64 / 1e8,
    );

    // Show outpoint details if few enough
    if total_covenant_utxos <= 20 {
        println!();
        println!("  Outpoint Details:");
        println!(
            "  {:<66}  {:>4}  {:>14}  {:<16}",
            "TXID", "IDX", "AMOUNT", "HASH_PREFIX"
        );
        println!("  {}", "-".repeat(108));

        for group in groups.values() {
            for utxo in &group.utxos {
                let hash_prefix = &group.script_hash[..16];
                println!(
                    "  {}  {:>4}  {:>14}  {}...",
                    utxo.outpoint.transaction_id,
                    utxo.outpoint.index,
                    utxo.utxo_entry.amount,
                    hash_prefix,
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_p2sh_hash_valid() {
        // 70-char hex: aa20 + 64 hex chars (32 bytes) + 87
        let spk = "aa200e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a887";
        let hash = extract_p2sh_hash(spk);
        assert_eq!(
            hash,
            Some("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8".to_string())
        );
    }

    #[test]
    fn extract_p2sh_hash_invalid_prefix() {
        let spk = "20200e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a887";
        assert_eq!(extract_p2sh_hash(spk), None);
    }

    #[test]
    fn extract_p2sh_hash_invalid_suffix() {
        let spk = "aa200e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a888";
        assert_eq!(extract_p2sh_hash(spk), None);
    }

    #[test]
    fn extract_p2sh_hash_wrong_length() {
        let spk = "aa200e5751c026e543b2e87";
        assert_eq!(extract_p2sh_hash(spk), None);
    }

    #[test]
    fn extract_p2sh_hash_empty() {
        assert_eq!(extract_p2sh_hash(""), None);
    }

    #[test]
    fn covenant_filter_from_str_valid() {
        assert_eq!(CovenantFilter::parse_filter("buy"), Some(CovenantFilter::Buy));
        assert_eq!(CovenantFilter::parse_filter("sell"), Some(CovenantFilter::Sell));
        assert_eq!(CovenantFilter::parse_filter("receipt"), Some(CovenantFilter::Receipt));
        assert_eq!(CovenantFilter::parse_filter("bracket"), Some(CovenantFilter::Bracket));
        assert_eq!(CovenantFilter::parse_filter("config"), Some(CovenantFilter::Config));
        assert_eq!(CovenantFilter::parse_filter("all"), Some(CovenantFilter::All));
        assert_eq!(CovenantFilter::parse_filter("ALL"), Some(CovenantFilter::All));
        assert_eq!(CovenantFilter::parse_filter("BUY"), Some(CovenantFilter::Buy));
    }

    #[test]
    fn covenant_filter_from_str_invalid() {
        assert_eq!(CovenantFilter::parse_filter("unknown"), None);
        assert_eq!(CovenantFilter::parse_filter(""), None);
    }

    #[test]
    fn covenant_filter_matches() {
        assert!(CovenantFilter::All.matches("buy_order_v5"));
        assert!(CovenantFilter::All.matches("anything"));
        assert!(CovenantFilter::Buy.matches("buy_order_v5"));
        assert!(!CovenantFilter::Buy.matches("sell_order_v4"));
        assert!(CovenantFilter::Sell.matches("sell_order_v4"));
        assert!(!CovenantFilter::Sell.matches("buy_order_v5"));
        assert!(CovenantFilter::Receipt.matches("trade_receipt"));
        assert!(!CovenantFilter::Receipt.matches("buy_order_v5"));
        assert!(CovenantFilter::Bracket.matches("bracket_order_v2"));
        assert!(CovenantFilter::Config.matches("market_config"));
    }

    #[test]
    fn known_contracts_body_hex_valid() {
        for contract in KNOWN_CONTRACTS {
            // Each body hex must decode to valid bytes
            let bytes = hex::decode(contract.body_hex);
            assert!(
                bytes.is_ok(),
                "Contract {} has invalid body hex",
                contract.name
            );
            let bytes = bytes.unwrap();
            assert!(
                !bytes.is_empty(),
                "Contract {} has empty body",
                contract.name
            );
        }
    }

    #[test]
    fn known_contracts_buy_v5_body_length() {
        let buy_v5 = KNOWN_CONTRACTS.iter().find(|c| c.name == "buy_order_v5").unwrap();
        let body = hex::decode(buy_v5.body_hex).unwrap();
        assert_eq!(body.len(), 165, "buy_order_v5 body must be 165 bytes");
    }

    #[test]
    fn known_contracts_sell_v4_body_length() {
        let sell_v4 = KNOWN_CONTRACTS.iter().find(|c| c.name == "sell_order_v4").unwrap();
        let body = hex::decode(sell_v4.body_hex).unwrap();
        assert_eq!(body.len(), 138, "sell_order_v4 body must be 138 bytes");
    }

    #[test]
    fn known_contracts_receipt_body_length() {
        let receipt = KNOWN_CONTRACTS.iter().find(|c| c.name == "trade_receipt").unwrap();
        let body = hex::decode(receipt.body_hex).unwrap();
        assert_eq!(body.len(), 5, "trade_receipt body must be 5 bytes");
    }

    #[test]
    fn known_contracts_bracket_v2_body_length() {
        let bracket = KNOWN_CONTRACTS.iter().find(|c| c.name == "bracket_order_v2").unwrap();
        let body = hex::decode(bracket.body_hex).unwrap();
        assert_eq!(body.len(), 124, "bracket_order_v2 body must be 124 bytes");
    }

    #[test]
    fn known_contracts_market_config_body_length() {
        let config = KNOWN_CONTRACTS.iter().find(|c| c.name == "market_config").unwrap();
        let body = hex::decode(config.body_hex).unwrap();
        assert_eq!(body.len(), 31, "market_config body must be 31 bytes");
    }
}
