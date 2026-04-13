//! `kob-cli status` -- Show system status: node info, wallet, balance.

use crate::node::NodeClient;
use kob_core::types::Network;
use std::path::Path;

/// Detect whether a wallet file is encrypted, plaintext, or missing.
fn wallet_format(path: &Path) -> &'static str {
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            if contents.contains("\"encrypted\"") {
                "encrypted"
            } else {
                "plaintext"
            }
        }
        Err(_) => "not found",
    }
}

pub async fn run(wallet_path: &Path, node_url: &str, _network: Network) -> anyhow::Result<()> {
    println!("KOB Status");

    // 1. Connect to RPC node
    let rpc = NodeClient::connect(node_url).await?;

    // 2. Call getInfo
    let info = rpc
        .call("getInfo", serde_json::json!({}))
        .await?;

    let server_version = info
        .get("serverVersion")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let is_synced = info
        .get("isSynced")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let network_id = info
        .get("networkId")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    println!("  Node:    {} ({})", node_url, network_id);
    println!("  Synced:  {}", is_synced);
    println!("  Version: {}", server_version);
    println!();

    // 3. Load wallet and query balance
    let format = wallet_format(wallet_path);

    if format == "not found" {
        println!("  Wallet:  {} ({})", wallet_path.display(), format);
        println!("  Balance: N/A");
        println!("  UTXOs:   N/A");
        return Ok(());
    }

    // Try loading the wallet (plaintext only for status; encrypted would need passphrase)
    let wallet_result = kob_core::wallet::WalletContext::load(wallet_path);

    match wallet_result {
        Ok(wallet) => {
            // Truncate address for display
            let addr = &wallet.address;
            let addr_display = if addr.len() > 20 {
                format!("{}...{}", &addr[..14], &addr[addr.len() - 6..])
            } else {
                addr.clone()
            };

            println!("  Wallet:  {} ({})", addr_display, format);

            // Query UTXOs
            let utxos = rpc.get_utxos_by_addresses(&[addr.as_str()]).await?;
            let total_sompi: u64 = utxos.iter().map(|u| u.utxo_entry.amount).sum();
            let utxo_count = utxos.len();

            println!("  Balance: {:.8} KAS", total_sompi as f64 / 1e8);
            println!("  UTXOs:   {}", utxo_count);
        }
        Err(_) => {
            // Encrypted wallet -- cannot load without passphrase
            println!("  Wallet:  {} ({})", wallet_path.display(), format);
            println!("  Balance: (encrypted wallet, passphrase required)");
            println!("  UTXOs:   N/A");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_format_missing_file() {
        let result = wallet_format(Path::new("/nonexistent/wallet.json"));
        assert_eq!(result, "not found");
    }

    #[test]
    fn wallet_format_plaintext() {
        let dir = std::env::temp_dir().join("kob_status_test_plain.json");
        std::fs::write(
            &dir,
            r#"{"privateKey":"aa","publicKey":"bb","address":"kaspatest:qr"}"#,
        )
        .unwrap();
        let result = wallet_format(&dir);
        assert_eq!(result, "plaintext");
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn wallet_format_encrypted() {
        let dir = std::env::temp_dir().join("kob_status_test_enc.json");
        std::fs::write(
            &dir,
            r#"{"encrypted":"base64data","salt":"aabb","nonce":"ccdd"}"#,
        )
        .unwrap();
        let result = wallet_format(&dir);
        assert_eq!(result, "encrypted");
        let _ = std::fs::remove_file(&dir);
    }
}
