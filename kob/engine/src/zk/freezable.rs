//! Freezable token covenant detection for OpZkPrecompile-guarded UTXOs.

use std::collections::HashSet;

use super::{has_zk_opcode, ZkProofSystem};

/// Returns `true` if the redeemScript contains OpZkPrecompile (0xa6),
/// indicating a freezable token covenant that requires ZK proof to spend.
pub fn is_freezable_covenant(redeem_script: &[u8]) -> bool {
    has_zk_opcode(redeem_script)
}

/// Check whether a token covenant ID is registered as a freezable token.
///
/// Freezable tokens (e.g. USDC) require a ZK proof at spend time to prove
/// the sender is not on the blacklist. Since the KOB order redeemScript
/// itself does not contain 0xa6, we check token_cov_id against a registry
/// of known freezable tokens.
///
/// Returns `true` if the token is in the registry.
pub fn is_freezable_token(token_cov_id: &str, registry: &FreezableTokenRegistry) -> bool {
    registry.contains(token_cov_id)
}

/// Registry of known freezable token covenant IDs.
///
/// The matcher operator configures this (via config file or CLI) with the
/// covenant IDs of tokens that require ZK proofs to spend (e.g. USDC).
#[derive(Debug, Clone, Default)]
pub struct FreezableTokenRegistry {
    /// Set of hex-encoded token covenant IDs (64 hex chars each).
    token_ids: HashSet<String>,
}

impl FreezableTokenRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a registry from a list of hex-encoded token covenant IDs.
    pub fn from_ids(ids: &[&str]) -> Self {
        Self {
            token_ids: ids.iter().map(|s| s.to_lowercase()).collect(),
        }
    }

    /// Add a token covenant ID to the registry.
    pub fn add(&mut self, token_cov_id: &str) {
        self.token_ids.insert(token_cov_id.to_lowercase());
    }

    /// Check if a token covenant ID is in the registry.
    pub fn contains(&self, token_cov_id: &str) -> bool {
        self.token_ids.contains(&token_cov_id.to_lowercase())
    }

    /// Return the number of registered freezable tokens.
    pub fn len(&self) -> usize {
        self.token_ids.len()
    }

    /// Return true if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.token_ids.is_empty()
    }
}

/// Configuration for handling freezable token covenants.
#[derive(Debug, Clone)]
pub struct FreezableConfig {
    /// URL of the blacklist oracle (e.g. USDC compliance API).
    pub blacklist_url: String,

    /// Which proof system to use for this token's ZK proofs.
    pub proof_system: ZkProofSystem,

    /// Whether to cache blacklist query results.
    pub cache_enabled: bool,

    /// Cache TTL in seconds. Ignored if `cache_enabled` is false.
    pub cache_ttl_secs: u64,
}

impl Default for FreezableConfig {
    fn default() -> Self {
        Self {
            blacklist_url: String::new(),
            proof_system: ZkProofSystem::Groth16,
            cache_enabled: true,
            cache_ttl_secs: 300, // 5 minutes
        }
    }
}

/// Check whether an address is blacklisted for a freezable token.
///
/// **Stub implementation**: always returns `Ok(false)` (not blacklisted).
pub async fn check_blacklist(
    _address: &str,
    _config: &FreezableConfig,
) -> Result<bool, super::ZkError> {
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::OP_ZK_PRECOMPILE;

    #[test]
    fn freezable_detection_positive() {
        let rs = vec![0x51, 0x20, OP_ZK_PRECOMPILE, 0x87];
        assert!(is_freezable_covenant(&rs));
    }

    #[test]
    fn freezable_detection_negative() {
        let rs = vec![0xb9, 0xc9, 0x76, 0x02, 0x77, 0x01, 0x9f, 0x63];
        assert!(!is_freezable_covenant(&rs));
    }

    #[test]
    fn freezable_detection_empty() {
        assert!(!is_freezable_covenant(&[]));
    }

    #[test]
    fn default_config() {
        let cfg = FreezableConfig::default();
        assert!(cfg.blacklist_url.is_empty());
        assert_eq!(cfg.proof_system, ZkProofSystem::Groth16);
        assert!(cfg.cache_enabled);
        assert_eq!(cfg.cache_ttl_secs, 300);
    }

    #[tokio::test]
    async fn stub_blacklist_returns_not_blacklisted() {
        let cfg = FreezableConfig::default();
        let result = check_blacklist("kaspa:qz...", &cfg).await;
        assert!(result.is_ok());
        assert!(!result.unwrap(), "stub should always return false (not blacklisted)");
    }

    #[tokio::test]
    async fn stub_blacklist_any_address() {
        let cfg = FreezableConfig::default();
        for addr in &["", "kaspa:deadbeef", "0x0000000000000000000000000000000000000000"] {
            let result = check_blacklist(addr, &cfg).await.unwrap();
            assert!(!result);
        }
    }

    // --- FreezableTokenRegistry ---

    #[test]
    fn registry_new_is_empty() {
        let reg = FreezableTokenRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn registry_from_ids() {
        let usdc_id = "ab".repeat(32);
        let reg = FreezableTokenRegistry::from_ids(&[&usdc_id]);
        assert_eq!(reg.len(), 1);
        assert!(reg.contains(&usdc_id));
        assert!(!reg.contains(&"cd".repeat(32)));
    }

    #[test]
    fn registry_add_and_contains() {
        let mut reg = FreezableTokenRegistry::new();
        let id = "01".repeat(32);
        assert!(!reg.contains(&id));
        reg.add(&id);
        assert!(reg.contains(&id));
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn registry_case_insensitive() {
        let reg = FreezableTokenRegistry::from_ids(&["AABB".repeat(8).as_str()]);
        assert!(reg.contains(&"aabb".repeat(8)));
        assert!(reg.contains(&"AABB".repeat(8)));
    }

    #[test]
    fn is_freezable_token_with_registry() {
        let usdc_id = "ab".repeat(32);
        let non_freezable_id = "cd".repeat(32);
        let reg = FreezableTokenRegistry::from_ids(&[&usdc_id]);
        assert!(is_freezable_token(&usdc_id, &reg));
        assert!(!is_freezable_token(&non_freezable_id, &reg));
    }
}
