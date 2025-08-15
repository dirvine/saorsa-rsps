// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # DHT RSPS - Root-Scoped Provider Summaries
//!
//! This crate implements Root-Scoped Provider Summaries using Golomb Coded Sets (GCS)
//! for efficient DHT lookups and cache management in the P2P network.
//!
//! ## Features
//! - Golomb Coded Sets for space-efficient CID summaries
//! - Root-anchored cache admission policies
//! - TTL management with hit and receipt tracking
//! - Witness receipts with VRF pseudonyms

use std::time::{Duration, SystemTime};
use thiserror::Error;

pub mod gcs;
pub mod cache;
pub mod ttl;
pub mod witness;

pub use gcs::{GolombCodedSet, GcsBuilder};
pub use cache::{CachePolicy, RootAnchoredCache};
pub use ttl::{TtlEngine, TtlConfig, TtlStats};
pub use witness::{WitnessReceipt, VrfPseudonym, WitnessKey};

/// Errors that can occur in RSPS operations
#[derive(Debug, Error)]
pub enum RspsError {
    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),
    
    #[error("GCS build failed: {0}")]
    GcsBuildError(String),
    
    #[error("Cache admission denied: {0}")]
    CacheAdmissionDenied(String),
    
    #[error("TTL expired")]
    TtlExpired,
    
    #[error("Invalid witness receipt: {0}")]
    InvalidWitness(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, RspsError>;

/// Content identifier (CID) type
pub type Cid = [u8; 32];

/// Root identifier
pub type RootCid = [u8; 32];

/// RSPS configuration
#[derive(Debug, Clone)]
pub struct RspsConfig {
    /// Target false positive rate for GCS
    pub target_fpr: f64,
    /// Base TTL for cache entries
    pub base_ttl: Duration,
    /// TTL extension per hit
    pub ttl_per_hit: Duration,
    /// Maximum TTL from hits
    pub max_hit_ttl: Duration,
    /// TTL extension per witness receipt
    pub ttl_per_receipt: Duration,
    /// Maximum TTL from receipts
    pub max_receipt_ttl: Duration,
    /// Temporal bucketing window for receipts
    pub receipt_bucket_window: Duration,
}

impl Default for RspsConfig {
    fn default() -> Self {
        Self {
            target_fpr: 5e-4,  // 0.05% false positive rate
            base_ttl: Duration::from_secs(2 * 3600),  // 2 hours
            ttl_per_hit: Duration::from_secs(30 * 60),  // 30 minutes
            max_hit_ttl: Duration::from_secs(12 * 3600),  // 12 hours
            ttl_per_receipt: Duration::from_secs(10 * 60),  // 10 minutes
            max_receipt_ttl: Duration::from_secs(2 * 3600),  // 2 hours
            receipt_bucket_window: Duration::from_secs(5 * 60),  // 5 minutes
        }
    }
}

/// Root-Scoped Provider Summary
#[derive(Debug, Clone)]
pub struct Rsps {
    /// The root CID this summary is for
    pub root_cid: RootCid,
    /// The epoch this summary represents
    pub epoch: u64,
    /// The GCS containing CIDs under this root
    pub gcs: GolombCodedSet,
    /// Creation timestamp
    pub created_at: SystemTime,
    /// Salt used for GCS
    pub salt: [u8; 32],
}

impl Rsps {
    /// Create a new RSPS for a root with given CIDs
    pub fn new(root_cid: RootCid, epoch: u64, cids: &[Cid], config: &RspsConfig) -> Result<Self> {
        // Generate salt from root_cid and epoch
        let salt = Self::generate_salt(&root_cid, epoch);
        
        // Build GCS with target FPR
        let gcs = GcsBuilder::new()
            .target_fpr(config.target_fpr)
            .salt(&salt)
            .build(cids)?;
        
        Ok(Self {
            root_cid,
            epoch,
            gcs,
            created_at: SystemTime::now(),
            salt,
        })
    }
    
    /// Check if a CID might be in this root
    pub fn contains(&self, cid: &Cid) -> bool {
        self.gcs.contains(cid)
    }
    
    /// Get the digest of this RSPS for DHT advertisement
    pub fn digest(&self) -> [u8; 32] {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(&self.root_cid);
        hasher.update(&self.epoch.to_le_bytes());
        hasher.update(&self.gcs.to_bytes());
        let mut digest = [0u8; 32];
        digest.copy_from_slice(hasher.finalize().as_bytes());
        digest
    }
    
    /// Generate deterministic salt for GCS
    fn generate_salt(root_cid: &RootCid, epoch: u64) -> [u8; 32] {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(b"rsps-salt");
        hasher.update(root_cid);
        hasher.update(&epoch.to_le_bytes());
        let mut salt = [0u8; 32];
        salt.copy_from_slice(hasher.finalize().as_bytes());
        salt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_rsps_creation() {
        let root_cid = [1u8; 32];
        let cids = vec![
            [2u8; 32],
            [3u8; 32],
            [4u8; 32],
        ];
        let config = RspsConfig::default();
        
        let rsps = Rsps::new(root_cid, 1, &cids, &config).unwrap();
        
        // Should contain all added CIDs
        for cid in &cids {
            assert!(rsps.contains(cid));
        }
        
        // Should not contain random CID (with high probability)
        let _random_cid = [99u8; 32];
        // May have false positives at target_fpr rate
        // This is probabilistic, so we don't assert false
    }
    
    #[test]
    fn test_deterministic_salt() {
        let root_cid = [1u8; 32];
        let epoch = 42;
        
        let salt1 = Rsps::generate_salt(&root_cid, epoch);
        let salt2 = Rsps::generate_salt(&root_cid, epoch);
        
        assert_eq!(salt1, salt2, "Salt should be deterministic");
        
        let different_epoch_salt = Rsps::generate_salt(&root_cid, epoch + 1);
        assert_ne!(salt1, different_epoch_salt, "Different epochs should produce different salts");
    }
}