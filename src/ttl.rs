// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TTL management engine with hit and receipt tracking

use crate::{Cid, Result};
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// TTL configuration
#[derive(Debug, Clone)]
pub struct TtlConfig {
    /// Base TTL for new entries
    pub base_ttl: Duration,
    /// TTL extension per hit
    pub ttl_per_hit: Duration,
    /// Maximum TTL from hits
    pub max_hit_ttl: Duration,
    /// TTL extension per witness receipt
    pub ttl_per_receipt: Duration,
    /// Maximum TTL from receipts
    pub max_receipt_ttl: Duration,
    /// Temporal bucketing window
    pub bucket_window: Duration,
}

impl Default for TtlConfig {
    fn default() -> Self {
        Self {
            base_ttl: Duration::from_secs(2 * 3600),        // 2 hours
            ttl_per_hit: Duration::from_secs(30 * 60),      // 30 minutes
            max_hit_ttl: Duration::from_secs(12 * 3600),    // 12 hours
            ttl_per_receipt: Duration::from_secs(10 * 60),  // 10 minutes
            max_receipt_ttl: Duration::from_secs(2 * 3600), // 2 hours
            bucket_window: Duration::from_secs(5 * 60),     // 5 minutes
        }
    }
}

/// TTL entry for a CID
#[derive(Debug, Clone)]
pub struct TtlEntry {
    /// The CID this TTL is for
    pub cid: Cid,
    /// Creation time
    pub created_at: SystemTime,
    /// Expiration time
    pub expires_at: SystemTime,
    /// Number of hits
    pub hit_count: u64,
    /// TTL from hits
    pub hit_ttl: Duration,
    /// Number of witness receipts
    pub receipt_count: u64,
    /// TTL from receipts
    pub receipt_ttl: Duration,
    /// Last activity time
    pub last_activity: SystemTime,
    /// Temporal buckets for receipts
    pub receipt_buckets: Vec<TemporalBucket>,
}

/// Temporal bucket for tracking receipts
#[derive(Debug, Clone)]
pub struct TemporalBucket {
    /// Start time of this bucket
    pub start_time: SystemTime,
    /// Number of receipts in this bucket
    pub receipt_count: u32,
    /// Unique witnesses in this bucket
    pub unique_witnesses: Vec<[u8; 32]>,
}

/// TTL management engine
#[derive(Debug)]
pub struct TtlEngine {
    /// Configuration
    config: TtlConfig,
    /// TTL entries by CID
    entries: Arc<DashMap<Cid, TtlEntry>>,
}

impl TtlEngine {
    /// Create a new TTL engine
    pub fn new(config: TtlConfig) -> Self {
        Self {
            config,
            entries: Arc::new(DashMap::new()),
        }
    }

    /// Create a new TTL entry for a CID
    pub fn create_entry(&self, cid: Cid) -> TtlEntry {
        let now = SystemTime::now();
        TtlEntry {
            cid,
            created_at: now,
            expires_at: now + self.config.base_ttl,
            hit_count: 0,
            hit_ttl: Duration::ZERO,
            receipt_count: 0,
            receipt_ttl: Duration::ZERO,
            last_activity: now,
            receipt_buckets: Vec::new(),
        }
    }

    /// Record a hit for a CID
    pub fn record_hit(&self, cid: &Cid) -> Result<Duration> {
        let mut entry = self
            .entries
            .entry(*cid)
            .or_insert_with(|| self.create_entry(*cid));

        entry.hit_count += 1;
        entry.last_activity = SystemTime::now();

        // Calculate new TTL from hits
        let new_hit_ttl = self.config.base_ttl + (self.config.ttl_per_hit * entry.hit_count as u32);
        entry.hit_ttl = new_hit_ttl.min(self.config.max_hit_ttl);

        // Update expiration
        self.update_expiration(&mut entry);

        Ok(entry.hit_ttl)
    }

    /// Record a witness receipt for a CID
    pub fn record_receipt(&self, cid: &Cid, witness_id: [u8; 32]) -> Result<Duration> {
        let mut entry = self
            .entries
            .entry(*cid)
            .or_insert_with(|| self.create_entry(*cid));

        let now = SystemTime::now();
        entry.receipt_count += 1;
        entry.last_activity = now;

        // Update temporal buckets
        self.update_buckets(&mut entry, witness_id, now);

        // Calculate new TTL from receipts
        let active_buckets = self.count_active_buckets(&entry, now);
        let new_receipt_ttl =
            self.config.base_ttl + (self.config.ttl_per_receipt * active_buckets as u32);
        entry.receipt_ttl = new_receipt_ttl.min(self.config.max_receipt_ttl);

        // Update expiration
        self.update_expiration(&mut entry);

        Ok(entry.receipt_ttl)
    }

    /// Update temporal buckets with new receipt
    fn update_buckets(&self, entry: &mut TtlEntry, witness_id: [u8; 32], now: SystemTime) {
        // Find or create current bucket
        let bucket_start = self.get_bucket_start(now);

        if let Some(bucket) = entry.receipt_buckets.last_mut()
            && bucket.start_time == bucket_start
        {
            // Add to existing bucket
            bucket.receipt_count += 1;
            if !bucket.unique_witnesses.contains(&witness_id) {
                bucket.unique_witnesses.push(witness_id);
            }
            return;
        }

        // Create new bucket
        entry.receipt_buckets.push(TemporalBucket {
            start_time: bucket_start,
            receipt_count: 1,
            unique_witnesses: vec![witness_id],
        });

        // Prune old buckets (keep last 24 hours)
        let cutoff = now - Duration::from_secs(24 * 3600);
        entry.receipt_buckets.retain(|b| b.start_time > cutoff);
    }

    /// Get the start time of the current bucket
    fn get_bucket_start(&self, time: SystemTime) -> SystemTime {
        let duration_since_epoch = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        let bucket_seconds = self.config.bucket_window.as_secs();
        let bucket_number = duration_since_epoch.as_secs() / bucket_seconds;
        SystemTime::UNIX_EPOCH + Duration::from_secs(bucket_number * bucket_seconds)
    }

    /// Count active buckets (buckets with receipts in recent time)
    fn count_active_buckets(&self, entry: &TtlEntry, now: SystemTime) -> usize {
        let cutoff = now - Duration::from_secs(3600); // Last hour
        entry
            .receipt_buckets
            .iter()
            .filter(|b| b.start_time > cutoff && b.receipt_count > 0)
            .count()
    }

    /// Update expiration time based on hits and receipts
    fn update_expiration(&self, entry: &mut TtlEntry) {
        let total_ttl = self.config.base_ttl + entry.hit_ttl + entry.receipt_ttl;
        entry.expires_at = entry.created_at + total_ttl;
    }

    /// Check if a CID has expired
    pub fn is_expired(&self, cid: &Cid) -> bool {
        if let Some(entry) = self.entries.get(cid) {
            SystemTime::now() > entry.expires_at
        } else {
            true // Non-existent entries are considered expired
        }
    }

    /// Get remaining TTL for a CID
    pub fn get_remaining_ttl(&self, cid: &Cid) -> Option<Duration> {
        self.entries
            .get(cid)
            .and_then(|entry| entry.expires_at.duration_since(SystemTime::now()).ok())
    }

    /// Clean up expired entries
    pub fn cleanup_expired(&self) -> Vec<Cid> {
        let now = SystemTime::now();
        let mut expired = Vec::new();

        self.entries.retain(|cid, entry| {
            if now > entry.expires_at {
                expired.push(*cid);
                false
            } else {
                true
            }
        });

        expired
    }

    /// Get statistics for a CID
    pub fn get_stats(&self, cid: &Cid) -> Option<TtlStats> {
        self.entries.get(cid).map(|entry| TtlStats {
            hit_count: entry.hit_count,
            receipt_count: entry.receipt_count,
            active_buckets: self.count_active_buckets(&entry, SystemTime::now()),
            remaining_ttl: entry
                .expires_at
                .duration_since(SystemTime::now())
                .unwrap_or(Duration::ZERO),
            total_ttl: entry.hit_ttl + entry.receipt_ttl,
        })
    }
}

/// TTL statistics for a CID
#[derive(Debug, Clone)]
pub struct TtlStats {
    pub hit_count: u64,
    pub receipt_count: u64,
    pub active_buckets: usize,
    pub remaining_ttl: Duration,
    pub total_ttl: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ttl_creation() {
        let engine = TtlEngine::new(TtlConfig::default());
        let cid = [1u8; 32];

        let entry = engine.create_entry(cid);
        assert_eq!(entry.cid, cid);
        assert_eq!(entry.hit_count, 0);
        assert_eq!(entry.receipt_count, 0);
    }

    #[test]
    fn test_hit_tracking() {
        let config = TtlConfig {
            base_ttl: Duration::from_secs(100),
            ttl_per_hit: Duration::from_secs(10),
            max_hit_ttl: Duration::from_secs(50),
            ..Default::default()
        };

        let engine = TtlEngine::new(config);
        let cid = [1u8; 32];

        // Record hits
        engine.record_hit(&cid).unwrap();
        engine.record_hit(&cid).unwrap();

        let stats = engine.get_stats(&cid).unwrap();
        assert_eq!(stats.hit_count, 2);
        assert_eq!(stats.total_ttl.as_secs(), 50); // base_ttl (100) + 2 * 10 = 120, capped at max_hit_ttl (50)
    }

    #[test]
    fn test_receipt_tracking() {
        let config = TtlConfig {
            base_ttl: Duration::from_secs(100),
            ttl_per_receipt: Duration::from_secs(5),
            max_receipt_ttl: Duration::from_secs(30),
            bucket_window: Duration::from_secs(60),
            ..Default::default()
        };

        let engine = TtlEngine::new(config);
        let cid = [1u8; 32];
        let witness1 = [2u8; 32];
        let witness2 = [3u8; 32];

        // Record receipts
        engine.record_receipt(&cid, witness1).unwrap();
        engine.record_receipt(&cid, witness2).unwrap();

        let stats = engine.get_stats(&cid).unwrap();
        assert_eq!(stats.receipt_count, 2);
        assert_eq!(stats.active_buckets, 1); // Same bucket
    }

    #[test]
    fn test_expiration() {
        let config = TtlConfig {
            base_ttl: Duration::from_millis(10), // Very short for testing
            ..Default::default()
        };

        let engine = TtlEngine::new(config);
        let cid = [1u8; 32];

        engine.create_entry(cid);
        engine.entries.insert(cid, engine.create_entry(cid));

        // Should not be expired immediately
        assert!(!engine.is_expired(&cid));

        // Wait and check expiration
        std::thread::sleep(Duration::from_millis(20));
        assert!(engine.is_expired(&cid));
    }

    #[test]
    fn test_cleanup() {
        let config = TtlConfig {
            base_ttl: Duration::from_millis(10),
            ..Default::default()
        };

        let engine = TtlEngine::new(config);
        let cid1 = [1u8; 32];
        let cid2 = [2u8; 32];

        // Insert entries
        engine.entries.insert(cid1, engine.create_entry(cid1));
        engine.entries.insert(cid2, engine.create_entry(cid2));

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(20));

        let expired = engine.cleanup_expired();
        assert_eq!(expired.len(), 2);
        assert!(expired.contains(&cid1));
        assert!(expired.contains(&cid2));
        assert_eq!(engine.entries.len(), 0);
    }
}
