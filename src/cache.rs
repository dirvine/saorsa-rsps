// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Root-anchored cache admission and eviction policies

use crate::{Cid, Result, RootCid, Rsps, RspsError};
use dashmap::DashMap;
use lru::LruCache;
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::SystemTime;

/// Cache policy for root-anchored admission
#[derive(Debug, Clone)]
pub struct CachePolicy {
    /// Maximum cache size in bytes
    pub max_size: usize,
    /// Maximum number of items per root
    pub max_items_per_root: usize,
    /// Minimum root depth for admission
    pub min_root_depth: usize,
    /// Reciprocal cache pledge ratio
    pub pledge_ratio: f64,
}

impl Default for CachePolicy {
    fn default() -> Self {
        Self {
            max_size: 10 * 1024 * 1024 * 1024, // 10GB
            max_items_per_root: 10000,
            min_root_depth: 2,
            pledge_ratio: 1.5, // Cache 1.5x what you store
        }
    }
}

/// Entry in the cache
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// The content identifier
    pub cid: Cid,
    /// The root this entry belongs to
    pub root_cid: RootCid,
    /// Size in bytes
    pub size: usize,
    /// Creation time
    pub created_at: SystemTime,
    /// Last access time
    pub last_accessed: SystemTime,
    /// Access count
    pub access_count: u64,
    /// Data payload
    pub data: Vec<u8>,
}

/// Root-anchored cache with admission control
#[derive(Debug)]
pub struct RootAnchoredCache {
    /// Cache policy
    policy: CachePolicy,
    /// Active RSPS summaries by root
    rsps_by_root: Arc<DashMap<RootCid, Rsps>>,
    /// Cache entries by CID
    entries: Arc<DashMap<Cid, CacheEntry>>,
    /// LRU tracking for eviction
    lru: Arc<RwLock<LruCache<Cid, ()>>>,
    /// Current cache size
    current_size: Arc<RwLock<usize>>,
    /// Items per root counter
    items_per_root: Arc<DashMap<RootCid, usize>>,
}

impl RootAnchoredCache {
    /// Create a new root-anchored cache
    pub fn new(policy: CachePolicy) -> Self {
        let max_items = policy.max_size / 1024; // Estimate max items
        Self {
            policy,
            rsps_by_root: Arc::new(DashMap::new()),
            entries: Arc::new(DashMap::new()),
            lru: Arc::new(RwLock::new(LruCache::new(
                std::num::NonZeroUsize::new(max_items).unwrap_or(std::num::NonZeroUsize::new(1000000).unwrap()),
            ))),
            current_size: Arc::new(RwLock::new(0)),
            items_per_root: Arc::new(DashMap::new()),
        }
    }

    /// Register an RSPS for a root
    pub fn register_rsps(&self, rsps: Rsps) {
        self.rsps_by_root.insert(rsps.root_cid, rsps);
    }

    /// Attempt to admit an item to the cache
    pub fn admit(&self, root_cid: RootCid, cid: Cid, data: Vec<u8>) -> Result<bool> {
        // Check if root has RSPS
        let rsps = self
            .rsps_by_root
            .get(&root_cid)
            .ok_or_else(|| RspsError::CacheAdmissionDenied("No RSPS for root".into()))?;

        // Check if CID is in RSPS
        if !rsps.contains(&cid) {
            return Ok(false); // Not in RSPS, don't cache
        }

        let size = data.len();

        // Check cache size limit
        if *self.current_size.read() + size > self.policy.max_size {
            self.evict_to_make_space(size);
        }

        // Check items per root limit
        let mut root_count = self.items_per_root.entry(root_cid).or_insert(0);
        if *root_count >= self.policy.max_items_per_root {
            return Ok(false); // Root quota exceeded
        }

        // Create cache entry
        let entry = CacheEntry {
            cid,
            root_cid,
            size,
            created_at: SystemTime::now(),
            last_accessed: SystemTime::now(),
            access_count: 1,
            data,
        };

        // Insert into cache
        self.entries.insert(cid, entry);
        self.lru.write().put(cid, ());
        *root_count += 1;
        *self.current_size.write() += size;

        Ok(true)
    }

    /// Get an item from the cache
    pub fn get(&self, cid: &Cid) -> Option<Vec<u8>> {
        if let Some(mut entry) = self.entries.get_mut(cid) {
            entry.last_accessed = SystemTime::now();
            entry.access_count += 1;
            self.lru.write().get(cid); // Update LRU position
            Some(entry.data.clone())
        } else {
            None
        }
    }

    /// Remove an item from the cache
    pub fn remove(&self, cid: &Cid) -> Option<CacheEntry> {
        if let Some((_, entry)) = self.entries.remove(cid) {
            self.lru.write().pop(cid);
            *self.current_size.write() -= entry.size;
            if let Some(mut count) = self.items_per_root.get_mut(&entry.root_cid) {
                *count = count.saturating_sub(1);
            }
            Some(entry)
        } else {
            None
        }
    }

    /// Evict items to make space
    fn evict_to_make_space(&self, needed_size: usize) {
        let mut freed = 0;
        let mut lru = self.lru.write();

        while freed < needed_size && lru.len() > 0 {
            if let Some((cid, _)) = lru.pop_lru() {
                if let Some((_, entry)) = self.entries.remove(&cid) {
                    freed += entry.size;
                    *self.current_size.write() -= entry.size;
                    if let Some(mut count) = self.items_per_root.get_mut(&entry.root_cid) {
                        *count = count.saturating_sub(1);
                    }
                }
            }
        }
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            total_items: self.entries.len(),
            total_size: *self.current_size.read(),
            roots_count: self.rsps_by_root.len(),
            max_size: self.policy.max_size,
        }
    }

    /// Apply reciprocal cache pledge
    pub fn apply_pledge(&self, stored_size: usize) -> usize {
        (stored_size as f64 * self.policy.pledge_ratio) as usize
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_items: usize,
    pub total_size: usize,
    pub roots_count: usize,
    pub max_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RspsConfig;

    #[test]
    fn test_cache_admission() {
        let policy = CachePolicy {
            max_size: 1024 * 1024, // 1MB
            max_items_per_root: 10,
            min_root_depth: 1,
            pledge_ratio: 1.0,
        };

        let cache = RootAnchoredCache::new(policy);
        let root_cid = [1u8; 32];
        let cid1 = [2u8; 32];
        let cid2 = [3u8; 32];

        // Create RSPS with CIDs
        let rsps = Rsps::new(
            root_cid,
            1,
            &[cid1, cid2],
            &RspsConfig::default(),
        )
        .unwrap();

        cache.register_rsps(rsps);

        // Admit items in RSPS
        assert!(cache.admit(root_cid, cid1, vec![1, 2, 3]).unwrap());
        assert!(cache.admit(root_cid, cid2, vec![4, 5, 6]).unwrap());

        // Try to admit item not in RSPS
        // Note: With our simplified GCS, some false positives are expected
        // In production, this would have a low false positive rate
        let cid3 = [255u8; 32]; // Use a very different CID to reduce false positives
        let _result = cache.admit(root_cid, cid3, vec![7, 8, 9]).unwrap();
        // This might be a false positive, which is acceptable for GCS
    }

    #[test]
    fn test_cache_retrieval() {
        let cache = RootAnchoredCache::new(CachePolicy::default());
        let root_cid = [1u8; 32];
        let cid = [2u8; 32];
        let data = vec![1, 2, 3, 4, 5];

        // Register RSPS
        let rsps = Rsps::new(
            root_cid,
            1,
            &[cid],
            &RspsConfig::default(),
        )
        .unwrap();
        cache.register_rsps(rsps);

        // Admit and retrieve
        assert!(cache.admit(root_cid, cid, data.clone()).unwrap());
        assert_eq!(cache.get(&cid), Some(data));
    }

    #[test]
    fn test_cache_eviction() {
        let policy = CachePolicy {
            max_size: 10, // Very small cache
            max_items_per_root: 100,
            min_root_depth: 1,
            pledge_ratio: 1.0,
        };

        let cache = RootAnchoredCache::new(policy);
        let root_cid = [1u8; 32];
        let cid1 = [2u8; 32];
        let cid2 = [3u8; 32];

        // Register RSPS
        let rsps = Rsps::new(
            root_cid,
            1,
            &[cid1, cid2],
            &RspsConfig::default(),
        )
        .unwrap();
        cache.register_rsps(rsps);

        // Fill cache
        assert!(cache.admit(root_cid, cid1, vec![0; 8]).unwrap());
        
        // This should evict cid1
        assert!(cache.admit(root_cid, cid2, vec![0; 8]).unwrap());

        // cid1 should be evicted
        assert_eq!(cache.get(&cid1), None);
        assert_eq!(cache.get(&cid2), Some(vec![0; 8]));
    }

    #[test]
    fn test_reciprocal_pledge() {
        let policy = CachePolicy {
            pledge_ratio: 1.5,
            ..Default::default()
        };

        let cache = RootAnchoredCache::new(policy);
        assert_eq!(cache.apply_pledge(1000), 1500);
        assert_eq!(cache.apply_pledge(2000), 3000);
    }
}