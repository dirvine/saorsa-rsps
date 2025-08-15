// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Golomb Coded Set implementation for space-efficient probabilistic data structures

use crate::{Result, RspsError};
use bitvec::prelude::*;

/// Golomb Coded Set - space-efficient probabilistic data structure
#[derive(Debug, Clone)]
pub struct GolombCodedSet {
    /// Number of items in the set
    n: u64,
    /// Golomb parameter P (related to false positive rate)
    p: u64,
    /// Compressed data
    data: Vec<u8>,
    /// Salt for hashing
    salt: [u8; 32],
}

impl GolombCodedSet {
    /// Check if an item might be in the set
    pub fn contains(&self, item: &[u8]) -> bool {
        if self.n == 0 {
            return false;
        }

        let hash = self.hash_item(item);
        let target = hash % (self.n * self.p);

        // Decode and search for target
        self.decode_and_contains(target)
    }

    /// Get the serialized size in bytes
    pub fn size_bytes(&self) -> usize {
        self.data.len() + 8 + 8 + 32 // data + n + p + salt
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.size_bytes());
        bytes.extend_from_slice(&self.n.to_le_bytes());
        bytes.extend_from_slice(&self.p.to_le_bytes());
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.data);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 48 {
            return Err(RspsError::InvalidParameters("GCS data too short".into()));
        }

        let mut n_bytes = [0u8; 8];
        let mut p_bytes = [0u8; 8];
        let mut salt = [0u8; 32];

        n_bytes.copy_from_slice(&bytes[0..8]);
        p_bytes.copy_from_slice(&bytes[8..16]);
        salt.copy_from_slice(&bytes[16..48]);

        let n = u64::from_le_bytes(n_bytes);
        let p = u64::from_le_bytes(p_bytes);
        let data = bytes[48..].to_vec();

        Ok(Self { n, p, data, salt })
    }

    /// Hash an item with the salt
    fn hash_item(&self, item: &[u8]) -> u64 {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(&self.salt);
        hasher.update(item);
        let hash = hasher.finalize();

        // Take first 8 bytes as u64
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&hash.as_bytes()[0..8]);
        u64::from_le_bytes(bytes)
    }

    /// Decode the Golomb-coded bitstream and check for target membership
    fn decode_and_contains(&self, target: u64) -> bool {
        if self.n == 0 {
            return false;
        }

        // Number of bits used to represent the remainder
        let remainder_bits = (self.p as f64).log2().ceil() as usize;
        if remainder_bits == 0 {
            // p == 1, so remainder is always 0 and quotient fully determines delta
        }

        let bits = BitSlice::<u8, Msb0>::from_slice(&self.data);
        let mut idx = 0usize;
        let mut prev = 0u64;
        let mut decoded_count = 0u64;

        while decoded_count < self.n && idx < bits.len() {
            // Read unary quotient (count of 1s until a 0)
            let mut q: u64 = 0;
            while idx < bits.len() {
                let bit = bits[idx];
                idx += 1;
                if bit {
                    q += 1;
                } else {
                    break;
                }
            }
            if idx >= bits.len() {
                break; // Truncated stream
            }

            // Read fixed-size remainder
            let mut r: u64 = 0;
            if remainder_bits > 0 {
                // Big-endian bit order for remainder as encoded
                for _ in 0..remainder_bits {
                    if idx >= bits.len() {
                        break; // Truncated
                    }
                    r = (r << 1) | (bits[idx] as u64);
                    idx += 1;
                }
            }

            let delta = q * self.p + r;
            let value = prev + delta;
            prev = value;
            decoded_count += 1;

            if value == target {
                return true;
            }

            // Early exit if values exceed target (since sequence is sorted)
            if value > target {
                return false;
            }
        }

        false
    }
}

/// Builder for Golomb Coded Sets
#[derive(Debug)]
pub struct GcsBuilder {
    target_fpr: f64,
    salt: Option<[u8; 32]>,
}

impl GcsBuilder {
    pub fn new() -> Self {
        Self {
            target_fpr: 1e-3, // 0.1% default
            salt: None,
        }
    }

    /// Set target false positive rate
    pub fn target_fpr(mut self, fpr: f64) -> Self {
        self.target_fpr = fpr;
        self
    }

    /// Set salt for hashing
    pub fn salt(mut self, salt: &[u8; 32]) -> Self {
        self.salt = Some(*salt);
        self
    }

    /// Build the GCS from items
    pub fn build(&self, items: &[[u8; 32]]) -> Result<GolombCodedSet> {
        let n = items.len() as u64;
        if n == 0 {
            return Ok(GolombCodedSet {
                n: 0,
                p: 1,
                data: vec![],
                salt: self.salt.unwrap_or([0u8; 32]),
            });
        }

        // Calculate P parameter from target FPR
        // P = ceil(1 / fpr)
        let p = (1.0 / self.target_fpr).ceil() as u64;

        let salt = self.salt.unwrap_or_else(|| {
            // Generate random salt if not provided
            let mut salt = [0u8; 32];
            use rand::Rng;
            rand::thread_rng().fill(&mut salt);
            salt
        });

        // Hash and sort items
        let mut hashes: Vec<u64> = items
            .iter()
            .map(|item| Self::hash_with_salt(item, &salt) % (n * p))
            .collect();
        hashes.sort_unstable();

        // Encode using Golomb coding
        let data = self.golomb_encode(&hashes, p)?;

        Ok(GolombCodedSet { n, p, data, salt })
    }

    /// Hash with salt
    fn hash_with_salt(item: &[u8], salt: &[u8; 32]) -> u64 {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(salt);
        hasher.update(item);
        let hash = hasher.finalize();

        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&hash.as_bytes()[0..8]);
        u64::from_le_bytes(bytes)
    }

    /// Golomb encode a sorted list of integers
    fn golomb_encode(&self, values: &[u64], p: u64) -> Result<Vec<u8>> {
        let mut bits = BitVec::<u8, Msb0>::new();
        let mut prev = 0u64;

        for &val in values {
            let delta = val - prev;
            prev = val;

            // Golomb coding: quotient in unary, remainder in binary
            let quotient = delta / p;
            let remainder = delta % p;

            // Write quotient in unary (q ones followed by zero)
            for _ in 0..quotient {
                bits.push(true);
            }
            bits.push(false);

            // Write remainder in binary (log2(p) bits)
            let remainder_bits = (p as f64).log2().ceil() as usize;
            for i in (0..remainder_bits).rev() {
                bits.push((remainder >> i) & 1 == 1);
            }
        }

        // Convert to bytes
        Ok(bits.into_vec())
    }
}

impl Default for GcsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gcs_build_empty() {
        let gcs = GcsBuilder::new().target_fpr(0.001).build(&[]).unwrap();

        assert_eq!(gcs.n, 0);
        assert!(gcs.data.is_empty());
    }

    #[test]
    fn test_gcs_build_and_query() {
        let items = vec![[1u8; 32], [2u8; 32], [3u8; 32]];

        let gcs = GcsBuilder::new().target_fpr(0.01).build(&items).unwrap();

        assert_eq!(gcs.n, 3);
        assert!(gcs.p > 0);
        assert!(!gcs.data.is_empty());
    }

    #[test]
    fn test_gcs_deterministic_with_salt() {
        let items = vec![[1u8; 32], [2u8; 32]];
        let salt = [42u8; 32];

        let gcs1 = GcsBuilder::new().salt(&salt).build(&items).unwrap();

        let gcs2 = GcsBuilder::new().salt(&salt).build(&items).unwrap();

        assert_eq!(gcs1.data, gcs2.data);
        assert_eq!(gcs1.salt, gcs2.salt);
    }

    #[test]
    fn test_gcs_serialization() {
        let items = vec![[1u8; 32], [2u8; 32]];

        let original = GcsBuilder::new().target_fpr(0.001).build(&items).unwrap();

        let bytes = original.to_bytes();
        let restored = GolombCodedSet::from_bytes(&bytes).unwrap();

        assert_eq!(original.n, restored.n);
        assert_eq!(original.p, restored.p);
        assert_eq!(original.salt, restored.salt);
        assert_eq!(original.data, restored.data);
    }

    #[test]
    fn test_gcs_membership_check() {
        let items = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let salt = [7u8; 32];
        let gcs = GcsBuilder::new()
            .salt(&salt)
            .target_fpr(0.01)
            .build(&items)
            .unwrap();

        // All inserted items should be reported as present
        for item in &items {
            assert!(gcs.contains(item));
        }
    }
}
