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

    /// Deserialize from bytes with comprehensive validation
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // Basic length validation
        if bytes.len() < 48 {
            return Err(RspsError::InvalidParameters("GCS data too short".into()));
        }

        // Maximum reasonable size to prevent DoS (100MB max)
        if bytes.len() > 100 * 1024 * 1024 {
            return Err(RspsError::InvalidParameters(
                "GCS data too large (>100MB)".into(),
            ));
        }

        let mut n_bytes = [0u8; 8];
        let mut p_bytes = [0u8; 8];
        let mut salt = [0u8; 32];

        n_bytes.copy_from_slice(&bytes[0..8]);
        p_bytes.copy_from_slice(&bytes[8..16]);
        salt.copy_from_slice(&bytes[16..48]);

        let n = u64::from_le_bytes(n_bytes);
        let p = u64::from_le_bytes(p_bytes);

        // Validate parameters
        if p == 0 || !p.is_power_of_two() {
            return Err(RspsError::InvalidParameters(
                "GCS parameter p must be a power of two (Rice coding) and >= 1".into(),
            ));
        }

        // Prevent DoS: limit n to reasonable values (max 10M items)
        if n > 10_000_000 {
            return Err(RspsError::InvalidParameters(
                "GCS n parameter too large (>10M items)".into(),
            ));
        }

        // Validate p is within reasonable bounds (max 2^40 to prevent overflow)
        if p > (1u64 << 40) {
            return Err(RspsError::InvalidParameters(
                "GCS parameter p too large (>2^40)".into(),
            ));
        }

        let data = bytes[48..].to_vec();

        // Validate data length is reasonable for the given n and p
        if n > 0 {
            let remainder_bits = p.trailing_zeros() as usize;
            // Each item needs at least 1 bit (unary 0) + remainder_bits
            let min_bits_per_item = 1 + remainder_bits;
            let min_total_bits = n.saturating_mul(min_bits_per_item as u64);
            let min_bytes = min_total_bits.div_ceil(8); // Round up to bytes

            if data.len() < min_bytes as usize {
                return Err(RspsError::InvalidParameters(
                    "GCS data too small for declared item count".into(),
                ));
            }

            // Also check maximum reasonable size based on worst case encoding
            // Worst case: each delta requires log2(n*p) bits plus overhead
            let max_bits_per_item = 64 + remainder_bits; // Conservative upper bound
            let max_total_bits = n.saturating_mul(max_bits_per_item as u64);
            let max_bytes = max_total_bits.div_ceil(8);

            if data.len() > max_bytes.saturating_mul(2) as usize {
                return Err(RspsError::InvalidParameters(
                    "GCS data suspiciously large for declared parameters".into(),
                ));
            }
        } else if !data.is_empty() {
            return Err(RspsError::InvalidParameters(
                "GCS with n=0 must have empty data".into(),
            ));
        }

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

        // Number of bits used to represent the remainder (Rice coding requires p to be a power of two)
        let remainder_bits = self.p.trailing_zeros() as usize;

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
                    // Prevent DoS: limit quotient to reasonable values
                    if q > 1000000 {
                        return false; // Malformed data
                    }
                } else {
                    break;
                }
            }
            if idx >= bits.len() {
                break; // Truncated stream
            }

            // Read fixed-size remainder
            let mut r: u64 = 0;
            if remainder_bits > 0 && remainder_bits <= 64 {
                // Big-endian bit order for remainder as encoded
                for _ in 0..remainder_bits {
                    if idx >= bits.len() {
                        break; // Truncated
                    }
                    r = (r << 1) | (bits[idx] as u64);
                    idx += 1;
                }
            }

            // Prevent integer overflow in delta calculation
            let delta = q.saturating_mul(self.p).saturating_add(r);
            
            // Prevent integer overflow in value calculation
            let value = prev.saturating_add(delta);
            
            // Detect overflow/wraparound which indicates malformed data
            if value < prev {
                return false; // Overflow detected
            }
            
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

        // Enforce Golomb-Rice coding by choosing p as a power of two.
        // k = ceil(log2(1/fpr)), p = 2^k
        if !(self.target_fpr.is_finite() && self.target_fpr > 0.0 && self.target_fpr < 1.0) {
            return Err(RspsError::InvalidParameters(
                "target_fpr must be in the open interval (0, 1)".into(),
            ));
        }
        let inv = 1.0 / self.target_fpr;
        let k = inv.log2().ceil().max(0.0) as u32;
        let k = k.min(60);
        let p: u64 = 1u64 << k;

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

        // Encode using Golomb-Rice coding
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

    /// Golomb-Rice encode a sorted list of integers
    fn golomb_encode(&self, values: &[u64], p: u64) -> Result<Vec<u8>> {
        if p == 0 || !p.is_power_of_two() {
            return Err(RspsError::InvalidParameters(
                "encoding requires p to be a power of two (Rice coding)".into(),
            ));
        }
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

            // Write remainder in binary where k = log2(p)
            let remainder_bits = p.trailing_zeros() as usize;
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
        assert!(gcs.p.is_power_of_two());
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

    #[test]
    fn test_rice_parameter_is_power_of_two_and_matches_fpr() {
        let items = (0..16).map(|i| [i as u8; 32]).collect::<Vec<_>>();
        let fpr = 0.01; // 1%
        let gcs = GcsBuilder::new().target_fpr(fpr).build(&items).unwrap();

        assert!(gcs.p.is_power_of_two(), "p must be power of two");
        let expected_k = (1.0 / fpr).log2().ceil().max(0.0) as u32;
        let expected_p = 1u64 << expected_k.min(60);
        assert_eq!(gcs.p, expected_p);
    }

    #[test]
    fn test_from_bytes_rejects_non_power_of_two_p() {
        // Build a minimal, but invalid, byte stream with p = 3 (not power of two)
        let n: u64 = 1;
        let p: u64 = 3;
        let salt = [0u8; 32];
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&n.to_le_bytes());
        bytes.extend_from_slice(&p.to_le_bytes());
        bytes.extend_from_slice(&salt);
        bytes.extend_from_slice(&[0u8; 1]); // some data

        let err = GolombCodedSet::from_bytes(&bytes).unwrap_err();
        match err {
            RspsError::InvalidParameters(msg) => {
                assert!(msg.contains("power of two"));
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_builder_rejects_invalid_fpr() {
        let items = vec![[1u8; 32]];
        // fpr <= 0
        assert!(GcsBuilder::new().target_fpr(0.0).build(&items).is_err());
        assert!(GcsBuilder::new().target_fpr(-0.1).build(&items).is_err());
        // fpr >= 1
        assert!(GcsBuilder::new().target_fpr(1.0).build(&items).is_err());
        assert!(GcsBuilder::new().target_fpr(2.0).build(&items).is_err());
    }

    #[test]
    fn test_serialization_roundtrip_preserves_membership() {
        let items = (0..64).map(|i| [i as u8; 32]).collect::<Vec<_>>();
        let gcs = GcsBuilder::new().target_fpr(0.02).build(&items).unwrap();

        let bytes = gcs.to_bytes();
        let restored = GolombCodedSet::from_bytes(&bytes).unwrap();

        for item in &items {
            assert!(restored.contains(item));
        }
    }

    #[test]
    fn test_false_positive_rate_reasonable_bound() {
        use rand::RngCore;

        let items = (0..256).map(|i| [i as u8; 32]).collect::<Vec<_>>();
        let fpr = 0.01; // 1%
        let gcs = GcsBuilder::new().target_fpr(fpr).build(&items).unwrap();

        let mut rng = rand::thread_rng();
        let trials = 3000usize;
        let mut non_member = [0u8; 32];
        let mut false_positives = 0usize;
        for _ in 0..trials {
            rng.fill_bytes(&mut non_member);
            if !items.contains(&non_member) && gcs.contains(&non_member) {
                false_positives += 1;
            }
        }

        let rate = false_positives as f64 / trials as f64;
        // Allow some wiggle room: rate should be below 8x the target for stability
        assert!(rate <= f64::max(0.08, fpr * 8.0), "rate {} too high", rate);
    }

    #[test]
    fn test_input_validation_rejects_malformed_data() {
        // Test data too large
        let large_data = vec![0u8; 101 * 1024 * 1024]; // 101MB
        assert!(GolombCodedSet::from_bytes(&large_data).is_err());

        // Test n too large
        let n: u64 = 20_000_000; // > 10M limit
        let p: u64 = 4;
        let salt = [0u8; 32];
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&n.to_le_bytes());
        bytes.extend_from_slice(&p.to_le_bytes());
        bytes.extend_from_slice(&salt);
        bytes.extend_from_slice(&[0u8; 100]);
        assert!(GolombCodedSet::from_bytes(&bytes).is_err());

        // Test p too large
        let n: u64 = 10;
        let p: u64 = 1u64 << 50; // > 2^40 limit
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&n.to_le_bytes());
        bytes.extend_from_slice(&p.to_le_bytes());
        bytes.extend_from_slice(&salt);
        bytes.extend_from_slice(&[0u8; 100]);
        assert!(GolombCodedSet::from_bytes(&bytes).is_err());

        // Test n=0 with non-empty data
        let n: u64 = 0;
        let p: u64 = 4;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&n.to_le_bytes());
        bytes.extend_from_slice(&p.to_le_bytes());
        bytes.extend_from_slice(&salt);
        bytes.extend_from_slice(&[1u8; 10]); // Non-empty data
        assert!(GolombCodedSet::from_bytes(&bytes).is_err());
    }
}
