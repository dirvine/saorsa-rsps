// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Witness receipts with VRF pseudonyms for privacy-preserving attestation

use crate::Cid;
use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// VRF-based pseudonym for witness privacy
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VrfPseudonym {
    /// The pseudonym value
    pub value: [u8; 32],
    /// Proof of correct VRF computation
    pub proof: VrfProof,
}

/// VRF proof (simplified for now, would use actual VRF in production)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VrfProof {
    /// Challenge value
    pub challenge: [u8; 32],
    /// Response value
    pub response: [u8; 32],
}

/// Witness receipt for content retrieval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessReceipt {
    /// The CID that was retrieved
    pub cid: Cid,
    /// VRF pseudonym of the witness
    pub witness_pseudonym: VrfPseudonym,
    /// Timestamp of retrieval
    pub timestamp: SystemTime,
    /// Optional metadata
    pub metadata: ReceiptMetadata,
    /// Signature over the receipt
    pub signature: Vec<u8>,
}

/// Metadata included in witness receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptMetadata {
    /// Retrieval latency in milliseconds
    pub latency_ms: u32,
    /// Size of content retrieved
    pub content_size: usize,
    /// Whether content was valid
    pub valid: bool,
    /// Optional error message
    pub error: Option<String>,
}

/// Witness key for generating VRF pseudonyms
#[derive(Debug)]
pub struct WitnessKey {
    /// Private key material
    secret: [u8; 32],
    /// Public key
    public: [u8; 32],
}

impl WitnessKey {
    /// Generate a new witness key
    pub fn generate() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut secret = [0u8; 32];
        rng.fill(&mut secret);
        
        // Derive public key (simplified - would use actual key derivation)
        let mut hasher = Hasher::new();
        hasher.update(b"witness-public");
        hasher.update(&secret);
        let mut public = [0u8; 32];
        public.copy_from_slice(hasher.finalize().as_bytes());
        
        Self { secret, public }
    }
    
    /// Create VRF pseudonym for a CID
    pub fn create_pseudonym(&self, cid: &Cid, epoch: u64) -> VrfPseudonym {
        // Compute VRF output (simplified - would use actual VRF)
        let mut hasher = Hasher::new();
        hasher.update(b"vrf-pseudonym");
        hasher.update(&self.secret);
        hasher.update(cid);
        hasher.update(&epoch.to_le_bytes());
        
        let mut value = [0u8; 32];
        value.copy_from_slice(hasher.finalize().as_bytes());
        
        // Generate proof
        let proof = self.generate_proof(cid, epoch, &value);
        
        VrfPseudonym { value, proof }
    }
    
    /// Generate VRF proof
    fn generate_proof(&self, cid: &Cid, epoch: u64, output: &[u8; 32]) -> VrfProof {
        // Simplified proof generation
        let mut hasher = Hasher::new();
        hasher.update(b"vrf-challenge");
        hasher.update(cid);
        hasher.update(&epoch.to_le_bytes());
        hasher.update(output);
        
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(hasher.finalize().as_bytes());
        
        hasher = Hasher::new();
        hasher.update(b"vrf-response");
        hasher.update(&self.secret);
        hasher.update(&challenge);
        
        let mut response = [0u8; 32];
        response.copy_from_slice(hasher.finalize().as_bytes());
        
        VrfProof { challenge, response }
    }
    
    /// Create a witness receipt
    pub fn create_receipt(
        &self,
        cid: Cid,
        epoch: u64,
        metadata: ReceiptMetadata,
    ) -> WitnessReceipt {
        let witness_pseudonym = self.create_pseudonym(&cid, epoch);
        let timestamp = SystemTime::now();
        
        // Sign the receipt
        let signature = self.sign_receipt(&cid, &witness_pseudonym, &timestamp, &metadata);
        
        WitnessReceipt {
            cid,
            witness_pseudonym,
            timestamp,
            metadata,
            signature,
        }
    }
    
    /// Sign a receipt
    fn sign_receipt(
        &self,
        cid: &Cid,
        pseudonym: &VrfPseudonym,
        timestamp: &SystemTime,
        metadata: &ReceiptMetadata,
    ) -> Vec<u8> {
        // Simplified signature (would use actual signature scheme)
        let mut hasher = Hasher::new();
        hasher.update(b"receipt-signature");
        hasher.update(&self.secret);
        hasher.update(cid);
        hasher.update(&pseudonym.value);
        hasher.update(&timestamp.duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_le_bytes());
        hasher.update(&metadata.latency_ms.to_le_bytes());
        hasher.update(&metadata.content_size.to_le_bytes());
        hasher.update(&[metadata.valid as u8]);
        
        let hash = hasher.finalize();
        let mut signature = Vec::with_capacity(64);
        signature.extend_from_slice(hash.as_bytes());
        signature.extend_from_slice(&self.public);
        
        signature
    }
    
    /// Get the public key
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }
}

/// Verify a VRF pseudonym
pub fn verify_pseudonym(
    pseudonym: &VrfPseudonym,
    cid: &Cid,
    epoch: u64,
    public_key: &[u8; 32],
) -> bool {
    // Simplified verification (would use actual VRF verification)
    let mut hasher = Hasher::new();
    hasher.update(b"vrf-verify");
    hasher.update(public_key);
    hasher.update(cid);
    hasher.update(&epoch.to_le_bytes());
    hasher.update(&pseudonym.proof.challenge);
    hasher.update(&pseudonym.proof.response);
    
    // In production, would properly verify the VRF proof
    true // Simplified for now
}

/// Verify a witness receipt
pub fn verify_receipt(receipt: &WitnessReceipt, _public_key: &[u8; 32]) -> bool {
    // Verify signature
    let mut hasher = Hasher::new();
    hasher.update(b"receipt-signature");
    // In production, would use the actual public key to verify
    hasher.update(&receipt.signature[32..64]); // Public key from signature
    hasher.update(&receipt.cid);
    hasher.update(&receipt.witness_pseudonym.value);
    hasher.update(&receipt.timestamp.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_le_bytes());
    hasher.update(&receipt.metadata.latency_ms.to_le_bytes());
    hasher.update(&receipt.metadata.content_size.to_le_bytes());
    hasher.update(&[receipt.metadata.valid as u8]);
    
    // Simplified verification
    true // In production, would properly verify signature
}

/// Batch verification of receipts
#[derive(Debug)]
pub struct ReceiptBatch {
    receipts: Vec<WitnessReceipt>,
}

impl ReceiptBatch {
    /// Create a new batch
    pub fn new() -> Self {
        Self {
            receipts: Vec::new(),
        }
    }
    
    /// Add a receipt to the batch
    pub fn add(&mut self, receipt: WitnessReceipt) {
        self.receipts.push(receipt);
    }
    
    /// Get receipts for a specific CID
    pub fn get_by_cid(&self, cid: &Cid) -> Vec<&WitnessReceipt> {
        self.receipts.iter()
            .filter(|r| r.cid == *cid)
            .collect()
    }
    
    /// Count unique witnesses for a CID
    pub fn count_unique_witnesses(&self, cid: &Cid) -> usize {
        use std::collections::HashSet;
        
        self.receipts.iter()
            .filter(|r| r.cid == *cid)
            .map(|r| &r.witness_pseudonym)
            .collect::<HashSet<_>>()
            .len()
    }
    
    /// Get temporal distribution of receipts
    pub fn temporal_distribution(&self, cid: &Cid, bucket_size: std::time::Duration) -> Vec<(SystemTime, usize)> {
        use std::collections::BTreeMap;
        
        let mut buckets = BTreeMap::new();
        
        for receipt in self.receipts.iter().filter(|r| r.cid == *cid) {
            let bucket_time = Self::round_to_bucket(receipt.timestamp, bucket_size);
            *buckets.entry(bucket_time).or_insert(0) += 1;
        }
        
        buckets.into_iter().collect()
    }
    
    /// Round timestamp to bucket
    fn round_to_bucket(time: SystemTime, bucket_size: std::time::Duration) -> SystemTime {
        let duration = time.duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        let bucket_secs = bucket_size.as_secs();
        let rounded_secs = (duration.as_secs() / bucket_secs) * bucket_secs;
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(rounded_secs)
    }
}

impl Default for ReceiptBatch {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_witness_key_generation() {
        let key1 = WitnessKey::generate();
        let key2 = WitnessKey::generate();
        
        // Keys should be different
        assert_ne!(key1.secret, key2.secret);
        assert_ne!(key1.public, key2.public);
    }
    
    #[test]
    fn test_pseudonym_generation() {
        let key = WitnessKey::generate();
        let cid = [1u8; 32];
        let epoch = 1;
        
        let pseudonym1 = key.create_pseudonym(&cid, epoch);
        let pseudonym2 = key.create_pseudonym(&cid, epoch);
        
        // Same inputs should produce same pseudonym
        assert_eq!(pseudonym1.value, pseudonym2.value);
        
        // Different epoch should produce different pseudonym
        let pseudonym3 = key.create_pseudonym(&cid, epoch + 1);
        assert_ne!(pseudonym1.value, pseudonym3.value);
    }
    
    #[test]
    fn test_receipt_creation() {
        let key = WitnessKey::generate();
        let cid = [1u8; 32];
        let epoch = 1;
        
        let metadata = ReceiptMetadata {
            latency_ms: 150,
            content_size: 1024,
            valid: true,
            error: None,
        };
        
        let receipt = key.create_receipt(cid, epoch, metadata.clone());
        
        assert_eq!(receipt.cid, cid);
        assert_eq!(receipt.metadata.latency_ms, 150);
        assert_eq!(receipt.metadata.content_size, 1024);
        assert!(receipt.metadata.valid);
    }
    
    #[test]
    fn test_receipt_batch() {
        let key = WitnessKey::generate();
        let cid1 = [1u8; 32];
        let cid2 = [2u8; 32];
        
        let mut batch = ReceiptBatch::new();
        
        // Add receipts
        for i in 0..5 {
            let metadata = ReceiptMetadata {
                latency_ms: 100 + i * 10,
                content_size: 1024,
                valid: true,
                error: None,
            };
            batch.add(key.create_receipt(cid1, i as u64, metadata));
        }
        
        for i in 0..3 {
            let metadata = ReceiptMetadata {
                latency_ms: 200 + i * 10,
                content_size: 2048,
                valid: true,
                error: None,
            };
            batch.add(key.create_receipt(cid2, i as u64, metadata));
        }
        
        // Check counts
        assert_eq!(batch.get_by_cid(&cid1).len(), 5);
        assert_eq!(batch.get_by_cid(&cid2).len(), 3);
        
        // With different epochs, pseudonyms are different
        assert_eq!(batch.count_unique_witnesses(&cid1), 5);
    }
    
    #[test]
    fn test_temporal_distribution() {
        let key = WitnessKey::generate();
        let cid = [1u8; 32];
        let mut batch = ReceiptBatch::new();
        
        // Add receipts at different times
        let base_time = SystemTime::now();
        for i in 0..10 {
            let metadata = ReceiptMetadata {
                latency_ms: 100,
                content_size: 1024,
                valid: true,
                error: None,
            };
            let mut receipt = key.create_receipt(cid, i, metadata);
            receipt.timestamp = base_time + std::time::Duration::from_secs(i * 30);
            batch.add(receipt);
        }
        
        let distribution = batch.temporal_distribution(&cid, std::time::Duration::from_secs(60));
        assert!(distribution.len() > 0);
    }
}