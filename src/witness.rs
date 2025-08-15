// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Witness receipts with VRF pseudonyms for privacy-preserving attestation

use crate::Cid;
use schnorrkel::vrf::{VRFPreOut, VRFProof};
use schnorrkel::{Keypair, PublicKey, Signature, signing_context};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// VRF-based pseudonym for witness privacy
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VrfPseudonym {
    /// The pseudonym value
    pub value: [u8; 32],
    /// Proof of correct VRF computation
    pub proof: Vec<u8>,
}

// The actual VRF proof bytes are produced by schnorrkel and serialized as-is

/// Witness receipt for content retrieval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessReceipt {
    /// The CID that was retrieved
    pub cid: Cid,
    /// VRF pseudonym of the witness
    pub witness_pseudonym: VrfPseudonym,
    /// Public key of the witness (sr25519)
    pub witness_public: [u8; 32],
    /// Timestamp of retrieval
    pub timestamp: SystemTime,
    /// Epoch under which the retrieval occurred
    pub epoch: u64,
    /// Optional metadata
    pub metadata: ReceiptMetadata,
    /// Signature over the receipt (sr25519)
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
#[derive(Debug, Clone)]
pub struct WitnessKey {
    keypair: Keypair,
}

impl WitnessKey {
    /// Generate a new witness key
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        let keypair: Keypair = Keypair::generate_with(OsRng);
        Self { keypair }
    }

    /// Create VRF pseudonym for a CID
    pub fn create_pseudonym(&self, cid: &Cid, epoch: u64) -> VrfPseudonym {
        let ctx = signing_context(b"saorsa-vrf");
        let mut message = Vec::with_capacity(32 + 8);
        message.extend_from_slice(cid);
        message.extend_from_slice(&epoch.to_le_bytes());
        let (io, proof, _batchable) = self.keypair.vrf_sign(ctx.bytes(&message));
        let preout: VRFPreOut = io.to_preout();
        let mut value = [0u8; 32];
        value.copy_from_slice(preout.to_bytes().as_ref());
        VrfPseudonym {
            value,
            proof: proof.to_bytes().to_vec(),
        }
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
        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(self.keypair.public.to_bytes().as_ref());
        WitnessReceipt {
            cid,
            witness_pseudonym,
            witness_public: pub_bytes,
            timestamp,
            epoch,
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
        let ctx = signing_context(b"saorsa-receipt");
        let mut msg = Vec::new();
        msg.extend_from_slice(cid);
        msg.extend_from_slice(&pseudonym.value);
        msg.extend_from_slice(
            &timestamp
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .to_le_bytes(),
        );
        msg.extend_from_slice(&metadata.latency_ms.to_le_bytes());
        msg.extend_from_slice(&metadata.content_size.to_le_bytes());
        msg.push(metadata.valid as u8);
        let sig: Signature = self.keypair.sign(ctx.bytes(&msg));
        sig.to_bytes().to_vec()
    }

    /// Get the public key
    pub fn public_key(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(self.keypair.public.to_bytes().as_ref());
        bytes
    }
}

/// Verify a VRF pseudonym
pub fn verify_pseudonym(
    pseudonym: &VrfPseudonym,
    cid: &Cid,
    epoch: u64,
    public_key: &[u8; 32],
) -> bool {
    let Ok(pk) = PublicKey::from_bytes(public_key) else {
        return false;
    };
    let ctx = signing_context(b"saorsa-vrf");
    let mut message = Vec::with_capacity(32 + 8);
    message.extend_from_slice(cid);
    message.extend_from_slice(&epoch.to_le_bytes());
    let proof = match VRFProof::from_bytes(&pseudonym.proof) {
        Ok(p) => p,
        Err(_) => return false,
    };
    // Verify proof against expected pre-output derived from pseudonym value
    let preout = match VRFPreOut::from_bytes(&pseudonym.value) {
        Ok(po) => po,
        Err(_) => return false,
    };
    pk.vrf_verify(ctx.bytes(&message), &preout, &proof).is_ok()
}

/// Verify a witness receipt
pub fn verify_receipt(receipt: &WitnessReceipt, public_key: &[u8; 32]) -> bool {
    // Verify VRF pseudonym first
    if !verify_pseudonym(
        &receipt.witness_pseudonym,
        &receipt.cid,
        receipt.epoch,
        &receipt.witness_public,
    ) {
        return false;
    }

    // Verify signature
    let Ok(pk) = PublicKey::from_bytes(public_key) else {
        return false;
    };
    let ctx = signing_context(b"saorsa-receipt");
    let mut msg = Vec::new();
    msg.extend_from_slice(&receipt.cid);
    msg.extend_from_slice(&receipt.witness_pseudonym.value);
    msg.extend_from_slice(
        &receipt
            .timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_le_bytes(),
    );
    msg.extend_from_slice(&receipt.metadata.latency_ms.to_le_bytes());
    msg.extend_from_slice(&receipt.metadata.content_size.to_le_bytes());
    msg.push(receipt.metadata.valid as u8);

    match Signature::from_bytes(&receipt.signature) {
        Ok(sig) => pk.verify(ctx.bytes(&msg), &sig).is_ok(),
        Err(_) => false,
    }
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
        self.receipts.iter().filter(|r| r.cid == *cid).collect()
    }

    /// Count unique witnesses for a CID
    pub fn count_unique_witnesses(&self, cid: &Cid) -> usize {
        use std::collections::HashSet;

        self.receipts
            .iter()
            .filter(|r| r.cid == *cid)
            .map(|r| &r.witness_pseudonym)
            .collect::<HashSet<_>>()
            .len()
    }

    /// Get temporal distribution of receipts
    pub fn temporal_distribution(
        &self,
        cid: &Cid,
        bucket_size: std::time::Duration,
    ) -> Vec<(SystemTime, usize)> {
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
        let duration = time
            .duration_since(SystemTime::UNIX_EPOCH)
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
        assert_ne!(key1.public_key(), key2.public_key());
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
        // Verify pseudonym
        let pk = key.public_key();
        assert!(verify_pseudonym(&pseudonym1, &cid, epoch, &pk));

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
        // Verify signature with witness public
        let pk = key.public_key();
        assert!(verify_receipt(&receipt, &pk));
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
        assert!(!distribution.is_empty());
    }
}
