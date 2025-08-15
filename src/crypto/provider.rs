use crate::crypto::types::*;
use ed25519_dalek::{Signer, Verifier};
use rand::rngs::OsRng;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("signature verification failed")]
    SigVerify,
    #[error("invalid signature bytes")]
    InvalidSignature,
    #[error("invalid key bytes")]
    InvalidKey,
    #[error("vrf verification failed")]
    VrfVerify,
}

/// A simple facade over signatures + VRF so the rest of the codebase stays backend-agnostic.
pub trait CryptoProvider {
    // --- Signatures (Ed25519) ---
    fn sig_keygen() -> SigKeypair;
    fn sign(msg: &[u8], sk: &SigSecretKey) -> Result<Signature, CryptoError>;
    fn verify(msg: &[u8], pk: &SigPublicKey, sig: &Signature) -> Result<(), CryptoError>;

    // --- VRF (RFC9381 Ristretto255) ---
    fn vrf_keygen() -> VrfKeypair;
    /// Returns (vrf_output, vrf_proof)
    fn vrf_prove(input: &[u8], sk: &VrfSecretKey) -> Result<(VrfOutput, VrfProof), CryptoError>;
    fn vrf_verify(
        input: &[u8],
        pk: &VrfPublicKey,
        proof: &VrfProof,
    ) -> Result<VrfOutput, CryptoError>;
}

/// Default provider: ed25519-dalek (signatures) + vrf-r255 (ECVRF-RISTRETTO255-SHA512)
pub struct DefaultCrypto;

impl CryptoProvider for DefaultCrypto {
    // --- Signatures ---
    fn sig_keygen() -> SigKeypair {
        let mut rng = OsRng;
        let signing = ed25519_dalek::SigningKey::generate(&mut rng);
        let verifying = signing.verifying_key();
        SigKeypair {
            public: SigPublicKey(verifying.to_bytes()),
            secret: SigSecretKey(signing.to_bytes()),
        }
    }

    fn sign(msg: &[u8], sk: &SigSecretKey) -> Result<Signature, CryptoError> {
        // From secret bytes back to SigningKey (ed25519-dalek v2 supports this API)
        let signing = ed25519_dalek::SigningKey::from_bytes(&sk.0);
        Ok(signing.sign(msg))
    }

    fn verify(msg: &[u8], pk: &SigPublicKey, sig: &Signature) -> Result<(), CryptoError> {
        let verifying =
            ed25519_dalek::VerifyingKey::from_bytes(&pk.0).map_err(|_| CryptoError::InvalidKey)?;
        verifying
            .verify(msg, sig)
            .map_err(|_| CryptoError::SigVerify)
    }

    // --- VRF ---
    fn vrf_keygen() -> VrfKeypair {
        let sk = vrf_r255::SecretKey::generate(rand::rngs::OsRng);
        let pk = vrf_r255::PublicKey::from(sk);
        VrfKeypair {
            public: VrfPublicKey(pk.to_bytes()),
            secret: VrfSecretKey(sk.to_bytes()),
        }
    }

    fn vrf_prove(input: &[u8], sk: &VrfSecretKey) -> Result<(VrfOutput, VrfProof), CryptoError> {
        let sk = vrf_r255::SecretKey::from_bytes(sk.0).into_option().ok_or(CryptoError::InvalidKey)?;
        let proof = sk.prove(input);
        let pk = vrf_r255::PublicKey::from(sk);
        let out_opt = pk.verify(input, &proof);
        // Per vrf-r255 docs, verify returns Option<HashOutput>; we return bytes for callers
        let out = out_opt.into_option().ok_or(CryptoError::VrfVerify)?;
        Ok((VrfOutput(out.to_vec()), VrfProof(proof.to_bytes().to_vec())))
    }

    fn vrf_verify(
        input: &[u8],
        pk: &VrfPublicKey,
        proof: &VrfProof,
    ) -> Result<VrfOutput, CryptoError> {
        let pk = vrf_r255::PublicKey::from_bytes(pk.0).ok_or(CryptoError::InvalidKey)?;
        if proof.0.len() != 80 {
            return Err(CryptoError::InvalidSignature);
        }
        let mut proof_bytes = [0u8; 80];
        proof_bytes.copy_from_slice(&proof.0);
        let proof = vrf_r255::Proof::from_bytes(proof_bytes).ok_or(CryptoError::InvalidSignature)?;
        let out_opt = pk.verify(input, &proof);
        out_opt
            .into_option()
            .map(|o| VrfOutput(o.to_vec()))
            .ok_or(CryptoError::VrfVerify)
    }
}

impl DefaultCrypto {
    /// Sign using a caller-provided Ed25519 secret key bytes
    pub fn sign_with_secret_bytes(
        msg: &[u8],
        secret_bytes: [u8; ed25519_dalek::SECRET_KEY_LENGTH],
    ) -> Result<Signature, CryptoError> {
        let signing = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
        Ok(signing.sign(msg))
    }

    /// Verify using caller-provided Ed25519 public key and signature bytes
    pub fn verify_with_bytes(
        msg: &[u8],
        public_key: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH],
        signature: [u8; ed25519_dalek::SIGNATURE_LENGTH],
    ) -> Result<(), CryptoError> {
        let verifying = ed25519_dalek::VerifyingKey::from_bytes(&public_key)
            .map_err(|_| CryptoError::InvalidKey)?;
        let sig = ed25519_dalek::Signature::from_bytes(&signature);
        verifying
            .verify(msg, &sig)
            .map_err(|_| CryptoError::SigVerify)
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::provider::{CryptoProvider, DefaultCrypto};

    #[test]
    fn sign_and_verify() {
        let kp = DefaultCrypto::sig_keygen();
        let msg = b"saorsa: witness-statement";
        let sig = DefaultCrypto::sign(msg, &kp.secret).unwrap();
        DefaultCrypto::verify(msg, &kp.public, &sig).unwrap();
    }

    #[test]
    fn vrf_roundtrip() {
        let vk = DefaultCrypto::vrf_keygen();
        let input = b"saorsa: slot-beacon";
        let (out, proof) = DefaultCrypto::vrf_prove(input, &vk.secret).unwrap();
        let verified = DefaultCrypto::vrf_verify(input, &vk.public, &proof).unwrap();
        assert_eq!(out.0, verified.0);
    }

    #[test]
    fn sign_and_verify_with_invalid_key() {
        let kp = DefaultCrypto::sig_keygen();
        let msg = b"test message";
        let sig = DefaultCrypto::sign(msg, &kp.secret).unwrap();
        
        // Try to verify with wrong public key
        let wrong_kp = DefaultCrypto::sig_keygen();
        assert!(DefaultCrypto::verify(msg, &wrong_kp.public, &sig).is_err());
    }

    #[test]
    fn vrf_deterministic() {
        let vk = DefaultCrypto::vrf_keygen();
        let input = b"deterministic-input";
        
        let (out1, proof1) = DefaultCrypto::vrf_prove(input, &vk.secret).unwrap();
        let (out2, proof2) = DefaultCrypto::vrf_prove(input, &vk.secret).unwrap();
        
        // Same input should produce same output and proof
        assert_eq!(out1.0, out2.0);
        assert_eq!(proof1.0, proof2.0);
    }

    #[test]
    fn vrf_different_inputs_different_outputs() {
        let vk = DefaultCrypto::vrf_keygen();
        
        let (out1, _) = DefaultCrypto::vrf_prove(b"input1", &vk.secret).unwrap();
        let (out2, _) = DefaultCrypto::vrf_prove(b"input2", &vk.secret).unwrap();
        
        // Different inputs should produce different outputs
        assert_ne!(out1.0, out2.0);
    }
}
