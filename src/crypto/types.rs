use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub type Signature = ed25519_dalek::Signature;

/// Raw VRF proof bytes wrapper (opaque to callers)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VrfProof(#[serde(with = "serde_bytes")] pub Vec<u8>);

/// Raw VRF output bytes wrapper
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VrfOutput(#[serde(with = "serde_bytes")] pub Vec<u8>);

/// Ed25519 public key
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigPublicKey(#[serde(with = "serde_bytes")] pub [u8; ed25519_dalek::PUBLIC_KEY_LENGTH]);

/// Ed25519 secret key (PKCS#8 not used here; store as raw bytes). Zeroized on drop.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct SigSecretKey(#[serde(with = "serde_bytes")] pub [u8; ed25519_dalek::SECRET_KEY_LENGTH]);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigKeypair {
    pub public: SigPublicKey,
    /// Raw secret bytes (zeroized on drop)
    pub secret: SigSecretKey,
}

/// VRF public key (ristretto255)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VrfPublicKey(#[serde(with = "serde_bytes")] pub [u8; 32]);

/// VRF secret key (ristretto255). Zeroized on drop.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct VrfSecretKey(#[serde(with = "serde_bytes")] pub [u8; 32]);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VrfKeypair {
    pub public: VrfPublicKey,
    pub secret: VrfSecretKey,
}
