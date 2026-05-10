//! Credential derivation from fingerprint secret + NIN.
//!
//! In production the NIMC fingerprint scanner produces a normalised biometric
//! template; here we use a short human-readable secret string as a stand-in.
//!
//! `derive_credential_secret` produces a 32-byte secret that is the root of
//! all per-voter cryptographic material (commitment blinding, nullifier, etc.).
//! It is derived deterministically so the enclave can re-derive it from the
//! same inputs on every session — no persistent voter secret storage needed.
//!
//! Domain separation: SHA-256("IDV2-v1-cred" ‖ nin ‖ 0x00 ‖ fp_secret)
//! The NUL byte prevents length-extension collisions between NIN and secret.

use sha2::{Digest, Sha256};
use curve25519_dalek::scalar::Scalar;

const CRED_DOMAIN: &[u8] = b"IDV2-v1-cred";
const BLINDING_DOMAIN: &[u8] = b"IDV2-v1-blinding";

/// Derive the 32-byte voter credential secret from NIN and fingerprint secret.
pub fn derive_credential_secret(nin: &str, fingerprint_secret: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CRED_DOMAIN);
    h.update(nin.as_bytes());
    h.update([0x00]);
    h.update(fingerprint_secret.as_bytes());
    h.finalize().into()
}

/// Derive a deterministic blinding scalar from a credential secret.
///
/// Used for demo registration where the enclave must re-derive the same
/// commitment on every call without storing the blinding factor.
/// In production, a random blinding scalar is used and stored under the HSM.
pub fn derive_blinding(credential_secret: &[u8; 32]) -> Scalar {
    let mut h = Sha256::new();
    h.update(BLINDING_DOMAIN);
    h.update(credential_secret);
    let bytes: [u8; 32] = h.finalize().into();
    Scalar::from_bytes_mod_order(bytes)
}

/// Produce a 32-byte session key for looking up in-memory voter state.
pub fn credential_hash(credential_secret: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(credential_secret).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let a = derive_credential_secret("12345678901", "fp-secret");
        let b = derive_credential_secret("12345678901", "fp-secret");
        assert_eq!(a, b);
    }

    #[test]
    fn different_nin_different_secret() {
        let a = derive_credential_secret("12345678901", "fp-secret");
        let b = derive_credential_secret("12345678902", "fp-secret");
        assert_ne!(a, b);
    }

    #[test]
    fn different_fp_different_secret() {
        let a = derive_credential_secret("12345678901", "fp-A");
        let b = derive_credential_secret("12345678901", "fp-B");
        assert_ne!(a, b);
    }

    #[test]
    fn blinding_is_deterministic() {
        let cred = derive_credential_secret("12345678901", "fp-secret");
        assert_eq!(derive_blinding(&cred), derive_blinding(&cred));
    }

    #[test]
    fn credential_hash_non_zero() {
        let cred = derive_credential_secret("12345678901", "fp-secret");
        assert_ne!(credential_hash(&cred), [0u8; 32]);
    }
}
