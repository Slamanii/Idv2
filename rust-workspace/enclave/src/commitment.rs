//! Ristretto255 Pedersen commitment: C = m·G + r·H
//!
//! m = Scalar::from_wide(SHA-512(credential_secret ‖ state_id ‖ lga_id_le))
//! r = caller-supplied blinding scalar — use `Scalar::random(&mut rng)` per registration
//! H = nothing-up-my-sleeve secondary generator derived from a domain tag via
//!     RistrettoPoint::from_uniform_bytes(SHA-512(b"IDV2-v1-commitment-H"))
//!
//! state_id and lga_id are absorbed into the message scalar so the 32-byte compressed
//! commitment encodes jurisdiction without linking to any externally-known identifier.
//! Any-booth voting is preserved: the relayer reads state_id/lga_id from the BallotAccount
//! plaintext fields written at cast time, not from the commitment itself.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use sha2::{Digest, Sha512};

fn h_generator() -> RistrettoPoint {
    let out = Sha512::digest(b"IDV2-v1-commitment-H");
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&out);
    RistrettoPoint::from_uniform_bytes(&bytes)
}

fn message_scalar(credential_secret: &[u8; 32], state_id: u8, lga_id: u16) -> Scalar {
    let mut h = Sha512::new();
    h.update(credential_secret);
    h.update([state_id]);
    h.update(lga_id.to_le_bytes());
    let out = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&out);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Return the compressed Ristretto255 Pedersen commitment for the given voter inputs.
///
/// The 32-byte result is the leaf value inserted into the voter registry Merkle tree.
/// `blinding` must be fresh (sampled from a CSPRNG) for each registration call.
pub fn commit(
    credential_secret: &[u8; 32],
    state_id: u8,
    lga_id: u16,
    blinding: &Scalar,
) -> CompressedRistretto {
    let m = message_scalar(credential_secret, state_id, lga_id);
    (RISTRETTO_BASEPOINT_TABLE * &m + h_generator() * blinding).compress()
}

/// Return true iff `commitment` opens correctly to the given inputs under `blinding`.
///
/// Used by the enclave self-check immediately after registration; not called on-chain.
pub fn verify(
    commitment: &CompressedRistretto,
    credential_secret: &[u8; 32],
    state_id: u8,
    lga_id: u16,
    blinding: &Scalar,
) -> bool {
    commit(credential_secret, state_id, lga_id, blinding).as_bytes() == commitment.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    const S_A: [u8; 32] = [0x01; 32];
    const S_B: [u8; 32] = [0x02; 32];

    fn det_blinding() -> Scalar {
        // Fixed value for deterministic test vectors — never use in production.
        Scalar::from(0xdeadbeef_cafecafe_u64)
    }

    // ── property tests ────────────────────────────────────────────────────────

    #[test]
    fn deterministic() {
        let c1 = commit(&S_A, 1, 100, &det_blinding());
        let c2 = commit(&S_A, 1, 100, &det_blinding());
        assert_eq!(c1.as_bytes(), c2.as_bytes());
    }

    #[test]
    fn different_secret_different_commitment() {
        let c1 = commit(&S_A, 1, 100, &det_blinding());
        let c2 = commit(&S_B, 1, 100, &det_blinding());
        assert_ne!(c1.as_bytes(), c2.as_bytes());
    }

    #[test]
    fn different_state_id_different_commitment() {
        let c1 = commit(&S_A, 1, 100, &det_blinding());
        let c2 = commit(&S_A, 2, 100, &det_blinding());
        assert_ne!(c1.as_bytes(), c2.as_bytes());
    }

    #[test]
    fn different_lga_id_different_commitment() {
        let c1 = commit(&S_A, 1, 100, &det_blinding());
        let c2 = commit(&S_A, 1, 101, &det_blinding());
        assert_ne!(c1.as_bytes(), c2.as_bytes());
    }

    #[test]
    fn different_blinding_different_commitment() {
        let c1 = commit(&S_A, 1, 100, &Scalar::from(1_u64));
        let c2 = commit(&S_A, 1, 100, &Scalar::from(2_u64));
        assert_ne!(c1.as_bytes(), c2.as_bytes());
    }

    #[test]
    fn output_decompresses_to_valid_ristretto_point() {
        let c = commit(&S_A, 1, 100, &det_blinding());
        assert!(
            c.decompress().is_some(),
            "commitment must be a valid Ristretto255 point"
        );
    }

    #[test]
    fn verify_accepts_correct_opening() {
        let r = det_blinding();
        let c = commit(&S_A, 1, 100, &r);
        assert!(verify(&c, &S_A, 1, 100, &r));
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let r = det_blinding();
        let c = commit(&S_A, 1, 100, &r);
        assert!(!verify(&c, &S_B, 1, 100, &r));
    }

    #[test]
    fn verify_rejects_wrong_state_id() {
        let r = det_blinding();
        let c = commit(&S_A, 1, 100, &r);
        assert!(!verify(&c, &S_A, 2, 100, &r));
    }

    #[test]
    fn verify_rejects_wrong_lga_id() {
        let r = det_blinding();
        let c = commit(&S_A, 1, 100, &r);
        assert!(!verify(&c, &S_A, 1, 101, &r));
    }

    #[test]
    fn verify_rejects_wrong_blinding() {
        let c = commit(&S_A, 1, 100, &Scalar::from(1_u64));
        assert!(!verify(&c, &S_A, 1, 100, &Scalar::from(2_u64)));
    }

    // ── known vectors (frozen 2026-04-27) ────────────────────────────────────

    #[test]
    fn known_vector_s_a_state1_lga100() {
        assert_eq!(
            commit(&S_A, 1, 100, &det_blinding()).as_bytes(),
            &[
                0x14, 0x04, 0x59, 0xe5, 0xed, 0x97, 0x4e, 0x82,
                0x2f, 0x67, 0x02, 0x3d, 0xa6, 0x2a, 0x08, 0x18,
                0xde, 0x46, 0x48, 0x36, 0x17, 0x2c, 0xc4, 0xf8,
                0xeb, 0x0d, 0xd1, 0x55, 0x45, 0xd1, 0x8d, 0x01,
            ]
        );
    }

    #[test]
    fn known_vector_zeros_state0_lga0_blind0() {
        assert_eq!(
            commit(&[0u8; 32], 0, 0, &Scalar::from(0_u64)).as_bytes(),
            &[
                0xa4, 0x2e, 0xf1, 0xbd, 0x53, 0x7f, 0x6e, 0x28,
                0xc5, 0x13, 0xff, 0x1b, 0x4d, 0xe6, 0x1f, 0x98,
                0xa6, 0x00, 0xe1, 0x47, 0xc4, 0x47, 0xf2, 0x5b,
                0xf7, 0x98, 0x56, 0x65, 0x35, 0x19, 0xe4, 0x49,
            ]
        );
    }

    // ── known-vector emission ─────────────────────────────────────────────────
    // Re-run if the hash function, generator tag, or input encoding ever changes.
    //
    //   cargo test -p enclave -- --ignored emit_commitment_vectors 2>&1
    #[test]
    #[ignore]
    fn emit_commitment_vectors() {
        let r = det_blinding();
        eprintln!(
            "commit([0x01;32], state=1, lga=100, r=0xdeadbeef_cafecafe) = {:02x?}",
            commit(&S_A, 1, 100, &r).as_bytes()
        );
        eprintln!(
            "commit([0x00;32], state=0, lga=0,   r=0) = {:02x?}",
            commit(&[0u8; 32], 0, 0, &Scalar::from(0_u64)).as_bytes()
        );
    }
}
