//! Nullifier derivation: SHA-3-256(credential_secret ‖ election_id_le)
//!
//! One nullifier per (voter, election) pair.  The on-chain nullifier PDA uses this
//! value as part of its seeds so that double-voting is detectable without linking
//! the nullifier back to the voter's identity.
//!
//! SHA-3-256 is chosen over SHA-2-256 because its sponge construction is
//! structurally distinct from the SHA-2 used for Merkle hashing in voter_registry,
//! eliminating any theoretical length-extension interaction between the two layers.

use sha3::{Digest, Sha3_256};

/// Derive a 32-byte nullifier from `credential_secret` and `election_id`.
///
/// The result is deterministic: the same (secret, election) pair always produces
/// the same nullifier, which is the required property for double-vote detection.
/// Different election IDs produce independent nullifiers, so a voter's participation
/// across elections is unlinkable.
pub fn derive(credential_secret: &[u8; 32], election_id: u64) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(credential_secret);
    h.update(election_id.to_le_bytes());
    let out = h.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const S_A: [u8; 32] = [0x01; 32];
    const S_B: [u8; 32] = [0x02; 32];

    // ── determinism ───────────────────────────────────────────────────────────

    #[test]
    fn deterministic() {
        assert_eq!(derive(&S_A, 42), derive(&S_A, 42));
    }

    // ── collision resistance ──────────────────────────────────────────────────

    #[test]
    fn different_election_ids_produce_different_nullifiers() {
        assert_ne!(derive(&S_A, 1), derive(&S_A, 2));
    }

    #[test]
    fn different_secrets_produce_different_nullifiers() {
        assert_ne!(derive(&S_A, 1), derive(&S_B, 1));
    }

    #[test]
    fn election_zero_distinct_from_election_one() {
        // Catches bugs where election_id bytes are silently ignored.
        assert_ne!(derive(&S_A, 0), derive(&S_A, 1));
    }

    #[test]
    fn election_boundary_values() {
        // u64::MAX should not collide with u64::MAX - 1.
        assert_ne!(derive(&S_A, u64::MAX), derive(&S_A, u64::MAX - 1));
    }

    // ── output shape ─────────────────────────────────────────────────────────

    #[test]
    fn output_is_32_bytes_and_non_zero() {
        let n = derive(&S_A, 1);
        assert_eq!(n.len(), 32);
        assert_ne!(n, [0u8; 32]);
    }

    // ── domain separation sanity ──────────────────────────────────────────────
    // Verify that the election_id bytes are actually included in the hash:
    // if election_id were silently truncated or reversed the first two tests
    // above would catch it, but this makes the intent explicit.

    #[test]
    fn nullifiers_for_same_prefix_differ_on_upper_bytes() {
        // election_id 256 vs 257 share the low byte (0x00 vs 0x01 at byte 1).
        assert_ne!(derive(&S_A, 256), derive(&S_A, 257));
    }

    // ── known vectors (frozen 2026-04-27) ────────────────────────────────────

    #[test]
    fn known_vector_s_a_eid_1() {
        assert_eq!(
            derive(&S_A, 1),
            [
                0x20, 0x4b, 0xb4, 0xf4, 0x4b, 0xbf, 0xa2, 0xfc,
                0x88, 0xb8, 0xe3, 0xc6, 0x37, 0xe1, 0xfd, 0xcc,
                0x22, 0x7a, 0xbe, 0x11, 0x24, 0x40, 0xef, 0xf3,
                0x59, 0x1f, 0x85, 0x93, 0xa6, 0x8d, 0x5e, 0x95,
            ]
        );
    }

    #[test]
    fn known_vector_zeros_eid_0() {
        assert_eq!(
            derive(&[0u8; 32], 0),
            [
                0xfd, 0xc6, 0xd5, 0x87, 0xc8, 0x3a, 0x34, 0x8e,
                0x45, 0x6b, 0x03, 0x4e, 0x1e, 0x0c, 0x31, 0xe9,
                0xa7, 0xe1, 0xa3, 0xaa, 0x66, 0xea, 0x28, 0xa7,
                0x59, 0xf0, 0x47, 0x22, 0x82, 0x63, 0x14, 0x21,
            ]
        );
    }

    #[test]
    fn known_vector_s_a_eid_max() {
        assert_eq!(
            derive(&S_A, u64::MAX),
            [
                0x44, 0xd2, 0x9f, 0x2e, 0xcd, 0x54, 0x47, 0x6e,
                0xe8, 0x09, 0x29, 0x22, 0x4a, 0x62, 0xda, 0x35,
                0xef, 0x89, 0xca, 0x79, 0x47, 0x8a, 0xa0, 0xef,
                0x5c, 0xc3, 0x79, 0xa1, 0xf1, 0x49, 0xa2, 0x0c,
            ]
        );
    }

    // ── known-vector emission ─────────────────────────────────────────────────
    // Re-run if the hash function or input encoding ever changes.
    //
    //   cargo test -p enclave -- --ignored emit_nullifier_vectors 2>&1
    #[test]
    #[ignore]
    fn emit_nullifier_vectors() {
        eprintln!(
            "nullifier([0x01;32], eid=1)       = {:02x?}",
            derive(&S_A, 1)
        );
        eprintln!(
            "nullifier([0x00;32], eid=0)       = {:02x?}",
            derive(&[0u8; 32], 0)
        );
        eprintln!(
            "nullifier([0x01;32], eid=u64::MAX)= {:02x?}",
            derive(&S_A, u64::MAX)
        );
    }
}
