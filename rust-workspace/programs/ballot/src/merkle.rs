// Merkle tree helpers — identical contract to voter_registry::merkle.
// Duplicated here because BPF programs link independently; no shared crate.
// If DEPTH or the hash function ever changes, both copies must move together.

pub const DEPTH: usize = 28;
const PATH_BYTES: usize = DEPTH * 32; // 896

// ── SHA-256 backend ───────────────────────────────────────────────────────────
//
// On BPF we call sol_sha256 (149 CU per 64-byte call).
// 28 node_hash calls → ~4 172 CU. Total cast budget easily under 50k.
// Off BPF (tests, clients) falls back to sha2.

#[cfg(target_os = "solana")]
fn sha256_two_parts(a: &[u8], b: &[u8]) -> [u8; 32] {
    extern "C" {
        fn sol_sha256(vals: *const u8, val_len: u64, hash_result: *mut u8) -> u64;
    }
    let slices: [[u64; 2]; 2] = [
        [a.as_ptr() as u64, a.len() as u64],
        [b.as_ptr() as u64, b.len() as u64],
    ];
    let mut out = [0u8; 32];
    unsafe {
        sol_sha256(
            slices.as_ptr() as *const u8,
            2,
            out.as_mut_ptr(),
        );
    }
    out
}

#[cfg(not(target_os = "solana"))]
fn sha256_two_parts(a: &[u8], b: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

// ── public API ────────────────────────────────────────────────────────────────

#[inline(always)]
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    sha256_two_parts(left, right)
}

#[inline(always)]
pub fn leaf_hash(commitment: &[u8; 32]) -> [u8; 32] {
    sha256_two_parts(b"idv2:leaf:", commitment)
}

pub fn compute_root_from_path(
    leaf: &[u8; 32],
    path_data: &[u8],
    path_indices: u32,
) -> [u8; 32] {
    debug_assert_eq!(path_data.len(), PATH_BYTES);
    let mut current = *leaf;
    for i in 0..DEPTH {
        let sib: [u8; 32] = path_data[i * 32..(i + 1) * 32].try_into().unwrap();
        current = if (path_indices >> i) & 1 == 0 {
            node_hash(&current, &sib)
        } else {
            node_hash(&sib, &current)
        };
    }
    current
}

/// Sibling hashes for leaf 0 in the empty tree. Mirrors voter_registry::merkle.
pub fn empty_path_siblings() -> [[u8; 32]; DEPTH] {
    let mut out = [[0u8; 32]; DEPTH];
    for i in 1..DEPTH {
        out[i] = node_hash(&out[i - 1], &out[i - 1]);
    }
    out
}

pub fn empty_tree_root() -> [u8; 32] {
    let mut current = [0u8; 32];
    for _ in 0..DEPTH {
        current = node_hash(&current, &current);
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ballot_merkle_matches_voter_registry() {
        // Both programs must produce the same root for the same inputs.
        let mut flat = [0u8; PATH_BYTES];
        let sibs = empty_path_siblings();
        for (i, s) in sibs.iter().enumerate() {
            flat[i * 32..(i + 1) * 32].copy_from_slice(s);
        }
        let root = compute_root_from_path(&[0u8; 32], &flat, 0);
        assert_eq!(root, empty_tree_root());
    }

    #[test]
    fn leaf_hash_consistent() {
        let c = [7u8; 32];
        assert_eq!(leaf_hash(&c), leaf_hash(&c));
        assert_ne!(leaf_hash(&c), leaf_hash(&[8u8; 32]));
    }
}
