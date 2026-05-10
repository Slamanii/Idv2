pub const DEPTH: usize = 28;

// ── SHA-256 backend ───────────────────────────────────────────────────────────
//
// On BPF (target_os = "solana") we call the sol_sha256 syscall directly.
// CU cost: 85 + 32 * ceil(bytes/32).
//   64-byte input  → 85 + 32*2 = 149 CU   (node_hash)
//   42-byte input  → 85 + 32*2 = 149 CU   (leaf_hash: "idv2:leaf:" + 32 B)
//   28 levels      → 28 * 149  ≈ 4 172 CU  (well below 50k target)
//
// Off BPF (unit tests, clients) we fall back to the sha2 crate.

#[cfg(target_os = "solana")]
fn sha256_two_parts(a: &[u8], b: &[u8]) -> [u8; 32] {
    extern "C" {
        fn sol_sha256(vals: *const u8, val_len: u64, hash_result: *mut u8) -> u64;
    }
    // The syscall takes an array of (ptr, len) pairs — each pair is 2×u64.
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

/// SHA-256 over left‖right. Convention for every internal node.
#[inline(always)]
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    sha256_two_parts(left, right)
}

/// Domain-separated hash applied to raw commitment before tree insertion.
/// Client MUST apply this before computing any Merkle path.
#[inline(always)]
pub fn leaf_hash(commitment: &[u8; 32]) -> [u8; 32] {
    sha256_two_parts(b"idv2:leaf:", commitment)
}

/// Walk `leaf` up DEPTH levels using sibling hashes packed consecutively in
/// `path_data` (DEPTH × 32 = 896 bytes). Bit i of `path_indices` == 0 means
/// current node is the LEFT child at level i.
/// Reads directly from the slice — never copies 896 bytes to the BPF stack.
pub fn compute_root_from_path(
    leaf: &[u8; 32],
    path_data: &[u8],
    path_indices: u32,
) -> [u8; 32] {
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

/// Root of a depth-DEPTH tree where every leaf is [0u8; 32].
/// Stored during `init_voter_registry`; this is the baseline every real
/// insertion departs from.
pub fn empty_tree_root() -> [u8; 32] {
    let mut current = [0u8; 32];
    for _ in 0..DEPTH {
        current = node_hash(&current, &current);
    }
    current
}

/// Sibling hashes for appending leaf at `index` into the current empty tree.
/// sib[0] = the adjacent empty leaf; sib[i] = empty subtree at level i.
/// Used in tests to build a valid path for the first insertion.
pub fn empty_path_siblings() -> [[u8; 32]; DEPTH] {
    let mut out = [[0u8; 32]; DEPTH];
    // out[0] = [0u8;32] (already set)
    for i in 1..DEPTH {
        out[i] = node_hash(&out[i - 1], &out[i - 1]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_root_deterministic() {
        assert_eq!(empty_tree_root(), empty_tree_root());
    }

    #[test]
    fn empty_path_reproduces_empty_root() {
        // The path for leaf 0 in the empty tree (all left children, path_indices = 0)
        // should reproduce empty_tree_root() when walked with the empty leaf [0u8;32].
        let sibs = empty_path_siblings();
        let mut flat = [0u8; DEPTH * 32];
        for (i, s) in sibs.iter().enumerate() {
            flat[i * 32..(i + 1) * 32].copy_from_slice(s);
        }
        let root = compute_root_from_path(&[0u8; 32], &flat, 0);
        assert_eq!(root, empty_tree_root());
    }

    #[test]
    fn insert_one_leaf_changes_root() {
        let sibs = empty_path_siblings();
        let mut flat = [0u8; DEPTH * 32];
        for (i, s) in sibs.iter().enumerate() {
            flat[i * 32..(i + 1) * 32].copy_from_slice(s);
        }
        let commitment = [42u8; 32];
        let leaf = leaf_hash(&commitment);
        let new_root = compute_root_from_path(&leaf, &flat, 0);
        assert_ne!(new_root, empty_tree_root());
    }

    #[test]
    fn leaf_hash_domain_separated_from_zero() {
        // leaf_hash([0;32]) must not equal [0;32] (the empty sentinel)
        assert_ne!(leaf_hash(&[0u8; 32]), [0u8; 32]);
    }

    #[test]
    fn node_hash_not_commutative() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_ne!(node_hash(&a, &b), node_hash(&b, &a));
    }
}
