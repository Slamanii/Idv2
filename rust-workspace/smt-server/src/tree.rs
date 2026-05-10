//! Incremental SHA-256 Merkle tree — mirrors voter_registry on-chain state.
//!
//! Hashing matches the on-chain program exactly:
//!   leaf  = sha256("idv2:leaf:" ‖ commitment)
//!   node  = sha256(left ‖ right)
//!   empty = [0u8; 32] at level 0; node_hash(empty[i-1], empty[i-1]) for i > 0
//!
//! The tree is append-only (depth 28, capacity 2^28 ≈ 268M leaves).
//! Subtrees beyond the current frontier are replaced by precomputed empty hashes,
//! so proof generation is O(n) in the number of inserted leaves — acceptable for
//! demo scale; add memoisation for production scale.

use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const DEPTH: usize = 28;

// ── Hashing primitives (must match voter_registry::merkle exactly) ────────────

pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    h.finalize().into()
}

pub fn leaf_hash(commitment: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"idv2:leaf:");
    h.update(commitment);
    h.finalize().into()
}

// ── Proof types ───────────────────────────────────────────────────────────────

/// Path for inserting the NEXT leaf into the tree.
///
/// Used by the relayer to build the `insert_commitment` instruction.
/// The on-chain program verifies that `leaf_hash([0u8;32])` walked through
/// this path reproduces the current `merkle_root` before accepting the insert.
pub struct InsertionPath {
    /// Current leaf count — this is the index the new leaf will occupy.
    pub index: u64,
    pub path: Vec<[u8; 32]>,
    pub path_indices: u32,
    pub root: [u8; 32],
}

pub struct MembershipProof {
    /// Leaf index (= lower 28 bits of path_indices).
    pub index: u64,
    /// `DEPTH` sibling hashes, level 0 (leaf) → level 27 (child of root).
    /// Packed into the ballot::cast `merkle_path` field as 28 × 32 = 896 bytes.
    pub path: Vec<[u8; 32]>,
    /// Bit i == 0 → leaf is the LEFT child at level i.
    /// Equals the leaf index as a u32 (lower DEPTH bits).
    pub path_indices: u32,
    /// Merkle root at the time the proof was generated.
    pub root: [u8; 32],
}

// ── Tree ──────────────────────────────────────────────────────────────────────

pub struct IncrementalMerkleTree {
    /// `leaf_hash(commitment)` for every inserted leaf, in insertion order.
    leaves: Vec<[u8; 32]>,
    /// Raw commitment → leaf index for O(1) proof lookup.
    commitment_to_index: HashMap<[u8; 32], usize>,
    /// Precomputed empty-subtree hashes: empty[0] = [0u8;32], empty[i] = node_hash(empty[i-1], empty[i-1]).
    empty: [[u8; 32]; DEPTH + 1],
}

impl IncrementalMerkleTree {
    pub fn new() -> Self {
        let mut empty = [[0u8; 32]; DEPTH + 1];
        for i in 1..=DEPTH {
            empty[i] = node_hash(&empty[i - 1], &empty[i - 1]);
        }
        Self {
            leaves: Vec::new(),
            commitment_to_index: HashMap::new(),
            empty,
        }
    }

    /// Append a commitment leaf.  Returns the assigned leaf index.
    /// Idempotent: inserting the same commitment twice returns the original index
    /// without adding a duplicate.
    pub fn insert(&mut self, commitment: &[u8; 32]) -> u64 {
        if let Some(&idx) = self.commitment_to_index.get(commitment) {
            return idx as u64;
        }
        let index = self.leaves.len();
        self.leaves.push(leaf_hash(commitment));
        self.commitment_to_index.insert(*commitment, index);
        index as u64
    }

    pub fn leaf_count(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// Current Merkle root over all inserted leaves.
    pub fn root(&self) -> [u8; 32] {
        self.subtree_hash(DEPTH, 0)
    }

    /// Generate the insertion path for the next leaf slot.
    ///
    /// The path proves that position `leaf_count` is currently empty by
    /// walking `[0u8;32]` (the empty sentinel) through the siblings and
    /// reproducing `self.root()`.  The relayer submits this with every
    /// `insert_commitment` instruction.
    pub fn insertion_path(&self) -> InsertionPath {
        let index = self.leaves.len();
        let mut path = Vec::with_capacity(DEPTH);
        for level in 0..DEPTH {
            let sib_node = (index >> level) ^ 1;
            let sib_start = sib_node << level;
            path.push(self.subtree_hash(level, sib_start));
        }
        InsertionPath {
            index: index as u64,
            path,
            path_indices: index as u32,
            root: self.root(),
        }
    }

    /// Generate a membership proof for `commitment`.
    /// Returns `None` if the commitment was never inserted.
    pub fn proof(&self, commitment: &[u8; 32]) -> Option<MembershipProof> {
        let &index = self.commitment_to_index.get(commitment)?;
        let mut path = Vec::with_capacity(DEPTH);
        for level in 0..DEPTH {
            // At `level`, our ancestor node index is `index >> level`.
            // Its sibling is `(index >> level) ^ 1`.
            // That sibling's subtree covers leaves starting at `sib_node << level`.
            let sib_node = (index >> level) ^ 1;
            let sib_start = sib_node << level;
            path.push(self.subtree_hash(level, sib_start));
        }
        Some(MembershipProof {
            index: index as u64,
            path,
            path_indices: index as u32,
            root: self.root(),
        })
    }

    /// Hash of the subtree rooted `level` levels above the leaf layer,
    /// covering `2^level` consecutive leaves starting at `start`.
    fn subtree_hash(&self, level: usize, start: usize) -> [u8; 32] {
        // Short-circuit: all leaves from `start` onward are empty.
        if start >= self.leaves.len() {
            return self.empty[level];
        }
        if level == 0 {
            return self.leaves[start];
        }
        let half = 1usize << (level - 1);
        let left  = self.subtree_hash(level - 1, start);
        let right = self.subtree_hash(level - 1, start + half);
        node_hash(&left, &right)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_root_deterministic() {
        assert_eq!(IncrementalMerkleTree::new().root(), IncrementalMerkleTree::new().root());
    }

    #[test]
    fn insert_changes_root() {
        let mut t = IncrementalMerkleTree::new();
        let before = t.root();
        t.insert(&[1u8; 32]);
        assert_ne!(t.root(), before);
    }

    #[test]
    fn idempotent_insert() {
        let mut t = IncrementalMerkleTree::new();
        let i1 = t.insert(&[7u8; 32]);
        let i2 = t.insert(&[7u8; 32]);
        assert_eq!(i1, i2);
        assert_eq!(t.leaf_count(), 1);
    }

    #[test]
    fn proof_verifies_with_compute_root_from_path() {
        let mut t = IncrementalMerkleTree::new();
        for i in 0u8..5 {
            t.insert(&[i; 32]);
        }
        let commitment = [2u8; 32];
        let proof = t.proof(&commitment).expect("must have proof");

        // Replicate ballot::cast Merkle verification
        let mut current = leaf_hash(&commitment);
        for (i, sib) in proof.path.iter().enumerate() {
            current = if (proof.path_indices >> i) & 1 == 0 {
                node_hash(&current, sib)
            } else {
                node_hash(sib, &current)
            };
        }
        assert_eq!(current, proof.root, "proof must reproduce the stored root");
    }

    #[test]
    fn proof_absent_for_unknown_commitment() {
        let t = IncrementalMerkleTree::new();
        assert!(t.proof(&[0xffu8; 32]).is_none());
    }

    #[test]
    fn root_matches_after_many_inserts() {
        let mut t = IncrementalMerkleTree::new();
        for i in 0u8..=255 {
            t.insert(&[i; 32]);
        }
        // All 256 proofs must verify
        for i in 0u8..=255 {
            let c = [i; 32];
            let proof = t.proof(&c).expect("proof present");
            let mut cur = leaf_hash(&c);
            for (j, sib) in proof.path.iter().enumerate() {
                cur = if (proof.path_indices >> j) & 1 == 0 {
                    node_hash(&cur, sib)
                } else {
                    node_hash(sib, &cur)
                };
            }
            assert_eq!(cur, t.root(), "proof failed for leaf {i}");
        }
    }
}
