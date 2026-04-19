//! voter_registry — Pinocchio program.
//!
//! Maintains the sparse Merkle tree of voter identity commitments.
//! Only the current root is stored on-chain; the tree itself lives off-chain
//! in the Merkle server (see ../../enclave/).

#![allow(dead_code)]

pub const VOTER_REGISTRY_ACCOUNT_SIZE: usize = 80;

#[repr(C)]
pub struct VoterRegistryAccount {
    pub election_id: [u8; 32],
    pub commitment_count: u64,
    pub last_root_update_slot: u64,
    pub current_root: [u8; 32],
}
