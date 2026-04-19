//! ballot — Pinocchio program. HOT PATH.
//!
//! Verifies signature, Merkle membership proof, and nullifier uniqueness for
//! every vote. Writes BallotAccount on success. See TIMELINE.md Phase 3.

#![allow(dead_code)]

pub const BALLOT_ACCOUNT_SIZE: usize = 112;

#[repr(C)]
pub struct BallotAccount {
    pub nullifier: [u8; 32],
    pub candidate_id: u8,
    pub state_id: u8,
    pub lga_id: u16,
    pub slot_submitted: u64,
    pub signature: [u8; 64],
    // padding to 112 bytes is handled by the allocator; see account layout in PROJECT-PLAN.md
}

#[repr(C)]
pub struct NullifierAccount {
    pub marked: u8,
}
