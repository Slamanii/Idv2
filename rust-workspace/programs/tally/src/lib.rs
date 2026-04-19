//! tally — Pinocchio program.
//!
//! Stores the canonical final tally once an election closes. Read-heavy.

#![allow(dead_code)]

#[repr(C)]
pub struct TallyAccount {
    pub election_id: [u8; 32],
    pub candidate_totals: [u64; 16], // up to 16 candidates per election
    pub finalized_slot: u64,
    pub finalized: u8,
}
