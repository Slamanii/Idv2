//! election_registry — Pinocchio program.
//!
//! Stores ElectionAccount state: election_id, timing bounds, voter Merkle root,
//! candidate count. See ../../../docs/PROJECT-PLAN.md for the account layout.
//!
//! Scaffold only — logic filled in on Day 8 of TIMELINE.md.

#![allow(dead_code)]

pub const ELECTION_ACCOUNT_SIZE: usize = 88;

#[repr(C)]
pub struct ElectionAccount {
    pub election_id: [u8; 32],
    pub start_slot: u64,
    pub end_slot: u64,
    pub voter_merkle_root: [u8; 32],
    pub candidate_count: u8,
    pub _padding: [u8; 7],
}
