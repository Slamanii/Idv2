//! election_registry — program that owns election lifecycle state.

//!
//! Holds `ElectionAccount` (1664 B, see docs/PROGRAMS.md). Only program
//! allowed to mutate `phase`, the candidate roster, and the aggregation
//! pubkey. Other programs read from `ElectionAccount` but never write.
//!
//! Instructions (ix_tag):
//!   0 = create_election
//!   1 = set_candidates             (v0 tx + ALT; payload ~1537 B)
//!   2 = rotate_aggregation_key
//!   3 = advance_phase

pub mod instructions;

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

#[cfg(not(feature = "no-entrypoint"))]
use pinocchio::entrypoint;

#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let (tag, rest) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match tag {
        0 => instructions::create_election(program_id, accounts, rest),
        1 => instructions::set_candidates(program_id, accounts, rest),
        2 => instructions::rotate_aggregation_key(program_id, accounts, rest),
        3 => instructions::advance_phase(program_id, accounts, rest),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Canonical layout — exact byte offsets per docs/PROGRAMS.md §"ElectionAccount".
/// Kept at ~1664 B total; candidate roster lives inline to save an account read
/// on every ballot::cast.
pub const ELECTION_ACCOUNT_SIZE: usize = 1664;
pub const MAX_CANDIDATES: usize = 32;

#[repr(C)]
pub struct Candidate {
    pub id: u8,
    pub name: [u8; 32],
    pub party: [u8; 15],
}

impl Candidate {
    pub const LEN: usize = 1 + 32 + 15; // = 48
}

#[repr(C)]
pub struct ElectionAccount {
    pub discriminator: [u8; 8],
    pub election_id: u64,
    pub authority: Pubkey,
    pub aggregation_pubkey: [u8; 32],
    pub registration_open_slot: u64,
    pub registration_close_slot: u64,
    pub voting_open_slot: u64,
    pub voting_close_slot: u64,
    pub phase: u8,
    pub candidate_count: u8,
    pub _pad0: [u8; 6],
    pub candidates: [Candidate; MAX_CANDIDATES],
    pub _reserved: [u8; 8],
}

impl ElectionAccount {
    pub const LEN: usize = 8 + 8 + 32 + 32 + 8 + 8 + 8 + 8 + 1 + 1 + 6
        + (Candidate::LEN * MAX_CANDIDATES) + 8; // = 1664
    pub const DISCRIMINATOR: [u8; 8] = *b"election";

    /// Cast account raw bytes to a mutable reference.
    /// Caller must ensure `data` is `LEN` bytes long and properly aligned.
    ///
    /// # Safety
    /// The account must have been allocated by this program (discriminator
    /// checked before calling in read paths).
    pub unsafe fn from_bytes_mut(data: &mut [u8]) -> &mut Self {
        &mut *(data.as_mut_ptr() as *mut Self)
    }

    /// Cast account raw bytes to an immutable reference.
    pub unsafe fn from_bytes(data: &[u8]) -> &Self {
        &*(data.as_ptr() as *const Self)
    }
}
/// Phases, as u8, in strict forward order. See PROGRAMS.md.
pub mod phase {
    pub const DRAFT: u8 = 0;
    pub const REG_OPEN: u8 = 1;
    pub const REG_CLOSED: u8 = 2;
    pub const VOTING_OPEN: u8 = 3;
    pub const VOTING_CLOSED: u8 = 4;
    pub const TALLIED: u8 = 5;
}

// -----------------------------------------------------------------------
// getrandom custom backend — the BPF VM has no entropy source. Any
// transitive caller that reaches this path is a bug; fail loud rather
// than hand back zeros. Randomness lives off-chain in the enclave.
// -----------------------------------------------------------------------
#[cfg(target_os = "solana")]
getrandom::register_custom_getrandom!(noop_getrandom);

#[cfg(target_os = "solana")]
pub fn noop_getrandom(_dest: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
