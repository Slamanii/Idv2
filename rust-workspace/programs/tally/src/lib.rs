//! tally — append-only vote counter.
//!
//! 128 u64 counters: 32 candidates × 4 per-zone shards.
//! Sharding bounds write-contention on heavy voting windows; the aggregation
//! server sums shards when reporting per-candidate totals.
//!
//! Instructions:
//!   0 = accumulate_votes  (CPI-only from ballot::cast)
//!   1 = finalise_tally    (authority; locks the account after voting closes)
//!   2 = verify_tally      (read-only; internal consistency + voter-count bound)
//!   3 = init_tally        (authority; one-time setup per election)

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
        0 => instructions::accumulate_votes(program_id, accounts, rest),
        1 => instructions::finalise_tally(program_id, accounts, rest),
        2 => instructions::verify_tally(program_id, accounts, rest),
        3 => instructions::init_tally(program_id, accounts, rest),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// ── constants ─────────────────────────────────────────────────────────────────

pub const COUNTERS_LEN: usize = 128; // 32 candidates × 4 shards
pub const CANDIDATE_SHARDS: usize = 4;

// ── TallyAccount ──────────────────────────────────────────────────────────────
//
// PDA: ["tally", election_id_le]
//
// counter layout: counters[candidate_id * 4 + (state_id % 4)]
// Shard index = state_id mod 4 distributes write-load across states without
// needing a separate account per geographic unit.

#[repr(C)]
pub struct TallyAccount {
    pub discriminator:      [u8; 8],
    pub election_id:        u64,
    pub last_updated_slot:  u64,
    pub total_votes:        u64,
    pub counters:           [u64; COUNTERS_LEN], // 1024 B
    pub finalized:          u8,
    pub _reserved:          [u8; 31],
}

impl TallyAccount {
    pub const LEN: usize = 8 + 8 + 8 + 8 + (COUNTERS_LEN * 8) + 1 + 31; // = 1088
    pub const DISCRIMINATOR: [u8; 8] = *b"tallying";

    pub unsafe fn from_bytes_mut(data: &mut [u8]) -> &mut Self {
        &mut *(data.as_mut_ptr() as *mut Self)
    }

    pub unsafe fn from_bytes(data: &[u8]) -> &Self {
        &*(data.as_ptr() as *const Self)
    }

    /// Candidate total across all 4 shards.
    pub fn candidate_total(&self, candidate_id: u8) -> u64 {
        let base = candidate_id as usize * CANDIDATE_SHARDS;
        self.counters[base]
            + self.counters[base + 1]
            + self.counters[base + 2]
            + self.counters[base + 3]
    }
}

// ── getrandom stub ────────────────────────────────────────────────────────────

#[cfg(target_os = "solana")]
getrandom::register_custom_getrandom!(noop_getrandom);

#[cfg(target_os = "solana")]
pub fn noop_getrandom(_dest: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
