//! voter_registry — append-only Merkle commitment tree.
//!
//! Holds `VoterRegistryAccount` (72 B header) keyed by `election_id`.
//! Each registered voter becomes one `LeafAccount` child PDA; the Merkle
//! root over all leaf hashes is stored in the header.
//!
//! Tree: SHA-256, depth 28 → 2^28 ≈ 268M leaves (Nigerian voter headroom).
//!
//! Instructions:
//!   0 = insert_commitment  (relayer; requires election_account read-only)
//!   1 = init_voter_registry (relayer; one-time setup per election)

pub mod instructions;
pub mod merkle;

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
        0 => instructions::insert_commitment(program_id, accounts, rest),
        1 => instructions::init_voter_registry(program_id, accounts, rest),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// ── constants ────────────────────────────────────────────────────────────────

pub const TREE_DEPTH: u8 = merkle::DEPTH as u8;

// ── VoterRegistryAccount ─────────────────────────────────────────────────────

#[repr(C)]
pub struct VoterRegistryAccount {
    pub discriminator: [u8; 8],
    pub election_id: u64,
    pub merkle_root: [u8; 32],
    pub leaf_count: u64,
    pub tree_depth: u8,
    pub _pad: [u8; 7],
    pub nullifier_count: u64,
}

impl VoterRegistryAccount {
    pub const LEN: usize = 8 + 8 + 32 + 8 + 1 + 7 + 8; // = 72
    pub const DISCRIMINATOR: [u8; 8] = *b"voterreg";

    pub unsafe fn from_bytes_mut(data: &mut [u8]) -> &mut Self {
        &mut *(data.as_mut_ptr() as *mut Self)
    }

    pub unsafe fn from_bytes(data: &[u8]) -> &Self {
        &*(data.as_ptr() as *const Self)
    }
}

// ── LeafAccount ──────────────────────────────────────────────────────────────
//
// PDA: ["leaf", election_id_le, leaf_index_le]
// Stores the raw Pedersen commitment so off-chain auditors can reconstruct
// the tree. The on-chain tree uses leaf_hash(commitment), not the raw value.

#[repr(C)]
pub struct LeafAccount {
    pub discriminator: [u8; 8],
    pub election_id: u64,
    pub index: u64,
    pub commitment: [u8; 32],
}

impl LeafAccount {
    pub const LEN: usize = 8 + 8 + 8 + 32; // = 56
    pub const DISCRIMINATOR: [u8; 8] = *b"leaf\0\0\0\0";

    pub unsafe fn from_bytes_mut(data: &mut [u8]) -> &mut Self {
        &mut *(data.as_mut_ptr() as *mut Self)
    }

    pub unsafe fn from_bytes(data: &[u8]) -> &Self {
        &*(data.as_ptr() as *const Self)
    }
}

// ── getrandom stub ───────────────────────────────────────────────────────────

#[cfg(target_os = "solana")]
getrandom::register_custom_getrandom!(noop_getrandom);

#[cfg(target_os = "solana")]
pub fn noop_getrandom(_dest: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
