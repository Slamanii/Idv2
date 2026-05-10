//! ballot — HOT PATH. One instruction: `cast`.
//!
//! Verifies voter membership via the on-chain LeafAccount (written during
//! registration), rejects duplicate nullifiers, writes an anonymous
//! `BallotAccount`, and CPIs to tally.  No commitment is stored in the ballot
//! — that separation is what makes `BallotAccount` unlinkable to any
//! `LeafAccount`.
//!
//! Instructions (ix_tag):
//!   0 = cast

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
        0 => instructions::cast(program_id, accounts, rest),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// ── BallotAccount ─────────────────────────────────────────────────────────────
//
// PDA: ["ballot", election_id_le, nullifier]
//
// The commitment is intentionally absent. Storing it would create an on-chain
// link between a voter's identity (commitment in LeafAccount) and their vote
// choice (candidate_id here), breaking receipt-freeness. The Merkle proof
// verifies membership at cast time and is discarded — nothing that connects
// these two accounts is written to the chain.

#[repr(C)]
pub struct BallotAccount {
    pub discriminator: [u8; 8],
    pub election_id:   u64,
    pub nullifier:     [u8; 32],
    pub state_id:      u8,
    pub candidate_id:  u8,
    pub lga_id:        u16,
    pub slot:          u64,
    pub _pad0:         [u8; 8],   // reserved; may hold wots_pubkey_hash in a future version
    pub _reserved:     [u8; 20],
}

impl BallotAccount {
    pub const LEN: usize = 8 + 8 + 32 + 1 + 1 + 2 + 8 + 8 + 20; // = 88
    pub const DISCRIMINATOR: [u8; 8] = *b"ballot\0\0";

    pub unsafe fn from_bytes_mut(data: &mut [u8]) -> &mut Self {
        &mut *(data.as_mut_ptr() as *mut Self)
    }

    pub unsafe fn from_bytes(data: &[u8]) -> &Self {
        &*(data.as_ptr() as *const Self)
    }
}

// ── NullifierAccount ──────────────────────────────────────────────────────────
//
// PDA: ["nullifier", election_id_le, nullifier]
//
// Existence-as-signal: the account existing means this nullifier was spent.
// The single `marked` byte differentiates an allocated-but-empty account
// from one we wrote. Double-vote rejection happens in two independent layers:
//   Layer 1 (on-chain) — this PDA.  If it exists, ballot::cast aborts.
//   Layer 2 (HSM)      — the monotonic counter sealed per voter in the HSM.
//                        Counter ≠ 0 → HSM refuses to produce a new signature.
// An attacker would need to defeat BOTH to cast a second ballot.

#[repr(C)]
pub struct NullifierAccount {
    pub marked: u8,
}

impl NullifierAccount {
    pub const LEN: usize = 1;
}

// ── getrandom stub ────────────────────────────────────────────────────────────

#[cfg(target_os = "solana")]
getrandom::register_custom_getrandom!(noop_getrandom);

#[cfg(target_os = "solana")]
pub fn noop_getrandom(_dest: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
