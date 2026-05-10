use pinocchio::{
    account_info::AccountInfo,
    instruction::{Seed, Signer},
    program_error::ProgramError,
    pubkey::{self, Pubkey},
    ProgramResult,
};
use pinocchio::log::sol_log;
use pinocchio_pubkey::pubkey as pk;
use pinocchio_system::instructions::CreateAccount;

use crate::{Candidate, ElectionAccount, MAX_CANDIDATES, phase};

// ── create_election (ix_tag = 0) ─────────────────────────────────────────────
//
// Accounts:  [authority (signer), election_account (writable), system_program]
//
// Data layout (after tag byte, all LE):
//   [0..8]   election_id              : u64
//   [8..16]  registration_open_slot   : u64
//   [16..24] registration_close_slot  : u64
//   [24..32] voting_open_slot         : u64
//   [32..40] voting_close_slot        : u64
//   [40..72] aggregation_pubkey       : [u8; 32]
//   [72..80] lamports                 : u64   (rent-exempt min, computed client-side)
//   [80]     bump                     : u8    (PDA bump, computed client-side)
//
// The client calculates lamports via rpc.get_minimum_balance_for_rent_exemption
// and the bump via Pubkey::find_program_address(&[b"election", &eid_le], pid).
pub fn create_election(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let [authority, election_account, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    // authority pays the rent lamports via CPI; must be writable.
    if !authority.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    if data.len() < 81 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let election_id             = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let registration_open_slot  = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let registration_close_slot = u64::from_le_bytes(data[16..24].try_into().unwrap());
    let voting_open_slot        = u64::from_le_bytes(data[24..32].try_into().unwrap());
    let voting_close_slot       = u64::from_le_bytes(data[32..40].try_into().unwrap());
    let aggregation_pubkey: [u8; 32] = data[40..72].try_into().unwrap();
    let lamports                = u64::from_le_bytes(data[72..80].try_into().unwrap());
    let bump                    = data[80];

    // Verify election_account is the canonical PDA for this election_id.
    // invoke_signed would also reject a mismatch, but checking early gives
    // a cleaner error before paying CPI overhead.
    let eid_le = election_id.to_le_bytes();
    let bump_arr = [bump];
    let expected = pubkey::create_program_address(
        &[b"election", &eid_le, &bump_arr],
        program_id,
    )?;
    if election_account.key() != &expected {
        return Err(ProgramError::InvalidAccountData);
    }

    // Reject duplicate create.
    if election_account.data_len() != 0 {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    // Slot ordering sanity — catch obviously wrong inputs before touching chain state.
    if registration_close_slot <= registration_open_slot
        || voting_open_slot < registration_close_slot
        || voting_close_slot <= voting_open_slot
    {
        return Err(ProgramError::InvalidInstructionData);
    }

    // CPI → system program: allocate the account and assign ownership to this program.
    let seeds = [
        Seed::from(b"election" as &[u8]),
        Seed::from(eid_le.as_ref()),
        Seed::from(bump_arr.as_ref()),
    ];
    CreateAccount {
        from:  authority,
        to:    election_account,
        lamports,
        space: ElectionAccount::LEN as u64,
        owner: program_id,
    }
    .invoke_signed(&[Signer::from(&seeds)])?;

    // Zero-copy write directly into the newly allocated account data.
    // `candidates` and `_reserved` are already zeroed by CreateAccount.
    let state = unsafe {
        ElectionAccount::from_bytes_mut(election_account.borrow_mut_data_unchecked())
    };
    state.discriminator           = ElectionAccount::DISCRIMINATOR;
    state.election_id             = election_id;
    state.authority               = *authority.key();
    state.aggregation_pubkey      = aggregation_pubkey;
    state.registration_open_slot  = registration_open_slot;
    state.registration_close_slot = registration_close_slot;
    state.voting_open_slot        = voting_open_slot;
    state.voting_close_slot       = voting_close_slot;
    state.phase                   = phase::DRAFT;
    state.candidate_count         = 0;

    Ok(())
}

// ── set_candidates (ix_tag = 1) ───────────────────────────────────────────────
//
// Accounts:  [authority (signer), election_account (writable PDA)]
//
// Data layout (after tag byte):
//   [0..8]          election_id     : u64
//   [8]             candidate_count : u8  (1..=32)
//   [9..9+count*48] candidates      : packed array
//
// Each Candidate (48 B):
//   [0]      id    : u8
//   [1..33]  name  : [u8; 32]  (UTF-8, zero-padded)
//   [33..48] party : [u8; 15]  (UTF-8, zero-padded)
//
// May be called repeatedly while phase < RegClosed (allows roster corrections).
// Advances phase Draft → RegOpen on the first successful call.
pub fn set_candidates(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let [authority, election_account] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Validate accounts before borrowing data.
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if unsafe { election_account.owner() } != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }

    if data.len() < 9 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let election_id     = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let candidate_count = data[8] as usize;

    if candidate_count == 0 || candidate_count > MAX_CANDIDATES {
        return Err(ProgramError::InvalidInstructionData);
    }
    if data.len() < 9 + candidate_count * Candidate::LEN {
        return Err(ProgramError::InvalidInstructionData);
    }

    let state = unsafe {
        ElectionAccount::from_bytes_mut(election_account.borrow_mut_data_unchecked())
    };

    if state.discriminator != ElectionAccount::DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    if state.election_id != election_id {
        return Err(ProgramError::InvalidAccountData);
    }
    if state.authority != *authority.key() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    // Roster is frozen once registration closes.
    if state.phase >= phase::REG_CLOSED {
        return Err(ProgramError::InvalidAccountData);
    }

    for i in 0..candidate_count {
        let off = 9 + i * Candidate::LEN;
        state.candidates[i].id = data[off];
        state.candidates[i].name.copy_from_slice(&data[off + 1..off + 33]);
        state.candidates[i].party.copy_from_slice(&data[off + 33..off + 48]);
    }
    state.candidate_count = candidate_count as u8;

    // First successful call advances Draft → RegOpen.
    if state.phase == phase::DRAFT {
        state.phase = phase::REG_OPEN;
    }

    Ok(())
}

// ── rotate_aggregation_key (ix_tag = 2) ──────────────────────────────────────
//
// Accounts:  [authority (signer), election_account (writable PDA)]
//
// Data layout (after tag byte):
//   [0..8]   election_id  : u64
//   [8..40]  new_pubkey   : [u8; 32]
//
// Allowed in any phase — the aggregation server can be rotated at any time
// before the tally is finalised without restarting the election.
pub fn rotate_aggregation_key(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let [authority, election_account] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if unsafe { election_account.owner() } != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }

    if data.len() < 40 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let election_id: u64 = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let new_pubkey: [u8; 32] = data[8..40].try_into().unwrap();

    let state = unsafe {
        ElectionAccount::from_bytes_mut(election_account.borrow_mut_data_unchecked())
    };

    if state.discriminator != ElectionAccount::DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    if state.election_id != election_id {
        return Err(ProgramError::InvalidAccountData);
    }
    if state.authority != *authority.key() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    state.aggregation_pubkey = new_pubkey;
    sol_log("agg_key_rotated");

    Ok(())
}

// ── advance_phase (ix_tag = 3) ────────────────────────────────────────────────
//
// Accounts:  [authority (signer), election_account (writable PDA), clock_sysvar]
//
// Data layout (after tag byte):
//   [0..8]  election_id   : u64
//   [8]     target_phase  : u8
//
// Valid slot-gated transitions:
//   REG_OPEN  → REG_CLOSED  : slot >= registration_close_slot
//   REG_CLOSED→ VOTING_OPEN : slot >= voting_open_slot
//   VOTING_OPEN→VOTING_CLOSED: slot >= voting_close_slot
//   VOTING_CLOSED→TALLIED   : no slot restriction (aggregator signals readiness)
//
// The DRAFT→REG_OPEN transition is handled by set_candidates, not here.
pub fn advance_phase(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let [authority, election_account, clock_sysvar] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if unsafe { election_account.owner() } != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }

    // Verify clock sysvar identity before reading its data.
    const CLOCK_ID: Pubkey = pk!("SysvarC1ock11111111111111111111111111111111");
    if clock_sysvar.key() != &CLOCK_ID {
        return Err(ProgramError::InvalidAccountData);
    }

    if data.len() < 9 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let election_id: u64  = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let target_phase: u8  = data[8];

    // Current slot lives at byte offset 0 of the Clock sysvar (u64 LE).
    let clock_data = clock_sysvar.try_borrow_data()?;
    if clock_data.len() < 8 {
        return Err(ProgramError::InvalidAccountData);
    }
    let current_slot = u64::from_le_bytes(clock_data[0..8].try_into().unwrap());

    let state = unsafe {
        ElectionAccount::from_bytes_mut(election_account.borrow_mut_data_unchecked())
    };

    if state.discriminator != ElectionAccount::DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    if state.election_id != election_id {
        return Err(ProgramError::InvalidAccountData);
    }
    if state.authority != *authority.key() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Enforce valid forward-only transitions with slot guards.
    match (state.phase, target_phase) {
        (p, t) if p == phase::REG_OPEN && t == phase::REG_CLOSED => {
            if current_slot < state.registration_close_slot {
                return Err(ProgramError::InvalidInstructionData);
            }
        }
        (p, t) if p == phase::REG_CLOSED && t == phase::VOTING_OPEN => {
            if current_slot < state.voting_open_slot {
                return Err(ProgramError::InvalidInstructionData);
            }
        }
        (p, t) if p == phase::VOTING_OPEN && t == phase::VOTING_CLOSED => {
            if current_slot < state.voting_close_slot {
                return Err(ProgramError::InvalidInstructionData);
            }
        }
        (p, t) if p == phase::VOTING_CLOSED && t == phase::TALLIED => {
            // Aggregator signals it has posted the tally; no slot gate needed.
        }
        _ => return Err(ProgramError::InvalidInstructionData),
    }

    state.phase = target_phase;

    Ok(())
}
