use pinocchio::{
    account_info::AccountInfo,
    instruction::{Seed, Signer},
    log::sol_log,
    program_error::ProgramError,
    pubkey::{self, Pubkey},
    ProgramResult,
};
use pinocchio_pubkey::pubkey as pk;
use pinocchio_system::instructions::CreateAccount;

use crate::{TallyAccount, CANDIDATE_SHARDS, COUNTERS_LEN};

// ── Raw byte offsets into ElectionAccount (election_registry, PROGRAMS.md) ───
const EA_DISC:      core::ops::Range<usize> = 0..8;
const EA_EID:       core::ops::Range<usize> = 8..16;
const EA_AUTHORITY: core::ops::Range<usize> = 16..48;
const EA_MIN_LEN:   usize = 48;

// ── Raw byte offsets into VoterRegistryAccount (voter_registry, PROGRAMS.md) ─
const VR_DISC:      core::ops::Range<usize> = 0..8;
const VR_EID:       core::ops::Range<usize> = 8..16;
const VR_LEAF_CNT:  core::ops::Range<usize> = 48..56;
const VR_MIN_LEN:   usize = 56;

// ── init_tally (ix_tag = 3) ───────────────────────────────────────────────────
//
// One-time setup per election. Called by the authority before voting opens.
//
// Accounts: [authority (signer, writable), tally_account (writable PDA), system_program]
//
// Data (after tag):
//   [0..8]  election_id : u64
//   [8..16] lamports    : u64   (rent-exempt min for 1088 B)
//   [16]    bump        : u8
pub fn init_tally(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let [authority, tally_account, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !authority.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }
    if data.len() < 17 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let election_id = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let lamports    = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let bump        = data[16];

    if tally_account.data_len() != 0 {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    let eid_le   = election_id.to_le_bytes();
    let bump_arr = [bump];

    let expected = pubkey::create_program_address(
        &[b"tally", &eid_le, &bump_arr],
        program_id,
    )?;
    if tally_account.key() != &expected {
        return Err(ProgramError::InvalidAccountData);
    }

    let seeds = [
        Seed::from(b"tally" as &[u8]),
        Seed::from(eid_le.as_ref()),
        Seed::from(bump_arr.as_ref()),
    ];
    CreateAccount {
        from:     authority,
        to:       tally_account,
        lamports,
        space:    TallyAccount::LEN as u64,
        owner:    program_id,
    }
    .invoke_signed(&[Signer::from(&seeds)])?;

    let state = unsafe {
        TallyAccount::from_bytes_mut(tally_account.borrow_mut_data_unchecked())
    };
    state.discriminator     = TallyAccount::DISCRIMINATOR;
    state.election_id       = election_id;
    state.last_updated_slot = 0;
    state.total_votes       = 0;
    state.finalized         = 0;

    sol_log("tally_initialized");
    Ok(())
}

// ── accumulate_votes (ix_tag = 0) ─────────────────────────────────────────────
//
// Increments the counter shard for one ballot. Intended to be called via CPI
// from ballot::cast only — it has no independent authentication beyond the
// tally account ownership check. A future version should store the ballot
// program ID in TallyAccount and assert it here.
//
// Shard: counters[candidate_id * 4 + (state_id % 4)]
// Using (state_id % 4) distributes Nigeria's 36 states + FCT across 4 write
// buckets without needing 37 separate accounts.
//
// Accounts: [tally_account (writable PDA), clock_sysvar]
//
// Data (after tag):
//   [0..8]  election_id  : u64
//   [8]     candidate_id : u8
//   [9]     state_id     : u8
pub fn accumulate_votes(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let [tally_account, clock_sysvar] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if unsafe { tally_account.owner() } != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }

    const CLOCK_ID: Pubkey = pk!("SysvarC1ock11111111111111111111111111111111");
    if clock_sysvar.key() != &CLOCK_ID {
        return Err(ProgramError::InvalidAccountData);
    }

    if data.len() < 10 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let election_id  = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let candidate_id = data[8] as usize;
    let state_id     = data[9] as usize;

    if candidate_id >= COUNTERS_LEN / CANDIDATE_SHARDS {
        return Err(ProgramError::InvalidInstructionData);
    }

    let current_slot = {
        let cd = clock_sysvar.try_borrow_data()?;
        if cd.len() < 8 {
            return Err(ProgramError::InvalidAccountData);
        }
        u64::from_le_bytes(cd[0..8].try_into().unwrap())
    };

    let state = unsafe {
        TallyAccount::from_bytes_mut(tally_account.borrow_mut_data_unchecked())
    };

    if state.discriminator != TallyAccount::DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    if state.election_id != election_id {
        return Err(ProgramError::InvalidAccountData);
    }
    if state.finalized != 0 {
        return Err(ProgramError::InvalidAccountData); // tally is locked
    }

    let shard = candidate_id * CANDIDATE_SHARDS + (state_id % CANDIDATE_SHARDS);
    state.counters[shard]  += 1;
    state.total_votes      += 1;
    state.last_updated_slot = current_slot;

    Ok(())
}

// ── finalise_tally (ix_tag = 1) ───────────────────────────────────────────────
//
// Locks the TallyAccount after voting closes. Sets finalized = 1; further
// accumulate_votes calls are rejected. Authority is verified against
// election_account.authority (offset 16..48) — no separate authority field
// needed in TallyAccount.
//
// Accounts:
//   [0] authority        (signer)
//   [1] election_account (read-only PDA from election_registry)
//   [2] tally_account    (writable PDA)
//
// Data (after tag):
//   [0..8] election_id : u64
pub fn finalise_tally(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let [authority, election_account, tally_account] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if unsafe { tally_account.owner() } != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }
    if data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let election_id = u64::from_le_bytes(data[0..8].try_into().unwrap());

    // Verify authority key against election_account.authority (offset 16..48).
    {
        let ea = election_account.try_borrow_data()?;
        if ea.len() < EA_MIN_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        if &ea[EA_DISC] != b"election" {
            return Err(ProgramError::InvalidAccountData);
        }
        if u64::from_le_bytes(ea[EA_EID].try_into().unwrap()) != election_id {
            return Err(ProgramError::InvalidAccountData);
        }
        let ea_authority: &[u8; 32] = ea[EA_AUTHORITY].try_into().unwrap();
        if ea_authority != authority.key() {
            return Err(ProgramError::MissingRequiredSignature);
        }
    }

    let state = unsafe {
        TallyAccount::from_bytes_mut(tally_account.borrow_mut_data_unchecked())
    };

    if state.discriminator != TallyAccount::DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    if state.election_id != election_id {
        return Err(ProgramError::InvalidAccountData);
    }
    if state.finalized != 0 {
        return Err(ProgramError::AccountAlreadyInitialized); // already finalized
    }

    state.finalized = 1;
    sol_log("tally_finalized");
    Ok(())
}

// ── verify_tally (ix_tag = 2) ─────────────────────────────────────────────────
//
// Read-only consistency check surfaced to the aggregation server and dashboard.
// Returns Ok(()) if both invariants hold:
//   ① sum(counters[0..128]) == total_votes
//   ② total_votes <= voter_registry.leaf_count  (can't have more votes than registered voters)
//
// The aggregation server calls this before signing any broadcast aggregate.
// If it fails, something tampered with the counter outside the ballot CPI path.
//
// Accounts:
//   [0] tally_account    (read-only PDA)
//   [1] voter_registry   (read-only PDA from voter_registry)
//
// Data (after tag):
//   [0..8] election_id : u64
pub fn verify_tally(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let [tally_account, voter_registry] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if unsafe { tally_account.owner() } != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }
    if data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let election_id = u64::from_le_bytes(data[0..8].try_into().unwrap());

    // ① counter sum == total_votes
    let (total_votes, counter_sum) = {
        let ta = tally_account.try_borrow_data()?;
        if ta.len() < TallyAccount::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        let state = unsafe { TallyAccount::from_bytes(&ta) };
        if state.discriminator != TallyAccount::DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        if state.election_id != election_id {
            return Err(ProgramError::InvalidAccountData);
        }
        let sum: u64 = state.counters.iter().sum();
        (state.total_votes, sum)
    };

    if counter_sum != total_votes {
        sol_log("verify_tally: counter_sum mismatch");
        return Err(ProgramError::InvalidAccountData);
    }

    // ② total_votes <= registered voter count
    let leaf_count = {
        let vr = voter_registry.try_borrow_data()?;
        if vr.len() < VR_MIN_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        if &vr[VR_DISC] != b"voterreg" {
            return Err(ProgramError::InvalidAccountData);
        }
        if u64::from_le_bytes(vr[VR_EID].try_into().unwrap()) != election_id {
            return Err(ProgramError::InvalidAccountData);
        }
        u64::from_le_bytes(vr[VR_LEAF_CNT].try_into().unwrap())
    };

    if total_votes > leaf_count {
        sol_log("verify_tally: votes exceed registered count");
        return Err(ProgramError::InvalidAccountData);
    }

    sol_log("verify_tally: ok");
    Ok(())
}
