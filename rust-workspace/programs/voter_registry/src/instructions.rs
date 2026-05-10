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

use crate::{LeafAccount, VoterRegistryAccount, merkle};

// ── Offsets into ElectionAccount raw bytes (election_registry layout) ─────────
// Defined in PROGRAMS.md §ElectionAccount; duplicated here to avoid a
// cross-program crate dependency (program IDs change per deploy).
const EA_DISCRIMINATOR_RANGE: core::ops::Range<usize> = 0..8;
const EA_ELECTION_ID_RANGE: core::ops::Range<usize> = 8..16;
const EA_REG_CLOSE_RANGE: core::ops::Range<usize> = 88..96;
const EA_PHASE_OFFSET: usize = 112;
const EA_MIN_LEN: usize = 113; // need at least through phase byte

const PHASE_REG_OPEN: u8 = 1;
const ELECTION_DISCRIMINATOR: &[u8; 8] = b"election";

// ── init_voter_registry (ix_tag = 1) ─────────────────────────────────────────
//
// One-time setup per election. Called by the relayer before any voter
// registration opens. Creates the VoterRegistryAccount PDA and sets the
// Merkle root to the empty depth-28 tree root.
//
// Accounts: [relayer (signer), voter_registry (writable PDA), system_program]
//
// Data layout (after tag):
//   [0..8]  election_id : u64
//   [8..16] lamports    : u64   (rent-exempt min)
//   [16]    bump        : u8
pub fn init_voter_registry(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let [relayer, voter_registry, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !relayer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !relayer.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    if data.len() < 17 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let election_id = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let lamports    = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let bump        = data[16];

    // Reject double-init.
    if voter_registry.data_len() != 0 {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    let eid_le   = election_id.to_le_bytes();
    let bump_arr = [bump];
    let seeds = [
        Seed::from(b"voter_registry" as &[u8]),
        Seed::from(eid_le.as_ref()),
        Seed::from(bump_arr.as_ref()),
    ];

    // Verify the PDA key matches our derivation before paying CPI overhead.
    let expected = pubkey::create_program_address(
        &[b"voter_registry", &eid_le, &bump_arr],
        program_id,
    )?;
    if voter_registry.key() != &expected {
        return Err(ProgramError::InvalidAccountData);
    }

    CreateAccount {
        from:     relayer,
        to:       voter_registry,
        lamports,
        space:    VoterRegistryAccount::LEN as u64,
        owner:    program_id,
    }
    .invoke_signed(&[Signer::from(&seeds)])?;

    let state = unsafe {
        VoterRegistryAccount::from_bytes_mut(voter_registry.borrow_mut_data_unchecked())
    };
    state.discriminator   = VoterRegistryAccount::DISCRIMINATOR;
    state.election_id     = election_id;
    state.merkle_root     = merkle::empty_tree_root();
    state.leaf_count      = 0;
    state.tree_depth      = crate::TREE_DEPTH;
    state.nullifier_count = 0;

    sol_log("vr_initialized");
    Ok(())
}

// ── insert_commitment (ix_tag = 0) ────────────────────────────────────────────
//
// Appends one voter commitment to the on-chain leaf log.
// The off-chain SMT server maintains the Merkle root; the on-chain
// LeafAccount is the authoritative membership proof used by ballot::cast.
//
// On-chain checks:
//   ① election_account.phase == REG_OPEN
//   ② current_slot < registration_close_slot
//   ③ PDA uniqueness at leaf_count enforces append-only, no gaps
//
// Accounts:
//   [0] relayer           (signer, writable — pays leaf rent)
//   [1] election_account  (read-only PDA from election_registry)
//   [2] voter_registry    (writable PDA)
//   [3] leaf_account      (writable, new PDA — ["leaf", eid_le, leaf_count_le])
//   [4] clock_sysvar      (read-only)
//   [5] system_program
//
// Data layout (after tag byte, 49 bytes):
//   [0..8]   election_id   : u64
//   [8..40]  commitment    : [u8; 32]
//   [40..48] leaf_lamports : u64
//   [48]     leaf_bump     : u8
pub fn insert_commitment(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let [relayer, election_account, voter_registry, leaf_account, clock_sysvar, _system_program] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // ── basic account validation ─────────────────────────────────────────────

    if !relayer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !relayer.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }
    if unsafe { voter_registry.owner() } != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }

    const CLOCK_ID: Pubkey = pk!("SysvarC1ock11111111111111111111111111111111");
    if clock_sysvar.key() != &CLOCK_ID {
        return Err(ProgramError::InvalidAccountData);
    }

    // ── parse instruction data ───────────────────────────────────────────────

    const DATA_LEN: usize = 8 + 32 + 8 + 1; // = 49
    if data.len() < DATA_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }

    let election_id: u64   = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let commitment: [u8; 32] = data[8..40].try_into().unwrap();
    let leaf_lamports: u64  = u64::from_le_bytes(data[40..48].try_into().unwrap());
    let leaf_bump: u8       = data[48];

    // ── read clock slot ──────────────────────────────────────────────────────

    let current_slot = {
        let cd = clock_sysvar.try_borrow_data()?;
        if cd.len() < 8 {
            return Err(ProgramError::InvalidAccountData);
        }
        u64::from_le_bytes(cd[0..8].try_into().unwrap())
    };

    // ── election_account checks ① and ② ─────────────────────────────────────

    let (election_phase, registration_close_slot) = {
        let ea = election_account.try_borrow_data()?;
        if ea.len() < EA_MIN_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        if &ea[EA_DISCRIMINATOR_RANGE] != ELECTION_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        let eid_on_chain = u64::from_le_bytes(ea[EA_ELECTION_ID_RANGE].try_into().unwrap());
        if eid_on_chain != election_id {
            return Err(ProgramError::InvalidAccountData);
        }
        let reg_close = u64::from_le_bytes(ea[EA_REG_CLOSE_RANGE].try_into().unwrap());
        (ea[EA_PHASE_OFFSET], reg_close)
    };

    if election_phase != PHASE_REG_OPEN {
        return Err(ProgramError::InvalidInstructionData);
    }
    if current_slot >= registration_close_slot {
        return Err(ProgramError::InvalidInstructionData);
    }

    // ── read voter_registry: get leaf_index = current leaf_count ─────────────

    let leaf_index = {
        let vr = voter_registry.try_borrow_data()?;
        if vr.len() < VoterRegistryAccount::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        let state = unsafe { VoterRegistryAccount::from_bytes(&vr) };
        if state.discriminator != VoterRegistryAccount::DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        if state.election_id != election_id {
            return Err(ProgramError::InvalidAccountData);
        }
        state.leaf_count
    };

    // ── create leaf PDA via CPI ───────────────────────────────────────────────
    // PDA uniqueness enforces check ③: CreateAccount fails if the account
    // already exists, preventing double-insertion at the same index.

    let eid_le   = election_id.to_le_bytes();
    let idx_le   = leaf_index.to_le_bytes();
    let bump_arr = [leaf_bump];
    let leaf_seeds = [
        Seed::from(b"leaf" as &[u8]),
        Seed::from(eid_le.as_ref()),
        Seed::from(idx_le.as_ref()),
        Seed::from(bump_arr.as_ref()),
    ];

    CreateAccount {
        from:     relayer,
        to:       leaf_account,
        lamports: leaf_lamports,
        space:    LeafAccount::LEN as u64,
        owner:    program_id,
    }
    .invoke_signed(&[Signer::from(&leaf_seeds)])?;

    // ── write leaf account ────────────────────────────────────────────────────

    let leaf_state = unsafe {
        LeafAccount::from_bytes_mut(leaf_account.borrow_mut_data_unchecked())
    };
    leaf_state.discriminator = LeafAccount::DISCRIMINATOR;
    leaf_state.election_id   = election_id;
    leaf_state.index         = leaf_index;
    leaf_state.commitment    = commitment;

    // ── update voter_registry leaf_count ─────────────────────────────────────

    let vr_state = unsafe {
        VoterRegistryAccount::from_bytes_mut(voter_registry.borrow_mut_data_unchecked())
    };
    vr_state.leaf_count = leaf_index + 1;

    Ok(())
}
