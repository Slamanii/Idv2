use mollusk_svm::{result::Check, Mollusk};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    program_error::ProgramError,
    pubkey::Pubkey,
};
use ballot::merkle;

const PROG_NAME: &str = "ballot";
const TAL_NAME:  &str = "tally";

fn program_id() -> Pubkey { Pubkey::new_unique() }

fn payer(lamports: u64) -> Account {
    Account { lamports, ..Default::default() }
}

fn ballot_pda(pid: &Pubkey, eid: u64, nullifier: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"ballot", &eid.to_le_bytes(), nullifier.as_ref()], pid)
}

fn nullifier_pda(pid: &Pubkey, eid: u64, nullifier: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"nullifier", &eid.to_le_bytes(), nullifier.as_ref()], pid)
}

fn tally_pda(tal_pid: &Pubkey, eid: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"tally", &eid.to_le_bytes()], tal_pid)
}

/// Pre-initialized TallyAccount bytes (finalized=0, all counters zero).
fn tally_init_bytes(tal_pid: &Pubkey, eid: u64) -> Vec<u8> {
    let mut d = vec![0u8; tally::TallyAccount::LEN];
    d[0..8].copy_from_slice(b"tallying");
    d[8..16].copy_from_slice(&eid.to_le_bytes());
    let _ = tal_pid;
    d
}

fn election_account_bytes(eid: u64, vote_close: u64, phase: u8, candidate_count: u8) -> Vec<u8> {
    let mut data = vec![0u8; 200];
    data[0..8].copy_from_slice(b"election");
    data[8..16].copy_from_slice(&eid.to_le_bytes());
    data[104..112].copy_from_slice(&vote_close.to_le_bytes());
    data[112] = phase;
    data[113] = candidate_count;
    data
}

fn vr_bytes(eid: u64, root: [u8; 32]) -> Vec<u8> {
    let mut data = vec![0u8; 64];
    data[0..8].copy_from_slice(b"voterreg");
    data[8..16].copy_from_slice(&eid.to_le_bytes());
    data[16..48].copy_from_slice(&root);
    data
}

fn empty_path_flat() -> Vec<u8> {
    let sibs = merkle::empty_path_siblings();
    let mut flat = vec![0u8; merkle::DEPTH * 32];
    for (i, s) in sibs.iter().enumerate() {
        flat[i * 32..(i + 1) * 32].copy_from_slice(s);
    }
    flat
}

fn root_after_insert(commitment: &[u8; 32]) -> [u8; 32] {
    let leaf_val = merkle::leaf_hash(commitment);
    let flat = empty_path_flat();
    merkle::compute_root_from_path(&leaf_val, &flat, 0)
}

#[allow(clippy::too_many_arguments)]
fn cast_data(
    eid: u64,
    nullifier: [u8; 32],
    commitment: [u8; 32],
    path_flat: &[u8],
    path_indices: u32,
    candidate_id: u8,
    state_id: u8,
    lga_id: u16,
    ballot_lamps: u64,
    null_lamps: u64,
    ballot_bump: u8,
    null_bump: u8,
) -> Vec<u8> {
    let mut d = vec![0u8];
    d.extend_from_slice(&eid.to_le_bytes());
    d.extend_from_slice(&nullifier);
    d.extend_from_slice(&commitment);
    d.extend_from_slice(path_flat);
    d.extend_from_slice(&path_indices.to_le_bytes());
    d.push(candidate_id);
    d.push(state_id);
    d.extend_from_slice(&lga_id.to_le_bytes());
    d.extend_from_slice(&ballot_lamps.to_le_bytes());
    d.extend_from_slice(&null_lamps.to_le_bytes());
    d.push(ballot_bump);
    d.push(null_bump);
    d
}

// ── cast — happy path ─────────────────────────────────────────────────────────
// Requires both ballot.so and tally.so. Tally is loaded via add_program so the
// accumulate_votes CPI actually executes and increments the counter shard.

#[test]
fn cast_happy() {
    let pid     = program_id();
    let tal_pid = Pubkey::new_unique();

    let mut m = Mollusk::new(&pid, PROG_NAME);
    m.add_program(&tal_pid, TAL_NAME, &mollusk_svm::program::loader_keys::LOADER_V3);

    let relayer    = Pubkey::new_unique();
    let eid: u64   = 1;
    let nullifier  = [11u8; 32];
    let commitment = [22u8; 32];

    let (ballot_key, ballot_bump) = ballot_pda(&pid, eid, &nullifier);
    let (null_key,   null_bump)   = nullifier_pda(&pid, eid, &nullifier);
    let (tally_key,  _)           = tally_pda(&tal_pid, eid);
    let (clock_id, mut clock_acc) = m.sysvars.keyed_account_for_clock_sysvar();
    clock_acc.data[0..8].copy_from_slice(&50u64.to_le_bytes()); // slot 50 < vote_close 400
    let (sys_id, sys_acc) = mollusk_svm::program::keyed_account_for_system_program();

    let election_key = Pubkey::new_unique();
    let ea_acc = Account {
        lamports: 5_000_000,
        data: election_account_bytes(eid, 400, 3, 5),
        ..Default::default()
    };

    let vr_key = Pubkey::new_unique();
    let vr_acc = Account {
        lamports: 5_000_000,
        data: vr_bytes(eid, root_after_insert(&commitment)),
        ..Default::default()
    };

    let tally_acc = Account {
        lamports: 10_000_000,
        data: tally_init_bytes(&tal_pid, eid),
        owner: tal_pid,
        ..Default::default()
    };
    let tal_program_acc = mollusk_svm::program::create_program_account_loader_v3(&tal_pid);

    let path_flat = empty_path_flat();
    let data = cast_data(
        eid, nullifier, commitment, &path_flat, 0,
        2, 1, 101, 2_000_000, 1_000_000, ballot_bump, null_bump,
    );

    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(relayer, true),
            AccountMeta::new_readonly(election_key, false),
            AccountMeta::new_readonly(vr_key, false),
            AccountMeta::new(ballot_key, false),
            AccountMeta::new(null_key, false),
            AccountMeta::new_readonly(clock_id, false),
            AccountMeta::new_readonly(sys_id, false),
            AccountMeta::new(tally_key, false),
            AccountMeta::new_readonly(tal_pid, false),
        ],
        data,
    };

    let result = m.process_and_validate_instruction(
        &ix,
        &[
            (relayer,      payer(100_000_000)),
            (election_key, ea_acc),
            (vr_key,       vr_acc),
            (ballot_key,   Account::default()),
            (null_key,     Account::default()),
            (clock_id,     clock_acc),
            (sys_id,       sys_acc),
            (tally_key,    tally_acc),
            (tal_pid,      tal_program_acc),
        ],
        &[Check::success()],
    );

    // Ballot written: discriminator + candidate_id at byte 49
    let ballot_out = result.resulting_accounts.iter()
        .find(|(k, _)| k == &ballot_key).map(|(_, v)| v).unwrap();
    assert_eq!(&ballot_out.data[0..8], b"ballot\0\0");
    assert_eq!(ballot_out.data[49], 2u8); // candidate_id

    // Tally counter shard = 2*4 + (1%4) = 9 should be 1
    let tally_out = result.resulting_accounts.iter()
        .find(|(k, _)| k == &tally_key).map(|(_, v)| v).unwrap();
    let shard_off = 32 + 9 * 8; // counters base=32, shard 9
    let shard_val = u64::from_le_bytes(tally_out.data[shard_off..shard_off + 8].try_into().unwrap());
    assert_eq!(shard_val, 1u64);
    assert_eq!(u64::from_le_bytes(tally_out.data[24..32].try_into().unwrap()), 1u64); // total_votes
}

// ── Negative tests — tally CPI is never reached; pass dummy tally accounts ───

fn dummy_tally_accounts() -> (Pubkey, Account, Pubkey, Account) {
    let tally_key = Pubkey::new_unique();
    let tal_pid   = Pubkey::new_unique();
    (tally_key, Account::default(), tal_pid, Account::default())
}

// ── cast — duplicate nullifier ────────────────────────────────────────────────

#[test]
fn cast_duplicate_nullifier() {
    let pid = program_id();
    let m = Mollusk::new(&pid, PROG_NAME);

    let relayer    = Pubkey::new_unique();
    let eid: u64   = 2;
    let nullifier  = [33u8; 32];
    let commitment = [44u8; 32];

    let (ballot_key, ballot_bump) = ballot_pda(&pid, eid, &nullifier);
    let (null_key,   null_bump)   = nullifier_pda(&pid, eid, &nullifier);
    let (clock_id, mut clock_acc) = m.sysvars.keyed_account_for_clock_sysvar();
    clock_acc.data[0..8].copy_from_slice(&50u64.to_le_bytes());
    let (sys_id, sys_acc)         = mollusk_svm::program::keyed_account_for_system_program();
    let (tally_key, tally_acc, tal_pid, tal_acc) = dummy_tally_accounts();

    let election_key = Pubkey::new_unique();
    let ea_acc = Account { lamports: 5_000_000, data: election_account_bytes(eid, 400, 3, 5), ..Default::default() };
    let vr_key = Pubkey::new_unique();
    let vr_acc = Account { lamports: 5_000_000, data: vr_bytes(eid, root_after_insert(&commitment)), ..Default::default() };

    let existing_null = Account { lamports: 1_000_000, data: vec![1u8], owner: pid, ..Default::default() };

    let data = cast_data(eid, nullifier, commitment, &empty_path_flat(), 0, 2, 1, 101, 2_000_000, 1_000_000, ballot_bump, null_bump);
    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(relayer, true),
            AccountMeta::new_readonly(election_key, false),
            AccountMeta::new_readonly(vr_key, false),
            AccountMeta::new(ballot_key, false),
            AccountMeta::new(null_key, false),
            AccountMeta::new_readonly(clock_id, false),
            AccountMeta::new_readonly(sys_id, false),
            AccountMeta::new(tally_key, false),
            AccountMeta::new_readonly(tal_pid, false),
        ],
        data,
    };

    m.process_and_validate_instruction(
        &ix,
        &[
            (relayer, payer(100_000_000)),
            (election_key, ea_acc),
            (vr_key, vr_acc),
            (ballot_key, Account::default()),
            (null_key, existing_null),
            (clock_id, clock_acc),
            (sys_id, sys_acc),
            (tally_key, tally_acc),
            (tal_pid, tal_acc),
        ],
        &[Check::err(ProgramError::AccountAlreadyInitialized)],
    );
}

// ── cast — wrong phase ────────────────────────────────────────────────────────

#[test]
fn cast_wrong_phase() {
    let pid = program_id();
    let m = Mollusk::new(&pid, PROG_NAME);

    let relayer    = Pubkey::new_unique();
    let eid: u64   = 3;
    let nullifier  = [55u8; 32];
    let commitment = [66u8; 32];

    let (ballot_key, ballot_bump) = ballot_pda(&pid, eid, &nullifier);
    let (null_key,   null_bump)   = nullifier_pda(&pid, eid, &nullifier);
    let (clock_id, mut clock_acc) = m.sysvars.keyed_account_for_clock_sysvar();
    clock_acc.data[0..8].copy_from_slice(&50u64.to_le_bytes());
    let (sys_id, sys_acc)         = mollusk_svm::program::keyed_account_for_system_program();
    let (tally_key, tally_acc, tal_pid, tal_acc) = dummy_tally_accounts();

    let election_key = Pubkey::new_unique();
    // phase=REG_OPEN(1) — fails before CPI
    let ea_acc = Account { lamports: 5_000_000, data: election_account_bytes(eid, 400, 1, 5), ..Default::default() };
    let vr_key = Pubkey::new_unique();
    let vr_acc = Account { lamports: 5_000_000, data: vr_bytes(eid, root_after_insert(&commitment)), ..Default::default() };

    let data = cast_data(eid, nullifier, commitment, &empty_path_flat(), 0, 2, 1, 101, 2_000_000, 1_000_000, ballot_bump, null_bump);
    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(relayer, true),
            AccountMeta::new_readonly(election_key, false),
            AccountMeta::new_readonly(vr_key, false),
            AccountMeta::new(ballot_key, false),
            AccountMeta::new(null_key, false),
            AccountMeta::new_readonly(clock_id, false),
            AccountMeta::new_readonly(sys_id, false),
            AccountMeta::new(tally_key, false),
            AccountMeta::new_readonly(tal_pid, false),
        ],
        data,
    };

    m.process_and_validate_instruction(
        &ix,
        &[
            (relayer, payer(100_000_000)),
            (election_key, ea_acc),
            (vr_key, vr_acc),
            (ballot_key, Account::default()),
            (null_key, Account::default()),
            (clock_id, clock_acc),
            (sys_id, sys_acc),
            (tally_key, tally_acc),
            (tal_pid, tal_acc),
        ],
        &[Check::err(ProgramError::InvalidInstructionData)],
    );
}

// ── cast — bad Merkle proof ───────────────────────────────────────────────────

#[test]
fn cast_bad_merkle_proof() {
    let pid = program_id();
    let m = Mollusk::new(&pid, PROG_NAME);

    let relayer    = Pubkey::new_unique();
    let eid: u64   = 4;
    let nullifier  = [77u8; 32];
    let commitment = [88u8; 32];

    let (ballot_key, ballot_bump) = ballot_pda(&pid, eid, &nullifier);
    let (null_key,   null_bump)   = nullifier_pda(&pid, eid, &nullifier);
    let (clock_id, mut clock_acc) = m.sysvars.keyed_account_for_clock_sysvar();
    clock_acc.data[0..8].copy_from_slice(&50u64.to_le_bytes());
    let (sys_id, sys_acc)         = mollusk_svm::program::keyed_account_for_system_program();
    let (tally_key, tally_acc, tal_pid, tal_acc) = dummy_tally_accounts();

    let election_key = Pubkey::new_unique();
    let ea_acc = Account { lamports: 5_000_000, data: election_account_bytes(eid, 400, 3, 5), ..Default::default() };
    let vr_key = Pubkey::new_unique();
    // Stored root is correct for commitment but path is all-zeros — mismatch.
    let vr_acc = Account { lamports: 5_000_000, data: vr_bytes(eid, root_after_insert(&commitment)), ..Default::default() };

    let bad_path = vec![0u8; merkle::DEPTH * 32];
    let data = cast_data(eid, nullifier, commitment, &bad_path, 0, 2, 1, 101, 2_000_000, 1_000_000, ballot_bump, null_bump);
    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(relayer, true),
            AccountMeta::new_readonly(election_key, false),
            AccountMeta::new_readonly(vr_key, false),
            AccountMeta::new(ballot_key, false),
            AccountMeta::new(null_key, false),
            AccountMeta::new_readonly(clock_id, false),
            AccountMeta::new_readonly(sys_id, false),
            AccountMeta::new(tally_key, false),
            AccountMeta::new_readonly(tal_pid, false),
        ],
        data,
    };

    m.process_and_validate_instruction(
        &ix,
        &[
            (relayer, payer(100_000_000)),
            (election_key, ea_acc),
            (vr_key, vr_acc),
            (ballot_key, Account::default()),
            (null_key, Account::default()),
            (clock_id, clock_acc),
            (sys_id, sys_acc),
            (tally_key, tally_acc),
            (tal_pid, tal_acc),
        ],
        &[Check::err(ProgramError::InvalidAccountData)],
    );
}

// ── cast — voting window closed ───────────────────────────────────────────────

#[test]
fn cast_voting_window_closed() {
    let pid = program_id();
    let m = Mollusk::new(&pid, PROG_NAME);

    let relayer    = Pubkey::new_unique();
    let eid: u64   = 5;
    let nullifier  = [99u8; 32];
    let commitment = [100u8; 32];

    let (ballot_key, ballot_bump) = ballot_pda(&pid, eid, &nullifier);
    let (null_key,   null_bump)   = nullifier_pda(&pid, eid, &nullifier);
    let (clock_id, mut clock_acc) = m.sysvars.keyed_account_for_clock_sysvar();
    clock_acc.data[0..8].copy_from_slice(&401u64.to_le_bytes()); // slot 401 >= vote_close 400
    let (sys_id, sys_acc)         = mollusk_svm::program::keyed_account_for_system_program();
    let (tally_key, tally_acc, tal_pid, tal_acc) = dummy_tally_accounts();

    let election_key = Pubkey::new_unique();
    let ea_acc = Account { lamports: 5_000_000, data: election_account_bytes(eid, 400, 3, 5), ..Default::default() };
    let vr_key = Pubkey::new_unique();
    let vr_acc = Account { lamports: 5_000_000, data: vr_bytes(eid, root_after_insert(&commitment)), ..Default::default() };

    let data = cast_data(eid, nullifier, commitment, &empty_path_flat(), 0, 2, 1, 101, 2_000_000, 1_000_000, ballot_bump, null_bump);
    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(relayer, true),
            AccountMeta::new_readonly(election_key, false),
            AccountMeta::new_readonly(vr_key, false),
            AccountMeta::new(ballot_key, false),
            AccountMeta::new(null_key, false),
            AccountMeta::new_readonly(clock_id, false),
            AccountMeta::new_readonly(sys_id, false),
            AccountMeta::new(tally_key, false),
            AccountMeta::new_readonly(tal_pid, false),
        ],
        data,
    };

    m.process_and_validate_instruction(
        &ix,
        &[
            (relayer, payer(100_000_000)),
            (election_key, ea_acc),
            (vr_key, vr_acc),
            (ballot_key, Account::default()),
            (null_key, Account::default()),
            (clock_id, clock_acc),
            (sys_id, sys_acc),
            (tally_key, tally_acc),
            (tal_pid, tal_acc),
        ],
        &[Check::err(ProgramError::InvalidInstructionData)],
    );
}

// ── cast — invalid candidate id ───────────────────────────────────────────────

#[test]
fn cast_invalid_candidate() {
    let pid = program_id();
    let m = Mollusk::new(&pid, PROG_NAME);

    let relayer    = Pubkey::new_unique();
    let eid: u64   = 6;
    let nullifier  = [101u8; 32];
    let commitment = [102u8; 32];

    let (ballot_key, ballot_bump) = ballot_pda(&pid, eid, &nullifier);
    let (null_key,   null_bump)   = nullifier_pda(&pid, eid, &nullifier);
    let (clock_id, mut clock_acc) = m.sysvars.keyed_account_for_clock_sysvar();
    clock_acc.data[0..8].copy_from_slice(&50u64.to_le_bytes());
    let (sys_id, sys_acc)         = mollusk_svm::program::keyed_account_for_system_program();
    let (tally_key, tally_acc, tal_pid, tal_acc) = dummy_tally_accounts();

    let election_key = Pubkey::new_unique();
    // Only 2 candidates, candidate_id=5 out of range — fails before CPI
    let ea_acc = Account { lamports: 5_000_000, data: election_account_bytes(eid, 400, 3, 2), ..Default::default() };
    let vr_key = Pubkey::new_unique();
    let vr_acc = Account { lamports: 5_000_000, data: vr_bytes(eid, root_after_insert(&commitment)), ..Default::default() };

    let data = cast_data(eid, nullifier, commitment, &empty_path_flat(), 0, 5, 1, 101, 2_000_000, 1_000_000, ballot_bump, null_bump);
    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(relayer, true),
            AccountMeta::new_readonly(election_key, false),
            AccountMeta::new_readonly(vr_key, false),
            AccountMeta::new(ballot_key, false),
            AccountMeta::new(null_key, false),
            AccountMeta::new_readonly(clock_id, false),
            AccountMeta::new_readonly(sys_id, false),
            AccountMeta::new(tally_key, false),
            AccountMeta::new_readonly(tal_pid, false),
        ],
        data,
    };

    m.process_and_validate_instruction(
        &ix,
        &[
            (relayer, payer(100_000_000)),
            (election_key, ea_acc),
            (vr_key, vr_acc),
            (ballot_key, Account::default()),
            (null_key, Account::default()),
            (clock_id, clock_acc),
            (sys_id, sys_acc),
            (tally_key, tally_acc),
            (tal_pid, tal_acc),
        ],
        &[Check::err(ProgramError::InvalidInstructionData)],
    );
}
