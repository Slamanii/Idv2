use mollusk_svm::{result::Check, Mollusk};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    program_error::ProgramError,
    pubkey::Pubkey,
};

const PROG_NAME: &str = "tally";

fn program_id() -> Pubkey {
    Pubkey::new_unique()
}

fn mollusk(pid: &Pubkey) -> Mollusk {
    Mollusk::new(pid, PROG_NAME)
}

fn payer(lamports: u64) -> Account {
    Account { lamports, ..Default::default() }
}

fn tally_pda(pid: &Pubkey, eid: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"tally", &eid.to_le_bytes()], pid)
}

/// Build a TallyAccount byte buffer.
fn tally_bytes(eid: u64, total_votes: u64, finalized: u8) -> Vec<u8> {
    let mut data = vec![0u8; tally::TallyAccount::LEN];
    data[0..8].copy_from_slice(b"tallying");
    data[8..16].copy_from_slice(&eid.to_le_bytes());
    // last_updated_slot at 16..24 left zero
    data[24..32].copy_from_slice(&total_votes.to_le_bytes());
    // counters at 32..1056 left zero (all counters = 0)
    data[1056] = finalized;
    data
}

/// Build a TallyAccount with one shard incremented.
fn tally_bytes_with_vote(eid: u64, candidate_id: u8, state_id: u8) -> Vec<u8> {
    let mut data = tally_bytes(eid, 1, 0);
    let shard = candidate_id as usize * 4 + (state_id as usize % 4);
    let off = 32 + shard * 8;
    data[off..off + 8].copy_from_slice(&1u64.to_le_bytes());
    data
}

/// Build ElectionAccount bytes (minimum for finalise_tally authority check).
fn election_account_bytes(eid: u64, authority: &Pubkey) -> Vec<u8> {
    let mut data = vec![0u8; 200];
    data[0..8].copy_from_slice(b"election");
    data[8..16].copy_from_slice(&eid.to_le_bytes());
    data[16..48].copy_from_slice(authority.as_ref());
    data
}

/// Build VoterRegistryAccount bytes (minimum for verify_tally leaf_count check).
fn vr_bytes(eid: u64, leaf_count: u64) -> Vec<u8> {
    let mut data = vec![0u8; 64];
    data[0..8].copy_from_slice(b"voterreg");
    data[8..16].copy_from_slice(&eid.to_le_bytes());
    data[48..56].copy_from_slice(&leaf_count.to_le_bytes());
    data
}

// ── init_tally ────────────────────────────────────────────────────────────────

#[test]
fn init_tally_happy() {
    let pid = program_id();
    let m = mollusk(&pid);

    let authority = Pubkey::new_unique();
    let eid: u64 = 1;
    let (tally_key, bump) = tally_pda(&pid, eid);
    let (sys_id, sys_acc) = mollusk_svm::program::keyed_account_for_system_program();

    let mut data = vec![3u8]; // ix_tag = 3
    data.extend_from_slice(&eid.to_le_bytes());
    data.extend_from_slice(&10_000_000u64.to_le_bytes());
    data.push(bump);

    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(authority, true),
            AccountMeta::new(tally_key, false),
            AccountMeta::new_readonly(sys_id, false),
        ],
        data,
    };

    let result = m.process_and_validate_instruction(
        &ix,
        &[
            (authority, payer(100_000_000)),
            (tally_key, Account::default()),
            (sys_id, sys_acc),
        ],
        &[Check::success()],
    );

    let acc = result.resulting_accounts.iter()
        .find(|(k, _)| k == &tally_key).map(|(_, v)| v).unwrap();
    assert_eq!(&acc.data[0..8], b"tallying");
    assert_eq!(u64::from_le_bytes(acc.data[8..16].try_into().unwrap()), eid);
    assert_eq!(acc.data[1056], 0u8); // finalized = 0
}

#[test]
fn init_tally_already_initialized() {
    let pid = program_id();
    let m = mollusk(&pid);

    let authority = Pubkey::new_unique();
    let eid: u64 = 2;
    let (tally_key, bump) = tally_pda(&pid, eid);
    let (sys_id, sys_acc) = mollusk_svm::program::keyed_account_for_system_program();

    let mut data = vec![3u8];
    data.extend_from_slice(&eid.to_le_bytes());
    data.extend_from_slice(&10_000_000u64.to_le_bytes());
    data.push(bump);

    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(authority, true),
            AccountMeta::new(tally_key, false),
            AccountMeta::new_readonly(sys_id, false),
        ],
        data,
    };

    let existing = Account {
        lamports: 10_000_000,
        data: vec![0u8; tally::TallyAccount::LEN],
        owner: pid,
        ..Default::default()
    };

    m.process_and_validate_instruction(
        &ix,
        &[
            (authority, payer(100_000_000)),
            (tally_key, existing),
            (sys_id, sys_acc),
        ],
        &[Check::err(ProgramError::AccountAlreadyInitialized)],
    );
}

// ── accumulate_votes ──────────────────────────────────────────────────────────

#[test]
fn accumulate_votes_increments_shard() {
    let pid = program_id();
    let m = mollusk(&pid);

    let eid: u64 = 10;
    let (tally_key, _) = tally_pda(&pid, eid);
    let (clock_id, mut clock_acc) = m.sysvars.keyed_account_for_clock_sysvar();
    clock_acc.data[0..8].copy_from_slice(&100u64.to_le_bytes());

    let tally_data = tally_bytes(eid, 0, 0);
    let tally_acc = Account { lamports: 10_000_000, data: tally_data, owner: pid, ..Default::default() };

    let mut data = vec![0u8]; // ix_tag = 0
    data.extend_from_slice(&eid.to_le_bytes());
    data.push(3u8); // candidate_id = 3
    data.push(5u8); // state_id = 5

    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(tally_key, false),
            AccountMeta::new_readonly(clock_id, false),
        ],
        data,
    };

    let result = m.process_and_validate_instruction(
        &ix,
        &[(tally_key, tally_acc), (clock_id, clock_acc)],
        &[Check::success()],
    );

    let acc = result.resulting_accounts.iter()
        .find(|(k, _)| k == &tally_key).map(|(_, v)| v).unwrap();

    // shard = 3 * 4 + (5 % 4) = 13
    let shard_off = 32 + 13 * 8;
    let shard_val = u64::from_le_bytes(acc.data[shard_off..shard_off + 8].try_into().unwrap());
    assert_eq!(shard_val, 1u64);

    let total = u64::from_le_bytes(acc.data[24..32].try_into().unwrap());
    assert_eq!(total, 1u64);
}

#[test]
fn accumulate_votes_shard_routing() {
    // Same candidate, two different state_ids that map to different shards.
    let pid = program_id();
    let m = mollusk(&pid);

    let eid: u64 = 11;
    let (tally_key, _) = tally_pda(&pid, eid);
    let (clock_id, mut clock_acc) = m.sysvars.keyed_account_for_clock_sysvar();
    clock_acc.data[0..8].copy_from_slice(&100u64.to_le_bytes());

    let tally_data = tally_bytes(eid, 0, 0);
    let tally_acc = Account { lamports: 10_000_000, data: tally_data, owner: pid, ..Default::default() };

    // Vote for candidate 0, state_id 0 → shard 0
    let mut data = vec![0u8];
    data.extend_from_slice(&eid.to_le_bytes());
    data.push(0u8); // candidate_id
    data.push(0u8); // state_id → shard 0*4+0 = 0

    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(tally_key, false),
            AccountMeta::new_readonly(clock_id, false),
        ],
        data,
    };

    let result = m.process_and_validate_instruction(
        &ix,
        &[(tally_key, tally_acc), (clock_id, clock_acc)],
        &[Check::success()],
    );

    let acc = result.resulting_accounts.iter()
        .find(|(k, _)| k == &tally_key).map(|(_, v)| v).unwrap();
    let shard0 = u64::from_le_bytes(acc.data[32..40].try_into().unwrap()); // shard 0
    assert_eq!(shard0, 1u64);
    let shard1 = u64::from_le_bytes(acc.data[40..48].try_into().unwrap()); // shard 1
    assert_eq!(shard1, 0u64);
}

#[test]
fn accumulate_votes_finalized_rejected() {
    let pid = program_id();
    let m = mollusk(&pid);

    let eid: u64 = 12;
    let (tally_key, _) = tally_pda(&pid, eid);
    let (clock_id, mut clock_acc) = m.sysvars.keyed_account_for_clock_sysvar();
    clock_acc.data[0..8].copy_from_slice(&100u64.to_le_bytes());

    // finalized = 1 → must reject
    let tally_data = tally_bytes(eid, 0, 1);
    let tally_acc = Account { lamports: 10_000_000, data: tally_data, owner: pid, ..Default::default() };

    let mut data = vec![0u8];
    data.extend_from_slice(&eid.to_le_bytes());
    data.push(0u8);
    data.push(0u8);

    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(tally_key, false),
            AccountMeta::new_readonly(clock_id, false),
        ],
        data,
    };

    m.process_and_validate_instruction(
        &ix,
        &[(tally_key, tally_acc), (clock_id, clock_acc)],
        &[Check::err(ProgramError::InvalidAccountData)],
    );
}

// ── finalise_tally ────────────────────────────────────────────────────────────

#[test]
fn finalise_tally_happy() {
    let pid = program_id();
    let m = mollusk(&pid);

    let authority = Pubkey::new_unique();
    let eid: u64 = 20;
    let (tally_key, _) = tally_pda(&pid, eid);

    let election_key = Pubkey::new_unique();
    let ea_data = election_account_bytes(eid, &authority);
    let ea_acc = Account { lamports: 5_000_000, data: ea_data, ..Default::default() };

    let tally_data = tally_bytes(eid, 5, 0);
    let tally_acc = Account { lamports: 10_000_000, data: tally_data, owner: pid, ..Default::default() };

    let mut data = vec![1u8]; // ix_tag = 1
    data.extend_from_slice(&eid.to_le_bytes());

    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(authority, true),
            AccountMeta::new_readonly(election_key, false),
            AccountMeta::new(tally_key, false),
        ],
        data,
    };

    let result = m.process_and_validate_instruction(
        &ix,
        &[
            (authority, payer(10_000_000)),
            (election_key, ea_acc),
            (tally_key, tally_acc),
        ],
        &[Check::success()],
    );

    let acc = result.resulting_accounts.iter()
        .find(|(k, _)| k == &tally_key).map(|(_, v)| v).unwrap();
    assert_eq!(acc.data[1056], 1u8); // finalized
}

#[test]
fn finalise_tally_already_finalized() {
    let pid = program_id();
    let m = mollusk(&pid);

    let authority = Pubkey::new_unique();
    let eid: u64 = 21;
    let (tally_key, _) = tally_pda(&pid, eid);

    let election_key = Pubkey::new_unique();
    let ea_data = election_account_bytes(eid, &authority);
    let ea_acc = Account { lamports: 5_000_000, data: ea_data, ..Default::default() };

    // Already finalized.
    let tally_data = tally_bytes(eid, 0, 1);
    let tally_acc = Account { lamports: 10_000_000, data: tally_data, owner: pid, ..Default::default() };

    let mut data = vec![1u8];
    data.extend_from_slice(&eid.to_le_bytes());

    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(authority, true),
            AccountMeta::new_readonly(election_key, false),
            AccountMeta::new(tally_key, false),
        ],
        data,
    };

    m.process_and_validate_instruction(
        &ix,
        &[
            (authority, payer(10_000_000)),
            (election_key, ea_acc),
            (tally_key, tally_acc),
        ],
        &[Check::err(ProgramError::AccountAlreadyInitialized)],
    );
}

// ── verify_tally ──────────────────────────────────────────────────────────────

#[test]
fn verify_tally_consistent() {
    let pid = program_id();
    let m = mollusk(&pid);

    let eid: u64 = 30;
    let (tally_key, _) = tally_pda(&pid, eid);
    let vr_key = Pubkey::new_unique();

    // 1 vote for candidate 2, state 5.
    let tally_data = tally_bytes_with_vote(eid, 2, 5);
    let tally_acc = Account { lamports: 10_000_000, data: tally_data, owner: pid, ..Default::default() };

    // 10 registered voters ≥ 1 vote.
    let vr_data = vr_bytes(eid, 10);
    let vr_acc = Account { lamports: 5_000_000, data: vr_data, ..Default::default() };

    let mut data = vec![2u8]; // ix_tag = 2
    data.extend_from_slice(&eid.to_le_bytes());

    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new_readonly(tally_key, false),
            AccountMeta::new_readonly(vr_key, false),
        ],
        data,
    };

    m.process_and_validate_instruction(
        &ix,
        &[(tally_key, tally_acc), (vr_key, vr_acc)],
        &[Check::success()],
    );
}

#[test]
fn verify_tally_counter_mismatch() {
    let pid = program_id();
    let m = mollusk(&pid);

    let eid: u64 = 31;
    let (tally_key, _) = tally_pda(&pid, eid);
    let vr_key = Pubkey::new_unique();

    // total_votes=5 but all counters are zero → mismatch.
    let tally_data = tally_bytes(eid, 5, 0);
    let tally_acc = Account { lamports: 10_000_000, data: tally_data, owner: pid, ..Default::default() };

    let vr_data = vr_bytes(eid, 10);
    let vr_acc = Account { lamports: 5_000_000, data: vr_data, ..Default::default() };

    let mut data = vec![2u8];
    data.extend_from_slice(&eid.to_le_bytes());

    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new_readonly(tally_key, false),
            AccountMeta::new_readonly(vr_key, false),
        ],
        data,
    };

    m.process_and_validate_instruction(
        &ix,
        &[(tally_key, tally_acc), (vr_key, vr_acc)],
        &[Check::err(ProgramError::InvalidAccountData)],
    );
}

#[test]
fn verify_tally_votes_exceed_registered() {
    let pid = program_id();
    let m = mollusk(&pid);

    let eid: u64 = 32;
    let (tally_key, _) = tally_pda(&pid, eid);
    let vr_key = Pubkey::new_unique();

    // 3 votes for candidate 0, state 0 (shard 0), total_votes = 3
    let mut tally_data = tally_bytes(eid, 3, 0);
    tally_data[32..40].copy_from_slice(&3u64.to_le_bytes()); // shard 0 = 3

    let tally_acc = Account { lamports: 10_000_000, data: tally_data, owner: pid, ..Default::default() };

    // Only 2 registered voters — votes (3) > leaf_count (2).
    let vr_data = vr_bytes(eid, 2);
    let vr_acc = Account { lamports: 5_000_000, data: vr_data, ..Default::default() };

    let mut data = vec![2u8];
    data.extend_from_slice(&eid.to_le_bytes());

    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new_readonly(tally_key, false),
            AccountMeta::new_readonly(vr_key, false),
        ],
        data,
    };

    m.process_and_validate_instruction(
        &ix,
        &[(tally_key, tally_acc), (vr_key, vr_acc)],
        &[Check::err(ProgramError::InvalidAccountData)],
    );
}
