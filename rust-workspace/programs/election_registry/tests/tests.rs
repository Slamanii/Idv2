use mollusk_svm::{result::Check, Mollusk};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    program_error::ProgramError,
    pubkey::Pubkey,
};

const PROG_NAME: &str = "election_registry";

fn program_id() -> Pubkey {
    Pubkey::new_unique()
}

fn mollusk(pid: &Pubkey) -> Mollusk {
    Mollusk::new(pid, PROG_NAME)
}

fn payer(lamports: u64) -> Account {
    Account { lamports, ..Default::default() }
}

fn election_pda(pid: &Pubkey, eid: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"election", &eid.to_le_bytes()], pid)
}

fn create_election_data(
    eid: u64,
    reg_open: u64,
    reg_close: u64,
    vote_open: u64,
    vote_close: u64,
    agg_key: [u8; 32],
    lamports: u64,
    bump: u8,
) -> Vec<u8> {
    let mut d = vec![0u8];
    d.extend_from_slice(&eid.to_le_bytes());
    d.extend_from_slice(&reg_open.to_le_bytes());
    d.extend_from_slice(&reg_close.to_le_bytes());
    d.extend_from_slice(&vote_open.to_le_bytes());
    d.extend_from_slice(&vote_close.to_le_bytes());
    d.extend_from_slice(&agg_key);
    d.extend_from_slice(&lamports.to_le_bytes());
    d.push(bump);
    d
}

fn set_candidates_data(eid: u64, count: u8) -> Vec<u8> {
    let mut d = vec![1u8];
    d.extend_from_slice(&eid.to_le_bytes());
    d.push(count);
    for i in 0..count as usize {
        d.push(i as u8);
        d.extend_from_slice(&[0u8; 32]);
        d.extend_from_slice(&[0u8; 15]);
    }
    d
}

/// Build minimal initialized ElectionAccount bytes.
fn election_account_bytes(
    pid: &Pubkey,
    eid: u64,
    authority: &Pubkey,
    reg_open: u64,
    reg_close: u64,
    vote_open: u64,
    vote_close: u64,
    phase: u8,
    candidate_count: u8,
) -> Vec<u8> {
    let mut data = vec![0u8; election_registry::ELECTION_ACCOUNT_SIZE];
    data[0..8].copy_from_slice(b"election");
    data[8..16].copy_from_slice(&eid.to_le_bytes());
    data[16..48].copy_from_slice(authority.as_ref());
    // agg_key at 48..80 left zero
    data[80..88].copy_from_slice(&reg_open.to_le_bytes());
    data[88..96].copy_from_slice(&reg_close.to_le_bytes());
    data[96..104].copy_from_slice(&vote_open.to_le_bytes());
    data[104..112].copy_from_slice(&vote_close.to_le_bytes());
    data[112] = phase;
    data[113] = candidate_count;
    let _ = pid;
    data
}

// ── create_election ───────────────────────────────────────────────────────────

#[test]
fn create_election_happy() {
    let pid = program_id();
    let m = mollusk(&pid);

    let authority = Pubkey::new_unique();
    let eid: u64 = 1;
    let (epda, bump) = election_pda(&pid, eid);
    let (sys_id, sys_acc) = mollusk_svm::program::keyed_account_for_system_program();
    let lamports = 10_000_000u64;

    let data = create_election_data(eid, 100, 200, 250, 400, [0u8; 32], lamports, bump);
    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(authority, true),
            AccountMeta::new(epda, false),
            AccountMeta::new_readonly(sys_id, false),
        ],
        data,
    };

    let result = m.process_and_validate_instruction(
        &ix,
        &[
            (authority, payer(100_000_000)),
            (epda, Account::default()),
            (sys_id, sys_acc),
        ],
        &[Check::success()],
    );

    let acc = result.resulting_accounts.iter()
        .find(|(k, _)| k == &epda).map(|(_, v)| v).unwrap();
    assert_eq!(&acc.data[0..8], b"election");
    assert_eq!(u64::from_le_bytes(acc.data[8..16].try_into().unwrap()), eid);
    assert_eq!(&acc.data[16..48], authority.as_ref());
    assert_eq!(acc.data[112], 0u8); // DRAFT
}

#[test]
fn create_election_bad_slot_order() {
    let pid = program_id();
    let m = mollusk(&pid);

    let authority = Pubkey::new_unique();
    let eid: u64 = 2;
    let (epda, bump) = election_pda(&pid, eid);
    let (sys_id, sys_acc) = mollusk_svm::program::keyed_account_for_system_program();

    // reg_close (100) <= reg_open (200) → invalid
    let data = create_election_data(eid, 200, 100, 250, 400, [0u8; 32], 10_000_000, bump);
    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(authority, true),
            AccountMeta::new(epda, false),
            AccountMeta::new_readonly(sys_id, false),
        ],
        data,
    };

    m.process_and_validate_instruction(
        &ix,
        &[
            (authority, payer(100_000_000)),
            (epda, Account::default()),
            (sys_id, sys_acc),
        ],
        &[Check::err(ProgramError::InvalidInstructionData)],
    );
}

#[test]
fn create_election_already_initialized() {
    let pid = program_id();
    let m = mollusk(&pid);

    let authority = Pubkey::new_unique();
    let eid: u64 = 3;
    let (epda, bump) = election_pda(&pid, eid);
    let (sys_id, sys_acc) = mollusk_svm::program::keyed_account_for_system_program();

    let data = create_election_data(eid, 100, 200, 250, 400, [0u8; 32], 10_000_000, bump);
    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(authority, true),
            AccountMeta::new(epda, false),
            AccountMeta::new_readonly(sys_id, false),
        ],
        data,
    };

    // Pre-populated account → data_len() != 0 → AlreadyInitialized
    let existing = Account {
        lamports: 10_000_000,
        data: vec![0u8; election_registry::ELECTION_ACCOUNT_SIZE],
        owner: pid,
        ..Default::default()
    };

    m.process_and_validate_instruction(
        &ix,
        &[
            (authority, payer(100_000_000)),
            (epda, existing),
            (sys_id, sys_acc),
        ],
        &[Check::err(ProgramError::AccountAlreadyInitialized)],
    );
}

// ── set_candidates ────────────────────────────────────────────────────────────

#[test]
fn set_candidates_happy() {
    let pid = program_id();
    let m = mollusk(&pid);

    let authority = Pubkey::new_unique();
    let eid: u64 = 10;
    let (epda, _) = election_pda(&pid, eid);

    let ea_data = election_account_bytes(&pid, eid, &authority, 100, 200, 250, 400, 0, 0);
    let ea_acc = Account { lamports: 10_000_000, data: ea_data, owner: pid, ..Default::default() };

    let data = set_candidates_data(eid, 3);
    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(authority, true),
            AccountMeta::new(epda, false),
        ],
        data,
    };

    let result = m.process_and_validate_instruction(
        &ix,
        &[(authority, payer(10_000_000)), (epda, ea_acc)],
        &[Check::success()],
    );

    let acc = result.resulting_accounts.iter()
        .find(|(k, _)| k == &epda).map(|(_, v)| v).unwrap();
    assert_eq!(acc.data[112], 1u8); // REG_OPEN
    assert_eq!(acc.data[113], 3u8);
}

#[test]
fn set_candidates_wrong_authority() {
    let pid = program_id();
    let m = mollusk(&pid);

    let authority = Pubkey::new_unique();
    let bad_auth = Pubkey::new_unique();
    let eid: u64 = 11;
    let (epda, _) = election_pda(&pid, eid);

    let ea_data = election_account_bytes(&pid, eid, &authority, 100, 200, 250, 400, 0, 0);
    let ea_acc = Account { lamports: 10_000_000, data: ea_data, owner: pid, ..Default::default() };

    let data = set_candidates_data(eid, 2);
    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(bad_auth, true),
            AccountMeta::new(epda, false),
        ],
        data,
    };

    m.process_and_validate_instruction(
        &ix,
        &[(bad_auth, payer(10_000_000)), (epda, ea_acc)],
        &[Check::err(ProgramError::MissingRequiredSignature)],
    );
}

// ── rotate_aggregation_key ────────────────────────────────────────────────────

#[test]
fn rotate_aggregation_key_happy() {
    let pid = program_id();
    let m = mollusk(&pid);

    let authority = Pubkey::new_unique();
    let eid: u64 = 20;
    let (epda, _) = election_pda(&pid, eid);

    let ea_data = election_account_bytes(&pid, eid, &authority, 100, 200, 250, 400, 1, 2);
    let ea_acc = Account { lamports: 10_000_000, data: ea_data, owner: pid, ..Default::default() };

    let new_key = [7u8; 32];
    let mut data = vec![2u8];
    data.extend_from_slice(&eid.to_le_bytes());
    data.extend_from_slice(&new_key);

    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(authority, true),
            AccountMeta::new(epda, false),
        ],
        data,
    };

    let result = m.process_and_validate_instruction(
        &ix,
        &[(authority, payer(10_000_000)), (epda, ea_acc)],
        &[Check::success()],
    );

    let acc = result.resulting_accounts.iter()
        .find(|(k, _)| k == &epda).map(|(_, v)| v).unwrap();
    assert_eq!(&acc.data[48..80], &new_key);
}

// ── advance_phase ─────────────────────────────────────────────────────────────

#[test]
fn advance_phase_reg_open_to_reg_closed() {
    let pid = program_id();
    let m = mollusk(&pid);

    let authority = Pubkey::new_unique();
    let eid: u64 = 30;
    let (epda, _) = election_pda(&pid, eid);
    let (clock_id, mut clock_acc) = m.sysvars.keyed_account_for_clock_sysvar();
    clock_acc.data[0..8].copy_from_slice(&201u64.to_le_bytes()); // slot > reg_close_slot=200

    let ea_data = election_account_bytes(&pid, eid, &authority, 100, 200, 250, 400, 1, 2);
    let ea_acc = Account { lamports: 10_000_000, data: ea_data, owner: pid, ..Default::default() };

    let mut data = vec![3u8];
    data.extend_from_slice(&eid.to_le_bytes());
    data.push(2u8); // REG_CLOSED

    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(authority, true),
            AccountMeta::new(epda, false),
            AccountMeta::new_readonly(clock_id, false),
        ],
        data,
    };

    let result = m.process_and_validate_instruction(
        &ix,
        &[(authority, payer(10_000_000)), (epda, ea_acc), (clock_id, clock_acc)],
        &[Check::success()],
    );

    let acc = result.resulting_accounts.iter()
        .find(|(k, _)| k == &epda).map(|(_, v)| v).unwrap();
    assert_eq!(acc.data[112], 2u8); // REG_CLOSED
}

#[test]
fn advance_phase_too_early() {
    let pid = program_id();
    let m = mollusk(&pid);

    let authority = Pubkey::new_unique();
    let eid: u64 = 31;
    let (epda, _) = election_pda(&pid, eid);
    let (clock_id, mut clock_acc) = m.sysvars.keyed_account_for_clock_sysvar();
    clock_acc.data[0..8].copy_from_slice(&150u64.to_le_bytes()); // slot 150 < reg_close 200

    let ea_data = election_account_bytes(&pid, eid, &authority, 100, 200, 250, 400, 1, 2);
    let ea_acc = Account { lamports: 10_000_000, data: ea_data, owner: pid, ..Default::default() };

    let mut data = vec![3u8];
    data.extend_from_slice(&eid.to_le_bytes());
    data.push(2u8);

    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(authority, true),
            AccountMeta::new(epda, false),
            AccountMeta::new_readonly(clock_id, false),
        ],
        data,
    };

    m.process_and_validate_instruction(
        &ix,
        &[(authority, payer(10_000_000)), (epda, ea_acc), (clock_id, clock_acc)],
        &[Check::err(ProgramError::InvalidInstructionData)],
    );
}

#[test]
fn advance_phase_wrong_authority() {
    let pid = program_id();
    let m = mollusk(&pid);

    let authority = Pubkey::new_unique();
    let bad_auth = Pubkey::new_unique();
    let eid: u64 = 32;
    let (epda, _) = election_pda(&pid, eid);
    let (clock_id, mut clock_acc) = m.sysvars.keyed_account_for_clock_sysvar();
    clock_acc.data[0..8].copy_from_slice(&201u64.to_le_bytes());

    let ea_data = election_account_bytes(&pid, eid, &authority, 100, 200, 250, 400, 1, 2);
    let ea_acc = Account { lamports: 10_000_000, data: ea_data, owner: pid, ..Default::default() };

    let mut data = vec![3u8];
    data.extend_from_slice(&eid.to_le_bytes());
    data.push(2u8);

    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(bad_auth, true),
            AccountMeta::new(epda, false),
            AccountMeta::new_readonly(clock_id, false),
        ],
        data,
    };

    m.process_and_validate_instruction(
        &ix,
        &[(bad_auth, payer(10_000_000)), (epda, ea_acc), (clock_id, clock_acc)],
        &[Check::err(ProgramError::MissingRequiredSignature)],
    );
}
