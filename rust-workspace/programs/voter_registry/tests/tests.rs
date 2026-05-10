use mollusk_svm::{result::Check, Mollusk};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    program_error::ProgramError,
    pubkey::Pubkey,
};
use voter_registry::merkle;

const PROG_NAME: &str = "voter_registry";

fn program_id() -> Pubkey {
    Pubkey::new_unique()
}

fn mollusk(pid: &Pubkey) -> Mollusk {
    Mollusk::new(pid, PROG_NAME)
}

fn payer(lamports: u64) -> Account {
    Account { lamports, ..Default::default() }
}

fn vr_pda(pid: &Pubkey, eid: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"voter_registry", &eid.to_le_bytes()], pid)
}

fn leaf_pda(pid: &Pubkey, eid: u64, idx: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"leaf", &eid.to_le_bytes(), &idx.to_le_bytes()],
        pid,
    )
}

/// Build a VoterRegistryAccount byte buffer with given root.
fn vr_bytes(pid: &Pubkey, eid: u64, root: [u8; 32], leaf_count: u64) -> Vec<u8> {
    let mut data = vec![0u8; voter_registry::VoterRegistryAccount::LEN];
    data[0..8].copy_from_slice(b"voterreg");
    data[8..16].copy_from_slice(&eid.to_le_bytes());
    data[16..48].copy_from_slice(&root);
    data[48..56].copy_from_slice(&leaf_count.to_le_bytes());
    data[56] = 28; // tree_depth
    let _ = pid;
    data
}

/// Build an ElectionAccount byte buffer (minimum fields needed by voter_registry).
fn election_account_bytes(
    eid: u64,
    reg_close: u64,
    phase: u8,
) -> Vec<u8> {
    let mut data = vec![0u8; 200];
    data[0..8].copy_from_slice(b"election");
    data[8..16].copy_from_slice(&eid.to_le_bytes());
    data[88..96].copy_from_slice(&reg_close.to_le_bytes()); // reg_close_slot
    data[112] = phase;
    data
}

/// Build init_voter_registry (ix_tag=1) data.
fn init_vr_data(eid: u64, lamports: u64, bump: u8) -> Vec<u8> {
    let mut d = vec![1u8];
    d.extend_from_slice(&eid.to_le_bytes());
    d.extend_from_slice(&lamports.to_le_bytes());
    d.push(bump);
    d
}

/// Build the flat 896-byte Merkle path from empty tree siblings.
fn empty_path_flat() -> Vec<u8> {
    let sibs = merkle::empty_path_siblings();
    let mut flat = vec![0u8; merkle::DEPTH * 32];
    for (i, s) in sibs.iter().enumerate() {
        flat[i * 32..(i + 1) * 32].copy_from_slice(s);
    }
    flat
}

/// Build insert_commitment (ix_tag=0) data for leaf index 0.
fn insert_commitment_data(
    eid: u64,
    commitment: [u8; 32],
    path_flat: &[u8],
    path_indices: u32,
    leaf_lamports: u64,
    leaf_bump: u8,
) -> Vec<u8> {
    let mut d = vec![0u8];
    d.extend_from_slice(&eid.to_le_bytes());
    d.extend_from_slice(&commitment);
    d.extend_from_slice(path_flat);
    d.extend_from_slice(&path_indices.to_le_bytes());
    d.extend_from_slice(&leaf_lamports.to_le_bytes());
    d.push(leaf_bump);
    d
}

// ── init_voter_registry ───────────────────────────────────────────────────────

#[test]
fn init_voter_registry_happy() {
    let pid = program_id();
    let m = mollusk(&pid);

    let relayer = Pubkey::new_unique();
    let eid: u64 = 1;
    let (vr_pda_key, bump) = vr_pda(&pid, eid);
    let (sys_id, sys_acc) = mollusk_svm::program::keyed_account_for_system_program();

    let data = init_vr_data(eid, 5_000_000, bump);
    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(relayer, true),
            AccountMeta::new(vr_pda_key, false),
            AccountMeta::new_readonly(sys_id, false),
        ],
        data,
    };

    let result = m.process_and_validate_instruction(
        &ix,
        &[
            (relayer, payer(100_000_000)),
            (vr_pda_key, Account::default()),
            (sys_id, sys_acc),
        ],
        &[Check::success()],
    );

    let acc = result.resulting_accounts.iter()
        .find(|(k, _)| k == &vr_pda_key).map(|(_, v)| v).unwrap();
    assert_eq!(&acc.data[0..8], b"voterreg");
    assert_eq!(u64::from_le_bytes(acc.data[8..16].try_into().unwrap()), eid);
    // Merkle root should be the empty tree root.
    let stored_root: [u8; 32] = acc.data[16..48].try_into().unwrap();
    assert_eq!(stored_root, merkle::empty_tree_root());
    assert_eq!(u64::from_le_bytes(acc.data[48..56].try_into().unwrap()), 0u64);
}

#[test]
fn init_voter_registry_already_initialized() {
    let pid = program_id();
    let m = mollusk(&pid);

    let relayer = Pubkey::new_unique();
    let eid: u64 = 2;
    let (vr_pda_key, bump) = vr_pda(&pid, eid);
    let (sys_id, sys_acc) = mollusk_svm::program::keyed_account_for_system_program();

    let data = init_vr_data(eid, 5_000_000, bump);
    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(relayer, true),
            AccountMeta::new(vr_pda_key, false),
            AccountMeta::new_readonly(sys_id, false),
        ],
        data,
    };

    // Pre-existing account → AlreadyInitialized
    let existing = Account {
        lamports: 5_000_000,
        data: vec![0u8; voter_registry::VoterRegistryAccount::LEN],
        owner: pid,
        ..Default::default()
    };

    m.process_and_validate_instruction(
        &ix,
        &[
            (relayer, payer(100_000_000)),
            (vr_pda_key, existing),
            (sys_id, sys_acc),
        ],
        &[Check::err(ProgramError::AccountAlreadyInitialized)],
    );
}

// ── insert_commitment ─────────────────────────────────────────────────────────

#[test]
fn insert_commitment_happy() {
    let pid = program_id();
    let m = mollusk(&pid);

    let relayer = Pubkey::new_unique();
    let eid: u64 = 10;
    let (vr_pda_key, _) = vr_pda(&pid, eid);
    let (leaf_key, leaf_bump) = leaf_pda(&pid, eid, 0);
    let (sys_id, sys_acc) = mollusk_svm::program::keyed_account_for_system_program();
    let (clock_id, mut clock_acc) = m.sysvars.keyed_account_for_clock_sysvar();
    clock_acc.data[0..8].copy_from_slice(&50u64.to_le_bytes()); // slot 50 < reg_close 200

    // ElectionAccount: phase=REG_OPEN(1), reg_close=200
    let election_key = Pubkey::new_unique();
    let ea_data = election_account_bytes(eid, 200, 1);
    let ea_acc = Account { lamports: 5_000_000, data: ea_data, ..Default::default() };

    // VoterRegistry starting from empty tree root.
    let vr_data = vr_bytes(&pid, eid, merkle::empty_tree_root(), 0);
    let vr_acc = Account { lamports: 5_000_000, data: vr_data, owner: pid, ..Default::default() };

    let commitment = [42u8; 32];
    let path_flat = empty_path_flat();
    let data = insert_commitment_data(eid, commitment, &path_flat, 0, 2_000_000, leaf_bump);

    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(relayer, true),
            AccountMeta::new_readonly(election_key, false),
            AccountMeta::new(vr_pda_key, false),
            AccountMeta::new(leaf_key, false),
            AccountMeta::new_readonly(clock_id, false),
            AccountMeta::new_readonly(sys_id, false),
        ],
        data,
    };

    let result = m.process_and_validate_instruction(
        &ix,
        &[
            (relayer, payer(100_000_000)),
            (election_key, ea_acc),
            (vr_pda_key, vr_acc),
            (leaf_key, Account::default()),
            (clock_id, clock_acc),
            (sys_id, sys_acc),
        ],
        &[Check::success()],
    );

    // leaf_count should be 1, root should have changed.
    let vr_out = result.resulting_accounts.iter()
        .find(|(k, _)| k == &vr_pda_key).map(|(_, v)| v).unwrap();
    assert_eq!(u64::from_le_bytes(vr_out.data[48..56].try_into().unwrap()), 1u64);
    let new_root: [u8; 32] = vr_out.data[16..48].try_into().unwrap();
    assert_ne!(new_root, merkle::empty_tree_root());

    // Leaf account should be written with correct discriminator.
    let leaf_out = result.resulting_accounts.iter()
        .find(|(k, _)| k == &leaf_key).map(|(_, v)| v).unwrap();
    assert_eq!(&leaf_out.data[0..8], b"leaf\0\0\0\0");
    assert_eq!(&leaf_out.data[24..56], &commitment);
}

#[test]
fn insert_commitment_wrong_phase() {
    let pid = program_id();
    let m = mollusk(&pid);

    let relayer = Pubkey::new_unique();
    let eid: u64 = 11;
    let (vr_pda_key, _) = vr_pda(&pid, eid);
    let (leaf_key, leaf_bump) = leaf_pda(&pid, eid, 0);
    let (sys_id, sys_acc) = mollusk_svm::program::keyed_account_for_system_program();
    let (clock_id, mut clock_acc) = m.sysvars.keyed_account_for_clock_sysvar();
    clock_acc.data[0..8].copy_from_slice(&50u64.to_le_bytes());

    let election_key = Pubkey::new_unique();
    // phase=DRAFT(0) — not REG_OPEN
    let ea_data = election_account_bytes(eid, 200, 0);
    let ea_acc = Account { lamports: 5_000_000, data: ea_data, ..Default::default() };

    let vr_data = vr_bytes(&pid, eid, merkle::empty_tree_root(), 0);
    let vr_acc = Account { lamports: 5_000_000, data: vr_data, owner: pid, ..Default::default() };

    let commitment = [42u8; 32];
    let path_flat = empty_path_flat();
    let data = insert_commitment_data(eid, commitment, &path_flat, 0, 2_000_000, leaf_bump);

    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(relayer, true),
            AccountMeta::new_readonly(election_key, false),
            AccountMeta::new(vr_pda_key, false),
            AccountMeta::new(leaf_key, false),
            AccountMeta::new_readonly(clock_id, false),
            AccountMeta::new_readonly(sys_id, false),
        ],
        data,
    };

    m.process_and_validate_instruction(
        &ix,
        &[
            (relayer, payer(100_000_000)),
            (election_key, ea_acc),
            (vr_pda_key, vr_acc),
            (leaf_key, Account::default()),
            (clock_id, clock_acc),
            (sys_id, sys_acc),
        ],
        &[Check::err(ProgramError::InvalidInstructionData)],
    );
}

#[test]
fn insert_commitment_deadline_passed() {
    let pid = program_id();
    let m = mollusk(&pid);

    let relayer = Pubkey::new_unique();
    let eid: u64 = 12;
    let (vr_pda_key, _) = vr_pda(&pid, eid);
    let (leaf_key, leaf_bump) = leaf_pda(&pid, eid, 0);
    let (sys_id, sys_acc) = mollusk_svm::program::keyed_account_for_system_program();
    let (clock_id, mut clock_acc) = m.sysvars.keyed_account_for_clock_sysvar();
    // slot 201 >= reg_close 200 → deadline passed
    clock_acc.data[0..8].copy_from_slice(&201u64.to_le_bytes());

    let election_key = Pubkey::new_unique();
    let ea_data = election_account_bytes(eid, 200, 1);
    let ea_acc = Account { lamports: 5_000_000, data: ea_data, ..Default::default() };

    let vr_data = vr_bytes(&pid, eid, merkle::empty_tree_root(), 0);
    let vr_acc = Account { lamports: 5_000_000, data: vr_data, owner: pid, ..Default::default() };

    let commitment = [42u8; 32];
    let path_flat = empty_path_flat();
    let data = insert_commitment_data(eid, commitment, &path_flat, 0, 2_000_000, leaf_bump);

    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(relayer, true),
            AccountMeta::new_readonly(election_key, false),
            AccountMeta::new(vr_pda_key, false),
            AccountMeta::new(leaf_key, false),
            AccountMeta::new_readonly(clock_id, false),
            AccountMeta::new_readonly(sys_id, false),
        ],
        data,
    };

    m.process_and_validate_instruction(
        &ix,
        &[
            (relayer, payer(100_000_000)),
            (election_key, ea_acc),
            (vr_pda_key, vr_acc),
            (leaf_key, Account::default()),
            (clock_id, clock_acc),
            (sys_id, sys_acc),
        ],
        &[Check::err(ProgramError::InvalidInstructionData)],
    );
}

#[test]
fn insert_commitment_stale_path_rejected() {
    let pid = program_id();
    let m = mollusk(&pid);

    let relayer = Pubkey::new_unique();
    let eid: u64 = 13;
    let (vr_pda_key, _) = vr_pda(&pid, eid);
    let (leaf_key, leaf_bump) = leaf_pda(&pid, eid, 0);
    let (sys_id, sys_acc) = mollusk_svm::program::keyed_account_for_system_program();
    let (clock_id, mut clock_acc) = m.sysvars.keyed_account_for_clock_sysvar();
    clock_acc.data[0..8].copy_from_slice(&50u64.to_le_bytes());

    let election_key = Pubkey::new_unique();
    let ea_data = election_account_bytes(eid, 200, 1);
    let ea_acc = Account { lamports: 5_000_000, data: ea_data, ..Default::default() };

    // Root is NOT empty_tree_root — simulates a stale/wrong path.
    let wrong_root = [0x99u8; 32];
    let vr_data = vr_bytes(&pid, eid, wrong_root, 0);
    let vr_acc = Account { lamports: 5_000_000, data: vr_data, owner: pid, ..Default::default() };

    let commitment = [42u8; 32];
    let path_flat = empty_path_flat(); // path is valid for empty root, but stored root differs
    let data = insert_commitment_data(eid, commitment, &path_flat, 0, 2_000_000, leaf_bump);

    let ix = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(relayer, true),
            AccountMeta::new_readonly(election_key, false),
            AccountMeta::new(vr_pda_key, false),
            AccountMeta::new(leaf_key, false),
            AccountMeta::new_readonly(clock_id, false),
            AccountMeta::new_readonly(sys_id, false),
        ],
        data,
    };

    m.process_and_validate_instruction(
        &ix,
        &[
            (relayer, payer(100_000_000)),
            (election_key, ea_acc),
            (vr_pda_key, vr_acc),
            (leaf_key, Account::default()),
            (clock_id, clock_acc),
            (sys_id, sys_acc),
        ],
        &[Check::err(ProgramError::InvalidAccountData)],
    );
}
