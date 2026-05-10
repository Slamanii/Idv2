// Full election lifecycle integration test.
// Sequence:
//   1.  create_election            (election_registry)
//   2.  set_candidates             (election_registry)
//   3.  init_voter_registry        (voter_registry)
//   4.  init_tally                 (tally)
//   5.  insert_commitment          (voter_registry)
//   6.  advance_phase REG_CLOSED   (election_registry)
//   7.  advance_phase VOTING_OPEN  (election_registry)
//   8.  cast ballot                (ballot)
//   9.  advance_phase VOTING_CLOSED(election_registry)
//  10.  finalise_tally             (tally)
//  11.  verify_tally               (tally)
//
// Each step uses a separate Mollusk instance for its program; accounts are
// threaded through as plain Account structs between steps.

use mollusk_svm::{result::Check, Mollusk};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};

// ── Program names (resolved at test time via SBF_OUT_DIR or BPF_OUT_DIR) ──────
const ER_NAME:  &str = "election_registry";
const VR_NAME:  &str = "voter_registry";
const BAL_NAME: &str = "ballot";
const TAL_NAME: &str = "tally";

fn payer(lamports: u64) -> Account {
    Account { lamports, ..Default::default() }
}

// ── Merkle helpers ─────────────────────────────────────────────────────────────

fn empty_path_flat() -> Vec<u8> {
    use voter_registry::merkle;
    let sibs = merkle::empty_path_siblings();
    let mut flat = vec![0u8; merkle::DEPTH * 32];
    for (i, s) in sibs.iter().enumerate() {
        flat[i * 32..(i + 1) * 32].copy_from_slice(s);
    }
    flat
}

fn empty_tree_root() -> [u8; 32] {
    voter_registry::merkle::empty_tree_root()
}

fn root_after_insert(commitment: &[u8; 32]) -> [u8; 32] {
    use voter_registry::merkle;
    let leaf_val = merkle::leaf_hash(commitment);
    let flat = empty_path_flat();
    merkle::compute_root_from_path(&leaf_val, &flat, 0)
}

// ── ElectionAccount raw-byte helpers (mirrors election_registry layout) ────────

const EA_SIZE: usize = election_registry::ELECTION_ACCOUNT_SIZE;

fn read_phase(data: &[u8]) -> u8 {
    data[112]
}

fn build_election_bytes(
    eid: u64,
    authority: &Pubkey,
    reg_open: u64,
    reg_close: u64,
    vote_open: u64,
    vote_close: u64,
    phase: u8,
    candidate_count: u8,
) -> Vec<u8> {
    let mut d = vec![0u8; EA_SIZE];
    d[0..8].copy_from_slice(b"election");
    d[8..16].copy_from_slice(&eid.to_le_bytes());
    d[16..48].copy_from_slice(authority.as_ref());
    d[80..88].copy_from_slice(&reg_open.to_le_bytes());
    d[88..96].copy_from_slice(&reg_close.to_le_bytes());
    d[96..104].copy_from_slice(&vote_open.to_le_bytes());
    d[104..112].copy_from_slice(&vote_close.to_le_bytes());
    d[112] = phase;
    d[113] = candidate_count;
    d
}

// ── VoterRegistryAccount helpers ──────────────────────────────────────────────

fn build_vr_bytes(pid: &Pubkey, eid: u64, root: [u8; 32], leaf_count: u64) -> Vec<u8> {
    let mut d = vec![0u8; voter_registry::VoterRegistryAccount::LEN];
    d[0..8].copy_from_slice(b"voterreg");
    d[8..16].copy_from_slice(&eid.to_le_bytes());
    d[16..48].copy_from_slice(&root);
    d[48..56].copy_from_slice(&leaf_count.to_le_bytes());
    d[56] = 28;
    let _ = pid;
    d
}

// ── TallyAccount helpers ──────────────────────────────────────────────────────

fn build_tally_bytes(pid: &Pubkey, eid: u64) -> Vec<u8> {
    let mut d = vec![0u8; tally::TallyAccount::LEN];
    d[0..8].copy_from_slice(b"tallying");
    d[8..16].copy_from_slice(&eid.to_le_bytes());
    let _ = pid;
    d
}

// ── The full lifecycle ─────────────────────────────────────────────────────────

#[test]
fn full_election_lifecycle() {
    // ── IDs and keys ──────────────────────────────────────────────────────────
    let eid: u64 = 42;

    let er_pid = Pubkey::new_unique();
    let vr_pid = Pubkey::new_unique();
    let bal_pid = Pubkey::new_unique();
    let tal_pid = Pubkey::new_unique();

    let authority = Pubkey::new_unique();
    let relayer   = Pubkey::new_unique();
    let commitment = [0xABu8; 32];
    let nullifier  = [0xCDu8; 32];

    // Slot timeline: reg_open=100, reg_close=300, vote_open=350, vote_close=700
    let reg_open: u64  = 100;
    let reg_close: u64 = 300;
    let vote_open: u64 = 350;
    let vote_close: u64 = 700;

    // PDAs
    let (epda, er_bump)   = Pubkey::find_program_address(&[b"election", &eid.to_le_bytes()], &er_pid);
    let (vr_pda, vr_bump) = Pubkey::find_program_address(&[b"voter_registry", &eid.to_le_bytes()], &vr_pid);
    let (leaf_pda, leaf_bump) = Pubkey::find_program_address(
        &[b"leaf", &eid.to_le_bytes(), &0u64.to_le_bytes()], &vr_pid,
    );
    let (tally_pda, tally_bump) = Pubkey::find_program_address(&[b"tally", &eid.to_le_bytes()], &tal_pid);
    let (ballot_pda, ballot_bump) = Pubkey::find_program_address(
        &[b"ballot", &eid.to_le_bytes(), nullifier.as_ref()], &bal_pid,
    );
    let (null_pda, null_bump) = Pubkey::find_program_address(
        &[b"nullifier", &eid.to_le_bytes(), nullifier.as_ref()], &bal_pid,
    );

    // ── Mollusk instances ─────────────────────────────────────────────────────
    let m_er  = Mollusk::new(&er_pid,  ER_NAME);
    let m_vr  = Mollusk::new(&vr_pid,  VR_NAME);
    let m_tal = Mollusk::new(&tal_pid, TAL_NAME);
    // ballot needs tally loaded so the accumulate_votes CPI executes
    let mut m_bal = Mollusk::new(&bal_pid, BAL_NAME);
    m_bal.add_program(&tal_pid, TAL_NAME, &mollusk_svm::program::loader_keys::LOADER_V3);

    let (sys_id, sys_acc) = mollusk_svm::program::keyed_account_for_system_program();

    // ── Step 1: create_election ───────────────────────────────────────────────
    {
        let mut data = vec![0u8];
        data.extend_from_slice(&eid.to_le_bytes());
        data.extend_from_slice(&reg_open.to_le_bytes());
        data.extend_from_slice(&reg_close.to_le_bytes());
        data.extend_from_slice(&vote_open.to_le_bytes());
        data.extend_from_slice(&vote_close.to_le_bytes());
        data.extend_from_slice(&[0u8; 32]); // agg_key
        data.extend_from_slice(&10_000_000u64.to_le_bytes());
        data.push(er_bump);

        let ix = Instruction {
            program_id: er_pid,
            accounts: vec![
                AccountMeta::new(authority, true),
                AccountMeta::new(epda, false),
                AccountMeta::new_readonly(sys_id, false),
            ],
            data,
        };

        let res = m_er.process_and_validate_instruction(
            &ix,
            &[(authority, payer(100_000_000)), (epda, Account::default()), (sys_id, sys_acc.clone())],
            &[Check::success()],
        );
        let acc = res.resulting_accounts.iter().find(|(k,_)| k==&epda).unwrap().1.clone();
        assert_eq!(read_phase(&acc.data), 0); // DRAFT
    }

    // ── Step 2: set_candidates ────────────────────────────────────────────────
    // Must happen before we snapshot the election account; it transitions DRAFT→REG_OPEN.
    let ea_after_set = {
        // Build from state in DRAFT
        let ea_data = build_election_bytes(
            eid, &authority, reg_open, reg_close, vote_open, vote_close, 0, 0,
        );
        let ea_acc = Account { lamports: 10_000_000, data: ea_data, owner: er_pid, ..Default::default() };

        let mut data = vec![1u8];
        data.extend_from_slice(&eid.to_le_bytes());
        data.push(4u8); // 4 candidates
        for i in 0..4usize {
            data.push(i as u8);
            data.extend_from_slice(&[0u8; 32]);
            data.extend_from_slice(&[0u8; 15]);
        }

        let ix = Instruction {
            program_id: er_pid,
            accounts: vec![
                AccountMeta::new(authority, true),
                AccountMeta::new(epda, false),
            ],
            data,
        };

        let res = m_er.process_and_validate_instruction(
            &ix,
            &[(authority, payer(10_000_000)), (epda, ea_acc)],
            &[Check::success()],
        );
        let acc = res.resulting_accounts.iter().find(|(k,_)| k==&epda).unwrap().1.clone();
        assert_eq!(read_phase(&acc.data), 1); // REG_OPEN
        acc
    };

    // ── Step 3: init_voter_registry ───────────────────────────────────────────
    let vr_after_init = {
        let mut data = vec![1u8];
        data.extend_from_slice(&eid.to_le_bytes());
        data.extend_from_slice(&5_000_000u64.to_le_bytes());
        data.push(vr_bump);

        let ix = Instruction {
            program_id: vr_pid,
            accounts: vec![
                AccountMeta::new(relayer, true),
                AccountMeta::new(vr_pda, false),
                AccountMeta::new_readonly(sys_id, false),
            ],
            data,
        };

        let res = m_vr.process_and_validate_instruction(
            &ix,
            &[(relayer, payer(100_000_000)), (vr_pda, Account::default()), (sys_id, sys_acc.clone())],
            &[Check::success()],
        );
        let acc = res.resulting_accounts.iter().find(|(k,_)| k==&vr_pda).unwrap().1.clone();
        let stored_root: [u8; 32] = acc.data[16..48].try_into().unwrap();
        assert_eq!(stored_root, empty_tree_root());
        acc
    };

    // ── Step 4: init_tally ────────────────────────────────────────────────────
    let tally_after_init = {
        let mut data = vec![3u8];
        data.extend_from_slice(&eid.to_le_bytes());
        data.extend_from_slice(&10_000_000u64.to_le_bytes());
        data.push(tally_bump);

        let ix = Instruction {
            program_id: tal_pid,
            accounts: vec![
                AccountMeta::new(authority, true),
                AccountMeta::new(tally_pda, false),
                AccountMeta::new_readonly(sys_id, false),
            ],
            data,
        };

        let res = m_tal.process_and_validate_instruction(
            &ix,
            &[(authority, payer(100_000_000)), (tally_pda, Account::default()), (sys_id, sys_acc.clone())],
            &[Check::success()],
        );
        res.resulting_accounts.iter().find(|(k,_)| k==&tally_pda).unwrap().1.clone()
    };
    let _ = tally_after_init; // used below

    // ── Step 5: insert_commitment ─────────────────────────────────────────────
    let vr_after_insert = {
        let (clock_id, mut clock_acc) = m_vr.sysvars.keyed_account_for_clock_sysvar();
        clock_acc.data[0..8].copy_from_slice(&150u64.to_le_bytes()); // slot 150 in reg window

        let path_flat = empty_path_flat();
        let mut data = vec![0u8];
        data.extend_from_slice(&eid.to_le_bytes());
        data.extend_from_slice(&commitment);
        data.extend_from_slice(&path_flat);
        data.extend_from_slice(&0u32.to_le_bytes()); // path_indices
        data.extend_from_slice(&2_000_000u64.to_le_bytes()); // leaf_lamports
        data.push(leaf_bump);

        let ix = Instruction {
            program_id: vr_pid,
            accounts: vec![
                AccountMeta::new(relayer, true),
                AccountMeta::new_readonly(epda, false),
                AccountMeta::new(vr_pda, false),
                AccountMeta::new(leaf_pda, false),
                AccountMeta::new_readonly(clock_id, false),
                AccountMeta::new_readonly(sys_id, false),
            ],
            data,
        };

        let res = m_vr.process_and_validate_instruction(
            &ix,
            &[
                (relayer, payer(100_000_000)),
                (epda, ea_after_set.clone()),
                (vr_pda, vr_after_init),
                (leaf_pda, Account::default()),
                (clock_id, clock_acc),
                (sys_id, sys_acc.clone()),
            ],
            &[Check::success()],
        );
        let acc = res.resulting_accounts.iter().find(|(k,_)| k==&vr_pda).unwrap().1.clone();
        let leaf_count = u64::from_le_bytes(acc.data[48..56].try_into().unwrap());
        assert_eq!(leaf_count, 1);
        let new_root: [u8; 32] = acc.data[16..48].try_into().unwrap();
        assert_eq!(new_root, root_after_insert(&commitment));
        acc
    };

    // ── Step 6: advance_phase → REG_CLOSED ───────────────────────────────────
    let ea_reg_closed = {
        let (clock_id, mut clock_acc) = m_er.sysvars.keyed_account_for_clock_sysvar();
        clock_acc.data[0..8].copy_from_slice(&301u64.to_le_bytes()); // > reg_close=300

        let mut data = vec![3u8];
        data.extend_from_slice(&eid.to_le_bytes());
        data.push(2u8); // REG_CLOSED

        let ix = Instruction {
            program_id: er_pid,
            accounts: vec![
                AccountMeta::new(authority, true),
                AccountMeta::new(epda, false),
                AccountMeta::new_readonly(clock_id, false),
            ],
            data,
        };

        let res = m_er.process_and_validate_instruction(
            &ix,
            &[(authority, payer(10_000_000)), (epda, ea_after_set.clone()), (clock_id, clock_acc)],
            &[Check::success()],
        );
        let acc = res.resulting_accounts.iter().find(|(k,_)| k==&epda).unwrap().1.clone();
        assert_eq!(read_phase(&acc.data), 2);
        acc
    };

    // ── Step 7: advance_phase → VOTING_OPEN ──────────────────────────────────
    let ea_voting_open = {
        let (clock_id, mut clock_acc) = m_er.sysvars.keyed_account_for_clock_sysvar();
        clock_acc.data[0..8].copy_from_slice(&360u64.to_le_bytes()); // > vote_open=350

        let mut data = vec![3u8];
        data.extend_from_slice(&eid.to_le_bytes());
        data.push(3u8); // VOTING_OPEN

        let ix = Instruction {
            program_id: er_pid,
            accounts: vec![
                AccountMeta::new(authority, true),
                AccountMeta::new(epda, false),
                AccountMeta::new_readonly(clock_id, false),
            ],
            data,
        };

        let res = m_er.process_and_validate_instruction(
            &ix,
            &[(authority, payer(10_000_000)), (epda, ea_reg_closed), (clock_id, clock_acc)],
            &[Check::success()],
        );
        let acc = res.resulting_accounts.iter().find(|(k,_)| k==&epda).unwrap().1.clone();
        assert_eq!(read_phase(&acc.data), 3);
        acc
    };

    // ── Step 8: cast ballot ───────────────────────────────────────────────────
    let tally_after_cast = {
        let (clock_id, mut clock_acc) = m_bal.sysvars.keyed_account_for_clock_sysvar();
        clock_acc.data[0..8].copy_from_slice(&500u64.to_le_bytes()); // in voting window

        let path_flat = empty_path_flat();
        let mut data = vec![0u8];
        data.extend_from_slice(&eid.to_le_bytes());
        data.extend_from_slice(&nullifier);
        data.extend_from_slice(&commitment);
        data.extend_from_slice(&path_flat);
        data.extend_from_slice(&0u32.to_le_bytes());
        data.push(1u8); // candidate_id = 1
        data.push(2u8); // state_id = 2
        data.extend_from_slice(&500u16.to_le_bytes()); // lga_id
        data.extend_from_slice(&2_000_000u64.to_le_bytes()); // ballot_lamports
        data.extend_from_slice(&1_000_000u64.to_le_bytes()); // null_lamports
        data.push(ballot_bump);
        data.push(null_bump);

        let tally_before_cast = Account {
            lamports: 10_000_000,
            data: build_tally_bytes(&tal_pid, eid),
            owner: tal_pid,
            ..Default::default()
        };
        let tal_program_acc = mollusk_svm::program::create_program_account_loader_v3(&tal_pid);

        let ix = Instruction {
            program_id: bal_pid,
            accounts: vec![
                AccountMeta::new(relayer, true),
                AccountMeta::new_readonly(epda, false),
                AccountMeta::new_readonly(vr_pda, false),
                AccountMeta::new(ballot_pda, false),
                AccountMeta::new(null_pda, false),
                AccountMeta::new_readonly(clock_id, false),
                AccountMeta::new_readonly(sys_id, false),
                AccountMeta::new(tally_pda, false),
                AccountMeta::new_readonly(tal_pid, false),
            ],
            data,
        };

        let res = m_bal.process_and_validate_instruction(
            &ix,
            &[
                (relayer,    payer(100_000_000)),
                (epda,       ea_voting_open.clone()),
                (vr_pda,     vr_after_insert.clone()),
                (ballot_pda, Account::default()),
                (null_pda,   Account::default()),
                (clock_id,   clock_acc),
                (sys_id,     sys_acc.clone()),
                (tally_pda,  tally_before_cast),
                (tal_pid,    tal_program_acc),
            ],
            &[Check::success()],
        );

        let ballot_out = res.resulting_accounts.iter()
            .find(|(k,_)| k==&ballot_pda).unwrap().1.clone();
        assert_eq!(&ballot_out.data[0..8], b"ballot\0\0");
        assert_eq!(ballot_out.data[49], 1u8); // candidate_id

        // Tally shard = 1*4 + (2%4) = 6 should be 1 after CPI
        let tally_out = res.resulting_accounts.iter()
            .find(|(k,_)| k==&tally_pda).unwrap().1.clone();
        let shard_off = 32 + 6 * 8;
        let shard_val = u64::from_le_bytes(tally_out.data[shard_off..shard_off + 8].try_into().unwrap());
        assert_eq!(shard_val, 1u64);
        assert_eq!(u64::from_le_bytes(tally_out.data[24..32].try_into().unwrap()), 1u64); // total_votes

        tally_out
    };

    // ── Step 9: advance_phase → VOTING_CLOSED ────────────────────────────────
    let ea_voting_closed = {
        let (clock_id, mut clock_acc) = m_er.sysvars.keyed_account_for_clock_sysvar();
        clock_acc.data[0..8].copy_from_slice(&701u64.to_le_bytes()); // > vote_close=700

        let mut data = vec![3u8];
        data.extend_from_slice(&eid.to_le_bytes());
        data.push(4u8); // VOTING_CLOSED

        let ix = Instruction {
            program_id: er_pid,
            accounts: vec![
                AccountMeta::new(authority, true),
                AccountMeta::new(epda, false),
                AccountMeta::new_readonly(clock_id, false),
            ],
            data,
        };

        let res = m_er.process_and_validate_instruction(
            &ix,
            &[(authority, payer(10_000_000)), (epda, ea_voting_open), (clock_id, clock_acc)],
            &[Check::success()],
        );
        let acc = res.resulting_accounts.iter().find(|(k,_)| k==&epda).unwrap().1.clone();
        assert_eq!(read_phase(&acc.data), 4);
        acc
    };

    // ── Step 10: finalise_tally ───────────────────────────────────────────────
    {
        let tally_acc = tally_after_cast;

        let mut data = vec![1u8];
        data.extend_from_slice(&eid.to_le_bytes());

        let ix = Instruction {
            program_id: tal_pid,
            accounts: vec![
                AccountMeta::new(authority, true),
                AccountMeta::new_readonly(epda, false),
                AccountMeta::new(tally_pda, false),
            ],
            data,
        };

        let res = m_tal.process_and_validate_instruction(
            &ix,
            &[
                (authority, payer(10_000_000)),
                (epda, ea_voting_closed),
                (tally_pda, tally_acc),
            ],
            &[Check::success()],
        );
        let acc = res.resulting_accounts.iter()
            .find(|(k,_)| k==&tally_pda).unwrap().1.clone();
        assert_eq!(acc.data[1056], 1u8); // finalized

        // ── Step 11: verify_tally (1 vote, 1 registered) ─────────────────────
        let tally_for_verify = acc;
        let vr_for_verify = Account {
            lamports: 5_000_000,
            data: build_vr_bytes(&vr_pid, eid, root_after_insert(&commitment), 1),
            ..Default::default()
        };

        let mut data2 = vec![2u8];
        data2.extend_from_slice(&eid.to_le_bytes());

        let ix2 = Instruction {
            program_id: tal_pid,
            accounts: vec![
                AccountMeta::new_readonly(tally_pda, false),
                AccountMeta::new_readonly(vr_pda, false),
            ],
            data: data2,
        };

        // 1 total_vote ≤ 1 leaf_count, counter_sum == 1 == total_votes → ok
        m_tal.process_and_validate_instruction(
            &ix2,
            &[(tally_pda, tally_for_verify), (vr_pda, vr_for_verify)],
            &[Check::success()],
        );
    }
}
