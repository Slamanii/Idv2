use pinocchio::{
    account_info::AccountInfo,
    cpi,
    instruction::{AccountMeta, Seed, Signer},
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};
use pinocchio_pubkey::pubkey as pk;
use pinocchio_system::instructions::CreateAccount;

use crate::{BallotAccount, NullifierAccount};

// Fixed Solana runtime addresses — same on every cluster.
const ED25519_PROG: Pubkey = pk!("Ed25519SigVerify111111111111111111111111111");
const IXS_SYSVAR:  Pubkey = pk!("Sysvar1nstructions1111111111111111111111111");

// Signing domain separator — must match the enclave's signing domain exactly.
const BALLOT_PREFIX: &[u8] = b"IDV2-v1-ballot"; // 14 bytes

// ── Raw byte offsets into ElectionAccount (election_registry layout, PROGRAMS.md) ──
const EA_DISC:        core::ops::Range<usize> = 0..8;
const EA_EID:         core::ops::Range<usize> = 8..16;
const EA_AGG_PK:      core::ops::Range<usize> = 48..80; // aggregation_pubkey = HSM ballot-sign pubkey
const EA_VOTE_CLOSE:  core::ops::Range<usize> = 104..112;
const EA_PHASE:       usize = 112;
const EA_CAND_COUNT:  usize = 113;
const EA_MIN_LEN:     usize = 114;
const PHASE_VOTING_OPEN: u8 = 3;

// ── Instruction data layout (after tag byte, 166 B) ───────────────────────────
//   [0..8]     election_id     : u64 LE
//   [8..16]    leaf_index      : u64 LE
//   [16..48]   nullifier       : [u8; 32]   H(identity_secret ‖ election_id)
//   [48]       candidate_id    : u8
//   [49]       state_id        : u8
//   [50..52]   lga_id          : u16 LE
//   [52..60]   ballot_lamports : u64        rent for BallotAccount (88 B)
//   [60..68]   null_lamports   : u64        rent for NullifierAccount (1 B)
//   [68]       ballot_bump     : u8
//   [69]       null_bump       : u8
//   [70..134]  hsm_sig         : [u8; 64]   Ed25519 sig over IDV2-v1-ballot ‖ nullifier ‖ commitment
//   [134..166] authority_pk    : [u8; 32]   must match ElectionAccount.aggregation_pubkey
//
// commitment is read zero-copy from LeafAccount.commitment[24..56] — not duplicated here.

const OFF_EID:          usize = 0;
const OFF_LEAF_INDEX:   usize = 8;
const OFF_NULLIFIER:    usize = 16;
const OFF_CANDIDATE_ID: usize = 48;
const OFF_STATE_ID:     usize = 49;
const OFF_LGA_ID:       usize = 50;
const OFF_BALLOT_LAMPS: usize = 52;
const OFF_NULL_LAMPS:   usize = 60;
const OFF_BALLOT_BUMP:  usize = 68;
const OFF_NULL_BUMP:    usize = 69;
const OFF_HSM_SIG:      usize = 70;
const OFF_AUTHORITY_PK: usize = 134;
const DATA_MIN:         usize = 166;

// ── cast (ix_tag = 0) ──────────────────────────────────────────────────────────
//
// Accounts:
//   [0]  relayer           (signer, writable — pays both PDA rents)
//   [1]  election_account  (read-only PDA from election_registry)
//   [2]  voter_registry    (read-only PDA from voter_registry) — used to get vr owner
//   [3]  leaf_account      (read-only — voter's LeafAccount owned by voter_registry program)
//   [4]  ballot_account    (writable, new PDA  ["ballot",    eid_le, nullifier])
//   [5]  nullifier_account (writable, new PDA  ["nullifier", eid_le, nullifier])
//   [6]  clock_sysvar
//   [7]  system_program
//   [8]  tally_account     (writable PDA from tally ["tally", eid_le])
//   [9]  tally_program     (executable — the tally program)
//   [10] ixs_sysvar        (read-only — Instructions sysvar, confirms Ed25519 precompile ran)
pub fn cast(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let [relayer, election_account, voter_registry, leaf_account, ballot_account,
         nullifier_account, clock_sysvar, _system_program, tally_account, tally_program,
         ixs_sysvar] = accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // ── basic account guards ─────────────────────────────────────────────────

    if !relayer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !relayer.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    const CLOCK_ID: Pubkey = pk!("SysvarC1ock11111111111111111111111111111111");
    if clock_sysvar.key() != &CLOCK_ID {
        return Err(ProgramError::InvalidAccountData);
    }

    // ── parse instruction data ───────────────────────────────────────────────

    if data.len() < DATA_MIN {
        return Err(ProgramError::InvalidInstructionData);
    }

    let election_id  = u64::from_le_bytes(data[OFF_EID..OFF_EID + 8].try_into().unwrap());
    let leaf_index   = u64::from_le_bytes(data[OFF_LEAF_INDEX..OFF_LEAF_INDEX + 8].try_into().unwrap());
    let nullifier: [u8; 32] = data[OFF_NULLIFIER..OFF_NULLIFIER + 32].try_into().unwrap();
    let candidate_id = data[OFF_CANDIDATE_ID];
    let state_id      = data[OFF_STATE_ID];
    let lga_id        = u16::from_le_bytes(data[OFF_LGA_ID..OFF_LGA_ID + 2].try_into().unwrap());
    let ballot_lamps  = u64::from_le_bytes(data[OFF_BALLOT_LAMPS..OFF_BALLOT_LAMPS + 8].try_into().unwrap());
    let null_lamps    = u64::from_le_bytes(data[OFF_NULL_LAMPS..OFF_NULL_LAMPS + 8].try_into().unwrap());
    let ballot_bump   = data[OFF_BALLOT_BUMP];
    let null_bump     = data[OFF_NULL_BUMP];
    let hsm_sig:       [u8; 64] = data[OFF_HSM_SIG..OFF_HSM_SIG + 64].try_into().unwrap();
    let authority_pk:  [u8; 32] = data[OFF_AUTHORITY_PK..OFF_AUTHORITY_PK + 32].try_into().unwrap();

    // ── read current slot ────────────────────────────────────────────────────

    let current_slot = {
        let cd = clock_sysvar.try_borrow_data()?;
        if cd.len() < 8 {
            return Err(ProgramError::InvalidAccountData);
        }
        u64::from_le_bytes(cd[0..8].try_into().unwrap())
    };

    // ── election_account: phase, voting window, candidate roster size ────────
    // Reads raw bytes at locked offsets (PROGRAMS.md §ElectionAccount).
    // No cross-program crate import — program IDs change per deploy.

    let (election_phase, voting_close_slot, candidate_count, stored_authority_pk) = {
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
        let vote_close = u64::from_le_bytes(ea[EA_VOTE_CLOSE].try_into().unwrap());
        let agg_pk: [u8; 32] = ea[EA_AGG_PK].try_into().unwrap();
        (ea[EA_PHASE], vote_close, ea[EA_CAND_COUNT], agg_pk)
    };

    if election_phase != PHASE_VOTING_OPEN {
        return Err(ProgramError::InvalidInstructionData); // wrong phase
    }
    if current_slot >= voting_close_slot {
        return Err(ProgramError::InvalidInstructionData); // voting window closed
    }
    if candidate_id >= candidate_count {
        return Err(ProgramError::InvalidInstructionData); // no such candidate
    }

    // ── leaf_account: verify voter membership + read commitment zero-copy ────
    // The LeafAccount was written during registration by voter_registry.
    // Its existence (owned by the correct program, correct discriminator,
    // correct election + index) is the membership proof.
    // commitment is read directly from the account — not duplicated in
    // instruction data — and used for HSM sig reconstruction below.

    let commitment: [u8; 32] = {
        let vr_owner   = unsafe { voter_registry.owner() };
        let leaf_owner = unsafe { leaf_account.owner() };
        if leaf_owner != vr_owner {
            return Err(ProgramError::InvalidAccountData);
        }

        let leaf_data = leaf_account.try_borrow_data()?;

        if leaf_data.len() < 56 {
            return Err(ProgramError::InvalidAccountData);
        }
        if &leaf_data[0..8] != b"leaf\0\0\0\0" {
            return Err(ProgramError::InvalidAccountData);
        }
        if u64::from_le_bytes(leaf_data[8..16].try_into().unwrap()) != election_id {
            return Err(ProgramError::InvalidAccountData);
        }
        if u64::from_le_bytes(leaf_data[16..24].try_into().unwrap()) != leaf_index {
            return Err(ProgramError::InvalidAccountData);
        }

        leaf_data[24..56].try_into().unwrap()
    };

    // ── HSM Ed25519 ballot authorisation ────────────────────────────────────
    //
    // The enclave signs `IDV2-v1-ballot ‖ nullifier ‖ commitment` (78 bytes)
    // under the election's Ed25519 ballot-signing key stored in
    // `ElectionAccount.aggregation_pubkey`.
    //
    // Step 1 — authority pubkey consistency check:
    //   `authority_pk` in instruction data must match the key in ElectionAccount.
    //   Prevents a rogue relayer substituting a different signing key.

    if authority_pk != stored_authority_pk {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Step 2 — verify the native Ed25519 precompile ran in ix[0] of this tx,
    //   covering exactly (authority_pk, hsm_sig, ballot_msg).
    //   The runtime executes precompile instructions before any program logic,
    //   so if we reach here and the sysvar confirms the precompile was present
    //   with matching inputs, the sig is cryptographically verified.

    let mut ballot_msg = [0u8; 78];
    ballot_msg[..14].copy_from_slice(BALLOT_PREFIX);
    ballot_msg[14..46].copy_from_slice(&nullifier);
    ballot_msg[46..78].copy_from_slice(&commitment);

    verify_ed25519_ix(ixs_sysvar, &authority_pk, &hsm_sig, &ballot_msg)?;

    // ── duplicate-vote guard: nullifier PDA existence check ──────────────────
    // Check before CPI for a clean error code (the CPI would also fail, but
    // with a generic system-program error rather than a domain-specific one).

    if nullifier_account.data_len() != 0 {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    // ── create nullifier PDA ─────────────────────────────────────────────────

    let eid_le        = election_id.to_le_bytes();
    let null_bump_arr = [null_bump];
    let null_seeds    = [
        Seed::from(b"nullifier" as &[u8]),
        Seed::from(eid_le.as_ref()),
        Seed::from(nullifier.as_ref()),
        Seed::from(null_bump_arr.as_ref()),
    ];
    CreateAccount {
        from:     relayer,
        to:       nullifier_account,
        lamports: null_lamps,
        space:    NullifierAccount::LEN as u64,
        owner:    program_id,
    }
    .invoke_signed(&[Signer::from(&null_seeds)])?;

    // Mark the byte so data_len() > 0 on any future call to this ix.
    let null_data = unsafe { nullifier_account.borrow_mut_data_unchecked() };
    null_data[0] = 1;

    // ── create ballot PDA ────────────────────────────────────────────────────

    let ballot_bump_arr = [ballot_bump];
    let ballot_seeds    = [
        Seed::from(b"ballot" as &[u8]),
        Seed::from(eid_le.as_ref()),
        Seed::from(nullifier.as_ref()),
        Seed::from(ballot_bump_arr.as_ref()),
    ];
    CreateAccount {
        from:     relayer,
        to:       ballot_account,
        lamports: ballot_lamps,
        space:    BallotAccount::LEN as u64,
        owner:    program_id,
    }
    .invoke_signed(&[Signer::from(&ballot_seeds)])?;

    // ── write ballot ──────────────────────────────────────────────────────────
    // commitment is deliberately omitted — no on-chain link to LeafAccount.

    let bs = unsafe {
        BallotAccount::from_bytes_mut(ballot_account.borrow_mut_data_unchecked())
    };
    bs.discriminator = BallotAccount::DISCRIMINATOR;
    bs.election_id   = election_id;
    bs.nullifier     = nullifier;
    bs.state_id      = state_id;
    bs.candidate_id  = candidate_id;
    bs.lga_id        = lga_id;
    bs.slot          = current_slot;

    // ── tally CPI: accumulate_votes (ix_tag = 0) ─────────────────────────────
    // Data layout: [tag=0, eid_le(8), candidate_id, state_id] = 11 bytes.
    // Shard written by tally: counters[candidate_id * 4 + (state_id % 4)].
    let mut tally_ix_data = [0u8; 11];
    tally_ix_data[1..9].copy_from_slice(&election_id.to_le_bytes());
    tally_ix_data[9]  = candidate_id;
    tally_ix_data[10] = state_id;

    let tally_ix = pinocchio::instruction::Instruction {
        program_id: tally_program.key(),
        accounts: &[
            AccountMeta::writable(tally_account.key()),
            AccountMeta::readonly(clock_sysvar.key()),
        ],
        data: &tally_ix_data,
    };

    cpi::slice_invoke(&tally_ix, &[tally_account, clock_sysvar])?;

    Ok(())
}

// ── Ed25519 precompile verifier ───────────────────────────────────────────────
//
// Confirms that ix[0] of the current transaction is a native Ed25519 precompile
// instruction that verifies `expected_sig` over `expected_msg` under `expected_pk`.
//
// Instructions sysvar binary layout (Solana docs §Instructions Sysvar):
//   [0..2]          num_instructions : u16 LE
//   [2..2+2*N]      offsets[N]       : u16 LE  (byte offset of each ix from sysvar start)
//   per instruction at offset O:
//     [O..O+2]      num_accounts     : u16 LE
//     [O+2..O+2+A*34] accounts       : (pubkey[32] + flags[2]) × A
//     [O+2+A*34 .. +32] program_id   : [u8; 32]
//     [+32..+34]    data_len         : u16 LE
//     [+34..+34+L]  data             : [u8; L]
//
// Ed25519 precompile data layout (1 signature entry, 190 bytes for 78-byte msg):
//   [0]         count     : u8  (must be 1)
//   [1]         padding   : u8  (0)
//   [2..4]      sig_offset       : u16 LE  (offset of sig within data)
//   [4..6]      sig_ix_index     : u16 LE  (0xFFFF = same ix data)
//   [6..8]      pk_offset        : u16 LE
//   [8..10]     pk_ix_index      : u16 LE  (0xFFFF)
//   [10..12]    msg_offset       : u16 LE
//   [12..14]    msg_len          : u16 LE  (78)
//   [14..16]    msg_ix_index     : u16 LE  (0xFFFF)
//   [16..80]    sig              : [u8; 64]
//   [80..112]   pubkey           : [u8; 32]
//   [112..190]  message          : [u8; 78]
fn verify_ed25519_ix(
    ixs_sysvar: &AccountInfo,
    expected_pk:  &[u8; 32],
    expected_sig: &[u8; 64],
    expected_msg: &[u8; 78],
) -> ProgramResult {
    if ixs_sysvar.key() != &IXS_SYSVAR {
        return Err(ProgramError::InvalidAccountData);
    }

    let sysvar = ixs_sysvar.try_borrow_data()?;

    // Need at least: num_instructions(2) + one offset(2) = 4 bytes.
    if sysvar.len() < 4 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let num_ix = u16::from_le_bytes([sysvar[0], sysvar[1]]) as usize;
    if num_ix == 0 {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Offset of ix[0] is at sysvar[2..4].
    let ix0_off = u16::from_le_bytes([sysvar[2], sysvar[3]]) as usize;

    // Parse ix[0]: num_accounts → skip accounts block → program_id → data.
    if sysvar.len() < ix0_off + 2 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let num_acc = u16::from_le_bytes([sysvar[ix0_off], sysvar[ix0_off + 1]]) as usize;

    // Each account entry: 32-byte pubkey + 2-byte flags = 34 bytes.
    let prog_id_off = ix0_off + 2 + num_acc * 34;
    if sysvar.len() < prog_id_off + 32 + 2 {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Confirm ix[0] belongs to the Ed25519 precompile program.
    if &sysvar[prog_id_off..prog_id_off + 32] != ED25519_PROG.as_ref() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let data_len_off = prog_id_off + 32;
    let data_len = u16::from_le_bytes([sysvar[data_len_off], sysvar[data_len_off + 1]]) as usize;
    let data_off  = data_len_off + 2;

    // Minimum Ed25519 precompile data for one 78-byte msg entry: 190 bytes.
    if data_len < 190 || sysvar.len() < data_off + data_len {
        return Err(ProgramError::InvalidInstructionData);
    }

    let d = &sysvar[data_off..data_off + data_len];

    // count must be 1 (exactly one sig entry in this instruction).
    if d[0] != 1 {
        return Err(ProgramError::InvalidInstructionData);
    }

    // All three ix_index fields must be 0xFFFF (data lives in this ix, not another).
    let sig_ix_idx = u16::from_le_bytes([d[4],  d[5]]);
    let pk_ix_idx  = u16::from_le_bytes([d[8],  d[9]]);
    let msg_ix_idx = u16::from_le_bytes([d[14], d[15]]);
    if sig_ix_idx != 0xFFFF || pk_ix_idx != 0xFFFF || msg_ix_idx != 0xFFFF {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Verify the offsets point at the packed layout we build in the client:
    //   sig @ 16..80, pk @ 80..112, msg @ 112..190.
    let sig_off = u16::from_le_bytes([d[2],  d[3]]) as usize;
    let pk_off  = u16::from_le_bytes([d[6],  d[7]]) as usize;
    let msg_off = u16::from_le_bytes([d[10], d[11]]) as usize;
    let msg_len = u16::from_le_bytes([d[12], d[13]]) as usize;

    if msg_len != 78 {
        return Err(ProgramError::InvalidInstructionData);
    }
    if sig_off + 64 > data_len || pk_off + 32 > data_len || msg_off + 78 > data_len {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Constant-time byte-equal comparisons against expected values.
    if &d[sig_off..sig_off + 64] != expected_sig {
        return Err(ProgramError::InvalidInstructionData);
    }
    if &d[pk_off..pk_off + 32] != expected_pk {
        return Err(ProgramError::InvalidInstructionData);
    }
    if &d[msg_off..msg_off + 78] != expected_msg {
        return Err(ProgramError::InvalidInstructionData);
    }

    Ok(())
}
